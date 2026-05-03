package campaign

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/mfonda/simhash"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"
)

// SimHashThreshold is the canonical Hamming distance bound for "near
// duplicate" — 3 bits out of 64, per Manku/Jain (Google) and consistent
// with ARCH-SPEC §8.2.
const SimHashThreshold = 3

// keyMeta returns the per-campaign metadata HASH key.
func keyMeta(orgID, campaignID int64) string {
	return fmt.Sprintf("simhash_meta:%d:%d", orgID, campaignID)
}

// keyIndex returns the per-org SET key listing all campaign IDs that
// have a stored SimHash. Used to bound the SCAN-free linear lookup.
func keyIndex(orgID int64) string {
	return fmt.Sprintf("simhash:idx:%d", orgID)
}

// SimHashTTL is the Valkey TTL on simhash_meta keys (per ARCH-SPEC §13).
const SimHashTTLSeconds = 30 * 24 * 3600

// Match is the result of a successful SimHash lookup.
type Match struct {
	CampaignID  int64
	Fingerprint string
	Hash        uint64
	Distance    int
}

// Computer wraps the mfonda/simhash library and the Redis-backed
// candidate index used by the engine to detect near-duplicate emails
// across slightly-different fingerprints (e.g. URL typosquatting).
type Computer struct {
	client            valkeygo.Client
	threshold         int
	log               zerolog.Logger
	lookupIndexSample prometheus.Observer // optional: SMEMBERS cardinality per Lookup
}

// NewComputer constructs a Computer. client may be nil — the Compute /
// Lookup / Store methods all become no-ops when no Valkey is wired,
// preserving the engine's degraded-mode contract. lookupIndexSample
// records len(SMEMBERS simhash:idx:{org}) each Lookup when non-nil.
func NewComputer(client valkeygo.Client, threshold int, log zerolog.Logger, lookupIndexSample prometheus.Observer) *Computer {
	if threshold <= 0 {
		threshold = SimHashThreshold
	}
	return &Computer{client: client, threshold: threshold, log: log, lookupIndexSample: lookupIndexSample}
}

// Compute returns the 64-bit SimHash of the input text. An empty input
// produces a zero hash; callers should use the (uint64, bool) form
// where the bool reflects "had usable content".
func (c *Computer) Compute(text string) (uint64, bool) {
	if text == "" {
		return 0, false
	}
	fs := simhash.NewWordFeatureSet([]byte(text))
	return simhash.Simhash(fs), true
}

// Lookup walks every campaign id in the per-org index and returns the
// first one whose stored SimHash is within the configured Hamming
// threshold. Returns (Match{}, false, nil) on no match. A non-nil
// error is returned only on genuine Redis errors; missing keys / empty
// indexes are not errors.
func (c *Computer) Lookup(ctx context.Context, orgID int64, hash uint64) (Match, bool, error) {
	if c == nil || c.client == nil {
		return Match{}, false, nil
	}
	idxKey := keyIndex(orgID)
	cmd := c.client.Do(ctx, c.client.B().Smembers().Key(idxKey).Build())
	members, err := cmd.AsStrSlice()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return Match{}, false, nil
		}
		return Match{}, false, fmt.Errorf("smembers %s: %w", idxKey, err)
	}
	if c.lookupIndexSample != nil {
		c.lookupIndexSample.Observe(float64(len(members)))
	}
	for _, m := range members {
		cid, perr := strconv.ParseInt(m, 10, 64)
		if perr != nil {
			continue
		}
		stored, fp, ok, herr := c.fetchMeta(ctx, orgID, cid)
		if herr != nil {
			c.log.Debug().Err(herr).Int64("campaign_id", cid).Msg("simhash fetch failed; skipping candidate")
			continue
		}
		if !ok {
			continue
		}
		dist := int(simhash.Compare(hash, stored))
		if dist <= c.threshold {
			return Match{CampaignID: cid, Fingerprint: fp, Hash: stored, Distance: dist}, true, nil
		}
	}
	return Match{}, false, nil
}

// Store records the (hash, fingerprint) pair under the campaign's
// metadata hash and adds the campaign id to the per-org index. Both
// keys are TTL'd to 30 days; the TTL is refreshed on every Store. A
// nil client makes this a no-op.
func (c *Computer) Store(ctx context.Context, orgID, campaignID int64, hash uint64, fingerprint string) error {
	if c == nil || c.client == nil {
		return nil
	}

	hashHex := strconv.FormatUint(hash, 16)

	// HSET the meta hash (hash + fingerprint).
	if err := c.client.Do(ctx,
		c.client.B().Hset().Key(keyMeta(orgID, campaignID)).
			FieldValue().
			FieldValue("hash", hashHex).
			FieldValue("fingerprint", fingerprint).
			Build(),
	).Error(); err != nil {
		return fmt.Errorf("simhash hset: %w", err)
	}
	if err := c.client.Do(ctx,
		c.client.B().Expire().Key(keyMeta(orgID, campaignID)).Seconds(SimHashTTLSeconds).Build(),
	).Error(); err != nil {
		return fmt.Errorf("simhash expire meta: %w", err)
	}

	// SADD the index, then refresh its TTL.
	if err := c.client.Do(ctx,
		c.client.B().Sadd().Key(keyIndex(orgID)).Member(strconv.FormatInt(campaignID, 10)).Build(),
	).Error(); err != nil {
		return fmt.Errorf("simhash sadd: %w", err)
	}
	if err := c.client.Do(ctx,
		c.client.B().Expire().Key(keyIndex(orgID)).Seconds(SimHashTTLSeconds).Build(),
	).Error(); err != nil {
		return fmt.Errorf("simhash expire idx: %w", err)
	}
	return nil
}

// fetchMeta retrieves (hash, fingerprint) for one campaign. Returns
// (0, "", false, nil) when the meta key is missing (campaign aged out
// of Valkey).
func (c *Computer) fetchMeta(ctx context.Context, orgID, campaignID int64) (uint64, string, bool, error) {
	cmd := c.client.Do(ctx, c.client.B().Hmget().Key(keyMeta(orgID, campaignID)).Field("hash", "fingerprint").Build())
	arr, err := cmd.ToArray()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return 0, "", false, nil
		}
		return 0, "", false, fmt.Errorf("simhash hmget to array: %w", err)
	}
	if len(arr) != 2 {
		return 0, "", false, errors.New("simhash hmget: unexpected reply length")
	}
	hashStr, _ := arr[0].ToString()
	fp, _ := arr[1].ToString()
	if hashStr == "" {
		return 0, "", false, nil
	}
	hash, err := strconv.ParseUint(hashStr, 16, 64)
	if err != nil {
		return 0, "", false, fmt.Errorf("parse stored simhash: %w", err)
	}
	return hash, fp, true, nil
}
