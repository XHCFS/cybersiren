// Package leader provides single-instance enforcement for SVC-11 via a Valkey
// lease. ARCH-SPEC §11 marks TI Sync as single-instance; today that relies on
// operator discipline. Only the elected leader runs the sync loop; other
// replicas idle, retrying acquisition, and take over within one TTL if the
// leader dies.
package leader

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"
)

// renewOwnedScript refreshes the lease TTL only if we still own it (atomic).
const renewOwnedScript = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end`

// releaseOwnedScript deletes the lease only if we still own it (atomic).
const releaseOwnedScript = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`

// Lease is a Valkey-backed leadership lock identified by a per-process token.
type Lease struct {
	vk  valkeygo.Client
	key string
	id  string
	ttl time.Duration
	log zerolog.Logger
}

// New creates a Lease. ttl must comfortably exceed the worst-case sync duration
// so the leader doesn't lose the lease mid-sync.
func New(vk valkeygo.Client, key string, ttl time.Duration, log zerolog.Logger) *Lease {
	return &Lease{vk: vk, key: key, id: newToken(), ttl: ttl, log: log}
}

// acquire attempts to take the lease (SET NX EX). Returns true if acquired.
func (l *Lease) acquire(ctx context.Context) (bool, error) {
	cmd := l.vk.B().Set().Key(l.key).Value(l.id).Nx().ExSeconds(int64(l.ttl.Seconds())).Build()
	err := l.vk.Do(ctx, cmd).Error()
	if err == nil {
		return true, nil
	}
	if valkeygo.IsValkeyNil(err) {
		return false, nil // held by someone else
	}
	return false, fmt.Errorf("leader: acquire: %w", err)
}

// renew extends the lease iff we still own it. Returns false if ownership lost.
func (l *Lease) renew(ctx context.Context) (bool, error) {
	cmd := l.vk.B().Eval().Script(renewOwnedScript).Numkeys(1).
		Key(l.key).Arg(l.id, fmt.Sprintf("%d", int64(l.ttl.Seconds()))).Build()
	n, err := l.vk.Do(ctx, cmd).ToInt64()
	if err != nil {
		return false, fmt.Errorf("leader: renew: %w", err)
	}
	return n == 1, nil
}

// release relinquishes the lease if we still own it (best-effort).
func (l *Lease) release(ctx context.Context) {
	cmd := l.vk.B().Eval().Script(releaseOwnedScript).Numkeys(1).Key(l.key).Arg(l.id).Build()
	_ = l.vk.Do(ctx, cmd).Error()
}

// RunAsLeader blocks until this instance wins the lease, then runs fn with a
// context that is cancelled if leadership is lost (failed renewal) or the parent
// ctx ends. Non-leaders poll every ttl/2 until they win or ctx ends. fn is the
// leader-only work (the sync loop) and should return when its ctx is cancelled.
func (l *Lease) RunAsLeader(ctx context.Context, fn func(ctx context.Context) error) error {
	pollEvery := l.ttl / 2
	if pollEvery <= 0 {
		pollEvery = time.Second
	}
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("leader: %w", err)
		}
		won, err := l.acquire(ctx)
		if err != nil {
			l.log.Warn().Err(err).Msg("leader: acquire failed; retrying")
		}
		if won {
			l.log.Info().Str("lease", l.key).Msg("acquired leadership")
			return l.lead(ctx, fn)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("leader: %w", ctx.Err())
		case <-time.After(pollEvery):
		}
	}
}

// lead runs fn while holding the lease, renewing in the background. If a renewal
// reports lost ownership, fn's context is cancelled so it stops promptly.
func (l *Lease) lead(ctx context.Context, fn func(ctx context.Context) error) error {
	leaderCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer l.release(context.WithoutCancel(ctx))

	go l.renewLoop(leaderCtx, cancel)
	return fn(leaderCtx)
}

// renewLoop refreshes the lease every ttl/3 and cancels leadership on loss.
func (l *Lease) renewLoop(ctx context.Context, cancel context.CancelFunc) {
	every := l.ttl / 3
	if every <= 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ok, err := l.renew(ctx)
			if err != nil {
				l.log.Warn().Err(err).Msg("leader: renew error")
				continue // transient; a later tick may succeed before TTL
			}
			if !ok {
				l.log.Warn().Msg("leader: lost lease; stepping down")
				cancel()
				return
			}
		}
	}
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
