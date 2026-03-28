-- Seed data for feeds table.
-- Idempotent by name via ON CONFLICT (name) DO UPDATE.
-- NOTE: feeds.feed_type currently accepts feed_type_enum values
-- ('threat_intel', 'reputation', 'blocklist', 'sandbox').
-- External URL feeds are represented here as 'threat_intel'.

-- Feed: phishtank
-- Data quality signal: community-verified phishing submissions with high confidence.
-- Auth requirement: API key required. The literal token {api_key} in the URL is replaced at runtime from FEED_PHISHTANK_API_KEY.
INSERT INTO feeds (
    name,
    display_name,
    feed_type,
    url,
    last_fetched_at,
    enabled,
    reliability_weight
) VALUES (
    'phishtank',
    'PhishTank',
    'threat_intel',
    'http://data.phishtank.com/data/{api_key}/online-valid.json',
    NULL,
    TRUE,
    0.95
)
ON CONFLICT (name) DO UPDATE
SET
    url = EXCLUDED.url,
    enabled = EXCLUDED.enabled,
    reliability_weight = EXCLUDED.reliability_weight;

-- Feed: openphish
-- Data quality signal: operational phishing URL feed with frequent updates and good signal.
-- Auth requirement: no API key required for the configured endpoint.
INSERT INTO feeds (
    name,
    display_name,
    feed_type,
    url,
    last_fetched_at,
    enabled,
    reliability_weight
) VALUES (
    'openphish',
    'OpenPhish',
    'threat_intel',
    'https://openphish.com/feed.txt',
    NULL,
    TRUE,
    0.80
)
ON CONFLICT (name) DO UPDATE
SET
    url = EXCLUDED.url,
    enabled = EXCLUDED.enabled,
    reliability_weight = EXCLUDED.reliability_weight;

-- Feed: urlhaus
-- Data quality signal: curated abuse.ch URL feed with strong malware/phishing coverage.
-- Auth requirement: no API key required for csv_recent endpoint.
INSERT INTO feeds (
    name,
    display_name,
    feed_type,
    url,
    last_fetched_at,
    enabled,
    reliability_weight
) VALUES (
    'urlhaus',
    'URLhaus',
    'threat_intel',
    'https://urlhaus.abuse.ch/downloads/csv_recent/',
    NULL,
    TRUE,
    0.80
)
ON CONFLICT (name) DO UPDATE
SET
    url = EXCLUDED.url,
    enabled = EXCLUDED.enabled,
    reliability_weight = EXCLUDED.reliability_weight;

-- Feed: threatfox
-- Data quality signal: abuse.ch IOC feed with broader indicator coverage and moderate confidence.
-- Auth requirement: no API key required for the public API endpoint.
INSERT INTO feeds (
    name,
    display_name,
    feed_type,
    url,
    last_fetched_at,
    enabled,
    reliability_weight
) VALUES (
    'threatfox',
    'ThreatFox',
    'threat_intel',
    'https://threatfox-api.abuse.ch/api/v1/',
    NULL,
    TRUE,
    0.75
)
ON CONFLICT (name) DO UPDATE
SET
    url = EXCLUDED.url,
    enabled = EXCLUDED.enabled,
    reliability_weight = EXCLUDED.reliability_weight;
