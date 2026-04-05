-- ============================================================
--  ti_demo_seed.sql
--
--  Seeds a demo TI feed and ~20 domain indicators for local
--  development and demo environments. Fully idempotent.
--
--  Demo TI seed data sourced from public feeds (OpenPhish, URLhaus)
--  Last updated: 2026-04-05
--  These are REAL known-bad domains for demo/testing purposes.
--
--  Sources:
--    • OpenPhish public feed — https://openphish.com/feed.txt
--    • URLhaus recent URLs   — https://urlhaus.abuse.ch/downloads/text_recent/
-- ============================================================


-- ============================================================
--  1.  Extend feed_type_enum with 'demo' (idempotent)
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum
        WHERE enumlabel = 'demo'
          AND enumtypid = (
              SELECT oid FROM pg_type WHERE typname = 'feed_type_enum'
          )
    ) THEN
        ALTER TYPE feed_type_enum ADD VALUE 'demo';
    END IF;
END;
$$;


-- ============================================================
--  2.  Insert demo feed (idempotent via ON CONFLICT)
-- ============================================================

INSERT INTO feeds (name, display_name, feed_type, url, last_fetched_at, enabled, reliability_weight)
VALUES ('demo-seed', 'Demo Seed', 'demo', 'local://demo', NULL, TRUE, 1.0)
ON CONFLICT (name) DO NOTHING;


-- ============================================================
--  3.  Insert demo domain indicators (idempotent via UNIQUE)
--
--  Real domains from public TI feeds, categorised:
--    • Phishing   (risk 85–100)  —  8 domains  (OpenPhish)
--    • Malware    (risk 90–100)  —  7 domains  (URLhaus)
--    • Botnet C2  (risk 80–95)   —  5 domains  (URLhaus)
-- ============================================================

INSERT INTO ti_indicators (
    feed_id,
    indicator_type,
    indicator_value,
    threat_type,
    risk_score,
    confidence,
    is_active,
    first_seen
) VALUES
    -- Phishing domains (OpenPhish feed, risk 85–100)
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'dpd.parcelstahdu.bond',            'phishing', 95,  0.92, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'dpd.parcelroutenotice.cfd',        'phishing', 93,  0.91, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'dpd.parcelsignalpoint.cfd',        'phishing', 90,  0.88, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'coinbase.aw-windblocker.com',      'phishing', 92,  0.90, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'coinbase.hrbwya.com',              'phishing', 88,  0.86, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'airbnb-dev.vercel.app',            'phishing', 85,  0.82, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'bitfghurt-login.webflow.io',       'phishing', 87,  0.84, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'cashenta.com',                     'phishing', 100, 0.95, TRUE, CURRENT_TIMESTAMP),

    -- Malware domains (URLhaus feed, risk 90–100)
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'adobe-viewer.0lsons.com',          'malware',  95,  0.93, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'adobe-viewer.iziliang.com',        'malware',  98,  0.96, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'adobe-viewer.parallelsw.com',      'malware',  92,  0.90, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'ads-storage.biz',                  'malware',  90,  0.88, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'aetherixcore.cc',                  'malware',  94,  0.91, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'aaa4b.com',                        'malware',  100, 0.97, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'adderall.rocks',                   'malware',  91,  0.89, TRUE, CURRENT_TIMESTAMP),

    -- C2 / botnet domains (URLhaus feed, risk 80–95)
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'agent-client-stoarge.webredirect.org', 'botnet_cc', 90, 0.87, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'a08ulcab.highjoke.in.net',            'botnet_cc', 85, 0.82, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'a4-scan-point.puroflusso.in.net',     'botnet_cc', 80, 0.78, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'admin-panel.sectoralcontrol.in.net',  'botnet_cc', 88, 0.85, TRUE, CURRENT_TIMESTAMP),
    ((SELECT id FROM feeds WHERE name = 'demo-seed'), 'domain', 'agentscript.dawnspire.in.net',        'botnet_cc', 95, 0.92, TRUE, CURRENT_TIMESTAMP)
ON CONFLICT ON CONSTRAINT uq_ti_indicators_feed_type_value DO NOTHING;
