-- ============================================================
--  header_rules_demo_seed.sql
--
--  Seeds a small set of *global* header-analysis rules so that
--  svc-04-header-analysis produces meaningful rule_hits / scores
--  in a fresh dev / demo environment.
--
--  These weights and thresholds are PRELIMINARY — they are not
--  calibrated against a labelled corpus. See MR follow-ups.
--
--  The DSL is implemented in:
--    services/svc-04-header-analysis/internal/rules/dsl.go
--
--  Layout of each rule's logic blob:
--    {
--      "category": "auth" | "reputation" | "structural",
--      "expr":     <leaf-or-composite>
--    }
--
--  Idempotent: ON CONFLICT (org_id, name, version) DO UPDATE.
-- ============================================================


-- ============================================================
--  AUTHENTICATION rules
-- ============================================================

INSERT INTO rules (org_id, name, description, version, status, target, score_impact, logic)
VALUES
    -- A.1  SPF outright fails: strong signal of spoofing.
    (NULL,
     'svc04.auth.spf_fail',
     'SPF check failed for sender domain.',
     '1.0.0', 'active', 'header', 25,
     '{
        "category": "auth",
        "expr": {"signal": "auth.spf", "op": "in", "value": ["fail", "softfail"]}
      }'::jsonb),

    -- A.2  DKIM fails or is missing while DMARC also fails.
    (NULL,
     'svc04.auth.dkim_and_dmarc_fail',
     'DKIM and DMARC both failed; very high spoof likelihood.',
     '1.0.0', 'active', 'header', 35,
     '{
        "category": "auth",
        "expr": {"all": [
            {"signal": "auth.dkim",  "op": "in", "value": ["fail", "none"]},
            {"signal": "auth.dmarc", "op": "in", "value": ["fail", "softfail"]}
        ]}
      }'::jsonb),

    -- A.3  From / Reply-To domain mismatch (common BEC pivot).
    (NULL,
     'svc04.auth.from_reply_to_mismatch',
     'From and Reply-To domains do not align.',
     '1.0.0', 'active', 'header', 20,
     '{
        "category": "auth",
        "expr": {"all": [
            {"signal": "auth.has_reply_to",        "op": "eq", "value": true},
            {"signal": "auth.from_reply_to_match", "op": "eq", "value": false}
        ]}
      }'::jsonb),

    -- A.4  From / Return-Path domain mismatch.
    (NULL,
     'svc04.auth.from_return_path_mismatch',
     'From and Return-Path domains do not align.',
     '1.0.0', 'active', 'header', 15,
     '{
        "category": "auth",
        "expr": {"all": [
            {"signal": "auth.has_return_path",        "op": "eq", "value": true},
            {"signal": "auth.from_return_path_match", "op": "eq", "value": false}
        ]}
      }'::jsonb)
ON CONFLICT (org_id, name, version) DO UPDATE
    SET description  = EXCLUDED.description,
        status       = EXCLUDED.status,
        target       = EXCLUDED.target,
        score_impact = EXCLUDED.score_impact,
        logic        = EXCLUDED.logic;


-- ============================================================
--  REPUTATION rules
-- ============================================================

INSERT INTO rules (org_id, name, description, version, status, target, score_impact, logic)
VALUES
    -- R.1  Sender domain matches an active TI indicator.
    (NULL,
     'svc04.reputation.ti_domain_match',
     'Sender domain present in active TI indicators.',
     '1.0.0', 'active', 'header', 50,
     '{
        "category": "reputation",
        "expr": {"signal": "reputation.ti_domain_match", "op": "eq", "value": true}
      }'::jsonb),

    -- R.2  Originating IP matches an active TI indicator.
    (NULL,
     'svc04.reputation.ti_ip_match',
     'Originating IP present in active TI indicators.',
     '1.0.0', 'active', 'header', 40,
     '{
        "category": "reputation",
        "expr": {"signal": "reputation.ti_ip_match", "op": "eq", "value": true}
      }'::jsonb),

    -- R.3  Typosquatting against the embedded brand list.
    (NULL,
     'svc04.reputation.typosquat_close_match',
     'Sender domain is within edit-distance 2 of a known brand domain.',
     '1.0.0', 'active', 'header', 35,
     '{
        "category": "reputation",
        "expr": {"all": [
            {"signal": "reputation.typosquat_distance", "op": "gt",  "value": 0},
            {"signal": "reputation.typosquat_distance", "op": "lte", "value": 2}
        ]}
      }'::jsonb),

    -- R.4  Free webmail provider sending business-style mail.
    (NULL,
     'svc04.reputation.free_provider',
     'Sender uses a free email provider domain.',
     '1.0.0', 'active', 'header', 10,
     '{
        "category": "reputation",
        "expr": {"signal": "reputation.is_free_provider", "op": "eq", "value": true}
      }'::jsonb)
ON CONFLICT (org_id, name, version) DO UPDATE
    SET description  = EXCLUDED.description,
        status       = EXCLUDED.status,
        target       = EXCLUDED.target,
        score_impact = EXCLUDED.score_impact,
        logic        = EXCLUDED.logic;


-- ============================================================
--  STRUCTURAL rules
-- ============================================================

INSERT INTO rules (org_id, name, description, version, status, target, score_impact, logic)
VALUES
    -- S.1  Unusually long received-chain.
    (NULL,
     'svc04.structural.excessive_hops',
     'Received-chain hop count exceeds configured threshold.',
     '1.0.0', 'active', 'header', 15,
     '{
        "category": "structural",
        "expr": {"signal": "structural.hop_count_above_threshold", "op": "eq", "value": true}
      }'::jsonb),

    -- S.2  Large clock drift between sent_timestamp and the chain.
    (NULL,
     'svc04.structural.time_drift',
     'Clock drift between Date and Received timestamps exceeds threshold.',
     '1.0.0', 'active', 'header', 15,
     '{
        "category": "structural",
        "expr": {"signal": "structural.time_drift_above_threshold", "op": "eq", "value": true}
      }'::jsonb),

    -- S.3  Suspicious / spoof-prone mailer agent strings.
    (NULL,
     'svc04.structural.suspicious_mailer',
     'X-Mailer / User-Agent matches a known spoofing-tool fingerprint.',
     '1.0.0', 'active', 'header', 20,
     '{
        "category": "structural",
        "expr": {"signal": "structural.suspicious_mailer_agent", "op": "eq", "value": true}
      }'::jsonb),

    -- S.4  Mailer header missing entirely.
    (NULL,
     'svc04.structural.missing_mailer',
     'Both X-Mailer and User-Agent headers are absent.',
     '1.0.0', 'active', 'header', 10,
     '{
        "category": "structural",
        "expr": {"signal": "structural.missing_mailer", "op": "eq", "value": true}
      }'::jsonb)
ON CONFLICT (org_id, name, version) DO UPDATE
    SET description  = EXCLUDED.description,
        status       = EXCLUDED.status,
        target       = EXCLUDED.target,
        score_impact = EXCLUDED.score_impact,
        logic        = EXCLUDED.logic;
