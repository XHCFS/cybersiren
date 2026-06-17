-- ============================================================
--  attachment_demo_seed.sql
--
--  Seeds the malicious-attachment hash the smoke superset fixture
--  (scripts/dev/inject_fake_email.sh INJECTION A) ships as
--  invoice.pdf.exe, so svc-05's hash-lookup → score-90 →
--  FlagMalicious → ti_source=attachment_library path runs
--  end-to-end in the demo pipeline.
--
--  CRITICAL: this sha256 MUST equal sha256(decoded attachment
--  bytes). The fixture attachment body is the base64 of the fixed
--  payload "CYBERSIREN-SMOKE-MALWARE-FIXTURE-V1\n", whose sha256 is:
--      printf 'CYBERSIREN-SMOKE-MALWARE-FIXTURE-V1\n' | sha256sum
--      ed8ac563a8b03e42b728cb322892d906d9b7da618704d13a1aeaa1f3551b00f4
--  If the fixture bytes change, recompute and update BOTH the
--  fixture base64 and this hash, or the lookup silently misses and
--  only the heuristic (.exe + double-ext = 60) path proves.
--
--  Mirrors the UpsertMalwareHash column shape
--  (db/queries/attachment_library.sql): only sha256 is NOT NULL.
--  Idempotent: ON CONFLICT (sha256) DO UPDATE.
-- ============================================================

INSERT INTO attachment_library (sha256, is_malicious, risk_score, threat_tags)
VALUES
    -- Smoke superset fixture (scripts/dev/inject_fake_email.sh INJECTION A):
    -- base64 of "CYBERSIREN-SMOKE-MALWARE-FIXTURE-V1\n".
    ('ed8ac563a8b03e42b728cb322892d906d9b7da618704d13a1aeaa1f3551b00f4', TRUE, 90, '{malware}'::text[]),
    -- cs-demo UI "malware" sample (demo/dashboard/web/index.html, invoice.pdf.exe).
    -- sha256 of its decoded base64 payload, so the sample classifies as malware
    -- (hash hit → score 90 → ≥76 malware-grade attachment → reconciled to malware).
    ('34b9348ecccb09747637e5bdaa744e48362a9e684b260766e49868f2e50cecab', TRUE, 90, '{malware}'::text[])
ON CONFLICT (sha256) DO UPDATE
    SET is_malicious = TRUE,
        risk_score   = GREATEST(attachment_library.risk_score, EXCLUDED.risk_score),
        threat_tags  = EXCLUDED.threat_tags;
