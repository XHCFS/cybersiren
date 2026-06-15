-- ============================================================
--  036_add_suspicious_threat_type.sql
--
--  Adds the 'suspicious' threat_type emitted by svc-03
--  (url-analysis) which was missing from the allowlist.  A row
--  carrying threat_type='suspicious' was rejected by the
--  trg_normalise_threat_type trigger, NACKing the consumer and
--  stalling the partition (poison-message stall).
--
--  Idempotent: ON CONFLICT (value) DO NOTHING.
-- ============================================================

INSERT INTO threat_type_values (value)
VALUES
	('suspicious')
ON CONFLICT (value) DO NOTHING;
