-- ============================================================
--  005_fix_current_verdicts.sql
--  Redefines current_verdicts to include created_by, which was
--  added to verdicts in 002 but omitted from the view.
--  Also adds 2027 partitions and fixes enriched_threats/orgs.
-- ============================================================

-- Fix current_verdicts view to include created_by
-- DROP first because CREATE OR REPLACE cannot add columns in the middle
DROP VIEW IF EXISTS current_verdicts;
CREATE VIEW current_verdicts AS
SELECT DISTINCT ON (entity_type, entity_id)
    entity_type,
    entity_id,
    label,
    confidence,
    source,
    model_version,
    notes,
    created_by,
    created_at
FROM verdicts
ORDER BY entity_type, entity_id, created_at DESC;

-- Add 2027 partitions to prevent rows from falling into default partition
CREATE TABLE IF NOT EXISTS emails_2027_01 PARTITION OF emails FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE IF NOT EXISTS emails_2027_02 PARTITION OF emails FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE IF NOT EXISTS emails_2027_03 PARTITION OF emails FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');
CREATE TABLE IF NOT EXISTS emails_2027_04 PARTITION OF emails FOR VALUES FROM ('2027-04-01') TO ('2027-05-01');
CREATE TABLE IF NOT EXISTS emails_2027_05 PARTITION OF emails FOR VALUES FROM ('2027-05-01') TO ('2027-06-01');
CREATE TABLE IF NOT EXISTS emails_2027_06 PARTITION OF emails FOR VALUES FROM ('2027-06-01') TO ('2027-07-01');
CREATE TABLE IF NOT EXISTS emails_2027_07 PARTITION OF emails FOR VALUES FROM ('2027-07-01') TO ('2027-08-01');
CREATE TABLE IF NOT EXISTS emails_2027_08 PARTITION OF emails FOR VALUES FROM ('2027-08-01') TO ('2027-09-01');
CREATE TABLE IF NOT EXISTS emails_2027_09 PARTITION OF emails FOR VALUES FROM ('2027-09-01') TO ('2027-10-01');
CREATE TABLE IF NOT EXISTS emails_2027_10 PARTITION OF emails FOR VALUES FROM ('2027-10-01') TO ('2027-11-01');
CREATE TABLE IF NOT EXISTS emails_2027_11 PARTITION OF emails FOR VALUES FROM ('2027-11-01') TO ('2027-12-01');
CREATE TABLE IF NOT EXISTS emails_2027_12 PARTITION OF emails FOR VALUES FROM ('2027-12-01') TO ('2028-01-01');

-- Add is_global flag to enriched_threats
ALTER TABLE enriched_threats
    ADD COLUMN IF NOT EXISTS is_global BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN enriched_threats.is_global IS
    'TRUE = shared across all tenants (e.g. ingested from a public feed). '
    'FALSE = attributed to org_id only. '
    'Queries for org-specific threats should filter WHERE is_global = FALSE AND org_id = $1. '
    'Queries for the full global TI corpus should filter WHERE is_global = TRUE.';

COMMENT ON COLUMN organisations.monthly_ingestion_limit IS
    'Soft cap on emails ingested per calendar month. '
    'NULL = unlimited. Enforcement is in the application layer (not a DB constraint). '
    'The enforcement window is calendar month, not rolling 30 days.';

