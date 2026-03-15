-- sqlc compatibility shims.
-- This file exists solely to help sqlc statically parse schema objects that are
-- created conditionally/dynamically in migrations (e.g., inside DO blocks).
-- Keep definitions here minimal and in sync with migration source-of-truth.

CREATE TYPE ti_indicator_type AS ENUM (
    'url',
    'domain',
    'ip',
    'cidr',
    'hash',
    'email_address'
);
