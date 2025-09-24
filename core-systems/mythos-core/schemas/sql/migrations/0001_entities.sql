-- mythos-core/schemas/sql/migrations/0001_entities.sql
-- Requires: PostgreSQL >= 13
-- Purpose : Base multi-tenant metadata for entity types

-- migrate:up
BEGIN;

-- Safety & deterministic DDL
SET LOCAL client_min_messages = WARNING;
SET LOCAL lock_timeout = '10s';
SET LOCAL idle_in_transaction_session_timeout = '5min';
SET LOCAL statement_timeout = '5min';

-- Extensions used
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gin;  -- useful composite indexes (optional)
CREATE EXTENSION IF NOT EXISTS btree_gist; -- optional, future-proofing

-- Dedicated schema
CREATE SCHEMA IF NOT EXISTS mythos;
COMMENT ON SCHEMA mythos IS 'mythos-core: base metadata schema for entity types and tenancy';

-- -----------------------------------------------------------------------------
-- Types
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'entity_status') THEN
    CREATE TYPE mythos.entity_status AS ENUM ('active','inactive','archived');
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Helper functions & triggers
-- -----------------------------------------------------------------------------
-- Auto-touch updated_at
CREATE OR REPLACE FUNCTION mythos.tg_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END$$;

COMMENT ON FUNCTION mythos.tg_touch_updated_at() IS
'Sets updated_at = now() on row UPDATE';

-- Validate slug-like identifiers (lowercase, digits, underscore; 2..64)
CREATE OR REPLACE FUNCTION mythos.is_valid_slug(text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT $1 ~ '^[a-z][a-z0-9_]{1,63}$';
$$;

COMMENT ON FUNCTION mythos.is_valid_slug(text) IS
'Validates machine-readable identifiers: ^[a-z][a-z0-9_]{1,63}$';

-- -----------------------------------------------------------------------------
-- Tenants (minimal)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mythos.tenants (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         text NOT NULL UNIQUE,
  name         text NOT NULL,
  description  text,
  created_at   timestamptz NOT NULL DEFAULT NOW(),
  updated_at   timestamptz NOT NULL DEFAULT NOW(),
  deleted_at   timestamptz
);
COMMENT ON TABLE mythos.tenants IS 'Tenants registry (multi-tenant isolation anchor)';
COMMENT ON COLUMN mythos.tenants.slug IS 'Human-stable tenant identifier (unique)';
COMMENT ON COLUMN mythos.tenants.deleted_at IS 'Soft-delete timestamp';

ALTER TABLE mythos.tenants
  ADD CONSTRAINT tenants_slug_valid_chk CHECK (mythos.is_valid_slug(slug));

DROP TRIGGER IF EXISTS trg_touch_updated_at ON mythos.tenants;
CREATE TRIGGER trg_touch_updated_at
BEFORE UPDATE ON mythos.tenants
FOR EACH ROW
EXECUTE FUNCTION mythos.tg_touch_updated_at();

-- -----------------------------------------------------------------------------
-- Entities (types/definitions)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mythos.entities (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES mythos.tenants(id) ON DELETE CASCADE,
  -- Machine-readable identity of entity type (e.g. "user", "order_item")
  name          text NOT NULL,
  -- Human-facing display name
  display_name  text NOT NULL,
  -- Join key used across data pipelines (e.g. "user_id")
  join_key      text NOT NULL,
  description   text,
  status        mythos.entity_status NOT NULL DEFAULT 'active',
  version       integer NOT NULL DEFAULT 1,
  -- Optional JSON Schema-like descriptor for fields (free-form)
  schema        jsonb,
  -- Labels/tags for indexing & governance
  labels        jsonb,
  created_at    timestamptz NOT NULL DEFAULT NOW(),
  updated_at    timestamptz NOT NULL DEFAULT NOW(),
  deleted_at    timestamptz,
  -- ETag/hash for optimistic caching (optional)
  etag          bytea
);

COMMENT ON TABLE mythos.entities IS 'Entity type registry per tenant (metadata for data/model joins)';
COMMENT ON COLUMN mythos.entities.name IS 'Machine-readable slug (lowercase, [a-z0-9_], 2..64)';
COMMENT ON COLUMN mythos.entities.join_key IS 'Canonical join key name for this entity type';
COMMENT ON COLUMN mythos.entities.schema IS 'JSONB: schema descriptor (org-specific)';
COMMENT ON COLUMN mythos.entities.labels IS 'JSONB: free-form labels/tags';
COMMENT ON COLUMN mythos.entities.deleted_at IS 'Soft-delete timestamp';

-- Invariants & uniqueness
ALTER TABLE mythos.entities
  ADD CONSTRAINT entities_name_valid_chk  CHECK (mythos.is_valid_slug(name)),
  ADD CONSTRAINT entities_join_key_valid_chk CHECK (mythos.is_valid_slug(join_key));

-- Unique per-tenant name and join_key
CREATE UNIQUE INDEX IF NOT EXISTS ux_entities_tenant_name
  ON mythos.entities(tenant_id, name)
  WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_entities_tenant_join_key
  ON mythos.entities(tenant_id, join_key)
  WHERE deleted_at IS NULL;

-- Search indexes
CREATE INDEX IF NOT EXISTS ix_entities_tenant_status
  ON mythos.entities(tenant_id, status)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_entities_labels_gin
  ON mythos.entities
  USING gin (labels);

CREATE INDEX IF NOT EXISTS ix_entities_schema_gin
  ON mythos.entities
  USING gin (schema);

-- Touch updated_at on UPDATE
DROP TRIGGER IF EXISTS trg_touch_updated_at ON mythos.entities;
CREATE TRIGGER trg_touch_updated_at
BEFORE UPDATE ON mythos.entities
FOR EACH ROW
EXECUTE FUNCTION mythos.tg_touch_updated_at();

-- Optional soft-delete view
CREATE OR REPLACE VIEW mythos.entities_active AS
  SELECT *
  FROM mythos.entities
  WHERE deleted_at IS NULL AND status = 'active';
COMMENT ON VIEW mythos.entities_active IS 'Active, non-deleted entity types';

-- -----------------------------------------------------------------------------
-- Row-Level Security (RLS) for multi-tenant isolation
-- Expectation: set `SET LOCAL mythos.tenant_id = ''<uuid>''` per request/job.
-- -----------------------------------------------------------------------------
ALTER TABLE mythos.tenants  ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.entities ENABLE ROW LEVEL SECURITY;

-- Helper: current tenant from GUC (nullable)
CREATE OR REPLACE FUNCTION mythos.current_tenant() RETURNS uuid
LANGUAGE sql STABLE
AS $$
  SELECT NULLIF(current_setting('mythos.tenant_id', true), '')::uuid;
$$;

-- Tenants: allow SELECT/UPDATE only for current_tenant(), INSERT allowed if NEW.id equals current_tenant()
DROP POLICY IF EXISTS tenants_isolation_select ON mythos.tenants;
CREATE POLICY tenants_isolation_select
ON mythos.tenants
FOR SELECT
USING (id = mythos.current_tenant());

DROP POLICY IF EXISTS tenants_isolation_update ON mythos.tenants;
CREATE POLICY tenants_isolation_update
ON mythos.tenants
FOR UPDATE
USING (id = mythos.current_tenant());

DROP POLICY IF EXISTS tenants_isolation_insert ON mythos.tenants;
CREATE POLICY tenants_isolation_insert
ON mythos.tenants
FOR INSERT
WITH CHECK (id = mythos.current_tenant());

-- Entities: CRUD only within current tenant
DROP POLICY IF EXISTS entities_isolation_all ON mythos.entities;
CREATE POLICY entities_isolation_all
ON mythos.entities
USING (tenant_id = mythos.current_tenant())
WITH CHECK (tenant_id = mythos.current_tenant());

-- (Optionally) restrict DML by role; grant read to app role, DDL to owner (configure in deployment)
-- Example GRANTS (adjust role names to your org):
-- GRANT USAGE ON SCHEMA mythos TO app_ro, app_rw;
-- GRANT SELECT ON ALL TABLES IN SCHEMA mythos TO app_ro;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mythos TO app_rw;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA mythos GRANT SELECT ON TABLES TO app_ro;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA mythos GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;

COMMIT;

-- migrate:down
BEGIN;

DROP POLICY IF EXISTS entities_isolation_all ON mythos.entities;
DROP POLICY IF EXISTS tenants_isolation_insert ON mythos.tenants;
DROP POLICY IF EXISTS tenants_isolation_update ON mythos.tenants;
DROP POLICY IF EXISTS tenants_isolation_select ON mythos.tenants;

ALTER TABLE IF EXISTS mythos.entities DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS mythos.tenants  DISABLE ROW LEVEL SECURITY;

DROP VIEW IF EXISTS mythos.entities_active;

DROP TRIGGER IF EXISTS trg_touch_updated_at ON mythos.entities;
DROP TRIGGER IF EXISTS trg_touch_updated_at ON mythos.tenants;

DROP TABLE IF EXISTS mythos.entities;
DROP TABLE IF EXISTS mythos.tenants;

DROP FUNCTION IF EXISTS mythos.current_tenant();
DROP FUNCTION IF EXISTS mythos.is_valid_slug(text);
DROP FUNCTION IF EXISTS mythos.tg_touch_updated_at();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'entity_status') THEN
    DROP TYPE mythos.entity_status;
  END IF;
END$$;

-- Keep schema & extensions; remove if you want full teardown:
-- DROP SCHEMA IF EXISTS mythos CASCADE;
-- DROP EXTENSION IF EXISTS btree_gist;
-- DROP EXTENSION IF EXISTS btree_gin;
-- DROP EXTENSION IF EXISTS pgcrypto;

COMMIT;
