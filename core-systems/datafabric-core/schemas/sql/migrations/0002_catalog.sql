-- 0002_catalog.sql
-- DataFabric Core: Catalog schema for datasets and versions (PostgreSQL 14+)

-- ===== SAFETY & PRELUDE ======================================================
\echo 'Applying migration 0002_catalog.sql ...'
BEGIN;

-- Extensions commonly used (idempotent)
CREATE EXTENSION IF NOT EXISTS pgcrypto;           -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gin;          -- for GIN mixed ops
CREATE EXTENSION IF NOT EXISTS pg_trgm;            -- trigram search (optional)

-- ===== SCHEMA ================================================================
CREATE SCHEMA IF NOT EXISTS catalog AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA catalog IS 'Data catalog: datasets, versions, labels, ACL, endpoints, stats';

-- ===== ENUM TYPES (idempotent creation via DO blocks) ========================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dataset_type') THEN
    CREATE TYPE catalog.dataset_type AS ENUM ('STREAM','BATCH','VIRTUAL');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dataset_state') THEN
    CREATE TYPE catalog.dataset_state AS ENUM ('ACTIVE','INACTIVE','DEPRECATED','DELETED');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'storage_format') THEN
    CREATE TYPE catalog.storage_format AS ENUM ('JSON','AVRO','PROTOBUF','PARQUET','CSV');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'access_level') THEN
    CREATE TYPE catalog.access_level AS ENUM ('PUBLIC','INTERNAL','RESTRICTED');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'retention_policy') THEN
    CREATE TYPE catalog.retention_policy AS ENUM ('TTL','FOREVER');
  END IF;
END$$;

-- ===== TENANT GUARD: application sets app.current_tenant per session =========
-- Expectation: SET LOCAL app.current_tenant = '<tenant_id>' in request scope.
-- RLS policies rely on this setting; NULL means deny.

-- ===== COMMON UTILITIES ======================================================
-- Updated_at trigger function (idempotent)
CREATE OR REPLACE FUNCTION catalog.tg_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- Label key/value validation (keys: <=64 chars, kebab/underscore; values: <=256)
CREATE OR REPLACE FUNCTION catalog.fn_validate_labels(labels jsonb)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  k text; v text;
BEGIN
  IF labels IS NULL THEN
    RETURN TRUE;
  END IF;

  IF jsonb_typeof(labels) <> 'object' THEN
    RAISE EXCEPTION 'labels must be a JSON object';
  END IF;

  FOR k, v IN
    SELECT key, value::text
    FROM jsonb_each_text(labels)
  LOOP
    IF length(k) > 64 OR k !~ '^[a-zA-Z0-9_\-\.]+$' THEN
      RAISE EXCEPTION 'invalid label key: %', k;
    END IF;
    IF length(v) > 256 THEN
      RAISE EXCEPTION 'label value too long for key %', k;
    END IF;
  END LOOP;
  RETURN TRUE;
END$$;

-- ===== TABLE: datasets =======================================================
CREATE TABLE IF NOT EXISTS catalog.datasets (
  dataset_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             text NOT NULL,                             -- tenant isolation
  name                  text NOT NULL,                             -- human-readable unique per tenant
  slug                  text GENERATED ALWAYS AS
                          (lower(regexp_replace(name, '[^a-zA-Z0-9]+', '-', 'g'))) STORED,
  description           text,
  type                  catalog.dataset_type NOT NULL,
  state                 catalog.dataset_state NOT NULL DEFAULT 'ACTIVE',
  access_level          catalog.access_level NOT NULL DEFAULT 'INTERNAL',

  storage_policy        catalog.retention_policy NOT NULL DEFAULT 'TTL',
  storage_ttl_seconds   bigint NOT NULL DEFAULT 15552000,          -- 180d
  default_format        catalog.storage_format NOT NULL DEFAULT 'PARQUET',

  labels                jsonb NOT NULL DEFAULT '{}'::jsonb,
  annotations           jsonb NOT NULL DEFAULT '{}'::jsonb,

  created_by            text NOT NULL,
  updated_by            text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),

  -- Constraints
  CONSTRAINT uq_datasets_tenant_slug UNIQUE (tenant_id, slug),
  CONSTRAINT ck_labels_valid CHECK (catalog.fn_validate_labels(labels)),
  CONSTRAINT ck_annotations_object CHECK (jsonb_typeof(annotations) IS NULL OR jsonb_typeof(annotations) = 'object'),
  CONSTRAINT ck_ttl_positive CHECK (storage_policy <> 'TTL' OR storage_ttl_seconds > 0)
);

COMMENT ON TABLE catalog.datasets IS 'Datasets catalog: single row per logical dataset.';
COMMENT ON COLUMN catalog.datasets.labels IS 'Free-form labels (validated keys/values).';

CREATE TRIGGER set_updated_at_datasets
BEFORE UPDATE ON catalog.datasets
FOR EACH ROW EXECUTE FUNCTION catalog.tg_set_updated_at();

-- Useful indexes
CREATE INDEX IF NOT EXISTS ix_datasets_tenant_state ON catalog.datasets (tenant_id, state);
CREATE INDEX IF NOT EXISTS ix_datasets_slug_trgm ON catalog.datasets USING gin (slug gin_trgm_ops);
CREATE INDEX IF NOT EXISTS ix_datasets_labels_gin ON catalog.datasets USING gin (labels jsonb_path_ops);

-- ===== TABLE: dataset_versions ==============================================
CREATE TABLE IF NOT EXISTS catalog.dataset_versions (
  version_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dataset_id            uuid NOT NULL REFERENCES catalog.datasets(dataset_id) ON DELETE CASCADE,

  version               integer NOT NULL,                           -- monotonically increasing per dataset
  schema_uri            text NOT NULL,
  schema_version        integer NOT NULL DEFAULT 1,
  format                catalog.storage_format NOT NULL,
  source_uri            text,                                       -- e.g., kafka://broker/topic
  sink_uri              text,                                       -- e.g., s3://bucket/prefix
  is_default            boolean NOT NULL DEFAULT false,

  labels                jsonb NOT NULL DEFAULT '{}'::jsonb,
  options               jsonb NOT NULL DEFAULT '{}'::jsonb,         -- writer/reader opts

  created_by            text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),

  -- Constraints
  CONSTRAINT uq_versions_dataset_version UNIQUE (dataset_id, version),
  CONSTRAINT ck_v_labels_valid CHECK (catalog.fn_validate_labels(labels)),
  CONSTRAINT ck_v_options_object CHECK (jsonb_typeof(options) = 'object')
);

COMMENT ON TABLE catalog.dataset_versions IS 'Dataset materialized/contract versions.';
COMMENT ON COLUMN catalog.dataset_versions.options IS 'Format/source/sink options (JSON).';

-- Only one default version per dataset
CREATE UNIQUE INDEX IF NOT EXISTS uq_versions_default_one
ON catalog.dataset_versions (dataset_id)
WHERE is_default;

-- Search/indexes
CREATE INDEX IF NOT EXISTS ix_versions_dataset ON catalog.dataset_versions (dataset_id, version DESC);
CREATE INDEX IF NOT EXISTS ix_versions_schema ON catalog.dataset_versions (schema_uri, schema_version);
CREATE INDEX IF NOT EXISTS ix_versions_labels_gin ON catalog.dataset_versions USING gin (labels jsonb_path_ops);

-- ===== TABLE: dataset_acls (optional fine-grained principals) ===============
CREATE TABLE IF NOT EXISTS catalog.dataset_acls (
  acl_id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dataset_id           uuid NOT NULL REFERENCES catalog.datasets(dataset_id) ON DELETE CASCADE,
  principal            text NOT NULL,                  -- user:alice|group:analysts|role:reader
  privileges           text[] NOT NULL,                -- e.g. {'read','write','admin'}
  created_by           text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_acl UNIQUE (dataset_id, principal)
);

CREATE INDEX IF NOT EXISTS ix_acl_dataset_principal ON catalog.dataset_acls (dataset_id, principal);

-- ===== TABLE: dataset_labels (history/override) =============================
CREATE TABLE IF NOT EXISTS catalog.dataset_labels (
  id                   bigserial PRIMARY KEY,
  dataset_id           uuid NOT NULL REFERENCES catalog.datasets(dataset_id) ON DELETE CASCADE,
  labels               jsonb NOT NULL,
  created_by           text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_hist_labels_valid CHECK (catalog.fn_validate_labels(labels))
);

CREATE INDEX IF NOT EXISTS ix_dl_dataset ON catalog.dataset_labels (dataset_id);
CREATE INDEX IF NOT EXISTS ix_dl_labels_gin ON catalog.dataset_labels USING gin (labels jsonb_path_ops);

-- ===== TABLE: dataset_endpoints (discovery) =================================
CREATE TABLE IF NOT EXISTS catalog.dataset_endpoints (
  endpoint_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dataset_id           uuid NOT NULL REFERENCES catalog.datasets(dataset_id) ON DELETE CASCADE,
  kind                 text NOT NULL,                 -- 'read','write','metrics','schema','console'
  url                  text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_endpoint UNIQUE (dataset_id, kind)
);

-- ===== TABLE: dataset_stats (observability) =================================
CREATE TABLE IF NOT EXISTS catalog.dataset_stats (
  dataset_id           uuid NOT NULL REFERENCES catalog.datasets(dataset_id) ON DELETE CASCADE,
  ts                   timestamptz NOT NULL,
  records_total        bigint,
  bytes_total          bigint,
  produce_qps          double precision,
  consume_qps          double precision,
  error_rate           double precision,
  PRIMARY KEY (dataset_id, ts)
);
CREATE INDEX IF NOT EXISTS ix_stats_recent ON catalog.dataset_stats (dataset_id, ts DESC);

-- ===== RLS (Row Level Security) by tenant ===================================
-- Strategy: enforce tenant_id equality with app.current_tenant setting.
-- Deny when current_tenant is NULL (no session tenant).
ALTER TABLE catalog.datasets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_datasets_isolation ON catalog.datasets;
CREATE POLICY p_datasets_isolation ON catalog.datasets
USING (
  current_setting('app.current_tenant', true) IS NOT NULL
  AND tenant_id = current_setting('app.current_tenant', true)
)
WITH CHECK (
  current_setting('app.current_tenant', true) IS NOT NULL
  AND tenant_id = current_setting('app.current_tenant', true)
);

-- Inherit via FK for child tables (Postgres applies RLS only on base table reads;
-- ensure access routes go through parent joins when necessary). Optionally replicate tenant_id.

-- ===== SEARCH VIEW: latest version per dataset ===============================
CREATE OR REPLACE VIEW catalog.v_datasets_latest AS
SELECT
  d.dataset_id,
  d.tenant_id,
  d.name,
  d.slug,
  d.description,
  d.type,
  d.state,
  d.access_level,
  d.storage_policy,
  d.storage_ttl_seconds,
  d.default_format,
  d.labels AS dataset_labels,
  d.annotations,
  v.version AS latest_version,
  v.schema_uri,
  v.schema_version,
  v.format AS latest_format,
  v.source_uri,
  v.sink_uri,
  v.labels AS version_labels,
  d.created_by, d.updated_by, d.created_at, d.updated_at
FROM catalog.datasets d
LEFT JOIN LATERAL (
  SELECT vv.*
  FROM catalog.dataset_versions vv
  WHERE vv.dataset_id = d.dataset_id
  ORDER BY vv.is_default DESC, vv.version DESC
  LIMIT 1
) v ON TRUE;

COMMENT ON VIEW catalog.v_datasets_latest IS 'Latest (or default) version metadata per dataset.';

-- ===== GRANTS (tight defaults; applications use dedicated role) ==============
-- Adjust roles to your deployment model; safe defaults shown.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_data_reader') THEN
    CREATE ROLE app_data_reader NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_data_writer') THEN
    CREATE ROLE app_data_writer NOINHERIT;
  END IF;
END$$;

GRANT USAGE ON SCHEMA catalog TO app_data_reader, app_data_writer;
GRANT SELECT ON catalog.v_datasets_latest TO app_data_reader;

GRANT SELECT ON catalog.datasets, catalog.dataset_versions,
             catalog.dataset_acls, catalog.dataset_endpoints
TO app_data_reader;

GRANT INSERT, UPDATE, DELETE ON catalog.datasets, catalog.dataset_versions,
                             catalog.dataset_acls, catalog.dataset_labels,
                             catalog.dataset_endpoints
TO app_data_writer;

-- Functions execute with invoker rights by default; grant EXECUTE selectively
GRANT EXECUTE ON FUNCTION catalog.tg_set_updated_at() TO app_data_writer, app_data_reader;
GRANT EXECUTE ON FUNCTION catalog.fn_validate_labels(jsonb) TO app_data_writer, app_data_reader;

-- ===== CHECKS & HOUSEKEEPING =================================================
-- Ensure only one default per dataset (already via partial unique index).
-- Optional: enforce version monotonicity via trigger.

CREATE OR REPLACE FUNCTION catalog.tg_versions_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  max_v integer;
BEGIN
  SELECT COALESCE(MAX(version), 0) INTO max_v FROM catalog.dataset_versions WHERE dataset_id = NEW.dataset_id;
  IF TG_OP = 'INSERT' AND NEW.version <= max_v THEN
    RAISE EXCEPTION 'version must be strictly increasing (new %, current max %)', NEW.version, max_v;
  END IF;
  IF NEW.is_default THEN
    UPDATE catalog.dataset_versions
      SET is_default = FALSE
    WHERE dataset_id = NEW.dataset_id AND version_id <> NEW.version_id AND is_default = TRUE;
  END IF;
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS set_versions_monotonic ON catalog.dataset_versions;
CREATE TRIGGER set_versions_monotonic
BEFORE INSERT OR UPDATE ON catalog.dataset_versions
FOR EACH ROW EXECUTE FUNCTION catalog.tg_versions_monotonic();

-- ===== SEARCH SUPPORT: FTS over name/description =============================
-- English/simple tokenizer as baseline; adjust dictionary per locale if needed.
ALTER TABLE catalog.datasets
  ADD COLUMN IF NOT EXISTS ts tsvector;

CREATE OR REPLACE FUNCTION catalog.tg_datasets_fts()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.ts :=
    setweight(to_tsvector('simple', coalesce(NEW.name,'')), 'A') ||
    setweight(to_tsvector('simple', coalesce(NEW.description,'')), 'B');
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS tsv_datasets ON catalog.datasets;
CREATE TRIGGER tsv_datasets
BEFORE INSERT OR UPDATE ON catalog.datasets
FOR EACH ROW EXECUTE FUNCTION catalog.tg_datasets_fts();

CREATE INDEX IF NOT EXISTS ix_datasets_fts ON catalog.datasets USING gin (ts);

-- ===== FINALIZE ==============================================================
COMMIT;
\echo 'Migration 0002_catalog.sql applied.'
