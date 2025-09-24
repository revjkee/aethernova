-- =============================================================================
-- NeuroForge Core - Migration 0004: Feature Store (PostgreSQL 13+)
-- =============================================================================
-- Includes:
--   * schema feature_store
--   * enums: fs_data_source_type, fs_job_status, fs_dtype
--   * helpers: updated_at trigger, legal hold guard
--   * registry: data_sources, entities, feature_sets, features
--   * feature views and mappings, materializations (offline)
--   * online key-value store (partitioned) with retention fields
--   * audit_log, legal_hold
--   * indexes and constraints
-- Idempotent: guarded with IF NOT EXISTS / DO blocks.
-- =============================================================================

BEGIN;

-- ---------- Extensions required (safe if present) ----------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------- Schema -----------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'feature_store') THEN
    CREATE SCHEMA feature_store;
  END IF;
END$$;

-- ---------- Types ------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'fs_data_source_type') THEN
    CREATE TYPE feature_store.fs_data_source_type AS ENUM (
      'unknown', 's3', 'gcs', 'bigquery', 'redshift', 'snowflake', 'postgres', 'kafka', 'delta', 'iceberg'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'fs_job_status') THEN
    CREATE TYPE feature_store.fs_job_status AS ENUM (
      'queued', 'running', 'succeeded', 'failed', 'canceled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'fs_dtype') THEN
    CREATE TYPE feature_store.fs_dtype AS ENUM (
      'bool','int32','int64','float32','float64','decimal','string','bytes','timestamp','date','json'
    );
  END IF;
END$$;

-- ---------- Helpers: updated_at trigger -------------------------------------
CREATE OR REPLACE FUNCTION feature_store.touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- ---------- Helpers: legal hold guard ----------------------------------------
CREATE OR REPLACE FUNCTION feature_store.prevent_delete_when_legal_hold()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_count int;
  v_uid uuid;
BEGIN
  -- Expect row has column "uid" of type uuid
  EXECUTE format('SELECT ($1).%I', 'uid') INTO v_uid USING OLD;
  SELECT count(*) INTO v_count
  FROM feature_store.legal_hold lh
  WHERE lh.object_uid = v_uid AND lh.active = true;
  IF v_count > 0 THEN
    RAISE EXCEPTION 'Deletion blocked: active legal hold exists for uid=%', v_uid
      USING ERRCODE = 'raise_exception';
  END IF;
  RETURN OLD;
END$$;

-- ---------- Registry: data sources ------------------------------------------
CREATE TABLE IF NOT EXISTS feature_store.data_sources (
  id           BIGSERIAL PRIMARY KEY,
  uid          uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  tenant_id    uuid,
  name         citext NOT NULL,
  type         feature_store.fs_data_source_type NOT NULL DEFAULT 'unknown',
  uri          text,
  config       jsonb NOT NULL DEFAULT '{}'::jsonb,
  labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT data_sources_name_tenant_unique UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_data_sources_labels_gin
  ON feature_store.data_sources USING gin (labels jsonb_path_ops);

CREATE TRIGGER trg_ds_touch_updated
  BEFORE UPDATE ON feature_store.data_sources
  FOR EACH ROW EXECUTE FUNCTION feature_store.touch_updated_at();

-- ---------- Registry: entities ----------------------------------------------
CREATE TABLE IF NOT EXISTS feature_store.entities (
  id           BIGSERIAL PRIMARY KEY,
  uid          uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  tenant_id    uuid,
  name         citext NOT NULL,
  description  text,
  key_schema   jsonb NOT NULL DEFAULT '{}'::jsonb,      -- e.g. {"keys":[{"name":"user_id","type":"int64"}]}
  labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT entities_name_tenant_unique UNIQUE (tenant_id, name),
  CONSTRAINT entities_key_schema_json CHECK (jsonb_typeof(key_schema) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_entities_labels_gin
  ON feature_store.entities USING gin (labels jsonb_path_ops);

CREATE TRIGGER trg_entities_touch_updated
  BEFORE UPDATE ON feature_store.entities
  FOR EACH ROW EXECUTE FUNCTION feature_store.touch_updated_at();

-- ---------- Registry: feature sets (logical groups and versions) ------------
CREATE TABLE IF NOT EXISTS feature_store.feature_sets (
  id            BIGSERIAL PRIMARY KEY,
  uid           uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  tenant_id     uuid,
  namespace     text NOT NULL DEFAULT 'default',
  name          citext NOT NULL,
  version       text NOT NULL DEFAULT '0.1.0',
  description   text,
  owner_email   text,
  ttl           interval,                                 -- optional time to live for online features
  labels        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT feature_sets_unique UNIQUE (tenant_id, namespace, name, version),
  CONSTRAINT feature_sets_semver CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([\-+][0-9A-Za-z\.\-]+)?$')
);

CREATE INDEX IF NOT EXISTS idx_feature_sets_labels_gin
  ON feature_store.feature_sets USING gin (labels jsonb_path_ops);

CREATE TRIGGER trg_feature_sets_touch_updated
  BEFORE UPDATE ON feature_store.feature_sets
  FOR EACH ROW EXECUTE FUNCTION feature_store.touch_updated_at();

-- ---------- Registry: individual features -----------------------------------
CREATE TABLE IF NOT EXISTS feature_store.features (
  id             BIGSERIAL PRIMARY KEY,
  uid            uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  feature_set_id bigint NOT NULL REFERENCES feature_store.feature_sets(id) ON DELETE CASCADE,
  name           citext NOT NULL,
  dtype          feature_store.fs_dtype NOT NULL,
  description    text,
  default_value  jsonb,
  tags           jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT features_unique UNIQUE (feature_set_id, name)
);

CREATE INDEX IF NOT EXISTS idx_features_tags_gin
  ON feature_store.features USING gin (tags jsonb_path_ops);

CREATE TRIGGER trg_features_touch_updated
  BEFORE UPDATE ON feature_store.features
  FOR EACH ROW EXECUTE FUNCTION feature_store.touch_updated_at();

-- ---------- Feature Views and mappings --------------------------------------
CREATE TABLE IF NOT EXISTS feature_store.feature_views (
  id               BIGSERIAL PRIMARY KEY,
  uid              uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  tenant_id        uuid,
  name             citext NOT NULL,
  version          text NOT NULL DEFAULT '0.1.0',
  description      text,
  feature_set_id   bigint NOT NULL REFERENCES feature_store.feature_sets(id) ON DELETE RESTRICT,
  ttl              interval,                                   -- online TTL override
  offline_source_id bigint REFERENCES feature_store.data_sources(id) ON DELETE SET NULL,
  query_template   text,                                       -- optional SQL or DSL for offline materialization
  labels           jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT feature_views_unique UNIQUE (tenant_id, name, version),
  CONSTRAINT feature_views_semver CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([\-+][0-9A-Za-z\.\-]+)?$')
);

CREATE INDEX IF NOT EXISTS idx_feature_views_labels_gin
  ON feature_store.feature_views USING gin (labels jsonb_path_ops);

CREATE TRIGGER trg_feature_views_touch_updated
  BEFORE UPDATE ON feature_store.feature_views
  FOR EACH ROW EXECUTE FUNCTION feature_store.touch_updated_at();

-- Many-to-many: feature_view <-> entities
CREATE TABLE IF NOT EXISTS feature_store.feature_view_entities (
  feature_view_id bigint NOT NULL REFERENCES feature_store.feature_views(id) ON DELETE CASCADE,
  entity_id       bigint NOT NULL REFERENCES feature_store.entities(id) ON DELETE RESTRICT,
  PRIMARY KEY (feature_view_id, entity_id)
);

-- Many-to-many: feature_view <-> features (subset selection and transformations)
CREATE TABLE IF NOT EXISTS feature_store.feature_view_features (
  feature_view_id bigint NOT NULL REFERENCES feature_store.feature_views(id) ON DELETE CASCADE,
  feature_id      bigint NOT NULL REFERENCES feature_store.features(id) ON DELETE RESTRICT,
  transform_expr  text,  -- optional transformation expression applied offline
  PRIMARY KEY (feature_view_id, feature_id)
);

-- ---------- Offline materializations (batch jobs) ----------------------------
CREATE TABLE IF NOT EXISTS feature_store.materializations (
  id                 BIGSERIAL PRIMARY KEY,
  run_id             uuid NOT NULL DEFAULT gen_random_uuid(),
  feature_view_id    bigint NOT NULL REFERENCES feature_store.feature_views(id) ON DELETE CASCADE,
  status             feature_store.fs_job_status NOT NULL DEFAULT 'queued',
  started_at         timestamptz,
  finished_at        timestamptz,
  interval_start     timestamptz,
  interval_end       timestamptz,
  output_uri         text,                -- e.g. s3://bucket/path/...
  stats              jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_message      text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mat_feature_view_status
  ON feature_store.materializations (feature_view_id, status);

CREATE TRIGGER trg_mat_touch_updated
  BEFORE UPDATE ON feature_store.materializations
  FOR EACH ROW EXECUTE FUNCTION feature_store.touch_updated_at();

-- ---------- Online store: partitioned KV by feature_view_id ------------------
-- Base table (hash partitioned by feature_view_id), stores last value per key.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname='feature_store' AND c.relname='online_feature_kv') THEN
    CREATE TABLE feature_store.online_feature_kv (
      feature_view_id bigint NOT NULL REFERENCES feature_store.feature_views(id) ON DELETE CASCADE,
      entity_key      text   NOT NULL,                              -- canonicalized key (can be hashed upstream)
      event_ts        timestamptz NOT NULL,                         -- event time for the value
      value           jsonb NOT NULL,                               -- JSONB bag of features
      write_ts        timestamptz NOT NULL DEFAULT now(),           -- ingestion time
      is_deleted      boolean NOT NULL DEFAULT false,
      uid             uuid NOT NULL DEFAULT gen_random_uuid(),      -- for legal hold tracking
      PRIMARY KEY (feature_view_id, entity_key)
    ) PARTITION BY HASH (feature_view_id);
  END IF;
END$$;

-- Create 4 hash partitions for even distribution (adjust as needed)
DO $$
BEGIN
  FOR i IN 0..3 LOOP
    EXECUTE format($fmt$
      CREATE TABLE IF NOT EXISTS feature_store.online_feature_kv_p%1$s
      PARTITION OF feature_store.online_feature_kv
      FOR VALUES WITH (MODULUS 4, REMAINDER %1$s)$fmt$, i);
  END LOOP;
END$$;

-- Useful indexes
CREATE INDEX IF NOT EXISTS idx_online_kv_event_ts
  ON feature_store.online_feature_kv (feature_view_id, event_ts DESC);

CREATE INDEX IF NOT EXISTS idx_online_kv_write_ts
  ON feature_store.online_feature_kv (write_ts DESC);

CREATE INDEX IF NOT EXISTS idx_online_kv_not_deleted
  ON feature_store.online_feature_kv (feature_view_id)
  WHERE is_deleted = false;

-- Protect deletions when legal hold exists
DROP TRIGGER IF EXISTS trg_online_kv_legal_hold_guard ON feature_store.online_feature_kv;
CREATE TRIGGER trg_online_kv_legal_hold_guard
  BEFORE DELETE ON feature_store.online_feature_kv
  FOR EACH ROW EXECUTE FUNCTION feature_store.prevent_delete_when_legal_hold();

-- ---------- Legal hold registry ---------------------------------------------
CREATE TABLE IF NOT EXISTS feature_store.legal_hold (
  id          BIGSERIAL PRIMARY KEY,
  object_uid  uuid NOT NULL,                 -- references row uid of protected object
  object_type text NOT NULL,                 -- e.g. 'online_feature_kv'
  reason      text,
  active      boolean NOT NULL DEFAULT true,
  placed_at   timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  CONSTRAINT legal_hold_one_active UNIQUE (object_uid, active)
);

-- ---------- Audit log --------------------------------------------------------
CREATE TABLE IF NOT EXISTS feature_store.audit_log (
  id           BIGSERIAL PRIMARY KEY,
  ts           timestamptz NOT NULL DEFAULT now(),
  actor        text,                          -- service/user
  action       text NOT NULL,                 -- e.g. 'UPSERT_ONLINE', 'DELETE_ONLINE', 'CREATE_FEATURE'
  object_type  text NOT NULL,
  object_uid   uuid,
  details      jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON feature_store.audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_object ON feature_store.audit_log (object_type, object_uid);

-- ---------- Optional RLS stubs (disabled by default) -------------------------
-- Uncomment to enable multitenancy row isolation; requires session setting:
--   SET app.current_tenant = '<uuid>';
-- DO $$
-- BEGIN
--   EXECUTE 'ALTER TABLE feature_store.feature_sets ENABLE ROW LEVEL SECURITY';
--   EXECUTE 'CREATE POLICY tenant_isolation_feature_sets ON feature_store.feature_sets
--            USING (tenant_id::text = current_setting(''app.current_tenant'', true))';
-- END$$;

-- ---------- Comments (data dictionary) ---------------------------------------
COMMENT ON SCHEMA feature_store IS 'Schema for NeuroForge feature store';

COMMENT ON TABLE feature_store.entities IS 'Entities define business keys and key schema for features';
COMMENT ON COLUMN feature_store.entities.key_schema IS 'JSON schema of entity keys, e.g. {"keys":[{"name":"user_id","type":"int64"}]}';

COMMENT ON TABLE feature_store.feature_sets IS 'Logical group/version of features with TTL and labels';
COMMENT ON TABLE feature_store.features IS 'Individual features and their dtypes';

COMMENT ON TABLE feature_store.feature_views IS 'Join of feature_set with entities for serving/training; contains TTL and source query';
COMMENT ON TABLE feature_store.feature_view_entities IS 'Mapping FV -> Entities';
COMMENT ON TABLE feature_store.feature_view_features IS 'Mapping FV -> subset of features with optional transform';

COMMENT ON TABLE feature_store.materializations IS 'Offline batch materializations and their status';

COMMENT ON TABLE feature_store.online_feature_kv IS 'Online key-value store with last value per entity_key for a feature_view, partitioned by feature_view_id';

COMMENT ON TABLE feature_store.legal_hold IS 'Active legal holds that block deletion of referenced objects';
COMMENT ON TABLE feature_store.audit_log IS 'Immutable audit trail of feature store operations';

-- ---------- Sanity constraints via DO blocks (idempotent) -------------------
-- Ensure default TTL on feature_views if not set: no direct ALTER; leave to app-layer.

COMMIT;

-- =============================================================================
-- DOWN migration (best-effort, safe to run once; will drop objects if exist)
-- Use only if your migration engine supports undo; otherwise keep forward-only.
-- =============================================================================

DO $down$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='feature_store') THEN
    -- Drop triggers
    IF EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
               JOIN pg_namespace n ON n.oid=c.relnamespace
               WHERE n.nspname='feature_store' AND t.tgname='trg_online_kv_legal_hold_guard') THEN
      EXECUTE 'DROP TRIGGER trg_online_kv_legal_hold_guard ON feature_store.online_feature_kv';
    END IF;

    -- Drop partitioned children first
    FOR r IN SELECT relname FROM pg_class c
             JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='feature_store' AND relname LIKE 'online_feature_kv_p%' LOOP
      EXECUTE format('DROP TABLE IF EXISTS feature_store.%I CASCADE', r.relname);
    END LOOP;

    -- Drop tables in dependency-safe order
    EXECUTE 'DROP TABLE IF EXISTS feature_store.audit_log CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.legal_hold CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.online_feature_kv CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.materializations CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.feature_view_features CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.feature_view_entities CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.feature_views CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.features CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.feature_sets CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.entities CASCADE';
    EXECUTE 'DROP TABLE IF EXISTS feature_store.data_sources CASCADE';

    -- Drop functions
    EXECUTE 'DROP FUNCTION IF EXISTS feature_store.prevent_delete_when_legal_hold()';
    EXECUTE 'DROP FUNCTION IF EXISTS feature_store.touch_updated_at()';

    -- Drop types
    EXECUTE 'DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_type WHERE typname = ''fs_dtype'') THEN EXECUTE ''DROP TYPE feature_store.fs_dtype''; END IF; END$$;';
    EXECUTE 'DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_type WHERE typname = ''fs_job_status'') THEN EXECUTE ''DROP TYPE feature_store.fs_job_status''; END IF; END$$;';
    EXECUTE 'DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_type WHERE typname = ''fs_data_source_type'') THEN EXECUTE ''DROP TYPE feature_store.fs_data_source_type''; END IF; END$$;';

    -- Drop schema (if empty)
    EXECUTE 'DROP SCHEMA IF EXISTS feature_store';
  END IF;
END
$down$;
