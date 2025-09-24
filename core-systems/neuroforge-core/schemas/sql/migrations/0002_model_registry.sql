-- =====================================================================
-- neuroforge-core : 0002_model_registry.sql
-- Production-grade model registry for PostgreSQL (>= 13)
-- Unverified: адаптируйте при необходимости. I cannot verify this.
-- =====================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- Safety & extensions
-- -----------------------------------------------------------------------------
SET statement_timeout = '5min';
SET lock_timeout = '1min';

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;    -- case-insensitive names

-- -----------------------------------------------------------------------------
-- Schema
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS model_registry AUTHORIZATION CURRENT_USER;

-- -----------------------------------------------------------------------------
-- Enumerations
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'model_stage') THEN
    CREATE TYPE model_registry.model_stage AS ENUM ('develop','staging','production','archived');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'artifact_kind') THEN
    CREATE TYPE model_registry.artifact_kind AS ENUM (
      'weights','onnx','code','docker_image','dataset','report','signature','other'
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'framework') THEN
    CREATE TYPE model_registry.framework AS ENUM (
      'pytorch','tensorflow','sklearn','xgboost','lightgbm','catboost','onnx','custom'
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'approval_status') THEN
    CREATE TYPE model_registry.approval_status AS ENUM ('pending','approved','rejected');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'resource_type') THEN
    CREATE TYPE model_registry.resource_type AS ENUM (
      'model','model_version','artifact','deployment'
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'lineage_node_type') THEN
    CREATE TYPE model_registry.lineage_node_type AS ENUM (
      'dataset','model','feature_set','pipeline','service'
    );
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Helpers (updated_at, guards, scope utilities)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION model_registry.utx_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END$$;

-- Active legal hold guard (raise on delete/soft-delete)
CREATE OR REPLACE FUNCTION model_registry.guard_legal_hold(p_type model_registry.resource_type, p_id uuid)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM model_registry.legal_holds lh
    WHERE lh.resource_type = p_type AND lh.resource_id = p_id AND lh.active = TRUE
  ) THEN
    RAISE EXCEPTION 'Operation blocked: active legal hold on %/%', p_type, p_id
      USING ERRCODE = '38000';
  END IF;
END$$;

-- WORM guard (raise if lock_until > now)
CREATE OR REPLACE FUNCTION model_registry.guard_worm_lock(p_type model_registry.resource_type, p_id uuid)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v_lock_until timestamptz;
BEGIN
  SELECT lock_until INTO v_lock_until
  FROM model_registry.worm_locks
  WHERE resource_type = p_type AND resource_id = p_id;
  IF v_lock_until IS NOT NULL AND v_lock_until > NOW() THEN
    RAISE EXCEPTION 'Operation blocked: WORM lock active until % on %/%', v_lock_until, p_type, p_id
      USING ERRCODE = '38000';
  END IF;
END$$;

-- Combined guard
CREATE OR REPLACE FUNCTION model_registry.guard_no_delete(p_type model_registry.resource_type, p_id uuid)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  PERFORM model_registry.guard_legal_hold(p_type, p_id);
  PERFORM model_registry.guard_worm_lock(p_type, p_id);
END$$;

-- Optional: scope utilities for RLS (read from GUC 'app.scopes' and 'app.user')
CREATE OR REPLACE FUNCTION model_registry.has_scope(p_scope text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT COALESCE( position(p_scope in COALESCE(current_setting('app.scopes', true), '')) > 0, false );
$$;

CREATE OR REPLACE FUNCTION model_registry.current_user_id()
RETURNS text LANGUAGE sql STABLE AS $$
  SELECT COALESCE(current_setting('app.user', true), current_user::text);
$$;

-- -----------------------------------------------------------------------------
-- Core tables
-- -----------------------------------------------------------------------------

-- Models
CREATE TABLE IF NOT EXISTS model_registry.models (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         citext NOT NULL,
  description  text,
  owner        text NOT NULL, -- email or group
  labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  deleted_at   timestamptz,

  CONSTRAINT models_owner_nonempty CHECK (length(trim(owner)) > 0)
);

-- Unique alive model names (ignore soft-deleted)
CREATE UNIQUE INDEX IF NOT EXISTS uq_models_name_alive
  ON model_registry.models (name)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_models_created_at ON model_registry.models (created_at);
CREATE INDEX IF NOT EXISTS ix_models_labels_gin ON model_registry.models USING GIN (labels);
CREATE INDEX IF NOT EXISTS ix_models_metadata_gin ON model_registry.models USING GIN (metadata);

CREATE TRIGGER trg_models_updated_at
  BEFORE UPDATE ON model_registry.models
  FOR EACH ROW EXECUTE FUNCTION model_registry.utx_updated_at();

-- Guard soft-delete
CREATE OR REPLACE FUNCTION model_registry.models_soft_delete_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF (TG_OP = 'UPDATE' AND NEW.deleted_at IS NOT NULL AND COALESCE(OLD.deleted_at, 'epoch'::timestamptz) IS DISTINCT FROM NEW.deleted_at)
     OR TG_OP = 'DELETE' THEN
    PERFORM model_registry.guard_no_delete('model'::model_registry.resource_type, OLD.id);
  END IF;
  RETURN NEW;
END$$;

CREATE TRIGGER trg_models_soft_delete_guard
  BEFORE UPDATE OR DELETE ON model_registry.models
  FOR EACH ROW EXECUTE FUNCTION model_registry.models_soft_delete_guard();

-- Model versions
CREATE TABLE IF NOT EXISTS model_registry.model_versions (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id          uuid NOT NULL REFERENCES model_registry.models(id) ON DELETE RESTRICT,
  version           integer NOT NULL,
  stage             model_registry.model_stage NOT NULL DEFAULT 'develop',
  framework         model_registry.framework NOT NULL DEFAULT 'custom',
  framework_version text,
  source_commit     text,
  run_id            text,
  artifact_uri      text,                 -- primary artifact / pointer
  content_hash      text,                 -- sha256 hex (64)
  size_bytes        bigint,
  metrics           jsonb NOT NULL DEFAULT '{}'::jsonb,
  params            jsonb NOT NULL DEFAULT '{}'::jsonb,
  tags              jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by        text NOT NULL DEFAULT model_registry.current_user_id(),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz,

  CONSTRAINT mv_version_positive CHECK (version > 0),
  CONSTRAINT mv_hash_format CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT mv_size_nonneg CHECK (size_bytes IS NULL OR size_bytes >= 0)
);

-- Unique alive (model, version)
CREATE UNIQUE INDEX IF NOT EXISTS uq_model_versions_model_version_alive
  ON model_registry.model_versions (model_id, version)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_model_versions_model_stage ON model_registry.model_versions (model_id, stage);
CREATE INDEX IF NOT EXISTS ix_model_versions_created_at ON model_registry.model_versions (created_at);
CREATE INDEX IF NOT EXISTS ix_model_versions_metrics_gin ON model_registry.model_versions USING GIN (metrics);
CREATE INDEX IF NOT EXISTS ix_model_versions_tags_gin ON model_registry.model_versions USING GIN (tags);

CREATE TRIGGER trg_model_versions_updated_at
  BEFORE UPDATE ON model_registry.model_versions
  FOR EACH ROW EXECUTE FUNCTION model_registry.utx_updated_at();

-- Guard soft-delete for versions
CREATE OR REPLACE FUNCTION model_registry.model_versions_soft_delete_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF (TG_OP = 'UPDATE' AND NEW.deleted_at IS NOT NULL AND COALESCE(OLD.deleted_at, 'epoch'::timestamptz) IS DISTINCT FROM NEW.deleted_at)
     OR TG_OP = 'DELETE' THEN
    PERFORM model_registry.guard_no_delete('model_version'::model_registry.resource_type, OLD.id);
  END IF;
  RETURN NEW;
END$$;

CREATE TRIGGER trg_model_versions_soft_delete_guard
  BEFORE UPDATE OR DELETE ON model_registry.model_versions
  FOR EACH ROW EXECUTE FUNCTION model_registry.model_versions_soft_delete_guard();

-- Artifacts
CREATE TABLE IF NOT EXISTS model_registry.artifacts (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_version_id  uuid NOT NULL REFERENCES model_registry.model_versions(id) ON DELETE CASCADE,
  kind              model_registry.artifact_kind NOT NULL,
  uri               text NOT NULL,
  content_hash      text,        -- sha256
  size_bytes        bigint,
  storage_class     text,        -- e.g., "s3_standard_ia"
  extra             jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz,

  CONSTRAINT art_hash_format CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT art_size_nonneg CHECK (size_bytes IS NULL OR size_bytes >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_artifacts_ver_kind_uri_alive
  ON model_registry.artifacts (model_version_id, kind, uri)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_artifacts_kind ON model_registry.artifacts (kind);
CREATE INDEX IF NOT EXISTS ix_artifacts_uri ON model_registry.artifacts (uri);
CREATE INDEX IF NOT EXISTS ix_artifacts_extra_gin ON model_registry.artifacts USING GIN (extra);

CREATE TRIGGER trg_artifacts_updated_at
  BEFORE UPDATE ON model_registry.artifacts
  FOR EACH ROW EXECUTE FUNCTION model_registry.utx_updated_at();

CREATE OR REPLACE FUNCTION model_registry.artifacts_soft_delete_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF (TG_OP = 'UPDATE' AND NEW.deleted_at IS NOT NULL AND COALESCE(OLD.deleted_at, 'epoch'::timestamptz) IS DISTINCT FROM NEW.deleted_at)
     OR TG_OP = 'DELETE' THEN
    PERFORM model_registry.guard_no_delete('artifact'::model_registry.resource_type, OLD.id);
  END IF;
  RETURN NEW;
END$$;

CREATE TRIGGER trg_artifacts_soft_delete_guard
  BEFORE UPDATE OR DELETE ON model_registry.artifacts
  FOR EACH ROW EXECUTE FUNCTION model_registry.artifacts_soft_delete_guard();

-- Deployments
CREATE TABLE IF NOT EXISTS model_registry.deployments (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_version_id  uuid NOT NULL REFERENCES model_registry.model_versions(id) ON DELETE RESTRICT,
  endpoint_name     citext NOT NULL,
  endpoint_url      text,
  environment       text NOT NULL DEFAULT 'staging',  -- e.g., "staging","prod"
  region            text,
  config            jsonb NOT NULL DEFAULT '{}'::jsonb,  -- autoscaling, resources, etc.
  traffic_percent   numeric(5,2) NOT NULL DEFAULT 100.00 CHECK (traffic_percent >= 0 AND traffic_percent <= 100),
  is_active         boolean NOT NULL DEFAULT true,
  created_by        text NOT NULL DEFAULT model_registry.current_user_id(),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz
);

-- One active deployment per (environment, endpoint_name)
CREATE UNIQUE INDEX IF NOT EXISTS uq_deployments_active_env_endpoint
  ON model_registry.deployments (environment, endpoint_name)
  WHERE is_active = TRUE AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_deployments_env_active ON model_registry.deployments (environment, is_active);
CREATE INDEX IF NOT EXISTS ix_deployments_config_gin ON model_registry.deployments USING GIN (config);

CREATE TRIGGER trg_deployments_updated_at
  BEFORE UPDATE ON model_registry.deployments
  FOR EACH ROW EXECUTE FUNCTION model_registry.utx_updated_at();

CREATE OR REPLACE FUNCTION model_registry.deployments_soft_delete_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF (TG_OP = 'UPDATE' AND NEW.deleted_at IS NOT NULL AND COALESCE(OLD.deleted_at, 'epoch'::timestamptz) IS DISTINCT FROM NEW.deleted_at)
     OR TG_OP = 'DELETE' THEN
    PERFORM model_registry.guard_no_delete('deployment'::model_registry.resource_type, OLD.id);
  END IF;
  RETURN NEW;
END$$;

CREATE TRIGGER trg_deployments_soft_delete_guard
  BEFORE UPDATE OR DELETE ON model_registry.deployments
  FOR EACH ROW EXECUTE FUNCTION model_registry.deployments_soft_delete_guard();

-- Approvals (governance)
CREATE TABLE IF NOT EXISTS model_registry.approvals (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_version_id  uuid NOT NULL REFERENCES model_registry.model_versions(id) ON DELETE CASCADE,
  status            model_registry.approval_status NOT NULL DEFAULT 'pending',
  approver          text,               -- assigned approver (email/login)
  comment           text,
  created_by        text NOT NULL DEFAULT model_registry.current_user_id(),
  created_at        timestamptz NOT NULL DEFAULT now(),
  decided_at        timestamptz
);

CREATE INDEX IF NOT EXISTS ix_approvals_mv_status ON model_registry.approvals (model_version_id, status);

-- Stage transitions (audit)
CREATE TABLE IF NOT EXISTS model_registry.transitions (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id          uuid NOT NULL REFERENCES model_registry.models(id) ON DELETE CASCADE,
  from_version_id   uuid REFERENCES model_registry.model_versions(id) ON DELETE SET NULL,
  to_version_id     uuid REFERENCES model_registry.model_versions(id) ON DELETE SET NULL,
  from_stage        model_registry.model_stage,
  to_stage          model_registry.model_stage NOT NULL,
  reason            text,
  created_by        text NOT NULL DEFAULT model_registry.current_user_id(),
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_transitions_model_time ON model_registry.transitions (model_id, created_at DESC);

-- Metrics/Params/Tags (KV stores)
CREATE TABLE IF NOT EXISTS model_registry.metrics (
  model_version_id  uuid NOT NULL REFERENCES model_registry.model_versions(id) ON DELETE CASCADE,
  key               text NOT NULL,
  value             double precision NOT NULL,
  recorded_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (model_version_id, key)
);

CREATE TABLE IF NOT EXISTS model_registry.params (
  model_version_id  uuid NOT NULL REFERENCES model_registry.model_versions(id) ON DELETE CASCADE,
  key               text NOT NULL,
  value             text NOT NULL,
  PRIMARY KEY (model_version_id, key)
);

CREATE TABLE IF NOT EXISTS model_registry.tags (
  model_version_id  uuid NOT NULL REFERENCES model_registry.model_versions(id) ON DELETE CASCADE,
  key               text NOT NULL,
  value             text,
  PRIMARY KEY (model_version_id, key)
);

-- Lineage (edges)
CREATE TABLE IF NOT EXISTS model_registry.lineage_edges (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  src_type          model_registry.lineage_node_type NOT NULL,
  src_id            text NOT NULL,
  dst_type          model_registry.lineage_node_type NOT NULL,
  dst_id            text NOT NULL,
  model_version_id  uuid REFERENCES model_registry.model_versions(id) ON DELETE CASCADE,
  attributes        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT lineage_no_self_edge CHECK (NOT (src_type = dst_type AND src_id = dst_id))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_lineage_edge_unique
  ON model_registry.lineage_edges (src_type, src_id, dst_type, dst_id, model_version_id);

CREATE INDEX IF NOT EXISTS ix_lineage_attr_gin ON model_registry.lineage_edges USING GIN (attributes);

-- ACL (coarse-grained; RLS может дополнять)
CREATE TABLE IF NOT EXISTS model_registry.acl (
  resource_type   model_registry.resource_type NOT NULL,
  resource_id     uuid NOT NULL,
  principal       text NOT NULL,    -- user/group/svc
  scope           text NOT NULL,    -- e.g., "ml:read","ml:write","ml:admin"
  allow           boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (resource_type, resource_id, principal, scope)
);

CREATE INDEX IF NOT EXISTS ix_acl_principal ON model_registry.acl (principal);

-- Legal Holds
CREATE TABLE IF NOT EXISTS model_registry.legal_holds (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_type  model_registry.resource_type NOT NULL,
  resource_id    uuid NOT NULL,
  label          text NOT NULL DEFAULT 'legal_hold',
  reason         text,
  created_by     text NOT NULL DEFAULT model_registry.current_user_id(),
  created_at     timestamptz NOT NULL DEFAULT now(),
  active         boolean NOT NULL DEFAULT true,
  released_at    timestamptz
);

CREATE INDEX IF NOT EXISTS ix_legal_holds_active ON model_registry.legal_holds (resource_type, resource_id) WHERE active = TRUE;

-- WORM locks
CREATE TABLE IF NOT EXISTS model_registry.worm_locks (
  resource_type  model_registry.resource_type PRIMARY KEY,
  resource_id    uuid NOT NULL,
  lock_until     timestamptz NOT NULL
);

-- Event log (generic audit)
CREATE TABLE IF NOT EXISTS model_registry.event_log (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  actor         text NOT NULL DEFAULT model_registry.current_user_id(),
  action        text NOT NULL,  -- e.g., "MODEL.CREATED"
  resource_type model_registry.resource_type,
  resource_id   uuid,
  details       jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_event_log_time ON model_registry.event_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_event_log_details_gin ON model_registry.event_log USING GIN (details);

-- -----------------------------------------------------------------------------
-- Convenience triggers to log key actions
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION model_registry.log_model_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO model_registry.event_log (action, resource_type, resource_id, details)
  VALUES ('MODEL.CREATED','model', NEW.id, jsonb_build_object('name', NEW.name, 'owner', NEW.owner));
  RETURN NEW;
END$$;

CREATE TRIGGER trg_models_log_insert
  AFTER INSERT ON model_registry.models
  FOR EACH ROW EXECUTE FUNCTION model_registry.log_model_insert();

CREATE OR REPLACE FUNCTION model_registry.log_stage_transition()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO model_registry.event_log (action, resource_type, resource_id, details)
  VALUES ('MODEL.STAGE_TRANSITION','model', NEW.model_id,
          jsonb_build_object('from_stage', NEW.from_stage, 'to_stage', NEW.to_stage,
                             'from_version_id', NEW.from_version_id, 'to_version_id', NEW.to_version_id));
  RETURN NEW;
END$$;

CREATE TRIGGER trg_transitions_log
  AFTER INSERT ON model_registry.transitions
  FOR EACH ROW EXECUTE FUNCTION model_registry.log_stage_transition();

-- -----------------------------------------------------------------------------
-- OPTIONAL: Row-Level Security (RLS) scaffolding (disabled by default)
-- To enable, uncomment ALTER TABLE ... ENABLE ROW LEVEL SECURITY;
-- And adjust policies to your needs (scopes: "ml:read","ml:write","ml:admin").
-- -----------------------------------------------------------------------------
-- ALTER TABLE model_registry.models ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY p_models_read ON model_registry.models
--   FOR SELECT USING (model_registry.has_scope('ml:read') OR model_registry.has_scope('ml:admin'));
-- CREATE POLICY p_models_write ON model_registry.models
--   FOR INSERT WITH CHECK (model_registry.has_scope('ml:write') OR model_registry.has_scope('ml:admin'));
-- CREATE POLICY p_models_upd ON model_registry.models
--   FOR UPDATE USING (model_registry.has_scope('ml:write') OR model_registry.has_scope('ml:admin'))
--             WITH CHECK (model_registry.has_scope('ml:write') OR model_registry.has_scope('ml:admin'));

-- -----------------------------------------------------------------------------
-- Useful views
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW model_registry.v_latest_versions AS
SELECT mv.*
FROM model_registry.model_versions mv
JOIN (
  SELECT model_id, MAX(version) AS max_version
  FROM model_registry.model_versions
  WHERE deleted_at IS NULL
  GROUP BY model_id
) q ON q.model_id = mv.model_id AND q.max_version = mv.version
WHERE mv.deleted_at IS NULL;

CREATE OR REPLACE VIEW model_registry.v_active_deployments AS
SELECT d.*, m.name AS model_name, mv.version AS model_version
FROM model_registry.deployments d
JOIN model_registry.model_versions mv ON mv.id = d.model_version_id
JOIN model_registry.models m ON m.id = mv.model_id
WHERE d.is_active = TRUE AND d.deleted_at IS NULL AND mv.deleted_at IS NULL AND m.deleted_at IS NULL;

-- -----------------------------------------------------------------------------
-- Grants (adjust role names as needed)
-- -----------------------------------------------------------------------------
-- GRANT USAGE ON SCHEMA model_registry TO readonly, readwrite, admin;
-- GRANT SELECT ON ALL TABLES IN SCHEMA model_registry TO readonly;
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA model_registry TO readwrite;
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA model_registry TO admin;

COMMIT;
