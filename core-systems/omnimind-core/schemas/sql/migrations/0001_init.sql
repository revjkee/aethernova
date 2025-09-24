/* ========================================================================== */
/* Omnimind Core — Initial DB Migration (PostgreSQL)                          */
/* Version: 0001                                                               */
/* Safe to run multiple times (idempotent where possible).                     */
/* ========================================================================== */

BEGIN;

-- ---------------------------------------------------------------------------
-- Extensions (idempotent)
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS btree_gin;     -- mixed GIN usage
CREATE EXTENSION IF NOT EXISTS btree_gist;    -- exclusion constraints (future)

-- ---------------------------------------------------------------------------
-- Schemas
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS app_meta;
CREATE SCHEMA IF NOT EXISTS app_audit;

-- ---------------------------------------------------------------------------
-- Roles and privileges (minimal, adjust to your org policy)
--   - app_owner: DDL owner
--   - app_rw: DML (read/write)
--   - app_ro: read-only
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_owner') THEN
    CREATE ROLE app_owner NOINHERIT LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
    CREATE ROLE app_rw NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_ro') THEN
    CREATE ROLE app_ro NOINHERIT;
  END IF;
END$$;

-- ownership
ALTER SCHEMA app       OWNER TO app_owner;
ALTER SCHEMA app_meta  OWNER TO app_owner;
ALTER SCHEMA app_audit OWNER TO app_owner;

-- revoke public
REVOKE ALL ON SCHEMA app, app_meta, app_audit FROM PUBLIC;

-- grants
GRANT USAGE ON SCHEMA app, app_meta, app_audit TO app_ro, app_rw;
GRANT SELECT ON ALL TABLES IN SCHEMA app, app_meta TO app_ro, app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO app_ro, app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT INSERT, UPDATE, DELETE ON TABLES TO app_rw;

-- ---------------------------------------------------------------------------
-- Migration registry
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_meta.migrations (
  version        text        PRIMARY KEY,
  checksum_sha256 bytea      NOT NULL,
  applied_at     timestamptz NOT NULL DEFAULT now(),
  applied_by     text        NOT NULL DEFAULT current_user
);

ALTER TABLE app_meta.migrations OWNER TO app_owner;
GRANT SELECT ON app_meta.migrations TO app_ro, app_rw;
GRANT INSERT ON app_meta.migrations TO app_rw;

-- ---------------------------------------------------------------------------
-- Domains & Types
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'email') THEN
    CREATE DOMAIN app.email AS text
      CHECK (VALUE ~* '^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$');
  END IF;
END$$;

CREATE TYPE app.tool_type AS ENUM (
  'MODEL',
  'CONNECTOR',
  'WORKFLOW',
  'JOB'
);
-- idempotent create enum:
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tool_type') THEN
    -- already created above; block left intentionally for clarity
    PERFORM 1;
  END IF;
END$$;

CREATE TYPE app.tool_state AS ENUM (
  'INACTIVE',
  'ACTIVE',
  'DEPRECATED',
  'DISABLED'
);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tool_state') THEN
    PERFORM 1;
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Utility functions: timestamps & etag, audit
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.fn_set_timestamps()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.id IS NULL THEN
      NEW.id := gen_random_uuid();
    END IF;
    NEW.created_at := COALESCE(NEW.created_at, now());
    NEW.updated_at := COALESCE(NEW.updated_at, NEW.created_at);
  ELSIF TG_OP = 'UPDATE' THEN
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END$$;

-- ETag: SHA256 over a canonical JSON of significant columns
CREATE OR REPLACE FUNCTION app.fn_compute_etag(_payload jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT encode(digest(_payload::text, 'sha256'), 'hex')
$$;

CREATE OR REPLACE FUNCTION app.fn_set_etag_tool()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  payload jsonb;
BEGIN
  payload := jsonb_build_object(
      'name_key', NEW.name_key,
      'display_name', NEW.display_name,
      'description', COALESCE(NEW.description, ''),
      'type', NEW.type,
      'config', COALESCE(NEW.config, '{}'::jsonb),
      'labels', COALESCE(NEW.labels, '{}'::jsonb),
      'annotations', COALESCE(NEW.annotations, '{}'::jsonb),
      'state', NEW.state,
      'owner', COALESCE(NEW.owner, '')
  );
  NEW.etag := app.fn_compute_etag(payload);
  RETURN NEW;
END$$;

-- Generic audit table and trigger
CREATE TABLE IF NOT EXISTS app_audit.audit_log (
  audit_id     bigserial      PRIMARY KEY,
  schema_name  text           NOT NULL,
  table_name   text           NOT NULL,
  op           text           NOT NULL CHECK (op IN ('I','U','D')),
  row_id       uuid           NULL,           -- if table has uuid id
  pk           jsonb          NULL,           -- fallback for composite keys
  old_data     jsonb,
  new_data     jsonb,
  actor        text           NOT NULL DEFAULT current_user,
  at           timestamptz    NOT NULL DEFAULT now(),
  txid         bigint         NOT NULL DEFAULT txid_current()
);
ALTER TABLE app_audit.audit_log OWNER TO app_owner;
GRANT SELECT ON app_audit.audit_log TO app_ro, app_rw;
GRANT INSERT ON app_audit.audit_log TO app_rw;

CREATE OR REPLACE FUNCTION app_audit.fn_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  _pk jsonb := NULL;
  _row_id uuid := NULL;
BEGIN
  IF TG_ARGV[0] IS DISTINCT FROM NULL AND TG_ARGV[0] <> '' THEN
    -- try to read NEW.id/OLD.id if exists
    IF TG_OP IN ('INSERT','UPDATE') AND NEW ? 'id' THEN _row_id := NEW.id; END IF;
    IF TG_OP = 'DELETE' AND OLD ? 'id' THEN _row_id := OLD.id; END IF;
  END IF;

  IF TG_OP = 'INSERT' THEN
    INSERT INTO app_audit.audit_log(schema_name, table_name, op, row_id, pk, old_data, new_data)
    VALUES (TG_TABLE_SCHEMA, TG_TABLE_NAME, 'I', _row_id, _pk, NULL, to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO app_audit.audit_log(schema_name, table_name, op, row_id, pk, old_data, new_data)
    VALUES (TG_TABLE_SCHEMA, TG_TABLE_NAME, 'U', _row_id, _pk, to_jsonb(OLD), to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO app_audit.audit_log(schema_name, table_name, op, row_id, pk, old_data, new_data)
    VALUES (TG_TABLE_SCHEMA, TG_TABLE_NAME, 'D', _row_id, _pk, to_jsonb(OLD), NULL);
    RETURN OLD;
  END IF;
  RETURN NULL;
END$$;

-- ---------------------------------------------------------------------------
-- Core entities
-- ---------------------------------------------------------------------------

-- Projects
CREATE TABLE IF NOT EXISTS app.project (
  id           uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  key          text          NOT NULL,                 -- human-friendly stable key, e.g. "alpha"
  display_name text          NOT NULL,
  description  text          NULL,
  owner_email  app.email     NULL,
  labels       jsonb         NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz   NOT NULL DEFAULT now(),
  updated_at   timestamptz   NOT NULL DEFAULT now(),
  UNIQUE (key)
);
ALTER TABLE app.project OWNER TO app_owner;
GRANT SELECT ON app.project TO app_ro, app_rw;
GRANT INSERT, UPDATE, DELETE ON app.project TO app_rw;

CREATE INDEX IF NOT EXISTS idx_project_labels_gin ON app.project USING gin (labels jsonb_path_ops);

CREATE TRIGGER trg_project_timestamps
BEFORE INSERT OR UPDATE ON app.project
FOR EACH ROW EXECUTE FUNCTION app.fn_set_timestamps();

CREATE TRIGGER trg_project_audit
AFTER INSERT OR UPDATE OR DELETE ON app.project
FOR EACH ROW EXECUTE FUNCTION app_audit.fn_audit();

-- Locations (scoped to project)
CREATE TABLE IF NOT EXISTS app.location (
  id           uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id   uuid          NOT NULL REFERENCES app.project(id) ON DELETE CASCADE,
  key          text          NOT NULL,               -- e.g. "eu-west1"
  display_name text          NOT NULL,
  labels       jsonb         NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz   NOT NULL DEFAULT now(),
  updated_at   timestamptz   NOT NULL DEFAULT now(),
  UNIQUE (project_id, key)
);
ALTER TABLE app.location OWNER TO app_owner;
GRANT SELECT ON app.location TO app_ro, app_rw;
GRANT INSERT, UPDATE, DELETE ON app.location TO app_rw;

CREATE INDEX IF NOT EXISTS idx_location_labels_gin ON app.location USING gin (labels jsonb_path_ops);

CREATE TRIGGER trg_location_timestamps
BEFORE INSERT OR UPDATE ON app.location
FOR EACH ROW EXECUTE FUNCTION app.fn_set_timestamps();

CREATE TRIGGER trg_location_audit
AFTER INSERT OR UPDATE OR DELETE ON app.location
FOR EACH ROW EXECUTE FUNCTION app_audit.fn_audit();

-- Tools (core resource)
CREATE TABLE IF NOT EXISTS app.tool (
  id            uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    uuid            NOT NULL REFERENCES app.project(id)  ON DELETE RESTRICT,
  location_id   uuid            NOT NULL REFERENCES app.location(id) ON DELETE RESTRICT,
  name_key      text            NOT NULL,    -- stable key in parent scope
  display_name  text            NOT NULL,
  description   text,
  type          app.tool_type   NOT NULL,
  state         app.tool_state  NOT NULL DEFAULT 'ACTIVE',
  config        jsonb           NOT NULL DEFAULT '{}'::jsonb,
  labels        jsonb           NOT NULL DEFAULT '{}'::jsonb,
  annotations   jsonb           NOT NULL DEFAULT '{}'::jsonb,
  owner         text            NULL,
  etag          text            NOT NULL,    -- maintained by trigger
  created_at    timestamptz     NOT NULL DEFAULT now(),
  updated_at    timestamptz     NOT NULL DEFAULT now(),
  deleted_at    timestamptz     NULL,        -- soft-delete tombstone
  CONSTRAINT tool_parent_fk CHECK (project_id IS NOT NULL AND location_id IS NOT NULL),
  CONSTRAINT tool_name_key_chk CHECK (name_key ~ '^[a-z0-9][a-z0-9\-_.]{1,254}$')
);
ALTER TABLE app.tool OWNER TO app_owner;
GRANT SELECT ON app.tool TO app_ro, app_rw;
GRANT INSERT, UPDATE, DELETE ON app.tool TO app_rw;

-- Uniqueness within live set (no soft-deleted duplicates)
CREATE UNIQUE INDEX IF NOT EXISTS uq_tool_parent_name_live
  ON app.tool(project_id, location_id, name_key)
  WHERE deleted_at IS NULL;

-- Search/filters
CREATE INDEX IF NOT EXISTS idx_tool_labels_gin
  ON app.tool USING gin (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_tool_annotations_gin
  ON app.tool USING gin (annotations jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_tool_config_gin
  ON app.tool USING gin (config jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_tool_state ON app.tool(state);
CREATE INDEX IF NOT EXISTS idx_tool_type  ON app.tool(type);
CREATE INDEX IF NOT EXISTS idx_tool_updated_at ON app.tool(updated_at DESC);

-- Aliases for tools (compatible with proto aliases)
CREATE TABLE IF NOT EXISTS app.tool_alias (
  tool_id     uuid  NOT NULL REFERENCES app.tool(id) ON DELETE CASCADE,
  alias       text  NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tool_id, alias),
  CONSTRAINT alias_format CHECK (alias ~ '^[A-Za-z0-9][A-Za-z0-9\-\._]{1,254}$')
);
ALTER TABLE app.tool_alias OWNER TO app_owner;
GRANT SELECT ON app.tool_alias TO app_ro, app_rw;
GRANT INSERT, UPDATE, DELETE ON app.tool_alias TO app_rw;

-- ETag + timestamps + audit triggers for tool
CREATE TRIGGER trg_tool_timestamps
BEFORE INSERT OR UPDATE ON app.tool
FOR EACH ROW EXECUTE FUNCTION app.fn_set_timestamps();

CREATE TRIGGER trg_tool_etag
BEFORE INSERT OR UPDATE ON app.tool
FOR EACH ROW EXECUTE FUNCTION app.fn_set_etag_tool();

CREATE TRIGGER trg_tool_audit
AFTER INSERT OR UPDATE OR DELETE ON app.tool
FOR EACH ROW EXECUTE FUNCTION app_audit.fn_audit();

-- ---------------------------------------------------------------------------
-- Row-Level Security (RLS): optional tenant isolation by project_id
--   Strategy: enable RLS; grant to app_rw/app_ro; define policy based on SET app.current_project
-- ---------------------------------------------------------------------------
ALTER TABLE app.tool ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.location ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.project ENABLE ROW LEVEL SECURITY;

-- helper GUC: SET app.current_project = '<uuid>';
DO $$
BEGIN
  PERFORM set_config('app.current_project', '', true);
EXCEPTION WHEN others THEN
  -- ignore if not allowed; user can still SET it at session level
  NULL;
END$$;

CREATE OR REPLACE FUNCTION app.fn_current_project() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_project', true), '')::uuid
$$;

-- Policies (read)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='app' AND tablename='project' AND policyname='project_read'
  ) THEN
    CREATE POLICY project_read ON app.project
      FOR SELECT
      TO app_ro, app_rw
      USING (app.fn_current_project() IS NULL OR id = app.fn_current_project());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='app' AND tablename='location' AND policyname='location_read'
  ) THEN
    CREATE POLICY location_read ON app.location
      FOR SELECT
      TO app_ro, app_rw
      USING (app.fn_current_project() IS NULL OR project_id = app.fn_current_project());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='app' AND tablename='tool' AND policyname='tool_read'
  ) THEN
    CREATE POLICY tool_read ON app.tool
      FOR SELECT
      TO app_ro, app_rw
      USING (app.fn_current_project() IS NULL OR project_id = app.fn_current_project());
  END IF;

  -- Write policies (app_rw)
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='app' AND tablename='tool' AND policyname='tool_write'
  ) THEN
    CREATE POLICY tool_write ON app.tool
      FOR INSERT, UPDATE, DELETE
      TO app_rw
      USING (app.fn_current_project() IS NULL OR project_id = app.fn_current_project())
      WITH CHECK (app.fn_current_project() IS NULL OR project_id = app.fn_current_project());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='app' AND tablename='location' AND policyname='location_write'
  ) THEN
    CREATE POLICY location_write ON app.location
      FOR INSERT, UPDATE, DELETE
      TO app_rw
      USING (app.fn_current_project() IS NULL OR project_id = app.fn_current_project())
      WITH CHECK (app.fn_current_project() IS NULL OR project_id = app.fn_current_project());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='app' AND tablename='project' AND policyname='project_write'
  ) THEN
    CREATE POLICY project_write ON app.project
      FOR INSERT, UPDATE, DELETE
      TO app_rw
      USING (app.fn_current_project() IS NULL OR id = app.fn_current_project())
      WITH CHECK (app.fn_current_project() IS NULL OR id = app.fn_current_project());
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Soft-delete helper (optional): mark tool as deleted
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.fn_tool_soft_delete(_id uuid, _expected_etag text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE app.tool
     SET deleted_at = now()
   WHERE id = _id
     AND deleted_at IS NULL
     AND (_expected_etag IS NULL OR etag = _expected_etag);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tool not found or etag mismatch'
      USING ERRCODE = 'no_data_found';
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Seed minimal records (optional; safe upserts). Comment out in prod if not needed.
-- ---------------------------------------------------------------------------
-- INSERT INTO app_meta.migrations(version, checksum_sha256)
-- VALUES ('0001', decode('<sha256-of-this-file-hex>', 'hex'))
-- ON CONFLICT (version) DO NOTHING;

COMMIT;

/* ========================================================================== */
/* End of 0001_init.sql                                                       */
/* ========================================================================== */
