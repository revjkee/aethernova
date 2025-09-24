-- physical-integration-core/schemas/sql/migrations/0004_safety_audit.sql
-- PostgreSQL >= 12
-- Safety & Audit layer: schema, enums, partitioned tables, RLS, triggers, retention tools.

BEGIN;

-- Defensive settings
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
SET LOCAL idle_in_transaction_session_timeout = '30s';
SET LOCAL client_min_messages = WARNING;

-- Ensure required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid(), digest()

-- Version guard
DO $$
BEGIN
  IF current_setting('server_version_num')::int < 120000 THEN
    RAISE EXCEPTION 'PostgreSQL 12+ required, found %', current_setting('server_version');
  END IF;
END$$;

-- Schema
CREATE SCHEMA IF NOT EXISTS safety_audit;
COMMENT ON SCHEMA safety_audit IS 'Physical Integration Core: safety events, actions, and audit trail';

-- =========================
-- Enums
-- =========================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'severity_level' AND typnamespace = 'safety_audit'::regnamespace) THEN
    CREATE TYPE safety_audit.severity_level AS ENUM ('low','medium','high','critical');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'event_kind' AND typnamespace = 'safety_audit'::regnamespace) THEN
    CREATE TYPE safety_audit.event_kind AS ENUM ('near_miss','incident','hazard','inspection','maintenance','test','audit');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_type' AND typnamespace = 'safety_audit'::regnamespace) THEN
    CREATE TYPE safety_audit.action_type AS ENUM ('ack','escalate','dispatch','shutdown','startup','notify','create_ticket','close');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_status' AND typnamespace = 'safety_audit'::regnamespace) THEN
    CREATE TYPE safety_audit.action_status AS ENUM ('open','in_progress','done','cancelled');
  END IF;
END$$;

-- =========================
-- Helper functions
-- =========================

-- Current tenant from session GUC app.current_tenant (UUID as text)
CREATE OR REPLACE FUNCTION safety_audit.current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::uuid
$$;
COMMENT ON FUNCTION safety_audit.current_tenant IS 'Reads tenant UUID from app.current_tenant GUC';

-- Timestamps trigger (created_at/updated_at + created_by/updated_by)
CREATE OR REPLACE FUNCTION safety_audit.fn_set_timestamps() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.created_at IS NULL THEN NEW.created_at := now(); END IF;
    IF NEW.updated_at IS NULL THEN NEW.updated_at := NEW.created_at; END IF;
    IF NEW.created_by IS NULL THEN NEW.created_by := COALESCE(current_setting('app.current_actor', true), session_user); END IF;
    IF NEW.updated_by IS NULL THEN NEW.updated_by := NEW.created_by; END IF;
  ELSE
    NEW.updated_at := now();
    NEW.updated_by := COALESCE(current_setting('app.current_actor', true), session_user);
  END IF;
  RETURN NEW;
END$$;
COMMENT ON FUNCTION safety_audit.fn_set_timestamps IS 'Maintains created/updated timestamps and actor fields';

-- Generic row change audit trigger
CREATE OR REPLACE FUNCTION safety_audit.fn_audit_changes() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_tenant uuid;
  v_pk text;
  v_changed text[];
BEGIN
  v_tenant := COALESCE(
    (CASE WHEN TG_TABLE_NAME = 'event_log' THEN COALESCE(NEW.tenant_id, OLD.tenant_id)
          WHEN TG_TABLE_NAME = 'action_log' THEN COALESCE(NEW.tenant_id, OLD.tenant_id)
          ELSE NULL END),
    safety_audit.current_tenant()
  );

  -- try to capture PK as UUID or text
  v_pk := COALESCE(
    (CASE WHEN TG_OP IN ('INSERT','UPDATE') THEN
       COALESCE((to_jsonb(NEW)->>'id'), (to_jsonb(NEW)->>'event_id'))
     ELSE
       COALESCE((to_jsonb(OLD)->>'id'), (to_jsonb(OLD)->>'event_id'))
     END),
    ''
  );

  IF TG_OP = 'UPDATE' THEN
    v_changed := ARRAY(
      SELECT k FROM jsonb_object_keys(to_jsonb(NEW)) AS k
      WHERE (to_jsonb(NEW)->k) IS DISTINCT FROM (to_jsonb(OLD)->k)
    );
  END IF;

  INSERT INTO safety_audit.audit_trail(
    occurred_at, schema_name, table_name, op, pk_text,
    actor, app_name, client_addr, txid, tenant_id,
    before, after, changed_columns
  ) VALUES (
    now(), TG_TABLE_SCHEMA, TG_TABLE_NAME, SUBSTRING(TG_OP,1,1),
    v_pk,
    COALESCE(current_setting('app.current_actor', true), session_user),
    current_setting('application_name', true),
    inet_client_addr(), txid_current(), v_tenant,
    CASE WHEN TG_OP IN ('UPDATE','DELETE') THEN to_jsonb(OLD) ELSE NULL END,
    CASE WHEN TG_OP IN ('UPDATE','INSERT') THEN to_jsonb(NEW) ELSE NULL END,
    v_changed
  );
  RETURN NULL;
END$$;
COMMENT ON FUNCTION safety_audit.fn_audit_changes IS 'Writes row-level audit entries for INSERT/UPDATE/DELETE';

-- Partition name helper
CREATE OR REPLACE FUNCTION safety_audit.partition_name(p_ts timestamptz)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT format('event_log_y%sm%02s', to_char(p_ts AT TIME ZONE 'UTC','YYYY'), to_char(p_ts AT TIME ZONE 'UTC','MM'))
$$;

-- Ensure monthly partition exists for given year/month
CREATE OR REPLACE FUNCTION safety_audit.ensure_month_partition(p_year int, p_month int) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  p_start timestamptz;
  p_end   timestamptz;
  tbl     text;
BEGIN
  p_start := make_timestamptz(p_year, p_month, 1, 0, 0, 0, 'UTC');
  p_end   := (p_start + INTERVAL '1 month');
  tbl     := safety_audit.partition_name(p_start);

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='safety_audit' AND c.relname=tbl
  ) THEN
    EXECUTE format($sql$
      CREATE TABLE safety_audit.%I PARTITION OF safety_audit.event_log
      FOR VALUES FROM (%L) TO (%L);
    $sql$, tbl, p_start, p_end);

    -- Indexes on partition
    EXECUTE format('CREATE INDEX %I_occured_at_idx ON safety_audit.%I (occurred_at);', tbl, tbl);
    EXECUTE format('CREATE INDEX %I_tenant_time_idx ON safety_audit.%I (tenant_id, occurred_at DESC);', tbl, tbl);
    EXECUTE format('CREATE INDEX %I_twin_idx ON safety_audit.%I (twin_name);', tbl, tbl);
    EXECUTE format('CREATE INDEX %I_severity_idx ON safety_audit.%I (severity);', tbl, tbl);
    EXECUTE format('CREATE INDEX %I_tags_gin ON safety_audit.%I USING GIN (tags);', tbl, tbl);
  END IF;
END$$;
COMMENT ON FUNCTION safety_audit.ensure_month_partition IS 'Creates monthly partition and its indexes if absent';

-- Drop old partitions keeping N most recent months
CREATE OR REPLACE FUNCTION safety_audit.drop_old_partitions(months_to_keep int DEFAULT 12) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
  cutoff timestamptz := date_trunc('month', now() AT TIME ZONE 'UTC') - (INTERVAL '1 month' * months_to_keep);
  dropped int := 0;
  r record;
BEGIN
  FOR r IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='safety_audit' AND c.relname LIKE 'event_log_y%m%' AND c.relkind='r'
  LOOP
    IF to_timestamp(substring(r.relname from 'event_log_y(\d{4})m(\d{2})')::text, 'YYYY"m"MM') < cutoff THEN
      EXECUTE format('DROP TABLE IF EXISTS safety_audit.%I;', r.relname);
      dropped := dropped + 1;
    END IF;
  END LOOP;
  RETURN dropped;
END$$;
COMMENT ON FUNCTION safety_audit.drop_old_partitions IS 'Drops event_log monthly partitions older than retention window';

-- =========================
-- Tables
-- =========================

-- Audit trail table
CREATE TABLE IF NOT EXISTS safety_audit.audit_trail (
  id               bigserial PRIMARY KEY,
  occurred_at      timestamptz NOT NULL DEFAULT now(),
  schema_name      text        NOT NULL,
  table_name       text        NOT NULL,
  op               char(1)     NOT NULL CHECK (op IN ('I','U','D')),
  pk_text          text        NOT NULL,
  actor            text        NOT NULL,
  app_name         text,
  client_addr      inet,
  txid             bigint      NOT NULL,
  tenant_id        uuid,
  before           jsonb,
  after            jsonb,
  changed_columns  text[]
);
COMMENT ON TABLE safety_audit.audit_trail IS 'Row-level DML audit trail for safety_audit tables';
CREATE INDEX IF NOT EXISTS audit_trail_ts_idx ON safety_audit.audit_trail (occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_trail_table_idx ON safety_audit.audit_trail (table_name, op);
CREATE INDEX IF NOT EXISTS audit_trail_tenant_idx ON safety_audit.audit_trail (tenant_id);

-- Main event log (partitioned)
CREATE TABLE IF NOT EXISTS safety_audit.event_log (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT safety_audit.current_tenant(),
  -- physical/twin identifiers (soft references)
  twin_name          text,           -- e.g. "twin/{id}"
  twin_uid           uuid,
  source_system      text NOT NULL,  -- producer system
  event_kind         safety_audit.event_kind NOT NULL,
  severity           safety_audit.severity_level NOT NULL,
  title              text NOT NULL,
  description        text,
  occurred_at        timestamptz NOT NULL,
  recorded_at        timestamptz NOT NULL DEFAULT now(),
  tags               jsonb NOT NULL DEFAULT '{}'::jsonb,  -- free-form labels
  attributes         jsonb NOT NULL DEFAULT '{}'::jsonb,  -- structured payload
  -- Fingerprint for deduplication (hash of critical fields)
  event_fingerprint  bytea GENERATED ALWAYS AS (
    digest(
      coalesce(twin_name,'') || '|' ||
      coalesce(title,'') || '|' ||
      event_kind::text || '|' ||
      to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    , 'sha256')
  ) STORED,
  -- bookkeeping
  created_at         timestamptz,
  created_by         text,
  updated_at         timestamptz,
  updated_by         text
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE safety_audit.event_log IS 'Time-partitioned safety/incident/hazard events';
COMMENT ON COLUMN safety_audit.event_log.event_fingerprint IS 'SHA-256 fingerprint for deduplication';

-- Uniqueness within tenant on fingerprint + kind
CREATE UNIQUE INDEX IF NOT EXISTS event_log_dedupe_uniq
ON safety_audit.event_log (tenant_id, event_kind, event_fingerprint);

-- Default partition (catch-all)
CREATE TABLE IF NOT EXISTS safety_audit.event_log_default PARTITION OF safety_audit.event_log DEFAULT;

-- Create partitions for current and next month
DO $$
DECLARE
  y int := EXTRACT(YEAR FROM now() AT TIME ZONE 'UTC');
  m int := EXTRACT(MONTH FROM now() AT TIME ZONE 'UTC');
BEGIN
  PERFORM safety_audit.ensure_month_partition(y, m);
  PERFORM safety_audit.ensure_month_partition(EXTRACT(YEAR FROM (now() AT TIME ZONE 'UTC' + INTERVAL '1 month'))::int,
                                             EXTRACT(MONTH FROM (now() AT TIME ZONE 'UTC' + INTERVAL '1 month'))::int);
END$$;

-- Foreign key to physical.twin(uid) IF EXISTS (NOT VALID to avoid fail on empty)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM   pg_namespace n
    JOIN   pg_class c ON c.relnamespace=n.oid
    JOIN   pg_attribute a ON a.attrelid=c.oid AND a.attname='uid'
    WHERE  n.nspname='physical' AND c.relname='twin'
  ) THEN
    ALTER TABLE safety_audit.event_log
      ADD CONSTRAINT event_log_twin_fk
      FOREIGN KEY (twin_uid) REFERENCES physical.twin(uid) NOT VALID;
  END IF;
END$$;

-- Actions taken for events
CREATE TABLE IF NOT EXISTS safety_audit.action_log (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL DEFAULT safety_audit.current_tenant(),
  event_id       uuid NOT NULL,
  action_type    safety_audit.action_type NOT NULL,
  status         safety_audit.action_status NOT NULL DEFAULT 'open',
  actor          text NOT NULL,              -- user/service who performed or owns the action
  notes          text,
  due_at         timestamptz,
  performed_at   timestamptz,                -- when actually performed
  created_at     timestamptz,
  created_by     text,
  updated_at     timestamptz,
  updated_by     text,
  CONSTRAINT action_event_fk
    FOREIGN KEY (event_id) REFERENCES safety_audit.event_log(id) ON DELETE CASCADE
);
COMMENT ON TABLE safety_audit.action_log IS 'Actions and responses taken for safety events';
CREATE INDEX IF NOT EXISTS action_event_idx ON safety_audit.action_log (event_id);
CREATE INDEX IF NOT EXISTS action_tenant_status_idx ON safety_audit.action_log (tenant_id, status);
CREATE INDEX IF NOT EXISTS action_due_idx ON safety_audit.action_log (due_at);

-- =========================
-- Triggers
-- =========================
CREATE TRIGGER trg_event_log_ts
BEFORE INSERT OR UPDATE ON safety_audit.event_log
FOR EACH ROW EXECUTE FUNCTION safety_audit.fn_set_timestamps();

CREATE TRIGGER trg_action_log_ts
BEFORE INSERT OR UPDATE ON safety_audit.action_log
FOR EACH ROW EXECUTE FUNCTION safety_audit.fn_set_timestamps();

-- Row-change audit triggers
CREATE TRIGGER trg_event_log_audit
AFTER INSERT OR UPDATE OR DELETE ON safety_audit.event_log
FOR EACH ROW EXECUTE FUNCTION safety_audit.fn_audit_changes();

CREATE TRIGGER trg_action_log_audit
AFTER INSERT OR UPDATE OR DELETE ON safety_audit.action_log
FOR EACH ROW EXECUTE FUNCTION safety_audit.fn_audit_changes();

-- =========================
-- Row Level Security (RLS)
-- =========================
ALTER TABLE safety_audit.event_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE safety_audit.action_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE safety_audit.audit_trail ENABLE ROW LEVEL SECURITY;

-- Select policy: tenant matches session GUC
CREATE POLICY event_log_tenant_sel ON safety_audit.event_log
FOR SELECT USING (tenant_id = safety_audit.current_tenant());

CREATE POLICY event_log_tenant_mod ON safety_audit.event_log
FOR INSERT WITH CHECK (tenant_id = safety_audit.current_tenant())
,   UPDATE USING (tenant_id = safety_audit.current_tenant())
       WITH CHECK (tenant_id = safety_audit.current_tenant());

CREATE POLICY action_log_tenant_sel ON safety_audit.action_log
FOR SELECT USING (tenant_id = safety_audit.current_tenant());

CREATE POLICY action_log_tenant_mod ON safety_audit.action_log
FOR INSERT WITH CHECK (tenant_id = safety_audit.current_tenant())
,   UPDATE USING (tenant_id = safety_audit.current_tenant())
       WITH CHECK (tenant_id = safety_audit.current_tenant());

-- Audit trail is readable within tenant; writes only from triggers (bypass via trigger origin)
CREATE POLICY audit_trail_tenant_sel ON safety_audit.audit_trail
FOR SELECT USING (tenant_id IS NULL OR tenant_id = safety_audit.current_tenant());

-- =========================
-- Views (operational convenience)
-- =========================
CREATE OR REPLACE VIEW safety_audit.v_recent_incidents AS
SELECT e.*
FROM safety_audit.event_log e
WHERE e.event_kind IN ('incident','hazard')
  AND e.occurred_at >= now() - INTERVAL '7 days'
  AND e.tenant_id = safety_audit.current_tenant();

CREATE OR REPLACE VIEW safety_audit.v_open_actions AS
SELECT a.*
FROM safety_audit.action_log a
WHERE a.status IN ('open','in_progress')
  AND a.tenant_id = safety_audit.current_tenant();

-- =========================
-- Grants (optional, applied only if roles exist)
-- =========================
DO $$
DECLARE r text;
BEGIN
  FOR r IN SELECT unnest(ARRAY['pic_app','pic_analyst']) LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT USAGE ON SCHEMA safety_audit TO %I;', r);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON safety_audit.event_log TO %I;', r);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON safety_audit.action_log TO %I;', r);
      EXECUTE format('GRANT SELECT ON safety_audit.audit_trail, safety_audit.v_recent_incidents, safety_audit.v_open_actions TO %I;', r);
    END IF;
  END LOOP;
END$$;

-- =========================
-- Constraints & data quality
-- =========================
ALTER TABLE safety_audit.event_log
  ADD CONSTRAINT event_time_not_future
  CHECK (occurred_at <= now() + INTERVAL '5 minutes')
  NOT VALID;

ALTER TABLE safety_audit.event_log
  ADD CONSTRAINT tags_is_object
  CHECK (jsonb_typeof(tags) = 'object')
  NOT VALID;

ALTER TABLE safety_audit.event_log
  ADD CONSTRAINT attributes_is_object
  CHECK (jsonb_typeof(attributes) = 'object')
  NOT VALID;

-- Optional partial index for high/critical severity searches
CREATE INDEX IF NOT EXISTS event_log_sev_urgent_idx
ON safety_audit.event_log (tenant_id, occurred_at DESC)
WHERE severity IN ('high','critical');

-- =========================
-- Comments
-- =========================
COMMENT ON COLUMN safety_audit.event_log.tenant_id IS 'Tenant isolation key (RLS via app.current_tenant)';
COMMENT ON COLUMN safety_audit.event_log.twin_name  IS 'Logical name of Twin resource (e.g., twin/{id})';
COMMENT ON COLUMN safety_audit.event_log.twin_uid   IS 'Platform UID of Twin (soft FK, NOT VALID)';
COMMENT ON VIEW safety_audit.v_recent_incidents IS 'Incidents/Hazards over the last 7 days for current tenant';
COMMENT ON VIEW safety_audit.v_open_actions IS 'Open/in-progress actions for current tenant';

COMMIT;
