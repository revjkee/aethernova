-- =============================================================================
-- VeilMind Core — Initial schema (0001_init)
-- PostgreSQL 13+ recommended
-- Idempotent where reasonable (IF NOT EXISTS)
-- =============================================================================

BEGIN;

-- -----------------------------
-- Safe session settings
-- -----------------------------
SET lock_timeout = '30s';
SET idle_in_transaction_session_timeout = '5min';
SET statement_timeout = '120s';

-- -----------------------------
-- Extensions (safe IF NOT EXISTS)
-- -----------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;        -- case-insensitive text
CREATE EXTENSION IF NOT EXISTS pg_trgm;       -- trigram search (for names)
-- CREATE EXTENSION IF NOT EXISTS btree_gin;  -- optional if needed later

-- -----------------------------
-- Schema
-- -----------------------------
CREATE SCHEMA IF NOT EXISTS veilmind AUTHORIZATION CURRENT_USER;

-- -----------------------------
-- Migration registry
-- -----------------------------
CREATE TABLE IF NOT EXISTS veilmind.schema_migrations (
  version      text PRIMARY KEY,
  checksum     text NOT NULL,
  applied_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE veilmind.schema_migrations IS 'Applied DB migrations registry';

-- =============================================================================
-- Core tables
-- =============================================================================

-- -----------------------------
-- DATASETS
-- Stores reusable dataset specs (schema + constraints + labels)
-- -----------------------------
CREATE TABLE IF NOT EXISTS veilmind.datasets (
  dataset_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           citext NOT NULL UNIQUE,
  -- Full SyntheticDatasetSpec (без output/streaming/schedule); валидируется приложением
  spec           jsonb  NOT NULL,
  labels         jsonb  NOT NULL DEFAULT '[]'::jsonb, -- [{"key":"k","value":"v"}, ...]
  created_by     text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  -- simple guard that top-level "schema" exists
  CONSTRAINT datasets_spec_has_schema CHECK (spec ? 'schema'),
  CONSTRAINT datasets_labels_array CHECK (jsonb_typeof(labels) = 'array')
);

COMMENT ON TABLE  veilmind.datasets IS 'Reusable synthetic dataset specifications';
COMMENT ON COLUMN veilmind.datasets.spec   IS 'JSONB: SyntheticDatasetSpec (subset)';
COMMENT ON COLUMN veilmind.datasets.labels IS 'JSONB array of {key,value} used for filtering';

-- Indexes for JSON search and name search
CREATE INDEX IF NOT EXISTS datasets_spec_gin
  ON veilmind.datasets USING gin (spec jsonb_path_ops);
CREATE INDEX IF NOT EXISTS datasets_labels_gin
  ON veilmind.datasets USING gin (labels);
CREATE INDEX IF NOT EXISTS datasets_name_trgm
  ON veilmind.datasets USING gin (name gin_trgm_ops);

-- -----------------------------
-- JOBS
-- A generation job (batch/stream/scheduled)
-- -----------------------------
CREATE TABLE IF NOT EXISTS veilmind.jobs (
  job_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dataset_id       uuid REFERENCES veilmind.datasets(dataset_id) ON DELETE SET NULL,
  dataset_name     citext NOT NULL, -- denormalized for easy search (copy of datasets.name at submit time)

  state            text   NOT NULL,
  percent_complete numeric(5,2) NOT NULL DEFAULT 0 CHECK (percent_complete >= 0 AND percent_complete <= 100),

  sink_uri         text,                              -- final sink/prefix (if any)
  output_spec      jsonb  NOT NULL DEFAULT '{}'::jsonb,
  streaming_spec   jsonb  NOT NULL DEFAULT '{}'::jsonb,
  schedule_spec    jsonb  NOT NULL DEFAULT '{}'::jsonb,
  metrics          jsonb  NOT NULL DEFAULT '{}'::jsonb,
  last_error       jsonb,

  labels           jsonb  NOT NULL DEFAULT '[]'::jsonb, -- [{"key":"k","value":"v"}]

  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  finished_at      timestamptz,

  CONSTRAINT jobs_state_valid CHECK (state IN ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELED')),
  CONSTRAINT jobs_labels_array CHECK (jsonb_typeof(labels) = 'array')
);

COMMENT ON TABLE  veilmind.jobs IS 'Synthetic generation jobs with lifecycle and metrics';
COMMENT ON COLUMN veilmind.jobs.state IS 'PENDING|RUNNING|SUCCEEDED|FAILED|CANCELED';

-- Useful indexes
CREATE INDEX IF NOT EXISTS jobs_state_created_idx
  ON veilmind.jobs (state, created_at DESC);
CREATE INDEX IF NOT EXISTS jobs_dataset_idx
  ON veilmind.jobs (dataset_id);
CREATE INDEX IF NOT EXISTS jobs_name_trgm
  ON veilmind.jobs USING gin (dataset_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS jobs_labels_gin
  ON veilmind.jobs USING gin (labels);
CREATE INDEX IF NOT EXISTS jobs_created_idx
  ON veilmind.jobs (created_at DESC);
-- Hot states quick lookup
CREATE INDEX IF NOT EXISTS jobs_hot_partial_idx
  ON veilmind.jobs (created_at DESC)
  WHERE state IN ('PENDING','RUNNING');

-- -----------------------------
-- JOB EVENTS (partitioned monthly by occurred_at)
-- Tracks state transitions and operational notes
-- -----------------------------
CREATE TABLE IF NOT EXISTS veilmind.job_events (
  event_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id        uuid NOT NULL REFERENCES veilmind.jobs(job_id) ON DELETE CASCADE,
  prev_state    text,
  new_state     text NOT NULL,
  reason        text,
  error         jsonb,
  actor         text, -- who/what changed it (svc, user id)
  occurred_at   timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (occurred_at);

COMMENT ON TABLE veilmind.job_events IS 'State transitions and audit trail for jobs';

-- default catch-all partition
CREATE TABLE IF NOT EXISTS veilmind.job_events_default
  PARTITION OF veilmind.job_events DEFAULT;

-- -----------------------------
-- JOB METRICS TIMESERIES (partitioned monthly by ts)
-- Aggregate points during generation (throughput, counters)
-- -----------------------------
CREATE TABLE IF NOT EXISTS veilmind.job_metrics_ts (
  job_id      uuid   NOT NULL REFERENCES veilmind.jobs(job_id) ON DELETE CASCADE,
  ts          timestamptz NOT NULL,
  metric_key  text   NOT NULL,
  value_num   double precision,
  value_json  jsonb,
  PRIMARY KEY (job_id, ts, metric_key)
) PARTITION BY RANGE (ts);

COMMENT ON TABLE veilmind.job_metrics_ts IS 'Job metrics time series (agg points/counters)';

CREATE TABLE IF NOT EXISTS veilmind.job_metrics_ts_default
  PARTITION OF veilmind.job_metrics_ts DEFAULT;

-- =============================================================================
-- Triggers & Functions
-- =============================================================================

-- updated_at automator
CREATE OR REPLACE FUNCTION veilmind.tg_set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS tr_set_updated_at_datasets ON veilmind.datasets;
CREATE TRIGGER tr_set_updated_at_datasets
BEFORE UPDATE ON veilmind.datasets
FOR EACH ROW EXECUTE FUNCTION veilmind.tg_set_updated_at();

DROP TRIGGER IF EXISTS tr_set_updated_at_jobs ON veilmind.jobs;
CREATE TRIGGER tr_set_updated_at_jobs
BEFORE UPDATE ON veilmind.jobs
FOR EACH ROW EXECUTE FUNCTION veilmind.tg_set_updated_at();

-- Enforce valid state transitions & set started_at/finished_at automatically
CREATE OR REPLACE FUNCTION veilmind.tg_jobs_state_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  old_state text := COALESCE(OLD.state, 'PENDING');
  new_state text := NEW.state;
BEGIN
  -- clamp percent
  IF NEW.percent_complete < 0 THEN NEW.percent_complete := 0; END IF;
  IF NEW.percent_complete > 100 THEN NEW.percent_complete := 100; END IF;

  -- state machine:
  -- PENDING -> RUNNING|FAILED|CANCELED
  -- RUNNING -> SUCCEEDED|FAILED|CANCELED
  -- Terminal states can't transition further.
  IF old_state = 'PENDING' AND new_state NOT IN ('RUNNING','FAILED','CANCELED') THEN
    RAISE EXCEPTION 'invalid transition from % to %', old_state, new_state;
  ELSIF old_state = 'RUNNING' AND new_state NOT IN ('SUCCEEDED','FAILED','CANCELED','RUNNING') THEN
    RAISE EXCEPTION 'invalid transition from % to %', old_state, new_state;
  ELSIF old_state IN ('SUCCEEDED','FAILED','CANCELED') AND new_state <> old_state THEN
    RAISE EXCEPTION 'attempt to change terminal state % to %', old_state, new_state;
  END IF;

  -- timestamps
  IF old_state = 'PENDING' AND new_state = 'RUNNING' AND NEW.started_at IS NULL THEN
    NEW.started_at := now();
  END IF;

  IF new_state IN ('SUCCEEDED','FAILED','CANCELED') AND NEW.finished_at IS NULL THEN
    NEW.finished_at := now();
  END IF;

  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS tr_jobs_state_guard ON veilmind.jobs;
CREATE TRIGGER tr_jobs_state_guard
BEFORE UPDATE ON veilmind.jobs
FOR EACH ROW EXECUTE FUNCTION veilmind.tg_jobs_state_guard();

-- Auto-insert job_events on state change
CREATE OR REPLACE FUNCTION veilmind.tg_jobs_log_event()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO veilmind.job_events(job_id, prev_state, new_state, reason, error, actor, occurred_at)
    VALUES (NEW.job_id, NULL, NEW.state, 'job.created', NULL, current_user, now());
  ELSIF TG_OP = 'UPDATE' AND NEW.state <> OLD.state THEN
    INSERT INTO veilmind.job_events(job_id, prev_state, new_state, reason, error, actor, occurred_at)
    VALUES (NEW.job_id, OLD.state, NEW.state, 'state.changed', NEW.last_error, current_user, now());
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS tr_jobs_log_event_ins ON veilmind.jobs;
CREATE TRIGGER tr_jobs_log_event_ins
AFTER INSERT ON veilmind.jobs
FOR EACH ROW EXECUTE FUNCTION veilmind.tg_jobs_log_event();

DROP TRIGGER IF EXISTS tr_jobs_log_event_upd ON veilmind.jobs;
CREATE TRIGGER tr_jobs_log_event_upd
AFTER UPDATE ON veilmind.jobs
FOR EACH ROW EXECUTE FUNCTION veilmind.tg_jobs_log_event();

-- Monthly partition helper for job_events
CREATE OR REPLACE FUNCTION veilmind.ensure_job_events_partition(ref_ts timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  start_ts timestamptz := date_trunc('month', ref_ts);
  end_ts   timestamptz := (start_ts + interval '1 month');
  part_name text := 'job_events_' || to_char(start_ts, 'YYYYMM');
  sql text;
BEGIN
  sql := format(
    'CREATE TABLE IF NOT EXISTS veilmind.%I PARTITION OF veilmind.job_events
     FOR VALUES FROM (%L) TO (%L);',
    part_name, start_ts, end_ts
  );
  EXECUTE sql;
END $$;

-- Monthly partition helper for job_metrics_ts
CREATE OR REPLACE FUNCTION veilmind.ensure_job_metrics_partition(ref_ts timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  start_ts timestamptz := date_trunc('month', ref_ts);
  end_ts   timestamptz := (start_ts + interval '1 month');
  part_name text := 'job_metrics_ts_' || to_char(start_ts, 'YYYYMM');
  sql text;
BEGIN
  sql := format(
    'CREATE TABLE IF NOT EXISTS veilmind.%I PARTITION OF veilmind.job_metrics_ts
     FOR VALUES FROM (%L) TO (%L);',
    part_name, start_ts, end_ts
  );
  EXECUTE sql;
END $$;

-- Create partitions for current and next month proactively
SELECT veilmind.ensure_job_events_partition(now());
SELECT veilmind.ensure_job_events_partition(now() + interval '1 month');
SELECT veilmind.ensure_job_metrics_partition(now());
SELECT veilmind.ensure_job_metrics_partition(now() + interval '1 month');

-- =============================================================================
-- Views
-- =============================================================================

CREATE OR REPLACE VIEW veilmind.v_job_counts AS
SELECT state, count(*) AS cnt
FROM veilmind.jobs
GROUP BY state;

CREATE OR REPLACE VIEW veilmind.v_jobs_running AS
SELECT job_id, dataset_name, created_at, started_at, percent_complete
FROM veilmind.jobs
WHERE state = 'RUNNING'
ORDER BY started_at NULLS LAST;

-- =============================================================================
-- Roles & Grants (optional but recommended)
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'veilmind_app') THEN
    CREATE ROLE veilmind_app NOINHERIT LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'veilmind_readonly') THEN
    CREATE ROLE veilmind_readonly NOINHERIT LOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA veilmind TO veilmind_app, veilmind_readonly;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  veilmind.datasets,
  veilmind.jobs
TO veilmind_app;

GRANT SELECT ON
  veilmind.datasets,
  veilmind.jobs,
  veilmind.job_events,
  veilmind.job_metrics_ts,
  veilmind.v_job_counts,
  veilmind.v_jobs_running
TO veilmind_readonly;

-- default privileges for future partitions
ALTER DEFAULT PRIVILEGES IN SCHEMA veilmind
GRANT SELECT ON TABLES TO veilmind_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA veilmind
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO veilmind_app;

-- =============================================================================
-- Finalize migration record
-- =============================================================================
INSERT INTO veilmind.schema_migrations(version, checksum)
VALUES ('0001_init', 'sha256:veilmind-0001-initial')
ON CONFLICT (version) DO NOTHING;

COMMIT;
