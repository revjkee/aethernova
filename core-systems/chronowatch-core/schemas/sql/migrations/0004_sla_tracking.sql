-- chronowatch-core/schemas/sql/migrations/0004_sla_tracking.sql
-- SLA / SLO / SLI tracking for ChronoWatch Core (PostgreSQL 12+)
-- Idempotent, transactional, partitioned by time, with MV + helper functions.

-- -------------------------------
-- Safety & session settings
-- -------------------------------
SET client_min_messages = WARNING;
SET lock_timeout = '5s';
SET statement_timeout = '0';
SET idle_in_transaction_session_timeout = '10min';

BEGIN;

-- -------------------------------
-- Schema
-- -------------------------------
CREATE SCHEMA IF NOT EXISTS chronowatch;
SET search_path = chronowatch, public;

-- -------------------------------
-- Helper domains and checks (no ENUMs to keep evolvable)
-- -------------------------------
DO $$
BEGIN
  -- create a role for app if your org uses dedicated user; ignore if exists
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chronowatch_app') THEN
    PERFORM 1; -- no-op; role creation is often handled outside migrations
  END IF;
END$$;

-- -------------------------------
-- Table: sla_slos
-- One record per SLO target (service/env/objective)
-- -------------------------------
CREATE TABLE IF NOT EXISTS sla_slos (
  id                BIGSERIAL PRIMARY KEY,
  service_name      TEXT NOT NULL CHECK (length(service_name) > 0),
  env               TEXT NOT NULL CHECK (env IN ('prod','staging','dev','test')),
  -- SLI identifier (e.g., 'http_success_ratio', 'latency_p95_ms')
  sli_name          TEXT NOT NULL CHECK (length(sli_name) > 0),

  -- Objective type: availability | latency | error_rate | custom
  objective_type    TEXT NOT NULL CHECK (objective_type IN ('availability','latency','error_rate','custom')),

  -- Target success fraction for availability/error_rate/custom [0..1]
  target_fraction   NUMERIC(6,5),
  -- Threshold for latency/custom objectives; unit in threshold_unit
  threshold_value   NUMERIC(14,6),
  threshold_unit    TEXT DEFAULT 'ms',

  -- Budgeting method per SRE workbook: 'timeslices' OR 'occurrences'
  budgeting_method  TEXT NOT NULL DEFAULT 'timeslices' CHECK (budgeting_method IN ('timeslices','occurrences')),

  -- Rolling evaluation window and slice granularity
  window_duration   INTERVAL NOT NULL DEFAULT '30 days',
  timeslice_interval INTERVAL NOT NULL DEFAULT '5 minutes',

  -- Activation period
  active            BOOLEAN NOT NULL DEFAULT TRUE,
  valid_from        TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_to          TIMESTAMPTZ,

  -- Freeform attributes / labels (JSONB)
  attributes        JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- Generated convenience: allowed error rate (1 - target_fraction)
  allowed_error_rate NUMERIC(6,5) GENERATED ALWAYS AS (
    CASE WHEN target_fraction IS NOT NULL THEN GREATEST(0, LEAST(1, 1 - target_fraction)) ELSE NULL END
  ) STORED
);

COMMENT ON TABLE sla_slos IS 'Service Level Objectives for ChronoWatch services';
COMMENT ON COLUMN sla_slos.target_fraction IS 'Target success fraction, e.g. 0.999 for 99.9% availability';
COMMENT ON COLUMN sla_slos.allowed_error_rate IS 'Computed allowed error rate = 1 - target_fraction';
COMMENT ON COLUMN sla_slos.timeslice_interval IS 'Granularity of SLI buckets, e.g. 5 minutes';

CREATE UNIQUE INDEX IF NOT EXISTS ux_sla_slos_unique
  ON sla_slos (service_name, env, sli_name, objective_type)
  WHERE active IS TRUE;

CREATE INDEX IF NOT EXISTS ix_sla_slos_env_service
  ON sla_slos (env, service_name);

-- -------------------------------
-- Table: sla_buckets (Partitioned)
-- Timeslice SLI data aggregated per SLO
-- -------------------------------
CREATE TABLE IF NOT EXISTS sla_buckets (
  id              BIGSERIAL,
  slo_id          BIGINT NOT NULL,
  bucket_start    TIMESTAMPTZ NOT NULL,
  bucket_end      TIMESTAMPTZ NOT NULL,
  -- SLI aggregation: counts
  good_events     BIGINT NOT NULL CHECK (good_events >= 0),
  bad_events      BIGINT NOT NULL CHECK (bad_events  >= 0),
  total_events    BIGINT GENERATED ALWAYS AS (good_events + bad_events) STORED,
  -- Optional latency accumulator (for latency SLI)
  sum_latency_ms  NUMERIC(20,6),
  -- Optional arbitrary numeric SLI (e.g., error_ratio in [0..1])
  sli_value       NUMERIC(18,8),
  attributes      JSONB NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT pk_sla_buckets PRIMARY KEY (slo_id, bucket_start),
  CONSTRAINT fk_sla_buckets_slo
    FOREIGN KEY (slo_id) REFERENCES sla_slos(id) ON DELETE CASCADE,
  CONSTRAINT ck_bucket_bounds CHECK (bucket_end > bucket_start)
) PARTITION BY RANGE (bucket_start);

COMMENT ON TABLE sla_buckets IS 'Time-sliced SLI aggregates per SLO (partitioned by time)';
COMMENT ON COLUMN sla_buckets.sli_value IS 'Optional precomputed SLI (e.g., success ratio) for custom objectives';

-- Default partition to prevent insert failures for gaps
CREATE TABLE IF NOT EXISTS sla_buckets_default
  PARTITION OF sla_buckets DEFAULT;

-- Helpful index on default partition (others inherit)
CREATE INDEX IF NOT EXISTS ix_sla_buckets_default_slo_ts
  ON sla_buckets_default (slo_id, bucket_start DESC);

-- Create rolling monthly partitions (-1 .. +24 months)
DO $$
DECLARE
  start_month DATE := date_trunc('month', now())::date - INTERVAL '1 month';
  i INT;
  part_start DATE;
  part_end   DATE;
  part_name  TEXT;
BEGIN
  FOR i IN 0..24 LOOP
    part_start := (start_month + (i || ' months')::interval)::date;
    part_end   := (date_trunc('month', part_start::timestamp) + INTERVAL '1 month')::date;
    part_name  := format('sla_buckets_p_%s', to_char(part_start, 'YYYYMM'));

    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I PARTITION OF chronowatch.sla_buckets
         FOR VALUES FROM (%L) TO (%L);',
      part_name, part_start, part_end
    );

    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS %I ON chronowatch.%I (slo_id, bucket_start DESC);',
      part_name || '_slo_ts_idx', part_name
    );
  END LOOP;
END$$;

-- -------------------------------
-- Table: sla_incidents
-- Production incidents linked to SLO(s)
-- -------------------------------
CREATE TABLE IF NOT EXISTS sla_incidents (
  id             BIGSERIAL PRIMARY KEY,
  slo_id         BIGINT NOT NULL,
  started_at     TIMESTAMPTZ NOT NULL,
  ended_at       TIMESTAMPTZ,
  severity       TEXT NOT NULL CHECK (severity IN ('sev1','sev2','sev3','sev4')),
  cause          TEXT,              -- short classifier/cause code
  summary        TEXT,              -- human summary
  details        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT fk_incident_slo
    FOREIGN KEY (slo_id) REFERENCES sla_slos(id) ON DELETE CASCADE,
  CONSTRAINT ck_incident_bounds CHECK (ended_at IS NULL OR ended_at > started_at)
);

COMMENT ON TABLE sla_incidents IS 'Incidents affecting SLOs with optional linkage to root cause';
CREATE INDEX IF NOT EXISTS ix_incidents_slo_ts ON sla_incidents (slo_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_open ON sla_incidents (slo_id) WHERE ended_at IS NULL;

-- -------------------------------
-- Materialized view: mv_slo_status
-- One row per SLO with rolling-window evaluation
-- -------------------------------
-- Base MV provides per-SLO 30d status by default;
-- window uses each row's sla_slos.window_duration & timeslice_interval.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_slo_status AS
WITH now_ts AS (SELECT now() AS ts),
win AS (
  SELECT
    s.id AS slo_id,
    s.service_name,
    s.env,
    s.sli_name,
    s.objective_type,
    s.target_fraction,
    s.allowed_error_rate,
    s.window_duration,
    s.timeslice_interval
  FROM sla_slos s
  WHERE s.active IS TRUE
),
agg AS (
  SELECT
    w.slo_id,
    sum(b.good_events)    AS good_30d,
    sum(b.bad_events)     AS bad_30d,
    sum(b.total_events)   AS total_30d
  FROM win w
  JOIN sla_buckets b
    ON b.slo_id = w.slo_id
   AND b.bucket_start >= (SELECT ts FROM now_ts) - w.window_duration
  GROUP BY w.slo_id
),
short AS (
  SELECT slo_id,
         sum(b.bad_events)   AS bad_1h,
         sum(b.total_events) AS total_1h
  FROM sla_buckets b
  WHERE b.bucket_start >= (SELECT ts FROM now_ts) - INTERVAL '1 hour'
  GROUP BY slo_id
),
long AS (
  SELECT slo_id,
         sum(b.bad_events)   AS bad_6h,
         sum(b.total_events) AS total_6h
  FROM sla_buckets b
  WHERE b.bucket_start >= (SELECT ts FROM now_ts) - INTERVAL '6 hours'
  GROUP BY slo_id
)
SELECT
  w.slo_id,
  w.service_name,
  w.env,
  w.sli_name,
  w.objective_type,
  w.target_fraction,
  w.allowed_error_rate,
  w.window_duration,
  w.timeslice_interval,

  COALESCE(a.good_30d, 0)  AS good_30d,
  COALESCE(a.bad_30d, 0)   AS bad_30d,
  COALESCE(a.total_30d, 0) AS total_30d,

  CASE
    WHEN COALESCE(a.total_30d,0) = 0 THEN NULL
    ELSE (COALESCE(a.good_30d,0)::numeric / NULLIF(a.total_30d,0))
  END AS sli_30d,

  CASE
    WHEN w.allowed_error_rate IS NULL OR COALESCE(a.total_30d,0) = 0 THEN NULL
    ELSE GREATEST(0, 1 - (COALESCE(a.bad_30d,0)::numeric / (a.total_30d * w.allowed_error_rate)))
  END AS error_budget_remaining,

  -- Burn rates: short/long observed error-rate divided by allowed error-rate
  CASE
    WHEN w.allowed_error_rate IS NULL THEN NULL
    WHEN COALESCE(s.total_1h,0) = 0 THEN NULL
    ELSE LEAST(1000, (COALESCE(s.bad_1h,0)::numeric / NULLIF(s.total_1h,0)) / NULLIF(w.allowed_error_rate,0))
  END AS burn_rate_1h,

  CASE
    WHEN w.allowed_error_rate IS NULL THEN NULL
    WHEN COALESCE(l.total_6h,0) = 0 THEN NULL
    ELSE LEAST(1000, (COALESCE(l.bad_6h,0)::numeric / NULLIF(l.total_6h,0)) / NULLIF(w.allowed_error_rate,0))
  END AS burn_rate_6h,

  now() AS computed_at
FROM win w
LEFT JOIN agg   a ON a.slo_id = w.slo_id
LEFT JOIN short s ON s.slo_id = w.slo_id
LEFT JOIN long  l ON l.slo_id = w.slo_id
WITH NO DATA;

-- Unique index is required for CONCURRENTLY refresh
CREATE UNIQUE INDEX IF NOT EXISTS ux_mv_slo_status_slo_id
  ON mv_slo_status (slo_id);

COMMENT ON MATERIALIZED VIEW mv_slo_status IS 'Per-SLO rolling status with SLI, error budget remaining and burn rates';

-- -------------------------------
-- Functions
-- -------------------------------

-- Compute error budget remaining for a given SLO now() using its window_duration.
CREATE OR REPLACE FUNCTION fn_slo_error_budget_remaining(p_slo_id BIGINT)
RETURNS NUMERIC LANGUAGE sql STABLE AS $$
  WITH s AS (
    SELECT id, allowed_error_rate, window_duration FROM sla_slos WHERE id = p_slo_id
  ),
  a AS (
    SELECT
      sum(b.bad_events)::numeric AS bad,
      sum(b.total_events)::numeric AS total
    FROM sla_buckets b
    JOIN s ON b.slo_id = s.id
    WHERE b.bucket_start >= now() - s.window_duration
  )
  SELECT
    CASE
      WHEN s.allowed_error_rate IS NULL OR COALESCE(a.total,0) = 0 THEN NULL
      ELSE GREATEST(0, 1 - (COALESCE(a.bad,0) / NULLIF(a.total * s.allowed_error_rate,0)))
    END
  FROM s, a;
$$;

COMMENT ON FUNCTION fn_slo_error_budget_remaining(BIGINT)
  IS 'Returns fraction of error budget remaining for SLO at current time';

-- Refresh MV; use CONCURRENTLY to avoid long locks if possible
CREATE OR REPLACE FUNCTION fn_refresh_mv_slo_status()
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM pg_matviews WHERE schemaname = 'chronowatch' AND matviewname = 'mv_slo_status';
  IF FOUND THEN
    -- Requires unique index on mv
    EXECUTE 'REFRESH MATERIALIZED VIEW CONCURRENTLY chronowatch.mv_slo_status';
  END IF;
END$$;

-- -------------------------------
-- Grants (optional; no-op if role absent)
-- -------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chronowatch_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON sla_slos, sla_buckets, sla_incidents TO chronowatch_app;
    GRANT SELECT ON mv_slo_status TO chronowatch_app;
  END IF;
END$$;

-- -------------------------------
-- Housekeeping constraints & indexes
-- -------------------------------
-- Ensure buckets align to SLO timeslice (soft check via interval divisibility)
-- (Informational; strict enforcement typically happens in ingestion layer)
CREATE OR REPLACE FUNCTION ck_bucket_alignment()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  ts INTERVAL;
BEGIN
  SELECT timeslice_interval INTO ts FROM sla_slos WHERE id = NEW.slo_id;
  IF ts IS NULL THEN
    RETURN NEW;
  END IF;
  -- If misaligned more than 1 second, raise notice (do not block ingestion)
  IF abs(extract(epoch FROM (NEW.bucket_start - date_trunc('minute', NEW.bucket_start)))) > 1 THEN
    RAISE NOTICE 'Bucket start is not minute-aligned: %', NEW.bucket_start;
  END IF;
  RETURN NEW;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_ck_bucket_alignment' AND tgrelid = 'chronowatch.sla_buckets_default'::regclass
  ) THEN
    EXECUTE 'CREATE TRIGGER trg_ck_bucket_alignment
             BEFORE INSERT ON chronowatch.sla_buckets_default
             FOR EACH ROW EXECUTE FUNCTION chronowatch.ck_bucket_alignment()';
  END IF;
END$$;

COMMIT;
