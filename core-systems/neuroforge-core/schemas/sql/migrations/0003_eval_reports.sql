-- File: neuroforge-core/schemas/sql/migrations/0003_eval_reports.sql
-- Purpose: Evaluation reports storage (industrial-grade)
-- Target: PostgreSQL 14+ (recommended 15/16)
-- Notes:
--  - Uses pgcrypto for gen_random_uuid()
--  - Monthly range partitioning by started_at
--  - RLS enforced by tenant_id
--  - JSONB metrics with GIN index
--  - Auditing to *_audit table

BEGIN;

-- ---------------------------------------------------------------------------
-- Extensions (idempotent)
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gin;    -- combined GIN ops

-- ---------------------------------------------------------------------------
-- Schema
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'neuroforge') THEN
    EXECUTE 'CREATE SCHEMA neuroforge';
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Roles (optional, created if not exist)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'neuroforge_app') THEN
    EXECUTE 'CREATE ROLE neuroforge_app NOINHERIT';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'neuroforge_readonly') THEN
    EXECUTE 'CREATE ROLE neuroforge_readonly NOINHERIT';
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'eval_status_enum') THEN
    CREATE TYPE neuroforge.eval_status_enum AS ENUM (
      'queued', 'running', 'succeeded', 'failed', 'canceled'
    );
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Parent partitioned table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS neuroforge.eval_reports (
  eval_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          UUID NOT NULL,                            -- RLS scope
  run_key            TEXT NOT NULL,                            -- идемпотентность (уникальна в аренде)
  model_id           UUID,                                     -- справочник моделей (если есть)
  dataset_id         UUID,                                     -- справочник датасетов (если есть)
  model_version      TEXT,                                     -- произвольная семантика версий модели
  artifact_version   TEXT,                                     -- версия артефакта/билда
  commit_sha         TEXT,                                     -- git sha, если применимо

  status             neuroforge.eval_status_enum NOT NULL DEFAULT 'queued',
  started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at       TIMESTAMPTZ,
  duration_ms        BIGINT GENERATED ALWAYS AS (
                       CASE
                         WHEN completed_at IS NOT NULL
                           THEN GREATEST(0, (EXTRACT(EPOCH FROM (completed_at - started_at))*1000)::BIGINT)
                         ELSE NULL
                       END
                     ) STORED,

  metrics            JSONB NOT NULL DEFAULT '{}'::jsonb,       -- числовые/категориальные метрики
  summary            JSONB NOT NULL DEFAULT '{}'::jsonb,       -- агрегаты/выводы
  tags               TEXT[] NOT NULL DEFAULT '{}'::text[],     -- произвольные метки
  trace_id           BYTEA,                                    -- 16 байт
  span_id            BYTEA,                                    -- 8 байт
  error_message      TEXT,
  artifacts_uri      TEXT,                                     -- где лежат артефакты/логи
  evidence_uri       TEXT,                                     -- bundle с доказательствами
  slsa_provenance    JSONB,                                    -- in-toto SLSA predicate (сжатая форма)
  sbom_ref           TEXT,                                     -- ссылка на SBOM

  retention_at       TIMESTAMPTZ,                              -- момент, после которого запись можно удалять
  created_by         TEXT,                                     -- субъект (login/service)
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT eval_reports_status_completion_chk
    CHECK (
      (status IN ('queued','running') AND completed_at IS NULL)
      OR (status IN ('succeeded','failed','canceled') AND completed_at IS NOT NULL)
    ),

  CONSTRAINT eval_reports_trace_len_chk
    CHECK (
      (trace_id IS NULL OR octet_length(trace_id) = 16) AND
      (span_id  IS NULL OR octet_length(span_id)  = 8)
    ),

  CONSTRAINT eval_reports_run_key_uniq UNIQUE (tenant_id, run_key)
) PARTITION BY RANGE (started_at);

COMMENT ON TABLE  neuroforge.eval_reports IS 'Evaluation reports (partitioned monthly by started_at)';
COMMENT ON COLUMN neuroforge.eval_reports.metrics         IS 'Raw KPIs (JSONB), indexed via GIN';
COMMENT ON COLUMN neuroforge.eval_reports.summary         IS 'Summarized evaluation outcomes';
COMMENT ON COLUMN neuroforge.eval_reports.retention_at    IS 'Soft-retention cutoff; used by retention jobs';
COMMENT ON COLUMN neuroforge.eval_reports.run_key         IS 'Idempotency key unique within tenant';
COMMENT ON COLUMN neuroforge.eval_reports.status          IS 'queued|running|succeeded|failed|canceled';

-- ---------------------------------------------------------------------------
-- Current and next month partitions (rolling window bootstrap)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  first_of_month DATE := date_trunc('month', now())::date;
  next_month     DATE := (date_trunc('month', now()) + interval '1 month')::date;
BEGIN
  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS neuroforge.eval_reports_%1$s
    PARTITION OF neuroforge.eval_reports
    FOR VALUES FROM (%L) TO (%L)$f$,
    to_char(first_of_month, 'YYYYMM'),
    first_of_month, next_month
  );

  -- also create previous month for late arrivals
  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS neuroforge.eval_reports_%1$s
    PARTITION OF neuroforge.eval_reports
    FOR VALUES FROM (%L) TO (%L)$f$,
    to_char(first_of_month - interval '1 month', 'YYYYMM'),
    (first_of_month - interval '1 month')::date, first_of_month
  );
END$$;

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
-- Global indexes on parent are not supported; create on each partition using template function
CREATE OR REPLACE FUNCTION neuroforge._ensure_eval_reports_indexes(p_rel regclass)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE format('
    DO $ix$
    BEGIN
      -- Composite index for typical queries by tenant+time+status
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = %L AND tablename = %L AND indexname = %L
      ) THEN
        EXECUTE %L;
      END IF;

      -- JSONB GIN on metrics
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = %L AND tablename = %L AND indexname = %L
      ) THEN
        EXECUTE %L;
      END IF;

      -- Partial for failed recent
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = %L AND tablename = %L AND indexname = %L
      ) THEN
        EXECUTE %L;
      END IF;
    END$ix$;',
    -- 1st index
    nspname(p_rel), relname(p_rel), relname(p_rel)||'_tenant_time_status_idx',
    format('CREATE INDEX %I ON %s USING btree (tenant_id, started_at DESC, status)', relname(p_rel)||'_tenant_time_status_idx', p_rel::text),
    -- 2nd index (GIN on metrics)
    nspname(p_rel), relname(p_rel), relname(p_rel)||'_metrics_gin',
    format('CREATE INDEX %I ON %s USING GIN (metrics jsonb_path_ops)', relname(p_rel)||'_metrics_gin', p_rel::text),
    -- 3rd index (partial failed in last 7d)
    nspname(p_rel), relname(p_rel), relname(p_rel)||'_failed_recent_idx',
    format('CREATE INDEX %I ON %s (started_at DESC) WHERE status = %L AND started_at >= now() - interval %L',
           relname(p_rel)||'_failed_recent_idx', p_rel::text, 'failed', '7 days')
  );
END$$;

-- Apply indexes to existing partitions
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT c.oid
    FROM   pg_class c
    JOIN   pg_namespace n ON n.oid = c.relnamespace
    WHERE  n.nspname = 'neuroforge'
    AND    c.relname LIKE 'eval_reports_%'
    AND    c.relkind = 'r'
  LOOP
    PERFORM neuroforge._ensure_eval_reports_indexes(r.oid);
  END LOOP;
END$$;

-- ---------------------------------------------------------------------------
-- Triggers: updated_at & retention_at defaults via GUC
-- ---------------------------------------------------------------------------
-- Optional GUC: neuroforge.retention_days (integer). If absent, default 365.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = '_eval_reports_biud') THEN
    CREATE FUNCTION neuroforge._eval_reports_biud()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $FN$
    DECLARE
      v_days int;
    BEGIN
      -- updated_at always now()
      NEW.updated_at := now();

      -- retention_at: respect explicit value, otherwise derive from started_at + retention_days
      IF NEW.retention_at IS NULL THEN
        BEGIN
          v_days := current_setting('neuroforge.retention_days')::int;
        EXCEPTION WHEN others THEN
          v_days := 365;
        END;
        NEW.retention_at := NEW.started_at + make_interval(days => v_days);
      END IF;

      RETURN NEW;
    END$FN$;
  END IF;
END$$;

DROP TRIGGER IF EXISTS trg_eval_reports_biud ON neuroforge.eval_reports;
CREATE TRIGGER trg_eval_reports_biud
BEFORE INSERT OR UPDATE ON neuroforge.eval_reports
FOR EACH ROW
EXECUTE FUNCTION neuroforge._eval_reports_biud();

-- ---------------------------------------------------------------------------
-- Auditing (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS neuroforge.eval_reports_audit (
  audit_id     BIGSERIAL PRIMARY KEY,
  action       TEXT NOT NULL,                             -- INSERT|UPDATE|DELETE
  action_ts    TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor        TEXT,                                      -- session_user / jwt.sub (пробрасывается приложением)
  tenant_id    UUID,
  eval_id      UUID,
  old_row      JSONB,
  new_row      JSONB
);

COMMENT ON TABLE neuroforge.eval_reports_audit IS 'Audit trail for eval_reports (append-only)';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = '_eval_reports_audit') THEN
    CREATE FUNCTION neuroforge._eval_reports_audit()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $AUD$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO neuroforge.eval_reports_audit(action, actor, tenant_id, eval_id, new_row)
        VALUES ('INSERT', current_setting('app.current_actor', true), NEW.tenant_id, NEW.eval_id, to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO neuroforge.eval_reports_audit(action, actor, tenant_id, eval_id, old_row, new_row)
        VALUES ('UPDATE', current_setting('app.current_actor', true), NEW.tenant_id, NEW.eval_id, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO neuroforge.eval_reports_audit(action, actor, tenant_id, eval_id, old_row)
        VALUES ('DELETE', current_setting('app.current_actor', true), OLD.tenant_id, OLD.eval_id, to_jsonb(OLD));
        RETURN OLD;
      END IF;
      RETURN NULL;
    END$AUD$;
  END IF;
END$$;

DROP TRIGGER IF EXISTS trg_eval_reports_audit_iud ON neuroforge.eval_reports;
CREATE TRIGGER trg_eval_reports_audit_iud
AFTER INSERT OR UPDATE OR DELETE ON neuroforge.eval_reports
FOR EACH ROW EXECUTE FUNCTION neuroforge._eval_reports_audit();

-- ---------------------------------------------------------------------------
-- RLS (Row-Level Security)
-- ---------------------------------------------------------------------------
ALTER TABLE neuroforge.eval_reports ENABLE ROW LEVEL SECURITY;

-- Policy: tenants may only see their rows (assumes SET app.current_tenant = '<uuid>')
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='neuroforge' AND tablename='eval_reports' AND policyname='tenant_isolation_sel') THEN
    EXECUTE $P$
      CREATE POLICY tenant_isolation_sel ON neuroforge.eval_reports
      FOR SELECT USING (
        current_setting('app.current_tenant', true)::uuid = tenant_id
      )$P$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='neuroforge' AND tablename='eval_reports' AND policyname='tenant_isolation_mod') THEN
    EXECUTE $P$
      CREATE POLICY tenant_isolation_mod ON neuroforge.eval_reports
      FOR ALL USING (
        current_setting('app.current_tenant', true)::uuid = tenant_id
      ) WITH CHECK (
        current_setting('app.current_tenant', true)::uuid = tenant_id
      )$P$;
  END IF;
END$$;

-- Grants
GRANT USAGE ON SCHEMA neuroforge TO neuroforge_app, neuroforge_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA neuroforge TO neuroforge_app;
GRANT SELECT ON ALL TABLES IN SCHEMA neuroforge TO neuroforge_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA neuroforge GRANT SELECT ON TABLES TO neuroforge_readonly;

-- ---------------------------------------------------------------------------
-- Views for common queries
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW neuroforge.v_latest_eval_per_model AS
SELECT DISTINCT ON (tenant_id, model_id)
  tenant_id, model_id, eval_id, status, started_at, completed_at, duration_ms,
  metrics, summary, tags, artifact_version, model_version
FROM neuroforge.eval_reports
WHERE status = 'succeeded'
ORDER BY tenant_id, model_id, started_at DESC;

COMMENT ON VIEW neuroforge.v_latest_eval_per_model IS 'Last succeeded evaluation per model per tenant';

-- Fast filtering helpers via jsonb_path_ops (examples)
CREATE OR REPLACE VIEW neuroforge.v_failed_recent AS
SELECT *
FROM neuroforge.eval_reports
WHERE status = 'failed'
  AND started_at >= now() - interval '7 days';

-- ---------------------------------------------------------------------------
-- Optional FKs to external catalogs (create only if targets exist)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='neuroforge' AND c.relname='models') THEN
    -- Model FK
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='eval_reports_model_fk') THEN
      ALTER TABLE neuroforge.eval_reports
        ADD CONSTRAINT eval_reports_model_fk
        FOREIGN KEY (model_id) REFERENCES neuroforge.models(model_id)
        ON UPDATE CASCADE ON DELETE SET NULL;
    END IF;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='neuroforge' AND c.relname='datasets') THEN
    -- Dataset FK
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='eval_reports_dataset_fk') THEN
      ALTER TABLE neuroforge.eval_reports
        ADD CONSTRAINT eval_reports_dataset_fk
        FOREIGN KEY (dataset_id) REFERENCES neuroforge.datasets(dataset_id)
        ON UPDATE CASCADE ON DELETE SET NULL;
    END IF;
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Maintenance helper: create partition for a given month (YYYYMM)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION neuroforge.ensure_eval_reports_partition(month_yyyymm TEXT)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  y int := substring(month_yyyymm,1,4)::int;
  m int := substring(month_yyyymm,5,2)::int;
  start_date date := make_date(y,m,1);
  end_date   date := (make_date(y,m,1) + interval '1 month')::date;
  part_name  text := format('eval_reports_%s', month_yyyymm);
BEGIN
  EXECUTE format('
    CREATE TABLE IF NOT EXISTS neuroforge.%I
    PARTITION OF neuroforge.eval_reports
    FOR VALUES FROM (%L) TO (%L)
  ', part_name, start_date, end_date);
  PERFORM neuroforge._ensure_eval_reports_indexes(format('neuroforge.%I', part_name)::regclass);
END$$;

COMMENT ON FUNCTION neuroforge.ensure_eval_reports_partition(TEXT)
  IS 'Create monthly partition for eval_reports and ensure indexes';

COMMIT;

-- End of migration 0003_eval_reports.sql
