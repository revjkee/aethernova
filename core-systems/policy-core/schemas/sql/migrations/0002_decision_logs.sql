-- =============================================================================
-- Migration: 0002_decision_logs.sql
-- Purpose : Decision logs storage (partitioned, secure, scalable)
-- Target  : PostgreSQL 13+ (recommended 14/15/16)
-- =============================================================================

-- Safety & timeouts
SET statement_timeout = 0;
SET lock_timeout = '5s';
SET idle_in_transaction_session_timeout = '15min';
SET client_min_messages = WARNING;

-- Schema
CREATE SCHEMA IF NOT EXISTS policy;

-- Extensions (used for gen_random_uuid, digest, etc.)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -----------------------------------------------------------------------------
-- Enum types (created idempotently)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typnamespace = 'policy'::regnamespace AND typname = 'decision_effect') THEN
    CREATE TYPE policy.decision_effect AS ENUM ('ALLOW','DENY','SHADOW_ALLOW','ERROR','INDETERMINATE');
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typnamespace = 'policy'::regnamespace AND typname = 'decision_mode') THEN
    CREATE TYPE policy.decision_mode AS ENUM ('enforce','monitor');
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Main partitioned table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy.decision_logs
(
  id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id         TEXT    NOT NULL,
  namespace         TEXT    NOT NULL,
  subject_id        TEXT    NOT NULL,
  subject_role      TEXT,
  service_account   BOOLEAN NOT NULL DEFAULT FALSE,

  policy_id         TEXT,
  policy_version    TEXT,
  rule_name         TEXT,
  rule_version      TEXT,

  resource          TEXT,
  action            TEXT,
  effect            policy.decision_effect NOT NULL,
  mode              policy.decision_mode   NOT NULL DEFAULT 'enforce',

  request_hash      BYTEA,                         -- SHA-256/xxhash и т.п.
  trace_id          TEXT,
  span_id           TEXT,

  ingress_ip        INET,
  user_agent        TEXT,

  latency_ms        INTEGER NOT NULL CHECK (latency_ms >= 0),
  decided_at        TIMESTAMPTZ NOT NULL DEFAULT now(),  -- время принятия решения (ключ партиционирования)
  ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),  -- время записи в БД

  attrs             JSONB   NOT NULL DEFAULT '{}'::jsonb,

  -- Доп. инварианты
  CONSTRAINT decision_logs_ns_ck CHECK (namespace <> ''),
  CONSTRAINT decision_logs_subject_ck CHECK (subject_id <> ''),

  -- Не жёсткий уникальный ключ, но защищает от очевидных дублей, если trace_id есть
  CONSTRAINT decision_logs_trace_unique UNIQUE (tenant_id, trace_id) DEFERRABLE INITIALLY DEFERRED
)
PARTITION BY RANGE (decided_at);

COMMENT ON TABLE policy.decision_logs IS
  'Append-only лог решений политик. Партиционирование по месяцу для высокой пропускной способности и ретенции.';
COMMENT ON COLUMN policy.decision_logs.attrs IS
  'Произвольные метаданные решения (JSONB). Хранить только безопасные к публикации атрибуты.';

-- -----------------------------------------------------------------------------
-- Partitioned indexes (btree). Эти индексы создаются на родителе и материализуются на партициях.
-- -----------------------------------------------------------------------------
-- По основному access-паттерну: запросы по tenant + временной интервал
CREATE INDEX IF NOT EXISTS decision_logs_pidx_tenant_time
  ON policy.decision_logs USING btree (tenant_id, decided_at DESC);

-- Трассировка
CREATE INDEX IF NOT EXISTS decision_logs_pidx_trace
  ON policy.decision_logs USING btree (trace_id);

-- По хэшу запроса (для дедупликации/поиска аналогичных запросов)
CREATE INDEX IF NOT EXISTS decision_logs_pidx_reqhash
  ON policy.decision_logs USING btree (request_hash);

-- По эффекту (фильтрация DENY/ERROR)
CREATE INDEX IF NOT EXISTS decision_logs_pidx_effect_time
  ON policy.decision_logs USING btree (effect, decided_at DESC);

-- -----------------------------------------------------------------------------
-- Helper: naming and range helpers for monthly partitions
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION policy._partition_name_for(ts timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT format('decision_logs_%s_%s',
                to_char(timezone('UTC', $1), 'YYYY'),
                to_char(timezone('UTC', $1), 'MM'));
$$;

CREATE OR REPLACE FUNCTION policy._month_bounds(ts timestamptz)
RETURNS TABLE (from_ts timestamptz, to_ts timestamptz)
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT date_trunc('month', $1) AS from_ts,
         (date_trunc('month', $1) + INTERVAL '1 month') AS to_ts;
$$;

-- -----------------------------------------------------------------------------
-- Function: ensure partition exists for month of supplied timestamp
-- Creates partition and per-partition BRIN index for decided_at
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION policy.ensure_decision_logs_partition(ts timestamptz)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  part_name text;
  from_ts   timestamptz;
  to_ts     timestamptz;
  exists_already boolean;
BEGIN
  SELECT policy._partition_name_for(ts), b.from_ts, b.to_ts
    INTO part_name, from_ts, to_ts
  FROM policy._month_bounds(ts) AS b;

  SELECT EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'policy'
      AND c.relname = part_name
  ) INTO exists_already;

  IF exists_already THEN
    RETURN;
  END IF;

  EXECUTE format($fmt$
    CREATE TABLE policy.%I
    PARTITION OF policy.decision_logs
    FOR VALUES FROM (%L) TO (%L)
  $fmt$, part_name, from_ts, to_ts);

  -- BRIN на каждой секции для ускорения сканов по времени при больших объемах
  EXECUTE format($fmt$
    CREATE INDEX %I_brin_decided_at
    ON policy.%I
    USING BRIN (decided_at)
    WITH (pages_per_range = 64)
  $fmt$, part_name, part_name);
END;
$$;

COMMENT ON FUNCTION policy.ensure_decision_logs_partition(timestamptz) IS
  'Создаёт месячную партицию для указанного времени и BRIN-индекс decided_at. Идемпотентно.';

-- -----------------------------------------------------------------------------
-- Function: bulk ensure partitions for current +/- N months
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION policy.ensure_decision_logs_partitions_span(past_months int, future_months int)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  i int;
BEGIN
  FOR i IN -GREATEST(past_months,0)..GREATEST(future_months,0) LOOP
    PERFORM policy.ensure_decision_logs_partition(date_trunc('month', now()) + make_interval(months => i));
  END LOOP;
END;
$$;

-- -----------------------------------------------------------------------------
-- Retention: drop old partitions older than retain_months
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION policy.drop_old_decision_logs_partitions(retain_months int)
RETURNS int
LANGUAGE plpgsql
AS $$
DECLARE
  dropped int := 0;
  cutoff timestamptz := date_trunc('month', now()) - make_interval(months => retain_months);
  r record;
BEGIN
  FOR r IN
    SELECT c.relname AS part_name
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE p.relname = 'decision_logs' AND n.nspname = 'policy'
  LOOP
    -- извлекаем YYYY_MM из имени и вычисляем конец диапазона
    -- имя ожидается как decision_logs_YYYY_MM
    IF r.part_name ~ '^decision_logs_[0-9]{4}_[0-9]{2}$' THEN
      PERFORM 1; -- no-op
      EXECUTE format($f$
        SELECT to_timestamp((regexp_replace(%L, '^decision_logs_([0-9]{4})_([0-9]{2})$', '\1-\2-01') || ' 00:00:00') , 'YYYY-MM-DD HH24:MI:SS')::timestamptz
      $f$, r.part_name)
      INTO STRICT cutoff; -- временно используем переменную (переопределим ниже)
    END IF;
  END LOOP;
  -- Удаляем через вычисление по каталогу (без переиспользования cutoff из цикла)
  FOR r IN
    SELECT c.relname AS part_name
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE p.relname = 'decision_logs' AND n.nspname = 'policy'
    ORDER BY c.relname
  LOOP
    IF r.part_name ~ '^decision_logs_[0-9]{4}_[0-9]{2}$' THEN
      -- вычисляем верхнюю границу партиции
      PERFORM 1;
      EXECUTE format($q$
        SELECT (date_trunc('month', to_date(regexp_replace(%L, '^decision_logs_([0-9]{4})_([0-9]{2})$', '\1-\2-01'), 'YYYY-MM-DD')) + INTERVAL '1 month')::timestamptz
      $q$, r.part_name)
      INTO STRICT cutoff;
      IF cutoff < (date_trunc('month', now()) - make_interval(months => retain_months)) THEN
        EXECUTE format('DROP TABLE IF EXISTS policy.%I', r.part_name);
        dropped := dropped + 1;
      END IF;
    END IF;
  END LOOP;
  RETURN dropped;
END;
$$;

COMMENT ON FUNCTION policy.drop_old_decision_logs_partitions(int) IS
  'Удаляет партиции старше retain_months от текущего месяца. Возвращает количество удалённых.';

-- -----------------------------------------------------------------------------
-- Seed initial partitions: предыдущий месяц, текущий, +6 месяцев вперёд
-- -----------------------------------------------------------------------------
SELECT policy.ensure_decision_logs_partitions_span(1, 6);

-- -----------------------------------------------------------------------------
-- Row Level Security (RLS): изоляция чтения по tenant.
-- Ожидается, что приложение устанавливает SET LOCAL app.tenant_id = '<id>';
-- -----------------------------------------------------------------------------
ALTER TABLE policy.decision_logs ENABLE ROW LEVEL SECURITY;

-- Админская роль (полный доступ) и прикладная роль
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_core_admin') THEN
    CREATE ROLE policy_core_admin NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_core_app') THEN
    CREATE ROLE policy_core_app NOINHERIT;
  END IF;
END$$;

GRANT USAGE ON SCHEMA policy TO policy_core_admin, policy_core_app;

-- Права по таблице (append-only характер для приложения)
GRANT INSERT, SELECT ON policy.decision_logs TO policy_core_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON policy.decision_logs TO policy_core_admin;

-- RLS-политика на чтение: tenant_id должен совпадать с current_setting('app.tenant_id')
DROP POLICY IF EXISTS tenant_read ON policy.decision_logs;
CREATE POLICY tenant_read ON policy.decision_logs
  FOR SELECT
  TO policy_core_app
  USING (tenant_id = current_setting('app.tenant_id', true));

-- Запись приложением разрешена без ограничений RLS (append-only)
DROP POLICY IF EXISTS app_insert ON policy.decision_logs;
CREATE POLICY app_insert ON policy.decision_logs
  FOR INSERT
  TO policy_core_app
  WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- Comments for governance/audit
-- -----------------------------------------------------------------------------
COMMENT ON COLUMN policy.decision_logs.effect IS 'Результат: ALLOW/DENY/SHADOW_ALLOW/ERROR/INDETERMINATE';
COMMENT ON COLUMN policy.decision_logs.mode   IS 'Режим: enforce|monitor';
COMMENT ON COLUMN policy.decision_logs.request_hash IS 'Хеш существенных полей запроса для корреляции/дедупликации';
COMMENT ON COLUMN policy.decision_logs.trace_id IS 'Trace ID для связки с трейсингом';
COMMENT ON COLUMN policy.decision_logs.latency_ms IS 'Время вычисления решения на стороне приложения/сервиса';

-- =============================================================================
-- END
-- =============================================================================
