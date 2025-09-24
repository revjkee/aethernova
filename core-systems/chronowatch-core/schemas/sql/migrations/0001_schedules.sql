-- 0001_schedules.sql
-- Chronowatch Core: Schedules subsystem (PostgreSQL 13+)
-- Idempotent, production-grade.

BEGIN;

-- -----------------------------------------------------------------------------
-- Schema & Extensions
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS chronowatch;

-- UUIDs, strong indexing helpers
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

-- -----------------------------------------------------------------------------
-- Helper: resolve schema OID for IF NOT EXISTS on types
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'schedule_kind' AND n.nspname = 'chronowatch'
  ) THEN
    CREATE TYPE chronowatch.schedule_kind AS ENUM ('cron','interval','oneoff');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'schedule_state' AND n.nspname = 'chronowatch'
  ) THEN
    CREATE TYPE chronowatch.schedule_state AS ENUM ('enabled','paused','disabled');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typname = 'run_status' AND n.nspname = 'chronowatch'
  ) THEN
    CREATE TYPE chronowatch.run_status AS ENUM ('scheduled','running','success','failed','canceled','skipped','timeout');
  END IF;
END $$;

COMMENT ON TYPE chronowatch.schedule_kind  IS 'Тип расписания: cron|interval|oneoff';
COMMENT ON TYPE chronowatch.schedule_state IS 'Состояние расписания: enabled|paused|disabled';
COMMENT ON TYPE chronowatch.run_status     IS 'Статус запуска расписания';

-- -----------------------------------------------------------------------------
-- Helpers: current tenant + validators (timezone, cron)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION chronowatch.current_tenant() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid;
$$;

COMMENT ON FUNCTION chronowatch.current_tenant() IS 'Возвращает текущий tenant_id из current_setting(app.tenant_id)';

CREATE OR REPLACE FUNCTION chronowatch.validate_timezone(tz text) RETURNS boolean
LANGUAGE plpgsql STABLE
AS $$
BEGIN
  IF tz IS NULL OR tz = '' THEN
    RETURN FALSE;
  END IF;
  -- Попытка применения таймзоны: исключение => некорректный идентификатор
  PERFORM now() AT TIME ZONE tz;
  RETURN TRUE;
EXCEPTION WHEN others THEN
  RETURN FALSE;
END;
$$;

COMMENT ON FUNCTION chronowatch.validate_timezone(text) IS 'Проверка валидности timezone с попыткой применения AT TIME ZONE';

CREATE OR REPLACE FUNCTION chronowatch.is_valid_cron(expr text) RETURNS boolean
LANGUAGE plpgsql STABLE
AS $$
DECLARE
  norm text;
  parts int;
  -- Разрешаем 5 или 6 полей (с секундами), допустимы *, числа, списки, диапазоны, шаги, буквенные месяцы/дни
  re_field constant text := '([0-9A-Za-z\*\?LW#\/,\-]+)';
BEGIN
  IF expr IS NULL OR btrim(expr) = '' THEN
    RETURN FALSE;
  END IF;

  -- Нормализуем пробелы
  norm := regexp_replace(btrim(expr), '\s+', ' ', 'g');
  parts := array_length(regexp_split_to_array(norm, ' '), 1);

  IF parts NOT IN (5,6) THEN
    RETURN FALSE;
  END IF;

  IF parts = 6 THEN
    RETURN norm ~ ('^' || re_field || ' ' || re_field || ' ' || re_field || ' ' || re_field || ' ' || re_field || ' ' || re_field || '$');
  ELSE
    RETURN norm ~ ('^' || re_field || ' ' || re_field || ' ' || re_field || ' ' || re_field || ' ' || re_field || '$');
  END IF;
END;
$$;

COMMENT ON FUNCTION chronowatch.is_valid_cron(text) IS 'Базовая валидация CRON (5/6 полей, допускает * ? L W # списки/диапазоны)';

-- -----------------------------------------------------------------------------
-- Audit helpers: touch updated_at + bump revision
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION chronowatch.tg_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  IF NEW.revision IS NULL THEN
    NEW.revision := 1;
  ELSE
    NEW.revision := NEW.revision + 1;
  END IF;
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION chronowatch.tg_touch_updated_at() IS 'Триггер: обновляет updated_at и увеличивает revision';

-- -----------------------------------------------------------------------------
-- TABLE: schedules
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chronowatch.schedules (
  schedule_id        uuid PRIMARY KEY DEFAULT public.gen_random_uuid(),
  tenant_id          uuid NOT NULL,
  name               text NOT NULL,
  description        text,
  owner              text,

  state              chronowatch.schedule_state NOT NULL DEFAULT 'enabled',
  kind               chronowatch.schedule_kind  NOT NULL,

  cron_expr          text,           -- kind=cron
  interval_ms        bigint,         -- kind=interval (миллисекунды)
  at_time            timestamptz,    -- kind=oneoff (абсолютное время)

  timezone           text NOT NULL DEFAULT 'UTC',

  start_after        timestamptz,    -- не запускать ранее
  end_before         timestamptz,    -- не запускать позже
  jitter_ms          integer NOT NULL DEFAULT 0 CHECK (jitter_ms BETWEEN 0 AND 86400000),
  max_drift_ms       integer NOT NULL DEFAULT 0 CHECK (max_drift_ms BETWEEN 0 AND 86400000),
  backfill_limit     integer NOT NULL DEFAULT 0 CHECK (backfill_limit BETWEEN 0 AND 100000),

  concurrency_limit  integer NOT NULL DEFAULT 1 CHECK (concurrency_limit BETWEEN 1 AND 1024),
  dedup_key          text,           -- ключ дедупликации (по группе)

  payload            jsonb NOT NULL DEFAULT '{}'::jsonb,
  labels             jsonb NOT NULL DEFAULT '{}'::jsonb,

  created_by         text,
  updated_by         text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz,
  revision           integer    NOT NULL DEFAULT 1,

  -- Взаимоисключающие требования по типу расписания
  CONSTRAINT schedules_kind_constraints CHECK (
    (kind = 'cron'     AND cron_expr IS NOT NULL AND interval_ms IS NULL AND at_time IS NULL)
 OR (kind = 'interval' AND interval_ms IS NOT NULL AND cron_expr IS NULL AND at_time IS NULL AND interval_ms >= 1000)
 OR (kind = 'oneoff'   AND at_time IS NOT NULL AND cron_expr IS NULL AND interval_ms IS NULL)
  ),

  -- Базовая валидация CRON
  CONSTRAINT schedules_cron_valid CHECK (
    kind <> 'cron' OR chronowatch.is_valid_cron(cron_expr)
  ),

  -- Валидность TZ
  CONSTRAINT schedules_tz_valid CHECK (chronowatch.validate_timezone(timezone)),

  -- Временные рамки
  CONSTRAINT schedules_time_window CHECK (end_before IS NULL OR start_after IS NULL OR end_before > start_after),

  -- JSON-форматы
  CONSTRAINT schedules_payload_object CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT schedules_labels_object  CHECK (jsonb_typeof(labels)  = 'object')
);

COMMENT ON TABLE  chronowatch.schedules IS 'Расписания задач/действий';
COMMENT ON COLUMN chronowatch.schedules.tenant_id         IS 'Идентификатор арендатора (мульти-тенантность)';
COMMENT ON COLUMN chronowatch.schedules.name              IS 'Человекочитаемое имя расписания (уникально в рамках тенанта)';
COMMENT ON COLUMN chronowatch.schedules.state             IS 'enabled|paused|disabled';
COMMENT ON COLUMN chronowatch.schedules.kind              IS 'cron|interval|oneoff';
COMMENT ON COLUMN chronowatch.schedules.cron_expr         IS 'CRON выражение (5 или 6 полей)';
COMMENT ON COLUMN chronowatch.schedules.interval_ms       IS 'Интервал в миллисекундах (>= 1000)';
COMMENT ON COLUMN chronowatch.schedules.at_time           IS 'Абсолютное время исполнения для oneoff';
COMMENT ON COLUMN chronowatch.schedules.timezone          IS 'IANA timezone (например, Europe/Stockholm)';
COMMENT ON COLUMN chronowatch.schedules.jitter_ms         IS 'Случайный джиттер исполнения';
COMMENT ON COLUMN chronowatch.schedules.max_drift_ms      IS 'Допустимый дрейф планировщика';
COMMENT ON COLUMN chronowatch.schedules.backfill_limit    IS 'Лимит бэкфилла пропущенных запусков';
COMMENT ON COLUMN chronowatch.schedules.concurrency_limit IS 'Ограничение одновременных запусков';
COMMENT ON COLUMN chronowatch.schedules.dedup_key         IS 'Ключ групповой дедупликации';
COMMENT ON COLUMN chronowatch.schedules.payload           IS 'Произвольные параметры запуска';
COMMENT ON COLUMN chronowatch.schedules.labels            IS 'Сервисные метки для поиска/политик';
COMMENT ON COLUMN chronowatch.schedules.revision          IS 'Версия записи (инкремент триггером)';
COMMENT ON COLUMN chronowatch.schedules.deleted_at        IS 'Мягкое удаление';

-- Имена уникальны в рамках тенанта для активных записей
CREATE UNIQUE INDEX IF NOT EXISTS ux_schedules_tenant_name
  ON chronowatch.schedules (tenant_id, lower(name))
  WHERE deleted_at IS NULL;

-- Индексы планировщика
CREATE INDEX IF NOT EXISTS ix_schedules_tenant_state_kind
  ON chronowatch.schedules (tenant_id, state, kind);

CREATE INDEX IF NOT EXISTS ix_schedules_time_bounds
  ON chronowatch.schedules (start_after, end_before);

-- Поиск по меткам (ключевые слова)
CREATE INDEX IF NOT EXISTS ix_schedules_labels_gin
  ON chronowatch.schedules USING gin (labels jsonb_path_ops);

-- Обеспечить отсутствие перекрытий oneoff по dedup_key в одном тенанте (опционально)
-- Требует btree_gist
ALTER TABLE chronowatch.schedules
  DROP CONSTRAINT IF EXISTS ex_schedules_oneoff_dedup;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ex_schedules_oneoff_dedup'
      AND connamespace = 'chronowatch'::regnamespace
  ) THEN
    ALTER TABLE chronowatch.schedules
      ADD CONSTRAINT ex_schedules_oneoff_dedup
      EXCLUDE USING gist (
        tenant_id WITH =,
        coalesce(dedup_key, '') WITH =,
        tstzrange(at_time, at_time, '[]') WITH &&
      )
      WHERE (kind = 'oneoff' AND at_time IS NOT NULL);
  END IF;
END $$;

-- Триггер updated_at + revision
DROP TRIGGER IF EXISTS trg_schedules_touch ON chronowatch.schedules;
CREATE TRIGGER trg_schedules_touch
  BEFORE UPDATE ON chronowatch.schedules
  FOR EACH ROW
  EXECUTE FUNCTION chronowatch.tg_touch_updated_at();

-- -----------------------------------------------------------------------------
-- TABLE: schedule_runs (execution records)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chronowatch.schedule_runs (
  run_id        uuid PRIMARY KEY DEFAULT public.gen_random_uuid(),
  schedule_id   uuid NOT NULL REFERENCES chronowatch.schedules(schedule_id) ON DELETE CASCADE,
  tenant_id     uuid NOT NULL,

  due_at        timestamptz NOT NULL,          -- плановое время
  started_at    timestamptz,
  finished_at   timestamptz,
  status        chronowatch.run_status NOT NULL DEFAULT 'scheduled',
  attempt       integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),

  worker_id     text,                           -- идентификатор воркера
  dedup_hash    bytea,                          -- для идемпотентности
  error         text,                           -- причина сбоя

  metrics       jsonb NOT NULL DEFAULT '{}'::jsonb, -- длительности, ретраи и т.п.
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT runs_finished_after_start CHECK (finished_at IS NULL OR started_at IS NOT NULL),
  CONSTRAINT runs_metrics_object       CHECK (jsonb_typeof(metrics) = 'object')
);

COMMENT ON TABLE chronowatch.schedule_runs IS 'Журнал запусков расписаний';
COMMENT ON COLUMN chronowatch.schedule_runs.due_at      IS 'Плановое время исполнения';
COMMENT ON COLUMN chronowatch.schedule_runs.status      IS 'scheduled|running|success|failed|canceled|skipped|timeout';

-- Индексы планировщика для подбора ближайших задач
CREATE INDEX IF NOT EXISTS ix_runs_tenant_status_due
  ON chronowatch.schedule_runs (tenant_id, status, due_at);

CREATE INDEX IF NOT EXISTS ix_runs_schedule_due
  ON chronowatch.schedule_runs (schedule_id, due_at);

CREATE INDEX IF NOT EXISTS ix_runs_updated_at
  ON chronowatch.schedule_runs (updated_at);

-- Триггер updated_at
DROP TRIGGER IF EXISTS trg_runs_touch ON chronowatch.schedule_runs;
CREATE TRIGGER trg_runs_touch
  BEFORE UPDATE ON chronowatch.schedule_runs
  FOR EACH ROW
  EXECUTE FUNCTION chronowatch.tg_touch_updated_at();

-- -----------------------------------------------------------------------------
-- Row-Level Security (tenant isolation)
-- -----------------------------------------------------------------------------
ALTER TABLE chronowatch.schedules      ENABLE ROW LEVEL SECURITY;
ALTER TABLE chronowatch.schedule_runs  ENABLE ROW LEVEL SECURITY;

-- Политики: чтение/запись разрешены только в рамках текущего tenant_id.
-- Если app.tenant_id не установлен (NULL) — политика не пускает.
DROP POLICY IF EXISTS p_schedules_tenant_sel ON chronowatch.schedules;
CREATE POLICY p_schedules_tenant_sel ON chronowatch.schedules
  FOR SELECT
  USING (tenant_id = chronowatch.current_tenant());

DROP POLICY IF EXISTS p_schedules_tenant_mod ON chronowatch.schedules;
CREATE POLICY p_schedules_tenant_mod ON chronowatch.schedules
  FOR ALL
  USING (tenant_id = chronowatch.current_tenant())
  WITH CHECK (tenant_id = chronowatch.current_tenant());

DROP POLICY IF EXISTS p_runs_tenant_sel ON chronowatch.schedule_runs;
CREATE POLICY p_runs_tenant_sel ON chronowatch.schedule_runs
  FOR SELECT
  USING (tenant_id = chronowatch.current_tenant());

DROP POLICY IF EXISTS p_runs_tenant_mod ON chronowatch.schedule_runs;
CREATE POLICY p_runs_tenant_mod ON chronowatch.schedule_runs
  FOR ALL
  USING (tenant_id = chronowatch.current_tenant())
  WITH CHECK (tenant_id = chronowatch.current_tenant());

-- -----------------------------------------------------------------------------
-- Useful comments on search_path expectations (do not change)
-- -----------------------------------------------------------------------------
COMMENT ON SCHEMA chronowatch IS 'Chronowatch core schema';

COMMIT;
