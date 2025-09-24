--==================================================================================================
-- OblivionVault Core • Jobs subsystem (PostgreSQL 13+; рекомендуется 14+)
-- Содержимое:
--   • Схема ov_jobs, типы, таблицы, индексы
--   • Триггеры updated_at и аудит переходов состояний
--   • Уведомления LISTEN/NOTIFY о доступных заданиях
--   • Функции: enqueue/claim/complete/fail/renew_lock/cancel/reap_stale_locks
-- Принципы: идемпотентность, минимальные блокировки, безопасность, наблюдаемость
--==================================================================================================

BEGIN;

SET client_min_messages = WARNING;
SET lock_timeout = '0';
SET idle_in_transaction_session_timeout = '0';
SET statement_timeout = '0';

-- Расширения
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gin;     -- GIN по btree типам, если понадобится
CREATE EXTENSION IF NOT EXISTS pg_stat_statements; -- рекомендация к наблюдаемости (no-op если уже есть)

-- Схема
CREATE SCHEMA IF NOT EXISTS ov_jobs AUTHORIZATION CURRENT_USER;

-- Типы
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_state' AND typnamespace = 'ov_jobs'::regnamespace) THEN
    CREATE TYPE ov_jobs.job_state AS ENUM (
      'queued',      -- в очереди, готово к выдаче по available_at
      'scheduled',   -- отложено до available_at
      'retry',       -- запланирован повтор после backoff
      'running',     -- выполняется рабочим
      'succeeded',   -- успешно выполнено
      'failed',      -- завершено с ошибкой (еще не dead)
      'cancelled',   -- отменено оператором/политикой
      'dead'         -- исчерпаны попытки
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'backoff_strategy' AND typnamespace = 'ov_jobs'::regnamespace) THEN
    CREATE TYPE ov_jobs.backoff_strategy AS ENUM ('none','constant','linear','exponential','exponential_jitter');
  END IF;
END$$;

-- Таблица заданий
CREATE TABLE IF NOT EXISTS ov_jobs.jobs (
  id                uuid                 PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid                             DEFAULT NULL,                  -- для мультиаренды (RLS-ready)
  queue             text                 NOT NULL    CHECK (length(queue) BETWEEN 1 AND 64),
  kind              text                 NOT NULL    CHECK (length(kind)  BETWEEN 1 AND 64),
  priority          smallint             NOT NULL    DEFAULT 0 CHECK (priority BETWEEN -100 AND 100),
  state             ov_jobs.job_state    NOT NULL    DEFAULT 'queued',
  attempts          integer              NOT NULL    DEFAULT 0 CHECK (attempts >= 0),
  max_attempts      integer              NOT NULL    DEFAULT 20 CHECK (max_attempts BETWEEN 1 AND 100),
  timeout_sec       integer              NOT NULL    DEFAULT 300 CHECK (timeout_sec BETWEEN 1 AND 86400),
  backoff           ov_jobs.backoff_strategy NOT NULL DEFAULT 'exponential_jitter',
  backoff_initial   interval             NOT NULL    DEFAULT interval '5 seconds',
  dedup_key         text                             DEFAULT NULL,                 -- ключ дедупликации
  available_at      timestamptz          NOT NULL    DEFAULT now(),                -- доступно к выдаче с этого времени
  scheduled_at      timestamptz                      DEFAULT now(),                -- исходное время планирования
  locked_at         timestamptz                      DEFAULT NULL,
  lock_expiry       timestamptz                      DEFAULT NULL,
  locked_by         text                             DEFAULT NULL,                 -- ид воркера
  payload           jsonb                NOT NULL    DEFAULT '{}'::jsonb,
  headers           jsonb                NOT NULL    DEFAULT '{}'::jsonb,
  meta              jsonb                NOT NULL    DEFAULT '{}'::jsonb,
  last_error        text                             DEFAULT NULL,
  last_error_at     timestamptz                      DEFAULT NULL,
  result            jsonb                            DEFAULT NULL,
  trace_id          text                             DEFAULT NULL,
  correlation_id    text                             DEFAULT NULL,

  created_at        timestamptz          NOT NULL    DEFAULT now(),
  updated_at        timestamptz          NOT NULL    DEFAULT now(),
  completed_at      timestamptz                      DEFAULT NULL,
  cancelled_at      timestamptz                      DEFAULT NULL,

  -- Инварианты безопасности
  CHECK (
    CASE state
      WHEN 'queued'    THEN locked_by IS NULL AND lock_expiry IS NULL
      WHEN 'scheduled' THEN locked_by IS NULL AND lock_expiry IS NULL
      WHEN 'retry'     THEN locked_by IS NULL AND lock_expiry IS NULL
      WHEN 'running'   THEN locked_by IS NOT NULL AND lock_expiry IS NOT NULL
      ELSE TRUE
    END
  )
);

COMMENT ON TABLE ov_jobs.jobs IS 'Очередь задач oblivionvault-core';
COMMENT ON COLUMN ov_jobs.jobs.dedup_key IS 'Ключ дедупликации для idempotent enqueue';

-- Уникальная дедупликация только для активных состояний
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname = 'ov_jobs' AND indexname = 'jobs_dedup_active_uniq'
  ) THEN
    EXECUTE $ix$
      CREATE UNIQUE INDEX jobs_dedup_active_uniq
      ON ov_jobs.jobs (dedup_key)
      WHERE dedup_key IS NOT NULL
        AND state IN ('queued','scheduled','retry','running');
    $ix$;
  END IF;
END$$;

-- Индексы под план выбора
CREATE INDEX IF NOT EXISTS jobs_ready_idx
  ON ov_jobs.jobs (queue, priority DESC, available_at, id)
  WHERE state IN ('queued','scheduled','retry');

CREATE INDEX IF NOT EXISTS jobs_locked_expire_idx
  ON ov_jobs.jobs (lock_expiry)
  WHERE state = 'running' AND lock_expiry IS NOT NULL;

CREATE INDEX IF NOT EXISTS jobs_state_created_idx
  ON ov_jobs.jobs (state, created_at);

CREATE INDEX IF NOT EXISTS jobs_kind_idx
  ON ov_jobs.jobs (kind, created_at);

CREATE INDEX IF NOT EXISTS jobs_payload_gin
  ON ov_jobs.jobs USING gin (payload jsonb_path_ops);

-- Партиционированный аудит событий
CREATE TABLE IF NOT EXISTS ov_jobs.job_events (
  id            bigserial PRIMARY KEY,
  job_id        uuid            NOT NULL REFERENCES ov_jobs.jobs(id) ON DELETE CASCADE,
  tenant_id     uuid                        DEFAULT NULL,
  ts            timestamptz     NOT NULL    DEFAULT now(),
  action        text            NOT NULL,              -- created/claimed/completed/failed/cancelled/state_change/timeout
  from_state    ov_jobs.job_state,
  to_state      ov_jobs.job_state,
  worker        text,
  attempt       integer         NOT NULL DEFAULT 0,
  message       text,
  error         jsonb,
  meta          jsonb           NOT NULL DEFAULT '{}'::jsonb
) PARTITION BY RANGE (ts);

-- Партиция по умолчанию + текущий месяц
CREATE TABLE IF NOT EXISTS ov_jobs.job_events_default PARTITION OF ov_jobs.job_events DEFAULT;

DO $$
DECLARE
  p_start date := date_trunc('month', now())::date;
  p_end   date := (date_trunc('month', now()) + interval '1 month')::date;
  part_name text := format('job_events_%s', to_char(p_start, 'YYYY_MM'));
  exists_part boolean;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'ov_jobs' AND c.relname = part_name
  ) INTO exists_part;

  IF NOT exists_part THEN
    EXECUTE format(
      'CREATE TABLE ov_jobs.%I PARTITION OF ov_jobs.job_events FOR VALUES FROM (%L) TO (%L);',
      part_name, p_start, p_end
    );
  END IF;
END$$;

-- Индексы для аудита
CREATE INDEX IF NOT EXISTS job_events_job_ts_idx
  ON ov_jobs.job_events (job_id, ts DESC);

-- Триггер updated_at
CREATE OR REPLACE FUNCTION ov_jobs.tg_set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS set_updated_at ON ov_jobs.jobs;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON ov_jobs.jobs
FOR EACH ROW EXECUTE FUNCTION ov_jobs.tg_set_updated_at();

-- Уведомления о доступных заданиях
-- Канал: ov_jobs_ready, payload = JSON {id,queue,priority,available_at}
CREATE OR REPLACE FUNCTION ov_jobs.tg_notify_ready()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  ready boolean;
BEGIN
  ready := (NEW.state IN ('queued','scheduled','retry')) AND NEW.available_at <= now();
  IF (TG_OP = 'INSERT' AND ready)
     OR (TG_OP = 'UPDATE' AND (NOT (OLD.state IN ('queued','scheduled','retry') AND OLD.available_at <= now())) AND ready)
  THEN
    PERFORM pg_notify(
      'ov_jobs_ready',
      json_build_object(
        'id', NEW.id::text,
        'queue', NEW.queue,
        'priority', NEW.priority,
        'available_at', NEW.available_at
      )::text
    );
  END IF;
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS notify_ready ON ov_jobs.jobs;
CREATE TRIGGER notify_ready
AFTER INSERT OR UPDATE OF state, available_at ON ov_jobs.jobs
FOR EACH ROW EXECUTE FUNCTION ov_jobs.tg_notify_ready();

-- Аудит переходов состояний
CREATE OR REPLACE FUNCTION ov_jobs.tg_log_state_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO ov_jobs.job_events(job_id, tenant_id, action, from_state, to_state, worker, attempt, meta)
    VALUES(NEW.id, NEW.tenant_id, 'created', NULL, NEW.state, NEW.locked_by, NEW.attempts, NEW.meta);
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
      INSERT INTO ov_jobs.job_events(job_id, tenant_id, action, from_state, to_state, worker, attempt, message, error, meta)
      VALUES(NEW.id, NEW.tenant_id, 'state_change', OLD.state, NEW.state, NEW.locked_by, NEW.attempts, NEW.last_error, NULL, NEW.meta);
    ELSIF NEW.last_error IS DISTINCT FROM OLD.last_error OR NEW.last_error_at IS DISTINCT FROM OLD.last_error_at THEN
      INSERT INTO ov_jobs.job_events(job_id, tenant_id, action, from_state, to_state, worker, attempt, message, error, meta)
      VALUES(NEW.id, NEW.tenant_id, 'error', NEW.state, NEW.state, NEW.locked_by, NEW.attempts, NEW.last_error, jsonb_build_object('at', NEW.last_error_at), NEW.meta);
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS log_state_change_ins ON ov_jobs.jobs;
CREATE TRIGGER log_state_change_ins
AFTER INSERT ON ov_jobs.jobs
FOR EACH ROW EXECUTE FUNCTION ov_jobs.tg_log_state_change();

DROP TRIGGER IF EXISTS log_state_change_upd ON ov_jobs.jobs;
CREATE TRIGGER log_state_change_upd
AFTER UPDATE ON ov_jobs.jobs
FOR EACH ROW EXECUTE FUNCTION ov_jobs.tg_log_state_change();

-- Расчет backoff
CREATE OR REPLACE FUNCTION ov_jobs.compute_backoff(
  p_strategy ov_jobs.backoff_strategy,
  p_initial  interval,
  p_attempts integer
) RETURNS interval
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  base interval := p_initial;
  res  interval;
  r    double precision;
BEGIN
  IF p_attempts <= 0 THEN
    RETURN base;
  END IF;

  CASE p_strategy
    WHEN 'none' THEN
      res := interval '0';
    WHEN 'constant' THEN
      res := base;
    WHEN 'linear' THEN
      res := make_interval(secs => EXTRACT(EPOCH FROM base) * p_attempts);
    WHEN 'exponential' THEN
      res := make_interval(secs => EXTRACT(EPOCH FROM base) * power(2, greatest(p_attempts-1,0)));
    WHEN 'exponential_jitter' THEN
      r := (random() * 0.5) + 0.75; -- 0.75x..1.25x
      res := make_interval(secs => (EXTRACT(EPOCH FROM base) * power(2, greatest(p_attempts-1,0))) * r);
    ELSE
      res := base;
  END CASE;

  -- Ограничим верхнюю границу backoff 1 час (business-safe default)
  IF res > interval '1 hour' THEN
    res := interval '1 hour';
  END IF;
  RETURN res;
END$$;

-- Функция enqueue с дедупликацией
CREATE OR REPLACE FUNCTION ov_jobs.enqueue_job(
  p_queue        text,
  p_kind         text,
  p_payload      jsonb DEFAULT '{}'::jsonb,
  p_options      jsonb DEFAULT '{}'::jsonb   -- {priority, max_attempts, timeout_sec, backoff, backoff_initial, dedup_key, tenant_id, available_at, headers, meta, trace_id, correlation_id}
) RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
  v_id uuid;
  v_priority smallint := COALESCE((p_options->>'priority')::smallint, 0);
  v_max_attempts int  := COALESCE((p_options->>'max_attempts')::int, 20);
  v_timeout int       := COALESCE((p_options->>'timeout_sec')::int, 300);
  v_backoff ov_jobs.backoff_strategy := COALESCE((p_options->>'backoff')::ov_jobs.backoff_strategy, 'exponential_jitter');
  v_backoff_initial interval := COALESCE((p_options->>'backoff_initial')::interval, interval '5 seconds');
  v_dedup text         := NULLIF(p_options->>'dedup_key','');
  v_tenant uuid        := NULLIF(p_options->>'tenant_id','')::uuid;
  v_available timestamptz := COALESCE((p_options->>'available_at')::timestamptz, now());
  v_headers jsonb      := COALESCE(p_options->'headers', '{}'::jsonb);
  v_meta jsonb         := COALESCE(p_options->'meta', '{}'::jsonb);
  v_trace text         := NULLIF(p_options->>'trace_id','');
  v_corr  text         := NULLIF(p_options->>'correlation_id','');
BEGIN
  IF p_queue IS NULL OR length(p_queue) = 0 THEN
    RAISE EXCEPTION 'queue required';
  END IF;
  IF p_kind IS NULL OR length(p_kind) = 0 THEN
    RAISE EXCEPTION 'kind required';
  END IF;

  IF v_dedup IS NOT NULL THEN
    -- идемпотентная вставка: если активная запись с тем же dedup_key уже есть – возвращаем ее id
    SELECT id INTO v_id
    FROM ov_jobs.jobs
    WHERE dedup_key = v_dedup
      AND state IN ('queued','scheduled','retry','running')
    LIMIT 1;

    IF FOUND THEN
      RETURN v_id;
    END IF;
  END IF;

  INSERT INTO ov_jobs.jobs(
    tenant_id, queue, kind, priority, state, attempts, max_attempts, timeout_sec,
    backoff, backoff_initial, dedup_key, available_at, scheduled_at,
    payload, headers, meta, trace_id, correlation_id
  )
  VALUES(
    v_tenant, p_queue, p_kind, v_priority, CASE WHEN v_available > now() THEN 'scheduled' ELSE 'queued' END,
    0, v_max_attempts, v_timeout, v_backoff, v_backoff_initial, v_dedup, v_available, now(),
    p_payload, v_headers, v_meta, v_trace, v_corr
  )
  RETURNING id INTO v_id;

  RETURN v_id;
END$$;

-- Выдача задания воркеру (lease с истечением)
CREATE OR REPLACE FUNCTION ov_jobs.claim_job(
  p_queue text,
  p_worker text,
  p_lease_seconds int DEFAULT 300
) RETURNS ov_jobs.jobs
LANGUAGE plpgsql AS $$
DECLARE
  v_job ov_jobs.jobs%ROWTYPE;
BEGIN
  IF p_queue IS NULL OR p_worker IS NULL THEN
    RAISE EXCEPTION 'queue and worker are required';
  END IF;

  WITH cte AS (
    SELECT id
    FROM ov_jobs.jobs
    WHERE queue = p_queue
      AND state IN ('queued','scheduled','retry')
      AND available_at <= now()
      AND attempts < max_attempts
    ORDER BY priority DESC, available_at ASC, created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  )
  UPDATE ov_jobs.jobs j
     SET state = 'running',
         attempts = j.attempts + 1,
         locked_by = p_worker,
         locked_at = now(),
         lock_expiry = now() + make_interval(secs => p_lease_seconds)
   WHERE j.id IN (SELECT id FROM cte)
  RETURNING j.* INTO v_job;

  RETURN v_job;
END$$;

-- Обновление аренды
CREATE OR REPLACE FUNCTION ov_jobs.renew_lock(
  p_id uuid,
  p_worker text,
  p_extend_seconds int DEFAULT 300
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
  updated int;
BEGIN
  UPDATE ov_jobs.jobs
     SET lock_expiry = now() + make_interval(secs => p_extend_seconds),
         locked_at = now()
   WHERE id = p_id
     AND state = 'running'
     AND locked_by = p_worker
     AND lock_expiry > now()
  RETURNING 1 INTO updated;

  RETURN COALESCE(updated,0) = 1;
END$$;

-- Успешное завершение
CREATE OR REPLACE FUNCTION ov_jobs.complete_job(
  p_id uuid,
  p_worker text,
  p_result jsonb DEFAULT '{}'::jsonb
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE ov_jobs.jobs
     SET state = 'succeeded',
         result = p_result,
         completed_at = now(),
         locked_by = NULL,
         locked_at = NULL,
         lock_expiry = NULL
   WHERE id = p_id
     AND state = 'running'
     AND locked_by = p_worker;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'complete_job: not found or not owned by %', p_worker;
  END IF;
END$$;

-- Ошибка выполнения с расчетом бэкофа
CREATE OR REPLACE FUNCTION ov_jobs.fail_job(
  p_id uuid,
  p_worker text,
  p_error text,
  p_error_details jsonb DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  v attempts int;
  v max_attempts int;
  v backoff ov_jobs.backoff_strategy;
  v initial interval;
  v avail interval;
BEGIN
  SELECT attempts, max_attempts, backoff, backoff_initial INTO v, v_max_attempts, backoff, initial
  FROM ov_jobs.jobs WHERE id = p_id FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'fail_job: job not found';
  END IF;

  IF v + 0 >= v_max_attempts THEN
    UPDATE ov_jobs.jobs
       SET state = 'dead',
           last_error = p_error,
           last_error_at = now(),
           locked_by = NULL,
           locked_at = NULL,
           lock_expiry = NULL,
           completed_at = now()
     WHERE id = p_id AND locked_by = p_worker;
    RETURN;
  END IF;

  avail := ov_jobs.compute_backoff(backoff, initial, v + 1);

  UPDATE ov_jobs.jobs
     SET state = 'retry',
         last_error = p_error,
         last_error_at = now(),
         available_at = now() + avail,
         locked_by = NULL,
         locked_at = NULL,
         lock_expiry = NULL
   WHERE id = p_id
     AND state = 'running'
     AND locked_by = p_worker;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'fail_job: not found or not owned by %', p_worker;
  END IF;

  -- Запишем детали ошибки в события
  INSERT INTO ov_jobs.job_events(job_id, action, from_state, to_state, worker, attempt, message, error)
  VALUES(p_id, 'failed', 'running', 'retry', p_worker, v+1, p_error, COALESCE(p_error_details, '{}'::jsonb));
END$$;

-- Отмена задания
CREATE OR REPLACE FUNCTION ov_jobs.cancel_job(
  p_id uuid,
  p_reason text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE ov_jobs.jobs
     SET state = 'cancelled',
         cancelled_at = now(),
         last_error = COALESCE(p_reason, last_error),
         last_error_at = CASE WHEN p_reason IS NOT NULL THEN now() ELSE last_error_at END,
         locked_by = NULL, locked_at = NULL, lock_expiry = NULL
   WHERE id = p_id
     AND state NOT IN ('succeeded','dead','cancelled');
END$$;

-- Реанимация протухших блокировок (таймаут исполнения)
CREATE OR REPLACE FUNCTION ov_jobs.reap_stale_locks(
  p_queue text,
  p_limit int DEFAULT 100
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_count int := 0;
  r record;
  avail interval;
BEGIN
  FOR r IN
    SELECT id, attempts, max_attempts, backoff, backoff_initial
    FROM ov_jobs.jobs
    WHERE queue = p_queue
      AND state = 'running'
      AND lock_expiry IS NOT NULL
      AND lock_expiry < now()
    ORDER BY lock_expiry ASC
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  LOOP
    IF r.attempts >= r.max_attempts THEN
      UPDATE ov_jobs.jobs
         SET state = 'dead',
             last_error = COALESCE(last_error, 'timeout'),
             last_error_at = now(),
             locked_by = NULL, locked_at = NULL, lock_expiry = NULL,
             completed_at = now()
       WHERE id = r.id;
    ELSE
      avail := ov_jobs.compute_backoff(r.backoff, r.backoff_initial, r.attempts + 1);
      UPDATE ov_jobs.jobs
         SET state = 'retry',
             last_error = COALESCE(last_error, 'timeout'),
             last_error_at = now(),
             available_at = now() + avail,
             locked_by = NULL, locked_at = NULL, lock_expiry = NULL
       WHERE id = r.id;
    END IF;

    INSERT INTO ov_jobs.job_events(job_id, action, from_state, to_state, message)
    VALUES(r.id, 'timeout', 'running', (SELECT state FROM ov_jobs.jobs WHERE id = r.id), 'lock expired');

    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END$$;

-- Безопасные дефолт-права (настраиваются позже по ролям проекта)
-- REVOKE ALL ON SCHEMA ov_jobs FROM PUBLIC;
-- GRANT USAGE ON SCHEMA ov_jobs TO app_role;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ov_jobs TO app_role;

-- (Опционально) RLS-поддержка для tenant_id — включать после настройки ролей
-- ALTER TABLE ov_jobs.jobs ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY jobs_tenant_isolation ON ov_jobs.jobs
--   USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('ov.tenant_id', true), '')::uuid);

COMMIT;
