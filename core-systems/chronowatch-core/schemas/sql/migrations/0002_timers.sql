-- Chronowatch Core
-- Migration: 0002_timers.sql
-- Purpose : Industrial-grade timers storage for schedulers (cron/rrule/once)
-- Target  : PostgreSQL 14+ (tested on 14/15)
-- Safety  : Transactional, idempotent-ish (CREATE IF NOT EXISTS where possible)

BEGIN;

--==============================================================
-- Safety/session settings
--==============================================================
SET LOCAL statement_timeout = '10min';
SET LOCAL lock_timeout      = '1min';
SET LOCAL idle_in_transaction_session_timeout = '5min';
SET LOCAL client_min_messages = warning;

--==============================================================
-- Extensions (safe if already installed)
--==============================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive text

--==============================================================
-- Enumerations
--==============================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'timer_status') THEN
    CREATE TYPE timer_status AS ENUM ('active','paused','disabled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'timer_type') THEN
    CREATE TYPE timer_type AS ENUM ('cron','rrule','once');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'timer_misfire_policy') THEN
    CREATE TYPE timer_misfire_policy AS ENUM ('fire_now','skip','catch_up');
  END IF;
END$$;

--==============================================================
-- Table: timers
--==============================================================
CREATE TABLE IF NOT EXISTS public.timers (
  id                 uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid            NOT NULL,
  owner_id           uuid            NOT NULL,                         -- создатель/владелец
  name               citext          NOT NULL,                         -- уникально в рамках tenant при deleted_at IS NULL
  description        text            NULL,

  type               timer_type      NOT NULL,                         -- cron | rrule | once
  cron_expr          text            NULL,                             -- например: "0 19 * * MON-FRI"
  rrule              text            NULL,                             -- iCalendar RRULE
  one_shot_at        timestamptz     NULL,                             -- единичное срабатывание

  timezone           text            NOT NULL DEFAULT 'UTC',           -- IANA TZ, валидируется на приложении
  start_at           timestamptz     NULL,                             -- окно активности (опц.)
  end_at             timestamptz     NULL,                             -- если задано, >= start_at

  status             timer_status    NOT NULL DEFAULT 'active',
  misfire_policy     timer_misfire_policy NOT NULL DEFAULT 'catch_up',
  max_concurrency    integer         NOT NULL DEFAULT 1 CHECK (max_concurrency BETWEEN 1 AND 64),
  jitter_ms          integer         NOT NULL DEFAULT 0 CHECK (jitter_ms BETWEEN 0 AND 600000), -- до 10 мин

  payload            jsonb           NOT NULL DEFAULT '{}'::jsonb,     -- произвольные данные для обработчика
  tags               jsonb           NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tags) = 'array'),

  last_run_at        timestamptz     NULL,
  next_run_at        timestamptz     NULL,
  last_success_at    timestamptz     NULL,
  last_error_at      timestamptz     NULL,
  last_error         text            NULL,
  run_count          bigint          NOT NULL DEFAULT 0 CHECK (run_count >= 0),

  created_at         timestamptz     NOT NULL DEFAULT now(),
  updated_at         timestamptz     NOT NULL DEFAULT now(),
  deleted_at         timestamptz     NULL,

  -- Schedule exclusivity and consistency
  CONSTRAINT timers_schedule_exclusive CHECK (
    (type = 'cron'  AND cron_expr IS NOT NULL AND rrule IS NULL AND one_shot_at IS NULL) OR
    (type = 'rrule' AND rrule     IS NOT NULL AND cron_expr IS NULL AND one_shot_at IS NULL) OR
    (type = 'once'  AND one_shot_at IS NOT NULL AND cron_expr IS NULL AND rrule IS NULL)
  ),

  CONSTRAINT timers_start_end_window CHECK (
    end_at IS NULL OR start_at IS NULL OR end_at >= start_at
  ),

  CONSTRAINT timers_timezone_not_empty CHECK (length(timezone) > 0)
);

COMMENT ON TABLE public.timers IS 'Chronowatch timers: multi-tenant, secure, industrial.';
COMMENT ON COLUMN public.timers.tenant_id IS 'Tenant/organization identifier (RLS enforced).';
COMMENT ON COLUMN public.timers.owner_id  IS 'Timer owner (user/service UUID).';
COMMENT ON COLUMN public.timers.type      IS 'cron|rrule|once; exactly one schedule source must be set.';
COMMENT ON COLUMN public.timers.cron_expr IS 'POSIX cron expression interpreted in "timezone".';
COMMENT ON COLUMN public.timers.rrule     IS 'iCalendar RRULE string; times in "timezone" unless specified.';
COMMENT ON COLUMN public.timers.one_shot_at IS 'Single-fire timestamp (tz-aware).';
COMMENT ON COLUMN public.timers.misfire_policy IS 'What to do on missed fire: fire_now|skip|catch_up.';
COMMENT ON COLUMN public.timers.jitter_ms IS 'Randomization window in milliseconds.';
COMMENT ON COLUMN public.timers.tags      IS 'JSONB array of tags for search/routing.';
COMMENT ON COLUMN public.timers.deleted_at IS 'Soft delete marker; partial unique indexes respect NULL here.';

--==============================================================
-- Uniqueness and performance indexes
--==============================================================
-- Уникальность имени таймера в рамках арендатора среди НЕ удаленных записей
CREATE UNIQUE INDEX IF NOT EXISTS uix_timers_tenant_name_alive
  ON public.timers (tenant_id, lower(name))
  WHERE deleted_at IS NULL;

-- Частые выборки планировщиком
CREATE INDEX IF NOT EXISTS ix_timers_next_due
  ON public.timers (status, next_run_at)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_timers_tenant_status
  ON public.timers (tenant_id, status)
  WHERE deleted_at IS NULL;

-- По владельцу для пользовательских списков
CREATE INDEX IF NOT EXISTS ix_timers_owner
  ON public.timers (owner_id)
  WHERE deleted_at IS NULL;

-- GIN индексы для меток/пейлоада
CREATE INDEX IF NOT EXISTS gin_timers_tags
  ON public.timers USING gin (tags jsonb_path_ops);

CREATE INDEX IF NOT EXISTS gin_timers_payload
  ON public.timers USING gin (payload jsonb_path_ops);

--==============================================================
-- Updated_at trigger
--==============================================================
CREATE OR REPLACE FUNCTION public.fn_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_timers_touch_updated_at'
  ) THEN
    CREATE TRIGGER trg_timers_touch_updated_at
      BEFORE UPDATE ON public.timers
      FOR EACH ROW
      EXECUTE FUNCTION public.fn_touch_updated_at();
  END IF;
END$$;

--==============================================================
-- Optional foreign keys (applied only if referenced tables exist)
--==============================================================
DO $$
BEGIN
  -- FK to tenants table if present
  IF EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'tenants' AND n.nspname = 'public'
  ) AND NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_timers_tenant'
  ) THEN
    EXECUTE 'ALTER TABLE public.timers
             ADD CONSTRAINT fk_timers_tenant
             FOREIGN KEY (tenant_id)
             REFERENCES public.tenants(id)
             ON UPDATE CASCADE ON DELETE RESTRICT
             DEFERRABLE INITIALLY DEFERRED';
  END IF;

  -- FK to users table if present
  IF EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'users' AND n.nspname = 'public'
  ) AND NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_timers_owner'
  ) THEN
    EXECUTE 'ALTER TABLE public.timers
             ADD CONSTRAINT fk_timers_owner
             FOREIGN KEY (owner_id)
             REFERENCES public.users(id)
             ON UPDATE CASCADE ON DELETE RESTRICT
             DEFERRABLE INITIALLY DEFERRED';
  END IF;
END$$;

--==============================================================
-- Row-Level Security (multi-tenant isolation)
--   Require app to set: SELECT set_config('app.tenant_id', '<uuid>', false);
--==============================================================
ALTER TABLE public.timers ENABLE ROW LEVEL SECURITY;

-- Policy: tenant can see only its rows
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='timers' AND policyname='timers_isolate_tenant'
  ) THEN
    CREATE POLICY timers_isolate_tenant
      ON public.timers
      USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
      )
      WITH CHECK (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
      );
  END IF;
END$$;

-- Optional read-only policy for monitoring role, if exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chronowatch_readonly') AND
     NOT EXISTS (
       SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='timers' AND policyname='timers_ro_monitoring'
     ) THEN
    CREATE POLICY timers_ro_monitoring
      ON public.timers
      FOR SELECT
      TO chronowatch_readonly
      USING (true);
  END IF;
END$$;

--==============================================================
-- Convenience VIEW for scheduler picks
--==============================================================
CREATE OR REPLACE VIEW public.timers_ready AS
SELECT
  t.*
FROM public.timers t
WHERE
  t.deleted_at IS NULL
  AND t.status = 'active'
  AND t.next_run_at IS NOT NULL
  AND t.next_run_at <= now();

COMMENT ON VIEW public.timers_ready IS 'Active timers ready to be picked by schedulers.';

--==============================================================
-- Grants (optional, applied if roles exist)
--==============================================================
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chronowatch_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.timers TO chronowatch_app;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chronowatch_readonly') THEN
    GRANT SELECT ON public.timers TO chronowatch_readonly;
    GRANT SELECT ON public.timers_ready TO chronowatch_readonly;
  END IF;
END$$;

COMMIT;
