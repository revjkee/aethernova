-- 0005_moderation.sql
-- Mythos Core: Moderation schema
-- PostgreSQL 13+ (рекомендуется 14/15)
-- Безопасные таймауты и ожидание блокировок
SET lock_timeout = '5s';
SET statement_timeout = '60s';
SET idle_in_transaction_session_timeout = '60s';

BEGIN;

-- Схема и расширения
CREATE SCHEMA IF NOT EXISTS moderation;
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- для gen_random_uuid()
-- JSONB GIN встроен; btree_gin по желанию
-- CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Enum-типы (через DO, чтобы не падать при повторном запуске)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moderation_category') THEN
    CREATE TYPE moderation_category AS ENUM (
      'toxicity','violence','sexual','self_harm','drugs','hate','harassment','pii','malware','other'
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moderation_severity') THEN
    CREATE TYPE moderation_severity AS ENUM ('low','medium','high','critical');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moderation_action') THEN
    CREATE TYPE moderation_action AS ENUM ('allow','soft_block','redact','review','block');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moderation_source') THEN
    CREATE TYPE moderation_source AS ENUM ('automated','user_report','external');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moderation_status') THEN
    CREATE TYPE moderation_status AS ENUM ('open','triaged','actioned','rejected','suppressed','escalated','closed');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'moderation_rule_kind') THEN
    CREATE TYPE moderation_rule_kind AS ENUM ('regex','substring','exact','glob');
  END IF;
END $$;

-- Общие функции-триггеры
CREATE OR REPLACE FUNCTION moderation.tg_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END $$;

-- Валидация переходов статусов и выставление временных меток
CREATE OR REPLACE FUNCTION moderation.tg_incidents_status_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  old_status moderation_status := OLD.status;
  new_status moderation_status := NEW.status;
BEGIN
  IF old_status IS DISTINCT FROM new_status THEN
    -- Разрешённые переходы
    IF old_status = 'open' AND new_status NOT IN ('triaged','actioned','rejected','suppressed','escalated','closed') THEN
      RAISE EXCEPTION 'invalid status transition: % -> %', old_status, new_status;
    ELSIF old_status = 'triaged' AND new_status NOT IN ('actioned','rejected','suppressed','escalated','closed') THEN
      RAISE EXCEPTION 'invalid status transition: % -> %', old_status, new_status;
    ELSIF old_status = 'escalated' AND new_status NOT IN ('actioned','rejected','suppressed','closed') THEN
      RAISE EXCEPTION 'invalid status transition: % -> %', old_status, new_status;
    ELSIF old_status = 'actioned' AND new_status NOT IN ('closed') THEN
      RAISE EXCEPTION 'invalid status transition: % -> %', old_status, new_status;
    ELSIF old_status = 'rejected' AND new_status NOT IN ('closed') THEN
      RAISE EXCEPTION 'invalid status transition: % -> %', old_status, new_status;
    ELSIF old_status = 'suppressed' AND new_status NOT IN ('closed') THEN
      RAISE EXCEPTION 'invalid status transition: % -> %', old_status, new_status;
    END IF;

    -- Проставление временных меток по событиям
    IF new_status = 'triaged' AND NEW.triaged_at IS NULL THEN
      NEW.triaged_at := NOW();
    END IF;
    IF new_status IN ('actioned','rejected','suppressed') AND NEW.resolved_at IS NULL THEN
      NEW.resolved_at := NOW();
    END IF;
    IF new_status = 'closed' AND NEW.closed_at IS NULL THEN
      NEW.closed_at := NOW();
    END IF;
  END IF;

  RETURN NEW;
END $$;

-- Таблица политик модерации (порогов и значений по умолчанию) на тенант/категорию
CREATE TABLE IF NOT EXISTS moderation.policies (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  category        moderation_category NOT NULL,
  min_score       numeric(5,4) NOT NULL DEFAULT 0.8000,  -- 0..1
  severity        moderation_severity NOT NULL DEFAULT 'medium',
  default_action  moderation_action NOT NULL DEFAULT 'review',
  enabled         boolean NOT NULL DEFAULT true,
  notes           text,
  created_at      timestamptz NOT NULL DEFAULT NOW(),
  updated_at      timestamptz NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_min_score_range CHECK (min_score >= 0 AND min_score <= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_policies_org_cat
  ON moderation.policies(org_id, category)
  WHERE enabled;

CREATE INDEX IF NOT EXISTS ix_policies_org
  ON moderation.policies(org_id);

CREATE TRIGGER tg_policies_updated_at
BEFORE UPDATE ON moderation.policies
FOR EACH ROW EXECUTE FUNCTION moderation.tg_touch_updated_at();

COMMENT ON TABLE moderation.policies IS 'Пороговые политики модерации по организации и категории';
COMMENT ON COLUMN moderation.policies.org_id IS 'Идентификатор тенанта/организации';
COMMENT ON COLUMN moderation.policies.min_score IS 'Минимальный модельный скор 0..1 для срабатывания';

-- Таблица правил (регулярки/паттерны), управляемых вручную
CREATE TABLE IF NOT EXISTS moderation.rules (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  name            text NOT NULL,
  kind            moderation_rule_kind NOT NULL,
  pattern         text NOT NULL,
  category        moderation_category NOT NULL,
  severity        moderation_severity NOT NULL DEFAULT 'medium',
  action_override moderation_action,
  enabled         boolean NOT NULL DEFAULT true,
  metadata        jsonb NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL DEFAULT NOW(),
  updated_at      timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_rules_org_enabled ON moderation.rules(org_id) WHERE enabled;
CREATE INDEX IF NOT EXISTS ix_rules_category ON moderation.rules(category) WHERE enabled;
CREATE INDEX IF NOT EXISTS ix_rules_metadata_gin ON moderation.rules USING gin (metadata);

CREATE TRIGGER tg_rules_updated_at
BEFORE UPDATE ON moderation.rules
FOR EACH ROW EXECUTE FUNCTION moderation.tg_touch_updated_at();

-- Инциденты модерации (основной агрегат)
CREATE TABLE IF NOT EXISTS moderation.incidents (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL,
  source             moderation_source NOT NULL,
  status             moderation_status NOT NULL DEFAULT 'open',
  category           moderation_category NOT NULL,
  severity           moderation_severity NOT NULL DEFAULT 'medium',
  score              numeric(5,4) NOT NULL DEFAULT 0.0000,
  threshold          numeric(5,4), -- копия сработавшего порога
  rule_id            uuid,         -- matched rule if any
  policy_id          uuid,         -- matched policy if any

  -- Ссылка на контент (проектно-агностично)
  content_type       text NOT NULL,     -- например: message, file, comment
  content_id         text,              -- внешний ID в доменной БД/сервисе
  content_uri        text,              -- ссылка на хранение/просмотр
  content_sha256     bytea,             -- отпечаток для дедупликации
  locale             text,              -- BCP-47

  -- Инициатор
  reported_by_user_id uuid,
  model_name         text,              -- имя модели
  model_version      text,              -- версия модели
  details            jsonb NOT NULL DEFAULT '{}', -- произвольные детали срабатывания

  -- Служебные метки/фильтры
  labels             jsonb NOT NULL DEFAULT '{}',

  triaged_at         timestamptz,
  resolved_at        timestamptz,
  closed_at          timestamptz,

  created_at         timestamptz NOT NULL DEFAULT NOW(),
  updated_at         timestamptz NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_score_range CHECK (score >= 0 AND score <= 1)
);

-- Индексы под основные сценарии
CREATE INDEX IF NOT EXISTS ix_incidents_org_status
  ON moderation.incidents(org_id, status)
  WHERE status IN ('open','triaged','escalated');

CREATE INDEX IF NOT EXISTS ix_incidents_org_created
  ON moderation.incidents(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_incidents_cat_sev
  ON moderation.incidents(category, severity);

CREATE INDEX IF NOT EXISTS ix_incidents_labels_gin
  ON moderation.incidents USING gin (labels);

CREATE INDEX IF NOT EXISTS ix_incidents_details_gin
  ON moderation.incidents USING gin (details);

CREATE UNIQUE INDEX IF NOT EXISTS ux_incidents_content_dedup
  ON moderation.incidents(org_id, content_type, content_id, category)
  WHERE content_id IS NOT NULL;

ALTER TABLE moderation.incidents
  ADD CONSTRAINT fk_incidents_rule
  FOREIGN KEY (rule_id) REFERENCES moderation.rules(id) ON DELETE SET NULL;

ALTER TABLE moderation.incidents
  ADD CONSTRAINT fk_incidents_policy
  FOREIGN KEY (policy_id) REFERENCES moderation.policies(id) ON DELETE SET NULL;

CREATE TRIGGER tg_incidents_updated_at
BEFORE UPDATE ON moderation.incidents
FOR EACH ROW EXECUTE FUNCTION moderation.tg_touch_updated_at();

CREATE TRIGGER tg_incidents_status_guard
BEFORE UPDATE ON moderation.incidents
FOR EACH ROW EXECUTE FUNCTION moderation.tg_incidents_status_guard();

COMMENT ON TABLE moderation.incidents IS 'Инциденты модерации по контенту';

-- Таблица решений по категориям для инцидента (детализация скора)
CREATE TABLE IF NOT EXISTS moderation.decisions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid NOT NULL,
  category    moderation_category NOT NULL,
  score       numeric(5,4) NOT NULL,
  threshold   numeric(5,4),
  action      moderation_action NOT NULL,
  rule_id     uuid,
  metadata    jsonb NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_decision_score CHECK (score >= 0 AND score <= 1),
  CONSTRAINT ux_decisions_incident_cat UNIQUE (incident_id, category),
  CONSTRAINT fk_decisions_incident FOREIGN KEY (incident_id) REFERENCES moderation.incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_decisions_rule FOREIGN KEY (rule_id) REFERENCES moderation.rules(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_decisions_action ON moderation.decisions(action);
CREATE INDEX IF NOT EXISTS ix_decisions_meta_gin ON moderation.decisions USING gin (metadata);

-- События по инцидентам (аудит-трек)
CREATE TABLE IF NOT EXISTS moderation.events (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id  uuid NOT NULL,
  event_kind   text NOT NULL,     -- created, status_change, note, assign, redact, external_ref
  actor_user_id uuid,
  from_status  moderation_status,
  to_status    moderation_status,
  note         text,
  payload      jsonb NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_events_incident FOREIGN KEY (incident_id) REFERENCES moderation.incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_events_incident_created ON moderation.events(incident_id, created_at);
CREATE INDEX IF NOT EXISTS ix_events_payload_gin ON moderation.events USING gin (payload);

-- Применённые редакции (замены/маскирование PII)
CREATE TABLE IF NOT EXISTS moderation.redactions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id   uuid NOT NULL,
  field         text NOT NULL,      -- поле исходного контента (например, body)
  kind          text NOT NULL,      -- mask, remove, replace
  range_start   integer,            -- позиционная редакция (опционально)
  range_end     integer,
  replacement   text,               -- чем заменили
  applied_by_user_id uuid,
  created_at    timestamptz NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_redactions_incident FOREIGN KEY (incident_id) REFERENCES moderation.incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_redactions_incident ON moderation.redactions(incident_id);

-- Внешние артефакты (снапшоты, вложения, ссылки)
CREATE TABLE IF NOT EXISTS moderation.artifacts (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id  uuid NOT NULL,
  name         text NOT NULL,
  uri          text NOT NULL,      -- ссылка на blob/object storage
  media_type   text,               -- MIME
  sha256       bytea,
  created_at   timestamptz NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_artifacts_incident FOREIGN KEY (incident_id) REFERENCES moderation.incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_artifacts_incident ON moderation.artifacts(incident_id);

-- Опциональные FK на пользователей (если существуют auth.users(id))
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'auth' AND table_name = 'users'
  ) THEN
    EXECUTE 'ALTER TABLE moderation.incidents
             ADD CONSTRAINT fk_incidents_reported_by
             FOREIGN KEY (reported_by_user_id) REFERENCES auth.users(id) ON DELETE SET NULL';
    EXCEPTION WHEN duplicate_object THEN
      -- FK уже существует
      NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'auth' AND table_name = 'users'
  ) THEN
    EXECUTE 'ALTER TABLE moderation.events
             ADD CONSTRAINT fk_events_actor
             FOREIGN KEY (actor_user_id) REFERENCES auth.users(id) ON DELETE SET NULL';
    EXCEPTION WHEN duplicate_object THEN
      NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'auth' AND table_name = 'users'
  ) THEN
    EXECUTE 'ALTER TABLE moderation.redactions
             ADD CONSTRAINT fk_redactions_actor
             FOREIGN KEY (applied_by_user_id) REFERENCES auth.users(id) ON DELETE SET NULL';
    EXCEPTION WHEN duplicate_object THEN
      NULL;
  END IF;
END $$;

-- Row Level Security по тенанту (org_id). Приложение должно выставлять:
-- SELECT set_config('mythos.current_org', '<UUID>', true);
ALTER TABLE moderation.policies   ENABLE ROW LEVEL SECURITY;
ALTER TABLE moderation.rules      ENABLE ROW LEVEL SECURITY;
ALTER TABLE moderation.incidents  ENABLE ROW LEVEL SECURITY;
ALTER TABLE moderation.decisions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE moderation.events     ENABLE ROW LEVEL SECURITY;
ALTER TABLE moderation.redactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE moderation.artifacts  ENABLE ROW LEVEL SECURITY;

-- Политики RLS: чтение/запись только в рамках текущего org_id
CREATE POLICY rls_policies_org ON moderation.policies
  USING (org_id::text = current_setting('mythos.current_org', true));

CREATE POLICY rls_rules_org ON moderation.rules
  USING (org_id::text = current_setting('mythos.current_org', true));

CREATE POLICY rls_incidents_org ON moderation.incidents
  USING (org_id::text = current_setting('mythos.current_org', true));

CREATE POLICY rls_decisions_org ON moderation.decisions
  USING (
    (SELECT org_id FROM moderation.incidents i WHERE i.id = incident_id)
      ::text = current_setting('mythos.current_org', true)
  );

CREATE POLICY rls_events_org ON moderation.events
  USING (
    (SELECT org_id FROM moderation.incidents i WHERE i.id = incident_id)
      ::text = current_setting('mythos.current_org', true)
  );

CREATE POLICY rls_redactions_org ON moderation.redactions
  USING (
    (SELECT org_id FROM moderation.incidents i WHERE i.id = incident_id)
      ::text = current_setting('mythos.current_org', true)
  );

CREATE POLICY rls_artifacts_org ON moderation.artifacts
  USING (
    (SELECT org_id FROM moderation.incidents i WHERE i.id = incident_id)
      ::text = current_setting('mythos.current_org', true)
  );

-- Комментарии для документации
COMMENT ON SCHEMA moderation IS 'Схема систем модерации контента Mythos Core';
COMMENT ON TYPE moderation_category IS 'Категории нарушений для модерации';
COMMENT ON TYPE moderation_status IS 'Жизненный цикл инцидента модерации';
COMMENT ON FUNCTION moderation.tg_incidents_status_guard() IS 'Проверка допустимых переходов статусов и установка временных меток';

COMMIT;
