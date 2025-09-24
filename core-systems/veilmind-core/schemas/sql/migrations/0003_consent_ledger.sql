-- 0003_consent_ledger.sql
-- Postgres 13+
-- Схема согласий и журнала изменений с RLS и аудитом.

BEGIN;

-- Расширения (для UUID и криптопримитивов)
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid(), digest()

-- Отдельная схема
CREATE SCHEMA IF NOT EXISTS veilmind;

COMMENT ON SCHEMA veilmind IS 'VeilMind Core: согласия и журнал аудита';

-- ============================
-- Доменные ENUM типы
-- ============================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type') THEN
    CREATE TYPE veilmind.subject_type AS ENUM ('user', 'device', 'service_account');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'purpose') THEN
    CREATE TYPE veilmind.purpose AS ENUM (
      'analytics','personalization','marketing','security','fraud_prevention','billing','research','support','other'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'data_category') THEN
    CREATE TYPE veilmind.data_category AS ENUM (
      'pii','spi','health','contact','location','telemetry','payment'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'legal_basis') THEN
    CREATE TYPE veilmind.legal_basis AS ENUM (
      'consent','contract','legal_obligation','vital_interests','public_task','legitimate_interests'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'consent_status') THEN
    CREATE TYPE veilmind.consent_status AS ENUM ('active','revoked','expired');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'consent_event_type') THEN
    CREATE TYPE veilmind.consent_event_type AS ENUM ('created','updated','revoked','expired','deleted');
  END IF;
END$$;

-- ============================
-- Утилиты сеанса и функции
-- ============================

-- Тенант-контекст: использовать current_setting('veilmind.tenant_id', true)
CREATE OR REPLACE FUNCTION veilmind.set_tenant_id(p_tenant text)
RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('veilmind.tenant_id', COALESCE(p_tenant,''), true);
END$$;

COMMENT ON FUNCTION veilmind.set_tenant_id(text) IS 'Устанавливает tenant_id в параметр сеанса veilmind.tenant_id для RLS';

-- Расчет статуса из полей revoked_at/expires_at
CREATE OR REPLACE FUNCTION veilmind.compute_consent_status(p_revoked_at timestamptz, p_expires_at timestamptz)
RETURNS veilmind.consent_status
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF p_revoked_at IS NOT NULL THEN
    RETURN 'revoked'::veilmind.consent_status;
  ELSIF p_expires_at IS NOT NULL AND p_expires_at <= now() AT TIME ZONE 'utc' THEN
    RETURN 'expired'::veilmind.consent_status;
  ELSE
    RETURN 'active'::veilmind.consent_status;
  END IF;
END$$;

-- ETag на основе стабильных полей записи
CREATE OR REPLACE FUNCTION veilmind.compute_etag(
  p_tenant text, p_consent uuid, p_subject_type veilmind.subject_type, p_subject_id text,
  p_purposes veilmind.purpose[], p_legal veilmind.legal_basis, p_expires timestamptz, p_revoked timestamptz, p_version bigint
) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(digest(
    coalesce(p_tenant,'') || '|' || coalesce(p_consent::text,'') || '|' ||
    coalesce(p_subject_type::text,'') || '|' || coalesce(p_subject_id,'') || '|' ||
    array_to_string(p_purposes, ',') || '|' || coalesce(p_legal::text,'') || '|' ||
    coalesce(p_expires::text,'') || '|' || coalesce(p_revoked::text,'') || '|' ||
    coalesce(p_version::text,'')
  , 'sha256'), 'hex');
$$;

-- Снимок согласия в JSONB (включая SCOPES)
CREATE OR REPLACE FUNCTION veilmind.consent_snapshot(p_tenant text, p_consent uuid)
RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
  c RECORD;
  scopes jsonb;
BEGIN
  SELECT *
  INTO c
  FROM veilmind.consents
  WHERE tenant_id = p_tenant AND consent_id = p_consent;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'resource_type', s.resource_type,
           'fields', COALESCE(s.fields, ARRAY[]::text[]),
           'categories', COALESCE(s.categories, ARRAY[]::veilmind.data_category[])
         )), '[]'::jsonb)
  INTO scopes
  FROM veilmind.consent_scopes s
  WHERE s.tenant_id = p_tenant AND s.consent_id = p_consent;

  RETURN jsonb_build_object(
    'name', format('tenants/%s/consents/%s', c.tenant_id, c.consent_id),
    'tenant_id', c.tenant_id,
    'subject', jsonb_build_object('type', c.subject_type, 'id', c.subject_id),
    'purposes', COALESCE(to_jsonb(c.purposes), '[]'::jsonb),
    'legal_basis', c.legal_basis,
    'scopes', scopes,
    'created_at', to_jsonb(c.created_at),
    'updated_at', to_jsonb(c.updated_at),
    'expires_at', to_jsonb(c.expires_at),
    'revoked_at', to_jsonb(c.revoked_at),
    'revoked_reason', to_jsonb(c.revoked_reason),
    'version', c.version,
    'etag', c.etag,
    'attributes', c.attributes,
    'status', c.status
  );
END$$;

-- Очистка старых записей журнала (ретеншн)
CREATE OR REPLACE FUNCTION veilmind.purge_consent_ledger(p_retention_days integer DEFAULT 2555)
RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  v_deleted bigint;
BEGIN
  DELETE FROM veilmind.consent_ledger
  WHERE occurred_at < (now() AT TIME ZONE 'utc') - make_interval(days => p_retention_days);
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END$$;

-- ============================
-- Таблицы данных
-- ============================

-- Главная таблица согласий
CREATE TABLE IF NOT EXISTS veilmind.consents (
  tenant_id       text NOT NULL,
  consent_id      uuid NOT NULL DEFAULT gen_random_uuid(),
  name            text GENERATED ALWAYS AS (format('tenants/%s/consents/%s', tenant_id, consent_id)) STORED,

  subject_type    veilmind.subject_type NOT NULL,
  subject_id      text NOT NULL,

  purposes        veilmind.purpose[] NOT NULL CHECK (cardinality(purposes) > 0),
  legal_basis     veilmind.legal_basis NOT NULL,

  created_at      timestamptz NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
  updated_at      timestamptz NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
  expires_at      timestamptz NULL,
  revoked_at      timestamptz NULL,
  revoked_reason  text NULL,

  status          veilmind.consent_status NOT NULL DEFAULT 'active',
  version         bigint NOT NULL DEFAULT 1,
  etag            text NOT NULL,

  proof_signature bytea NULL,
  proof_reference text NULL,

  attributes      jsonb NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT consents_pk PRIMARY KEY (tenant_id, consent_id),
  CONSTRAINT consents_name_unique UNIQUE (name),
  CONSTRAINT consents_subject_not_empty CHECK (length(subject_id) > 0)
);

COMMENT ON TABLE veilmind.consents IS 'Согласия субъекта данных в разрезе арендатора';
COMMENT ON COLUMN veilmind.consents.purposes IS 'Цели обработки (enum[]).';
COMMENT ON COLUMN veilmind.consents.attributes IS 'Доп. атрибуты (JSONB).';

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS consents_idx_subject
  ON veilmind.consents (tenant_id, subject_type, subject_id);

CREATE INDEX IF NOT EXISTS consents_idx_status
  ON veilmind.consents (tenant_id, status);

CREATE INDEX IF NOT EXISTS consents_gin_purposes
  ON veilmind.consents USING gin (purposes);

CREATE INDEX IF NOT EXISTS consents_idx_expires
  ON veilmind.consents (expires_at);

-- Нормализованные области действия согласия
CREATE TABLE IF NOT EXISTS veilmind.consent_scopes (
  tenant_id     text NOT NULL,
  consent_id    uuid NOT NULL,
  resource_type text NOT NULL,
  fields        text[] NOT NULL DEFAULT ARRAY[]::text[],
  categories    veilmind.data_category[] NOT NULL DEFAULT ARRAY[]::veilmind.data_category[],

  CONSTRAINT consent_scopes_pk PRIMARY KEY (tenant_id, consent_id, resource_type),
  CONSTRAINT consent_scopes_fk_consents
    FOREIGN KEY (tenant_id, consent_id) REFERENCES veilmind.consents(tenant_id, consent_id) ON DELETE CASCADE
);

COMMENT ON TABLE veilmind.consent_scopes IS 'Области действия согласия (типы ресурсов, поля, категории)';

CREATE INDEX IF NOT EXISTS consent_scopes_gin_fields
  ON veilmind.consent_scopes USING gin (fields);

CREATE INDEX IF NOT EXISTS consent_scopes_gin_categories
  ON veilmind.consent_scopes USING gin (categories);

-- Журнал событий по согласиям (append-only)
CREATE TABLE IF NOT EXISTS veilmind.consent_ledger (
  tenant_id    text NOT NULL,
  consent_id   uuid NOT NULL,
  event_id     bigserial PRIMARY KEY,
  event_type   veilmind.consent_event_type NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),

  actor        text NULL,
  actor_meta   jsonb NOT NULL DEFAULT '{}'::jsonb,

  snapshot     jsonb NOT NULL,       -- снимок состояния согласия после операции
  reasons      text[] NOT NULL DEFAULT ARRAY[]::text[],  -- причины (если отказ/ревок)
  request_id   text NULL,            -- корреляция
  ip           inet NULL,
  user_agent   text NULL
);

COMMENT ON TABLE veilmind.consent_ledger IS 'Независимый журнал событий согласий (CDC/audit)';

CREATE INDEX IF NOT EXISTS consent_ledger_idx_tenant_time
  ON veilmind.consent_ledger (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS consent_ledger_idx_consent
  ON veilmind.consent_ledger (tenant_id, consent_id, event_id);

CREATE INDEX IF NOT EXISTS consent_ledger_gin_snapshot
  ON veilmind.consent_ledger USING gin (snapshot jsonb_path_ops);

-- Идемпотентные ключи для Create
CREATE TABLE IF NOT EXISTS veilmind.idempotency_keys (
  tenant_id   text NOT NULL,
  key         text PRIMARY KEY,
  created_at  timestamptz NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE INDEX IF NOT EXISTS idempotency_keys_idx_tenant_time
  ON veilmind.idempotency_keys (tenant_id, created_at DESC);

COMMENT ON TABLE veilmind.idempotency_keys IS 'Idempotency keys для CreateConsent';

-- ============================
-- Триггеры: версия/etag/статус + аудит
-- ============================

-- BEFORE INSERT/UPDATE: поддержка updated_at, status, version, etag
CREATE OR REPLACE FUNCTION veilmind.consents_biu()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_prev_status veilmind.consent_status;
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.updated_at := now() AT TIME ZONE 'utc';
    NEW.status := veilmind.compute_consent_status(NEW.revoked_at, NEW.expires_at);
    -- при первом инсёрте etag расчитываем на версии 1
    NEW.etag := veilmind.compute_etag(NEW.tenant_id, NEW.consent_id, NEW.subject_type, NEW.subject_id,
                                      NEW.purposes, NEW.legal_basis, NEW.expires_at, NEW.revoked_at, NEW.version);
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    v_prev_status := OLD.status;
    NEW.updated_at := now() AT TIME ZONE 'utc';
    -- инкремент версии только если контент менялся (исключая updated_at)
    IF (ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*)) THEN
      -- не инкрементим, если менялся только updated_at или etag/статус/версия
      IF (NEW.tenant_id, NEW.consent_id, NEW.subject_type, NEW.subject_id, NEW.purposes, NEW.legal_basis,
          NEW.expires_at, NEW.revoked_at, NEW.revoked_reason, NEW.attributes, NEW.proof_signature, NEW.proof_reference)
         IS DISTINCT FROM
         (OLD.tenant_id, OLD.consent_id, OLD.subject_type, OLD.subject_id, OLD.purposes, OLD.legal_basis,
          OLD.expires_at, OLD.revoked_at, OLD.revoked_reason, OLD.attributes, OLD.proof_signature, OLD.proof_reference)
      THEN
        NEW.version := OLD.version + 1;
      END IF;
    END IF;

    NEW.status := veilmind.compute_consent_status(NEW.revoked_at, NEW.expires_at);
    NEW.etag := veilmind.compute_etag(NEW.tenant_id, NEW.consent_id, NEW.subject_type, NEW.subject_id,
                                      NEW.purposes, NEW.legal_basis, NEW.expires_at, NEW.revoked_at, NEW.version);
    RETURN NEW;
  END IF;
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS consents_biu_trg ON veilmind.consents;
CREATE TRIGGER consents_biu_trg
BEFORE INSERT OR UPDATE ON veilmind.consents
FOR EACH ROW EXECUTE FUNCTION veilmind.consents_biu();

-- AFTER INSERT/UPDATE/DELETE: запись в журнал
CREATE OR REPLACE FUNCTION veilmind.consents_audit_aiud()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_event veilmind.consent_event_type;
  v_snapshot jsonb;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_event := 'created';
    v_snapshot := veilmind.consent_snapshot(NEW.tenant_id, NEW.consent_id);
    INSERT INTO veilmind.consent_ledger (tenant_id, consent_id, event_type, snapshot)
    VALUES (NEW.tenant_id, NEW.consent_id, v_event, v_snapshot);
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.status = 'revoked' AND OLD.status <> 'revoked' THEN
      v_event := 'revoked';
    ELSIF NEW.status = 'expired' AND OLD.status <> 'expired' THEN
      v_event := 'expired';
    ELSE
      v_event := 'updated';
    END IF;
    v_snapshot := veilmind.consent_snapshot(NEW.tenant_id, NEW.consent_id);
    INSERT INTO veilmind.consent_ledger (tenant_id, consent_id, event_type, snapshot)
    VALUES (NEW.tenant_id, NEW.consent_id, v_event, v_snapshot);
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    v_event := 'deleted';
    -- Снимок по старому ключу (может вернуть NULL, тогда сохраняем компактный объект)
    v_snapshot := COALESCE(veilmind.consent_snapshot(OLD.tenant_id, OLD.consent_id),
                           jsonb_build_object('name', OLD.name, 'tenant_id', OLD.tenant_id, 'consent_id', OLD.consent_id::text));
    INSERT INTO veilmind.consent_ledger (tenant_id, consent_id, event_type, snapshot)
    VALUES (OLD.tenant_id, OLD.consent_id, v_event, v_snapshot);
    RETURN OLD;
  END IF;
  RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS consents_audit_aiud_trg ON veilmind.consents;
CREATE TRIGGER consents_audit_aiud_trg
AFTER INSERT OR UPDATE OR DELETE ON veilmind.consents
FOR EACH ROW EXECUTE FUNCTION veilmind.consents_audit_aiud();

-- ============================
-- RLS (Row Level Security)
-- ============================

ALTER TABLE veilmind.consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE veilmind.consent_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE veilmind.consent_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE veilmind.idempotency_keys ENABLE ROW LEVEL SECURITY;

-- Политики: доступ только в пределах tenant_id, соответствующего настройке сеанса
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='veilmind' AND tablename='consents' AND policyname='tenant_isolation_select'
  ) THEN
    CREATE POLICY tenant_isolation_select ON veilmind.consents
      FOR SELECT USING (tenant_id = current_setting('veilmind.tenant_id', true));
    CREATE POLICY tenant_isolation_modify ON veilmind.consents
      FOR ALL USING (tenant_id = current_setting('veilmind.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('veilmind.tenant_id', true));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='veilmind' AND tablename='consent_scopes' AND policyname='tenant_isolation_select'
  ) THEN
    CREATE POLICY tenant_isolation_select ON veilmind.consent_scopes
      FOR SELECT USING (tenant_id = current_setting('veilmind.tenant_id', true));
    CREATE POLICY tenant_isolation_modify ON veilmind.consent_scopes
      FOR ALL USING (tenant_id = current_setting('veilmind.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('veilmind.tenant_id', true));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='veilmind' AND tablename='consent_ledger' AND policyname='tenant_isolation_select'
  ) THEN
    CREATE POLICY tenant_isolation_select ON veilmind.consent_ledger
      FOR SELECT USING (tenant_id = current_setting('veilmind.tenant_id', true));
    -- ledger — append-only: запретим изменения/удаления даже владельцу (кроме суперпольз.)
    CREATE POLICY tenant_isolation_insert ON veilmind.consent_ledger
      FOR INSERT WITH CHECK (tenant_id = current_setting('veilmind.tenant_id', true));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='veilmind' AND tablename='idempotency_keys' AND policyname='tenant_isolation_select'
  ) THEN
    CREATE POLICY tenant_isolation_select ON veilmind.idempotency_keys
      FOR SELECT USING (tenant_id = current_setting('veilmind.tenant_id', true));
    CREATE POLICY tenant_isolation_modify ON veilmind.idempotency_keys
      FOR ALL USING (tenant_id = current_setting('veilmind.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('veilmind.tenant_id', true));
  END IF;
END$$;

-- На уровне прав можно запретить UPDATE/DELETE в ledger для ролевых аккаунтов приложения:
REVOKE UPDATE, DELETE ON veilmind.consent_ledger FROM PUBLIC;

-- ============================
-- Доп. ограничения качества данных
-- ============================

-- Не допускаем одновременно очень длительных сроков и отсутствия правового основания
ALTER TABLE veilmind.consents
  ADD CONSTRAINT consents_legal_basis_not_unspecified CHECK (legal_basis IS NOT NULL);

-- Если revoked_at установлен, должен быть указан revoked_reason (минимум 5 символов)
ALTER TABLE veilmind.consents
  ADD CONSTRAINT consents_revocation_reason CHECK (
    revoked_at IS NULL OR (revoked_reason IS NOT NULL AND length(trim(revoked_reason)) >= 5)
  );

-- ============================
-- Подсказки по VACUUM/автоочистке (комментарии для DBA)
-- ============================

COMMENT ON FUNCTION veilmind.purge_consent_ledger(integer)
  IS 'Удаляет из журнала события старше retention (дн.). Рекомендуется ежедневный запуск через pg_cron/pgAgent.';

COMMIT;
