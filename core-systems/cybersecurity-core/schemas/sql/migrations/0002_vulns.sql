-- file: cybersecurity-core/schemas/jsonschema/v1/sql/migrations/0002_vulns.sql
-- purpose: Industrial-grade vulnerabilities storage with RLS, partitioning, auditing, indexes.
-- requires: PostgreSQL 14+ (recommended), extensions pgcrypto, pg_trgm
-- author: Aethernova / cybersecurity-core

BEGIN;

-- 1) Базовая схема и расширения
CREATE SCHEMA IF NOT EXISTS security;

-- Расширения (генерация UUID и триграммы для поиска)
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 2) Типы-перечисления (ENUM) — создаём безопасно
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='vuln_severity' AND n.nspname='security') THEN
    EXECUTE $$CREATE TYPE security.vuln_severity AS ENUM ('low','medium','high','critical')$$;
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='vuln_status' AND n.nspname='security') THEN
    EXECUTE $$CREATE TYPE security.vuln_status AS ENUM (
      'open','in_progress','mitigated','resolved','accepted','false_positive','risk_accepted','duplicate','wont_fix','closed'
    )$$;
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='vuln_source' AND n.nspname='security') THEN
    EXECUTE $$CREATE TYPE security.vuln_source AS ENUM (
      'scanner','bug_bounty','pentest','siem','edr','oss_advisory','vendor_advisory','internal_report','external_report','other'
    )$$;
  END IF;
END$$;

-- 3) Служебные функции: нормализация и валидация

-- Валидация массива тегов без подзапросов в CHECK (immutable)
CREATE OR REPLACE FUNCTION security.tags_are_valid(tags text[])
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE t text;
BEGIN
  IF tags IS NULL THEN
    RETURN TRUE;
  END IF;
  FOREACH t IN ARRAY tags LOOP
    IF t IS NULL OR length(t) = 0 OR length(t) > 63 OR t !~ '^[a-z0-9][a-z0-9_.-]{0,62}$' THEN
      RETURN FALSE;
    END IF;
  END LOOP;
  RETURN TRUE;
END$$;

-- Обновление tsvector по названию/описанию
CREATE OR REPLACE FUNCTION security.vuln_update_search()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.search := to_tsvector('simple', coalesce(NEW.title,'') || ' ' || coalesce(NEW.description,''));
  RETURN NEW;
END$$;

-- Автообновление updated_at и lock_version
CREATE OR REPLACE FUNCTION security.touch_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  NEW.lock_version := COALESCE(OLD.lock_version, 0) + 1;
  RETURN NEW;
END$$;

-- Аудит изменений
CREATE TABLE IF NOT EXISTS security.vulnerabilities_audit
(
  audit_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action          text NOT NULL CHECK (action IN ('INSERT','UPDATE','DELETE')),
  changed_at      timestamptz NOT NULL DEFAULT now(),
  actor_id        text, -- ожидается app.user_id (uuid или login)
  tenant_id       uuid,
  vuln_id         uuid,
  old_row         jsonb,
  new_row         jsonb
);

CREATE OR REPLACE FUNCTION security.vuln_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_actor text := current_setting('app.user_id', true);
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO security.vulnerabilities_audit(action, actor_id, tenant_id, vuln_id, old_row, new_row)
    VALUES ('INSERT', v_actor, NEW.tenant_id, NEW.vuln_id, NULL, to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO security.vulnerabilities_audit(action, actor_id, tenant_id, vuln_id, old_row, new_row)
    VALUES ('UPDATE', v_actor, NEW.tenant_id, NEW.vuln_id, to_jsonb(OLD), to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO security.vulnerabilities_audit(action, actor_id, tenant_id, vuln_id, old_row, new_row)
    VALUES ('DELETE', v_actor, OLD.tenant_id, OLD.vuln_id, to_jsonb(OLD), NULL);
    RETURN OLD;
  END IF;
  RETURN NULL;
END$$;

-- 4) Основная таблица: декларативное партиционирование по discovered_at (год)
-- Партиционируем для масштабируемости и ретеншна.
CREATE TABLE IF NOT EXISTS security.vulnerabilities
(
  vuln_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL,
  source             security.vuln_source NOT NULL DEFAULT 'other',
  cve_id             text,           -- 'CVE-YYYY-NNNN...' (может отсутствовать до присвоения)
  title              text NOT NULL,
  description        text,
  status             security.vuln_status NOT NULL DEFAULT 'open',
  severity           security.vuln_severity NOT NULL DEFAULT 'medium',
  severity_level     int GENERATED ALWAYS AS
                      (CASE severity
                         WHEN 'low'::security.vuln_severity     THEN 1
                         WHEN 'medium'::security.vuln_severity  THEN 2
                         WHEN 'high'::security.vuln_severity    THEN 3
                         WHEN 'critical'::security.vuln_severity THEN 4
                       END) STORED,
  cvss_version       text CHECK (cvss_version IS NULL OR cvss_version IN ('2.0','3.0','3.1','4.0')),
  cvss_vector        text,                         -- оригинальный вектор (без строгого парсинга)
  cvss_base_score    numeric(4,1) CHECK (cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)),
  discovered_at      timestamptz NOT NULL DEFAULT now(),
  first_seen_at      timestamptz,
  last_seen_at       timestamptz,
  resolved_at        timestamptz,
  due_at             timestamptz,                 -- внутренний срок устранения
  tags               text[] DEFAULT '{}',
  evidence           jsonb,                       -- произвольные артефакты: скриншоты, трассы, ссылки
  references         jsonb,                       -- массив ссылок/советов (advisories), формально как JSON
  metadata           jsonb,                       -- кастомные поля (сканер, сенсоры и т.д.)
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  lock_version       integer NOT NULL DEFAULT 0,
  search             tsvector,                    -- tsvector по title/description
  -- Инварианты целостности
  CONSTRAINT cve_format_chk
    CHECK (cve_id IS NULL OR cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  CONSTRAINT timeline_chk
    CHECK (last_seen_at IS NULL OR first_seen_at IS NULL OR last_seen_at >= first_seen_at),
  CONSTRAINT status_resolution_chk
    CHECK (
      status NOT IN ('resolved','closed','mitigated','wont_fix','risk_accepted') OR resolved_at IS NOT NULL
    ),
  CONSTRAINT tags_valid_chk
    CHECK (security.tags_are_valid(tags))
)
PARTITION BY RANGE (discovered_at);

COMMENT ON TABLE security.vulnerabilities IS 'Реестр уязвимостей с RLS, партиционированием и аудитом';
COMMENT ON COLUMN security.vulnerabilities.tenant_id IS 'Арендатор (мультитенантность, RLS)';
COMMENT ON COLUMN security.vulnerabilities.cvss_vector IS 'Оригинальная строка CVSS (v2/v3/v4)';
COMMENT ON COLUMN security.vulnerabilities.search IS 'TSVECTOR для полнотекстового поиска по title/description';

-- 4.1) Партиции: текущий год + дефолт
DO $$
DECLARE
  y int := EXTRACT(YEAR FROM now())::int;
  part text := format('security.vulnerabilities_y%s', y);
  sql text;
BEGIN
  -- Партиция текущего года
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='security' AND c.relname=part
  ) THEN
    sql := format($$CREATE TABLE security.%I PARTITION OF security.vulnerabilities
                  FOR VALUES FROM (%L) TO (%L)$$,
                  part, make_timestamp(y,1,1,0,0,0)::timestamptz, make_timestamp(y+1,1,1,0,0,0)::timestamptz);
    EXECUTE sql;
  END IF;

  -- Дефолтная партиция (на случай «старых» дат)
  IF NOT EXISTS (
    SELECT 1 FROM pg_inherits i
    JOIN pg_class c ON c.oid=i.inhrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE i.inhparent = 'security.vulnerabilities'::regclass
      AND n.nspname='security' AND c.relname='vulnerabilities_default'
  ) THEN
    EXECUTE $$CREATE TABLE security.vulnerabilities_default
             PARTITION OF security.vulnerabilities DEFAULT$$;
  END IF;
END$$;

-- 5) Индексы и частичные уникальные ключи
-- Уникальность CVE в рамках арендатора, если CVE указан
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname='security' AND indexname='vulnerabilities_tenant_cve_uidx'
  ) THEN
    EXECUTE $$CREATE UNIQUE INDEX vulnerabilities_tenant_cve_uidx
             ON security.vulnerabilities (tenant_id, cve_id)
             WHERE cve_id IS NOT NULL$$;
  END IF;
END$$;

-- BTREE по статус/серьёзности/срокам
CREATE INDEX IF NOT EXISTS vulnerabilities_status_idx
  ON security.vulnerabilities (status);

CREATE INDEX IF NOT EXISTS vulnerabilities_severity_level_idx
  ON security.vulnerabilities (severity_level);

CREATE INDEX IF NOT EXISTS vulnerabilities_due_at_idx
  ON security.vulnerabilities (due_at);

-- BRIN по discovered_at (масштаб)
CREATE INDEX IF NOT EXISTS vulnerabilities_discovered_brin
  ON security.vulnerabilities USING BRIN (discovered_at);

-- GIN по tags и evidence/metadata для быстрых json/тег запросов
CREATE INDEX IF NOT EXISTS vulnerabilities_tags_gin
  ON security.vulnerabilities USING GIN (tags);

CREATE INDEX IF NOT EXISTS vulnerabilities_metadata_gin
  ON security.vulnerabilities USING GIN (metadata jsonb_path_ops);

CREATE INDEX IF NOT EXISTS vulnerabilities_evidence_gin
  ON security.vulnerabilities USING GIN (evidence jsonb_path_ops);

-- Полнотекстовый поиск
CREATE INDEX IF NOT EXISTS vulnerabilities_search_gin
  ON security.vulnerabilities USING GIN (search);

-- 6) Триггеры на базовой таблице (наследуются партициями)
DROP TRIGGER IF EXISTS trg_vuln_search ON security.vulnerabilities;
CREATE TRIGGER trg_vuln_search
BEFORE INSERT OR UPDATE OF title, description
ON security.vulnerabilities
FOR EACH ROW
EXECUTE FUNCTION security.vuln_update_search();

DROP TRIGGER IF EXISTS trg_vuln_touch ON security.vulnerabilities;
CREATE TRIGGER trg_vuln_touch
BEFORE UPDATE
ON security.vulnerabilities
FOR EACH ROW
EXECUTE FUNCTION security.touch_row();

DROP TRIGGER IF EXISTS trg_vuln_audit ON security.vulnerabilities;
CREATE TRIGGER trg_vuln_audit
AFTER INSERT OR UPDATE OR DELETE
ON security.vulnerabilities
FOR EACH ROW
EXECUTE FUNCTION security.vuln_audit();

-- 7) RLS: изоляция по tenant_id с использованием app.tenant_id
ALTER TABLE security.vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Политики: чтение и запись только в рамках текущего арендатора
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='security' AND tablename='vulnerabilities' AND policyname='vuln_tenant_select'
  ) THEN
    EXECUTE $policy$
      CREATE POLICY vuln_tenant_select ON security.vulnerabilities
      FOR SELECT
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
    $policy$;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='security' AND tablename='vulnerabilities' AND policyname='vuln_tenant_modify'
  ) THEN
    EXECUTE $policy$
      CREATE POLICY vuln_tenant_modify ON security.vulnerabilities
      FOR INSERT WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      TO PUBLIC;
    $policy$;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='security' AND tablename='vulnerabilities' AND policyname='vuln_tenant_update'
  ) THEN
    EXECUTE $policy$
      CREATE POLICY vuln_tenant_update ON security.vulnerabilities
      FOR UPDATE
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
    $policy$;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='security' AND tablename='vulnerabilities' AND policyname='vuln_tenant_delete'
  ) THEN
    EXECUTE $policy$
      CREATE POLICY vuln_tenant_delete ON security.vulnerabilities
      FOR DELETE
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
    $policy$;
  END IF;
END$$;

-- 8) Материализованный вид для быстрого выборочного доступа к «открытым» уязвимостям
CREATE MATERIALIZED VIEW IF NOT EXISTS security.vulnerabilities_open_mv AS
SELECT
  vuln_id, tenant_id, cve_id, title, severity, severity_level, status,
  discovered_at, due_at, last_seen_at
FROM security.vulnerabilities
WHERE status IN ('open','in_progress','mitigated')
WITH NO DATA;

-- Индекс для MV
CREATE INDEX IF NOT EXISTS vulnerabilities_open_mv_tenant_severity_idx
  ON security.vulnerabilities_open_mv (tenant_id, severity_level);

-- 9) Безошибочные гранты (выполняются только если роли существуют)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='security_app') THEN
    GRANT USAGE ON SCHEMA security TO security_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON security.vulnerabilities TO security_app;
    GRANT SELECT ON security.vulnerabilities_audit TO security_app;
    GRANT SELECT ON security.vulnerabilities_open_mv TO security_app;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='security_readonly') THEN
    GRANT USAGE ON SCHEMA security TO security_readonly;
    GRANT SELECT ON security.vulnerabilities TO security_readonly;
    GRANT SELECT ON security.vulnerabilities_open_mv TO security_readonly;
  END IF;
END$$;

COMMIT;
