-- 0003_legal_holds.sql
-- PostgreSQL 12+ (RLS, generated always/JSONB ops, extensions)
-- Транзакция миграции
-- migrate:up
BEGIN;

-- Расширения для UUID/GIN/TRGM
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Схема приложения
CREATE SCHEMA IF NOT EXISTS oblivion;

-- Типы
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'legal_hold_status') THEN
    CREATE TYPE oblivion.legal_hold_status AS ENUM ('active','paused','released');
  END IF;
END$$;

-- Основная таблица Legal Holds
CREATE TABLE IF NOT EXISTS oblivion.legal_holds (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT        NOT NULL,
  status        oblivion.legal_hold_status NOT NULL DEFAULT 'active',
  hard          BOOLEAN     NOT NULL DEFAULT FALSE, -- hard-hold запрещает override согласно политике
  title         TEXT        NOT NULL CHECK (length(title) > 0),
  description   TEXT,
  case_id       TEXT,                                -- опциональная основная связь с делом
  scope         JSONB       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(scope) = 'object'),
  labels        JSONB       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object'),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by    TEXT        NOT NULL,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by    TEXT,
  expires_at    TIMESTAMPTZ,
  -- Защита от нелогичных дат
  CONSTRAINT legal_hold_expires_after_created CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Индексы по частым фильтрам
CREATE INDEX IF NOT EXISTS idx_lh_tenant_status     ON oblivion.legal_holds (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_lh_active_expires    ON oblivion.legal_holds (expires_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_lh_case_partial      ON oblivion.legal_holds (tenant_id, case_id) WHERE status IN ('active','paused');
CREATE INDEX IF NOT EXISTS idx_lh_scope_gin         ON oblivion.legal_holds USING gin (scope jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_lh_labels_gin        ON oblivion.legal_holds USING gin (labels);

-- Аудит/обновление updated_at
CREATE OR REPLACE FUNCTION oblivion.tg_set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_lh_set_updated_at ON oblivion.legal_holds;
CREATE TRIGGER trg_lh_set_updated_at
BEFORE UPDATE ON oblivion.legal_holds
FOR EACH ROW EXECUTE FUNCTION oblivion.tg_set_updated_at();

-- Таблица approvals для двухперсонного правила
CREATE TABLE IF NOT EXISTS oblivion.legal_hold_approvals (
  id             BIGSERIAL PRIMARY KEY,
  hold_id        UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  approver_id    TEXT NOT NULL,
  approver_role  TEXT NOT NULL,
  justification  TEXT NOT NULL CHECK (length(trim(justification)) >= 10),
  approved_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_lh_approver UNIQUE (hold_id, approver_id)
);

CREATE INDEX IF NOT EXISTS idx_lh_appr_hold_time ON oblivion.legal_hold_approvals (hold_id, approved_at DESC);

-- Нормализованные индексные таблицы scope (+tenant_id для RLS)
CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_any (
  hold_id    UUID PRIMARY KEY REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_subjects (
  hold_id    UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id  TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  PRIMARY KEY (hold_id, subject_id)
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_cases (
  hold_id   UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  case_id   TEXT NOT NULL,
  PRIMARY KEY (hold_id, case_id)
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_labels (
  hold_id   UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  key       TEXT NOT NULL,
  value     TEXT NOT NULL,
  PRIMARY KEY (hold_id, key, value)
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_s3 (
  hold_id   UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  bucket    TEXT NOT NULL,
  prefix    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (hold_id, bucket, prefix)
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_posix (
  hold_id   UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  pattern   TEXT NOT NULL, -- glob-паттерн
  PRIMARY KEY (hold_id, pattern)
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_rdbms (
  hold_id   UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  engine    TEXT NOT NULL CHECK (engine IN ('postgres','clickhouse')),
  "database" TEXT NOT NULL,
  table_name TEXT NOT NULL,
  PRIMARY KEY (hold_id, engine, "database", table_name)
);

CREATE TABLE IF NOT EXISTS oblivion.legal_hold_scope_kafka (
  hold_id   UUID NOT NULL REFERENCES oblivion.legal_holds(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  topic     TEXT NOT NULL,
  PRIMARY KEY (hold_id, topic)
);

-- Индексы для быстрого поиска по скоупам
CREATE INDEX IF NOT EXISTS idx_lh_lbl_key_val      ON oblivion.legal_hold_scope_labels (key, value);
CREATE INDEX IF NOT EXISTS idx_lh_s3_bucket_pref   ON oblivion.legal_hold_scope_s3 (bucket, prefix);
CREATE INDEX IF NOT EXISTS idx_lh_posix_trgm       ON oblivion.legal_hold_scope_posix USING gin (pattern gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_lh_rdbms_db_tbl     ON oblivion.legal_hold_scope_rdbms (engine, "database", table_name);
CREATE INDEX IF NOT EXISTS idx_lh_subjects         ON oblivion.legal_hold_scope_subjects (subject_id);
CREATE INDEX IF NOT EXISTS idx_lh_kafka_topic      ON oblivion.legal_hold_scope_kafka (topic);

-- Функция синхронизации нормализованных таблиц из JSONB scope
CREATE OR REPLACE FUNCTION oblivion.sync_legal_hold_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_scope JSONB;
  v_any   BOOLEAN;
  v_item  JSONB;
  v_key   TEXT;
  v_val   JSONB;
  v_text  TEXT;
BEGIN
  -- Объект, который актуализируем
  v_scope := NEW.scope;

  -- Очистка старых записей
  DELETE FROM oblivion.legal_hold_scope_any     WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_subjects WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_cases    WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_labels   WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_s3       WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_posix    WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_rdbms    WHERE hold_id = NEW.id;
  DELETE FROM oblivion.legal_hold_scope_kafka    WHERE hold_id = NEW.id;

  -- any: true/false
  v_any := COALESCE( (v_scope ->> 'any')::BOOLEAN, FALSE );
  IF v_any THEN
    INSERT INTO oblivion.legal_hold_scope_any(hold_id, tenant_id)
    VALUES (NEW.id, NEW.tenant_id);
  END IF;

  -- subjects: ["subj-1","subj-2"]
  FOR v_item IN SELECT jsonb_array_elements(v_scope -> 'subjects')
  LOOP
    INSERT INTO oblivion.legal_hold_scope_subjects(hold_id, tenant_id, subject_id)
    VALUES (NEW.id, NEW.tenant_id, v_item::TEXT::TEXT);
  END LOOP;

  -- cases: ["CASE-123", ...]
  FOR v_item IN SELECT jsonb_array_elements(v_scope -> 'cases')
  LOOP
    INSERT INTO oblivion.legal_hold_scope_cases(hold_id, tenant_id, case_id)
    VALUES (NEW.id, NEW.tenant_id, v_item::TEXT::TEXT);
  END LOOP;

  -- labels: { "key": ["v1","v2"] | "v" }
  FOR v_key, v_val IN SELECT key, value FROM jsonb_each(v_scope -> 'labels')
  LOOP
    IF jsonb_typeof(v_val) = 'array' THEN
      FOR v_item IN SELECT jsonb_array_elements(v_val)
      LOOP
        INSERT INTO oblivion.legal_hold_scope_labels(hold_id, tenant_id, key, value)
        VALUES (NEW.id, NEW.tenant_id, v_key, v_item::TEXT::TEXT);
      END LOOP;
    ELSE
      INSERT INTO oblivion.legal_hold_scope_labels(hold_id, tenant_id, key, value)
      VALUES (NEW.id, NEW.tenant_id, v_key, v_val::TEXT::TEXT);
    END IF;
  END LOOP;

  -- s3: [{bucket:"...", prefix:"..."}]
  FOR v_item IN SELECT jsonb_array_elements(v_scope -> 's3')
  LOOP
    INSERT INTO oblivion.legal_hold_scope_s3(hold_id, tenant_id, bucket, prefix)
    VALUES (
      NEW.id, NEW.tenant_id,
      COALESCE(v_item ->> 'bucket',''),
      COALESCE(v_item ->> 'prefix','')
    );
  END LOOP;

  -- posix: [{glob:"/mnt/ov/media/**"}]
  FOR v_item IN SELECT jsonb_array_elements(v_scope -> 'posix')
  LOOP
    v_text := COALESCE(v_item ->> 'glob','');
    IF v_text <> '' THEN
      INSERT INTO oblivion.legal_hold_scope_posix(hold_id, tenant_id, pattern)
      VALUES (NEW.id, NEW.tenant_id, v_text);
    END IF;
  END LOOP;

  -- rdbms: [{engine:"postgres", database:"ov", table:"events"}]
  FOR v_item IN SELECT jsonb_array_elements(v_scope -> 'rdbms')
  LOOP
    INSERT INTO oblivion.legal_hold_scope_rdbms(hold_id, tenant_id, engine, "database", table_name)
    VALUES (
      NEW.id, NEW.tenant_id,
      COALESCE(v_item ->> 'engine',''),
      COALESCE(v_item ->> 'database',''),
      COALESCE(v_item ->> 'table','')
    );
  END LOOP;

  -- kafka: [{topic:"ov-audit"}]
  FOR v_item IN SELECT jsonb_array_elements(v_scope -> 'kafka')
  LOOP
    v_text := COALESCE(v_item ->> 'topic','');
    IF v_text <> '' THEN
      INSERT INTO oblivion.legal_hold_scope_kafka(hold_id, tenant_id, topic)
      VALUES (NEW.id, NEW.tenant_id, v_text);
    END IF;
  END LOOP;

  RETURN NEW;
END$$;

-- Триггеры синхронизации scope-индексов
DROP TRIGGER IF EXISTS trg_lh_sync_scope_ins ON oblivion.legal_holds;
CREATE TRIGGER trg_lh_sync_scope_ins
AFTER INSERT ON oblivion.legal_holds
FOR EACH ROW EXECUTE FUNCTION oblivion.sync_legal_hold_scope();

DROP TRIGGER IF EXISTS trg_lh_sync_scope_upd ON oblivion.legal_holds;
CREATE TRIGGER trg_lh_sync_scope_upd
AFTER UPDATE OF scope, tenant_id ON oblivion.legal_holds
FOR EACH ROW EXECUTE FUNCTION oblivion.sync_legal_hold_scope();

-- Представление активных Legal Hold с агрегированным скоупом (для API)
CREATE OR REPLACE VIEW oblivion.v_legal_holds_active AS
SELECT
  lh.*,
  EXISTS (SELECT 1 FROM oblivion.legal_hold_scope_any a WHERE a.hold_id = lh.id) AS scope_any
FROM oblivion.legal_holds lh
WHERE lh.status = 'active' AND (lh.expires_at IS NULL OR lh.expires_at > now());

CREATE OR REPLACE VIEW oblivion.v_legal_holds_scope_flat AS
SELECT
  lh.id,
  lh.tenant_id,
  lh.status,
  lh.hard,
  lh.title,
  lh.case_id,
  lh.expires_at,
  lh.created_at,
  lh.created_by,
  lh.updated_at,
  lh.updated_by,
  EXISTS (SELECT 1 FROM oblivion.legal_hold_scope_any a WHERE a.hold_id = lh.id) AS scope_any,
  COALESCE((
    SELECT ARRAY_AGG(s.subject_id ORDER BY s.subject_id)
    FROM oblivion.legal_hold_scope_subjects s WHERE s.hold_id = lh.id
  ), '{}') AS subjects,
  COALESCE((
    SELECT ARRAY_AGG(c.case_id ORDER BY c.case_id)
    FROM oblivion.legal_hold_scope_cases c WHERE c.hold_id = lh.id
  ), '{}') AS cases,
  COALESCE((
    SELECT jsonb_object_agg(k, vlist) FROM (
      SELECT l.key AS k, ARRAY_AGG(DISTINCT l.value ORDER BY l.value) AS vlist
      FROM oblivion.legal_hold_scope_labels l
      WHERE l.hold_id = lh.id
      GROUP BY l.key
    ) t
  ), '{}'::jsonb) AS labels_index,
  COALESCE((
    SELECT jsonb_agg(jsonb_build_object('bucket', s.bucket, 'prefix', s.prefix) ORDER BY s.bucket, s.prefix)
    FROM oblivion.legal_hold_scope_s3 s WHERE s.hold_id = lh.id
  ), '[]'::jsonb) AS s3,
  COALESCE((
    SELECT ARRAY_AGG(p.pattern ORDER BY p.pattern)
    FROM oblivion.legal_hold_scope_posix p WHERE p.hold_id = lh.id
  ), '{}') AS posix_patterns,
  COALESCE((
    SELECT jsonb_agg(jsonb_build_object('engine', r.engine, 'database', r."database", 'table', r.table_name)
                     ORDER BY r.engine, r."database", r.table_name)
    FROM oblivion.legal_hold_scope_rdbms r WHERE r.hold_id = lh.id
  ), '[]'::jsonb) AS rdbms,
  COALESCE((
    SELECT ARRAY_AGG(k.topic ORDER BY k.topic)
    FROM oblivion.legal_hold_scope_kafka k WHERE k.hold_id = lh.id
  ), '{}') AS kafka_topics
FROM oblivion.legal_holds lh;

-- Row Level Security (изоляция по tenant_id)
ALTER TABLE oblivion.legal_holds               ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_approvals      ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_any      ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_cases    ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_labels   ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_s3       ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_posix    ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_rdbms    ENABLE ROW LEVEL SECURITY;
ALTER TABLE oblivion.legal_hold_scope_kafka    ENABLE ROW LEVEL SECURITY;

-- Политики RLS. Ожидается, что app задаёт current_setting('app.tenant_id', true)
CREATE POLICY lh_tenant_isolation ON oblivion.legal_holds
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_appr_tenant_isolation ON oblivion.legal_hold_approvals
  USING (hold_id IN (SELECT id FROM oblivion.legal_holds WHERE tenant_id = current_setting('app.tenant_id', true)));

CREATE POLICY lh_any_tenant_isolation ON oblivion.legal_hold_scope_any
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_subj_tenant_isolation ON oblivion.legal_hold_scope_subjects
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_cases_tenant_isolation ON oblivion.legal_hold_scope_cases
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_labels_tenant_isolation ON oblivion.legal_hold_scope_labels
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_s3_tenant_isolation ON oblivion.legal_hold_scope_s3
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_posix_tenant_isolation ON oblivion.legal_hold_scope_posix
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_rdbms_tenant_isolation ON oblivion.legal_hold_scope_rdbms
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY lh_kafka_tenant_isolation ON oblivion.legal_hold_scope_kafka
  USING (tenant_id = current_setting('app.tenant_id', true));

COMMIT;

-- migrate:down
BEGIN;

DROP VIEW IF EXISTS oblivion.v_legal_holds_scope_flat;
DROP VIEW IF EXISTS oblivion.v_legal_holds_active;

DROP TRIGGER IF EXISTS trg_lh_sync_scope_upd ON oblivion.legal_holds;
DROP TRIGGER IF EXISTS trg_lh_sync_scope_ins ON oblivion.legal_holds;
DROP TRIGGER IF EXISTS trg_lh_set_updated_at ON oblivion.legal_holds;

DROP FUNCTION IF EXISTS oblivion.sync_legal_hold_scope();
DROP FUNCTION IF EXISTS oblivion.tg_set_updated_at();

DROP TABLE IF EXISTS oblivion.legal_hold_scope_kafka;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_rdbms;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_posix;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_s3;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_labels;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_cases;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_subjects;
DROP TABLE IF EXISTS oblivion.legal_hold_scope_any;
DROP TABLE IF EXISTS oblivion.legal_hold_approvals;
DROP TABLE IF EXISTS oblivion.legal_holds;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'legal_hold_status') THEN
    DROP TYPE oblivion.legal_hold_status;
  END IF;
END$$;

COMMIT;
