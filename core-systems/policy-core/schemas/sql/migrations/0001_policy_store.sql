-- policy-core/schemas/sql/migrations/0001_policy_store.sql
-- Создание хранилища политик для PostgreSQL 15+ (рекомендовано 16).
-- I cannot verify this.

BEGIN;

-- ---------------------------------------------
-- Безопасные таймауты и детерминированность
-- ---------------------------------------------
SET statement_timeout = '5min';
SET lock_timeout = '30s';
SET idle_in_transaction_session_timeout = '2min';
SET client_min_messages = warning;

-- ---------------------------------------------
-- Расширения
-- ---------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- digest()/gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- регистронезависимые ключи
CREATE EXTENSION IF NOT EXISTS btree_gin;  -- комбинированные индексы
CREATE EXTENSION IF NOT EXISTS btree_gist; -- для ограничений/индексов (при необходимости)

-- ---------------------------------------------
-- Схема
-- ---------------------------------------------
CREATE SCHEMA IF NOT EXISTS policy_core AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA policy_core IS 'Core schema for policy storage (policies, versions, audit).';

SET search_path = policy_core, public;

-- ---------------------------------------------
-- Типы
-- ---------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policy_status_enum') THEN
    CREATE TYPE policy_status_enum AS ENUM ('DRAFT', 'IN_REVIEW', 'APPROVED', 'PUBLISHED', 'DEPRECATED', 'ARCHIVED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policy_language_enum') THEN
    CREATE TYPE policy_language_enum AS ENUM ('REGO','CEL','DSL_V1','DSL_V2');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rollout_channel_enum') THEN
    CREATE TYPE rollout_channel_enum AS ENUM ('canary','stable','hotfix');
  END IF;
END$$;

-- ---------------------------------------------
-- Таблица проектов (мульти-тенант)
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_key   CITEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT projects_key_ck CHECK (length(project_key) BETWEEN 1 AND 128)
);
COMMENT ON TABLE projects IS 'Logical project/tenant boundary.';
COMMENT ON COLUMN projects.project_key IS 'Stable external identifier, unique across cluster.';

-- ---------------------------------------------
-- Общие функции/триггеры
-- ---------------------------------------------
-- Обновление updated_at при изменении строки.
CREATE OR REPLACE FUNCTION trg_touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- Вычисление sha256-хэша содержимого JSONB (детерминированно для jsonb).
CREATE OR REPLACE FUNCTION compute_content_hash(p_spec JSONB)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
  SELECT 'sha256:' || encode(digest(COALESCE(p_spec::text,'')::bytea, 'sha256'), 'hex')
$$;

-- Вычисление ETag из (content_hash, revision) в безопасном base64 (короткий).
CREATE OR REPLACE FUNCTION compute_etag(p_content_hash TEXT, p_revision BIGINT)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
  SELECT substring(encode(digest((COALESCE(p_content_hash,'') || ':' || p_revision)::bytea, 'sha256'), 'base64') FROM 1 FOR 27)
$$;

-- Проверка допустимости переходов статуса.
CREATE OR REPLACE FUNCTION assert_status_transition(old_status policy_status_enum, new_status policy_status_enum)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  IF old_status IS NULL THEN
    RETURN; -- вставка
  END IF;

  IF old_status = new_status THEN
    RETURN;
  END IF;

  IF old_status = 'DRAFT' AND new_status IN ('IN_REVIEW','ARCHIVED') THEN RETURN; END IF;
  IF old_status = 'IN_REVIEW' AND new_status IN ('APPROVED','DRAFT','ARCHIVED') THEN RETURN; END IF;
  IF old_status = 'APPROVED' AND new_status IN ('PUBLISHED','DEPRECATED') THEN RETURN; END IF;
  IF old_status = 'PUBLISHED' AND new_status IN ('DEPRECATED') THEN RETURN; END IF;
  IF old_status = 'DEPRECATED' AND new_status IN ('ARCHIVED') THEN RETURN; END IF;

  RAISE EXCEPTION 'Invalid status transition: % -> %', old_status, new_status
    USING ERRCODE = 'check_violation';
END $$;

-- ---------------------------------------------
-- Таблица policies (редактируемый ресурс)
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id     UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  policy_key     CITEXT NOT NULL,  -- уникален в рамках проекта
  display_name   TEXT NOT NULL,
  description    TEXT,
  labels         JSONB NOT NULL DEFAULT '{}'::jsonb,
  owners         TEXT[] NOT NULL DEFAULT '{}'::text[],
  -- Текущая редактируемая спецификация
  language       policy_language_enum NOT NULL DEFAULT 'REGO',
  entrypoint     TEXT,
  entrypoints    JSONB NOT NULL DEFAULT '{}'::jsonb,   -- map<string,string>
  spec           JSONB,                                -- inline/uri/bundle — как договоритесь на уровне приложения
  settings       JSONB NOT NULL DEFAULT '{}'::jsonb,   -- engine-specific opaque
  require_signature BOOLEAN NOT NULL DEFAULT FALSE,
  -- Текущее состояние/контроль версий
  status         policy_status_enum NOT NULL DEFAULT 'DRAFT',
  revision       BIGINT NOT NULL DEFAULT 0,
  content_hash   TEXT,
  signature      BYTEA,
  etag           TEXT,
  tags           TEXT[] NOT NULL DEFAULT '{}'::text[],
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, policy_key)
);
COMMENT ON TABLE policies IS 'Editable policy resource. Latest draft/spec and metadata live here.';
COMMENT ON COLUMN policies.policy_key IS 'Identifier unique per project (e.g., "authz.login").';

-- Индексы для поиска
CREATE INDEX IF NOT EXISTS idx_policies_project_key ON policies(project_id, policy_key);
CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_policies_labels_gin ON policies USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_policies_spec_gin   ON policies USING GIN (spec jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_policies_tags_gin   ON policies USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_policies_content_hash ON policies(content_hash);

-- Триггеры на policies
CREATE OR REPLACE FUNCTION trg_policies_before_ins_upd()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  new_hash TEXT;
BEGIN
  -- Контент-хэш и etag считаются от spec/revision
  IF TG_OP = 'INSERT' OR NEW.spec IS DISTINCT FROM OLD.spec THEN
    new_hash := compute_content_hash(NEW.spec);
    NEW.content_hash := new_hash;
  ELSE
    new_hash := COALESCE(NEW.content_hash, compute_content_hash(NEW.spec));
  END IF;

  IF TG_OP = 'UPDATE' AND NEW.spec IS DISTINCT FROM OLD.spec THEN
    NEW.revision := OLD.revision + 1;
  END IF;

  NEW.etag := compute_etag(new_hash, NEW.revision);

  RETURN NEW;
END $$;

CREATE TRIGGER policies_before_ins_upd
BEFORE INSERT OR UPDATE ON policies
FOR EACH ROW
EXECUTE FUNCTION trg_policies_before_ins_upd();

CREATE TRIGGER policies_touch_updated_at
BEFORE UPDATE ON policies
FOR EACH ROW
EXECUTE FUNCTION trg_touch_updated_at();

-- ---------------------------------------------
-- Таблица policy_versions (неизменяемые снимки)
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS policy_versions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  -- Последовательность версий внутри policy:
  version_seq     INTEGER NOT NULL,                -- 1..N внутри policy
  version_id      TEXT GENERATED ALWAYS AS ('v' || lpad(version_seq::text, 6, '0')) STORED,
  spec            JSONB NOT NULL,
  language        policy_language_enum NOT NULL,
  entrypoint      TEXT,
  entrypoints     JSONB NOT NULL DEFAULT '{}'::jsonb,
  settings        JSONB NOT NULL DEFAULT '{}'::jsonb,
  content_hash    TEXT NOT NULL,
  signature       BYTEA,
  status          policy_status_enum NOT NULL DEFAULT 'DRAFT',
  etag            TEXT NOT NULL,
  release_notes   TEXT,
  created_by      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_by     TEXT,
  approve_time    TIMESTAMPTZ,
  published_by    TEXT,
  publish_time    TIMESTAMPTZ,
  channel         rollout_channel_enum,
  UNIQUE (policy_id, version_seq),
  UNIQUE (policy_id, version_id)
);
COMMENT ON TABLE policy_versions IS 'Immutable snapshots of policy specs with lifecycle metadata.';

-- Индексы для выборок
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy ON policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_status ON policy_versions(status);
CREATE INDEX IF NOT EXISTS idx_policy_versions_hash   ON policy_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_policy_versions_spec_gin ON policy_versions USING GIN (spec jsonb_path_ops);

-- Получение следующего version_seq внутри policy в конкурентной среде
CREATE OR REPLACE FUNCTION next_version_seq(p_policy_id UUID)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
  seq INTEGER;
BEGIN
  -- Блокируем строку policy для последовательности версий
  PERFORM 1 FROM policies WHERE id = p_policy_id FOR UPDATE;
  SELECT COALESCE(MAX(version_seq), 0) + 1 INTO seq
  FROM policy_versions
  WHERE policy_id = p_policy_id;
  RETURN seq;
END $$;

-- Триггер наполняет служебные поля перед вставкой
CREATE OR REPLACE FUNCTION trg_policy_versions_before_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_seq INTEGER;
  v_hash TEXT;
BEGIN
  IF NEW.version_seq IS NULL OR NEW.version_seq <= 0 THEN
    v_seq := next_version_seq(NEW.policy_id);
    NEW.version_seq := v_seq;
  END IF;

  v_hash := compute_content_hash(NEW.spec);
  NEW.content_hash := v_hash;
  NEW.etag := compute_etag(v_hash, NEW.version_seq);

  RETURN NEW;
END $$;

CREATE TRIGGER policy_versions_before_insert
BEFORE INSERT ON policy_versions
FOR EACH ROW
EXECUTE FUNCTION trg_policy_versions_before_insert();

-- Иммутабельность policy_versions, кроме допускаемых переходов статуса и полей аудита
CREATE OR REPLACE FUNCTION trg_policy_versions_before_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  -- Контроль переходов статусов
  PERFORM assert_status_transition(OLD.status, NEW.status);

  -- Запрет модификации immutable полей
  IF NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.version_seq IS DISTINCT FROM OLD.version_seq
     OR NEW.version_id IS DISTINCT FROM OLD.version_id
     OR NEW.spec IS DISTINCT FROM OLD.spec
     OR NEW.language IS DISTINCT FROM OLD.language
     OR NEW.entrypoint IS DISTINCT FROM OLD.entrypoint
     OR NEW.entrypoints IS DISTINCT FROM OLD.entrypoints
     OR NEW.settings IS DISTINCT FROM OLD.settings
     OR NEW.content_hash IS DISTINCT FROM OLD.content_hash THEN
    RAISE EXCEPTION 'Immutable fields of policy_versions cannot be modified'
      USING ERRCODE = 'read_only_sql_transaction';
  END IF;

  -- Автозаполнение approve/publish таймштампов
  IF OLD.status <> 'APPROVED' AND NEW.status = 'APPROVED' AND NEW.approve_time IS NULL THEN
    NEW.approve_time := now();
  END IF;

  IF OLD.status <> 'PUBLISHED' AND NEW.status = 'PUBLISHED' AND NEW.publish_time IS NULL THEN
    NEW.publish_time := now();
  END IF;

  -- eTag пересчитывать не нужно (immutable), но если меняется статус — можно оставить прежним
  RETURN NEW;
END $$;

CREATE TRIGGER policy_versions_before_update
BEFORE UPDATE ON policy_versions
FOR EACH ROW
EXECUTE FUNCTION trg_policy_versions_before_update();

-- ---------------------------------------------
-- Зависимости версий (на другие policies/версии)
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS policy_version_deps (
  version_id             UUID NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
  depends_on_policy_id   UUID NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
  depends_on_version_id  UUID, -- опционально: фиксированная версия
  CONSTRAINT policy_version_deps_pk PRIMARY KEY (version_id, depends_on_policy_id, depends_on_version_id)
);
COMMENT ON TABLE policy_version_deps IS 'Explicit dependencies of a policy version on other policies/versions.';
CREATE INDEX IF NOT EXISTS idx_pvdeps_dep_policy ON policy_version_deps(depends_on_policy_id);
CREATE INDEX IF NOT EXISTS idx_pvdeps_dep_version ON policy_version_deps(depends_on_version_id);

-- ---------------------------------------------
-- Аудит событий (партиционирование по месяцам)
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
  id            BIGINT GENERATED BY DEFAULT AS IDENTITY,
  project_id    UUID NOT NULL,
  policy_id     UUID,
  policy_version_id UUID,
  actor         TEXT,            -- user:alice@example.com / svc:policy-admin
  verb          TEXT NOT NULL,   -- create/update/approve/publish/delete/rollback/…
  details       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
COMMENT ON TABLE audit_events IS 'Append-only audit trail of policy administrative actions.';

-- Текущий раздел
DO $$
DECLARE
  part_name TEXT;
  part_from TIMESTAMPTZ;
  part_to   TIMESTAMPTZ;
BEGIN
  part_from := date_trunc('month', now());
  part_to := part_from + INTERVAL '1 month';
  part_name := format('audit_events_%s', to_char(part_from, 'YYYYMM'));
  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events
    FOR VALUES FROM (%L) TO (%L)$f$, part_name, part_from, part_to);
END $$;

-- Индексы аудита
CREATE INDEX IF NOT EXISTS idx_audit_events_prj_time ON audit_events USING BRIN (project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_policy ON audit_events(policy_id);

-- ---------------------------------------------
-- Вьюхи быстрых выборок
-- ---------------------------------------------
CREATE OR REPLACE VIEW v_policies_latest_published AS
SELECT p.project_id, p.id AS policy_id, p.policy_key,
       v.id AS version_id, v.version_id AS version_str, v.publish_time, v.channel
FROM policies p
JOIN LATERAL (
  SELECT v1.* FROM policy_versions v1
  WHERE v1.policy_id = p.id AND v1.status = 'PUBLISHED'
  ORDER BY v1.publish_time DESC NULLS LAST, v1.version_seq DESC
  LIMIT 1
) v ON TRUE;

COMMENT ON VIEW v_policies_latest_published IS 'Latest published version per policy.';

-- ---------------------------------------------
-- RLS (опционально; включите при использовании PG-ролевой модели)
-- ---------------------------------------------
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_version_deps ENABLE ROW LEVEL SECURITY;

-- Роли-примеры: policy_core_admin (full), policy_core_app (read)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_core_admin') THEN
    CREATE ROLE policy_core_admin NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'policy_core_app') THEN
    CREATE ROLE policy_core_app NOINHERIT;
  END IF;
END $$;

-- Политики доступа: администраторам все
CREATE POLICY pol_policies_admin_all ON policies FOR ALL TO policy_core_admin USING (true) WITH CHECK (true);
CREATE POLICY pol_versions_admin_all ON policy_versions FOR ALL TO policy_core_admin USING (true) WITH CHECK (true);
CREATE POLICY pol_pvdeps_admin_all ON policy_version_deps FOR ALL TO policy_core_admin USING (true) WITH CHECK (true);

-- Приложению — только чтение
CREATE POLICY pol_policies_app_sel ON policies FOR SELECT TO policy_core_app USING (true);
CREATE POLICY pol_versions_app_sel ON policy_versions FOR SELECT TO policy_core_app USING (true);
CREATE POLICY pol_pvdeps_app_sel  ON policy_version_deps FOR SELECT TO policy_core_app USING (true);

-- ---------------------------------------------
-- Доп. проверки целостности
-- ---------------------------------------------
-- Нельзя хранить PUBLISHED в таблице policies (она отражает редактируемую "текущую" версию)
ALTER TABLE policies
  ADD CONSTRAINT policies_status_ck CHECK (status <> 'PUBLISHED');

-- Контроль ключей/имен
ALTER TABLE policies
  ADD CONSTRAINT policies_key_len_ck CHECK (length(policy_key) BETWEEN 1 AND 128);

-- ---------------------------------------------
-- Комментарии к столбцам
-- ---------------------------------------------
COMMENT ON COLUMN policies.labels IS 'Arbitrary labels map (JSONB).';
COMMENT ON COLUMN policies.owners IS 'List of owner principals.';
COMMENT ON COLUMN policies.spec IS 'Editable latest spec (JSONB).';
COMMENT ON COLUMN policies.settings IS 'Engine-specific opaque settings.';
COMMENT ON COLUMN policies.require_signature IS 'If true, signatures required on versions.';

COMMENT ON COLUMN policy_versions.version_seq IS 'Sequential number within a policy (1..N).';
COMMENT ON COLUMN policy_versions.version_id IS 'Readable id, e.g., v000001.';
COMMENT ON COLUMN policy_versions.channel IS 'Release channel for publishing.';

-- ---------------------------------------------
-- Завершение
-- ---------------------------------------------
COMMIT;
