-- datafabric-core/schemas/sql/migrations/0001_init.sql
-- Постгрес 13+ / прод-уровень. Идемпотентность, блокировка, партиционирование, RBAC, аудит.

-- =========================================
-- 0) Транзакция и защита от параллельного запуска
-- =========================================
BEGIN;

-- Advisory lock (константа — хэш пространства миграций). Освободится при COMMIT/ROLLBACK.
SELECT pg_advisory_lock(827154221551000001);

-- =========================================
-- 1) Расширения (безопасно при повторном запуске)
-- =========================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gin;    -- GIN для btree опов
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- триграммы (поиск, LIKE)

-- =========================================
-- 2) Схемы и базовые настройки
-- =========================================
CREATE SCHEMA IF NOT EXISTS datafabric AUTHORIZATION CURRENT_USER;
CREATE SCHEMA IF NOT EXISTS app_private AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA datafabric IS 'Публичные объекты приложения Datafabric Core';
COMMENT ON SCHEMA app_private IS 'Приватные объекты (функции/триггеры/служебное)';

-- =========================================
-- 3) Типы / enum'ы
-- =========================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'task_state') THEN
    CREATE TYPE datafabric.task_state AS ENUM (
      'PENDING','QUEUED','LEASED','RUNNING','SUCCEEDED','FAILED','CANCELLED','EXPIRED'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'task_priority') THEN
    CREATE TYPE datafabric.task_priority AS ENUM ('LOW','NORMAL','HIGH','CRITICAL');
  END IF;
END$$;

-- =========================================
-- 4) Служебные функции и триггеры
-- =========================================

-- Автообновление updated_at
CREATE OR REPLACE FUNCTION app_private.set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now() AT TIME ZONE 'UTC';
  RETURN NEW;
END$$;

-- Запрет изменения created_at
CREATE OR REPLACE FUNCTION app_private.protect_created_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'created_at is immutable';
  END IF;
  RETURN NEW;
END$$;

-- Валидатор, что timestamptz в UTC (offset = 0)
CREATE OR REPLACE FUNCTION app_private.ensure_utc(ts timestamptz)
RETURNS timestamptz LANGUAGE sql IMMUTABLE AS $$
  SELECT ts AT TIME ZONE 'UTC'
$$;

-- =========================================
-- 5) Таблица версий миграций
-- =========================================
CREATE TABLE IF NOT EXISTS datafabric.schema_version (
  id              smallserial PRIMARY KEY,
  version         text        NOT NULL UNIQUE,
  applied_at      timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  checksum        text        NOT NULL,
  meta            jsonb       NOT NULL DEFAULT '{}'
);
COMMENT ON TABLE datafabric.schema_version IS 'История применённых миграций';

-- Регистрируем текущую миграцию, если не записана
INSERT INTO datafabric.schema_version(version, checksum, meta)
SELECT '0001_init', 'sha256:bootstrap', '{}'
WHERE NOT EXISTS (SELECT 1 FROM datafabric.schema_version WHERE version = '0001_init');

-- =========================================
-- 6) Tenants (мульти-аренда)
-- =========================================
CREATE TABLE IF NOT EXISTS datafabric.tenants (
  tenant_id    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         citext      NOT NULL UNIQUE,
  name         text        NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  updated_at   timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  active       boolean     NOT NULL DEFAULT true,
  labels       jsonb       NOT NULL DEFAULT '{}'
);

CREATE TRIGGER trg_tenants_set_updated
BEFORE UPDATE ON datafabric.tenants
FOR EACH ROW EXECUTE FUNCTION app_private.set_updated_at();

CREATE TRIGGER trg_tenants_protect_created
BEFORE UPDATE ON datafabric.tenants
FOR EACH ROW EXECUTE FUNCTION app_private.protect_created_at();

COMMENT ON TABLE datafabric.tenants IS 'Арендаторы/изоляторы (multi-tenant)';

-- =========================================
-- 7) Connectors registry
-- =========================================
CREATE TABLE IF NOT EXISTS datafabric.connectors (
  connector_id uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid        NOT NULL REFERENCES datafabric.tenants(tenant_id) ON DELETE CASCADE,
  key          text        NOT NULL,
  type         text        NOT NULL,
  spec         jsonb       NOT NULL, -- валидируется приложением
  created_at   timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  updated_at   timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  enabled      boolean     NOT NULL DEFAULT true,
  UNIQUE(tenant_id, key)
);

CREATE INDEX IF NOT EXISTS idx_connectors_tenant_key ON datafabric.connectors(tenant_id, key);
CREATE INDEX IF NOT EXISTS idx_connectors_type ON datafabric.connectors(type);
CREATE INDEX IF NOT EXISTS idx_connectors_enabled ON datafabric.connectors(enabled);

CREATE TRIGGER trg_connectors_set_updated
BEFORE UPDATE ON datafabric.connectors
FOR EACH ROW EXECUTE FUNCTION app_private.set_updated_at();

CREATE TRIGGER trg_connectors_protect_created
BEFORE UPDATE ON datafabric.connectors
FOR EACH ROW EXECUTE FUNCTION app_private.protect_created_at();

COMMENT ON TABLE datafabric.connectors IS 'Реестр коннекторов с параметрами и статусом';

-- =========================================
-- 8) Events (append-only, партиционирование по месяцу)
-- =========================================

-- Родительская таблица
CREATE TABLE IF NOT EXISTS datafabric.events (
  event_id        uuid        NOT NULL,
  tenant_id       uuid        NOT NULL REFERENCES datafabric.tenants(tenant_id) ON DELETE CASCADE,
  type            text        NOT NULL,
  subject         text,
  partition_key   text,
  occurred_at     timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  received_at     timestamptz NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  headers         jsonb       NOT NULL DEFAULT '{}',
  attributes      jsonb       NOT NULL DEFAULT '{}',
  payload         jsonb       NOT NULL, -- Avro/Protobuf сохраняйте как bytes отдельно; jsonb для поиска
  trace_id        text,
  span_id         text,
  correlation_id  text,
  PRIMARY KEY (tenant_id, event_id)
) PARTITION BY RANGE (occurred_at);

COMMENT ON TABLE datafabric.events IS 'События (append-only), партиционирование по времени';

-- Функция создания месячной партиции
CREATE OR REPLACE FUNCTION app_private.ensure_events_partition(p_month date)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  start_ts timestamptz := date_trunc('month', p_month)::timestamptz;
  end_ts   timestamptz := (date_trunc('month', p_month) + INTERVAL '1 month')::timestamptz;
  part_name text := format('events_y%sm% s', to_char(start_ts,'YYYY'), to_char(start_ts,'MM'));
  full_name text := format('datafabric.%I', part_name);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname='datafabric' AND c.relname=part_name) THEN
    EXECUTE format('CREATE TABLE %s PARTITION OF datafabric.events
                    FOR VALUES FROM (%L) TO (%L);',
                    full_name, start_ts, end_ts);
    -- Индексы на партиции
    EXECUTE format('CREATE INDEX %I ON %s(tenant_id, occurred_at);', part_name||'_tenant_time', full_name);
    EXECUTE format('CREATE INDEX %I ON %s(type);',         part_name||'_type', full_name);
    EXECUTE format('CREATE INDEX %I ON %s((attributes->>''subject''));', part_name||'_attr_subject', full_name);
    EXECUTE format('CREATE INDEX %I ON %s USING GIN (payload jsonb_path_ops);', part_name||'_payload_gin', full_name);
  END IF;
END$$;

-- Создаём партицию на текущий месяц и следующий (превентивно)
SELECT app_private.ensure_events_partition(date_trunc('month', now())::date);
SELECT app_private.ensure_events_partition((date_trunc('month', now()) + INTERVAL '1 month')::date);

-- =========================================
-- 9) Batch tasks / attempts / leases
-- =========================================

CREATE TABLE IF NOT EXISTS datafabric.batch_tasks (
  task_id        uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid            NOT NULL REFERENCES datafabric.tenants(tenant_id) ON DELETE CASCADE,
  client_id      text            NOT NULL,     -- инициатор (для квот/аудита)
  dedup_key      text,                           -- идемпотентность на уровне клиента
  priority       datafabric.task_priority NOT NULL DEFAULT 'NORMAL',
  state          datafabric.task_state    NOT NULL DEFAULT 'PENDING',
  kind           text            NOT NULL,     -- CONTAINER|SQL|SPARK|SCRIPT
  spec           jsonb           NOT NULL,     -- TaskSpec (см. protobuf)
  labels         jsonb           NOT NULL DEFAULT '{}',
  annotations    jsonb           NOT NULL DEFAULT '{}',
  created_at     timestamptz     NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  updated_at     timestamptz     NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  queued_at      timestamptz,
  started_at     timestamptz,
  finished_at    timestamptz,
  error          jsonb,                        -- сериализованный ErrorStatus
  result         jsonb,                        -- TaskResult summary
  UNIQUE (tenant_id, client_id, dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_tasks_tenant_state ON datafabric.batch_tasks(tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_tasks_priority ON datafabric.batch_tasks(priority);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON datafabric.batch_tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_kind ON datafabric.batch_tasks(kind);

CREATE TRIGGER trg_tasks_set_updated
BEFORE UPDATE ON datafabric.batch_tasks
FOR EACH ROW EXECUTE FUNCTION app_private.set_updated_at();

CREATE TRIGGER trg_tasks_protect_created
BEFORE UPDATE ON datafabric.batch_tasks
FOR EACH ROW EXECUTE FUNCTION app_private.protect_created_at();

COMMENT ON TABLE datafabric.batch_tasks IS 'Очередь пакетных задач (спецификация и агрегированный статус)';

-- Попытки выполнения (история)
CREATE TABLE IF NOT EXISTS datafabric.batch_task_attempts (
  attempt_id     bigserial      PRIMARY KEY,
  task_id        uuid           NOT NULL REFERENCES datafabric.batch_tasks(task_id) ON DELETE CASCADE,
  attempt        int            NOT NULL CHECK (attempt >= 1),
  worker_id      text,
  leased_at      timestamptz    NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  started_at     timestamptz,
  finished_at    timestamptz,
  runtime_ms     int,
  progress_pct   real           CHECK (progress_pct BETWEEN 0 AND 100),
  metrics        jsonb          NOT NULL DEFAULT '{}',
  error          jsonb,
  result         jsonb,
  UNIQUE(task_id, attempt)
);

CREATE INDEX IF NOT EXISTS idx_attempts_task_attempt ON datafabric.batch_task_attempts(task_id, attempt DESC);

COMMENT ON TABLE datafabric.batch_task_attempts IS 'История попыток выполнения задач';

-- Текущие "лизинги" задач воркерам
CREATE TABLE IF NOT EXISTS datafabric.batch_task_leases (
  lease_id       uuid           PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id        uuid           NOT NULL UNIQUE REFERENCES datafabric.batch_tasks(task_id) ON DELETE CASCADE,
  worker_id      text           NOT NULL,
  expires_at     timestamptz    NOT NULL,
  heartbeat_at   timestamptz    NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  created_at     timestamptz    NOT NULL DEFAULT now() AT TIME ZONE 'UTC'
);

CREATE INDEX IF NOT EXISTS idx_leases_expiry ON datafabric.batch_task_leases(expires_at);
CREATE INDEX IF NOT EXISTS idx_leases_worker ON datafabric.batch_task_leases(worker_id);

COMMENT ON TABLE datafabric.batch_task_leases IS 'Лизинги задач (эксклюзивное владение воркера до истечения)';

-- =========================================
-- 10) Аудит
-- =========================================
CREATE TABLE IF NOT EXISTS datafabric.audit_log (
  audit_id     bigserial      PRIMARY KEY,
  tenant_id    uuid           NOT NULL REFERENCES datafabric.tenants(tenant_id) ON DELETE CASCADE,
  who          text           NOT NULL,           -- субъект (oidc sub/имя сервиса)
  action       text           NOT NULL,           -- CRUD/INGEST/EXPORT/CONFIG/…
  resource     text           NOT NULL,           -- URI/FQN сущности
  success      boolean        NOT NULL,
  severity     text           NOT NULL DEFAULT 'INFO',
  occurred_at  timestamptz    NOT NULL DEFAULT now() AT TIME ZONE 'UTC',
  attributes   jsonb          NOT NULL DEFAULT '{}' -- PII-free
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON datafabric.audit_log(tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON datafabric.audit_log(resource);

COMMENT ON TABLE datafabric.audit_log IS 'Аудит действий (PII-free, для комплаенса и расследований)';

-- =========================================
-- 11) RBAC (минимальные роли/привилегии)
-- Пример: создаем роли только если их нет. Привяжите к вашим группам/USERS отдельно.
-- =========================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'df_readonly') THEN
    CREATE ROLE df_readonly;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'df_writer') THEN
    CREATE ROLE df_writer;
  END IF;
END$$;

GRANT USAGE ON SCHEMA datafabric TO df_readonly, df_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA datafabric TO df_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA datafabric TO df_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA datafabric GRANT SELECT ON TABLES TO df_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA datafabric GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO df_writer;

-- =========================================
-- 12) RLS (пример включения для events; по умолчанию OFF — включайте осознанно)
-- =========================================
-- ALTER TABLE datafabric.events ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY events_tenant_isolation ON datafabric.events
--   USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
-- COMMENT: приложение должно выставлять SET app.tenant_id = '<uuid>';

-- =========================================
-- 13) Завершение: фиксация и unlock
-- =========================================
COMMIT;
-- Освобождение advisory lock происходит автоматически при COMMIT.
