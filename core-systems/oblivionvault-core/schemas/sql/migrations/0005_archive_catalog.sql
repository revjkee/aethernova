-- ============================================================
-- OblivionVault Core — Migration 0005: Archive Catalog (PostgreSQL)
-- Requirements: PostgreSQL 13+, extension pgcrypto
-- Idempotent and transaction-safe
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 0) Extensions
-- ------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------
-- 1) Schema
-- ------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS archive;
COMMENT ON SCHEMA archive IS 'OblivionVault: архивный каталог, объекты хранения и цепочка доказательств';

-- ------------------------------------------------------------
-- 2) Types (SAFE create if missing)
-- ------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='archive_status' AND n.nspname='archive') THEN
    CREATE TYPE archive.archive_status AS ENUM (
      'AVAILABLE',   -- доступен
      'SEALED',      -- запечатан (read-only)
      'FROZEN',      -- заморожен (legal hold)
      'RECALLED',    -- отозван в онлайновое хранилище
      'DELETED'      -- физически удалён (каталожная запись может жить)
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='storage_backend' AND n.nspname='archive') THEN
    CREATE TYPE archive.storage_backend AS ENUM (
      'S3','MINIO','GCS','AZURE_BLOB','GLACIER','FS','NFS'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='hash_algo' AND n.nspname='archive') THEN
    CREATE TYPE archive.hash_algo AS ENUM ('SHA256','SHA3_512','BLAKE3');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='coc_event' AND n.nspname='archive') THEN
    CREATE TYPE archive.coc_event AS ENUM (
      'INGEST','SEAL','LEGAL_HOLD_APPLY','LEGAL_HOLD_RELEASE',
      'RECALL','ERASURE','EXPORT','VERIFY','MUTATION','NOTE'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='source_system' AND n.nspname='archive') THEN
    CREATE TYPE archive.source_system AS ENUM (
      'POSTGRES','MYSQL','CLICKHOUSE','ELASTICSEARCH','KAFKA','S3','MINIO','GCS','AZURE_BLOB','FS','NFS','KUBERNETES'
    );
  END IF;
END$$;

-- ------------------------------------------------------------
-- 3) Security helpers & RLS
-- ------------------------------------------------------------

-- GUC-установщик текущего арендатора (для RLS)
CREATE OR REPLACE FUNCTION archive.set_tenant(p_tenant text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM set_config('oblivionvault.tenant_id', COALESCE(p_tenant,''), true);
END$$;
COMMENT ON FUNCTION archive.set_tenant(text) IS 'Устанавливает текущего арендатора в GUC oblivionvault.tenant_id для RLS.';

-- Утилита чтения текущего арендатора (NULL-safe)
CREATE OR REPLACE FUNCTION archive.current_tenant()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('oblivionvault.tenant_id', true), '')
$$;
COMMENT ON FUNCTION archive.current_tenant() IS 'Возвращает текущий tenant_id из GUC или NULL.';

-- ------------------------------------------------------------
-- 4) Core tables
-- ------------------------------------------------------------

-- 4.1) Бэкенды/бакеты хранения
CREATE TABLE IF NOT EXISTS archive.bucket (
  bucket_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text        NOT NULL,                       -- логическое имя/ARN/имя бакета
  backend        archive.storage_backend NOT NULL,
  region         text,
  endpoint       text,
  kms_key_arn    text,
  config         jsonb       NOT NULL DEFAULT '{}'::jsonb,   -- доп. опции провайдера
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (name, backend)
);
COMMENT ON TABLE archive.bucket IS 'Регистр хранилищ (S3/MinIO/...); хранит параметры и метки безопасности.';
COMMENT ON COLUMN archive.bucket.config IS 'Произвольные безопасные настройки (без секретов).';

-- 4.2) Логические "сейфы" (vaults) поверх бакетов
CREATE TABLE IF NOT EXISTS archive.vault (
  vault_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      text        NOT NULL,
  title          text        NOT NULL,
  bucket_id      uuid        NOT NULL REFERENCES archive.bucket(bucket_id) ON DELETE RESTRICT,
  base_prefix    text        NOT NULL DEFAULT '',
  retention_min  interval    NOT NULL DEFAULT interval '365 days',
  retention_max  interval    NOT NULL DEFAULT interval '3650 days',
  compliance_mode boolean    NOT NULL DEFAULT true,     -- запрет сокращения ретеншена
  legal_hold_default boolean NOT NULL DEFAULT false,    -- включать hold по умолчанию
  labels         jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_by     text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, title)
);
COMMENT ON TABLE archive.vault IS 'Логические контейнеры архива в разрезе арендатора и политики ретеншена.';
ALTER TABLE archive.vault
  ADD CONSTRAINT vault_labels_is_object CHECK (jsonb_typeof(labels) = 'object');

-- 4.3) Каталог архивных единиц (partitioned by RANGE archived_at month)
CREATE TABLE IF NOT EXISTS archive.catalog (
  catalog_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      text        NOT NULL,
  vault_id       uuid        NOT NULL REFERENCES archive.vault(vault_id) ON DELETE RESTRICT,
  status         archive.archive_status NOT NULL DEFAULT 'AVAILABLE',
  legal_hold     boolean     NOT NULL DEFAULT false,
  legal_matter_id text,
  source_system  archive.source_system NOT NULL,
  source_ref     text        NOT NULL,          -- таблица/индекс/бакет:префикс и т.п.
  object_id      text        NOT NULL,          -- первичный ключ/URI/путь в исходной системе
  locator        jsonb       NOT NULL,          -- унифицированный указатель на физический объект
  size_bytes     bigint      NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
  content_type   text,
  storage_uri    text        NOT NULL,          -- canonical URI (s3://bucket/prefix/key?versionId=...)
  backend        archive.storage_backend NOT NULL,
  hash_algo      archive.hash_algo NOT NULL DEFAULT 'SHA256',
  hash_value     bytea       NOT NULL,          -- бинарный digest
  e_tag          text,                          -- для S3-совместимых
  version_id     text,                          -- версия в объектном хранилище
  archived_at    timestamptz NOT NULL DEFAULT now(),  -- время помещения в архив
  expires_at     timestamptz,                   -- дата, когда ретеншен позволяет удалить
  recalled_at    timestamptz,
  deleted_at     timestamptz,
  labels         jsonb       NOT NULL DEFAULT '{}'::jsonb,
  metadata       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_by     text,
  updated_at     timestamptz NOT NULL DEFAULT now()
)
PARTITION BY RANGE (archived_at);
COMMENT ON TABLE archive.catalog IS 'Каталог архивных единиц с партиционированием по дате помещения в архив.';
ALTER TABLE archive.catalog
  ADD CONSTRAINT catalog_labels_is_object CHECK (jsonb_typeof(labels) = 'object');
ALTER TABLE archive.catalog
  ADD CONSTRAINT catalog_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object');

-- 4.4) Цепочка доказательств (hash chain)
CREATE TABLE IF NOT EXISTS archive.chain_of_custody (
  coc_id        bigserial PRIMARY KEY,
  catalog_id    uuid NOT NULL REFERENCES archive.catalog(catalog_id) ON DELETE CASCADE,
  seq_no        bigint NOT NULL,                              -- порядковый номер события в рамках catalog_id
  event_type    archive.coc_event NOT NULL,
  actor         text NOT NULL,                                -- пользователь/сервис
  actor_roles   text[] NOT NULL DEFAULT '{}',
  event_time    timestamptz NOT NULL DEFAULT now(),
  details       jsonb NOT NULL DEFAULT '{}'::jsonb,           -- произвольные детали
  prev_hash     bytea,                                        -- хеш предыдущего события
  curr_hash     bytea,                                        -- хеш текущего события (по полям)
  signature     bytea,                                        -- опционально KMS/PKI подпись curr_hash
  UNIQUE (catalog_id, seq_no)
);
COMMENT ON TABLE archive.chain_of_custody IS 'Неизменяемая цепочка событий для каждой архивной записи (хеш-сцепление).';
ALTER TABLE archive.chain_of_custody
  ADD CONSTRAINT coc_details_is_object CHECK (jsonb_typeof(details) = 'object');

-- ------------------------------------------------------------
-- 5) Triggers & functions
-- ------------------------------------------------------------

-- Универсальный триггер обновления updated_at
CREATE OR REPLACE FUNCTION archive.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- Применяем к таблицам с updated_at
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema='archive' AND table_name='bucket' AND column_name='updated_at') THEN
    CREATE TRIGGER trg_bucket_updated_at
    BEFORE UPDATE ON archive.bucket
    FOR EACH ROW EXECUTE FUNCTION archive.touch_updated_at();
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema='archive' AND table_name='vault' AND column_name='updated_at') THEN
    CREATE TRIGGER trg_vault_updated_at
    BEFORE UPDATE ON archive.vault
    FOR EACH ROW EXECUTE FUNCTION archive.touch_updated_at();
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema='archive' AND table_name='catalog' AND column_name='updated_at') THEN
    CREATE TRIGGER trg_catalog_updated_at
    BEFORE UPDATE ON archive.catalog
    FOR EACH ROW EXECUTE FUNCTION archive.touch_updated_at();
  END IF;
END$$;

-- Автонумерация seq_no и построение hash-цепочки для CoC
CREATE OR REPLACE FUNCTION archive.coc_chain_fill()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_prev_hash bytea;
  v_prev_seq  bigint;
  v_payload   text;
BEGIN
  SELECT curr_hash, seq_no
    INTO v_prev_hash, v_prev_seq
  FROM archive.chain_of_custody
  WHERE catalog_id = NEW.catalog_id
  ORDER BY seq_no DESC
  LIMIT 1;

  NEW.seq_no := COALESCE(v_prev_seq, 0) + 1;

  -- payload для хеширования: ключевые поля события
  v_payload := jsonb_build_object(
                  'catalog_id', NEW.catalog_id,
                  'seq_no',     NEW.seq_no,
                  'event_type', NEW.event_type,
                  'actor',      NEW.actor,
                  'actor_roles', NEW.actor_roles,
                  'event_time', NEW.event_time,
                  'details',    COALESCE(NEW.details, '{}'::jsonb),
                  'prev_hash',  CASE WHEN v_prev_hash IS NULL THEN NULL ELSE encode(v_prev_hash,'hex') END
               )::text;

  -- Используем SHA3-512 как по умолчанию
  NEW.prev_hash := v_prev_hash;
  NEW.curr_hash := digest(v_payload, 'sha3-512');

  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_coc_chain_fill ON archive.chain_of_custody;
CREATE TRIGGER trg_coc_chain_fill
BEFORE INSERT ON archive.chain_of_custody
FOR EACH ROW EXECUTE FUNCTION archive.coc_chain_fill();

-- ------------------------------------------------------------
-- 6) Partition management helpers
-- ------------------------------------------------------------

-- Создать месячную партицию для заданной даты (UTC)
CREATE OR REPLACE FUNCTION archive.create_month_partition(p_for_date date)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  p_start date := date_trunc('month', p_for_date)::date;
  p_end   date := (date_trunc('month', p_for_date) + interval '1 month')::date;
  part_name text := format('catalog_y%sm%s', to_char(p_start,'YYYY'), to_char(p_start,'MM'));
  ddl text;
BEGIN
  IF EXISTS (
      SELECT 1 FROM pg_inherits
      JOIN pg_class c ON c.oid=inhrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE inhparent = 'archive.catalog'::regclass
        AND c.relname = part_name
        AND n.nspname = 'archive'
  ) THEN
    RETURN;
  END IF;

  ddl := format($sql$
    CREATE TABLE archive.%I
    PARTITION OF archive.catalog
    FOR VALUES FROM (%L) TO (%L);
    CREATE INDEX IF NOT EXISTS %I_tenant_status_archived_at_idx
      ON archive.%I (tenant_id, status, archived_at);
    CREATE INDEX IF NOT EXISTS %I_legal_hold_idx
      ON archive.%I (legal_hold) WHERE legal_hold = true;
    CREATE INDEX IF NOT EXISTS %I_expires_at_idx
      ON archive.%I (expires_at) WHERE expires_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS %I_source_lookup_idx
      ON archive.%I (source_system, source_ref, object_id);
    CREATE INDEX IF NOT EXISTS %I_backend_uri_idx
      ON archive.%I (backend, storage_uri);
    CREATE INDEX IF NOT EXISTS %I_labels_gin
      ON archive.%I USING gin (labels);
  $sql$,
    part_name, p_start, p_end,
    part_name, part_name,
    part_name, part_name,
    part_name, part_name,
    part_name, part_name,
    part_name, part_name,
    part_name, part_name
  );

  EXECUTE ddl;
END$$;

-- Обеспечить N партиций начиная с месяца p_start_date (включая)
CREATE OR REPLACE FUNCTION archive.ensure_partitions(p_start_date date, p_months integer)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  i int := 0;
BEGIN
  IF p_months IS NULL OR p_months < 1 THEN
    RAISE EXCEPTION 'p_months must be >= 1';
  END IF;

  WHILE i < p_months LOOP
    PERFORM archive.create_month_partition((date_trunc('month', p_start_date) + (i || ' month')::interval)::date);
    i := i + 1;
  END LOOP;
END$$;

-- Создаём партицию для текущего месяца и следующего
SELECT archive.ensure_partitions((now())::date, 2);

-- ------------------------------------------------------------
-- 7) Indexes & constraints on parents
-- ------------------------------------------------------------

-- На родителе только GIN по меткам/метаданным (для планировщиков)
CREATE INDEX IF NOT EXISTS catalog_labels_gin_parent
  ON archive.catalog USING gin (labels);

CREATE INDEX IF NOT EXISTS catalog_metadata_gin_parent
  ON archive.catalog USING gin (metadata);

-- Доп. индекс для ретеншена (планировщик чистки может использовать родителя)
CREATE INDEX IF NOT EXISTS catalog_expires_parent_idx
  ON archive.catalog (expires_at) WHERE expires_at IS NOT NULL;

-- ------------------------------------------------------------
-- 8) RLS (Row-Level Security) по tenant_id
-- ------------------------------------------------------------

-- Включаем RLS
ALTER TABLE archive.vault   ENABLE ROW LEVEL SECURITY;
ALTER TABLE archive.catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE archive.chain_of_custody ENABLE ROW LEVEL SECURITY;

-- Политики: tenant_id = current_setting('oblivionvault.tenant_id', true)
DO $$
BEGIN
  -- vault
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='archive' AND tablename='vault' AND policyname='vault_tenant_isolation') THEN
    CREATE POLICY vault_tenant_isolation ON archive.vault
      USING (tenant_id = COALESCE(archive.current_tenant(), tenant_id));
  END IF;

  -- catalog
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='archive' AND tablename='catalog' AND policyname='catalog_tenant_isolation') THEN
    CREATE POLICY catalog_tenant_isolation ON archive.catalog
      USING (tenant_id = COALESCE(archive.current_tenant(), tenant_id));
  END IF;

  -- chain_of_custody — через связь с catalog
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='archive' AND tablename='chain_of_custody' AND policyname='coc_tenant_isolation') THEN
    CREATE POLICY coc_tenant_isolation ON archive.chain_of_custody
      USING (EXISTS (
        SELECT 1 FROM archive.catalog c
        WHERE c.catalog_id = chain_of_custody.catalog_id
          AND c.tenant_id = COALESCE(archive.current_tenant(), c.tenant_id)
      ));
  END IF;
END$$;

-- По умолчанию разрешаем SELECT; права INSERT/UPDATE/DELETE настраивайте на уровне ролей
ALTER TABLE archive.vault            FORCE ROW LEVEL SECURITY;
ALTER TABLE archive.catalog          FORCE ROW LEVEL SECURITY;
ALTER TABLE archive.chain_of_custody FORCE ROW LEVEL SECURITY;

-- ------------------------------------------------------------
-- 9) Helpful views
-- ------------------------------------------------------------

-- Записи, готовые к удалению по ретеншену (без legal hold)
CREATE OR REPLACE VIEW archive.ready_for_purge AS
SELECT c.*
FROM archive.catalog c
WHERE c.status IN ('AVAILABLE','SEALED','RECALLED')
  AND c.legal_hold = false
  AND c.expires_at IS NOT NULL
  AND now() >= c.expires_at;

COMMENT ON VIEW archive.ready_for_purge IS 'Каталожные записи, подпадающие под плановое удаление (retention), без legal hold.';

-- ------------------------------------------------------------
-- 10) Permissions baseline (optional hardening)
-- ------------------------------------------------------------
-- Пример: предоставьте чтение службе аналитики (замените роль на свою)
-- GRANT USAGE ON SCHEMA archive TO role_analytics;
-- GRANT SELECT ON ALL TABLES IN SCHEMA archive TO role_analytics;

COMMIT;

-- ========================== END =============================
