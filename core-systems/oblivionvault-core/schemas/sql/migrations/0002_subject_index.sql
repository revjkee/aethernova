-- File: oblivionvault-core/schemas/sql/migrations/0002_subject_index.sql
-- Purpose: Автоматически создать производственные индексы по subject для всех релевантных таблиц.
-- Target:  PostgreSQL 12+

----------------------------------------------------------------------
-- ВАЖНО: Скрипт использует обычное CREATE INDEX (не CONCURRENTLY),
-- так как динамическое создание через DO $$ ... $$ выполняется в транзакции.
-- Он минимизирует риск проставляя lock_timeout и statement_timeout.
-- Если ваш миграционный раннер поддерживает "безтранзакционные" шаги,
-- можно вручную заменить EXECUTE ... на CREATE INDEX CONCURRENTLY.
----------------------------------------------------------------------

-- Безопасные таймауты, чтобы не зависнуть на долгих блокировках
SET lock_timeout       = '2s';
SET statement_timeout  = '10min';
SET idle_in_transaction_session_timeout = '10min';
SET client_min_messages = warning;

-- Требуемая версия PostgreSQL
DO $checkver$
BEGIN
  IF current_setting('server_version_num')::int < 120000 THEN
    RAISE EXCEPTION 'PostgreSQL 12+ required, got %', current_setting('server_version');
  END IF;
END
$checkver$;

-- Хелпер: безопасно создать индекс, если он отсутствует
CREATE OR REPLACE FUNCTION ov__create_index_if_absent(idx_ddl text, idx_name text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF to_regclass(idx_name) IS NULL THEN
    EXECUTE idx_ddl;
  END IF;
EXCEPTION
  WHEN duplicate_table THEN
    -- Индекс уже создан конкурентно другим процессом
    NULL;
  WHEN others THEN
    RAISE WARNING 'Failed to create index %: %', idx_name, SQLERRM;
END;
$$;

-- Хелпер: нормализовать имя индекса (<=63 байт) с коротким хэшем
CREATE OR REPLACE FUNCTION ov__idx_name(schema_name text, table_name text, suffix text)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
  base text := lower(replace(schema_name||'_'||table_name||'__'||suffix, '"', ''));
  hashed text := substr(md5(base), 1, 6);
  trimmed text := substr(base, 1, GREATEST(1, 63 - 1 - length(hashed))); -- место под '_' и хэш
BEGIN
  RETURN trimmed || '_' || hashed;
END;
$$;

-- Основная процедура: обойти все таблицы и создать релевантные индексы
DO $$
DECLARE
  r record;
  has_tenant boolean;
  has_created boolean;
  idx_name text;
  ddl text;
BEGIN
  FOR r IN
    SELECT
      c.table_schema,
      c.table_name
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema
     AND t.table_name   = c.table_name
     AND t.table_type   = 'BASE TABLE'
    WHERE c.column_name = 'subject_id'
      AND c.table_schema NOT IN ('pg_catalog', 'information_schema')
  LOOP
    -- Проверки наличия других полезных колонок
    SELECT EXISTS (
             SELECT 1 FROM information_schema.columns
              WHERE table_schema = r.table_schema
                AND table_name   = r.table_name
                AND column_name  = 'tenant_id'
           )
      INTO has_tenant;

    SELECT EXISTS (
             SELECT 1 FROM information_schema.columns
              WHERE table_schema = r.table_schema
                AND table_name   = r.table_name
                AND column_name  = 'created_at'
           )
      INTO has_created;

    ------------------------------------------------------------------
    -- 1) BTREE по subject_id
    ------------------------------------------------------------------
    idx_name := ov__idx_name(r.table_schema, r.table_name, 'subject_id_btree');
    ddl := format(
      'CREATE INDEX %I ON %I.%I USING BTREE (subject_id)',
      idx_name, r.table_schema, r.table_name
    );
    PERFORM ov__create_index_if_absent(ddl, idx_name);

    ------------------------------------------------------------------
    -- 2) Составной BTREE (tenant_id, subject_id) для мультиарендности
    ------------------------------------------------------------------
    IF has_tenant THEN
      idx_name := ov__idx_name(r.table_schema, r.table_name, 'tenant_subject_btree');
      ddl := format(
        'CREATE INDEX %I ON %I.%I USING BTREE (tenant_id, subject_id)',
        idx_name, r.table_schema, r.table_name
      );
      PERFORM ov__create_index_if_absent(ddl, idx_name);
    END IF;

    ------------------------------------------------------------------
    -- 3) Временные запросы по subject: (subject_id, created_at DESC)
    ------------------------------------------------------------------
    IF has_created THEN
      idx_name := ov__idx_name(r.table_schema, r.table_name, 'subject_created_at_btree');
      ddl := format(
        'CREATE INDEX %I ON %I.%I USING BTREE (subject_id, created_at DESC)',
        idx_name, r.table_schema, r.table_name
      );
      PERFORM ov__create_index_if_absent(ddl, idx_name);
    END IF;

    ------------------------------------------------------------------
    -- 4) Расширенная статистика для планировщика (корреляция колонок)
    ------------------------------------------------------------------
    IF has_tenant THEN
      idx_name := ov__idx_name(r.table_schema, r.table_name, 'st_tenant_subject');
      ddl := format(
        'CREATE STATISTICS %I ON tenant_id, subject_id FROM %I.%I',
        idx_name, r.table_schema, r.table_name
      );
      -- CREATE STATISTICS IF NOT EXISTS доступно с PG16; для совместимости проверим вручную
      IF to_regclass(idx_name) IS NULL THEN
        BEGIN
          EXECUTE ddl;
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;
      END IF;
    END IF;

    -- Анализ таблицы после изменений
    EXECUTE format('ANALYZE %I.%I', r.table_schema, r.table_name);
  END LOOP;
END
$$;

----------------------------------------------------------------------
-- 5) JSONB: GIN индексы для колонок, содержащих ключи subject/*
-- Ищем типичные колоноки JSONB: metadata, attributes, payload, data
-- Индекс по jsonb_path_ops хорошо ускоряет операции @>
----------------------------------------------------------------------

DO $json$
DECLARE
  r record;
  idx_name text;
  ddl text;
BEGIN
  FOR r IN
    SELECT
      c.table_schema,
      c.table_name,
      c.column_name
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema
     AND t.table_name   = c.table_name
     AND t.table_type   = 'BASE TABLE'
    WHERE c.data_type = 'jsonb'
      AND c.column_name IN ('metadata', 'attributes', 'payload', 'data')
      AND c.table_schema NOT IN ('pg_catalog', 'information_schema')
  LOOP
    idx_name := ov__idx_name(r.table_schema, r.table_name, r.column_name || '_gin_subject');
    ddl := format(
      'CREATE INDEX %I ON %I.%I USING GIN (%I jsonb_path_ops)',
      idx_name, r.table_schema, r.table_name, r.column_name
    );
    PERFORM ov__create_index_if_absent(ddl, idx_name);

    -- Частичный индекс (если ключ "subject" чаще верхнего уровня) — опционально:
    -- idx_name := ov__idx_name(r.table_schema, r.table_name, r.column_name || '_gin_subject_top');
    -- ddl := format(
    --   $$CREATE INDEX %I ON %I.%I USING GIN ((%I -> 'subject') jsonb_path_ops) WHERE %I ? 'subject'$$,
    --   idx_name, r.table_schema, r.table_name, r.column_name, r.column_name
    -- );
    -- PERFORM ov__create_index_if_absent(ddl, idx_name);

    EXECUTE format('ANALYZE %I.%I', r.table_schema, r.table_name);
  END LOOP;
END
$json$;

----------------------------------------------------------------------
-- Уборка: опционально можно удалить функции‑хелперы после миграции.
-- Оставим их – возможен повторный запуск в окружениях.
----------------------------------------------------------------------

-- Конец миграции.
