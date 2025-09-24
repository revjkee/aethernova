-- File: security-core/schemas/sql/migrations/0002_audit_indices.sql
-- Purpose: Industrial-grade indexes for audit/auth tables in security-core.
-- Target: PostgreSQL 14+.
-- Notes:
--   - Идемпотентно: проверяет наличие таблиц/столбцов, CREATE INDEX IF NOT EXISTS.
--   - Безопасность: не меняет данные, только DDL индексов.
--   - Блокировки: типичные CREATE INDEX берут SHARE UPDATE EXCLUSIVE; ограничиваем ожидание через lock_timeout.
--   - Если у вас требование STRICT no-lock, выполните аналог с CONCURRENTLY вне транзакций вашего мигратора.
--   - I cannot verify this.

SET lock_timeout TO '2s';
SET statement_timeout TO '0';
SET maintenance_work_mem TO '1GB';

-- =========================
--  security.audit_log
-- =========================
DO $$
DECLARE
  v_schema text := 'security';
  v_table  text := 'audit_log';
  v_full   text := format('%I.%I', v_schema, v_table);
BEGIN
  -- Таблица должна существовать
  IF to_regclass(v_full) IS NULL THEN
    RAISE NOTICE 'Skip: %.% does not exist', v_schema, v_table;
    RETURN;
  END IF;

  -- BRIN по времени для больших исторических сканов
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'created_at') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_created_at_brin ON %s USING brin (created_at) WITH (pages_per_range = 128)', v_full);
  END IF;

  -- Узкий BTREE индекс для «последних 30 дней» (частые онлайн‑запросы)
  -- Если нужна строгая совместимость, оставьте без partial WHERE.
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'created_at') THEN
    EXECUTE format($sql$
      DO $inner$
      BEGIN
        -- Проверим, существует ли частичный индекс, т.к. IF NOT EXISTS не различает partial выражение
        IF NOT EXISTS (
          SELECT 1 FROM pg_indexes
           WHERE schemaname = %L AND tablename = %L AND indexname = 'idx_audit_log_created_at_recent_btree'
        ) THEN
          EXECUTE 'CREATE INDEX idx_audit_log_created_at_recent_btree ON %s USING btree (created_at) WHERE created_at >= now() - interval ''30 days''';
        END IF;
      END
      $inner$;
    $sql$, v_schema, v_table, v_full);
  END IF;

  -- Селекторы актора / типа события / арендатора
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'actor_id') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON %s (actor_id)', v_full);
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'event_type') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON %s (event_type)', v_full);
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'tenant_id') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON %s (tenant_id)', v_full);
  END IF;

  -- Ресурс (тип + id) для быстрой навигации по объектам
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name IN ('resource_type','resource_id')
             GROUP BY table_schema, table_name
             HAVING count(*) = 2) THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON %s (resource_type, resource_id)', v_full);
  END IF;

  -- Корреляция инцидентов/трассировка
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'correlation_id') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_correlation_id ON %s (correlation_id)', v_full);
  END IF;

  -- Сетевые признаки
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'src_ip') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_src_ip ON %s (src_ip)', v_full);
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'severity') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_severity ON %s (severity)', v_full);
  END IF;

  -- JSONB metadata/details (GIN)
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND data_type = 'jsonb' AND column_name = 'metadata') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_metadata_gin ON %s USING gin (metadata)', v_full);
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND data_type = 'jsonb' AND column_name = 'details') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_log_details_gin ON %s USING gin (details)', v_full);
  END IF;

  -- Уникальность/дедупликация по неизменяемому хешу события (если предусмотрен)
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'immutable_hash') THEN
    EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_immutable_hash_uniq ON %s (immutable_hash)', v_full);
  END IF;

END $$ LANGUAGE plpgsql;

-- =========================
--  security.auth_event
-- =========================
DO $$
DECLARE
  v_schema text := 'security';
  v_table  text := 'auth_event';
  v_full   text := format('%I.%I', v_schema, v_table);
BEGIN
  IF to_regclass(v_full) IS NULL THEN
    RAISE NOTICE 'Skip: %.% does not exist', v_schema, v_table;
    RETURN;
  END IF;

  -- Основная временная ось
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'created_at') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_auth_event_created_at_brin ON %s USING brin (created_at) WITH (pages_per_range = 128)', v_full);
  END IF;

  -- Пользователь + время (частые выборки последних событий пользователя)
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name IN ('user_id','created_at')
             GROUP BY table_schema, table_name
             HAVING count(*) = 2) THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_auth_event_user_created_at ON %s (user_id, created_at DESC)', v_full);
  END IF;

  -- Исход события (успех/неуспех) + время
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name IN ('outcome','created_at')
             GROUP BY table_schema, table_name
             HAVING count(*) = 2) THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_auth_event_outcome_created_at ON %s (outcome, created_at DESC)', v_full);
  END IF;

  -- Арендатор
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'tenant_id') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_auth_event_tenant_id ON %s (tenant_id)', v_full);
  END IF;

  -- Сетевые признаки
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND column_name = 'src_ip') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_auth_event_src_ip ON %s (src_ip)', v_full);
  END IF;

  -- JSONB метаданные/контекст
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = v_schema AND table_name = v_table AND data_type = 'jsonb' AND column_name = 'metadata') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_auth_event_metadata_gin ON %s USING gin (metadata)', v_full);
  END IF;

END $$ LANGUAGE plpgsql;

RESET maintenance_work_mem;
RESET statement_timeout;
RESET lock_timeout;
