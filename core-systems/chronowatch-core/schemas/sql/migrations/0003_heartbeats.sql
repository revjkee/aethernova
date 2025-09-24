-- chronowatch-core/schemas/sql/migrations/0003_heartbeats.sql
-- PostgreSQL 13+ (рекомендуется 14/15)
-- Миграция создаёт схему heartbeats с партиционированием, агрегированием и индексами.

-----------------------------
-- SESSION SAFETY SETTINGS --
-----------------------------
BEGIN;

-- Ограничение на долгие блокировки и висящие транзакции
SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '15s';
SET LOCAL idle_in_transaction_session_timeout = '30s';

----------------------
-- NAMESPACE & TYPE --
----------------------
CREATE SCHEMA IF NOT EXISTS chronowatch;

-- Enum статусов heartbeat: ок, предупреждение, сбой
DO $$
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE t.typname = 'heartbeat_status_type' AND n.nspname = 'chronowatch'
  ) THEN
    CREATE TYPE chronowatch.heartbeat_status_type AS ENUM ('ok','warn','fail');
  END IF;
END
$$;

COMMENT ON TYPE chronowatch.heartbeat_status_type IS
  'Статус heartbeat: ok|warn|fail';

--------------------------
-- HEARTBEATS (PARENT)  --
--------------------------
-- Партиционированная таблица по ts_utc (RANGE)
CREATE TABLE IF NOT EXISTS chronowatch.heartbeats (
  heartbeat_id      BIGSERIAL PRIMARY KEY,
  node_id           UUID        NOT NULL,                            -- идентификатор узла/инстанса
  service           TEXT        NOT NULL,                            -- имя сервиса
  env               TEXT        NOT NULL DEFAULT 'production',       -- окружение (dev/staging/prod)
  region            TEXT,                                            -- регион/POP
  ts_utc            TIMESTAMPTZ NOT NULL DEFAULT now(),              -- время события (UTC)
  received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),              -- время приёма
  status            chronowatch.heartbeat_status_type NOT NULL,      -- статус
  latency_ms        INTEGER     CHECK (latency_ms IS NULL OR (latency_ms >= 0 AND latency_ms <= 86400000)),
  payload           JSONB       NOT NULL DEFAULT '{}'::jsonb,        -- доп. поля (структурированные)
  build_version     TEXT,                                            -- версия билд/приложения
  build_ref         TEXT,                                            -- git sha/commit/tag
  request_id        TEXT,                                            -- корреляция запросов
  source_ip         INET,                                            -- ip источника (если есть)
  seq               BIGINT      NOT NULL DEFAULT 0,                  -- последовательность от источника
  -- Доп. уникальность для защиты от дубликатов входа:
  CONSTRAINT heartbeats_uq_source UNIQUE (node_id, service, ts_utc, seq)
) PARTITION BY RANGE (ts_utc);

COMMENT ON TABLE chronowatch.heartbeats IS 'Поток heartbeat-событий (партиционирован по ts_utc).';
COMMENT ON COLUMN chronowatch.heartbeats.node_id IS 'UUID узла/инстанса отправителя.';
COMMENT ON COLUMN chronowatch.heartbeats.service IS 'Имя сервиса/компонента.';
COMMENT ON COLUMN chronowatch.heartbeats.env IS 'Окружение: dev/staging/production и т. п.';
COMMENT ON COLUMN chronowatch.heartbeats.ts_utc IS 'Момент события в UTC (ключ партиционирования).';
COMMENT ON COLUMN chronowatch.heartbeats.status IS 'Статус: ok|warn|fail.';
COMMENT ON COLUMN chronowatch.heartbeats.payload IS 'Произвольные данные события (JSONB).';

-- Default-партиция для любых неохваченных диапазонов (страховочная)
CREATE TABLE IF NOT EXISTS chronowatch.heartbeats_default
  PARTITION OF chronowatch.heartbeats DEFAULT;

COMMENT ON TABLE chronowatch.heartbeats_default IS 'Партиция по умолчанию для heartbeats.';

-------------------------------
-- PARTITION INDEX TEMPLATES --
-------------------------------
-- Партиционированные индексы на родительской таблице.
-- PostgreSQL создаст соответствующие индексы на существующих партициях и будет требовать
-- соответствия на новых партициях (attach).

-- По времени
CREATE INDEX IF NOT EXISTS heartbeats_ts_idx
  ON chronowatch.heartbeats (ts_utc DESC);

-- По (service, ts_utc) для быстрых отчётов по сервису
CREATE INDEX IF NOT EXISTS heartbeats_service_ts_idx
  ON chronowatch.heartbeats (service, ts_utc DESC);

-- По (node_id, ts_utc) для отчётов по узлу
CREATE INDEX IF NOT EXISTS heartbeats_node_ts_idx
  ON chronowatch.heartbeats (node_id, ts_utc DESC);

-- Частичные индексы по статусам (часто выбираемые слайсы)
CREATE INDEX IF NOT EXISTS heartbeats_status_ok_ts_idx
  ON chronowatch.heartbeats (ts_utc DESC) WHERE status = 'ok';

CREATE INDEX IF NOT EXISTS heartbeats_status_warn_ts_idx
  ON chronowatch.heartbeats (ts_utc DESC) WHERE status = 'warn';

CREATE INDEX IF NOT EXISTS heartbeats_status_fail_ts_idx
  ON chronowatch.heartbeats (ts_utc DESC) WHERE status = 'fail';

-- GIN по payload для фильтраций по ключам/значениям JSONB
CREATE INDEX IF NOT EXISTS heartbeats_payload_gin
  ON chronowatch.heartbeats USING GIN (payload jsonb_path_ops);

---------------------------------------------
-- MONTHLY PARTITIONS (CREATE IF NOT EXISTS) --
---------------------------------------------
-- Создаём партиции помесячно: с прошлого месяца до +12 месяцев вперёд.
DO $$
DECLARE
  m_start  date := date_trunc('month', now())::date - INTERVAL '1 month';
  m_end    date := date_trunc('month', now())::date + INTERVAL '12 months';
  cur      date;
  p_start  timestamptz;
  p_end    timestamptz;
  p_name   text;
BEGIN
  cur := m_start;
  WHILE cur < m_end LOOP
    p_start := cur;
    p_end   := (cur + INTERVAL '1 month');
    p_name  := format('heartbeats_%s', to_char(cur, 'YYYYMM'));

    EXECUTE format($f$
      CREATE TABLE IF NOT EXISTS chronowatch.%I
      PARTITION OF chronowatch.heartbeats
      FOR VALUES FROM (%L) TO (%L);
    $f$, p_name, p_start, p_end);

    -- Индексы на партиции наследуются от партиционированных индексов;
    -- для совместимости убедимся в наличии (attach при необходимости).
    -- PostgreSQL обеспечит соответствие при создании индексов выше.
    cur := (cur + INTERVAL '1 month')::date;
  END LOOP;
END$$;

-----------------------------------
-- HOURLY AGGREGATE (ROLLUP TABLE) --
-----------------------------------
-- Онлайновая агрегирующая таблица (upsert при вставке heartbeat).
CREATE TABLE IF NOT EXISTS chronowatch.heartbeats_hourly (
  bucket_ts        TIMESTAMPTZ NOT NULL,        -- часовой бакет: date_trunc('hour', ts_utc)
  service          TEXT        NOT NULL,
  env              TEXT        NOT NULL,
  region           TEXT,
  node_id          UUID        NOT NULL,
  total_count      BIGINT      NOT NULL DEFAULT 0,
  ok_count         BIGINT      NOT NULL DEFAULT 0,
  warn_count       BIGINT      NOT NULL DEFAULT 0,
  fail_count       BIGINT      NOT NULL DEFAULT 0,
  sum_latency_ms   BIGINT      NOT NULL DEFAULT 0,
  min_latency_ms   INTEGER,
  max_latency_ms   INTEGER,
  PRIMARY KEY (bucket_ts, service, env, COALESCE(region, ''), node_id)
);

COMMENT ON TABLE chronowatch.heartbeats_hourly IS
  'Часовая онлайновая агрегация heartbeats (счётчики и latency-сводка).';

CREATE INDEX IF NOT EXISTS heartbeats_hourly_ts_idx
  ON chronowatch.heartbeats_hourly (bucket_ts DESC, service, env);

------------------------------
-- AGGREGATION TRIGGER FN   --
------------------------------
-- Триггерная функция инкрементального апдейта агрегата.
CREATE OR REPLACE FUNCTION chronowatch.fn_heartbeats_hourly_upsert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_bucket TIMESTAMPTZ := date_trunc('hour', NEW.ts_utc);
  v_latency INTEGER := NEW.latency_ms;
BEGIN
  -- Нормализуем NULL-latency к 0 для суммирования
  IF v_latency IS NULL THEN
    v_latency := 0;
  END IF;

  INSERT INTO chronowatch.heartbeats_hourly AS h (
    bucket_ts, service, env, region, node_id,
    total_count, ok_count, warn_count, fail_count,
    sum_latency_ms, min_latency_ms, max_latency_ms
  )
  VALUES (
    v_bucket, NEW.service, NEW.env, NEW.region, NEW.node_id,
    1,
    CASE WHEN NEW.status = 'ok'   THEN 1 ELSE 0 END,
    CASE WHEN NEW.status = 'warn' THEN 1 ELSE 0 END,
    CASE WHEN NEW.status = 'fail' THEN 1 ELSE 0 END,
    v_latency,
    NULLIF(v_latency, 0),
    v_latency
  )
  ON CONFLICT (bucket_ts, service, env, COALESCE(region, ''), node_id)
  DO UPDATE SET
    total_count    = h.total_count + 1,
    ok_count       = h.ok_count    + (CASE WHEN EXCLUDED.ok_count   = 1 THEN 1 ELSE 0 END),
    warn_count     = h.warn_count  + (CASE WHEN EXCLUDED.warn_count = 1 THEN 1 ELSE 0 END),
    fail_count     = h.fail_count  + (CASE WHEN EXCLUDED.fail_count = 1 THEN 1 ELSE 0 END),
    sum_latency_ms = h.sum_latency_ms + EXCLUDED.sum_latency_ms,
    min_latency_ms = LEAST(COALESCE(h.min_latency_ms, EXCLUDED.min_latency_ms), COALESCE(EXCLUDED.min_latency_ms, h.min_latency_ms)),
    max_latency_ms = GREATEST(COALESCE(h.max_latency_ms, EXCLUDED.max_latency_ms), COALESCE(EXCLUDED.max_latency_ms, h.max_latency_ms));

  RETURN NULL;
END
$$;

-- Триггер на парент-таблицу (наследуется партициями)
DROP TRIGGER IF EXISTS trg_heartbeats_hourly_upsert ON chronowatch.heartbeats;
CREATE TRIGGER trg_heartbeats_hourly_upsert
AFTER INSERT ON chronowatch.heartbeats
FOR EACH ROW
EXECUTE FUNCTION chronowatch.fn_heartbeats_hourly_upsert();

--------------------------------------
-- ANALYTICS: MATERIALIZED VIEW (MV) --
--------------------------------------
-- Материализованное представление с p95 latency по часам (дорого считать онлайн).
-- REFRESH CONCURRENTLY потребует уникальный индекс.
CREATE MATERIALIZED VIEW IF NOT EXISTS chronowatch.mv_heartbeats_hourly_latency AS
SELECT
  date_trunc('hour', ts_utc)          AS bucket_ts,
  service,
  env,
  region,
  COUNT(*)                            AS total_count,
  COUNT(*) FILTER (WHERE status='ok')   AS ok_count,
  COUNT(*) FILTER (WHERE status='warn') AS warn_count,
  COUNT(*) FILTER (WHERE status='fail') AS fail_count,
  AVG(latency_ms)::BIGINT             AS avg_latency_ms,
  PERCENTILE_DISC(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms
FROM chronowatch.heartbeats
WHERE latency_ms IS NOT NULL
GROUP BY 1,2,3,4;

-- Индекс для CONCURRENTLY refresh
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname='chronowatch'
      AND indexname='mv_heartbeats_hourly_latency_pk'
  ) THEN
    CREATE UNIQUE INDEX mv_heartbeats_hourly_latency_pk
      ON chronowatch.mv_heartbeats_hourly_latency (bucket_ts, service, env, COALESCE(region, ''));
  END IF;
END$$;

COMMENT ON MATERIALIZED VIEW chronowatch.mv_heartbeats_hourly_latency IS
  'Hourly latency stats with p95 for analytical queries (refresh concurrently in background).';

------------------------------
-- ADDITIONAL CONSTRAINTS   --
------------------------------
-- Минимальная валидация длины service/env (опционально ужесточить)
ALTER TABLE chronowatch.heartbeats
  ADD CONSTRAINT heartbeats_service_chk CHECK (char_length(service) BETWEEN 1 AND 200) NOT VALID;

ALTER TABLE chronowatch.heartbeats
  ADD CONSTRAINT heartbeats_env_chk CHECK (char_length(env) BETWEEN 2 AND 32) NOT VALID;

-- Валидируем позже в фоне (чтобы избежать простоя)
ALTER TABLE chronowatch.heartbeats VALIDATE CONSTRAINT heartbeats_service_chk;
ALTER TABLE chronowatch.heartbeats VALIDATE CONSTRAINT heartbeats_env_chk;

-----------------
-- FINALIZE    --
-----------------
COMMIT;

-- Конец миграции 0003_heartbeats.sql
