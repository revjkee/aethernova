-- ============================================================
-- Migration: 0003_dialogues.sql
-- PostgreSQL >= 13
-- Creates mythos.dialogues and mythos.dialogue_turns (+ partitions),
-- indexes, triggers, helper functions, and summary view.
-- Idempotent: safe on repeated runs.
-- ============================================================

BEGIN;

-- ---------- Prerequisites ----------
CREATE SCHEMA IF NOT EXISTS mythos;

-- UUID and TRGM support
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------- Domains / helper checks ----------
-- Status as text with CHECK (more flexible than ENUM for future)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.domains
    WHERE domain_schema = 'mythos' AND domain_name = 'status_text'
  ) THEN
    CREATE DOMAIN mythos.status_text AS text
      CHECK (VALUE IN ('active','closed','errored'));
  END IF;
END$$;

-- ---------- Tables ----------

-- Dialogs header table
CREATE TABLE IF NOT EXISTS mythos.dialogues (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        text,                                 -- опционально для мультиаренды
  session_id       uuid        NOT NULL,                 -- логическая сессия клиента
  user_id          text,                                 -- анонимный или внешний идентификатор
  channel          text        NOT NULL DEFAULT 'http',  -- http|slack|telegram|...
  locale           text        NOT NULL DEFAULT 'ru',
  status           mythos.status_text NOT NULL DEFAULT 'active',
  tags             text[]      NOT NULL DEFAULT '{}',
  meta             jsonb       NOT NULL DEFAULT '{}'::jsonb, -- произвольные атрибуты
  started_at       timestamptz NOT NULL DEFAULT now(),
  ended_at         timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT dialogues_ended_after_start CHECK (ended_at IS NULL OR ended_at >= started_at)
);

COMMENT ON TABLE mythos.dialogues IS 'Диалоговые сессии Mythos';
COMMENT ON COLUMN mythos.dialogues.meta IS 'Произвольные атрибуты в JSONB';
COMMENT ON COLUMN mythos.dialogues.tags IS 'Свободные теги для маршрутизации/аналитики';

-- Indices for dialogues
CREATE INDEX IF NOT EXISTS dialogues_session_idx     ON mythos.dialogues (session_id);
CREATE INDEX IF NOT EXISTS dialogues_status_idx      ON mythos.dialogues (status);
CREATE INDEX IF NOT EXISTS dialogues_started_idx     ON mythos.dialogues (started_at);
CREATE INDEX IF NOT EXISTS dialogues_tenant_idx      ON mythos.dialogues (tenant_id);
CREATE INDEX IF NOT EXISTS dialogues_tags_gin        ON mythos.dialogues USING gin (tags);
CREATE INDEX IF NOT EXISTS dialogues_meta_gin        ON mythos.dialogues USING gin (meta jsonb_path_ops);

-- Dialogue turns (partitioned by created_at month)
-- Parent
CREATE TABLE IF NOT EXISTS mythos.dialogue_turns (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dialogue_id        uuid        NOT NULL REFERENCES mythos.dialogues(id) ON DELETE CASCADE,
  tenant_id          text,
  turn_index         integer     NOT NULL,                       -- 0..N в рамках одного диалога
  role               text        NOT NULL CHECK (role IN ('system','user','assistant','tool')),
  input_text         text,
  input_tokens       integer     NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  attachments        jsonb       NOT NULL DEFAULT '[]'::jsonb,
  tool_calls         jsonb       NOT NULL DEFAULT '[]'::jsonb,
  tool_results       jsonb       NOT NULL DEFAULT '[]'::jsonb,
  rag_citations      jsonb       NOT NULL DEFAULT '[]'::jsonb,   -- массив объектов с источниками
  moderation         jsonb       NOT NULL DEFAULT '{}'::jsonb,   -- результаты модерации
  output_text        text,
  output_tokens      integer     NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  latency_ms         integer     NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
  cost_usd           numeric(12,6) NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
  prompt_fingerprint text,                                       -- хэш промпта/системного контекста
  metrics            jsonb       NOT NULL DEFAULT '{}'::jsonb,   -- любые числовые/счетчики
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (dialogue_id, turn_index)
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE mythos.dialogue_turns IS 'Отдельные ходы диалога';
COMMENT ON COLUMN mythos.dialogue_turns.turn_index IS 'Счетчик хода в рамках диалога, начинается с 0';

-- Default catch-all partition (safety net)
CREATE TABLE IF NOT EXISTS mythos.dialogue_turns_default
  PARTITION OF mythos.dialogue_turns DEFAULT;

-- Helpful indexes on parent (propagated to partitions if created per partition; we add on default and rely on creation for new partitions)
CREATE INDEX IF NOT EXISTS dialogue_turns_dialogue_idx    ON mythos.dialogue_turns_default (dialogue_id, created_at);
CREATE INDEX IF NOT EXISTS dialogue_turns_tenant_idx      ON mythos.dialogue_turns_default (tenant_id);
CREATE INDEX IF NOT EXISTS dialogue_turns_created_idx     ON mythos.dialogue_turns_default (created_at);
CREATE INDEX IF NOT EXISTS dialogue_turns_role_idx        ON mythos.dialogue_turns_default (role);
CREATE INDEX IF NOT EXISTS dialogue_turns_metrics_gin     ON mythos.dialogue_turns_default USING gin (metrics);
CREATE INDEX IF NOT EXISTS dialogue_turns_tools_gin       ON mythos.dialogue_turns_default USING gin (tool_calls);
CREATE INDEX IF NOT EXISTS dialogue_turns_citations_gin   ON mythos.dialogue_turns_default USING gin (rag_citations);
CREATE INDEX IF NOT EXISTS dialogue_turns_in_trgm         ON mythos.dialogue_turns_default USING gin (input_text gin_trgm_ops);
CREATE INDEX IF NOT EXISTS dialogue_turns_out_trgm        ON mythos.dialogue_turns_default USING gin (output_text gin_trgm_ops);

-- ---------- Functions and triggers ----------

-- Autoupdate updated_at on UPDATE
CREATE OR REPLACE FUNCTION mythos.set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- Set ended_at when status becomes closed/errored
CREATE OR REPLACE FUNCTION mythos.set_ended_at_on_close()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IN ('closed','errored') AND (NEW.ended_at IS NULL) THEN
    NEW.ended_at := now();
  END IF;
  RETURN NEW;
END$$;

-- Advisory-locked auto-increment of turn_index per dialogue
CREATE OR REPLACE FUNCTION mythos.assign_turn_index()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  lock_key bigint;
  next_idx integer;
BEGIN
  IF NEW.turn_index IS NOT NULL AND NEW.turn_index >= 0 THEN
    RETURN NEW; -- already set explicitly
  END IF;

  -- lock on dialogue_id to avoid race
  lock_key := hashtextextended(NEW.dialogue_id::text, 0);
  PERFORM pg_advisory_xact_lock(lock_key);

  SELECT COALESCE(MAX(t.turn_index), -1) + 1
    INTO next_idx
  FROM mythos.dialogue_turns t
  WHERE t.dialogue_id = NEW.dialogue_id;

  NEW.turn_index := COALESCE(next_idx, 0);
  RETURN NEW;
END$$;

-- Optional: auto-create monthly partition for dialogue_turns
-- Creates partition [YYYY-MM-01, YYYY-(MM+1)-01)
CREATE OR REPLACE FUNCTION mythos.ensure_month_partition(ts timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  p_start date := date_trunc('month', ts)::date;
  p_end   date := (date_trunc('month', ts) + interval '1 month')::date;
  p_name  text := format('dialogue_turns_%s', to_char(p_start, 'YYYY_MM'));
  full_name text := format('mythos.%I', p_name);
  exists bool;
BEGIN
  SELECT to_regclass(full_name) IS NOT NULL INTO exists;
  IF exists THEN
    RETURN;
  END IF;

  EXECUTE format($f$
    CREATE TABLE %s
      PARTITION OF mythos.dialogue_turns
      FOR VALUES FROM (%L) TO (%L)
  $f$, full_name, p_start, p_end);

  -- create same indexes as on default partition
  EXECUTE format('CREATE INDEX %I_dialogue_idx ON %s (dialogue_id, created_at)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_tenant_idx   ON %s (tenant_id)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_created_idx  ON %s (created_at)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_role_idx     ON %s (role)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_metrics_gin  ON %s USING gin (metrics)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_tools_gin    ON %s USING gin (tool_calls)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_cit_gin      ON %s USING gin (rag_citations)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_in_trgm      ON %s USING gin (input_text gin_trgm_ops)', p_name, full_name);
  EXECUTE format('CREATE INDEX %I_out_trgm     ON %s USING gin (output_text gin_trgm_ops)', p_name, full_name);
END$$;

-- BEFORE INSERT trigger to ensure partition and turn index
CREATE OR REPLACE FUNCTION mythos.before_insert_turn()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM mythos.ensure_month_partition(COALESCE(NEW.created_at, now()));
  NEW := (SELECT (mythos.assign_turn_index()).* FROM (SELECT NEW.*) AS s);
  RETURN NEW;
END$$;

-- Attach triggers
DROP TRIGGER IF EXISTS trg_dialogues_updated_at ON mythos.dialogues;
CREATE TRIGGER trg_dialogues_updated_at
BEFORE UPDATE ON mythos.dialogues
FOR EACH ROW EXECUTE FUNCTION mythos.set_updated_at();

DROP TRIGGER IF EXISTS trg_dialogues_end_on_status ON mythos.dialogues;
CREATE TRIGGER trg_dialogues_end_on_status
BEFORE UPDATE ON mythos.dialogues
FOR EACH ROW EXECUTE FUNCTION mythos.set_ended_at_on_close();

DROP TRIGGER IF EXISTS trg_turns_updated_at ON mythos.dialogue_turns;
CREATE TRIGGER trg_turns_updated_at
BEFORE UPDATE ON mythos.dialogue_turns
FOR EACH ROW EXECUTE FUNCTION mythos.set_updated_at();

DROP TRIGGER IF EXISTS trg_turns_before_insert ON mythos.dialogue_turns;
CREATE TRIGGER trg_turns_before_insert
BEFORE INSERT ON mythos.dialogue_turns
FOR EACH ROW EXECUTE FUNCTION mythos.before_insert_turn();

-- ---------- Views ----------

-- Summary per dialogue: counts, last activity, totals
CREATE OR REPLACE VIEW mythos.v_dialogue_summary AS
SELECT
  d.id                                AS dialogue_id,
  d.session_id,
  d.user_id,
  d.channel,
  d.locale,
  d.status,
  d.started_at,
  COALESCE(d.ended_at, max(t.created_at)) AS last_activity_at,
  COUNT(t.*)                           AS turns_total,
  SUM(CASE WHEN t.role = 'user' THEN 1 ELSE 0 END)       AS user_turns,
  SUM(CASE WHEN t.role = 'assistant' THEN 1 ELSE 0 END)  AS assistant_turns,
  SUM(t.input_tokens)  AS input_tokens_total,
  SUM(t.output_tokens) AS output_tokens_total,
  SUM(t.cost_usd)      AS cost_usd_total
FROM mythos.dialogues d
LEFT JOIN mythos.dialogue_turns t ON t.dialogue_id = d.id
GROUP BY d.id, d.session_id, d.user_id, d.channel, d.locale, d.status, d.started_at, d.ended_at;

COMMENT ON VIEW mythos.v_dialogue_summary IS 'Сводные метрики по диалогам';

-- ---------- Optional RLS scaffolding (disabled by default) ----------
-- ALTER TABLE mythos.dialogues ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE mythos.dialogue_turns ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation_dialogues ON mythos.dialogues
--   USING (tenant_id IS NULL OR tenant_id = current_setting('mythos.tenant_id', true));
-- CREATE POLICY tenant_isolation_turns ON mythos.dialogue_turns
--   USING (tenant_id IS NULL OR tenant_id = current_setting('mythos.tenant_id', true));

COMMIT;

-- =========================
-- Notes:
-- 1) Партиционирование: функция ensure_month_partition автоматически создаст месячную партицию при вставке.
--    При большом потоке рекомендуется создавать партиции заранее миграциями по расписанию.
-- 2) TRGM: для поиска по input_text/output_text используйте ILIKE или %...% — индексы gin_trgm_ops ускоряют запросы.
-- 3) Идемпотентность: повторный запуск не приводит к ошибкам; CREATE OR REPLACE для функций/представлений.
-- =========================
