-- mythos-core/schemas/sql/migrations/0002_quests.sql
-- PostgreSQL 14+
-- Подсистема квестов: определения, версии, шаги/цели/награды, AB, раскатка, сегментация,
-- пользовательский прогресс, событийный лог, леджер наград, индексация, RLS.

BEGIN;

-- 0) Базовые расширения и схема
CREATE SCHEMA IF NOT EXISTS mythos;

-- Для gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA pg_catalog;
-- На случай окружений без pgcrypto: (не критично, но полезно)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

-- 1) Утилиты: updated_at
CREATE OR REPLACE FUNCTION mythos.tg__set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- 2) Домены/типы
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'quest_status') THEN
    CREATE TYPE mythos.quest_status AS ENUM ('draft','published','archived');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'quest_difficulty') THEN
    CREATE TYPE mythos.quest_difficulty AS ENUM ('easy','normal','hard','legendary');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'quest_step_kind') THEN
    CREATE TYPE mythos.quest_step_kind AS ENUM ('event','counter','collect','visit','custom');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'objective_type') THEN
    CREATE TYPE mythos.objective_type AS ENUM ('counter','item','flag','custom');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'track_mode') THEN
    CREATE TYPE mythos.track_mode AS ENUM ('server','client');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_quest_state') THEN
    CREATE TYPE mythos.user_quest_state AS ENUM ('active','completed','failed','expired','cooldown');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ledger_kind') THEN
    CREATE TYPE mythos.ledger_kind AS ENUM ('currency','xp','item','other');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'event_kind') THEN
    CREATE TYPE mythos.event_kind AS ENUM ('started','progressed','completed','failed','claimed');
  END IF;
END$$;

-- Домен для тега локали BCP-47 (упрощенная валидация)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'bcp47') THEN
    CREATE DOMAIN mythos.bcp47 AS text
      CHECK (VALUE ~* '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$');
  END IF;
END$$;

-- 3) Справочник квестов (ключи стабильные, без бизнес-логики)
CREATE TABLE IF NOT EXISTS mythos.quests (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quest_key     text NOT NULL UNIQUE,           -- стабильный строковый ID (напр., "daily_login_streak")
  category      text NOT NULL,                  -- произвольная категория (напр., "daily","combat")
  difficulty    mythos.quest_difficulty NOT NULL DEFAULT 'normal',
  tags          text[] NOT NULL DEFAULT '{}',   -- быстрые теги для фильтров
  is_active     boolean NOT NULL DEFAULT true,  -- включен ли квест в принципе (поверх версий)
  meta          jsonb NOT NULL DEFAULT '{}'::jsonb, -- произвольные метаданные (ui и пр.)
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  created_by    text,
  updated_by    text
);
CREATE INDEX IF NOT EXISTS quests_tags_gin ON mythos.quests USING gin (tags);
CREATE TRIGGER trg_quests_updated
BEFORE UPDATE ON mythos.quests
FOR EACH ROW EXECUTE FUNCTION mythos.tg__set_updated_at();

-- 4) Версии квестов (иммутабельные по смыслу, кроме поля is_current)
CREATE TABLE IF NOT EXISTS mythos.quest_versions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quest_id         uuid NOT NULL REFERENCES mythos.quests(id) ON DELETE CASCADE,
  revision         int  NOT NULL CHECK (revision > 0),
  status           mythos.quest_status NOT NULL DEFAULT 'draft',
  is_current       boolean NOT NULL DEFAULT false, -- частично-уникально на квест
  checksum_sha256  bytea,                          -- для детерминизма
  availability     jsonb NOT NULL DEFAULT '{}'::jsonb, -- окна, cooldown, лимиты
  segmentation     jsonb NOT NULL DEFAULT '{}'::jsonb, -- регионы/платформы/атрибуты
  flags            jsonb NOT NULL DEFAULT '{}'::jsonb, -- enabled, mutuallyExclusiveGroups, autoClaimOnComplete и пр.
  rewards          jsonb NOT NULL DEFAULT '{}'::jsonb, -- базовые/firstTime/повторные/кап
  anti_cheat       jsonb NOT NULL DEFAULT '{}'::jsonb,
  rollout          jsonb NOT NULL DEFAULT '{}'::jsonb,
  ab_config        jsonb NOT NULL DEFAULT '{}'::jsonb, -- high-level описание AB-бакетов
  source_locale    mythos.bcp47,                      -- исходный язык
  i18n             jsonb NOT NULL DEFAULT '{}'::jsonb, -- короткие тексты (name/description) по локалям, если храните в БД
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (quest_id, revision)
);
-- Ровно одна текущая версия на квест (если помечена)
CREATE UNIQUE INDEX IF NOT EXISTS quest_versions_one_current_idx
  ON mythos.quest_versions(quest_id)
  WHERE is_current;
CREATE INDEX IF NOT EXISTS quest_versions_qid_status_idx ON mythos.quest_versions(quest_id, status);
CREATE INDEX IF NOT EXISTS quest_versions_i18n_gin ON mythos.quest_versions USING gin (i18n jsonb_path_ops);
CREATE TRIGGER trg_quest_versions_updated
BEFORE UPDATE ON mythos.quest_versions
FOR EACH ROW EXECUTE FUNCTION mythos.tg__set_updated_at();

-- 5) Шаги и цели (каждая запись привязана к версии)
CREATE TABLE IF NOT EXISTS mythos.quest_steps (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quest_version_id uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE CASCADE,
  step_key         text NOT NULL,
  kind             mythos.quest_step_kind NOT NULL,
  event_name       text,             -- для kind=event/counter/custom
  conditions       jsonb NOT NULL DEFAULT '{}'::jsonb,
  failure_rules    jsonb NOT NULL DEFAULT '{}'::jsonb,
  position         int  NOT NULL DEFAULT 0,
  UNIQUE (quest_version_id, step_key)
);
CREATE INDEX IF NOT EXISTS quest_steps_qv_pos_idx ON mythos.quest_steps(quest_version_id, position);

CREATE TABLE IF NOT EXISTS mythos.quest_objectives (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quest_version_id uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE CASCADE,
  step_id          uuid NOT NULL REFERENCES mythos.quest_steps(id) ON DELETE CASCADE,
  objective_key    text NOT NULL,
  type             mythos.objective_type NOT NULL,
  target_numeric   numeric(18,4) NOT NULL DEFAULT 1,
  weight           numeric(10,4) NOT NULL DEFAULT 1,
  track            mythos.track_mode NOT NULL DEFAULT 'server',
  extra            jsonb NOT NULL DEFAULT '{}'::jsonb,
  position         int NOT NULL DEFAULT 0,
  UNIQUE (quest_version_id, objective_key)
);
CREATE INDEX IF NOT EXISTS quest_objectives_step_pos_idx ON mythos.quest_objectives(step_id, position);

-- 6) Мьютекс-группы (взаимоисключающие наборы)
CREATE TABLE IF NOT EXISTS mythos.quest_mutex_groups (
  id        bigserial PRIMARY KEY,
  group_name text NOT NULL,
  quest_key  text NOT NULL REFERENCES mythos.quests(quest_key) ON DELETE CASCADE,
  UNIQUE (group_name, quest_key)
);
CREATE INDEX IF NOT EXISTS quest_mutex_groups_group_idx ON mythos.quest_mutex_groups(group_name);

-- 7) Раскатка (rollout) по стадиям — детализированно (можно также хранить в jsonb; здесь — нормализовано)
CREATE TABLE IF NOT EXISTS mythos.quest_rollout_stages (
  id                bigserial PRIMARY KEY,
  quest_version_id  uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE CASCADE,
  percent           int  NOT NULL CHECK (percent >= 0 AND percent <= 100),
  since             timestamptz NOT NULL,
  position          int NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS quest_rollout_qv_idx ON mythos.quest_rollout_stages(quest_version_id, position);

-- 8) AB-тест: бакеты и варианты
CREATE TABLE IF NOT EXISTS mythos.quest_ab_buckets (
  id                bigserial PRIMARY KEY,
  quest_version_id  uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE CASCADE,
  bucket_key        text NOT NULL, -- напр., "daily_login_copy"
  description       text,
  UNIQUE (quest_version_id, bucket_key)
);

CREATE TABLE IF NOT EXISTS mythos.quest_ab_variants (
  id                bigserial PRIMARY KEY,
  quest_version_id  uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE CASCADE,
  bucket_id         bigint NOT NULL REFERENCES mythos.quest_ab_buckets(id) ON DELETE CASCADE,
  variant_key       text   NOT NULL, -- напр., "A","B"
  traffic_percent   int    NOT NULL CHECK (traffic_percent >= 0 AND traffic_percent <= 100),
  overrides         jsonb  NOT NULL DEFAULT '{}'::jsonb, -- i18n/rewards/прочие оверрайды
  position          int    NOT NULL DEFAULT 0,
  UNIQUE (bucket_id, variant_key)
);
CREATE INDEX IF NOT EXISTS quest_ab_variants_bucket_idx ON mythos.quest_ab_variants(bucket_id);

-- DEFERRABLE-контроль: сумма трафика по бакету = 100 (или 0, если вариантов нет)
CREATE OR REPLACE FUNCTION mythos.tg__ab_traffic_sum_check()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  s int;
BEGIN
  -- Проверяем все бакеты затронутой версии
  FOR s IN
    SELECT v.bucket_id
    FROM mythos.quest_ab_variants v
    WHERE v.quest_version_id = COALESCE(NEW.quest_version_id, OLD.quest_version_id)
    GROUP BY v.bucket_id
  LOOP
    PERFORM 1 FROM mythos.quest_ab_variants WHERE bucket_id = s;
    IF FOUND THEN
      IF (SELECT COALESCE(SUM(traffic_percent),0) FROM mythos.quest_ab_variants WHERE bucket_id = s) <> 100 THEN
        RAISE EXCEPTION 'AB traffic sum for bucket % must be 100%', s;
      END IF;
    END IF;
  END LOOP;
  RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_ab_variants_sum_check_ins ON mythos.quest_ab_variants;
DROP TRIGGER IF EXISTS trg_ab_variants_sum_check_upd ON mythos.quest_ab_variants;
CREATE CONSTRAINT TRIGGER trg_ab_variants_sum_check_ins
AFTER INSERT ON mythos.quest_ab_variants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mythos.tg__ab_traffic_sum_check();
CREATE CONSTRAINT TRIGGER trg_ab_variants_sum_check_upd
AFTER UPDATE ON mythos.quest_ab_variants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mythos.tg__ab_traffic_sum_check();

-- 9) Пользовательские данные: прогресс по квестам и целям
CREATE TABLE IF NOT EXISTS mythos.user_quests (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            text NOT NULL, -- идентификатор пользователя (строка, чтобы не ограничивать источник)
  quest_key          text NOT NULL REFERENCES mythos.quests(quest_key) ON DELETE CASCADE,
  quest_version_id   uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE RESTRICT,
  state              mythos.user_quest_state NOT NULL DEFAULT 'active',
  started_at         timestamptz NOT NULL DEFAULT now(),
  completed_at       timestamptz,
  expires_at         timestamptz,
  last_event_at      timestamptz,
  daily_count        int NOT NULL DEFAULT 0,
  weekly_count       int NOT NULL DEFAULT 0,
  lifetime_count     int NOT NULL DEFAULT 0,
  ab_assignments     jsonb NOT NULL DEFAULT '{}'::jsonb, -- bucket_key -> variant_key
  UNIQUE (user_id, quest_key, quest_version_id) -- пользователь не может иметь дубликат одной версии
);
CREATE INDEX IF NOT EXISTS user_quests_user_state_idx ON mythos.user_quests(user_id, state);
CREATE INDEX IF NOT EXISTS user_quests_qk_idx ON mythos.user_quests(quest_key);

CREATE TABLE IF NOT EXISTS mythos.user_objective_progress (
  user_id            text NOT NULL,
  quest_key          text NOT NULL REFERENCES mythos.quests(quest_key) ON DELETE CASCADE,
  quest_version_id   uuid NOT NULL REFERENCES mythos.quest_versions(id) ON DELETE CASCADE,
  objective_id       uuid NOT NULL REFERENCES mythos.quest_objectives(id) ON DELETE CASCADE,
  progress_numeric   numeric(18,4) NOT NULL DEFAULT 0,
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, quest_version_id, objective_id)
);
CREATE INDEX IF NOT EXISTS user_obj_prog_qv_idx ON mythos.user_objective_progress(quest_version_id);
CREATE TRIGGER trg_user_obj_prog_updated
BEFORE UPDATE ON mythos.user_objective_progress
FOR EACH ROW EXECUTE FUNCTION mythos.tg__set_updated_at();

-- 10) Событийный лог (партиционированный по дате)
CREATE TABLE IF NOT EXISTS mythos.user_quest_events (
  id                 bigserial,
  event_time         timestamptz NOT NULL DEFAULT now(),
  event_date         date GENERATED ALWAYS AS (event_time::date) STORED,
  user_id            text NOT NULL,
  quest_key          text NOT NULL,
  quest_version_id   uuid NOT NULL,
  kind               mythos.event_kind NOT NULL,
  payload            jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (id, event_date)
) PARTITION BY RANGE (event_date);

-- Дефолтная партиция (на случай отсутствия ежемесячных партиций)
CREATE TABLE IF NOT EXISTS mythos.user_quest_events_p_default
  PARTITION OF mythos.user_quest_events
  DEFAULT;

CREATE INDEX IF NOT EXISTS uqevents_user_date_idx ON mythos.user_quest_events(user_id, event_date);
CREATE INDEX IF NOT EXISTS uqevents_qk_kind_time_idx ON mythos.user_quest_events(quest_key, kind, event_time DESC);

-- 11) Леджер наград с идемпотентностью
CREATE TABLE IF NOT EXISTS mythos.reward_ledger (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            text NOT NULL,
  quest_key          text NOT NULL,
  quest_version_id   uuid NOT NULL,
  kind               mythos.ledger_kind NOT NULL,
  currency_code      text,           -- для kind='currency'
  amount             numeric(18,4),  -- сумма валюты
  xp_amount          int,            -- для kind='xp'
  item_id            text,           -- для kind='item'
  item_qty           int,
  meta               jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at         timestamptz NOT NULL DEFAULT now(),
  idempotency_key    text,           -- для предотвращения двойной выдачи
  UNIQUE (user_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS reward_ledger_user_time_idx ON mythos.reward_ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS reward_ledger_qk_idx ON mythos.reward_ledger(quest_key);

-- 12) Инварианты на «текущую» версию: триггер, блокирующий >1 current=true
-- (дополнительно к частичному уникальному индексу; полезно при массовых апдейтах)
CREATE OR REPLACE FUNCTION mythos.tg__ensure_single_current()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.is_current THEN
    UPDATE mythos.quest_versions
    SET is_current = false
    WHERE quest_id = NEW.quest_id
      AND id <> NEW.id
      AND is_current = true;
  END IF;
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_qv_single_current ON mythos.quest_versions;
CREATE TRIGGER trg_qv_single_current
BEFORE INSERT OR UPDATE OF is_current ON mythos.quest_versions
FOR EACH ROW EXECUTE FUNCTION mythos.tg__ensure_single_current();

-- 13) RLS для пользовательских таблиц (опционально включите в проде)
-- Ожидается, что приложение устанавливает: SET LOCAL mythos.user_id = '<uid>';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_settings WHERE name = 'mythos.user_id') THEN
    PERFORM set_config('mythos.user_id', '', false);
  END IF;
END$$;

ALTER TABLE mythos.user_quests ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.user_objective_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.user_quest_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.reward_ledger ENABLE ROW LEVEL SECURITY;

-- Политики: доступ только к строкам текущего пользователя
CREATE POLICY IF NOT EXISTS p_user_quests_self
  ON mythos.user_quests
  USING (user_id = current_setting('mythos.user_id', true));

CREATE POLICY IF NOT EXISTS p_user_obj_prog_self
  ON mythos.user_objective_progress
  USING (user_id = current_setting('mythos.user_id', true));

CREATE POLICY IF NOT EXISTS p_user_events_self
  ON mythos.user_quest_events
  USING (user_id = current_setting('mythos.user_id', true));

CREATE POLICY IF NOT EXISTS p_reward_ledger_self
  ON mythos.reward_ledger
  USING (user_id = current_setting('mythos.user_id', true));

-- 14) Индексы для jsonb и поиска
CREATE INDEX IF NOT EXISTS quest_versions_flags_gin       ON mythos.quest_versions USING gin (flags);
CREATE INDEX IF NOT EXISTS quest_versions_rewards_gin     ON mythos.quest_versions USING gin (rewards);
CREATE INDEX IF NOT EXISTS quest_versions_segmentation_gin ON mythos.quest_versions USING gin (segmentation);

-- 15) Вспомогательная функция для создания месячной партиции событий (по YYYY-MM)
CREATE OR REPLACE FUNCTION mythos.ensure_user_quest_events_partition(p_year int, p_month int)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  start_date date := make_date(p_year, p_month, 1);
  end_date   date := (start_date + INTERVAL '1 month')::date;
  tbl_name   text := format('user_quest_events_p_%s', to_char(start_date, 'YYYYMM'));
  sql        text;
BEGIN
  IF to_regclass('mythos.'||tbl_name) IS NULL THEN
    sql := format($f$
      CREATE TABLE mythos.%I
      PARTITION OF mythos.user_quest_events
      FOR VALUES FROM (%L) TO (%L);
      CREATE INDEX %I_user_time_idx ON mythos.%I(user_id, event_time);
    $f$, tbl_name, start_date, end_date, tbl_name, tbl_name);
    EXECUTE sql;
  END IF;
END$$;

COMMIT;

-- Конец миграции 0002_quests.sql
