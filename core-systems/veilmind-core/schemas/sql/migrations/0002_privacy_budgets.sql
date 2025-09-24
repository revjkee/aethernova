-- =====================================================================
-- 0002_privacy_budgets.sql — Дифференциальная приватность: бюджеты и леджер
-- Требования: PostgreSQL >= 13 (рекомендуется 14+), расширение pgcrypto
-- Принципы: Zero Trust, изоляция арендатора (RLS), идемпотентность миграции
-- =====================================================================

-- Безопасное расширение для UUID
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Схема privacy
CREATE SCHEMA IF NOT EXISTS privacy AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA privacy IS 'Veilmind: учёт бюджетов дифференциальной приватности (ε/δ), леджер списаний, функции и RLS';

-- -----------------------------------------------------------------------------
-- Доменные/enum типы
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='subject_kind' AND n.nspname='privacy') THEN
    CREATE TYPE privacy.subject_kind AS ENUM ('user','dataset','client','service');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                 WHERE t.typname='budget_status' AND n.nspname='privacy') THEN
    CREATE TYPE privacy.budget_status AS ENUM ('active','paused','exhausted');
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Таблица бюджетов (ε/δ), многотенантная
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS privacy.budgets (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           text        NOT NULL,
  subject_kind        privacy.subject_kind NOT NULL,
  subject_id          text        NOT NULL,

  -- Нормативные бюджеты (total) и потраченные величины (spent)
  epsilon_total       numeric(12,6) NOT NULL CHECK (epsilon_total  > 0),
  delta_total         numeric(12,9) NOT NULL CHECK (delta_total   > 0 AND delta_total < 1),
  epsilon_spent       numeric(12,6) NOT NULL DEFAULT 0 CHECK (epsilon_spent >= 0),
  delta_spent         numeric(12,9) NOT NULL DEFAULT 0 CHECK (delta_spent  >= 0),

  -- Оконные параметры: фиксированное окно [start,end] ИЛИ скользящее rolling_window
  window_start        timestamptz,
  window_end          timestamptz,
  rolling_window      interval,  -- если задан, расход обнуляется при выходе за окно

  status              privacy.budget_status NOT NULL DEFAULT 'active',
  soft_limit_ratio    numeric(5,4) NOT NULL DEFAULT 0.80 CHECK (soft_limit_ratio > 0 AND soft_limit_ratio < 1),
  last_soft_alert_at  timestamptz,

  description         text,
  meta                jsonb       NOT NULL DEFAULT '{}'::jsonb,

  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),

  -- Уникальность бюджета в рамках (tenant, subject_kind, subject_id, активное окно)
  CONSTRAINT budgets_uniq UNIQUE (tenant_id, subject_kind, subject_id)
);

COMMENT ON TABLE privacy.budgets IS 'Бюджеты дифференциальной приватности ε/δ по субъектам и арендаторам';
COMMENT ON COLUMN privacy.budgets.rolling_window IS 'Если задано: скользящее окно (например, 30 days) для накопления расхода';

-- Индексы
CREATE INDEX IF NOT EXISTS idx_budgets_tenant_subject
  ON privacy.budgets (tenant_id, subject_kind, subject_id);

CREATE INDEX IF NOT EXISTS idx_budgets_status
  ON privacy.budgets (status);

CREATE INDEX IF NOT EXISTS idx_budgets_updated
  ON privacy.budgets (updated_at DESC);

-- -----------------------------------------------------------------------------
-- Леджер списаний из бюджета
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS privacy.ledger (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  budget_id       uuid NOT NULL REFERENCES privacy.budgets(id) ON DELETE CASCADE,
  tenant_id       text NOT NULL,
  ts              timestamptz NOT NULL DEFAULT now(),

  epsilon_spent   numeric(12,6) NOT NULL CHECK (epsilon_spent > 0),
  delta_spent     numeric(12,9) NOT NULL CHECK (delta_spent  > 0 AND delta_spent < 1),

  purpose         text NOT NULL,              -- метка цели/маршрута
  actor_id        text,                       -- инициатор (пользователь/сервис)
  request_id      text,                       -- корреляция запроса
  trace_id        text,                       -- трассировка
  client_ip       inet,
  meta            jsonb NOT NULL DEFAULT '{}'::jsonb
);

COMMENT ON TABLE privacy.ledger IS 'Аудитное списание ε/δ из бюджетов (неизменяемая история)';

-- Индексы леджера
CREATE INDEX IF NOT EXISTS idx_ledger_budget_ts ON privacy.ledger (budget_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_ts ON privacy.ledger (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_reqid    ON privacy.ledger (request_id);

-- -----------------------------------------------------------------------------
-- RLS: изоляция арендатора через GUC app.tenant_id
-- -----------------------------------------------------------------------------
ALTER TABLE privacy.budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy.ledger  ENABLE ROW LEVEL SECURITY;

-- Политики: чтение/изменение только в своём tenant_id
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='privacy' AND tablename='budgets' AND policyname='budgets_tenant_isolation'
  ) THEN
    CREATE POLICY budgets_tenant_isolation ON privacy.budgets
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='privacy' AND tablename='ledger' AND policyname='ledger_tenant_isolation'
  ) THEN
    CREATE POLICY ledger_tenant_isolation ON privacy.ledger
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END$$;

COMMENT ON POLICY budgets_tenant_isolation ON privacy.budgets IS 'RLS: доступ к бюджетам в рамках current_setting(app.tenant_id)';
COMMENT ON POLICY ledger_tenant_isolation  ON privacy.ledger  IS 'RLS: доступ к леджеру в рамках current_setting(app.tenant_id)';

-- -----------------------------------------------------------------------------
-- Триггеры консистентности и soft‑alert
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION privacy.budgets_set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_budgets_set_updated ON privacy.budgets;
CREATE TRIGGER trg_budgets_set_updated
BEFORE UPDATE ON privacy.budgets
FOR EACH ROW EXECUTE FUNCTION privacy.budgets_set_updated_at();

-- Пересчёт статуса и soft‑alert при изменении расходов
CREATE OR REPLACE FUNCTION privacy.budgets_recalc_status()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  eps_ratio numeric;
BEGIN
  eps_ratio := CASE WHEN NEW.epsilon_total > 0 THEN NEW.epsilon_spent / NEW.epsilon_total ELSE 0 END;

  IF NEW.epsilon_spent >= NEW.epsilon_total OR NEW.delta_spent >= NEW.delta_total THEN
    NEW.status := 'exhausted';
  ELSIF eps_ratio >= NEW.soft_limit_ratio AND (NEW.last_soft_alert_at IS NULL OR NEW.last_soft_alert_at < now() - interval '1 hour') THEN
    NEW.last_soft_alert_at := now();
  ELSE
    IF NEW.status = 'exhausted' AND NEW.epsilon_spent < NEW.epsilon_total AND NEW.delta_spent < NEW.delta_total THEN
      NEW.status := 'active';
    END IF;
  END IF;

  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_budgets_recalc_status ON privacy.budgets;
CREATE TRIGGER trg_budgets_recalc_status
BEFORE INSERT OR UPDATE ON privacy.budgets
FOR EACH ROW EXECUTE FUNCTION privacy.budgets_recalc_status();

-- -----------------------------------------------------------------------------
-- Функция атомарного списания бюджета (с защитой от гонок)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION privacy.consume_budget(
  p_tenant_id     text,
  p_subject_kind  privacy.subject_kind,
  p_subject_id    text,
  p_epsilon       numeric,
  p_delta         numeric,
  p_purpose       text,
  p_actor_id      text DEFAULT NULL,
  p_request_id    text DEFAULT NULL,
  p_trace_id      text DEFAULT NULL,
  p_client_ip     inet DEFAULT NULL,
  p_meta          jsonb DEFAULT '{}'::jsonb,
  OUT o_ledger_id uuid,
  OUT o_status    text
)
RETURNS record
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_budget privacy.budgets;
  v_now timestamptz := now();
BEGIN
  IF p_epsilon IS NULL OR p_delta IS NULL OR p_epsilon <= 0 OR p_delta <= 0 OR p_delta >= 1 THEN
    RAISE EXCEPTION 'invalid epsilon/delta values';
  END IF;

  -- Установить GUC для RLS, если не задан
  PERFORM set_config('app.tenant_id', p_tenant_id, true);

  -- Найти бюджет и заблокировать строку для исключения гонок
  SELECT * INTO v_budget
  FROM privacy.budgets
  WHERE tenant_id = p_tenant_id
    AND subject_kind = p_subject_kind
    AND subject_id = p_subject_id
  FOR UPDATE;

  IF NOT FOUND THEN
    o_status := 'not_found';
    RETURN;
  END IF;

  -- Обработка окон: если задано фиксированное окно и мы вне его — блокировать
  IF v_budget.window_start IS NOT NULL AND v_budget.window_end IS NOT NULL THEN
    IF v_now < v_budget.window_start OR v_now > v_budget.window_end THEN
      o_status := 'out_of_window';
      RETURN;
    END IF;
  END IF;

  -- Скользящее окно: при необходимости «обнулить» расход
  IF v_budget.rolling_window IS NOT NULL THEN
    IF v_budget.updated_at < v_now - v_budget.rolling_window THEN
      -- сбрасываем накопленный расход в рамках нового окна
      UPDATE privacy.budgets
         SET epsilon_spent = 0,
             delta_spent = 0,
             updated_at = v_now,
             status = 'active'
       WHERE id = v_budget.id;
      -- перечитываем под блокировкой
      SELECT * INTO v_budget FROM privacy.budgets WHERE id = v_budget.id FOR UPDATE;
    END IF;
  END IF;

  -- Проверка лимитов
  IF v_budget.status = 'paused' THEN
    o_status := 'paused';
    RETURN;
  END IF;

  IF (v_budget.epsilon_spent + p_epsilon) > v_budget.epsilon_total
     OR (v_budget.delta_spent + p_delta) > v_budget.delta_total THEN
    o_status := 'exhausted';
    RETURN;
  END IF;

  -- Запись леджера
  INSERT INTO privacy.ledger(budget_id, tenant_id, epsilon_spent, delta_spent, purpose, actor_id, request_id, trace_id, client_ip, meta)
  VALUES (v_budget.id, p_tenant_id, p_epsilon, p_delta, p_purpose, p_actor_id, p_request_id, p_trace_id, p_client_ip, p_meta)
  RETURNING id INTO o_ledger_id;

  -- Обновление агрегатов
  UPDATE privacy.budgets
     SET epsilon_spent = epsilon_spent + p_epsilon,
         delta_spent   = delta_spent   + p_delta,
         updated_at    = v_now
   WHERE id = v_budget.id;

  -- Итоговый статус
  SELECT CASE
           WHEN epsilon_spent >= epsilon_total OR delta_spent >= delta_total THEN 'exhausted'
           ELSE 'active'
         END
    INTO o_status
  FROM privacy.budgets WHERE id = v_budget.id;

  RETURN;
END
$$;

COMMENT ON FUNCTION privacy.consume_budget(text,privacy.subject_kind,text,numeric,numeric,text,text,text,text,inet,jsonb)
IS 'Атомарное списание ε/δ с леджером и защитой от гонок. Возвращает (ledger_id, status)';

-- -----------------------------------------------------------------------------
-- Представления для мониторинга
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW privacy.v_budget_usage AS
SELECT
  b.id,
  b.tenant_id,
  b.subject_kind,
  b.subject_id,
  b.status,
  b.epsilon_total,
  b.epsilon_spent,
  (b.epsilon_total - b.epsilon_spent) AS epsilon_remaining,
  b.delta_total,
  b.delta_spent,
  (b.delta_total - b.delta_spent)      AS delta_remaining,
  ROUND(CASE WHEN b.epsilon_total>0 THEN (b.epsilon_spent/b.epsilon_total)*100 ELSE 0 END,2) AS eps_used_percent,
  b.soft_limit_ratio,
  b.window_start,
  b.window_end,
  b.rolling_window,
  b.updated_at
FROM privacy.budgets b;

COMMENT ON VIEW privacy.v_budget_usage IS 'Сводная витрина использования бюджетов ε/δ';

-- -----------------------------------------------------------------------------
-- Гранты ролям приложения (при необходимости скорректируйте имена ролей)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='veilmind_app') THEN
    GRANT USAGE ON SCHEMA privacy TO veilmind_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON privacy.budgets TO veilmind_app;
    GRANT SELECT, INSERT ON privacy.ledger TO veilmind_app;
    GRANT SELECT ON privacy.v_budget_usage TO veilmind_app;
    GRANT EXECUTE ON FUNCTION privacy.consume_budget(text,privacy.subject_kind,text,numeric,numeric,text,text,text,text,inet,jsonb) TO veilmind_app;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='veilmind_readonly') THEN
    GRANT USAGE ON SCHEMA privacy TO veilmind_readonly;
    GRANT SELECT ON privacy.budgets, privacy.ledger, privacy.v_budget_usage TO veilmind_readonly;
  END IF;
END$$;

-- =====================================================================
-- Конец миграции
-- =====================================================================
