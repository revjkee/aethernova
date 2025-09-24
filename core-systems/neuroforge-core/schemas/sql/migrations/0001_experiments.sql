-- neuroforge-core/schemas/sql/migrations/0001_experiments.sql
-- PostgreSQL >= 13. Фокус: multi-tenant, строгие ограничения, производительные индексы, RLS.

BEGIN;

-- 0) Расширения и схема
CREATE SCHEMA IF NOT EXISTS mlops;

-- UUID генератор (gen_random_uuid)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1) Типы (enum) — через DO для идемпотентности на старых версиях
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'experiment_stage') THEN
    CREATE TYPE mlops.experiment_stage AS ENUM ('DRAFT','ACTIVE','ARCHIVED');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'run_status') THEN
    CREATE TYPE mlops.run_status AS ENUM ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'artifact_type') THEN
    CREATE TYPE mlops.artifact_type AS ENUM ('MODEL','DATASET','METRIC_PLOT','LOG','OTHER');
  END IF;
END $$;

-- 2) Универсальная функция updated_at
CREATE OR REPLACE FUNCTION mlops.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- 3) Функции-гарды для выравнивания tenant_id
CREATE OR REPLACE FUNCTION mlops.set_run_tenant_from_experiment()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  exp_tenant text;
BEGIN
  SELECT tenant_id INTO exp_tenant FROM mlops.experiments WHERE id = NEW.experiment_id;
  IF exp_tenant IS NULL THEN
    RAISE EXCEPTION 'Experiment % not found for run', NEW.experiment_id;
  END IF;
  NEW.tenant_id := exp_tenant;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mlops.set_child_tenant_from_run()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  run_tenant text;
BEGIN
  SELECT tenant_id INTO run_tenant FROM mlops.experiment_runs WHERE id = NEW.run_id;
  IF run_tenant IS NULL THEN
    RAISE EXCEPTION 'Run % not found for child row', NEW.run_id;
  END IF;
  NEW.tenant_id := run_tenant;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mlops.set_lineage_tenant_from_run()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  parent_t text;
  child_t  text;
BEGIN
  SELECT tenant_id INTO parent_t FROM mlops.experiment_runs WHERE id = NEW.parent_run_id;
  SELECT tenant_id INTO child_t  FROM mlops.experiment_runs WHERE id = NEW.child_run_id;
  IF parent_t IS NULL OR child_t IS NULL THEN
    RAISE EXCEPTION 'Parent or child run not found for lineage';
  END IF;
  IF parent_t <> child_t THEN
    RAISE EXCEPTION 'Lineage across different tenants is not allowed (% vs %)', parent_t, child_t;
  END IF;
  NEW.tenant_id := parent_t;
  RETURN NEW;
END;
$$;

-- 4) Таблица экспериментов
CREATE TABLE IF NOT EXISTS mlops.experiments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       text NOT NULL,
  key             text NOT NULL,                        -- технический ключ (короткий, URL-safe)
  name            text NOT NULL,                        -- человеко-читаемое имя
  description     text,
  stage           mlops.experiment_stage NOT NULL DEFAULT 'DRAFT',
  owner_id        text,
  labels          jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,

  CONSTRAINT experiments_key_format_chk CHECK (key ~* '^[a-z0-9]([a-z0-9_-]{0,62})$'),
  CONSTRAINT experiments_labels_obj_chk CHECK (jsonb_typeof(labels) = 'object'),
  CONSTRAINT experiments_metadata_obj_chk CHECK (jsonb_typeof(metadata) = 'object')
);

-- Уникальность активных записей по (tenant_id, key)
CREATE UNIQUE INDEX IF NOT EXISTS ux_experiments_tenant_key_active
ON mlops.experiments (tenant_id, key)
WHERE deleted_at IS NULL;

-- Индексы
CREATE INDEX IF NOT EXISTS ix_experiments_tenant ON mlops.experiments (tenant_id);
CREATE INDEX IF NOT EXISTS ix_experiments_stage  ON mlops.experiments (stage);
CREATE INDEX IF NOT EXISTS ix_experiments_labels_gin ON mlops.experiments USING gin (labels jsonb_path_ops);

-- Триггер updated_at
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.experiments'::regclass AND tgname = 'trg_experiments_updated_at'
  ) THEN
    CREATE TRIGGER trg_experiments_updated_at
    BEFORE UPDATE ON mlops.experiments
    FOR EACH ROW EXECUTE FUNCTION mlops.set_updated_at();
  END IF;
END $$;

COMMENT ON TABLE  mlops.experiments IS 'Эксперименты (multi-tenant). Частично уникальны по (tenant_id,key) среди не удалённых.';
COMMENT ON COLUMN mlops.experiments.key IS 'Машинный ключ (URL-safe), ^[a-z0-9][a-z0-9_-]{0,62}$';
COMMENT ON COLUMN mlops.experiments.labels IS 'Произвольные метки для селекции (JSON-объект)';

-- 5) Таблица запусков
CREATE TABLE IF NOT EXISTS mlops.experiment_runs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  experiment_id   uuid NOT NULL REFERENCES mlops.experiments(id) ON DELETE CASCADE,
  tenant_id       text NOT NULL,                  -- выравнивается с эксперимента триггером
  run_key         text,                           -- опциональный машинный ключ запуска
  status          mlops.run_status NOT NULL DEFAULT 'PENDING',
  started_at      timestamptz NOT NULL DEFAULT now(),
  finished_at     timestamptz,
  params          jsonb NOT NULL DEFAULT '{}'::jsonb,
  metrics         jsonb NOT NULL DEFAULT '{}'::jsonb,
  tags_json       jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_by      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,

  CONSTRAINT runs_time_order_chk CHECK (finished_at IS NULL OR finished_at >= started_at),
  CONSTRAINT runs_params_obj_chk  CHECK (jsonb_typeof(params)  = 'object'),
  CONSTRAINT runs_metrics_obj_chk CHECK (jsonb_typeof(metrics) = 'object'),
  CONSTRAINT runs_tags_arr_chk    CHECK (jsonb_typeof(tags_json) = 'array')
);

-- Уникальность run_key в рамках эксперимента (для живых записей)
CREATE UNIQUE INDEX IF NOT EXISTS ux_runs_experiment_key_active
ON mlops.experiment_runs (experiment_id, run_key)
WHERE deleted_at IS NULL AND run_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_runs_experiment ON mlops.experiment_runs (experiment_id);
CREATE INDEX IF NOT EXISTS ix_runs_tenant     ON mlops.experiment_runs (tenant_id);
CREATE INDEX IF NOT EXISTS ix_runs_status     ON mlops.experiment_runs (status);
CREATE INDEX IF NOT EXISTS ix_runs_started_at ON mlops.experiment_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS ix_runs_params_gin ON mlops.experiment_runs USING gin (params jsonb_path_ops);
CREATE INDEX IF NOT EXISTS ix_runs_metrics_gin ON mlops.experiment_runs USING gin (metrics jsonb_path_ops);

-- Триггеры: updated_at + выравнивание tenant_id
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.experiment_runs'::regclass AND tgname = 'trg_runs_updated_at'
  ) THEN
    CREATE TRIGGER trg_runs_updated_at
    BEFORE UPDATE ON mlops.experiment_runs
    FOR EACH ROW EXECUTE FUNCTION mlops.set_updated_at();
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.experiment_runs'::regclass AND tgname = 'trg_runs_set_tenant'
  ) THEN
    CREATE TRIGGER trg_runs_set_tenant
    BEFORE INSERT OR UPDATE OF experiment_id ON mlops.experiment_runs
    FOR EACH ROW EXECUTE FUNCTION mlops.set_run_tenant_from_experiment();
  END IF;
END $$;

COMMENT ON TABLE mlops.experiment_runs IS 'Запуски экспериментов. tenant_id наследуется от эксперимента (триггер).';

-- 6) Метрики (нормализованные точки)
CREATE TABLE IF NOT EXISTS mlops.metrics (
  id        bigserial PRIMARY KEY,
  run_id    uuid NOT NULL REFERENCES mlops.experiment_runs(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,  -- смикширован триггером
  key       text NOT NULL,
  value     double precision NOT NULL,
  step      bigint NOT NULL DEFAULT 0,
  ts        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_metrics_run_key_step ON mlops.metrics (run_id, key, step);
CREATE INDEX IF NOT EXISTS ix_metrics_ts           ON mlops.metrics (ts DESC);
CREATE INDEX IF NOT EXISTS ix_metrics_tenant       ON mlops.metrics (tenant_id);

-- 7) Параметры (нормализованные)
CREATE TABLE IF NOT EXISTS mlops.params (
  run_id    uuid NOT NULL REFERENCES mlops.experiment_runs(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  key       text NOT NULL,
  value     text NOT NULL,
  PRIMARY KEY (run_id, key)
);

CREATE INDEX IF NOT EXISTS ix_params_tenant ON mlops.params (tenant_id);

-- 8) Артефакты
CREATE TABLE IF NOT EXISTS mlops.artifacts (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id         uuid NOT NULL REFERENCES mlops.experiment_runs(id) ON DELETE CASCADE,
  tenant_id      text NOT NULL,
  uri            text NOT NULL,
  path           text,
  type           mlops.artifact_type NOT NULL DEFAULT 'OTHER',
  checksum_sha256 text,
  size_bytes     bigint,
  etag           text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_artifacts_run_type ON mlops.artifacts (run_id, type);
CREATE INDEX IF NOT EXISTS ix_artifacts_tenant   ON mlops.artifacts (tenant_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.artifacts'::regclass AND tgname = 'trg_artifacts_updated_at'
  ) THEN
    CREATE TRIGGER trg_artifacts_updated_at
    BEFORE UPDATE ON mlops.artifacts
    FOR EACH ROW EXECUTE FUNCTION mlops.set_updated_at();
  END IF;
END $$;

-- 9) Теги (нормализованные)
CREATE TABLE IF NOT EXISTS mlops.experiment_tags (
  experiment_id uuid NOT NULL REFERENCES mlops.experiments(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  key           text NOT NULL,
  value         text NOT NULL,
  PRIMARY KEY (experiment_id, key)
);

CREATE INDEX IF NOT EXISTS ix_experiment_tags_tenant ON mlops.experiment_tags (tenant_id);

CREATE TABLE IF NOT EXISTS mlops.run_tags (
  run_id    uuid NOT NULL REFERENCES mlops.experiment_runs(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  key       text NOT NULL,
  value     text NOT NULL,
  PRIMARY KEY (run_id, key)
);

CREATE INDEX IF NOT EXISTS ix_run_tags_tenant ON mlops.run_tags (tenant_id);

-- 10) Линидж (граф зависимостей запусков)
CREATE TABLE IF NOT EXISTS mlops.lineage (
  parent_run_id uuid NOT NULL REFERENCES mlops.experiment_runs(id) ON DELETE CASCADE,
  child_run_id  uuid NOT NULL REFERENCES mlops.experiment_runs(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  PRIMARY KEY (parent_run_id, child_run_id),
  CONSTRAINT lineage_no_self_loop CHECK (parent_run_id <> child_run_id)
);

CREATE INDEX IF NOT EXISTS ix_lineage_parent ON mlops.lineage (parent_run_id);
CREATE INDEX IF NOT EXISTS ix_lineage_child  ON mlops.lineage (child_run_id);
CREATE INDEX IF NOT EXISTS ix_lineage_tenant ON mlops.lineage (tenant_id);

-- 11) Триггеры заполнения tenant_id от run_id
-- metrics
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.metrics'::regclass AND tgname = 'trg_metrics_set_tenant'
  ) THEN
    CREATE TRIGGER trg_metrics_set_tenant
    BEFORE INSERT ON mlops.metrics
    FOR EACH ROW EXECUTE FUNCTION mlops.set_child_tenant_from_run();
  END IF;
END $$;

-- params
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.params'::regclass AND tgname = 'trg_params_set_tenant'
  ) THEN
    CREATE TRIGGER trg_params_set_tenant
    BEFORE INSERT ON mlops.params
    FOR EACH ROW EXECUTE FUNCTION mlops.set_child_tenant_from_run();
  END IF;
END $$;

-- artifacts
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.artifacts'::regclass AND tgname = 'trg_artifacts_set_tenant'
  ) THEN
    CREATE TRIGGER trg_artifacts_set_tenant
    BEFORE INSERT ON mlops.artifacts
    FOR EACH ROW EXECUTE FUNCTION mlops.set_child_tenant_from_run();
  END IF;
END $$;

-- run_tags
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.run_tags'::regclass AND tgname = 'trg_run_tags_set_tenant'
  ) THEN
    CREATE TRIGGER trg_run_tags_set_tenant
    BEFORE INSERT ON mlops.run_tags
    FOR EACH ROW EXECUTE FUNCTION mlops.set_child_tenant_from_run();
  END IF;
END $$;

-- experiment_tags — от эксперимента
CREATE OR REPLACE FUNCTION mlops.set_tag_tenant_from_experiment()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  exp_tenant text;
BEGIN
  SELECT tenant_id INTO exp_tenant FROM mlops.experiments WHERE id = NEW.experiment_id;
  IF exp_tenant IS NULL THEN
    RAISE EXCEPTION 'Experiment % not found for tag', NEW.experiment_id;
  END IF;
  NEW.tenant_id := exp_tenant;
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.experiment_tags'::regclass AND tgname = 'trg_experiment_tags_set_tenant'
  ) THEN
    CREATE TRIGGER trg_experiment_tags_set_tenant
    BEFORE INSERT ON mlops.experiment_tags
    FOR EACH ROW EXECUTE FUNCTION mlops.set_tag_tenant_from_experiment();
  END IF;
END $$;

-- lineage
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgrelid = 'mlops.lineage'::regclass AND tgname = 'trg_lineage_set_tenant'
  ) THEN
    CREATE TRIGGER trg_lineage_set_tenant
    BEFORE INSERT ON mlops.lineage
    FOR EACH ROW EXECUTE FUNCTION mlops.set_lineage_tenant_from_run();
  END IF;
END $$;

-- 12) Представления (быстрый доступ)
CREATE OR REPLACE VIEW mlops.v_last_run AS
SELECT DISTINCT ON (r.experiment_id)
  r.experiment_id,
  r.id          AS last_run_id,
  r.status      AS last_status,
  r.started_at  AS last_started_at,
  r.finished_at AS last_finished_at
FROM mlops.experiment_runs r
WHERE r.deleted_at IS NULL
ORDER BY r.experiment_id, r.started_at DESC;

CREATE OR REPLACE VIEW mlops.v_last_success AS
SELECT DISTINCT ON (r.experiment_id)
  r.experiment_id,
  r.id          AS last_success_run_id,
  r.started_at  AS last_success_started_at,
  r.finished_at AS last_success_finished_at
FROM mlops.experiment_runs r
WHERE r.deleted_at IS NULL AND r.status = 'SUCCEEDED'
ORDER BY r.experiment_id, r.finished_at DESC NULLS LAST;

-- 13) Row Level Security (RLS)
-- Политика: видимость и изменения только в рамках tenant_id = current_setting('app.tenant_id', true)
-- Для админов платфоры можно установить app.tenant_id = '*' и включить BYPASS (пример не приводится здесь).

-- Хелпер-предикат
CREATE OR REPLACE FUNCTION mlops.tenant_predicate(t text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    CASE
      WHEN current_setting('app.tenant_id', true) IS NULL THEN false
      WHEN current_setting('app.tenant_id', true) = '*' THEN true
      ELSE t = current_setting('app.tenant_id', true)
    END
$$;

-- Включаем RLS и объявляем политики
-- experiments
ALTER TABLE mlops.experiments ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='experiments' AND policyname='experiments_tenant_isolation'
  ) THEN
    CREATE POLICY experiments_tenant_isolation ON mlops.experiments
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

-- runs
ALTER TABLE mlops.experiment_runs ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='experiment_runs' AND policyname='runs_tenant_isolation'
  ) THEN
    CREATE POLICY runs_tenant_isolation ON mlops.experiment_runs
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

-- metrics
ALTER TABLE mlops.metrics ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='metrics' AND policyname='metrics_tenant_isolation'
  ) THEN
    CREATE POLICY metrics_tenant_isolation ON mlops.metrics
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

-- params
ALTER TABLE mlops.params ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='params' AND policyname='params_tenant_isolation'
  ) THEN
    CREATE POLICY params_tenant_isolation ON mlops.params
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

-- artifacts
ALTER TABLE mlops.artifacts ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='artifacts' AND policyname='artifacts_tenant_isolation'
  ) THEN
    CREATE POLICY artifacts_tenant_isolation ON mlops.artifacts
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

-- tags
ALTER TABLE mlops.experiment_tags ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='experiment_tags' AND policyname='experiment_tags_tenant_isolation'
  ) THEN
    CREATE POLICY experiment_tags_tenant_isolation ON mlops.experiment_tags
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

ALTER TABLE mlops.run_tags ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='run_tags' AND policyname='run_tags_tenant_isolation'
  ) THEN
    CREATE POLICY run_tags_tenant_isolation ON mlops.run_tags
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

-- lineage
ALTER TABLE mlops.lineage ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname='mlops' AND tablename='lineage' AND policyname='lineage_tenant_isolation'
  ) THEN
    CREATE POLICY lineage_tenant_isolation ON mlops.lineage
      USING (mlops.tenant_predicate(tenant_id))
      WITH CHECK (mlops.tenant_predicate(tenant_id));
  END IF;
END $$;

COMMIT;

-- Примечания по эксплуатации:
--   * Перед запросами установите SET app.tenant_id = '<TENANT>'; для админов — '*'.
--   * Частичные уникальные индексы исключают «мягко удалённые» записи (deleted_at IS NULL).
--   * Представления v_last_run/v_last_success ускоряют типовые выборки для дашбордов.
