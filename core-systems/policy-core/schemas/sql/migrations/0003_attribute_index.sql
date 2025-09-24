-- policy-core/schemas/sql/migrations/0003_attribute_index.sql
-- Цель: ускорить фильтрацию и поиск по JSONB-атрибутам и основным метаданным.
-- Совместимость: PostgreSQL 13+ (рекомендовано 14/15+).
-- Транзакционная миграция; при необходимости "ONLINE" варианта используйте CONCURRENTLY в отдельном шаге.

BEGIN;

-- Консервативные таймауты, чтобы не держать долгие блокировки
SET LOCAL lock_timeout TO '5s';
SET LOCAL statement_timeout TO '15min';
SET LOCAL idle_in_transaction_session_timeout TO '5min';

-- Полезные расширения: триграммы и btree_gin для смешанных стратегий
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Выбор целевой схемы: если существует policy_core — используем её, иначе текущую
DO $$
DECLARE
  target_schema text := 'policy_core';
  have_schema   bool;
BEGIN
  SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = target_schema) INTO have_schema;
  IF NOT have_schema THEN
    target_schema := current_schema;
  END IF;
  PERFORM set_config('policy_core.target_schema', target_schema, true);
END$$;

-- Универсальная утилита создания индексов, безопасная к повторным запускам
DO $$
DECLARE
  s text := current_setting('policy_core.target_schema', true);
  rec record;
  idx_name text;
  ddl text;

  -- Хелпер: усечение имени индекса до 63 символов
  FUNCTION idx_trunc(name_in text) RETURNS text AS $f$
  BEGIN
    IF length(name_in) > 63 THEN
      RETURN substring(name_in from 1 for 55) || '_' || to_char(abs(hashtextextended(name_in, 0))::bigint, 'FM999999999999');
    END IF;
    RETURN name_in;
  END
  $f$ LANGUAGE plpgsql;

BEGIN
  ---------------------------------------------------------------------------
  -- 1) GIN по JSONB-колонкам attributes и labels (для @> и ?/?|/?& и т.п.)
  ---------------------------------------------------------------------------
  FOR rec IN
    SELECT c.table_name, c.column_name
    FROM information_schema.columns c
    WHERE c.table_schema = s
      AND c.data_type = 'jsonb'
      AND c.column_name IN ('attributes','labels')
  LOOP
    idx_name := idx_trunc(format('idx_%s_%s_gin', rec.table_name, rec.column_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I USING GIN (%I jsonb_path_ops) WITH (fastupdate = on)',
      idx_name, s, rec.table_name, rec.column_name
    );
    EXECUTE ddl;
    EXECUTE format('COMMENT ON INDEX %I.%I IS %L',
      s, idx_name, format('GIN jsonb_path_ops for %s.%s.%s', s, rec.table_name, rec.column_name));
  END LOOP;

  ---------------------------------------------------------------------------
  -- 2) Выражения по часто используемым ключам JSONB c partial index
  --    attributes: department, cost_center, country_code
  --    labels:     type, action, required_geo_zone
  ---------------------------------------------------------------------------
  FOR rec IN
    SELECT c.table_name, c.column_name
    FROM information_schema.columns c
    WHERE c.table_schema = s
      AND c.data_type = 'jsonb'
      AND c.column_name = 'attributes'
  LOOP
    -- department
    idx_name := idx_trunc(format('idx_%s_attr_department_btree', rec.table_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I ((lower((%I ->> %L)))) WHERE %I ? %L',
      idx_name, s, rec.table_name, rec.column_name, 'department', rec.column_name, 'department'
    );
    EXECUTE ddl;

    -- cost_center
    idx_name := idx_trunc(format('idx_%s_attr_cost_center_btree', rec.table_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I ((%I ->> %L)) WHERE %I ? %L',
      idx_name, s, rec.table_name, rec.column_name, 'cost_center', rec.column_name, 'cost_center'
    );
    EXECUTE ddl;

    -- country_code
    idx_name := idx_trunc(format('idx_%s_attr_country_code_btree', rec.table_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I ((upper((%I ->> %L)))) WHERE %I ? %L',
      idx_name, s, rec.table_name, rec.column_name, 'country_code', rec.column_name, 'country_code'
    );
    EXECUTE ddl;
  END LOOP;

  FOR rec IN
    SELECT c.table_name, c.column_name
    FROM information_schema.columns c
    WHERE c.table_schema = s
      AND c.data_type = 'jsonb'
      AND c.column_name = 'labels'
  LOOP
    -- type
    idx_name := idx_trunc(format('idx_%s_labels_type_btree', rec.table_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I ((%I ->> %L)) WHERE %I ? %L',
      idx_name, s, rec.table_name, rec.column_name, 'type', rec.column_name, 'type'
    );
    EXECUTE ddl;

    -- action
    idx_name := idx_trunc(format('idx_%s_labels_action_btree', rec.table_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I ((%I ->> %L)) WHERE %I ? %L',
      idx_name, s, rec.table_name, rec.column_name, 'action', rec.column_name, 'action'
    );
    EXECUTE ddl;

    -- required_geo_zone
    idx_name := idx_trunc(format('idx_%s_labels_required_geo_zone_btree', rec.table_name));
    ddl := format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I ((%I ->> %L)) WHERE %I ? %L',
      idx_name, s, rec.table_name, rec.column_name, 'required_geo_zone', rec.column_name, 'required_geo_zone'
    );
    EXECUTE ddl;
  END LOOP;

  ---------------------------------------------------------------------------
  -- 3) B-Tree индексы по базовым колонкам, если они есть
  --    effect, tenant_id, decision_time, subject_id, resource_id
  ---------------------------------------------------------------------------
  FOR rec IN
    SELECT c.table_name, c.column_name
    FROM information_schema.columns c
    WHERE c.table_schema = s
      AND c.column_name IN ('tenant_id','subject_id','resource_id','effect','decision_time')
  LOOP
    idx_name := idx_trunc(format('idx_%s_%s_btree', rec.table_name, rec.column_name));
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I.%I (%I)', idx_name, s, rec.table_name, rec.column_name);
  END LOOP;

  ---------------------------------------------------------------------------
  -- 4) Композитные индексы для высокочастотных запросов аудита/решений,
  --    если таблица содержит нужные столбцы (tenant_id, decision_time, effect)
  ---------------------------------------------------------------------------
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = s AND table_name = 'decisions' AND column_name = 'tenant_id'
  ) AND EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = s AND table_name = 'decisions' AND column_name = 'decision_time'
  ) THEN
    idx_name := idx_trunc('idx_decisions_tenant_time_btree');
    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I (tenant_id, decision_time DESC)',
      idx_name, s, 'decisions'
    );
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = s AND table_name = 'decisions' AND column_name = 'effect'
  ) THEN
    idx_name := idx_trunc('idx_decisions_effect_time_btree');
    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS %I ON %I.%I (effect, decision_time DESC)',
      idx_name, s, 'decisions'
    );
  END IF;

END$$;

-- ПРИМЕЧАНИЕ ПО ONLINE-СОЗДАНИЮ:
-- Если требуется исключить долгие блокировки на больших таблицах, выполните ниже аналогичные
-- команды с ключевым словом CONCURRENTLY В ОТДЕЛЬНОМ миграционном шаге (вне транзакции).
-- Пример:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_decisions_tenant_time_btree
--   ON policy_core.decisions (tenant_id, decision_time DESC);

COMMIT;

-- Конец миграции 0003_attribute_index.sql
