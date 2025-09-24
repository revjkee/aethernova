-- =====================================================================
-- physical-integration-core / schemas / sql / migrations / 0003_twin_indices.sql
-- PostgreSQL 12+ (INCLUDE требует 11+, extended statistics — 10+)
-- Цель: индексы/статистика для сущностей Digital Twin.
-- Примечание: CREATE INDEX CONCURRENTLY внутри DO/транзакции невозможен.
-- Для больших таблиц вынесите CONCURRENTLY в отдельную no-TX миграцию.
-- =====================================================================

-- Хелперы: проверка таблиц/колонок/индексов + фич СУБД
DO $$
DECLARE
  v_server int := current_setting('server_version_num')::int;
  v_include_supported boolean := (v_server >= 110000);     -- INCLUDE в btree
  v_extended_stats_supported boolean := (v_server >= 100000);
  r record;

  -- Список целевых таблиц (имена — ожидаемые; ищем во всех current_schemas)
  tgt_tables text[] := ARRAY[
    'twin',                 -- pk: id; связи: device_id, site
    'twin_state',           -- twin_id, ts, version, data(jsonb), archived?
    'twin_event',           -- twin_id, ts, type, severity, attrs(jsonb), site
    'twin_metric',          -- twin_id, metric, ts, value, tags(jsonb)
    'twin_relation',        -- parent_twin_id, child_twin_id, edge_type, valid_to
    'twin_command_log'      -- twin_id, device_id, ts, status, command, impact_level
  ];

  -- Возвращает OID таблицы, если найдена в одном из видимых схем
  FUNCTION find_table_oid(p_rel text) RETURNS oid LANGUAGE plpgsql AS $f$
  DECLARE o oid;
  BEGIN
    SELECT c.oid INTO o
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND c.relname = p_rel
      AND n.nspname = ANY (current_schemas(true))
    LIMIT 1;
    RETURN o;
  END
  $f$;

  -- Полное имя таблицы (schema.quoted_table) по OID
  FUNCTION qname(p_oid oid) RETURNS text LANGUAGE plpgsql AS $f$
  DECLARE outn text;
  BEGIN
    SELECT format('%I.%I', n.nspname, c.relname)
      INTO outn
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = p_oid;
    RETURN outn;
  END
  $f$;

  -- Проверка наличия колонки
  FUNCTION col_exists(p_oid oid, p_col text) RETURNS boolean LANGUAGE plpgsql AS $f$
  DECLARE ok boolean;
  BEGIN
    SELECT EXISTS (
      SELECT 1
      FROM pg_attribute
      WHERE attrelid = p_oid
        AND attname = p_col
        AND attisdropped = false
        AND attnum > 0
    ) INTO ok;
    RETURN ok;
  END
  $f$;

  -- Проверка наличия индекса по имени
  FUNCTION idx_exists(p_schema text, p_idx text) RETURNS boolean LANGUAGE plpgsql AS $f$
  DECLARE ok boolean;
  BEGIN
    SELECT EXISTS (
      SELECT 1 FROM pg_class ic
      JOIN pg_namespace n ON n.oid = ic.relnamespace
      WHERE ic.relkind = 'i'
        AND ic.relname = p_idx
        AND n.nspname = p_schema
    ) INTO ok;
    RETURN ok;
  END
  $f$;

  -- Имя схемы по OID
  FUNCTION schema_of(p_oid oid) RETURNS text LANGUAGE plpgsql AS $f$
  DECLARE sn text;
  BEGIN
    SELECT n.nspname INTO sn
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = p_oid;
    RETURN sn;
  END
  $f$;

BEGIN
  -- Обрабатываем каждую известную таблицу, если она присутствует
  FOREACH r IN ARRAY (
    SELECT json_build_object(
      'oid', find_table_oid(tn),
      'name', tn
    )
    FROM unnest(tgt_tables) AS tn
  )
  LOOP
    IF (r->>'oid') IS NULL THEN
      CONTINUE; -- таблица не найдена в видимых схемах
    END IF;

    PERFORM 1;
    -- Преобразуем JSON в локальные переменные
    DECLARE
      t_oid oid := (r->>'oid')::oid;
      t_rel text := qname((r->>'oid')::oid);
      t_schema text := schema_of((r->>'oid')::oid);
      idx_name text;
    BEGIN
      -- =========================
      -- twin: индексы для связей
      -- =========================
      IF (r->>'name') = 'twin' THEN
        IF col_exists(t_oid, 'device_id') THEN
          idx_name := format('idx_%s_twin_device', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (device_id)', idx_name, t_rel);
          END IF;
        END IF;

        IF col_exists(t_oid, 'site') THEN
          idx_name := format('idx_%s_twin_site', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (site)', idx_name, t_rel);
          END IF;
        END IF;
      END IF;

      -- ======================================
      -- twin_state: «последнее состояние» и JSONB
      -- ======================================
      IF (r->>'name') = 'twin_state' THEN
        -- Уникальность версии близнеца
        IF col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'version') THEN
          idx_name := format('uidx_%s_twin_state_twin_version', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, version)', idx_name, t_rel);
          END IF;
        END IF;

        -- Поиск последнего состояния по времени
        IF col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('idx_%s_twin_state_latest', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            IF v_include_supported AND col_exists(t_oid, 'version') THEN
              EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, ts DESC) INCLUDE (version)', idx_name, t_rel);
            ELSE
              EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, ts DESC)', idx_name, t_rel);
            END IF;
          END IF;

          -- BRIN для длинной истории во времени
          idx_name := format('brin_%s_twin_state_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING brin (ts) WITH (pages_per_range = 128)', idx_name, t_rel);
          END IF;
        END IF;

        -- Частичный индекс «активных» состояний (если есть archived)
        IF col_exists(t_oid, 'archived') AND col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('pidx_%s_twin_state_active', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, ts DESC) WHERE archived IS NOT TRUE', idx_name, t_rel);
          END IF;
        END IF;

        -- GIN по JSONB-данным
        IF col_exists(t_oid, 'data') THEN
          idx_name := format('gin_%s_twin_state_data', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING gin (data jsonb_path_ops)', idx_name, t_rel);
          END IF;
        END IF;

        -- Extended statistics: (twin_id, ts)
        IF v_extended_stats_supported AND col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'ts') THEN
          EXECUTE format('DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_statistic_ext WHERE stxname = %L AND stxnamespace = %L::regnamespace) THEN CREATE STATISTICS %I ON twin_id, ts FROM %s; END IF; END $$;',
                         format('stx_%s_twin_state_twin_ts', t_schema), t_schema, format('stx_%s_twin_state_twin_ts', t_schema), t_rel);
        END IF;
      END IF;

      -- ======================================
      -- twin_event: фильтры по типу/серьёзности и JSONB-attrs
      -- ======================================
      IF (r->>'name') = 'twin_event' THEN
        IF col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('idx_%s_twin_event_twin_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, ts DESC)', idx_name, t_rel);
          END IF;

          -- BRIN по времени для историй
          idx_name := format('brin_%s_twin_event_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING brin (ts) WITH (pages_per_range = 128)', idx_name, t_rel);
          END IF;
        END IF;

        IF col_exists(t_oid, 'type') AND col_exists(t_oid, 'severity') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('idx_%s_twin_event_type_sev_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (type, severity, ts DESC)', idx_name, t_rel);
          END IF;
        END IF;

        IF col_exists(t_oid, 'attrs') THEN
          idx_name := format('gin_%s_twin_event_attrs', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING gin (attrs jsonb_path_ops)', idx_name, t_rel);
          END IF;
        END IF;
      END IF;

      -- ======================================
      -- twin_metric: last-value per metric, JSONB-tags, BRIN по ts
      -- ======================================
      IF (r->>'name') = 'twin_metric' THEN
        IF col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'metric') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('idx_%s_twin_metric_last', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            IF v_include_supported AND col_exists(t_oid, 'value') THEN
              EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, metric, ts DESC) INCLUDE (value)', idx_name, t_rel);
            ELSE
              EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, metric, ts DESC)', idx_name, t_rel);
            END IF;
          END IF;

          idx_name := format('brin_%s_twin_metric_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING brin (ts) WITH (pages_per_range = 128)', idx_name, t_rel);
          END IF;
        END IF;

        IF col_exists(t_oid, 'tags') THEN
          idx_name := format('gin_%s_twin_metric_tags', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING gin (tags jsonb_path_ops)', idx_name, t_rel);
          END IF;
        END IF;

        IF v_extended_stats_supported AND col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'metric') AND col_exists(t_oid, 'ts') THEN
          EXECUTE format('DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_statistic_ext WHERE stxname = %L AND stxnamespace = %L::regnamespace) THEN CREATE STATISTICS %I ON twin_id, metric, ts FROM %s; END IF; END $$;',
                         format('stx_%s_twin_metric_twin_metric_ts', t_schema), t_schema, format('stx_%s_twin_metric_twin_metric_ts', t_schema), t_rel);
        END IF;
      END IF;

      -- ======================================
      -- twin_relation: активные связи и уникальность ребра
      -- ======================================
      IF (r->>'name') = 'twin_relation' THEN
        IF col_exists(t_oid, 'parent_twin_id') AND col_exists(t_oid, 'child_twin_id') AND col_exists(t_oid, 'edge_type') THEN
          idx_name := format('uidx_%s_twin_relation_edge', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS %I ON %s USING btree (parent_twin_id, child_twin_id, edge_type)', idx_name, t_rel);
          END IF;
        END IF;

        IF col_exists(t_oid, 'child_twin_id') THEN
          idx_name := format('idx_%s_twin_relation_child', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (child_twin_id)', idx_name, t_rel);
          END IF;
        END IF;

        IF col_exists(t_oid, 'valid_to') AND col_exists(t_oid, 'parent_twin_id') AND col_exists(t_oid, 'child_twin_id') THEN
          idx_name := format('pidx_%s_twin_relation_active', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (parent_twin_id, child_twin_id) WHERE valid_to IS NULL', idx_name, t_rel);
          END IF;
        END IF;
      END IF;

      -- ======================================
      -- twin_command_log: быстрые фильтры статусов/последние команды
      -- ======================================
      IF (r->>'name') = 'twin_command_log' THEN
        IF col_exists(t_oid, 'twin_id') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('idx_%s_twin_cmd_twin_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            IF v_include_supported AND col_exists(t_oid, 'status') AND col_exists(t_oid, 'command') THEN
              EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, ts DESC) INCLUDE (status, command)', idx_name, t_rel);
            ELSE
              EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (twin_id, ts DESC)', idx_name, t_rel);
            END IF;
          END IF;

          -- BRIN по времени (для больших журналов)
          idx_name := format('brin_%s_twin_cmd_ts', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING brin (ts) WITH (pages_per_range = 128)', idx_name, t_rel);
          END IF;
        END IF;

        -- Частичный индекс по ожиданию выполнения
        IF col_exists(t_oid, 'status') AND col_exists(t_oid, 'ts') THEN
          idx_name := format('pidx_%s_twin_cmd_pending', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (ts DESC) WHERE status = ''pending''', idx_name, t_rel);
          END IF;
        END IF;

        -- Фильтр по уровню воздействия
        IF col_exists(t_oid, 'impact_level') THEN
          idx_name := format('idx_%s_twin_cmd_impact', t_schema);
          IF NOT idx_exists(t_schema, idx_name) THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s USING btree (impact_level)', idx_name, t_rel);
          END IF;
        END IF;
      END IF;

      -- Анализ обновлённых таблиц
      EXECUTE format('ANALYZE %s', t_rel);
    END;
  END LOOP;
END
$$ LANGUAGE plpgsql;

-- Конец миграции
