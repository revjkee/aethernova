-- Подключение расширения TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Создание hypertable для хранения метрик, если отсутствует
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'metrics'
  ) THEN
    PERFORM create_hypertable('metrics', 'time', if_not_exists => TRUE);
  END IF;
END
$$;

-- Добавление политики автоматического удаления данных старше 90 дней для 'metrics'
SELECT add_retention_policy('metrics', INTERVAL '90 days');

-- Создание hypertable для событий, если отсутствует
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'events'
  ) THEN
    PERFORM create_hypertable('events', 'time', if_not_exists => TRUE);
  END IF;
END
$$;

-- Добавление политики автоматического удаления данных старше 180 дней для 'events'
SELECT add_retention_policy('events', INTERVAL '180 days');

-- Создание hypertable для логов, если отсутствует
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'logs'
  ) THEN
    PERFORM create_hypertable('logs', 'time', if_not_exists => TRUE);
  END IF;
END
$$;

-- Добавление политики автоматического удаления данных старше 30 дней для 'logs'
SELECT add_retention_policy('logs', INTERVAL '30 days');

-- Добавление политики сжатия для 'metrics' старше 7 дней
SELECT add_compression_policy('metrics', INTERVAL '7 days');

-- Добавление политики сжатия для 'events' старше 30 дней
SELECT add_compression_policy('events', INTERVAL '30 days');
