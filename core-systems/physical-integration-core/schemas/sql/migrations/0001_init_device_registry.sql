-- =====================================================================
-- physical-integration-core / schemas/sql/migrations/0001_init_device_registry.sql
-- PostgreSQL 14+ (TimescaleDB совместимо). Идемпотентная и безопасная миграция.
-- =====================================================================

-- 0) Расширения
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid(), шифрование
CREATE EXTENSION IF NOT EXISTS citext;    -- регистронезависимые строки

-- 1) Схема
CREATE SCHEMA IF NOT EXISTS physical_registry AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA physical_registry IS
  'Device Registry: multi-tenant модели производителей, устройств, датчиков, прошивок и аудита.';

-- 2) Доменные типы и enum’ы
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_status') THEN
    CREATE TYPE physical_registry.device_status AS ENUM (
      'provisioned', 'active', 'inactive', 'retired', 'decommissioned', 'lost'
    );
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auth_type') THEN
    CREATE TYPE physical_registry.auth_type AS ENUM (
      'none', 'psk', 'x509', 'oauth2', 'jwt'
    );
  END IF;
END$$;

-- 3) Служебные функции

-- 3.1) Триггерные таймстампы
CREATE OR REPLACE FUNCTION physical_registry.tg_set_timestamps()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_at := COALESCE(NEW.created_at, now());
    NEW.updated_at := COALESCE(NEW.updated_at, now());
  ELSE
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END$$;

-- 3.2) Аудит (Insert/Update/Delete)
CREATE TABLE IF NOT EXISTS physical_registry.audit_log (
  id               bigserial PRIMARY KEY,
  occurred_at      timestamptz NOT NULL DEFAULT now(),
  actor            text        NOT NULL DEFAULT current_user,
  table_name       text        NOT NULL,
  operation        text        NOT NULL CHECK (operation IN ('INSERT','UPDATE','DELETE')),
  row_pk_uuid      uuid,
  old_row          jsonb,
  new_row          jsonb,
  tenant_id        uuid,
  context          jsonb        NOT NULL DEFAULT '{}'::jsonb
);

CREATE OR REPLACE FUNCTION physical_registry.tg_audit_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_tenant text;
BEGIN
  v_tenant := current_setting('app.tenant_id', true);
  IF TG_OP = 'INSERT' THEN
    INSERT INTO physical_registry.audit_log(table_name, operation, row_pk_uuid, new_row, tenant_id)
    VALUES (TG_TABLE_NAME, 'INSERT', NEW.id, to_jsonb(NEW), NULLIF(v_tenant,'')::uuid);
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO physical_registry.audit_log(table_name, operation, row_pk_uuid, old_row, new_row, tenant_id)
    VALUES (TG_TABLE_NAME, 'UPDATE', NEW.id, to_jsonb(OLD), to_jsonb(NEW), NULLIF(v_tenant,'')::uuid);
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO physical_registry.audit_log(table_name, operation, row_pk_uuid, old_row, tenant_id)
    VALUES (TG_TABLE_NAME, 'DELETE', OLD.id, to_jsonb(OLD), NULLIF(v_tenant,'')::uuid);
    RETURN OLD;
  END IF;
  RETURN NULL;
END$$;

-- 3.3) СемВЕР проверка
CREATE OR REPLACE FUNCTION physical_registry.is_semver(ver text)
RETURNS boolean
LANGUAGE sql
AS $$
  SELECT ver ~* '^v?\d+\.\d+\.\d+(-[0-9A-Za-z\.-]+)?(\+[0-9A-Za-z\.-]+)?$'
$$;

-- 3.4) Безопасный доступ к tenant_id (на уровне соединения приложения выполняйте SET)
COMMENT ON FUNCTION physical_registry.is_semver(text) IS 'Проверка версии по SemVer 2.0.0.';

-- 4) Базовые таблицы (multi-tenant)

-- 4.1) Арендаторы
CREATE TABLE IF NOT EXISTS physical_registry.tenants (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         citext NOT NULL UNIQUE,
  status       text   NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER tenants_ts
BEFORE INSERT OR UPDATE ON physical_registry.tenants
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.2) Производители
CREATE TABLE IF NOT EXISTS physical_registry.manufacturers (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         citext NOT NULL UNIQUE,
  country      text,
  website      text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER manufacturers_ts
BEFORE INSERT OR UPDATE ON physical_registry.manufacturers
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.3) Модели устройств
CREATE TABLE IF NOT EXISTS physical_registry.device_models (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  manufacturer_id uuid NOT NULL REFERENCES physical_registry.manufacturers(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  name           citext NOT NULL,
  hardware_rev   text,
  description    text,
  interfaces     jsonb NOT NULL DEFAULT '{}'::jsonb, -- например, {"mqtt":true,"ble":false}
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE(manufacturer_id, name, COALESCE(hardware_rev, ''))
);
CREATE INDEX IF NOT EXISTS device_models_mfr_idx ON physical_registry.device_models(manufacturer_id);
CREATE TRIGGER device_models_ts
BEFORE INSERT OR UPDATE ON physical_registry.device_models
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.4) Устройства
CREATE TABLE IF NOT EXISTS physical_registry.devices (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES physical_registry.tenants(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  manufacturer_id uuid NOT NULL REFERENCES physical_registry.manufacturers(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  model_id        uuid NOT NULL REFERENCES physical_registry.device_models(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  device_uid      citext NOT NULL,  -- внешний идентификатор (MAC/SN/UID)
  serial_number   citext,           -- если отдельно от UID
  status          physical_registry.device_status NOT NULL DEFAULT 'provisioned',
  labels          jsonb  NOT NULL DEFAULT '{}'::jsonb,  -- k/v метки
  location        jsonb  NOT NULL DEFAULT '{}'::jsonb,  -- {"site":"A","lat":..,"lon":..}
  manufactured_at date,
  commissioned_at timestamptz,
  last_seen_at    timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT devices_labels_is_object CHECK (jsonb_typeof(labels) = 'object'),
  CONSTRAINT devices_location_is_object CHECK (jsonb_typeof(location) = 'object'),
  CONSTRAINT devices_uid_chars CHECK (device_uid ~ '^[A-Za-z0-9_\-:\.]{3,128}$'),
  CONSTRAINT devices_serial_chars CHECK (serial_number IS NULL OR serial_number ~ '^[A-Za-z0-9_\-:\.]{3,128}$'),
  UNIQUE(tenant_id, device_uid),
  UNIQUE(tenant_id, serial_number)
);
CREATE INDEX IF NOT EXISTS devices_tenant_idx ON physical_registry.devices(tenant_id);
CREATE INDEX IF NOT EXISTS devices_status_idx ON physical_registry.devices(status);
CREATE INDEX IF NOT EXISTS devices_last_seen_idx ON physical_registry.devices(last_seen_at);
CREATE INDEX IF NOT EXISTS devices_labels_gin ON physical_registry.devices USING gin (labels jsonb_path_ops);
CREATE TRIGGER devices_ts
BEFORE INSERT OR UPDATE ON physical_registry.devices
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.5) Датчики устройства
CREATE TABLE IF NOT EXISTS physical_registry.sensors (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id    uuid NOT NULL REFERENCES physical_registry.devices(id) ON UPDATE CASCADE ON DELETE CASCADE,
  kind         text NOT NULL,    -- "imu.gyro", "thermistor", "camera", ...
  channel      text NOT NULL,    -- "x","y","z","rgb","depth","ch1"
  unit_ucum    text,             -- UCUM, напр. "Cel","m/s^2"
  labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT sensors_labels_is_object CHECK (jsonb_typeof(labels) = 'object'),
  UNIQUE(device_id, kind, channel)
);
CREATE INDEX IF NOT EXISTS sensors_device_idx ON physical_registry.sensors(device_id);
CREATE TRIGGER sensors_ts
BEFORE INSERT OR UPDATE ON physical_registry.sensors
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.6) Прошивки (каталог)
CREATE TABLE IF NOT EXISTS physical_registry.firmwares (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id       uuid REFERENCES physical_registry.device_models(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  version        text NOT NULL,
  image_uri      text NOT NULL,    -- s3://... или https://...
  sha256         text NOT NULL CHECK (sha256 ~ '^[A-Fa-f0-9]{64}$'),
  signed         boolean NOT NULL DEFAULT true,
  release_notes  text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT firmwares_semver CHECK (physical_registry.is_semver(version)),
  UNIQUE(model_id, version)
);
CREATE INDEX IF NOT EXISTS firmwares_model_idx ON physical_registry.firmwares(model_id);
CREATE TRIGGER firmwares_ts
BEFORE INSERT OR UPDATE ON physical_registry.firmwares
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.7) Текущая/установленная прошивка устройства
CREATE TABLE IF NOT EXISTS physical_registry.device_firmwares (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id      uuid NOT NULL REFERENCES physical_registry.devices(id) ON UPDATE CASCADE ON DELETE CASCADE,
  firmware_id    uuid NOT NULL REFERENCES physical_registry.firmwares(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  is_current     boolean NOT NULL DEFAULT false,
  installed_at   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE(device_id, firmware_id)
);
CREATE INDEX IF NOT EXISTS device_firmwares_curr_idx ON physical_registry.device_firmwares(device_id) WHERE is_current;
CREATE TRIGGER device_firmwares_ts
BEFORE INSERT OR UPDATE ON physical_registry.device_firmwares
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.8) Учётные данные/секреты устройства
CREATE TABLE IF NOT EXISTS physical_registry.device_credentials (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id         uuid NOT NULL REFERENCES physical_registry.devices(id) ON UPDATE CASCADE ON DELETE CASCADE,
  type              physical_registry.auth_type NOT NULL,
  public_key_pem    text,     -- для x509/jwt
  secret_encrypted  bytea,    -- pgp_sym_encrypt(...) или внешний KMS (колонка для совместимости)
  not_before        timestamptz,
  not_after         timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT credentials_time_window CHECK (not_before IS NULL OR not_after IS NULL OR not_after > not_before)
);
CREATE UNIQUE INDEX IF NOT EXISTS device_credentials_unique_type
ON physical_registry.device_credentials(device_id, type);
CREATE TRIGGER device_credentials_ts
BEFORE INSERT OR UPDATE ON physical_registry.device_credentials
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 4.9) Свободные k/v ярлыки на устройство (быстрый текстовый поиск)
CREATE TABLE IF NOT EXISTS physical_registry.device_kv_labels (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   uuid NOT NULL REFERENCES physical_registry.devices(id) ON UPDATE CASCADE ON DELETE CASCADE,
  key         citext NOT NULL,
  value       text   NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE(device_id, key)
);
CREATE INDEX IF NOT EXISTS device_kv_labels_key_idx ON physical_registry.device_kv_labels(key);
CREATE TRIGGER device_kv_labels_ts
BEFORE INSERT OR UPDATE ON physical_registry.device_kv_labels
FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_set_timestamps();

-- 5) Политики безопасности: RLS (изоляция по tenant_id)
-- Для таблиц, содержащих tenant_id (devices и производные), включаем RLS.
ALTER TABLE physical_registry.devices           ENABLE ROW LEVEL SECURITY;
ALTER TABLE physical_registry.sensors           ENABLE ROW LEVEL SECURITY;
ALTER TABLE physical_registry.device_firmwares  ENABLE ROW LEVEL SECURITY;
ALTER TABLE physical_registry.device_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE physical_registry.device_kv_labels  ENABLE ROW LEVEL SECURITY;

-- Политики: SELECT/INSERT/UPDATE/DELETE разрешены, если tenant_id совпадает с current_setting('app.tenant_id')
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='physical_registry' AND tablename='devices' AND policyname='devices_tenant_isolation') THEN
    CREATE POLICY devices_tenant_isolation ON physical_registry.devices
      USING ( tenant_id::text = current_setting('app.tenant_id', true) )
      WITH CHECK ( tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='physical_registry' AND tablename='sensors' AND policyname='sensors_tenant_isolation') THEN
    CREATE POLICY sensors_tenant_isolation ON physical_registry.sensors
      USING ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = sensors.device_id)::text = current_setting('app.tenant_id', true) )
      WITH CHECK ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = sensors.device_id)::text = current_setting('app.tenant_id', true) );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='physical_registry' AND tablename='device_firmwares' AND policyname='device_fw_tenant_isolation') THEN
    CREATE POLICY device_fw_tenant_isolation ON physical_registry.device_firmwares
      USING ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = device_firmwares.device_id)::text = current_setting('app.tenant_id', true) )
      WITH CHECK ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = device_firmwares.device_id)::text = current_setting('app.tenant_id', true) );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='physical_registry' AND tablename='device_credentials' AND policyname='device_creds_tenant_isolation') THEN
    CREATE POLICY device_creds_tenant_isolation ON physical_registry.device_credentials
      USING ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = device_credentials.device_id)::text = current_setting('app.tenant_id', true) )
      WITH CHECK ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = device_credentials.device_id)::text = current_setting('app.tenant_id', true) );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='physical_registry' AND tablename='device_kv_labels' AND policyname='device_kv_tenant_isolation') THEN
    CREATE POLICY device_kv_tenant_isolation ON physical_registry.device_kv_labels
      USING ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = device_kv_labels.device_id)::text = current_setting('app.tenant_id', true) )
      WITH CHECK ( (SELECT tenant_id FROM physical_registry.devices d WHERE d.id = device_kv_labels.device_id)::text = current_setting('app.tenant_id', true) );
  END IF;
END$$;

-- 6) Аудит: навешиваем триггеры на ключевые таблицы
DO $$
BEGIN
  PERFORM 1 FROM pg_trigger WHERE tgname='audit_devices_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_devices_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.devices
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_sensors_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_sensors_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.sensors
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_firmwares_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_firmwares_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.firmwares
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_device_firmwares_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_device_firmwares_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.device_firmwares
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_device_credentials_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_device_credentials_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.device_credentials
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_device_kv_labels_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_device_kv_labels_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.device_kv_labels
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_manufacturers_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_manufacturers_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.manufacturers
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_device_models_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_device_models_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.device_models
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;

  PERFORM 1 FROM pg_trigger WHERE tgname='audit_tenants_row';
  IF NOT FOUND THEN
    CREATE TRIGGER audit_tenants_row
      AFTER INSERT OR UPDATE OR DELETE ON physical_registry.tenants
      FOR EACH ROW EXECUTE FUNCTION physical_registry.tg_audit_row();
  END IF;
END$$;

-- 7) Просмотр (view) для удобного чтения
CREATE OR REPLACE VIEW physical_registry.v_device_full AS
SELECT
  d.id,
  d.tenant_id,
  t.name           AS tenant_name,
  d.device_uid,
  d.serial_number,
  d.status,
  mfr.name         AS manufacturer,
  mdl.name         AS model,
  mdl.hardware_rev AS model_hw_rev,
  d.labels,
  d.location,
  d.manufactured_at,
  d.commissioned_at,
  d.last_seen_at,
  d.created_at,
  d.updated_at,
  fw.version       AS current_fw_version,
  fw.image_uri     AS current_fw_image_uri,
  fw.sha256        AS current_fw_sha256
FROM physical_registry.devices d
JOIN physical_registry.tenants t ON t.id = d.tenant_id
JOIN physical_registry.manufacturers mfr ON mfr.id = d.manufacturer_id
JOIN physical_registry.device_models mdl ON mdl.id = d.model_id
LEFT JOIN LATERAL (
  SELECT f.*
  FROM physical_registry.device_firmwares df
  JOIN physical_registry.firmwares f ON f.id = df.firmware_id
  WHERE df.device_id = d.id AND df.is_current
  ORDER BY df.installed_at DESC NULLS LAST
  LIMIT 1
) fw ON TRUE;

COMMENT ON VIEW physical_registry.v_device_full IS
  'Джоин устройства с tenant, производителем/моделью и текущей прошивкой.';

-- 8) Рекомендация: ограничить прямой доступ к таблицам ролями, пользователю приложения дать SELECT на view и RLS-доступ к таблицам по политикам.

-- =====================================================================
-- Конец миграции 0001
-- =====================================================================
