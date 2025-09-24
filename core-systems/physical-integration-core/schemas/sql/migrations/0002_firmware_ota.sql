-- physical-integration-core/schemas/sql/migrations/0002_firmware_ota.sql
-- PostgreSQL industrial migration for Firmware OTA subsystem

SET statement_timeout = '60s';
SET lock_timeout = '15s';
SET idle_in_transaction_session_timeout = '60s';
SET client_min_messages = WARNING;
SET search_path = public;

BEGIN;

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

-- -----------------------------------------------------------------------------
-- Helper trigger: updated_at
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at'
  ) THEN
    CREATE OR REPLACE FUNCTION public.set_updated_at()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $fn$
    BEGIN
      NEW.updated_at := now();
      RETURN NEW;
    END;
    $fn$;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- ENUM types (idempotent via catalog checks)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ota_strategy_enum') THEN
    CREATE TYPE ota_strategy_enum AS ENUM ('immediate','progressive','staged');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ota_device_status_enum') THEN
    CREATE TYPE ota_device_status_enum AS ENUM (
      'idle','queued','downloading','verifying','installing','rebooting','done','failed','rolled_back','canceled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ota_campaign_status_enum') THEN
    CREATE TYPE ota_campaign_status_enum AS ENUM (
      'draft','scheduled','running','paused','completed','canceled','failed'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ota_signature_alg_enum') THEN
    CREATE TYPE ota_signature_alg_enum AS ENUM ('ed25519','rsa_pss_sha256','ecdsa_p256_sha256');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ota_event_action_enum') THEN
    CREATE TYPE ota_event_action_enum AS ENUM (
      'assign','download_start','download_complete','verify_ok','verify_fail',
      'install_start','install_complete','reboot','rollback','status','error'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ota_actor_type_enum') THEN
    CREATE TYPE ota_actor_type_enum AS ENUM ('system','user','device');
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- firmware_images: каталог образов прошивок
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firmware_images (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL,
  device_model            text NOT NULL,
  hw_revision             text,
  version                 text NOT NULL,
  version_major           int2 GENERATED ALWAYS AS (NULLIF(split_part(version,'.',1),'')::int2) STORED,
  version_minor           int2 GENERATED ALWAYS AS (NULLIF(split_part(version,'.',2),'')::int2) STORED,
  version_patch           int2 GENERATED ALWAYS AS (NULLIF(regexp_replace(split_part(version,'.',3),'[^0-9].*$',''), '')::int2) STORED,
  size_bytes              int8 NOT NULL CHECK (size_bytes > 0),
  sha256                  bytea NOT NULL CHECK (octet_length(sha256) = 32),
  signature               bytea,
  signature_alg           ota_signature_alg_enum,
  sig_cert_fingerprint    bytea,
  content_type            text,
  storage_url             text NOT NULL,
  release_notes           text,
  critical                boolean NOT NULL DEFAULT false,
  is_published            boolean NOT NULL DEFAULT false,
  published_at            timestamptz,
  revoked_at              timestamptz,
  revoked_reason          text,
  metadata                jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([\-+][0-9A-Za-z\.-]+)?$'),
  CHECK (signature IS NULL OR signature_alg IS NOT NULL),
  CHECK (NOT is_published OR (signature IS NOT NULL AND published_at IS NOT NULL)),
  CHECK (revoked_at IS NULL OR is_published = false)
);

COMMENT ON TABLE firmware_images IS 'Каталог образов прошивок OTA';
COMMENT ON COLUMN firmware_images.sha256 IS 'Двоичный SHA-256 (32 байта)';
COMMENT ON COLUMN firmware_images.signature IS 'Цифровая подпись всего артефакта';
COMMENT ON COLUMN firmware_images.critical IS 'Принудительное обновление (критический релиз)';

-- Уникальность версии внутри модели и арендатора
CREATE UNIQUE INDEX IF NOT EXISTS ux_firmware_images_tenant_model_version
  ON firmware_images (tenant_id, device_model, version);

-- Поиск последних опубликованных
CREATE INDEX IF NOT EXISTS ix_firmware_images_published
  ON firmware_images (tenant_id, device_model, is_published, published_at DESC);

-- Триггер updated_at
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'tr_firmware_images_updated_at'
  ) THEN
    CREATE TRIGGER tr_firmware_images_updated_at
    BEFORE UPDATE ON firmware_images
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- firmware_channels: каналы релизов (stable/beta/canary и т.п.)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firmware_channels (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL,
  name          text NOT NULL,
  description   text,
  is_protected  boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

COMMENT ON TABLE firmware_channels IS 'Каналы релизов прошивок';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'tr_firmware_channels_updated_at'
  ) THEN
    CREATE TRIGGER tr_firmware_channels_updated_at
    BEFORE UPDATE ON firmware_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END$$;

-- Привязка образов к каналам
CREATE TABLE IF NOT EXISTS firmware_image_channels (
  image_id    uuid NOT NULL,
  channel_id  uuid NOT NULL,
  PRIMARY KEY (image_id, channel_id),
  CONSTRAINT fk_fic_image FOREIGN KEY (image_id) REFERENCES firmware_images(id) ON DELETE CASCADE,
  CONSTRAINT fk_fic_channel FOREIGN KEY (channel_id) REFERENCES firmware_channels(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- device_firmware_state: текущее и целевое состояние прошивки на устройстве
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_firmware_state (
  tenant_id         uuid NOT NULL,
  device_id         uuid NOT NULL,
  current_version   text,
  target_image_id   uuid,
  last_status       ota_device_status_enum NOT NULL DEFAULT 'idle',
  last_error_code   text,
  last_error_msg    text,
  battery_percent   int2,
  free_storage_mb   int4,
  last_check_at     timestamptz,
  last_update_at    timestamptz,
  attributes        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, device_id),
  CONSTRAINT fk_device_target_image FOREIGN KEY (target_image_id) REFERENCES firmware_images(id)
    ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_device_state_target
  ON device_firmware_state (tenant_id, target_image_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'tr_device_firmware_state_updated_at'
  ) THEN
    CREATE TRIGGER tr_device_firmware_state_updated_at
    BEFORE UPDATE ON device_firmware_state
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- ota_campaigns: кампании раскатки OTA
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ota_campaigns (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL,
  name                    text NOT NULL,
  description             text,
  channel_id              uuid,
  image_id                uuid,
  strategy                ota_strategy_enum NOT NULL DEFAULT 'progressive',
  canary_percent          numeric(5,2) NOT NULL DEFAULT 10.00 CHECK (canary_percent >= 0 AND canary_percent <= 100),
  batch_size              int4 NOT NULL DEFAULT 100 CHECK (batch_size > 0),
  rollout_rate_per_minute int4 NOT NULL DEFAULT 200 CHECK (rollout_rate_per_minute > 0),
  require_charging        boolean NOT NULL DEFAULT true,
  require_idle            boolean NOT NULL DEFAULT true,
  min_battery_percent     int2 NOT NULL DEFAULT 50 CHECK (min_battery_percent BETWEEN 0 AND 100),
  min_free_storage_mb     int4 NOT NULL DEFAULT 200 CHECK (min_free_storage_mb >= 0),
  starts_at               timestamptz,
  ends_at                 timestamptz,
  status                  ota_campaign_status_enum NOT NULL DEFAULT 'draft',
  created_by              text,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CHECK (channel_id IS NOT NULL OR image_id IS NOT NULL),
  CHECK (ends_at IS NULL OR starts_at IS NULL OR ends_at > starts_at),
  UNIQUE (tenant_id, name),
  CONSTRAINT fk_campaign_channel FOREIGN KEY (channel_id) REFERENCES firmware_channels(id) ON DELETE SET NULL,
  CONSTRAINT fk_campaign_image   FOREIGN KEY (image_id)   REFERENCES firmware_images(id)   ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_ota_campaigns_tenant_status
  ON ota_campaigns (tenant_id, status, starts_at);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'tr_ota_campaigns_updated_at'
  ) THEN
    CREATE TRIGGER tr_ota_campaigns_updated_at
    BEFORE UPDATE ON ota_campaigns
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- ota_campaign_targets: конкретные устройства в кампании
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ota_campaign_targets (
  tenant_id       uuid NOT NULL,
  campaign_id     uuid NOT NULL,
  device_id       uuid NOT NULL,
  status          ota_device_status_enum NOT NULL DEFAULT 'queued',
  attempt_count   int4 NOT NULL DEFAULT 0,
  last_event_at   timestamptz,
  next_retry_at   timestamptz,
  error_code      text,
  error_msg       text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, campaign_id, device_id),
  CONSTRAINT fk_targets_campaign FOREIGN KEY (campaign_id) REFERENCES ota_campaigns(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_targets_retry
  ON ota_campaign_targets (tenant_id, campaign_id, status, next_retry_at);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'tr_ota_campaign_targets_updated_at'
  ) THEN
    CREATE TRIGGER tr_ota_campaign_targets_updated_at
    BEFORE UPDATE ON ota_campaign_targets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- ota_audit_log: аудит действий OTA (партиционирование по месяцам)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ota_audit_log (
  id            bigserial,
  tenant_id     uuid NOT NULL,
  device_id     uuid,
  image_id      uuid,
  campaign_id   uuid,
  action        ota_event_action_enum NOT NULL,
  status        ota_device_status_enum,
  actor_type    ota_actor_type_enum NOT NULL DEFAULT 'system',
  actor_id      text,
  code          text,
  message       text,
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  details       jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Индексы для партиций создаются на дочерних таблицах при создании
-- Партиция по текущему месяцу
DO $$
DECLARE
  p_start date := date_trunc('month', now())::date;
  p_end   date := (date_trunc('month', now()) + interval '1 month')::date;
  p_name  text := 'ota_audit_log_p_' || to_char(p_start, 'YYYYMM');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = p_name) THEN
    EXECUTE format('CREATE TABLE %I PARTITION OF ota_audit_log FOR VALUES FROM (%L) TO (%L);', p_name, p_start, p_end);
    EXECUTE format('CREATE INDEX %I ON %I (tenant_id, occurred_at);', p_name || '_ix_tenant_time', p_name);
    EXECUTE format('CREATE INDEX %I ON %I (campaign_id, occurred_at);', p_name || '_ix_campaign_time', p_name);
    EXECUTE format('CREATE INDEX %I ON %I (device_id, occurred_at);', p_name || '_ix_device_time', p_name);
  END IF;
END$$;

-- Резервная дефолтная партиция
CREATE TABLE IF NOT EXISTS ota_audit_log_default
  PARTITION OF ota_audit_log DEFAULT;

CREATE INDEX IF NOT EXISTS ota_audit_log_default_ix_tenant_time
  ON ota_audit_log_default (tenant_id, occurred_at);

-- -----------------------------------------------------------------------------
-- VIEW: прогресс кампаний
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_ota_campaign_progress AS
SELECT
  c.id                 AS campaign_id,
  c.tenant_id,
  c.name,
  c.status             AS campaign_status,
  COUNT(t.device_id)   AS total_devices,
  COUNT(*) FILTER (WHERE t.status = 'queued')        AS queued,
  COUNT(*) FILTER (WHERE t.status = 'downloading')   AS downloading,
  COUNT(*) FILTER (WHERE t.status = 'verifying')     AS verifying,
  COUNT(*) FILTER (WHERE t.status = 'installing')    AS installing,
  COUNT(*) FILTER (WHERE t.status = 'rebooting')     AS rebooting,
  COUNT(*) FILTER (WHERE t.status = 'done')          AS done,
  COUNT(*) FILTER (WHERE t.status = 'failed')        AS failed,
  COUNT(*) FILTER (WHERE t.status = 'rolled_back')   AS rolled_back
FROM ota_campaigns c
LEFT JOIN ota_campaign_targets t
  ON t.campaign_id = c.id AND t.tenant_id = c.tenant_id
GROUP BY c.id, c.tenant_id, c.name, c.status;

-- -----------------------------------------------------------------------------
-- RLS (Row-Level Security) по tenant_id
-- Используется параметр сессии: SELECT set_config('app.tenant_id', '<uuid>', true);
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  -- Таблицы с tenant_id
  PERFORM 1;

  -- firmware_images
  EXECUTE $SQL$
    ALTER TABLE firmware_images ENABLE ROW LEVEL SECURITY;
    ALTER TABLE firmware_images FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_firmware_images_tenant'
      AND tablename = 'firmware_images'
  ) THEN
    CREATE POLICY rls_firmware_images_tenant ON firmware_images
      USING ( current_setting('app.tenant_id', true) IS NOT NULL
              AND tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

  -- firmware_channels
  EXECUTE $SQL$
    ALTER TABLE firmware_channels ENABLE ROW LEVEL SECURITY;
    ALTER TABLE firmware_channels FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_firmware_channels_tenant'
      AND tablename = 'firmware_channels'
  ) THEN
    CREATE POLICY rls_firmware_channels_tenant ON firmware_channels
      USING ( current_setting('app.tenant_id', true) IS NOT NULL
              AND tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

  -- firmware_image_channels (через канал)
  EXECUTE $SQL$
    ALTER TABLE firmware_image_channels ENABLE ROW LEVEL SECURITY;
    ALTER TABLE firmware_image_channels FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_firmware_image_channels_tenant'
      AND tablename = 'firmware_image_channels'
  ) THEN
    CREATE POLICY rls_firmware_image_channels_tenant ON firmware_image_channels
      USING (
        EXISTS (SELECT 1 FROM firmware_channels ch
                WHERE ch.id = firmware_image_channels.channel_id
                  AND ch.tenant_id::text = current_setting('app.tenant_id', true))
      );
  END IF;

  -- device_firmware_state
  EXECUTE $SQL$
    ALTER TABLE device_firmware_state ENABLE ROW LEVEL SECURITY;
    ALTER TABLE device_firmware_state FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_device_firmware_state_tenant'
      AND tablename = 'device_firmware_state'
  ) THEN
    CREATE POLICY rls_device_firmware_state_tenant ON device_firmware_state
      USING ( current_setting('app.tenant_id', true) IS NOT NULL
              AND tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

  -- ota_campaigns
  EXECUTE $SQL$
    ALTER TABLE ota_campaigns ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ota_campaigns FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_ota_campaigns_tenant'
      AND tablename = 'ota_campaigns'
  ) THEN
    CREATE POLICY rls_ota_campaigns_tenant ON ota_campaigns
      USING ( current_setting('app.tenant_id', true) IS NOT NULL
              AND tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

  -- ota_campaign_targets
  EXECUTE $SQL$
    ALTER TABLE ota_campaign_targets ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ota_campaign_targets FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_ota_campaign_targets_tenant'
      AND tablename = 'ota_campaign_targets'
  ) THEN
    CREATE POLICY rls_ota_campaign_targets_tenant ON ota_campaign_targets
      USING ( current_setting('app.tenant_id', true) IS NOT NULL
              AND tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

  -- ota_audit_log (по tenant_id)
  EXECUTE $SQL$
    ALTER TABLE ota_audit_log ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ota_audit_log FORCE ROW LEVEL SECURITY;
  $SQL$;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE polname = 'rls_ota_audit_log_tenant'
      AND tablename = 'ota_audit_log'
  ) THEN
    CREATE POLICY rls_ota_audit_log_tenant ON ota_audit_log
      USING ( current_setting('app.tenant_id', true) IS NOT NULL
              AND tenant_id::text = current_setting('app.tenant_id', true) );
  END IF;

END$$;

-- -----------------------------------------------------------------------------
-- Foreign keys VALIDATE (неблокирующая стратегия)
-- -----------------------------------------------------------------------------
-- Нечего валидировать дополнительно: FK создавались уже валидными.

COMMIT;

-- END OF FILE
