-- =============================================================================
-- 0001_assets.sql  |  Cybersecurity Core – Asset Inventory (PostgreSQL 14+)
-- =============================================================================
-- Features:
-- - Multi-tenant isolation via org_id + Row-Level Security (RLS)
-- - HASH partitioning by org_id (8 partitions)
-- - Strong enums for type/status/criticality/sensitivity/environment/exposure
-- - Rich asset model + normalized tables (interfaces/identifiers/software/tags)
-- - Audit log (INSERT/UPDATE/DELETE) with old/new row JSONB snapshots
-- - Updated-at trigger, soft delete, generated columns
-- - Robust indexes: GIN(JSONB), pg_trgm for fast search, partial/unique
-- - Idempotent creation (safe re-run)
-- =============================================================================

BEGIN;

-- Safety/consistency
SET client_min_messages = WARNING;
SET statement_timeout = '60s';
SET lock_timeout = '15s';
SET idle_in_transaction_session_timeout = '30s';

-- Required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive text
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- trigram indexes

-- -----------------------------------------------------------------------------
-- ENUM types (created idempotently)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_type_enum') THEN
    EXECUTE $SQL$
      CREATE TYPE asset_type_enum AS ENUM (
        'endpoint','server','container','vm','mobile','network_device','iot',
        'cloud_account','database','application','user_account','service_account',
        'repo','bucket','k8s_cluster','function','unknown'
      );
    $SQL$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_status_enum') THEN
    EXECUTE $SQL$
      CREATE TYPE asset_status_enum AS ENUM ('active','inactive','retired','quarantined','deleted');
    $SQL$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'criticality_enum') THEN
    EXECUTE $SQL$
      CREATE TYPE criticality_enum AS ENUM ('low','medium','high','critical');
    $SQL$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sensitivity_enum') THEN
    EXECUTE $SQL$
      CREATE TYPE sensitivity_enum AS ENUM ('public','internal','confidential','restricted');
    $SQL$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'environment_enum') THEN
    EXECUTE $SQL$
      CREATE TYPE environment_enum AS ENUM ('prod','staging','dev','test','qa','sandbox');
    $SQL$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'exposure_enum') THEN
    EXECUTE $SQL$
      CREATE TYPE exposure_enum AS ENUM ('internet','internal','isolated','unknown');
    $SQL$;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Helper functions (idempotent creation)
-- -----------------------------------------------------------------------------
-- updated_at auto-maintenance
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at' AND pg_function_is_visible(oid)
  ) THEN
    EXECUTE $SQL$
      CREATE FUNCTION set_updated_at() RETURNS trigger AS $fn$
      BEGIN
        NEW.updated_at := now();
        RETURN NEW;
      END
      $fn$ LANGUAGE plpgsql;
    $SQL$;
  END IF;
END$$;

-- Audit trigger for assets
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc WHERE proname = 'audit_assets' AND pg_function_is_visible(oid)
  ) THEN
    EXECUTE $SQL$
      CREATE FUNCTION audit_assets() RETURNS trigger AS $fn$
      DECLARE
        v_action text := TG_OP;
      BEGIN
        IF v_action = 'INSERT' THEN
          INSERT INTO assets_audit(asset_id, org_id, action, actor, occurred_at, txid, old_row, new_row)
          VALUES (NEW.id, NEW.org_id, 'I', current_user, now(), txid_current(), NULL, to_jsonb(NEW));
          RETURN NEW;
        ELSIF v_action = 'UPDATE' THEN
          INSERT INTO assets_audit(asset_id, org_id, action, actor, occurred_at, txid, old_row, new_row)
          VALUES (NEW.id, NEW.org_id, 'U', current_user, now(), txid_current(), to_jsonb(OLD), to_jsonb(NEW));
          RETURN NEW;
        ELSIF v_action = 'DELETE' THEN
          INSERT INTO assets_audit(asset_id, org_id, action, actor, occurred_at, txid, old_row, new_row)
          VALUES (OLD.id, OLD.org_id, 'D', current_user, now(), txid_current(), to_jsonb(OLD), NULL);
          RETURN OLD;
        END IF;
        RETURN NULL;
      END
      $fn$ LANGUAGE plpgsql;
    $SQL$;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Core table: assets (partitioned by HASH(org_id))
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id              uuid NOT NULL,

  external_id         text,                    -- foreign inventory id
  name                citext NOT NULL,
  fqdn                citext,
  hostname            citext,
  canonical_hostname  citext GENERATED ALWAYS AS (COALESCE(fqdn, hostname, name::citext)) STORED,

  asset_type          asset_type_enum NOT NULL DEFAULT 'unknown',
  status              asset_status_enum NOT NULL DEFAULT 'active',
  criticality         criticality_enum NOT NULL DEFAULT 'medium',
  sensitivity         sensitivity_enum NOT NULL DEFAULT 'internal',
  environment         environment_enum NOT NULL DEFAULT 'prod',
  exposure            exposure_enum NOT NULL DEFAULT 'unknown',

  business_unit       text,
  owner_principal     text,                    -- e.g., user/sa group, IAM principal
  owner_email         text,

  provider            text,                    -- aws|azure|gcp|onprem|...
  platform            text,                    -- windows|linux|macos|ios|android|esxi|...
  os_name             text,
  os_version          text,
  os_family           text,
  kernel_version      text,
  architecture        text,
  manufacturer        text,
  model               text,
  serial_number       text,

  agent_version       text,
  edr_vendor          text,
  edr_status          text,
  is_encrypted        boolean,

  compliance_posture  jsonb,                   -- per-standard posture snapshot
  labels              jsonb NOT NULL DEFAULT '{}'::jsonb, -- structured labels
  attributes          jsonb NOT NULL DEFAULT '{}'::jsonb, -- arbitrary KV
  slsa_provenance     jsonb,                   -- optional SLSA/provenance docs
  attestation         jsonb,                   -- supply-chain attestation refs
  sbom_sha256         text,                    -- SBOM digest (if any)

  risk_score          numeric(5,2) NOT NULL DEFAULT 0
                      CHECK (risk_score >= 0 AND risk_score <= 100),
  risk_level          text GENERATED ALWAYS AS (
                        CASE
                          WHEN risk_score >= 75 THEN 'critical'
                          WHEN risk_score >= 50 THEN 'high'
                          WHEN risk_score >= 25 THEN 'medium'
                          WHEN risk_score > 0  THEN 'low'
                          ELSE 'none'
                        END
                      ) STORED,

  lifecycle           text,                    -- discovered|approved|deployed|...
  discovery_source    text,
  source_event_id     text,

  first_seen          timestamptz NOT NULL DEFAULT now(),
  last_seen           timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz,
  is_deleted          boolean GENERATED ALWAYS AS (deleted_at IS NOT NULL) STORED,

  last_modified_by    text DEFAULT current_user,

  -- Uniqueness within tenant
  CONSTRAINT uq_assets_org_name      UNIQUE (org_id, name),
  CONSTRAINT uq_assets_org_external  UNIQUE (org_id, external_id)
) PARTITION BY HASH (org_id);

-- Also expose (id, org_id) as unique to enable composite FKs from child tables
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM   pg_indexes
    WHERE  schemaname = ANY (current_schemas(true))
    AND    indexname = 'uq_assets_id_org'
  ) THEN
    EXECUTE 'CREATE UNIQUE INDEX uq_assets_id_org ON assets (id, org_id)';
  END IF;
END$$;

-- Create 8 hash partitions
DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS assets_p%s PARTITION OF assets
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

-- Indexes (tenant-scoped, search, JSONB)
CREATE INDEX IF NOT EXISTS idx_assets_org_last_seen   ON assets (org_id, last_seen DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_assets_org_status      ON assets (org_id, status)          WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_assets_org_risk        ON assets (org_id, risk_score DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_assets_labels_gin      ON assets USING GIN (labels);
CREATE INDEX IF NOT EXISTS idx_assets_attributes_gin  ON assets USING GIN (attributes);
CREATE INDEX IF NOT EXISTS idx_assets_comp_posture_gin ON assets USING GIN (compliance_posture);
CREATE INDEX IF NOT EXISTS idx_assets_name_trgm       ON assets USING GIN (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_assets_host_trgm       ON assets USING GIN (canonical_hostname gin_trgm_ops);

-- Triggers on parent apply to partitions
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 't_assets_updated_at'
  ) THEN
    EXECUTE 'CREATE TRIGGER t_assets_updated_at BEFORE UPDATE ON assets
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Audit table + trigger
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets_audit (
  id         bigserial PRIMARY KEY,
  asset_id   uuid NOT NULL,
  org_id     uuid NOT NULL,
  action     char(1) NOT NULL CHECK (action IN ('I','U','D')),
  actor      text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  txid       bigint NOT NULL,
  old_row    jsonb,
  new_row    jsonb
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 't_assets_audit_iud'
  ) THEN
    EXECUTE 'CREATE TRIGGER t_assets_audit_iud
             AFTER INSERT OR UPDATE OR DELETE ON assets
             FOR EACH ROW EXECUTE FUNCTION audit_assets()';
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Child tables (all partitioned by org_id, FK to (id, org_id))
-- -----------------------------------------------------------------------------

-- Network interfaces
CREATE TABLE IF NOT EXISTS asset_network_interfaces (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id        uuid NOT NULL,
  org_id          uuid NOT NULL,
  interface_name  text,
  mac             macaddr,
  ipv4            inet,
  ipv6            inet,
  is_primary      boolean DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_ani_asset FOREIGN KEY (asset_id, org_id)
    REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS asset_network_interfaces_p%s
         PARTITION OF asset_network_interfaces
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

-- Indexes & constraints for interfaces
CREATE INDEX IF NOT EXISTS idx_ani_org_asset     ON asset_network_interfaces (org_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_ani_org_updated   ON asset_network_interfaces (org_id, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ani_org_iface
  ON asset_network_interfaces (org_id, asset_id, interface_name) WHERE interface_name IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ani_org_ipv4
  ON asset_network_interfaces (org_id, ipv4) WHERE ipv4 IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ani_org_ipv6
  ON asset_network_interfaces (org_id, ipv6) WHERE ipv6 IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 't_ani_updated_at'
  ) THEN
    EXECUTE 'CREATE TRIGGER t_ani_updated_at BEFORE UPDATE ON asset_network_interfaces
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- Identifiers (e.g., EC2 instance-id, Azure resource-id, serial_number alt, etc.)
CREATE TABLE IF NOT EXISTS asset_identifiers (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id   uuid NOT NULL,
  org_id     uuid NOT NULL,
  id_type    text NOT NULL,
  id_value   text NOT NULL,
  source     text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_ai_asset FOREIGN KEY (asset_id, org_id)
    REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS asset_identifiers_p%s
         PARTITION OF asset_identifiers
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_org_type_value
  ON asset_identifiers (org_id, id_type, id_value);
CREATE INDEX IF NOT EXISTS idx_ai_org_asset ON asset_identifiers (org_id, asset_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 't_ai_updated_at'
  ) THEN
    EXECUTE 'CREATE TRIGGER t_ai_updated_at BEFORE UPDATE ON asset_identifiers
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- Installed software inventory (lightweight; SBOM linking via sbom_sha256 in assets)
CREATE TABLE IF NOT EXISTS asset_software (
  id           bigserial PRIMARY KEY,
  asset_id     uuid NOT NULL,
  org_id       uuid NOT NULL,
  package_name text NOT NULL,
  version      text,
  vendor       text,
  purl         text,         -- package URL (if available)
  cpe          text,         -- CPE string (if available)
  source       text,         -- scanner/source
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_asw_asset FOREIGN KEY (asset_id, org_id)
    REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS asset_software_p%s
         PARTITION OF asset_software
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_asw_org_asset_name ON asset_software (org_id, asset_id, package_name);
CREATE UNIQUE INDEX IF NOT EXISTS uq_asw_org_asset_pkg_ver_src
  ON asset_software (org_id, asset_id, package_name, COALESCE(version, ''), COALESCE(source, ''));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 't_asw_updated_at'
  ) THEN
    EXECUTE 'CREATE TRIGGER t_asw_updated_at BEFORE UPDATE ON asset_software
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- Tags (denormalized tags in assets.labels; this table supports exact/tag analytics)
CREATE TABLE IF NOT EXISTS asset_tags (
  asset_id   uuid NOT NULL,
  org_id     uuid NOT NULL,
  tag        text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pk_asset_tags PRIMARY KEY (asset_id, org_id, tag),
  CONSTRAINT fk_at_asset FOREIGN KEY (asset_id, org_id)
    REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS asset_tags_p%s
         PARTITION OF asset_tags
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_at_org_tag ON asset_tags (org_id, tag);

-- Risk history (time series)
CREATE TABLE IF NOT EXISTS asset_risk_history (
  id         bigserial PRIMARY KEY,
  asset_id   uuid NOT NULL,
  org_id     uuid NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  risk_score numeric(5,2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  reason     text,
  CONSTRAINT fk_arh_asset FOREIGN KEY (asset_id, org_id)
    REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS asset_risk_history_p%s
         PARTITION OF asset_risk_history
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_arh_org_asset_time ON asset_risk_history (org_id, asset_id, observed_at DESC);

-- -----------------------------------------------------------------------------
-- Row-Level Security (RLS)
-- Policy uses session GUC: SET app.current_org = '<uuid>';
-- If app.current_org is not set, access is denied.
-- -----------------------------------------------------------------------------
ALTER TABLE assets                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_network_interfaces  ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_identifiers         ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_software            ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_tags                ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_risk_history        ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets_audit              ENABLE ROW LEVEL SECURITY;

-- Helper macro to create identical RLS policy on multiple tables
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT unnest(ARRAY[
      'assets',
      'asset_network_interfaces',
      'asset_identifiers',
      'asset_software',
      'asset_tags',
      'asset_risk_history',
      'assets_audit'
    ]) AS tbl
  LOOP
    EXECUTE format($fmt$
      DO $inner$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_policies WHERE schemaname = ANY (current_schemas(true))
          AND tablename = %L AND policyname = 'org_isolation'
        ) THEN
          EXECUTE format(
            'CREATE POLICY org_isolation ON %I
               USING ( current_setting(''app.current_org'', true) IS NOT NULL
                       AND org_id = current_setting(''app.current_org'')::uuid )
              WITH CHECK ( current_setting(''app.current_org'', true) IS NOT NULL
                           AND org_id = current_setting(''app.current_org'')::uuid )',
            %I
          );
        END IF;
      END
      $inner$;
    $fmt$, r.tbl, r.tbl);
  END LOOP;
END$$;

-- Optionally restrict PUBLIC (keep for superusers/automation to adjust)
-- We wrap GRANTs to avoid errors if roles do not exist.
DO $$
BEGIN
  BEGIN
    EXECUTE 'REVOKE ALL ON assets, assets_audit, asset_network_interfaces, asset_identifiers, asset_software, asset_tags, asset_risk_history FROM PUBLIC';
  EXCEPTION WHEN undefined_table THEN NULL;
  END;

  BEGIN
    EXECUTE 'GRANT SELECT ON assets, asset_network_interfaces, asset_identifiers, asset_software, asset_tags, asset_risk_history TO cyber_readonly';
  EXCEPTION WHEN undefined_object THEN NULL;
  END;

  BEGIN
    EXECUTE 'GRANT INSERT, UPDATE, DELETE ON assets, asset_network_interfaces, asset_identifiers, asset_software, asset_tags, asset_risk_history TO cyber_writer';
  EXCEPTION WHEN undefined_object THEN NULL;
  END;
END$$;

COMMIT;

-- =============================================================================
-- Usage notes:
-- 1) For tenant isolation set at session start:
--      SET app.current_org = '<uuid>';
-- 2) Soft delete: UPDATE assets SET deleted_at = now() WHERE id = ...;
-- 3) Search: use GIN/pg_trgm indexes, e.g. WHERE name ILIKE '%term%' OR labels @> '{"key":"value"}'
-- =============================================================================
