-- File: zero-trust-core/schemas/sql/migrations/0001_init.sql
-- Purpose: Initial schema for Zero Trust session store (PostgreSQL 13+)
-- Notes:
-- - All token values are stored only as SHA-256 hashes (hex). Raw tokens MUST NOT be persisted.
-- - Enable RLS by tenant; set: SELECT set_config('app.tenant_id','<tenant>', true);

BEGIN;

-- Safety: tune locks to avoid long blocking during deploys (adjust in your tooling)
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Extensions used (optional but recommended)
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS btree_gin;    -- GIN for btree operators on JSONB (improves mixed workloads)
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- optional, for LIKE/ILIKE on UA, model, etc.

-- Dedicated schema
CREATE SCHEMA IF NOT EXISTS zt_core AUTHORIZATION CURRENT_USER;

-- =========================
-- Enumerations
-- =========================
CREATE TYPE zt_core.session_state AS ENUM (
  'active',
  'pending_step_up',
  'revoked',
  'expired',
  'locked'
);

CREATE TYPE zt_core.risk_action AS ENUM (
  'allow',
  'step_up',
  'deny'
);

CREATE TYPE zt_core.binding_type AS ENUM (
  'none',
  'dpop_jkt',
  'mtls_x5t_s256',
  'jwk_thumbprint'
);

CREATE TYPE zt_core.revocation_reason AS ENUM (
  'user_logout',
  'admin_force',
  'risk_deny',
  'token_replay',
  'key_rollover'
);

-- =========================
-- Utility functions and triggers
-- =========================

-- updated_at trigger
CREATE OR REPLACE FUNCTION zt_core.tg_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END
$$;

-- simple IPv4/IPv6 masking to /24 or /64 for public view analytics
CREATE OR REPLACE FUNCTION zt_core.mask_inet(ip inet)
RETURNS inet
LANGUAGE SQL
AS $$
  SELECT
    CASE
      WHEN family($1) = 4 THEN set_masklen($1, 24)
      WHEN family($1) = 6 THEN set_masklen($1, 64)
      ELSE NULL
    END
$$;

-- helper to coalesce app.tenant_id for RLS (empty string if not set)
CREATE OR REPLACE FUNCTION zt_core.current_tenant()
RETURNS text
LANGUAGE SQL
AS $$ SELECT COALESCE(current_setting('app.tenant_id', true), '') $$;

-- =========================
-- Core tables
-- =========================

-- Sessions
CREATE TABLE IF NOT EXISTS zt_core.sessions (
  session_id           text PRIMARY KEY,                         -- ksuid/uuidv7 as opaque text
  tenant_id            text NOT NULL,
  subject_id           text NOT NULL,
  state                zt_core.session_state NOT NULL DEFAULT 'active',

  created_at           timestamptz NOT NULL DEFAULT NOW(),
  updated_at           timestamptz NOT NULL DEFAULT NOW(),
  expires_at           timestamptz NOT NULL,
  idle_expires_at      timestamptz NOT NULL,

  -- Risk
  risk_score           int2 NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  risk_action          zt_core.risk_action NOT NULL DEFAULT 'allow',

  -- Key binding (cnf)
  binding_type         zt_core.binding_type NOT NULL DEFAULT 'none',
  binding_value        text NOT NULL DEFAULT '',                 -- base64url jkt / x5t#S256 / jwk thumbprint
  binding_required     boolean NOT NULL DEFAULT false,

  -- Counters
  cnt_logins           bigint NOT NULL DEFAULT 0,
  cnt_refreshes        bigint NOT NULL DEFAULT 0,
  cnt_stepups          bigint NOT NULL DEFAULT 0,

  -- Step-up requirement (if any)
  step_up_required     boolean NOT NULL DEFAULT false,
  step_up_methods      text[] NOT NULL DEFAULT '{}',
  step_up_until        timestamptz,

  -- Network context (last touch)
  ip                   inet,
  country_iso          char(2),
  asn                  integer,
  via_corp_vpn         boolean,

  -- Client context (last touch)
  user_agent           text,
  client_version       text,
  client_platform      text,
  app_attested         boolean,

  -- Low-cardinality labels/attributes for search
  labels               jsonb NOT NULL DEFAULT '{}'::jsonb,       -- tenant-scoped labels, object only
  attributes           jsonb NOT NULL DEFAULT '{}'::jsonb,       -- extra metadata, object only

  -- Device posture snapshot (normalized minimal and raw blob)
  device_platform      text,                                     -- windows|macos|linux|ios|android
  device_model         text,
  device_os_name       text,
  device_os_version    text,
  device_os_build      text,
  device_posture       jsonb NOT NULL DEFAULT '{}'::jsonb,

  -- Duplicates for common lookups
  aud_default          text,                                     -- optional default audience
  iss                  text,

  -- Constraints
  CHECK (char_length(session_id) BETWEEN 8 AND 128),
  CHECK (jsonb_typeof(labels) = 'object'),
  CHECK (jsonb_typeof(attributes) = 'object'),
  CHECK (jsonb_typeof(device_posture) = 'object'),
  CHECK (country_iso IS NULL OR country_iso ~ '^[A-Z]{2}$')
);

COMMENT ON TABLE zt_core.sessions IS 'Zero Trust sessions. Raw tokens are never stored.';
COMMENT ON COLUMN zt_core.sessions.binding_value IS 'Base64url JKT / x5t#S256 / JWK thumbprint (no PII)';

CREATE INDEX IF NOT EXISTS sessions_tenant_subject_idx
  ON zt_core.sessions (tenant_id, subject_id);

CREATE INDEX IF NOT EXISTS sessions_state_idx
  ON zt_core.sessions (state);

-- Only live or pending sessions queried by expiry
CREATE INDEX IF NOT EXISTS sessions_exp_live_idx
  ON zt_core.sessions (expires_at)
  WHERE state IN ('active','pending_step_up');

-- Idle expiry hot path
CREATE INDEX IF NOT EXISTS sessions_idle_exp_live_idx
  ON zt_core.sessions (idle_expires_at)
  WHERE state IN ('active','pending_step_up');

-- Search by labels/attributes (GIN). Prefer jsonb_path_ops if your PG version and queries fit.
CREATE INDEX IF NOT EXISTS sessions_labels_gin
  ON zt_core.sessions
  USING GIN (labels);

CREATE INDEX IF NOT EXISTS sessions_attributes_gin
  ON zt_core.sessions
  USING GIN (attributes);

-- User agent searches (optional)
CREATE INDEX IF NOT EXISTS sessions_user_agent_trgm
  ON zt_core.sessions
  USING GIN (user_agent gin_trgm_ops);

-- Update timestamp trigger
DROP TRIGGER IF EXISTS trg_sessions_updated_at ON zt_core.sessions;
CREATE TRIGGER trg_sessions_updated_at
BEFORE UPDATE ON zt_core.sessions
FOR EACH ROW EXECUTE FUNCTION zt_core.tg_set_updated_at();

-- Access tokens (metadata only)
CREATE TABLE IF NOT EXISTS zt_core.access_tokens (
  token_id             text PRIMARY KEY,                         -- opaque id/handle
  session_id           text NOT NULL REFERENCES zt_core.sessions(session_id) ON DELETE CASCADE,
  tenant_id            text NOT NULL,                            -- denormalized for fast RLS filtering
  subject_id           text NOT NULL,

  sha256_hex           text NOT NULL,                            -- lower hex SHA-256 of raw token
  stateless            boolean NOT NULL DEFAULT true,
  dpop                 boolean NOT NULL DEFAULT false,

  issuer               text,
  audience             text,
  kid                  text,
  scope                text[] NOT NULL DEFAULT '{}',

  issued_at            timestamptz NOT NULL,
  not_before           timestamptz,
  expires_at           timestamptz NOT NULL,

  binding_type         zt_core.binding_type NOT NULL DEFAULT 'none',
  binding_value        text NOT NULL DEFAULT '',
  binding_required     boolean NOT NULL DEFAULT false,

  labels               jsonb NOT NULL DEFAULT '{}'::jsonb,

  created_at           timestamptz NOT NULL DEFAULT NOW(),
  updated_at           timestamptz NOT NULL DEFAULT NOW(),

  CHECK (char_length(token_id) BETWEEN 8 AND 128),
  CHECK (sha256_hex ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(labels) = 'object')
);

COMMENT ON TABLE zt_core.access_tokens IS 'Access token metadata (hashes only).';

CREATE UNIQUE INDEX IF NOT EXISTS access_tokens_sha256_uniq
  ON zt_core.access_tokens (sha256_hex);

CREATE INDEX IF NOT EXISTS access_tokens_exp_idx
  ON zt_core.access_tokens (expires_at);

CREATE INDEX IF NOT EXISTS access_tokens_tenant_subject_idx
  ON zt_core.access_tokens (tenant_id, subject_id);

DROP TRIGGER IF EXISTS trg_access_tokens_updated_at ON zt_core.access_tokens;
CREATE TRIGGER trg_access_tokens_updated_at
BEFORE UPDATE ON zt_core.access_tokens
FOR EACH ROW EXECUTE FUNCTION zt_core.tg_set_updated_at();

-- Refresh tokens (rotation chains, no raw values)
CREATE TABLE IF NOT EXISTS zt_core.refresh_tokens (
  token_id             text PRIMARY KEY,
  session_id           text NOT NULL REFERENCES zt_core.sessions(session_id) ON DELETE CASCADE,
  tenant_id            text NOT NULL,
  subject_id           text NOT NULL,

  sha256_hex           text NOT NULL,                            -- lower hex SHA-256 of raw token
  one_time             boolean NOT NULL DEFAULT true,
  rotation_counter     integer NOT NULL DEFAULT 0 CHECK (rotation_counter >= 0),
  parent_id            text REFERENCES zt_core.refresh_tokens(token_id) ON DELETE SET NULL,

  issued_at            timestamptz NOT NULL,
  expires_at           timestamptz NOT NULL,
  revoked              boolean NOT NULL DEFAULT false,

  labels               jsonb NOT NULL DEFAULT '{}'::jsonb,

  created_at           timestamptz NOT NULL DEFAULT NOW(),
  updated_at           timestamptz NOT NULL DEFAULT NOW(),

  CHECK (char_length(token_id) BETWEEN 8 AND 128),
  CHECK (sha256_hex ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(labels) = 'object')
);

COMMENT ON TABLE zt_core.refresh_tokens IS 'Refresh token metadata (hashes only), with rotation chain.';

-- Prevent duplicates across all tenants/sessions
CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_sha256_uniq
  ON zt_core.refresh_tokens (sha256_hex);

CREATE INDEX IF NOT EXISTS refresh_tokens_exp_idx
  ON zt_core.refresh_tokens (expires_at);

-- Hot path: non-revoked and not expired
CREATE INDEX IF NOT EXISTS refresh_tokens_active_idx
  ON zt_core.refresh_tokens (tenant_id, subject_id, expires_at)
  WHERE revoked = false;

DROP TRIGGER IF EXISTS trg_refresh_tokens_updated_at ON zt_core.refresh_tokens;
CREATE TRIGGER trg_refresh_tokens_updated_at
BEFORE UPDATE ON zt_core.refresh_tokens
FOR EACH ROW EXECUTE FUNCTION zt_core.tg_set_updated_at();

-- =========================
-- Revocation events (partitioned by month)
-- =========================

CREATE TABLE IF NOT EXISTS zt_core.revocations (
  id                   bigserial,
  session_id           text NOT NULL REFERENCES zt_core.sessions(session_id) ON DELETE CASCADE,
  tenant_id            text NOT NULL,
  reason               zt_core.revocation_reason NOT NULL,
  initiated_by         text NOT NULL,                            -- system/admin/user
  labels               jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at           timestamptz NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id, created_at)                                   -- composite for partitioning
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE zt_core.revocations IS 'Revocation event stream, time-partitioned monthly.';

-- Create current month partition (example). Your migrator can create partitions ahead-of-time.
DO $$
DECLARE
  start_ts timestamptz := date_trunc('month', NOW());
  end_ts   timestamptz := (start_ts + INTERVAL '1 month');
  part_name text := format('revocations_%s', to_char(start_ts, 'YYYYMM'));
  sql text;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'zt_core' AND c.relname = part_name
  ) THEN
    sql := format($f$
      CREATE TABLE zt_core.%I PARTITION OF zt_core.revocations
      FOR VALUES FROM (%L) TO (%L);
    $f$, part_name, start_ts, end_ts);
    EXECUTE sql;
    EXECUTE format('CREATE INDEX %I_tenant_created_idx ON zt_core.%I (tenant_id, created_at DESC);', part_name, part_name);
    EXECUTE format('CREATE INDEX %I_session_idx ON zt_core.%I (session_id, created_at DESC);', part_name, part_name);
  END IF;
END$$;

-- =========================
-- Row Level Security (RLS)
-- =========================

ALTER TABLE zt_core.sessions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE zt_core.access_tokens  ENABLE ROW LEVEL SECURITY;
ALTER TABLE zt_core.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE zt_core.revocations    ENABLE ROW LEVEL SECURITY;

-- Policies: tenant isolation by app.tenant_id (empty means deny)
CREATE POLICY sessions_tenant_rls ON zt_core.sessions
  USING (tenant_id = zt_core.current_tenant());

CREATE POLICY access_tokens_tenant_rls ON zt_core.access_tokens
  USING (tenant_id = zt_core.current_tenant());

CREATE POLICY refresh_tokens_tenant_rls ON zt_core.refresh_tokens
  USING (tenant_id = zt_core.current_tenant());

CREATE POLICY revocations_tenant_rls ON zt_core.revocations
  USING (tenant_id = zt_core.current_tenant());

-- Optionally restrict INSERT/UPDATE to same tenant (defense in depth)
CREATE POLICY sessions_tenant_w ON zt_core.sessions
  FOR INSERT WITH CHECK (tenant_id = zt_core.current_tenant());
CREATE POLICY access_tokens_tenant_w ON zt_core.access_tokens
  FOR INSERT WITH CHECK (tenant_id = zt_core.current_tenant());
CREATE POLICY refresh_tokens_tenant_w ON zt_core.refresh_tokens
  FOR INSERT WITH CHECK (tenant_id = zt_core.current_tenant());
CREATE POLICY revocations_tenant_w ON zt_core.revocations
  FOR INSERT WITH CHECK (tenant_id = zt_core.current_tenant());

-- =========================
-- Public analytical view (PII-minimized)
-- =========================

CREATE OR REPLACE VIEW zt_core.sessions_public AS
SELECT
  s.session_id,
  s.tenant_id,
  s.subject_id,
  s.state,
  s.created_at,
  s.updated_at,
  s.expires_at,
  s.idle_expires_at,
  s.risk_score,
  s.risk_action,
  s.binding_type,
  (s.binding_value <> '') AS binding_present,
  s.cnt_logins,
  s.cnt_refreshes,
  s.cnt_stepups,
  s.step_up_required,
  s.step_up_methods,
  s.step_up_until,
  zt_core.mask_inet(s.ip) AS ip_masked,
  s.country_iso,
  s.asn,
  s.via_corp_vpn,
  NULL::text AS user_agent,            -- UA excluded from public view
  s.client_version,
  s.client_platform,
  s.app_attested,
  s.labels,
  s.attributes,
  s.device_platform,
  s.device_model,
  s.device_os_name,
  s.device_os_version,
  s.device_os_build
FROM zt_core.sessions s;

COMMENT ON VIEW zt_core.sessions_public IS 'Public, PII-minimized projection of sessions.';

-- =========================
-- Helpful upsert/touch procedures (optional)
-- =========================

-- Touch: extend idle expiry for active sessions only (idempotent)
CREATE OR REPLACE FUNCTION zt_core.touch_session(
  p_session_id text,
  p_new_idle_expires_at timestamptz,
  p_ip inet DEFAULT NULL,
  p_country_iso char(2) DEFAULT NULL,
  p_asn integer DEFAULT NULL,
  p_via_corp_vpn boolean DEFAULT NULL,
  p_user_agent text DEFAULT NULL,
  p_client_version text DEFAULT NULL,
  p_client_platform text DEFAULT NULL,
  p_app_attested boolean DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE zt_core.sessions s
     SET idle_expires_at = GREATEST(s.idle_expires_at, p_new_idle_expires_at),
         ip = COALESCE(p_ip, s.ip),
         country_iso = COALESCE(p_country_iso, s.country_iso),
         asn = COALESCE(p_asn, s.asn),
         via_corp_vpn = COALESCE(p_via_corp_vpn, s.via_corp_vpn),
         user_agent = COALESCE(p_user_agent, s.user_agent),
         client_version = COALESCE(p_client_version, s.client_version),
         client_platform = COALESCE(p_client_platform, s.client_platform),
         app_attested = COALESCE(p_app_attested, s.app_attested)
   WHERE s.session_id = p_session_id
     AND s.state IN ('active','pending_step_up');
  RETURN FOUND;
END
$$;

-- Revoke session: set state and append event
CREATE OR REPLACE FUNCTION zt_core.revoke_session(
  p_session_id text,
  p_reason zt_core.revocation_reason,
  p_initiated_by text,
  p_labels jsonb DEFAULT '{}'::jsonb
) RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  v_tenant text;
BEGIN
  SELECT tenant_id INTO v_tenant FROM zt_core.sessions WHERE session_id = p_session_id;
  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;

  UPDATE zt_core.sessions
     SET state = 'revoked'
   WHERE session_id = p_session_id
     AND state <> 'revoked';

  INSERT INTO zt_core.revocations (session_id, tenant_id, reason, initiated_by, labels)
  VALUES (p_session_id, v_tenant, p_reason, p_initiated_by, COALESCE(p_labels, '{}'::jsonb));

  RETURN TRUE;
END
$$;

-- =========================
-- Privileges (adjust to your roles model; example grants only)
-- =========================
-- REVOKE ALL ON SCHEMA zt_core FROM PUBLIC;
-- GRANT USAGE ON SCHEMA zt_core TO app_role;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA zt_core TO app_role;
-- GRANT SELECT ON zt_core.sessions_public TO analytics_role;

COMMIT;
