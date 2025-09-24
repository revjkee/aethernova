-- file: policy-core/schemas/sql/migrations/0004_bundle_versions.sql
-- Purpose: Industrial-grade bundle versioning for policy-core (PostgreSQL 13+)

BEGIN;

SET client_min_messages = WARNING;
SET statement_timeout = '10min';
SET lock_timeout       = '2min';

-- Extensions used: pgcrypto for gen_random_uuid(), citext for case-insensitive bundle names.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- Dedicated schema (optional; keep public if undesired)
CREATE SCHEMA IF NOT EXISTS policy;
SET search_path = policy, public;

------------------------------------------------------------
-- Utility: actor resolution for audit (session variable or DB user)
------------------------------------------------------------
CREATE OR REPLACE FUNCTION policy._actor()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(current_setting('app.user_id', true), session_user)
$$;

------------------------------------------------------------
-- SemVer parser: validates and returns components
------------------------------------------------------------
CREATE OR REPLACE FUNCTION policy.semver_parse(v text)
RETURNS TABLE(major int, minor int, patch int, prerelease text, build text)
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
  m text[];
BEGIN
  -- Regex: optional v/V prefix, MAJOR.MINOR.PATCH, optional -prerelease, optional +build
  m := regexp_match(v, '^[vV]?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z\.-]+))?(?:\+([0-9A-Za-z\.-]+))?$');
  IF m IS NULL THEN
    RAISE EXCEPTION 'Invalid SemVer string: %', v USING ERRCODE = '22023';
  END IF;
  major := m[1]::int;
  minor := m[2]::int;
  patch := m[3]::int;
  prerelease := NULLIF(m[4], '');
  build := NULLIF(m[5], '');
  RETURN NEXT;
END;
$$;

------------------------------------------------------------
-- Tables: bundles, versions, channels, audit
------------------------------------------------------------

-- Root bundle descriptor
CREATE TABLE IF NOT EXISTS policy.bundle (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           citext NOT NULL UNIQUE,                 -- case-insensitive bundle key
  owner_tenant   text   NOT NULL,
  description    text,
  metadata       jsonb  NOT NULL DEFAULT '{}',
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Touch updated_at
CREATE OR REPLACE FUNCTION policy._touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_bundle_touch ON policy.bundle;
CREATE TRIGGER trg_bundle_touch
BEFORE UPDATE ON policy.bundle
FOR EACH ROW
EXECUTE FUNCTION policy._touch_updated_at();

-- Immutable bundle version entity (OPA bundle artifact)
CREATE TABLE IF NOT EXISTS policy.bundle_version (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id           uuid NOT NULL REFERENCES policy.bundle(id) ON DELETE CASCADE,
  -- Original version string (with optional leading 'v')
  version             text NOT NULL,
  -- Parsed components (set by trigger; not user-writable)
  version_major       int  NOT NULL,
  version_minor       int  NOT NULL,
  version_patch       int  NOT NULL,
  version_prerelease  text,
  version_build       text,
  is_prerelease       boolean GENERATED ALWAYS AS (version_prerelease IS NOT NULL) STORED,

  -- Artifact integrity and location
  checksum_sha256     bytea NOT NULL,                     -- 32 bytes
  size_bytes          bigint NOT NULL CHECK (size_bytes >= 0),
  storage_url         text   NOT NULL CHECK (storage_url ~ '^(https?|s3|gs|oci|file)://'),

  -- Signing / provenance
  signed              boolean NOT NULL DEFAULT false,
  signature_envelope  jsonb,                              -- DSSE, Sigstore bundle, etc.

  -- Lifecycle
  created_by          text NOT NULL DEFAULT policy._actor(),
  created_at          timestamptz NOT NULL DEFAULT now(),
  published_at        timestamptz,                        -- when exposed to clients
  metadata            jsonb NOT NULL DEFAULT '{}',

  -- Uniqueness and basic format checks
  CONSTRAINT uq_bundle_version UNIQUE (bundle_id, version),
  CONSTRAINT chk_version_format CHECK (version ~* '^[vV]?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z\.-]+)?(?:\+[0-9A-Za-z\.-]+)?$'),
  CONSTRAINT chk_sha256_len    CHECK (octet_length(checksum_sha256) = 32),
  CONSTRAINT chk_version_bounds CHECK (version_major >= 0 AND version_minor >= 0 AND version_patch >= 0),
  CONSTRAINT chk_prerelease_len CHECK (version_prerelease IS NULL OR length(version_prerelease) <= 128),
  CONSTRAINT chk_build_len      CHECK (version_build IS NULL OR length(version_build) <= 128)
);

-- BEFORE INS/UPD: parse SemVer and lock immutable fields
CREATE OR REPLACE FUNCTION policy.bundle_version_biu()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  p_major int; p_minor int; p_patch int; p_pre text; p_build text;
BEGIN
  -- Parse & populate on INSERT/UPDATE when version changes
  IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND NEW.version IS DISTINCT FROM OLD.version) THEN
    SELECT major, minor, patch, prerelease, build
      INTO p_major, p_minor, p_patch, p_pre, p_build
    FROM policy.semver_parse(NEW.version);

    NEW.version_major      := p_major;
    NEW.version_minor      := p_minor;
    NEW.version_patch      := p_patch;
    NEW.version_prerelease := p_pre;
    NEW.version_build      := p_build;
  END IF;

  -- Enforce immutability: content fields cannot be altered after creation
  IF TG_OP = 'UPDATE' THEN
    IF NEW.bundle_id          IS DISTINCT FROM OLD.bundle_id
       OR NEW.version         IS DISTINCT FROM OLD.version
       OR NEW.checksum_sha256 IS DISTINCT FROM OLD.checksum_sha256
       OR NEW.size_bytes      IS DISTINCT FROM OLD.size_bytes
       OR NEW.storage_url     IS DISTINCT FROM OLD.storage_url
       OR NEW.signed          IS DISTINCT FROM OLD.signed
       OR NEW.signature_envelope IS DISTINCT FROM OLD.signature_envelope THEN
      RAISE EXCEPTION 'bundle_version is immutable after creation (content fields cannot change)';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_bundle_version_biu ON policy.bundle_version;
CREATE TRIGGER trg_bundle_version_biu
BEFORE INSERT OR UPDATE ON policy.bundle_version
FOR EACH ROW
EXECUTE FUNCTION policy.bundle_version_biu();

-- Soft audit log for versions (insert/update/delete)
CREATE TABLE IF NOT EXISTS policy.bundle_version_audit (
  id            bigserial PRIMARY KEY,
  version_id    uuid,
  action        text NOT NULL CHECK (action IN ('INSERT','UPDATE','DELETE')),
  at            timestamptz NOT NULL DEFAULT now(),
  actor         text NOT NULL DEFAULT policy._actor(),
  old_row       jsonb,
  new_row       jsonb
);

CREATE OR REPLACE FUNCTION policy.bundle_version_audit_trg()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO policy.bundle_version_audit(version_id, action, new_row)
    VALUES (NEW.id, 'INSERT', to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO policy.bundle_version_audit(version_id, action, old_row, new_row)
    VALUES (NEW.id, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO policy.bundle_version_audit(version_id, action, old_row)
    VALUES (OLD.id, 'DELETE', to_jsonb(OLD));
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_bundle_version_audit ON policy.bundle_version;
CREATE TRIGGER trg_bundle_version_audit
AFTER INSERT OR UPDATE OR DELETE ON policy.bundle_version
FOR EACH ROW
EXECUTE FUNCTION policy.bundle_version_audit_trg();

-- Deduplication helper: avoid identical artifacts within one bundle
CREATE UNIQUE INDEX IF NOT EXISTS ux_bundle_version_sha
ON policy.bundle_version (bundle_id, checksum_sha256);

-- Fast selection for "latest" (composite index to support ORDER BY below)
CREATE INDEX IF NOT EXISTS ix_bundle_version_sort
ON policy.bundle_version (
  bundle_id,
  version_major DESC,
  version_minor DESC,
  version_patch DESC,
  is_prerelease ASC,
  created_at DESC
);

-- Optional: partial index for published versions only
CREATE INDEX IF NOT EXISTS ix_bundle_version_published
ON policy.bundle_version (bundle_id, published_at DESC)
WHERE published_at IS NOT NULL;

-- Release channels (stable/canary/dev or arbitrary)
CREATE TABLE IF NOT EXISTS policy.bundle_channel (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id          uuid NOT NULL REFERENCES policy.bundle(id) ON DELETE CASCADE,
  name               text NOT NULL,                          -- e.g., 'stable', 'canary', 'dev'
  pinned_version_id  uuid,                                   -- optional explicit pin
  rollout_percent    int  NOT NULL DEFAULT 100 CHECK (rollout_percent BETWEEN 0 AND 100),
  metadata           jsonb NOT NULL DEFAULT '{}',
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_bundle_channel UNIQUE (bundle_id, name)
);

-- Ensure pinned_version belongs to the same bundle
CREATE OR REPLACE FUNCTION policy.bundle_channel_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_count int;
BEGIN
  IF NEW.pinned_version_id IS NOT NULL THEN
    SELECT count(*) INTO v_count
    FROM policy.bundle_version v
    WHERE v.id = NEW.pinned_version_id
      AND v.bundle_id = NEW.bundle_id;
    IF v_count = 0 THEN
      RAISE EXCEPTION 'Pinned version % does not belong to bundle %', NEW.pinned_version_id, NEW.bundle_id;
    END IF;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_bundle_channel_guard ON policy.bundle_channel;
CREATE TRIGGER trg_bundle_channel_guard
BEFORE INSERT OR UPDATE ON policy.bundle_channel
FOR EACH ROW
EXECUTE FUNCTION policy.bundle_channel_guard();

------------------------------------------------------------
-- Views: latest stable per bundle; effective per channel
------------------------------------------------------------

-- Latest (prefer non-prerelease; fallback to highest prerelease if no stable exists)
CREATE OR REPLACE VIEW policy.v_bundle_version_latest AS
WITH ranked AS (
  SELECT
    v.*,
    ROW_NUMBER() OVER (
      PARTITION BY v.bundle_id
      ORDER BY
        v.version_major DESC,
        v.version_minor DESC,
        v.version_patch DESC,
        v.is_prerelease ASC,         -- stable first
        COALESCE(v.version_prerelease, '') DESC,
        v.created_at DESC
    ) AS rn
  FROM policy.bundle_version v
  WHERE v.published_at IS NOT NULL
)
SELECT * FROM ranked WHERE rn = 1;

-- Effective version per channel:
-- if pinned_version_id is set -> use it; else fallback to latest stable for the bundle
CREATE OR REPLACE VIEW policy.v_bundle_channel_effective AS
SELECT
  c.id               AS channel_id,
  c.bundle_id,
  c.name             AS channel,
  COALESCE(c.pinned_version_id, ls.id) AS version_id,
  COALESCE(c.pinned_version_id, ls.id) IS DISTINCT FROM c.pinned_version_id AS is_fallback,
  c.rollout_percent,
  c.metadata,
  c.updated_at
FROM policy.bundle_channel c
LEFT JOIN policy.v_bundle_version_latest ls
  ON ls.bundle_id = c.bundle_id;

------------------------------------------------------------
-- Helper: secure default channels for existing bundles
------------------------------------------------------------
-- Seed default channels for all bundles (idempotent)
INSERT INTO policy.bundle_channel (bundle_id, name, pinned_version_id, rollout_percent)
SELECT b.id, x.name, NULL, 100
FROM policy.bundle b
CROSS JOIN (VALUES ('stable'), ('canary'), ('dev')) AS x(name)
ON CONFLICT (bundle_id, name) DO NOTHING;

COMMIT;
