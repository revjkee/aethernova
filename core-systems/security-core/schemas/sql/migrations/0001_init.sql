-- security-core/schemas/sql/migrations/0001_init.sql
-- Copyright (c) Aethernova.
-- SPDX-License-Identifier: Apache-2.0
-- PostgreSQL 13+ recommended

BEGIN;

-- 0) Schema & extensions
CREATE SCHEMA IF NOT EXISTS security;
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid(), gen_random_bytes(), digest()

-- 1) Enum types
CREATE TYPE security.environment AS ENUM ('PROD','STAGING','DEV','TEST');
CREATE TYPE security.data_classification AS ENUM ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED');
CREATE TYPE security.secret_type AS ENUM (
  'GENERIC','API_KEY','PASSWORD','TOKEN','JWT','SESSION_COOKIE','DB_CREDENTIALS',
  'SERVICE_ACCOUNT','PRIVATE_KEY','CERTIFICATE_PEM','TLS_BUNDLE','SSH_KEY',
  'OAUTH_REFRESH','OPAQUE_BLOB','KMS_REFERENCE','VAULT_REFERENCE'
);
CREATE TYPE security.lifecycle_state AS ENUM (
  'ACTIVE','DISABLED','EXPIRED','COMPROMISED','PENDING_ROTATION','SCHEDULED_DELETE','DESTROYED'
);
CREATE TYPE security.version_state AS ENUM ('ENABLED','DISABLED','DESTROYED','PENDING','EXPIRED');
CREATE TYPE security.rotation_strategy AS ENUM (
  'RANDOM_ALPHANUM','UUID4','HEX','DICEWARE','ASYM_ED25519','ASYM_RSA2048','ASYM_RSA4096',
  'TLS_RSA','TLS_ECDSA','OAUTH_TOKEN'
);
CREATE TYPE security.remote_secret_provider AS ENUM ('AWS_SECRETS_MANAGER','GCP_SECRET_MANAGER','AZURE_KEY_VAULT','HASHICORP_VAULT','ONEPASSWORD','CYBERARK');
CREATE TYPE security.kms_provider AS ENUM ('AWS','GCP','AZURE','VAULT_TRANSIT','LOCAL_HSM','NITRO_ENCLAVE');
CREATE TYPE security.principal_type AS ENUM ('USER','SERVICE','GROUP','ROLE');
CREATE TYPE security.source_type AS ENUM ('ENCRYPTED','REMOTE');

-- 2) Helpers: request context & permissions

-- Store request-scoped subject/tenant/project in GUCs (session-local).
CREATE OR REPLACE FUNCTION security.set_request_context(p_subject_id text, p_tenant_id text, p_project_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  PERFORM set_config('app.subject_id', COALESCE(p_subject_id,''), true);
  PERFORM set_config('app.tenant_id',  COALESCE(p_tenant_id,''),  true);
  PERFORM set_config('app.project_id', COALESCE(p_project_id,''), true);
END$$;

CREATE OR REPLACE FUNCTION security.current_subject_id()
RETURNS text LANGUAGE sql AS $$ SELECT current_setting('app.subject_id', true) $$;

CREATE OR REPLACE FUNCTION security.current_tenant_id()
RETURNS text LANGUAGE sql AS $$ SELECT current_setting('app.tenant_id', true) $$;

CREATE OR REPLACE FUNCTION security.current_project_id()
RETURNS text LANGUAGE sql AS $$ SELECT current_setting('app.project_id', true) $$;

-- 3) Principals directory (optional cache of identities)
CREATE TABLE IF NOT EXISTS security.principals (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_ext_id   text NOT NULL UNIQUE,     -- внешняя идентичность (subject)
  type               security.principal_type NOT NULL,
  display_name       text,
  create_time        timestamptz NOT NULL DEFAULT now(),
  update_time        timestamptz NOT NULL DEFAULT now()
);

-- 4) Secrets
CREATE TABLE IF NOT EXISTS security.secrets (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id            text NOT NULL,                       -- URL-safe slug
  project_id           text NOT NULL,
  tenant_id            text NOT NULL,
  environment          security.environment NOT NULL,
  type                 security.secret_type NOT NULL,
  classification       security.data_classification NOT NULL DEFAULT 'CONFIDENTIAL',
  labels               jsonb NOT NULL DEFAULT '{}'::jsonb,
  annotations          jsonb NOT NULL DEFAULT '{}'::jsonb,

  -- Replication (normalized in child table + summary JSONB optional)
  replication_meta     jsonb NOT NULL DEFAULT '{}'::jsonb,

  -- Rotation policy (flattened for efficient querying)
  rotation_auto_rotate boolean NOT NULL DEFAULT false,
  rotation_interval    interval,
  rotation_cron        text,
  rotation_last_time   timestamptz,
  rotation_next_time   timestamptz,
  rotation_strategy    security.rotation_strategy,
  rotation_window      interval,
  expire_time          timestamptz,

  lifecycle            security.lifecycle_state NOT NULL DEFAULT 'ACTIVE',
  compliance_tags      text[] NOT NULL DEFAULT ARRAY[]::text[],

  current_version_uuid uuid, -- FK set after versions table creation

  create_time          timestamptz NOT NULL DEFAULT now(),
  update_time          timestamptz NOT NULL DEFAULT now(),
  created_by_ext       text,
  updated_by_ext       text,
  etag                 bytea NOT NULL DEFAULT gen_random_bytes(16),

  checksum_sha256      bytea,
  checksum_crc32c      int4,

  resource_name        text GENERATED ALWAYS AS (
    'projects/'||project_id||'/tenants/'||tenant_id||'/secrets/'||secret_id
  ) STORED,

  CONSTRAINT uq_secret_scope UNIQUE (project_id, tenant_id, secret_id),
  CONSTRAINT chk_rotation_schedule CHECK (
    (rotation_interval IS NULL OR rotation_cron IS NULL)
  )
);

-- Replication regions
CREATE TABLE IF NOT EXISTS security.secret_replication_regions (
  id          bigserial PRIMARY KEY,
  secret_uuid uuid NOT NULL REFERENCES security.secrets(id) ON DELETE CASCADE,
  location    text NOT NULL,     -- e.g. eu-west-1
  is_primary  boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS ix_replication_regions_secret ON security.secret_replication_regions(secret_uuid);

-- 5) IAM Policy model
CREATE TABLE IF NOT EXISTS security.access_policies (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_uuid  uuid NOT NULL REFERENCES security.secrets(id) ON DELETE CASCADE,
  etag         bytea NOT NULL DEFAULT gen_random_bytes(16),
  create_time  timestamptz NOT NULL DEFAULT now(),
  update_time  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_policies_secret ON security.access_policies(secret_uuid);

CREATE TABLE IF NOT EXISTS security.bindings (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_uuid  uuid NOT NULL REFERENCES security.access_policies(id) ON DELETE CASCADE,
  role         text NOT NULL,         -- e.g. roles/secret.admin, roles/secret.reader
  condition_cel text,                 -- условие в CEL (валидируется на приложении)
  CONSTRAINT chk_role_not_empty CHECK (length(role) > 0)
);
CREATE INDEX IF NOT EXISTS ix_bindings_policy ON security.bindings(policy_uuid);

CREATE TABLE IF NOT EXISTS security.binding_principals (
  binding_uuid     uuid NOT NULL REFERENCES security.bindings(id) ON DELETE CASCADE,
  principal_ext_id text NOT NULL,
  PRIMARY KEY (binding_uuid, principal_ext_id)
);

-- 6) Secret versions (partitioned)
CREATE SEQUENCE IF NOT EXISTS security.secret_version_seq;

CREATE TABLE IF NOT EXISTS security.secret_versions (
  version_uuid      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_uuid       uuid NOT NULL REFERENCES security.secrets(id) ON DELETE CASCADE,
  version_num       bigint NOT NULL DEFAULT nextval('security.secret_version_seq'),
  state             security.version_state NOT NULL DEFAULT 'ENABLED',

  source            security.source_type NOT NULL,

  -- Encrypted payload (for source = ENCRYPTED)
  ciphertext        bytea,
  algorithm         text,
  key_id            text,
  iv                bytea,
  tag               bytea,
  aad               bytea,
  kms_provider      security.kms_provider,
  kms_resource      text,     -- ARN/resource/path
  kms_location      text,

  -- Remote reference (for source = REMOTE)
  remote_provider   security.remote_secret_provider,
  remote_uri        text,
  remote_version    text,
  remote_region     text,
  remote_params     jsonb,

  create_time       timestamptz NOT NULL DEFAULT now(),
  disable_time      timestamptz,
  destroy_time      timestamptz,
  expire_time       timestamptz,

  checksum_sha256   bytea,
  checksum_crc32c   int4,
  created_by_ext    text,
  etag              bytea NOT NULL DEFAULT gen_random_bytes(16),

  CONSTRAINT uq_secret_version UNIQUE (secret_uuid, version_num),
  CONSTRAINT chk_encrypted_fields CHECK (
    (source <> 'ENCRYPTED') OR
    (ciphertext IS NOT NULL AND algorithm IS NOT NULL AND tag IS NOT NULL)
  ),
  CONSTRAINT chk_remote_fields CHECK (
    (source <> 'REMOTE') OR
    (remote_provider IS NOT NULL AND remote_uri IS NOT NULL)
  )
) PARTITION BY RANGE (create_time);

-- Default partition to avoid immediate DDL churn
CREATE TABLE IF NOT EXISTS security.secret_versions_default
  PARTITION OF security.secret_versions
  FOR VALUES FROM ('2000-01-01') TO ('2100-01-01');

-- FK from secrets.current_version_uuid to secret_versions.version_uuid (after table exists)
ALTER TABLE security.secrets
  ADD CONSTRAINT fk_secrets_current_version
  FOREIGN KEY (current_version_uuid)
  REFERENCES security.secret_versions(version_uuid)
  DEFERRABLE INITIALLY DEFERRED;

-- 7) Audit log
CREATE TABLE IF NOT EXISTS security.audit_events (
  id             bigserial PRIMARY KEY,
  occurred_at    timestamptz NOT NULL DEFAULT now(),
  actor_ext_id   text,
  tenant_id      text,
  project_id     text,
  resource_type  text NOT NULL,   -- 'secret' | 'secret_version' | 'policy'
  resource_uuid  uuid,
  action         text NOT NULL,   -- 'INSERT' | 'UPDATE' | 'DELETE'
  old_row        jsonb,
  new_row        jsonb
);

-- 8) Triggers: updated_at, etag refresh, checksum (metadata) and audit

CREATE OR REPLACE FUNCTION security.touch_update_time()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.update_time := now();
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION security.bump_etag()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.etag := gen_random_bytes(16);
  RETURN NEW;
END$$;

-- Simple metadata checksum for secrets (labels+annotations+lifecycle+rotation summary)
CREATE OR REPLACE FUNCTION security.compute_secret_checksum()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  payload bytea;
BEGIN
  payload :=
    convert_to(COALESCE(NEW.lifecycle::text,''), 'UTF8') ||
    COALESCE(digest(coalesce(NEW.labels::text,''), 'sha256'), '\x') ||
    COALESCE(digest(coalesce(NEW.annotations::text,''), 'sha256'), '\x') ||
    convert_to(COALESCE(NEW.rotation_strategy::text,''), 'UTF8') ||
    convert_to(COALESCE(NEW.rotation_cron,''), 'UTF8');
  NEW.checksum_sha256 := digest(payload, 'sha256');
  RETURN NEW;
END$$;

-- Generic row change auditor
CREATE OR REPLACE FUNCTION security.audit_row()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  actor text := current_setting('app.subject_id', true);
  ten   text := current_setting('app.tenant_id', true);
  proj  text := current_setting('app.project_id', true);
  rtype text := TG_ARGV[0];
BEGIN
  IF (TG_OP = 'INSERT') THEN
    INSERT INTO security.audit_events(actor_ext_id, tenant_id, project_id, resource_type, resource_uuid, action, new_row)
    VALUES (actor, ten, proj, rtype, (NEW).id, TG_OP, to_jsonb(NEW));
    RETURN NEW;
  ELSIF (TG_OP = 'UPDATE') THEN
    INSERT INTO security.audit_events(actor_ext_id, tenant_id, project_id, resource_type, resource_uuid, action, old_row, new_row)
    VALUES (actor, ten, proj, rtype, (NEW).id, TG_OP, to_jsonb(OLD), to_jsonb(NEW));
    RETURN NEW;
  ELSE
    INSERT INTO security.audit_events(actor_ext_id, tenant_id, project_id, resource_type, resource_uuid, action, old_row)
    VALUES (actor, ten, proj, rtype, (OLD).id, TG_OP, to_jsonb(OLD));
    RETURN OLD;
  END IF;
END$$;

-- Attach triggers

-- secrets
CREATE TRIGGER trg_secrets_touch BEFORE UPDATE ON security.secrets
FOR EACH ROW EXECUTE FUNCTION security.touch_update_time();

CREATE TRIGGER trg_secrets_etag BEFORE UPDATE ON security.secrets
FOR EACH ROW EXECUTE FUNCTION security.bump_etag();

CREATE TRIGGER trg_secrets_checksum BEFORE INSERT OR UPDATE ON security.secrets
FOR EACH ROW EXECUTE FUNCTION security.compute_secret_checksum();

CREATE TRIGGER trg_secrets_audit_ins AFTER INSERT ON security.secrets
FOR EACH ROW EXECUTE FUNCTION security.audit_row('secret');

CREATE TRIGGER trg_secrets_audit_upd AFTER UPDATE ON security.secrets
FOR EACH ROW EXECUTE FUNCTION security.audit_row('secret');

CREATE TRIGGER trg_secrets_audit_del AFTER DELETE ON security.secrets
FOR EACH ROW EXECUTE FUNCTION security.audit_row('secret');

-- access_policies
CREATE TRIGGER trg_policies_touch BEFORE UPDATE ON security.access_policies
FOR EACH ROW EXECUTE FUNCTION security.touch_update_time();

CREATE TRIGGER trg_policies_etag BEFORE UPDATE ON security.access_policies
FOR EACH ROW EXECUTE FUNCTION security.bump_etag();

CREATE TRIGGER trg_policies_audit_ins AFTER INSERT ON security.access_policies
FOR EACH ROW EXECUTE FUNCTION security.audit_row('policy');

CREATE TRIGGER trg_policies_audit_upd AFTER UPDATE ON security.access_policies
FOR EACH ROW EXECUTE FUNCTION security.audit_row('policy');

CREATE TRIGGER trg_policies_audit_del AFTER DELETE ON security.access_policies
FOR EACH ROW EXECUTE FUNCTION security.audit_row('policy');

-- secret_versions
CREATE TRIGGER trg_versions_etag BEFORE UPDATE ON security.secret_versions
FOR EACH ROW EXECUTE FUNCTION security.bump_etag();

CREATE TRIGGER trg_versions_audit_ins AFTER INSERT ON security.secret_versions
FOR EACH ROW EXECUTE FUNCTION security.audit_row('secret_version');

CREATE TRIGGER trg_versions_audit_upd AFTER UPDATE ON security.secret_versions
FOR EACH ROW EXECUTE FUNCTION security.audit_row('secret_version');

CREATE TRIGGER trg_versions_audit_del AFTER DELETE ON security.secret_versions
FOR EACH ROW EXECUTE FUNCTION security.audit_row('secret_version');

-- 9) Indexes
CREATE INDEX IF NOT EXISTS ix_secrets_scope ON security.secrets(project_id, tenant_id, secret_id);
CREATE INDEX IF NOT EXISTS ix_secrets_lifecycle ON security.secrets(lifecycle);
CREATE INDEX IF NOT EXISTS ix_secrets_labels_gin ON security.secrets USING gin (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS ix_secrets_annotations_gin ON security.secrets USING gin (annotations jsonb_path_ops);
CREATE INDEX IF NOT EXISTS ix_versions_secret_time ON security.secret_versions(secret_uuid, create_time DESC);
CREATE INDEX IF NOT EXISTS ix_versions_state ON security.secret_versions(state);
CREATE INDEX IF NOT EXISTS ix_versions_remote ON security.secret_versions(remote_provider, remote_uri);

-- 10) Row-Level Security (RLS)

-- Helper predicate: subject has one of required roles on secret
CREATE OR REPLACE FUNCTION security.has_secret_role(p_secret_uuid uuid, VARIADIC p_roles text[])
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM security.access_policies ap
    JOIN security.bindings b ON b.policy_uuid = ap.id
    JOIN security.binding_principals bp ON bp.binding_uuid = b.id
    WHERE ap.secret_uuid = p_secret_uuid
      AND bp.principal_ext_id = current_setting('app.subject_id', true)
      AND b.role = ANY (p_roles)
  );
$$;

ALTER TABLE security.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.secret_versions ENABLE ROW LEVEL SECURITY;

-- SELECT: same tenant/project AND has reader/admin
CREATE POLICY rls_secrets_select ON security.secrets
  FOR SELECT
  USING (
    tenant_id  = current_setting('app.tenant_id', true) AND
    project_id = current_setting('app.project_id', true) AND
    security.has_secret_role(id, 'roles/secret.reader','roles/secret.admin')
  );

-- INSERT/UPDATE/DELETE: only admin
CREATE POLICY rls_secrets_modify ON security.secrets
  FOR ALL
  USING (
    tenant_id  = current_setting('app.tenant_id', true) AND
    project_id = current_setting('app.project_id', true) AND
    security.has_secret_role(id, 'roles/secret.admin')
  )
  WITH CHECK (
    tenant_id  = current_setting('app.tenant_id', true) AND
    project_id = current_setting('app.project_id', true) AND
    security.has_secret_role(id, 'roles/secret.admin')
  );

-- Versions inherit secret ACL
CREATE POLICY rls_versions_select ON security.secret_versions
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM security.secrets s
      WHERE s.id = secret_uuid
        AND s.tenant_id  = current_setting('app.tenant_id', true)
        AND s.project_id = current_setting('app.project_id', true)
        AND security.has_secret_role(s.id, 'roles/secret.reader','roles/secret.admin')
    )
  );

CREATE POLICY rls_versions_modify ON security.secret_versions
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM security.secrets s
      WHERE s.id = secret_uuid
        AND s.tenant_id  = current_setting('app.tenant_id', true)
        AND s.project_id = current_setting('app.project_id', true)
        AND security.has_secret_role(s.id, 'roles/secret.admin')
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM security.secrets s
      WHERE s.id = secret_uuid
        AND s.tenant_id  = current_setting('app.tenant_id', true)
        AND s.project_id = current_setting('app.project_id', true)
        AND security.has_secret_role(s.id, 'roles/secret.admin')
    )
  );

COMMIT;
