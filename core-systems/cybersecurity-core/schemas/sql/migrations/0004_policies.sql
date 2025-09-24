-- cybersecurity-core / schemas / jsonschema / v1 / sql / migrations / 0004_policies.sql
-- Purpose: Introduce policies registry with RLS, auditing, constraints, and indexes.
-- Requires: PostgreSQL 13+ (generated columns), recommended 14+.
-- Idempotent by design.

BEGIN;

-- 1. Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS citext;    -- case-insensitive text
CREATE EXTENSION IF NOT EXISTS btree_gin; -- GIN for btree operators

-- 2. Schema
CREATE SCHEMA IF NOT EXISTS cybersecurity;
COMMENT ON SCHEMA cybersecurity IS 'Security artifacts for cybersecurity-core';

-- 3. Enum types (idempotent pattern)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policy_status') THEN
        CREATE TYPE cybersecurity.policy_status AS ENUM ('draft','active','deprecated','archived');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policy_type') THEN
        CREATE TYPE cybersecurity.policy_type AS ENUM (
            'detection','suppression','response','rbac','rate_limit',
            'network','edr','siem','correlation','playbook'
        );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policy_effect') THEN
        CREATE TYPE cybersecurity.policy_effect AS ENUM (
            'allow','deny','alert','block','quarantine','enrich','escalate'
        );
    END IF;
END$$;

-- 4. Helper domain or regex for SemVer
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'semver_pattern_dummy_check') THEN
        -- no-op placeholder to keep DO section symmetrical
        PERFORM 1;
    END IF;
END$$;

-- 5. Table: policies
CREATE TABLE IF NOT EXISTS cybersecurity.policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,

    tenant_id           UUID, -- optional multi-tenancy; RLS enforces access

    name                CITEXT NOT NULL,      -- logical policy name
    description         TEXT,

    version             TEXT NOT NULL,        -- SemVer
    status              cybersecurity.policy_status NOT NULL DEFAULT 'draft',
    policy_type         cybersecurity.policy_type NOT NULL,
    effect              cybersecurity.policy_effect NOT NULL,

    priority            INT NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000),

    tags                TEXT[] NOT NULL DEFAULT '{}',

    -- Core content
    conditions          JSONB NOT NULL DEFAULT '{}'::jsonb,
    actions             JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Optional mappings and context
    mitre_attack        TEXT[] NOT NULL DEFAULT '{}',       -- e.g., T1059, T1190
    kill_chain          TEXT,                                -- reconnaissance..actions-on-objective
    scope               JSONB NOT NULL DEFAULT '{}'::jsonb,  -- scoping: sources, env, labels

    -- Time validity
    valid_from          TIMESTAMPTZ,
    valid_until         TIMESTAMPTZ,

    -- Fingerprint of policy content for integrity and quick diff
    content_fingerprint TEXT GENERATED ALWAYS AS (
        encode(
            digest(
                coalesce(lower(name)::text,'') || '|' ||
                coalesce(version,'') || '|' ||
                coalesce(description,'') || '|' ||
                coalesce(policy_type::text,'') || '|' ||
                coalesce(effect::text,'') || '|' ||
                coalesce(priority::text,'') || '|' ||
                coalesce(conditions::text,'{}') || '|' ||
                coalesce(actions::text,'[]') || '|' ||
                coalesce(scope::text,'{}') || '|' ||
                coalesce(array_to_string(mitre_attack,','),'') || '|' ||
                coalesce(kill_chain,'')
            , 'sha256')
        , 'hex')
    ) STORED
);

COMMENT ON TABLE cybersecurity.policies IS 'Registry of security policies for detection/suppression/response with multi-tenant isolation and integrity fingerprint';
COMMENT ON COLUMN cybersecurity.policies.conditions IS 'JSONB condition tree for matching (validated at app level, type-enforced by jsonb_typeof checks)';
COMMENT ON COLUMN cybersecurity.policies.actions    IS 'JSONB action list for enforcement or response';
COMMENT ON COLUMN cybersecurity.policies.scope      IS 'JSONB scope, eg. sensor, environment, labels';
COMMENT ON COLUMN cybersecurity.policies.version    IS 'SemVer policy version';
COMMENT ON COLUMN cybersecurity.policies.mitre_attack IS 'List of MITRE ATT&CK technique IDs (e.g., T1059, T1059.003)';

-- 6. Constraints
-- SemVer pattern
ALTER TABLE cybersecurity.policies
    ADD CONSTRAINT policies_version_semver_ck
    CHECK (
        version ~ '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
    )
    NOT VALID;
-- JSON types sanity
ALTER TABLE cybersecurity.policies
    ADD CONSTRAINT policies_conditions_json_ck
    CHECK (jsonb_typeof(conditions) IN ('object'))
    NOT VALID;

ALTER TABLE cybersecurity.policies
    ADD CONSTRAINT policies_actions_json_ck
    CHECK (jsonb_typeof(actions) IN ('array'))
    NOT VALID;

ALTER TABLE cybersecurity.policies
    ADD CONSTRAINT policies_scope_json_ck
    CHECK (jsonb_typeof(scope) IN ('object'))
    NOT VALID;

-- validity window
ALTER TABLE cybersecurity.policies
    ADD CONSTRAINT policies_valid_window_ck
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from);

-- uniqueness: same tenant, same name, same version (excluding soft-deleted)
CREATE UNIQUE INDEX IF NOT EXISTS ux_policies_tenant_name_version_alive
    ON cybersecurity.policies (tenant_id, lower(name), version)
    WHERE deleted_at IS NULL;

-- only one ACTIVE version per tenant-name at a time (excluding soft-deleted)
CREATE UNIQUE INDEX IF NOT EXISTS ux_policies_one_active_per_name_tenant
    ON cybersecurity.policies (tenant_id, lower(name))
    WHERE status = 'active' AND deleted_at IS NULL;

-- 7. Generated search vector and index (PostgreSQL 12+ supports STORED)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='cybersecurity' AND table_name='policies' AND column_name='search'
    ) THEN
        ALTER TABLE cybersecurity.policies
        ADD COLUMN search tsvector GENERATED ALWAYS AS (
            setweight(to_tsvector('simple', coalesce(name::text,'')), 'A') ||
            setweight(to_tsvector('simple', coalesce(description,'')), 'B') ||
            setweight(to_tsvector('simple', array_to_string(tags,' ')), 'C')
        ) STORED;
    END IF;
END$$;

-- 8. Indexes
CREATE INDEX IF NOT EXISTS ix_policies_status_type_priority
    ON cybersecurity.policies (status, policy_type, priority);

CREATE INDEX IF NOT EXISTS ix_policies_validity_window
    ON cybersecurity.policies (valid_from, valid_until);

CREATE INDEX IF NOT EXISTS ix_policies_tags_gin
    ON cybersecurity.policies USING GIN (tags);

CREATE INDEX IF NOT EXISTS ix_policies_conditions_gin
    ON cybersecurity.policies USING GIN (conditions jsonb_path_ops);

CREATE INDEX IF NOT EXISTS ix_policies_actions_gin
    ON cybersecurity.policies USING GIN (actions jsonb_path_ops);

CREATE INDEX IF NOT EXISTS ix_policies_scope_gin
    ON cybersecurity.policies USING GIN (scope jsonb_path_ops);

CREATE INDEX IF NOT EXISTS ix_policies_search_gin
    ON cybersecurity.policies USING GIN (search);

-- 9. Trigger: updated_at
CREATE OR REPLACE FUNCTION cybersecurity.tg_set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS set_updated_at ON cybersecurity.policies;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON cybersecurity.policies
FOR EACH ROW EXECUTE FUNCTION cybersecurity.tg_set_updated_at();

-- 10. Auditing
CREATE TABLE IF NOT EXISTS cybersecurity.policies_audit (
    id              BIGSERIAL PRIMARY KEY,
    happened_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor           TEXT, -- from app.actor
    action          TEXT NOT NULL CHECK (action IN ('INSERT','UPDATE','DELETE')),
    policy_id       UUID,
    old_row         JSONB,
    new_row         JSONB
);

COMMENT ON TABLE cybersecurity.policies_audit IS 'Audit log for policy mutations';

CREATE OR REPLACE FUNCTION cybersecurity.tg_policies_audit()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_actor TEXT := current_setting('app.actor', true);
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO cybersecurity.policies_audit(actor, action, policy_id, old_row, new_row)
        VALUES (v_actor, 'INSERT', NEW.id, NULL, to_jsonb(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO cybersecurity.policies_audit(actor, action, policy_id, old_row, new_row)
        VALUES (v_actor, 'UPDATE', NEW.id, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO cybersecurity.policies_audit(actor, action, policy_id, old_row, new_row)
        VALUES (v_actor, 'DELETE', OLD.id, to_jsonb(OLD), NULL);
        RETURN OLD;
    END IF;
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS policies_audit_trg ON cybersecurity.policies;
CREATE TRIGGER policies_audit_trg
AFTER INSERT OR UPDATE OR DELETE ON cybersecurity.policies
FOR EACH ROW EXECUTE FUNCTION cybersecurity.tg_policies_audit();

-- 11. Row-Level Security (RLS)
ALTER TABLE cybersecurity.policies ENABLE ROW LEVEL SECURITY;

-- Access policy: tenant isolation with optional global rows (tenant_id IS NULL)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersecurity' AND tablename='policies' AND policyname='policies_tenant_isolation'
    ) THEN
        CREATE POLICY policies_tenant_isolation
        ON cybersecurity.policies
        USING (
            tenant_id IS NULL
            OR (
                current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = (current_setting('app.tenant_id', true))::uuid
            )
        )
        WITH CHECK (
            tenant_id IS NULL
            OR (
                current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = (current_setting('app.tenant_id', true))::uuid
            )
        );
    END IF;
END$$;

-- Note: Grant management is environment-specific; apply in deployment tooling (e.g., role soc_app).

-- 12. View of active policies
CREATE OR REPLACE VIEW cybersecurity.v_active_policies AS
SELECT *
FROM cybersecurity.policies p
WHERE p.deleted_at IS NULL
  AND p.status = 'active'
  AND (
      (p.valid_from IS NULL OR p.valid_from <= now())
      AND (p.valid_until IS NULL OR p.valid_until >  now())
  );

COMMENT ON VIEW cybersecurity.v_active_policies IS 'Convenience view for currently effective active policies';

-- 13. Validate NOT VALID constraints to lock in if data allows (optional; safe when initial load empty)
-- You may leave them NOT VALID for online adoption and validate later in a maintenance window.
-- ALTER TABLE cybersecurity.policies VALIDATE CONSTRAINT policies_version_semver_ck;
-- ALTER TABLE cybersecurity.policies VALIDATE CONSTRAINT policies_conditions_json_ck;
-- ALTER TABLE cybersecurity.policies VALIDATE CONSTRAINT policies_actions_json_ck;
-- ALTER TABLE cybersecurity.policies VALIDATE CONSTRAINT policies_scope_json_ck;

COMMIT;
