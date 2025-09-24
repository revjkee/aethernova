-- 0003_findings.sql
-- PostgreSQL 13+ | Aethernova Cybersecurity-Core
-- Реестр security findings с multi-tenant изоляцией, полнотекстовым поиском и доказуемой целостностью.

BEGIN;

-- 1) Схема и расширения
CREATE SCHEMA IF NOT EXISTS cybersec;

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- gin_trgm_ops, триграммы
CREATE EXTENSION IF NOT EXISTS plpgsql;   -- на случай минимальных сборок

-- 2) Типы
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                   WHERE t.typname = 'severity_level' AND n.nspname='cybersec') THEN
        CREATE TYPE cybersec.severity_level AS ENUM ('informational','low','medium','high','critical');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                   WHERE t.typname = 'finding_status' AND n.nspname='cybersec') THEN
        CREATE TYPE cybersec.finding_status AS ENUM (
            'open','triaged','in_progress','accepted_risk','resolved','closed','false_positive','duplicate','wont_fix'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                   WHERE t.typname = 'finding_source' AND n.nspname='cybersec') THEN
        CREATE TYPE cybersec.finding_source AS ENUM (
            'edr','siem','soar','scanner','pentest','bug_bounty','manual','other'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                   WHERE t.typname = 'asset_type' AND n.nspname='cybersec') THEN
        CREATE TYPE cybersec.asset_type AS ENUM (
            'host','ip','user','process','file','registry','url','domain','container','repository','cloud_resource','other'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                   WHERE t.typname = 'evidence_type' AND n.nspname='cybersec') THEN
        CREATE TYPE cybersec.evidence_type AS ENUM ('log','pcap','dump','screenshot','report','artifact','other');
    END IF;
END
$$ LANGUAGE plpgsql;

-- 3) Утилитарные функции/триггеры
CREATE OR REPLACE FUNCTION cybersec.tg_set_timestamp()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION cybersec.tg_log_status_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO cybersec.finding_status_history(
            id, finding_id, from_status, to_status, changed_by, changed_at, reason
        ) VALUES (
            gen_random_uuid(),
            NEW.id,
            OLD.status,
            NEW.status,
            COALESCE(current_setting('app.actor', true), current_user),
            NOW(),
            COALESCE(NEW.status_change_reason, 'status changed')
        );
    END IF;
    RETURN NEW;
END;
$$;

-- 4) Основная таблица findings
CREATE TABLE IF NOT EXISTS cybersec.findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,                -- изоляция арендатора (RLS)
    external_id         TEXT,                         -- ID из внешней системы (сканер, SOAR и т. п.)
    title               TEXT NOT NULL,
    description         TEXT,
    category            TEXT,
    subcategory         TEXT,

    status              cybersec.finding_status NOT NULL DEFAULT 'open',
    severity            cybersec.severity_level NOT NULL DEFAULT 'low',
    source              cybersec.finding_source NOT NULL DEFAULT 'other',

    cvss_vector         TEXT,
    cvss_score          NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cwe_id              INTEGER CHECK (cwe_id IS NULL OR cwe_id >= 0),

    mitre_attack_techniques TEXT[] NOT NULL DEFAULT '{}',   -- например: {'T1059.001','T1047'}
    tags                TEXT[] NOT NULL DEFAULT '{}',

    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    asset_key           TEXT,                                -- ключ описания главного объекта (hostname/IP/URL/идентификатор)
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at       TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Полнотекстовый поиск
    search_tsv          tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', COALESCE(title, '')), 'A') ||
        setweight(to_tsvector('simple', COALESCE(description, '')), 'B') ||
        setweight(to_tsvector('simple', array_to_string(tags, ' ')), 'C')
    ) STORED,

    -- Отпечаток для дедупликации (tenant_id + title + category + asset_key)
    fingerprint         bytea GENERATED ALWAYS AS (
        digest(COALESCE(tenant_id,'') || '|' || COALESCE(title,'') || '|' ||
               COALESCE(category,'')  || '|' || COALESCE(asset_key,''), 'sha256')
    ) STORED,

    -- Служебное поле для записи причины смены статуса (используется триггером)
    status_change_reason TEXT,

    CONSTRAINT findings_last_ge_first CHECK (
        first_seen_at IS NULL OR last_seen_at IS NULL OR last_seen_at >= first_seen_at
    ),
    CONSTRAINT findings_closed_requires_time CHECK (
        status NOT IN ('resolved','closed') OR resolved_at IS NOT NULL OR closed_at IS NOT NULL
    )
);

-- Уникальность по внешнему ID в рамках арендатора (частичный индекс для non-null)
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_tenant_external
    ON cybersec.findings(tenant_id, external_id)
    WHERE external_id IS NOT NULL;

-- Дедупликация по отпечатку в рамках арендатора
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_tenant_fingerprint
    ON cybersec.findings(tenant_id, fingerprint);

-- Индексы для частых запросов
CREATE INDEX IF NOT EXISTS ix_findings_tenant_status
    ON cybersec.findings(tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_findings_severity
    ON cybersec.findings(severity);

CREATE INDEX IF NOT EXISTS ix_findings_detected_at
    ON cybersec.findings(detected_at DESC);

CREATE INDEX IF NOT EXISTS ix_findings_tags_gin
    ON cybersec.findings USING GIN (tags);

CREATE INDEX IF NOT EXISTS ix_findings_metadata_gin
    ON cybersec.findings USING GIN (metadata);

CREATE INDEX IF NOT EXISTS ix_findings_search_tsv_gin
    ON cybersec.findings USING GIN (search_tsv);

-- Триггеры на обновление updated_at и лог статусов
DROP TRIGGER IF EXISTS trg_findings_set_timestamp ON cybersec.findings;
CREATE TRIGGER trg_findings_set_timestamp
    BEFORE UPDATE ON cybersec.findings
    FOR EACH ROW EXECUTE FUNCTION cybersec.tg_set_timestamp();

DROP TRIGGER IF EXISTS trg_findings_log_status ON cybersec.findings;
CREATE TRIGGER trg_findings_log_status
    BEFORE UPDATE OF status ON cybersec.findings
    FOR EACH ROW EXECUTE FUNCTION cybersec.tg_log_status_change();

-- 5) Таблица привязки активов к finding
CREATE TABLE IF NOT EXISTS cybersec.finding_assets (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   UUID NOT NULL REFERENCES cybersec.findings(id) ON DELETE CASCADE,
    asset_type   cybersec.asset_type NOT NULL,
    asset_id     TEXT NOT NULL,
    attributes   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT finding_assets_asset_uniq UNIQUE (finding_id, asset_type, asset_id)
);

CREATE INDEX IF NOT EXISTS ix_fasset_finding
    ON cybersec.finding_assets(finding_id);

CREATE INDEX IF NOT EXISTS ix_fasset_type
    ON cybersec.finding_assets(asset_type);

CREATE INDEX IF NOT EXISTS ix_fasset_attributes_gin
    ON cybersec.finding_assets USING GIN (attributes);

-- 6) Доказательства/артефакты
CREATE TABLE IF NOT EXISTS cybersec.finding_evidence (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id    UUID NOT NULL REFERENCES cybersec.findings(id) ON DELETE CASCADE,
    type          cybersec.evidence_type NOT NULL,
    uri           TEXT,                                    -- ссылка на хранилище/объект
    sha256        TEXT CHECK (sha256 ~* '^[a-f0-9]{64}$'),
    size_bytes    BIGINT CHECK (size_bytes IS NULL OR size_bytes >= 0),
    description   TEXT,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_fevidence_finding
    ON cybersec.finding_evidence(finding_id);

-- Уникальность по (finding, sha256) если хэш известен
CREATE UNIQUE INDEX IF NOT EXISTS ux_fevidence_sha
    ON cybersec.finding_evidence(finding_id, sha256)
    WHERE sha256 IS NOT NULL;

-- 7) Журнал смен статусов
CREATE TABLE IF NOT EXISTS cybersec.finding_status_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   UUID NOT NULL REFERENCES cybersec.findings(id) ON DELETE CASCADE,
    from_status  cybersec.finding_status,
    to_status    cybersec.finding_status NOT NULL,
    changed_by   TEXT,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason       TEXT
);

CREATE INDEX IF NOT EXISTS ix_fhist_finding_time
    ON cybersec.finding_status_history(finding_id, changed_at DESC);

-- 8) RLS (Row-Level Security) для мультиарендности
ALTER TABLE cybersec.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cybersec.finding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE cybersec.finding_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE cybersec.finding_status_history ENABLE ROW LEVEL SECURITY;

-- Политики SELECT
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='findings' AND policyname='rls_findings_tenant_select'
    ) THEN
        CREATE POLICY rls_findings_tenant_select ON cybersec.findings
            FOR SELECT USING (
                current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='finding_assets' AND policyname='rls_fassets_tenant_select'
    ) THEN
        CREATE POLICY rls_fassets_tenant_select ON cybersec.finding_assets
            FOR SELECT USING (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='finding_evidence' AND policyname='rls_fevidence_tenant_select'
    ) THEN
        CREATE POLICY rls_fevidence_tenant_select ON cybersec.finding_evidence
            FOR SELECT USING (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='finding_status_history' AND policyname='rls_fhist_tenant_select'
    ) THEN
        CREATE POLICY rls_fhist_tenant_select ON cybersec.finding_status_history
            FOR SELECT USING (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;
END
$$ LANGUAGE plpgsql;

-- Политики INSERT/UPDATE/DELETE
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='findings' AND policyname='rls_findings_tenant_cud'
    ) THEN
        CREATE POLICY rls_findings_tenant_cud ON cybersec.findings
            FOR ALL TO PUBLIC
            USING (
                current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='finding_assets' AND policyname='rls_fassets_tenant_cud'
    ) THEN
        CREATE POLICY rls_fassets_tenant_cud ON cybersec.finding_assets
            FOR ALL TO PUBLIC
            USING (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='finding_evidence' AND policyname='rls_fevidence_tenant_cud'
    ) THEN
        CREATE POLICY rls_fevidence_tenant_cud ON cybersec.finding_evidence
            FOR ALL TO PUBLIC
            USING (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='cybersec' AND tablename='finding_status_history' AND policyname='rls_fhist_tenant_cud'
    ) THEN
        CREATE POLICY rls_fhist_tenant_cud ON cybersec.finding_status_history
            FOR ALL TO PUBLIC
            USING (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM cybersec.findings f
                    WHERE f.id = finding_id
                      AND f.tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;
END
$$ LANGUAGE plpgsql;

-- 9) Комментарии (self-doc)
COMMENT ON SCHEMA cybersec IS 'Кибербезопасность: findings/evidence/assets/history с RLS и полнотекстом';
COMMENT ON TABLE cybersec.findings IS 'Security findings (multi-tenant, searchable, deduplicated)';
COMMENT ON COLUMN cybersec.findings.tenant_id IS 'Идентификатор арендатора; RLS использует app.tenant_id';
COMMENT ON COLUMN cybersec.findings.fingerprint IS 'SHA-256 отпечаток (tenant|title|category|asset_key) для дедупликации';
COMMENT ON TABLE cybersec.finding_assets IS 'Связанные активы конкретного finding';
COMMENT ON TABLE cybersec.finding_evidence IS 'Артефакты/доказательства по finding';
COMMENT ON TABLE cybersec.finding_status_history IS 'Журнал переходов статусов finding';

COMMIT;

-- DOWN (мануальный откат; при необходимости выполнять по порядку):
-- BEGIN;
-- DROP TABLE IF EXISTS cybersec.finding_status_history;
-- DROP TABLE IF EXISTS cybersec.finding_evidence;
-- DROP TABLE IF EXISTS cybersec.finding_assets;
-- DROP TABLE IF EXISTS cybersec.findings;
-- DROP TYPE IF EXISTS cybersec.evidence_type;
-- DROP TYPE IF EXISTS cybersec.asset_type;
-- DROP TYPE IF EXISTS cybersec.finding_source;
-- DROP TYPE IF EXISTS cybersec.finding_status;
-- DROP TYPE IF EXISTS cybersec.severity_level;
-- COMMIT;
