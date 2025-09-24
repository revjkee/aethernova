-- File: cybersecurity-core/schemas/jsonschema/v1/sql/migrations/0005_ti_feed.sql
-- Purpose: Threat Intelligence feed registry (industrial-grade)
-- Engine: PostgreSQL 13+ (tested with 13/14/15)

BEGIN;

-- 1) Extensions (idempotent)
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;       -- case-insensitive text
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- trigram for fast LIKE/ILIKE search

-- 2) Schema namespace
CREATE SCHEMA IF NOT EXISTS cybersecurity;

-- 3) ENUM types (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ti_feed_type') THEN
        CREATE TYPE cybersecurity.ti_feed_type AS ENUM (
            'stix2', 'misp', 'taxii', 'csv', 'json', 'ndjson', 'yara', 'sigma', 'suricata', 'custom'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ti_auth_method') THEN
        CREATE TYPE cybersecurity.ti_auth_method AS ENUM (
            'none', 'basic', 'api_key', 'bearer', 'mtls', 'oauth2_client_credentials', 'aws_sigv4'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ti_ingestion_status') THEN
        CREATE TYPE cybersecurity.ti_ingestion_status AS ENUM (
            'active', 'paused', 'error', 'disabled'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ti_severity_level') THEN
        CREATE TYPE cybersecurity.ti_severity_level AS ENUM (
            'informational', 'low', 'medium', 'high', 'critical'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tlp_level') THEN
        CREATE TYPE cybersecurity.tlp_level AS ENUM (
            'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ti_dedup_strategy') THEN
        CREATE TYPE cybersecurity.ti_dedup_strategy AS ENUM (
            'none', 'by_external_id', 'by_content_hash'
        );
    END IF;
END$$;

-- 4) Helper function: updated_at = now()
CREATE OR REPLACE FUNCTION cybersecurity.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

-- 5) Table
CREATE TABLE IF NOT EXISTS cybersecurity.ti_feed (
    id                      uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  uuid            NULL, -- optional multi-tenancy; null => global
    name                    citext          NOT NULL,
    description             text            NULL,

    enabled                 boolean         NOT NULL DEFAULT true,
    status                  cybersecurity.ti_ingestion_status NOT NULL DEFAULT 'active',

    feed_type               cybersecurity.ti_feed_type NOT NULL,
    content_type            text            NULL, -- MIME, e.g. application/stix+json
    url                     text            NOT NULL,
    http_method             text            NOT NULL DEFAULT 'GET' CHECK (http_method IN ('GET','POST')),

    request_headers         jsonb           NOT NULL DEFAULT '{}'::jsonb,
    request_body            jsonb           NULL,

    auth_method             cybersecurity.ti_auth_method NOT NULL DEFAULT 'none',
    auth_config             jsonb           NULL,     -- non-secret parameters (e.g., header name)
    credentials_ciphertext  bytea           NULL,     -- envelope-encrypted secrets (optional)

    ingestion_interval      interval        NOT NULL DEFAULT interval '1 hour',
    next_run_at             timestamptz     NULL,
    last_ingested_at        timestamptz     NULL,
    backoff_seconds         integer         NOT NULL DEFAULT 0 CHECK (backoff_seconds >= 0),
    retry_count             integer         NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    max_retry               integer         NOT NULL DEFAULT 5 CHECK (max_retry >= 0),

    etag                    text            NULL,
    last_modified           text            NULL,

    pagination_cursor       text            NULL,
    cursor_json             jsonb           NULL,

    dedup_strategy          cybersecurity.ti_dedup_strategy NOT NULL DEFAULT 'by_external_id',
    hash_algo               text            NOT NULL DEFAULT 'sha256',

    mapping                 jsonb           NULL,     -- transform rules to internal schema
    default_tlp             cybersecurity.tlp_level NOT NULL DEFAULT 'TLP:AMBER',
    default_confidence      smallint        NOT NULL DEFAULT 60 CHECK (default_confidence BETWEEN 0 AND 100),
    default_severity        cybersecurity.ti_severity_level NOT NULL DEFAULT 'medium',

    source_name             text            NULL,     -- human-readable source label
    source_type             text            NULL CHECK (source_type IN ('osint','partner','internal','commercial','isac','community')),
    source_reliability      text            NULL CHECK (source_reliability IN ('A','B','C','D','E','F')),
    source_credibility      text            NULL CHECK (source_credibility IN ('1','2','3','4','5','6')),

    tags                    text[]          NOT NULL DEFAULT ARRAY[]::text[],

    created_at              timestamptz     NOT NULL DEFAULT NOW(),
    updated_at              timestamptz     NOT NULL DEFAULT NOW(),
    deleted_at              timestamptz     NULL,

    -- Constraints
    CONSTRAINT ti_feed_url_valid CHECK (
        url ~* '^(https?|ftp|s3|gs)://'
    ),
    CONSTRAINT ti_feed_interval_min CHECK (
        ingestion_interval >= interval '1 minute'
    ),
    CONSTRAINT ti_feed_backoff_vs_retry CHECK (
        (status <> 'error') OR (retry_count >= 0)
    )
);

-- 6) Uniqueness within org (case-insensitive name via citext)
--    Unique index uses COALESCE(org_id, zero-UUID) to enforce uniqueness even when org_id is NULL.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity'
          AND indexname = 'ti_feed_org_name_uniq'
    ) THEN
        CREATE UNIQUE INDEX ti_feed_org_name_uniq
            ON cybersecurity.ti_feed (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
    END IF;
END$$;

-- 7) Operational indexes
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity' AND indexname = 'ti_feed_next_run_idx'
    ) THEN
        CREATE INDEX ti_feed_next_run_idx
            ON cybersecurity.ti_feed (enabled, status, next_run_at)
            WHERE deleted_at IS NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity' AND indexname = 'ti_feed_url_trgm_idx'
    ) THEN
        CREATE INDEX ti_feed_url_trgm_idx
            ON cybersecurity.ti_feed
            USING gin (url gin_trgm_ops);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity' AND indexname = 'ti_feed_headers_gin'
    ) THEN
        CREATE INDEX ti_feed_headers_gin
            ON cybersecurity.ti_feed
            USING gin (request_headers);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity' AND indexname = 'ti_feed_mapping_gin'
    ) THEN
        CREATE INDEX ti_feed_mapping_gin
            ON cybersecurity.ti_feed
            USING gin (mapping);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity' AND indexname = 'ti_feed_tags_gin'
    ) THEN
        CREATE INDEX ti_feed_tags_gin
            ON cybersecurity.ti_feed
            USING gin (tags);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'cybersecurity' AND indexname = 'ti_feed_cursor_gin'
    ) THEN
        CREATE INDEX ti_feed_cursor_gin
            ON cybersecurity.ti_feed
            USING gin (cursor_json);
    END IF;
END$$;

-- 8) Trigger: updated_at auto
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'ti_feed_set_updated_at'
    ) THEN
        CREATE TRIGGER ti_feed_set_updated_at
        BEFORE UPDATE ON cybersecurity.ti_feed
        FOR EACH ROW
        EXECUTE FUNCTION cybersecurity.set_updated_at();
    END IF;
END$$;

-- 9) Comments (data dictionary)
COMMENT ON TABLE  cybersecurity.ti_feed IS 'Registry of Threat Intelligence feeds (ingestion config, scheduling, defaults, and operational metadata).';
COMMENT ON COLUMN cybersecurity.ti_feed.org_id                IS 'Tenant/organization id (NULL for global).';
COMMENT ON COLUMN cybersecurity.ti_feed.name                  IS 'Unique feed name within organization.';
COMMENT ON COLUMN cybersecurity.ti_feed.enabled               IS 'Enables ingestion for this feed.';
COMMENT ON COLUMN cybersecurity.ti_feed.status                IS 'Operational status of the feed: active, paused, error, disabled.';
COMMENT ON COLUMN cybersecurity.ti_feed.feed_type             IS 'Feed/application protocol or format (stix2, misp, taxii, csv, json, ndjson, yara, sigma, suricata, custom).';
COMMENT ON COLUMN cybersecurity.ti_feed.url                   IS 'Endpoint URL (http/https/ftp/s3/gs).';
COMMENT ON COLUMN cybersecurity.ti_feed.request_headers       IS 'Custom HTTP headers (JSONB).';
COMMENT ON COLUMN cybersecurity.ti_feed.request_body          IS 'Request payload for POST (JSONB).';
COMMENT ON COLUMN cybersecurity.ti_feed.auth_method           IS 'Authentication method.';
COMMENT ON COLUMN cybersecurity.ti_feed.auth_config           IS 'Non-secret auth parameters (JSONB).';
COMMENT ON COLUMN cybersecurity.ti_feed.credentials_ciphertext IS 'Encrypted credentials (envelope encryption).';
COMMENT ON COLUMN cybersecurity.ti_feed.ingestion_interval    IS 'Polling interval (>= 1 minute).';
COMMENT ON COLUMN cybersecurity.ti_feed.next_run_at           IS 'Planned next run timestamp.';
COMMENT ON COLUMN cybersecurity.ti_feed.last_ingested_at      IS 'Last successful ingestion timestamp.';
COMMENT ON COLUMN cybersecurity.ti_feed.backoff_seconds       IS 'Dynamic backoff for error handling.';
COMMENT ON COLUMN cybersecurity.ti_feed.etag                  IS 'HTTP ETag for conditional requests.';
COMMENT ON COLUMN cybersecurity.ti_feed.last_modified         IS 'HTTP Last-Modified for conditional requests.';
COMMENT ON COLUMN cybersecurity.ti_feed.pagination_cursor     IS 'Opaque cursor for paginated APIs.';
COMMENT ON COLUMN cybersecurity.ti_feed.cursor_json           IS 'Structured cursor state (JSONB).';
COMMENT ON COLUMN cybersecurity.ti_feed.dedup_strategy        IS 'Deduplication strategy during ingestion.';
COMMENT ON COLUMN cybersecurity.ti_feed.hash_algo             IS 'Hash algorithm used for dedup/content hashing.';
COMMENT ON COLUMN cybersecurity.ti_feed.mapping               IS 'Transformation mapping to internal schema (JSONB).';
COMMENT ON COLUMN cybersecurity.ti_feed.default_tlp           IS 'Default TLP for produced indicators.';
COMMENT ON COLUMN cybersecurity.ti_feed.default_confidence    IS 'Default confidence [0..100].';
COMMENT ON COLUMN cybersecurity.ti_feed.default_severity      IS 'Default severity level.';
COMMENT ON COLUMN cybersecurity.ti_feed.source_name           IS 'Human-readable source name.';
COMMENT ON COLUMN cybersecurity.ti_feed.source_type           IS 'Source taxonomy: osint, partner, internal, commercial, isac, community.';
COMMENT ON COLUMN cybersecurity.ti_feed.source_reliability    IS 'Admiralty source reliability (A..F).';
COMMENT ON COLUMN cybersecurity.ti_feed.source_credibility    IS 'Admiralty information credibility (1..6).';
COMMENT ON COLUMN cybersecurity.ti_feed.tags                  IS 'Free-form tags.';
COMMENT ON COLUMN cybersecurity.ti_feed.deleted_at            IS 'Soft delete timestamp.';
COMMENT ON COLUMN cybersecurity.ti_feed.created_at            IS 'Creation timestamp.';
COMMENT ON COLUMN cybersecurity.ti_feed.updated_at            IS 'Last update timestamp (auto).';

COMMIT;
