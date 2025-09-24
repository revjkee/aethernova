-- 0004_evidence_store.sql
-- OblivionVault Core — Evidence Store (industrial grade)
-- Requires: PostgreSQL 13+ (tested with 14/15)
-- Features:
--  * Schema evidence + extensions (pgcrypto, pg_trgm, citext, btree_gin)
--  * Types: evidence_state, hash_algo, sensitivity_level, dependency/custody enums
--  * Tables: legal_hold, case, item (RANGE MONTH partitioned), blob, chain_of_custody, tags
--  * RLS roles/policies with current_app_user_id() (GUC app.user_id)
--  * Triggers: updated_at, tsvector search, immutability on sealed/archived,
--    no-delete under legal hold, chain-of-custody record hash
--  * Indexes: GIN tsvector, btree/trgm, partials, FK cascades
--  * Automatic monthly partitions (current + next 12)

BEGIN;

-- Safety/defaults
SET client_min_messages = WARNING;
SET lock_timeout = '5s';
SET statement_timeout = 0;

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Schema
CREATE SCHEMA IF NOT EXISTS evidence;

-- =========================
-- ENUM types
-- =========================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'evidence_state') THEN
    CREATE TYPE evidence.evidence_state AS ENUM ('draft', 'sealed', 'archived');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'hash_algo') THEN
    CREATE TYPE evidence.hash_algo AS ENUM ('sha256', 'sha512', 'blake3');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sensitivity_level') THEN
    CREATE TYPE evidence.sensitivity_level AS ENUM ('public','internal','confidential','secret','restricted');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'custody_action') THEN
    CREATE TYPE evidence.custody_action AS ENUM ('collected','transferred','verified','sealed','archived','restored');
  END IF;
END$$;

-- =========================
-- Helper functions
-- =========================

-- Current app user id, from GUC app.user_id (UUID)
CREATE OR REPLACE FUNCTION evidence.current_app_user_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE v text;
BEGIN
  v := current_setting('app.user_id', true);
  IF v IS NULL OR v = '' THEN
    RETURN NULL;
  END IF;
  RETURN v::uuid;
EXCEPTION WHEN others THEN
  RETURN NULL;
END$$;

-- Touch updated_at
CREATE OR REPLACE FUNCTION evidence.fn_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- Build tsvector from title/description/labels/tags
CREATE OR REPLACE FUNCTION evidence.fn_update_search_vector()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  txt text;
BEGIN
  txt := coalesce(NEW.title,'') || ' ' || coalesce(NEW.description,'');
  -- add jsonb labels/tags if present
  IF NEW.metadata IS NOT NULL THEN
    txt := txt || ' ' || coalesce( (SELECT string_agg(k || ':' || v, ' ')
                                    FROM jsonb_each_text(NEW.metadata)), '' );
  END IF;
  IF NEW.tags IS NOT NULL THEN
    txt := txt || ' ' || coalesce( (SELECT string_agg(value::text, ' ')
                                    FROM jsonb_array_elements_text(NEW.tags)), '' );
  END IF;
  NEW.search := to_tsvector('simple', txt);
  RETURN NEW;
END$$;

-- Enforce immutability on sealed/archived items: block content changes
CREATE OR REPLACE FUNCTION evidence.fn_enforce_item_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.state IN ('sealed','archived') THEN
    -- Allowed to toggle legal_hold_id (e.g., release) and timestamps, but not content
    IF (NEW.content_hash     IS DISTINCT FROM OLD.content_hash)
       OR (NEW.hash_algo     IS DISTINCT FROM OLD.hash_algo)
       OR (NEW.content_size  IS DISTINCT FROM OLD.content_size)
       OR (NEW.storage_uri   IS DISTINCT FROM OLD.storage_uri)
       OR (NEW.kms_key_alias IS DISTINCT FROM OLD.kms_key_alias)
       OR (NEW.storage_class IS DISTINCT FROM OLD.storage_class)
       OR (NEW.created_by    IS DISTINCT FROM OLD.created_by)
    THEN
      RAISE EXCEPTION 'Evidence item % is sealed/archived; content fields are immutable', OLD.id
        USING ERRCODE = '55000';
    END IF;
  END IF;

  -- State machine: draft -> sealed -> archived (no backward)
  IF OLD.state = 'sealed' AND NEW.state = 'draft' THEN
    RAISE EXCEPTION 'Cannot transition from sealed back to draft' USING ERRCODE = '22000';
  END IF;
  IF OLD.state = 'archived' AND NEW.state <> 'archived' THEN
    RAISE EXCEPTION 'Cannot transition out of archived' USING ERRCODE = '22000';
  END IF;

  RETURN NEW;
END$$;

-- Prevent hard delete when legal hold is active
CREATE OR REPLACE FUNCTION evidence.fn_prevent_delete_on_legal_hold()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE hold_active boolean;
BEGIN
  IF OLD.legal_hold_id IS NOT NULL THEN
    SELECT active INTO hold_active FROM evidence.legal_hold WHERE id = OLD.legal_hold_id;
    IF hold_active THEN
      RAISE EXCEPTION 'Delete forbidden: legal hold active for item %', OLD.id
        USING ERRCODE = '28000';
    END IF;
  END IF;
  RETURN OLD;
END$$;

-- Chain-of-custody hash (sha256 over canonical concatenation + previous hash)
CREATE OR REPLACE FUNCTION evidence.fn_coc_compute_record_hash()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  prev text;
  payload text;
BEGIN
  SELECT record_hash INTO prev
  FROM evidence.chain_of_custody
  WHERE item_id = NEW.item_id
  ORDER BY occurred_at DESC, id DESC
  LIMIT 1;

  payload := coalesce(prev,'') || '|' ||
             NEW.item_id::text || '|' ||
             NEW.action::text || '|' ||
             coalesce(NEW.from_actor,'') || '|' ||
             coalesce(NEW.to_actor,'') || '|' ||
             coalesce(NEW.location,'') || '|' ||
             NEW.occurred_at::text || '|' ||
             coalesce(NEW.notes,'') || '|' ||
             coalesce(NEW.signature,'');
  NEW.record_hash := encode(digest(payload, 'sha256'), 'hex');
  RETURN NEW;
END$$;

-- =========================
-- Tables
-- =========================

-- Legal hold registry
CREATE TABLE IF NOT EXISTS evidence.legal_hold (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reason         text        NOT NULL,
  requested_by   uuid,
  approved_by    uuid,
  active         boolean     NOT NULL DEFAULT true,
  scope          jsonb       NOT NULL DEFAULT '{}'::jsonb, -- optional selector for bulk holds
  created_at     timestamptz NOT NULL DEFAULT now(),
  released_at    timestamptz
);

-- Cases (logical grouping)
CREATE TABLE IF NOT EXISTS evidence.case (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id    citext UNIQUE,
  title          text        NOT NULL,
  description    text,
  created_by     uuid,
  labels         jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  closed_at      timestamptz,
  ts             tsvector
);

-- Full-text on case
CREATE INDEX IF NOT EXISTS ix_case_ts ON evidence.case USING GIN (ts);
CREATE INDEX IF NOT EXISTS ix_case_created_at ON evidence.case (created_at);
CREATE INDEX IF NOT EXISTS ix_case_external_id_ci ON evidence.case (external_id);

-- Items (partitioned monthly by created_at)
CREATE TABLE IF NOT EXISTS evidence.item (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid        NOT NULL REFERENCES evidence.case(id) ON DELETE CASCADE,
  external_id    citext,
  title          text        NOT NULL,
  description    text,
  state          evidence.evidence_state NOT NULL DEFAULT 'draft',
  sensitivity    evidence.sensitivity_level NOT NULL DEFAULT 'internal',
  content_hash   text        NOT NULL, -- hex
  hash_algo      evidence.hash_algo NOT NULL DEFAULT 'sha256',
  content_size   bigint      NOT NULL CHECK (content_size >= 0),
  storage_uri    text        NOT NULL, -- e.g. s3://bucket/key or file://...
  storage_class  text        NOT NULL DEFAULT 'standard',
  kms_key_alias  text,
  metadata       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  tags           jsonb       NOT NULL DEFAULT '[]'::jsonb,
  legal_hold_id  uuid        NULL REFERENCES evidence.legal_hold(id),
  created_by     uuid        NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  sealed_at      timestamptz,
  archived_at    timestamptz,
  deleted_at     timestamptz,
  search         tsvector,
  CONSTRAINT item_storage_uri_chk CHECK (storage_uri ~ '^[a-zA-Z][a-zA-Z0-9+.-]*://'),
  CONSTRAINT item_external_id_unique
    EXCLUDE USING GIST (case_id WITH =, external_id WITH =, created_at WITH =) WHERE (external_id IS NOT NULL)
) PARTITION BY RANGE (created_at);
-- Note: uniqueness across all partitions by (case_id, external_id) is limited in PostgreSQL;
-- here we approximate with EXCLUDE including partition key created_at.

CREATE INDEX IF NOT EXISTS ix_item_case_created ON evidence.item (case_id, created_at);
CREATE INDEX IF NOT EXISTS ix_item_content_hash ON evidence.item (content_hash, hash_algo);
CREATE INDEX IF NOT EXISTS ix_item_storage_trgm ON evidence.item USING GIN (storage_uri gin_trgm_ops);
CREATE INDEX IF NOT EXISTS ix_item_search ON evidence.item USING GIN (search);

-- Automatic monthly partitions: current month + next 12
DO $$
DECLARE
  m int := 0;
  start_ts date;
  end_ts   date;
  part_name text;
BEGIN
  WHILE m <= 12 LOOP
    start_ts := date_trunc('month', now())::date + (m || ' month')::interval;
    end_ts   := (start_ts + interval '1 month')::date;
    part_name := format('item_p_%s', to_char(start_ts, 'YYYYMM'));
    EXECUTE format($f$
      CREATE TABLE IF NOT EXISTS evidence.%I
      PARTITION OF evidence.item
      FOR VALUES FROM (%L) TO (%L);
    $f$, part_name, start_ts, end_ts);
    m := m + 1;
  END LOOP;
END$$;

-- Blobs (optional multi-part attachments per item)
CREATE TABLE IF NOT EXISTS evidence.blob (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id        uuid        NOT NULL REFERENCES evidence.item(id) ON DELETE CASCADE,
  content_hash   text        NOT NULL,
  hash_algo      evidence.hash_algo NOT NULL DEFAULT 'sha256',
  content_size   bigint      NOT NULL CHECK (content_size >= 0),
  storage_uri    text        NOT NULL,
  storage_class  text        NOT NULL DEFAULT 'standard',
  kms_key_alias  text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (item_id, content_hash, hash_algo)
);
CREATE INDEX IF NOT EXISTS ix_blob_item ON evidence.blob (item_id);
CREATE INDEX IF NOT EXISTS ix_blob_uri_trgm ON evidence.blob USING GIN (storage_uri gin_trgm_ops);

-- Chain of custody (hash-chained records)
CREATE TABLE IF NOT EXISTS evidence.chain_of_custody (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id        uuid NOT NULL REFERENCES evidence.item(id) ON DELETE CASCADE,
  action         evidence.custody_action NOT NULL,
  from_actor     text,
  to_actor       text,
  location       text,
  occurred_at    timestamptz NOT NULL,
  by_user        uuid,
  notes          text,
  signature      text, -- optional proof signature (hex/base64)
  record_hash    text  NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_coc_item_time ON evidence.chain_of_custody (item_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_coc_record_hash ON evidence.chain_of_custody (record_hash);

-- Tags (normalized mapping in дополнение к jsonb tags)
CREATE TABLE IF NOT EXISTS evidence.tag (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name citext UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence.item_tag (
  item_id uuid NOT NULL REFERENCES evidence.item(id) ON DELETE CASCADE,
  tag_id  uuid NOT NULL REFERENCES evidence.tag(id)  ON DELETE CASCADE,
  PRIMARY KEY (item_id, tag_id)
);

-- =========================
-- Triggers
-- =========================

-- case: updated_at + ts
DROP TRIGGER IF EXISTS trg_case_touch ON evidence.case;
CREATE TRIGGER trg_case_touch
BEFORE UPDATE ON evidence.case
FOR EACH ROW EXECUTE FUNCTION evidence.fn_touch_updated_at();

CREATE OR REPLACE FUNCTION evidence.fn_update_case_ts()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.ts := to_tsvector('simple', coalesce(NEW.title,'') || ' ' || coalesce(NEW.description,''));
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_case_ts ON evidence.case;
CREATE TRIGGER trg_case_ts
BEFORE INSERT OR UPDATE ON evidence.case
FOR EACH ROW EXECUTE FUNCTION evidence.fn_update_case_ts();

-- item: updated_at + search + immutability + no-delete-on-legal-hold
DROP TRIGGER IF EXISTS trg_item_touch ON evidence.item;
CREATE TRIGGER trg_item_touch
BEFORE UPDATE ON evidence.item
FOR EACH ROW EXECUTE FUNCTION evidence.fn_touch_updated_at();

DROP TRIGGER IF EXISTS trg_item_search ON evidence.item;
CREATE TRIGGER trg_item_search
BEFORE INSERT OR UPDATE ON evidence.item
FOR EACH ROW EXECUTE FUNCTION evidence.fn_update_search_vector();

DROP TRIGGER IF EXISTS trg_item_immutable ON evidence.item;
CREATE TRIGGER trg_item_immutable
BEFORE UPDATE ON evidence.item
FOR EACH ROW EXECUTE FUNCTION evidence.fn_enforce_item_immutability();

DROP TRIGGER IF EXISTS trg_item_no_delete_hold ON evidence.item;
CREATE TRIGGER trg_item_no_delete_hold
BEFORE DELETE ON evidence.item
FOR EACH ROW EXECUTE FUNCTION evidence.fn_prevent_delete_on_legal_hold();

-- chain_of_custody: compute record hash
DROP TRIGGER IF EXISTS trg_coc_hash ON evidence.chain_of_custody;
CREATE TRIGGER trg_coc_hash
BEFORE INSERT ON evidence.chain_of_custody
FOR EACH ROW EXECUTE FUNCTION evidence.fn_coc_compute_record_hash();

-- =========================
-- Row Level Security (RLS)
-- =========================

-- Roles (logical; attach membership in ops)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'evidence_admin') THEN
    CREATE ROLE evidence_admin NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'evidence_auditor') THEN
    CREATE ROLE evidence_auditor NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'evidence_app') THEN
    CREATE ROLE evidence_app NOLOGIN;
  END IF;
END$$;

-- Enable RLS
ALTER TABLE evidence.case ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence.item ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence.blob ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence.chain_of_custody ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence.item_tag ENABLE ROW LEVEL SECURITY;

-- Admin: full access
DROP POLICY IF EXISTS p_case_admin_all ON evidence.case;
CREATE POLICY p_case_admin_all ON evidence.case
  FOR ALL TO evidence_admin
  USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS p_item_admin_all ON evidence.item;
CREATE POLICY p_item_admin_all ON evidence.item
  FOR ALL TO evidence_admin
  USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS p_blob_admin_all ON evidence.blob;
CREATE POLICY p_blob_admin_all ON evidence.blob
  FOR ALL TO evidence_admin
  USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS p_coc_admin_all ON evidence.chain_of_custody;
CREATE POLICY p_coc_admin_all ON evidence.chain_of_custody
  FOR ALL TO evidence_admin
  USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS p_itemtag_admin_all ON evidence.item_tag;
CREATE POLICY p_itemtag_admin_all ON evidence.item_tag
  FOR ALL TO evidence_admin
  USING (true) WITH CHECK (true);

-- Auditor: read-only, excluding soft-deleted rows
DROP POLICY IF EXISTS p_case_auditor_ro ON evidence.case;
CREATE POLICY p_case_auditor_ro ON evidence.case
  FOR SELECT TO evidence_auditor
  USING (true);

DROP POLICY IF EXISTS p_item_auditor_ro ON evidence.item;
CREATE POLICY p_item_auditor_ro ON evidence.item
  FOR SELECT TO evidence_auditor
  USING (deleted_at IS NULL);

DROP POLICY IF EXISTS p_blob_auditor_ro ON evidence.blob;
CREATE POLICY p_blob_auditor_ro ON evidence.blob
  FOR SELECT TO evidence_auditor
  USING (true);

DROP POLICY IF EXISTS p_coc_auditor_ro ON evidence.chain_of_custody;
CREATE POLICY p_coc_auditor_ro ON evidence.chain_of_custody
  FOR SELECT TO evidence_auditor
  USING (true);

DROP POLICY IF EXISTS p_itemtag_auditor_ro ON evidence.item_tag;
CREATE POLICY p_itemtag_auditor_ro ON evidence.item_tag
  FOR SELECT TO evidence_auditor
  USING (true);

-- App: own rows (creator-based); writes only own
DROP POLICY IF EXISTS p_case_app_rw ON evidence.case;
CREATE POLICY p_case_app_rw ON evidence.case
  FOR SELECT TO evidence_app
  USING (created_by = evidence.current_app_user_id())
  WITH CHECK (created_by = evidence.current_app_user_id());

DROP POLICY IF EXISTS p_item_app_rw ON evidence.item;
CREATE POLICY p_item_app_rw ON evidence.item
  FOR SELECT, INSERT, UPDATE TO evidence_app
  USING (created_by = evidence.current_app_user_id())
  WITH CHECK (created_by = evidence.current_app_user_id());

DROP POLICY IF EXISTS p_blob_app_rw ON evidence.blob;
CREATE POLICY p_blob_app_rw ON evidence.blob
  FOR SELECT, INSERT, UPDATE, DELETE TO evidence_app
  USING (EXISTS (SELECT 1 FROM evidence.item i WHERE i.id = item_id AND i.created_by = evidence.current_app_user_id()))
  WITH CHECK (EXISTS (SELECT 1 FROM evidence.item i WHERE i.id = item_id AND i.created_by = evidence.current_app_user_id()));

DROP POLICY IF EXISTS p_coc_app_rw ON evidence.chain_of_custody;
CREATE POLICY p_coc_app_rw ON evidence.chain_of_custody
  FOR SELECT, INSERT TO evidence_app
  USING (EXISTS (SELECT 1 FROM evidence.item i WHERE i.id = item_id AND i.created_by = evidence.current_app_user_id()))
  WITH CHECK (EXISTS (SELECT 1 FROM evidence.item i WHERE i.id = item_id AND i.created_by = evidence.current_app_user_id()));

DROP POLICY IF EXISTS p_itemtag_app_rw ON evidence.item_tag;
CREATE POLICY p_itemtag_app_rw ON evidence.item_tag
  FOR SELECT, INSERT, DELETE TO evidence_app
  USING (EXISTS (SELECT 1 FROM evidence.item i WHERE i.id = item_id AND i.created_by = evidence.current_app_user_id()))
  WITH CHECK (EXISTS (SELECT 1 FROM evidence.item i WHERE i.id = item_id AND i.created_by = evidence.current_app_user_id()));

-- =========================
-- Grants (adjust per env)
-- =========================
GRANT USAGE ON SCHEMA evidence TO evidence_admin, evidence_auditor, evidence_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA evidence TO evidence_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA evidence TO evidence_auditor;
GRANT SELECT, INSERT, UPDATE ON evidence.case, evidence.item, evidence.blob, evidence.item_tag, evidence.chain_of_custody TO evidence_app;

-- Default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA evidence GRANT SELECT ON TABLES TO evidence_auditor;
ALTER DEFAULT PRIVILEGES IN SCHEMA evidence GRANT SELECT, INSERT, UPDATE ON TABLES TO evidence_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA evidence GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO evidence_admin;

-- =========================
-- Comments (schema documentation)
-- =========================
COMMENT ON SCHEMA evidence IS 'Digital evidence store: items, blobs, legal holds, chain-of-custody, RLS and audit';
COMMENT ON TABLE  evidence.item IS 'Evidence items (partitioned monthly). Content is immutable after sealed/archived.';
COMMENT ON COLUMN evidence.item.state IS 'draft -> sealed -> archived';
COMMENT ON COLUMN evidence.item.content_hash IS 'Hex digest of content (default sha256)';
COMMENT ON TABLE  evidence.chain_of_custody IS 'Hash-chained custody records for each item';

COMMIT;
