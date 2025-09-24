-- ledger-core/schemas/sql/migrations/0002_anchors.sql
-- Purpose: On-chain anchors (Merkle roots, tx references, block refs) for ledger-core
-- Requires: PostgreSQL 13+ (tested with 14/15)
-- Notes:
--  - This is an "UP" migration. Prepare a paired file 0002_anchors.down.sql for rollback if your runner supports it.
--  - All CREATEs are idempotent-safe via IF NOT EXISTS or guarded DO blocks.
--  - RLS is enabled with a permissive default; tighten policies if multi-tenant.

BEGIN;

-- ------------------------------------------------------------
-- 0) Ensure schema
-- ------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS ledger AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA ledger IS 'Logical schema for ledger-core domain objects';

-- ------------------------------------------------------------
-- 1) Enumerations (stable wire values; extend only by appending)
-- ------------------------------------------------------------

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'anchor_chain') THEN
    CREATE TYPE ledger.anchor_chain AS ENUM ('internal', 'ethereum', 'bitcoin', 'other');
    COMMENT ON TYPE ledger.anchor_chain IS 'Anchor chain identifiers';
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subject_type') THEN
    CREATE TYPE ledger.subject_type AS ENUM ('transaction', 'document', 'state', 'block');
    COMMENT ON TYPE ledger.subject_type IS 'What is being anchored';
  END IF;
END$$;

-- ------------------------------------------------------------
-- 2) Helper objects
-- ------------------------------------------------------------

-- Validate lowercase hex with even length (for tx/block hashes) - optional guard
CREATE OR REPLACE FUNCTION ledger.is_hex_even(p text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT p ~ '^[0-9a-f]+$' AND length(p) % 2 = 0
$$;

COMMENT ON FUNCTION ledger.is_hex_even(text) IS 'True if text is lowercase hex string of even length';

-- ------------------------------------------------------------
-- 3) Main table: anchors
-- ------------------------------------------------------------

-- Anchors: one row per on-chain anchoring event (e.g., Merkle root committed in a tx)
-- Uniqueness constraints ensure no duplicate tx per chain and no duplicate (chain,block,root).
CREATE TABLE IF NOT EXISTS ledger.anchors (
    id               bigserial PRIMARY KEY,
    chain            ledger.anchor_chain NOT NULL,
    chain_id         text                NOT NULL DEFAULT 'mainnet', -- e.g., "mainnet", "sepolia", "internal"
    subject_type     ledger.subject_type NOT NULL,
    subject_id       text                NOT NULL,                    -- e.g., UUID/URN/TxID from application domain
    merkle_root      bytea               NOT NULL,                    -- 32/64 bytes depending on algo
    merkle_hash_alg  text                NOT NULL DEFAULT 'sha256',   -- normalized lowercase name of hash algorithm
    tx_hash          text,                                           -- hex (chain specific format)
    block_number     bigint,                                         -- block height (>=0)
    block_hash       text,                                           -- hex
    anchored_at      timestamptz         NOT NULL DEFAULT now(),     -- server time when recorded
    observed_at      timestamptz,                                    -- on-chain observation time (oracle)
    attributes       jsonb               NOT NULL DEFAULT '{}'::jsonb, -- extra chain/provider metadata
    created_by       text,                                           -- issuer/principal
    -- Data integrity
    CONSTRAINT anchors_subject_ck CHECK (length(subject_id) BETWEEN 1 AND 512),
    CONSTRAINT anchors_merkle_root_ck CHECK (octet_length(merkle_root) BETWEEN 16 AND 128),
    CONSTRAINT anchors_tx_hash_hex_ck CHECK (tx_hash IS NULL OR ledger.is_hex_even(tx_hash)),
    CONSTRAINT anchors_block_hash_hex_ck CHECK (block_hash IS NULL OR ledger.is_hex_even(block_hash)),
    CONSTRAINT anchors_block_number_ck CHECK (block_number IS NULL OR block_number >= 0)
);

COMMENT ON TABLE ledger.anchors IS 'On-chain anchor records tying ledger subjects to blockchain references';
COMMENT ON COLUMN ledger.anchors.chain IS 'Target chain enum';
COMMENT ON COLUMN ledger.anchors.chain_id IS 'Logical chain id/network name';
COMMENT ON COLUMN ledger.anchors.subject_type IS 'Type of anchored subject';
COMMENT ON COLUMN ledger.anchors.subject_id IS 'Application-level subject identifier (opaque)';
COMMENT ON COLUMN ledger.anchors.merkle_root IS 'Binary Merkle root (bytea)';
COMMENT ON COLUMN ledger.anchors.merkle_hash_alg IS 'Hash algorithm used to compute Merkle root (e.g., sha256, blake2b256)';
COMMENT ON COLUMN ledger.anchors.tx_hash IS 'On-chain transaction hash (lowercase hex)';
COMMENT ON COLUMN ledger.anchors.block_number IS 'On-chain block height';
COMMENT ON COLUMN ledger.anchors.block_hash IS 'On-chain block hash (lowercase hex)';
COMMENT ON COLUMN ledger.anchors.anchored_at IS 'Server timestamp of anchor registration';
COMMENT ON COLUMN ledger.anchors.observed_at IS 'Observed on-chain time, if provided by indexer/oracle';
COMMENT ON COLUMN ledger.anchors.attributes IS 'Free-form metadata (JSONB) for provider-specific details';
COMMENT ON COLUMN ledger.anchors.created_by IS 'Who recorded the anchor (service/user principal)';

-- Functional uniqueness constraints (NULLs allowed)
-- 1) One tx per chain (prevents duplicates) when tx_hash present
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'anchors_tx_unique'
       AND conrelid = 'ledger.anchors'::regclass
  ) THEN
    ALTER TABLE ledger.anchors
      ADD CONSTRAINT anchors_tx_unique
      UNIQUE NULLS NOT DISTINCT (chain, chain_id, tx_hash);
  END IF;
END$$;

-- 2) Prevent duplicates for same (chain, block_number, merkle_root) when provided
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'anchors_block_root_unique'
       AND conrelid = 'ledger.anchors'::regclass
  ) THEN
    ALTER TABLE ledger.anchors
      ADD CONSTRAINT anchors_block_root_unique
      UNIQUE NULLS NOT DISTINCT (chain, chain_id, block_number, merkle_root);
  END IF;
END$$;

-- 3) Ensure subject can be anchored multiple times but not duplicated for the same tx
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'anchors_subject_tx_unique'
       AND conrelid = 'ledger.anchors'::regclass
  ) THEN
    ALTER TABLE ledger.anchors
      ADD CONSTRAINT anchors_subject_tx_unique
      UNIQUE NULLS NOT DISTINCT (subject_type, subject_id, chain, chain_id, tx_hash);
  END IF;
END$$;

-- ------------------------------------------------------------
-- 4) Indexes for typical queries
-- ------------------------------------------------------------

-- Fast lookups by subject
CREATE INDEX IF NOT EXISTS ix_anchors_subject
  ON ledger.anchors (subject_type, subject_id);

-- Chain/block navigations
CREATE INDEX IF NOT EXISTS ix_anchors_chain_block
  ON ledger.anchors (chain, chain_id, block_number DESC);

-- By tx hash
CREATE INDEX IF NOT EXISTS ix_anchors_tx
  ON ledger.anchors (chain, chain_id, tx_hash);

-- Search by Merkle root (hash opclass offers little benefit on bytea; btree works for exact)
CREATE INDEX IF NOT EXISTS ix_anchors_merkle_root
  ON ledger.anchors (merkle_root);

-- GIN on attributes for structured queries
CREATE INDEX IF NOT EXISTS ix_anchors_attributes_gin
  ON ledger.anchors USING gin (attributes jsonb_path_ops);

-- Time-based for housekeeping
CREATE INDEX IF NOT EXISTS ix_anchors_anchored_at
  ON ledger.anchors (anchored_at DESC);

-- ------------------------------------------------------------
-- 5) Audit table (append-only)
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ledger.anchor_audit (
    audit_id     bigserial PRIMARY KEY,
    anchor_id    bigint NOT NULL REFERENCES ledger.anchors(id) ON DELETE CASCADE,
    action       text   NOT NULL CHECK (action IN ('insert','update','delete')),
    at           timestamptz NOT NULL DEFAULT now(),
    actor        text,
    before_row   jsonb,
    after_row    jsonb
);

COMMENT ON TABLE ledger.anchor_audit IS 'Append-only audit trail for anchors table changes';

-- Minimal trigger to capture row changes; keep it simple and deterministic
CREATE OR REPLACE FUNCTION ledger.trg_anchor_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO ledger.anchor_audit(anchor_id, action, actor, after_row)
    VALUES (NEW.id, 'insert', current_user, to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO ledger.anchor_audit(anchor_id, action, actor, before_row, after_row)
    VALUES (NEW.id, 'update', current_user, to_jsonb(OLD), to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO ledger.anchor_audit(anchor_id, action, actor, before_row)
    VALUES (OLD.id, 'delete', current_user, to_jsonb(OLD));
    RETURN OLD;
  END IF;
  RETURN NULL;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
     WHERE tgname = 'trg_anchor_audit_row'
       AND tgrelid = 'ledger.anchors'::regclass
  ) THEN
    CREATE TRIGGER trg_anchor_audit_row
    AFTER INSERT OR UPDATE OR DELETE ON ledger.anchors
    FOR EACH ROW EXECUTE FUNCTION ledger.trg_anchor_audit();
  END IF;
END$$;

-- ------------------------------------------------------------
-- 6) Row-Level Security (RLS) — optional baseline
--     Enabled with permissive default; refine in your overlay migrations.
-- ------------------------------------------------------------
ALTER TABLE ledger.anchors ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'ledger' AND tablename = 'anchors' AND policyname = 'anchors_allow_all_read'
  ) THEN
    CREATE POLICY anchors_allow_all_read
      ON ledger.anchors
      FOR SELECT
      USING (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'ledger' AND tablename = 'anchors' AND policyname = 'anchors_allow_all_write'
  ) THEN
    CREATE POLICY anchors_allow_all_write
      ON ledger.anchors
      FOR INSERT, UPDATE, DELETE
      USING (true)
      WITH CHECK (true);
  END IF;
END$$;

COMMENT ON POLICY anchors_allow_all_read ON ledger.anchors IS 'Baseline RLS: allow read by all db users (tighten in prod)';
COMMENT ON POLICY anchors_allow_all_write ON ledger.anchors IS 'Baseline RLS: allow write by all db users (tighten in prod)';

-- ------------------------------------------------------------
-- 7) Housekeeping and ownership
-- ------------------------------------------------------------

-- Optional: set table owners to a dedicated role (replace with your role if needed)
-- ALTER TABLE ledger.anchors      OWNER TO ledger_owner;
-- ALTER TABLE ledger.anchor_audit OWNER TO ledger_owner;

COMMIT;
