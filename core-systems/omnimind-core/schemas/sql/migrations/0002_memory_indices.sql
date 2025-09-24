-- ops/schemas/sql/migrations/0002_memory_indices.sql
-- Purpose: Industrial-grade indexing for memory subsystem.
-- Target:  PostgreSQL 14+ (recommended 15/16 for HNSW with pgvector >= 0.6.0)
-- Safety:  Uses CREATE INDEX CONCURRENTLY and IF NOT EXISTS where possible.

-- -----------------------------------------------------------------------------
-- Session safety knobs (tune per-env)
-- -----------------------------------------------------------------------------
SET lock_timeout      = '2s';
SET statement_timeout = '10min';
SET maintenance_work_mem = '1GB';

-- -----------------------------------------------------------------------------
-- Required extensions (idempotent)
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;
-- pgvector is required for ANN indexes on embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- -----------------------------------------------------------------------------
-- Notes on expected tables/columns (schema omnimind, adjust if needed):
--   omnimind.memories:
--     id uuid PK, tenant_id uuid, subject_id uuid, kind text, status text,
--     content_json jsonb, content_text text, content_tsv tsvector (optional),
--     embedding vector(768), created_at timestamptz, updated_at timestamptz,
--     deleted_at timestamptz NULL
--   omnimind.memory_chunks:
--     id uuid PK, memory_id uuid FK -> memories(id), chunk_no int,
--     content_text text, content_tsv tsvector (optional),
--     embedding vector(768), metadata jsonb, created_at timestamptz
--   omnimind.memory_edges:
--     src uuid, dst uuid, relation text, weight real,
--     tenant_id uuid, created_at timestamptz
-- If your actual names differ, adjust ON <schema>.<table>(<cols>) below.
-- -----------------------------------------------------------------------------

-- Schema alias (optional). Comment out if you are on "public".
SET LOCAL search_path = public, omnimind, pg_catalog;

-- -----------------------------------------------------------------------------
-- Base hot-path filters for memories
-- -----------------------------------------------------------------------------

-- Cover (tenant_id, subject_id, kind, status, created_at DESC)
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_tenant_subject_kind_status_created
  ON omnimind.memories (tenant_id, subject_id, kind, status, created_at DESC)
  INCLUDE (id, updated_at)
;

-- Recent active (partial) for queries on active rows only
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_active_recent
  ON omnimind.memories (tenant_id, created_at DESC)
  WHERE deleted_at IS NULL
;

-- Updated_at for sync streams/checkpoint scans
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_updated_at
  ON omnimind.memories (updated_at DESC)
;

-- Status hot filter
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_status
  ON omnimind.memories (status)
  WHERE deleted_at IS NULL
;

-- -----------------------------------------------------------------------------
-- Text search / trigram
-- -----------------------------------------------------------------------------

-- Prefer generated tsvector column if present, fallback to expression index
-- tsvector GIN (russian + simple as example; adjust your TS config)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'omnimind' AND table_name = 'memories' AND column_name = 'content_tsv'
  ) THEN
    EXECUTE $DDL$
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_tsv_gin
      ON omnimind.memories
      USING GIN (content_tsv)
    $DDL$;
  ELSE
    EXECUTE $DDL$
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_tsv_gin
      ON omnimind.memories
      USING GIN (to_tsvector('simple', coalesce(content_text,'')))
    $DDL$;
  END IF;
END$$;

-- Trigram index for fuzzy search on content_text
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_text_trgm
  ON omnimind.memories
  USING GIN (content_text gin_trgm_ops)
;

-- JSONB metadata (if present)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'omnimind' AND table_name = 'memories' AND column_name = 'content_json'
  ) THEN
    EXECUTE $DDL$
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_jsonb
      ON omnimind.memories
      USING GIN (content_json jsonb_path_ops)
    $DDL$;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- ANN (Approximate Nearest Neighbors) for embeddings
-- -----------------------------------------------------------------------------
-- Choose HNSW if pgvector >= 0.6.0; otherwise IVFFlat. Both are idempotent here.
-- Distance: cosine. Adjust lists/ef_* per workload.

-- Create HNSW on memories.embedding
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'omnimind' AND table_name = 'memories' AND column_name = 'embedding'
  ) THEN
    BEGIN
      EXECUTE $DDL$
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_embed_hnsw
        ON omnimind.memories
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 200)
      $DDL$;
    EXCEPTION WHEN undefined_object THEN
      -- Fallback to IVFFlat if HNSW is not available
      EXECUTE $DDL$
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memories_embed_ivfflat
        ON omnimind.memories
        USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 200)
      $DDL$;
    END;
  END IF;
END$$;

-- Same for memory_chunks.embedding
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'omnimind' AND table_name = 'memory_chunks' AND column_name = 'embedding'
  ) THEN
    BEGIN
      EXECUTE $DDL$
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memchunks_embed_hnsw
        ON omnimind.memory_chunks
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 200)
      $DDL$;
    EXCEPTION WHEN undefined_object THEN
      EXECUTE $DDL$
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memchunks_embed_ivfflat
        ON omnimind.memory_chunks
        USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 400)
      $DDL$;
    END;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- memory_chunks locality and search
-- -----------------------------------------------------------------------------

-- FK locality + time for chunk scans
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memchunks_memory_time
  ON omnimind.memory_chunks (memory_id, created_at DESC)
  INCLUDE (chunk_no)
;

-- Optional tsvector for chunk content
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'omnimind' AND table_name = 'memory_chunks' AND column_name = 'content_tsv'
  ) THEN
    EXECUTE $DDL$
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memchunks_tsv_gin
      ON omnimind.memory_chunks
      USING GIN (content_tsv)
    $DDL$;
  ELSIF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'omnimind' AND table_name = 'memory_chunks' AND column_name = 'content_text'
  ) THEN
    EXECUTE $DDL$
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memchunks_text_trgm
      ON omnimind.memory_chunks
      USING GIN (content_text gin_trgm_ops)
    $DDL$;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- Graph/relations (edges)
-- -----------------------------------------------------------------------------

-- Fast adjacency by tenant + src
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memedges_src
  ON omnimind.memory_edges (tenant_id, src, relation)
  INCLUDE (dst, weight, created_at)
;

-- Reverse adjacency by tenant + dst
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_memedges_dst
  ON omnimind.memory_edges (tenant_id, dst, relation)
  INCLUDE (src, weight, created_at)
;

-- Unique edge per relation to prevent duplicates (optional; adjust if needed)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname = 'omnimind' AND indexname = 'ux_memedges_unique'
  ) THEN
    -- Use a UNIQUE index with NULLS NOT DISTINCT if PG15+; otherwise default UNIQUE
    BEGIN
      EXECUTE $DDL$
        CREATE UNIQUE INDEX CONCURRENTLY ux_memedges_unique
        ON omnimind.memory_edges (tenant_id, src, dst, relation)
      $DDL$;
    EXCEPTION WHEN feature_not_supported THEN
      -- Fallback (should not trigger on supported versions)
      EXECUTE $DDL$
        CREATE UNIQUE INDEX CONCURRENTLY ux_memedges_unique
        ON omnimind.memory_edges (tenant_id, src, dst, relation)
      $DDL$;
    END;
  END IF;
END$$;

-- -----------------------------------------------------------------------------
-- BRIN for large append-only timelines (cheap index for audits/retention scans)
-- -----------------------------------------------------------------------------

-- BRIN on created_at for memories (pages_per_range tuned)
CREATE INDEX CONCURRENTLY IF NOT EXISTS brin_memories_created_at
  ON omnimind.memories
  USING brin (created_at) WITH (pages_per_range = 64)
;

-- BRIN on memory_chunks.created_at
CREATE INDEX CONCURRENTLY IF NOT EXISTS brin_memchunks_created_at
  ON omnimind.memory_chunks
  USING brin (created_at) WITH (pages_per_range = 64)
;

-- -----------------------------------------------------------------------------
-- Housekeeping: comments for catalog visibility
-- -----------------------------------------------------------------------------
COMMENT ON INDEX ix_memories_tenant_subject_kind_status_created IS
  'Hot-path: tenant/subject/kind/status with created_at DESC, INCLUDE (id, updated_at)';
COMMENT ON INDEX ix_memories_active_recent IS
  'Partial index for active (deleted_at IS NULL) memories, ordered by created_at';
COMMENT ON INDEX ix_memories_text_trgm IS
  'GIN trigram index for fuzzy search on content_text';
COMMENT ON INDEX ix_memories_jsonb IS
  'GIN jsonb_path_ops for content_json metadata queries';
COMMENT ON INDEX ix_memories_updated_at IS
  'Support sync/checkpoint scans by updated_at';
COMMENT ON INDEX ix_memedges_src IS
  'Adjacency by src for graph traversals with tenant scope';
COMMENT ON INDEX ix_memedges_dst IS
  'Adjacency by dst for reverse graph traversals with tenant scope';
COMMENT ON INDEX brin_memories_created_at IS
  'BRIN for large timeline scans on memories.created_at';
COMMENT ON INDEX brin_memchunks_created_at IS
  'BRIN for large timeline scans on memory_chunks.created_at';

-- End of 0002_memory_indices.sql
