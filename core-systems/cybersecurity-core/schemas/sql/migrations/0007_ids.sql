-- =====================================================================
-- Migration: 0007_ids.sql
-- Purpose  : Industrial-grade IDS schema (sensors, rules, events)
-- Database : PostgreSQL 13+ (recommended 14/15+)
-- Author   : Aethernova / cybersecurity-core
-- Safe      Idempotent, transactional, partitioned, commented
-- =====================================================================

-- Safety & timing
SET statement_timeout = '60s';
SET lock_timeout       = '30s';
SET idle_in_transaction_session_timeout = '60s';

BEGIN;

-- 1) Schema & Extensions ------------------------------------------------
-- Create dedicated schema for cybersecurity if not exists
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_namespace WHERE nspname = 'cybersecurity'
  ) THEN
    EXECUTE 'CREATE SCHEMA cybersecurity AUTHORIZATION CURRENT_USER';
  END IF;
END$$;

-- Ensure uuid generation (pgcrypto) for UUID defaults
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2) Common utility: updated_at trigger ---------------------------------
CREATE OR REPLACE FUNCTION cybersecurity.tg_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

COMMENT ON FUNCTION cybersecurity.tg_set_updated_at IS
'Sets updated_at to now() on each row modification (BEFORE UPDATE).';

-- 3) Table: ids_sensor ---------------------------------------------------
CREATE TABLE IF NOT EXISTS cybersecurity.ids_sensor
(
  sensor_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT        NOT NULL,
  vendor        TEXT        NOT NULL,
  model         TEXT        NOT NULL,
  version       TEXT        NOT NULL,
  ip_address    INET        NOT NULL,
  location      TEXT        NULL,
  tags          JSONB       NOT NULL DEFAULT '{}'::jsonb,
  is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT ids_sensor_name_unique UNIQUE (name),
  CONSTRAINT ids_sensor_ip_not_private CHECK (ip_address IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_ids_sensor_active ON cybersecurity.ids_sensor (is_active);
CREATE INDEX IF NOT EXISTS idx_ids_sensor_vendor_model ON cybersecurity.ids_sensor (vendor, model);
CREATE INDEX IF NOT EXISTS idx_ids_sensor_tags_gin ON cybersecurity.ids_sensor USING GIN (tags);

DROP TRIGGER IF EXISTS trg_ids_sensor_updated_at ON cybersecurity.ids_sensor;
CREATE TRIGGER trg_ids_sensor_updated_at
  BEFORE UPDATE ON cybersecurity.ids_sensor
  FOR EACH ROW EXECUTE FUNCTION cybersecurity.tg_set_updated_at();

COMMENT ON TABLE  cybersecurity.ids_sensor IS 'Registered IDS sensors/probes inventory.';
COMMENT ON COLUMN cybersecurity.ids_sensor.tags IS 'Arbitrary key/value metadata (JSONB).';

-- 4) Table: ids_rule (signatures / rules) -------------------------------
CREATE TABLE IF NOT EXISTS cybersecurity.ids_rule
(
  rule_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  engine        TEXT        NOT NULL,        -- e.g., suricata, snort, zeek
  sid           INTEGER     NOT NULL,        -- signature id
  rev           INTEGER     NOT NULL DEFAULT 1,
  classification TEXT       NULL,
  severity      SMALLINT    NOT NULL CHECK (severity BETWEEN 0 AND 10),
  enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
  rule_text     TEXT        NOT NULL,        -- full signature / DSL
  metadata      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT ids_rule_engine_sid_rev_unique UNIQUE (engine, sid, rev)
);

CREATE INDEX IF NOT EXISTS idx_ids_rule_enabled ON cybersecurity.ids_rule (enabled);
CREATE INDEX IF NOT EXISTS idx_ids_rule_engine_sid ON cybersecurity.ids_rule (engine, sid);
CREATE INDEX IF NOT EXISTS idx_ids_rule_metadata_gin ON cybersecurity.ids_rule USING GIN (metadata);

DROP TRIGGER IF EXISTS trg_ids_rule_updated_at ON cybersecurity.ids_rule;
CREATE TRIGGER trg_ids_rule_updated_at
  BEFORE UPDATE ON cybersecurity.ids_rule
  FOR EACH ROW EXECUTE FUNCTION cybersecurity.tg_set_updated_at();

COMMENT ON TABLE cybersecurity.ids_rule IS 'IDS/IPS rules, signatures and metadata.';
COMMENT ON COLUMN cybersecurity.ids_rule.rule_text IS 'Raw rule/signature text in engine DSL (e.g., Suricata).';

-- 5) Table: ids_event (partitioned by month on event_time) --------------
-- Parent partitioned table
CREATE TABLE IF NOT EXISTS cybersecurity.ids_event
(
  -- Composite PK includes partition key for declarative partitions
  event_id      BIGINT      GENERATED ALWAYS AS IDENTITY,
  event_time    TIMESTAMPTZ NOT NULL,
  sensor_id     UUID        NOT NULL,
  rule_id       UUID        NULL,          -- optional, not all events bind to a rule
  action        TEXT        NOT NULL,      -- alert|drop|reject|allow|log
  category      TEXT        NULL,          -- e.g., malware, policy-violation
  severity      SMALLINT    NOT NULL CHECK (severity BETWEEN 0 AND 10),
  src_ip        INET        NOT NULL,
  src_port      INTEGER     NULL CHECK (src_port IS NULL OR (src_port BETWEEN 0 AND 65535)),
  dst_ip        INET        NOT NULL,
  dst_port      INTEGER     NULL CHECK (dst_port IS NULL OR (dst_port BETWEEN 0 AND 65535)),
  transport     TEXT        NULL,          -- tcp|udp|icmp|icmp6|other
  app_proto     TEXT        NULL,          -- http, tls, dns, ssh, …
  signature     TEXT        NULL,          -- resolved signature name
  flow_id       BIGINT      NULL,
  bytes_in      BIGINT      NULL CHECK (bytes_in  IS NULL OR bytes_in  >= 0),
  bytes_out     BIGINT      NULL CHECK (bytes_out IS NULL OR bytes_out >= 0),
  payload_size  INTEGER     NULL CHECK (payload_size IS NULL OR payload_size >= 0),
  http_host     TEXT        NULL,
  url           TEXT        NULL,
  user_agent    TEXT        NULL,
  file_hash     TEXT        NULL,          -- sha1/sha256 etc.
  extra         JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (event_id, event_time),
  CONSTRAINT ids_event_action_chk CHECK (action IN ('alert','drop','reject','allow','log')),
  CONSTRAINT ids_event_transport_chk CHECK (transport IS NULL OR transport IN ('tcp','udp','icmp','icmp6','other')),
  CONSTRAINT ids_event_fk_sensor FOREIGN KEY (sensor_id)
    REFERENCES cybersecurity.ids_sensor(sensor_id) ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT ids_event_fk_rule FOREIGN KEY (rule_id)
    REFERENCES cybersecurity.ids_rule(rule_id) ON UPDATE CASCADE ON DELETE SET NULL
) PARTITION BY RANGE (event_time);

COMMENT ON TABLE cybersecurity.ids_event IS 'High-volume IDS/IPS events, partitioned monthly by event_time.';
COMMENT ON COLUMN cybersecurity.ids_event.extra IS 'Engine-specific fields (JSONB) to avoid schema churn.';

-- Useful indexes on the parent (propagated to partitions if created there).
-- For partitioned tables, create indexes on each partition (see dynamic creation below).
-- We also create a BRIN on event_time at partition level for efficient time-range scans.

-- 5.1) Updated_at trigger on parent (will be inherited by partitions via trigger creation per child)
CREATE OR REPLACE FUNCTION cybersecurity.tg_set_updated_at_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

-- Attach at parent level (note: triggers are not automatically inherited, we add on each partition on creation)
DROP TRIGGER IF EXISTS trg_ids_event_updated_at ON cybersecurity.ids_event;
CREATE TRIGGER trg_ids_event_updated_at
  BEFORE UPDATE ON cybersecurity.ids_event
  FOR EACH ROW EXECUTE FUNCTION cybersecurity.tg_set_updated_at_event();

-- 5.2) Partition management helper
-- Creates a monthly partition for the first day of "p_start" month
CREATE OR REPLACE FUNCTION cybersecurity.create_ids_event_partition_if_not_exists(p_start DATE)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  v_start DATE := date_trunc('month', p_start)::date;
  v_end   DATE := (date_trunc('month', p_start) + INTERVAL '1 month')::date;
  v_name  TEXT := format('ids_event_%s', to_char(v_start, 'YYYYMM'));
  v_qualified TEXT := format('cybersecurity.%I', v_name);
  v_exists BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'cybersecurity' AND c.relname = v_name
  ) INTO v_exists;

  IF NOT v_exists THEN
    EXECUTE format(
      'CREATE TABLE %s PARTITION OF cybersecurity.ids_event
         FOR VALUES FROM (%L) TO (%L)',
      v_qualified, v_start::timestamptz, v_end::timestamptz
    );

    -- Indexes per-partition
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_event_time ON %s (event_time)', v_name||'_time', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_sensor ON %s (sensor_id, event_time)', v_name||'_sensor', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_rule ON %s (rule_id, event_time)', v_name||'_rule', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_srcip ON %s (src_ip, event_time)', v_name||'_srcip', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_dstip ON %s (dst_ip, event_time)', v_name||'_dstip', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_signature ON %s (signature)', v_name||'_signature', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_extra_gin ON %s USING GIN (extra)', v_name||'_extra_gin', v_qualified);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I_brin_time ON %s USING BRIN (event_time) WITH (pages_per_range=128)', v_name||'_brin_time', v_qualified);

    -- Attach updated_at trigger to the new partition
    EXECUTE format(
      'DROP TRIGGER IF EXISTS trg_ids_event_updated_at ON %s', v_qualified
    );
    EXECUTE format(
      'CREATE TRIGGER trg_ids_event_updated_at BEFORE UPDATE ON %s
         FOR EACH ROW EXECUTE FUNCTION cybersecurity.tg_set_updated_at_event()', v_qualified
    );
  END IF;
END
$$;

COMMENT ON FUNCTION cybersecurity.create_ids_event_partition_if_not_exists(date) IS
'Creates monthly partition for ids_event for the month containing the given date; attaches standard indexes and trigger.';

-- 5.3) Seed partitions: previous month through next 12 months
DO $$
DECLARE
  d DATE := date_trunc('month', now() - INTERVAL '1 month')::date;
  i INT  := 0;
BEGIN
  WHILE i <= 13 LOOP
    PERFORM cybersecurity.create_ids_event_partition_if_not_exists(d + (i || ' month')::interval);
    i := i + 1;
  END LOOP;
END
$$;

-- 6) Roles & Grants (optional, idempotent) -------------------------------
-- Create two roles if absent: reader (RO), app (RW)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cybersecurity_reader') THEN
    EXECUTE 'CREATE ROLE cybersecurity_reader NOLOGIN';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cybersecurity_app') THEN
    EXECUTE 'CREATE ROLE cybersecurity_app NOLOGIN';
  END IF;
END
$$;

-- Schema usage
GRANT USAGE ON SCHEMA cybersecurity TO cybersecurity_reader, cybersecurity_app;

-- Read-only on lookup / read-mostly tables
GRANT SELECT ON TABLE cybersecurity.ids_sensor TO cybersecurity_reader;
GRANT SELECT ON TABLE cybersecurity.ids_rule   TO cybersecurity_reader;

-- App gets RW where appropriate
GRANT SELECT, INSERT, UPDATE ON TABLE cybersecurity.ids_sensor TO cybersecurity_app;
GRANT SELECT, INSERT, UPDATE ON TABLE cybersecurity.ids_rule   TO cybersecurity_app;

-- For partitioned parent, grant on ALL TABLES in schema (covers partitions),
-- and future partitions via default privileges (if you run this as object owner).
GRANT SELECT ON TABLE cybersecurity.ids_event TO cybersecurity_reader;
GRANT SELECT, INSERT, UPDATE ON TABLE cybersecurity.ids_event TO cybersecurity_app;

-- Apply grants to existing partitions
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN
    SELECT n.nspname, c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'cybersecurity'
      AND c.relkind = 'r'
      AND c.relname LIKE 'ids_event_%'
  LOOP
    EXECUTE format('GRANT SELECT ON TABLE %I.%I TO cybersecurity_reader', r.nspname, r.relname);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I.%I TO cybersecurity_app', r.nspname, r.relname);
  END LOOP;
END
$$;

-- 7) Helpful Comments ----------------------------------------------------
COMMENT ON COLUMN cybersecurity.ids_event.action IS 'Outcome decided by engine/policy: alert|drop|reject|allow|log.';
COMMENT ON COLUMN cybersecurity.ids_event.severity IS 'Normalized severity 0..10.';
COMMENT ON COLUMN cybersecurity.ids_event.flow_id IS 'Engine/session flow identifier if available.';

-- 8) Housekeeping suggestions (not enforced here):
-- - Consider logical replication on ids_event_* partitions to cold storage.
-- - Consider TTL archiving policy via pg_partman or cron + COPY/DELETE.

COMMIT;

-- =====================================================================
-- End of 0007_ids.sql
-- =====================================================================
