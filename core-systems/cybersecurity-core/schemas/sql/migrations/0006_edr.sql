-- =============================================================================
-- 0006_edr.sql | Cybersecurity Core – EDR Domain (PostgreSQL 14+)
-- =============================================================================
-- Features:
-- - Multi-tenant isolation (org_id) with Row-Level Security (RLS)
-- - HASH partitioning by org_id
-- - Strong enums for severity/confidence/status/event/action types
-- - Normalized EDR domain: agents, events, detections, actions, quarantine,
--   policies, rules, processes, heartbeats, enrichments, suppressions
-- - Audit log for sensitive tables
-- - Robust indexes: GIN(JSONB), pg_trgm, partials
-- - Triggers: updated_at
-- - Idempotent creation (safe re-run)
-- =============================================================================

BEGIN;

SET client_min_messages = WARNING;
SET statement_timeout = '90s';
SET lock_timeout = '20s';
SET idle_in_transaction_session_timeout = '60s';

-- Extensions (idempotent)
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- =============================================================================
-- ENUM types (idempotent)
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_severity_enum') THEN
    EXECUTE $$CREATE TYPE edr_severity_enum AS ENUM ('info','low','medium','high','critical')$$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_confidence_enum') THEN
    EXECUTE $$CREATE TYPE edr_confidence_enum AS ENUM ('low','medium','high','confirmed')$$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_detection_status_enum') THEN
    EXECUTE $$CREATE TYPE edr_detection_status_enum AS ENUM
      ('open','in_progress','contained','resolved','dismissed','false_positive','suppressed')$$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_action_type_enum') THEN
    EXECUTE $$CREATE TYPE edr_action_type_enum AS ENUM
      ('isolate_host','release_isolation','kill_process','quarantine_file','restore_file',
       'block_hash','unblock_hash','block_ip','unblock_ip','scan','remediate','custom')$$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_action_status_enum') THEN
    EXECUTE $$CREATE TYPE edr_action_status_enum AS ENUM
      ('requested','executing','succeeded','failed','cancelled')$$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_event_type_enum') THEN
    EXECUTE $$CREATE TYPE edr_event_type_enum AS ENUM
      ('process_start','process_end','file_create','file_modify','file_delete','network_connect',
       'dns_query','registry_modify','module_load','driver_load','user_login','privilege_escalation',
       'policy_change','alert','telemetry','heartbeat','other')$$;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'edr_agent_status_enum') THEN
    EXECUTE $$CREATE TYPE edr_agent_status_enum AS ENUM
      ('online','offline','installing','error','deprecated','unsupported','uninstalling')$$;
  END IF;
END$$;

-- =============================================================================
-- Helper functions (idempotent)
-- =============================================================================
-- updated_at trigger function
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at' AND pg_function_is_visible(oid)
  ) THEN
    EXECUTE $SQL$
      CREATE FUNCTION set_updated_at() RETURNS trigger AS $fn$
      BEGIN
        NEW.updated_at := now();
        RETURN NEW;
      END
      $fn$ LANGUAGE plpgsql;
    $SQL$;
  END IF;
END$$;

-- Generic audit function for EDR tables
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc WHERE proname = 'audit_edr' AND pg_function_is_visible(oid)
  ) THEN
    EXECUTE $SQL$
      CREATE FUNCTION audit_edr() RETURNS trigger AS $fn$
      DECLARE
        v_action text := TG_OP;
        v_org uuid;
        v_obj_id text;
      BEGIN
        -- Try to detect org_id and object id generically
        v_org := COALESCE(
          CASE WHEN TG_OP IN ('INSERT','UPDATE') THEN NEW.org_id END,
          CASE WHEN TG_OP = 'DELETE' THEN OLD.org_id END
        );
        v_obj_id := COALESCE(
          CASE WHEN TG_OP IN ('INSERT','UPDATE') THEN NEW.id::text END,
          CASE WHEN TG_OP = 'DELETE' THEN OLD.id::text END,
          NULL
        );

        INSERT INTO edr_audit(org_id, object_type, object_id, table_name, action, actor, occurred_at, txid, old_row, new_row)
        VALUES (
          v_org,
          TG_ARGV[0],     -- object_type provided by trigger binding
          v_obj_id,
          TG_TABLE_NAME,
          SUBSTRING(v_action,1,1),
          current_user,
          now(),
          txid_current(),
          CASE WHEN v_action = 'UPDATE' OR v_action = 'DELETE' THEN to_jsonb(OLD) END,
          CASE WHEN v_action = 'UPDATE' OR v_action = 'INSERT' THEN to_jsonb(NEW) END
        );

        IF v_action = 'DELETE' THEN
          RETURN OLD;
        ELSE
          RETURN NEW;
        END IF;
      END
      $fn$ LANGUAGE plpgsql;
    $SQL$;
  END IF;
END$$;

-- =============================================================================
-- Audit table
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_audit (
  id           bigserial PRIMARY KEY,
  org_id       uuid,
  object_type  text NOT NULL,         -- e.g., 'agent','detection','action','quarantine','policy','rule'
  object_id    text,
  table_name   text NOT NULL,
  action       char(1) NOT NULL CHECK (action IN ('I','U','D')),
  actor        text NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  txid         bigint NOT NULL,
  old_row      jsonb,
  new_row      jsonb
);

-- =============================================================================
-- Core: Agents
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_agents (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL,
  asset_id         uuid NOT NULL,
  vendor           text NOT NULL,              -- vendor name (e.g., CrowdStrike, Defender, SentinelOne)
  agent_uid        text,                       -- vendor's agent id
  device_id        text,                       -- optional device id
  version          text,
  status           edr_agent_status_enum NOT NULL DEFAULT 'offline',
  last_heartbeat   timestamptz,
  installed_at     timestamptz,
  registered_at    timestamptz,
  policy_uid       text,
  capabilities     jsonb NOT NULL DEFAULT '{}'::jsonb,
  settings         jsonb NOT NULL DEFAULT '{}'::jsonb,
  health_score     numeric(5,2) NOT NULL DEFAULT 100 CHECK (health_score >= 0 AND health_score <= 100),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_edr_agents_asset FOREIGN KEY (asset_id, org_id)
    REFERENCES assets (id, org_id) ON DELETE CASCADE,
  CONSTRAINT uq_edr_agent_org_vendor_uid UNIQUE (org_id, vendor, agent_uid)
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_agents_p%s PARTITION OF edr_agents
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_edr_agents_org_asset   ON edr_agents (org_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_edr_agents_org_vendor  ON edr_agents (org_id, vendor);
CREATE INDEX IF NOT EXISTS idx_edr_agents_org_status  ON edr_agents (org_id, status);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_edr_agents_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_edr_agents_updated_at BEFORE UPDATE ON edr_agents
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- =============================================================================
-- Heartbeats
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_heartbeats (
  id             bigserial PRIMARY KEY,
  org_id         uuid NOT NULL,
  agent_id       uuid NOT NULL,
  asset_id       uuid NOT NULL,
  heartbeat_at   timestamptz NOT NULL DEFAULT now(),
  agent_status   edr_agent_status_enum NOT NULL,
  metrics        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_hb_agent FOREIGN KEY (agent_id) REFERENCES edr_agents (id) ON DELETE CASCADE,
  CONSTRAINT fk_hb_asset FOREIGN KEY (asset_id, org_id) REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_heartbeats_p%s PARTITION OF edr_heartbeats
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_hb_org_agent_time ON edr_heartbeats (org_id, agent_id, heartbeat_at DESC);

-- =============================================================================
-- Events (raw/normalized telemetry)
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_events (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL,
  asset_id         uuid NOT NULL,
  agent_id         uuid,
  vendor           text,
  vendor_event_id  text,
  event_time       timestamptz NOT NULL,
  ingested_at      timestamptz NOT NULL DEFAULT now(),
  event_type       edr_event_type_enum NOT NULL,
  severity         edr_severity_enum,
  user_name        citext,
  process_name     text,
  process_path     text,
  process_cmdline  text,
  process_sha256   text,
  parent_process   text,
  parent_pid       bigint,
  pid              bigint,
  file_path        text,
  file_sha256      text,
  registry_key     text,
  domain           text,
  src_ip           inet,
  dst_ip           inet,
  src_port         integer,
  dst_port         integer,
  protocol         text,
  container_id     text,
  k8s_pod          text,
  k8s_namespace    text,
  raw_event        jsonb NOT NULL,
  attributes       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_ev_asset FOREIGN KEY (asset_id, org_id) REFERENCES assets (id, org_id) ON DELETE CASCADE,
  CONSTRAINT fk_ev_agent FOREIGN KEY (agent_id) REFERENCES edr_agents (id) ON DELETE SET NULL
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_events_p%s PARTITION OF edr_events
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_ev_org_time_type   ON edr_events (org_id, event_time DESC, event_type);
CREATE INDEX IF NOT EXISTS idx_ev_org_proc_trgm   ON edr_events USING GIN (process_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_ev_org_file_trgm   ON edr_events USING GIN (file_path gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_ev_org_raw_gin     ON edr_events USING GIN (raw_event);
CREATE INDEX IF NOT EXISTS idx_ev_org_attrs_gin   ON edr_events USING GIN (attributes);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_ev_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_ev_updated_at BEFORE UPDATE ON edr_events
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- =============================================================================
-- Detections (alerts/findings)
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_detections (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL,
  asset_id           uuid NOT NULL,
  agent_id           uuid,
  vendor             text NOT NULL,
  detection_uid      text,                      -- vendor detection id
  detection_source   text,                      -- sensor/analytics pipe name
  event_time         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  severity           edr_severity_enum NOT NULL,
  confidence         edr_confidence_enum NOT NULL DEFAULT 'medium',
  status             edr_detection_status_enum NOT NULL DEFAULT 'open',
  rule_uid           text,
  rule_name          text,
  rule_version       text,
  mitre_tactic       text,
  mitre_technique    text,
  mitre_subtechnique text,
  category           text,
  description        text,
  process_name       text,
  process_path       text,
  process_sha256     text,
  file_path          text,
  file_sha256        text,
  user_name          citext,
  src_ip             inet,
  dst_ip             inet,
  dst_port           integer,
  protocol           text,
  correlation_id     text,
  parent_detection_id uuid,
  labels             jsonb NOT NULL DEFAULT '{}'::jsonb,
  attributes         jsonb NOT NULL DEFAULT '{}'::jsonb,
  evidence           jsonb,
  triage_owner       text,
  assigned_to        text,
  closed_at          timestamptz,
  close_reason       text,
  CONSTRAINT fk_det_asset FOREIGN KEY (asset_id, org_id) REFERENCES assets (id, org_id) ON DELETE CASCADE,
  CONSTRAINT fk_det_agent FOREIGN KEY (agent_id) REFERENCES edr_agents (id) ON DELETE SET NULL
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_detections_p%s PARTITION OF edr_detections
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_det_org_vendor_uid ON edr_detections (org_id, vendor, COALESCE(detection_uid,''));
CREATE INDEX IF NOT EXISTS idx_det_org_time_sev   ON edr_detections (org_id, created_at DESC, severity);
CREATE INDEX IF NOT EXISTS idx_det_org_status     ON edr_detections (org_id, status);
CREATE INDEX IF NOT EXISTS idx_det_labels_gin     ON edr_detections USING GIN (labels);
CREATE INDEX IF NOT EXISTS idx_det_attrs_gin      ON edr_detections USING GIN (attributes);
CREATE INDEX IF NOT EXISTS idx_det_evidence_gin   ON edr_detections USING GIN (evidence);
CREATE INDEX IF NOT EXISTS idx_det_proc_trgm      ON edr_detections USING GIN (process_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_det_file_trgm      ON edr_detections USING GIN (file_path gin_trgm_ops);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_det_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_det_updated_at BEFORE UPDATE ON edr_detections
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- Audit for detections
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_det_audit_iud') THEN
    EXECUTE $$CREATE TRIGGER t_det_audit_iud
             AFTER INSERT OR UPDATE OR DELETE ON edr_detections
             FOR EACH ROW EXECUTE FUNCTION audit_edr('detection')$$;
  END IF;
END$$;

-- =============================================================================
-- Actions (response)
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_actions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL,
  detection_id     uuid,
  agent_id         uuid,
  asset_id         uuid,
  action_type      edr_action_type_enum NOT NULL,
  status           edr_action_status_enum NOT NULL DEFAULT 'requested',
  requested_by     text NOT NULL DEFAULT current_user,
  requested_at     timestamptz NOT NULL DEFAULT now(),
  executed_by      text,
  executed_at      timestamptz,
  failure_reason   text,
  parameters       jsonb NOT NULL DEFAULT '{}'::jsonb,   -- input
  result           jsonb,                                 -- output/result
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_act_det   FOREIGN KEY (detection_id) REFERENCES edr_detections (id) ON DELETE SET NULL,
  CONSTRAINT fk_act_agent FOREIGN KEY (agent_id)     REFERENCES edr_agents (id) ON DELETE SET NULL,
  CONSTRAINT fk_act_asset FOREIGN KEY (asset_id, org_id) REFERENCES assets (id, org_id) ON DELETE SET NULL
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_actions_p%s PARTITION OF edr_actions
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_act_org_status_type_time ON edr_actions (org_id, status, action_type, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_org_det              ON edr_actions (org_id, detection_id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_act_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_act_updated_at BEFORE UPDATE ON edr_actions
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- Audit for actions
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_act_audit_iud') THEN
    EXECUTE $$CREATE TRIGGER t_act_audit_iud
             AFTER INSERT OR UPDATE OR DELETE ON edr_actions
             FOR EACH ROW EXECUTE FUNCTION audit_edr('action')$$;
  END IF;
END$$;

-- =============================================================================
-- Quarantine files
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_quarantine_files (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL,
  detection_id     uuid,
  agent_id         uuid,
  asset_id         uuid NOT NULL,
  path             text NOT NULL,
  sha256           text,
  size_bytes       bigint,
  reason           text,
  quarantined_at   timestamptz NOT NULL DEFAULT now(),
  restored_at      timestamptz,
  storage_ref      text,                    -- storage pointer (vault/S3/etc.)
  attributes       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_qf_det   FOREIGN KEY (detection_id) REFERENCES edr_detections (id) ON DELETE SET NULL,
  CONSTRAINT fk_qf_agent FOREIGN KEY (agent_id)     REFERENCES edr_agents (id) ON DELETE SET NULL,
  CONSTRAINT fk_qf_asset FOREIGN KEY (asset_id, org_id) REFERENCES assets (id, org_id) ON DELETE CASCADE
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_quarantine_files_p%s PARTITION OF edr_quarantine_files
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_qf_org_path_sha ON edr_quarantine_files (org_id, path, COALESCE(sha256,''));
CREATE INDEX IF NOT EXISTS idx_qf_org_time           ON edr_quarantine_files (org_id, quarantined_at DESC);
CREATE INDEX IF NOT EXISTS idx_qf_path_trgm          ON edr_quarantine_files USING GIN (path gin_trgm_ops);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_qf_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_qf_updated_at BEFORE UPDATE ON edr_quarantine_files
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- Audit for quarantine
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_qf_audit_iud') THEN
    EXECUTE $$CREATE TRIGGER t_qf_audit_iud
             AFTER INSERT OR UPDATE OR DELETE ON edr_quarantine_files
             FOR EACH ROW EXECUTE FUNCTION audit_edr('quarantine')$$;
  END IF;
END$$;

-- =============================================================================
-- Policies and Rules
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_policy_versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  vendor        text NOT NULL,
  name          text NOT NULL,
  version       text NOT NULL,
  is_active     boolean NOT NULL DEFAULT false,
  created_by    text NOT NULL DEFAULT current_user,
  created_at    timestamptz NOT NULL DEFAULT now(),
  rolled_out_at timestamptz,
  policy_doc    jsonb NOT NULL,          -- vendor policy json
  policy_hash   text,                    -- sha256 of normalized doc
  notes         text,
  CONSTRAINT uq_policy_org_vendor_name_version UNIQUE (org_id, vendor, name, version)
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_policy_versions_p%s PARTITION OF edr_policy_versions
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_policy_org_vendor_active ON edr_policy_versions (org_id, vendor, is_active);

-- Rules
CREATE TABLE IF NOT EXISTS edr_rule_versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  vendor        text NOT NULL,
  rule_uid      text NOT NULL,           -- vendor rule id
  rule_name     text,
  version       text NOT NULL,
  enabled       boolean NOT NULL DEFAULT true,
  created_by    text NOT NULL DEFAULT current_user,
  created_at    timestamptz NOT NULL DEFAULT now(),
  tags          text[],
  query         text,                    -- rule query / KQL / XQL
  sigma_yaml    text,                    -- optional Sigma form
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT uq_rule_org_vendor_uid_version UNIQUE (org_id, vendor, rule_uid, version)
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_rule_versions_p%s PARTITION OF edr_rule_versions
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_rule_org_vendor_enabled ON edr_rule_versions (org_id, vendor, enabled);

-- =============================================================================
-- Processes (normalized)
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_processes (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL,
  asset_id         uuid NOT NULL,
  agent_id         uuid,
  event_time       timestamptz NOT NULL,
  pid              bigint,
  ppid             bigint,
  process_name     text,
  process_path     text,
  command_line     text,
  sha256           text,
  user_name        citext,
  session_id       text,
  integrity_level  text,
  first_seen       timestamptz NOT NULL DEFAULT now(),
  last_seen        timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_proc_asset FOREIGN KEY (asset_id, org_id) REFERENCES assets (id, org_id) ON DELETE CASCADE,
  CONSTRAINT fk_proc_agent FOREIGN KEY (agent_id) REFERENCES edr_agents (id) ON DELETE SET NULL
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_processes_p%s PARTITION OF edr_processes
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_proc_org_asset_pid_time ON edr_processes (org_id, asset_id, pid, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_proc_name_trgm           ON edr_processes USING GIN (process_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_proc_path_trgm           ON edr_processes USING GIN (process_path gin_trgm_ops);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_proc_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_proc_updated_at BEFORE UPDATE ON edr_processes
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- =============================================================================
-- Enrichments (TI, IoCs) for detections
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_enrichments (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  detection_id  uuid NOT NULL,
  ioc_type      text NOT NULL,          -- hash|domain|ip|url|email|yara|...
  ioc_value     text NOT NULL,
  tlp           text,
  source        text,                   -- TI feed/source
  confidence    edr_confidence_enum NOT NULL DEFAULT 'medium',
  attributes    jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_enr_det FOREIGN KEY (detection_id) REFERENCES edr_detections (id) ON DELETE CASCADE,
  CONSTRAINT uq_enr_org_det_ioc UNIQUE (org_id, detection_id, ioc_type, ioc_value, COALESCE(source,''))
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_enrichments_p%s PARTITION OF edr_enrichments
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_enr_org_det ON edr_enrichments (org_id, detection_id);

-- =============================================================================
-- Suppressions (noise control)
-- =============================================================================
CREATE TABLE IF NOT EXISTS edr_suppressions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  vendor        text NOT NULL,
  rule_uid      text NOT NULL,
  reason        text,
  created_by    text NOT NULL DEFAULT current_user,
  valid_from    timestamptz NOT NULL DEFAULT now(),
  valid_to      timestamptz,
  conditions    jsonb NOT NULL DEFAULT '{}'::jsonb,   -- e.g. asset tags, paths, users, nets
  is_active     boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_sup_org_vendor_rule_from UNIQUE (org_id, vendor, rule_uid, valid_from)
) PARTITION BY HASH (org_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS edr_suppressions_p%s PARTITION OF edr_suppressions
         FOR VALUES WITH (MODULUS 8, REMAINDER %s);', i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_sup_org_active ON edr_suppressions (org_id, is_active);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_sup_updated_at') THEN
    EXECUTE 'CREATE TRIGGER t_sup_updated_at BEFORE UPDATE ON edr_suppressions
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()';
  END IF;
END$$;

-- =============================================================================
-- RLS enablement (same policy pattern as assets: app.current_org must be set)
-- =============================================================================
ALTER TABLE edr_audit              ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_agents             ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_heartbeats         ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_events             ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_detections         ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_actions            ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_quarantine_files   ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_policy_versions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_rule_versions      ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_processes          ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_enrichments        ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_suppressions       ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT unnest(ARRAY[
      'edr_audit',
      'edr_agents',
      'edr_heartbeats',
      'edr_events',
      'edr_detections',
      'edr_actions',
      'edr_quarantine_files',
      'edr_policy_versions',
      'edr_rule_versions',
      'edr_processes',
      'edr_enrichments',
      'edr_suppressions'
    ]) AS tbl
  LOOP
    EXECUTE format($fmt$
      DO $inner$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_policies
          WHERE schemaname = ANY (current_schemas(true))
            AND tablename = %L AND policyname = 'org_isolation'
        ) THEN
          EXECUTE format(
            'CREATE POLICY org_isolation ON %I
               USING ( current_setting(''app.current_org'', true) IS NOT NULL
                       AND org_id = current_setting(''app.current_org'')::uuid )
              WITH CHECK ( current_setting(''app.current_org'', true) IS NOT NULL
                           AND org_id = current_setting(''app.current_org'')::uuid )',
            %I
          );
        END IF;
      END
      $inner$;
    $fmt$, r.tbl, r.tbl);
  END LOOP;
END$$;

-- =============================================================================
-- Privileges (optional, idempotent)
-- =============================================================================
DO $$
BEGIN
  BEGIN
    EXECUTE 'REVOKE ALL ON edr_audit, edr_agents, edr_heartbeats, edr_events, edr_detections,
                         edr_actions, edr_quarantine_files, edr_policy_versions, edr_rule_versions,
                         edr_processes, edr_enrichments, edr_suppressions FROM PUBLIC';
  EXCEPTION WHEN undefined_table THEN NULL;
  END;

  BEGIN
    EXECUTE 'GRANT SELECT ON edr_agents, edr_heartbeats, edr_events, edr_detections,
                         edr_actions, edr_quarantine_files, edr_policy_versions, edr_rule_versions,
                         edr_processes, edr_enrichments, edr_suppressions TO cyber_readonly';
  EXCEPTION WHEN undefined_object THEN NULL;
  END;

  BEGIN
    EXECUTE 'GRANT INSERT, UPDATE, DELETE ON edr_agents, edr_heartbeats, edr_events, edr_detections,
                         edr_actions, edr_quarantine_files, edr_policy_versions, edr_rule_versions,
                         edr_processes, edr_enrichments, edr_suppressions TO cyber_writer';
  EXCEPTION WHEN undefined_object THEN NULL;
  END;
END$$;

COMMIT;

-- =============================================================================
-- Usage:
-- SET app.current_org = '<uuid>';
-- INSERT/SELECT obey tenant isolation via RLS
-- =============================================================================
