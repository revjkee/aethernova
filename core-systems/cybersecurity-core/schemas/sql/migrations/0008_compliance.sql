-- =====================================================================
-- Migration: 0008_compliance.sql
-- Purpose : Industrial-grade compliance module foundation
-- Target  : PostgreSQL 13+ (tested up to 16)
-- Notes   : Idempotent creation, strict constraints, auditing, indices.
-- Assumptions: No prior objects with the same names exist.
-- =====================================================================

-- Safety guards
SET statement_timeout = '10min';
SET lock_timeout       = '1min';
SET client_min_messages = WARNING;

BEGIN;

-- =====================================================================
-- Extensions (optional, safe if already present)
-- =====================================================================
-- For cryptographic digest if you need evidence checksums generation in-DB
-- CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================================
-- ENUM types (idempotent via DO blocks)
-- =====================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'compliance_impact_enum') THEN
    CREATE TYPE compliance_impact_enum AS ENUM ('low','medium','high','critical');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'compliance_result_enum') THEN
    CREATE TYPE compliance_result_enum AS ENUM ('passed','failed','partial','not_applicable','not_tested');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'compliance_severity_enum') THEN
    CREATE TYPE compliance_severity_enum AS ENUM ('info','low','medium','high','critical');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'compliance_finding_status_enum') THEN
    CREATE TYPE compliance_finding_status_enum AS ENUM ('open','in_progress','deferred','mitigated','accepted_risk','false_positive','closed');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'compliance_assessment_status_enum') THEN
    CREATE TYPE compliance_assessment_status_enum AS ENUM ('draft','in_progress','completed','abandoned');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'compliance_evidence_type_enum') THEN
    CREATE TYPE compliance_evidence_type_enum AS ENUM ('document','screenshot','log','config','ticket','dataset','url','other');
  END IF;
END $$;

-- =====================================================================
-- Utility trigger: updated_at maintenance
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;

-- =====================================================================
-- Centralized audit log + trigger
-- =====================================================================
CREATE TABLE IF NOT EXISTS compliance_audit_log (
  id           BIGSERIAL PRIMARY KEY,
  table_name   TEXT        NOT NULL,
  operation    TEXT        NOT NULL CHECK (operation IN ('INSERT','UPDATE','DELETE')),
  row_pk       TEXT        NOT NULL,
  before_row   JSONB,
  after_row    JSONB,
  actor        TEXT        NOT NULL DEFAULT current_user,
  occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE compliance_audit_log IS 'Append-only audit trail for compliance tables';
COMMENT ON COLUMN compliance_audit_log.row_pk IS 'Primary key value of affected row as text';

CREATE OR REPLACE FUNCTION compliance_audit_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO compliance_audit_log(table_name, operation, row_pk, before_row, after_row)
    VALUES (TG_TABLE_NAME, 'INSERT', NEW.id::TEXT, NULL, to_jsonb(NEW));
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    IF to_jsonb(OLD) IS DISTINCT FROM to_jsonb(NEW) THEN
      INSERT INTO compliance_audit_log(table_name, operation, row_pk, before_row, after_row)
      VALUES (TG_TABLE_NAME, 'UPDATE', NEW.id::TEXT, to_jsonb(OLD), to_jsonb(NEW));
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO compliance_audit_log(table_name, operation, row_pk, before_row, after_row)
    VALUES (TG_TABLE_NAME, 'DELETE', OLD.id::TEXT, to_jsonb(OLD), NULL);
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;

-- =====================================================================
-- Core tables
-- =====================================================================

-- 1) Compliance frameworks (e.g., ISO 27001:2022, NIST CSF 2.0, SOC 2, GDPR)
CREATE TABLE IF NOT EXISTS compliance_framework (
  id            BIGSERIAL PRIMARY KEY,
  framework_key TEXT        NOT NULL,
  name          TEXT        NOT NULL,
  version       TEXT        NOT NULL DEFAULT 'latest',
  description   TEXT,
  authority_url TEXT,
  is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
  metadata      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT compliance_framework_key_uk UNIQUE (framework_key),
  CONSTRAINT compliance_framework_key_len_chk CHECK (char_length(framework_key) BETWEEN 1 AND 64),
  CONSTRAINT compliance_framework_metadata_obj CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE compliance_framework IS 'Compliance frameworks registry';
COMMENT ON COLUMN compliance_framework.framework_key IS 'Stable key (e.g., ISO27001_2022, NIST_CSF_2_0, SOC2_TSC_2017, GDPR)';
COMMENT ON COLUMN compliance_framework.metadata IS 'Free-form JSON for extra attributes';

-- Trigger: updated_at
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_compliance_framework_updated_at') THEN
    CREATE TRIGGER trg_compliance_framework_updated_at
    BEFORE UPDATE ON compliance_framework
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
  END IF;
END $$;

-- Audit trigger
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aud_compliance_framework') THEN
    CREATE TRIGGER aud_compliance_framework
    AFTER INSERT OR UPDATE OR DELETE ON compliance_framework
    FOR EACH ROW EXECUTE FUNCTION compliance_audit_trigger();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_compliance_framework_active ON compliance_framework (is_active);
CREATE INDEX IF NOT EXISTS idx_compliance_framework_name_trgm ON compliance_framework (name);

-- 2) Controls within frameworks (e.g., AC-2, A.5.37, PR.AC-1)
CREATE TABLE IF NOT EXISTS compliance_control (
  id            BIGSERIAL PRIMARY KEY,
  framework_id  BIGINT      NOT NULL REFERENCES compliance_framework(id) ON DELETE CASCADE,
  control_code  TEXT        NOT NULL,
  title         TEXT        NOT NULL,
  description   TEXT,
  category      TEXT,
  impact        compliance_impact_enum,
  priority      SMALLINT    CHECK (priority BETWEEN 1 AND 5),
  is_mandatory  BOOLEAN     NOT NULL DEFAULT TRUE,
  version       TEXT        NOT NULL DEFAULT '1.0',
  metadata      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT compliance_control_uk UNIQUE (framework_id, control_code),
  CONSTRAINT compliance_control_code_len_chk CHECK (char_length(control_code) BETWEEN 1 AND 64),
  CONSTRAINT compliance_control_metadata_obj CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE compliance_control IS 'Controls catalog by framework';
COMMENT ON COLUMN compliance_control.control_code IS 'Control identifier (e.g., AC-2, A.5.37, PR.AC-1)';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_compliance_control_updated_at') THEN
    CREATE TRIGGER trg_compliance_control_updated_at
    BEFORE UPDATE ON compliance_control
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aud_compliance_control') THEN
    CREATE TRIGGER aud_compliance_control
    AFTER INSERT OR UPDATE OR DELETE ON compliance_control
    FOR EACH ROW EXECUTE FUNCTION compliance_audit_trigger();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_compliance_control_framework_id ON compliance_control (framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_control_code ON compliance_control (control_code);
CREATE INDEX IF NOT EXISTS idx_compliance_control_impact ON compliance_control (impact);

-- 3) Assessments (an engagement that evaluates a scope vs a framework)
CREATE TABLE IF NOT EXISTS compliance_assessment (
  id            BIGSERIAL PRIMARY KEY,
  framework_id  BIGINT      NOT NULL REFERENCES compliance_framework(id) ON DELETE RESTRICT,
  name          TEXT        NOT NULL,
  scope         TEXT,
  assessor      TEXT,
  methodology   TEXT,
  status        compliance_assessment_status_enum NOT NULL DEFAULT 'draft',
  started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at  TIMESTAMPTZ,
  metadata      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT compliance_assessment_name_uk UNIQUE (name),
  CONSTRAINT compliance_assessment_metadata_obj CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT compliance_assessment_time_chk CHECK (completed_at IS NULL OR completed_at >= started_at)
);

COMMENT ON TABLE compliance_assessment IS 'A single compliance assessment for a given framework and scope';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_compliance_assessment_updated_at') THEN
    CREATE TRIGGER trg_compliance_assessment_updated_at
    BEFORE UPDATE ON compliance_assessment
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aud_compliance_assessment') THEN
    CREATE TRIGGER aud_compliance_assessment
    AFTER INSERT OR UPDATE OR DELETE ON compliance_assessment
    FOR EACH ROW EXECUTE FUNCTION compliance_audit_trigger();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_compliance_assessment_framework_id ON compliance_assessment (framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessment_status ON compliance_assessment (status);

-- 4) Per-assessment control status (the result per control within an assessment)
CREATE TABLE IF NOT EXISTS compliance_control_status (
  id             BIGSERIAL PRIMARY KEY,
  assessment_id  BIGINT      NOT NULL REFERENCES compliance_assessment(id) ON DELETE CASCADE,
  control_id     BIGINT      NOT NULL REFERENCES compliance_control(id)     ON DELETE CASCADE,
  result         compliance_result_enum NOT NULL,
  severity       compliance_severity_enum,
  residual_risk  compliance_severity_enum,
  owner          TEXT,
  due_date       DATE,
  summary        TEXT,
  details        TEXT,
  last_reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT compliance_control_status_uk UNIQUE (assessment_id, control_id),
  CONSTRAINT compliance_control_status_metadata_obj CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE compliance_control_status IS 'Control result for a specific assessment (pass/fail/partial/etc.)';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_compliance_control_status_updated_at') THEN
    CREATE TRIGGER trg_compliance_control_status_updated_at
    BEFORE UPDATE ON compliance_control_status
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aud_compliance_control_status') THEN
    CREATE TRIGGER aud_compliance_control_status
    AFTER INSERT OR UPDATE OR DELETE ON compliance_control_status
    FOR EACH ROW EXECUTE FUNCTION compliance_audit_trigger();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ccs_assessment_id ON compliance_control_status (assessment_id);
CREATE INDEX IF NOT EXISTS idx_ccs_control_id    ON compliance_control_status (control_id);
CREATE INDEX IF NOT EXISTS idx_ccs_result        ON compliance_control_status (result);
CREATE INDEX IF NOT EXISTS idx_ccs_due_date      ON compliance_control_status (due_date);

-- 5) Evidence attached to assessment/control
CREATE TABLE IF NOT EXISTS compliance_evidence (
  id             BIGSERIAL PRIMARY KEY,
  assessment_id  BIGINT      NOT NULL REFERENCES compliance_assessment(id) ON DELETE CASCADE,
  control_id     BIGINT      NOT NULL REFERENCES compliance_control(id)     ON DELETE CASCADE,
  evidence_type  compliance_evidence_type_enum NOT NULL,
  uri            TEXT        NOT NULL, -- e.g., s3://..., https://..., file path
  checksum       TEXT,
  storage_class  TEXT        NOT NULL DEFAULT 'standard',
  collected_by   TEXT,
  collected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  notes          TEXT,
  metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT compliance_evidence_uk UNIQUE (assessment_id, control_id, uri),
  CONSTRAINT compliance_evidence_metadata_obj CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE compliance_evidence IS 'Evidence artifacts backing up control results';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_compliance_evidence_updated_at') THEN
    CREATE TRIGGER trg_compliance_evidence_updated_at
    BEFORE UPDATE ON compliance_evidence
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aud_compliance_evidence') THEN
    CREATE TRIGGER aud_compliance_evidence
    AFTER INSERT OR UPDATE OR DELETE ON compliance_evidence
    FOR EACH ROW EXECUTE FUNCTION compliance_audit_trigger();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_compliance_evidence_assessment_id ON compliance_evidence (assessment_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_control_id    ON compliance_evidence (control_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_type          ON compliance_evidence (evidence_type);

-- 6) Findings created during assessment
CREATE TABLE IF NOT EXISTS compliance_finding (
  id             BIGSERIAL PRIMARY KEY,
  assessment_id  BIGINT      NOT NULL REFERENCES compliance_assessment(id) ON DELETE CASCADE,
  control_id     BIGINT      REFERENCES compliance_control(id) ON DELETE SET NULL,
  status         compliance_finding_status_enum NOT NULL DEFAULT 'open',
  severity       compliance_severity_enum       NOT NULL DEFAULT 'medium',
  title          TEXT        NOT NULL,
  description    TEXT,
  recommendation TEXT,
  owner          TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  due_at         TIMESTAMPTZ,
  closed_at      TIMESTAMPTZ,
  metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT compliance_finding_uk UNIQUE (assessment_id, title),
  CONSTRAINT compliance_finding_time_chk CHECK (closed_at IS NULL OR closed_at >= created_at),
  CONSTRAINT compliance_finding_metadata_obj CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE compliance_finding IS 'Compliance issues discovered during assessments';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aud_compliance_finding') THEN
    CREATE TRIGGER aud_compliance_finding
    AFTER INSERT OR UPDATE OR DELETE ON compliance_finding
    FOR EACH ROW EXECUTE FUNCTION compliance_audit_trigger();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_compliance_finding_assessment_id ON compliance_finding (assessment_id);
CREATE INDEX IF NOT EXISTS idx_compliance_finding_status       ON compliance_finding (status);
CREATE INDEX IF NOT EXISTS idx_compliance_finding_severity     ON compliance_finding (severity);
CREATE INDEX IF NOT EXISTS idx_compliance_finding_due_at       ON compliance_finding (due_at);

-- 7) Tagging for controls (taxonomy)
CREATE TABLE IF NOT EXISTS compliance_tag (
  id        BIGSERIAL PRIMARY KEY,
  tag_key   TEXT        NOT NULL,
  label     TEXT        NOT NULL,
  category  TEXT,
  metadata  JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT compliance_tag_key_uk UNIQUE (tag_key),
  CONSTRAINT compliance_tag_key_len_chk CHECK (char_length(tag_key) BETWEEN 1 AND 64),
  CONSTRAINT compliance_tag_metadata_obj CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE IF NOT EXISTS compliance_control_tag (
  control_id BIGINT NOT NULL REFERENCES compliance_control(id) ON DELETE CASCADE,
  tag_id     BIGINT NOT NULL REFERENCES compliance_tag(id)     ON DELETE CASCADE,
  PRIMARY KEY (control_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_cct_tag_id     ON compliance_control_tag (tag_id);
CREATE INDEX IF NOT EXISTS idx_cct_control_id ON compliance_control_tag (control_id);

-- =====================================================================
-- Views
-- =====================================================================
CREATE OR REPLACE VIEW vw_compliance_posture AS
SELECT
  a.id                    AS assessment_id,
  f.framework_key,
  a.name                  AS assessment_name,
  a.status                AS assessment_status,
  COUNT(cs.id)            AS controls_total,
  COUNT(CASE WHEN cs.result = 'passed' THEN 1 END)         AS controls_passed,
  COUNT(CASE WHEN cs.result = 'failed' THEN 1 END)         AS controls_failed,
  COUNT(CASE WHEN cs.result = 'partial' THEN 1 END)        AS controls_partial,
  COUNT(CASE WHEN cs.result = 'not_applicable' THEN 1 END) AS controls_na,
  COUNT(CASE WHEN cs.result = 'not_tested' THEN 1 END)     AS controls_not_tested,
  COUNT(cf.id)           AS findings_total,
  COUNT(CASE WHEN cf.status IN ('open','in_progress','deferred') THEN 1 END) AS findings_open_like
FROM compliance_assessment a
JOIN compliance_framework f ON f.id = a.framework_id
LEFT JOIN compliance_control_status cs ON cs.assessment_id = a.id
LEFT JOIN compliance_finding       cf ON cf.assessment_id = a.id
GROUP BY a.id, f.framework_key, a.name, a.status;

COMMENT ON VIEW vw_compliance_posture IS 'Summary posture per assessment (controls by result + findings)';

-- =====================================================================
-- Optional seed data (safe: ON CONFLICT DO NOTHING)
-- =====================================================================
INSERT INTO compliance_framework (framework_key, name, version, description, authority_url)
VALUES
  ('ISO27001_2022','ISO/IEC 27001','2022','Information security, cybersecurity and privacy protection — ISMS requirements','https://www.iso.org/standard/27001'),
  ('NIST_CSF_2_0','NIST Cybersecurity Framework','2.0','Framework for Improving Critical Infrastructure Cybersecurity','https://www.nist.gov/cyberframework'),
  ('SOC2_TSC_2017','AICPA SOC 2 Trust Services Criteria','2017','Security, Availability, Processing Integrity, Confidentiality, Privacy','https://www.aicpa.org'),
  ('GDPR','EU General Data Protection Regulation','2016/679','EU regulation on data protection and privacy','https://eur-lex.europa.eu/eli/reg/2016/679/oj')
ON CONFLICT (framework_key) DO NOTHING;

-- =====================================================================
-- Apply updated_at triggers where missing (guarded above per-table)
-- =====================================================================
-- Already applied per table with DO-block guards.

COMMIT;

-- =====================================================================
-- End of 0008_compliance.sql
-- =====================================================================
