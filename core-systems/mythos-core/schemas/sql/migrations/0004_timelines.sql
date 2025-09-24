-- mythos-core / schemas/sql/migrations/0004_timelines.sql
-- PostgreSQL industrial migration for Release/ML timelines.
-- Safe to run multiple times (idempotent DDL parts where possible).

BEGIN;

-- =========================
-- Extensions (safe)
-- =========================
CREATE EXTENSION IF NOT EXISTS pgcrypto;    -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gist;  -- exclusion constraints on ranges

-- =========================
-- Schema
-- =========================
CREATE SCHEMA IF NOT EXISTS mythos;

-- =========================
-- Enums
-- =========================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'timeline_event_status') THEN
    CREATE TYPE mythos.timeline_event_status AS ENUM (
      'draft','scheduled','running','on_hold','succeeded','failed','canceled'
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'timeline_event_sched_kind') THEN
    CREATE TYPE mythos.timeline_event_sched_kind AS ENUM (
      'schedule',       -- cron
      'window',         -- cron + duration
      'timebox',        -- explicit start..end
      'ad_hoc'          -- one-shot manual
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'timeline_run_outcome') THEN
    CREATE TYPE mythos.timeline_run_outcome AS ENUM (
      'succeeded','failed','canceled','held','timeout'
    );
  END IF;
END$$;

-- =========================
-- Common helpers (updated_at)
-- =========================
CREATE OR REPLACE FUNCTION mythos.tg_touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END$$;

-- Validate event temporal fields
CREATE OR REPLACE FUNCTION mythos.tg_validate_event_time()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.sched_kind = 'timebox') THEN
    IF NEW.start_at IS NULL OR NEW.end_at IS NULL THEN
      RAISE EXCEPTION 'timebox requires start_at and end_at';
    END IF;
    IF NEW.end_at <= NEW.start_at THEN
      RAISE EXCEPTION 'end_at must be greater than start_at';
    END IF;
  ELSIF (NEW.sched_kind = 'schedule' OR NEW.sched_kind = 'window') THEN
    IF NEW.cron IS NULL OR length(btrim(NEW.cron)) = 0 THEN
      RAISE EXCEPTION 'schedule/window requires cron expression';
    END IF;
    IF NEW.sched_kind = 'window' AND (NEW.window_duration IS NULL OR NEW.window_duration <= interval '0') THEN
      RAISE EXCEPTION 'window requires positive window_duration';
    END IF;
  END IF;
  RETURN NEW;
END$$;

-- =========================
-- Projects (tenant scope)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_project (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant        text NOT NULL,                       -- multi-tenant isolation key
  key           text NOT NULL,                       -- short unique key within tenant
  name          text NOT NULL,
  timezone      text NOT NULL DEFAULT 'Europe/Stockholm',
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,  -- free-form labels, owners, etc.
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT timeline_project_key_uniq UNIQUE (tenant, key)
);

CREATE INDEX IF NOT EXISTS idx_timeline_project_tenant ON mythos.timeline_project(tenant);
CREATE TRIGGER tr_timeline_project_touch
  BEFORE UPDATE ON mythos.timeline_project
  FOR EACH ROW EXECUTE FUNCTION mythos.tg_touch_updated_at();

COMMENT ON TABLE mythos.timeline_project IS 'Root scope for timelines; tenant-separated.';
COMMENT ON COLUMN mythos.timeline_project.tenant IS 'RLS key; set via SET LOCAL mythos.tenant';

-- =========================
-- Profiles (deployment policies per project)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_profile (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant        text NOT NULL,
  project_id    uuid NOT NULL REFERENCES mythos.timeline_project(id) ON DELETE CASCADE,
  name          text NOT NULL,                                  -- e.g. dev/stage/prod
  approvals_required boolean NOT NULL DEFAULT true,
  min_approvers int NOT NULL DEFAULT 2 CHECK (min_approvers >= 0),
  approver_groups text[] NOT NULL DEFAULT '{}',
  rollout       jsonb NOT NULL DEFAULT '{}'::jsonb,             -- waves/gates defaults
  freeze_windows tstzrange[] NOT NULL DEFAULT '{}',             -- optional freeze ranges
  labels        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT timeline_profile_name_uniq UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_timeline_profile_project ON mythos.timeline_profile(project_id);
CREATE INDEX IF NOT EXISTS idx_timeline_profile_labels_gin ON mythos.timeline_profile USING gin (labels);
CREATE TRIGGER tr_timeline_profile_touch
  BEFORE UPDATE ON mythos.timeline_profile
  FOR EACH ROW EXECUTE FUNCTION mythos.tg_touch_updated_at();

-- =========================
-- Templates (reusable event definitions)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_template (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant        text NOT NULL,
  project_id    uuid NOT NULL REFERENCES mythos.timeline_project(id) ON DELETE CASCADE,
  key           text NOT NULL,                          -- unique within project (e.g., release.deploy)
  version       text NOT NULL,                          -- semver string
  kind          text NOT NULL,                          -- "release" | "ml-training" | "data" ...
  steps         jsonb NOT NULL DEFAULT '[]'::jsonb,
  gates         jsonb NOT NULL DEFAULT '[]'::jsonb,     -- gate expressions/queries
  notifications jsonb NOT NULL DEFAULT '{}'::jsonb,     -- channels/routes
  active        boolean NOT NULL DEFAULT true,
  created_by    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT timeline_template_key_uniq UNIQUE (project_id, key, version)
);

CREATE INDEX IF NOT EXISTS idx_timeline_template_project ON mythos.timeline_template(project_id);
CREATE INDEX IF NOT EXISTS idx_timeline_template_active ON mythos.timeline_template(project_id, active);
CREATE TRIGGER tr_timeline_template_touch
  BEFORE UPDATE ON mythos.timeline_template
  FOR EACH ROW EXECUTE FUNCTION mythos.tg_touch_updated_at();

-- =========================
-- Events (scheduled concrete executions)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_event (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant        text NOT NULL,
  project_id    uuid NOT NULL REFERENCES mythos.timeline_project(id) ON DELETE CASCADE,
  template_id   uuid REFERENCES mythos.timeline_template(id) ON DELETE SET NULL,
  profile_id    uuid REFERENCES mythos.timeline_profile(id) ON DELETE SET NULL,
  key           text NOT NULL,                                -- unique within project (e.g., rel-llm-chat-2025-09-01)
  name          text NOT NULL,
  status        mythos.timeline_event_status NOT NULL DEFAULT 'draft',
  sched_kind    mythos.timeline_event_sched_kind NOT NULL,
  cron          text,                                         -- for schedule/window
  window_duration interval,                                   -- for window
  start_at      timestamptz,                                  -- for timebox or ad_hoc planned start
  end_at        timestamptz,                                  -- for timebox planned end
  timezone      text NOT NULL DEFAULT 'Europe/Stockholm',
  respect_business_hours boolean NOT NULL DEFAULT false,
  labels        jsonb NOT NULL DEFAULT '{}'::jsonb,           -- arbitrary labels (service, version, risk, etc.)
  owners_dri    text[] NOT NULL DEFAULT '{}',
  owners_backups text[] NOT NULL DEFAULT '{}',
  rollout       jsonb NOT NULL DEFAULT '{}'::jsonb,           -- waves overrides
  success_criteria text[] NOT NULL DEFAULT '{}',
  cancel_policy text,                                         -- e.g., auto-hold
  risk          jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),

  -- Generated time range for GIST/overlap queries ([start,end))
  timebox       tstzrange GENERATED ALWAYS AS (
                   CASE
                     WHEN start_at IS NOT NULL AND end_at IS NOT NULL
                       THEN tstzrange(start_at, end_at, '[)')
                     ELSE NULL
                   END
                 ) STORED,

  CONSTRAINT timeline_event_key_uniq UNIQUE (project_id, key),
  CONSTRAINT chk_event_time_valid CHECK (
    (sched_kind = 'timebox' AND start_at IS NOT NULL AND end_at IS NOT NULL AND end_at > start_at)
    OR (sched_kind = 'schedule' AND cron IS NOT NULL AND length(btrim(cron)) > 0)
    OR (sched_kind = 'window'   AND cron IS NOT NULL AND length(btrim(cron)) > 0 AND window_duration IS NOT NULL AND window_duration > interval '0')
    OR (sched_kind = 'ad_hoc')
  )
);

CREATE INDEX IF NOT EXISTS idx_timeline_event_project ON mythos.timeline_event(project_id);
CREATE INDEX IF NOT EXISTS idx_timeline_event_status ON mythos.timeline_event(project_id, status);
CREATE INDEX IF NOT EXISTS idx_timeline_event_labels_gin ON mythos.timeline_event USING gin (labels);
CREATE INDEX IF NOT EXISTS idx_timeline_event_timebox_gist ON mythos.timeline_event USING gist (timebox);
CREATE INDEX IF NOT EXISTS idx_timeline_event_start_at ON mythos.timeline_event(start_at);
CREATE INDEX IF NOT EXISTS idx_timeline_event_cron_notnull ON mythos.timeline_event((cron IS NOT NULL)) WHERE cron IS NOT NULL;

CREATE TRIGGER tr_timeline_event_touch
  BEFORE UPDATE ON mythos.timeline_event
  FOR EACH ROW EXECUTE FUNCTION mythos.tg_touch_updated_at();

CREATE TRIGGER tr_timeline_event_validate
  BEFORE INSERT OR UPDATE ON mythos.timeline_event
  FOR EACH ROW EXECUTE FUNCTION mythos.tg_validate_event_time();

COMMENT ON COLUMN mythos.timeline_event.timebox IS 'Derived range [start_at,end_at) for timebox events.';

-- Optional: prevent overlapping timeboxes within the same project for the same label "service" if present
-- (uses JSONB ->> 'service', only when both ranges exist)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'timeline_event_no_overlap_same_service'
  ) THEN
    ALTER TABLE mythos.timeline_event
      ADD CONSTRAINT timeline_event_no_overlap_same_service EXCLUDE USING gist
      (
        project_id WITH =,
        (labels ->> 'service') WITH =,
        timebox WITH &&
      )
      WHERE (timebox IS NOT NULL);
  END IF;
END$$;

-- =========================
-- Dependencies (DAG)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_event_dependency (
  event_id      uuid NOT NULL REFERENCES mythos.timeline_event(id) ON DELETE CASCADE,
  depends_on_id uuid NOT NULL REFERENCES mythos.timeline_event(id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (event_id, depends_on_id),
  CONSTRAINT chk_no_self_dependency CHECK (event_id <> depends_on_id)
);

CREATE INDEX IF NOT EXISTS idx_timeline_dep_on ON mythos.timeline_event_dependency(depends_on_id);

-- =========================
-- Event runs (execution history)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_event_run (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant        text NOT NULL,
  event_id      uuid NOT NULL REFERENCES mythos.timeline_event(id) ON DELETE CASCADE,
  run_index     bigint GENERATED BY DEFAULT AS IDENTITY,   -- local sequence within table
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  outcome       mythos.timeline_run_outcome,
  gate_results  jsonb NOT NULL DEFAULT '[]'::jsonb,        -- array of gate evaluations
  metrics       jsonb NOT NULL DEFAULT '{}'::jsonb,        -- e.g., error_ratio, latency
  notes         text,
  actor         text,                                      -- who initiated (user/bot)
  duration_ms   bigint GENERATED ALWAYS AS
                 (CASE WHEN finished_at IS NOT NULL
                       THEN floor(extract(epoch FROM (finished_at - started_at)) * 1000)::bigint
                       ELSE NULL END) STORED
);

CREATE INDEX IF NOT EXISTS idx_timeline_run_event ON mythos.timeline_event_run(event_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_run_outcome ON mythos.timeline_event_run(outcome);
CREATE INDEX IF NOT EXISTS idx_timeline_run_metrics_gin ON mythos.timeline_event_run USING gin (metrics);
COMMENT ON COLUMN mythos.timeline_event_run.duration_ms IS 'Computed when finished_at set.';

-- =========================
-- Notification routes (optional matching rules)
-- =========================
CREATE TABLE IF NOT EXISTS mythos.timeline_notification_route (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant        text NOT NULL,
  project_id    uuid NOT NULL REFERENCES mythos.timeline_project(id) ON DELETE CASCADE,
  active        boolean NOT NULL DEFAULT true,
  priority      int NOT NULL DEFAULT 100,
  match         jsonb NOT NULL DEFAULT '{}'::jsonb,   -- e.g., {"labels": {"service":"llm-chat-demo"}}
  channels      jsonb NOT NULL DEFAULT '[]'::jsonb,   -- e.g., [{"kind":"slack","target":"#releases"}]
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_timeline_route_project ON mythos.timeline_notification_route(project_id, active, priority);
CREATE INDEX IF NOT EXISTS idx_timeline_route_match_gin ON mythos.timeline_notification_route USING gin (match);
CREATE TRIGGER tr_timeline_route_touch
  BEFORE UPDATE ON mythos.timeline_notification_route
  FOR EACH ROW EXECUTE FUNCTION mythos.tg_touch_updated_at();

-- =========================
-- RLS (Row-Level Security) by tenant
-- =========================
-- Use: SET LOCAL mythos.tenant = '<tenant_id>' in app session/txn.
DO $$
BEGIN
  PERFORM 1 FROM pg_settings WHERE name = 'mythos.tenant';
  IF NOT FOUND THEN
    PERFORM set_config('mythos.tenant', '', false);
  END IF;
END$$;

-- Enable RLS on all tenant-scoped tables
ALTER TABLE mythos.timeline_project ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.timeline_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.timeline_template ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.timeline_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.timeline_event_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE mythos.timeline_notification_route ENABLE ROW LEVEL SECURITY;

-- Policies: tenant column must equal current_setting('mythos.tenant', true)
CREATE OR REPLACE FUNCTION mythos.fn_current_tenant() RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT current_setting('mythos.tenant', true)
$$;

-- Helper to apply policy if not exists
DO $$
DECLARE
  _tbl text;
BEGIN
  FOR _tbl IN
    SELECT unnest(ARRAY[
      'timeline_project','timeline_profile','timeline_template',
      'timeline_event','timeline_event_run','timeline_notification_route'
    ])
  LOOP
    EXECUTE format($f$
      DO $i$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_policies
          WHERE schemaname = 'mythos' AND tablename = %L AND policyname = %L
        ) THEN
          EXECUTE '
            CREATE POLICY tenant_isolation_select ON mythos.%I
              FOR SELECT USING (tenant = mythos.fn_current_tenant() OR mythos.fn_current_tenant() IS NULL);
          ';
          EXECUTE '
            CREATE POLICY tenant_isolation_update ON mythos.%I
              FOR UPDATE USING (tenant = mythos.fn_current_tenant() OR mythos.fn_current_tenant() IS NULL)
              WITH CHECK (tenant = mythos.fn_current_tenant() OR mythos.fn_current_tenant() IS NULL);
          ';
          EXECUTE '
            CREATE POLICY tenant_isolation_insert ON mythos.%I
              FOR INSERT WITH CHECK (tenant = mythos.fn_current_tenant() OR mythos.fn_current_tenant() IS NULL);
          ';
          EXECUTE '
            CREATE POLICY tenant_isolation_delete ON mythos.%I
              FOR DELETE USING (tenant = mythos.fn_current_tenant() OR mythos.fn_current_tenant() IS NULL);
          ';
        END IF;
      END $i$;
    $f$, _tbl, 'tenant_isolation_select', _tbl, _tbl, _tbl, _tbl);
  END LOOP;
END$$;

-- =========================
-- Views (quality-of-life)
-- =========================
CREATE OR REPLACE VIEW mythos.v_timeline_upcoming AS
SELECT
  e.id, e.project_id, e.key, e.name, e.status, e.sched_kind,
  e.cron, e.window_duration, e.start_at, e.end_at, e.timezone,
  e.labels, e.owners_dri, e.rollout,
  -- naive next_at: for timebox & ad_hoc use start_at; for schedule/window NULL (computed in app)
  CASE
    WHEN e.sched_kind IN ('timebox','ad_hoc') THEN e.start_at
    ELSE NULL
  END AS next_at
FROM mythos.timeline_event e
WHERE
  (e.start_at IS NULL OR e.start_at >= now())
  AND (e.status IN ('draft','scheduled','on_hold'));

COMMENT ON VIEW mythos.v_timeline_upcoming IS
'Upcoming events (next_at for timebox/ad_hoc only; cron evaluation is handled in the app layer).';

-- =========================
-- Comments (documentation)
-- =========================
COMMENT ON TABLE mythos.timeline_profile IS 'Per-environment deployment policies and defaults.';
COMMENT ON TABLE mythos.timeline_template IS 'Reusable event definitions with steps/gates/notifications.';
COMMENT ON TABLE mythos.timeline_event IS 'Concrete scheduled events; can reference template/profile.';
COMMENT ON TABLE mythos.timeline_event_dependency IS 'DAG edges between events (no cycle enforcement here).';
COMMENT ON TABLE mythos.timeline_event_run IS 'Execution history with gate results and metrics.';
COMMENT ON TABLE mythos.timeline_notification_route IS 'Routing rules for notifications by labels/kind.';

COMMIT;

-- End of migration 0004
