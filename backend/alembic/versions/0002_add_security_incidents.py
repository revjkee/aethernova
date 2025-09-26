# backend/alembic/versions/0002_add_security_incidents.py
"""add security_incidents table with enums, indexes and triggers

Revision ID: 0002_add_security_incidents
Revises: 0001_initial
Create Date: 2025-09-26

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as psql

# --- Alembic identifiers ---
revision = "0002_add_security_incidents"
down_revision = "0001_initial"  # при необходимости скорректируйте под вашу историю миграций
branch_labels = None
depends_on = None


# --- Enum names (DB-level) ---
SEVERITY_ENUM = "incident_severity_enum"
STATUS_ENUM = "incident_status_enum"


def upgrade() -> None:
    # Ensure required extensions (pgcrypto for gen_random_uuid)
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Create ENUM types
    severity_enum = psql.ENUM(
        "low", "medium", "high", "critical",
        name=SEVERITY_ENUM,
        create_type=False,
    )
    status_enum = psql.ENUM(
        "new", "triage", "contained", "monitoring", "resolved", "false_positive", "closed",
        name=STATUS_ENUM,
        create_type=False,
    )

    op.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{SEVERITY_ENUM}') THEN CREATE TYPE {SEVERITY_ENUM} AS ENUM ('low','medium','high','critical'); END IF; END $$;")
    op.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{STATUS_ENUM}') THEN CREATE TYPE {STATUS_ENUM} AS ENUM ('new','triage','contained','monitoring','resolved','false_positive','closed'); END IF; END $$;")

    # Create table
    op.create_table(
        "security_incidents",
        sa.Column("id", psql.UUID(as_uuid=True), primary_key=True, nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", psql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),

        sa.Column("severity", sa.Enum(name=SEVERITY_ENUM, native_enum=False), nullable=False),
        sa.Column("status", sa.Enum(name=STATUS_ENUM, native_enum=False), nullable=False, server_default=sa.text("'new'")),

        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("reporter_email", sa.String(length=320), nullable=True),

        sa.Column("occurred_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("detected_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("closed_at",   psql.TIMESTAMP(timezone=True), nullable=True),

        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),

        # Structured fields
        sa.Column("indicators", psql.JSONB(astext_type=sa.Text()), nullable=True),        # IOCs, hashes, IPs, etc.
        sa.Column("artifacts", psql.JSONB(astext_type=sa.Text()), nullable=True),         # collected evidence
        sa.Column("containment_actions", psql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("remediation_actions", psql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("metadata", psql.JSONB(astext_type=sa.Text()), nullable=True),

        sa.Column("tags", psql.ARRAY(sa.Text()), nullable=True),

        # Optional references (kept as plain UUIDs to avoid hard FK coupling)
        sa.Column("related_user_id", psql.UUID(as_uuid=True), nullable=True),
        sa.Column("assigned_to_user_id", psql.UUID(as_uuid=True), nullable=True),

        # Optional cost tracking
        sa.Column("estimated_cost_usd", sa.Numeric(18, 2), nullable=True),

        # Unique natural-ish key to avoid duplicates inside one tenant
        sa.UniqueConstraint("tenant_id", "source", "occurred_at", "title", name="uq_incident_tenant_source_time_title"),

        # Checks
        sa.CheckConstraint("length(title) > 0", name="ck_incident_title_nonempty"),
        sa.CheckConstraint("(detected_at IS NULL) OR (occurred_at IS NULL) OR (detected_at >= occurred_at)", name="ck_incident_detected_after_occurred"),
        sa.CheckConstraint("(closed_at IS NULL) OR (detected_at IS NULL) OR (closed_at >= detected_at)", name="ck_incident_closed_after_detected"),
    )

    # B-Tree indexes
    op.create_index("ix_security_incidents_tenant", "security_incidents", ["tenant_id"], unique=False)
    op.create_index("ix_security_incidents_severity", "security_incidents", ["severity"], unique=False)
    op.create_index("ix_security_incidents_status", "security_incidents", ["status"], unique=False)
    op.create_index("ix_security_incidents_occurred_at", "security_incidents", ["occurred_at"], unique=False)
    op.create_index("ix_security_incidents_detected_at", "security_incidents", ["detected_at"], unique=False)
    op.create_index("ix_security_incidents_closed_at", "security_incidents", ["closed_at"], unique=False)

    # Partial index to speed up queries for "open" incidents
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_incidents_open_only "
        "ON security_incidents (status) WHERE closed_at IS NULL"
    )

    # GIN indexes for JSONB / ARRAY fields
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_incidents_indicators_gin "
        "ON security_incidents USING GIN (indicators jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_incidents_artifacts_gin "
        "ON security_incidents USING GIN (artifacts jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_incidents_metadata_gin "
        "ON security_incidents USING GIN (metadata jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_incidents_tags_gin "
        "ON security_incidents USING GIN (tags)"
    )

    # updated_at trigger (keeps updated_at in sync on UPDATE)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at := NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_set_updated_at ON security_incidents;
        CREATE TRIGGER trg_set_updated_at
        BEFORE UPDATE ON security_incidents
        FOR EACH ROW
        EXECUTE FUNCTION set_updated_at();
        """
    )


def downgrade() -> None:
    # Drop trigger and function
    op.execute("DROP TRIGGER IF EXISTS trg_set_updated_at ON security_incidents")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at()")

    # Drop indexes created via raw SQL first
    op.execute("DROP INDEX IF EXISTS ix_security_incidents_open_only")
    op.execute("DROP INDEX IF EXISTS ix_security_incidents_indicators_gin")
    op.execute("DROP INDEX IF EXISTS ix_security_incidents_artifacts_gin")
    op.execute("DROP INDEX IF EXISTS ix_security_incidents_metadata_gin")
    op.execute("DROP INDEX IF EXISTS ix_security_incidents_tags_gin")

    # Drop declarative indexes
    op.drop_index("ix_security_incidents_closed_at", table_name="security_incidents")
    op.drop_index("ix_security_incidents_detected_at", table_name="security_incidents")
    op.drop_index("ix_security_incidents_occurred_at", table_name="security_incidents")
    op.drop_index("ix_security_incidents_status", table_name="security_incidents")
    op.drop_index("ix_security_incidents_severity", table_name="security_incidents")
    op.drop_index("ix_security_incidents_tenant", table_name="security_incidents")

    # Drop table
    op.drop_table("security_incidents")

    # Drop ENUMs if unused
    op.execute(
        f"DO $$ BEGIN "
        f"IF EXISTS (SELECT 1 FROM pg_type WHERE typname = '{SEVERITY_ENUM}') "
        f"THEN DROP TYPE {SEVERITY_ENUM}; END IF; END $$;"
    )
    op.execute(
        f"DO $$ BEGIN "
        f"IF EXISTS (SELECT 1 FROM pg_type WHERE typname = '{STATUS_ENUM}') "
        f"THEN DROP TYPE {STATUS_ENUM}; END IF; END $$;"
    )

    # Note: pgcrypto extension is left installed intentionally
