"""initial schema (users, roles, permissions, auth, audit)

Revision ID: 0001_initial
Revises: 
Create Date: 2025-09-26 00:00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as psql

# Revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def _utc_now():
    return sa.text("timezone('utc', now())")


def upgrade() -> None:
    # 1) Ensure required extensions (PostgreSQL)
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext;")  # optional: for provider ids, etc.

    # 2) Helper function + trigger for updated_at
    op.execute(
        """
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = timezone('utc', now());
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    # 3) Core tables

    # users
    op.create_table(
        "users",
        sa.Column(
            "id",
            psql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("updated_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("last_login_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )

    # Case-insensitive unique index for email (lower(email))
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_lower ON users (lower(email));"
    )
    op.create_index("ix_users_username", "users", ["username"], unique=False)

    # roles
    op.create_table(
        "roles",
        sa.Column(
            "id",
            psql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("updated_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )

    # permissions
    op.create_table(
        "permissions",
        sa.Column(
            "id",
            psql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("code", sa.String(128), nullable=False),  # e.g. "users.read"
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("updated_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.UniqueConstraint("code", name="uq_permissions_code"),
    )

    # user_roles (M2M)
    op.create_table(
        "user_roles",
        sa.Column("user_id", psql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", psql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_roles_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_user_roles_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"),
    )
    op.create_index("ix_user_roles_user_id", "user_roles", ["user_id"], unique=False)
    op.create_index("ix_user_roles_role_id", "user_roles", ["role_id"], unique=False)

    # role_permissions (M2M)
    op.create_table(
        "role_permissions",
        sa.Column("role_id", psql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", psql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_permissions_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name="pk_role_permissions"),
    )
    op.create_index("ix_role_permissions_role_id", "role_permissions", ["role_id"], unique=False)
    op.create_index("ix_role_permissions_permission_id", "role_permissions", ["permission_id"], unique=False)

    # oauth_accounts
    op.create_table(
        "oauth_accounts",
        sa.Column(
            "id",
            psql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", psql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),  # e.g. 'google', 'github'
        sa.Column("provider_account_id", sa.String(255), nullable=False),
        sa.Column("access_token_encrypted", sa.Text(), nullable=True),
        sa.Column("refresh_token_encrypted", sa.Text(), nullable=True),
        sa.Column("expires_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("updated_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_oauth_accounts_user_id_users",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "uq_oauth_provider_account",
        "oauth_accounts",
        ["provider", "provider_account_id"],
        unique=True,
    )

    # api_keys (store only hashes)
    op.create_table(
        "api_keys",
        sa.Column(
            "id",
            psql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", psql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=True),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("expires_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_api_keys_user_id_users",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"], unique=False)

    # refresh_tokens (store only hashes)
    op.create_table(
        "refresh_tokens",
        sa.Column(
            "id",
            psql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", psql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("expires_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", psql.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_refresh_tokens_user_id_users",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"], unique=False)

    # audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),  # e.g. "auth.login", "user.create"
        sa.Column("actor_user_id", psql.UUID(as_uuid=True), nullable=True),
        sa.Column("target", sa.String(255), nullable=True),  # free-form 'entity:id'
        sa.Column("ip", sa.String(45), nullable=True),  # IPv4/IPv6 textual
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("payload", psql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", psql.TIMESTAMP(timezone=True), nullable=False, server_default=_utc_now()),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_audit_log_actor_user_id_users",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_audit_log_event_type", "audit_log", ["event_type"], unique=False)
    op.create_index("ix_audit_log_actor_user_id", "audit_log", ["actor_user_id"], unique=False)
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"], unique=False)

    # 4) Attach updated_at triggers to tables that have updated_at column
    for table in ("users", "roles", "permissions", "oauth_accounts"):
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = '{table}_set_updated_at_trg'
                ) THEN
                    CREATE TRIGGER {table}_set_updated_at_trg
                    BEFORE UPDATE ON {table}
                    FOR EACH ROW
                    EXECUTE FUNCTION set_updated_at();
                END IF;
            END$$;
            """
        )


def downgrade() -> None:
    # Drop triggers
    for table in ("users", "roles", "permissions", "oauth_accounts"):
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = '{table}_set_updated_at_trg'
                ) THEN
                    DROP TRIGGER {table}_set_updated_at_trg ON {table};
                END IF;
            END$$;
            """
        )

    # Drop indexes explicitly created via op.execute or op.create_index
    op.execute("DROP INDEX IF EXISTS uq_users_email_lower;")

    for idx in [
        "ix_audit_log_created_at",
        "ix_audit_log_actor_user_id",
        "ix_audit_log_event_type",
        "ix_refresh_tokens_user_id",
        "ix_api_keys_user_id",
        "uq_oauth_provider_account",
        "ix_role_permissions_permission_id",
        "ix_role_permissions_role_id",
        "ix_user_roles_role_id",
        "ix_user_roles_user_id",
        "ix_users_username",
    ]:
        op.execute(f"DROP INDEX IF EXISTS {idx};")

    # Drop tables in reverse dependency order
    op.drop_table("audit_log")
    op.drop_table("refresh_tokens")
    op.drop_table("api_keys")
    op.drop_table("oauth_accounts")
    op.drop_table("role_permissions")
    op.drop_table("user_roles")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")

    # Drop helper function
    op.execute("DROP FUNCTION IF EXISTS set_updated_at;")

    # Extensions are left installed intentionally (idempotent and may be reused by other migrations)
