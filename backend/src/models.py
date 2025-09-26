import sqlalchemy as sa

metadata = sa.MetaData()

users = sa.Table(
    "users",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("username", sa.String, unique=True, nullable=False),
    sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
)

# Table for security incidents displayed in the frontend
security_incidents = sa.Table(
    "security_incidents",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("title", sa.String, nullable=False),
    sa.Column("severity", sa.String, nullable=True),
    sa.Column("description", sa.Text, nullable=True),
    sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
)
