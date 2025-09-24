## automation-core/src/automation_core/databases/migrations/script.py.mako
## -*- coding: utf-8 -*-
<%doc>
Промышленный шаблон Alembic revision script.

Факты и источники:
- Alembic Tutorial (структура ревизий, переменные Mako): https://alembic.sqlalchemy.org/en/latest/tutorial.html
- Alembic Operations API (операции, autocommit): https://alembic.sqlalchemy.org/en/latest/ops.html
- SQLAlchemy Inspector (инспекция схемы): https://docs.sqlalchemy.org/en/20/core/reflection.html#sqlalchemy.engine.reflection.Inspector

Замечания:
- Для PostgreSQL создание/удаление индексов с флагом CONCURRENTLY должно выполняться вне транзакции; используем
  op.get_context().autocommit_block() (см. Operations API). Для других СУБД выполняется обычная операция create_index.
- Все хелперы выполняют проверки существования, что снижает риск сбоев при повторных прогонах/ветвлениях.
- По умолчанию заготовки upgrade()/downgrade() пустые; добавляйте операции ниже.
</%doc>
"""${message or "database revision"}.

Revision ID: ${up_revision}
Revises: ${down_revision | repr}
Create Date: ${create_date}
"""

from __future__ import annotations

from typing import Optional, Sequence

import sqlalchemy as sa
from alembic import op

# Ревизионные идентификаторы Alembic
revision: str = "${up_revision}"
down_revision: Optional[str] = ${down_revision | repr}
branch_labels: Optional[Sequence[str]] = ${branch_labels | repr}
depends_on: Optional[Sequence[str]] = ${depends_on | repr}

# ------------------------------------------------------------------------------
# ХЕЛПЕРЫ ДЛЯ БЕЗОПАСНЫХ МИГРАЦИЙ (идемпотентные проверки)
# Документация:
# - Alembic Operations API: https://alembic.sqlalchemy.org/en/latest/ops.html
# - SQLAlchemy Inspector: https://docs.sqlalchemy.org/en/20/core/reflection.html#sqlalchemy.engine.reflection.Inspector
# ------------------------------------------------------------------------------

def _inspector() -> sa.engine.reflection.Inspector:
    bind = op.get_bind()
    return sa.inspect(bind)

def has_table(table_name: str, schema: Optional[str] = None) -> bool:
    insp = _inspector()
    return insp.has_table(table_name, schema=schema)

def has_column(table_name: str, column_name: str, schema: Optional[str] = None) -> bool:
    insp = _inspector()
    for col in insp.get_columns(table_name, schema=schema):
        if col.get("name") == column_name:
            return True
    return False

def has_index(table_name: str, index_name: str, schema: Optional[str] = None) -> bool:
    insp = _inspector()
    for idx in insp.get_indexes(table_name, schema=schema):
        if idx.get("name") == index_name:
            return True
    return False

def create_index_if_not_exists(
    name: str,
    table_name: str,
    columns: Sequence[str],
    *,
    unique: bool = False,
    schema: Optional[str] = None,
    concurrently: bool = False,
) -> None:
    if has_index(table_name, name, schema=schema):
        return
    dialect = op.get_bind().dialect.name
    # PostgreSQL: CONCURRENTLY — только вне транзакции
    if dialect == "postgresql" and concurrently:
        # Важно: autocommit_block требуется для CONCURRENTLY (см. Alembic ops)
        with op.get_context().autocommit_block():
            op.create_index(
                name, table_name, [sa.text(c) for c in columns],
                unique=unique, schema=schema, postgresql_concurrently=True
            )
    else:
        op.create_index(name, table_name, [sa.text(c) for c in columns], unique=unique, schema=schema)

def drop_index_if_exists(
    name: str,
    table_name: str,
    *,
    schema: Optional[str] = None,
    concurrently: bool = False,
) -> None:
    if not has_index(table_name, name, schema=schema):
        return
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql" and concurrently:
        with op.get_context().autocommit_block():
            op.drop_index(name, table_name=table_name, schema=schema, postgresql_concurrently=True)
    else:
        op.drop_index(name, table_name=table_name, schema=schema)

def add_column_if_not_exists(
    table_name: str,
    column: sa.Column,
    *,
    schema: Optional[str] = None,
    nullable: Optional[bool] = None,
) -> None:
    if has_column(table_name, column.name, schema=schema):
        return
    op.add_column(table_name, column, schema=schema)
    # При необходимости изменяем nullability отдельно (особенно для БД, требующих двух шагов)
    if nullable is not None:
        op.alter_column(table_name, column.name, nullable=nullable, schema=schema)

def drop_column_if_exists(
    table_name: str,
    column_name: str,
    *,
    schema: Optional[str] = None,
) -> None:
    if not has_column(table_name, column_name, schema=schema):
        return
    op.drop_column(table_name, column_name, schema=schema)

def create_table_if_not_exists(
    table_name: str,
    *columns: sa.Column,
    schema: Optional[str] = None,
    **kw,
) -> None:
    if has_table(table_name, schema=schema):
        return
    op.create_table(table_name, *columns, schema=schema, **kw)

# ------------------------------------------------------------------------------
# UPGRADE / DOWNGRADE — ДОБАВЛЯЙТЕ ОПЕРАЦИИ НИЖЕ
# ------------------------------------------------------------------------------

def upgrade() -> None:
    """Применение ревизии (вперёд). Добавляйте операции ниже.

    Примеры (см. Alembic Operations API):
        # Создать таблицу, если её нет
        create_table_if_not_exists(
            "example_table",
            sa.Column("id", sa.BigInteger, primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("name", sa.Text, nullable=False),
            sa.UniqueConstraint("name", name="uq_example_name"),
        )

        # Добавить колонку безопасно
        add_column_if_not_exists("example_table", sa.Column("description", sa.Text), nullable=True)

        # Индекс (PostgreSQL CONCURRENTLY)
        create_index_if_not_exists(
            "ix_example_created_at", "example_table", ["created_at"],
            concurrently=True  # только для PostgreSQL
        )
    """
    pass


def downgrade() -> None:
    """Откат ревизии (назад). Добавляйте обратные операции ниже.

    Примеры:
        drop_index_if_exists("ix_example_created_at", "example_table", concurrently=True)
        drop_column_if_exists("example_table", "description")
        # op.drop_table("example_table")
    """
    pass
