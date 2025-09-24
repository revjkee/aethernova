from __future__ import annotations

"""
automation_core.databases.models.account
Промышленная ORM-модель учетной записи (SQLAlchemy 2.0 style).

Характеристики:
- UUID первичный ключ (v4).
- Нормализация email/username и уникальность по нормализованным полям.
- Аудит-поля: created_at, updated_at, last_login_at, deleted_at (soft delete).
- Флаги безопасности: is_active, is_superuser, mfa_enabled.
- Приземленные ограничения длины, индексы по статусу/времени.
- Кросс-СУБД совместимость (SQLite/MySQL/PostgreSQL) + оптимизация для PostgreSQL (функциональный индекс lower(email)).
- JSON-профиль/настройки.
- Минимум бизнес-логики: хэш пароля хранится как строка; валидацию/хэширование выполняйте в сервисном слое.

Зависимости: SQLAlchemy >= 2.0

Примечание:
- Проверку формата email оставляем на уровень сервиса/валидатора. Здесь — нормализация и уникальность.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event,
    func,
)
from sqlalchemy import JSON as SA_JSON  # кросс-СУБД JSON
from sqlalchemy.dialects import postgresql as pg  # type: ignore
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates


# ----------------------------- База и конвенции ------------------------------

class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    # Всегда сохраняем в UTC
    return datetime.now(timezone.utc)


# ----------------------------- Перечисления ----------------------------------

class AccountStatus(str, enum.Enum):
    ACTIVE = "active"
    LOCKED = "locked"
    PENDING = "pending"
    DISABLED = "disabled"


# ----------------------------- Модель Account --------------------------------

class Account(Base):
    __tablename__ = "account"

    # Идентификатор
    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True) if hasattr(pg, "UUID") else String(36),
        primary_key=True,
        default=uuid.uuid4,
        doc="UUID v4 первичный ключ",
    )

    # Учётные поля
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False)

    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    username_normalized: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[AccountStatus] = mapped_column(
        Enum(AccountStatus, native_enum=False, length=16),
        default=AccountStatus.ACTIVE,
        nullable=False,
    )

    # Флаги безопасности/ролей
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Дополнительные сведения
    phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    locale: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    profile: Mapped[Dict[str, Any]] = mapped_column(
        (pg.JSONB if hasattr(pg, "JSONB") else SA_JSON),  # JSONB в PG, JSON в остальных
        default=dict,
        server_default="{}" if not hasattr(pg, "JSONB") else None,
        nullable=False,
        doc="Произвольные настройки/профиль пользователя",
    )

    # Аудит/временные метки
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Soft delete
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Принятие условий/политик
    terms_accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Уникальность по нормализованным значениям
        UniqueConstraint("email_normalized", name="uq_account_email_norm"),
        UniqueConstraint("username_normalized", name="uq_account_username_norm"),
        # Базовые ограничения длины/содержимого (перечисление статусов покрыто Enum)
        CheckConstraint("length(email) >= 3", name="ck_account_email_minlen"),
        CheckConstraint("length(email_normalized) >= 3", name="ck_account_email_norm_minlen"),
        CheckConstraint("(username_normalized IS NULL) OR (length(username_normalized) >= 3)", name="ck_account_username_minlen"),
        # Флаговая взаимосвязь: DISABLED подразумевает is_active=false (на уровне модели, не триггер)
        # (поддерживается доп. валидацией на Python-уровне)
        Index("ix_account_status", "status"),
        Index("ix_account_created_at", "created_at"),
        Index("ix_account_deleted_at", "deleted_at"),
    )

    # ------------------------- Методы модели ---------------------------------

    def mark_deleted(self) -> None:
        self.deleted_at = _utcnow()
        self.is_active = False
        if self.status == AccountStatus.ACTIVE:
            self.status = AccountStatus.DISABLED

    def restore(self) -> None:
        self.deleted_at = None
        # Восстановление оставляет прежний статус, но включает is_active если статус активен
        if self.status == AccountStatus.ACTIVE:
            self.is_active = True

    def set_last_login(self) -> None:
        self.last_login_at = _utcnow()

    # ------------------------- Нормализация ----------------------------------

    @staticmethod
    def _normalize_email(value: str) -> str:
        # Простая нормализация: trim + lower
        return (value or "").strip().lower()

    @staticmethod
    def _normalize_username(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return value.strip().lower() or None

    @validates("email")
    def _set_email(self, key: str, value: str) -> str:
        norm = self._normalize_email(value)
        object.__setattr__(self, "email_normalized", norm)
        return value

    @validates("username")
    def _set_username(self, key: str, value: Optional[str]) -> Optional[str]:
        norm = self._normalize_username(value)
        object.__setattr__(self, "username_normalized", norm)
        return value

    @validates("status", "is_active")
    def _validate_status_active(self, key: str, value: Any) -> Any:
        # Мягкая инварианта: если статус DISABLED — is_active должен быть False.
        # Не бросаем ошибку, а автоисправляем для устойчивости.
        if key == "status" and value == AccountStatus.DISABLED:
            self.is_active = False
        if key == "is_active" and bool(value) is True and getattr(self, "status", None) == AccountStatus.DISABLED:
            # если явно активируют — переводим статус в ACTIVE
            self.status = AccountStatus.ACTIVE
        return value

    # ------------------------- Представление ---------------------------------

    def __repr__(self) -> str:  # pragma: no cover - репрезентация для логов
        return f"<Account id={self.id} email={self.email!r} status={self.status} active={self.is_active}>"


# ------------------------ Пост-объектные индексы (PostgreSQL) ----------------

# Функциональный уникальный индекс по lower(email) для PostgreSQL.
# Для других СУБД уже действует уникальность по email_normalized.
@event.listens_for(Account.__table__, "after_parent_attach")
def _add_pg_functional_indexes(table, parent):  # pragma: no cover - DDL-путь
    try:
        if table.metadata.bind and table.metadata.bind.dialect.name != "postgresql":
            return
    except Exception:
        # metadata.bind может быть None; индекс все равно добавим — он применится при создании в PG
        pass

    # Проверяем, не добавлен ли уже
    names = {ix.name for ix in table.indexes}
    if "uq_account_email_lower" not in names:
        Index(
            "uq_account_email_lower",
            func.lower(table.c.email),
            unique=True,
            postgresql_using="btree",
        ).create(bind=table.metadata.bind) if table.metadata.bind is not None else None


# ------------------------ Хуки обновления времени ----------------------------

@event.listens_for(Account, "before_update", propagate=True)
def _touch_updated_at(mapper, connection, target: Account) -> None:
    # onupdate сработает, но этот хук гарантирует метку даже при частичных апдейтах на некоторых диалектах
    target.updated_at = _utcnow()


__all__ = [
    "Base",
    "Account",
    "AccountStatus",
]
