# File: automation-core/examples/save_accounts_sqlite.py
"""
Промышленный асинхронный импорт и апсерт аккаунтов в SQLite (SQLAlchemy 2.x, asyncio).

Возможности:
- Только асинхронный SQLAlchemy (create_async_engine, AsyncSession).
- Надёжная валидация входных данных, отчёты об ошибках, структурированное логирование.
- Идемпотентный апсерт по username/email (предварительная выборка, массовое обновление/добавление).
- Уникальные ограничения и индексы на уровне БД.
- Безопасное хранение пароля: PBKDF2-HMAC-SHA256 с солью и префиксом формата.
- Прозрачные PRAGMA для SQLite (WAL, foreign_keys, busy_timeout).
- Поддержка JSON/CSV источников.
- Пакетная обработка с настраиваемым размером батча.
- Типизация, docstring, детерминированная обработка времени (UTC).

Зависимости:
- Python 3.11+
- SQLAlchemy 2.0+
- aiosqlite (драйвер для async SQLite через SQLAlchemy)

Установка:
    pip install "sqlalchemy>=2.0" "aiosqlite>=0.20"

Примеры запуска:
    # JSON массив объектов
    python -m automation_core.examples.save_accounts_sqlite \
        --db sqlite+aiosqlite:///./accounts.db \
        --input ./accounts.json \
        --format json

    # CSV с заголовками: username,email,password,display_name,status
    python -m automation_core.examples.save_accounts_sqlite \
        --db sqlite+aiosqlite:///./accounts.db \
        --input ./accounts.csv \
        --format csv \
        --batch-size 1000

Формат входных записей (JSON и CSV):
{
  "username": "alice",          # обязателен (либо email)
  "email": "alice@example.com", # обязателен (либо username)
  "password": "plain-or-empty", # опционально; если пусто — hash не записывается
  "display_name": "Alice",      # опционально
  "status": "active"            # опционально: active|disabled|pending
}

Примечание:
- Если присутствуют и username, и email — поиск существующей записи идёт по username, затем по email.
- Если password отсутствует/пустой — поле password_hash останется NULL (в дальнейшем можно установить через отдельный процесс).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    String,
    UniqueConstraint,
    select,
    text,
    func,
    literal_column,
    or_,
)
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------
# Логирование (минималистичное структурированное)
# ---------------------------

LOG = logging.getLogger("save_accounts_sqlite")
_handler = logging.StreamHandler(sys.stdout)
_formatter = logging.Formatter(
    fmt='%(asctime)s %(levelname)s %(name)s | msg="%(message)s"'
)
_handler.setFormatter(_formatter)
LOG.addHandler(_handler)
LOG.setLevel(logging.INFO)

# ---------------------------
# Константы и утилиты
# ---------------------------

EMAIL_RE = re.compile(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}$", re.IGNORECASE)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,64}$")
STATUS_ALLOWED = {"active", "disabled", "pending"}

PBKDF2_ALGO = "pbkdf2_sha256"
PBKDF2_ITERATIONS_DEFAULT = 210_000
PBKDF2_SALT_BYTES = 16
PBKDF2_DERIVED_KEY_LEN = 32  # 256-bit

UTC = dt.timezone.utc


def utcnow() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def normalize_status(value: Optional[str]) -> str:
    if not value:
        return "active"
    v = value.strip().lower()
    return v if v in STATUS_ALLOWED else "pending"


def hash_password_pbkdf2(password: str, iterations: int = PBKDF2_ITERATIONS_DEFAULT) -> str:
    """
    Хэш пароля PBKDF2-HMAC-SHA256.
    Формат хранения: pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>
    """
    if not password:
        raise ValueError("Empty password cannot be hashed")
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=PBKDF2_DERIVED_KEY_LEN)
    return f"{PBKDF2_ALGO}${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def validate_email(email: Optional[str]) -> Optional[str]:
    if email is None:
        return None
    e = email.strip()
    if not e:
        return None
    if not EMAIL_RE.match(e):
        raise ValueError(f"Invalid email: {e}")
    return e.lower()


def validate_username(username: Optional[str]) -> Optional[str]:
    if username is None:
        return None
    u = username.strip()
    if not u:
        return None
    if not USERNAME_RE.match(u):
        raise ValueError(f"Invalid username: {u}")
    return u


# ---------------------------
# Модель и база
# ---------------------------

class Base(AsyncAttrs, DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="UUIDv4 в строковом виде",
    )
    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(254), nullable=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    # Техническая версия для оптимистичных обновлений и отладки миграций/апсертов
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("username", name="uq_accounts_username"),
        UniqueConstraint("email", name="uq_accounts_email"),
        CheckConstraint(
            "status in ('active','disabled','pending')",
            name="ck_accounts_status",
        ),
        Index("ix_accounts_username", "username"),
        Index("ix_accounts_email", "email"),
        Index("ix_accounts_status", "status"),
        Index("ix_accounts_updated_at", "updated_at"),
    )

    def __repr__(self) -> str:
        return f"<Account id={self.id} username={self.username} email={self.email} status={self.status}>"


# ---------------------------
# DTO и парсинг входа
# ---------------------------

@dataclasses.dataclass(slots=True, frozen=True)
class AccountIn:
    username: Optional[str]
    email: Optional[str]
    password: Optional[str]
    display_name: Optional[str]
    status: Optional[str]

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "AccountIn":
        return AccountIn(
            username=d.get("username"),
            email=d.get("email"),
            password=d.get("password"),
            display_name=d.get("display_name"),
            status=d.get("status"),
        )

    def validated(self) -> "AccountIn":
        u = validate_username(self.username)
        e = validate_email(self.email)
        if not (u or e):
            raise ValueError("Either username or email must be provided")
        s = normalize_status(self.status)
        dn = (self.display_name or "").strip() or None
        pw = (self.password or "").strip() or None
        return AccountIn(username=u, email=e, password=pw, display_name=dn, status=s)


def read_json_records(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        # допускаем объект-обёртку {"items":[...]}
        items = data.get("items")
        if isinstance(items, list):
            return [r for r in items if isinstance(r, dict)]
        raise ValueError("JSON must be an array or an object with 'items' list")
    if not isinstance(data, list):
        raise ValueError("JSON must be an array")
    return [r for r in data if isinstance(r, dict)]


def read_csv_records(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def load_accounts(path: Path, fmt: str) -> list[AccountIn]:
    if fmt == "json":
        raw = read_json_records(path)
    elif fmt == "csv":
        raw = read_csv_records(path)
    else:
        raise ValueError("Unsupported format: must be 'json' or 'csv'")
    records: list[AccountIn] = []
    errors = 0
    for i, r in enumerate(raw, start=1):
        try:
            records.append(AccountIn.from_dict(r).validated())
        except Exception as exc:
            errors += 1
            LOG.warning(f"skip record #{i}: validation error: {exc}")
    LOG.info(f"parsed={len(records)} skipped={errors}")
    return records


# ---------------------------
# Подключение к БД и PRAGMA
# ---------------------------

async def apply_sqlite_pragmas(session: AsyncSession) -> None:
    # Важные PRAGMA для производительности и надёжности импорта
    await session.execute(text("PRAGMA journal_mode=WAL"))
    await session.execute(text("PRAGMA foreign_keys=ON"))
    await session.execute(text("PRAGMA busy_timeout=5000"))  # мс


def create_engine_and_sessionmaker(dsn: str) -> tuple[Any, async_sessionmaker[AsyncSession]]:
    """
    Создает AsyncEngine и фабрику сессий.
    dsn пример: sqlite+aiosqlite:///./accounts.db
    """
    engine = create_async_engine(
        dsn,
        echo=False,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={"timeout": 30},  # для aiosqlite
    )
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    return engine, session_factory


# ---------------------------
# Идемпотентный апсерт
# ---------------------------

async def fetch_existing_accounts(
    session: AsyncSession,
    usernames: set[str],
    emails: set[str],
) -> list[Account]:
    conds = []
    if usernames:
        conds.append(Account.username.in_(usernames))
    if emails:
        conds.append(Account.email.in_(emails))
    if not conds:
        return []
    stmt = select(Account).where(or_(*conds))
    res = await session.execute(stmt)
    return list(res.scalars().all())


def _prepare_maps(existing: Sequence[Account]) -> tuple[dict[str, Account], dict[str, Account]]:
    by_username: dict[str, Account] = {}
    by_email: dict[str, Account] = {}
    for acc in existing:
        if acc.username:
            by_username[acc.username] = acc
        if acc.email:
            by_email[acc.email] = acc
    return by_username, by_email


def _hash_or_none(password: Optional[str]) -> Optional[str]:
    if not password:
        return None
    return hash_password_pbkdf2(password)


def _update_account(acc: Account, src: AccountIn) -> bool:
    """
    Обновляет поля существующей записи acc значениями из src.
    Возвращает True, если были изменения.
    """
    changed = False

    # Поля для сравнения/обновления:
    fields: list[tuple[str, Any, Any]] = [
        ("email", acc.email, src.email),
        ("display_name", acc.display_name, src.display_name),
        ("status", acc.status, normalize_status(src.status)),
    ]

    for name, old, new in fields:
        if new is not None and new != old:
            setattr(acc, name, new)
            changed = True

    if src.password:
        new_hash = _hash_or_none(src.password)
        if new_hash and new_hash != acc.password_hash:
            acc.password_hash = new_hash
            changed = True

    if changed:
        # принудительно увеличим ревизию (для отладки апсерт-процесса)
        acc.revision = int(acc.revision or 0) + 1
        acc.updated_at = utcnow()

    return changed


def _new_account(src: AccountIn) -> Account:
    return Account(
        username=src.username,
        email=src.email,
        password_hash=_hash_or_none(src.password),
        display_name=src.display_name,
        status=normalize_status(src.status),
        created_at=utcnow(),
        updated_at=utcnow(),
        revision=0,
    )


async def upsert_accounts(
    session: AsyncSession,
    items: Sequence[AccountIn],
    batch_size: int = 1000,
) -> tuple[int, int]:
    """
    Массовый идемпотентный апсерт:
    - Предварительно выбирает существующие аккаунты по username/email (один раунд запроса).
    - Обновляет найденные, добавляет новые.
    - Коммитит транзакциями по батчам.

    Возвращает (updated, inserted).
    """
    if not items:
        return (0, 0)

    # Соберём ключи
    usernames: set[str] = {i.username for i in items if i.username}
    emails: set[str] = {i.email for i in items if i.email}

    # Одним запросом получим существующие
    existing = await fetch_existing_accounts(session, usernames, emails)
    by_username, by_email = _prepare_maps(existing)

    to_insert: list[Account] = []
    updated = 0

    # Пройдём по входным данным детерминированно
    for src in items:
        acc = None
        if src.username and src.username in by_username:
            acc = by_username[src.username]
        elif src.email and src.email in by_email:
            acc = by_email[src.email]

        if acc is not None:
            if _update_account(acc, src):
                updated += 1
        else:
            to_insert.append(_new_account(src))

    inserted = 0
    # Добавляем новыe аккаунты пакетами
    for i in range(0, len(to_insert), batch_size):
        chunk = to_insert[i : i + batch_size]
        session.add_all(chunk)
        await session.flush()  # получим раннюю проверку ограничений
        inserted += len(chunk)

    return updated, inserted


# ---------------------------
# Инициализация схемы
# ---------------------------

async def ensure_schema(engine, session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        async with session.begin():
            await apply_sqlite_pragmas(session)
    async with engine.begin() as conn:
        # создаём таблицы, если их нет
        await conn.run_sync(Base.metadata.create_all)


# ---------------------------
# CLI
# ---------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="save_accounts_sqlite",
        description="Асинхронный импорт/апсерт аккаунтов в SQLite (SQLAlchemy 2.x).",
    )
    p.add_argument(
        "--db",
        required=True,
        help="DSN БД, напр. sqlite+aiosqlite:///./accounts.db",
    )
    p.add_argument(
        "--input",
        required=True,
        help="Путь к файлу входных данных (JSON/CSV).",
    )
    p.add_argument(
        "--format",
        choices=["json", "csv"],
        required=True,
        help="Формат входных данных.",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Размер батча для вставки новых записей.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Не совершать запись, только валидация и отчёт.",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Уровень логирования.",
    )
    return p.parse_args(argv)


async def main_async(ns: argparse.Namespace) -> int:
    LOG.setLevel(getattr(logging, ns.log_level))
    input_path = Path(ns.input).resolve()
    if not input_path.exists():
        LOG.error(f"input file not found: {input_path}")
        return 2

    try:
        records = load_accounts(input_path, ns.format)
    except Exception as exc:
        LOG.error(f"failed to load input: {exc}")
        return 2

    if not records:
        LOG.info("nothing to do: no valid records")
        return 0

    engine, session_factory = create_engine_and_sessionmaker(ns.db)

    try:
        await ensure_schema(engine, session_factory)
        if ns.dry_run:
            LOG.info("dry-run mode: schema ensured, no writes will occur")

        async with session_factory() as session:
            async with session.begin():
                await apply_sqlite_pragmas(session)

                if ns.dry_run:
                    # В dry-run проверим предварительную выборку, но не будем писать
                    existing = await fetch_existing_accounts(
                        session,
                        {r.username for r in records if r.username},
                        {r.email for r in records if r.email},
                    )
                    LOG.info(
                        f"dry-run: loaded={len(records)} existing={len(existing)}"
                    )
                else:
                    updated, inserted = await upsert_accounts(
                        session, records, batch_size=ns.batch_size
                    )
                    LOG.info(
                        f"done: loaded={len(records)} updated={updated} inserted={inserted}"
                    )
    finally:
        await engine.dispose()

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    ns = parse_args(argv)
    return asyncio.run(main_async(ns))


if __name__ == "__main__":
    raise SystemExit(main())
