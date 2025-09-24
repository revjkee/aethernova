# oblivionvault-core/oblivionvault/workers/legal_hold_worker.py
"""
Legal Hold Worker — промышленный асинхронный воркер для OblivionVault.

Функции:
- Приём и идемпотентная обработка команд Legal Hold (apply, extend, release, check).
- Политики удержания (нельзя сокращать срок, режимы COMPLIANCE/GOVERNANCE, минимальные/максимальные сроки).
- Устойчивые ретраи с экспоненциальным backoff и джиттером.
- Аудит всех операций через oblivionvault.audit.logger.AuditLogger.
- Устойчивое хранилище состояния и идемпотентных ключей на SQLite.
- Абстракции очереди и backend’а; реализация backend’а для S3 Object Lock.

Зависимости (обязательные): стандартная библиотека, oblivionvault.audit.logger (ваш модуль аудита).
Опциональные: aioboto3, botocore — только если используется S3 backend.

Интеграция:
    from oblivionvault.audit.logger import AuditConfig, AuditLogger, FileSink
    from oblivionvault.workers.legal_hold_worker import (
        LegalHoldWorker, LegalHoldConfig, InMemoryQueue, S3LegalHoldBackend, PolicyConfig
    )

    audit = await AuditLogger.start(AuditConfig(...))
    queue = InMemoryQueue()
    backend = S3LegalHoldBackend(bucket="vault-data", endpoint_url=None, region_name="eu-north-1")

    cfg = LegalHoldConfig(
        sqlite_path="/var/lib/oblivionvault/legal_hold.db",
        concurrency=8,
        max_backoff_seconds=8.0
    )
    policy = PolicyConfig(
        default_mode="COMPLIANCE",
        min_retention_days=7,
        max_retention_days=3650,   # 10 лет
        forbid_shorten=True
    )

    worker = await LegalHoldWorker.start(cfg, backend=backend, queue=queue, audit=audit, policy=policy)
    ...
    await worker.close()

Команда (пример):
    await queue.feed({
        "id": "cmd-123",
        "type": "APPLY",
        "key": "docs/contract.pdf",
        "version_id": None,
        "until": "2030-01-01T00:00:00Z",
        "reason": "Litigation XYZ",
        "policy_id": "case-xyz",
        "requester": "legal:alice",
    })
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import random
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple, Union

# ----- Опциональные импорты для S3 backend -----
try:  # pragma: no cover
    import aioboto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
    _S3_AVAILABLE = True
except Exception:  # pragma: no cover
    _S3_AVAILABLE = False

# ----- Аудит -----
with contextlib.suppress(Exception):
    # Предполагается, что модуль аудита присутствует в проекте.
    from oblivionvault.audit.logger import AuditLogger  # type: ignore
    _AUDIT_AVAILABLE = True
try:
    AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    _AUDIT_AVAILABLE = False
    class AuditLogger:  # type: ignore
        async def log(self, **_: Any) -> None: ...
        @classmethod
        async def start(cls, *_: Any, **__: Any) -> "AuditLogger": return cls()
        async def close(self) -> None: ...


# ==========================
# Константы и утилиты
# ==========================
ISO8601 = "%Y-%m-%dT%H:%M:%SZ"

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def parse_ts(ts: Union[str, datetime, None]) -> Optional[datetime]:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc)
    # Поддержка Z-формата и ISO
    try:
        if ts.endswith("Z"):
            return datetime.strptime(ts, ISO8601).replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        raise ValueError(f"Invalid timestamp: {ts}")

def to_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime(ISO8601)

def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def jittered_backoff(base: float, attempt: int, cap: float) -> float:
    # экспоненциальный рост с джиттером
    delay = min(cap, base * (2 ** attempt))
    return delay * (0.5 + random.random() / 2.0)


# ==========================
# Команды Legal Hold
# ==========================
class CommandType(str, Enum):
    APPLY = "APPLY"
    EXTEND = "EXTEND"
    RELEASE = "RELEASE"
    CHECK = "CHECK"

@dataclass(frozen=True)
class LegalHoldCommand:
    id: str
    type: CommandType
    key: str
    version_id: Optional[str] = None
    until: Optional[datetime] = None
    reason: Optional[str] = None
    policy_id: Optional[str] = None
    requester: Optional[str] = None
    created_at: datetime = field(default_factory=utcnow)

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "LegalHoldCommand":
        return LegalHoldCommand(
            id=str(d["id"]),
            type=CommandType(str(d["type"]).upper()),
            key=str(d["key"]),
            version_id=d.get("version_id"),
            until=parse_ts(d.get("until")),
            reason=d.get("reason"),
            policy_id=d.get("policy_id"),
            requester=d.get("requester"),
            created_at=parse_ts(d.get("created_at")) or utcnow(),
        )


# ==========================
# Политики удержания
# ==========================
@dataclass(frozen=True)
class PolicyConfig:
    default_mode: str = "COMPLIANCE"   # или GOVERNANCE
    min_retention_days: int = 1
    max_retention_days: int = 3650
    forbid_shorten: bool = True

class PolicyEngine:
    def __init__(self, cfg: PolicyConfig) -> None:
        mode = cfg.default_mode.upper()
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("default_mode must be COMPLIANCE or GOVERNANCE")
        self.cfg = cfg

    def decide(self, cmd: LegalHoldCommand, current_until: Optional[datetime]) -> Tuple[str, Optional[datetime]]:
        """
        Возвращает (mode, effective_until) для APPLY/EXTEND.
        Для RELEASE валидация производится отдельно.
        """
        mode = self.cfg.default_mode
        now = utcnow()
        # нормализуем until по политикам
        if cmd.until is None:
            # Минимум
            eff = now + timedelta(days=self.cfg.min_retention_days)
        else:
            eff = cmd.until
        # Ограничения
        min_until = now + timedelta(days=self.cfg.min_retention_days)
        max_until = now + timedelta(days=self.cfg.max_retention_days)
        if eff < min_until:
            eff = min_until
        if eff > max_until:
            eff = max_until
        # Нельзя сокращать существующее удержание
        if self.cfg.forbid_shorten and current_until and eff < current_until:
            eff = current_until
        return mode, eff

    def can_release(self, current_until: Optional[datetime]) -> bool:
        # Разрешаем снятие только если уже истёк срок и forbid_shorten=True.
        # При GOVERNANCE-моде можно снять при наличии специальных полномочий — вне рамок воркера.
        if not self.cfg.forbid_shorten:
            return True
        if current_until is None:
            return True
        return utcnow() >= current_until


# ==========================
# State Store (SQLite)
# ==========================
class SQLiteLegalHoldState:
    """
    Хранит:
    - processed(id TEXT PRIMARY KEY, at TIMESTAMP)
    - holds(key TEXT, version_id TEXT, until TIMESTAMP, mode TEXT, policy_id TEXT, reason TEXT, updated_at TIMESTAMP,
            PRIMARY KEY(key, COALESCE(version_id,'')))
    """
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._init_done = False

    async def init(self) -> None:
        async with self._lock:
            if self._init_done:
                return
            await asyncio.to_thread(self._init_sync)
            self._init_done = True

    def _init_sync(self) -> None:
        con = sqlite3.connect(self.path.as_posix(), timeout=30.0, isolation_level=None)
        try:
            con.execute("PRAGMA journal_mode=WAL;")
            con.execute("PRAGMA synchronous=NORMAL;")
            con.execute("""
                CREATE TABLE IF NOT EXISTS processed(
                    id TEXT PRIMARY KEY,
                    at TIMESTAMP NOT NULL
                );
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS holds(
                    key TEXT NOT NULL,
                    version_id TEXT,
                    until TIMESTAMP,
                    mode TEXT,
                    policy_id TEXT,
                    reason TEXT,
                    updated_at TIMESTAMP NOT NULL,
                    PRIMARY KEY(key, COALESCE(version_id,''))
                );
            """)
        finally:
            con.close()

    async def is_processed(self, cmd_id: str) -> bool:
        await self.init()
        def _q() -> bool:
            con = sqlite3.connect(self.path.as_posix(), timeout=30.0, isolation_level=None)
            try:
                cur = con.execute("SELECT 1 FROM processed WHERE id=?;", (cmd_id,))
                return cur.fetchone() is not None
            finally:
                con.close()
        return await asyncio.to_thread(_q)

    async def mark_processed(self, cmd_id: str) -> None:
        await self.init()
        def _ins() -> None:
            con = sqlite3.connect(self.path.as_posix(), timeout=30.0, isolation_level=None)
            try:
                con.execute("INSERT OR IGNORE INTO processed(id, at) VALUES(?,?);", (cmd_id, utcnow().isoformat()))
            finally:
                con.close()
        await asyncio.to_thread(_ins)

    async def get_hold(self, key: str, version_id: Optional[str]) -> Tuple[Optional[datetime], Optional[str]]:
        await self.init()
        def _q() -> Tuple[Optional[datetime], Optional[str]]:
            con = sqlite3.connect(self.path.as_posix(), timeout=30.0, isolation_level=None)
            try:
                cur = con.execute(
                    "SELECT until, mode FROM holds WHERE key=? AND COALESCE(version_id,'')=COALESCE(?, '');",
                    (key, version_id),
                )
                row = cur.fetchone()
                if not row:
                    return None, None
                until_raw, mode = row
                until = parse_ts(until_raw) if isinstance(until_raw, str) else None
                return until, mode
            finally:
                con.close()
        return await asyncio.to_thread(_q)

    async def upsert_hold(
        self, key: str, version_id: Optional[str], until: Optional[datetime], mode: Optional[str],
        policy_id: Optional[str], reason: Optional[str]
    ) -> None:
        await self.init()
        def _do() -> None:
            con = sqlite3.connect(self.path.as_posix(), timeout=30.0, isolation_level=None)
            try:
                con.execute(
                    """
                    INSERT INTO holds(key, version_id, until, mode, policy_id, reason, updated_at)
                    VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(key, COALESCE(version_id,'')) DO UPDATE SET
                        until=excluded.until, mode=excluded.mode, policy_id=excluded.policy_id,
                        reason=excluded.reason, updated_at=excluded.updated_at;
                    """,
                    (
                        key,
                        version_id,
                        to_iso(until),
                        mode,
                        policy_id,
                        reason,
                        utcnow().isoformat(),
                    ),
                )
            finally:
                con.close()
        await asyncio.to_thread(_do)


# ==========================
# Backend абстракция
# ==========================
class LegalHoldError(Exception): ...
class BackendNotSupported(LegalHoldError): ...
class BackendTransientError(LegalHoldError): ...

class LegalHoldBackend:
    async def apply(self, key: str, version_id: Optional[str], mode: str, until: datetime) -> None:
        raise NotImplementedError
    async def extend(self, key: str, version_id: Optional[str], mode: str, until: datetime) -> None:
        # По умолчанию то же, что apply (идемпотентно)
        await self.apply(key, version_id, mode, until)
    async def release(self, key: str, version_id: Optional[str]) -> None:
        raise NotImplementedError
    async def get(self, key: str, version_id: Optional[str]) -> Tuple[Optional[datetime], Optional[str]]:
        raise NotImplementedError


# ==========================
# S3 Object Lock backend
# ==========================
class S3LegalHoldBackend(LegalHoldBackend):
    """
    Требуется: бакет с включённым Object Lock.
    Использует:
      - put_object_retention/get_object_retention для срока удержания,
      - put_object_legal_hold/get_object_legal_hold для флага LegalHold ON/OFF.
    """
    def __init__(
        self,
        bucket: str,
        endpoint_url: Optional[str] = None,
        region_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
        path_style: bool = False,
        signature_version: Optional[str] = None,
        connect_timeout: float = 10.0,
        read_timeout: float = 60.0,
    ) -> None:
        if not _S3_AVAILABLE:
            raise BackendNotSupported("aioboto3/botocore not available for S3 backend")
        self.bucket = bucket
        self.endpoint_url = endpoint_url
        self.region_name = region_name
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.path_style = path_style
        self.signature_version = signature_version
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self._session = aioboto3.Session()
        self._client = None  # type: ignore

    async def _client_ctx(self):
        if self._client is None:
            from botocore.config import Config as BotoConfig  # type: ignore
            cfg = BotoConfig(
                s3={"addressing_style": "path" if self.path_style else "auto"},
                signature_version=self.signature_version,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
                retries={"max_attempts": 10, "mode": "standard"},
            )
            self._client = await self._session.client(
                "s3",
                region_name=self.region_name,
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                aws_session_token=self.session_token,
                config=cfg,
            ).__aenter__()
        return self._client

    async def _with_client(self):
        c = await self._client_ctx()
        return c

    async def apply(self, key: str, version_id: Optional[str], mode: str, until: datetime) -> None:
        c = await self._with_client()
        try:
            await c.put_object_retention(
                Bucket=self.bucket,
                Key=key,
                VersionId=version_id,
                Retention={
                    "Mode": mode.upper(),  # COMPLIANCE | GOVERNANCE
                    "RetainUntilDate": until.astimezone(timezone.utc)
                },
                BypassGovernanceRetention=False,
            )
            await c.put_object_legal_hold(
                Bucket=self.bucket,
                Key=key,
                VersionId=version_id,
                LegalHold={"Status": "ON"},
            )
        except ClientError as e:  # pragma: no cover
            code = (e.response or {}).get("Error", {}).get("Code")
            if code in {"InternalError", "ServiceUnavailable", "SlowDown"}:
                raise BackendTransientError(str(e))
            raise

    async def extend(self, key: str, version_id: Optional[str], mode: str, until: datetime) -> None:
        # В S3 продление — то же, что установка большего RetainUntilDate
        await self.apply(key, version_id, mode, until)

    async def release(self, key: str, version_id: Optional[str]) -> None:
        c = await self._with_client()
        try:
            # Снимаем LegalHold (если срок истёк, это разрешено; иначе Governance требует bypass)
            await c.put_object_legal_hold(
                Bucket=self.bucket,
                Key=key,
                VersionId=version_id,
                LegalHold={"Status": "OFF"},
            )
        except ClientError as e:  # pragma: no cover
            code = (e.response or {}).get("Error", {}).get("Code")
            if code in {"InternalError", "ServiceUnavailable", "SlowDown"}:
                raise BackendTransientError(str(e))
            raise

    async def get(self, key: str, version_id: Optional[str]) -> Tuple[Optional[datetime], Optional[str]]:
        c = await self._with_client()
        until: Optional[datetime] = None
        mode: Optional[str] = None
        try:
            r = await c.get_object_retention(Bucket=self.bucket, Key=key, VersionId=version_id)
            ret = r.get("Retention") or {}
            mode = ret.get("Mode")
            u = ret.get("RetainUntilDate")
            if u:
                until = u if isinstance(u, datetime) else parse_ts(str(u))
        except ClientError:
            pass  # не установлен retention
        # LegalHold статус можно получить при необходимости, но для политики достаточно RetainUntilDate
        return until, mode


# ==========================
# Очередь команд
# ==========================
class LegalHoldQueue:
    async def poll(self, timeout: float = 1.0) -> Optional[Mapping[str, Any]]:
        raise NotImplementedError

class InMemoryQueue(LegalHoldQueue):
    def __init__(self) -> None:
        self._q: asyncio.Queue[Mapping[str, Any]] = asyncio.Queue()

    async def feed(self, item: Mapping[str, Any]) -> None:
        await self._q.put(dict(item))

    async def poll(self, timeout: float = 1.0) -> Optional[Mapping[str, Any]]:
        try:
            return await asyncio.wait_for(self._q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


# ==========================
# Конфигурация воркера
# ==========================
@dataclass
class LegalHoldConfig:
    sqlite_path: Union[str, Path]
    concurrency: int = 4
    max_backoff_seconds: float = 8.0
    base_backoff_seconds: float = 0.25
    poll_timeout_seconds: float = 1.0
    shutdown_grace_seconds: float = 20.0


# ==========================
# Воркер
# ==========================
class LegalHoldWorker:
    def __init__(
        self,
        cfg: LegalHoldConfig,
        backend: LegalHoldBackend,
        queue: LegalHoldQueue,
        audit: Optional[AuditLogger],
        policy: PolicyConfig,
    ) -> None:
        self.cfg = cfg
        self.backend = backend
        self.queue = queue
        self.audit = audit
        self.policy = PolicyEngine(policy)
        self.state = SQLiteLegalHoldState(cfg.sqlite_path)
        self._stop = asyncio.Event()
        self._tasks: Sequence[asyncio.Task] = []

    @classmethod
    async def start(
        cls,
        cfg: LegalHoldConfig,
        *,
        backend: LegalHoldBackend,
        queue: LegalHoldQueue,
        audit: Optional[AuditLogger],
        policy: PolicyConfig,
    ) -> "LegalHoldWorker":
        self = cls(cfg, backend=backend, queue=queue, audit=audit, policy=policy)
        await self.state.init()
        # Параллельные воркеры
        self._tasks = [asyncio.create_task(self._run_loop(i), name=f"legal-hold-{i}") for i in range(cfg.concurrency)]
        return self

    async def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(asyncio.gather(*self._tasks), timeout=self.cfg.shutdown_grace_seconds)

    # -------- Основной цикл --------
    async def _run_loop(self, wid: int) -> None:
        attempt = 0
        while not self._stop.is_set():
            try:
                cmd_raw = await self.queue.poll(timeout=self.cfg.poll_timeout_seconds)
                if cmd_raw is None:
                    attempt = 0
                    continue
                cmd = LegalHoldCommand.from_dict(cmd_raw)
                await self._process(cmd)
                attempt = 0
            except BackendTransientError as e:
                delay = jittered_backoff(self.cfg.base_backoff_seconds, attempt, self.cfg.max_backoff_seconds)
                attempt += 1
                await self._audit("legalhold.retry", outcome="error", details={"reason": str(e), "attempt": attempt})
                await asyncio.sleep(delay)
            except Exception as e:
                # Не прячем ошибки — но не падаем аварийно
                await self._audit("legalhold.unexpected_error", outcome="error", details={"error": repr(e)})
                attempt = 0

    # -------- Обработка команд --------
    async def _process(self, cmd: LegalHoldCommand) -> None:
        # Идемпотентность
        if await self.state.is_processed(cmd.id):
            await self._audit("legalhold.skip_duplicate", outcome="success", details={"cmd_id": cmd.id})
            return

        # Текущее состояние удержания
        current_until, current_mode = await self.state.get_hold(cmd.key, cmd.version_id)

        if cmd.type in (CommandType.APPLY, CommandType.EXTEND):
            mode, eff_until = self.policy.decide(cmd, current_until)
            assert eff_until is not None
            # Если удержание уже длиннее — no-op
            if current_until and eff_until <= current_until:
                await self._audit("legalhold.noop", outcome="success", details={
                    "cmd_id": cmd.id, "key": cmd.key, "version_id": cmd.version_id,
                    "current_until": to_iso(current_until), "requested_until": to_iso(eff_until)
                })
                await self.state.mark_processed(cmd.id)
                return
            # Применяем/продлеваем
            await self.backend.extend(cmd.key, cmd.version_id, mode, eff_until)
            await self.state.upsert_hold(cmd.key, cmd.version_id, eff_until, mode, cmd.policy_id, cmd.reason)
            await self.state.mark_processed(cmd.id)
            await self._audit("legalhold.applied", outcome="success", details={
                "cmd_id": cmd.id, "key": cmd.key, "version_id": cmd.version_id,
                "mode": mode, "until": to_iso(eff_until), "policy_id": cmd.policy_id, "reason": cmd.reason
            })
            return

        if cmd.type == CommandType.RELEASE:
            if not self.policy.can_release(current_until):
                await self._audit("legalhold.release_blocked", outcome="deny", details={
                    "cmd_id": cmd.id, "key": cmd.key, "version_id": cmd.version_id,
                    "current_until": to_iso(current_until)
                })
                # Идемпотентность: команду пометим обработанной, чтобы не зацикливаться,
                # но внешняя система может сгенерировать повтор позже
                await self.state.mark_processed(cmd.id)
                return
            await self.backend.release(cmd.key, cmd.version_id)
            await self.state.upsert_hold(cmd.key, cmd.version_id, None, current_mode, None, "released")
            await self.state.mark_processed(cmd.id)
            await self._audit("legalhold.released", outcome="success", details={
                "cmd_id": cmd.id, "key": cmd.key, "version_id": cmd.version_id
            })
            return

        if cmd.type == CommandType.CHECK:
            # Сверяемся с backend, актуализируем состояние
            b_until, b_mode = await self.backend.get(cmd.key, cmd.version_id)
            # Если backend сообщил больше — доверяем backend
            eff_until = b_until
            if b_until and current_until and b_until < current_until:
                # Не сокращаем локально, но фиксируем расхождение
                await self._audit("legalhold.discrepancy", outcome="info", details={
                    "cmd_id": cmd.id, "key": cmd.key, "backend_until": to_iso(b_until),
                    "local_until": to_iso(current_until)
                })
                eff_until = current_until
            await self.state.upsert_hold(cmd.key, cmd.version_id, eff_until, b_mode or current_mode, cmd.policy_id, cmd.reason)
            await self.state.mark_processed(cmd.id)
            await self._audit("legalhold.checked", outcome="success", details={
                "cmd_id": cmd.id, "key": cmd.key, "version_id": cmd.version_id,
                "backend_until": to_iso(b_until), "mode": b_mode
            })
            return

        # Неизвестный тип
        raise ValueError(f"Unsupported command type: {cmd.type}")

    # -------- Аудит --------
    async def _audit(self, action: str, outcome: str, details: Mapping[str, Any]) -> None:
        if not _AUDIT_AVAILABLE or self.audit is None:
            return
        await self.audit.log(
            action=action,
            actor="worker:legal_hold",
            outcome=outcome,
            details=dict(details),
            labels={"component": "legal_hold_worker"}
        )


# ==========================
# Мини-CLI (опционально)
# ==========================
async def _stdin_loop(worker: LegalHoldWorker) -> None:
    """
    Опциональный режим: читать команды из stdin построчно в формате JSON.
    """
    loop = asyncio.get_running_loop()
    q = worker.queue
    if not isinstance(q, InMemoryQueue):
        return
    def _readline() -> Optional[str]:
        try:
            return input()
        except EOFError:
            return None
    while True:
        line = await asyncio.to_thread(_readline)
        if line is None:
            break
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            await q.feed(obj)
        except Exception:
            await worker._audit("legalhold.cli_bad_input", outcome="error", details={"line": line})


if __name__ == "__main__":  # pragma: no cover
    # Пример запуска в самостоятельном режиме — читает JSON-команды из stdin.
    # Под реальные деплой-конфиги интегрируйте воркер в ваш рантайм.
    async def main():
        cfg = LegalHoldConfig(sqlite_path=os.environ.get("OV_LEGAL_HOLD_DB", "./legal_hold.db"))
        queue = InMemoryQueue()
        policy = PolicyConfig()
        backend: LegalHoldBackend
        if _S3_AVAILABLE:
            backend = S3LegalHoldBackend(
                bucket=os.environ.get("OV_S3_BUCKET", "vault-data"),
                endpoint_url=os.environ.get("OV_S3_ENDPOINT"),
                region_name=os.environ.get("OV_S3_REGION"),
                access_key_id=os.environ.get("OV_S3_ACCESS_KEY_ID"),
                secret_access_key=os.environ.get("OV_S3_SECRET_ACCESS_KEY"),
                session_token=os.environ.get("OV_S3_SESSION_TOKEN"),
                path_style=os.environ.get("OV_S3_PATH_STYLE", "false").lower() == "true",
                signature_version=os.environ.get("OV_S3_SIGVER") or None,
            )
        else:
            raise SystemExit("S3 backend unavailable: install aioboto3/botocore or integrate a custom backend")

        audit = None
        worker = await LegalHoldWorker.start(cfg, backend=backend, queue=queue, audit=audit, policy=policy)
        await _stdin_loop(worker)
        await worker.close()

    asyncio.run(main())
