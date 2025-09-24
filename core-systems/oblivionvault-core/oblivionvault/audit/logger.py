# oblivionvault-core/oblivionvault/audit/logger.py
"""
Промышленный модуль аудита OblivionVault.

Возможности:
- JSON Lines аудит (по одной записи в строке), каноническая сериализация.
- Неизменяемая хеш-цепочка (prev_hash -> hash) для обнаружения tamper.
- Подлинность: HMAC-SHA256 (обязательно) + опциональная подпись Ed25519.
- OpenTelemetry-трассировка (trace_id/span_id) при наличии.
- Асинхронная очередь, батчинг, фоновый флашер, backpressure.
- Приёмники (sinks): FileSink, StdoutSink, S3ChunkSink (S3-совместимый, чанки).
- Безопасная персистенция состояния цепочки (JSON, atomic replace).
- Автоматическое редактирование PII/секретов (настройка ключей и regex).
- Утилита verify_file() для оффлайн-проверки целостности цепочки и подписи.
- Строгая типизация, структурные исключения, устойчивое поведение.

Зависимости: только стандартная библиотека.
Опционально: cryptography (Ed25519 подпись): pip install cryptography
Опционально: opentelemetry-api (трасс-контекст): pip install opentelemetry-api

Пример быстрой инициализации:
    cfg = AuditConfig(
        app="oblivionvault",
        node="vault-1",
        chain_id="daily",
        state_path="/var/lib/oblivionvault/audit_state.json",
        hmac_key=b"...your-strong-key...",
        hmac_key_id="k-2025-08",
        sinks=[FileSink("/var/log/oblivionvault/audit.jsonl")]
    )
    audit = await AuditLogger.start(cfg)
    await audit.log(action="auth.login", actor="user:123", outcome="success", details={"ip":"1.2.3.4"})
    await audit.close()

S3 пример (запись immutable-частей):
    s3sink = S3ChunkSink(
        put_callable=your_async_put_bytes,  # async def(key: str, data: bytes) -> None
        key_prefix="audit/",
        chunk_size=512*1024,                # 512 KiB
        chunk_rollover_sec=10               # или по времени
    )

Политики приватности:
- Поле `details` допускает любой JSON (dict). Редактор PII замещает чувствительные ключи/шаблоны.
- Старайтесь не писать PII без необходимости.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import io
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union, Callable, Awaitable

# -------- Опциональная криптография (Ed25519) --------
try:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False
    Ed25519PrivateKey = Any  # type: ignore
    Ed25519PublicKey = Any  # type: ignore

# -------- Опциональная трассировка --------
try:  # pragma: no cover
    from opentelemetry import trace
    _OTEL_TRACER = trace.get_tracer(__name__)
    def _otel_ids() -> Tuple[Optional[str], Optional[str]]:
        ctx = trace.get_current_span().get_span_context()
        if not ctx or not ctx.is_valid:
            return None, None
        return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
except Exception:  # pragma: no cover
    def _otel_ids() -> Tuple[Optional[str], Optional[str]]:
        return None, None


# ==========================
# Исключения
# ==========================
class AuditError(Exception):
    pass


class AuditQueueOverflow(AuditError):
    pass


class AuditVerificationError(AuditError):
    pass


# ==========================
# Конфигурация и редактирование
# ==========================
@dataclass(frozen=True)
class RedactRule:
    # Ключи словаря, которые надо скрывать (без учёта регистра)
    keys: Tuple[str, ...] = ("password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "cookie")
    # Регулярные выражения для поиска в строках
    patterns: Tuple[str, ...] = (r"(?i)bearer\s+[a-z0-9\.\-_]+", r"(?i)apikey\s*=\s*[a-z0-9\-_]+")
    # Какое значение подставлять
    replacement: str = "***REDACTED***"


class Redactor:
    def __init__(self, rule: Optional[RedactRule] = None) -> None:
        self.rule = rule or RedactRule()
        self._keyset = {k.lower() for k in self.rule.keys}
        self._regexes = [re.compile(p) for p in self.rule.patterns]

    def redact_obj(self, obj: Any) -> Any:
        return self._redact(obj)

    def _redact(self, v: Any) -> Any:
        if isinstance(v, Mapping):
            out: Dict[str, Any] = {}
            for k, val in v.items():
                if str(k).lower() in self._keyset:
                    out[k] = self.rule.replacement
                else:
                    out[k] = self._redact(val)
            return out
        if isinstance(v, list):
            return [self._redact(it) for it in v]
        if isinstance(v, str):
            red = v
            for rx in self._regexes:
                red = rx.sub(self.rule.replacement, red)
            return red
        return v


# ==========================
# Каноническая сериализация
# ==========================
def canonical_json(obj: Any) -> bytes:
    # Стабильная сериализация для HMAC/подписи/хеш-цепочки.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ==========================
# Состояние цепочки
# ==========================
@dataclass
class ChainState:
    chain_id: str
    seq: int = 0
    last_hash_b64: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "ChainState":
        return ChainState(
            chain_id=str(d.get("chain_id", "")),
            seq=int(d.get("seq", 0)),
            last_hash_b64=d.get("last_hash_b64"),
        )


async def _atomic_write(path: Union[str, Path], data: bytes) -> None:
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    def _write():
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    await asyncio.to_thread(_write)


async def _atomic_read(path: Union[str, Path]) -> Optional[bytes]:
    path = Path(path)
    if not path.exists():
        return None
    def _read() -> bytes:
        with open(path, "rb") as f:
            return f.read()
    return await asyncio.to_thread(_read)


# ==========================
# Приёмники (sinks)
# ==========================
class AuditSink:
    async def write_many(self, payloads: Sequence[bytes]) -> None:
        for p in payloads:
            await self.write(p)

    async def write(self, payload: bytes) -> None:
        raise NotImplementedError

    async def flush(self) -> None:
        return None

    async def close(self) -> None:
        return None


class FileSink(AuditSink):
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)

    async def write_many(self, payloads: Sequence[bytes]) -> None:
        # Снижаем syscalls: одно открытие/запись на батч
        data = b"".join(payloads)
        await asyncio.to_thread(self._append, data)

    def _append(self, data: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "ab", buffering=0) as f:
            f.write(data)

    async def write(self, payload: bytes) -> None:
        await asyncio.to_thread(self._append, payload)


class StdoutSink(AuditSink):
    async def write_many(self, payloads: Sequence[bytes]) -> None:
        data = b"".join(payloads)
        await asyncio.to_thread(sys.stdout.buffer.write, data)

    async def write(self, payload: bytes) -> None:
        await asyncio.to_thread(sys.stdout.buffer.write, payload)


class S3ChunkSink(AuditSink):
    """
    Запись чанков в S3-совместимое хранилище как immutable-части.

    put_callable: async def(key: str, data: bytes) -> None
       - например, адаптер S3StorageAdapter.put_bytes(key, data, content_type="application/x-ndjson")
    Схема ключей: {key_prefix}{date}/{chain_id}/{unixms}-{seq}.jsonl
    """
    def __init__(
        self,
        put_callable: Callable[[str, bytes], Awaitable[Any]],
        key_prefix: str = "audit/",
        chunk_size: int = 512 * 1024,
        chunk_rollover_sec: int = 30,
        content_type: str = "application/x-ndjson",
    ) -> None:
        self.put_callable = put_callable
        self.key_prefix = key_prefix
        self.chunk_size = int(chunk_size)
        self.chunk_rollover_sec = int(chunk_rollover_sec)
        self.content_type = content_type
        self._buf = io.BytesIO()
        self._created = time.time()
        self._seq = 0
        self._lock = asyncio.Lock()

    async def write_many(self, payloads: Sequence[bytes]) -> None:
        async with self._lock:
            for p in payloads:
                self._buf.write(p)
                if self._buf.tell() >= self.chunk_size or (time.time() - self._created) >= self.chunk_rollover_sec:
                    await self._flush_locked()

    async def write(self, payload: bytes) -> None:
        await self.write_many([payload])

    async def flush(self) -> None:
        async with self._lock:
            if self._buf.tell() > 0:
                await self._flush_locked()

    async def close(self) -> None:
        await self.flush()

    async def _flush_locked(self) -> None:
        data = self._buf.getvalue()
        self._buf = io.BytesIO()
        self._created = time.time()
        self._seq += 1
        now = datetime.now(timezone.utc)
        date = now.strftime("%Y-%m-%d")
        unixms = int(now.timestamp() * 1000)
        key = f"{self.key_prefix}{date}/{unixms}-{self._seq}.jsonl"
        # put_callable должен уметь проставить content_type, если поддерживает.
        await self.put_callable(key, data)


# ==========================
# Схема события аудита
# ==========================
@dataclass
class AuditEvent:
    action: str
    actor: Optional[str] = None
    subject: Optional[str] = None
    outcome: Optional[str] = None  # success | deny | error | info
    resource: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    tenant: Optional[str] = None
    labels: Optional[Mapping[str, Any]] = None
    details: Optional[Mapping[str, Any]] = None


# ==========================
# Конфиг аудит-логгера
# ==========================
def _default_chain_id() -> str:
    # Ротация цепочки по дню
    return datetime.now(timezone.utc).strftime("chain-%Y-%m-%d")


@dataclass
class AuditConfig:
    app: str
    node: str
    state_path: Union[str, Path]
    sinks: Sequence[AuditSink]
    hmac_key: bytes
    hmac_key_id: str

    # Цепочка и очередь
    chain_id: Optional[str] = None  # если None — auto daily
    queue_maxsize: int = 10000
    batch_size: int = 100
    flush_interval_sec: float = 1.0
    enqueue_timeout_sec: float = 5.0

    # Подпись (опционально, если установлен cryptography)
    ed25519_private_pem: Optional[bytes] = None  # PKCS8 private key (PEM)
    ed25519_key_id: Optional[str] = None

    # Редактор PII
    redact_rule: Optional[RedactRule] = None

    # Пользовательские поля
    extra_static: Optional[Mapping[str, Any]] = None

    # Валидация в рантайме
    def __post_init__(self) -> None:
        if not isinstance(self.hmac_key, (bytes, bytearray)) or len(self.hmac_key) < 32:
            raise ValueError("hmac_key must be >= 32 bytes")
        if not self.hmac_key_id:
            raise ValueError("hmac_key_id must be non-empty")


# ==========================
# Основной аудит-логгер
# ==========================
class AuditLogger:
    def __init__(self, cfg: AuditConfig) -> None:
        self.cfg = cfg
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=cfg.queue_maxsize)
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._redactor = Redactor(cfg.redact_rule)
        self._chain: Optional[ChainState] = None
        self._lock = asyncio.Lock()
        self._signer: Optional[Ed25519PrivateKey] = None
        if cfg.ed25519_private_pem:
            if not _CRYPTO_AVAILABLE:
                raise RuntimeError("cryptography is required for Ed25519 signing")
            self._signer = Ed25519PrivateKey.from_private_bytes(
                _load_pkcs8_raw(cfg.ed25519_private_pem)
            )

    @classmethod
    async def start(cls, cfg: AuditConfig) -> "AuditLogger":
        self = cls(cfg)
        await self._load_or_init_chain()
        self._task = asyncio.create_task(self._flusher_loop(), name="audit-flusher")
        return self

    async def close(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
        await self._flush_sinks()

    # ---------- Публичный API ----------
    async def log(
        self,
        *,
        action: str,
        actor: Optional[str] = None,
        subject: Optional[str] = None,
        outcome: Optional[str] = None,
        resource: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        tenant: Optional[str] = None,
        labels: Optional[Mapping[str, Any]] = None,
        details: Optional[Mapping[str, Any]] = None,
        ts: Optional[datetime] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """
        Основной метод записи аудит-события.
        Блокирует при переполнении очереди не более enqueue_timeout_sec.
        """
        if ts is None:
            ts = datetime.now(timezone.utc)

        # Сбор базовой записи (без хеша/подписи)
        trace_id, span_id = _otel_ids()
        base: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "ts": ts.isoformat(),
            "app": self.cfg.app,
            "node": self.cfg.node,
            "action": action,
            "actor": actor,
            "subject": subject,
            "outcome": outcome,
            "resource": resource,
            "ip": ip,
            "user_agent": user_agent,
            "tenant": tenant,
            "labels": labels or {},
            "details": self._redactor.redact_obj(details or {}),
            "request_id": request_id,
            "session_id": session_id,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        if self.cfg.extra_static:
            # В extra_static запрещаем перекрывать структурные ключи
            for k, v in self.cfg.extra_static.items():
                if k not in base:
                    base[k] = v

        # Дополняем цепочными атрибутами и криптографией
        payload = await self._finalize_event(base)

        # Пытаемся поставить в очередь с таймаутом
        try:
            await asyncio.wait_for(self._queue.put(payload), timeout=self.cfg.enqueue_timeout_sec)
        except asyncio.TimeoutError:
            raise AuditQueueOverflow("audit queue is full; backpressure")  # намеренная ошибка

    # ---------- Служебные ----------
    async def _finalize_event(self, base: Dict[str, Any]) -> Dict[str, Any]:
        async with self._lock:
            await self._maybe_rotate_chain()
            assert self._chain is not None

            base["chain_id"] = self._chain.chain_id
            base["seq"] = self._chain.seq + 1
            base["prev_hash"] = self._chain.last_hash_b64

            # Хешируем канонический вид без полей hash/hmac/signature
            canon = canonical_json(base)
            ev_hash = hashlib.sha256(canon).digest()
            base["hash"] = base64.b64encode(ev_hash).decode("ascii")

            # HMAC
            hmac_bytes = hmac.new(self.cfg.hmac_key, canon, hashlib.sha256).digest()
            base["hmac"] = base64.b64encode(hmac_bytes).decode("ascii")
            base["hmac_key_id"] = self.cfg.hmac_key_id

            # Подпись (опционально)
            if self._signer and self.cfg.ed25519_key_id:
                sig = self._signer.sign(canon)
                base["sig_ed25519"] = base64.b64encode(sig).decode("ascii")
                base["sig_key_id"] = self.cfg.ed25519_key_id

            # Обновляем состояние цепочки и сохраняем на диск атомарно
            self._chain.seq += 1
            self._chain.last_hash_b64 = base["hash"]
            await self._save_chain_state()

            return base

    async def _maybe_rotate_chain(self) -> None:
        # Ротация: если chain_id задан явно — не трогаем; иначе daily на основе даты.
        if self._chain is None:
            return
        if self.cfg.chain_id:
            return
        current = _default_chain_id()
        if self._chain.chain_id != current:
            # новая цепочка
            self._chain = ChainState(chain_id=current, seq=0, last_hash_b64=None)
            await self._save_chain_state()

    async def _load_or_init_chain(self) -> None:
        raw = await _atomic_read(self.cfg.state_path)
        if raw:
            try:
                d = json.loads(raw.decode("utf-8"))
                st = ChainState.from_dict(d)
            except Exception:
                # повреждение состояния — начинаем новую цепочку
                st = ChainState(chain_id=self.cfg.chain_id or _default_chain_id(), seq=0, last_hash_b64=None)
        else:
            st = ChainState(chain_id=self.cfg.chain_id or _default_chain_id(), seq=0, last_hash_b64=None)
        self._chain = st
        await self._save_chain_state()

    async def _save_chain_state(self) -> None:
        assert self._chain is not None
        await _atomic_write(self.cfg.state_path, canonical_json(self._chain.to_dict()))

    async def _flusher_loop(self) -> None:
        """
        Сбор батчей из очереди и запись в синки.
        Гарантия порядка внутри одной цепочки сохраняется.
        """
        batch: List[bytes] = []
        next_flush = time.time() + self.cfg.flush_interval_sec
        while not (self._stop.is_set() and self._queue.empty()):
            timeout = max(0.0, next_flush - time.time())
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                batch.append(canonical_json(item) + b"\n")
                if len(batch) >= self.cfg.batch_size:
                    await self._write_batch(batch)
                    batch.clear()
                    next_flush = time.time() + self.cfg.flush_interval_sec
            except asyncio.TimeoutError:
                if batch:
                    await self._write_batch(batch)
                    batch.clear()
                next_flush = time.time() + self.cfg.flush_interval_sec

        if batch:
            await self._write_batch(batch)

        # Завершаем синки
        await self._flush_sinks()

    async def _write_batch(self, batch: Sequence[bytes]) -> None:
        # Пишем последовательно во все синки; ошибки не прячем.
        for sink in self.cfg.sinks:
            await sink.write_many(batch)

    async def _flush_sinks(self) -> None:
        for sink in self.cfg.sinks:
            try:
                await sink.flush()
                await sink.close()
            except Exception:
                # Аудит должен быть максимально устойчивым; ошибки закрытия логируем в stderr.
                msg = f"[audit] sink {sink.__class__.__name__} close/flush failed"
                await asyncio.to_thread(sys.stderr.write, msg + "\n")


# ==========================
# Подпись: утилиты PKCS8->raw
# ==========================
def _load_pkcs8_raw(pem: bytes) -> bytes:
    """
    Принимает PKCS#8 PEM с Ed25519 приватным ключом и возвращает сырые 32 байта.
    """
    if not _CRYPTO_AVAILABLE:  # pragma: no cover
        raise RuntimeError("cryptography is required for Ed25519 PEM loading")
    key = serialization.load_pem_private_key(pem, password=None)
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw


# ==========================
# Верификация файлов журнала
# ==========================
def verify_file(
    path: Union[str, Path],
    *,
    hmac_keys: Mapping[str, bytes],
    ed25519_public_pems: Optional[Mapping[str, bytes]] = None,
) -> None:
    """
    Оффлайн-проверка целостности и подлинности.
    - Проверяет хеш-цепочку (prev_hash -> hash).
    - Проверяет HMAC по ключу hmac_key_id.
    - Если есть sig_ed25519, проверяет подпись по sig_key_id.

    Поднимает AuditVerificationError при первой найденной проблеме.
    """
    pubkeys: Dict[str, Ed25519PublicKey] = {}
    if ed25519_public_pems:
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography is required for Ed25519 verification")
        for kid, pem in ed25519_public_pems.items():
            pubkeys[kid] = serialization.load_pem_public_key(pem)  # type: ignore

    prev_hash: Optional[str] = None
    line_no = 0

    with open(path, "rb") as f:
        for raw in f:
            line_no += 1
            line = raw.strip()
            if not line:
                continue
            try:
                ev: Dict[str, Any] = json.loads(line.decode("utf-8"))
            except Exception as e:
                raise AuditVerificationError(f"line {line_no}: invalid json: {e}")

            # Копия без полей hash/hmac/sig для канонизации
            ev_core = dict(ev)
            ev_hash_b64 = ev_core.pop("hash", None)
            ev_hmac = ev_core.pop("hmac", None)
            hmac_kid = ev_core.pop("hmac_key_id", None)
            sig = ev_core.pop("sig_ed25519", None)
            sig_kid = ev_core.pop("sig_key_id", None)

            canon = canonical_json(ev_core)
            # 1) Проверка hash и prev_hash
            want_hash = base64.b64encode(hashlib.sha256(canon).digest()).decode("ascii")
            if ev_hash_b64 != want_hash:
                raise AuditVerificationError(f"line {line_no}: hash mismatch")
            if ev_core.get("prev_hash") != prev_hash:
                raise AuditVerificationError(f"line {line_no}: prev_hash chain break")
            prev_hash = ev_hash_b64

            # 2) Проверка HMAC
            if not hmac_kid or hmac_kid not in hmac_keys:
                raise AuditVerificationError(f"line {line_no}: unknown hmac_key_id")
            calc_hmac = base64.b64encode(hmac.new(hmac_keys[hmac_kid], canon, hashlib.sha256).digest()).decode("ascii")
            if not _const_time_equal(ev_hmac or "", calc_hmac):
                raise AuditVerificationError(f"line {line_no}: hmac mismatch")

            # 3) Проверка подписи (если присутствует)
            if sig:
                if not sig_kid or sig_kid not in pubkeys:
                    raise AuditVerificationError(f"line {line_no}: unknown sig_key_id")
                try:
                    pubkeys[sig_kid].verify(base64.b64decode(sig), canon)  # type: ignore
                except Exception:
                    raise AuditVerificationError(f"line {line_no}: invalid ed25519 signature")


def _const_time_equal(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


# ==========================
# Удобные шорткаты доменных действий
# ==========================
class AuditShortcuts:
    """
    Набор готовых методов для частых действий.
    """
    def __init__(self, logger: AuditLogger) -> None:
        self._l = logger

    async def auth_success(self, user_id: str, ip: Optional[str] = None, **kw: Any) -> None:
        await self._l.log(action="auth.success", actor=f"user:{user_id}", outcome="success", ip=ip, details=kw)

    async def auth_failure(self, user_id: Optional[str], ip: Optional[str] = None, reason: str = "", **kw: Any) -> None:
        await self._l.log(action="auth.failure", actor=(f"user:{user_id}" if user_id else None),
                          outcome="deny", ip=ip, details={"reason": reason, **kw})

    async def data_access(self, actor: str, resource: str, subject: Optional[str] = None, **kw: Any) -> None:
        await self._l.log(action="data.access", actor=actor, resource=resource, subject=subject,
                          outcome="success", details=kw)

    async def admin_action(self, admin_id: str, action: str, **kw: Any) -> None:
        await self._l.log(action=f"admin.{action}", actor=f"admin:{admin_id}", outcome="success", details=kw)
