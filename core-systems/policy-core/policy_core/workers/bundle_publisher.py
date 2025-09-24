# policy_core/workers/bundle_publisher.py
from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import functools
import hashlib
import io
import json as _json
import logging
import os
import tarfile
import tempfile
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# -------- Optional deps (graceful fallback) --------
try:
    import orjson as _fastjson  # type: ignore
except Exception:  # pragma: no cover
    _fastjson = None

try:
    # Ed25519 signing (PyNaCl)
    from nacl.signing import SigningKey  # type: ignore
    from nacl.exceptions import BadSignatureError  # type: ignore
except Exception:  # pragma: no cover
    SigningKey = None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = None  # type: ignore

try:
    import aioboto3  # type: ignore
except Exception:  # pragma: no cover
    aioboto3 = None  # type: ignore
# ---------------------------------------------------

_logger = logging.getLogger("policy_core.workers.bundle_publisher")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s bundle_publisher: %(message)s"))
    _logger.addHandler(h)
    _logger.setLevel(logging.INFO)


# ===================== Utilities =====================

def _json_dumps(obj: Any) -> bytes:
    if _fastjson:
        return _fastjson.dumps(obj)  # type: ignore
    return _json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _now() -> float:
    return time.time()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_filelike(fp: io.BufferedReader, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    while True:
        chunk = fp.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


# ===================== Data models =====================

@dataclass(slots=True)
class PolicyFile:
    """Единица контента для бандла."""
    path: str  # относительный путь внутри архива, например "policies/abac.rego"
    content: bytes  # уже сериализованные байты
    mode: int = 0o644


@dataclass(slots=True)
class BundleSpec:
    """Описание бандла для публикации."""
    scope: str                     # namespace/tenant
    version: str                   # логическая версия (semver/commit-hash/epoch)
    items: Sequence[PolicyFile]    # файлы внутри бандла
    metadata: Dict[str, Any] = field(default_factory=dict)  # произвольные метаданные
    previous_version: Optional[str] = None
    created_by: Optional[str] = None
    ttl_seconds: Optional[int] = None  # подсказка потребителям/кешам


@dataclass(slots=True)
class BundleArtifact:
    """Результат сборки и размещения бандла."""
    scope: str
    version: str
    artifact_url: str
    size_bytes: int
    sha256: str
    signature_b64: Optional[str]
    signature_alg: Optional[str]
    manifest_sha256: str


@dataclass(slots=True)
class PublishTask:
    """Задача публикации: что собрать и куда отдать сигнал."""
    spec: BundleSpec
    idempotency_key: Optional[str] = None  # если None, рассчитывается из (scope,version,hash)
    priority: int = 100  # меньше = выше приоритета
    # флаги поведения
    force: bool = False  # игнорировать коалессацию/дедупликацию для этого scope


@dataclass(slots=True)
class PublisherStats:
    enqueued: int = 0
    built: int = 0
    stored: int = 0
    published: int = 0
    retries: int = 0
    failures: int = 0

    def snapshot(self) -> Dict[str, int]:
        return dataclasses.asdict(self)


# ===================== Abstract Ports =====================

class ArtifactStorage(ABC):
    """Хранилище артефактов (bundle tar.gz). Возвращает доступный URL."""
    @abstractmethod
    async def save(self, *, key: str, content: bytes, content_type: str = "application/gzip") -> str:
        ...

    async def close(self) -> None:  # optional
        return None


class EventBus(ABC):
    """Шина событий для уведомления потребителей о новой версии."""
    @abstractmethod
    async def publish(self, *, topic: str, payload: bytes) -> None:
        ...

    async def close(self) -> None:
        return None


class Signer(ABC):
    """Подпись манифеста/артефакта (опционально)."""
    @abstractmethod
    def sign(self, data: bytes) -> Tuple[str, str]:
        """
        Возвращает (signature_b64, algorithm_name).
        """
        ...


# ===================== Adapters: Storage =====================

class LocalFilesystemStorage(ArtifactStorage):
    """Сохраняет в локальную директорию, возвращает file:// URL."""
    def __init__(self, base_dir: str) -> None:
        self._base = os.path.abspath(base_dir)
        os.makedirs(self._base, exist_ok=True)

    async def save(self, *, key: str, content: bytes, content_type: str = "application/gzip") -> str:
        full = os.path.join(self._base, key.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        # атомарная запись через tmp + rename
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".tmp_bundle_", dir=os.path.dirname(full))
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, full)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)
        return f"file://{full}"


class S3Storage(ArtifactStorage):
    """S3/MinIO хранилище. Требует aioboto3."""
    def __init__(self, bucket: str, prefix: str = "", *, region_name: Optional[str] = None) -> None:
        if aioboto3 is None:
            raise RuntimeError("aioboto3 is not installed")
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._region = region_name
        self._session = aioboto3.Session()

    async def save(self, *, key: str, content: bytes, content_type: str = "application/gzip") -> str:
        s3_key = f"{self._prefix}/{key}".lstrip("/")
        async with self._session.client("s3", region_name=self._region) as s3:
            await s3.put_object(Bucket=self._bucket, Key=s3_key, Body=content, ContentType=content_type)
            # Предполагаем публичный/подписываемый URL вне зоны ответственности
            return f"s3://{self._bucket}/{s3_key}"


# ===================== Adapters: EventBus =====================

class NoopEventBus(EventBus):
    async def publish(self, *, topic: str, payload: bytes) -> None:
        _logger.info("NoopEventBus publish to %s (%d bytes)", topic, len(payload))


class RedisEventBus(EventBus):
    """Redis канал (pub/sub) или stream."""
    def __init__(self, url: Optional[str] = None, *, channel: Optional[str] = None, stream: Optional[str] = None) -> None:
        if aioredis is None:
            raise RuntimeError("redis.asyncio is not installed")
        self._r = aioredis.from_url(url or os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=False)
        self._channel = channel
        self._stream = stream
        if not (self._channel or self._stream):
            raise ValueError("Either channel or stream must be provided")

    async def publish(self, *, topic: str, payload: bytes) -> None:
        if self._channel:
            chan = f"{self._channel}.{topic}" if topic else self._channel
            await self._r.publish(chan, payload)
        else:
            stream = self._stream if self._stream else "policy.bundle"
            fields = {b"topic": topic.encode(), b"payload": payload}
            await self._r.xadd(stream, fields, maxlen=10000, approximate=True)

    async def close(self) -> None:
        await self._r.close()


class KafkaEventBus(EventBus):
    """Kafka producer для публикации сообщений."""
    def __init__(self, *, bootstrap_servers: str, topic_prefix: str = "policy.bundle") -> None:
        if AIOKafkaProducer is None:
            raise RuntimeError("aiokafka is not installed")
        self._producer = AIOKafkaProducer(bootstrap_servers=bootstrap_servers)
        self._topic_prefix = topic_prefix
        self._started = False

    async def _ensure_start(self) -> None:
        if not self._started:
            await self._producer.start()
            self._started = True

    async def publish(self, *, topic: str, payload: bytes) -> None:
        await self._ensure_start()
        await self._producer.send_and_wait(f"{self._topic_prefix}.{topic}" if topic else self._topic_prefix, payload)

    async def close(self) -> None:
        if self._started:
            await self._producer.stop()
            self._started = False


# ===================== Signers =====================

class Ed25519Signer(Signer):
    """Подписывает байты через Ed25519 (PyNaCl)."""
    def __init__(self, private_key_b64: str) -> None:
        if SigningKey is None:
            raise RuntimeError("PyNaCl is not installed")
        self._key = SigningKey(base64.b64decode(private_key_b64))

    def sign(self, data: bytes) -> Tuple[str, str]:
        sig = self._key.sign(data).signature
        return base64.b64encode(sig).decode(), "ed25519"


class NoopSigner(Signer):
    def sign(self, data: bytes) -> Tuple[str, str]:
        return (None, None)  # type: ignore


# ===================== Builder =====================

class BundleBuilder:
    """
    Собирает tar.gz бандл с детерминированным порядком файлов и манифестом.
    """
    def __init__(self, *, manifest_name: str = "manifest.json") -> None:
        self._manifest_name = manifest_name

    def build(self, spec: BundleSpec, *, signer: Optional[Signer] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Возвращает (bundle_bytes, manifest_dict).
        """
        # Детерминированный порядок по пути
        items = sorted(spec.items, key=lambda x: x.path)
        file_hashes: Dict[str, Dict[str, Any]] = {}

        mem = io.BytesIO()
        with tarfile.open(fileobj=mem, mode="w:gz", compresslevel=9) as tar:
            # Пишем файлы политик
            for pf in items:
                data = pf.content
                h = sha256_bytes(data)
                file_hashes[pf.path] = {"sha256": h, "size": len(data)}
                info = tarfile.TarInfo(name=pf.path)
                info.size = len(data)
                info.mode = pf.mode
                info.mtime = int(spec.metadata.get("mtime", _now()))
                tar.addfile(info, io.BytesIO(data))

            # Формируем манифест
            manifest = {
                "schema": "policy-bundle/1",
                "scope": spec.scope,
                "version": spec.version,
                "previous_version": spec.previous_version,
                "created_at": int(_now()),
                "created_by": spec.created_by,
                "files": file_hashes,
                "metadata": spec.metadata or {},
                "hash_alg": "sha256",
            }
            # Предподпись: подпись считается от JSON манифеста без полей signature*
            manifest_bytes = _json_dumps(manifest)
            sig_b64, sig_alg = (None, None)
            if signer and not isinstance(signer, NoopSigner):
                try:
                    sig_b64, sig_alg = signer.sign(manifest_bytes)
                    manifest["signature"] = {"alg": sig_alg, "sig_b64": sig_b64}
                except Exception as e:  # pragma: no cover
                    _logger.error("signing failed: %s", e)
                    manifest["signature_error"] = str(e)

            # Записываем манифест
            mbytes = _json_dumps(manifest)
            info = tarfile.TarInfo(name=self._manifest_name)
            info.size = len(mbytes)
            info.mode = 0o644
            info.mtime = int(_now())
            tar.addfile(info, io.BytesIO(mbytes))

        content = mem.getvalue()
        # Контрольный хэш всего архива
        archive_sha256 = sha256_bytes(content)
        manifest_sha256 = sha256_bytes(mbytes)
        return content, {
            "manifest": manifest,
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
            "signature_b64": sig_b64,
            "signature_alg": sig_alg,
        }


# ===================== Publisher Worker =====================

class BundlePublisherWorker:
    """
    Очередь задач публикации policy-bundle с коалессацией по scope, ретраями и телеметрией.
    """
    def __init__(
        self,
        *,
        storage: ArtifactStorage,
        bus: EventBus,
        signer: Optional[Signer] = None,
        queue_maxsize: int = 1000,
        concurrency: int = 2,
        topic: str = "update",
        key_prefix: str = "bundles",
        backoff_min: float = 0.2,
        backoff_max: float = 5.0,
        max_retries: int = 5,
    ) -> None:
        self._storage = storage
        self._bus = bus
        self._signer = signer or NoopSigner()
        self._queue: asyncio.PriorityQueue[Tuple[int, str, PublishTask]] = asyncio.PriorityQueue(maxsize=queue_maxsize)
        self._coalesce: Dict[str, PublishTask] = {}  # по scope => последняя таска
        self._dedupe: Dict[str, float] = {}          # idempotency_key => ts
        self._builder = BundleBuilder()
        self._topic = topic
        self._key_prefix = key_prefix.strip("/")
        self._concurrency = max(1, concurrency)
        self._tasks: List[asyncio.Task] = []
        self._stopping = asyncio.Event()
        self._stats = PublisherStats()
        self._backoff_min = backoff_min
        self._backoff_max = backoff_max
        self._max_retries = max_retries

    # -------- Public API --------
    def stats(self) -> Dict[str, int]:
        return self._stats.snapshot()

    async def start(self) -> None:
        self._stopping.clear()
        for _ in range(self._concurrency):
            self._tasks.append(asyncio.create_task(self._worker_loop()))

    async def stop(self, *, drain: bool = True, timeout: float = 15.0) -> None:
        if drain:
            await self._queue.join()
        self._stopping.set()
        for t in self._tasks:
            t.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True), timeout=timeout)
        self._tasks.clear()
        await self._bus.close()
        await self._storage.close()

    async def submit(self, task: PublishTask) -> None:
        """
        Добавляет задачу. Коалессация: на scope хранится только последняя версия, если force=False.
        """
        scope = task.spec.scope
        idem = task.idempotency_key or self._calc_idem_key(task.spec)
        task.idempotency_key = idem

        # Дедупликация уже выполненных/в очереди
        if idem in self._dedupe:
            _logger.info("skip duplicate task idem=%s scope=%s version=%s", idem, scope, task.spec.version)
            return

        if not task.force:
            # Переписываем последнюю задачу для scope, если есть
            self._coalesce[scope] = task
        else:
            # Force — кладем сразу
            await self._queue.put((task.priority, idem, task))
            self._stats.enqueued += 1

    async def flush_scope(self, scope: str) -> None:
        """
        Принудительно отправить коалесцированную задачу по scope в очередь.
        """
        task = self._coalesce.pop(scope, None)
        if task:
            idem = task.idempotency_key or self._calc_idem_key(task.spec)
            await self._queue.put((task.priority, idem, task))
            self._stats.enqueued += 1

    async def flush_all(self) -> None:
        """
        Отправить все коалесцированные задачи в очередь.
        """
        scopes = list(self._coalesce.keys())
        for s in scopes:
            await self.flush_scope(s)

    # -------- Internal --------
    def _calc_idem_key(self, spec: BundleSpec) -> str:
        # В idem участвуют scope, version и хэши файлов
        h = hashlib.sha256()
        h.update(spec.scope.encode())
        h.update(b"\x00")
        h.update(spec.version.encode())
        h.update(b"\x00")
        for pf in sorted(spec.items, key=lambda x: x.path):
            h.update(pf.path.encode())
            h.update(b"\x00")
            h.update(hashlib.sha256(pf.content).digest())
        return h.hexdigest()

    async def _worker_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                # Периодически выбрасываем накопленные коалессы
                if not self._queue.full() and self._coalesce:
                    # отправляем все, чтобы не висели
                    await self.flush_all()

                priority, idem, task = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue
            try:
                await self._process_task(idem, task)
            except Exception as e:  # pragma: no cover
                _logger.exception("task failed: idem=%s scope=%s err=%s", idem, task.spec.scope, e)
                self._stats.failures += 1
            finally:
                self._queue.task_done()

    async def _process_task(self, idem: str, task: PublishTask) -> None:
        # Защита от повторов: если уже обработали, выходим
        if idem in self._dedupe:
            _logger.debug("already processed idem=%s", idem)
            return

        spec = task.spec
        # Telemetry span, if available
        if trace:
            tracer = trace.get_tracer("policy_core.workers.bundle_publisher")
            with tracer.start_as_current_span("publish.bundle") as span:  # type: ignore
                span.set_attribute("bundle.scope", spec.scope)  # type: ignore
                span.set_attribute("bundle.version", spec.version)  # type: ignore
                await self._build_store_publish(spec, idem)
        else:
            await self._build_store_publish(spec, idem)

        self._dedupe[idem] = _now()

    async def _build_store_publish(self, spec: BundleSpec, idem: str) -> None:
        # 1) Build
        content, meta = self._builder.build(spec, signer=self._signer)
        self._stats.built += 1

        # 2) Store
        key = self._build_key(spec, meta["archive_sha256"])
        url = await self._retry(lambda: self._storage.save(key=key, content=content), what="storage.save")
        self._stats.stored += 1

        # 3) Publish event
        event = {
            "schema": "policy-bundle-event/1",
            "scope": spec.scope,
            "version": spec.version,
            "previous_version": spec.previous_version,
            "artifact_url": url,
            "artifact_sha256": meta["archive_sha256"],
            "manifest_sha256": meta["manifest_sha256"],
            "signature": {
                "alg": meta["signature_alg"],
                "sig_b64": meta["signature_b64"],
            },
            "size_bytes": len(content),
            "ttl": spec.ttl_seconds,
            "created_at": int(_now()),
            "created_by": spec.created_by,
            "idempotency_key": idem,
        }
        payload = _json_dumps(event)
        await self._retry(lambda: self._bus.publish(topic=self._topic, payload=payload), what="bus.publish")
        self._stats.published += 1
        _logger.info("bundle published scope=%s version=%s url=%s", spec.scope, spec.version, url)

    def _build_key(self, spec: BundleSpec, archive_sha256: str) -> str:
        # {prefix}/{scope}/{version}_{hash12}.tar.gz
        return f"{self._key_prefix}/{spec.scope}/{spec.version}_{archive_sha256[:12]}.tar.gz"

    async def _retry(self, fn, *, what: str):
        attempt = 0
        delay = self._backoff_min
        while True:
            try:
                return await fn()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                attempt += 1
                if attempt > self._max_retries:
                    _logger.error("%s failed after %d attempts: %s", what, attempt - 1, e)
                    self._stats.failures += 1
                    raise
                self._stats.retries += 1
                _logger.warning("%s failed (attempt %d/%d): %s; retry in %.2fs",
                                what, attempt, self._max_retries, e, delay)
                await asyncio.sleep(delay)
                delay = min(self._backoff_max, delay * 2.0)


# ===================== Convenience factory =====================

def create_default_local_worker(
    *,
    artifacts_dir: str,
    redis_url: Optional[str] = None,
    redis_channel: Optional[str] = None,
    kafka_bootstrap: Optional[str] = None,
    topic: str = "update",
    signer: Optional[Signer] = None,
) -> BundlePublisherWorker:
    """
    Быстрая сборка воркера:
    - FS storage -> artifacts_dir
    - EventBus -> Redis(channel) | Kafka | Noop
    """
    storage = LocalFilesystemStorage(artifacts_dir)
    if redis_url and redis_channel:
        if aioredis is None:
            raise RuntimeError("redis.asyncio is not installed")
        bus = RedisEventBus(url=redis_url, channel=redis_channel)
    elif kafka_bootstrap:
        if AIOKafkaProducer is None:
            raise RuntimeError("aiokafka is not installed")
        bus = KafkaEventBus(bootstrap_servers=kafka_bootstrap, topic_prefix="policy.bundle")
    else:
        bus = NoopEventBus()
    return BundlePublisherWorker(storage=storage, bus=bus, signer=signer, topic=topic)


__all__ = [
    "PolicyFile",
    "BundleSpec",
    "BundleArtifact",
    "PublishTask",
    "PublisherStats",
    "ArtifactStorage",
    "EventBus",
    "Signer",
    "LocalFilesystemStorage",
    "S3Storage",
    "RedisEventBus",
    "KafkaEventBus",
    "Ed25519Signer",
    "NoopSigner",
    "BundleBuilder",
    "BundlePublisherWorker",
    "create_default_local_worker",
]
