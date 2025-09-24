# policy_core/pap/publisher.py
# Industrial-grade PAP Publisher for policy-core
# Python 3.11+, async-only
from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import pathlib
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

# -------- Optional deps (soft) --------
try:
    from pydantic import BaseModel, Field, ValidationError
except Exception as e:  # minimal fallback
    raise RuntimeError("pydantic must be installed for publisher.py") from e

try:
    import jsonschema
except Exception as e:
    raise RuntimeError("jsonschema must be installed for publisher.py") from e

# Ed25519 is optional; falls back to HMAC
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False

# Prometheus metrics optional
try:
    from prometheus_client import Counter, Histogram
    _METRICS_OK = True
except Exception:
    _METRICS_OK = False

# Async SQLite (idempotency)
try:
    import aiosqlite
    _SQLITE_OK = True
except Exception:
    _SQLITE_OK = False

# Kafka (optional)
try:
    from aiokafka import AIOKafkaProducer
    _KAFKA_OK = True
except Exception:
    _KAFKA_OK = False

# RabbitMQ (optional)
try:
    import aio_pika
    _RABBIT_OK = True
except Exception:
    _RABBIT_OK = False

# S3 (optional)
try:
    import aioboto3
    _S3_OK = True
except Exception:
    _S3_OK = False


# =========================
# Config & Constants
# =========================

DEF_STORAGE_URI = os.getenv("POLICY_STORAGE_URI", "file://./_policy_store")
DEF_MESSAGE_BUS_URI = os.getenv("POLICY_MESSAGE_BUS_URI", "noop://")
DEF_SIGNING_KEY_PATH = os.getenv("POLICY_SIGNING_KEY_PATH", "")
DEF_SIGNING_ALG = os.getenv("POLICY_SIGNING_ALG", "ed25519" if _CRYPTO_OK else "hmac-sha256")
DEF_AUDIT_PATH = os.getenv("POLICY_AUDIT_PATH", "./_policy_audit")
DEF_IDEMPOTENCY_URI = os.getenv("POLICY_IDEMPOTENCY_URI", "sqlite://./_policy_idempotency.db")
DEF_NAMESPACE = os.getenv("POLICY_DEFAULT_NAMESPACE", "default")
DEF_EVENT_TOPIC = os.getenv("POLICY_EVENT_TOPIC", "policy.bundle.published")
DEF_RBAC_MODE = os.getenv("POLICY_RBAC_MODE", "scopes")  # "scopes" | "roles"
DEF_SCHEMA_PATH = os.getenv("POLICY_SCHEMA_PATH", "")  # optional JSON Schema for bundle

# Metrics
if _METRICS_OK:
    METRIC_PUBLISH_COUNT = Counter(
        "policy_pap_publish_total",
        "Number of policy bundle publish attempts",
        ["result", "backend_storage", "backend_bus"],
    )
    METRIC_PUBLISH_LAT = Histogram(
        "policy_pap_publish_seconds",
        "Latency of policy bundle publish",
        buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )


# =========================
# Models
# =========================

class Principal(BaseModel):
    subject: str
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)


class PolicyDocument(BaseModel):
    id: str
    name: str
    type: str = Field(description="e.g., 'rego', 'json', 'yaml', 'xacml'", default="json")
    version: Optional[str] = None
    content: Union[Dict[str, Any], str]
    sha256: Optional[str] = None

    def canonical_bytes(self) -> bytes:
        if isinstance(self.content, str):
            data = self.content.encode("utf-8")
        else:
            data = json.dumps(self.content, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return data

    def ensure_hash(self) -> "PolicyDocument":
        payload = self.canonical_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        return self.copy(update={"sha256": digest})


class PolicyBundle(BaseModel):
    bundle_id: str
    namespace: str = DEF_NAMESPACE
    version: Optional[str] = None  # if None, assigned on publish
    created_at: Optional[str] = None
    documents: List[PolicyDocument] = Field(default_factory=list)
    annotations: Dict[str, Any] = Field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        # Ensure documents include hashes for canonicalization
        docs = [d.ensure_hash().model_dump() for d in self.documents]
        obj = {
            "bundle_id": self.bundle_id,
            "namespace": self.namespace,
            "version": self.version,
            "created_at": self.created_at,
            "documents": docs,
            "annotations": self.annotations,
        }
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


class Signature(BaseModel):
    alg: str
    key_id: str
    signature_b64: str


class PublishRequest(BaseModel):
    principal: Principal
    bundle: PolicyBundle
    idempotency_key: Optional[str] = None
    correlation_id: Optional[str] = None


class PublishResult(BaseModel):
    status: str
    bundle_uri: str
    version: str
    correlation_id: str
    signature: Signature
    bundle_sha256: str
    message_bus: str
    storage_backend: str


# =========================
# JSON Schema Validation
# =========================

class BundleValidator:
    def __init__(self, schema_path: Optional[str] = None) -> None:
        self._schema = None
        if schema_path and pathlib.Path(schema_path).exists():
            with open(schema_path, "r", encoding="utf-8") as f:
                self._schema = json.load(f)

    def validate(self, bundle: PolicyBundle) -> None:
        if self._schema:
            jsonschema.validate(instance=bundle.model_dump(), schema=self._schema)
        # Additional lightweight checks
        if not bundle.documents:
            raise ValueError("PolicyBundle.documents must not be empty")
        ids = [d.id for d in bundle.documents]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate document ids in bundle")


# =========================
# Authorizer (RBAC/Scopes)
# =========================

class Authorizer(Protocol):
    async def check_publish(self, principal: Principal) -> None: ...


class SimpleAuthorizer:
    def __init__(self, mode: str = DEF_RBAC_MODE) -> None:
        self.mode = mode

    async def check_publish(self, principal: Principal) -> None:
        if self.mode == "scopes":
            if "policies:publish" in principal.scopes or "admin" in principal.scopes:
                return
        else:
            if "admin" in principal.roles or "policy-admin" in principal.roles:
                return
        raise PermissionError("Publish denied by RBAC/Scopes")


# =========================
# Signers
# =========================

class Signer(Protocol):
    def key_id(self) -> str: ...
    def alg(self) -> str: ...
    def sign(self, payload: bytes) -> Signature: ...


class Ed25519Signer:
    def __init__(self, key_bytes: bytes, key_id: str = "ed25519/1") -> None:
        if not _CRYPTO_OK:
            raise RuntimeError("cryptography is required for Ed25519Signer")
        self._sk = Ed25519PrivateKey.from_private_bytes(key_bytes)
        self._key_id = key_id

    def key_id(self) -> str:
        return self._key_id

    def alg(self) -> str:
        return "ed25519"

    def sign(self, payload: bytes) -> Signature:
        sig = self._sk.sign(payload)
        return Signature(alg=self.alg(), key_id=self.key_id(), signature_b64=base64.b64encode(sig).decode())


class HMACSHA256Signer:
    def __init__(self, secret: bytes, key_id: str = "hmac/1") -> None:
        self._secret = secret
        self._key_id = key_id

    def key_id(self) -> str:
        return self._key_id

    def alg(self) -> str:
        return "hmac-sha256"

    def sign(self, payload: bytes) -> Signature:
        mac = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return Signature(alg=self.alg(), key_id=self.key_id(), signature_b64=base64.b64encode(mac).decode())


def load_signer() -> Signer:
    alg = DEF_SIGNING_ALG.lower()
    path = DEF_SIGNING_KEY_PATH
    if alg == "ed25519":
        if not path:
            raise RuntimeError("POLICY_SIGNING_KEY_PATH must be set for ed25519")
        key = pathlib.Path(path).read_bytes()
        # Support PEM or raw 32 bytes
        if b"PRIVATE KEY" in key:
            sk = serialization.load_pem_private_key(key, password=None)
            raw = sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return Ed25519Signer(raw, key_id="ed25519/pem")
        else:
            return Ed25519Signer(key, key_id="ed25519/raw")
    # default HMAC
    secret = (pathlib.Path(path).read_bytes() if path else os.getenv("POLICY_HMAC_SECRET", "change-me").encode())
    return HMACSHA256Signer(secret)


# =========================
# Storage backends
# =========================

class PolicyStorage(Protocol):
    async def put_bytes(self, path: str, data: bytes) -> str: ...
    async def exists(self, path: str) -> bool: ...
    async def makedirs(self, path: str) -> None: ...


class LocalFileSystemStorage:
    def __init__(self, base_dir: str) -> None:
        self.base = pathlib.Path(base_dir).resolve()
        self.base.mkdir(parents=True, exist_ok=True)

    async def makedirs(self, path: str) -> None:
        (self.base / path).parent.mkdir(parents=True, exist_ok=True)

    async def put_bytes(self, path: str, data: bytes) -> str:
        target = self.base / path
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(target)
        return f"file://{target.as_posix()}"

    async def exists(self, path: str) -> bool:
        return (self.base / path).exists()


class S3Storage:
    def __init__(self, bucket: str, prefix: str = "", region: Optional[str] = None) -> None:
        if not _S3_OK:
            raise RuntimeError("aioboto3 is required for S3 storage")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.region = region
        self._session = aioboto3.Session()

    def _key(self, path: str) -> str:
        p = f"{self.prefix}/{path}".strip("/")
        return p

    async def makedirs(self, path: str) -> None:
        return  # NOP for S3

    async def put_bytes(self, path: str, data: bytes) -> str:
        key = self._key(path)
        async with self._session.client("s3", region_name=self.region) as s3:
            await s3.put_object(Bucket=self.bucket, Key=key, Body=data)
        return f"s3://{self.bucket}/{key}"

    async def exists(self, path: str) -> bool:
        key = self._key(path)
        async with self._session.client("s3", region_name=self.region) as s3:
            try:
                await s3.head_object(Bucket=self.bucket, Key=key)
                return True
            except Exception:
                return False


def storage_from_uri(uri: str) -> PolicyStorage:
    if uri.startswith("file://") or "://" not in uri:
        base = uri.replace("file://", "")
        return LocalFileSystemStorage(base)
    if uri.startswith("s3://"):
        # s3://bucket/prefix
        rest = uri[len("s3://"):]
        parts = rest.split("/", 1)
        bucket = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""
        return S3Storage(bucket=bucket, prefix=prefix)
    raise ValueError(f"Unsupported storage uri: {uri}")


# =========================
# Message bus
# =========================

class MessageBus(Protocol):
    async def publish(self, topic: str, key: Optional[bytes], value: bytes, headers: Mapping[str, str]) -> None: ...
    def name(self) -> str: ...


class NoopBus:
    async def publish(self, topic: str, key: Optional[bytes], value: bytes, headers: Mapping[str, str]) -> None:
        return

    def name(self) -> str:
        return "noop"


class KafkaBus:
    def __init__(self, bootstrap_servers: str) -> None:
        if not _KAFKA_OK:
            raise RuntimeError("aiokafka is required for KafkaBus")
        self._servers = bootstrap_servers
        self._producer: Optional[AIOKafkaProducer] = None

    async def _ensure(self) -> None:
        if self._producer is None:
            self._producer = AIOKafkaProducer(bootstrap_servers=self._servers)
            await self._producer.start()

    async def publish(self, topic: str, key: Optional[bytes], value: bytes, headers: Mapping[str, str]) -> None:
        await self._ensure()
        assert self._producer
        hdrs = [(k, v.encode()) for k, v in headers.items()]
        await self._producer.send_and_wait(topic, value=value, key=key, headers=hdrs)

    def name(self) -> str:
        return "kafka"

    async def close(self) -> None:
        if self._producer:
            await self._producer.stop()


class RabbitBus:
    def __init__(self, url: str) -> None:
        if not _RABBIT_OK:
            raise RuntimeError("aio_pika is required for RabbitBus")
        self._url = url
        self._conn: Optional[aio_pika.RobustConnection] = None
        self._chan: Optional[aio_pika.abc.AbstractChannel] = None

    async def _ensure(self) -> None:
        if self._conn is None:
            self._conn = await aio_pika.connect_robust(self._url)
            self._chan = await self._conn.channel()

    async def publish(self, topic: str, key: Optional[bytes], value: bytes, headers: Mapping[str, str]) -> None:
        await self._ensure()
        assert self._chan
        exchange = await self._chan.declare_exchange(topic, aio_pika.ExchangeType.FANOUT, durable=True)
        msg = aio_pika.Message(body=value, headers=headers)
        await exchange.publish(msg, routing_key="")

    def name(self) -> str:
        return "rabbitmq"

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()


def bus_from_uri(uri: str) -> MessageBus:
    if uri.startswith("kafka://"):
        servers = uri.replace("kafka://", "")
        return KafkaBus(servers)
    if uri.startswith("amqp://") or uri.startswith("amqps://"):
        return RabbitBus(uri)
    if uri.startswith("noop://"):
        return NoopBus()
    # default: noop
    return NoopBus()


# =========================
# Idempotency store
# =========================

class IdempotencyStore(Protocol):
    async def check_and_record(self, key: str, ttl_seconds: int, result: Optional[PublishResult] = None) -> Tuple[bool, Optional[PublishResult]]: ...
    async def save_result(self, key: str, result: PublishResult) -> None: ...


class SQLiteIdempotencyStore:
    def __init__(self, sqlite_path: str) -> None:
        if not _SQLITE_OK:
            raise RuntimeError("aiosqlite required for SQLiteIdempotencyStore")
        self._path = sqlite_path
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def _ensure(self) -> None:
        async with self._init_lock:
            if self._initialized:
                return
            async with aiosqlite.connect(self._path) as db:
                await db.execute("""
                CREATE TABLE IF NOT EXISTS idem (
                    key TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    result_json TEXT
                )
                """)
                await db.commit()
            self._initialized = True

    async def check_and_record(self, key: str, ttl_seconds: int, result: Optional[PublishResult] = None) -> Tuple[bool, Optional[PublishResult]]:
        await self._ensure()
        now = int(time.time())
        async with aiosqlite.connect(self._path) as db:
            # try read
            async with db.execute("SELECT created_at, result_json FROM idem WHERE key = ?", (key,)) as cur:
                row = await cur.fetchone()
            if row:
                created_at, result_json = row
                if now - created_at <= ttl_seconds:
                    if result_json:
                        return True, PublishResult.model_validate_json(result_json)
                    return True, None
                # expired: replace
                await db.execute("DELETE FROM idem WHERE key = ?", (key,))
                await db.commit()
            await db.execute("INSERT INTO idem(key, created_at, result_json) VALUES (?, ?, ?)",
                             (key, now, result.model_dump_json() if result else None))
            await db.commit()
        return False, None

    async def save_result(self, key: str, result: PublishResult) -> None:
        await self._ensure()
        async with aiosqlite.connect(self._path) as db:
            await db.execute("UPDATE idem SET result_json = ? WHERE key = ?", (result.model_dump_json(), key))
            await db.commit()


class FSIdempotencyStore:
    def __init__(self, base_dir: str) -> None:
        self.base = pathlib.Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    def _path(self, key: str) -> pathlib.Path:
        return self.base / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    async def check_and_record(self, key: str, ttl_seconds: int, result: Optional[PublishResult] = None) -> Tuple[bool, Optional[PublishResult]]:
        async with self._lock:
            p = self._path(key)
            now = int(time.time())
            if p.exists():
                data = json.loads(p.read_text("utf-8"))
                if now - data.get("created_at", 0) <= ttl_seconds:
                    if data.get("result_json"):
                        return True, PublishResult.model_validate_json(data["result_json"])
                    return True, None
                # expired
                p.unlink(missing_ok=True)
            payload = {"created_at": now, "result_json": result.model_dump_json() if result else None}
            p.write_text(json.dumps(payload), encoding="utf-8")
        return False, None

    async def save_result(self, key: str, result: PublishResult) -> None:
        async with self._lock:
            p = self._path(key)
            if not p.exists():
                return
            data = json.loads(p.read_text("utf-8"))
            data["result_json"] = result.model_dump_json()
            p.write_text(json.dumps(data), encoding="utf-8")


def idem_from_uri(uri: str) -> IdempotencyStore:
    if uri.startswith("sqlite://"):
        path = uri.replace("sqlite://", "")
        return SQLiteIdempotencyStore(path)
    if uri.startswith("file://") or "://" not in uri:
        base = uri.replace("file://", "")
        return FSIdempotencyStore(base)
    raise ValueError(f"Unsupported idempotency uri: {uri}")


# =========================
# Audit
# =========================

class AuditSink(Protocol):
    async def write(self, entry: Dict[str, Any]) -> None: ...


class FileAuditSink:
    def __init__(self, base_dir: str) -> None:
        self.base = pathlib.Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    async def write(self, entry: Dict[str, Any]) -> None:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        p = self.base / f"audit-{day}.log"
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")


# =========================
# Logging
# =========================

class JsonLogger:
    def __init__(self, name: str = "policy-publisher") -> None:
        self._log = logging.getLogger(name)
        if not self._log.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self._log.addHandler(handler)
            self._log.setLevel(logging.INFO)

    def info(self, **fields: Any) -> None:
        self._log.info(json.dumps(fields, ensure_ascii=False))

    def error(self, **fields: Any) -> None:
        self._log.error(json.dumps(fields, ensure_ascii=False))

    def warning(self, **fields: Any) -> None:
        self._log.warning(json.dumps(fields, ensure_ascii=False))


# =========================
# Utilities
# =========================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def make_correlation_id(corr: Optional[str]) -> str:
    return corr or str(uuid.uuid4())

def make_version(existing: Optional[str]) -> str:
    return existing or datetime.now(timezone.utc).strftime("%Y.%m.%d-%H%M%S")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

async def retry(
    func,
    *args,
    retries: int = 5,
    base_delay: float = 0.2,
    max_delay: float = 3.0,
    **kwargs,
):
    attempt = 0
    while True:
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            attempt += 1
            if attempt > retries:
                raise
            await asyncio.sleep(min(max_delay, base_delay * (2 ** (attempt - 1))))


# =========================
# Publisher
# =========================

class PolicyPublisher:
    def __init__(
        self,
        storage: PolicyStorage,
        bus: MessageBus,
        signer: Signer,
        authorizer: Authorizer,
        validator: BundleValidator,
        audit: AuditSink,
        idem: IdempotencyStore,
        logger: Optional[JsonLogger] = None,
    ) -> None:
        self.storage = storage
        self.bus = bus
        self.signer = signer
        self.authorizer = authorizer
        self.validator = validator
        self.audit = audit
        self.idem = idem
        self.log = logger or JsonLogger()

    async def publish(self, req: PublishRequest) -> PublishResult:
        started = time.perf_counter()
        corr_id = make_correlation_id(req.correlation_id)
        bundle = req.bundle
        bundle.created_at = bundle.created_at or now_iso()
        bundle.version = make_version(bundle.version)

        # RBAC
        await self.authorizer.check_publish(req.principal)

        # Validate bundle
        self.validator.validate(bundle)

        # Canonical payload & hash
        payload = bundle.canonical_bytes()
        b_hash = sha256_hex(payload)

        # Idempotency
        idem_key = req.idempotency_key or f"{bundle.namespace}:{bundle.bundle_id}:{b_hash}"
        existed, prior = await self.idem.check_and_record(idem_key, ttl_seconds=24 * 3600)
        if existed and prior:
            if _METRICS_OK:
                METRIC_PUBLISH_COUNT.labels("idempotent-return", self.storage.__class__.__name__, self.bus.name()).inc()
                METRIC_PUBLISH_LAT.observe(time.perf_counter() - started)
            return prior

        # Paths
        base_path = f"{bundle.namespace}/{bundle.bundle_id}/v{bundle.version}"
        bundle_path = f"{base_path}/bundle.json"
        meta_path = f"{base_path}/meta.json"
        sig_path = f"{base_path}/bundle.sig"

        # Store bundle atomically
        await self.storage.makedirs(bundle_path)
        bundle_uri = await self.storage.put_bytes(bundle_path, payload)

        # Sign
        sig = self.signer.sign(payload)
        await self.storage.put_bytes(sig_path, json.dumps(sig.model_dump(), separators=(",", ":"), sort_keys=True).encode())

        # Meta
        meta = {
            "bundle_id": bundle.bundle_id,
            "namespace": bundle.namespace,
            "version": bundle.version,
            "created_at": bundle.created_at,
            "sha256": b_hash,
            "signature": sig.model_dump(),
            "publisher": {
                "alg": self.signer.alg(),
                "key_id": self.signer.key_id(),
            },
        }
        await self.storage.put_bytes(meta_path, json.dumps(meta, separators=(",", ":"), sort_keys=True).encode())

        # Event
        event = {
            "type": "policy.bundle.published",
            "topic": DEF_EVENT_TOPIC,
            "ts": now_iso(),
            "correlation_id": corr_id,
            "bundle": {
                "bundle_id": bundle.bundle_id,
                "namespace": bundle.namespace,
                "version": bundle.version,
                "sha256": b_hash,
                "uri": bundle_uri,
            },
            "signature": sig.model_dump(),
            "principal": req.principal.model_dump(),
        }
        event_bytes = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()

        async def _publish():
            await self.bus.publish(
                topic=DEF_EVENT_TOPIC,
                key=bundle.bundle_id.encode(),
                value=event_bytes,
                headers={"correlation_id": corr_id},
            )
        await retry(_publish, retries=5, base_delay=0.25, max_delay=2.0)

        # Audit
        await self.audit.write({
            "ts": now_iso(),
            "action": "publish",
            "bundle_id": bundle.bundle_id,
            "namespace": bundle.namespace,
            "version": bundle.version,
            "sha256": b_hash,
            "uri": bundle_uri,
            "principal": req.principal.model_dump(),
            "correlation_id": corr_id,
        })

        result = PublishResult(
            status="ok",
            bundle_uri=bundle_uri,
            version=bundle.version,
            correlation_id=corr_id,
            signature=sig,
            bundle_sha256=b_hash,
            message_bus=self.bus.name(),
            storage_backend=self.storage.__class__.__name__,
        )
        await self.idem.save_result(idem_key, result)

        if _METRICS_OK:
            METRIC_PUBLISH_COUNT.labels("ok", self.storage.__class__.__name__, self.bus.name()).inc()
            METRIC_PUBLISH_LAT.observe(time.perf_counter() - started)

        self.log.info(event="published", correlation_id=corr_id, bundle_id=bundle.bundle_id,
                      namespace=bundle.namespace, version=bundle.version, uri=bundle_uri)

        return result


# =========================
# Factory
# =========================

@dataclass
class PublisherWiring:
    storage: PolicyStorage
    bus: MessageBus
    signer: Signer
    authorizer: Authorizer
    validator: BundleValidator
    audit: AuditSink
    idem: IdempotencyStore
    logger: JsonLogger

def build_publisher() -> PolicyPublisher:
    storage = storage_from_uri(DEF_STORAGE_URI)
    bus = bus_from_uri(DEF_MESSAGE_BUS_URI)
    signer = load_signer()
    authorizer = SimpleAuthorizer(DEF_RBAC_MODE)
    validator = BundleValidator(DEF_SCHEMA_PATH or None)
    audit = FileAuditSink(DEF_AUDIT_PATH)
    idem = idem_from_uri(DEF_IDEMPOTENCY_URI)
    logger = JsonLogger()
    return PolicyPublisher(storage, bus, signer, authorizer, validator, audit, idem, logger)


# =========================
# Minimal self-check (optional)
# =========================
# The module is designed to be imported and used from the PAP service.
# If executed directly, it performs a quick dry-run with Noop backends.
if __name__ == "__main__":
    async def _demo():
        os.environ.setdefault("POLICY_MESSAGE_BUS_URI", "noop://")
        os.environ.setdefault("POLICY_STORAGE_URI", "file://./_policy_store")
        pub = build_publisher()
        req = PublishRequest(
            principal=Principal(subject="system:demo", roles=["policy-admin"], scopes=["policies:publish"]),
            bundle=PolicyBundle(
                bundle_id="example",
                namespace="default",
                documents=[
                    PolicyDocument(id="allow_all", name="AllowAll", type="rego", content='package demo\nallow = true'),
                    PolicyDocument(id="limits", name="Limits", type="json", content={"rate": 1000}),
                ],
            ),
            idempotency_key=str(uuid.uuid4()),
        )
        res = await pub.publish(req)
        print(json.dumps(res.model_dump(), indent=2, ensure_ascii=False))
    asyncio.run(_demo())
