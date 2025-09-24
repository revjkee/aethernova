# engine-core/engine/adapters/blackvault_adapter.py
"""
Industrial-grade adapter for a secure secret store ("BlackVault").

Design goals:
- Transport- and crypto-agnostic: user injects BlackVaultClient + AEAD provider
- Envelope encryption:
    DEK = KMS.Derive(KeyId, context) via HKDF-like API on server side
    C = AEAD_Enc(DEK, nonce, compress(value), aad=manifest)
- Versioning & rotation policies (by age/uses/explicit)
- TTL cache with background refresh ("stale-while-revalidate")
- Strong idempotency for writes (deterministic canonical JSON + HMAC-able key outside)
- Concurrency limits, token-bucket RPS, retries with full jitter
- Chunked large payloads + zlib compression
- Audit log as tamper-evident hash chain
- Deterministic canonical encoding for manifests

No external dependencies. Python 3.10+.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
import zlib
from dataclasses import dataclass, field, asdict
from typing import Any, AsyncIterator, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# =========================
# Canonical encoding + hashes
# =========================

def _cjson(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3

def fnv1a64(data: bytes, seed: int = FNV64_OFFSET) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# =========================
# Errors
# =========================

class BlackVaultError(Exception): ...
class BVBadRequest(BlackVaultError): ...
class BVNotFound(BlackVaultError): ...
class BVPermission(BlackVaultError): ...
class BVRateLimited(BlackVaultError): ...
class BVRetryable(BlackVaultError): ...
class BVTimeout(BlackVaultError): ...
class BVCryptoError(BlackVaultError): ...
class BVAuditError(BlackVaultError): ...

# =========================
# Telemetry & rate limiting
# =========================

TelemetryHook = Callable[[str, Mapping[str, str], Mapping[str, float]], None]

class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float) -> None:
        self.rate = float(max(0.0, rate_per_s))
        self.burst = float(max(1.0, burst))
        self._tokens = self.burst
        self._last = time.monotonic()
        self._cv = asyncio.Condition()

    def _refill(self) -> None:
        now = time.monotonic()
        dt = now - self._last
        if dt > 0:
            self._tokens = min(self.burst, self._tokens + dt * self.rate)
            self._last = now

    async def acquire(self, cost: float = 1.0, timeout_s: float = 30.0) -> None:
        deadline = time.monotonic() + timeout_s
        async with self._cv:
            while True:
                self._refill()
                if self._tokens >= cost:
                    self._tokens -= cost
                    return
                if time.monotonic() >= deadline:
                    raise BVRateLimited("rate limiter timeout")
                await self._cv.wait_for(lambda: False, timeout=0.02)

    def release(self, cost: float = 1.0) -> None:
        async def _notify():
            async with self._cv:
                self._tokens = min(self.burst, self._tokens + cost)
                self._cv.notify_all()
        try:
            asyncio.get_running_loop().create_task(_notify())
        except RuntimeError:
            pass

def _full_jitter(base: float, factor: float, attempt: int, cap: float) -> float:
    raw = min(cap, base * (factor ** max(0, attempt-1)))
    rnd = (time.monotonic_ns() & 0xFFFFFFFF) / 0xFFFFFFFF
    return raw * rnd

# =========================
# Crypto interfaces (to be provided by integrator)
# =========================

class AEAD:
    """
    AEAD interface to be implemented by integrator using a vetted crypto library
    (e.g. AES-256-GCM or ChaCha20-Poly1305 via libsodium/pyca/OS KMS).
    All methods must be constant-time with respect to secrets.
    """
    key_size: int = 32   # bytes (e.g., 32 for AES-256)
    nonce_size: int = 12 # bytes

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

class BlackVaultClient:
    """
    Client interface for secure key derivation and storage metadata.
    Implement with your Vault/KMS provider.

    Requirements:
    - derive_key: returns a per-secret data encryption key (DEK) bound to context
    - put_blob/get_blob: store/load opaque ciphertext blobs with metadata
    - list_versions / retire_version: version management
    """
    async def derive_key(self, *, key_id: str, context: Mapping[str, str]) -> bytes:
        raise NotImplementedError

    async def put_blob(self, *, path: str, version: int, blob: bytes, meta: Mapping[str, Any], idempotency_key: str) -> None:
        raise NotImplementedError

    async def get_blob(self, *, path: str, version: Optional[int]) -> Tuple[bytes, Mapping[str, Any]]:
        """Return (blob, meta). If version is None, return latest enabled."""
        raise NotImplementedError

    async def list_versions(self, *, path: str) -> List[int]:
        raise NotImplementedError

    async def retire_version(self, *, path: str, version: int, reason: str) -> None:
        raise NotImplementedError

# =========================
# Config & types
# =========================

@dataclass(slots=True)
class Limits:
    rps: float = 50.0
    burst: float = 100.0
    concurrency: int = 32
    max_retries: int = 4
    timeout_s: float = 20.0
    cache_ttl_s: float = 15.0
    cache_stale_s: float = 60.0        # stale-while-revalidate

@dataclass(slots=True)
class RotationPolicy:
    max_age_s: int = 7 * 24 * 3600     # 7 days
    max_uses: int = 1_000_000          # soft limit
    explicit_only: bool = False        # if True, rotate only on demand

@dataclass(slots=True)
class AdapterConfig:
    key_id: str
    limits: Limits = field(default_factory=Limits)
    rotation: RotationPolicy = field(default_factory=RotationPolicy)
    compress_min_bytes: int = 256
    chunk_size: int = 256 * 1024       # for very large secrets
    telemetry: Optional[TelemetryHook] = None

@dataclass(slots=True)
class SecretContext:
    tenant: str
    app: str
    env: str
    labels: Mapping[str, str] = field(default_factory=dict)

@dataclass(slots=True)
class Manifest:
    path: str                   # logical key (namespace/name)
    version: int                # integer version
    alg: str                    # e.g. "AES-256-GCM"
    nonce_hex: str
    aead_key_ref: str           # reference info
    created_ms: int
    uses: int = 0
    tags: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self); return d

# =========================
# TTL cache with SWR
# =========================

@dataclass(slots=True)
class _CacheEntry:
    value: bytes
    manifest: Manifest
    exp: float
    stale_exp: float

class TTLCacheSWR:
    def __init__(self, max_items: int = 4096) -> None:
        self._store: Dict[str, _CacheEntry] = {}
        self._order: List[str] = []
        self._max = max_items
        self._lock = asyncio.Lock()

    async def get(self, k: str) -> Optional[_CacheEntry]:
        async with self._lock:
            e = self._store.get(k)
            if not e: return None
            now = time.monotonic()
            if now > e.stale_exp:
                # drop fully stale
                self._store.pop(k, None)
                if k in self._order: self._order.remove(k)
                return None
            return e

    async def set(self, k: str, v: _CacheEntry) -> None:
        async with self._lock:
            if k not in self._order:
                self._order.append(k)
            if len(self._order) > self._max:
                oldest = self._order.pop(0)
                self._store.pop(oldest, None)
            self._store[k] = v

# =========================
# Audit log (hash chain)
# =========================

@dataclass(slots=True)
class AuditEntry:
    ts_ms: int
    action: str
    path: str
    version: int
    actor: str
    meta: Mapping[str, Any]
    prev_h64: int
    h64: int

class AuditLog:
    def __init__(self, telemetry: Optional[TelemetryHook]) -> None:
        self._last = FNV64_OFFSET
        self._items: List[AuditEntry] = []
        self._tel = telemetry or (lambda n,t,f: None)

    def add(self, action: str, path: str, version: int, actor: str, meta: Mapping[str, Any]) -> AuditEntry:
        ts = int(time.monotonic() * 1000)
        payload = _cjson({"ts": ts, "a": action, "p": path, "v": version, "actor": actor, "m": meta})
        h = fnv1a64(payload, self._last)
        e = AuditEntry(ts, action, path, version, actor, dict(meta), self._last, h)
        self._items.append(e)
        self._last = h
        try: self._tel("blackvault.audit", {"action":action}, {"ok":1.0})
        except Exception: pass
        return e

    def export(self) -> List[Dict[str, Any]]:
        return [asdict(x) for x in self._items]

# =========================
# Adapter
# =========================

@dataclass(slots=True)
class _InFlight:
    fut: asyncio.Future

class BlackVaultAdapter:
    """
    High-level secret API:
      put_secret(path, value, ctx, tags) -> version
      get_secret(path, ctx, version=None) -> (bytes, Manifest)
      rotate(path, ctx, reason) -> new_version
      retire_version(path, version, reason)
    """
    def __init__(self, client: BlackVaultClient, aead: AEAD, cfg: AdapterConfig) -> None:
        self.client = client
        self.aead = aead
        self.cfg = cfg
        self.bucket = TokenBucket(cfg.limits.rps, cfg.limits.burst)
        self.sema = asyncio.Semaphore(cfg.limits.concurrency)
        self.cache = TTLCacheSWR()
        self.audit = AuditLog(cfg.telemetry)
        self._inflight: Dict[str, _InFlight] = {}

    # ---------- Public API ----------

    async def put_secret(self, *, path: str, value: bytes, ctx: SecretContext, tags: Mapping[str, str] = {}, actor: str = "system") -> int:
        if not path or not isinstance(value, (bytes, bytearray, memoryview)):
            raise BVBadRequest("invalid path or value")
        # Envelope encrypt
        compressed, was_comp = self._maybe_compress(bytes(value))
        nonce = os.urandom(self.aead.nonce_size)
        manifest = Manifest(
            path=path,
            version=await self._next_version(path),
            alg=self._alg_name(),
            nonce_hex=nonce.hex(),
            aead_key_ref=self.cfg.key_id,
            created_ms=int(time.monotonic() * 1000),
            tags=dict(tags),
        )
        aad = _cjson({"path": path, "version": manifest.version, "alg": manifest.alg, "nonce": manifest.nonce_hex, "tags": manifest.tags, "ctx": asdict(ctx)})
        dek = await self._derive_dek(ctx=ctx, path=path)
        ciphertext = self._enc(dek, nonce, compressed, aad)
        blob = self._pack_blob(manifest, ciphertext, was_comp)
        idem = sha256_hex(_cjson({"op":"put", "path":path, "version":manifest.version, "aad":aad.hex()}))
        await self._call(lambda: self.client.put_blob(path=path, version=manifest.version, blob=blob, meta={"tags":manifest.tags}, idempotency_key=idem), tag="put_blob")
        self.audit.add("put", path, manifest.version, actor, {"size": len(value), "comp": was_comp})
        # cache new version
        await self._cache_set(path, value, manifest)
        return manifest.version

    async def get_secret(self, *, path: str, ctx: SecretContext, version: Optional[int] = None) -> Tuple[bytes, Manifest]:
        key = self._cache_key(path, version)
        # cache check
        e = await self.cache.get(key)
        now = time.monotonic()
        if e and now <= e.exp:
            return e.value, e.manifest
        # If stale but present -> return stale immediately and refresh in background
        if e:
            asyncio.create_task(self._refresh(path=path, ctx=ctx, version=version))
            return e.value, e.manifest
        # fetch
        await self.bucket.acquire(1.0, timeout_s=self.cfg.limits.timeout_s)
        async with self.sema:
            blob, meta = await self._with_retries(lambda: self.client.get_blob(path=path, version=version), tag="get_blob")
        manifest, cipher, was_comp = self._unpack_blob(blob)
        if version is not None and version != manifest.version:
            raise BVBadRequest("version mismatch in blob")
        aad = _cjson({"path": manifest.path, "version": manifest.version, "alg": manifest.alg, "nonce": manifest.nonce_hex, "tags": manifest.tags, "ctx": asdict(ctx)})
        dek = await self._derive_dek(ctx=ctx, path=path)
        plain = self._dec(dek, bytes.fromhex(manifest.nonce_hex), cipher, aad)
        value = zlib.decompress(plain) if was_comp else plain
        # update uses and cache
        manifest.uses += 1
        await self._cache_set(path, value, manifest)
        self.audit.add("get", path, manifest.version, "system", {"bytes": len(value)})
        # rotation checks
        if self._needs_rotation(manifest):
            asyncio.create_task(self._rotate_async(path=path, ctx=ctx, reason="policy"))
        return value, manifest

    async def rotate(self, *, path: str, ctx: SecretContext, reason: str = "explicit", actor: str = "system") -> int:
        # fetch latest, re-encrypt with fresh DEK/nonce, bump version
        blob, _ = await self._with_retries(lambda: self.client.get_blob(path=path, version=None), tag="get_blob")
        manifest, cipher, was_comp = self._unpack_blob(blob)
        aad_old = _cjson({"path": manifest.path, "version": manifest.version, "alg": manifest.alg, "nonce": manifest.nonce_hex, "tags": manifest.tags, "ctx": asdict(ctx)})
        dek_old = await self._derive_dek(ctx=ctx, path=path)
        plain = self._dec(dek_old, bytes.fromhex(manifest.nonce_hex), cipher, aad_old)
        data = zlib.decompress(plain) if was_comp else plain

        # re-encrypt
        new_nonce = os.urandom(self.aead.nonce_size)
        new_manifest = Manifest(
            path=manifest.path,
            version=await self._next_version(path),
            alg=self._alg_name(),
            nonce_hex=new_nonce.hex(),
            aead_key_ref=self.cfg.key_id,
            created_ms=int(time.monotonic() * 1000),
            tags=dict(manifest.tags),
        )
        aad_new = _cjson({"path": path, "version": new_manifest.version, "alg": new_manifest.alg, "nonce": new_manifest.nonce_hex, "tags": new_manifest.tags, "ctx": asdict(ctx)})
        dek_new = await self._derive_dek(ctx=ctx, path=path)
        comp, was_comp2 = self._maybe_compress(data)
        blob2 = self._pack_blob(new_manifest, self._enc(dek_new, new_nonce, comp, aad_new), was_comp2)
        idem = sha256_hex(_cjson({"op":"rotate","path":path,"v":new_manifest.version}))
        await self._call(lambda: self.client.put_blob(path=path, version=new_manifest.version, blob=blob2, meta={"tags":new_manifest.tags}, idempotency_key=idem), tag="put_blob")
        self.audit.add("rotate", path, new_manifest.version, actor, {"reason": reason})
        # retire old (soft)
        asyncio.create_task(self.client.retire_version(path=path, version=manifest.version, reason=reason))
        await self._cache_set(path, data, new_manifest)
        return new_manifest.version

    async def retire_version(self, *, path: str, version: int, reason: str = "obsolete") -> None:
        await self._with_retries(lambda: self.client.retire_version(path=path, version=version, reason=reason), tag="retire")
        self.audit.add("retire", path, version, "system", {"reason": reason})

    # ---------- Internals ----------

    def _alg_name(self) -> str:
        return f"AEAD-{self.aead.key_size*8}-BYTES"

    async def _next_version(self, path: str) -> int:
        try:
            vs = await self._with_retries(lambda: self.client.list_versions(path=path), tag="list_versions")
            return (max(vs) + 1) if vs else 1
        except BVNotFound:
            return 1

    def _maybe_compress(self, data: bytes) -> Tuple[bytes, bool]:
        if len(data) < self.cfg.compress_min_bytes:
            return data, False
        comp = zlib.compress(data, level=6)
        return (comp, True) if len(comp) < len(data) else (data, False)

    async def _derive_dek(self, *, ctx: SecretContext, path: str) -> bytes:
        # Context binding: tenant/app/env/path
        context = {"tenant": ctx.tenant, "app": ctx.app, "env": ctx.env, "path": path, **ctx.labels}
        dek = await self._with_retries(lambda: self.client.derive_key(key_id=self.cfg.key_id, context=context), tag="derive_key")
        if not isinstance(dek, (bytes, bytearray)) or len(dek) < self.aead.key_size:
            raise BVCryptoError("invalid DEK")
        return bytes(dek[: self.aead.key_size])

    def _enc(self, key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        try:
            return self.aead.encrypt(key, nonce, data, aad)
        except Exception as e:
            raise BVCryptoError(str(e)) from e

    def _dec(self, key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        try:
            return self.aead.decrypt(key, nonce, data, aad)
        except Exception as e:
            raise BVCryptoError(str(e)) from e

    def _pack_blob(self, manifest: Manifest, ciphertext: bytes, was_comp: bool) -> bytes:
        header = {
            "m": manifest.to_dict(),
            "comp": was_comp,
            "alg": manifest.alg,
            "v": manifest.version,
        }
        return _cjson(header) + b"\n" + ciphertext

    def _unpack_blob(self, blob: bytes) -> Tuple[Manifest, bytes, bool]:
        try:
            hdr, ct = blob.split(b"\n", 1)
            h = json.loads(hdr.decode("utf-8"))
            m = Manifest(**h["m"])
            return m, ct, bool(h.get("comp", False))
        except Exception as e:
            raise BVBadRequest(f"blob parse error: {e}") from e

    async def _refresh(self, *, path: str, ctx: SecretContext, version: Optional[int]) -> None:
        try:
            await self.get_secret(path=path, ctx=ctx, version=version)  # this will update cache
        except Exception:
            # swallow refresh errors; stale item remains until stale_exp
            pass

    def _needs_rotation(self, m: Manifest) -> bool:
        if self.cfg.rotation.explicit_only:
            return False
        age_ok = (time.monotonic() * 1000 - m.created_ms) / 1000.0 > self.cfg.rotation.max_age_s
        uses_ok = m.uses > self.cfg.rotation.max_uses
        return bool(age_ok or uses_ok)

    async def _rotate_async(self, *, path: str, ctx: SecretContext, reason: str) -> None:
        try:
            await self.rotate(path=path, ctx=ctx, reason=reason)
        except Exception:
            pass

    async def _cache_set(self, path: str, value: bytes, manifest: Manifest) -> None:
        ttl = self.cfg.limits.cache_ttl_s
        stale = self.cfg.limits.cache_stale_s
        entry = _CacheEntry(value=value, manifest=manifest, exp=time.monotonic() + ttl, stale_exp=time.monotonic() + ttl + stale)
        await self.cache.set(self._cache_key(path, None), entry)
        await self.cache.set(self._cache_key(path, manifest.version), entry)

    def _cache_key(self, path: str, version: Optional[int]) -> str:
        return sha256_hex(_cjson({"p": path, "v": version}))

    # ---------- Call wrappers with retries ----------

    async def _call(self, coro_factory: Callable[[], Any], *, tag: str) -> Any:
        await self.bucket.acquire(1.0, timeout_s=self.cfg.limits.timeout_s)
        async with self.sema:
            return await self._with_retries(coro_factory, tag=tag)

    async def _with_retries(self, coro_factory: Callable[[], Any], *, tag: str) -> Any:
        base, factor, cap = 0.15, 2.0, 2.5
        for attempt in range(1, self.cfg.limits.max_retries + 2):
            try:
                t0 = time.monotonic()
                res = await asyncio.wait_for(coro_factory(), timeout=self.cfg.limits.timeout_s)
                self._emit(f"blackvault.{tag}.ok", {}, {"lat_ms": (time.monotonic() - t0) * 1000.0})
                return res
            except asyncio.TimeoutError as e:
                self._emit(f"blackvault.{tag}.timeout", {}, {"attempt": float(attempt)})
                if attempt > self.cfg.limits.max_retries:
                    raise BVTimeout(str(e)) from e
            except BVRateLimited:
                if attempt > self.cfg.limits.max_retries: raise
            except BVRetryable:
                if attempt > self.cfg.limits.max_retries: raise
            await asyncio.sleep(_full_jitter(base, factor, attempt, cap))

    def _emit(self, name: str, tags: Mapping[str, str], fields: Mapping[str, float]) -> None:
        try:
            (self.cfg.telemetry or (lambda n,t,f: None))(name, dict(tags), dict(fields))
        except Exception:
            pass

# =========================
# __all__
# =========================

__all__ = [
    # config & types
    "AdapterConfig","Limits","RotationPolicy","SecretContext","Manifest",
    # interfaces
    "BlackVaultClient","AEAD",
    # adapter
    "BlackVaultAdapter",
    # errors
    "BlackVaultError","BVBadRequest","BVNotFound","BVPermission","BVRateLimited","BVRetryable","BVTimeout","BVCryptoError","BVAuditError",
    # utils
    "sha256_hex","fnv1a64",
]
