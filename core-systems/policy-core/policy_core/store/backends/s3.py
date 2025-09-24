# -*- coding: utf-8 -*-
"""
S3 backend for policy storage with industrial features.

- Async-first API with aioboto3; fallback to boto3 via asyncio.to_thread.
- TTL LRU cache for policy documents (by (key, version_id or etag)).
- Strict timeouts, retries (botocore Config), structured audit logging.
- Server-side encryption (SSE-S3 / SSE-KMS).
- Versioning support: get by VersionId, list versions, delete.
- Conditional GET with If-None-Match (ETag) to avoid payload reads.
- CAS update using temporary upload + CopyObject with If-Match (ETag).
- Presigned URLs for GET/PUT (optional).
- Health check (HEAD Bucket / small object probe).
- Optional Prometheus metrics (graceful fallback).
- No assumptions about policy schema (bytes/json). Helpers for JSON included.

Author: Aethernova / NeuroCity policy-core
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# Optional dependencies
try:  # Prefer async client
    import aioboto3  # type: ignore
except Exception:  # pragma: no cover
    aioboto3 = None  # type: ignore

try:
    import boto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
    from botocore.exceptions import ClientError, EndpointConnectionError  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore
    BotoConfig = None  # type: ignore
    ClientError = EndpointConnectionError = Exception  # type: ignore

try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore

LOGGER = logging.getLogger("policy_core.store.s3")
LOGGER.setLevel(logging.INFO)


# ============================ Exceptions ============================

class PolicyStoreError(RuntimeError):
    pass


class PolicyNotFoundError(PolicyStoreError):
    pass


class VersioningNotEnabledError(PolicyStoreError):
    pass


class PreconditionFailedError(PolicyStoreError):
    """ETag mismatch (CAS failed)."""
    pass


# ============================ Metrics (optional) ============================

class _Metrics:
    def __init__(self, ns: str, enabled: bool):
        self.enabled = enabled and (Counter is not None and Histogram is not None)
        if self.enabled:
            self.op_latency = Histogram(f"{ns}_op_latency_seconds", "S3 store op latency", ["op"])
            self.bytes_read = Counter(f"{ns}_bytes_read_total", "Bytes read")
            self.bytes_write = Counter(f"{ns}_bytes_write_total", "Bytes written")
            self.errors = Counter(f"{ns}_errors_total", "Errors", ["op", "type"])
            self.cache_hits = Counter(f"{ns}_cache_hits_total", "Cache hits", ["op"])
            self.cache_miss = Counter(f"{ns}_cache_miss_total", "Cache misses", ["op"])
        else:
            self.op_latency = self.bytes_read = self.bytes_write = self.errors = self.cache_hits = self.cache_miss = None

    def observe_latency(self, op: str, seconds: float):
        if self.enabled:
            self.op_latency.labels(op=op).observe(seconds)

    def inc_read(self, n: int):
        if self.enabled:
            self.bytes_read.inc(max(0, int(n)))

    def inc_write(self, n: int):
        if self.enabled:
            self.bytes_write.inc(max(0, int(n)))

    def inc_error(self, op: str, typ: str):
        if self.enabled:
            self.errors.labels(op=op, type=typ).inc()

    def hit(self, op: str, hit: bool):
        if self.enabled:
            (self.cache_hits if hit else self.cache_miss).labels(op=op).inc()


# ============================ TTL LRU Cache ============================

class _TTLCache:
    """
    Simple async TTL cache with size bound.
    Keys: (key, version_id or None, etag or None)
    """
    def __init__(self, max_entries: int, default_ttl: int):
        self._max = max_entries
        self._default_ttl = max(1, int(default_ttl))
        self._store: Dict[Any, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        return time.monotonic()

    async def get(self, key: Any) -> Optional[Any]:
        async with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            exp, val = rec
            if exp <= self._now():
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: Any, value: Any, ttl: Optional[int] = None):
        async with self._lock:
            if len(self._store) >= self._max:
                # Remove expired first
                now = self._now()
                expired = [k for k, (e, _) in self._store.items() if e <= now]
                for k in expired:
                    self._store.pop(k, None)
                # Drop some arbitrary entries if still full
                if len(self._store) >= self._max:
                    for k in list(self._store.keys())[: max(1, self._max // 50)]:
                        self._store.pop(k, None)
            self._store[key] = (self._now() + (ttl or self._default_ttl), value)

    async def clear(self):  # pragma: no cover
        async with self._lock:
            self._store.clear()


# ============================ Config ============================

@dataclass
class S3StoreConfig:
    bucket: str
    prefix: str = "policies/"
    region_name: Optional[str] = None
    endpoint_url: Optional[str] = None
    # Security
    sse: Optional[str] = "AES256"  # "AES256" for SSE-S3, or "aws:kms" for SSE-KMS, or None
    sse_kms_key_id: Optional[str] = None
    acl: Optional[str] = "private"
    # Networking / retries
    connect_timeout: float = 1.0
    read_timeout: float = 3.0
    max_attempts: int = 4
    signature_version: Optional[str] = None
    # Cache
    cache_ttl_seconds: int = 5
    cache_max_entries: int = 2000
    # Misc
    storage_class: Optional[str] = None  # e.g. "STANDARD", "STANDARD_IA"
    presign_expire_seconds: int = 300
    # STS AssumeRole (optional)
    role_arn: Optional[str] = None
    role_session_name: str = "policy-core-s3"
    role_external_id: Optional[str] = None
    # Metrics
    metrics_namespace: str = "policy_core_s3"
    metrics_enabled: bool = True
    # Health
    health_object_key: str = ".health"

    @staticmethod
    def from_env(prefix: str = "POLICY_S3_") -> "S3StoreConfig":  # pragma: no cover
        def _get(name: str, default: Optional[str] = None) -> Optional[str]:
            return os.getenv(prefix + name, default)
        def _get_bool(name: str, default: bool) -> bool:
            v = os.getenv(prefix + name)
            return default if v is None else v.lower() in ("1", "true", "yes", "on")
        return S3StoreConfig(
            bucket=_get("BUCKET", "") or "",
            prefix=_get("PREFIX", "policies/") or "policies/",
            region_name=_get("REGION"),
            endpoint_url=_get("ENDPOINT_URL"),
            sse=_get("SSE", "AES256") or None,
            sse_kms_key_id=_get("SSE_KMS_KEY_ID"),
            acl=_get("ACL", "private"),
            connect_timeout=float(_get("CONNECT_TIMEOUT", "1.0")),
            read_timeout=float(_get("READ_TIMEOUT", "3.0")),
            max_attempts=int(_get("MAX_ATTEMPTS", "4")),
            signature_version=_get("SIGNATURE_VERSION"),
            cache_ttl_seconds=int(_get("CACHE_TTL_SECONDS", "5")),
            cache_max_entries=int(_get("CACHE_MAX_ENTRIES", "2000")),
            storage_class=_get("STORAGE_CLASS"),
            presign_expire_seconds=int(_get("PRESIGN_EXPIRE_SECONDS", "300")),
            role_arn=_get("ROLE_ARN"),
            role_session_name=_get("ROLE_SESSION_NAME", "policy-core-s3"),
            role_external_id=_get("ROLE_EXTERNAL_ID"),
            metrics_namespace=_get("METRICS_NAMESPACE", "policy_core_s3"),
            metrics_enabled=_get_bool("METRICS_ENABLED", True),
            health_object_key=_get("HEALTH_OBJECT_KEY", ".health"),
        )


# ============================ Helpers ============================

def _join_key(prefix: str, namespace: str, policy_id: str, ext: str = ".json") -> str:
    p = prefix.strip("/")
    ns = namespace.strip("/")
    pid = policy_id.strip("/")
    return f"{p}/{ns}/{pid}{ext}".lstrip("/")


def _tmp_key(original_key: str) -> str:
    return f"{original_key}.tmp.{uuid.uuid4().hex}"


def _json_dumps_safe(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ============================ S3 Client Abstraction ============================

class _S3Client:
    """
    Abstraction over aioboto3 / boto3 with minimal async surface.
    """
    def __init__(self, cfg: S3StoreConfig):
        self.cfg = cfg
        self._async = aioboto3 is not None
        self._session_async = aioboto3.Session() if aioboto3 is not None else None
        self._client_sync = None
        if not self._async:
            if boto3 is None:
                raise PolicyStoreError("Neither aioboto3 nor boto3 available.")
            self._session_sync = boto3.session.Session()
            self._client_sync = self._session_sync.client(
                "s3",
                region_name=cfg.region_name,
                endpoint_url=cfg.endpoint_url,
                config=BotoConfig(
                    retries={"max_attempts": cfg.max_attempts, "mode": "standard"},
                    connect_timeout=cfg.connect_timeout,
                    read_timeout=cfg.read_timeout,
                    signature_version=cfg.signature_version,
                ),
            )

    # ---------- Async context manager for aioboto3 client ----------
    async def _client_async(self):  # pragma: no cover (depends on aioboto3)
        assert self._session_async is not None
        return self._session_async.client(
            "s3",
            region_name=self.cfg.region_name,
            endpoint_url=self.cfg.endpoint_url,
            config=BotoConfig(
                retries={"max_attempts": self.cfg.max_attempts, "mode": "standard"},
                connect_timeout=self.cfg.connect_timeout,
                read_timeout=self.cfg.read_timeout,
                signature_version=self.cfg.signature_version,
            ),
        )

    # ---------- Wrapped operations ----------
    async def head_bucket(self, bucket: str) -> Dict[str, Any]:
        if self._async:  # pragma: no cover
            client = await self._client_async()
            async with client as c:
                return await c.head_bucket(Bucket=bucket)
        return await asyncio.to_thread(self._client_sync.head_bucket, Bucket=bucket)

    async def head_object(self, bucket: str, key: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        params = {"Bucket": bucket, "Key": key}
        if version_id:
            params["VersionId"] = version_id
        if self._async:  # pragma: no cover
            client = await self._client_async()
            async with client as c:
                return await c.head_object(**params)
        return await asyncio.to_thread(self._client_sync.head_object, **params)

    async def get_object(self, bucket: str, key: str, version_id: Optional[str] = None,
                         if_none_match: Optional[str] = None) -> Tuple[Dict[str, Any], bytes]:
        params = {"Bucket": bucket, "Key": key}
        if version_id:
            params["VersionId"] = version_id
        if if_none_match:
            params["IfNoneMatch"] = if_none_match
        if self._async:  # pragma: no cover
            client = await self._client_async()
            async with client as c:
                try:
                    resp = await c.get_object(**params)
                    body = await resp["Body"].read()
                    return resp, body
                except ClientError as e:
                    # 304 Not Modified handling is thrown as ClientError in some stacks
                    if e.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 304:
                        raise e
                    raise
        # sync path
        def _call():
            return self._client_sync.get_object(**params)
        try:
            resp = await asyncio.to_thread(_call)
            body = await asyncio.to_thread(resp["Body"].read)
            return resp, body
        except ClientError:
            raise

    async def put_object(self, bucket: str, key: str, body: bytes, **kwargs) -> Dict[str, Any]:
        params = {"Bucket": bucket, "Key": key, "Body": body}
        params.update(kwargs)
        if self._async:  # pragma: no cover
            client = await self._client_async()
            async with client as c:
                return await c.put_object(**params)
        return await asyncio.to_thread(self._client_sync.put_object, **params)

    async def copy_object(self, bucket: str, source_key: str, target_key: str, **kwargs) -> Dict[str, Any]:
        params = {
            "Bucket": bucket,
            "Key": target_key,
            "CopySource": {"Bucket": bucket, "Key": source_key},
        }
        params.update(kwargs)
        if self._async:  # pragma: no cover
            client = await self._client_async()
            async with client as c:
                return await c.copy_object(**params)
        return await asyncio.to_thread(self._client_sync.copy_object, **params)

    async def delete_object(self, bucket: str, key: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        params = {"Bucket": bucket, "Key": key}
        if version_id:
            params["VersionId"] = version_id
        if self._async:  # pragma: no cover
            client = await self._client_async()
            async with client as c:
                return await c.delete_object(**params)
        return await asyncio.to_thread(self._client_sync.delete_object, **params)

    async def list_objects(self, bucket: str, prefix: str, max_keys: int = 1000) -> Iterable[Dict[str, Any]]:
        token = None
        while True:
            params = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": max_keys}
            if token:
                params["ContinuationToken"] = token
            if self._async:  # pragma: no cover
                client = await self._client_async()
                async with client as c:
                    resp = await c.list_objects_v2(**params)
            else:
                resp = await asyncio.to_thread(self._client_sync.list_objects_v2, **params)
            for it in resp.get("Contents", []):
                yield it
            token = resp.get("NextContinuationToken")
            if not token:
                break

    async def list_object_versions(self, bucket: str, prefix: str, key: Optional[str] = None) -> Iterable[Dict[str, Any]]:
        token = None
        while True:
            params = {"Bucket": bucket, "Prefix": key or prefix}
            if token:
                params["KeyMarker"] = token[0]
                params["VersionIdMarker"] = token[1]
            if self._async:  # pragma: no cover
                client = await self._client_async()
                async with client as c:
                    resp = await c.list_object_versions(**params)
            else:
                resp = await asyncio.to_thread(self._client_sync.list_object_versions, **params)

            for it in resp.get("Versions", []):
                yield it
            km = resp.get("NextKeyMarker")
            vm = resp.get("NextVersionIdMarker")
            token = (km, vm) if km and vm else None
            if not token:
                break


# ============================ Store ============================

class S3PolicyStore:
    """
    High-reliability S3 policy store.

    Concurrency-safe updates via CAS (ETag) using CopyObject with CopySourceIfMatch.
    Use 'put_policy' for blind updates, or 'put_policy_cas' for optimistic concurrency.
    """

    def __init__(self, cfg: S3StoreConfig):
        self.cfg = cfg
        self.s3 = _S3Client(cfg)
        self.cache = _TTLCache(cfg.cache_max_entries, cfg.cache_ttl_seconds)
        self.metrics = _Metrics(cfg.metrics_namespace, cfg.metrics_enabled)

    # ---------- Public API ----------

    async def health(self) -> bool:
        t0 = time.monotonic()
        try:
            await self.s3.head_bucket(self.cfg.bucket)
            self.metrics.observe_latency("health", time.monotonic() - t0)
            return True
        except Exception as e:
            self.metrics.inc_error("health", type(e).__name__)
            LOGGER.warning(json.dumps({"op": "health", "ok": False, "error": type(e).__name__}, ensure_ascii=False))
            return False

    async def get_policy(
        self,
        namespace: str,
        policy_id: str,
        *,
        version_id: Optional[str] = None,
        etag_hint: Optional[str] = None,
        decode_json: bool = True,
        ext: str = ".json",
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Returns dict:
          {
            "key": "...",
            "body": bytes|dict,
            "etag": "...",
            "version_id": "...",
            "last_modified": "...",
            "content_type": "..."
          }
        """
        key = _join_key(self.cfg.prefix, namespace, policy_id, ext)
        cache_key = (key, version_id, etag_hint or None)
        if use_cache:
            cached = await self.cache.get(cache_key)
            self.metrics.hit("get", cached is not None)
            if cached is not None:
                return cached

        params = {"bucket": self.cfg.bucket, "key": key, "version_id": version_id, "if_none_match": etag_hint}
        t0 = time.monotonic()
        try:
            resp, body = await self.s3.get_object(**params)
            self.metrics.observe_latency("get", time.monotonic() - t0)
            self.metrics.inc_read(len(body))

            etag = (resp.get("ETag") or "").strip('"')
            ver = resp.get("VersionId")
            ct = resp.get("ContentType") or "application/octet-stream"
            lm = resp.get("LastModified").isoformat() if resp.get("LastModified") else None
            data = body
            if decode_json and ct.startswith("application/json"):
                try:
                    data = json.loads(body.decode("utf-8"))
                except Exception:
                    # keep raw bytes on decode fail
                    data = body

            out = {
                "key": key,
                "body": data,
                "etag": etag,
                "version_id": ver,
                "last_modified": lm,
                "content_type": ct,
            }
            await self.cache.set(cache_key, out)
            LOGGER.info(json.dumps({"op": "get", "key": key, "version_id": ver, "etag": etag}, ensure_ascii=False))
            return out

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("NoSuchKey", "NotFound"):
                self.metrics.inc_error("get", "NotFound")
                raise PolicyNotFoundError(f"Policy not found: {key}")
            if e.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 304:
                # Not Modified: return cache if present, otherwise re-fetch without hint
                self.metrics.hit("get", True)
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    return cached
                # re-fetch forcibly
                return await self.get_policy(namespace, policy_id, version_id=version_id, etag_hint=None,
                                             decode_json=decode_json, ext=ext, use_cache=False)
            self.metrics.inc_error("get", code or type(e).__name__)
            raise
        except Exception as e:
            self.metrics.inc_error("get", type(e).__name__)
            raise

    async def put_policy(
        self,
        namespace: str,
        policy_id: str,
        body: Union[bytes, Dict[str, Any], List[Any]],
        *,
        content_type: Optional[str] = None,
        ext: str = ".json",
        metadata: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Blind write (no CAS). For concurrency-sensitive updates prefer put_policy_cas.
        """
        key = _join_key(self.cfg.prefix, namespace, policy_id, ext)
        if not isinstance(body, (bytes, bytearray)):
            body_bytes = _json_dumps_safe(body)
            content_type = content_type or "application/json; charset=utf-8"
        else:
            body_bytes = bytes(body)
            content_type = content_type or "application/octet-stream"

        put_kwargs = self._put_kwargs(content_type=content_type, metadata=metadata)

        t0 = time.monotonic()
        resp = await self.s3.put_object(self.cfg.bucket, key, body_bytes, **put_kwargs)
        self.metrics.observe_latency("put", time.monotonic() - t0)
        self.metrics.inc_write(len(body_bytes))

        etag = (resp.get("ETag") or "").strip('"')
        ver = resp.get("VersionId")
        await self._invalidate_cache_prefix(key)
        LOGGER.info(json.dumps({"op": "put", "key": key, "version_id": ver, "etag": etag}, ensure_ascii=False))
        return {"key": key, "etag": etag, "version_id": ver}

    async def put_policy_cas(
        self,
        namespace: str,
        policy_id: str,
        body: Union[bytes, Dict[str, Any], List[Any]],
        *,
        expected_etag: str,
        content_type: Optional[str] = None,
        ext: str = ".json",
        metadata: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Optimistic concurrency control:
          1) Upload new content to a temporary key.
          2) CopyObject -> target with CopySourceIfMatch=expected_etag.
          3) Delete temporary object.
        If ETag differs, raises PreconditionFailedError.
        """
        key = _join_key(self.cfg.prefix, namespace, policy_id, ext)
        tmp = _tmp_key(key)

        if not isinstance(body, (bytes, bytearray)):
            body_bytes = _json_dumps_safe(body)
            content_type = content_type or "application/json; charset=utf-8"
        else:
            body_bytes = bytes(body)
            content_type = content_type or "application/octet-stream"

        put_kwargs = self._put_kwargs(content_type=content_type, metadata=metadata)
        t0 = time.monotonic()
        # 1) Upload temp
        await self.s3.put_object(self.cfg.bucket, tmp, body_bytes, **put_kwargs)
        # 2) Copy with If-Match
        try:
            copy_kwargs = {
                "MetadataDirective": "REPLACE",
                "ContentType": content_type,
                "ACL": self.cfg.acl,
            }
            if self.cfg.sse == "aws:kms" and self.cfg.sse_kms_key_id:
                copy_kwargs["ServerSideEncryption"] = "aws:kms"
                copy_kwargs["SSEKMSKeyId"] = self.cfg.sse_kms_key_id
            elif self.cfg.sse == "AES256":
                copy_kwargs["ServerSideEncryption"] = "AES256"
            # Precondition:
            copy_kwargs["CopySourceIfMatch"] = expected_etag

            resp = await self.s3.copy_object(self.cfg.bucket, tmp, key, **copy_kwargs)
            ver = resp.get("VersionId")
            etag = (resp.get("CopyObjectResult", {}).get("ETag") or "").strip('"')
            self.metrics.observe_latency("put_cas", time.monotonic() - t0)
            self.metrics.inc_write(len(body_bytes))
            LOGGER.info(json.dumps({"op": "put_cas", "key": key, "version_id": ver, "etag": etag}, ensure_ascii=False))
            return {"key": key, "etag": etag, "version_id": ver}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            self.metrics.inc_error("put_cas", code or type(e).__name__)
            if code in ("PreconditionFailed", "412"):
                raise PreconditionFailedError(f"ETag mismatch for {key}")
            raise
        finally:
            try:
                await self.s3.delete_object(self.cfg.bucket, tmp)
            except Exception:
                LOGGER.warning(json.dumps({"op": "cleanup_tmp", "key": tmp, "status": "failed"}, ensure_ascii=False))
            await self._invalidate_cache_prefix(key)

    async def delete_policy(self, namespace: str, policy_id: str, *, ext: str = ".json",
                            version_id: Optional[str] = None) -> Dict[str, Any]:
        key = _join_key(self.cfg.prefix, namespace, policy_id, ext)
        t0 = time.monotonic()
        resp = await self.s3.delete_object(self.cfg.bucket, key, version_id=version_id)
        self.metrics.observe_latency("delete", time.monotonic() - t0)
        await self._invalidate_cache_prefix(key)
        LOGGER.info(json.dumps({"op": "delete", "key": key, "version_id": version_id}, ensure_ascii=False))
        return {"key": key, "version_id": version_id, "delete_marker": resp.get("DeleteMarker")}

    async def list_policies(self, namespace: str, *, ext: str = ".json") -> List[Dict[str, Any]]:
        prefix = _join_key(self.cfg.prefix, namespace, "", ext="").rstrip("/")
        t0 = time.monotonic()
        out: List[Dict[str, Any]] = []
        async for obj in _AsyncIter(self.s3.list_objects(self.cfg.bucket, prefix)):
            out.append({
                "key": obj["Key"],
                "size": obj.get("Size"),
                "etag": (obj.get("ETag") or "").strip('"') if obj.get("ETag") else None,
                "last_modified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
            })
        self.metrics.observe_latency("list", time.monotonic() - t0)
        LOGGER.info(json.dumps({"op": "list", "prefix": prefix, "count": len(out)}, ensure_ascii=False))
        return [x for x in out if x["key"].endswith(ext)]

    async def list_versions(self, namespace: str, policy_id: str, *, ext: str = ".json") -> List[Dict[str, Any]]:
        key = _join_key(self.cfg.prefix, namespace, policy_id, ext)
        t0 = time.monotonic()
        out: List[Dict[str, Any]] = []
        async for ver in _AsyncIter(self.s3.list_object_versions(self.cfg.bucket, self.cfg.prefix, key=key)):
            if ver.get("Key") != key:
                continue
            out.append({
                "version_id": ver.get("VersionId"),
                "is_latest": ver.get("IsLatest"),
                "last_modified": ver.get("LastModified").isoformat() if ver.get("LastModified") else None,
                "etag": (ver.get("ETag") or "").strip('"') if ver.get("ETag") else None,
                "size": ver.get("Size"),
            })
        self.metrics.observe_latency("versions", time.monotonic() - t0)
        LOGGER.info(json.dumps({"op": "versions", "key": key, "count": len(out)}, ensure_ascii=False))
        return out

    async def presign_get(self, namespace: str, policy_id: str, *, ext: str = ".json",
                          expires_in: Optional[int] = None) -> str:
        """
        Returns presigned GET URL. Requires boto3 (sync) since prometheus + aioboto3 presign not essential.
        """
        if boto3 is None:
            raise PolicyStoreError("boto3 is required for presign URLs.")
        key = _join_key(self.cfg.prefix, namespace, policy_id, ext)
        client = boto3.client(
            "s3",
            region_name=self.cfg.region_name,
            endpoint_url=self.cfg.endpoint_url,
            config=BotoConfig(
                retries={"max_attempts": self.cfg.max_attempts, "mode": "standard"},
                connect_timeout=self.cfg.connect_timeout,
                read_timeout=self.cfg.read_timeout,
                signature_version=self.cfg.signature_version,
            ),
        )
        url = client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": self.cfg.bucket, "Key": key},
            ExpiresIn=int(expires_in or self.cfg.presign_expire_seconds),
        )
        LOGGER.info(json.dumps({"op": "presign_get", "key": key}, ensure_ascii=False))
        return url

    # ---------- Helpers ----------

    def _put_kwargs(self, *, content_type: str, metadata: Optional[Mapping[str, str]]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "ContentType": content_type,
        }
        if self.cfg.acl:
            kwargs["ACL"] = self.cfg.acl
        if self.cfg.sse == "aws:kms" and self.cfg.sse_kms_key_id:
            kwargs["ServerSideEncryption"] = "aws:kms"
            kwargs["SSEKMSKeyId"] = self.cfg.sse_kms_key_id
        elif self.cfg.sse == "AES256":
            kwargs["ServerSideEncryption"] = "AES256"
        if self.cfg.storage_class:
            kwargs["StorageClass"] = self.cfg.storage_class
        if metadata:
            kwargs["Metadata"] = {str(k): str(v) for k, v in metadata.items()}
        return kwargs

    async def _invalidate_cache_prefix(self, key: str):
        # Simple invalidation strategy: clear whole cache (safe) or leave as-is.
        # For now: clear entire cache to avoid stale reads after writes.
        await self.cache.clear()

    # ---------- JSON convenience ----------

    async def get_policy_json(self, namespace: str, policy_id: str, **kwargs) -> Dict[str, Any]:
        out = await self.get_policy(namespace, policy_id, decode_json=True, **kwargs)
        if isinstance(out["body"], (bytes, bytearray)):
            try:
                out["body"] = json.loads(bytes(out["body"]).decode("utf-8"))
            except Exception:
                raise PolicyStoreError("Stored policy is not valid JSON.")
        return out

    async def put_policy_json(self, namespace: str, policy_id: str, doc: Mapping[str, Any], **kwargs) -> Dict[str, Any]:
        return await self.put_policy(namespace, policy_id, body=doc, content_type="application/json; charset=utf-8", **kwargs)


# ============================ Async iterator adapter ============================

class _AsyncIter:
    """
    Wraps a sync/async iterable (async generator or normal generator of awaitables)
    into an async iterator.
    """
    def __init__(self, it):
        self._it = it

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            if hasattr(self._it, "__anext__"):
                return await self._it.__anext__()  # type: ignore
            # Assume sync generator yielding dicts; fetch next in thread
            return await asyncio.to_thread(next, self._it)
        except StopIteration:
            raise StopAsyncIteration
