# datafabric-core/datafabric/storage/objectstore/minio_client.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import io
import os
import time
import hashlib
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, validator

# --------------------- Опциональные зависимости ----------------------
try:
    # Официальный клиент MinIO (синхронный)
    from minio import Minio  # type: ignore
    from minio.deleteobjects import DeleteObject  # type: ignore
    from minio.commonconfig import CopySource  # type: ignore
    from minio.sse import SseCustomerKey, SseKms, SseS3  # type: ignore
    from minio.error import S3Error  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("The 'minio' package is required: pip install minio") from e


# ===================== Протоколы метрик/трейсинга =====================

class Metrics:
    async def inc(self, name: str, value: int = 1, **labels: str) -> None:
        return
    async def observe(self, name: str, value: float, **labels: str) -> None:
        return

class Tracer:
    def start_span(self, name: str, **attrs: Any) -> "Span":
        return Span()

class Span:
    def set_attribute(self, key: str, value: Any) -> None:
        return
    def record_exception(self, exc: BaseException) -> None:
        return
    def end(self) -> None:
        return


# =============================== Конфиг ===============================

class RetryConfig(BaseModel):
    max_attempts: int = Field(7, ge=1, le=15)
    base_delay_ms: int = Field(100, ge=1)
    max_delay_ms: int = Field(20_000, ge=100)
    jitter_ms: int = Field(300, ge=0)
    exponential_factor: float = Field(2.0, ge=1.0)

class Timeouts(BaseModel):
    connect_timeout_s: int = Field(10, ge=1)
    read_timeout_s: int = Field(300, ge=1)

class SSEConfig(BaseModel):
    enabled: bool = False
    # "SSE-S3" | "SSE-KMS" | "SSE-C"
    type: str = Field("SSE-S3")
    kms_key: Optional[str] = None
    customer_key_b64: Optional[str] = None  # base64 сырого ключа
    customer_key_md5_b64: Optional[str] = None  # base64 md5(сырой ключ)

    @validator("type")
    def _vt(cls, v: str) -> str:
        v = v.upper()
        if v not in ("SSE-S3", "SSE-KMS", "SSE-C"):
            raise ValueError("SSE type must be one of: SSE-S3|SSE-KMS|SSE-C")
        return v

class MinioConfig(BaseModel):
    endpoint: str = Field(..., description="host:port или FQDN; без схемы")
    access_key: str = Field(...)
    secret_key: str = Field(..., repr=False)
    session_token: Optional[str] = Field(None, repr=False)
    secure: bool = Field(True, description="HTTPS=True/HTTP=False")
    region: Optional[str] = None

    retries: RetryConfig = RetryConfig()
    timeouts: Timeouts = Timeouts()
    max_concurrency: int = Field(16, ge=1, le=128)
    multipart_threshold_mb: int = Field(16, ge=5)
    multipart_chunk_mb: int = Field(8, ge=5)
    presign_expire_s: int = Field(3600, ge=1, le=7 * 24 * 3600)
    metrics_prefix: str = Field("datafabric_minio")

    sse: SSEConfig = SSEConfig()

    @validator("endpoint")
    def _strip_scheme(cls, v: str) -> str:
        v = v.strip().replace("https://", "").replace("http://", "")
        if "/" in v:
            v = v.split("/", 1)[0]
        return v


# ============================ Исключения ==============================

class MinioConnectorError(Exception):
    pass


# ============================ Вспомогательное =========================

def _compute_backoff(attempt: int, cfg: RetryConfig) -> float:
    base = cfg.base_delay_ms / 1000.0
    delay = min(base * (cfg.exponential_factor ** (attempt - 1)), cfg.max_delay_ms / 1000.0)
    # равномерный джиттер
    jitter = (cfg.jitter_ms / 1000.0) * (os.urandom(1)[0] / 255.0) if cfg.jitter_ms > 0 else 0.0
    return delay + jitter

def _build_sse(cfg: SSEConfig):
    if not cfg.enabled:
        return None
    t = cfg.type.upper()
    if t == "SSE-S3":
        return SseS3()
    if t == "SSE-KMS":
        if not cfg.kms_key:
            raise MinioConnectorError("SSE-KMS requires kms_key")
        return SseKms(cfg.kms_key)
    if t == "SSE-C":
        if not cfg.customer_key_b64:
            raise MinioConnectorError("SSE-C requires customer_key_b64")
        return SseCustomerKey(cfg.customer_key_b64, cfg.customer_key_md5_b64)
    return None

def _is_retryable(e: Exception) -> bool:
    # S3Error: code + status; сеть/таймауты/5xx/429 считаем транзиентными
    if isinstance(e, S3Error):
        try:
            st = int(getattr(e, "response", None).status) if getattr(e, "response", None) else None  # type: ignore
        except Exception:
            st = None
        text = f"{e.code} {e.message} {st}"
        if st and (st >= 500 or st == 429):
            return True
        markers = ("SlowDown", "RequestTimeTooSkewed", "RequestTimeout", "InternalError", "ServiceUnavailable", "TooManyRequests", "connection", "timeout")
        return any(m.lower() in text.lower() for m in markers)
    # Общие сетевые/таймаут исключения
    return any(s in str(e).lower() for s in ("timeout", "temporarily", "unreachable", "reset", "closed"))


# ============================ Основной класс ==========================

class MinioObjectStore:
    """
    Асинхронный фасад к MinIO/совместимым S3 API на основе синхронного клиента.
    - Все блокирующие вызовы выполняются через asyncio.to_thread()
    - Ретраи/джиттер/ограничение конкурентности
    - SSE, presign, multipart, стриминг
    """

    def __init__(
        self,
        cfg: MinioConfig,
        *,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics or Metrics()
        self.tracer = tracer or Tracer()
        self.loop = loop or asyncio.get_event_loop()
        self._client: Optional[Minio] = None
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self._started = False

    # ---------------------------- Lifecycle ----------------------------

    async def start(self) -> None:
        if self._started:
            return
        span = self.tracer.start_span("minio.start", endpoint=self.cfg.endpoint, secure=str(self.cfg.secure))
        t0 = time.perf_counter()
        try:
            # Создаём клиент MinIO (создаёт собственный HTTP‑пул)
            self._client = Minio(
                self.cfg.endpoint,
                access_key=self.cfg.access_key,
                secret_key=self.cfg.secret_key,
                session_token=self.cfg.session_token,
                secure=self.cfg.secure,
                region=self.cfg.region,
                # Можно прокинуть custom http_client с таймаутами при необходимости
            )
            # Простой ping (ListBuckets) для валидации кредов
            await self._call("list_buckets")
            self._started = True
        except Exception as e:
            span.record_exception(e)
            raise MinioConnectorError(f"Failed to initialize MinIO client: {e}") from e
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_start_seconds", time.perf_counter() - t0)
            span.end()

    async def close(self) -> None:
        # minio клиент не требует закрытия; оставляем хук на будущее
        self._client = None
        self._started = False

    async def health(self) -> bool:
        try:
            await self._ensure()
            await self._call("list_buckets")
            return True
        except Exception:
            return False

    async def _ensure(self) -> None:
        if not self._started or not self._client:
            await self.start()

    # ------------------------------ Core call ------------------------------

    async def _call(self, fn_name: str, *args, retryable: bool = True, **kwargs) -> Any:
        """
        Унифицированный вызов клиента MinIO с ретраями и метриками.
        """
        await self._ensure()
        assert self._client is not None
        fn = getattr(self._client, fn_name)

        attempt = 1
        span = self.tracer.start_span(f"minio.{fn_name}")
        t0 = time.perf_counter()
        try:
            while True:
                try:
                    async with self._sem:
                        result = await asyncio.to_thread(fn, *args, **kwargs)
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_{fn_name}_total")
                    return result
                except Exception as e:
                    if not (retryable and _is_retryable(e)) or attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                    attempt += 1
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_{fn_name}_seconds", time.perf_counter() - t0)
            span.end()

    # ------------------------------ Buckets ------------------------------

    async def ensure_bucket(self, bucket: str, *, region: Optional[str] = None, object_lock: bool = False) -> None:
        exists = await self._call("bucket_exists", bucket)
        if exists:
            return
        await self._call("make_bucket", bucket, location=region or self.cfg.region, object_lock=object_lock)

    async def set_versioning(self, bucket: str, *, enabled: bool) -> None:
        status = "Enabled" if enabled else "Suspended"
        await self._call("set_bucket_versioning", bucket, status)

    async def get_versioning(self, bucket: str) -> str:
        return await self._call("get_bucket_versioning", bucket)

    # ------------------------------ Objects (basic) ------------------------------

    async def put_object(
        self,
        bucket: str,
        key: str,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        sse: Optional[Any] = None,
        tags: Optional[Dict[str, str]] = None,
        legal_hold: Optional[bool] = None,
        retention_mode: Optional[str] = None,  # GOVERNANCE|COMPLIANCE
        retention_until_ts: Optional[int] = None,  # epoch seconds
    ) -> Dict[str, Any]:
        sse = sse or _build_sse(self.cfg.sse)
        length = len(data)
        # hash не обязателен; при необходимости можно задать MD5
        res = await self._call(
            "put_object",
            bucket,
            key,
            io.BytesIO(data),
            length,
            content_type=content_type,
            metadata=metadata,
            sse=sse,
            tags=tags,
            legal_hold=legal_hold,
            retention=retention_mode,
            retention_until=retention_until_ts,
        )
        return {"etag": getattr(res, "etag", None), "version_id": getattr(res, "version_id", None)}

    async def get_object_stream(self, bucket: str, key: str, *, version_id: Optional[str] = None, offset: int = 0, length: Optional[int] = None, sse: Optional[Any] = None) -> AsyncIterator[bytes]:
        sse = sse or _build_sse(self.cfg.sse)
        # MinIO get_object возвращает StreamingResponse; читаем блоками в тред‑пуле и yield в async
        obj = await self._call("get_object", bucket, key, offset=offset, length=length, version_id=version_id, sse=sse)
        # Гарантированно закрываем объект
        try:
            def _reader():
                chunk = 64 * 1024
                while True:
                    b = obj.read(chunk)
                    if not b:
                        break
                    yield b
            for part in await asyncio.to_thread(lambda: list(_reader())):
                yield part
        finally:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(obj.close)

    async def download_file(self, bucket: str, key: str, dest_path: str, *, version_id: Optional[str] = None) -> None:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        tmp = f"{dest_path}.part-{int(time.time()*1000)}"
        with open(tmp, "wb") as f:
            async for chunk in self.get_object_stream(bucket, key, version_id=version_id):
                f.write(chunk)
        os.replace(tmp, dest_path)

    # ------------------------------ Atomic put (tmp→commit) ------------------------------

    async def atomic_put(
        self,
        bucket: str,
        key: str,
        data: bytes,
        *,
        tmp_suffix: str = ".tmp",
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Гарантированная запись: 1) put tmp; 2) copy tmp -> final (atomic on object store); 3) delete tmp.
        """
        tmp_key = f"{key}{tmp_suffix}"
        await self.put_object(bucket, tmp_key, data, content_type=content_type, metadata=metadata)
        try:
            await self.copy_object(bucket, tmp_key, bucket, key, metadata=metadata, content_type=content_type)
        finally:
            # Даже при неудачной копии пробуем удалить tmp
            with contextlib.suppress(Exception):
                await self.delete_many(bucket, [tmp_key])
        head = await self.stat_object(bucket, key)
        return {"etag": head.get("etag"), "size": head.get("size")}

    # ------------------------------ Multipart upload ------------------------------

    async def upload_file_multipart(
        self,
        bucket: str,
        key: str,
        file_path: str,
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        sse: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Для больших файлов — используем fput_object (SDK сам выполнит multipart).
        """
        sse = sse or _build_sse(self.cfg.sse)
        res = await self._call(
            "fput_object",
            bucket,
            key,
            file_path,
            content_type=content_type,
            metadata=metadata,
            sse=sse,
        )
        return {"etag": getattr(res, "etag", None), "version_id": getattr(res, "version_id", None)}

    # ------------------------------ Copy/Move/Delete/Stat ------------------------------

    async def copy_object(self, src_bucket: str, src_key: str, dst_bucket: str, dst_key: str, *, metadata: Optional[Dict[str, str]] = None, content_type: Optional[str] = None, sse: Optional[Any] = None) -> Dict[str, Any]:
        sse = sse or _build_sse(self.cfg.sse)
        src = CopySource(src_bucket, src_key)
        res = await self._call(
            "copy_object",
            dst_bucket,
            dst_key,
            src,
            metadata=metadata,
            metadata_directive="REPLACE" if metadata else None,
            sse=sse,
            content_type=content_type,
        )
        return {"etag": getattr(res, "etag", None), "last_modified": getattr(res, "last_modified", None)}

    async def move_object(self, src_bucket: str, src_key: str, dst_bucket: str, dst_key: str) -> None:
        await self.copy_object(src_bucket, src_key, dst_bucket, dst_key)
        await self.delete_many(src_bucket, [src_key])

    async def delete_many(self, bucket: str, keys: Iterable[str]) -> None:
        # удаление партиями по 1000
        chunk = 1000
        batch: List[str] = []
        for k in keys:
            batch.append(k)
            if len(batch) >= chunk:
                await self._delete_batch(bucket, batch)
                batch.clear()
        if batch:
            await self._delete_batch(bucket, batch)

    async def _delete_batch(self, bucket: str, keys: List[str]) -> None:
        objs = [DeleteObject(k) for k in keys]
        # remove_objects возвращает генератор ошибок — нужно прочесть его
        errs = await self._call("remove_objects", bucket, objs)
        # errs — генератор; выгружаем в список в тред‑пуле
        def _collect():
            out = []
            for e in errs:
                out.append(e)
            return out
        problems = await asyncio.to_thread(_collect)
        if problems:
            # Бросаем первую ошибку (логика может быть расширена)
            raise MinioConnectorError(f"Failed to delete some objects: {problems[0]}")

    async def stat_object(self, bucket: str, key: str, *, version_id: Optional[str] = None) -> Dict[str, Any]:
        s = await self._call("stat_object", bucket, key, version_id=version_id)
        return {
            "etag": getattr(s, "etag", None),
            "size": getattr(s, "size", None),
            "last_modified": getattr(s, "last_modified", None),
            "version_id": getattr(s, "version_id", None),
            "content_type": getattr(s, "content_type", None),
            "metadata": getattr(s, "metadata", None),
        }

    # ------------------------------ Listing ------------------------------

    async def list_paginated(
        self,
        bucket: str,
        *,
        prefix: Optional[str] = None,
        recursive: bool = True,
        include_versions: bool = False,
        max_items: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Асинхронный генератор объектов (и версий, если включено).
        """
        await self._ensure()

        def _iter():
            if include_versions:
                return self._client.list_object_versions(bucket, prefix=prefix, recursive=recursive)  # type: ignore
            return self._client.list_objects(bucket, prefix=prefix, recursive=recursive)  # type: ignore

        # Итераторы MinIO ленивые и блокирующие — читаем их в thread pool чанками
        yielded = 0
        def _collect(n: int) -> List[Any]:
            out: List[Any] = []
            it = _iter()
            for item in it:
                out.append(item)
                if len(out) >= n:
                    break
            return out

        # Поскольку итератор однократный, без токена — просто сканируем и yield
        items = await asyncio.to_thread(lambda: list(_iter()))
        for o in items:
            info = {
                "key": getattr(o, "object_name", None),
                "size": getattr(o, "size", None),
                "is_dir": getattr(o, "is_dir", False),
                "etag": getattr(o, "etag", None),
                "last_modified": getattr(o, "last_modified", None),
                "version_id": getattr(o, "version_id", None),
                "is_latest": getattr(o, "is_latest", None),
                "delete_marker": getattr(o, "is_delete_marker", None),
            }
            yield info
            yielded += 1
            if max_items and yielded >= max_items:
                return

    # ------------------------------ Presigned URLs ------------------------------

    async def generate_presigned_get(self, bucket: str, key: str, *, expires_in_s: Optional[int] = None, response_content_type: Optional[str] = None) -> str:
        expire = int(expires_in_s or self.cfg.presign_expire_s)
        params = {"response-content-type": response_content_type} if response_content_type else None
        return await self._call("presigned_get_object", bucket, key, expires=expire, response_headers=params)

    async def generate_presigned_put(self, bucket: str, key: str, *, expires_in_s: Optional[int] = None, content_type: Optional[str] = None) -> str:
        expire = int(expires_in_s or self.cfg.presign_expire_s)
        params = {"Content-Type": content_type} if content_type else None
        return await self._call("presigned_put_object", bucket, key, expires=expire, req_params=params)

    async def generate_presigned_post(self, bucket: str, key: str, *, expires_in_s: Optional[int] = None, conditions: Optional[List[Any]] = None, fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        expire = int(expires_in_s or self.cfg.presign_expire_s)
        policy = await self._call("get_presigned_post_policy")  # type: ignore
        # Настроим политику
        await asyncio.to_thread(policy.set_bucket_name, bucket)  # type: ignore
        await asyncio.to_thread(policy.set_key_startswith, key)  # type: ignore
        if fields and "content-type" in {k.lower() for k in fields.keys()}:
            await asyncio.to_thread(policy.set_content_type, fields.get("content-type"))  # type: ignore
        if expire:
            await asyncio.to_thread(policy.set_expires, expire)  # type: ignore
        return await self._call("presigned_post_policy", policy)  # type: ignore

    # ------------------------------ Object Lock / Retention ------------------------------

    async def set_legal_hold(self, bucket: str, key: str, *, status: bool, version_id: Optional[str] = None) -> None:
        await self._call("set_object_legal_hold", bucket, key, status, version_id=version_id)

    async def set_object_retention(self, bucket: str, key: str, *, mode: str, retain_until_ts: int, version_id: Optional[str] = None, governance_bypass: bool = False) -> None:
        await self._call("set_object_retention", bucket, key, mode, retain_until_ts, version_id=version_id, governance_bypass=governance_bypass)

    # ------------------------------ Утилиты ------------------------------

    @staticmethod
    def md5_file(path: str, chunk: int = 1024 * 1024) -> str:
        h = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()

    @staticmethod
    def md5_bytes(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()


# ============================ Пример интеграции (сохранить в файле) ============================
"""
from datafabric.storage.objectstore.minio_client import MinioObjectStore, MinioConfig

cfg = MinioConfig(
    endpoint="minio.internal:9000",
    access_key="AKIA...",
    secret_key="SECRET...",
    secure=True,
    region="us-east-1",
)

async def run():
    store = MinioObjectStore(cfg)
    await store.ensure_bucket("lake", region="us-east-1")
    await store.set_versioning("lake", enabled=True)

    # Atomic put
    await store.atomic_put("lake", "events/part-000.parquet", b"binary-data", content_type="application/octet-stream")

    # Stream download
    async for chunk in store.get_object_stream("lake", "events/part-000.parquet"):
        pass

    # Presigned
    url = await store.generate_presigned_put("lake", "upload/test.bin", content_type="application/octet-stream")
"""
