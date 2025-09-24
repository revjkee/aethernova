# datafabric-core/datafabric/connectors/s3.py
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import math
import os
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, Field, validator

# Опциональные зависимости
try:
    import aioboto3  # type: ignore
except Exception:  # pragma: no cover
    aioboto3 = None

import boto3  # type: ignore
from botocore.client import Config as BotoConfig  # type: ignore
from botocore.exceptions import ClientError, BotoCoreError  # type: ignore


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

class S3RetryConfig(BaseModel):
    max_attempts: int = Field(7, ge=1, le=15, description="Максимум попыток (включая первую)")
    base_delay_ms: int = Field(100, ge=1)
    max_delay_ms: int = Field(20_000, ge=100)
    jitter_ms: int = Field(300, ge=0)
    exponential_factor: float = Field(2.0, ge=1.0)

class S3Timeouts(BaseModel):
    connect_timeout_s: int = Field(10, ge=1)
    read_timeout_s: int = Field(300, ge=1)

class S3SSEConfig(BaseModel):
    enabled: bool = Field(False)
    type: str = Field("SSE-S3", description="SSE-S3|SSE-KMS|SSE-C")
    kms_key_id: Optional[str] = None
    sse_customer_algorithm: Optional[str] = None
    sse_customer_key_b64: Optional[str] = None

class S3Config(BaseModel):
    # Доступ и окружение
    region_name: Optional[str] = Field(None)
    endpoint_url: Optional[str] = Field(None, description="Например, MinIO/совместимый S3")
    profile_name: Optional[str] = Field(None, description="Именованный профиль AWS")
    role_arn: Optional[str] = Field(None, description="Опционально: STS AssumeRole")

    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None

    # Производительность/надежность
    retries: S3RetryConfig = S3RetryConfig()
    timeouts: S3Timeouts = S3Timeouts()
    max_concurrency: int = Field(16, ge=1, le=128)
    multipart_threshold_mb: int = Field(16, ge=5, description="Порог multipart")
    multipart_chunk_mb: int = Field(8, ge=5, description="Размер части multipart")
    use_accelerate_endpoint: bool = Field(False)
    addressing_style: str = Field("auto", description="auto|virtual|path")

    # Шифрование
    sse: S3SSEConfig = S3SSEConfig()

    # Подписанные URLs
    presign_expire_s: int = Field(3600, ge=1, le=7 * 24 * 3600)

    # Метрики/трейсинг
    metrics_prefix: str = Field("datafabric_s3")

    @validator("addressing_style")
    def _addr_style(cls, v: str) -> str:
        v = v.lower()
        if v not in ("auto", "virtual", "path"):
            raise ValueError("addressing_style must be auto|virtual|path")
        return v


# ============================ Исключения ==============================

class S3ConnectorError(Exception):
    pass


# ============================ Вспомогательное =========================

def _md5_hexdigest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def _compute_backoff(attempt: int, cfg: S3RetryConfig) -> float:
    base = cfg.base_delay_ms / 1000.0
    delay = min(base * (cfg.exponential_factor ** (attempt - 1)), cfg.max_delay_ms / 1000.0)
    jitter = (cfg.jitter_ms / 1000.0) * (os.urandom(1)[0] / 255.0) if cfg.jitter_ms > 0 else 0.0
    return delay + jitter

def _sse_kwargs(cfg: S3SSEConfig) -> Dict[str, Any]:
    if not cfg.enabled:
        return {}
    t = cfg.type.upper()
    if t == "SSE-S3":
        return {"ServerSideEncryption": "AES256"}
    if t == "SSE-KMS":
        kw: Dict[str, Any] = {"ServerSideEncryption": "aws:kms"}
        if cfg.kms_key_id:
            kw["SSEKMSKeyId"] = cfg.kms_key_id
        return kw
    if t == "SSE-C":
        kw: Dict[str, Any] = {}
        if cfg.sse_customer_algorithm:
            kw["SSECustomerAlgorithm"] = cfg.sse_customer_algorithm
        if cfg.sse_customer_key_b64:
            kw["SSECustomerKey"] = cfg.sse_customer_key_b64
        return kw
    return {}


# ============================= Основной класс =========================

class S3Connector:
    """
    Универсальный S3‑коннектор: работает в async‑режиме с aioboto3, либо
    в fallback‑режиме через boto3 с выполнением блокирующих операций в thread pool.
    """

    def __init__(
        self,
        cfg: S3Config,
        *,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics or Metrics()
        self.tracer = tracer or Tracer()
        self.loop = loop or asyncio.get_event_loop()
        self._session = None  # boto3.Session
        self._aio_session = None  # aioboto3.Session
        self._client = None
        self._resource = None
        self._aio_client_ctx = None  # async context manager for aioboto3 client

    # ---------------------------- Инициализация ----------------------------

    def _boto_config(self) -> BotoConfig:
        retries = {"max_attempts": self.cfg.retries.max_attempts, "mode": "adaptive"}
        return BotoConfig(
            region_name=self.cfg.region_name,
            connect_timeout=self.cfg.timeouts.connect_timeout_s,
            read_timeout=self.cfg.timeouts.read_timeout_s,
            retries=retries,
            s3={"addressing_style": self.cfg.addressing_style},
            s3_accelerate=self.cfg.use_accelerate_endpoint,
        )

    async def __aenter__(self) -> "S3Connector":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_client(self) -> None:
        if self._client is not None:
            return

        span = self.tracer.start_span("s3.ensure_client")
        try:
            if aioboto3:
                # aioboto3 путь
                self._aio_session = aioboto3.Session(profile_name=self.cfg.profile_name) if self.cfg.profile_name else aioboto3.Session()
                self._aio_client_ctx = self._aio_session.client(
                    "s3",
                    endpoint_url=self.cfg.endpoint_url,
                    region_name=self.cfg.region_name,
                    aws_access_key_id=self.cfg.aws_access_key_id,
                    aws_secret_access_key=self.cfg.aws_secret_access_key,
                    aws_session_token=self.cfg.aws_session_token,
                    config=self._boto_config(),
                )
                # контекстный менеджер клиента
                self._client = await self._aio_client_ctx.__aenter__()
            else:
                # boto3 + thread pool
                self._session = boto3.Session(
                    profile_name=self.cfg.profile_name,
                    aws_access_key_id=self.cfg.aws_access_key_id,
                    aws_secret_access_key=self.cfg.aws_secret_access_key,
                    aws_session_token=self.cfg.aws_session_token,
                    region_name=self.cfg.region_name,
                )
                self._client = self._session.client(
                    "s3",
                    endpoint_url=self.cfg.endpoint_url,
                    config=self._boto_config(),
                )
        except Exception as e:
            span.record_exception(e)
            raise S3ConnectorError(f"Failed to initialize S3 client: {e}") from e
        finally:
            span.end()

    async def close(self) -> None:
        if aioboto3 and self._aio_client_ctx:
            with contextlib.suppress(Exception):
                await self._aio_client_ctx.__aexit__(None, None, None)
        self._client = None

    # ----------------------------- Утилиты вызовов -----------------------------

    async def _call(
        self,
        fn_name: str,
        *,
        retryable: bool = True,
        **kwargs: Any,
    ) -> Any:
        """
        Унифицированный вызов client.<fn_name> с ретраями и метриками.
        """
        await self._ensure_client()
        client = self._client
        assert client is not None

        span = self.tracer.start_span(f"s3.{fn_name}", **{k: str(v)[:128] for k, v in kwargs.items() if k in ("Bucket", "Key")})
        attempt = 1
        start = time.perf_counter()
        try:
            while True:
                try:
                    if aioboto3:
                        coro = getattr(client, fn_name)(**kwargs)
                        result = await coro
                    else:
                        # Выполняем блокирующий вызов в тредпуле
                        result = await asyncio.to_thread(getattr(client, fn_name), **kwargs)
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_{fn_name}_total")
                    return result
                except (ClientError, BotoCoreError) as e:
                    code = getattr(getattr(e, "response", {}).get("Error", {}), "get", lambda *_: None)("Code")
                    transient = retryable and _is_retryable_error(e, code)
                    if not transient or attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    delay = _compute_backoff(attempt, self.cfg.retries)
                    attempt += 1
                    await asyncio.sleep(delay)
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_{fn_name}_seconds", time.perf_counter() - start)
            span.end()

    # ----------------------------- Бакеты -----------------------------

    async def ensure_bucket(self, bucket: str, *, acl: Optional[str] = None) -> None:
        try:
            await self._call("head_bucket", Bucket=bucket)
        except Exception:
            params: Dict[str, Any] = {"Bucket": bucket}
            if self.cfg.region_name:
                params["CreateBucketConfiguration"] = {"LocationConstraint": self.cfg.region_name}
            if acl:
                params["ACL"] = acl
            await self._call("create_bucket", **params)

    async def put_bucket_policy(self, bucket: str, policy_json: Dict[str, Any]) -> None:
        await self._call("put_bucket_policy", Bucket=bucket, Policy=json.dumps(policy_json))

    async def put_lifecycle(self, bucket: str, rules: List[Dict[str, Any]]) -> None:
        await self._call("put_bucket_lifecycle_configuration", Bucket=bucket, LifecycleConfiguration={"Rules": rules})

    # ----------------------------- Объекты -----------------------------

    async def head_object(self, bucket: str, key: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._call("head_object", Bucket=bucket, Key=key)
        except ClientError as e:
            if e.response and e.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                return None
            raise

    async def get_object_stream(self, bucket: str, key: str, *, range_header: Optional[str] = None) -> AsyncIterator[bytes]:
        """
        Асинхронный генератор по чанкам body. Не грузит объект целиком в память.
        """
        resp = await self._call("get_object", Bucket=bucket, Key=key, Range=range_header) if range_header else await self._call("get_object", Bucket=bucket, Key=key)
        body = resp["Body"]
        chunk = 64 * 1024

        if aioboto3:
            # У aioboto3 body — это StreamingBody совместимый с async read
            while True:
                data = await body.read(chunk)
                if not data:
                    break
                yield data
        else:
            # boto3: читаем в thread pool и публикуем в async генератор
            def _reader():
                while True:
                    b = body.read(chunk)
                    if not b:
                        break
                    yield b
            for part in await asyncio.to_thread(lambda: list(_reader())):
                yield part

    async def put_object(
        self,
        bucket: str,
        key: str,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        checksum_md5_hex: Optional[str] = None,
        acl: Optional[str] = None,
        storage_class: Optional[str] = None,
    ) -> Dict[str, Any]:
        kw: Dict[str, Any] = dict(Bucket=bucket, Key=key, Body=data)
        if content_type:
            kw["ContentType"] = content_type
        if metadata:
            kw["Metadata"] = metadata
        if acl:
            kw["ACL"] = acl
        if storage_class:
            kw["StorageClass"] = storage_class
        if checksum_md5_hex:
            kw["ContentMD5"] = _b64_md5(checksum_md5_hex)
        kw.update(_sse_kwargs(self.cfg.sse))
        return await self._call("put_object", **kw)

    async def download_file(self, bucket: str, key: str, dest_path: str) -> None:
        """
        Надежная выгрузка в файл с временным именем и атомарным rename.
        """
        tmp_path = f"{dest_path}.part-{int(time.time()*1000)}"
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(tmp_path, "wb") as f:
            async for chunk in self.get_object_stream(bucket, key):
                f.write(chunk)
        os.replace(tmp_path, dest_path)

    async def upload_file_multipart(
        self,
        bucket: str,
        key: str,
        file_path: str,
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        acl: Optional[str] = None,
        storage_class: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Multipart‑загрузка с ограничением параллелизма и ретраями частей.
        """
        await self._ensure_client()
        size = os.path.getsize(file_path)
        threshold = self.cfg.multipart_threshold_mb * 1024 * 1024
        part_size = self.cfg.multipart_chunk_mb * 1024 * 1024

        if size < threshold:
            with open(file_path, "rb") as fh:
                data = fh.read()
            return await self.put_object(bucket, key, data, content_type=content_type, metadata=metadata, acl=acl, storage_class=storage_class)

        # Initiate MPU
        kw_init: Dict[str, Any] = dict(Bucket=bucket, Key=key)
        if content_type:
            kw_init["ContentType"] = content_type
        if metadata:
            kw_init["Metadata"] = metadata
        if acl:
            kw_init["ACL"] = acl
        if storage_class:
            kw_init["StorageClass"] = storage_class
        kw_init.update(_sse_kwargs(self.cfg.sse))
        mpu = await self._call("create_multipart_upload", **kw_init)
        upload_id = mpu["UploadId"]

        parts_etags: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.cfg.max_concurrency)

        async def _upload_part(part_number: int, offset: int, length: int) -> Dict[str, Any]:
            async with sem:
                attempt = 1
                while True:
                    try:
                        with open(file_path, "rb") as fh:
                            fh.seek(offset)
                            body = fh.read(length)
                        resp = await self._call(
                            "upload_part",
                            Bucket=bucket,
                            Key=key,
                            UploadId=upload_id,
                            PartNumber=part_number,
                            Body=body,
                        )
                        return {"ETag": resp["ETag"], "PartNumber": part_number}
                    except Exception as e:
                        if attempt >= self.cfg.retries.max_attempts:
                            raise
                        await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                        attempt += 1

        try:
            tasks: List[Awaitable[Dict[str, Any]]] = []
            part_count = math.ceil(size / part_size)
            for i in range(part_count):
                offset = i * part_size
                length = min(part_size, size - offset)
                tasks.append(_upload_part(i + 1, offset, length))

            for coro in asyncio.as_completed(tasks):
                parts_etags.append(await coro)

            parts_etags.sort(key=lambda x: x["PartNumber"])
            return await self._call(
                "complete_multipart_upload",
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts_etags},
            )
        except Exception:
            with contextlib.suppress(Exception):
                await self._call("abort_multipart_upload", Bucket=bucket, Key=key, UploadId=upload_id)
            raise

    async def copy_object(self, src_bucket: str, src_key: str, dst_bucket: str, dst_key: str, *, metadata: Optional[Dict[str, str]] = None, acl: Optional[str] = None, storage_class: Optional[str] = None) -> Dict[str, Any]:
        kw: Dict[str, Any] = dict(
            Bucket=dst_bucket,
            Key=dst_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
        )
        if metadata:
            kw["Metadata"] = metadata
            kw["MetadataDirective"] = "REPLACE"
        if acl:
            kw["ACL"] = acl
        if storage_class:
            kw["StorageClass"] = storage_class
        kw.update(_sse_kwargs(self.cfg.sse))
        return await self._call("copy_object", **kw)

    async def move_object(self, src_bucket: str, src_key: str, dst_bucket: str, dst_key: str) -> None:
        await self.copy_object(src_bucket, src_key, dst_bucket, dst_key)
        await self.delete_many(src_bucket, [src_key])

    async def delete_many(self, bucket: str, keys: Iterable[str]) -> None:
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
        await self._call("delete_objects", Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys]})

    # ----------------------------- Листинг/пагинация -----------------------------

    async def list_paginated(
        self,
        bucket: str,
        *,
        prefix: Optional[str] = None,
        delimiter: Optional[str] = None,
        page_size: int = 1000,
        max_keys: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Асинхронный генератор объектов (Summary словари, как в ListObjectsV2).
        """
        fetched = 0
        token = None
        while True:
            kw = dict(Bucket=bucket, MaxKeys=min(page_size, 1000))
            if prefix:
                kw["Prefix"] = prefix
            if delimiter:
                kw["Delimiter"] = delimiter
            if token:
                kw["ContinuationToken"] = token
            resp = await self._call("list_objects_v2", **kw)
            for item in resp.get("Contents", []):
                yield item
                fetched += 1
                if max_keys is not None and fetched >= max_keys:
                    return
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")

    # ----------------------------- Presigned URLs ------------------------------

    async def generate_presigned_get(self, bucket: str, key: str, *, expires_in_s: Optional[int] = None, response_content_type: Optional[str] = None) -> str:
        params = {"Bucket": bucket, "Key": key}
        if response_content_type:
            params["ResponseContentType"] = response_content_type
        return await self._presign("get_object", params, expires_in_s)

    async def generate_presigned_put(self, bucket: str, key: str, *, expires_in_s: Optional[int] = None, content_type: Optional[str] = None) -> str:
        params = {"Bucket": bucket, "Key": key}
        if content_type:
            params["ContentType"] = content_type
        params.update(_sse_kwargs(self.cfg.sse))
        return await self._presign("put_object", params, expires_in_s)

    async def generate_presigned_post(self, bucket: str, key: str, *, expires_in_s: Optional[int] = None, conditions: Optional[List[Any]] = None, fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        await self._ensure_client()
        client = self._client
        expire = int(expires_in_s or self.cfg.presign_expire_s)
        fields = dict(fields or {})
        fields.update(_sse_kwargs(self.cfg.sse))
        if aioboto3:
            return await client.generate_presigned_post(bucket, key, Fields=fields or None, Conditions=conditions or None, ExpiresIn=expire)
        return await asyncio.to_thread(client.generate_presigned_post, bucket, key, Fields=fields or None, Conditions=conditions or None, ExpiresIn=expire)

    async def _presign(self, op: str, params: Dict[str, Any], expires_in_s: Optional[int]) -> str:
        await self._ensure_client()
        client = self._client
        expire = int(expires_in_s or self.cfg.presign_expire_s)
        if aioboto3:
            return await client.generate_presigned_url(op, Params=params, ExpiresIn=expire)
        return await asyncio.to_thread(client.generate_presigned_url, op, Params=params, ExpiresIn=expire)

    # ----------------------------- Glacier Restore -----------------------------

    async def restore_glacier(self, bucket: str, key: str, *, days: int = 1, tier: str = "Standard") -> None:
        """
        Инициирует восстановление объекта (Deep Archive/Glacier).
        tier: Expedited|Standard|Bulk
        """
        await self._call(
            "restore_object",
            Bucket=bucket,
            Key=key,
            RestoreRequest={"Days": days, "GlacierJobParameters": {"Tier": tier}},
        )

    # ----------------------------- Проверка контрольной суммы -------------------

    async def verify_etag_md5(self, bucket: str, key: str, *, local_path: str) -> bool:
        """
        Проверка для НЕ‑multipart объектов (ETag == MD5). Для multipart ETag содержит “-<n>”.
        """
        head = await self.head_object(bucket, key)
        if not head:
            return False
        etag = head.get("ETag", "").strip('"')
        if "-" in etag:  # multipart
            return False
        md5 = await asyncio.to_thread(_md5_file, local_path)
        return md5 == etag


# ========================= Низкоуровневые утилиты =====================

def _md5_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def _b64_md5(hex_md5: str) -> str:
    # botocore ожидает base64 от сырого md5; но ContentMD5 должен быть base64‑строкой.
    import base64, binascii
    raw = binascii.unhexlify(hex_md5)
    return base64.b64encode(raw).decode("ascii")

def _is_retryable_error(exc: Exception, code: Optional[str]) -> bool:
    # Упрощенная эвристика: сеть/транзиент/лимиты
    text = str(exc)
    transient_markers = ("Throttling", "SlowDown", "RequestTimeout", "Timeout", "Connection", "Broken pipe", "InternalError", "ServiceUnavailable")
    return any(m in text for m in transient_markers) or (code in {"503", "500", "RequestTimeout"} if code else False)
