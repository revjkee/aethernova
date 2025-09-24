# oblivionvault-core/oblivionvault/adapters/storage_s3.py
"""
Промышленный асинхронный адаптер S3 для oblivionvault-core.

Возможности:
- Асинхронный S3-клиент (aioboto3/aiobotocore).
- Потоковая загрузка/скачивание, включая multipart upload для крупных объектов.
- Ретраи с экспоненциальным backoff и джиттером, настраиваемые таймауты.
- SSE/SSE-KMS (Server-Side Encryption) и совместимость с MinIO/совместимыми S3.
- Пресайны (GET/PUT), листинг с пагинацией, удаление объектов/префиксов.
- Строгая типизация, единые исключения, структурное логирование.
- Необязательная трассировка (OpenTelemetry), безопасные метаданные/теги.

Зависимости:
    pip install aioboto3 botocore

Опционально (для трассировки):
    pip install opentelemetry-api

Пример:
    from oblivionvault.adapters.storage_s3 import S3Config, S3StorageAdapter

    cfg = S3Config.from_env(bucket="vault-data")
    async with S3StorageAdapter(cfg) as s3:
        await s3.put_bytes("path/to/file.bin", b"payload", content_type="application/octet-stream")
        data = await s3.get_bytes("path/to/file.bin")
        url = await s3.generate_presigned_url("path/to/file.bin", method="get_object", expires_in=900)
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Tuple

try:
    import aioboto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
    )  # type: ignore
except Exception as e:  # pragma: no cover
    raise ImportError(
        "storage_s3.py requires 'aioboto3' and 'botocore'. Install with: pip install aioboto3 botocore"
    ) from e

try:
    # Опциональная трассировка
    from opentelemetry import trace  # type: ignore

    _TRACER = trace.get_tracer(__name__)
    def _span(name: str):
        return _TRACER.start_as_current_span(name)
except Exception:  # pragma: no cover
    from contextlib import nullcontext as _nullcontext

    def _span(name: str):
        return _nullcontext()


# ==========================
# Исключения адаптера
# ==========================
class StorageError(Exception):
    """Базовая ошибка хранилища."""


class NotFoundError(StorageError):
    """Объект не найден."""


class AlreadyExistsError(StorageError):
    """Объект уже существует (при условии ожидания отсутствия)."""


class TransientError(StorageError):
    """Временная ошибка, допустима к ретраю."""


# ==========================
# Конфигурация
# ==========================
@dataclass(frozen=True)
class S3Config:
    bucket: str
    region_name: Optional[str] = None
    endpoint_url: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None

    # S3 доп. настройки
    path_style: bool = False
    signature_version: Optional[str] = None  # e.g. "s3v4"
    max_pool_connections: int = 50
    connect_timeout: float = 10.0
    read_timeout: float = 60.0
    retries_max_attempts: int = 10  # botocore внутр. ретраи; пов-ся с нашим backoff

    # Безопасность
    sse: Optional[str] = None  # "AES256" или "aws:kms"
    sse_kms_key_id: Optional[str] = None
    acl: Optional[str] = None  # "bucket-owner-full-control" и т.п.

    # Multipart
    multipart_threshold: int = 8 * 1024 * 1024  # 8 MiB
    multipart_chunk_size: int = 8 * 1024 * 1024  # 8 MiB

    # Backoff
    backoff_base: float = 0.2
    backoff_cap: float = 5.0
    backoff_max_retries: int = 5

    # Генерация пресайнов
    presign_default_exp: int = 900  # 15 минут

    @staticmethod
    def from_env(
        bucket: str,
        *,
        prefix: str = "OV_S3_",
        defaults: Optional[Mapping[str, Any]] = None,
    ) -> "S3Config":
        """
        Инициализация конфигурации из окружения.
        Доступные переменные (c префиксом, по умолчанию OV_S3_):
            REGION, ENDPOINT, ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN,
            PATH_STYLE, SIGNATURE_VERSION, MAX_POOL, CONNECT_TIMEOUT, READ_TIMEOUT,
            SSE, SSE_KMS_KEY_ID, ACL, MULTIPART_THRESHOLD, MULTIPART_CHUNK_SIZE,
            BACKOFF_BASE, BACKOFF_CAP, BACKOFF_MAX_RETRIES, PRESIGN_DEFAULT_EXP
        """
        d = defaults or {}

        def getenv(name: str, cast: Any = str, default: Any = None):
            v = os.getenv(prefix + name, d.get(name, default))
            if v is None:
                return None
            try:
                return cast(v)
            except Exception:
                return v

        return S3Config(
            bucket=bucket,
            region_name=getenv("REGION", str, None),
            endpoint_url=getenv("ENDPOINT", str, None),
            access_key_id=getenv("ACCESS_KEY_ID", str, None),
            secret_access_key=getenv("SECRET_ACCESS_KEY", str, None),
            session_token=getenv("SESSION_TOKEN", str, None),
            path_style=bool(str(getenv("PATH_STYLE", str, "false")).lower() == "true"),
            signature_version=getenv("SIGNATURE_VERSION", str, None),
            max_pool_connections=int(getenv("MAX_POOL", int, 50)),
            connect_timeout=float(getenv("CONNECT_TIMEOUT", float, 10.0)),
            read_timeout=float(getenv("READ_TIMEOUT", float, 60.0)),
            retries_max_attempts=int(getenv("BOTOCORE_RETRIES", int, 10)),
            sse=getenv("SSE", str, None),
            sse_kms_key_id=getenv("SSE_KMS_KEY_ID", str, None),
            acl=getenv("ACL", str, None),
            multipart_threshold=int(getenv("MULTIPART_THRESHOLD", int, 8 * 1024 * 1024)),
            multipart_chunk_size=int(getenv("MULTIPART_CHUNK_SIZE", int, 8 * 1024 * 1024)),
            backoff_base=float(getenv("BACKOFF_BASE", float, 0.2)),
            backoff_cap=float(getenv("BACKOFF_CAP", float, 5.0)),
            backoff_max_retries=int(getenv("BACKOFF_MAX_RETRIES", int, 5)),
            presign_default_exp=int(getenv("PRESIGN_DEFAULT_EXP", int, 900)),
        )


# ==========================
# Утилиты
# ==========================
def _serialize_tags(tags: Optional[Mapping[str, str]]) -> Optional[str]:
    if not tags:
        return None
    from urllib.parse import quote_plus

    # S3 требует URL-кодирование: "k1=v1&k2=v2"
    return "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in tags.items())


def _is_retryable_error(error: Exception) -> bool:
    # Маркируем ошибки как временные для наших ретраев
    if isinstance(error, (EndpointConnectionError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError)):
        return True
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        return code in {
            "Throttling",
            "ThrottlingException",
            "RequestTimeout",
            "RequestTimeoutException",
            "InternalError",
            "SlowDown",
            "ServiceUnavailable",
            "503",
        }
    if isinstance(error, BotoCoreError):
        # Общие сетевые/внутренние
        return True
    return False


async def _with_backoff(
    func,
    *args,
    max_retries: int,
    base: float,
    cap: float,
    logger: logging.Logger,
    span_name: str,
    **kwargs,
):
    attempt = 0
    while True:
        try:
            with _span(span_name):
                return await func(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            if _is_retryable_error(e) and attempt < max_retries:
                delay = min(cap, base * (2 ** attempt)) * (0.5 + random.random() / 2.0)
                logger.warning(
                    "S3 transient error on %s (attempt=%s): %s; retrying in %.2fs",
                    span_name,
                    attempt + 1,
                    getattr(e, "message", repr(e)),
                    delay,
                    extra={"event": "s3_retry", "attempt": attempt + 1, "op": span_name},
                )
                await asyncio.sleep(delay)
                attempt += 1
                continue
            raise


# ==========================
# Адаптер
# ==========================
class S3StorageAdapter:
    """
    Асинхронный S3-адаптер для oblivionvault-core.
    Использует низкоуровневый aioboto3 client.

    Контракт методов ориентирован на бинарные безопасные объекты хранилища:
      - put_bytes / put_stream
      - get_bytes / stream_to
      - head, exists, list, delete, delete_prefix
      - generate_presigned_url
    """

    def __init__(
        self,
        config: S3Config,
        *,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._cfg = config
        self._session = aioboto3.Session()
        self._client = None  # type: ignore
        self._logger = logger or logging.getLogger("oblivionvault.s3")
        self._logger.debug("S3StorageAdapter initialized", extra={"event": "s3_init"})

    # -------- Context Manager --------
    async def __aenter__(self) -> "S3StorageAdapter":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_client(self) -> None:
        if self._client is not None:
            return
        s3_config = BotoConfig(
            s3={"addressing_style": "path" if self._cfg.path_style else "auto"},
            signature_version=self._cfg.signature_version,
            retries={"max_attempts": self._cfg.retries_max_attempts, "mode": "standard"},
            max_pool_connections=self._cfg.max_pool_connections,
            connect_timeout=self._cfg.connect_timeout,
            read_timeout=self._cfg.read_timeout,
        )
        self._client = await self._session.client(
            "s3",
            region_name=self._cfg.region_name,
            endpoint_url=self._cfg.endpoint_url,
            aws_access_key_id=self._cfg.access_key_id,
            aws_secret_access_key=self._cfg.secret_access_key,
            aws_session_token=self._cfg.session_token,
            config=s3_config,
        ).__aenter__()
        self._logger.info(
            "S3 client created",
            extra={
                "event": "s3_client_created",
                "bucket": self._cfg.bucket,
                "endpoint": self._cfg.endpoint_url,
                "region": self._cfg.region_name,
                "path_style": self._cfg.path_style,
            },
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.__aexit__(None, None, None)
            self._client = None
            self._logger.info("S3 client closed", extra={"event": "s3_client_closed"})

    # -------- Bucket helpers --------
    async def ensure_bucket(self, create_if_missing: bool = False) -> None:
        """
        Проверяет существование бакета; опционально создаёт (для MinIO/локальных стендов).
        """
        await self._ensure_client()

        async def _head_bucket():
            return await self._client.head_bucket(Bucket=self._cfg.bucket)

        try:
            await _with_backoff(
                _head_bucket,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.head_bucket",
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in {"404", "NoSuchBucket"}:
                if not create_if_missing:
                    raise NotFoundError(f"Bucket '{self._cfg.bucket}' not found")
                async def _create():
                    kwargs = {"Bucket": self._cfg.bucket}
                    if self._cfg.region_name and (self._cfg.endpoint_url is None):  # AWS S3 create_bucket LocationConstraint
                        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": self._cfg.region_name}
                    return await self._client.create_bucket(**kwargs)

                await _with_backoff(
                    _create,
                    max_retries=self._cfg.backoff_max_retries,
                    base=self._cfg.backoff_base,
                    cap=self._cfg.backoff_cap,
                    logger=self._logger,
                    span_name="s3.create_bucket",
                )
                self._logger.info("Bucket created", extra={"event": "s3_bucket_created", "bucket": self._cfg.bucket})
            else:
                raise

    # -------- Core operations --------
    async def put_bytes(
        self,
        key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: Optional[Mapping[str, str]] = None,
        tags: Optional[Mapping[str, str]] = None,
        storage_class: Optional[str] = None,
        if_none_match: bool = False,
        checksum_sha256_b64: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Загрузка небольших объектов одним запросом.
        if_none_match=True — эквивалент "не перезаписывать, если существует".
        checksum_sha256_b64 — значение SHA256 в base64 для проверки на стороне S3 (ChecksumSHA256).
        """
        await self._ensure_client()

        def _headers() -> Dict[str, Any]:
            h: Dict[str, Any] = {
                "Bucket": self._cfg.bucket,
                "Key": key,
                "Body": data,
                "ContentType": content_type,
            }
            if metadata:
                h["Metadata"] = dict(metadata)
            tag_str = _serialize_tags(tags)
            if tag_str:
                h["Tagging"] = tag_str
            if storage_class:
                h["StorageClass"] = storage_class
            if self._cfg.acl:
                h["ACL"] = self._cfg.acl
            if self._cfg.sse:
                h["ServerSideEncryption"] = self._cfg.sse
            if self._cfg.sse_kms_key_id:
                h["SSEKMSKeyId"] = self._cfg.sse_kms_key_id
            if if_none_match:
                h["ExpectedBucketOwner"] = None  # no-op for AWS; удерживаем интерфейс
                h["IfNoneMatch"] = "*"  # создаст 412, если объект существует
            if checksum_sha256_b64:
                h["ChecksumSHA256"] = checksum_sha256_b64
            return h

        async def _put():
            return await self._client.put_object(**_headers())

        try:
            resp = await _with_backoff(
                _put,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.put_object",
            )
            return {"ETag": resp.get("ETag"), "VersionId": resp.get("VersionId")}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if if_none_match and code in {"PreconditionFailed"}:
                raise AlreadyExistsError(f"Object '{key}' already exists") from e
            raise

    async def put_stream(
        self,
        key: str,
        chunks: AsyncIterator[bytes],
        *,
        content_type: str = "application/octet-stream",
        metadata: Optional[Mapping[str, str]] = None,
        tags: Optional[Mapping[str, str]] = None,
        storage_class: Optional[str] = None,
        checksum_sha256_b64: Optional[str] = None,
        min_part_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Потоковая загрузка крупного объекта через multipart upload.
        chunks — асинхронный итератор байтов.
        min_part_size — минимальный размер части (по умолчанию multipart_chunk_size).
        """
        await self._ensure_client()
        part_size = max(min_part_size or self._cfg.multipart_chunk_size, 5 * 1024 * 1024)

        create_kwargs: Dict[str, Any] = {
            "Bucket": self._cfg.bucket,
            "Key": key,
            "ContentType": content_type,
        }
        if metadata:
            create_kwargs["Metadata"] = dict(metadata)
        tag_str = _serialize_tags(tags)
        if tag_str:
            create_kwargs["Tagging"] = tag_str
        if storage_class:
            create_kwargs["StorageClass"] = storage_class
        if self._cfg.acl:
            create_kwargs["ACL"] = self._cfg.acl
        if self._cfg.sse:
            create_kwargs["ServerSideEncryption"] = self._cfg.sse
        if self._cfg.sse_kms_key_id:
            create_kwargs["SSEKMSKeyId"] = self._cfg.sse_kms_key_id
        if checksum_sha256_b64:
            create_kwargs["ChecksumSHA256"] = checksum_sha256_b64

        async def _create():
            return await self._client.create_multipart_upload(**create_kwargs)

        mp = await _with_backoff(
            _create,
            max_retries=self._cfg.backoff_max_retries,
            base=self._cfg.backoff_base,
            cap=self._cfg.backoff_cap,
            logger=self._logger,
            span_name="s3.create_multipart_upload",
        )
        upload_id = mp["UploadId"]
        parts: List[Dict[str, Any]] = []
        part_number = 1

        async def abort():
            async def _abort():
                return await self._client.abort_multipart_upload(
                    Bucket=self._cfg.bucket, Key=key, UploadId=upload_id
                )
            try:
                await _with_backoff(
                    _abort,
                    max_retries=self._cfg.backoff_max_retries,
                    base=self._cfg.backoff_base,
                    cap=self._cfg.backoff_cap,
                    logger=self._logger,
                    span_name="s3.abort_multipart_upload",
                )
            except Exception as _:
                self._logger.error(
                    "Failed to abort multipart upload",
                    extra={"event": "s3_abort_failed", "key": key, "upload_id": upload_id},
                )

        try:
            buffer = bytearray()
            async for chunk in chunks:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise TypeError("chunks must yield bytes")
                buffer.extend(chunk)
                while len(buffer) >= part_size:
                    part = bytes(buffer[:part_size])
                    del buffer[:part_size]

                    async def _upload_part():
                        return await self._client.upload_part(
                            Bucket=self._cfg.bucket,
                            Key=key,
                            UploadId=upload_id,
                            PartNumber=part_number,
                            Body=part,
                        )

                    resp = await _with_backoff(
                        _upload_part,
                        max_retries=self._cfg.backoff_max_retries,
                        base=self._cfg.backoff_base,
                        cap=self._cfg.backoff_cap,
                        logger=self._logger,
                        span_name="s3.upload_part",
                    )
                    parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
                    part_number += 1

            # хвост
            if buffer:
                final_part = bytes(buffer)

                async def _upload_last():
                    return await self._client.upload_part(
                        Bucket=self._cfg.bucket,
                        Key=key,
                        UploadId=upload_id,
                        PartNumber=part_number,
                        Body=final_part,
                    )

                resp = await _with_backoff(
                    _upload_last,
                    max_retries=self._cfg.backoff_max_retries,
                    base=self._cfg.backoff_base,
                    cap=self._cfg.backoff_cap,
                    logger=self._logger,
                    span_name="s3.upload_part",
                )
                parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})

            async def _complete():
                return await self._client.complete_multipart_upload(
                    Bucket=self._cfg.bucket,
                    Key=key,
                    UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                )

            comp = await _with_backoff(
                _complete,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.complete_multipart_upload",
            )
            return {"ETag": comp.get("ETag"), "VersionId": comp.get("VersionId")}
        except Exception:
            await abort()
            raise

    async def get_bytes(self, key: str, *, byte_range: Optional[Tuple[int, int]] = None) -> bytes:
        """
        Скачивание объекта целиком или диапазона.
        byte_range=(start, end) включая end. Пример: (0, 1023) — первые 1024 байта.
        """
        await self._ensure_client()

        def _headers():
            h = {"Bucket": self._cfg.bucket, "Key": key}
            if byte_range:
                h["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
            return h

        async def _get():
            return await self._client.get_object(**_headers())

        try:
            resp = await _with_backoff(
                _get,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.get_object",
            )
            body = await resp["Body"].read()
            return body
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in {"NoSuchKey", "404"}:
                raise NotFoundError(f"Object '{key}' not found")
            raise

    async def stream_to(self, key: str, writer: Any, *, chunk_size: int = 1024 * 1024) -> int:
        """
        Стриминг объекта в пользовательский writer, имеющий async def write(bytes) -> Any.
        Возвращает количество записанных байт.
        """
        await self._ensure_client()

        async def _get():
            return await self._client.get_object(Bucket=self._cfg.bucket, Key=key)

        try:
            resp = await _with_backoff(
                _get,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.get_object",
            )
            body = resp["Body"]
            written = 0
            while True:
                chunk = await body.read(chunk_size)
                if not chunk:
                    break
                await writer.write(chunk)
                written += len(chunk)
            return written
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in {"NoSuchKey", "404"}:
                raise NotFoundError(f"Object '{key}' not found")
            raise

    async def head(self, key: str) -> Dict[str, Any]:
        """Метаданные объекта."""
        await self._ensure_client()

        async def _head():
            return await self._client.head_object(Bucket=self._cfg.bucket, Key=key)

        try:
            resp = await _with_backoff(
                _head,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.head_object",
            )
            # нормализуем
            return {
                "ContentLength": resp.get("ContentLength"),
                "ContentType": resp.get("ContentType"),
                "ETag": resp.get("ETag"),
                "LastModified": resp.get("LastModified"),
                "Metadata": resp.get("Metadata", {}),
                "StorageClass": resp.get("StorageClass"),
                "ChecksumCRC32C": resp.get("ChecksumCRC32C"),
                "ChecksumSHA256": resp.get("ChecksumSHA256"),
                "VersionId": resp.get("VersionId"),
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in {"404", "NoSuchKey"}:
                raise NotFoundError(f"Object '{key}' not found")
            raise

    async def exists(self, key: str) -> bool:
        """Быстрая проверка наличия объекта."""
        try:
            await self.head(key)
            return True
        except NotFoundError:
            return False

    async def delete(self, key: str) -> None:
        """Удаление объекта (idempotent)."""
        await self._ensure_client()

        async def _del():
            return await self._client.delete_object(Bucket=self._cfg.bucket, Key=key)

        await _with_backoff(
            _del,
            max_retries=self._cfg.backoff_max_retries,
            base=self._cfg.backoff_base,
            cap=self._cfg.backoff_cap,
            logger=self._logger,
            span_name="s3.delete_object",
        )

    async def delete_prefix(self, prefix: str, *, batch_size: int = 1000) -> int:
        """
        Массовое удаление по префиксу.
        Возвращает число запрошенных к удалению объектов (может отличаться от фактического у провайдера).
        """
        await self._ensure_client()
        total = 0
        batch: List[Dict[str, str]] = []

        async for obj in self.iter_list(prefix=prefix):
            batch.append({"Key": obj["Key"]})
            if len(batch) >= batch_size:
                total += await self._delete_batch(batch)
                batch.clear()
        if batch:
            total += await self._delete_batch(batch)
        return total

    async def _delete_batch(self, objs: List[Dict[str, str]]) -> int:
        async def _del_many():
            return await self._client.delete_objects(Bucket=self._cfg.bucket, Delete={"Objects": objs})

        await _with_backoff(
            _del_many,
            max_retries=self._cfg.backoff_max_retries,
            base=self._cfg.backoff_base,
            cap=self._cfg.backoff_cap,
            logger=self._logger,
            span_name="s3.delete_objects",
        )
        return len(objs)

    async def iter_list(
        self,
        *,
        prefix: Optional[str] = None,
        continuation_token: Optional[str] = None,
        page_size: int = 1000,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Асинхронный генератор объектов (Key, Size, ETag, LastModified, StorageClass).
        """
        await self._ensure_client()
        token = continuation_token
        while True:
            kwargs = {
                "Bucket": self._cfg.bucket,
                "MaxKeys": page_size,
            }
            if prefix:
                kwargs["Prefix"] = prefix
            if token:
                kwargs["ContinuationToken"] = token

            async def _list():
                return await self._client.list_objects_v2(**kwargs)

            resp = await _with_backoff(
                _list,
                max_retries=self._cfg.backoff_max_retries,
                base=self._cfg.backoff_base,
                cap=self._cfg.backoff_cap,
                logger=self._logger,
                span_name="s3.list_objects_v2",
            )
            for it in resp.get("Contents", []) or []:
                yield {
                    "Key": it.get("Key"),
                    "Size": it.get("Size"),
                    "ETag": it.get("ETag"),
                    "LastModified": it.get("LastModified"),
                    "StorageClass": it.get("StorageClass"),
                }

            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")

    # -------- Presigned URLs --------
    async def generate_presigned_url(
        self,
        key: str,
        *,
        method: str = "get_object",
        expires_in: Optional[int] = None,
        content_type: Optional[str] = None,
        acl: Optional[str] = None,
        sse: Optional[str] = None,
        sse_kms_key_id: Optional[str] = None,
    ) -> str:
        """
        Генерация временной подписанной URL (GET/PUT).
        Для PUT можно указать content_type/acl/sse.
        """
        await self._ensure_client()
        params: Dict[str, Any] = {"Bucket": self._cfg.bucket, "Key": key}
        if method == "put_object":
            if content_type:
                params["ContentType"] = content_type
            if acl or self._cfg.acl:
                params["ACL"] = acl or self._cfg.acl
            if sse or self._cfg.sse:
                params["ServerSideEncryption"] = sse or self._cfg.sse
            if sse_kms_key_id or self._cfg.sse_kms_key_id:
                params["SSEKMSKeyId"] = sse_kms_key_id or self._cfg.sse_kms_key_id

        exp = int(expires_in or self._cfg.presign_default_exp)

        async def _presign():
            return await self._client.generate_presigned_url(
                ClientMethod=method,
                Params=params,
                ExpiresIn=exp,
            )

        url = await _with_backoff(
            _presign,
            max_retries=self._cfg.backoff_max_retries,
            base=self._cfg.backoff_base,
            cap=self._cfg.backoff_cap,
            logger=self._logger,
            span_name="s3.generate_presigned_url",
        )
        return str(url)
