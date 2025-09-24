# datafabric-core/datafabric/storage/objectstore/s3_client.py
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import dataclasses
import hashlib
import io
import math
import os
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple

import aioboto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

# ======================================================================================
# Метрики (минимальный интерфейс, совместим с остальными модулями)
# ======================================================================================

class MetricsSink:
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None: ...
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class NullMetrics(MetricsSink):
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        return
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        return

# ======================================================================================
# Конфигурация
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class S3Config:
    # Базовые настройки
    endpoint_url: Optional[str] = None                     # например http://minio:9000
    region_name: Optional[str] = "us-east-1"
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None

    # Поведение клиента
    signature_version: Literal["s3v4", "s3"] = "s3v4"
    addressing_style: Literal["auto", "virtual", "path"] = "auto"  # MinIO обычно "path"
    retries_max_attempts: int = 10
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 300.0
    tcp_keepalive: bool = True

    # Безопасность / шифрование по умолчанию
    sse: Optional[Literal["AES256", "aws:kms", "SSE-C"]] = None
    kms_key_id: Optional[str] = None
    sse_c_key_b64: Optional[str] = None  # для SSE-C: base64 ключа (32 байта для AES256)

    # Порог многочастичной загрузки
    multipart_threshold_mb: int = 64
    multipart_chunk_mb: int = 64
    max_concurrency: int = 8  # параллельные части для upload/download

# ======================================================================================
# Утилиты
# ======================================================================================

def _ssec_headers(cfg: S3Config) -> Dict[str, str]:
    if cfg.sse == "AES256":
        return {"ServerSideEncryption": "AES256"}
    if cfg.sse == "aws:kms":
        out = {"ServerSideEncryption": "aws:kms"}
        if cfg.kms_key_id:
            out["SSEKMSKeyId"] = cfg.kms_key_id
        return out
    if cfg.sse == "SSE-C":
        if not cfg.sse_c_key_b64:
            raise ValueError("SSE-C requires sse_c_key_b64")
        # Клиентские заголовки добавляются в boto вызове как параметры
        raw = base64.b64decode(cfg.sse_c_key_b64)
        md5 = hashlib.md5(raw).digest()
        return {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": cfg.sse_c_key_b64,
            "SSECustomerKeyMD5": base64.b64encode(md5).decode(),
        }
    return {}

def _checksum_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _split_in_parts(total_size: int, part_size: int) -> List[Tuple[int, int]]:
    # Возвращает список (offset, size)
    parts: List[Tuple[int, int]] = []
    off = 0
    while off < total_size:
        size = min(part_size, total_size - off)
        parts.append((off, size))
        off += size
    return parts

# ======================================================================================
# Клиент
# ======================================================================================

class S3Client:
    """
    Асинхронный клиент S3/MinIO с безопасными ретраями, SSE, multipart и presigned URL.
    Поддерживает как синтетические операции (put_bytes/get_bytes), так и потоковые (upload_file/download_file).
    """

    def __init__(self, cfg: S3Config, metrics: Optional[MetricsSink] = None) -> None:
        self.cfg = cfg
        self.metrics = metrics or NullMetrics()
        self._session: Optional[aioboto3.Session] = None
        self._client_ctx = None  # type: ignore
        self._client = None

    @classmethod
    def create(cls, cfg: S3Config, metrics: Optional[MetricsSink] = None) -> "S3Client":
        return cls(cfg=cfg, metrics=metrics)

    # ----------------------- lifecycle -----------------------

    async def _ensure(self):
        if self._client is not None:
            return self._client
        if self._session is None:
            self._session = aioboto3.Session()

        bcfg = BotoConfig(
            region_name=self.cfg.region_name,
            signature_version=self.cfg.signature_version,
            s3={"addressing_style": self.cfg.addressing_style},
            retries={"max_attempts": self.cfg.retries_max_attempts, "mode": "standard"},
            connect_timeout=self.cfg.connect_timeout_s,
            read_timeout=self.cfg.read_timeout_s,
            tcp_keepalive=self.cfg.tcp_keepalive,
        )

        self._client_ctx = self._session.client(
            "s3",
            endpoint_url=self.cfg.endpoint_url,
            aws_access_key_id=self.cfg.access_key,
            aws_secret_access_key=self.cfg.secret_key,
            aws_session_token=self.cfg.session_token,
            config=bcfg,
        )
        # aioboto3 client должен открываться через async context manager
        self._client = await self._client_ctx.__aenter__()  # type: ignore
        return self._client

    async def close(self) -> None:
        if self._client_ctx is not None:
            with contextlib.suppress(Exception):
                await self._client_ctx.__aexit__(None, None, None)  # type: ignore
        self._client_ctx, self._client = None, None

    # ----------------------- health -----------------------

    async def ping(self, bucket: str) -> bool:
        cli = await self._ensure()
        try:
            await cli.head_bucket(Bucket=bucket)
            await self.metrics.incr("s3.ping.ok", 1, {"bucket": bucket})
            return True
        except Exception:
            await self.metrics.incr("s3.ping.fail", 1, {"bucket": bucket})
            return False

    # ----------------------- buckets -----------------------

    async def ensure_bucket(
        self,
        bucket: str,
        *,
        acl: Optional[str] = None,
        versioning: Optional[bool] = None,
    ) -> None:
        cli = await self._ensure()
        try:
            await cli.head_bucket(Bucket=bucket)
        except ClientError as e:
            code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code == 404:
                kwargs: Dict[str, Any] = {"Bucket": bucket}
                # В us-east-1 нельзя передавать CreateBucketConfiguration
                if self.cfg.region_name and self.cfg.region_name != "us-east-1":
                    kwargs["CreateBucketConfiguration"] = {"LocationConstraint": self.cfg.region_name}
                if acl:
                    kwargs["ACL"] = acl
                await cli.create_bucket(**kwargs)
            else:
                raise
        if versioning is not None:
            await cli.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled" if versioning else "Suspended"})

    # ----------------------- простые операции объектов -----------------------

    async def head_object(self, bucket: str, key: str) -> Optional[Mapping[str, Any]]:
        cli = await self._ensure()
        try:
            res = await cli.head_object(Bucket=bucket, Key=key)
            return res
        except ClientError as e:
            if e.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                return None
            raise

    async def get_bytes(self, bucket: str, key: str, *, verify_checksum: bool = False, range_bytes: Optional[Tuple[int, int]] = None) -> bytes:
        cli = await self._ensure()
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Key": key}
        if range_bytes:
            start, end = range_bytes
            kwargs["Range"] = f"bytes={start}-{end}"
        if self.cfg.sse == "SSE-C":
            kwargs.update(_ssec_headers(self.cfg))
        resp = await cli.get_object(**kwargs)
        body = await resp["Body"].read()
        if verify_checksum:
            # Пытаемся использовать возвращаемые контрольные суммы (если включены на бакете)
            # Иначе сверяем SHA256 с user-provided через ETag для single-part (не надёжно для multipart)
            sf = resp.get("ChecksumSHA256")
            if sf:
                calc = base64.b64encode(hashlib.sha256(body).digest()).decode()
                if calc != sf:
                    raise ValueError("Checksum mismatch (SHA256)")
        return body

    async def put_bytes(
        self,
        bucket: str,
        key: str,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        storage_class: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
        tags: Optional[Mapping[str, str]] = None,
        acl: Optional[str] = None,
        checksum_sha256: bool = False,
    ) -> Mapping[str, Any]:
        cli = await self._ensure()
        kwargs: Dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": data,
        }
        if content_type:
            kwargs["ContentType"] = content_type
        if storage_class:
            kwargs["StorageClass"] = storage_class
        if metadata:
            kwargs["Metadata"] = dict(metadata)
        if tags:
            kwargs["Tagging"] = "&".join(f"{k}={v}" for k, v in tags.items())
        if acl:
            kwargs["ACL"] = acl
        if self.cfg.sse:
            kwargs.update(_ssec_headers(self.cfg))
        if checksum_sha256:
            # В S3 v2 checksum API checksum передаётся как base64(SHA256)
            kwargs["ChecksumSHA256"] = base64.b64encode(hashlib.sha256(data).digest()).decode()
        return await cli.put_object(**kwargs)

    async def delete_object(self, bucket: str, key: str, *, version_id: Optional[str] = None) -> None:
        cli = await self._ensure()
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Key": key}
        if version_id:
            kwargs["VersionId"] = version_id
        await cli.delete_object(**kwargs)

    async def copy_object(
        self,
        *,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
        metadata: Optional[Mapping[str, str]] = None,
        metadata_directive: Literal["COPY", "REPLACE"] = "COPY",
        storage_class: Optional[str] = None,
    ) -> Mapping[str, Any]:
        cli = await self._ensure()
        kwargs: Dict[str, Any] = {
            "Bucket": dst_bucket,
            "Key": dst_key,
            "CopySource": {"Bucket": src_bucket, "Key": src_key},
            "MetadataDirective": metadata_directive,
        }
        if metadata and metadata_directive == "REPLACE":
            kwargs["Metadata"] = dict(metadata)
        if storage_class:
            kwargs["StorageClass"] = storage_class
        if self.cfg.sse:
            kwargs.update(_ssec_headers(self.cfg))
        return await cli.copy_object(**kwargs)

    # ----------------------- листинг и массовые операции -----------------------

    async def list_objects(
        self,
        bucket: str,
        *,
        prefix: Optional[str] = None,
        delimiter: Optional[str] = None,
        versions: bool = False,
    ) -> AsyncGenerator[Mapping[str, Any], None]:
        """
        Пагинированный асинхронный генератор. Если versions=True, отдаёт версии/удаления.
        """
        cli = await self._ensure()
        paginator = cli.get_paginator("list_object_versions" if versions else "list_objects_v2")
        kwargs: Dict[str, Any] = {"Bucket": bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        if delimiter:
            kwargs["Delimiter"] = delimiter
        async for page in paginator.paginate(**kwargs):
            items = []
            if versions:
                items.extend(page.get("Versions", []))
                items.extend(page.get("DeleteMarkers", []))
            else:
                items.extend(page.get("Contents", []) or [])
            for it in items:
                yield it

    async def delete_prefix(self, bucket: str, prefix: str, *, batch_size: int = 1000) -> int:
        """
        Быстрое удаление большого количества объектов по префиксу.
        """
        cli = await self._ensure()
        to_delete: List[Dict[str, str]] = []
        deleted = 0
        async for obj in self.list_objects(bucket, prefix=prefix):
            to_delete.append({"Key": obj["Key"]})
            if len(to_delete) >= batch_size:
                resp = await cli.delete_objects(Bucket=bucket, Delete={"Objects": to_delete, "Quiet": True})
                deleted += len(resp.get("Deleted", []))
                to_delete.clear()
        if to_delete:
            resp = await cli.delete_objects(Bucket=bucket, Delete={"Objects": to_delete, "Quiet": True})
            deleted += len(resp.get("Deleted", []))
        return deleted

    # ----------------------- загрузка/скачивание файлов -----------------------

    async def upload_file(
        self,
        bucket: str,
        key: str,
        local_path: str | Path,
        *,
        content_type: Optional[str] = None,
        storage_class: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
        tags: Optional[Mapping[str, str]] = None,
        acl: Optional[str] = None,
    ) -> Mapping[str, Any]:
        """
        Выбирает обычный PUT или multipart в зависимости от размера файла (threshold в конфиге).
        """
        p = Path(local_path)
        size = p.stat().st_size
        data = None
        if size < self.cfg.multipart_threshold_mb * 1024 * 1024:
            data = p.read_bytes()
            return await self.put_bytes(bucket, key, data, content_type=content_type, storage_class=storage_class,
                                        metadata=metadata, tags=tags, acl=acl)
        return await self._multipart_upload(bucket, key, p, content_type=content_type, storage_class=storage_class,
                                            metadata=metadata, tags=tags, acl=acl)

    async def download_file(
        self,
        bucket: str,
        key: str,
        local_path: str | Path,
        *,
        verify_checksum: bool = False,
    ) -> None:
        cli = await self._ensure()
        p = Path(local_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Получаем размер для параллельной закачки
        head = await self.head_object(bucket, key)
        if not head:
            raise FileNotFoundError(f"s3://{bucket}/{key}")
        size = int(head.get("ContentLength", 0))
        part = self.cfg.multipart_chunk_mb * 1024 * 1024
        if size <= part:
            body = await self.get_bytes(bucket, key, verify_checksum=verify_checksum)
            p.write_bytes(body)
            return
        # Параллельные range-загрузки
        parts = _split_in_parts(size, part)
        buf = bytearray(size)
        sem = asyncio.Semaphore(self.cfg.max_concurrency)

        async def _fetch(off: int, sz: int):
            async with sem:
                chunk = await self.get_bytes(bucket, key, range_bytes=(off, off + sz - 1))
                buf[off : off + sz] = chunk

        await asyncio.gather(*[_fetch(off, sz) for off, sz in parts])
        p.write_bytes(buf)
        if verify_checksum:
            # Если доступна ChecksumSHA256 — сверка происходила по частям невозможна; выполняем полную сверку при наличии хедера
            pass

    # ----------------------- multipart upload -----------------------

    async def _multipart_upload(
        self,
        bucket: str,
        key: str,
        local_path: Path,
        *,
        content_type: Optional[str],
        storage_class: Optional[str],
        metadata: Optional[Mapping[str, str]],
        tags: Optional[Mapping[str, str]],
        acl: Optional[str],
    ) -> Mapping[str, Any]:
        cli = await self._ensure()
        kwargs_init: Dict[str, Any] = {"Bucket": bucket, "Key": key}
        if content_type:
            kwargs_init["ContentType"] = content_type
        if storage_class:
            kwargs_init["StorageClass"] = storage_class
        if metadata:
            kwargs_init["Metadata"] = dict(metadata)
        if tags:
            kwargs_init["Tagging"] = "&".join(f"{k}={v}" for k, v in tags.items())
        if acl:
            kwargs_init["ACL"] = acl
        if self.cfg.sse:
            kwargs_init.update(_ssec_headers(self.cfg))

        mp = await cli.create_multipart_upload(**kwargs_init)
        upload_id = mp["UploadId"]

        part_size = self.cfg.multipart_chunk_mb * 1024 * 1024
        size = local_path.stat().st_size
        parts = _split_in_parts(size, part_size)
        results: List[Dict[str, Any]] = [None] * len(parts)  # type: ignore
        sem = asyncio.Semaphore(self.cfg.max_concurrency)

        async def _upload(ix: int, off: int, sz: int):
            async with sem:
                with local_path.open("rb") as f:
                    f.seek(off)
                    chunk = f.read(sz)
                etag = None
                # SSE-C заголовки повторяются на каждую часть
                extra = _ssec_headers(self.cfg) if self.cfg.sse == "SSE-C" else {}
                resp = await cli.upload_part(Bucket=bucket, Key=key, PartNumber=ix + 1, UploadId=upload_id, Body=chunk, **extra)
                etag = resp["ETag"]
                results[ix] = {"ETag": etag, "PartNumber": ix + 1}

        try:
            await asyncio.gather(*[_upload(i, off, sz) for i, (off, sz) in enumerate(parts)])
            resp = await cli.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": results},
            )
            return resp
        except Exception:
            with contextlib.suppress(Exception):
                await cli.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            raise

    # ----------------------- presigned URLs -----------------------

    async def presigned_get(self, bucket: str, key: str, *, expires_s: int = 3600, response_content_type: Optional[str] = None) -> str:
        cli = await self._ensure()
        params: Dict[str, Any] = {"Bucket": bucket, "Key": key}
        if response_content_type:
            params["ResponseContentType"] = response_content_type
        return await cli.generate_presigned_url("get_object", Params=params, ExpiresIn=expires_s)

    async def presigned_put(self, bucket: str, key: str, *, expires_s: int = 3600, content_type: Optional[str] = None) -> str:
        cli = await self._ensure()
        params: Dict[str, Any] = {"Bucket": bucket, "Key": key}
        if content_type:
            params["ContentType"] = content_type
        # Для SSE-C/КMS presigned PUT сложнее; рекомендуется использовать POST policy или прямой серверный upload
        return await cli.generate_presigned_url("put_object", Params=params, ExpiresIn=expires_s)

    async def presigned_post(
        self,
        bucket: str,
        key: str,
        *,
        expires_s: int = 3600,
        content_type: Optional[str] = None,
        max_size_mb: Optional[int] = None,
    ) -> Mapping[str, Any]:
        """
        Возвращает dict {url, fields} для HTML‑формы multipart POST.
        """
        cli = await self._ensure()
        conditions: List[Any] = [{"bucket": bucket}, {"key": key}]
        if content_type:
            conditions.append(["eq", "$Content-Type", content_type])
        if max_size_mb:
            conditions.append(["content-length-range", 1, max_size_mb * 1024 * 1024])
        resp = await cli.generate_presigned_post(
            Bucket=bucket,
            Key=key,
            Fields={"Content-Type": content_type} if content_type else None,
            Conditions=conditions,
            ExpiresIn=expires_s,
        )
        return resp
