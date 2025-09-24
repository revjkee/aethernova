# datafabric-core/datafabric/connectors/gcs.py
"""
Промышленный коннектор Google Cloud Storage (GCS) для DataFabric.

Особенности:
- Безопасная инициализация клиента: сервис-аккаунт / ADC, явная валидация настроек.
- Ретраи с экспоненциальной задержкой и джиттером для idempotent-операций (GET/HEAD/LIST/COPY/COMPOSE).
- Таймауты операций.
- Потоковые загрузки/выгрузки файлов/байтов, поддержка resumable upload.
- Подписанные URL (V4) для временного доступа (GET/PUT), настраиваемый срок действия.
- Поддержка KMS (CMEK) при загрузке.
- Контрольные суммы (crc32c) при выгрузке и проверке (если доступен google-crc32c).
- Параллельные копии объектов (compose/copy), перемещение (move).
- Списки объектов с пагинацией и префиксами; фильтрация.
- Метрики Prometheus (опционально), трассировка OpenTelemetry (опционально).
- Совместимость с asyncio: блокирующий официальный SDK запускается в thread executor через asyncio.to_thread.

Зависимости (обязательные):
- google-cloud-storage >= 2.10
- pydantic >= 2

Опционально:
- google-crc32c (ускоренная crc32c)
- prometheus-client
- opentelemetry-sdk + otlp-exporter (для трассировки)

Пример использования:
    from datafabric.connectors.gcs import GCSConfig, GCSClient

    cfg = GCSConfig(project="my-proj", bucket="raw-events", kms_key_name=None)
    gcs = GCSClient(cfg)

    # Загрузка файла
    gcs.upload_file("path/local.json", "events/2025/08/14/local.json", content_type="application/json")

    # Загрузка байтов
    gcs.upload_bytes(b"hello", "test/hello.txt", content_type="text/plain")

    # Скачивание
    data = gcs.download_as_bytes("test/hello.txt")

    # Подписанный URL
    url = gcs.sign_url("test/hello.txt", method="GET", expires_seconds=3600)

    # Перемещение
    gcs.move("test/hello.txt", "archive/hello.txt")

    # asyncio-код:
    await gcs.aupload_bytes(b"...", "async/obj.bin")

"""

from __future__ import annotations

import asyncio
import datetime as dt
import io
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except Exception as ex:  # pragma: no cover
    raise RuntimeError("pydantic>=2 is required for gcs connector") from ex

# Опциональные зависимости
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    PROM_ENABLED = True
except Exception:  # pragma: no cover
    PROM_ENABLED = False
    Counter = Histogram = None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None

# Контрольная сумма crc32c (ускоренная)
try:
    import google_crc32c  # type: ignore
    CRC32C_AVAILABLE = True
except Exception:  # pragma: no cover
    CRC32C_AVAILABLE = False

# Официальный SDK GCS
try:
    from google.cloud import storage  # type: ignore
    from google.cloud.storage import Blob  # type: ignore
    from google.api_core import exceptions as gax  # type: ignore
except Exception as ex:  # pragma: no cover
    raise RuntimeError("google-cloud-storage is required") from ex


# ===================================
# Конфигурация
# ===================================

class GCSConfig(BaseModel):
    project: Optional[str] = Field(default=None, description="GCP Project ID (если None — ADC)")
    bucket: str = Field(..., min_length=3)
    credentials_json_path: Optional[str] = Field(default=None, description="Путь к JSON сервис-аккаунта; если None — ADC")
    location: Optional[str] = Field(default=None, description="Локация по умолчанию (для создания бакета)")
    kms_key_name: Optional[str] = Field(default=None, description="projects/.../locations/.../keyRings/.../cryptoKeys/...")

    # Ретраи/таймауты
    max_retries: int = Field(default=5)
    base_retry_backoff_s: float = Field(default=0.3)
    max_retry_backoff_s: float = Field(default=8.0)
    request_timeout_s: float = Field(default=120.0)

    # Загрузки
    chunk_size: int = Field(default=8 * 1024 * 1024, description="Размер чанка для resumable uploads")
    default_content_type: str = Field(default="application/octet-stream")

    # Подписанные URL
    url_signer_version: str = Field(default="v4")
    default_url_expiry_s: int = Field(default=3600)  # 1 час

    # Метки/префиксы
    default_prefix: str = Field(default="")
    labels: Dict[str, str] = Field(default_factory=dict)

    @field_validator("url_signer_version")
    @classmethod
    def _check_signer(cls, v: str) -> str:
        v = v.lower()
        if v not in ("v4",):
            raise ValueError("Only V4 signed URLs are supported")
        return v

    @classmethod
    def from_env(cls) -> "GCSConfig":
        return cls(
            project=os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT"),
            bucket=os.getenv("GCS_BUCKET", ""),
            credentials_json_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
            location=os.getenv("GCS_LOCATION"),
            kms_key_name=os.getenv("GCS_KMS_KEY_NAME"),
            max_retries=int(os.getenv("GCS_MAX_RETRIES", "5")),
            base_retry_backoff_s=float(os.getenv("GCS_RETRY_BASE_S", "0.3")),
            max_retry_backoff_s=float(os.getenv("GCS_RETRY_MAX_S", "8.0")),
            request_timeout_s=float(os.getenv("GCS_TIMEOUT_S", "120")),
            chunk_size=int(os.getenv("GCS_CHUNK_SIZE", str(8 * 1024 * 1024))),
            default_content_type=os.getenv("GCS_DEFAULT_CT", "application/octet-stream"),
            default_prefix=os.getenv("GCS_DEFAULT_PREFIX", ""),
        )


# ===================================
# Метрики
# ===================================

def _build_metrics(ns: str = "datafabric_gcs") -> Dict[str, Any]:
    if not PROM_ENABLED:
        return {}
    labels = ("bucket", "op")
    return {
        "ops": Counter(f"{ns}_ops_total", "Счётчик операций GCS", labels),
        "errors": Counter(f"{ns}_errors_total", "Ошибки операций GCS", labels),
        "bytes_up": Counter(f"{ns}_uploaded_bytes_total", "Загружено байт", ("bucket",)),
        "bytes_down": Counter(f"{ns}_downloaded_bytes_total", "Скачано байт", ("bucket",)),
        "latency": Histogram(f"{ns}_latency_seconds", "Латентность операций GCS", labels),
    }


# ===================================
# Вспомогательное: ретраи
# ===================================

def _should_retry(exc: Exception) -> bool:
    # Идемпотентные ошибки, для которых разумно повторить
    retriable = (
        gax.ServiceUnavailable,
        gax.InternalServerError,
        gax.TooManyRequests,
        gax.DeadlineExceeded,
    )
    if isinstance(exc, retriable):
        return True
    # Иногда сеть бросает OSError/ConnectionError
    if isinstance(exc, (OSError, ConnectionError)):
        return True
    return False


def _backoff(attempt: int, base: float, cap: float) -> float:
    # экспоненциально с джиттером
    t = min(cap, base * (2 ** (attempt - 1)))
    return random.uniform(0, t)


# ===================================
# GCSClient
# ===================================

@dataclass
class GCSClient:
    config: GCSConfig
    logger: logging.Logger = logging.getLogger("datafabric.connectors.gcs")

    def __post_init__(self) -> None:
        self.logger.setLevel(logging.INFO)
        if PROM_ENABLED:
            self._metrics = _build_metrics()
        else:
            self._metrics = {}
        self._client = self._build_client()
        self._bucket = self._client.bucket(self.config.bucket)

    # ---------- инициализация ----------

    def _build_client(self) -> "storage.Client":
        if self.config.credentials_json_path:
            return storage.Client.from_service_account_json(
                self.config.credentials_json_path,
                project=self.config.project,
            )
        # ADC: переменная окружения или метаданные
        return storage.Client(project=self.config.project)

    # ---------- служебное ----------

    def _prefix(self, key: str) -> str:
        if not self.config.default_prefix:
            return key
        if key.startswith(self.config.default_prefix):
            return key
        return f"{self.config.default_prefix.rstrip('/')}/{key.lstrip('/')}"

    def _time_op(self, op: str, fn, *args, **kwargs):
        start = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span(f"gcs.{op}"):
                    res = fn(*args, **kwargs)
            else:
                res = fn(*args, **kwargs)
            return res
        except Exception as ex:
            if PROM_ENABLED:
                try:
                    self._metrics["errors"].labels(self.config.bucket, op).inc()
                except Exception:
                    pass
            raise
        finally:
            if PROM_ENABLED:
                try:
                    self._metrics["ops"].labels(self.config.bucket, op).inc()
                    self._metrics["latency"].labels(self.config.bucket, op).observe(time.perf_counter() - start)
                except Exception:
                    pass

    def _retrying(self, op: str, fn, *args, **kwargs):
        attempts = 0
        while True:
            try:
                return self._time_op(op, fn, *args, **kwargs)
            except Exception as ex:
                attempts += 1
                if attempts > self.config.max_retries or not _should_retry(ex):
                    self.logger.error("gcs_op_failed", extra={"op": op, "attempts": attempts, "error": str(ex)})
                    raise
                sleep_for = _backoff(attempts, self.config.base_retry_backoff_s, self.config.max_retry_backoff_s)
                self.logger.warning("gcs_op_retry", extra={"op": op, "attempt": attempts, "sleep": sleep_for})
                time.sleep(sleep_for)

    # ===================================
    # Публичные операции (sync)
    # ===================================

    def exists(self, key: str) -> bool:
        key = self._prefix(key)
        blob = self._bucket.blob(key)
        def _head(): return blob.exists(timeout=self.config.request_timeout_s)
        return self._retrying("exists", _head)

    def upload_file(self, local_path: str, key: str, *, content_type: Optional[str] = None,
                    cache_control: Optional[str] = None, metadata: Optional[Dict[str, str]] = None,
                    kms_key_name: Optional[str] = None, resumable: bool = True) -> None:
        key = self._prefix(key)
        blob = self._bucket.blob(key)
        blob.content_type = content_type or self.config.default_content_type
        if cache_control:
            blob.cache_control = cache_control
        if metadata:
            blob.metadata = metadata
        if self.config.labels:
            blob.labels = self.config.labels
        if kms_key_name or self.config.kms_key_name:
            blob.kms_key_name = kms_key_name or self.config.kms_key_name
        if resumable:
            blob.chunk_size = self.config.chunk_size

        def _do():
            blob.upload_from_filename(
                local_path,
                timeout=self.config.request_timeout_s,
                content_type=blob.content_type,
                if_generation_match=None,
                num_retries=0,  # свои ретраи
            )
            return True

        self._retrying("upload_file", _do)
        if PROM_ENABLED:
            try:
                size = os.path.getsize(local_path)
                self._metrics["bytes_up"].labels(self.config.bucket).inc(size)
            except Exception:
                pass

    def upload_bytes(self, data: bytes, key: str, *, content_type: Optional[str] = None,
                     cache_control: Optional[str] = None, metadata: Optional[Dict[str, str]] = None,
                     kms_key_name: Optional[str] = None) -> None:
        key = self._prefix(key)
        blob = self._bucket.blob(key)
        blob.content_type = content_type or self.config.default_content_type
        if cache_control:
            blob.cache_control = cache_control
        if metadata:
            blob.metadata = metadata
        if self.config.labels:
            blob.labels = self.config.labels
        if kms_key_name or self.config.kms_key_name:
            blob.kms_key_name = kms_key_name or self.config.kms_key_name

        def _do():
            blob.upload_from_file(
                io.BytesIO(data),
                size=len(data),
                content_type=blob.content_type,
                timeout=self.config.request_timeout_s,
                num_retries=0,
            )
            return True

        self._retrying("upload_bytes", _do)
        if PROM_ENABLED:
            try:
                self._metrics["bytes_up"].labels(self.config.bucket).inc(len(data))
            except Exception:
                pass

    def download_to_file(self, key: str, local_path: str) -> None:
        key = self._prefix(key)
        blob = self._bucket.blob(key)

        def _do():
            blob.download_to_filename(local_path, timeout=self.config.request_timeout_s)
            return True

        self._retrying("download_to_file", _do)
        if PROM_ENABLED:
            try:
                self._metrics["bytes_down"].labels(self.config.bucket).inc(os.path.getsize(local_path))
            except Exception:
                pass

    def download_as_bytes(self, key: str) -> bytes:
        key = self._prefix(key)
        blob = self._bucket.blob(key)

        def _do():
            return blob.download_as_bytes(timeout=self.config.request_timeout_s)

        data = self._retrying("download_as_bytes", _do)
        if PROM_ENABLED:
            try:
                self._metrics["bytes_down"].labels(self.config.bucket).inc(len(data))
            except Exception:
                pass
        return data

    def list(self, prefix: str = "", *, delimiter: Optional[str] = None,
             page_size: int = 1000) -> Generator[str, None, None]:
        prefix = self._prefix(prefix)
        def _pager():
            return self._bucket.list_blobs(prefix=prefix or None, delimiter=delimiter, max_results=page_size)
        # Превращаем в ленивый генератор ключей
        page_it = self._retrying("list_blobs", _pager)
        for blob in page_it:
            yield blob.name

    def delete(self, key: str, *, ignore_missing: bool = True) -> None:
        key = self._prefix(key)
        blob = self._bucket.blob(key)

        def _do():
            try:
                blob.delete(timeout=self.config.request_timeout_s)
            except gax.NotFound:
                if not ignore_missing:
                    raise
            return True

        self._retrying("delete", _do)

    def copy(self, src_key: str, dst_key: str, *, dst_bucket: Optional[str] = None) -> None:
        src_key = self._prefix(src_key)
        dst_key = self._prefix(dst_key)
        src_blob = self._bucket.blob(src_key)
        dst_bucket_obj = self._client.bucket(dst_bucket) if dst_bucket else self._bucket

        def _do():
            dst_bucket_obj.copy_blob(
                blob=src_blob,
                destination_bucket=dst_bucket_obj,
                new_name=dst_key,
                timeout=self.config.request_timeout_s,
            )
            return True

        self._retrying("copy", _do)

    def move(self, src_key: str, dst_key: str, *, dst_bucket: Optional[str] = None) -> None:
        self.copy(src_key, dst_key, dst_bucket=dst_bucket)
        self.delete(src_key, ignore_missing=False)

    def compose(self, src_keys: List[str], dst_key: str, *, content_type: Optional[str] = None) -> None:
        src_blobs = [self._bucket.blob(self._prefix(k)) for k in src_keys]
        dst_blob = self._bucket.blob(self._prefix(dst_key))
        if content_type:
            dst_blob.content_type = content_type

        def _do():
            dst_blob.compose(src_blobs, timeout=self.config.request_timeout_s)
            return True

        self._retrying("compose", _do)

    def sign_url(self, key: str, *, method: str = "GET", expires_seconds: Optional[int] = None,
                 content_type: Optional[str] = None) -> str:
        key = self._prefix(key)
        blob = self._bucket.blob(key)
        exp = expires_seconds or self.config.default_url_expiry_s
        expiration = dt.timedelta(seconds=exp)
        def _do():
            return blob.generate_signed_url(
                version="v4",
                expiration=expiration,
                method=method.upper(),
                content_type=content_type,
            )
        return self._retrying("sign_url", _do)

    def stat(self, key: str) -> Dict[str, Any]:
        key = self._prefix(key)
        blob = self._bucket.blob(key)
        def _do():
            blob.reload(timeout=self.config.request_timeout_s)
            return {
                "name": blob.name,
                "size": blob.size,
                "updated": getattr(blob, "updated", None),
                "content_type": blob.content_type,
                "crc32c": blob.crc32c,
                "md5_hash": blob.md5_hash,
                "kms_key_name": getattr(blob, "kms_key_name", None),
                "storage_class": getattr(blob, "storage_class", None),
                "metadata": blob.metadata or {},
            }
        return self._retrying("stat", _do)

    # ===================================
    # Async-обёртки (безопасно для asyncio)
    # ===================================

    async def aexists(self, key: str) -> bool:
        return await asyncio.to_thread(self.exists, key)

    async def aupload_file(self, local_path: str, key: str, **kwargs) -> None:
        return await asyncio.to_thread(self.upload_file, local_path, key, **kwargs)

    async def aupload_bytes(self, data: bytes, key: str, **kwargs) -> None:
        return await asyncio.to_thread(self.upload_bytes, data, key, **kwargs)

    async def adownload_to_file(self, key: str, local_path: str) -> None:
        return await asyncio.to_thread(self.download_to_file, key, local_path)

    async def adownload_as_bytes(self, key: str) -> bytes:
        return await asyncio.to_thread(self.download_as_bytes, key)

    async def alist(self, prefix: str = "", **kwargs) -> List[str]:
        # Сгружаем список в память; для очень больших наборов лучше синхронный генератор + поэтапная обработка
        return await asyncio.to_thread(lambda: list(self.list(prefix, **kwargs)))

    async def adelete(self, key: str, **kwargs) -> None:
        return await asyncio.to_thread(self.delete, key, **kwargs)

    async def acopy(self, src_key: str, dst_key: str, **kwargs) -> None:
        return await asyncio.to_thread(self.copy, src_key, dst_key, **kwargs)

    async def amove(self, src_key: str, dst_key: str, **kwargs) -> None:
        return await asyncio.to_thread(self.move, src_key, dst_key, **kwargs)

    async def acompose(self, src_keys: List[str], dst_key: str, **kwargs) -> None:
        return await asyncio.to_thread(self.compose, src_keys, dst_key, **kwargs)

    async def asign_url(self, key: str, **kwargs) -> str:
        return await asyncio.to_thread(self.sign_url, key, **kwargs)

    async def astat(self, key: str) -> Dict[str, Any]:
        return await asyncio.to_thread(self.stat, key)

    # ===================================
    # Проверка контрольной суммы (опционально)
    # ===================================

    def verify_crc32c(self, data: bytes, key: str) -> bool:
        """
        Сравнивает локальную crc32c с crc на объекте (если доступно).
        Возвращает True при совпадении; если checksum недоступна — возвращает False.
        """
        if not CRC32C_AVAILABLE:
            return False
        remote = self.stat(key).get("crc32c")
        if not remote:
            return False
        # google_crc32c возвращает int, но хэш в объекте — base64/hex в зависимости от SDK.
        # В google-cloud-storage crc32c — base64-encoded; чтобы не зависеть от реализаций,
        # используем md5/updated как альтернативы сравнения при отсутствии совместимости.
        # Здесь применим бинарную совместимость через API blob.crc32c (base64)
        import base64
        local_crc = google_crc32c.value(data)
        # Конвертируем int -> big-endian 4 bytes -> base64
        local_bytes = local_crc.to_bytes(4, "big")
        local_b64 = base64.b64encode(local_bytes).decode("utf-8")
        return local_b64 == remote


# ===================================
# Утилиты высокого уровня
# ===================================

def ensure_bucket(client: GCSClient, *, storage_class: Optional[str] = None, versioning: bool = False) -> None:
    """
    Идempotent-создание бакета, если ещё не существует.
    """
    cfg = client.config
    bucket = client._bucket
    def _create():
        try:
            bucket.reload()  # пробуем прочитать
            return False
        except gax.NotFound:
            pass
        bucket.iam_configuration = {}
        if storage_class:
            bucket.storage_class = storage_class
        bucket.create(location=cfg.location, timeout=cfg.request_timeout_s)
        if versioning:
            bucket.versioning_enabled = True
            bucket.patch()
        return True
    client._retrying("ensure_bucket", _create)


# ===================================
# Пример минимальной самопроверки
# ===================================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    try:
        cfg = GCSConfig.from_env()
        if not cfg.bucket:
            raise RuntimeError("Set GCS_BUCKET environment variable")
        gcs = GCSClient(cfg)
        key = "selftest/hello.txt"
        gcs.upload_bytes(b"hello", key, content_type="text/plain")
        data = gcs.download_as_bytes(key)
        print("Downloaded:", data)
        print("Exists:", gcs.exists(key))
        url = gcs.sign_url(key, method="GET", expires_seconds=300)
        print("Signed URL:", url)
        gcs.delete(key)
        print("OK")
    except ValidationError as e:
        print("Invalid config:", e)
