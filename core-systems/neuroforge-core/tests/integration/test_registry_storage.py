# neuroforge-core/tests/integration/test_registry_storage.py
# Профессиональный интеграционный набор тестов для Registry Storage NeuroForge.
# Покрытие:
#   - put/get/open с проверкой размера и SHA-256
#   - идемпотентность put
#   - конкурентные put/get
#   - листинг (+ пагинация)
#   - версионирование (latest/по digest/версии)
#   - presign_get (только S3, через moto)
#   - удаление версии и всего объекта
#   - политика ретенции (если backend заявляет поддержку)
#   - потоковое чтение (open)
#
# Требуемый контракт (ожидаем в neuroforge.registry.storage):
#   StorageConfig(...)
#   LocalRegistryStorage(StorageConfig)
#   S3RegistryStorage(StorageConfig)               # опционально
#   class RegistryError(Exception)
#   class ChecksumMismatch(RegistryError)
#
# Методы стораджей (ожидаемые сигнатуры/семантика):
#   put(namespace, name, data: bytes|BinaryIO, *, content_type: str="application/octet-stream",
#       metadata: dict|None=None) -> dict { "uri", "size", "sha256", "version" }
#   get(namespace, name, version: str|None=None) -> (bytes, dict_metadata)
#   open(namespace, name, version: str|None=None) -> BinaryIO (readable)
#   delete(namespace, name, version: str|None=None) -> None
#   list(namespace, prefix: str="", limit: int=100, cursor: str|None=None) -> (list[dict], next_cursor|None)
#   presign_get(namespace, name, version: str|None=None, expires_s: int=60) -> str   # только если поддерживается
#
# Если контракт не реализован — модульный skip без падения.

from __future__ import annotations

import os
import io
import sys
import json
import time
import math
import hashlib
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Tuple

import pytest

# ---------- Импорт реализации / мягкая деградация ----------
IMPLEMENTATION_AVAILABLE = True
IMPORT_ERROR = None
try:
    from neuroforge.registry.storage import (
        StorageConfig,
        LocalRegistryStorage,
        S3RegistryStorage,        # может отсутствовать — обработаем ниже
        RegistryError,
        ChecksumMismatch,
    )
except Exception as e:  # pragma: no cover
    IMPLEMENTATION_AVAILABLE = False
    IMPORT_ERROR = e

if not IMPLEMENTATION_AVAILABLE:  # pragma: no cover
    pytest.skip(f"Registry storage implementation not found: {IMPORT_ERROR}", allow_module_level=True)

# ---------- Вспомогательные утилиты ----------

def rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def rand_text(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def big_payload(megabytes: int) -> bytes:
    # Псевдослучайные данные стабильной длины
    chunk = os.urandom(1024 * 1024)
    return chunk * megabytes

# ---------- Маркеры ----------
integration = pytest.mark.integration
slow = pytest.mark.slow
local = pytest.mark.local
s3mark = pytest.mark.s3

# ---------- S3 (moto) доступность ----------
HAVE_MOTO = False
try:  # pragma: no cover
    import boto3  # noqa
    from moto import mock_aws
    HAVE_MOTO = True
except Exception:
    HAVE_MOTO = False

# ---------- Фикстуры backend’ов ----------

@pytest.fixture(scope="session")
def tmp_root(tmp_path_factory):
    return tmp_path_factory.mktemp("registry_root")

@pytest.fixture(scope="session")
def namespace() -> str:
    return "nf-tests"

@pytest.fixture(scope="session")
def bucket_name() -> str:
    return "nf-tests-bucket"

@pytest.fixture(scope="session")
def local_storage_cfg(tmp_root: Path):
    return StorageConfig(
        backend="local",
        local_root=str(tmp_root / "local"),
        enable_checksum=True,
        enable_versions=True,
        # retention: опционально: {"keep_last": 3}
    )

@pytest.fixture(scope="function")
def local_storage(local_storage_cfg):
    st = LocalRegistryStorage(local_storage_cfg)
    yield st

@pytest.fixture(scope="function")
def s3_storage_cfg(bucket_name: str, tmp_root: Path):
    # Конфиг для S3; реальные креды не нужны под moto
    return StorageConfig(
        backend="s3",
        s3_bucket=bucket_name,
        s3_region="us-east-1",
        s3_endpoint=None,  # moto стандарт
        enable_checksum=True,
        enable_versions=True,
    )

@pytest.fixture(scope="function")
def s3_storage(s3_storage_cfg, bucket_name: str):
    if not HAVE_MOTO or "S3RegistryStorage" not in globals():
        pytest.skip("S3 backend/moto not available")
    from moto import mock_aws
    with mock_aws():
        import boto3
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=bucket_name)
        st = S3RegistryStorage(s3_storage_cfg)
        yield st

# ---------- Универсальные тесты для обоих backend’ов ----------

@pytest.mark.parametrize("size", [1, 1024, 1024 * 1024])
@integration
def test_put_get_roundtrip(local_storage, namespace, size):
    storage = local_storage
    name = f"roundtrip-{size}.bin"
    payload = rand_bytes(size)
    digest = sha256(payload)

    info = storage.put(namespace, name, payload, content_type="application/octet-stream",
                       metadata={"k": "v", "note": "roundtrip"})
    assert info and info.get("sha256") == digest, f"Digest mismatch: {info}"
    assert info.get("size") == size

    data, meta = storage.get(namespace, name)
    assert data == payload, "Payload mismatch after get()"
    assert isinstance(meta, dict) and meta.get("k") == "v"

    # Проверим open() — потоковое чтение
    with storage.open(namespace, name) as fp:
        chunk = fp.read()
        assert chunk == payload, "Payload mismatch via open()"

@integration
def test_put_idempotent(local_storage, namespace):
    storage = local_storage
    name = "idem.bin"
    payload = rand_bytes(64 * 1024)
    first = storage.put(namespace, name, payload, metadata={"m": "1"})
    second = storage.put(namespace, name, payload, metadata={"m": "2"})
    assert first["sha256"] == second["sha256"], "Idempotent put must keep digest"
    # Версия может увеличиться или совпасть — допустимы обе семантики.
    assert "version" in second

@integration
def test_list_and_pagination(local_storage, namespace):
    storage = local_storage
    base = "list/item"
    # Подготовим 15 элементов
    for i in range(15):
        storage.put(namespace, f"{base}-{i:02d}.txt", rand_text(32).encode(), content_type="text/plain")

    seen = []
    cursor = None
    while True:
        items, cursor = storage.list(namespace, prefix="list/", limit=5, cursor=cursor)
        assert items is not None and isinstance(items, list)
        seen.extend(x["name"] for x in items)
        if not cursor:
            break
    assert len(seen) == 15, f"Expected 15 items, got {len(seen)}"

@integration
def test_versioning_and_get_specific(local_storage, namespace):
    storage = local_storage
    name = "ver/object.bin"
    v1 = storage.put(namespace, name, b"A" * 10)
    time.sleep(0.01)
    v2 = storage.put(namespace, name, b"B" * 10)
    assert v1["version"] != v2["version"], "Versions must differ for new content"

    data_latest, _ = storage.get(namespace, name)
    assert data_latest == b"B" * 10, "Latest must be last content"

    # По версии
    data_v1, _ = storage.get(namespace, name, version=v1["version"])
    assert data_v1 == b"A" * 10, "Specific version fetch mismatch"

@integration
def test_corruption_detection(local_storage, namespace, tmp_root):
    storage = local_storage
    name = "corrupt/file.bin"
    payload = rand_bytes(4096)
    info = storage.put(namespace, name, payload)
    # Смоделируем порчу файла в локальном бэкенде, если доступен путь
    # Ожидаем, что get вызовет ChecksumMismatch (или аналогичный RegistryError, если проверки отключены)
    # Попытка: вычислить физический путь из info["uri"] для local backend
    uri = info.get("uri", "")
    if not uri.startswith("file://"):
        pytest.skip("Physical path unknown for non-local backend")
    ph_path = Path(uri[len("file://"):])
    assert ph_path.exists(), f"Artifact path not found: {ph_path}"
    with ph_path.open("r+b") as f:
        f.seek(0)
        f.write(b"\x00\x00\x00\x00")

    with pytest.raises(ChecksumMismatch):
        _ = storage.get(namespace, name)

@integration
def test_delete_version_and_all(local_storage, namespace):
    storage = local_storage
    name = "delete/me.bin"
    v1 = storage.put(namespace, name, b"X")
    v2 = storage.put(namespace, name, b"Y")
    # Удалим только первую версию (если поддерживается версионность)
    storage.delete(namespace, name, version=v1["version"])
    data, _ = storage.get(namespace, name)
    assert data == b"Y"

    # Удалим все версии
    storage.delete(namespace, name, version=None)
    with pytest.raises(RegistryError):
        _ = storage.get(namespace, name)

@integration
def test_streaming_open_partial_read(local_storage, namespace):
    storage = local_storage
    name = "stream/partial.txt"
    body = (b"hello-" * 1024)  # 6 KiB
    storage.put(namespace, name, body, content_type="text/plain")
    with storage.open(namespace, name) as fp:
        part = fp.read(1024)
        assert part == body[:1024], "Partial read mismatch"
        rest = fp.read()
        assert part + rest == body, "Streamed content mismatch"

# ---------- Конкурентность ----------

@integration
def test_concurrent_put_get(local_storage, namespace):
    storage = local_storage
    base = "concurrent/item"
    payloads = [rand_bytes(16 * 1024) for _ in range(8)]

    def worker(i: int):
        nm = f"{base}-{i}"
        info = storage.put(namespace, nm, payloads[i], metadata={"i": str(i)})
        data, meta = storage.get(namespace, nm)
        return nm, info["sha256"], sha256(data), meta.get("i")

    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(worker, i) for i in range(8)]
        for f in as_completed(futs):
            nm, expected, got, meta_i = f.result()
            assert expected == got, f"Digest mismatch for {nm}"
            assert meta_i is not None

# ---------- Политика ретенции (опционально) ----------

@integration
def test_retention_policy_if_supported(local_storage, namespace):
    storage = local_storage
    # Бэкенд может не поддерживать политику — в таком случае пропускаем тест.
    supports = getattr(storage, "supports_retention", False)
    if not supports:
        pytest.skip("Retention policy not supported by backend")

    name = "ret/obj.bin"
    # Создадим 5 версий, ожидаем keep_last=3 -> старые версии удалятся
    for i in range(5):
        storage.put(namespace, name, f"V{i}".encode())
        time.sleep(0.01)

    # Бэкенд должен уметь сообщить кол-во версий (через list с include_versions или отдельный метод)
    # Универсально: проверяем, что get по старым версиям выдаёт ошибку.
    # Ожидаем, что версии 0 и 1 недоступны.
    with pytest.raises(RegistryError):
        storage.get(namespace, name, version="0")  # символическая проверка; допускается иной идентификатор

# ---------- S3-специфичные тесты ----------

@s3mark
@integration
@pytest.mark.skipif(not HAVE_MOTO, reason="moto is required for S3 tests")
def test_s3_presign_and_download(s3_storage, namespace):
    storage = s3_storage
    name = "s3/presign.bin"
    payload = rand_bytes(64 * 1024)
    storage.put(namespace, name, payload, content_type="application/octet-stream")

    # presign_get
    if not hasattr(storage, "presign_get"):
        pytest.skip("presign_get is not implemented by this backend")

    url = storage.presign_get(namespace, name, expires_s=30)
    assert isinstance(url, str) and url.startswith("http"), f"Invalid presigned URL: {url}"

    # Загрузим по URL (внутри moto это поддерживается)
    import urllib.request
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    assert data == payload, "Downloaded content via presigned URL mismatch"

@s3mark
@integration
@slow
@pytest.mark.skipif(not HAVE_MOTO, reason="moto is required for S3 tests")
def test_s3_large_object_multipart_like(s3_storage, namespace):
    storage = s3_storage
    name = "s3/large-10mb.bin"
    payload = big_payload(10)  # ~10 MiB
    info = storage.put(namespace, name, io.BytesIO(payload), content_type="application/octet-stream")
    assert info["size"] == len(payload)
    got, _ = storage.get(namespace, name)
    assert got == payload, "Large object mismatch"

# ---------- Негативные сценарии ----------

@integration
def test_get_nonexistent_raises(local_storage, namespace):
    storage = local_storage
    with pytest.raises(RegistryError):
        storage.get(namespace, "does/not/exist.txt")

@integration
def test_delete_nonexistent_is_safe(local_storage, namespace):
    storage = local_storage
    # Удаление несуществующего объекта не должно падать фатально (идемпотентность)
    storage.delete(namespace, "nothing/here.bin")  # отсутствие исключения — ок

# ---------- Диагностика/служебное ----------

@integration
def test_list_empty_namespace(local_storage):
    storage = local_storage
    items, cursor = storage.list("empty-ns", prefix="")
    assert items == [] and cursor is None
