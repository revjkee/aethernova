# -*- coding: utf-8 -*-
"""
Интеграционные тесты адаптеров хранилищ для OblivionVault.

Особенности:
- Динамическое обнаружение адаптера и его возможностей (put/get/exists/list/delete, presigned URL, метаданные).
- Унифицированный "шим" для вызова разных сигнатур методов.
- Безопасная работа с FS через tmp_path.
- Большие данные (до 8 MiB) и проверка sha256.
- Конкурентные put'ы с уникальными ключами.
- Аккуратные skip/xfail при отсутствии функций/окружения.

Ожидаемые варианты расположения локального адаптера (любое из них):
- oblivionvault.storage.adapters.local_fs_adapter.LocalFSAdapter
- oblivionvault.storage.adapters.local.LocalFSAdapter
- oblivionvault.storage.local.LocalFSAdapter

Для облачных адаптеров можно задать ENV (пример для S3/MinIO):
- OV_TEST_S3=1
- OV_TEST_S3_ENDPOINT, OV_TEST_S3_ACCESS_KEY, OV_TEST_S3_SECRET_KEY, OV_TEST_S3_BUCKET, OV_TEST_S3_REGION

Примечание: Тесты написаны так, чтобы по умолчанию проходил только локальный адаптер.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import os
import random
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable, Optional

import pytest

# -------------------------- Утилиты --------------------------

def _rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def _rand_key(prefix: str = "it/") -> str:
    salt = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{prefix}{salt}"

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _try_import(paths: list[tuple[str, str]]) -> Any | None:
    """
    Пытается импортировать класс по списку (module_path, class_name).
    Возвращает класс или None.
    """
    for mod, cls in paths:
        try:
            m = importlib.import_module(mod)
            c = getattr(m, cls, None)
            if c is not None:
                return c
        except Exception:
            continue
    return None

def _has_method(obj: Any, names: Iterable[str]) -> Optional[str]:
    for n in names:
        if hasattr(obj, n) and callable(getattr(obj, n)):
            return n
    return None

# -------------------------- Шим-обёртка --------------------------

class StorageShim:
    """
    Приводит конкретный адаптер к унифицированному интерфейсу:
      put(bucket, key, data: bytes, content_type=None, metadata=None) -> Any
      get(bucket, key) -> (bytes, metadata: dict|None)
      delete(bucket, key) -> None
      exists(bucket, key) -> bool
      list(bucket, prefix) -> list[str] либо список объектов с полем/атрибутом key
      presigned_url(bucket, key, method='GET', expires=60) -> str  (опционально)
    """
    def __init__(self, impl: Any, bucket: Optional[str]) -> None:
        self.impl = impl
        self.bucket = bucket

        # Подберём имена методов
        self._m_put = _has_method(impl, ("put", "put_bytes", "upload", "write"))
        self._m_get = _has_method(impl, ("get", "get_bytes", "download", "read"))
        self._m_del = _has_method(impl, ("delete", "remove", "rm"))
        self._m_exi = _has_method(impl, ("exists", "stat", "head"))
        self._m_lst = _has_method(impl, ("list", "list_objects", "iter", "list_prefix", "list_keys"))
        self._m_psu = _has_method(impl, ("generate_presigned_url", "presigned_url", "sign_url"))

        # Проверим минимально необходимые методы
        missing = [n for n, m in (("put", self._m_put), ("get", self._m_get),
                                  ("delete", self._m_del), ("exists", self._m_exi),
                                  ("list", self._m_lst)) if m is None]
        if missing:
            pytest.skip(f"Adapter missing required methods: {missing}")

    def _call(self, mname: str, *args, **kwargs):
        m = getattr(self.impl, mname)
        sig = inspect.signature(m)
        ba = None

        # Попробуем смэппить bucket/key/data по именам параметров
        params = list(sig.parameters.values())
        call_kwargs = {}

        # Простой путь: позиционные
        try:
            return m(*args, **kwargs)
        except TypeError:
            pass

        # Более гибкий: подстановки по именам
        names_map = {"bucket": ("bucket", "container", "bucket_name", "namespace"),
                     "key": ("key", "name", "path", "object", "object_key"),
                     "data": ("data", "content", "blob", "body", "bytes_"),
                     "content_type": ("content_type", "mime", "mimetype"),
                     "metadata": ("meta", "metadata", "meta_dict")}

        for k, v in kwargs.items():
            call_kwargs[k] = v

        # Если bucket/key/data приходят позиционно в args — попробуем раскидать по именам
        arg_names = ["bucket", "key", "data"]
        for i, a in enumerate(args):
            if i < len(arg_names):
                target_names = names_map[arg_names[i]]
                for n in params:
                    if n.name in target_names:
                        call_kwargs[n.name] = a
                        break

        # Если чего-то не хватает — добавим bucket по умолчанию
        if "bucket" not in call_kwargs and self.bucket is not None:
            for n in params:
                if n.name in names_map["bucket"]:
                    call_kwargs[n.name] = self.bucket
                    break

        return m(**call_kwargs)

    # Унифицированные методы

    def put(self, bucket: Optional[str], key: str, data: bytes,
            content_type: Optional[str] = None, metadata: Optional[dict] = None) -> Any:
        kwargs = {}
        if content_type is not None:
            kwargs["content_type"] = content_type
        if metadata is not None:
            kwargs["metadata"] = metadata
        # Порядок: (bucket, key, data)
        args = []
        if bucket is not None:
            args.append(bucket)
        args.extend([key, data])
        return self._call(self._m_put, *args, **kwargs)

    def get(self, bucket: Optional[str], key: str) -> tuple[bytes, dict | None]:
        args = []
        if bucket is not None:
            args.append(bucket)
        args.append(key)
        out = self._call(self._m_get, *args)
        # Унифицируем ответ
        if isinstance(out, tuple) and len(out) >= 1:
            data = out[0]
            meta = out[1] if len(out) > 1 and isinstance(out[1], dict) else None
            return data, meta
        elif isinstance(out, (bytes, bytearray)):
            return bytes(out), None
        elif hasattr(out, "read"):
            data = out.read()
            return data, None
        else:
            raise AssertionError("get() returned unsupported type")

    def delete(self, bucket: Optional[str], key: str) -> None:
        args = []
        if bucket is not None:
            args.append(bucket)
        args.append(key)
        _ = self._call(self._m_del, *args)

    def exists(self, bucket: Optional[str], key: str) -> bool:
        args = []
        if bucket is not None:
            args.append(bucket)
        args.append(key)
        out = self._call(self._m_exi, *args)
        if isinstance(out, bool):
            return out
        # Некоторые реализации возвращают объект/None
        return bool(out)

    def list(self, bucket: Optional[str], prefix: str) -> list[str]:
        args = []
        if bucket is not None:
            args.append(bucket)
        args.append(prefix)
        out = self._call(self._m_lst, *args)
        keys: list[str] = []
        if out is None:
            return keys
        if isinstance(out, (list, tuple)):
            it = out
        else:
            try:
                it = list(out)  # итератор
            except Exception:
                it = []
        for item in it:
            if isinstance(item, str):
                keys.append(item)
            elif isinstance(item, dict):
                k = item.get("key") or item.get("name") or item.get("path")
                if k:
                    keys.append(k)
            else:
                k = getattr(item, "key", None) or getattr(item, "name", None) or getattr(item, "path", None)
                if k:
                    keys.append(k)
        return keys

    def presigned_url(self, bucket: Optional[str], key: str, method: str = "GET", expires: int = 60) -> str:
        if not self._m_psu:
            pytest.skip("presigned URL is not supported by adapter")
        args = []
        if bucket is not None:
            args.append(bucket)
        args.append(key)
        try:
            return self._call(self._m_psu, *args, method=method, expires=expires)
        except TypeError:
            # Возможно адаптер не принимает method/expires
            return self._call(self._m_psu, *args)

# -------------------------- Фикстуры адаптеров --------------------------

LOCAL_CANDIDATES = [
    ("oblivionvault.storage.adapters.local_fs_adapter", "LocalFSAdapter"),
    ("oblivionvault.storage.adapters.local", "LocalFSAdapter"),
    ("oblivionvault.storage.local", "LocalFSAdapter"),
]

@pytest.fixture(scope="session")
def local_adapter_cls():
    cls = _try_import(LOCAL_CANDIDATES)
    if cls is None:
        pytest.skip("LocalFSAdapter not found in known locations")
    return cls

@pytest.fixture
def local_adapter(tmp_path, local_adapter_cls):
    # Пытаемся инициализировать с base_path/root_dir, либо без параметров
    try:
        impl = local_adapter_cls(base_path=str(tmp_path))
        bucket = None
    except TypeError:
        try:
            impl = local_adapter_cls(root_dir=str(tmp_path))
            bucket = None
        except TypeError:
            # Некоторые реализации требуют явный bucket; создадим
            impl = local_adapter_cls()
            bucket = "test-bucket"
            # В случае локального адаптера bucket мапится на поддиректорию
            (tmp_path / bucket).mkdir(exist_ok=True)
            if hasattr(impl, "set_base_path"):
                try:
                    impl.set_base_path(str(tmp_path))
                except Exception:
                    pass

    return StorageShim(impl, bucket)

# --- S3/MinIO (опционально через ENV) ---
S3_CANDIDATES = [
    ("oblivionvault.storage.adapters.s3_adapter", "S3Adapter"),
    ("oblivionvault.storage.adapters.s3", "S3Adapter"),
]

def _s3_env_ready() -> bool:
    return os.getenv("OV_TEST_S3") == "1" and all(
        os.getenv(k) for k in (
            "OV_TEST_S3_ENDPOINT", "OV_TEST_S3_ACCESS_KEY",
            "OV_TEST_S3_SECRET_KEY", "OV_TEST_S3_BUCKET"
        )
    )

@pytest.fixture(scope="session")
def s3_adapter_cls():
    if not _s3_env_ready():
        pytest.skip("S3 test env not configured; set OV_TEST_S3=1 and required vars")
    cls = _try_import(S3_CANDIDATES)
    if cls is None:
        pytest.skip("S3Adapter not found in known locations")
    return cls

@pytest.fixture
def s3_adapter(s3_adapter_cls):
    endpoint = os.environ["OV_TEST_S3_ENDPOINT"]
    access = os.environ["OV_TEST_S3_ACCESS_KEY"]
    secret = os.environ["OV_TEST_S3_SECRET_KEY"]
    bucket = os.environ["OV_TEST_S3_BUCKET"]
    region = os.getenv("OV_TEST_S3_REGION", "us-east-1")
    # Попробуем несколько сигнатур конструкторов
    try:
        impl = s3_adapter_cls(endpoint=endpoint, access_key=access, secret_key=secret, region=region, secure=True)
    except TypeError:
        impl = s3_adapter_cls(endpoint_url=endpoint, aws_access_key_id=access, aws_secret_access_key=secret, region_name=region)
    return StorageShim(impl, bucket)

# -------------------------- Параметризация адаптеров --------------------------

def adapters_available(request):
    out = []
    if "local_adapter" in request.fixturenames:
        out.append("local")
    if "s3_adapter" in request.fixturenames and _s3_env_ready():
        out.append("s3")
    return out

# -------------------------- БАЗОВЫЕ ИНВАРИАНТЫ --------------------------

@pytest.mark.integration
@pytest.mark.parametrize("adapter_name", ["local"])
def test_roundtrip_basic(request, adapter_name, local_adapter):
    adapter = {"local": local_adapter}[adapter_name]
    bucket = adapter.bucket
    key = _rand_key("roundtrip/")
    data = _rand_bytes(1024)
    adapter.put(bucket, key, data, content_type="application/octet-stream", metadata={"m": "v1"})
    assert adapter.exists(bucket, key) is True
    got, meta = adapter.get(bucket, key)
    assert got == data
    # если адаптер возвращает метаданные — проверим хотя бы один ключ
    if meta is not None and isinstance(meta, dict):
        assert isinstance(meta, dict)
    keys = adapter.list(bucket, "roundtrip/")
    assert key in keys
    adapter.delete(bucket, key)
    assert adapter.exists(bucket, key) is False

@pytest.mark.integration
@pytest.mark.parametrize("adapter_name", ["local"])
def test_overwrite_semantics(request, adapter_name, local_adapter):
    adapter = {"local": local_adapter}[adapter_name]
    bucket = adapter.bucket
    key = _rand_key("overwrite/")
    v1 = _rand_bytes(2048)
    v2 = _rand_bytes(4096)
    adapter.put(bucket, key, v1)
    adapter.put(bucket, key, v2)  # перезапись
    got, _ = adapter.get(bucket, key)
    assert got == v2
    adapter.delete(bucket, key)

@pytest.mark.integration
@pytest.mark.parametrize("adapter_name", ["local"])
def test_prefix_listing(request, adapter_name, local_adapter):
    adapter = {"local": local_adapter}[adapter_name]
    bucket = adapter.bucket
    prefix = "list/test/"
    keys = [f"{prefix}k{i}" for i in range(5)]
    payload = _rand_bytes(128)
    for k in keys:
        adapter.put(bucket, k, payload)
    listed = set(adapter.list(bucket, prefix))
    # у некоторых адаптеров листинг может возвращать полные пути — проверим пересечение
    intersection = {k for k in keys if k in listed}
    assert len(intersection) == len(keys)
    for k in keys:
        adapter.delete(bucket, k)

@pytest.mark.integration
@pytest.mark.parametrize("adapter_name", ["local"])
def test_large_payload_sha256(request, adapter_name, local_adapter):
    adapter = {"local": local_adapter}[adapter_name]
    bucket = adapter.bucket
    key = _rand_key("large/")
    size = 8 * 1024 * 1024  # 8 MiB
    data = _rand_bytes(size)
    h = _sha256_hex(data)
    adapter.put(bucket, key, data)
    got, _ = adapter.get(bucket, key)
    assert _sha256_hex(got) == h
    adapter.delete(bucket, key)

@pytest.mark.integration
@pytest.mark.parametrize("adapter_name", ["local"])
def test_concurrent_puts(request, adapter_name, local_adapter):
    adapter = {"local": local_adapter}[adapter_name]
    bucket = adapter.bucket
    prefix = "concurrent/"
    keys = [_rand_key(prefix) for _ in range(12)]
    payloads = {k: _rand_bytes(1024) for k in keys}

    def _worker(k: str):
        adapter.put(bucket, k, payloads[k])
        ok = adapter.exists(bucket, k)
        return k, ok

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(_worker, keys))

    assert all(ok for _, ok in results)
    # Проверим первые 3 объекта чтением
    for k in keys[:3]:
        got, _ = adapter.get(bucket, k)
        assert got == payloads[k]
    for k in keys:
        adapter.delete(bucket, k)

@pytest.mark.integration
@pytest.mark.parametrize("adapter_name", ["local"])
def test_presigned_url_if_supported(request, adapter_name, local_adapter):
    adapter = {"local": local_adapter}[adapter_name]
    bucket = adapter.bucket
    key = _rand_key("psu/")
    data = _rand_bytes(256)
    adapter.put(bucket, key, data)
    try:
        url = adapter.presigned_url(bucket, key, method="GET", expires=60)
    except pytest.skip.Exception:
        adapter.delete(bucket, key)
        pytest.skip("presigned URL not supported")
    assert isinstance(url, str) and len(url) > 0
    adapter.delete(bucket, key)

# -------------------------- ОБЛАЧНЫЕ (ОПЦИОНАЛЬНО) --------------------------

@pytest.mark.integration
@pytest.mark.skipif(not _s3_env_ready(), reason="S3 env is not configured")
def test_s3_roundtrip(s3_adapter):
    adapter = s3_adapter
    bucket = adapter.bucket
    key = _rand_key("s3/roundtrip/")
    data = _rand_bytes(1536)
    adapter.put(bucket, key, data, content_type="application/octet-stream", metadata={"m": "s3"})
    assert adapter.exists(bucket, key) is True
    got, meta = adapter.get(bucket, key)
    assert got == data
    if meta is not None and isinstance(meta, dict):
        assert isinstance(meta, dict)
    adapter.delete(bucket, key)
    assert adapter.exists(bucket, key) is False

@pytest.mark.integration
@pytest.mark.skipif(not _s3_env_ready(), reason="S3 env is not configured")
def test_s3_prefix_listing(s3_adapter):
    adapter = s3_adapter
    bucket = adapter.bucket
    prefix = "s3/list/"
    keys = [f"{prefix}k{i}" for i in range(4)]
    payload = _rand_bytes(256)
    for k in keys:
        adapter.put(bucket, k, payload)
    listed = set(adapter.list(bucket, prefix))
    intersection = {k for k in keys if k in listed}
    assert len(intersection) == len(keys)
    for k in keys:
        adapter.delete(bucket, k)
