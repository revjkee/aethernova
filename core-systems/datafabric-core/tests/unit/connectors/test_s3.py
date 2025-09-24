# -*- coding: utf-8 -*-
import io
import json
import os
import random
import string
import tempfile
import time
import uuid
from pathlib import Path

import pytest

# ---- Опциональные зависимости (аккуратно скипаем при отсутствии) ----
boto3 = pytest.importorskip("boto3")
botocore = pytest.importorskip("botocore")
from botocore.client import Config as BotoConfig  # type: ignore

# moto менял API: поддерживаем и mock_aws, и mock_s3
_moto = pytest.importorskip("moto")
if hasattr(_moto, "mock_aws"):
    mock_ctx_factory = _moto.mock_aws
else:
    mock_ctx_factory = _moto.mock_s3  # type: ignore

# Коннектор проекта
_s3_module = pytest.importorskip("datafabric.connectors.s3")
S3Connector = getattr(_s3_module, "S3Connector")

pytestmark = pytest.mark.unit


# =============================== Утилиты =====================================

def _rand_key(prefix="it/"):
    return f"{prefix}{uuid.uuid4().hex}/{uuid.uuid4().hex}.bin"

def _rand_bytes(n=1024):
    return os.urandom(n)

def _ascii(n=16):
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


# =============================== Фикстуры ====================================

@pytest.fixture(scope="session")
def aws_credentials(monkeypatch):
    # Безопасные фиктивные креды
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    yield


@pytest.fixture(scope="function")
def moto_aws(aws_credentials):
    with mock_ctx_factory():
        yield


@pytest.fixture(scope="function")
def s3_client(moto_aws):
    # В moto region us-east-1 допускает create_bucket без конфигурации
    return boto3.client("s3", region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"), config=BotoConfig(s3={"addressing_style": "path"}))


@pytest.fixture(scope="function", params=["us-east-1", "eu-west-1"])
def bucket_name(s3_client, request):
    region = request.param
    name = f"df-test-{region}-{uuid.uuid4().hex[:10]}"
    if region == "us-east-1":
        s3_client.create_bucket(Bucket=name)
    else:
        s3_client.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    yield name


@pytest.fixture(scope="function")
def versioned_bucket(s3_client, bucket_name):
    s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    yield bucket_name


@pytest.fixture(scope="function")
def connector(s3_client, bucket_name):
    # Предпочитаем инъекцию готового клиента
    return S3Connector(client=s3_client, default_bucket=bucket_name)


# =============================== Тесты =======================================

def test_put_and_get_bytes_roundtrip(connector, bucket_name):
    key = _rand_key("rt/bytes/")
    payload = _rand_bytes(4096)
    meta = {"x-trace": _ascii(8), "purpose": "unit"}
    tags = {"env": "test", "team": "qa"}

    # put
    connector.put_bytes(bucket_name, key, payload, metadata=meta, tags=tags)

    # exists + head
    assert connector.exists(bucket_name, key) is True
    head = connector.head_object(bucket_name, key)
    assert head["ResponseMetadata"]["HTTPStatusCode"] in (200, 204)

    # get
    out = connector.get_bytes(bucket_name, key)
    assert out == payload

    # метаданные (user-metadata в S3 нормализуются в lower-case)
    got_meta = connector.get_object_metadata(bucket_name, key)
    assert got_meta.get("x-trace") == meta["x-trace"]
    assert got_meta.get("purpose") == "unit"

    # теги
    got_tags = connector.get_object_tags(bucket_name, key)
    assert got_tags == tags


def test_put_and_get_file_roundtrip(tmp_path, connector, bucket_name):
    key = _rand_key("rt/file/")
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    data = "hello, datafabric\n" * 50
    src.write_text(data, encoding="utf-8")

    connector.put_file(bucket_name, key, src)
    assert connector.exists(bucket_name, key)

    connector.get_file(bucket_name, key, dst)
    assert dst.exists()
    assert dst.read_text(encoding="utf-8") == data


@pytest.mark.slow
def test_list_keys_pagination(connector, bucket_name):
    prefix = "list/prefix/"
    # Создаем > 1000 объектов для проверки пагинации листинга
    total = 1203
    for i in range(total):
        connector.put_bytes(bucket_name, f"{prefix}obj-{i:04d}", b"x")

    # list (итератор/батчи)
    keys = list(connector.list_keys(bucket_name, prefix=prefix, recursive=True))
    assert len(keys) == total
    assert keys[0].startswith(prefix)
    assert keys[-1].startswith(prefix)


def test_copy_and_delete_prefix(connector, bucket_name):
    src_key = _rand_key("cp/src/")
    dst_key = _rand_key("cp/dst/")
    connector.put_bytes(bucket_name, src_key, b"abc")

    connector.copy(bucket_name, src_key, bucket_name, dst_key)
    assert connector.exists(bucket_name, dst_key)

    # delete_prefix
    connector.delete_prefix(bucket_name, "cp/src/")
    assert connector.exists(bucket_name, src_key) is False


def test_presigned_url_signature(connector, bucket_name):
    key = _rand_key("signed/")
    connector.put_bytes(bucket_name, key, b"content")
    url = connector.generate_presigned_url(bucket_name, key, expires_in=600, method="get_object")
    # В оффлайне не делаем HTTP-запрос. Проверяем валидность структуры и наличие подписи.
    assert isinstance(url, str) and url.startswith("http")
    assert "X-Amz-Signature=" in url or "X-Amz-Credential=" in url


def test_metadata_and_tags_update(connector, bucket_name):
    key = _rand_key("meta/")
    connector.put_bytes(bucket_name, key, b"m", metadata={"k1": "v1"}, tags={"t1": "v1"})
    # обновляем
    connector.put_object_metadata(bucket_name, key, {"k2": "v2"})
    connector.put_object_tags(bucket_name, key, {"t2": "v2"})

    meta = connector.get_object_metadata(bucket_name, key)
    tags = connector.get_object_tags(bucket_name, key)
    assert "k2" in meta and meta["k2"] == "v2"
    assert tags == {"t2": "v2"}


def test_sse_s3_encryption(connector, bucket_name):
    key = _rand_key("sse/")
    # SSE-S3 (AES256)
    connector.put_bytes(bucket_name, key, b"secret", sse="AES256")
    head = connector.head_object(bucket_name, key)
    # Поле может называться 'ServerSideEncryption' в boto3 head_object
    assert head.get("ServerSideEncryption", "") == "AES256"
    assert connector.get_bytes(bucket_name, key) == b"secret"


def test_versioning_latest(versioned_bucket, s3_client):
    bucket = versioned_bucket
    # Обходимся без коннектора: проверяем корректность в окружении moto и совместимость с boto3
    key = _rand_key("ver/")
    s3_client.put_object(Bucket=bucket, Key=key, Body=b"v1")
    s3_client.put_object(Bucket=bucket, Key=key, Body=b"v2")
    head = s3_client.head_object(Bucket=bucket, Key=key)
    assert "VersionId" in head  # последняя версия
    # Получаем обе версии
    versions = s3_client.list_object_versions(Bucket=bucket, Prefix=key).get("Versions", [])
    assert len([v for v in versions if v["Key"] == key]) == 2


@pytest.mark.slow
def test_multipart_put_if_supported(tmp_path, connector, bucket_name):
    # Если у коннектора нет отдельного метода мультимпарт — скипаем
    if not hasattr(connector, "multipart_put_file"):
        pytest.skip("multipart_put_file is not implemented in connector")
    key = _rand_key("mp/")
    # ~10 МБ для нескольких частей (в тестовом методе можно задать part_size)
    size = 10 * 1024 * 1024 + 1234
    fpath = tmp_path / "big.bin"
    with open(fpath, "wb") as f:
        f.write(os.urandom(size))
    connector.multipart_put_file(bucket_name, key, fpath, part_size=5 * 1024 * 1024)
    assert connector.exists(bucket_name, key)
    # контроль размера
    head = connector.head_object(bucket_name, key)
    assert int(head.get("ContentLength", -1)) == size


def test_exists_and_delete_key(connector, bucket_name):
    key = _rand_key("del/")
    connector.put_bytes(bucket_name, key, b"x")
    assert connector.exists(bucket_name, key)
    connector.delete_key(bucket_name, key)
    assert connector.exists(bucket_name, key) is False


def test_list_non_recursive(connector, bucket_name):
    base = "nr/pfx/"
    connector.put_bytes(bucket_name, base + "a/file1", b"x")
    connector.put_bytes(bucket_name, base + "a/file2", b"x")
    connector.put_bytes(bucket_name, base + "b/file3", b"x")
    # Нерекурсивный листинг возвращает только прямых потомков
    items = list(connector.list_keys(bucket_name, prefix=base, recursive=False))
    # Ожидаем каталоги-префиксы либо первые уровни ключей
    assert any("a/" in x or x.endswith("a") for x in items) or any(x.endswith("b") for x in items)


def test_json_helpers_if_any(connector, bucket_name):
    # Эти методы могут отсутствовать — тогда скипаем.
    if not all(hasattr(connector, m) for m in ("put_json", "get_json")):
        pytest.skip("JSON helpers not implemented")
    key = _rand_key("json/")
    payload = {"a": 1, "b": "x", "ts": int(time.time())}
    connector.put_json(bucket_name, key, payload, content_type="application/json")
    got = connector.get_json(bucket_name, key)
    assert got == payload
