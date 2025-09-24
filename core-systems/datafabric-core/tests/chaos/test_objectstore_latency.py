# datafabric-core/tests/chaos/test_objectstore_latency.py
# Хаос-тесты латентности и отказоустойчивости объектного хранилища (S3-мок).
# Покрытие:
#  - гарантированная латентность put/get с заданным MockChaos.latency_ms
#  - суммарная латентность постраничного листинга (пагинация) под задержками
#  - ретраи при транзиентных ошибках (интеграция с datafabric.utils.retry, при отсутствии — фолбэк)
#  - конкурентные операции аплоада под задержками без потерь/дедлоков
#  - корректная форма пресайна
#
# Тесты используют mocks.connectors.s3_mock.{S3MockClient, MockConfig, MockChaos}.
# При отсутствии модуля помечаются xfail с понятной причиной.

from __future__ import annotations

import io
import os
import time
import types
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional

import pytest

# ---------- Импорт мока S3 и retry-утилит с мягкой деградацией ----------
try:
    from mocks.connectors.s3_mock import (
        client as s3_client_factory,
        MockConfig,
        MockChaos,
        ClientError,
    )
    S3MOCK_AVAILABLE = True
except Exception:
    S3MOCK_AVAILABLE = False

try:
    from datafabric.utils.retry import retry_call, default_http_retry_policy, RetryPolicy  # type: ignore
    RETRY_AVAILABLE = True
except Exception:
    RETRY_AVAILABLE = False

    class RetryPolicy:  # минимальный фолбэк для тестов
        def __init__(self, **kw: Any):
            self.max_attempts = int(kw.get("max_attempts", 5))
            self.backoff_base = float(kw.get("backoff_base", 0.05))
            self.backoff_multiplier = float(kw.get("backoff_multiplier", 1.0))

    def default_http_retry_policy(name: str = "http") -> RetryPolicy:
        return RetryPolicy(max_attempts=6, backoff_base=0.02, backoff_multiplier=1.0)

    def retry_call(fn, *, policy: Optional[RetryPolicy] = None, **kwargs):
        p = policy or default_http_retry_policy()
        delay = p.backoff_base
        last_exc = None
        for attempt in range(1, p.max_attempts + 1):
            try:
                return fn(**kwargs)
            except Exception as e:  # noqa: BLE001
                last_exc = e
                if attempt == p.max_attempts:
                    raise
                time.sleep(delay)
        raise last_exc  # noqa: TRY200

pytestmark = [pytest.mark.chaos]

# ---------- Общие фикстуры ----------

@pytest.fixture(autouse=True)
def _xfail_if_no_s3mock():
    if not S3MOCK_AVAILABLE:
        pytest.xfail("mocks.connectors.s3_mock is not available")

@pytest.fixture
def tmp_root(tmp_path):
    root = tmp_path / ".s3mock"
    root.mkdir(parents=True, exist_ok=True)
    return root

def _mk_client(root, latency_ms: int = 0, fail_ratio: float = 0.0, seed: int = 123, page_size: int = 1000,
               eventual: bool = False, lag_ms: int = 0):
    chaos = MockChaos(latency_ms=latency_ms, fail_ratio=fail_ratio, seed=seed)
    cfg = MockConfig(root_dir=root, page_size=page_size, eventual_consistency=eventual,
                     consistency_lag_ms=lag_ms, deterministic=True, chaos=chaos)
    s3 = s3_client_factory(cfg)
    s3.create_bucket(Bucket="t")
    return s3

# ---------- Вспомогательные замеры времени ----------

class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self
    def __exit__(self, *exc):
        self.dt = time.perf_counter() - self.t0

def _assert_ge_with_tolerance(actual_sec: float, expected_sec: float, tolerance_sec: float):
    # допускаем небольшие флуктуации планировщика и диска
    assert actual_sec + tolerance_sec >= expected_sec, f"actual={actual_sec:.4f}s expected>={expected_sec:.4f}s tol={tolerance_sec:.4f}s"

# ---------- ТЕСТЫ ЛАТЕНТНОСТИ PUT/GET ----------

@pytest.mark.parametrize("latency_ms", [0, 50, 120])
def test_put_get_respects_configured_latency(tmp_root, latency_ms):
    s3 = _mk_client(tmp_root, latency_ms=latency_ms)
    payload = b"x" * 128

    # PUT
    with Timer() as t_put:
        s3.put_object(Bucket="t", Key="a.bin", Body=payload)
    # GET
    with Timer() as t_get:
        obj = s3.get_object(Bucket="t", Key="a.bin")
        _ = obj["Body"].read()

    # Каждая операция включает как минимум один вызов chaos.maybe_sleep()
    expected = latency_ms / 1000.0
    tol = 0.02  # 20 мс на системные флуктуации
    _assert_ge_with_tolerance(t_put.dt, expected, tol)
    _assert_ge_with_tolerance(t_get.dt, expected, tol)

# ---------- ТЕСТЫ ПАГИНАЦИИ И СУММАРНОЙ ЛАТЕНТНОСТИ ----------

@pytest.mark.parametrize("page_size,objects,latency_ms", [(100, 550, 40), (200, 1200, 80)])
def test_list_pagination_accumulates_latency(tmp_root, page_size, objects, latency_ms):
    s3 = _mk_client(tmp_root, latency_ms=latency_ms, page_size=page_size)
    # Подготовка данных
    for i in range(objects):
        s3.put_object(Bucket="t", Key=f"p/{i:06d}.dat", Body=b"x")

    paginator = s3.get_paginator("list_objects_v2")
    with Timer() as t_list:
        total = 0
        for page in paginator.paginate(Bucket="t", Prefix="p/"):
            total += len(page.get("Contents", []))

    assert total == objects
    pages = (objects + page_size - 1) // page_size
    expected = (latency_ms / 1000.0) * pages
    tol = 0.05 + pages * 0.005  # 50 мс + 5 мс на страницу
    _assert_ge_with_tolerance(t_list.dt, expected, tol)

# ---------- ТЕСТЫ РЕТРАЕВ НА ТРАНЗИЕНТНЫХ ОШИБКАХ ----------

def test_retry_on_transient_failures_for_put_object(tmp_root, monkeypatch):
    s3 = _mk_client(tmp_root, latency_ms=10)
    attempts = {"n": 0}

    orig_put = s3.put_object

    def flaky_put(**kw):
        # Первые 3 попытки — транзиентная ошибка
        attempts["n"] += 1
        if attempts["n"] <= 3:
            raise ClientError({"Error": {"Code": "InternalError", "Message": "injected"},"ResponseMetadata":{"HTTPStatusCode":500}}, "PutObject")
        return orig_put(**kw)

    monkeypatch.setattr(s3, "put_object", flaky_put)

    pol = default_http_retry_policy(name="s3_put_test")
    # Гарантируем, что хватит попыток
    pol.max_attempts = max(getattr(pol, "max_attempts", 6), 5)  # type: ignore[attr-defined]

    with Timer() as t:
        url = retry_call(lambda: s3.put_object(Bucket="t", Key="retry.bin", Body=b"ok"), policy=pol)
    # Операция должна закончиться успехом после ретраев
    assert attempts["n"] >= 4
    got = s3.get_object(Bucket="t", Key="retry.bin")
    assert got["Body"].read() == b"ok"
    # Время должно быть не меньше суммы базовых задержек (3 отказа + финальный успех, у нас есть 4 вызова put_object)
    min_calls = attempts["n"]
    expected_min = (10 / 1000.0) * min_calls  # только вклад chaos.latency
    _assert_ge_with_tolerance(t.dt, expected_min, 0.1)

# ---------- КОНКУРЕНТНЫЕ ОПЕРАЦИИ ПОД ЗАДЕРЖКАМИ ----------

@pytest.mark.parametrize("latency_ms,workers,items", [(20, 8, 200), (50, 12, 300)])
def test_concurrent_uploads_complete_without_errors(tmp_root, latency_ms, workers, items):
    s3 = _mk_client(tmp_root, latency_ms=latency_ms)
    payload = b"x" * 256

    def up(i: int):
        s3.put_object(Bucket="t", Key=f"concurrent/{i:05d}.bin", Body=payload)
        # проверка чтения
        obj = s3.get_object(Bucket="t", Key=f"concurrent/{i:05d}.bin")
        assert obj["Body"].read() == payload
        return i

    with Timer() as t:
        errs = []
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(up, i) for i in range(items)]
            for f in as_completed(futs):
                try:
                    _ = f.result()
                    done += 1
                except Exception as e:  # noqa: BLE001
                    errs.append(e)
    assert not errs
    assert done == items
    # Оценочно проверим, что параллелизм дал выигрыш: время меньше, чем последовательное выполнение с учётом латентности
    seq_time = (latency_ms / 1000.0) * 2 * items  # put + get
    assert t.dt < seq_time

# ---------- EVENTUAL CONSISTENCY: задержка листинга ----------

@pytest.mark.parametrize("lag_ms", [30, 120])
def test_eventual_consistency_adds_list_latency(tmp_root, lag_ms):
    # Эмуляция eventual consistency: листинг "запаздывает" на lag_ms.
    s3 = _mk_client(tmp_root, latency_ms=0, eventual=True, lag_ms=lag_ms, page_size=500)
    # Создаём партию объектов
    for i in range(800):
        s3.put_object(Bucket="t", Key=f"ec/{i:04d}.dat", Body=b"x")

    paginator = s3.get_paginator("list_objects_v2")
    with Timer() as t:
        total = sum(len(p.get("Contents", [])) for p in paginator.paginate(Bucket="t", Prefix="ec/"))

    assert total == 800
    pages = (800 + 500 - 1) // 500
    expected = (lag_ms / 1000.0) * pages
    tol = 0.03 + pages * 0.003
    _assert_ge_with_tolerance(t.dt, expected, tol)

# ---------- PRESIGNED URL ФОРМА ----------

def test_generate_presigned_url_shape(tmp_root):
    s3 = _mk_client(tmp_root, latency_ms=0)
    s3.put_object(Bucket="t", Key="presign.dat", Body=b"1")
    url = s3.generate_presigned_url("get_object", {"Bucket": "t", "Key": "presign.dat"}, ExpiresIn=600)
    assert "https://s3.mock/t/presign.dat" in url
    assert "exp=600" in url
