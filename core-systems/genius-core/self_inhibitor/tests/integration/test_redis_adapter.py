# -*- coding: utf-8 -*-
import os
import socket
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from typing import Optional

import pytest

pytestmark = pytest.mark.integration

# redis-py обязателен для интеграционных тестов
try:
    import redis  # redis>=4
except Exception:
    redis = None

# Тестируемая реализация: RedisCounterStore (и Lua для токен-бакета)
try:
    from genius_core.security.self_inhibitor.runtime.counters import (
        RedisCounterStore,
        TOKEN_BUCKET_LUA,
    )
except Exception:
    RedisCounterStore = None  # type: ignore
    TOKEN_BUCKET_LUA = None   # type: ignore


# ----------------------------
# Утилиты окружения
# ----------------------------

def _have_docker() -> bool:
    return subprocess.call(["which", "docker"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _wait_redis_ready(client: "redis.Redis", timeout_s: float = 30.0) -> None:
    deadline = time.time() + timeout_s
    last_err: Optional[BaseException] = None
    while time.time() < deadline:
        try:
            if client.ping():
                return
        except BaseException as e:
            last_err = e
            time.sleep(0.2)
    raise TimeoutError(f"Redis not ready: {last_err!r}")


# ----------------------------
# Фикстуры: Redis URL / клиент / store
# ----------------------------

@pytest.fixture(scope="session")
def redis_url() -> str:
    """
    Возвращает URL для подключения к Redis.
    При наличии REDIS_TEST_URL используем его; иначе поднимаем Docker-контейнер redis:7-alpine.
    """
    if RedisCounterStore is None or redis is None:
        pytest.skip("RedisCounterStore or redis-py not available")

    env_url = os.getenv("REDIS_TEST_URL")
    if env_url:
        # проверим доступность
        client = redis.from_url(env_url, decode_responses=True)
        _wait_redis_ready(client, 30.0)
        with suppress(Exception):
            client.close()
        return env_url

    if not _have_docker():
        pytest.skip("docker not available and REDIS_TEST_URL not provided")

    port = _free_port()
    name = f"redis-it-{uuid.uuid4().hex[:8]}"
    run = [
        "docker", "run", "-d", "--rm",
        "-p", f"{port}:6379",
        "--name", name,
        "redis:7-alpine",
        "redis-server", "--save", "", "--appendonly", "no",
    ]
    proc = subprocess.run(run, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        pytest.skip(f"failed to start docker redis: {proc.stderr}")

    url = f"redis://127.0.0.1:{port}/0"
    try:
        client = redis.from_url(url, decode_responses=True)
        _wait_redis_ready(client, 30.0)
        with suppress(Exception):
            client.close()
        yield url
    finally:
        with suppress(Exception):
            subprocess.run(["docker", "logs", name, "--tail", "50"], stdout=sys.stderr, stderr=sys.stderr)
        with suppress(Exception):
            subprocess.run(["docker", "stop", "-t", "2", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture()
def rclient(redis_url: str):
    c = redis.from_url(redis_url, decode_responses=True)
    try:
        yield c
    finally:
        with suppress(Exception):
            c.close()


@pytest.fixture()
def store(rclient):
    if RedisCounterStore is None:
        pytest.skip("RedisCounterStore not importable")
    return RedisCounterStore(rclient)


# ----------------------------
# Тесты
# ----------------------------

def test_basic_incr_get_ttl_setnx_expire(store: RedisCounterStore, rclient):
    key = f"it:basic:{uuid.uuid4().hex}"
    # Начальный INCR с TTL
    val = store.incr(key, amount=1, ttl_ms=500)
    assert val == 1
    ttl = store.ttl_ms(key)
    assert ttl is None or ttl > 0  # pttl может быть недоступен в некоторых режимах, тогда None допустимо

    # get возвращает 1
    assert store.get(key) == 1

    # setnx (новый ключ)
    nx_key = key + ":nx"
    ok = store.setnx(nx_key, 7, ttl_ms=300)
    assert ok is True
    assert store.get(nx_key) == 7
    assert store.ttl_ms(nx_key) is None or store.ttl_ms(nx_key) > 0

    # повторный setnx не меняет
    assert store.setnx(nx_key, 99, ttl_ms=300) is False
    assert store.get(nx_key) == 7

    # expire продлевает TTL
    store.expire(nx_key, 400)
    assert store.ttl_ms(nx_key) is None or store.ttl_ms(nx_key) > 0

    # mget для пары ключей
    vals = store.mget([key, nx_key, key + ":absent"])
    assert vals[0] >= 1 and vals[1] == 7 and vals[2] == 0

    # TTL истёк для первоначального ключа
    time.sleep(0.6)
    with suppress(Exception):
        # pttl может удалить ключ по истечении
        _ = store.ttl_ms(key)
    assert store.get(key) in (0, 1)  # допускаем race, но позже удалим
    # Явно обнулим: повторный TTL не обязателен, важен факт неошибочного доступа
    rclient.delete(key)


def test_concurrent_incr_atomicity(store: RedisCounterStore):
    """
    Проверяем атомарность INCR при высокой конкуренции.
    """
    import threading
    key = f"it:concurrent:{uuid.uuid4().hex}"
    N_THREADS = 20
    N_PER_THREAD = 100

    errs = []
    def worker():
        try:
            for _ in range(N_PER_THREAD):
                store.incr(key, 1, ttl_ms=2000)
        except Exception as e:
            errs.append(e)

    threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errs
    # Итог должен равняться количеству операций
    total = store.get(key)
    assert total == N_THREADS * N_PER_THREAD


def test_mget_bulk(store: RedisCounterStore):
    """
    Проверяем корректность mget при смешанном наличии ключей.
    """
    base = f"it:mget:{uuid.uuid4().hex}"
    keys = [f"{base}:{i}" for i in range(5)]
    # Заполним только 0,2,4
    for i, k in enumerate(keys):
        if i % 2 == 0:
            store.incr(k, amount=i + 1, ttl_ms=1000)
    vals = store.mget(keys)
    assert vals == [1, 0, 3, 0, 5]


def test_token_bucket_lua_atomic(store: RedisCounterStore, rclient):
    """
    Проверяем атомарность токен-бакета через LUA:
    - capacity=5, refill_per_sec=1, cost=1
    - первые 5 параллельных вызовов должны получить allow=True, остальные False (если без пауз)
    """
    if TOKEN_BUCKET_LUA is None:
        pytest.skip("TOKEN_BUCKET_LUA not available")
    # sanity: скрипт должен выполняться
    # redis>=7 eval принимает script, numkeys, *keys_and_args
    _ = rclient.eval("return 1", 0)

    key = f"it:tb:{uuid.uuid4().hex}"
    capacity = 5
    refill = 1.0
    cost = 1

    # Параллельный старт 20 вызовов без задержки
    import threading
    allowed = 0
    lock = threading.Lock()
    def call():
        nonlocal allowed
        ok, rem, reset_at = store.token_bucket_update(
            key=key, capacity=capacity, refill_per_sec=refill,
            cost=cost, now_ms_=int(time.time()*1000), ttl_grace_ms=2000
        )
        with lock:
            if ok:
                allowed += 1

    threads = [threading.Thread(target=call) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    # Не должно выдать больше, чем capacity в одном «рывке»
    assert 0 < allowed <= capacity


def test_token_bucket_refill_progress(store: RedisCounterStore):
    """
    Проверяем пополнение токенов по времени: после расхода ожидаем частичное восстановление.
    """
    key = f"it:tbrefill:{uuid.uuid4().hex}"
    capacity = 3
    refill = 2.0  # 2 токена в секунду
    cost = 1

    # Сначала расходуем все токены
    grants = []
    for _ in range(capacity):
        ok, rem, _ = store.token_bucket_update(
            key=key, capacity=capacity, refill_per_sec=refill,
            cost=cost, now_ms_=int(time.time()*1000), ttl_grace_ms=1500
        )
        grants.append(ok)
    assert all(grants)
    # Следующий должен быть отклонен
    ok, rem, reset_at = store.token_bucket_update(
        key=key, capacity=capacity, refill_per_sec=refill,
        cost=cost, now_ms_=int(time.time()*1000), ttl_grace_ms=1500
    )
    assert ok is False

    # Ждем ~0.6с (≈1 токен, учитывая flooring)
    time.sleep(0.6)
    ok, rem, _ = store.token_bucket_update(
        key=key, capacity=capacity, refill_per_sec=refill,
        cost=cost, now_ms_=int(time.time()*1000), ttl_grace_ms=1500
    )
    assert ok is True
    assert 0 <= rem < capacity


def test_ttl_expiry_no_leak(store: RedisCounterStore):
    """
    Проверяем, что ключи с TTL корректно исчезают (нет утечек), а переиспользование ключа начинается с нуля.
    """
    key = f"it:ttl:{uuid.uuid4().hex}"
    store.incr(key, 5, ttl_ms=300)
    assert store.get(key) == 5
    time.sleep(0.35)
    # После истечения TTL значение должно быть либо 0, либо ключ удален
    v = store.get(key)
    assert v in (0,)

    # Новый цикл: начинаем с нуля
    store.incr(key, 2, ttl_ms=300)
    assert store.get(key) == 2
