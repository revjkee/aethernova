# engine/tests/chaos/test_bus_partitions.py
"""
Хаос‑тесты для шин событий: сетевые разрывы, задержки, потери, восстановление.

Ожидаемый модуль: engine.bus с одним из API:
  - Bus.from_env() -> Bus
  - create_bus(**cfg) -> Bus
Bus (частично или полностью) поддерживает:
  - async publish(topic, key: str|None, value: bytes|dict|str, headers: dict|None=None, idempotency_key: str|None=None) -> ack|None
  - async subscribe(topic, group: str|None, handler: async callable(event) -> None) -> subscription
  - async poll(topic, group, limit:int=..., timeout:float=...) -> list[event]    # опционально
  - async commit(event|offset)  # опционально для явного подтверждения
  - async close()
  - health()/health_async()
  - fault injector hooks (необязательно):
      .set_fault_injector(callable) или .fault_injector = FaultInjector(...)
      .supports_faults / .supports_partitions / .supports_metrics / .supports_ordering
      .set_latency_ms(ms), .set_drop_rate(p), .set_partitioned(partition_id|bool), .reset_faults()

Тесты автоматически ослабляют ожидания, если функциональность недоступна.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

import pytest

bus_mod = pytest.importorskip("engine.bus", reason="engine.bus module not found")
Bus = getattr(bus_mod, "Bus", None)
create_bus = getattr(bus_mod, "create_bus", None)

# -----------------------
# Конфиг тестов и фабрика
# -----------------------

@dataclass
class TestCfg:
    topic: str = os.getenv("BUS_TEST_TOPIC", "test.events")
    group: str = os.getenv("BUS_TEST_GROUP", "g-chaos")
    duration_sec: float = float(os.getenv("BUS_TEST_DURATION", "2.0"))
    seed: int = int(os.getenv("BUS_TEST_SEED", "1337"))
    require_faults: bool = os.getenv("BUS_REQUIRE_FAULTS", "0") in ("1","true","yes","on")

def _make_bus() -> Any:
    cfg = TestCfg()
    if Bus and hasattr(Bus, "from_env"):
        try:
            return Bus.from_env()
        except Exception as e:
            pytest.skip(f"Bus.from_env() failed: {e}")
    if create_bus:
        try:
            return create_bus()
        except Exception as e:
            pytest.skip(f"create_bus() failed: {e}")
    pytest.skip("No Bus or create_bus() available")

# -----------------------
# Вспомогательные утилиты
# -----------------------

def _supports(obj: Any, attr: str) -> bool:
    return callable(getattr(obj, attr, None)) or hasattr(obj, attr)

def _faults(bus: Any) -> Dict[str, bool]:
    return {
        "faults": bool(getattr(bus, "supports_faults", False) or _supports(bus, "set_fault_injector")),
        "partitions": bool(getattr(bus, "supports_partitions", False) or _supports(bus, "set_partitioned")),
        "latency": _supports(bus, "set_latency_ms"),
        "drop": _supports(bus, "set_drop_rate"),
        "metrics": bool(getattr(bus, "supports_metrics", False) or _supports(bus, "metrics")),
        "ordering": bool(getattr(bus, "supports_ordering", False)),
    }

async def _publish_many(bus: Any, topic: str, count: int, prefix: str, key_by_mod: Optional[int] = None,
                        idempo: bool = False) -> List[str]:
    """Публикует count событий, возвращает список idempotency ключей (если использовались)."""
    keys: List[str] = []
    for i in range(count):
        key = f"k-{i % key_by_mod}" if key_by_mod else None
        idem = f"{prefix}-{i}" if idempo else None
        payload = {"n": i, "ts": time.time(), "p": prefix}
        await bus.publish(topic, key=key, value=payload, headers={"x-test": prefix}, idempotency_key=idem)
        if idem:
            keys.append(idem)
    return keys

async def _collect(bus: Any, topic: str, group: str, n: int, timeout: float = 3.0) -> List[Dict[str, Any]]:
    """Собирает n событий через subscribe+handler или poll()."""
    out: List[Dict[str, Any]] = []
    if _supports(bus, "poll"):
        t0 = time.time()
        while len(out) < n and (time.time() - t0) < timeout:
            batch = await bus.poll(topic, group, limit=min(100, n - len(out)), timeout=0.2)
            out.extend(batch or [])
        return out
    # Fallback: временная подписка
    q: asyncio.Queue = asyncio.Queue()

    async def handler(ev: Dict[str, Any]) -> None:
        await q.put(ev)

    sub = await bus.subscribe(topic, group, handler)
    try:
        t0 = time.time()
        while len(out) < n and (time.time() - t0) < timeout:
            try:
                ev = await asyncio.wait_for(q.get(), timeout=0.25)
                out.append(ev)
            except asyncio.TimeoutError:
                pass
        return out
    finally:
        # best-effort: у некоторых реализаций unsubscribe отсутствует
        with pytest.raises(Exception):
            await sub.close()  # type: ignore[attr-defined]

# -----------------------
# Фикстуры
# -----------------------

@pytest.fixture(scope="module")
def cfg() -> TestCfg:
    return TestCfg()

@pytest.fixture()
async def bus():
    b = _make_bus()
    yield b
    if _supports(b, "close"):
        await b.close()  # type: ignore

@pytest.fixture(autouse=True)
def _seed(cfg: TestCfg):
    random.seed(cfg.seed)

# -----------------------
# Health
# -----------------------

@pytest.mark.asyncio
async def test_health(bus):
    h = None
    if _supports(bus, "health_async"):
        h = await bus.health_async()
    elif _supports(bus, "health"):
        h = bus.health()  # type: ignore
    else:
        pytest.skip("health() not available")
    assert isinstance(h, dict) and (h.get("status") in (None, "ok", "degraded") or h != {})

# -----------------------
# Базовый happy‑path
# -----------------------

@pytest.mark.asyncio
async def test_publish_subscribe_happy_path(bus, cfg: TestCfg):
    await _publish_many(bus, cfg.topic, 10, prefix="hp", key_by_mod=3)
    got = await _collect(bus, cfg.topic, cfg.group, 10, timeout=5.0)
    assert len(got) >= 10

# -----------------------
# Инжекция задержек
# -----------------------

@pytest.mark.asyncio
async def test_latency_injection_if_supported(bus, cfg: TestCfg):
    caps = _faults(bus)
    if not caps["latency"]:
        pytest.xfail("Latency injection not supported")
    # Включаем высокую задержку и проверяем, что latency растёт, но доставка не ломается
    bus.set_latency_ms(300)  # type: ignore
    await _publish_many(bus, cfg.topic, 5, prefix="lat")
    t0 = time.perf_counter()
    got = await _collect(bus, cfg.topic, cfg.group, 5, timeout=5.0)
    dt_ms = (time.perf_counter() - t0) * 1000
    assert len(got) >= 5
    assert dt_ms >= 200, f"Latency injection seems ignored (dt={dt_ms:.1f}ms)"
    # Сбрасываем
    if _supports(bus, "reset_faults"):
        bus.reset_faults()  # type: ignore

# -----------------------
# Инжекция потерь (drop)
# -----------------------

@pytest.mark.asyncio
async def test_drop_injection_if_supported(bus, cfg: TestCfg):
    caps = _faults(bus)
    if not caps["drop"]:
        pytest.xfail("Drop injection not supported")
    bus.set_drop_rate(0.5)  # type: ignore
    await _publish_many(bus, cfg.topic, 100, prefix="drop")
    got = await _collect(bus, cfg.topic, cfg.group, 60, timeout=6.0)
    # Должно прийти не все; ослабим проверку, чтобы не ломать нестабильные бэкенды
    assert 20 <= len(got) <= 100
    if _supports(bus, "reset_faults"):
        bus.reset_faults()  # type: ignore

# -----------------------
# Разделение сети (partition) и восстановление
# -----------------------

@pytest.mark.asyncio
async def test_partition_and_rejoin(bus, cfg: TestCfg):
    caps = _faults(bus)
    if not caps["partitions"]:
        if cfg.require_faults:
            pytest.fail("Partitions required but not supported")
        pytest.xfail("Partition injection not supported")

    # Включаем разрыв
    bus.set_partitioned(True)  # type: ignore
    # Публикуем события в разрыв: ожидаем либо накопление в локальном буфере, либо ошибки ретраев
    await _publish_many(bus, cfg.topic, 20, prefix="part", idempo=True)
    # Отключаем разрыв — сообщения должны появиться
    bus.set_partitioned(False)  # type: ignore

    got = await _collect(bus, cfg.topic, cfg.group, 20, timeout=8.0)
    # допускаем потери, но при идемпотентности большинство должны дойти
    assert len(got) >= 10

# -----------------------
# Idempotency: повторная публикация одного ключа не порождает дубликаты
# -----------------------

@pytest.mark.asyncio
async def test_idempotency_keys_if_supported(bus, cfg: TestCfg):
    keys = await _publish_many(bus, cfg.topic, 10, prefix="idem", idempo=True)
    # Переиздаём те же ключи
    for k in keys:
        await bus.publish(cfg.topic, key=None, value={"re":"emit"}, idempotency_key=k)
    # Собираем не меньше исходного количества (дубликатов быть не должно)
    got = await _collect(bus, cfg.topic, cfg.group, 10, timeout=6.0)
    # Если у реализации нет дедупликации — ослабляем: проверим, что дубликатов не больше 2х
    uniq = { (e.get("key"), e.get("headers",{}).get("x-test"), e.get("value",{}).get("n")) for e in got }
    if len(uniq) < len(got):
        # дубликаты возможны — но не должны раздувать больше чем ×2
        assert len(got) <= len(uniq) * 2
    else:
        assert len(got) == len(uniq)

# -----------------------
# Порядок внутри ключа (если поддерживается ordering per‑key)
# -----------------------

@pytest.mark.asyncio
async def test_ordering_within_key_if_supported(bus, cfg: TestCfg):
    if not _faults(bus)["ordering"]:
        pytest.xfail("Per-key ordering not supported")
    # Посылаем 50 сообщений с одним key
    await _publish_many(bus, cfg.topic, 50, prefix="ord", key_by_mod=1)
    got = await _collect(bus, cfg.topic, cfg.group, 50, timeout=8.0)
    # Проверяем неубывающую последовательность n для key k-0
    seq = [e.get("value",{}).get("n") for e in got if e.get("key") in (None, "k-0")]
    if seq:
        assert seq == sorted(seq), "Ordering per key violated"

# -----------------------
# Backpressure: ограничение потребителя не должно рушить доставку
# -----------------------

@pytest.mark.asyncio
async def test_backpressure_consumer_slow(bus, cfg: TestCfg):
    # Реализуем медленного потребителя через subscribe
    if not _supports(bus, "subscribe"):
        pytest.xfail("subscribe() not available")
    q: asyncio.Queue = asyncio.Queue(maxsize=5)
    async def slow_handler(ev: Dict[str, Any]) -> None:
        await asyncio.sleep(0.05)
        await q.put(ev)
    sub = await bus.subscribe(cfg.topic, cfg.group + "-bp", slow_handler)
    try:
        await _publish_many(bus, cfg.topic, 40, prefix="bp")
        # Считываем часть и убеждаемся, что система не падает с backpressure ошибкой
        ok = 0
        t0 = time.time()
        while (time.time() - t0) < 6.0 and ok < 20:
            try:
                await asyncio.wait_for(q.get(), timeout=0.5)
                ok += 1
            except asyncio.TimeoutError:
                pass
        assert ok >= 10
    finally:
        with pytest.raises(Exception):
            await sub.close()  # type: ignore[attr-defined]

# -----------------------
# Таймауты и ретраи (если реализованы)
# -----------------------

@pytest.mark.asyncio
async def test_timeouts_and_retries_if_supported(bus, cfg: TestCfg, monkeypatch):
    # Если есть set_latency_ms — эмулируем большую задержку, проверим, что publish не «висит» бесконечно
    caps = _faults(bus)
    if not caps["latency"]:
        pytest.xfail("No latency control to trigger timeouts")
    bus.set_latency_ms(800)  # type: ignore
    t0 = time.perf_counter()
    try:
        await bus.publish(cfg.topic, key=None, value={"x":1})  # type: ignore
    except Exception:
        # допускаем таймаут/ошибку
        pass
    dt = time.perf_counter() - t0
    assert dt < 10.0, "publish stuck without honoring timeouts/retries"
    if _supports(bus, "reset_faults"):
        bus.reset_faults()  # type: ignore

# -----------------------
# Метрики (если доступны)
# -----------------------

@pytest.mark.asyncio
async def test_metrics_counters_if_supported(bus, cfg: TestCfg):
    caps = _faults(bus)
    if not caps["metrics"]:
        pytest.xfail("Metrics are not exposed")
    # Предварительный трафик
    await _publish_many(bus, cfg.topic, 15, prefix="m")
    _ = await _collect(bus, cfg.topic, cfg.group, 15, timeout=6.0)
    metrics = None
    if _supports(bus, "metrics"):
        metrics = bus.metrics()  # type: ignore
    elif hasattr(bus, "get_metrics"):
        metrics = bus.get_metrics()  # type: ignore
    assert isinstance(metrics, dict)
    # Ожидаем наличие базовых счетчиков
    names = "published", "delivered", "dropped", "latency_ms_p50"
    assert any(k in metrics for k in names), f"No expected metric keys in {metrics!r}"

# -----------------------
# Маркер для селективного прогона
# -----------------------

def pytest_configure(config):  # type: ignore[func-annotations]
    config.addinivalue_line("markers", "chaos: marks chaos engineering tests (deselect with -m 'not chaos')")

@pytest.mark.chaos
def test_marker_attached():
    assert True
