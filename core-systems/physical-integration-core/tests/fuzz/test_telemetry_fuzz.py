# -*- coding: utf-8 -*-
import asyncio
import contextlib
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Tuple

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

# Импортируем адаптер и локальный транспорт без внешних брокеров
from physical_integration.adapters.cloud_iot_adapter import (
    CloudIoTAdapter,
    CloudIoTConfig,
    AuthConfig,
    TLSConfig,
    TopicTemplates,
    LocalTransport,
)

# -----------------------
# Вспомогательные утилиты
# -----------------------

def _canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    # В адаптере используется ensure_ascii=False, separators=(",", ":"), sort_keys=True
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _hmac_hex(secret: str, body: bytes, alg: str = "sha256") -> str:
    digest = getattr(hashlib, alg)
    return hmac.new(secret.encode("utf-8"), body, digest).hexdigest()

async def _make_adapter(hmac_secret: str | None = None) -> Tuple[CloudIoTAdapter, LocalTransport]:
    cfg = CloudIoTConfig(
        provider="test",
        endpoint="local",
        port=0,
        client_id="test-client",
        tls=TLSConfig(enable=False),
        auth=AuthConfig(hmac_secret=hmac_secret) if hmac_secret else AuthConfig(),
        allow_local_fallback=True,
    )
    transport = LocalTransport()
    adapter = CloudIoTAdapter(config=cfg, transport=transport)
    await adapter.connect()
    return adapter, transport

# Перехват телеметрии с помощью подписки на локальном транспорте
async def _subscribe_capture_telemetry(transport: LocalTransport):
    queue: asyncio.Queue[Tuple[str, bytes]] = asyncio.Queue()

    async def handler(topic: str, payload: bytes):
        await queue.put((topic, payload))

    await transport.subscribe("devices/+/telemetry", handler)
    return queue

# -------------
# Стратегии данных
# -------------

# Скалярные JSON-значения, включая NaN/Inf (допускаются json-модулем Python)
json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10**12, max_value=10**12),
    st.floats(allow_nan=True, allow_infinity=True, width=64),
    st.text(min_size=0, max_size=64),
)

# Рекурсивные структуры JSON с ограничениями по размеру
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(st.text(min_size=0, max_size=32), children, max_size=6),
    ),
    max_leaves=20,
)

# Корректная полезная нагрузка телеметрии — словарь
telemetry_payloads = st.dictionaries(
    keys=st.text(min_size=0, max_size=32),
    values=json_values,
    max_size=8,
)

device_ids = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="-_",
    ),
    min_size=1,
    max_size=32,
)

# Невалидные (несерилизуемые) вложенные значения
non_serializable_payloads = st.sampled_from([
    {"bad": bytes(b"\x00\xff")},
    {"bad": {1, 2, 3}},
    {"bad": object()},
])


# -----------------------
# Тест 1: Fuzz-схема конверта
# -----------------------
@pytest.mark.asyncio
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(dev_id=device_ids, payload=telemetry_payloads)
async def test_publish_telemetry_envelope_fuzz(dev_id: str, payload: Dict[str, Any]):
    adapter, transport = await _make_adapter(None)
    q = await _subscribe_capture_telemetry(transport)

    try:
        await adapter.register_device(dev_id)
        t0 = int(time.time() * 1000)
        await adapter.publish_telemetry(dev_id, payload)
        topic, raw = await asyncio.wait_for(q.get(), timeout=1.0)
        t1 = int(time.time() * 1000)

        # Проверяем тему
        assert topic == f"devices/{dev_id}/telemetry"

        # Парсим конверт
        env = json.loads(raw.decode("utf-8"))
        assert env["device_id"] == dev_id
        assert env["type"] == "telemetry"
        assert "payload" in env
        # ts в разумном временном окне (+/- 5 секунд)
        assert isinstance(env["ts"], int)
        assert (t0 - 5000) <= env["ts"] <= (t1 + 5000)
    finally:
        with contextlib.suppress(Exception):
            await adapter.disconnect()


# -----------------------
# Тест 2: HMAC-подпись и канонизация
# -----------------------
@pytest.mark.asyncio
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(dev_id=device_ids, payload=telemetry_payloads)
async def test_publish_telemetry_hmac_signature(dev_id: str, payload: Dict[str, Any]):
    secret = "top-secret-key"
    adapter, transport = await _make_adapter(secret)
    q = await _subscribe_capture_telemetry(transport)

    try:
        await adapter.register_device(dev_id)
        await adapter.publish_telemetry(dev_id, payload)
        _, raw = await asyncio.wait_for(q.get(), timeout=1.0)
        env = json.loads(raw.decode("utf-8"))

        # Подпись присутствует
        assert "sig" in env and "value" in env["sig"] and env["sig"].get("alg", "sha256") == "sha256"

        # Пересчитываем подпись поверх канонизированного объекта без поля sig
        clone = dict(env)
        clone.pop("sig", None)
        body = _canonical_json_bytes(clone)
        expected = _hmac_hex(secret, body, "sha256")
        assert hmac.compare_digest(expected, env["sig"]["value"])
    finally:
        with contextlib.suppress(Exception):
            await adapter.disconnect()


# -----------------------
# Тест 3: Несерилизуемые значения должны приводить к контролируемой ошибке
# -----------------------
@pytest.mark.asyncio
@settings(max_examples=3, deadline=None)
@given(dev_id=device_ids, payload=non_serializable_payloads)
async def test_publish_telemetry_non_serializable_raises(dev_id: str, payload: Dict[str, Any]):
    adapter, _ = await _make_adapter(None)
    try:
        await adapter.register_device(dev_id)
        with pytest.raises(TypeError):
            await adapter.publish_telemetry(dev_id, payload)
    finally:
        with contextlib.suppress(Exception):
            await adapter.disconnect()


# -----------------------
# Тест 4: Конкурентная отправка сотен сообщений и полная доставка
# -----------------------
@pytest.mark.asyncio
async def test_publish_telemetry_concurrent_delivery():
    adapter, transport = await _make_adapter(None)
    q = await _subscribe_capture_telemetry(transport)
    dev_id = "dev-concurrent"

    try:
        await adapter.register_device(dev_id)

        count = 200
        # Подготовим разные полезные нагрузки
        tasks = []
        for i in range(count):
            payload = {"seq": i, "v": i * 1.5}
            tasks.append(adapter.publish_telemetry(dev_id, payload))

        await asyncio.gather(*tasks)

        # Собираем все сообщения
        received = 0
        seq_seen = set()
        try:
            for _ in range(count):
                _, raw = await asyncio.wait_for(q.get(), timeout=2.0)
                env = json.loads(raw.decode("utf-8"))
                assert env["device_id"] == dev_id
                assert env["type"] == "telemetry"
                seq_seen.add(env["payload"]["seq"])
                received += 1
        except asyncio.TimeoutError:
            pass

        assert received == count
        assert len(seq_seen) == count
    finally:
        with contextlib.suppress(Exception):
            await adapter.disconnect()
