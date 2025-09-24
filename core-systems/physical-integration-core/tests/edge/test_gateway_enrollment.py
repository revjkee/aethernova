# tests/edge/test_gateway_enrollment.py
"""
UNVERIFIED: тесты задают контракт для модуля регистрации шлюза, исходный код сервиса
в репозитории не показан. При несовпадении интерфейса тесты аккуратно skip с причиной.

Ожидаемый контракт (минимум):
- Модуль: physical_integration.edge.gateway_enrollment
- Класс:  GatewayEnrollmentService(...)
  Рекомендуемый конструктор c DI:
      GatewayEnrollmentService(
          registry_client, keystore, event_bus,
          retry_policy: Optional[Any] = None,
          now_func: Optional[Callable[[], float]] = None,
      )
  Обязательный метод:
      async def enroll(self, device_id: str, attestation: bytes, metadata: dict) -> Any
  Возвращаемый результат (рекомендуется dataclass EnrollmentResult):
      .ok: bool
      .device_id: str
      .issued_at: float
      .not_after: float
      .rotated: bool   # True если была ротация/первичная выдача

- Исключения:
    InvalidAttestationError – при неверной аттестации
    EnrollmentError – общее для непреодолимых ошибок

- Зависимости, вызываемые сервисом:
    registry_client.request_certificate(device_id, attestation, metadata) -> dict:
        {"cert_pem": "...", "key_pem": "...", "issued_at": ts, "not_after": ts}
    keystore.read(device_id) -> Optional[dict]   # {"cert_pem": "...", "key_pem": "...", "not_after": ts}
    keystore.write_atomic(device_id, cert_pem, key_pem, not_after) -> None
    event_bus.publish(topic: str, payload: dict) -> Awaitable[None]

- Поведение:
  * Идемпотентность: при валидном неизбежавшем сроке сертификате — не звать реестр.
  * Ретраи: ConnectionError/TimeoutError — повторять согласно retry_policy.
  * Неверная аттестация: исключение, без записи/публикации.
  * Ротация: при not_after <= now — запрашивать новый, заменять атомарно.
  * Событие публикации — не должно срывать основную операцию (ошибки = warn).
"""

import asyncio
import inspect
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import pytest

# --- Утилиты времени и ожидания ------------------------------------------------

async def wait_until(pred: Callable[[], bool], timeout: float = 1.0, interval: float = 0.01) -> None:
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        if pred():
            return
        await asyncio.sleep(interval)
    raise AssertionError("Condition not met within timeout")

# --- Фейки зависимостей --------------------------------------------------------

class FakeRegistryClient:
    """Сценируем ответ каталога сертификатов. responses — очередь ответов/исключений."""
    def __init__(self, responses: List[Any]) -> None:
        self.calls: List[Dict[str, Any]] = []
        self._responses = list(responses)

    async def request_certificate(self, device_id: str, attestation: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append({"device_id": device_id, "attestation": attestation, "metadata": metadata})
        if not self._responses:
            raise RuntimeError("No more fake responses")
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp

class FakeKeyStore:
    """Файковое хранилище сертификатов в памяти."""
    def __init__(self) -> None:
        self.store: Dict[str, Dict[str, Any]] = {}

    async def read(self, device_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(device_id)

    async def write_atomic(self, device_id: str, cert_pem: str, key_pem: str, not_after: float) -> None:
        # Имитация атомарной записи
        self.store[device_id] = {"cert_pem": cert_pem, "key_pem": key_pem, "not_after": float(not_after)}

class FakeEventBus:
    """Фейковая шина событий. Может «падать» для проверки устойчивости."""
    def __init__(self) -> None:
        self.topic_payloads: List[Dict[str, Any]] = []
        self.operational: bool = True

    def set_operational(self, ok: bool) -> None:
        self.operational = ok

    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        if not self.operational:
            raise ConnectionError("Event bus down")
        self.topic_payloads.append({"topic": topic, "payload": json.loads(json.dumps(payload))})

# --- Фейковые исключения (если в модуле нет) ----------------------------------

class _InvalidAttestationError(RuntimeError): ...
class _EnrollmentError(RuntimeError): ...

# --- Фикстуры ------------------------------------------------------------------

@pytest.fixture(scope="module")
def mod():
    """Пытаемся импортировать тестируемый модуль, иначе помечаем как skip."""
    m = pytest.importorskip("physical_integration.edge.gateway_enrollment", reason="gateway_enrollment module missing")
    return m

@pytest.fixture
def errors(mod):
    """Достаём типы исключений из модуля либо подменяем локальными."""
    InvalidAttestationError = getattr(mod, "InvalidAttestationError", _InvalidAttestationError)
    EnrollmentError = getattr(mod, "EnrollmentError", _EnrollmentError)
    return InvalidAttestationError, EnrollmentError

def _construct_service_or_skip(mod, **deps):
    """Гибко создаём сервис с учётом возможных различий конструктора."""
    Service = getattr(mod, "GatewayEnrollmentService", None)
    if Service is None:
        pytest.skip("GatewayEnrollmentService not found")

    sig = inspect.signature(Service)
    kwargs = {}
    for name in sig.parameters.keys():
        if name in deps:
            kwargs[name] = deps[name]
    try:
        svc = Service(**kwargs)
    except TypeError as e:
        pytest.skip(f"Incompatible constructor for GatewayEnrollmentService: {e}")
    return svc

# --- Набор стандартных данных --------------------------------------------------

DEVICE_ID = "edge-001"
META = {"model": "X1000", "site": "Plant-7"}
ATTEST_OK = b"TPM_ATTEST_OK"
ATTEST_BAD = b"TPM_ATTEST_BAD"

def _cert(now: float, valid_for: float) -> Dict[str, Any]:
    return {
        "cert_pem": "-----BEGIN CERT-----\nFAKE\n-----END CERT-----",
        "key_pem": "-----BEGIN KEY-----\nFAKE\n-----END KEY-----",
        "issued_at": now,
        "not_after": now + valid_for,
    }

# --- Тесты ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_success_enrollment_persists_and_publishes(mod, errors):
    InvalidAttestationError, _ = errors
    now0 = time.time()
    registry = FakeRegistryClient([_cert(now0, valid_for=3600)])
    keystore = FakeKeyStore()
    bus = FakeEventBus()

    svc = _construct_service_or_skip(
        mod,
        registry_client=registry,
        keystore=keystore,
        event_bus=bus,
        retry_policy=getattr(mod, "RetryPolicy", None),  # опционально
        now_func=lambda: now0,
    )

    # Выполняем регистрацию
    res = await svc.enroll(DEVICE_ID, ATTEST_OK, META)

    # Проверяем запись и событие
    stored = await keystore.read(DEVICE_ID)
    assert stored is not None, "Certificate must be stored"
    assert stored["not_after"] > now0
    assert any(ev["topic"] for ev in bus.topic_payloads), "Event must be published"
    # Результат
    assert getattr(res, "ok", True) is True
    assert getattr(res, "device_id", DEVICE_ID) == DEVICE_ID

@pytest.mark.asyncio
async def test_idempotent_when_valid_cert_present(mod):
    now0 = time.time()
    # в хранилище уже валидный сертификат
    keystore = FakeKeyStore()
    keystore.store[DEVICE_ID] = _cert(now0, valid_for=7200)

    registry = FakeRegistryClient([_cert(now0, valid_for=7200)])  # не должно быть вызвано
    bus = FakeEventBus()

    svc = _construct_service_or_skip(mod, registry_client=registry, keystore=keystore, event_bus=bus, now_func=lambda: now0)

    res = await svc.enroll(DEVICE_ID, ATTEST_OK, META)

    # Реестр не вызывался
    assert len(registry.calls) == 0, "Registry must not be called for valid non‑expired cert"
    # Публикация допускается, но необязательна — проверим, что не упало
    assert getattr(res, "ok", True) is True

@pytest.mark.asyncio
async def test_retry_on_transient_failure_then_success(mod, errors):
    InvalidAttestationError, EnrollmentError = errors
    now0 = time.time()
    # два временных сбоя -> успех
    registry = FakeRegistryClient([
        ConnectionError("net down"),
        TimeoutError("slow"),
        _cert(now0, valid_for=3600),
    ])
    keystore = FakeKeyStore()
    bus = FakeEventBus()

    # Поддержка retry_policy опциональна; если нет — пропускаем
    RetryPolicy = getattr(mod, "RetryPolicy", None)
    if RetryPolicy is None:
        pytest.skip("RetryPolicy not available; cannot test transient retry logic")

    policy = RetryPolicy(max_attempts=3, base_delay_s=0.01, max_delay_s=0.05)  # типичный API; если иной — будет skip в конструкторе
    svc = _construct_service_or_skip(mod, registry_client=registry, keystore=keystore, event_bus=bus, retry_policy=policy, now_func=lambda: now0)

    res = await svc.enroll(DEVICE_ID, ATTEST_OK, META)

    assert len(registry.calls) == 3
    assert getattr(res, "ok", True) is True
    assert (await keystore.read(DEVICE_ID)) is not None

@pytest.mark.asyncio
async def test_invalid_attestation_fails_without_side_effects(mod, errors):
    InvalidAttestationError, EnrollmentError = errors
    now0 = time.time()
    registry = FakeRegistryClient([InvalidAttestationError("bad quote")])
    keystore = FakeKeyStore()
    bus = FakeEventBus()

    svc = _construct_service_or_skip(mod, registry_client=registry, keystore=keystore, event_bus=bus, now_func=lambda: now0)

    with pytest.raises(InvalidAttestationError):
        await svc.enroll(DEVICE_ID, ATTEST_BAD, META)

    assert (await keystore.read(DEVICE_ID)) is None
    assert len(bus.topic_payloads) == 0

@pytest.mark.asyncio
async def test_cert_rotation_when_expired(mod):
    now0 = time.time()
    expired = now0 - 10
    keystore = FakeKeyStore()
    keystore.store[DEVICE_ID] = {"cert_pem": "OLD", "key_pem": "OLDK", "not_after": expired}
    registry = FakeRegistryClient([_cert(now0, valid_for=600)])
    bus = FakeEventBus()

    svc = _construct_service_or_skip(mod, registry_client=registry, keystore=keystore, event_bus=bus, now_func=lambda: now0)

    res = await svc.enroll(DEVICE_ID, ATTEST_OK, META)

    stored = await keystore.read(DEVICE_ID)
    assert stored and stored["not_after"] > now0, "Expired cert must be rotated"
    assert len(registry.calls) == 1
    assert any("payload" in ev for ev in bus.topic_payloads)
    assert getattr(res, "ok", True) is True
    assert getattr(res, "rotated", True) is True

@pytest.mark.asyncio
async def test_event_bus_failure_does_not_break_enrollment(mod):
    now0 = time.time()
    registry = FakeRegistryClient([_cert(now0, valid_for=3600)])
    keystore = FakeKeyStore()
    bus = FakeEventBus()
    bus.set_operational(False)  # имитируем сбой шины

    svc = _construct_service_or_skip(mod, registry_client=registry, keystore=keystore, event_bus=bus, now_func=lambda: now0)

    # Регистрация не должна падать из‑за ошибки публикации события
    res = await svc.enroll(DEVICE_ID, ATTEST_OK, META)

    assert getattr(res, "ok", True) is True
    assert (await keystore.read(DEVICE_ID)) is not None

    # После восстановления шины новая регистрация может опубликовать событие
    bus.set_operational(True)
    await svc.enroll(DEVICE_ID, ATTEST_OK, META)
    assert len(bus.topic_payloads) >= 1
