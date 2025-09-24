# physical-integration-core/tests/integration/test_ota_flow.py
import asyncio
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Tuple, Optional

import pytest

from physical_integration.workers.firmware_rollout_worker import (
    RolloutSettings,
    FileStore,
    FirmwareRolloutWorker,
    FirmwareRolloutJob,
    FirmwareArtifact,
    DeviceDescriptor,
    RolloutWave,
    GateMode,
    DeviceState,
    JobStatus,
    DeviceClient,
)

# ----------------------------- Фейковые клиенты устройств -----------------------------

class AlwaysOKClient(DeviceClient):
    async def precheck(self, d: DeviceDescriptor, art: FirmwareArtifact) -> Tuple[bool, str]:
        await asyncio.sleep(0.01)
        return True, "ok"

    async def start_update(self, d: DeviceDescriptor, art: FirmwareArtifact, token: str) -> Tuple[bool, str]:
        await asyncio.sleep(0.01)
        return True, "started"

    async def poll_status(self, d: DeviceDescriptor, token: str, timeout_sec: float, interval_sec: float) -> Tuple[bool, str]:
        await asyncio.sleep(0.02)
        return True, "done"

    async def rollback(self, d: DeviceDescriptor, token: str) -> Tuple[bool, str]:
        return True, "rollback ok"


class AlwaysFailStartClient(DeviceClient):
    async def precheck(self, d: DeviceDescriptor, art: FirmwareArtifact) -> Tuple[bool, str]:
        return True, "ok"

    async def start_update(self, d: DeviceDescriptor, art: FirmwareArtifact, token: str) -> Tuple[bool, str]:
        await asyncio.sleep(0.01)
        return False, "start refused"

    async def poll_status(self, d: DeviceDescriptor, token: str, timeout_sec: float, interval_sec: float) -> Tuple[bool, str]:
        return False, "not used"

    async def rollback(self, d: DeviceDescriptor, token: str) -> Tuple[bool, str]:
        return True, "rollback ok"


class ConcurrencyProbeClient(DeviceClient):
    """
    Клиент для измерения фактического уровня параллелизма.
    """
    def __init__(self, delay: float = 0.1):
        self.current = 0
        self.peak = 0
        self.delay = delay
        self._lock = asyncio.Lock()

    async def precheck(self, d: DeviceDescriptor, art: FirmwareArtifact) -> Tuple[bool, str]:
        return True, "ok"

    async def start_update(self, d: DeviceDescriptor, art: FirmwareArtifact, token: str) -> Tuple[bool, str]:
        async with self._lock:
            self.current += 1
            self.peak = max(self.peak, self.current)
        await asyncio.sleep(self.delay)
        async with self._lock:
            self.current -= 1
        return True, "started"

    async def poll_status(self, d: DeviceDescriptor, token: str, timeout_sec: float, interval_sec: float) -> Tuple[bool, str]:
        await asyncio.sleep(self.delay)
        return True, "done"

    async def rollback(self, d: DeviceDescriptor, token: str) -> Tuple[bool, str]:
        return True, "rollback ok"


# ----------------------------- Утилиты тестов ---------------------------------

async def wait_for(predicate, timeout: float = 10.0, interval: float = 0.05):
    start = time.time()
    while time.time() - start < timeout:
        if await predicate():
            return True
        await asyncio.sleep(interval)
    return False

def make_artifact(tmp_path, size: int = 32, set_hash: Optional[str] = None) -> FirmwareArtifact:
    blob = os.urandom(size)
    p = tmp_path / "fw.bin"
    p.write_bytes(blob)
    h = hashlib.sha256(blob).hexdigest()
    return FirmwareArtifact(
        url=f"file://{p}",
        version="1.0.0",
        sha256=set_hash or h,
        size_bytes=size,
    )

def make_devices(n: int) -> List[DeviceDescriptor]:
    return [
        DeviceDescriptor(id=f"dev-{i:03d}", endpoint=f"http://127.0.0.1:{8000+i}", model="X1", group="A")
        for i in range(n)
    ]

def make_waves() -> List[RolloutWave]:
    return [
        RolloutWave(name="canary", percentage=10.0, max_concurrency=3, halt_on_failure_ratio=0.5, min_success_ratio_to_proceed=0.7, observe_wait_sec=0.01),
        RolloutWave(name="ramp-50", percentage=50.0, max_concurrency=5, halt_on_failure_ratio=0.4, min_success_ratio_to_proceed=0.8, observe_wait_sec=0.01),
        RolloutWave(name="final", percentage=100.0, max_concurrency=10, halt_on_failure_ratio=0.4, min_success_ratio_to_proceed=0.9, observe_wait_sec=0.0),
    ]


@pytest.fixture
def settings(tmp_path) -> RolloutSettings:
    return RolloutSettings(
        device_request_timeout_sec=2.0,
        device_poll_interval_sec=0.02,
        device_poll_timeout_sec=2.0,
        retries=1,
        backoff_base_sec=0.02,
        backoff_max_sec=0.1,
        max_concurrent_updates=5,
        rate_per_sec=0.0,
        require_signature=False,
        allow_unsigned=True,
        store_dir=str(tmp_path / "store"),
        audit_path=str(tmp_path / "audit.log"),
        metrics_port=None,
    )


@pytest.mark.asyncio
async def test_rollout_success_auto_all_waves(tmp_path, settings):
    store = FileStore(settings.store_dir, settings.audit_path)
    worker = FirmwareRolloutWorker(settings, store, AlwaysOKClient())
    await worker.start()

    art = make_artifact(tmp_path)
    devices = make_devices(20)
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=make_waves(), gate_mode=GateMode.AUTO)
    job_id = await worker.submit_job(job)

    async def finished_ok():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED)

    assert await wait_for(finished_ok, timeout=10.0)
    j = await store.load_job(job_id)
    assert j.status == JobStatus.SUCCEEDED
    assert sum(1 for s in j.device_states.values() if s == DeviceState.SUCCEEDED) == len(devices)


@pytest.mark.asyncio
async def test_rollout_halt_on_failures(tmp_path, settings):
    store = FileStore(settings.store_dir, settings.audit_path)
    # Клиент всегда валит старт — первая волна должна быть остановлена по порогу
    worker = FirmwareRolloutWorker(settings, store, AlwaysFailStartClient())
    await worker.start()

    art = make_artifact(tmp_path)
    devices = make_devices(10)
    waves = [RolloutWave(name="canary", percentage=50.0, max_concurrency=5, halt_on_failure_ratio=0.2, min_success_ratio_to_proceed=0.9, observe_wait_sec=0.01)]
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=waves, gate_mode=GateMode.AUTO)
    job_id = await worker.submit_job(job)

    async def halted():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.HALTED, JobStatus.FAILED)

    assert await wait_for(halted, timeout=5.0)
    j = await store.load_job(job_id)
    # В нашем коде при остановке волны мы помечаем job как HALTED
    assert j.status == JobStatus.HALTED
    # Дальше волны нет
    assert j.current_wave_index == 0


@pytest.mark.asyncio
async def test_manual_gate_flow(tmp_path, settings):
    store = FileStore(settings.store_dir, settings.audit_path)
    worker = FirmwareRolloutWorker(settings, store, AlwaysOKClient())
    await worker.start()

    art = make_artifact(tmp_path)
    devices = make_devices(12)
    waves = make_waves()
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=waves, gate_mode=GateMode.MANUAL)
    job_id = await worker.submit_job(job)

    # Ждём завершения первой волны и остановки на ручном гейте (воркер завершает цикл после волны)
    async def first_wave_done_and_waiting():
        j = await store.load_job(job_id)
        # После первой волны current_wave_index ещё указывает на текущую волну
        # но цикл прерывается; проверим, что некоторые устройства уже SUCCESS/FAILED
        succ = sum(1 for s in j.device_states.values() if s in (DeviceState.SUCCEEDED, DeviceState.FAILED))
        return succ > 0 and j.status == JobStatus.RUNNING

    assert await wait_for(first_wave_done_and_waiting, timeout=5.0)

    # Разрешаем следующую волну
    await worker.approve_next_wave(job_id)

    async def finished():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED)

    assert await wait_for(finished, timeout=10.0)
    j = await store.load_job(job_id)
    assert j.status == JobStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_artifact_sha256_mismatch_fails_fast(tmp_path, settings):
    store = FileStore(settings.store_dir, settings.audit_path)
    worker = FirmwareRolloutWorker(settings, store, AlwaysOKClient())
    await worker.start()

    # Подсовываем неправильный SHA256
    art = make_artifact(tmp_path, set_hash="0" * 64)
    devices = make_devices(5)
    waves = [RolloutWave(name="canary", percentage=100.0)]
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=waves)
    job_id = await worker.submit_job(job)

    async def finished():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED)

    assert await wait_for(finished, timeout=3.0)
    j = await store.load_job(job_id)
    assert j.status == JobStatus.FAILED
    assert j.notes and "sha256 verification failed" in j.notes


@pytest.mark.asyncio
async def test_concurrency_limit_is_respected(tmp_path, settings):
    # Задаём общий лимит параллелизма 4 и проверяем, что пик не выше
    settings.max_concurrent_updates = 4
    store = FileStore(settings.store_dir, settings.audit_path)
    client = ConcurrencyProbeClient(delay=0.05)
    worker = FirmwareRolloutWorker(settings, store, client)
    await worker.start()

    art = make_artifact(tmp_path)
    devices = make_devices(15)
    waves = [RolloutWave(name="all", percentage=100.0, max_concurrency=4)]
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=waves)
    job_id = await worker.submit_job(job)

    async def finished():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED)

    assert await wait_for(finished, timeout=10.0)
    j = await store.load_job(job_id)
    assert j.status == JobStatus.SUCCEEDED
    assert client.peak <= 4, f"peak concurrency {client.peak} exceeds limit"


# ----------------------------- Опционально: подписи (cryptography) ---------------------

cryptography = pytest.importorskip("cryptography", reason="cryptography not installed", allow_module_level=True)
from cryptography.hazmat.primitives.asymmetric import rsa, padding as _pad
from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser

@pytest.mark.asyncio
async def test_signature_required_valid_passes(tmp_path, settings):
    # Генерируем ключ и подпись метаданных
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()

    blob = os.urandom(64)
    p = tmp_path / "fw_signed.bin"
    p.write_bytes(blob)
    sha = hashlib.sha256(blob).hexdigest()

    meta = json.dumps({"url": f"file://{p}", "version": "9.9.9", "sha256": sha, "size": len(blob)}, sort_keys=True, separators=(",", ":")).encode()
    sig = key.sign(meta, _pad.PKCS1v15(), _hashes.SHA256())

    art = FirmwareArtifact(
        url=f"file://{p}", version="9.9.9", sha256=sha, size_bytes=len(blob),
        signature_b64=__import__("base64").b64encode(sig).decode(),
        public_key_pem=pub_pem,
    )

    settings.require_signature = True
    settings.allow_unsigned = False

    store = FileStore(settings.store_dir, settings.audit_path)
    worker = FirmwareRolloutWorker(settings, store, AlwaysOKClient())
    await worker.start()

    devices = make_devices(6)
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=[RolloutWave(name="all", percentage=100.0)])
    job_id = await worker.submit_job(job)

    async def finished():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED)

    assert await wait_for(finished, timeout=6.0)
    j = await store.load_job(job_id)
    assert j.status == JobStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_signature_required_invalid_fails(tmp_path, settings):
    # Подписываем метаданные для одной версии, а в артефакте укажем другую — подпись станет невалидной
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()

    blob = os.urandom(64)
    p = tmp_path / "fw_bad.bin"
    p.write_bytes(blob)
    sha = hashlib.sha256(blob).hexdigest()

    meta_right = json.dumps({"url": f"file://{p}", "version": "1.0.0", "sha256": sha, "size": len(blob)}, sort_keys=True, separators=(",", ":")).encode()
    sig = key.sign(meta_right, _pad.PKCS1v15(), _hashes.SHA256())

    # Но в артефакте подменим версию — подпись не совпадёт
    art = FirmwareArtifact(
        url=f"file://{p}", version="1.0.1", sha256=sha, size_bytes=len(blob),
        signature_b64=__import__("base64").b64encode(sig).decode(),
        public_key_pem=pub_pem,
    )

    settings.require_signature = True
    settings.allow_unsigned = False

    store = FileStore(settings.store_dir, settings.audit_path)
    worker = FirmwareRolloutWorker(settings, store, AlwaysOKClient())
    await worker.start()

    devices = make_devices(3)
    job = FirmwareRolloutJob(artifact=art, devices=devices, waves=[RolloutWave(name="all", percentage=100.0)])
    job_id = await worker.submit_job(job)

    async def finished():
        j = await store.load_job(job_id)
        return j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED)

    assert await wait_for(finished, timeout=4.0)
    j = await store.load_job(job_id)
    assert j.status == JobStatus.FAILED
    assert j.notes and "signature required" in j.notes
