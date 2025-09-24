# security-core/security/workers/key_rotation_worker.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

logger = logging.getLogger("security_core.workers.key_rotation")


# ============================== Вспомогательные утилиты ==============================

def _now_s() -> int:
    return int(time.time())

def _with_jitter(base_s: float, factor: float = 0.2) -> float:
    d = base_s * factor
    return max(0.0, base_s - d + random.random() * 2.0 * d)


# ============================== Протоколы интеграции ==============================

class MetricsHook(Protocol):
    def __call__(self, name: str, tags: Mapping[str, Any]) -> None: ...


class KeyAdminClient(Protocol):
    """
    Минимальный интерфейс административных операций провайдера KMS.
    name_ref: canonical 'keys/{key}[/versions/{v}]'
    """
    async def create_new_version(self, name_ref: str, *, algorithm: Optional[str] = None, key_params: Optional[Mapping[str, Any]] = None) -> str: ...
    async def set_primary_version(self, name_ref: str, *, version_id: str) -> None: ...
    async def disable_version(self, name_ref: str, *, version_id: str) -> None: ...
    async def schedule_destroy(self, name_ref: str, *, version_id: str, after_days: int = 7) -> None: ...
    async def list_versions(self, name_ref: str) -> Sequence[Mapping[str, Any]]: ...
    async def close(self) -> None: ...


class LockManager(Protocol):
    """
    Дистрибутивная блокировка по ключу.
    """
    async def acquire(self, key: str, ttl_s: int) -> bool: ...
    async def release(self, key: str) -> None: ...


class RotationStateStore(Protocol):
    """
    Персистентное состояние ротации ключей.
    """
    async def get(self, key: str) -> Optional[Mapping[str, Any]]: ...
    async def put(self, key: str, state: Mapping[str, Any]) -> None: ...
    async def delete(self, key: str) -> None: ...


# ============================== Опциональные реализации (Redis) ==============================

try:
    from redis.asyncio import Redis  # type: ignore
    _HAVE_REDIS = True
except Exception:  # pragma: no cover
    _HAVE_REDIS = False  # type: ignore


class InMemoryLockManager:
    def __init__(self) -> None:
        self._locks: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, key: str, ttl_s: int) -> bool:
        async with self._lock:
            now = time.time()
            exp = self._locks.get(key)
            if exp is not None and exp > now:
                return False
            self._locks[key] = now + ttl_s
            return True

    async def release(self, key: str) -> None:
        async with self._lock:
            self._locks.pop(key, None)


class RedisLockManager:
    def __init__(self, redis: "Redis", prefix: str = "sec:rotlock") -> None:  # type: ignore[name-defined]
        if not _HAVE_REDIS:
            raise RuntimeError("redis.asyncio is required for RedisLockManager")
        self.r = redis
        self.prefix = prefix

    async def acquire(self, key: str, ttl_s: int) -> bool:
        k = f"{self.prefix}:{key}"
        ok = await self.r.set(k, "1", nx=True, ex=max(1, ttl_s))
        return bool(ok)

    async def release(self, key: str) -> None:
        await self.r.delete(f"{self.prefix}:{key}")


class InMemoryStateStore(RotationStateStore):
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    async def get(self, key: str) -> Optional[Mapping[str, Any]]:
        return self._store.get(key)

    async def put(self, key: str, state: Mapping[str, Any]) -> None:
        self._store[key] = dict(state)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


# ============================== Конфигурация ротации ==============================

class Phase(Enum):
    STEADY = "STEADY"            # стабильное состояние (один primary, старые активны для verify)
    NEW_VERSION = "NEW_VERSION"  # создана новая версия
    PROMOTED = "PROMOTED"        # новая версия промотирована в primary
    DECOMMISSION = "DECOMMISSION"# начата деактивация старых
    DONE = "DONE"                # цикл завершён


@dataclass(frozen=True)
class KeyConfig:
    tenant: str
    name_ref: str                   # 'keys/{key}' или 'keys/{key}/versions/{v}'
    algorithm: str                  # RS256/PS256/ES256/EdDSA/...
    rotate_every_s: int             # целевой криптопериод
    grace_verify_s: int             # окно совместимости для verify старой версии
    deactivate_after_s: int         # через сколько после PROMOTED деактивировать старую версию
    destroy_after_s: int            # через сколько после деактивации планировать уничтожение
    min_age_s: int = 0              # минимальный возраст текущего primary перед новой ротацией
    destroy_grace_days: int = 14    # отложенное уничтожение в днях
    params: Mapping[str, Any] = field(default_factory=dict)  # дополнительные параметры создания ключа


@dataclass
class RotationState:
    phase: Phase = Phase.STEADY
    last_rotated_at: int = 0
    current_primary_version: Optional[str] = None
    previous_primary_version: Optional[str] = None
    new_version: Optional[str] = None
    promoted_at: Optional[int] = None
    decommission_started_at: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["phase"] = self.phase.value
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "RotationState":
        return RotationState(
            phase=Phase(d.get("phase", "STEADY")),
            last_rotated_at=int(d.get("last_rotated_at", 0)),
            current_primary_version=d.get("current_primary_version"),
            previous_primary_version=d.get("previous_primary_version"),
            new_version=d.get("new_version"),
            promoted_at=d.get("promoted_at"),
            decommission_started_at=d.get("decommission_started_at"),
        )


# ============================== sec‑kms HTTP админ‑клиент (опционально) ==============================

try:
    import httpx  # type: ignore
    _HAVE_HTTPX = True
except Exception:  # pragma: no cover
    _HAVE_HTTPX = False  # type: ignore


class SecKmsAdminClient(KeyAdminClient):
    """
    Административный клиент внутреннего sec‑kms API (HTTP).
    Ожидаемые эндпойнты:
        POST {base}/{name_ref}:rotate
        POST {base}/{name_ref}:setPrimary   body: {"version":"..."}
        POST {base}/{name_ref}:disable      body: {"version":"..."}
        POST {base}/{name_ref}:scheduleDestroy body: {"version":"...","after_days":int}
        GET  {base}/{name_ref}/versions
    """
    def __init__(self, base_url: str, token: Optional[str] = None, timeout_s: float = 5.0) -> None:
        if not _HAVE_HTTPX:
            raise RuntimeError("httpx is required for SecKmsAdminClient")
        self.base = base_url.rstrip("/")
        self.token = token
        self.cli = httpx.AsyncClient(timeout=timeout_s)

    def _h(self) -> Dict[str, str]:
        h = {"accept": "application/json"}
        if self.token:
            h["authorization"] = f"Bearer {self.token}"
        return h

    async def create_new_version(self, name_ref: str, *, algorithm: Optional[str] = None, key_params: Optional[Mapping[str, Any]] = None) -> str:
        url = f"{self.base}/{name_ref}:rotate"
        body = {"algorithm": algorithm, "key_params": dict(key_params or {})}
        r = await self.cli.post(url, json=body, headers=self._h())
        r.raise_for_status()
        v = r.json().get("version") or r.json().get("name_ref", "").split("/")[-1]
        return str(v)

    async def set_primary_version(self, name_ref: str, *, version_id: str) -> None:
        url = f"{self.base}/{name_ref}:setPrimary"
        r = await self.cli.post(url, json={"version": version_id}, headers=self._h())
        r.raise_for_status()

    async def disable_version(self, name_ref: str, *, version_id: str) -> None:
        url = f"{self.base}/{name_ref}:disable"
        r = await self.cli.post(url, json={"version": version_id}, headers=self._h())
        r.raise_for_status()

    async def schedule_destroy(self, name_ref: str, *, version_id: str, after_days: int = 7) -> None:
        url = f"{self.base}/{name_ref}:scheduleDestroy"
        r = await self.cli.post(url, json={"version": version_id, "after_days": after_days}, headers=self._h())
        r.raise_for_status()

    async def list_versions(self, name_ref: str) -> Sequence[Mapping[str, Any]]:
        url = f"{self.base}/{name_ref}/versions"
        r = await self.cli.get(url, headers=self._h())
        r.raise_for_status()
        js = r.json()
        # Ожидаемый формат: [{"version":"1","state":"PRIMARY","created_at":...}, ...]
        return list(js)

    async def close(self) -> None:
        await self.cli.aclose()


# ============================== Реестр ключей (источник правды) ==============================

class KeyRegistry(Protocol):
    async def list_key_configs(self) -> Sequence[KeyConfig]: ...


class StaticKeyRegistry:
    """
    Примитивный реестр из заданного списка KeyConfig.
    """
    def __init__(self, keys: Sequence[KeyConfig]) -> None:
        self._keys = list(keys)

    async def list_key_configs(self) -> Sequence[KeyConfig]:
        return list(self._keys)


# ============================== Воркфлоу ротации ==============================

@dataclass
class WorkerConfig:
    loop_interval_s: int = 30
    lock_ttl_s: int = 60
    max_concurrency: int = 8
    base_backoff_s: float = 0.2
    max_attempts: int = 5
    # sec-kms интеграция (если используется HTTP админ-клиент)
    seckms_base_url: Optional[str] = None
    seckms_token: Optional[str] = None


class KeyRotationWorker:
    """
    Пошаговая безопасная ротация:
      1) NEW_VERSION: создать новую версию
      2) PROMOTED: сделать новую версию primary (подписываем новым, проверяем также старым)
      3) DECOMMISSION: по истечении grace деактивировать старую версию
      4) DONE: запланировать уничтожение старой версии, фиксация состояния → STEADY
    """
    def __init__(
        self,
        *,
        registry: KeyRegistry,
        admin_client: Optional[KeyAdminClient] = None,
        state_store: Optional[RotationStateStore] = None,
        lock_manager: Optional[LockManager] = None,
        metrics: Optional[MetricsHook] = None,
        cfg: Optional[WorkerConfig] = None,
        on_changed: Optional[Callable[[KeyConfig, RotationState], Awaitable[None]]] = None,  # колбэк после изменений (например, публикация JWKS)
    ) -> None:
        self.cfg = cfg or WorkerConfig()
        self.registry = registry
        self.admin = admin_client or (SecKmsAdminClient(self.cfg.seckms_base_url or "", self.cfg.seckms_token) if self.cfg.seckms_base_url else None)
        if self.admin is None:
            raise RuntimeError("KeyAdminClient is required (e.g., SecKmsAdminClient)")
        self.state = state_store or InMemoryStateStore()
        self.locks = lock_manager or InMemoryLockManager()
        self.metrics = metrics
        self.on_changed = on_changed

    async def run_forever(self) -> None:
        sem = asyncio.Semaphore(self.cfg.max_concurrency)
        while True:
            try:
                cfgs = await self.registry.list_key_configs()
            except Exception as e:
                logger.exception("registry_error: %s", e)
                await asyncio.sleep(_with_jitter(self.cfg.loop_interval_s))
                continue

            tasks = []
            for kc in cfgs:
                tasks.append(asyncio.create_task(self._with_sem(sem, self._process_key, kc)))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            await asyncio.sleep(_with_jitter(self.cfg.loop_interval_s))

    async def run_once(self) -> None:
        cfgs = await self.registry.list_key_configs()
        sem = asyncio.Semaphore(self.cfg.max_concurrency)
        await asyncio.gather(*(self._with_sem(sem, self._process_key, kc) for kc in cfgs), return_exceptions=True)

    async def _with_sem(self, sem: asyncio.Semaphore, fn: Callable[[KeyConfig], Awaitable[None]], kc: KeyConfig) -> None:
        async with sem:
            await fn(kc)

    # ----------------------------- Основной цикл по ключу -----------------------------

    async def _process_key(self, kc: KeyConfig) -> None:
        lock_key = f"rot:{kc.tenant}:{kc.name_ref}"
        if not await self.locks.acquire(lock_key, self.cfg.lock_ttl_s):
            return
        try:
            await self._metric("rotation_check_begin", {"tenant": kc.tenant, "key": kc.name_ref})
            state = await self._load_state(kc)
            action = await self._decide_action(kc, state)
            if action is None:
                await self._metric("rotation_noop", {"tenant": kc.tenant, "key": kc.name_ref})
                return
            await self._execute_action(kc, state, action)
            await self._save_state(kc, state)
            if self.on_changed:
                try:
                    await self.on_changed(kc, state)
                except Exception as e:
                    logger.warning("on_changed callback failed: %s", e)
            await self._metric("rotation_action", {"tenant": kc.tenant, "key": kc.name_ref, "phase": state.phase.value})
        except Exception as e:
            await self._metric("rotation_error", {"tenant": kc.tenant, "key": kc.name_ref, "err": type(e).__name__})
            logger.exception("rotation_error for %s: %s", kc.name_ref, e)
        finally:
            await self.locks.release(lock_key)

    async def _load_state(self, kc: KeyConfig) -> RotationState:
        key = self._state_key(kc)
        raw = await self.state.get(key)
        if raw:
            return RotationState.from_dict(raw)
        # Инициализация из провайдера: узнаем primary и его версию
        versions = await self._retry(lambda: self.admin.list_versions(kc.name_ref))
        primary = None
        for v in versions:
            if str(v.get("state")).upper() == "PRIMARY":
                primary = str(v.get("version"))
                break
        st = RotationState(
            phase=Phase.STEADY,
            last_rotated_at=_now_s(),
            current_primary_version=primary,
            previous_primary_version=None,
            new_version=None,
            promoted_at=None,
            decommission_started_at=None,
        )
        await self.state.put(key, st.to_dict())
        return st

    async def _save_state(self, kc: KeyConfig, st: RotationState) -> None:
        await self.state.put(self._state_key(kc), st.to_dict())

    def _state_key(self, kc: KeyConfig) -> str:
        return f"{kc.tenant}|{kc.name_ref}"

    # ----------------------------- Принятие решения -----------------------------

    async def _decide_action(self, kc: KeyConfig, st: RotationState) -> Optional[str]:
        now = _now_s()
        # STEADY: проверяем срок криптопериода и минимальный возраст primary
        if st.phase == Phase.STEADY:
            age = now - int(st.last_rotated_at or now)
            if age >= kc.rotate_every_s and age >= kc.min_age_s:
                return "create_new_version"
            return None

        # NEW_VERSION: ждём немедленную промоцию
        if st.phase == Phase.NEW_VERSION and st.new_version:
            return "promote_new_version"

        # PROMOTED: ждём grace_verify_s до начала деактивации старой версии
        if st.phase == Phase.PROMOTED and st.promoted_at:
            if now - int(st.promoted_at) >= kc.deactivate_after_s:
                return "start_decommission"
            return None

        # DECOMMISSION: планируем уничтожение и завершаем цикл
        if st.phase == Phase.DECOMMISSION and st.decommission_started_at:
            if now - int(st.decommission_started_at) >= kc.destroy_after_s:
                return "schedule_destroy_and_finish"
            return None

        # DONE: откат в STEADY (fail‑safe)
        if st.phase == Phase.DONE:
            st.phase = Phase.STEADY
            return None

        return None

    # ----------------------------- Исполнение действий -----------------------------

    async def _execute_action(self, kc: KeyConfig, st: RotationState, action: str) -> None:
        if action == "create_new_version":
            v = await self._retry(lambda: self.admin.create_new_version(kc.name_ref, algorithm=kc.algorithm, key_params=kc.params))
            st.new_version = v
            st.phase = Phase.NEW_VERSION
            return

        if action == "promote_new_version":
            assert st.new_version, "new_version is required"
            await self._retry(lambda: self.admin.set_primary_version(kc.name_ref, version_id=st.new_version or ""))
            st.previous_primary_version = st.current_primary_version
            st.current_primary_version = st.new_version
            st.promoted_at = _now_s()
            st.last_rotated_at = st.promoted_at
            st.phase = Phase.PROMOTED
            return

        if action == "start_decommission":
            if st.previous_primary_version:
                # Старая версия остаётся доступной для verify; переводим в 'DISABLED' для sign/encrypt
                await self._retry(lambda: self.admin.disable_version(kc.name_ref, version_id=st.previous_primary_version or ""))
                st.decommission_started_at = _now_s()
                st.phase = Phase.DECOMMISSION
            else:
                # Нечего деактивировать
                st.phase = Phase.DONE
            return

        if action == "schedule_destroy_and_finish":
            if st.previous_primary_version:
                await self._retry(lambda: self.admin.schedule_destroy(kc.name_ref, version_id=st.previous_primary_version or "", after_days=max(1, kc.destroy_grace_days)))
            # Завершение цикла
            st.previous_primary_version = None
            st.new_version = None
            st.promoted_at = None
            st.decommission_started_at = None
            st.phase = Phase.DONE
            return

        raise RuntimeError(f"unknown_action:{action}")

    # ----------------------------- Ретрай с бэкоффом -----------------------------

    async def _retry(self, fn: Callable[[], Awaitable[Any]]) -> Any:
        last: Optional[BaseException] = None
        for i in range(self.cfg.max_attempts):
            try:
                return await fn()
            except Exception as e:  # pragma: no cover
                last = e
                await asyncio.sleep(_with_jitter(self.cfg.base_backoff_s * (2 ** i)))
        assert last is not None
        raise last

    async def _metric(self, name: str, tags: Mapping[str, Any]) -> None:
        try:
            if self.metrics:
                self.metrics(name, tags)
        except Exception:
            pass


# ============================== Пример подключения ==============================

"""
Пример (псевдо):

# 1) Реестр ключей (обычно из БД/конфига):
keys = [
    KeyConfig(
        tenant="tenantA",
        name_ref="keys/tenantA/my-signing-key",
        algorithm="EdDSA",
        rotate_every_s=7*24*3600,
        grace_verify_s=24*3600,
        deactivate_after_s=24*3600,
        destroy_after_s=7*24*3600,
        min_age_s=24*3600,
        destroy_grace_days=14,
        params={"curve": "Ed25519"}
    ),
    KeyConfig(
        tenant="tenantB",
        name_ref="keys/tenantB/kms-rsa",
        algorithm="RS256",
        rotate_every_s=30*24*3600,
        grace_verify_s=7*24*3600,
        deactivate_after_s=7*24*3600,
        destroy_after_s=30*24*3600,
        params={"modulus_bits": 2048, "public_exponent": 65537}
    ),
]

registry = StaticKeyRegistry(keys)

# 2) Админ-клиент sec-kms:
admin = SecKmsAdminClient(base_url="https://kms.internal/api/v1/tenants/tenantA", token="...")

# 3) Состояние/блокировки/метрики:
state_store = InMemoryStateStore()
lock_mgr = InMemoryLockManager()
metrics = lambda name, tags: print(name, dict(tags))

# 4) Колбэк (например, публикация JWKS после промоции):
async def on_changed(kc: KeyConfig, st: RotationState) -> None:
    if st.phase in (Phase.NEW_VERSION, Phase.PROMOTED, Phase.DECOMMISSION, Phase.DONE):
        # здесь обновите кэш JWKS/конфигов сервисов
        pass

worker = KeyRotationWorker(
    registry=registry,
    admin_client=admin,
    state_store=state_store,
    lock_manager=lock_mgr,
    metrics=metrics,
)

# Запуск единичного прохода:
# asyncio.run(worker.run_once())

# Или фоновый цикл:
# asyncio.run(worker.run_forever())
"""
