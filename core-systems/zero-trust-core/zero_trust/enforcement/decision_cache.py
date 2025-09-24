# zero-trust-core/zero_trust/enforcement/decision_cache.py
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple

# --------------------------------------------------------------------------------------
# Конфигурация и публичные типы
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class DecisionCacheConfig:
    """
    Конфигурация кэша решений PDP.
    """
    namespace: str = "zt"                       # соль для ключей
    max_entries: int = 100_000                  # верхний предел элементов LRU
    default_ttl_seconds: int = 300              # TTL для ALLOW/CONDITIONAL/ISOLATE/STEP_UP
    deny_ttl_seconds: int = 60                  # TTL для DENY/ERROR (короче)
    stale_while_revalidate_seconds: int = 0     # окно возврата "устаревшего" решения (0 = запрет)
    hash_algo: str = "blake2b"                  # blake2b/sha256
    key_version: int = 1                        # версия алгоритма формирования ключа

@dataclass
class CachedDecision:
    """
    Хранимое решение PDP.
    """
    key: str
    payload: Dict[str, Any]                     # JSON-совместимое решение (EnforcementDecision/Response)
    effect: str                                 # ALLOW/DENY/STEP_UP/ISOLATE/CONDITIONAL/ERROR
    tenant: Optional[str]
    tags: Set[str] = field(default_factory=set) # произвольные теги для инвалидации
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    soft_expire_at: float = 0.0                 # created_at + ttl + swr (если включен)

@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale_hits: int = 0
    sets: int = 0
    evictions: int = 0

class CacheEntryState:
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"

# --------------------------------------------------------------------------------------
# Вспомогательные функции
# --------------------------------------------------------------------------------------

def _canonical_json(data: Any) -> str:
    """
    Детерминированный JSON без пробелов и с отсортированными ключами.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _hash_bytes(data: bytes, algo: str = "blake2b") -> str:
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    # blake2b короче и быстрее, достаточно 16 байт для кэша
    h = hashlib.blake2b(digest_size=16)
    h.update(data)
    return h.hexdigest()

def _bucketize(val: Optional[float | int], bounds: Tuple[int, ...]) -> int:
    """
    Превращает число в бакет по порогам. Например, bounds=(10,40,70) -> 0/1/2/3.
    """
    if val is None:
        return -1
    for i, b in enumerate(bounds):
        if val <= b:
            return i
    return len(bounds)

def _as_mapping(obj: Any) -> Mapping[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, Mapping):
        return obj
    # Pydantic/BaseModel
    if hasattr(obj, "model_dump"):
        return obj.model_dump()  # type: ignore[attr-defined]
    # Dataclass
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError("unsupported request object type for key normalization")

# --------------------------------------------------------------------------------------
# Формирование ключа кэша из EnforcementRequest (или эквивалента)
# --------------------------------------------------------------------------------------

class DecisionKeyBuilder:
    """
    Строит устойчивый кэш‑ключ из "сущностно значимых" полей EnforcementRequest.
    Игнорирует requestId, traceId и прочие эфемерные атрибуты.
    """

    @staticmethod
    def build(
        request: Mapping[str, Any] | Any,
        *,
        namespace: str = "zt",
        hash_algo: str = "blake2b",
        version: int = 1,
    ) -> Tuple[str, Dict[str, Any], Optional[str]]:
        """
        Возвращает (key, normalized_view, tenant).
        """
        req = _as_mapping(request)
        n = DecisionKeyBuilder._normalize(req, version=version)
        tenant = n.get("tenant")
        raw = f"ns={namespace};v={version};{_canonical_json(n)}".encode("utf-8")
        key = _hash_bytes(raw, algo=hash_algo)
        return key, n, tenant  # type: ignore[return-value]

    @staticmethod
    def _normalize(req: Mapping[str, Any], *, version: int) -> Dict[str, Any]:
        # Поля верхнего уровня
        tenant = req.get("tenant")
        subject = _as_mapping(req.get("subject"))
        identity = _as_mapping(subject.get("identity")) if subject else {}
        resource = _as_mapping(req.get("resource"))
        action = _as_mapping(req.get("action"))
        context = _as_mapping(req.get("context"))

        # Нормализация списков/множества → отсортированный список
        def _sorted_list(v: Any) -> List[Any]:
            if v is None:
                return []
            if isinstance(v, (list, tuple, set)):
                return sorted(v)
            return [v]

        # Извлекаем релевантные поля
        groups = _sorted_list(subject.get("groups"))
        roles = _sorted_list(subject.get("roles"))

        # Device posture (только устойчивые флаги)
        device = _as_mapping(context.get("device"))
        dev_profile = device.get("profile")
        edr_healthy = device.get("edrHealthy")
        disk_enc = device.get("diskEncryption")
        secure_boot = device.get("secureBoot")
        patch_days = device.get("osPatchStalenessDays")

        # TLS и зона
        tls = _as_mapping(context.get("tls"))
        mtls = tls.get("clientAuth")

        network = _as_mapping(context.get("network"))
        zone = network.get("zone")
        geo = network.get("geoCountry")

        # Идентичность
        aal = identity.get("aal")
        mfa_methods = _sorted_list(identity.get("mfaMethods"))

        # Approvals/Break-glass
        approvals = _sorted_list(context.get("approvals"))
        break_glass = _as_mapping(context.get("breakGlass")).get("active") if context.get("breakGlass") else None

        # Риск: используем бакет, а не точное значение
        risk = _as_mapping(context.get("risk"))
        risk_total_bucket = _bucketize(risk.get("total"), (10, 20, 30, 40, 50, 70, 90))

        # Ресурс/действие
        app = resource.get("app")
        resid = resource.get("resourceId")
        labels = _sorted_list(resource.get("labels"))
        sensitivity = resource.get("sensitivity")

        act_type = action.get("type")
        method = str(action.get("method") or "").upper() or None
        path = action.get("path") or None

        # Цель использования
        pou = _sorted_list(req.get("purposeOfUse"))

        # На случай провалов типизации — простая маскировка None → отсутствие поля
        view: Dict[str, Any] = {
            "tenant": tenant,
            "sub": {
                "type": subject.get("type"),
                "uid": subject.get("userId") or subject.get("serviceId"),
                "groups": groups,
                "roles": roles,
                "aal": aal,
                "mfa": mfa_methods,
            },
            "res": {
                "app": app,
                "id": resid,
                "labels": labels,
                "sens": sensitivity,
            },
            "act": {
                "type": act_type,
                "method": method,
                "path": path,
            },
            "ctx": {
                "mtls": mtls,
                "zone": zone,
                "geo": geo,
                "dev": {
                    "profile": dev_profile,
                    "edr": edr_healthy,
                    "disk": disk_enc,
                    "boot": secure_boot,
                    "patch_bucket": _bucketize(patch_days, (0, 3, 14, 30, 60, 120)),
                },
                "risk_bucket": risk_total_bucket,
                "approvals": approvals,
                "breakglass": break_glass,
            },
            "pou": pou,
        }

        # Удалим None/пустые контейнеры для стабильности
        def _prune(x: Any) -> Any:
            if isinstance(x, dict):
                return {k: _prune(v) for k, v in x.items() if v not in (None, [], {}, "")}
            if isinstance(x, list):
                return [ _prune(v) for v in x if v not in (None, [], {}, "") ]
            return x

        return _prune(view)

# --------------------------------------------------------------------------------------
# Основной LRU+TTL кэш с single-flight и инвалидацией по тегам
# --------------------------------------------------------------------------------------

ComputeFn = Callable[[], Awaitable[Tuple[Dict[str, Any], int]]]
# compute() -> (payload, ttl_seconds)

class DecisionCache:
    """
    Безопасный кэш решений PDP.
    - LRU + TTL с отрицательным кэшированием
    - Single-flight: параллельные запросы на один ключ объединяются
    - Инвалидация по тегам/политике/субъекту/приложению/арендатору
    - Опциональный stale-while-revalidate
    """

    def __init__(self, cfg: Optional[DecisionCacheConfig] = None) -> None:
        self.cfg = cfg or DecisionCacheConfig()
        self._lru: "OrderedDict[str, CachedDecision]" = OrderedDict()
        self._tags_index: Dict[str, Set[str]] = defaultdict(set)  # tag -> {key}
        self._tenant_index: Dict[str, Set[str]] = defaultdict(set)
        self._policy_index: Dict[str, Set[str]] = defaultdict(set)
        self._subject_index: Dict[str, Set[str]] = defaultdict(set)  # subject composite -> keys
        self._inflight: Dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()
        self.stats = CacheStats()

    # ------------------------------- Публичный API -------------------------------

    async def get(self, key: str, *, now: Optional[float] = None) -> Tuple[Optional[CachedDecision], str]:
        """
        Возвращает (entry, state), где state ∈ {fresh, stale, expired}.
        """
        now = now or time.time()
        async with self._lock:
            entry = self._lru.get(key)
            if entry is None:
                self.stats.misses += 1
                return None, CacheEntryState.EXPIRED

            # Переместим в хвост LRU
            self._lru.move_to_end(key)

            if now < entry.expires_at:
                self.stats.hits += 1
                return entry, CacheEntryState.FRESH

            if self.cfg.stale_while_revalidate_seconds > 0 and now < entry.soft_expire_at:
                self.stats.stale_hits += 1
                return entry, CacheEntryState.STALE

            # просрочено без S‑W‑R
            self.stats.misses += 1
            return None, CacheEntryState.EXPIRED

    async def set(
        self,
        key: str,
        payload: Dict[str, Any],
        *,
        ttl_seconds: Optional[int],
        tenant: Optional[str],
        tags: Optional[Iterable[str]] = None,
    ) -> CachedDecision:
        """
        Сохраняет решение с TTL/тегами, возвращает созданную запись.
        """
        now = time.time()
        effect = str(payload.get("effect") or payload.get("decision", {}).get("effect") or "ALLOW")
        ttl = int(ttl_seconds or self._ttl_for_effect(effect))
        expires_at = now + max(0, ttl)
        soft_expire_at = expires_at + max(0, self.cfg.stale_while_revalidate_seconds)

        entry = CachedDecision(
            key=key,
            payload=payload,
            effect=effect,
            tenant=tenant,
            tags=set(tags or []),
            created_at=now,
            expires_at=expires_at,
            soft_expire_at=soft_expire_at,
        )

        async with self._lock:
            # вставка/обновление
            if key in self._lru:
                self._remove_indices(self._lru[key])
            self._lru[key] = entry
            self._lru.move_to_end(key)
            self._add_indices(entry)
            self.stats.sets += 1
            await self._enforce_capacity_locked()

        return entry

    async def get_or_compute(
        self,
        request: Mapping[str, Any] | Any,
        compute: ComputeFn,
        *,
        allow_stale: bool = True,
        attach_tags: Optional[Iterable[str]] = None,
        policy_id: Optional[str] = None,
        subject_key: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], CacheEntryState, str]:
        """
        Универсальный путь: получить решение из кэша, при необходимости вычислить.
        - request: EnforcementRequest (или эквивалент)
        - compute: coroutine, возвращающая (payload, ttl_seconds)
        - allow_stale: разрешить возврат устаревшего решения, если S‑W‑R включён
        - attach_tags: доп. теги для инвалидации (например, ["app:payments","policy:xyz"])
        - policy_id: если известно, построим индекс политики
        - subject_key: если известно (например, "tenant:user:123"), индексируем по субъекту
        """
        key, normalized, tenant = DecisionKeyBuilder.build(
            request, namespace=self.cfg.namespace, hash_algo=self.cfg.hash_algo, version=self.cfg.key_version
        )

        # Попробуем кэш
        entry, state = await self.get(key)
        if entry and (state == CacheEntryState.FRESH or (state == CacheEntryState.STALE and allow_stale)):
            return entry.payload, state, key

        # Single-flight: один compute на ключ
        async with self._lock:
            fut = self._inflight.get(key)
            if fut is None:
                fut = asyncio.get_event_loop().create_future()
                self._inflight[key] = fut

        if not fut.done():
            try:
                payload, ttl = await compute()
                # Проставим теги: tenant, app, policy, subject
                tags = set(attach_tags or [])
                app = (
                    (_as_mapping(request).get("resource") or {}).get("app")
                    if isinstance(request, Mapping) else None
                )
                if tenant:
                    tags.add(f"tenant:{tenant}")
                if app:
                    tags.add(f"app:{app}")
                if policy_id:
                    tags.add(f"policy:{policy_id}")
                if subject_key:
                    tags.add(f"sub:{subject_key}")

                await self.set(key, payload, ttl_seconds=ttl, tenant=tenant, tags=tags)
                fut.set_result((payload, CacheEntryState.FRESH))
            except Exception as ex:
                # Не удалось вычислить — очистим inflight и пробросим
                try:
                    fut.set_exception(ex)
                finally:
                    async with self._lock:
                        self._inflight.pop(key, None)
                raise
            else:
                # Уберём inflight
                async with self._lock:
                    self._inflight.pop(key, None)

        # Результат из single-flight
        payload, st = await fut
        return payload, st, key

    # ------------------------------- Инвалидация --------------------------------

    async def invalidate_by_tag(self, tag: str) -> int:
        """
        Инвалидация по одному тегу. Возвращает число удалённых записей.
        """
        async with self._lock:
            keys = list(self._tags_index.get(tag, set()))
            for k in keys:
                self._delete_locked(k)
            return len(keys)

    async def invalidate_by_policy(self, policy_id: str) -> int:
        return await self.invalidate_by_tag(f"policy:{policy_id}")

    async def invalidate_by_subject(self, tenant: str, subject_id: str) -> int:
        # Композитный ключ субъекта
        return await self.invalidate_by_tag(f"sub:{tenant}:{subject_id}")

    async def invalidate_by_app(self, app: str) -> int:
        return await self.invalidate_by_tag(f"app:{app}")

    async def invalidate_by_tenant(self, tenant: str) -> int:
        return await self.invalidate_by_tag(f"tenant:{tenant}")

    async def invalidate_all(self) -> int:
        async with self._lock:
            n = len(self._lru)
            self._lru.clear()
            self._tags_index.clear()
            self._tenant_index.clear()
            self._policy_index.clear()
            self._subject_index.clear()
            return n

    # ------------------------------- Вспомогательное ----------------------------

    def _ttl_for_effect(self, effect: str) -> int:
        eff = (effect or "").upper()
        if eff in ("DENY", "ERROR"):
            return self.cfg.deny_ttl_seconds
        return self.cfg.default_ttl_seconds

    async def _enforce_capacity_locked(self) -> None:
        while len(self._lru) > self.cfg.max_entries:
            # Выселим самый старый (голова OrderedDict)
            k, _ = self._lru.popitem(last=False)
            self.stats.evictions += 1
            # Индексы подчистим
            # (запись уже удалена из LRU, но нужна копия для индексов)
            # Без попытки получить её повторно.
            # Для простоты индексы пересобираем через _remove_indices_if_present:
            # (но у нас нет entry) — игнорируем: индексы чистятся в _delete_locked
            # поэтому перед popitem лучше использовать _delete_locked.
            # Пересделаем корректно: вернём назад и удалим через _delete_locked.
            pass  # исправим ниже

    def _add_indices(self, entry: CachedDecision) -> None:
        for t in entry.tags:
            self._tags_index[t].add(entry.key)
            # Дополнительные индексы по префиксам
            if t.startswith("tenant:"):
                self._tenant_index[t.split(":", 1)[1]].add(entry.key)
            elif t.startswith("policy:"):
                self._policy_index[t.split(":", 1)[1]].add(entry.key)
            elif t.startswith("sub:"):
                self._subject_index[t.split(":", 1)[1]].add(entry.key)

    def _remove_indices(self, entry: CachedDecision) -> None:
        for t in list(entry.tags):
            keys = self._tags_index.get(t)
            if keys:
                keys.discard(entry.key)
                if not keys:
                    self._tags_index.pop(t, None)
            if t.startswith("tenant:"):
                k = t.split(":", 1)[1]
                s = self._tenant_index.get(k)
                if s:
                    s.discard(entry.key)
                    if not s:
                        self._tenant_index.pop(k, None)
            elif t.startswith("policy:"):
                k = t.split(":", 1)[1]
                s = self._policy_index.get(k)
                if s:
                    s.discard(entry.key)
                    if not s:
                        self._policy_index.pop(k, None)
            elif t.startswith("sub:"):
                k = t.split(":", 1)[1]
                s = self._subject_index.get(k)
                if s:
                    s.discard(entry.key)
                    if not s:
                        self._subject_index.pop(k, None)

    def _delete_locked(self, key: str) -> None:
        entry = self._lru.pop(key, None)
        if entry:
            self._remove_indices(entry)
            self.stats.evictions += 1

    # Исправленная реализация контроля ёмкости
    async def _enforce_capacity_locked(self) -> None:  # type: ignore[no-redef]
        while len(self._lru) > self.cfg.max_entries:
            k = next(iter(self._lru.keys()))
            self._delete_locked(k)

# --------------------------------------------------------------------------------------
# Утилиты для интеграции: построение subject_key и tag‑наборов
# --------------------------------------------------------------------------------------

def build_subject_key(tenant: Optional[str], request: Mapping[str, Any] | Any) -> Optional[str]:
    """
    Возвращает "tenant:user_or_service" для индексации по субъекту.
    """
    req = _as_mapping(request)
    sub = _as_mapping(req.get("subject"))
    uid = sub.get("userId") or sub.get("serviceId")
    if not tenant or not uid:
        return None
    return f"{tenant}:{uid}"

def default_tags(tenant: Optional[str], request: Mapping[str, Any] | Any, *, policy_id: Optional[str] = None) -> Set[str]:
    req = _as_mapping(request)
    res = _as_mapping(req.get("resource"))
    app = res.get("app")
    tags: Set[str] = set()
    if tenant:
        tags.add(f"tenant:{tenant}")
    if app:
        tags.add(f"app:{app}")
    if policy_id:
        tags.add(f"policy:{policy_id}")
    subj = build_subject_key(tenant, request)
    if subj:
        tags.add(f"sub:{subj}")
    return tags

# --------------------------------------------------------------------------------------
# Пример использования (докстринг)
# --------------------------------------------------------------------------------------

__doc__ = """
Пример интеграции в PEP:

    cache = DecisionCache(DecisionCacheConfig(max_entries=20000, default_ttl_seconds=300, deny_ttl_seconds=60))

    async def evaluate_with_cache(request_json: dict) -> dict:
        async def compute():
            # здесь вызываем PDP
            resp = await call_pdp(request_json)          # -> dict с 'effect', 'decisionTtlSeconds', ...
            ttl = int(resp.get("decisionTtlSeconds", 0)) or None
            return resp, ttl

        payload, state, key = await cache.get_or_compute(
            request_json,
            compute,
            allow_stale=True,
            attach_tags=default_tags(tenant=request_json.get("tenant"), request=request_json, policy_id=None),
            policy_id=None,
            subject_key=build_subject_key(request_json.get("tenant"), request_json),
        )
        # state: 'fresh'/'stale' — можно проставить X-Cache: HIT/STH/...
        return payload

Инвалидация:

    await cache.invalidate_by_policy("payments_requires_strong_identity")
    await cache.invalidate_by_subject("acme", "user:123")
    await cache.invalidate_by_app("git_forge")
    await cache.invalidate_by_tenant("acme")
    await cache.invalidate_all()
"""

__all__ = [
    "DecisionCacheConfig",
    "CachedDecision",
    "CacheStats",
    "CacheEntryState",
    "DecisionKeyBuilder",
    "DecisionCache",
    "build_subject_key",
    "default_tags",
]
