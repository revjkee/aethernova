# policy_core/adapters/security_core_adapter.py
# Промышленный адаптер интеграции policy-core <-> security-core
# Python 3.11+

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Awaitable, Callable, Dict, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

try:
    # Опциональная интеграция OpenTelemetry
    from opentelemetry import trace as otel_trace  # type: ignore
    _OTEL_TRACER = otel_trace.get_tracer("policy_core.adapters.security_core_adapter")
except Exception:  # pragma: no cover
    class _NoTracer:
        @contextlib.contextmanager
        def start_as_current_span(self, name: str):
            yield
    _OTEL_TRACER = _NoTracer()  # type: ignore


__all__ = [
    "SecurityCoreClientProtocol",
    "DecisionLike",
    "AdapterConfig",
    "ObligationExecutionResult",
    "SecurityCoreAdapter",
    "AdapterError",
    "RetryableError",
    "NotRetryableError",
]

log = logging.getLogger("policy_core.adapters.security_core_adapter")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    log.addHandler(h)
    log.setLevel(logging.INFO)


# ========================== Исключения ==========================

class AdapterError(RuntimeError):
    """Базовая ошибка адаптера."""


class RetryableError(AdapterError):
    """Ошибка, потенциально устранимая повтором."""


class NotRetryableError(AdapterError):
    """Окончательная ошибка (повторы бессмысленны)."""


# ========================== Вспомогательные типы ==========================

class DecisionLike(Protocol):
    """
    Мини-протокол для объяснения решения PDP (совместим с policy_core.pdp.explain.DecisionExplanation).
    Достаточно методов/полей ниже, адаптер бережно извлечёт данные.
    """
    effect: Any

    def to_dict(self) -> Mapping[str, Any]: ...


class SecurityCoreClientProtocol(Protocol):
    """
    Протокол клиента security-core. Реальная реализация может использовать aiohttp/grpc/амqp и т.п.
    Все методы — асинхронные.
    """
    async def get_subject_attributes(self, subject_id: str, *, hint: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]: ...
    async def get_resource_attributes(self, resource_id: str, *, hint: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]: ...
    async def get_risk(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                        action: Mapping[str, Any], environment: Mapping[str, Any]) -> Mapping[str, Any]: ...
    async def audit_decision(self, *, decision: Mapping[str, Any], extra: Optional[Mapping[str, Any]] = None) -> None: ...
    async def ueba_event(self, *, kind: str, payload: Mapping[str, Any]) -> None: ...
    async def enforce(self, *, action: str, subject: Mapping[str, Any], resource: Mapping[str, Any],
                      params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]: ...


# ========================== Конфигурация/кэш ==========================

@dataclass(slots=True)
class AdapterConfig:
    # Таймауты и повторы для вызовов во внешний security-core
    request_timeout_s: float = 2.0
    max_retries: int = 2
    base_backoff_s: float = 0.08
    max_backoff_s: float = 0.8
    jitter_s: float = 0.05

    # Circuit breaker
    cb_fail_threshold: int = 5
    cb_reset_timeout_s: float = 10.0

    # TTL кэша атрибутов/риска
    ttl_subject_s: float = 60.0
    ttl_resource_s: float = 60.0
    ttl_risk_s: float = 5.0

    # Редакция секретов при логировании
    redact_keys: Tuple[str, ...] = ("password", "secret", "token", "api_key", "authorization", "cookie")

    # Dry-run: не исполнять реальные обязательства, а только планировать
    dry_run: bool = False


@dataclass(slots=True)
class _TTLItem:
    value: Any
    exp: float


class _TTLCache:
    """Простой неблокирующий TTL-кэш в памяти с защитой от dogpile (per-key lock)."""

    def __init__(self) -> None:
        self._data: Dict[str, _TTLItem] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._gc_last = 0.0
        self._gc_interval = 30.0

    def _now(self) -> float:
        return time.monotonic()

    def _key_lock(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if not lock:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def get(self, key: str) -> Optional[Any]:
        it = self._data.get(key)
        if it and it.exp > self._now():
            return it.value
        if it:
            self._data.pop(key, None)
        return None

    def set(self, key: str, value: Any, ttl_s: float) -> None:
        self._data[key] = _TTLItem(value=value, exp=self._now() + ttl_s)
        # периодическая чистка
        if self._now() - self._gc_last > self._gc_interval:
            self._gc_last = self._now()
            expired = [k for k, v in self._data.items() if v.exp <= self._gc_last]
            for k in expired:
                self._data.pop(k, None)

    def lock(self, key: str) -> asyncio.Lock:
        return self._key_lock(key)


# ========================== Утилиты/редакция ==========================

def _redact(obj: Any, redact_keys: Sequence[str]) -> Any:
    if isinstance(obj, Mapping):
        return {k: ("***" if str(k).lower() in redact_keys else _redact(v, redact_keys)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        t = type(obj)
        return t(_redact(v, redact_keys) for v in obj)
    if isinstance(obj, str) and len(obj) >= 24:
        return "***"
    return obj


async def _with_timeout(coro: Awaitable[Any], timeout_s: float) -> Any:
    return await asyncio.wait_for(coro, timeout=timeout_s)


async def _retry(
    func: Callable[[], Awaitable[Any]],
    *,
    max_retries: int,
    base_backoff_s: float,
    max_backoff_s: float,
    jitter_s: float,
) -> Any:
    attempt = 0
    delay = base_backoff_s
    while True:
        try:
            return await func()
        except RetryableError as e:
            attempt += 1
            if attempt > max_retries:
                raise
            await asyncio.sleep(min(delay, max_backoff_s) + (jitter_s * (0.5 - time.time() % 1)))
            delay *= 2
            continue


# ========================== Обязательства/исполнение ==========================

class ObligationExecutionStatus(Enum):
    SUCCESS = auto()
    SKIPPED = auto()
    FAILED = auto()


@dataclass(slots=True)
class ObligationExecutionResult:
    name: str
    status: ObligationExecutionStatus
    detail: Optional[str] = None
    payload: Optional[Mapping[str, Any]] = None


# ========================== Адаптер ==========================

class SecurityCoreAdapter:
    """
    Адаптер между policy-core и security-core.
    Задачи:
      - PIP: получить/объединить атрибуты субъекта и ресурса + риск-оценка контекста.
      - Reporting: audit/UEBA решений PDP.
      - PEP obligations: исполнять обязательства, возвращённые PDP.
      - Надёжность: таймауты, ретраи, circuit-breaker, кэш.

    Примечание: адаптер НЕ решает за PDP; он предоставляет данные и исполняет побочные эффекты.
    """

    def __init__(self, client: SecurityCoreClientProtocol, config: Optional[AdapterConfig] = None) -> None:
        self._client = client
        self._cfg = config or AdapterConfig()
        self._cache = _TTLCache()

        # Circuit breaker счетчики
        self._cb_failures = 0
        self._cb_opened_at = 0.0

        # Таблица маршрутизации обязательств -> executor
        self._obligation_handlers: Dict[str, Callable[..., Awaitable[Mapping[str, Any]]]] = {
            "require_mfa": self._ob_mfa,
            "add_watermark": self._ob_watermark,
            "mask_fields": self._ob_mask_fields,
            "rate_limit": self._ob_rate_limit,
            "session_terminate": self._ob_session_terminate,
        }

    # --------------------- Circuit Breaker ---------------------

    def _cb_now(self) -> float:
        return time.monotonic()

    def _cb_is_open(self) -> bool:
        if self._cb_failures < self._cfg.cb_fail_threshold:
            return False
        # Если открыто — проверяем таймаут на полуоткрытое
        return (self._cb_now() - self._cb_opened_at) < self._cfg.cb_reset_timeout_s

    def _cb_on_success(self) -> None:
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    def _cb_on_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_failures >= self._cfg.cb_fail_threshold:
            if self._cb_opened_at == 0.0:
                self._cb_opened_at = self._cb_now()
            log.warning("SecurityCore CB opened: failures=%s", self._cb_failures)

    # --------------------- Внешние методы ---------------------

    async def get_attributes(
        self,
        *,
        subject: Union[str, Mapping[str, Any]],
        resource: Union[str, Mapping[str, Any]],
        action: Mapping[str, Any],
        environment: Optional[Mapping[str, Any]] = None,
        derive: bool = True,
    ) -> Mapping[str, Any]:
        """
        Получить объединённые атрибуты (subject/resource/action/environment) и риск.
        - subject/resource могут быть id либо уже частично заполненными dict'ами.
        - derive=True добавляет производные признаки (например, is_owner).
        """
        environment = environment or {}

        # Идентификаторы
        subject_id = subject if isinstance(subject, str) else str(subject.get("id", ""))
        resource_id = resource if isinstance(resource, str) else str(resource.get("id", ""))

        # Загружаем/кэшируем
        s_attrs = await self._get_subject_cached(subject_id, hint=subject if isinstance(subject, Mapping) else None)
        r_attrs = await self._get_resource_cached(resource_id, hint=resource if isinstance(resource, Mapping) else None)

        # Слияние: входные hint атрибуты усиливают/перекрывают БД
        if isinstance(subject, Mapping):
            s_attrs = {**s_attrs, **dict(subject)}
        if isinstance(resource, Mapping):
            r_attrs = {**r_attrs, **dict(resource)}

        if derive:
            s_attrs, r_attrs = self._derive_features(s_attrs, r_attrs)

        risk = await self._get_risk_cached(subject=s_attrs, resource=r_attrs, action=action, environment=environment)

        return {
            "subject": s_attrs,
            "resource": r_attrs,
            "action": dict(action),
            "environment": dict(environment),
            "risk": risk,
        }

    async def report_decision(
        self,
        *,
        decision: Union[DecisionLike, Mapping[str, Any]],
        extra: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Отправить решение PDP в security-core (audit) + UEBA сигнал.
        Надёжность: таймауты/ретраи/CB. Ошибки логируются, но не пробрасываются наружу.
        """
        if self._cb_is_open():
            log.warning("SecurityCore CB open: skip report_decision")
            return

        # Приведение к dict
        if hasattr(decision, "to_dict"):
            d: Mapping[str, Any] = decision.to_dict()  # type: ignore
        elif isinstance(decision, Mapping):
            d = decision
        else:
            d = {"effect": getattr(decision, "effect", "Unknown")}  # best-effort

        red_decision = _redact(d, self._cfg.redact_keys)
        red_extra = _redact(extra or {}, self._cfg.redact_keys)

        async def _call():
            with _OTEL_TRACER.start_as_current_span("sec.audit_decision"):
                await _with_timeout(
                    self._client.audit_decision(decision=red_decision, extra=red_extra),
                    self._cfg.request_timeout_s,
                )
                # UEBA side-channel (best-effort)
                try:
                    await _with_timeout(
                        self._client.ueba_event(kind="pdp_decision", payload={"decision": red_decision, "extra": red_extra}),
                        self._cfg.request_timeout_s,
                    )
                except Exception as ue:
                    log.debug("UEBA event failed (ignored): %s", ue)

        try:
            await _retry(_call, max_retries=self._cfg.max_retries, base_backoff_s=self._cfg.base_backoff_s,
                         max_backoff_s=self._cfg.max_backoff_s, jitter_s=self._cfg.jitter_s)
            self._cb_on_success()
        except Exception as e:
            self._cb_on_failure()
            log.warning("report_decision failed: %s", e)

    async def enforce_obligations(
        self,
        *,
        obligations: Sequence[Mapping[str, Any]],
        subject: Mapping[str, Any],
        resource: Mapping[str, Any],
    ) -> Sequence[ObligationExecutionResult]:
        """
        Исполнить обязательства, возвращённые PDP. В dry_run возвращает план без реального вызова.
        Неуспех отдельного обязательства не прерывает обработку остальных.
        """
        results: list[ObligationExecutionResult] = []

        for ob in obligations:
            name = str(ob.get("name") or ob.get("id") or "")
            params = ob.get("params") or {}
            handler = self._obligation_handlers.get(name)
            if not handler:
                results.append(ObligationExecutionResult(name=name, status=ObligationExecutionStatus.SKIPPED,
                                                         detail="no_handler"))
                continue

            if self._cfg.dry_run:
                results.append(ObligationExecutionResult(name=name, status=ObligationExecutionStatus.SKIPPED,
                                                         detail="dry_run"))
                continue

            try:
                with _OTEL_TRACER.start_as_current_span(f"sec.obligation:{name}"):
                    payload = await _retry(
                        lambda: _with_timeout(handler(subject=subject, resource=resource, params=params),
                                              self._cfg.request_timeout_s),
                        max_retries=self._cfg.max_retries,
                        base_backoff_s=self._cfg.base_backoff_s,
                        max_backoff_s=self._cfg.max_backoff_s,
                        jitter_s=self._cfg.jitter_s,
                    )
                results.append(ObligationExecutionResult(name=name, status=ObligationExecutionStatus.SUCCESS,
                                                         payload=payload))
                self._cb_on_success()
            except NotRetryableError as e:
                self._cb_on_failure()
                log.warning("Obligation '%s' failed (no-retry): %s", name, e)
                results.append(ObligationExecutionResult(name=name, status=ObligationExecutionStatus.FAILED,
                                                         detail=str(e)))
            except Exception as e:
                self._cb_on_failure()
                log.warning("Obligation '%s' failed: %s", name, e)
                results.append(ObligationExecutionResult(name=name, status=ObligationExecutionStatus.FAILED,
                                                         detail=str(e)))

        return results

    # --------------------- Частные методы: загрузка/кэш ---------------------

    async def _get_subject_cached(self, subject_id: str, *, hint: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
        if not subject_id:
            return dict(hint or {})
        key = f"subject:{subject_id}"
        cached = self._cache.get(key)
        if cached:
            return dict(cached)

        async with self._cache.lock(key):
            cached = self._cache.get(key)
            if cached:
                return dict(cached)

            if self._cb_is_open():
                log.warning("SecurityCore CB open: return hint for subject")
                return dict(hint or {})

            async def _call():
                with _OTEL_TRACER.start_as_current_span("sec.get_subject_attributes"):
                    return await _with_timeout(
                        self._client.get_subject_attributes(subject_id, hint=hint),
                        self._cfg.request_timeout_s,
                    )

            try:
                data = await _retry(_call, max_retries=self._cfg.max_retries, base_backoff_s=self._cfg.base_backoff_s,
                                    max_backoff_s=self._cfg.max_backoff_s, jitter_s=self._cfg.jitter_s)
                self._cache.set(key, data, self._cfg.ttl_subject_s)
                self._cb_on_success()
                return dict(data)
            except Exception as e:
                self._cb_on_failure()
                log.warning("get_subject_attributes failed (%s), using hint", e)
                return dict(hint or {})

    async def _get_resource_cached(self, resource_id: str, *, hint: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
        if not resource_id:
            return dict(hint or {})
        key = f"resource:{resource_id}"
        cached = self._cache.get(key)
        if cached:
            return dict(cached)

        async with self._cache.lock(key):
            cached = self._cache.get(key)
            if cached:
                return dict(cached)

            if self._cb_is_open():
                log.warning("SecurityCore CB open: return hint for resource")
                return dict(hint or {})

            async def _call():
                with _OTEL_TRACER.start_as_current_span("sec.get_resource_attributes"):
                    return await _with_timeout(
                        self._client.get_resource_attributes(resource_id, hint=hint),
                        self._cfg.request_timeout_s,
                    )

            try:
                data = await _retry(_call, max_retries=self._cfg.max_retries, base_backoff_s=self._cfg.base_backoff_s,
                                    max_backoff_s=self._cfg.max_backoff_s, jitter_s=self._cfg.jitter_s)
                self._cache.set(key, data, self._cfg.ttl_resource_s)
                self._cb_on_success()
                return dict(data)
            except Exception as e:
                self._cb_on_failure()
                log.warning("get_resource_attributes failed (%s), using hint", e)
                return dict(hint or {})

    async def _get_risk_cached(
        self,
        *,
        subject: Mapping[str, Any],
        resource: Mapping[str, Any],
        action: Mapping[str, Any],
        environment: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        # Ключ из «существенных» частей
        digest = hashlib.sha256(
            json.dumps(
                {"s": subject.get("id"), "r": resource.get("id"), "a": action.get("op"), "env": environment.get("ip")},
                ensure_ascii=False, sort_keys=True
            ).encode("utf-8")
        ).hexdigest()
        key = f"risk:{digest}"
        cached = self._cache.get(key)
        if cached:
            return dict(cached)

        async with self._cache.lock(key):
            cached = self._cache.get(key)
            if cached:
                return dict(cached)

            if self._cb_is_open():
                log.warning("SecurityCore CB open: return default risk")
                return {"score": 0.0, "level": "low", "default": True}

            async def _call():
                with _OTEL_TRACER.start_as_current_span("sec.get_risk"):
                    return await _with_timeout(
                        self._client.get_risk(subject=subject, resource=resource, action=action, environment=environment),
                        self._cfg.request_timeout_s,
                    )

            try:
                data = await _retry(_call, max_retries=self._cfg.max_retries, base_backoff_s=self._cfg.base_backoff_s,
                                    max_backoff_s=self._cfg.max_backoff_s, jitter_s=self._cfg.jitter_s)
                self._cache.set(key, data, self._cfg.ttl_risk_s)
                self._cb_on_success()
                return dict(data)
            except Exception as e:
                self._cb_on_failure()
                log.warning("get_risk failed (%s), using default low risk", e)
                return {"score": 0.0, "level": "low", "default": True}

    # --------------------- Производные признаки ---------------------

    def _derive_features(
        self,
        subject: Mapping[str, Any],
        resource: Mapping[str, Any],
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        s = dict(subject)
        r = dict(resource)

        # is_owner
        try:
            s_id = str(s.get("id"))
            owner = str(r.get("owner") or r.get("owner_id"))
            r["is_owner"] = bool(s_id and owner and s_id == owner)
        except Exception:
            r["is_owner"] = False

        # device posture -> subject flags
        device = s.get("device") or {}
        s["device_trusted"] = bool(device.get("trusted"))
        s["device_managed"] = bool(device.get("is_managed"))

        # geo/risk hints
        geo = s.get("geo") or {}
        s["geo_country"] = geo.get("country")

        return s, r

    # --------------------- Handlers обязательств ---------------------

    async def _ob_mfa(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                      params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        """Принудительная MFA перед доступом."""
        try:
            return await self._client.enforce(action="require_mfa", subject=subject, resource=resource, params=params)
        except Exception as e:
            # MFA важно — помечаем как не повторяемую ошибку
            raise NotRetryableError(f"MFA enforcement failed: {e}") from e

    async def _ob_watermark(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                            params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        """Водяной знак (например, в отчёте/PDF)."""
        try:
            return await self._client.enforce(action="add_watermark", subject=subject, resource=resource, params=params)
        except Exception as e:
            # Допустимо повторить — отнесём к ретраибл
            raise RetryableError(f"Watermark failed: {e}") from e

    async def _ob_mask_fields(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                              params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        """Маскирование чувствительных полей в ответе."""
        try:
            return await self._client.enforce(action="mask_fields", subject=subject, resource=resource, params=params)
        except Exception as e:
            raise RetryableError(f"Mask fields failed: {e}") from e

    async def _ob_rate_limit(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                             params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        """Временное ограничение запросов."""
        try:
            return await self._client.enforce(action="rate_limit", subject=subject, resource=resource, params=params)
        except Exception as e:
            raise RetryableError(f"Rate limit apply failed: {e}") from e

    async def _ob_session_terminate(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                                    params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        """Прекращение сессии пользователя/устройства."""
        try:
            return await self._client.enforce(action="session_terminate", subject=subject, resource=resource, params=params)
        except Exception as e:
            raise NotRetryableError(f"Session terminate failed: {e}") from e


# ========================== Пример тестового клиента (опционально) ==========================

class _DummySecurityCoreClient(SecurityCoreClientProtocol):  # pragma: no cover
    """Упрощённая заглушка для локальных тестов без сети."""

    async def get_subject_attributes(self, subject_id: str, *, hint: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        await asyncio.sleep(0.001)
        return {"id": subject_id, "role": "user", "device": {"trusted": True, "is_managed": True}, **(hint or {})}

    async def get_resource_attributes(self, resource_id: str, *, hint: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        await asyncio.sleep(0.001)
        return {"id": resource_id, "owner": "u1", "classification": "internal", **(hint or {})}

    async def get_risk(self, *, subject: Mapping[str, Any], resource: Mapping[str, Any],
                        action: Mapping[str, Any], environment: Mapping[str, Any]) -> Mapping[str, Any]:
        await asyncio.sleep(0.001)
        score = 0.1 if subject.get("device_trusted") else 0.7
        return {"score": score, "level": "low" if score < 0.5 else "high"}

    async def audit_decision(self, *, decision: Mapping[str, Any], extra: Optional[Mapping[str, Any]] = None) -> None:
        await asyncio.sleep(0.0001)
        return None

    async def ueba_event(self, *, kind: str, payload: Mapping[str, Any]) -> None:
        await asyncio.sleep(0.0001)
        return None

    async def enforce(self, *, action: str, subject: Mapping[str, Any], resource: Mapping[str, Any],
                      params: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        await asyncio.sleep(0.0005)
        return {"action": action, "applied": True, "params": params or {}}


# ========================== Локальный self-test (опционально) ==========================

if __name__ == "__main__":  # pragma: no cover
    async def _demo():
        client = _DummySecurityCoreClient()
        adapter = SecurityCoreAdapter(client, AdapterConfig(dry_run=False))

        attrs = await adapter.get_attributes(
            subject={"id": "u1", "geo": {"country": "SE"}},
            resource={"id": "doc-42", "owner": "u1"},
            action={"op": "read"},
            environment={"ip": "10.0.0.5"},
        )
        print("ATTRS:", json.dumps(attrs, ensure_ascii=False))

        # Псевдорешение PDP
        decision = {"effect": "Permit", "subject": attrs["subject"], "resource": attrs["resource"], "obligations": [
            {"name": "add_watermark", "params": {"text": "CONFIDENTIAL"}},
            {"name": "require_mfa"},
        ]}
        await adapter.report_decision(decision=decision, extra={"policy_id": "base-policy"})

        res = await adapter.enforce_obligations(
            obligations=decision["obligations"],
            subject=attrs["subject"],
            resource=attrs["resource"],
        )
        print("OBLIGATIONS:", [dataclasses.asdict(r) for r in res])

    asyncio.run(_demo())
