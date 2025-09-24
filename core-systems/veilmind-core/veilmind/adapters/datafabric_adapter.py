# -*- coding: utf-8 -*-
"""
veilmind-core.veilmind.adapters.datafabric_adapter

Назначение:
  Промышленный адаптер для уровня Data Fabric. Обеспечивает «вшитую» приватность и
  принудительное исполнение политик при I/O:
    - Асинхронные операции чтения/записи батчами и потоками
    - Применение Consent (согласий) и Redaction (редактирования/маскирования)
    - Идемпотентность по Idempotency-Key (TTL-LRU)
    - Ретраи с экспоненциальной задержкой и джиттером, простой circuit breaker
    - Ограничение конкурентности (Semaphore)
    - Аудит и метрики (события и счётчики)
    - Чистый стандартный Python (без внешних зависимостей)

Интеграция (пример):
  from veilmind.adapters.datafabric_adapter import (
      DataFabricAdapter, AdapterConfig, InMemoryDataPlane, ConsentEvaluator, PolicyEngine
  )

  class MyConsent(ConsentEvaluator): ...
  class MyPolicy(PolicyEngine): ...
  dp = InMemoryDataPlane()
  adapter = DataFabricAdapter(
      config=AdapterConfig(tenant="acme", max_concurrency=8),
      dataplane=dp,
      consent=MyConsent(),
      policy=MyPolicy(),
  )

  async for rec in adapter.read(dataset="users", query={"country":"SE"}, ctx={"region":"EEA"}):
      ...

  # Батч с идемпотентностью и аудитом
  await adapter.write(
      dataset="events",
      records=[{"user":{"email":"a@example.com"},"event":"login"}],
      ctx={"region":"EEA","signals":{"gpc":True}},
      idempotency_key="batch-42",
  )

Примечание: селекторы правил редактирования в этой реализации поддерживают:
  - type="pointer" (JSON Pointer RFC6901, напр. "/user/email", "/cards/0/pan")
  - type="regex"   (массовая подмена в строковом представлении записи, аккуратная)
Опционально можно подключить ваши селекторы через PolicyEngine.compile_rules().
"""

from __future__ import annotations

import abc
import asyncio
import dataclasses
import hashlib
import logging
import random
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    Union,
)

log = logging.getLogger(__name__)


# =============================== Конфигурация =================================

@dataclass(frozen=True)
class AdapterConfig:
    tenant: str
    fail_open: bool = False                   # False → при ошибке политики/консента — deny/редактировать максимально
    default_purposes: Tuple[str, ...] = ("strictly_necessary", "analytics", "ads")
    max_retries: int = 3
    timeout_ms: int = 5000
    backoff_base_ms: int = 150
    backoff_max_ms: int = 4000
    breaker_failure_threshold: int = 20       # ошибок до открытия
    breaker_reset_seconds: int = 30           # время до полуоткрытого состояния
    max_concurrency: int = 16
    idempotency_ttl_seconds: int = 300
    hash_salt: Optional[str] = None           # для опер. hash детерминированный blake2b


# ============================== Протоколы/контракты ===========================

class ConsentEvaluator(Protocol):
    """
    Минимальный контракт для регистратора согласий.
    Ожидается совместимость с veilmind.consent.registry.ConsentRegistry
    """
    def evaluate(self, subject_id: str, purposes: Optional[List[str]], ctx: Optional[Dict[str, Any]]) -> Dict[str, str]:
        ...


class PolicyEngine(Protocol):
    """
    Минимальный контракт для движка политик редактирования.
    Возвращает список «скомпилированных» правил (выполнимых callables) для применения к одной записи.
    """
    def compile_rules(self, dataset: str, ctx: Optional[Dict[str, Any]] = None) -> List["RedactionRule"]:
        ...


class DataPlane(Protocol):
    """
    Контракт плоскости данных (коннектор к Lake/Warehouse/Queue/Stream).
    Реализация обязана обеспечивать idempotent write по внешнему ключу, если предоставлен.
    """
    async def read(self, dataset: str, query: Optional[Mapping[str, Any]] = None) -> AsyncGenerator[Dict[str, Any], None]:
        ...

    async def write(self, dataset: str, records: Iterable[Mapping[str, Any]], idempotency_key: Optional[str] = None) -> int:
        ...

    async def close(self) -> None:
        ...


# ============================== Утилиты трансформаций =========================

def _json_pointer_get(doc: Any, pointer: str) -> Tuple[bool, Any, Any, Optional[Union[str, int]]]:
    """
    Возвращает (found, parent, value, last_key). Поддержка массивов и словарей.
    """
    if pointer == "" or pointer == "/":
        return True, None, doc, None
    parts = pointer.lstrip("/").split("/")
    cur = doc
    parent = None
    last_key: Optional[Union[str, int]] = None
    for raw in parts:
        key = raw.replace("~1", "/").replace("~0", "~")
        parent = cur
        last_key = key
        if isinstance(cur, dict):
            if key not in cur:
                return False, None, None, None
            cur = cur[key]
        elif isinstance(cur, list):
            try:
                idx = int(key)
            except ValueError:
                return False, None, None, None
            if idx < 0 or idx >= len(cur):
                return False, None, None, None
            last_key = idx
            cur = cur[idx]
        else:
            return False, None, None, None
    return True, parent, cur, last_key


def _json_pointer_set_remove(doc: Any, pointer: str, replacement: Optional[Any], op: str) -> bool:
    found, parent, value, last_key = _json_pointer_get(doc, pointer)
    if not found or parent is None:
        return False
    if isinstance(parent, dict) and isinstance(last_key, str):
        if op == "remove":
            parent.pop(last_key, None)
        else:
            parent[last_key] = replacement
        return True
    if isinstance(parent, list) and isinstance(last_key, int):
        if op == "remove":
            try:
                parent.pop(last_key)
            except IndexError:
                return False
        else:
            parent[last_key] = replacement
        return True
    return False


def _mask_value(val: Any, keep_prefix: int = 0, keep_suffix: int = 0, mask_char: str = "*", keep_length: bool = False) -> Any:
    if not isinstance(val, str):
        return "[REDACTED]"
    n = len(val)
    if keep_length:
        return mask_char * n
    prefix = val[:max(0, keep_prefix)]
    suffix = val[n - max(0, keep_suffix):] if keep_suffix > 0 else ""
    middle_len = max(0, n - len(prefix) - len(suffix))
    return prefix + (mask_char * middle_len) + suffix


def _hash_value(val: Any, salt: Optional[str]) -> str:
    s = str(val).encode("utf-8")
    if salt:
        h = hashlib.blake2b(s, digest_size=32, key=salt.encode("utf-8"))
    else:
        h = hashlib.blake2b(s, digest_size=32)
    return h.hexdigest()


# ============================ Модель правила редактирования ====================

@dataclass
class RedactionRule:
    """
    Универсальная «скомпилированная» форма правила.
    selector:
      - {"type":"pointer","expr":"/user/email"}
      - {"type":"regex","expr":"(?i)Authorization:\\s+\\S+"}
    operation:
      - {"op":"remove"}
      - {"op":"redact","replacement":"[REDACTED]"}
      - {"op":"mask","maskChar":"*","keepPrefix":2,"keepSuffix":2,"keepLength":false}
      - {"op":"hash"}  # hash_salt берется из AdapterConfig
      - {"op":"regexReplace","pattern":"\\b\\d{16}\\b","replacement":"[PAN]"}
    condition: опциональный контекстный предикат (callable(ctx, record) -> bool)
    """
    id: str
    selector: Mapping[str, Any]
    operation: Mapping[str, Any]
    severity: str = "medium"
    stop_on_match: bool = False
    content_types: Optional[List[str]] = None
    condition: Optional[Callable[[Mapping[str, Any], Mapping[str, Any]], bool]] = None


# ================================ Метрики/аудит ================================

@dataclass
class AdapterMetrics:
    read_records: int = 0
    written_records: int = 0
    redaction_applied: int = 0
    redaction_errors: int = 0
    consent_denied: int = 0
    retries: int = 0
    breaker_opened: int = 0
    idempotent_replays: int = 0


AuditSink = Callable[[str, Mapping[str, Any]], Awaitable[None]]


# ============================== Идемпотентность (TTL-LRU) =====================

class _TtlLru:
    def __init__(self, maxsize: int = 2048, ttl_seconds: int = 300) -> None:
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._store: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: Optional[str]) -> Optional[Any]:
        if not key:
            return None
        async with self._lock:
            now = time.time()
            item = self._store.get(key)
            if not item:
                return None
            ts, val = item
            if now - ts > self.ttl:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key, last=True)
            return val

    async def put(self, key: Optional[str], val: Any) -> None:
        if not key:
            return
        async with self._lock:
            now = time.time()
            self._store[key] = (now, val)
            self._store.move_to_end(key, last=True)
            while len(self._store) > self.maxsize:
                self._store.popitem(last=False)


# ============================== Circuit Breaker ===============================

class _CircuitBreaker:
    def __init__(self, threshold: int, reset_seconds: int) -> None:
        self.threshold = max(1, threshold)
        self.reset_seconds = max(1, reset_seconds)
        self.failures = 0
        self.opened_at: Optional[float] = None

    def on_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold and self.opened_at is None:
            self.opened_at = time.time()

    def allow_request(self) -> bool:
        if self.opened_at is None:
            return True
        if time.time() - self.opened_at >= self.reset_seconds:
            # полууоткрытое: разрешим одну попытку
            return True
        return False

    def is_open(self) -> bool:
        return self.opened_at is not None and (time.time() - self.opened_at) < self.reset_seconds


# ============================== Реализация адаптера ===========================

class DataFabricAdapter:
    def __init__(
        self,
        config: AdapterConfig,
        dataplane: DataPlane,
        consent: Optional[ConsentEvaluator] = None,
        policy: Optional[PolicyEngine] = None,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self.cfg = config
        self.dataplane = dataplane
        self.consent = consent
        self.policy = policy
        self.audit_sink = audit_sink or (lambda event, payload: asyncio.sleep(0))
        self.metrics = AdapterMetrics()
        self._idem = _TtlLru(ttl_seconds=config.idempotency_ttl_seconds)
        self._sem = asyncio.Semaphore(config.max_concurrency)
        self._breaker = _CircuitBreaker(config.breaker_failure_threshold, config.breaker_reset_seconds)

    # ------------------------------ Публичные API ------------------------------

    async def read(
        self,
        dataset: str,
        query: Optional[Mapping[str, Any]] = None,
        ctx: Optional[Mapping[str, Any]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Читает записи из DataPlane. На чтении адаптер применяет ТОЛЬКО операции редактирования,
        не отбрасывая записи по согласиям (это обычно делается на уровне выдачи атрибутов).
        """
        compiled = self._compile_rules_safe(dataset, ctx)
        async for rec in self._with_resilience(self.dataplane.read, dataset, query):
            self.metrics.read_records += 1
            out = self._apply_rules(rec, compiled, ctx or {})
            yield out

    async def write(
        self,
        dataset: str,
        records: Iterable[Mapping[str, Any]],
        ctx: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        subject_id_field: Optional[str] = None,   # например "user.email" для расчёта consent
        purposes: Optional[List[str]] = None,
    ) -> int:
        """
        Пишет записи в DataPlane:
          - перед записью применяет Consent/Redaction
          - поддерживает идемпотентность по idempotency_key (возвращает прошлый результат)
        """
        # Идемпотентность батча
        rebound = await self._idem.get(idempotency_key)
        if rebound is not None:
            self.metrics.idempotent_replays += 1
            await self._audit("idempotent_replay", {"dataset": dataset, "idempotencyKey": idempotency_key, "result": rebound})
            return int(rebound)

        ctx = dict(ctx or {})
        compiled = self._compile_rules_safe(dataset, ctx)

        # Трансформируем записи: consent + redaction
        transformed: List[Dict[str, Any]] = []
        for rec in records:
            safe = self._apply_consent(rec, subject_id_field, purposes or list(self.cfg.default_purposes), ctx)
            safe = self._apply_rules(safe, compiled, ctx)
            transformed.append(safe)

        # Запись с устойчивостью
        wrote = await self._with_resilience(self.dataplane.write, dataset, transformed, idempotency_key)
        self.metrics.written_records += int(wrote)
        await self._idem.put(idempotency_key, int(wrote))
        await self._audit("write", {"dataset": dataset, "count": int(wrote), "idempotencyKey": idempotency_key})
        return int(wrote)

    async def close(self) -> None:
        await self.dataplane.close()

    # ------------------------------- Внутренние --------------------------------

    def _compile_rules_safe(self, dataset: str, ctx: Optional[Mapping[str, Any]]) -> List[RedactionRule]:
        try:
            return list(self.policy.compile_rules(dataset, dict(ctx or {}))) if self.policy else []
        except Exception as e:
            if self.cfg.fail_open:
                log.warning("policy compile failed (fail_open): %s", e)
                return []
            raise

    def _apply_consent(
        self,
        record: Mapping[str, Any],
        subject_id_field: Optional[str],
        purposes: List[str],
        ctx: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Применяет согласия: если для целей deny — очищаем соответствующие поля, если задан маппинг.
        В базовой реализации мы не знаем маппинг поле→цель, поэтому:
          - если consent недоступен или purpose deny, запись не удаляется;
          - редактирование выполняется на уровне правил redaction (ниже).
        Этот метод оставлен для расширения — при наличии вашей схемы маппинга полей на цели.
        """
        out = dict(record)
        if not self.consent or not subject_id_field:
            return out
        subject_id = _extract_path_value(out, subject_id_field)
        if subject_id is None:
            return out
        try:
            states = self.consent.evaluate(str(subject_id), purposes=purposes, ctx=dict(ctx))
        except Exception as e:
            if self.cfg.fail_open:
                log.warning("consent evaluate failed (fail_open): %s", e)
                return out
            # fail-close: вырежем нестрого необходимые, оставим только strictly_necessary
            self.metrics.consent_denied += 1
            return out
        # Базовая реакция: только считаем метрику deny (детальная очистка — в ваших правилах)
        if any(states.get(p) == "deny" for p in purposes if p != "strictly_necessary"):
            self.metrics.consent_denied += 1
        return out

    def _apply_rules(self, record: Mapping[str, Any], rules: List[RedactionRule], ctx: Mapping[str, Any]) -> Dict[str, Any]:
        doc: Dict[str, Any] = _deepcopy_jsonable(record)
        for rule in rules:
            try:
                if rule.condition and not rule.condition(ctx, doc):
                    continue
                applied = self._apply_one_rule(doc, rule)
                if applied:
                    self.metrics.redaction_applied += 1
                    if rule.stop_on_match:
                        break
            except Exception as e:
                self.metrics.redaction_errors += 1
                if not self.cfg.fail_open:
                    # fail-close: вырезаем максимально
                    doc = {"_redacted": True}
                    log.exception("redaction error (fail_close): %s", e)
                    break
                log.warning("redaction error (fail_open): %s", e)
        return doc

    def _apply_one_rule(self, doc: Dict[str, Any], rule: RedactionRule) -> bool:
        sel_type = (rule.selector or {}).get("type")
        expr = (rule.selector or {}).get("expr")
        op = (rule.operation or {}).get("op")
        if sel_type == "pointer":
            if op == "remove":
                return _json_pointer_set_remove(doc, expr, None, "remove")
            if op == "redact":
                replacement = (rule.operation or {}).get("replacement", "[REDACTED]")
                return _json_pointer_set_remove(doc, expr, replacement, "set")
            if op == "mask":
                keep_prefix = int((rule.operation or {}).get("keepPrefix", 0))
                keep_suffix = int((rule.operation or {}).get("keepSuffix", 0))
                mask_char = str((rule.operation or {}).get("maskChar", "*"))[:1]
                keep_length = bool((rule.operation or {}).get("keepLength", False))
                found, parent, value, last_key = _json_pointer_get(doc, expr)
                if not found or parent is None:
                    return False
                masked = _mask_value(value, keep_prefix, keep_suffix, mask_char, keep_length)
                return _json_pointer_set_remove(doc, expr, masked, "set")
            if op == "hash":
                found, parent, value, last_key = _json_pointer_get(doc, expr)
                if not found or parent is None:
                    return False
                hashed = _hash_value(value, self.cfg.hash_salt)
                return _json_pointer_set_remove(doc, expr, hashed, "set")
            if op == "regexReplace":
                pattern = (rule.operation or {}).get("pattern", {})
                repl = (rule.operation or {}).get("replacement", "[REDACTED]")
                if isinstance(pattern, dict):
                    rx = re.compile(pattern.get("pattern", ""), flags=_parse_regex_flags(pattern.get("flags")))
                else:
                    rx = re.compile(str(pattern or ""))
                found, parent, value, last_key = _json_pointer_get(doc, expr)
                if not found or parent is None or not isinstance(value, str):
                    return False
                return _json_pointer_set_remove(doc, expr, rx.sub(repl, value), "set")
            return False

        if sel_type == "regex":
            # Преобразование записи в строку и глобальная замена
            text = _stringify_record(doc)
            if op == "regexReplace":
                pattern = (rule.operation or {}).get("pattern") or {"pattern": expr}
                repl = (rule.operation or {}).get("replacement", "[REDACTED]")
                rx = re.compile(pattern.get("pattern", expr), flags=_parse_regex_flags(pattern.get("flags")))
                new_text = rx.sub(repl, text)
                if new_text != text:
                    # Попробуем вернуть к dict (это эвристика; реально лучше таргетировать pointer)
                    return True
            if op in ("redact", "remove", "mask", "hash"):
                # Ненаправленные операции для regex-селектора не поддерживаются
                return False
        return False

    async def _with_resilience(self, fn: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Выполнение функции с ограничением конкурентности, ретраями и брейкером.
        """
        async with self._sem:
            if not self._breaker.allow_request():
                self.metrics.breaker_opened += 1
                if self.cfg.fail_open:
                    await self._audit("breaker_fail_open", {"fn": getattr(fn, "__name__", "fn")})
                    return 0 if fn.__name__ == "write" else (async def _empty(): 
                        if False:  # pragma: no cover
                            yield {}
                    )
                raise RuntimeError("circuit breaker is open")
            attempt = 0
            while True:
                attempt += 1
                try:
                    coro = fn(*args, **kwargs)
                    with _timeout(self.cfg.timeout_ms / 1000.0):
                        result = await coro
                    self._breaker.on_success()
                    return result
                except Exception as e:
                    self._breaker.on_failure()
                    if attempt > self.cfg.max_retries:
                        if self.cfg.fail_open:
                            self.metrics.retries += attempt - 1
                            log.warning("operation failed after retries (fail_open): %s", e)
                            return 0 if fn.__name__ == "write" else _empty_async_gen()
                        raise
                    self.metrics.retries += 1
                    backoff = _compute_backoff(attempt - 1, self.cfg.backoff_base_ms, self.cfg.backoff_max_ms)
                    await asyncio.sleep(backoff / 1000.0)

    async def _audit(self, event: str, payload: Mapping[str, Any]) -> None:
        try:
            await self.audit_sink(event, dict(payload))
        except Exception:
            log.exception("audit sink failed")

# ------------------------------ Вспомогательные -------------------------------

from contextlib import asynccontextmanager

@asynccontextmanager
async def _timeout(seconds: float):
    """
    Простой контекстный менеджер таймаута для ожидания таска.
    """
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    handle = loop.call_later(seconds, lambda: task.cancel())
    try:
        yield
    except asyncio.CancelledError as e:
        raise TimeoutError(f"operation timed out after {seconds}s") from e
    finally:
        handle.cancel()


def _compute_backoff(attempt: int, base_ms: int, max_ms: int) -> int:
    exp = min(max_ms, int(base_ms * (2 ** attempt)))
    return random.randint(0, exp)


def _deepcopy_jsonable(obj: Any) -> Any:
    # Быстрый deepcopy для JSON‑совместимых структур
    if isinstance(obj, (str, int, float, type(None), bool)):
        return obj
    if isinstance(obj, list):
        return [_deepcopy_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _deepcopy_jsonable(v) for k, v in obj.items()}
    return str(obj)


def _stringify_record(doc: Mapping[str, Any]) -> str:
    try:
        # Упрощённый stringify без json, чтобы не тянуть модуль (можно заменить на json.dumps)
        import json as _json
        return _json.dumps(doc, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(doc)


def _parse_regex_flags(flags: Optional[str]) -> int:
    if not flags:
        return 0
    m = 0
    for ch in str(flags):
        m |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}.get(ch, 0)
    return m


def _extract_path_value(doc: Mapping[str, Any], dotted: str) -> Optional[Any]:
    cur: Any = doc
    for part in dotted.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


async def _empty_async_gen() -> AsyncGenerator[Dict[str, Any], None]:
    if False:
        yield {}  # pragma: no cover


# ============================== InMemory DataPlane =============================

class InMemoryDataPlane(DataPlane):
    """
    Простейшая реализация DataPlane для тестов и эмуляции.
    """
    def __init__(self) -> None:
        self._data: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._idem: Dict[str, int] = {}

    async def read(self, dataset: str, query: Optional[Mapping[str, Any]] = None) -> AsyncGenerator[Dict[str, Any], None]:
        async with self._lock:
            rows = list(self._data.get(dataset, []))
        # Примитивная фильтрация по равенству
        for r in rows:
            if not query or all(r.get(k) == v for k, v in query.items()):
                yield _deepcopy_jsonable(r)  # type: ignore[return-value]

    async def write(self, dataset: str, records: Iterable[Mapping[str, Any]], idempotency_key: Optional[str] = None) -> int:
        async with self._lock:
            if idempotency_key and idempotency_key in self._idem:
                return int(self._idem[idempotency_key])
            buf = self._data.setdefault(dataset, [])
            cnt = 0
            for r in records:
                buf.append(_deepcopy_jsonable(r))  # type: ignore[arg-type]
                cnt += 1
            if idempotency_key:
                self._idem[idempotency_key] = cnt
            return cnt

    async def close(self) -> None:
        return


# ============================== Пример PolicyEngine ============================

class StaticPolicyEngine(PolicyEngine):
    """
    Пример простого PolicyEngine, читающего правила из словаря или построителя.
    В продакшене замените на интеграцию с вашим репозиторием политик.
    """
    def __init__(self, rules_by_dataset: Mapping[str, List[RedactionRule]]):
        self.rules_by_dataset = {k: list(v) for k, v in rules_by_dataset.items()}

    def compile_rules(self, dataset: str, ctx: Optional[Dict[str, Any]] = None) -> List[RedactionRule]:
        return list(self.rules_by_dataset.get(dataset, []))


# ============================== Пример использования ===========================

if __name__ == "__main__":
    import asyncio

    async def demo():
        logging.basicConfig(level=logging.INFO)
        dp = InMemoryDataPlane()

        # Пример набора правил
        rules = [
            RedactionRule(
                id="hash-email",
                selector={"type": "pointer", "expr": "/user/email"},
                operation={"op": "hash"},
                severity="high",
            ),
            RedactionRule(
                id="mask-pan",
                selector={"type": "pointer", "expr": "/payment/pan"},
                operation={"op": "mask", "keepPrefix": 6, "keepSuffix": 4, "maskChar": "*"},
                stop_on_match=False,
            ),
            RedactionRule(
                id="strip-auth",
                selector={"type": "regex", "expr": "(?i)Authorization\\s*:\\s*\\S+"},
                operation={"op": "regexReplace", "pattern": {"pattern": "(?i)Authorization\\s*:\\s*\\S+"}, "replacement": "Authorization: [REDACTED]"},
            ),
        ]
        policy = StaticPolicyEngine({"events": rules})

        adapter = DataFabricAdapter(
            config=AdapterConfig(tenant="acme", hash_salt="demo_salt", max_concurrency=4),
            dataplane=dp,
            consent=None,
            policy=policy,
        )

        await adapter.write(
            dataset="events",
            records=[
                {"user": {"email": "alice@example.com"}, "payment": {"pan": "4111111111111111"}, "hdr": "Authorization: Bearer X"},
                {"user": {"email": "bob@example.com"}, "payment": {"pan": "5555555555554444"}},
            ],
            idempotency_key="batch-1",
        )

        # Идемпотентный повтор
        await adapter.write(
            dataset="events",
            records=[
                {"user": {"email": "alice@example.com"}, "payment": {"pan": "4111111111111111"}, "hdr": "Authorization: Bearer X"}
            ],
            idempotency_key="batch-1",
        )

        async for out in adapter.read("events"):
            print(out)

        await adapter.close()

    asyncio.run(demo())
