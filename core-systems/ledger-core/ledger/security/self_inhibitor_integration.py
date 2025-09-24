# ledger-core/ledger/security/self_inhibitor_integration.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, Mapping, Optional, Tuple, Union

# ------- Типы и модели --------

class Decision(str, Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"

@dataclass(frozen=True)
class Policy:
    name: str = "default"
    kill_switch: bool = False
    maintenance_windows_utc: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)  # [(HH:MM,HH:MM)]
    risk_threshold: float = 0.80          # блокировать, если risk_score >= threshold
    warn_threshold: float = 0.60          # warn, если warn <= risk < risk_threshold
    rate_limit_per_min: int = 120         # на ключ (policy_key) за минуту
    anomaly_window_sec: int = 60
    anomaly_stddev_mult: float = 3.0      # простая сигнатура «выброса»
    cooldown_after_block_sec: int = 30
    quorum_required: int = 0              # если >0 — требуется столько аппрувалов
    allowed_scopes: Tuple[str, ...] = tuple()
    dry_run: bool = False                 # только сигнализация, не блокировать фактически
    policy_key_fields: Tuple[str, ...] = ("actor", "action")  # агрегирование RL/аномалий
    etag: Optional[str] = None            # для кэш‑валидации

@dataclass(frozen=True)
class Approval:
    approver: str
    comment: Optional[str] = None
    ts_utc: Optional[str] = None

@dataclass(frozen=True)
class EvaluationInput:
    action: str
    actor: str
    risk_score: float
    context: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    operation_id: Optional[str] = None    # идемпотентность/повторы
    scopes: Tuple[str, ...] = tuple()
    approvals: Tuple[Approval, ...] = tuple()

@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    reason: str
    policy: Policy
    cooldown_until_ts: Optional[float] = None
    counters: Mapping[str, Any] = dataclasses.field(default_factory=dict)

# ------- Интерфейсы стора и аудита --------

class Store(abc.ABC):
    """Минимально необходимый контракт для отказоустойчивых счётчиков/флагов."""

    @abc.abstractmethod
    async def incr(self, key: str, window_sec: int) -> int: ...
    @abc.abstractmethod
    async def get(self, key: str) -> Optional[str]: ...
    @abc.abstractmethod
    async def set(self, key: str, value: str, ttl_sec: Optional[int] = None) -> None: ...
    @abc.abstractmethod
    async def now(self) -> float: ...

class InMemoryStore(Store):
    def __init__(self) -> None:
        self._kv: Dict[str, Tuple[str, Optional[float]]] = {}
        self._ctr: Dict[str, Tuple[int, float, int]] = {}  # key -> (count, window_start, window_sec)
        self._lock = asyncio.Lock()

    async def incr(self, key: str, window_sec: int) -> int:
        async with self._lock:
            now = time.time()
            cnt, start, win = self._ctr.get(key, (0, now, window_sec))
            if now - start >= win:
                cnt, start, win = 0, now, window_sec
            cnt += 1
            self._ctr[key] = (cnt, start, win)
            return cnt

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            v = self._kv.get(key)
            if not v:
                return None
            value, exp = v
            if exp and time.time() > exp:
                del self._kv[key]
                return None
            return value

    async def set(self, key: str, value: str, ttl_sec: Optional[int] = None) -> None:
        async with self._lock:
            exp = time.time() + ttl_sec if ttl_sec else None
            self._kv[key] = (value, exp)

    async def now(self) -> float:
        return time.time()

# Опциональный Redis‑store без жёсткой зависимости
class RedisStore(Store):
    def __init__(self, redis_client) -> None:
        self._r = redis_client

    async def incr(self, key: str, window_sec: int) -> int:
        # INCR + EXPIRE по первому разу
        p = self._r.pipeline()
        p.incr(key)
        p.expire(key, window_sec, nx=True)
        cnt, _ = await p.execute()
        return int(cnt)

    async def get(self, key: str) -> Optional[str]:
        v = await self._r.get(key)
        return None if v is None else (v.decode() if isinstance(v, (bytes, bytearray)) else str(v))

    async def set(self, key: str, value: str, ttl_sec: Optional[int] = None) -> None:
        if ttl_sec:
            await self._r.set(key, value, ex=ttl_sec)
        else:
            await self._r.set(key, value)

    async def now(self) -> float:
        # точное серверное время
        t = await self._r.time()
        return float(t[0]) + float(t[1]) / 1_000_000.0

AuditSink = Callable[[Mapping[str, Any]], Awaitable[None]]
MetricsHook = Callable[[str, Mapping[str, Union[int, float, str]]], Awaitable[None]]

# ------- Сам инHIBитор --------

def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class SelfInhibitor:
    """
    Композитная защита для критичных операций:
      - Kill‑switch и maintenance‑окна
      - Пороговый риск (WARN/BLOCK)
      - Rate‑limit на ключ (actor,action,…)
      - Простая детекция аномалий (выброс частоты) в окне
      - Quorum‑аппрувалы
      - Cooldown после BLOCK
      - Dry‑run режим
      - Идемпотентность по operation_id (дедуп блоков/варнов)
      - HMAC‑цепь аудита (tamper‑evident)
    """

    def __init__(
        self,
        *,
        store: Store,
        policy_loader: Callable[[], Awaitable[Policy]],
        audit_secret: Optional[bytes] = None,
        audit_sink: Optional[AuditSink] = None,
        metrics_hook: Optional[MetricsHook] = None,
        policy_cache_ttl_sec: float = 2.0,
        id_namespace: str = "ledger-core",
    ) -> None:
        self._store = store
        self._policy_loader = policy_loader
        self._policy_cache_ttl = policy_cache_ttl_sec
        self._audit_secret = audit_secret or hashlib.sha256(b"default-audit-key").digest()
        self._audit_sink = audit_sink
        self._metrics = metrics_hook
        self._id_ns = id_namespace

        self._policy: Optional[Policy] = None
        self._policy_exp: float = 0.0
        self._audit_prev: bytes = b"\x00" * 32  # цепь HMAC

    # ---------- Публичный API ----------

    async def evaluate(self, data: EvaluationInput) -> EvaluationResult:
        p = await self._get_policy()

        # scopes
        if p.allowed_scopes and not set(data.scopes).intersection(p.allowed_scopes):
            return await self._finalize(
                data, Decision.BLOCK, "scope_not_allowed", p, counters={}
            )

        # kill switch
        if p.kill_switch:
            return await self._finalize(
                data, Decision.BLOCK if not p.dry_run else Decision.WARN, "kill_switch", p, counters={}
            )

        # maintenance окна
        if _in_maintenance(p.maintenance_windows_utc, await self._store.now()):
            return await self._finalize(
                data, Decision.BLOCK if not p.dry_run else Decision.WARN, "maintenance_window", p, counters={}
            )

        # cooldown
        cd_key = self._key("cooldown", data)
        cd_until = await self._store.get(cd_key)
        if cd_until and float(cd_until) > await self._store.now():
            return await self._finalize(
                data, Decision.BLOCK if not p.dry_run else Decision.WARN, "cooldown_active", p, counters={}
            )

        # rate limit
        rl_key = self._key("rate", data)
        count = await self._store.incr(rl_key, 60)
        if count > p.rate_limit_per_min:
            # блокируем и включаем cooldown
            await self._set_cooldown(cd_key, p.cooldown_after_block_sec)
            return await self._finalize(
                data, Decision.BLOCK if not p.dry_run else Decision.WARN, "rate_limit_exceeded", p, counters={"rate_count": count}
            )

        # аномалии (простой выброс: сравним скорость с историческим окном в local store)
        an_key = self._key("anom", data)
        an_count = await self._store.incr(an_key, p.anomaly_window_sec)
        # грубая эвристика: если скорость кратно превышает среднюю ожидаемую (threshold * stddev)
        # без хранения полной истории — сравниваем с rate_limit_per_min в пересчёте на окно
        expected = max(1.0, p.rate_limit_per_min * (p.anomaly_window_sec / 60.0))
        if an_count > expected * p.anomaly_stddev_mult:
            dec = Decision.WARN if p.dry_run else Decision.BLOCK
            await self._set_cooldown(cd_key, p.cooldown_after_block_sec)
            return await self._finalize(
                data, dec, "anomaly_spike", p, counters={"anomaly_count": an_count, "expected": expected}
            )

        # риск‑порог
        if data.risk_score >= p.risk_threshold:
            dec = Decision.WARN if p.dry_run else Decision.BLOCK
            await self._set_cooldown(cd_key, p.cooldown_after_block_sec)
            return await self._finalize(data, dec, "risk_threshold", p, counters={"risk": data.risk_score})

        if data.risk_score >= p.warn_threshold:
            # предупреждение, но пропускаем
            return await self._finalize(data, Decision.WARN, "risk_warn", p, counters={"risk": data.risk_score})

        # quorum approvals
        if p.quorum_required > 0 and len(data.approvals) < p.quorum_required:
            dec = Decision.WARN if p.dry_run else Decision.BLOCK
            return await self._finalize(
                data, dec, "quorum_not_met", p, counters={"approvals": len(data.approvals), "required": p.quorum_required}
            )

        # ok
        return await self._finalize(data, Decision.PASS, "ok", p, counters={"rate_count": count})

    async def inhibited(self, data: EvaluationInput):
        """
        Async‑контекст: блокирует выполнение критичной секции, если решение != PASS.
        Пример:
            async with inhibitor.inhibited(EvaluationInput(...)):
                await do_critical()
        """
        res = await self.evaluate(data)
        if res.decision == Decision.BLOCK:
            raise InhibitedError(res.reason, result=res)
        return _InhibitContext(self, data, res)

    def decorator(self, data_builder: Callable[..., EvaluationInput]):
        """
        Декоратор для async‑функций. data_builder должен принимать ровно те же аргументы и вернуть EvaluationInput.
        """
        def _wrap(func):
            async def _inner(*args, **kwargs):
                data = data_builder(*args, **kwargs)
                res = await self.evaluate(data)
                if res.decision == Decision.BLOCK:
                    raise InhibitedError(res.reason, result=res)
                return await func(*args, **kwargs)
            return _inner
        return _wrap

    # ---------- Внутреннее ----------

    async def _finalize(
        self,
        data: EvaluationInput,
        decision: Decision,
        reason: str,
        policy: Policy,
        counters: Mapping[str, Any],
    ) -> EvaluationResult:
        # идемпотентность по operation_id: если ранее блокировали — повторим то же решение
        if data.operation_id:
            ikey = f"idemp:{data.operation_id}"
            prev = await self._store.get(ikey)
            if prev:
                dprev = json.loads(prev)
                decision = Decision(dprev["decision"])
                reason = dprev["reason"]
            else:
                await self._store.set(ikey, json.dumps({"decision": decision.value, "reason": reason}), ttl_sec=600)

        res = EvaluationResult(
            decision=decision,
            reason=reason,
            policy=policy,
            cooldown_until_ts=None,
            counters=dict(counters),
        )
        # аудит
        await self._audit_emit(data, res)
        # метрики
        if self._metrics:
            await self._metrics(
                "self_inhibitor_eval",
                {
                    "decision": res.decision.value,
                    "reason": res.reason,
                    "risk": data.risk_score,
                    "rate_count": int(res.counters.get("rate_count", 0)),
                },
            )
        return res

    async def _set_cooldown(self, cd_key: str, cooldown_sec: int) -> None:
        if cooldown_sec <= 0:
            return
        now = await self._store.now()
        until = now + cooldown_sec
        await self._store.set(cd_key, str(until), ttl_sec=cooldown_sec)

    async def _get_policy(self) -> Policy:
        now = await self._store.now()
        if self._policy and now < self._policy_exp:
            return self._policy
        p = await self._policy_loader()
        if p.etag is None:
            # детерминируем ETag
            et = hashlib.sha256(json.dumps(dataclasses.asdict(p), sort_keys=True, default=str).encode("utf-8")).hexdigest()
            p = dataclasses.replace(p, etag=et)
        self._policy = p
        self._policy_exp = now + self._policy_cache_ttl
        return p

    def _key(self, kind: str, data: EvaluationInput) -> str:
        # policy key = namespace:kind:field1=value1|field2=value2
        pfx = f"{self._id_ns}:{kind}:"
        fields = []
        # policy определяет какие поля агрегируются
        if self._policy:
            flds = self._policy.policy_key_fields
        else:
            flds = ("actor", "action")
        for f in flds:
            v = getattr(data, f, None) or data.context.get(f)
            fields.append(f"{f}={v}")
        return pfx + "|".join(fields)

    async def _audit_emit(self, data: EvaluationInput, res: EvaluationResult) -> None:
        event = {
            "ts_utc": _utc_now(),
            "action": data.action,
            "actor": data.actor,
            "risk": round(float(data.risk_score), 6),
            "decision": res.decision.value,
            "reason": res.reason,
            "operation_id": data.operation_id or "",
            "scopes": list(data.scopes),
            "approvals": [dataclasses.asdict(a) for a in data.approvals],
            "policy": dataclasses.asdict(res.policy),
            "counters": dict(res.counters),
        }
        # HMAC‑цепь для невскрываемости: H = HMAC(secret, prev || json)
        blob = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
        mac = hmac.new(self._audit_secret, self._audit_prev + blob, hashlib.sha256).hexdigest()
        self._audit_prev = bytes.fromhex(mac)
        event["hmac_chain"] = mac
        if self._audit_sink:
            await self._audit_sink(event)

class _InhibitContext:
    """Заглушка для совместимости (можно в будущем добавить post‑hooks)."""
    def __init__(self, inhibitor: SelfInhibitor, data: EvaluationInput, res: EvaluationResult) -> None:
        self._inh = inhibitor
        self.data = data
        self.result = res

    async def __aenter__(self) -> "_InhibitContext":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: D401
        # Здесь можно отправлять post‑audit/метрики по факту исполнения.
        return None

# ------- Вспомогательные --------

def _in_maintenance(windows: Iterable[Tuple[str, str]], now_epoch: float) -> bool:
    if not windows:
        return False
    t = time.gmtime(now_epoch)
    cur = t.tm_hour * 60 + t.tm_min
    for start, end in windows:
        s_h, s_m = [int(x) for x in start.split(":")]
        e_h, e_m = [int(x) for x in end.split(":")]
        s = s_h * 60 + s_m
        e = e_h * 60 + e_m
        if s <= cur <= e:
            return True
    return False

class InhibitedError(RuntimeError):
    def __init__(self, reason: str, *, result: EvaluationResult) -> None:
        super().__init__(f"inhibited: {reason}")
        self.result = result

# ------- Полезные фабрики/заготовки --------

async def env_policy_loader() -> Policy:
    """
    Пример загрузчика политики из ENV. Можно заменить на fetch из конфига/файла.
    """
    kill = os.getenv("INHIBITOR_KILL", "0") == "1"
    dry = os.getenv("INHIBITOR_DRY_RUN", "0") == "1"
    rate = int(os.getenv("INHIBITOR_RATE_PER_MIN", "120"))
    risk_thr = float(os.getenv("INHIBITOR_RISK_THRESHOLD", "0.8"))
    warn_thr = float(os.getenv("INHIBITOR_WARN_THRESHOLD", "0.6"))
    quorum = int(os.getenv("INHIBITOR_QUORUM", "0"))
    cooldown = int(os.getenv("INHIBITOR_COOLDOWN_SEC", "30"))
    scopes = tuple(s.strip() for s in os.getenv("INHIBITOR_ALLOWED_SCOPES", "").split(",") if s.strip())
    windows = tuple(
        tuple(w.strip() for w in pair.split("-"))
        for pair in os.getenv("INHIBITOR_MAINT", "").split(",")
        if "-" in pair
    )
    p = Policy(
        name="env",
        kill_switch=kill,
        maintenance_windows_utc=windows,  # формат "HH:MM-HH:MM,HH:MM-HH:MM"
        risk_threshold=risk_thr,
        warn_threshold=warn_thr,
        rate_limit_per_min=rate,
        anomaly_window_sec=int(os.getenv("INHIBITOR_ANOM_WIN_SEC", "60")),
        anomaly_stddev_mult=float(os.getenv("INHIBITOR_ANOM_STD", "3.0")),
        cooldown_after_block_sec=cooldown,
        quorum_required=quorum,
        allowed_scopes=scopes,
        dry_run=dry,
        policy_key_fields=("actor", "action"),
    )
    # ETag
    et = hashlib.sha256(json.dumps(dataclasses.asdict(p), sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return dataclasses.replace(p, etag=et)

async def default_audit_sink(evt: Mapping[str, Any]) -> None:
    # Здесь можно заменить на запись в БД/ELK/обсервабилити.
    # По умолчанию печатаем JSON‑строку одной линией (без PII).
    safe = dict(evt)
    print(json.dumps(safe, separators=(",", ":"), sort_keys=True))

async def default_metrics(name: str, tags: Mapping[str, Union[int, float, str]]) -> None:
    # Заглушка под StatsD/Prometheus. Ничего не делаем.
    return None

# ------- Пример интеграции (доктест‑подобно) --------

async def _example() -> None:  # pragma: no cover
    store = InMemoryStore()
    inhibitor = SelfInhibitor(
        store=store,
        policy_loader=env_policy_loader,
        audit_secret=hashlib.sha256(b"secret").digest(),
        audit_sink=default_audit_sink,
        metrics_hook=default_metrics,
        id_namespace="ledger",
    )

    # Пример критичной операции перевода средств
    op_id = str(uuid.uuid4())
    inp = EvaluationInput(
        action="transfer.create",
        actor="user:42",
        risk_score=0.35,
        context={"amount": "100.00", "currency": "EUR"},
        operation_id=op_id,
        scopes=("payments",),
        approvals=(),
    )
    async with inhibitor.inhibited(inp):
        # тут реальный код транзакции
        await asyncio.sleep(0.01)

# if __name__ == "__main__":  # pragma: no cover
#     asyncio.run(_example())
