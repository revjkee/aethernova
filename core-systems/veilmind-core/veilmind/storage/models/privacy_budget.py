# -*- coding: utf-8 -*-
"""
Privacy Budget Models and Repository (ε, δ) for DP accounting.
==============================================================

Назначение:
  - Доменные модели для учёта и ограничения бюджета приватности (ε,δ) по окнам.
  - Тампер-видимая хеш-цепочка журнала (ledger).
  - Композиция механизмов: базовая и advanced (Dwork et al., 2010).
  - Усиление приватности при Poisson-подвыборке.
  - Репозиторий с атомарной проверкой и списанием бюджета, in-memory эталон.

Зависимости: стандартная библиотека Python. Опционально — veilmind.dp.sampling
(если есть в среде), иначе будут использованы встроенные безопасные эквиваленты.

Примечание по консервативности:
  Для принятия решения об остатке бюджета используем «строгое» правило:
    - ε_total = min(ε_basic_sum, ε_advanced_bound) (если advanced применим),
    - δ_total = max(δ_basic_sum, δ_advanced_bound).
  Это не занижает приватностные потери и предпочтительно для продакшн-лимитов.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import math
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# -----------------------------------------------------------------------------
# Безопасные утилиты
# -----------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def _canonical(obj: Mapping) -> bytes:
    # Минимальный канонический JSON без зависимостей
    import json
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

# ULID (монотонный, без внешних зависимостей)
_B32 = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_LOCK = threading.Lock()
_ULID_LAST_TS = 0
_ULID_LAST_RAND = bytearray(hashlib.sha256(str(time.time()).encode()).digest()[:10])

def _ulid() -> str:
    global _ULID_LAST_TS, _ULID_LAST_RAND
    with _ULID_LOCK:
        ts = int(time.time() * 1000)
        if ts == _ULID_LAST_TS:
            for i in range(9, -1, -1):
                _ULID_LAST_RAND[i] = (_ULID_LAST_RAND[i] + 1) & 0xFF
                if _ULID_LAST_RAND[i] != 0:
                    break
        else:
            _ULID_LAST_TS = ts
            _ULID_LAST_RAND = bytearray(hashlib.blake2b(str(ts).encode(), digest_size=10).digest())
        ts_b = ts.to_bytes(6, "big")
        raw = ts_b + bytes(_ULID_LAST_RAND)
    v = int.from_bytes(raw, "big")
    out = bytearray(26)
    for i in range(25, -1, -1):
        out[i] = _B32[v & 31]
        v >>= 5
    return out.decode("ascii")

def _iso_duration_to_seconds(value: str) -> int:
    """
    Простейший парсер ограниченного подмножества ISO8601 Durations: PnDTnHnMnS, PnD, PTnH, PTnM, PTnS.
    Для производственного использования достаточно (окна суток/часов/минут/секунд).
    """
    import re
    m = re.match(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$", value)
    if not m:
        raise ValueError("Unsupported duration format")
    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    minutes = int(m.group(3) or 0)
    seconds = int(m.group(4) or 0)
    return days * 86400 + hours * 3600 + minutes * 60 + seconds

def _window_anchor(now: datetime, window_seconds: int) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    n = int((now - epoch).total_seconds())
    start = (n // window_seconds) * window_seconds
    return epoch + timedelta(seconds=start)

def _chain_next(prev_hash: Optional[str], payload: Mapping[str, object]) -> str:
    inner = _sha256(_canonical(payload))
    if prev_hash:
        pad = "=" * ((4 - len(prev_hash) % 4) % 4)
        prev_raw = base64.urlsafe_b64decode(prev_hash + pad)
        data = prev_raw + inner
    else:
        data = inner
    return _b64url(_sha256(data))

# -----------------------------------------------------------------------------
# DP утилиты (c fallback)
# -----------------------------------------------------------------------------

try:
    # Если модуль доступен в проекте — используем его
    from veilmind.dp.sampling import amplify_eps_delta_poisson as _amplify
    from veilmind.dp.sampling import compose_advanced as _compose_advanced
except Exception:
    def _amplify(epsilon: float, delta: float, q: float) -> Tuple[float, float]:
        # ε' = ln(1 + q*(e^ε - 1)), δ' = q*δ
        if not (0.0 <= q <= 1.0):
            raise ValueError("q must be in [0,1]")
        return math.log1p(q * (math.exp(epsilon) - 1.0)), q * delta

    def _compose_advanced(epsilon: float, delta: float, k: int, *, delta_prime: float) -> Tuple[float, float]:
        if k < 1:
            raise ValueError("k>=1")
        eps_total = math.sqrt(2.0 * k * math.log(1.0 / delta_prime)) * epsilon + k * epsilon * (math.exp(epsilon) - 1.0)
        delta_total = k * delta + delta_prime
        return eps_total, delta_total

# -----------------------------------------------------------------------------
# Доменные модели
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class PrivacyBudgetKey:
    """
    Ключ бюджета: по умолчанию — на субъекта (entity_id) и цель обработки (scope),
    в пределах арендатора (tenant).
    """
    tenant: Optional[str]
    scope: str                # например: "analytics.export", "training.synth"
    entity_id: str            # субъект/группа: пользователь, датасет, клиент

@dataclass
class PrivacyBudgetPolicy:
    """
    Политика бюджета для (tenant, scope). Лимиты применяются к каждому entity_id отдельно.
    """
    tenant: Optional[str]
    scope: str
    epsilon_limit: float
    delta_limit: float
    window_iso: str = "P1D"   # ISO 8601 duration (например "P1D", "PT1H")
    composition: str = "basic"  # "basic" | "advanced"
    advanced_delta_prime: float = 1e-6

    @property
    def window_seconds(self) -> int:
        return _iso_duration_to_seconds(self.window_iso)

@dataclass
class PrivacyLedgerEntry:
    id: str
    key: PrivacyBudgetKey
    window_start: datetime             # начало окна UTC
    ts: datetime                       # время добавления
    epsilon: float
    delta: float
    mechanism: str                     # метка механизма или «операции»
    activity_id: Optional[str] = None  # внешняя корреляция
    subsampling_q: Optional[float] = None  # если есть Poisson-подвыборка
    tags: Dict[str, str] = field(default_factory=dict)
    chain_prev: Optional[str] = None
    chain_hash: Optional[str] = None
    version: int = 0                   # для оптимистичной блокировки

@dataclass
class PrivacyBudgetSummary:
    key: PrivacyBudgetKey
    window_start: datetime
    count: int
    epsilon_spent: float
    delta_spent: float
    epsilon_limit: float
    delta_limit: float

    @property
    def epsilon_remaining(self) -> float:
        return max(0.0, self.epsilon_limit - self.epsilon_spent)

    @property
    def delta_remaining(self) -> float:
        return max(0.0, self.delta_limit - self.delta_spent)

    @property
    def exhausted(self) -> bool:
        return self.epsilon_spent >= self.epsilon_limit or self.delta_spent >= self.delta_limit

# -----------------------------------------------------------------------------
# Исключения
# -----------------------------------------------------------------------------

class BudgetError(Exception): ...
class PolicyNotFound(BudgetError): ...
class BudgetExceeded(BudgetError): ...
class ConcurrencyError(BudgetError): ...

# -----------------------------------------------------------------------------
# Репозиторий (абстракция)
# -----------------------------------------------------------------------------

class PrivacyBudgetRepository:
    """
    Интерфейс репозитория. Реализация должна обеспечивать атомарность «проверить и списать».
    """

    # Политики
    async def get_policy(self, tenant: Optional[str], scope: str) -> Optional[PrivacyBudgetPolicy]:
        raise NotImplementedError

    async def put_policy(self, policy: PrivacyBudgetPolicy) -> None:
        raise NotImplementedError

    # Чтение состояния
    async def get_summary(self, key: PrivacyBudgetKey, now: Optional[datetime] = None) -> PrivacyBudgetSummary:
        raise NotImplementedError

    # Списание (атомарно)
    async def spend(
        self,
        key: PrivacyBudgetKey,
        *,
        epsilon: float,
        delta: float,
        mechanism: str,
        activity_id: Optional[str] = None,
        subsampling_q: Optional[float] = None,
        tags: Optional[Dict[str, str]] = None,
        now: Optional[datetime] = None,
    ) -> Tuple[PrivacyLedgerEntry, PrivacyBudgetSummary]:
        """
        Списывает бюджет, если после операции суммарные ε,δ остаются ≤ лимитов.
        Возвращает созданную запись и обновлённый summary.
        """
        raise NotImplementedError

# -----------------------------------------------------------------------------
# In-memory эталон
# -----------------------------------------------------------------------------

class InMemoryPrivacyBudgetRepository(PrivacyBudgetRepository):
    """
    Эталонная in-memory реализация для тестов/дев. Обеспечивает:
      - Атомарность операций (lock).
      - Тампер-видимый ledger (chain_hash).
      - Консервативную оценку композиции («basic»/«advanced»).
    Структуры:
      _policies[(tenant, scope)] = PrivacyBudgetPolicy
      _ledger[(window_start, tenant, scope, entity_id)] = [PrivacyLedgerEntry...]
      _chain_tail[(tenant, scope, entity_id)] = last_chain_hash
    """
    def __init__(self) -> None:
        self._policies: Dict[Tuple[Optional[str], str], PrivacyBudgetPolicy] = {}
        self._ledger: Dict[Tuple[datetime, Optional[str], str, str], List[PrivacyLedgerEntry]] = {}
        self._chain_tail: Dict[Tuple[Optional[str], str, str], Optional[str]] = {}
        self._lock = threading.RLock()

    # -------------------- Политики --------------------

    async def get_policy(self, tenant: Optional[str], scope: str) -> Optional[PrivacyBudgetPolicy]:
        with self._lock:
            return self._policies.get((tenant, scope))

    async def put_policy(self, policy: PrivacyBudgetPolicy) -> None:
        with self._lock:
            self._policies[(policy.tenant, policy.scope)] = policy

    # -------------------- Чтение состояния --------------------

    async def get_summary(self, key: PrivacyBudgetKey, now: Optional[datetime] = None) -> PrivacyBudgetSummary:
        now = now or _utcnow()
        policy = await self.get_policy(key.tenant, key.scope)
        if not policy:
            raise PolicyNotFound(f"policy not found for tenant={key.tenant} scope={key.scope}")
        wstart = _window_anchor(now, policy.window_seconds)
        with self._lock:
            items = list(self._ledger.get((wstart, key.tenant, key.scope, key.entity_id), []))
        eps, delt = _accumulate(items, policy)
        return PrivacyBudgetSummary(
            key=key,
            window_start=wstart,
            count=len(items),
            epsilon_spent=eps,
            delta_spent=delt,
            epsilon_limit=policy.epsilon_limit,
            delta_limit=policy.delta_limit,
        )

    # -------------------- Списание (атомарно) --------------------

    async def spend(
        self,
        key: PrivacyBudgetKey,
        *,
        epsilon: float,
        delta: float,
        mechanism: str,
        activity_id: Optional[str] = None,
        subsampling_q: Optional[float] = None,
        tags: Optional[Dict[str, str]] = None,
        now: Optional[datetime] = None,
    ) -> Tuple[PrivacyLedgerEntry, PrivacyBudgetSummary]:
        if epsilon < 0 or delta < 0:
            raise BudgetError("epsilon and delta must be non-negative")
        now = now or _utcnow()
        policy = await self.get_policy(key.tenant, key.scope)
        if not policy:
            raise PolicyNotFound(f"policy not found for tenant={key.tenant} scope={key.scope}")

        wstart = _window_anchor(now, policy.window_seconds)

        with self._lock:
            bucket_key = (wstart, key.tenant, key.scope, key.entity_id)
            entries = self._ledger.setdefault(bucket_key, [])
            # Подготовим новую запись с усилением подвыборкой (если указано q)
            eff_eps, eff_del = float(epsilon), float(delta)
            if subsampling_q is not None:
                eff_eps, eff_del = _amplify(epsilon, delta, subsampling_q)

            # Рассчитаем суммарные ε,δ с учётом новой записи (консервативно)
            eps_before, del_before = _accumulate(entries, policy)
            eps_after, del_after = _accumulate(entries + [
                _ephemeral_entry_for_sum(key, wstart, eff_eps, eff_del, mechanism, subsampling_q)
            ], policy)

            if eps_after > policy.epsilon_limit or del_after > policy.delta_limit:
                raise BudgetExceeded(
                    f"privacy budget exceeded: (ε={eps_after:.6f}/{policy.epsilon_limit}, δ={del_after:.2e}/{policy.delta_limit})"
                )

            # Сформируем и добавим запись
            prev = self._chain_tail.get((key.tenant, key.scope, key.entity_id))
            entry = PrivacyLedgerEntry(
                id=_ulid(),
                key=key,
                window_start=wstart,
                ts=now,
                epsilon=eff_eps,
                delta=eff_del,
                mechanism=mechanism,
                activity_id=activity_id,
                subsampling_q=subsampling_q,
                tags=dict(tags or {}),
                chain_prev=prev,
                chain_hash=None,
                version=len(entries) + 1,
            )
            entry.chain_hash = _chain_next(prev, {
                "id": entry.id,
                "tenant": key.tenant,
                "scope": key.scope,
                "entity_id": key.entity_id,
                "window_start": int(wstart.timestamp()),
                "ts": int(now.timestamp()),
                "epsilon": entry.epsilon,
                "delta": entry.delta,
                "mechanism": mechanism,
            })
            entries.append(entry)
            self._chain_tail[(key.tenant, key.scope, key.entity_id)] = entry.chain_hash

            # Итоговый summary
            eps_after, del_after = _accumulate(entries, policy)
            summary = PrivacyBudgetSummary(
                key=key,
                window_start=wstart,
                count=len(entries),
                epsilon_spent=eps_after,
                delta_spent=del_after,
                epsilon_limit=policy.epsilon_limit,
                delta_limit=policy.delta_limit,
            )
            return entry, summary

# -----------------------------------------------------------------------------
# Вспомогательные вычисления композиции
# -----------------------------------------------------------------------------

def _ephemeral_entry_for_sum(
    key: PrivacyBudgetKey,
    wstart: datetime,
    eps: float,
    delt: float,
    mechanism: str,
    q: Optional[float],
) -> PrivacyLedgerEntry:
    return PrivacyLedgerEntry(
        id="__ephemeral__",
        key=key,
        window_start=wstart,
        ts=_utcnow(),
        epsilon=eps,
        delta=delt,
        mechanism=mechanism,
        subsampling_q=q,
    )

def _accumulate(entries: Sequence[PrivacyLedgerEntry], policy: PrivacyBudgetPolicy) -> Tuple[float, float]:
    """
    Возвращает (ε_total, δ_total) по списку записей с учётом политики композиции.
    Консервативно: ε=min(basic, advanced), δ=max(basic, advanced) (если advanced доступна).
    """
    # Базовая композиция — простые суммы
    eps_basic = sum(max(0.0, e.epsilon) for e in entries)
    del_basic = sum(max(0.0, e.delta) for e in entries)

    if policy.composition != "advanced" or not entries:
        return eps_basic, del_basic

    # Advanced применима корректно для k одинаковых ε,δ. Для гетерогенных — группируем по ε,δ
    # с небольшой толерантностью и агрегируем, затем суммируем по группам; добавляем один δ' на всю совокупность.
    TOL = 1e-12
    groups: Dict[Tuple[int, int], List[PrivacyLedgerEntry]] = {}
    for e in entries:
        ke = int(round(e.epsilon / TOL))
        kd = int(round(e.delta / TOL))
        groups.setdefault((ke, kd), []).append(e)

    eps_adv_total = 0.0
    del_adv_total = 0.0
    # Распределим δ' поровну между группами (консервативно по δ возьмём max потом)
    gcount = max(1, len(groups))
    delta_prime_each = policy.advanced_delta_prime / gcount

    for (_, _), grp in groups.items():
        k = len(grp)
        e0 = grp[0].epsilon
        d0 = grp[0].delta
        eps_adv, del_adv = _compose_advanced(epsilon=e0, delta=d0, k=k, delta_prime=delta_prime_each)
        eps_adv_total += eps_adv
        del_adv_total += del_adv

    # Консервативная комбинация
    eps_total = min(eps_basic, eps_adv_total)
    delta_total = max(del_basic, del_adv_total)
    return eps_total, delta_total

# -----------------------------------------------------------------------------
# Пример использования
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio

    async def main():
        repo = InMemoryPrivacyBudgetRepository()
        # Политика: на суточное окно, лимиты ε=3.0, δ=1e-5, advanced composition
        policy = PrivacyBudgetPolicy(tenant="acme", scope="analytics.export", epsilon_limit=3.0, delta_limit=1e-5, window_iso="P1D", composition="advanced", advanced_delta_prime=1e-6)
        await repo.put_policy(policy)

        key = PrivacyBudgetKey(tenant="acme", scope="analytics.export", entity_id="user:42")

        # Первая операция (ε=0.5, δ=1e-6) без подвыборки
        entry1, summary1 = await repo.spend(key, epsilon=0.5, delta=1e-6, mechanism="gauss", activity_id="job-1")
        print("after #1:", summary1.epsilon_spent, summary1.delta_spent, "remaining:", summary1.epsilon_remaining, summary1.delta_remaining)

        # Вторая операция с Poisson-подвыборкой q=0.2
        entry2, summary2 = await repo.spend(key, epsilon=0.5, delta=1e-6, subsampling_q=0.2, mechanism="gauss", activity_id="job-2")
        print("after #2:", summary2.epsilon_spent, summary2.delta_spent)

        # Попытка превышения
        try:
            await repo.spend(key, epsilon=5.0, delta=1e-6, mechanism="gauss", activity_id="job-3")
        except BudgetExceeded as e:
            print("budget exceeded as expected:", e)

    asyncio.run(main())
