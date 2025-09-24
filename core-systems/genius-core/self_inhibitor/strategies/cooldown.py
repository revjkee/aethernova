# core-systems/genius_core/security/self_inhibitor/strategies/cooldown.py
from __future__ import annotations

import logging
import math
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

LOG = logging.getLogger("genius_core.security.self_inhibitor.cooldown")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_h)
LOG.setLevel(logging.INFO)


# =========================
# Исключения и результаты
# =========================

class CooldownError(Exception):
    pass


class CooldownDenied(CooldownError):
    def __init__(self, key: str, retry_after_s: float, until_ts: float, strikes: float):
        super().__init__(f"Cooldown active for key='{key}', retry_after={retry_after_s:.3f}s")
        self.key = key
        self.retry_after_s = max(0.0, float(retry_after_s))
        self.until_ts = float(until_ts)
        self.strikes = float(strikes)


@dataclass(slots=True)
class Decision:
    allowed: bool
    reason: str
    retry_after_s: float = 0.0
    cooldown_until_ts: float = 0.0
    strikes: float = 0.0
    next_penalty_s: float = 0.0
    key: str = ""


# =========================
# Конфигурация и состояние
# =========================

Clock = Callable[[], float]  # возвращает time.time()-совместимые секунды (epoch)

@dataclass(slots=True)
class CooldownConfig:
    """
    Настройки стратегии кулдауна.

    base_cooldown_s: базовое окно при первом нарушении (если warmup_strikes == 0).
    backoff_multiplier: множитель экспоненты (например, 2.0).
    max_cooldown_s: верхняя граница окна.
    warmup_strikes: сколько нарушений игнорировать без кулдауна.
    decay_s: время распада одной "единицы" strikes (нецелевой, плавающий).
    jitter_ratio: +/- доля джиттера (0.1 = +-10%).
    namespace: префикс ключа в хранилище.
    default_ttl_floor_s: минимальный TTL записи (страховка против раннего вымывания).
    """
    base_cooldown_s: float = 1.0
    backoff_multiplier: float = 2.0
    max_cooldown_s: float = 60.0
    warmup_strikes: int = 0
    decay_s: float = 30.0
    jitter_ratio: float = 0.10
    namespace: str = "cd"
    default_ttl_floor_s: float = 5.0
    clock: Clock = time.time

    def validate(self) -> None:
        if self.base_cooldown_s < 0 or self.backoff_multiplier < 1.0 or self.max_cooldown_s < 0:
            raise ValueError("Invalid cooldown parameters")
        if self.jitter_ratio < 0.0 or self.jitter_ratio > 0.5:
            raise ValueError("jitter_ratio must be in [0.0, 0.5]")
        if self.decay_s < 0:
            raise ValueError("decay_s must be >= 0")


@dataclass(slots=True)
class _State:
    strikes: float = 0.0
    cooldown_until_ts: float = 0.0
    last_update_ts: float = field(default_factory=time.time)


# =========================
# Интерфейс хранилища
# =========================

class CooldownStore:
    """
    Абстракция хранилища. Реализация должна быть потокобезопасной.
    """

    def get(self, key: str) -> Optional[_State]:
        raise NotImplementedError

    def set(self, key: str, state: _State, ttl_s: float) -> None:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError


class InMemoryCooldownStore(CooldownStore):
    """
    Потокобезопасное in-memory хранилище с TTL.
    """

    def __init__(self) -> None:
        self._data: Dict[str, Tuple[_State, float]] = {}
        self._lock = threading.RLock()

    def _gc(self) -> None:
        now = time.time()
        for k, (_, exp) in list(self._data.items()):
            if exp <= now:
                self._data.pop(k, None)

    def get(self, key: str) -> Optional[_State]:
        with self._lock:
            self._gc()
            item = self._data.get(key)
            if not item:
                return None
            state, exp = item
            if exp <= time.time():
                self._data.pop(key, None)
                return None
            # возвращаем копию, чтобы не мутировать напрямую
            return _State(strikes=state.strikes, cooldown_until_ts=state.cooldown_until_ts, last_update_ts=state.last_update_ts)

    def set(self, key: str, state: _State, ttl_s: float) -> None:
        ttl_s = max(0.0, float(ttl_s))
        with self._lock:
            self._gc()
            self._data[key] = (state, time.time() + ttl_s)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


# =========================
# Основная стратегия
# =========================

class CooldownStrategy:
    """
    Прогрессивный кулдаун с экспоненциальным бэкоффом и распадом страйков.

    Типичная интеграция:
        cd = CooldownStrategy()
        dec = cd.evaluate("user:42:action")   # проверка
        if not dec.allowed: ...  # сообщить retry_after
        # выполнить действие
        cd.commit("user:42:action", success=True)  # либо False при нарушении

    Или безопаснее — через guard:
        with cd.guard("user:42:action") as g:
            if not g.allowed:
                return http_429_retry_after(g.retry_after_s)
            do_work()
            g.success()  # можно не вызывать: успех коммитится автоматически, если не было исключений
    """

    def __init__(self, cfg: Optional[CooldownConfig] = None, store: Optional[CooldownStore] = None) -> None:
        self.cfg = cfg or CooldownConfig()
        self.cfg.validate()
        self.store = store or InMemoryCooldownStore()

    # ---------- Публичный API ----------

    def evaluate(self, key: str, *, now_ts: Optional[float] = None) -> Decision:
        """
        Проверяет, разрешено ли выполнение, без фиксации исхода.
        """
        k = self._nk(key)
        now = self._now(now_ts)
        st = self._get_state(k)
        st = self._decay(st, now)

        retry_after = max(0.0, st.cooldown_until_ts - now)
        allowed = retry_after <= 0.0
        next_penalty = self._predict_penalty_seconds(st, strikes_delta=1.0 if not allowed else 0.0)

        return Decision(
            allowed=allowed,
            reason="ok" if allowed else "cooldown",
            retry_after_s=retry_after if not allowed else 0.0,
            cooldown_until_ts=st.cooldown_until_ts,
            strikes=st.strikes,
            next_penalty_s=next_penalty,
            key=k,
        )

    def commit(self, key: str, *, success: bool, weight: float = 1.0, now_ts: Optional[float] = None) -> Decision:
        """
        Фиксирует исход операции и обновляет состояние кулдауна.
        success=True уменьшает strikes (с распадом), False — увеличивает и задаёт окно кулдауна.
        """
        k = self._nk(key)
        now = self._now(now_ts)

        st = self._get_state(k)
        st = self._decay(st, now)

        if success:
            st.strikes = max(0.0, st.strikes - max(0.0, float(weight)))
            # успех не обнуляет принудительно cooldown_until_ts, но TTL сократится естественным распадом
            st.last_update_ts = now
            ttl = self._recommended_ttl(st, now)
            self.store.set(k, st, ttl)
            return self.evaluate(k, now_ts=now)

        # нарушение: увеличиваем strikes и считаем окно
        st.strikes = max(0.0, st.strikes + max(0.0, float(weight)))
        penalty = self._penalty_seconds_after(st)
        st.cooldown_until_ts = min(now + penalty, now + self.cfg.max_cooldown_s) if self.cfg.max_cooldown_s > 0 else now + penalty
        st.last_update_ts = now
        ttl = self._recommended_ttl(st, now)
        self.store.set(k, st, ttl)

        dec = self.evaluate(k, now_ts=now)
        return dec

    def guard(self, key: str, *, raise_on_deny: bool = False, now_ts: Optional[float] = None):
        """
        Контекст-менеджер: на входе — проверка, на выходе — авто-commit успеха/ошибки.
        """
        strategy = self
        decision = self.evaluate(key, now_ts=now_ts)

        class _Guard:
            __slots__ = ("decision", "_key", "_strategy", "_committed")

            def __init__(self, d: Decision, k: str, s: CooldownStrategy) -> None:
                self.decision = d
                self._key = k
                self._strategy = s
                self._committed = False

            def __enter__(self) -> Decision:
                if not self.decision.allowed and raise_on_deny:
                    raise CooldownDenied(self._key, self.decision.retry_after_s, self.decision.cooldown_until_ts, self.decision.strikes)
                return self.decision

            def success(self) -> Decision:
                if not self._committed:
                    self._committed = True
                    self.decision = self._strategy.commit(self._key, success=True)
                return self.decision

            def failure(self, *, weight: float = 1.0) -> Decision:
                if not self._committed:
                    self._committed = True
                    self.decision = self._strategy.commit(self._key, success=False, weight=weight)
                return self.decision

            def __exit__(self, exc_type, exc, tb) -> bool:
                if self._committed:
                    return False
                if exc_type is None:
                    self._strategy.commit(self._key, success=True)
                    return False
                else:
                    # исключение трактуем как неуспех операции
                    self._strategy.commit(self._key, success=False)
                    return False

        return _Guard(decision, self._nk(key), strategy)

    # ---------- Внутренняя логика ----------

    def _nk(self, key: str) -> str:
        key = str(key).strip()
        if not key:
            raise ValueError("key must be non-empty")
        # нормализуем до детерминированного вида
        return f"{self.cfg.namespace}:{key}"

    def _now(self, now_ts: Optional[float]) -> float:
        return float(now_ts if now_ts is not None else self.cfg.clock())

    def _get_state(self, key: str) -> _State:
        st = self.store.get(key)
        if st is None:
            st = _State(strikes=0.0, cooldown_until_ts=0.0, last_update_ts=self._now(None))
        return st

    def _decay(self, st: _State, now: float) -> _State:
        if self.cfg.decay_s > 0:
            delta = max(0.0, now - st.last_update_ts)
            if delta > 0:
                decay_units = delta / self.cfg.decay_s
                old = st.strikes
                st.strikes = max(0.0, st.strikes - decay_units)
                st.last_update_ts = now
                if old != st.strikes:
                    LOG.debug("decay strikes: %.3f -> %.3f (Δt=%.3fs)", old, st.strikes, delta)
        # если окно прошло — сбросим cooldown_until
        if st.cooldown_until_ts and now >= st.cooldown_until_ts:
            st.cooldown_until_ts = 0.0
        return st

    def _penalty_seconds_after(self, st: _State) -> float:
        """
        Вычисляет окно кулдауна после уже инкрементированных strikes.
        """
        s = st.strikes
        if self.cfg.warmup_strikes > 0 and s <= float(self.cfg.warmup_strikes):
            return 0.0
        # уровень санкции (целый)
        level = max(1, int(math.floor(s - self.cfg.warmup_strikes)) + 0)
        base = self.cfg.base_cooldown_s
        mult = self.cfg.backoff_multiplier
        penalty = base * (mult ** (level - 1))
        penalty = min(penalty, self.cfg.max_cooldown_s) if self.cfg.max_cooldown_s > 0 else penalty
        # джиттер +-ratio
        if self.cfg.jitter_ratio > 0:
            r = self.cfg.jitter_ratio
            jitter = 1.0 + random.uniform(-r, r)
            penalty *= jitter
        return max(0.0, float(penalty))

    def _predict_penalty_seconds(self, st: _State, *, strikes_delta: float = 1.0) -> float:
        tmp = _State(strikes=max(0.0, st.strikes + strikes_delta), cooldown_until_ts=st.cooldown_until_ts, last_update_ts=st.last_update_ts)
        return self._penalty_seconds_after(tmp)

    def _recommended_ttl(self, st: _State, now: float) -> float:
        """
        TTL ≥ максимум из:
          - оставшегося кулдауна,
          - времени до распада текущих strikes,
          - нижнего порога default_ttl_floor_s.
        """
        cd_left = max(0.0, st.cooldown_until_ts - now)
        decay_left = st.strikes * self.cfg.decay_s if self.cfg.decay_s > 0 else self.cfg.default_ttl_floor_s
        ttl = max(cd_left, decay_left, self.cfg.default_ttl_floor_s)
        # ограничение разумного TTL при очень больших decay
        return float(ttl)


# =========================
# Демонстрация (локальный)
# =========================

if __name__ == "__main__":
    cfg = CooldownConfig(
        base_cooldown_s=1.0,
        backoff_multiplier=2.0,
        max_cooldown_s=16.0,
        warmup_strikes=1,
        decay_s=5.0,
        jitter_ratio=0.0,  # для повторяемости
        namespace="demo",
    )
    cd = CooldownStrategy(cfg=cfg)

    key = "user:42:post-message"
    # Первое нарушение (в пределах warmup) — без кулдауна
    print("EVAL-0:", cd.evaluate(key))
    print("VIOL-1:", cd.commit(key, success=False))  # strikes=1 -> warmup => 0s
    # Второе нарушение — 1s
    print("VIOL-2:", cd.commit(key, success=False))
    # Третье нарушение — 2s
    print("VIOL-3:", cd.commit(key, success=False))
    # Проверка — должно запрещать
    print("CHECK:", cd.evaluate(key))
    # Успех — смягчит страйки
    time.sleep(1.5)
    print("SUCCESS:", cd.commit(key, success=True))
    # Guard-контекст
    with cd.guard(key) as g:
        if not g.allowed:
            print("RETRY AFTER:", g.retry_after_s)
        else:
            # имитация успешной работы
            pass
