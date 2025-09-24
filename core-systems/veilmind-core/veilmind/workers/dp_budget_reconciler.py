# -*- coding: utf-8 -*-
"""
VeilMind — DP Budget Reconciler Worker (industrial grade)

Функциональность:
- Согласование (reconcile) леджера DP-зарядов с бюджетами (ε, δ) на окна.
- Поддержка типов зарядов:
    * "direct": прямые epsilon, delta.
    * "gaussian": σ (std), sensitivity (по умолчанию 1.0), count (повторение механизма).
- Композиция через Rényi DP (RDP) с конверсией в (ε, δ): eps(δ) = min_α (ε_RDP(α) + ln(1/δ)/(α-1)).
  Для Gaussian: ε_RDP(α) = α * Δ² / (2 σ²), где Δ — L2-сенситивность (по умолчанию 1.0).
- Идемпотентность: обрабатывает только PENDING леджер, атомарно помечает POSTED/REJECTED.
- Окна бюджета: calendar (day/week/month) или fixed (seconds), вычисление границ окна.
- Политики: пределы epsilon_limit, delta_limit, поведение при превышении (REJECT/ALLOW_WITH_FLAG).
- Конкурентность: опциональная распределённая блокировка (Postgres advisory lock), иначе локальная.
- Репозитории: SQLAlchemyRepo (если доступен SQLAlchemy) и InMemoryRepo для тестов.
- Конфигурация через ENV и/или ServerConfig; безопасные дефолты.
- Логирование: структурные события на logger "veilmind.dp.reconciler".

Примечания:
- Модель таблиц в БД должна содержать эквивалентные поля (см. SQLAlchemyRepo ниже). Если структура иная — адаптируйте
  маппинг в репозитории. Если ваша схема отличается — I cannot verify this.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import math
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

logger = logging.getLogger("veilmind.dp.reconciler")


# =============================================================================
# Конфигурация
# =============================================================================

@dataclass(frozen=True)
class ReconcilerConfig:
    # Источник данных: SQLAlchemy URL (postgresql://...); если пусто — InMemoryRepo (для теста/демо)
    database_url: str = os.getenv("DATABASE_URL", "")
    # Batch размер зарядов за цикл
    batch_limit: int = int(os.getenv("DP_RECON_BATCH", "500"))
    # DP-доменные параметры
    default_alphas: Tuple[int, ...] = tuple(int(x) for x in os.getenv("DP_RDP_ALPHAS", "2,3,4,5,8,16,32,64,128,256").split(","))
    default_sensitivity: float = float(os.getenv("DP_DEFAULT_SENSITIVITY", "1.0"))
    # Поведение при попытке превышения лимита
    on_overflow: str = os.getenv("DP_OVERFLOW_MODE", "REJECT")  # REJECT | ALLOW_WITH_FLAG
    # Гранулярность окна: calendar_day|calendar_week|calendar_month|fixed_seconds
    window_kind: str = os.getenv("DP_WINDOW_KIND", "calendar_month")
    window_seconds: int = int(os.getenv("DP_WINDOW_SECONDS", "0"))  # для fixed_seconds
    # Распределённая блокировка (только Postgres): 64-бит ключ
    advisory_lock_key: int = int(os.getenv("DP_ADVISORY_LOCK_KEY", "851093847"))
    # Максимальная длительность цикла (сек): защитный таймаут
    cycle_timeout_sec: int = int(os.getenv("DP_CYCLE_TIMEOUT_SEC", "50"))
    # Сухой прогон (не писать изменения)
    dry_run: bool = os.getenv("DP_DRY_RUN", "0") == "1"


# =============================================================================
# Модель домена
# =============================================================================

@dataclass
class BudgetWindow:
    start: datetime
    end: datetime

@dataclass
class DpBudget:
    """Снимок бюджета в окне."""
    account_id: str
    window: BudgetWindow
    epsilon_limit: float
    delta_limit: float
    # накопленные значения
    epsilon_spent: float = 0.0
    # агрегированная RDP по α (для более корректной композиции)
    rdp_spent: Dict[int, float] = field(default_factory=dict)
    # служебные
    status: str = "ACTIVE"  # ACTIVE|EXHAUSTED|SUSPENDED
    version: int = 0        # для оптимистичных апдейтов

@dataclass
class DpCharge:
    """Запись леджера, ожидающая списания."""
    id: str
    account_id: str
    ts: datetime
    mechanism: str  # "direct" | "gaussian"
    # для direct
    epsilon: Optional[float] = None
    delta: Optional[float] = None
    # для gaussian
    sigma: Optional[float] = None
    sensitivity: Optional[float] = None
    count: int = 1
    # метки
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Окна бюджета
# =============================================================================

def _start_of_day(dt_utc: datetime) -> datetime:
    return datetime(dt_utc.year, dt_utc.month, dt_utc.day, tzinfo=timezone.utc)

def _start_of_week(dt_utc: datetime) -> datetime:
    sod = _start_of_day(dt_utc)
    # ISO: monday=0
    delta = timedelta(days=sod.weekday())
    return sod - delta

def _start_of_month(dt_utc: datetime) -> datetime:
    return datetime(dt_utc.year, dt_utc.month, 1, tzinfo=timezone.utc)

def resolve_window(now_utc: datetime, cfg: ReconcilerConfig) -> BudgetWindow:
    if cfg.window_kind == "calendar_day":
        s = _start_of_day(now_utc)
        e = s + timedelta(days=1)
        return BudgetWindow(s, e)
    if cfg.window_kind == "calendar_week":
        s = _start_of_week(now_utc)
        e = s + timedelta(days=7)
        return BudgetWindow(s, e)
    if cfg.window_kind == "calendar_month":
        s = _start_of_month(now_utc)
        # следующий месяц
        if s.month == 12:
            e = datetime(s.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            e = datetime(s.year, s.month + 1, 1, tzinfo=timezone.utc)
        return BudgetWindow(s, e)
    if cfg.window_kind == "fixed_seconds" and cfg.window_seconds > 0:
        seconds = cfg.window_seconds
        # якорим от эпохи
        start_epoch = int(now_utc.timestamp()) // seconds * seconds
        s = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
        e = s + timedelta(seconds=seconds)
        return BudgetWindow(s, e)
    # дефолт
    return resolve_window(now_utc, dataclasses.replace(cfg, window_kind="calendar_month"))


# =============================================================================
# RDP Accountant
# =============================================================================

class RdpAccountant:
    """
    Композиция RDP для Gaussian и конверсия в (ε,δ).
    Формулы:
      - Gaussian(σ, Δ): ε_RDP(α) = α * Δ^2 / (2 σ^2) для α > 1.
      - Конверсия: ε(δ) = min_α [ ε_RDP(α) + ln(1/δ)/(α-1) ].
    """
    def __init__(self, alphas: Sequence[int]) -> None:
        self.alphas = tuple(sorted(set(a for a in alphas if int(a) > 1)))

    @staticmethod
    def gaussian_rdp(alpha: int, sigma: float, sensitivity: float = 1.0) -> float:
        if sigma <= 0.0:
            raise ValueError("sigma must be > 0")
        if alpha <= 1:
            raise ValueError("alpha must be > 1")
        return (alpha * (sensitivity ** 2)) / (2.0 * (sigma ** 2))

    def compose_gaussian(self, rdp: MutableMapping[int, float], sigma: float, sensitivity: float, count: int = 1) -> None:
        for a in self.alphas:
            rdp[a] = rdp.get(a, 0.0) + count * self.gaussian_rdp(a, sigma, sensitivity)

    @staticmethod
    def compose_direct(epsilon: float, delta: float, acc_rdp: MutableMapping[int, float], alphas: Sequence[int]) -> None:
        """
        Хак: представим прямую (ε,δ) через эквивалентную «надбавку» в RDP на оптимальном α.
        Из соотношения ε(δ) = min_α (ε_RDP(α) + ln(1/δ)/(α-1)) следует нижняя оценка:
            ε_RDP(α) ≥ ε - ln(1/δ)/(α-1)
        Мы распределим вклад ε равномерно по α, не нарушив минимума.
        Консервативно: добавим по максимуму из 0 и (ε - ln(1/δ)/(α-1)).
        Это даёт верхнюю границу ε при обратной конверсии, т. е. не занижает расход.
        """
        if delta <= 0 or delta >= 1:
            raise ValueError("delta must be in (0,1)")
        ln_term = math.log(1.0 / delta)
        for a in alphas:
            add = max(0.0, epsilon - ln_term / (a - 1))
            acc_rdp[a] = acc_rdp.get(a, 0.0) + add

    @staticmethod
    def epsilon_at_delta(rdp: Mapping[int, float], delta: float) -> float:
        if not rdp:
            return 0.0
        if delta <= 0 or delta >= 1:
            raise ValueError("delta must be in (0,1)")
        ln_term = math.log(1.0 / delta)
        eps_vals: List[float] = []
        for a, eps_rdp in rdp.items():
            eps = eps_rdp + ln_term / (a - 1)
            eps_vals.append(eps)
        return float(min(eps_vals))


# =============================================================================
# Репозитории (абстракция)
# =============================================================================

class RepoError(RuntimeError):
    pass


class AbstractRepo:
    """Абстракция источника данных бюджета и леджера."""

    # ---- чтение ----
    def load_current_budgets(self, accounts: Optional[Sequence[str]], window: BudgetWindow) -> Dict[str, DpBudget]:
        raise NotImplementedError

    def load_pending_charges(self, limit: int, window: BudgetWindow) -> List[DpCharge]:
        raise NotImplementedError

    # ---- запись/транзакции ----
    def begin(self) -> Any:
        """Возвращает контекстный менеджер транзакции."""
        raise NotImplementedError

    def post_charge_and_update_budget(
        self,
        charge: DpCharge,
        budget_before: DpBudget,
        budget_after: DpBudget,
        decision: str,  # "POSTED" | "REJECTED"
        reason: str,
    ) -> None:
        """
        Атомарно переводит леджер charge в указанный статус и пишет обновление бюджета.
        Должна проверять версию (optimistic concurrency) budget_before.version.
        """
        raise NotImplementedError

    # ---- блокировки (опционально) ----
    def try_advisory_lock(self, key: int) -> bool:
        return True

    def advisory_unlock(self, key: int) -> None:
        return None


# ------------------------ InMemoryRepo (для теста/демо) -----------------------

class InMemoryRepo(AbstractRepo):
    def __init__(self) -> None:
        self._budgets: Dict[Tuple[str, str, str], DpBudget] = {}  # (account_id, window.start.iso, window.end.iso)
        self._charges: Dict[str, Tuple[str, DpCharge]] = {}       # id -> (status, charge)
        self._version: Dict[Tuple[str, str, str], int] = {}

    def seed_budget(self, account_id: str, window: BudgetWindow, epsilon_limit: float, delta_limit: float) -> None:
        key = (account_id, window.start.isoformat(), window.end.isoformat())
        self._budgets[key] = DpBudget(account_id=account_id, window=window, epsilon_limit=epsilon_limit,
                                      delta_limit=delta_limit, epsilon_spent=0.0, rdp_spent={}, status="ACTIVE", version=0)
        self._version[key] = 0

    def seed_charge(self, charge: DpCharge, status: str = "PENDING") -> None:
        self._charges[charge.id] = (status, charge)

    def load_current_budgets(self, accounts: Optional[Sequence[str]], window: BudgetWindow) -> Dict[str, DpBudget]:
        out: Dict[str, DpBudget] = {}
        for (acc, ws, we), b in self._budgets.items():
            if ws == window.start.isoformat() and we == window.end.isoformat():
                if accounts is None or acc in accounts:
                    out[acc] = dataclasses.replace(b)
        return out

    def load_pending_charges(self, limit: int, window: BudgetWindow) -> List[DpCharge]:
        res: List[DpCharge] = []
        for status, ch in self._charges.values():
            if status == "PENDING" and window.start <= ch.ts < window.end:
                res.append(ch)
                if len(res) >= limit:
                    break
        # сортировка по времени для детерминизма
        res.sort(key=lambda c: c.ts)
        return res

    def begin(self):
        class _Tx:
            def __enter__(self_nonlocal): return self
            def __exit__(self_nonlocal, exc_type, exc, tb): return False
        return _Tx()

    def post_charge_and_update_budget(self, charge: DpCharge, budget_before: DpBudget, budget_after: DpBudget, decision: str, reason: str) -> None:
        # optimistic: проверим, что версия не изменилась
        key = (budget_before.account_id, budget_before.window.start.isoformat(), budget_before.window.end.isoformat())
        cur_ver = self._version.get(key, 0)
        if cur_ver != budget_before.version:
            raise RepoError("budget version changed")
        # Применяем
        self._budgets[key] = dataclasses.replace(budget_after, version=budget_after.version)
        self._version[key] = budget_after.version
        # Леджер
        if charge.id not in self._charges:
            raise RepoError("charge missing")
        self._charges[charge.id] = (decision, charge)
        logger.info("ledger_update", extra={"charge_id": charge.id, "decision": decision, "reason": reason})

    # InMemory: блокировка не требуется
    def try_advisory_lock(self, key: int) -> bool:
        return True

    def advisory_unlock(self, key: int) -> None:
        return None


# ------------------------ SQLAlchemyRepo (опционально) ------------------------
# Зависит от наличия SQLAlchemy и вашей схемы таблиц. Если она отличается — адаптируйте.
try:
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    _SA_OK = True
except Exception:
    _SA_OK = False

class SQLAlchemyRepo(AbstractRepo):
    """
    Ожидаем таблицы (примерная схема, ИМЕНА/ТИПЫ МОГУТ ОТЛИЧАТЬСЯ — адаптируйте под вашу БД):
      dp_budgets(account_id text, window_start timestamptz, window_end timestamptz,
                 epsilon_limit double, delta_limit double, epsilon_spent double,
                 rdp_spent jsonb, status text, version int, PRIMARY KEY (account_id, window_start, window_end))
      dp_ledger(id uuid, account_id text, ts timestamptz, mechanism text,
                epsilon double, delta double, sigma double, sensitivity double, count int,
                metadata jsonb, status text, reason text, PRIMARY KEY (id))
    Столбцы status: PENDING|POSTED|REJECTED.
    Если ваша схема иная — I cannot verify this.
    """
    def __init__(self, url: str, advisory_key: int) -> None:
        if not _SA_OK:
            raise RepoError("SQLAlchemy is not available")
        self._engine = sa.create_engine(url, pool_pre_ping=True, future=True)
        self._Session = sessionmaker(bind=self._engine, autoflush=False, autocommit=False, future=True)
        self._advisory_key = advisory_key

    def begin(self):
        return self._Session.begin()

    def _window_filter(self, window: BudgetWindow):
        return sa.and_(
            sa.text("window_start = :ws"),
            sa.text("window_end = :we"),
        )

    def load_current_budgets(self, accounts: Optional[Sequence[str]], window: BudgetWindow) -> Dict[str, DpBudget]:
        with self._Session() as s:
            params = {"ws": window.start, "we": window.end}
            q = "SELECT account_id, epsilon_limit, delta_limit, epsilon_spent, rdp_spent, status, version FROM dp_budgets WHERE window_start = :ws AND window_end = :we"
            if accounts:
                q += " AND account_id = ANY(:accs)"
                params["accs"] = list(accounts)
            rows = s.execute(sa.text(q), params).all()
            out: Dict[str, DpBudget] = {}
            for r in rows:
                out[r[0]] = DpBudget(
                    account_id=r[0],
                    window=window,
                    epsilon_limit=float(r[1]),
                    delta_limit=float(r[2]),
                    epsilon_spent=float(r[3] or 0.0),
                    rdp_spent=dict(r[4] or {}),
                    status=str(r[5] or "ACTIVE"),
                    version=int(r[6] or 0),
                )
            return out

    def load_pending_charges(self, limit: int, window: BudgetWindow) -> List[DpCharge]:
        with self._Session() as s:
            rows = s.execute(sa.text("""
                SELECT id::text, account_id, ts, mechanism, epsilon, delta, sigma, sensitivity, COALESCE(count,1), COALESCE(metadata,'{}'::jsonb)
                FROM dp_ledger
                WHERE status = 'PENDING' AND ts >= :ws AND ts < :we
                ORDER BY ts ASC
                LIMIT :lim
            """), {"ws": window.start, "we": window.end, "lim": limit}).all()
            res: List[DpCharge] = []
            for r in rows:
                res.append(DpCharge(
                    id=str(r[0]), account_id=str(r[1]), ts=r[2].replace(tzinfo=timezone.utc) if r[2].tzinfo is None else r[2],
                    mechanism=str(r[3]), epsilon=r[4], delta=r[5], sigma=r[6], sensitivity=r[7], count=int(r[8]),
                    metadata=dict(r[9] or {}),
                ))
            return res

    def post_charge_and_update_budget(self, charge: DpCharge, budget_before: DpBudget, budget_after: DpBudget, decision: str, reason: str) -> None:
        with self._Session.begin() as s:
            # optimistic version check
            upd = s.execute(sa.text("""
                UPDATE dp_budgets
                SET epsilon_spent = :eps, rdp_spent = :rdp::jsonb, status = :status, version = version + 1
                WHERE account_id = :acc AND window_start = :ws AND window_end = :we AND version = :ver
            """), {
                "eps": budget_after.epsilon_spent,
                "rdp": json.dumps(budget_after.rdp_spent),
                "status": budget_after.status,
                "acc": budget_before.account_id,
                "ws": budget_before.window.start,
                "we": budget_before.window.end,
                "ver": budget_before.version,
            })
            if upd.rowcount != 1:
                raise RepoError("concurrent budget modification")

            upd2 = s.execute(sa.text("""
                UPDATE dp_ledger
                SET status = :st, reason = :rs
                WHERE id = :id AND status = 'PENDING'
            """), {"st": decision, "rs": reason, "id": charge.id})
            if upd2.rowcount != 1:
                raise RepoError("charge already processed")

    def try_advisory_lock(self, key: int) -> bool:
        with self._Session() as s:
            val = s.execute(sa.text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar()
            return bool(val)

    def advisory_unlock(self, key: int) -> None:
        with self._Session() as s:
            s.execute(sa.text("SELECT pg_advisory_unlock(:k)"), {"k": key})
            s.commit()


# =============================================================================
# Reconciler
# =============================================================================

class DpBudgetReconciler:
    def __init__(self, cfg: ReconcilerConfig, repo: AbstractRepo):
        self.cfg = cfg
        self.repo = repo
        self.acc = RdpAccountant(alphas=cfg.default_alphas)

    def reconcile_once(self) -> int:
        """
        Выполняет один цикл согласования.
        Возвращает кол-во обработанных (не обязательно «проведённых») записей леджера.
        """
        t0 = time.time()
        now = datetime.now(timezone.utc)
        win = resolve_window(now, self.cfg)

        # Advisory lock (опционально)
        locked = self.repo.try_advisory_lock(self.cfg.advisory_lock_key)
        if not locked:
            logger.info("advisory_lock_busy", extra={"key": self.cfg.advisory_lock_key})
            return 0

        try:
            charges = self.repo.load_pending_charges(self.cfg.batch_limit, win)
            if not charges:
                return 0

            # Подгружаем бюджеты для затронутых аккаунтов
            accounts = sorted({c.account_id for c in charges})
            budgets = self.repo.load_current_budgets(accounts, win)

            processed = 0
            for ch in charges:
                if time.time() - t0 > self.cfg.cycle_timeout_sec:
                    logger.warning("cycle_timeout_reached", extra={"processed": processed})
                    break

                b = budgets.get(ch.account_id)
                if not b:
                    # Нет бюджета -> отклоняем
                    self._reject(ch, reason="budget_not_found")
                    processed += 1
                    continue

                # «Примеряем» списание к копии бюджета
                b_after = dataclasses.replace(b, rdp_spent=dict(b.rdp_spent), version=b.version)
                try:
                    self._apply_charge_to_budget(ch, b_after)
                except Exception as e:
                    # недопустимые параметры чарджа
                    logger.exception("charge_invalid")
                    self._reject(ch, reason=f"invalid_charge: {e}")
                    processed += 1
                    continue

                # Проверяем лимит
                overflow = (b_after.epsilon_spent > b_after.epsilon_limit + 1e-12) or (b_after.status == "SUSPENDED")
                if overflow and self.cfg.on_overflow == "REJECT":
                    self._reject(ch, reason="epsilon_limit_exceeded")
                    processed += 1
                    continue

                # Иначе — POSTED (либо флаг, если overflow но разрешено)
                if overflow and self.cfg.on_overflow == "ALLOW_WITH_FLAG":
                    reason = "epsilon_limit_exceeded_but_allowed"
                else:
                    reason = "ok"

                # Финализируем статус бюджета
                b_after.status = "EXHAUSTED" if b_after.epsilon_spent >= b_after.epsilon_limit - 1e-12 else "ACTIVE"

                if self.cfg.dry_run:
                    logger.info("dry_run_decision", extra={"charge_id": ch.id, "decision": "POSTED" if not overflow else "FLAGGED", "epsilon_after": b_after.epsilon_spent})
                else:
                    with self.repo.begin():
                        self.repo.post_charge_and_update_budget(
                            charge=ch,
                            budget_before=b,
                            budget_after=dataclasses.replace(b_after, version=b.version + 1),
                            decision="POSTED" if not overflow else "POSTED",
                            reason=reason,
                        )
                    # локально обновим снимок
                    budgets[ch.account_id] = dataclasses.replace(b_after, version=b.version + 1)

                processed += 1

            return processed

        finally:
            try:
                self.repo.advisory_unlock(self.cfg.advisory_lock_key)
            except Exception:
                pass

    # -------------------------- внутренние методы --------------------------

    def _apply_charge_to_budget(self, ch: DpCharge, b_after: DpBudget) -> None:
        """
        Модифицирует b_after (rdp_spent/epsilon_spent) с учётом зарядов.
        """
        if ch.mechanism == "direct":
            if ch.epsilon is None or ch.delta is None:
                raise ValueError("direct charge requires epsilon and delta")
            if not (0.0 < ch.delta < 1.0) or ch.epsilon < 0.0:
                raise ValueError("invalid epsilon/delta")
            # Консервативная аппроксимация direct через RDP (см. RdpAccountant.compose_direct)
            RdpAccountant.compose_direct(ch.epsilon, ch.delta, b_after.rdp_spent, self.acc.alphas)

        elif ch.mechanism == "gaussian":
            if ch.sigma is None:
                raise ValueError("gaussian charge requires sigma")
            sens = ch.sensitivity if (ch.sensitivity is not None and ch.sensitivity > 0) else self.cfg.default_sensitivity
            cnt = int(ch.count or 1)
            self.acc.compose_gaussian(b_after.rdp_spent, sigma=ch.sigma, sensitivity=sens, count=cnt)
        else:
            raise ValueError(f"unknown mechanism: {ch.mechanism}")

        # Пересчитываем epsilon_spent на базе delta_limit бюджета
        eps_new = self.acc.epsilon_at_delta(b_after.rdp_spent, b_after.delta_limit)
        b_after.epsilon_spent = eps_new

    def _reject(self, ch: DpCharge, reason: str) -> None:
        if self.cfg.dry_run:
            logger.info("dry_run_reject", extra={"charge_id": ch.id, "reason": reason})
            return
        # Для InMemoryRepo выполняем внутри begin() no-op
        with self.repo.begin():
            # Мы не меняем бюджет, только статус леджера
            dummy_before = DpBudget(account_id=ch.account_id, window=resolve_window(ch.ts, self.cfg),
                                    epsilon_limit=0.0, delta_limit=1e-9)  # не используется
            dummy_after = dataclasses.replace(dummy_before)
            try:
                self.repo.post_charge_and_update_budget(ch, dummy_before, dummy_after, decision="REJECTED", reason=reason)
            except RepoError:
                # возможно, уже обработан
                logger.warning("reject_conflict", extra={"charge_id": ch.id, "reason": reason})


# =============================================================================
# CLI
# =============================================================================

def _build_repo(cfg: ReconcilerConfig) -> AbstractRepo:
    if cfg.database_url:
        return SQLAlchemyRepo(cfg.database_url, advisory_key=cfg.advisory_lock_key)
    return InMemoryRepo()

def _setup_logging() -> None:
    lvl = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=lvl, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")

def main(argv: Optional[Sequence[str]] = None) -> int:
    _setup_logging()
    cfg = ReconcilerConfig()
    repo = _build_repo(cfg)

    # Если InMemoryRepo — продемонстрируем работу на демо-данных
    if isinstance(repo, InMemoryRepo):
        now = datetime.now(timezone.utc)
        win = resolve_window(now, cfg)
        repo.seed_budget("acctA", win, epsilon_limit=2.0, delta_limit=1e-9)
        repo.seed_charge(DpCharge(id="c1", account_id="acctA", ts=now, mechanism="gaussian", sigma=2.0, sensitivity=1.0, count=10))
        repo.seed_charge(DpCharge(id="c2", account_id="acctA", ts=now, mechanism="direct", epsilon=0.3, delta=1e-9))
        # Малоизвестный формат — будет отклонён
        repo.seed_charge(DpCharge(id="c3", account_id="acctA", ts=now, mechanism="direct", epsilon=-1.0, delta=1e-9))

    reconciler = DpBudgetReconciler(cfg, repo)
    processed = reconciler.reconcile_once()
    logger.info("reconcile_done", extra={"processed": processed})
    return 0

if __name__ == "__main__":
    sys.exit(main())
