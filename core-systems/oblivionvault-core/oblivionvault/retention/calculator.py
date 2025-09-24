# oblivionvault-core/oblivionvault/retention/calculator.py
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple, Iterable, Sequence, Union
from uuid import UUID, uuid5

from pydantic import BaseModel, Field, validator

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# ------------------------------------------------------------------------------
# Logging (structlog если доступен)
# ------------------------------------------------------------------------------
try:
    import structlog  # type: ignore

    log = structlog.get_logger(__name__)
except Exception:  # pragma: no cover
    log = logging.getLogger(__name__)
    if not log.handlers:
        h = logging.StreamHandler()
        f = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
        h.setFormatter(f)
        log.addHandler(h)
    log.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Доменные перечисления
# ------------------------------------------------------------------------------

class StorageClass(str, Enum):
    hot = "hot"
    warm = "warm"
    cold = "cold"
    glacier = "glacier"


class ActionType(str, Enum):
    transition = "transition"
    delete = "delete"
    anonymize = "anonymize"
    compact = "compact"
    freeze = "freeze"  # информативное действие — зафиксировано hold'ом


class RetentionBasis(str, Enum):
    created_at = "created_at"
    last_access_at = "last_access_at"


class Jurisdiction(str, Enum):
    eu = "eu"
    us = "us"
    ru = "ru"
    global_default = "global"


# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------

def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _align_to_window(dt: datetime, hour: int, minute: int, second: int, tz: Optional[str]) -> datetime:
    """
    Сдвигает момент на ближайшее будущее попадание в сервисное окно BYHOUR:BYMINUTE:BYSECOND.
    Если tz задан — сначала интерпретируем локально, затем возвращаем в UTC.
    """
    base = dt
    if tz and ZoneInfo:
        local = dt.astimezone(ZoneInfo(tz))
        aligned = local.replace(hour=hour, minute=minute, second=second, microsecond=0)
        if aligned <= local:
            aligned = aligned + timedelta(days=1)
        return aligned.astimezone(timezone.utc)
    # Без TZ: работаем в UTC
    aligned = base.replace(hour=hour, minute=minute, second=second, microsecond=0)
    if aligned <= base:
        aligned = aligned + timedelta(days=1)
    return aligned

def _deterministic_jitter_seconds(record_key: str, max_seconds: int) -> int:
    """
    Детерминированный джиттер (0..max_seconds), чтобы «размазывать» действия и
    избегать шторма. Используем UUID5 поверх NAMESPACE_URL + ключ.
    """
    if max_seconds <= 0:
        return 0
    u = uuid5(UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"), record_key)  # NAMESPACE_DNS эквивалентен, семантика не важна
    # Превратим UUID в стабильное число
    val = int.from_bytes(u.bytes, "big")
    return val % (max_seconds + 1)

def _canonical_json(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

# ------------------------------------------------------------------------------
# Стоимостная модель (FinOps)
# ------------------------------------------------------------------------------

class CostModel(Protocol):
    def storage_cost(self, storage_class: StorageClass, bytes_size: int, days: int) -> float:
        """
        Возвращает ориентировочную стоимость хранения за заданное количество дней.
        Метрика: у.е. (конфигурируемая). Реализация может учитывать «per GB-month».
        """

    def transition_cost(self, from_class: StorageClass, to_class: StorageClass, bytes_size: int) -> float:
        """Стоимость операции перехода (миграции)."""

    def delete_cost(self, bytes_size: int) -> float:
        """Стоимость удаления, если провайдер её тарифицирует (обычно 0)."""

    def anonymize_cost(self, bytes_size: int) -> float:
        """Стоимость анонимизации, если применимо."""


class EnvSimpleCostModel(CostModel):
    """
    Простая модель стоимости из переменных окружения.
    Единицы: у.е./GB-месяц для хранения, у.е./GB для операций (переход/удаление/анонимизация).
    """
    def __init__(self) -> None:
        # Хранение
        self._store_rate = {
            StorageClass.hot: float(os.getenv("OV_COST_HOT_GB_MONTH", "0.020")),
            StorageClass.warm: float(os.getenv("OV_COST_WARM_GB_MONTH", "0.012")),
            StorageClass.cold: float(os.getenv("OV_COST_COLD_GB_MONTH", "0.006")),
            StorageClass.glacier: float(os.getenv("OV_COST_GLACIER_GB_MONTH", "0.003")),
        }
        # Операции
        self._op_transition_per_gb = float(os.getenv("OV_COST_TRANSITION_GB", "0.000"))
        self._op_delete_per_gb = float(os.getenv("OV_COST_DELETE_GB", "0.000"))
        self._op_anon_per_gb = float(os.getenv("OV_COST_ANON_GB", "0.000"))

    @staticmethod
    def _gb(bytes_size: int) -> float:
        return bytes_size / (1024 ** 3)

    def storage_cost(self, storage_class: StorageClass, bytes_size: int, days: int) -> float:
        if days <= 0 or bytes_size <= 0:
            return 0.0
        gb = self._gb(bytes_size)
        # month ~ 30.4375 days (среднее по году)
        months = days / 30.4375
        return gb * self._store_rate[storage_class] * months

    def transition_cost(self, from_class: StorageClass, to_class: StorageClass, bytes_size: int) -> float:
        if bytes_size <= 0 or from_class == to_class:
            return 0.0
        return self._gb(bytes_size) * self._op_transition_per_gb

    def delete_cost(self, bytes_size: int) -> float:
        if bytes_size <= 0:
            return 0.0
        return self._gb(bytes_size) * self._op_delete_per_gb

    def anonymize_cost(self, bytes_size: int) -> float:
        if bytes_size <= 0:
            return 0.0
        return self._gb(bytes_size) * self._op_anon_per_gb


# ------------------------------------------------------------------------------
# Схемы входа (контекст) и политики
# ------------------------------------------------------------------------------

class LegalHold(BaseModel):
    code: str = Field(..., min_length=1, max_length=128, description="Идентификатор/номер удержания")
    starts_at: datetime = Field(..., description="UTC datetime начала удержания")
    ends_at: Optional[datetime] = Field(None, description="UTC datetime завершения; None = бессрочно")

    @validator("starts_at", "ends_at", pre=True)
    def _tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _utc(v) if isinstance(v, datetime) else v

    def is_active(self, at: datetime) -> bool:
        at = _utc(at)
        if self.ends_at is None:
            return at >= self.starts_at
        return self.starts_at <= at <= self.ends_at


class RecordContext(BaseModel):
    record_key: str = Field(..., description="Стабильный ключ/ID записи для джиттера")
    created_at: datetime
    last_access_at: Optional[datetime] = None
    size_bytes: int = Field(..., ge=0)
    is_pii: bool = False
    consent_revoked_at: Optional[datetime] = None
    subject_erasure_at: Optional[datetime] = None
    jurisdiction: Jurisdiction = Jurisdiction.global_default
    legal_holds: List[LegalHold] = Field(default_factory=list)
    current_storage_class: StorageClass = StorageClass.hot

    @validator("created_at", "last_access_at", "consent_revoked_at", "subject_erasure_at", pre=True)
    def _tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _utc(v) if isinstance(v, datetime) else v


class RetentionStep(BaseModel):
    after_days: int = Field(..., ge=0, description="Через сколько дней от базы выполнить шаг")
    to_storage_class: Optional[StorageClass] = None
    action: Optional[ActionType] = None  # compact/anonymize и т.п.
    note: Optional[str] = None


class DailyWindow(BaseModel):
    hour: int = Field(2, ge=0, le=23)
    minute: int = Field(0, ge=0, le=59)
    second: int = Field(0, ge=0, le=59)
    timezone: Optional[str] = Field(None, description="IANA TZ, например 'Europe/Stockholm'")

class PiiOverrides(BaseModel):
    erasure_can_override_min: bool = True
    respect_max_retention: bool = True
    # Если отозвано согласие — ограничиваем верхнюю границу относительно события:
    max_days_after_consent_revoke: Optional[int] = None

class JurisdictionOverrides(BaseModel):
    min_days: Optional[int] = None
    max_days: Optional[int] = None
    freeze_on_hold: Optional[bool] = None

class RetentionPolicy(BaseModel):
    name: str
    basis: RetentionBasis = RetentionBasis.created_at
    min_days: int = Field(0, ge=0)
    max_days: Optional[int] = Field(None, ge=1)
    steps: List[RetentionStep] = Field(default_factory=list)
    delete_action: ActionType = ActionType.delete  # delete|anonymize
    soft_delete_grace_days: int = Field(0, ge=0)
    freeze_on_hold: bool = True
    jitter_seconds: int = Field(0, ge=0, le=3600)
    daily_window: Optional[DailyWindow] = None
    pii: PiiOverrides = Field(default_factory=PiiOverrides)
    jurisdiction_overrides: Dict[Jurisdiction, JurisdictionOverrides] = Field(default_factory=dict)

    @validator("steps")
    def _sorted_steps(cls, v: List[RetentionStep]) -> List[RetentionStep]:
        return sorted(v, key=lambda s: s.after_days)


# ------------------------------------------------------------------------------
# Результаты планирования
# ------------------------------------------------------------------------------

class PlannedAction(BaseModel):
    when: datetime
    type: ActionType
    reason: str
    from_storage_class: Optional[StorageClass] = None
    to_storage_class: Optional[StorageClass] = None
    est_cost: float = 0.0

    class Config:
        json_encoders = {datetime: lambda d: d.isoformat()}

class RetentionPlan(BaseModel):
    effective_basis_at: datetime
    effective_min_end: datetime
    effective_max_end: Optional[datetime]
    final_delete_at: Optional[datetime]
    final_action: Optional[ActionType]
    actions: List[PlannedAction]
    final_storage_class: StorageClass
    frozen_by_hold: bool
    notes: List[str] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Исключения домена
# ------------------------------------------------------------------------------

class RetentionError(Exception):
    pass


# ------------------------------------------------------------------------------
# Слияние политик (приоритет слева направо)
# ------------------------------------------------------------------------------

def merge_policies(policies: Sequence[RetentionPolicy]) -> RetentionPolicy:
    """
    Консервативное слияние: берём наиболее строгие параметры.
    Приоритет списка — слева направо (policies[0] — наивысший).
    """
    if not policies:
        raise RetentionError("no policies to merge")

    base = policies[0].dict()
    for p in policies[1:]:
        d = p.dict()
        # База: самый консервативный — created_at (т.к. last_access может продлевать)
        if base["basis"] != RetentionBasis.created_at.value:
            base["basis"] = d["basis"]
        # min — максимум из всех (строже)
        base["min_days"] = max(base["min_days"], d["min_days"])
        # max — минимум из всех заданных (строже)
        if base["max_days"] is None:
            base["max_days"] = d["max_days"]
        elif d["max_days"] is not None:
            base["max_days"] = min(base["max_days"], d["max_days"]) if base["max_days"] is not None else d["max_days"]
        # freeze_on_hold — если где-то True, оставляем True
        base["freeze_on_hold"] = base["freeze_on_hold"] or d["freeze_on_hold"]
        # delete_action — anonymize строже, чем delete (сохраняем anonymize если встречается)
        if base["delete_action"] != ActionType.anonymize.value and d["delete_action"] == ActionType.anonymize.value:
            base["delete_action"] = d["delete_action"]
        # grace — максимум (безопаснее)
        base["soft_delete_grace_days"] = max(base["soft_delete_grace_days"], d["soft_delete_grace_days"])
        # шаги — объединяем и сортируем (дедуп не делаем для простоты)
        base["steps"].extend(d["steps"])
        # jitter — максимум
        base["jitter_seconds"] = max(base["jitter_seconds"], d["jitter_seconds"])
        # daily_window — оставляем первый заданный (явный приоритет)
        if not base["daily_window"] and d["daily_window"]:
            base["daily_window"] = d["daily_window"]
        # pii overrides
        base["pii"]["erasure_can_override_min"] = (
            base["pii"]["erasure_can_override_min"] and d["pii"]["erasure_can_override_min"]
        )
        base["pii"]["respect_max_retention"] = (
            base["pii"]["respect_max_retention"] and d["pii"]["respect_max_retention"]
        )
        if base["pii"]["max_days_after_consent_revoke"] is None:
            base["pii"]["max_days_after_consent_revoke"] = d["pii"]["max_days_after_consent_revoke"]
        elif d["pii"]["max_days_after_consent_revoke"] is not None:
            base["pii"]["max_days_after_consent_revoke"] = min(
                base["pii"]["max_days_after_consent_revoke"], d["pii"]["max_days_after_consent_revoke"]
            )

        # юрисдикции — объединяем, но делаем «строже»
        for j, ov in d["jurisdiction_overrides"].items():
            cur = base["jurisdiction_overrides"].get(j, {})
            if ov.get("min_days") is not None:
                cur["min_days"] = max(cur.get("min_days", 0), ov["min_days"])
            if ov.get("max_days") is not None:
                cur["max_days"] = min(cur.get("max_days", ov["max_days"]), ov["max_days"]) if cur.get("max_days") is not None else ov["max_days"]
            if ov.get("freeze_on_hold") is True:
                cur["freeze_on_hold"] = True
            base["jurisdiction_overrides"][j] = cur

    merged = RetentionPolicy.parse_obj(base)
    merged.steps = sorted(merged.steps, key=lambda s: s.after_days)
    return merged


# ------------------------------------------------------------------------------
# Основной калькулятор
# ------------------------------------------------------------------------------

class RetentionCalculator:
    def __init__(self, cost_model: Optional[CostModel] = None) -> None:
        self._cost = cost_model or EnvSimpleCostModel()

    # ---------------------- публичные методы ----------------------

    def compute_plan(self, ctx: RecordContext, policy: RetentionPolicy) -> RetentionPlan:
        """
        Основной детерминированный расчёт плана с учётом холдов, PII, окон и джиттера.
        """
        now = _now_utc()
        notes: List[str] = []

        # Применяем юрисдикционные оверрайды
        eff_policy = self._apply_jurisdiction(policy, ctx.jurisdiction)

        basis_at = self._basis_date(ctx, eff_policy.basis)
        min_end = basis_at + timedelta(days=eff_policy.min_days)
        max_end = None if eff_policy.max_days is None else basis_at + timedelta(days=eff_policy.max_days)

        # PII‑специфика: отзыв согласия/запрос субъекта
        if ctx.is_pii:
            notes.extend(self._apply_pii_constraints(ctx, eff_policy, basis_at, min_end, max_end))
            # после корректировок min_end/max_end могли обновиться через notes? Нет — вернём значения
            # через кортеж:
            min_end, max_end = self._recompute_min_max_from_notes(basis_at, notes, min_end, max_end)

        # Юридические холды
        frozen = False
        if eff_policy.freeze_on_hold and self._has_active_hold(ctx.legal_holds, now):
            frozen = True
            notes.append("frozen:active_legal_hold")

        # Строим временную шкалу переходов
        actions: List[PlannedAction] = []
        current_class = ctx.current_storage_class
        cursor = now if now > basis_at else basis_at

        if eff_policy.steps:
            for step in eff_policy.steps:
                step_at = basis_at + timedelta(days=step.after_days)
                if max_end and step_at > max_end:
                    break  # после потолка шаги не имеют смысла
                when = self._schedule_time(step_at, eff_policy, ctx.record_key)
                if when <= now:
                    # просроченные шаги: сдвигаем к ближайшему окну в будущем
                    when = self._schedule_time(now + timedelta(seconds=1), eff_policy, ctx.record_key)
                if step.to_storage_class and step.to_storage_class != current_class:
                    cost = 0.0 if frozen else self._cost.transition_cost(current_class, step.to_storage_class, ctx.size_bytes)
                    actions.append(PlannedAction(
                        when=when,
                        type=ActionType.transition,
                        reason=step.note or f"tier:{current_class.value}->{step.to_storage_class.value}",
                        from_storage_class=current_class,
                        to_storage_class=step.to_storage_class,
                        est_cost=0.0 if frozen else cost,
                    ))
                    current_class = step.to_storage_class
                if step.action and step.action != ActionType.transition:
                    actions.append(PlannedAction(
                        when=when,
                        type=step.action,
                        reason=step.note or "step-action",
                        from_storage_class=current_class,
                        to_storage_class=None,
                        est_cost=0.0 if frozen else (
                            self._cost.anonymize_cost(ctx.size_bytes) if step.action == ActionType.anonymize else 0.0
                        ),
                    ))

        # Окончательное действие удаления/анонимизации
        delete_at, final_action = self._compute_final_action_times(
            ctx, eff_policy, basis_at, min_end, max_end
        )

        if delete_at:
            when = self._schedule_time(delete_at, eff_policy, ctx.record_key)
            if when <= now:
                when = self._schedule_time(now + timedelta(seconds=1), eff_policy, ctx.record_key)
            actions.append(PlannedAction(
                when=when,
                type=final_action or eff_policy.delete_action,
                reason="retention-end",
                from_storage_class=current_class,
                to_storage_class=None,
                est_cost=0.0 if frozen else (
                    self._cost.delete_cost(ctx.size_bytes) if (final_action or eff_policy.delete_action) == ActionType.delete
                    else self._cost.anonymize_cost(ctx.size_bytes)
                ),
            ))

        # Если заморожено — помечаем freeze, но не меняем расписание (исполнитель может блокировать выполнение)
        if frozen:
            actions.insert(0, PlannedAction(
                when=now,
                type=ActionType.freeze,
                reason="active_legal_hold",
                from_storage_class=current_class,
                to_storage_class=None,
                est_cost=0.0,
            ))

        # Суммируем длительность хранения для оценки storage_cost по интервалам между действиями
        actions_sorted = sorted(actions, key=lambda a: a.when)
        self._annotate_storage_costs(actions_sorted, ctx.size_bytes, ctx.current_storage_class, basis_at)

        final_storage = actions_sorted[-1].to_storage_class if actions_sorted and actions_sorted[-1].type == ActionType.transition else current_class

        return RetentionPlan(
            effective_basis_at=basis_at,
            effective_min_end=min_end,
            effective_max_end=max_end,
            final_delete_at=delete_at,
            final_action=final_action or eff_policy.delete_action,
            actions=actions_sorted,
            final_storage_class=final_storage or current_class,
            frozen_by_hold=frozen,
            notes=notes,
        )

    async def async_compute_plan(self, ctx: RecordContext, policy: RetentionPolicy) -> RetentionPlan:
        # Обёртка для унификации с остальным async‑кодом проекта
        return self.compute_plan(ctx, policy)

    # ---------------------- внутренние методы ----------------------

    def _apply_jurisdiction(self, policy: RetentionPolicy, j: Jurisdiction) -> RetentionPolicy:
        ov = policy.jurisdiction_overrides.get(j)
        if not ov:
            return policy
        p = policy.copy(deep=True)
        if ov.min_days is not None:
            p.min_days = max(p.min_days, ov.min_days)
        if ov.max_days is not None:
            p.max_days = ov.max_days if p.max_days is None else min(p.max_days, ov.max_days)
        if ov.freeze_on_hold is True:
            p.freeze_on_hold = True
        return p

    def _basis_date(self, ctx: RecordContext, basis: RetentionBasis) -> datetime:
        if basis == RetentionBasis.last_access_at and ctx.last_access_at:
            return ctx.last_access_at
        return ctx.created_at

    def _has_active_hold(self, holds: Iterable[LegalHold], at: datetime) -> bool:
        for h in holds:
            if h.is_active(at):
                return True
        return False

    def _schedule_time(self, dt: datetime, policy: RetentionPolicy, record_key: str) -> datetime:
        dt = _utc(dt)
        # Выравнивание
        if policy.daily_window:
            dt = _align_to_window(dt, policy.daily_window.hour, policy.daily_window.minute, policy.daily_window.second, policy.daily_window.timezone)
        # Джиттер
        js = policy.jitter_seconds
        if js > 0:
            jitter = _deterministic_jitter_seconds(record_key, js)
            dt = dt + timedelta(seconds=jitter)
        return dt

    def _compute_final_action_times(
        self,
        ctx: RecordContext,
        policy: RetentionPolicy,
        basis_at: datetime,
        min_end: datetime,
        max_end: Optional[datetime],
    ) -> Tuple[Optional[datetime], Optional[ActionType]]:
        """
        Возвращает (момент конечного действия, тип действия). Может вернуть None, если max не задан и нет оснований удалять.
        Правила:
          - нижняя граница: min_end
          - верхняя граница: max_end (если задана)
          - erasure/consent revoke могут уменьшать срок, но не нарушая min, если erasure_can_override_min=False
        """
        # Базовый кандидат — min_end
        candidate = min_end
        # Subject erasure
        if ctx.subject_erasure_at:
            if policy.pii.erasure_can_override_min:
                candidate = max(candidate, ctx.subject_erasure_at)
            else:
                candidate = max(candidate, min_end)

        # Consent revoke: если задан max после revoke и это pii
        if ctx.is_pii and ctx.consent_revoked_at and policy.pii.max_days_after_consent_revoke is not None:
            limit = ctx.consent_revoked_at + timedelta(days=policy.pii.max_days_after_consent_revoke)
            candidate = min(candidate, limit)

        # Потолок max_end (если задан): удалить не позже него
        if max_end:
            candidate = min(candidate, max_end)

        # Итог — применяем soft-delete grace
        candidate = candidate + timedelta(days=policy.soft_delete_grace_days)

        return candidate, policy.delete_action

    def _annotate_storage_costs(
        self,
        actions: List[PlannedAction],
        size_bytes: int,
        start_class: StorageClass,
        start_at: datetime,
    ) -> None:
        """
        Грубая оценка стоимости хранения между действиями. Предполагаем, что
        между переходами класс хранения постоянен.
        """
        if not actions:
            return
        current_class = start_class
        cursor = start_at
        for a in actions:
            days = max(0, math.ceil((a.when - cursor).total_seconds() / 86400))
            if days > 0:
                # добавим стоимость хранения как «вложенную» к действию (для отчётности)
                a.est_cost += self._cost.storage_cost(current_class, size_bytes, days)
            if a.type == ActionType.transition and a.to_storage_class:
                current_class = a.to_storage_class
            cursor = a.when

    def _apply_pii_constraints(
        self,
        ctx: RecordContext,
        p: RetentionPolicy,
        basis_at: datetime,
        min_end: datetime,
        max_end: Optional[datetime],
    ) -> List[str]:
        """
        Возвращает список заметок, которые могут повлиять на интерпретацию итогов.
        (Для прозрачности аудита, сами даты пересчитываются отдельно.)
        """
        notes: List[str] = []
        if ctx.subject_erasure_at:
            if p.pii.erasure_can_override_min:
                notes.append("pii:erasure_may_override_min")
            else:
                notes.append("pii:erasure_respects_min")
        if ctx.consent_revoked_at and p.pii.max_days_after_consent_revoke is not None:
            notes.append(f"pii:consent_revoked_limit:{p.pii.max_days_after_consent_revoke}d")
        if p.max_days is not None and p.pii.respect_max_retention:
            notes.append("pii:respect_max_retention")
        return notes

    def _recompute_min_max_from_notes(
        self,
        basis_at: datetime,
        notes: List[str],
        min_end: datetime,
        max_end: Optional[datetime],
    ) -> Tuple[datetime, Optional[datetime]]:
        # В текущей реализации сами даты не меняем, оставляем как есть; хук для кастомной логики.
        return min_end, max_end


# ------------------------------------------------------------------------------
# Утилиты экспорта
# ------------------------------------------------------------------------------

__all__ = [
    "StorageClass",
    "ActionType",
    "RetentionBasis",
    "Jurisdiction",
    "LegalHold",
    "RecordContext",
    "RetentionStep",
    "DailyWindow",
    "PiiOverrides",
    "JurisdictionOverrides",
    "RetentionPolicy",
    "PlannedAction",
    "RetentionPlan",
    "CostModel",
    "EnvSimpleCostModel",
    "RetentionCalculator",
    "merge_policies",
]
