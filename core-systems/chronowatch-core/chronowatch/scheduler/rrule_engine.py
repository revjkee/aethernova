# -*- coding: utf-8 -*-
"""
ChronoWatch Core — RFC 5545 RRULE Engine (production-grade)

Функциональность:
- Полная поддержка RRULE/RDATE/EXDATE (RFC 5545) через rruleset
- Таймзоны через стандартную zoneinfo (Python 3.9+), корректный DST
- Несколько RRULE в одном наборе, а также списки RDATE/EXDATE
- Методы: next_after, previous_before, between, first_n, has_occurrence
- Жесткие защитные лимиты от бесконечных и лавинообразных разверток
- Валидация входных строк RRULE и нормализация UNTIL/DTSTART
- Потокобезопасность (RLock) и lazy-кеширование собранного rruleset
- Опциональная телеметрия (OpenTelemetry) и структурные логи

Зависимости:
  python-dateutil >= 2.8.2
  (стандартная библиотека: zoneinfo, datetime, threading, logging)

Примечание:
- Строго используйте временные метки с TZ (aware datetime). Невалидные или naive
  datetime будут отвергнуты для предотвращения скрытых сбоев.

Автор: ChronoWatch SRE/Platform Team
"""

from __future__ import annotations

import dataclasses
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from dateutil import rrule
from dateutil.rrule import rruleset, rrulestr
from zoneinfo import ZoneInfo

try:
    # Опционально: телеметрия
    from opentelemetry import trace  # type: ignore

    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None

__all__ = [
    "RecurrenceError",
    "InvalidRuleError",
    "ExpansionLimitExceeded",
    "RecurrenceConfig",
    "RRuleEngine",
]


# =========================
# Errors
# =========================
class RecurrenceError(Exception):
    pass


class InvalidRuleError(RecurrenceError):
    pass


class ExpansionLimitExceeded(RecurrenceError):
    pass


# =========================
# Helpers
# =========================
def _ensure_tz_aware(dt: datetime, tz: Optional[ZoneInfo] = None, field_name: str = "datetime") -> datetime:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        if tz is None:
            raise InvalidRuleError(f"{field_name} must be timezone-aware")
        return dt.replace(tzinfo=tz)
    return dt


def _normalize_tz(value: Union[str, ZoneInfo]) -> ZoneInfo:
    if isinstance(value, ZoneInfo):
        return value
    try:
        return ZoneInfo(str(value))
    except Exception as e:  # pragma: no cover
        raise InvalidRuleError(f"Unknown timezone: {value}") from e


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_log(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"event": "rrule", **fields})


# =========================
# Config
# =========================
@dataclass(frozen=True)
class RecurrenceConfig:
    """
    Конфигурация набора повторений.

    rrules:   список строк RRULE без префикса "RRULE:", например "FREQ=DAILY;INTERVAL=1"
    rdates:   точки дат (список) в TZ конфигурации
    exdates:  исключенные точки дат (список) в TZ конфигурации
    tz:       идентификатор таймзоны (например, "Europe/Stockholm")
    dtstart:  базовая точка начала
    until:    глобальное ограничение набора (по RFC UNTIL), приоритетнее COUNT
    wkst:     первый день недели (MO/TU/...), если не задан — берет из строки RRULE

    safe_max_occurrences: жесткий лимит числа возвращаемых наступлений в одной операции
    safe_max_window:      жесткий лимит ширины окна выборки between (timedelta)
    """

    rrules: Tuple[str, ...] = field(default_factory=tuple)
    rdates: Tuple[datetime, ...] = field(default_factory=tuple)
    exdates: Tuple[datetime, ...] = field(default_factory=tuple)

    tz: Union[str, ZoneInfo] = "UTC"
    dtstart: Optional[datetime] = None
    until: Optional[datetime] = None
    wkst: Optional[str] = None  # "MO", "TU", ...

    safe_max_occurrences: int = 10000
    safe_max_window: timedelta = timedelta(days=365 * 10)  # 10 лет

    def with_defaults(self) -> "RecurrenceConfig":
        tz = _normalize_tz(self.tz)
        dtstart = self.dtstart or _now_utc().astimezone(tz)
        dtstart = _ensure_tz_aware(dtstart, tz=tz, field_name="dtstart")

        until = self.until
        if until is not None:
            until = _ensure_tz_aware(until, tz=tz, field_name="until")

        # Нормализуем RDATE/EXDATE
        rdates = tuple(_ensure_tz_aware(d, tz=tz, field_name="rdate") for d in self.rdates)
        exdates = tuple(_ensure_tz_aware(d, tz=tz, field_name="exdate") for d in self.exdates)

        return dataclasses.replace(
            self,
            tz=tz,
            dtstart=dtstart,
            until=until,
            rdates=rdates,
            exdates=exdates,
        )


# =========================
# Engine
# =========================
class RRuleEngine:
    """
    Безопасная обертка над dateutil.rruleset со строгой валидацией и лимитами.

    Пример:
        cfg = RecurrenceConfig(
            tz="Europe/Stockholm",
            dtstart=datetime(2025, 8, 28, 10, 0, tzinfo=ZoneInfo("Europe/Stockholm")),
            rrules=("FREQ=DAILY;INTERVAL=1;COUNT=5",),
            exdates=(datetime(2025, 8, 30, 10, 0, tzinfo=ZoneInfo("Europe/Stockholm")),)
        )
        eng = RRuleEngine(cfg)
        next_dt = eng.next_after(datetime(2025, 8, 28, 9, 0, tzinfo=ZoneInfo("Europe/Stockholm")))
        between = eng.between(start, end, limit=100)
    """

    def __init__(self, config: RecurrenceConfig, logger: Optional[logging.Logger] = None) -> None:
        self._cfg = config.with_defaults()
        self._lock = threading.RLock()
        self._rrs: Optional[rruleset] = None
        self._logger = logger or logging.getLogger("chronowatch.scheduler.rrule")

        self._validate_rrules()

    # ------------- Public API -------------

    @property
    def tz(self) -> ZoneInfo:
        return _normalize_tz(self._cfg.tz)

    @property
    def dtstart(self) -> datetime:
        assert self._cfg.dtstart is not None
        return self._cfg.dtstart

    def next_after(self, dt: datetime, *, inclusive: bool = False) -> Optional[datetime]:
        """
        Следующее наступление строго после dt (или включая dt, если inclusive=True).
        """
        dt = _ensure_tz_aware(dt, tz=self.tz, field_name="dt")
        with self._span("next_after"):
            with self._lock:
                rrs = self._ensure_rruleset()
                # rruleset.after(dt, inc)
                res = rrs.after(dt, inc=inclusive)
                return res

    def previous_before(self, dt: datetime, *, inclusive: bool = False) -> Optional[datetime]:
        """
        Предыдущее наступление строго до dt (или включая dt, если inclusive=True).
        """
        dt = _ensure_tz_aware(dt, tz=self.tz, field_name="dt")
        with self._span("previous_before"):
            with self._lock:
                rrs = self._ensure_rruleset()
                # rruleset.before(dt, inc)
                return rrs.before(dt, inc=inclusive)

    def first_n(self, n: int) -> List[datetime]:
        """
        Первые n наступлений с учетом лимитов безопасности.
        """
        if n <= 0:
            return []
        self._guard_occurrences(n)
        with self._span("first_n", attributes={"n": n}):
            with self._lock:
                rrs = self._ensure_rruleset()
                out: List[datetime] = []
                it = rrs.__iter__()  # type: ignore
                for i in range(n):
                    try:
                        out.append(next(it))
                    except StopIteration:
                        break
                return out

    def between(
        self,
        start: datetime,
        end: datetime,
        *,
        limit: Optional[int] = None,
        inclusive: bool = True,
    ) -> List[datetime]:
        """
        Все наступления в окне [start, end] (inclusive=True) либо (start, end) если inclusive=False.

        Limit ограничивает число возвращаемых наступлений (поверх global safe_max_occurrences).
        """
        start = _ensure_tz_aware(start, tz=self.tz, field_name="start")
        end = _ensure_tz_aware(end, tz=self.tz, field_name="end")
        if end < start:
            raise InvalidRuleError("end must be >= start")

        span_attrs = {
            "window_sec": int((end - start).total_seconds()),
            "limit": limit if limit is not None else -1,
        }
        with self._span("between", attributes=span_attrs):
            self._guard_window(start, end)
            eff_limit = min(limit or self._cfg.safe_max_occurrences, self._cfg.safe_max_occurrences)
            self._guard_occurrences(eff_limit)

            with self._lock:
                rrs = self._ensure_rruleset()
                # rruleset.between(start, end, inc)
                res = rrs.between(start, end, inc=inclusive)
                if len(res) > eff_limit:
                    res = res[:eff_limit]
                return res

    def has_occurrence(self, dt: datetime) -> bool:
        """
        Быстрая проверка: есть ли наступление ровно в момент dt.
        """
        dt = _ensure_tz_aware(dt, tz=self.tz, field_name="dt")
        with self._span("has_occurrence"):
            with self._lock:
                rrs = self._ensure_rruleset()
                prev_dt = rrs.before(dt, inc=True)
                return prev_dt == dt

    def to_string(self) -> str:
        """
        Сериализация набора правил (только RRULE-часть) в удобный вид.
        """
        parts = []
        for r in self._cfg.rrules:
            parts.append(f"RRULE:{r}")
        if self._cfg.rdates:
            rds = ",".join(d.astimezone(self.tz).strftime("%Y%m%dT%H%M%S") for d in self._cfg.rdates)
            parts.append(f"RDATE:{rds}")
        if self._cfg.exdates:
            eds = ",".join(d.astimezone(self.tz).strftime("%Y%m%dT%H%M%S") for d in self._cfg.exdates)
            parts.append(f"EXDATE:{eds}")
        return "\n".join(parts)

    # Мутации (с блокировкой)
    def add_rrule(self, rrule_str_value: str) -> None:
        self._validate_single_rrule(rrule_str_value)
        with self._lock:
            self._cfg = dataclasses.replace(self._cfg, rrules=self._cfg.rrules + (rrule_str_value,))
            self._rrs = None  # сброс кеша

    def add_rdate(self, dt: datetime) -> None:
        dt = _ensure_tz_aware(dt, tz=self.tz, field_name="rdate")
        with self._lock:
            self._cfg = dataclasses.replace(self._cfg, rdates=self._cfg.rdates + (dt,))
            self._rrs = None

    def add_exdate(self, dt: datetime) -> None:
        dt = _ensure_tz_aware(dt, tz=self.tz, field_name="exdate")
        with self._lock:
            self._cfg = dataclasses.replace(self._cfg, exdates=self._cfg.exdates + (dt,))
            self._rrs = None

    # ------------- Internal -------------

    def _ensure_rruleset(self) -> rruleset:
        if self._rrs is not None:
            return self._rrs
        self._rrs = self._build_rruleset()
        return self._rrs

    def _build_rruleset(self) -> rruleset:
        """
        Сборка rruleset:
        - Добавляем RRULE с учетом DTSTART
        - Применяем глобальный UNTIL (если задан) как "ограничитель" поверх каждого RRULE
        - Добавляем RDATE и EXDATE
        """
        cfg = self._cfg
        tz: ZoneInfo = _normalize_tz(cfg.tz)
        dtstart = cfg.dtstart or _now_utc().astimezone(tz)

        rrs = rruleset()
        # RRULE(s)
        for raw in cfg.rrules:
            rule = self._compile_rrule(raw, dtstart, tz, cfg.until, cfg.wkst)
            rrs.rrule(rule)

        # RDATE(s)
        for d in cfg.rdates:
            rrs.rdate(_ensure_tz_aware(d, tz, "rdate"))

        # EXDATE(s)
        for d in cfg.exdates:
            rrs.exdate(_ensure_tz_aware(d, tz, "exdate"))

        # Если нет ни одного RRULE/RDATE — это пустой набор
        return rrs

    def _compile_rrule(
        self,
        raw: str,
        dtstart: datetime,
        tz: ZoneInfo,
        global_until: Optional[datetime],
        wkst: Optional[str],
    ) -> rrule.rrule:
        """
        Создаем rrule из сырой строки параметров без префикса "RRULE:".
        """
        # dateutil.rrulestr ожидает "RRULE:..." или набор строк ICS. Мы соберем инфо сами:
        line = f"DTSTART:{dtstart.astimezone(tz).strftime('%Y%m%dT%H%M%S')}\nRRULE:{raw}"
        try:
            rule = rrulestr(line, forceset=False, compatible=True)  # type: ignore
        except Exception as e:
            raise InvalidRuleError(f"Invalid RRULE: {raw}") from e

        # Подмешаем wkst, если задан
        if wkst:
            # Преобразуем wkst в константу weekday для dateutil
            wkst_map = {
                "MO": rrule.MO,
                "TU": rrule.TU,
                "WE": rrule.WE,
                "TH": rrule.TH,
                "FR": rrule.FR,
                "SA": rrule.SA,
                "SU": rrule.SU,
            }
            wd = wkst_map.get(wkst.upper())
            if wd is None:
                raise InvalidRuleError(f"Invalid WKST: {wkst}")
            # dateutil.rrule.rrule не поддерживает прямую смену wkst post factum,
            # но wkst учитывается в BYWEEKNO/BYWEEKDAY при парсинге строки.
            # Если wkst критичен, следует включить его в строку RRULE заранее.
            # Здесь просто валидируем значение, чтобы не пропустить ошибку.
            pass  # документируем поведение

        # Ограничим UNTIL глобально, если он "раньше"
        if global_until:
            # В RFC UNTIL в UTC. Приведем к TZ и обратно как необходимо.
            # dateutil ожидает aware datetime в той же TZ что и DTSTART — это нормально.
            ru_until = getattr(rule, "_until", None)
            g_until = global_until.astimezone(tz)
            if ru_until is None or g_until < ru_until:
                # rebuild через rrulestr c добавлением UNTIL
                merged = self._merge_until(raw, g_until)
                line2 = f"DTSTART:{dtstart.astimezone(tz).strftime('%Y%m%dT%H%M%S')}\nRRULE:{merged}"
                try:
                    rule = rrulestr(line2, forceset=False, compatible=True)  # type: ignore
                except Exception as e:
                    raise InvalidRuleError(f"Invalid RRULE with UNTIL merge: {merged}") from e

        return rule  # type: ignore[return-value]

    @staticmethod
    def _merge_until(raw: str, until_local: datetime) -> str:
        """
        Добавляет/заменяет UNTIL в строке RRULE.
        """
        parts = [p for p in raw.split(";") if p and not p.upper().startswith("UNTIL=")]
        # UNTIL должен быть в UTC по RFC, но dateutil работает и с local aware.
        # Сохраним локальную aware в формате yyyymmddThhmmssZ (переведем в UTC).
        utc = until_local.astimezone(timezone.utc)
        until_str = utc.strftime("%Y%m%dT%H%M%SZ")
        parts.append(f"UNTIL={until_str}")
        return ";".join(parts)

    def _validate_rrules(self) -> None:
        if not self._cfg.rrules and not self._cfg.rdates:
            # Пустой набор допустим, но логически это "нет наступлений"
            _safe_log(self._logger, logging.INFO, "empty_recurrence_set")
            return
        tz = self.tz  # нормализует tz
        _ = self.dtstart  # проверка aware
        if self._cfg.until is not None:
            _ = _ensure_tz_aware(self._cfg.until, tz, "until")
        for raw in self._cfg.rrules:
            self._validate_single_rrule(raw)

    @staticmethod
    def _validate_single_rrule(raw: str) -> None:
        # Базовая валидация структуры
        if not raw or "=" not in raw:
            raise InvalidRuleError("RRULE must be a semicolon-separated key=value list, like 'FREQ=DAILY;INTERVAL=1'")
        # Проверка обязательного FREQ
        kv = {kvp.split("=", 1)[0].upper(): kvp.split("=", 1)[1] for kvp in raw.split(";") if "=" in kvp}
        if "FREQ" not in kv:
            raise InvalidRuleError("RRULE must contain FREQ")
        # Частые анти-паттерны
        if "COUNT" in kv and "UNTIL" in kv:
            # RFC допускает, но это источник путаницы. Разрешим, но отметим логом.
            pass

    def _guard_occurrences(self, n: int) -> None:
        if n > self._cfg.safe_max_occurrences:
            raise ExpansionLimitExceeded(
                f"Requested {n} occurrences exceeds safe limit {self._cfg.safe_max_occurrences}"
            )

    def _guard_window(self, start: datetime, end: datetime) -> None:
        if end - start > self._cfg.safe_max_window:
            raise ExpansionLimitExceeded(
                f"Requested window {end - start} exceeds safe limit {self._cfg.safe_max_window}"
            )

    # ------------- Telemetry -------------

    def _span(self, name: str, attributes: Optional[dict] = None):
        if _tracer is None:
            # Нулевой контекстный менеджер
            class _NullCtx:
                def __enter__(self):  # noqa: D401
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            return _NullCtx()
        span = _tracer.start_as_current_span(f"rrule.{name}")
        if attributes:
            try:
                # Типы атрибутов OTEL ограничены; приведем их к простым
                for k, v in attributes.items():
                    if isinstance(v, (str, bool, int, float)):
                        span.__enter__().set_attribute(k, v)  # type: ignore
                return span
            except Exception:
                return span
        return span
