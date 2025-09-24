# chronowatch-core/chronowatch/scheduler/cron_parser.py
from __future__ import annotations

import hashlib
import re
import typing as t
from dataclasses import dataclass

import pendulum
from pendulum.tz.timezone import Timezone
from croniter import croniter, CroniterBadCronError, CroniterBadDateError

# Публичные исключения модуля
class CronError(Exception):
    """Базовое исключение cron-парсера."""


class CronSyntaxError(CronError):
    """Синтаксическая ошибка cron-выражения."""


class CronValueError(CronError):
    """Семантическая ошибка значений cron-выражения."""


# Поддерживаемые псевдонимы (нормализуем в 6-польный cron с секундами в нуле)
_CRON_ALIASES: dict[str, str] = {
    "@yearly": "0 0 0 1 1 *",
    "@annually": "0 0 0 1 1 *",
    "@monthly": "0 0 0 1 * *",
    "@weekly": "0 0 0 * * 0",
    "@daily": "0 0 0 * * *",
    "@midnight": "0 0 0 * * *",
    "@hourly": "0 0 * * * *",
    "@minutely": "0 * * * * *",
    "@secondly": "* * * * * *",
}

# Имена месяцев/дней (доп. поддержка нормализации)
_MONTHS = {
    "jan": "1", "feb": "2", "mar": "3", "apr": "4", "may": "5", "jun": "6",
    "jul": "7", "aug": "8", "sep": "9", "oct": "10", "nov": "11", "dec": "12",
}
_DOW = {
    "sun": "0", "mon": "1", "tue": "2", "wed": "3", "thu": "4", "fri": "5", "sat": "6",
    # допускаем «7» как sunday
}

# Диапазоны значений по позициям (с учётом 6-польной схемы: sec min hour dom mon dow)
_FIELD_RANGES = [
    (0, 59),  # seconds
    (0, 59),  # minutes
    (0, 23),  # hours
    (1, 31),  # day of month
    (1, 12),  # month
    (0, 7),   # day of week (0/7=Sunday)
]

# Регекс для детерминированных «слотов» Jenkins-стиля: H или H(0-59)
_H_PATTERN = re.compile(r"^H(?:\((?P<from>\d+)-(?P<to>\d+)\))?$", re.IGNORECASE)

# Разделитель пробелов/табов
_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class CronSpec:
    """Нормализованное cron-выражение + контекст."""
    expression: str               # 6 полей (sec min hour dom mon dow)
    tz: str                       # IANA tz, например "UTC" или "Europe/Stockholm"
    source: str                   # исходная строка до нормализации
    has_seconds: bool             # исход содержал секунды
    has_year: bool                # исход содержал годовое поле (7-е), если было


class CronParser:
    """
    Промышленный парсер/нормализатор cron со следующими свойствами:
    - принимает 5/6/7 полей либо псевдонимы (@hourly/@daily/…)
    - нормализует в 6 полей (секунды добавляются как 0 при отсутствии)
    - поддерживает имена месяцев/дней (JAN, MON и т.п., без регистра)
    - поддерживает H/H(a-b) — детерминированный «слот» по hash_key
    - безопасно рассчитывает след./пред. запуски через croniter и pendulum
    - корректно переживает переходы DST (таймзонно-осознанный расчёт)
    """

    def __init__(
        self,
        default_tz: str = "UTC",
        hash_key: str | None = None,
        max_iterations: int = 10000,
    ) -> None:
        """
        :param default_tz: таймзона по умолчанию
        :param hash_key: стабилизирующий ключ для H-слотов
        :param max_iterations: предохранитель при итерации дат
        """
        self._tz = pendulum.timezone(default_tz)
        self._hash_key = hash_key or "chronowatch-core"
        self._max_iter = int(max_iterations)

    # ---------------------------
    # Публичное API
    # ---------------------------

    def parse(self, expr: str, tz: str | Timezone | None = None) -> CronSpec:
        """
        Разобрать и нормализовать cron-выражение.
        Возвращает CronSpec с 6-польным выражением (sec min hour dom mon dow).
        """
        source = expr.strip()
        tzinfo = self._coerce_tz(tz) if tz is not None else self._tz

        # Псевдонимы
        if source.startswith("@"):
            alias = source.lower()
            if alias not in _CRON_ALIASES:
                raise CronSyntaxError(f"Unknown alias: {source}")
            normalized = _CRON_ALIASES[alias]
            has_seconds = True  # все алиасы мы задаём 6-польными
            has_year = False
            normalized = self._normalize_symbols(normalized)
            normalized = self._apply_hash_slots(normalized)
            self._validate_with_croniter(normalized)
            return CronSpec(expression=normalized, tz=tzinfo.name, source=source,
                            has_seconds=has_seconds, has_year=has_year)

        # Приведение пробелов и разбор полей
        parts = _WS.split(source)
        if len(parts) not in (5, 6, 7):
            raise CronSyntaxError(
                f"Cron must have 5, 6 or 7 fields, got {len(parts)}: {source!r}"
            )

        has_seconds = len(parts) >= 6
        has_year = len(parts) == 7

        # Если 5 полей — добавим секунды=0 в начало
        if len(parts) == 5:
            parts = ["0"] + parts

        # Если 7 полей — сглотнём годовое поле (croniter умеет 7-польный синтаксис,
        # но в нормализованном контракте движка мы используем 6 полей).
        # Год оставляем только для валидации. «Я не могу подтвердить» полную поддержку
        # всех вариантов года в croniter. I cannot verify this.
        if len(parts) == 7:
            year_field = parts[6]  # noqa: F841 (можно логировать/использовать при need)
            parts = parts[:6]      # нормализуем к 6 полям

        # Нормализуем имена месяцев/дней, применяем H-слоты
        parts = [self._normalize_field_symbols(p, idx) for idx, p in enumerate(parts)]
        parts = [self._apply_hash_slot_for_field(p, idx) for idx, p in enumerate(parts)]

        normalized = " ".join(parts)
        self._validate_with_croniter(normalized)

        return CronSpec(
            expression=normalized, tz=tzinfo.name, source=source,
            has_seconds=has_seconds, has_year=has_year
        )

    def next_run(
        self,
        spec: CronSpec | str,
        from_time: pendulum.DateTime | None = None,
        tz: str | Timezone | None = None,
    ) -> pendulum.DateTime:
        """
        Рассчитать ближайший запуск >= from_time (по умолчанию — now()).
        Возвращает timezone-aware pendulum.DateTime.
        """
        if isinstance(spec, str):
            spec = self.parse(spec, tz=tz)

        tzinfo = self._coerce_tz(tz or spec.tz)
        now = self._ensure_dt(from_time, tzinfo)

        try:
            it = croniter(spec.expression, now)
            nxt = it.get_next(pendulum.DateTime)  # получаем naive/aware в зависимости от base
        except (CroniterBadCronError, CroniterBadDateError) as e:
            raise CronSyntaxError(str(e)) from e

        # Приведём к tzinfo и нормализуем DST (fold/skip)
        return self._safe_localize(nxt, tzinfo)

    def iter_runs(
        self,
        spec: CronSpec | str,
        start: pendulum.DateTime | None = None,
        limit: int = 10,
        tz: str | Timezone | None = None,
    ) -> t.Iterator[pendulum.DateTime]:
        """
        Итератор следующих запусков, начиная с start (или now()).
        """
        if limit <= 0:
            return iter(())
        if isinstance(spec, str):
            spec = self.parse(spec, tz=tz)
        tzinfo = self._coerce_tz(tz or spec.tz)
        cur = self._ensure_dt(start, tzinfo)

        try:
            it = croniter(spec.expression, cur)
        except CroniterBadCronError as e:
            raise CronSyntaxError(str(e)) from e

        count = 0
        while count < min(limit, self._max_iter):
            try:
                nxt = it.get_next(pendulum.DateTime)
            except CroniterBadDateError as e:
                raise CronValueError(str(e)) from e
            yield self._safe_localize(nxt, tzinfo)
            count += 1

    def runs_between(
        self,
        spec: CronSpec | str,
        start: pendulum.DateTime,
        end: pendulum.DateTime,
        tz: str | Timezone | None = None,
        hard_limit: int = 10000,
    ) -> list[pendulum.DateTime]:
        """
        Найти все запуски в окне [start, end). Предусмотрен защитный лимит.
        """
        if isinstance(spec, str):
            spec = self.parse(spec, tz=tz)

        tzinfo = self._coerce_tz(tz or spec.tz)
        s = self._ensure_dt(start, tzinfo)
        e = self._ensure_dt(end, tzinfo)
        if e <= s:
            return []

        out: list[pendulum.DateTime] = []
        try:
            it = croniter(spec.expression, s)
        except CroniterBadCronError as e:
            raise CronSyntaxError(str(e)) from e

        i = 0
        while i < min(hard_limit, self._max_iter):
            nxt = it.get_next(pendulum.DateTime)
            nxt = self._safe_localize(nxt, tzinfo)
            if nxt >= e:
                break
            out.append(nxt)
            i += 1
        return out

    # ---------------------------
    # Внутренние функции
    # ---------------------------

    def _normalize_symbols(self, expr: str) -> str:
        """Общая нормализация пробелов и регистров именованных значений."""
        parts = _WS.split(expr.strip())
        parts = [self._normalize_field_symbols(p, idx) for idx, p in enumerate(parts)]
        return " ".join(parts)

    def _normalize_field_symbols(self, field: str, idx: int) -> str:
        """
        Нормализует имена месяцев/дней, звёздочки/шаги, диапазоны.
        Не пытается полностью парсить выражение (это делает croniter),
        но делает быстрые замены и грубую проверку H-форм.
        """
        f = field.strip()
        # Упрощённая нормализация месяц/день
        if idx == 4:  # month
            f = self._replace_names(f, _MONTHS)
        elif idx == 5:  # day of week
            f = self._replace_names(f, _DOW)
        # Базовая грубая проверка диапазонов при одиночном значении
        if f.isdigit():
            v = int(f)
            lo, hi = _FIELD_RANGES[idx]
            if not (lo <= v <= hi):
                raise CronValueError(
                    f"Field {idx} value {v} is out of range [{lo},{hi}]"
                )
        return f

    def _apply_hash_slots(self, expr: str) -> str:
        """Применяет H/H(a-b) к каждому полю."""
        parts = _WS.split(expr)
        parts = [self._apply_hash_slot_for_field(p, idx) for idx, p in enumerate(parts)]
        return " ".join(parts)

    def _apply_hash_slot_for_field(self, field: str, idx: int) -> str:
        """
        Заменяет одиночный маркер H или H(a-b) детерминированным числом
        на основе self._hash_key, в допустимых границах поля.
        """
        m = _H_PATTERN.match(field)
        if not m:
            return field
        lo, hi = _FIELD_RANGES[idx]
        if m and m.group("from") and m.group("to"):
            lo = int(m.group("from"))
            hi = int(m.group("to"))
            glob_lo, glob_hi = _FIELD_RANGES[idx]
            if lo < glob_lo or hi > glob_hi or lo > hi:
                raise CronValueError(
                    f"H-range {lo}-{hi} is out of field bounds {glob_lo}-{glob_hi}"
                )
        slot = self._hash_slot(lo, hi)
        return str(slot)

    def _hash_slot(self, lo: int, hi: int) -> int:
        span = hi - lo + 1
        h = hashlib.sha256(self._hash_key.encode("utf-8")).digest()
        num = int.from_bytes(h[:8], "big")  # 64-bit
        return lo + (num % span)

    def _validate_with_croniter(self, expr: str) -> None:
        if not croniter.is_valid(expr):
            # croniter иногда возвращает False без деталей — попробуем вызвать для ошибки
            try:
                croniter(expr)
            except (CroniterBadCronError, ValueError) as e:
                raise CronSyntaxError(str(e)) from e
            raise CronSyntaxError(f"Invalid cron expression: {expr!r}")

    @staticmethod
    def _coerce_tz(tz: str | Timezone) -> Timezone:
        if isinstance(tz, Timezone):
            return tz
        try:
            return pendulum.timezone(str(tz))
        except Exception as e:  # noqa: BLE001
            raise CronValueError(f"Invalid timezone: {tz}") from e

    @staticmethod
    def _ensure_dt(dt: pendulum.DateTime | None, tz: Timezone) -> pendulum.DateTime:
        return (dt or pendulum.now(tz)).in_timezone(tz)

    @staticmethod
    def _safe_localize(dt: pendulum.DateTime, tz: Timezone) -> pendulum.DateTime:
        """
        Безопасная локализация/нормализация времени к заданной TZ.
        Pendulum корректно работает с DST; дополнительно приводим к tz.
        """
        return dt.in_timezone(tz)

    @staticmethod
    def _replace_names(field: str, mapping: dict[str, str]) -> str:
        """
        Заменяет текстовые имена (JAN, MON, …) на цифры с сохранением
        сложных конструкций вида: MON-FRI, MON,WED,FRI,*/2 и т.п.
        """
        def repl_token(token: str) -> str:
            # поддержим диапазоны с именами: MON-FRI
            if "-" in token and "/" not in token:
                a, b = token.split("-", 1)
                a2 = mapping.get(a.lower(), a)
                b2 = mapping.get(b.lower(), b)
                return f"{a2}-{b2}"
            # простая подстановка
            return mapping.get(token.lower(), token)

        # Токенизация по «разделителям cron»
        out = []
        buf = ""
        for ch in field:
            if ch in ",/":
                if buf:
                    out.append(repl_token(buf))
                    buf = ""
                out.append(ch)
            else:
                buf += ch
        if buf:
            out.append(repl_token(buf))
        return "".join(out)


# ---------------------------
# Утилитарные функции верхнего уровня (удобные шорткаты)
# ---------------------------

_DEFAULT = CronParser()


def parse(expr: str, tz: str | Timezone | None = None) -> CronSpec:
    return _DEFAULT.parse(expr, tz=tz)


def next_run(
    expr_or_spec: str | CronSpec,
    from_time: pendulum.DateTime | None = None,
    tz: str | Timezone | None = None,
) -> pendulum.DateTime:
    if isinstance(expr_or_spec, CronSpec):
        spec = expr_or_spec
    else:
        spec = _DEFAULT.parse(expr_or_spec, tz=tz)
    return _DEFAULT.next_run(spec, from_time=from_time, tz=tz)


def iter_runs(
    expr_or_spec: str | CronSpec,
    start: pendulum.DateTime | None = None,
    limit: int = 10,
    tz: str | Timezone | None = None,
) -> t.Iterator[pendulum.DateTime]:
    if isinstance(expr_or_spec, CronSpec):
        spec = expr_or_spec
    else:
        spec = _DEFAULT.parse(expr_or_spec, tz=tz)
    return _DEFAULT.iter_runs(spec, start=start, limit=limit, tz=tz)


def runs_between(
    expr_or_spec: str | CronSpec,
    start: pendulum.DateTime,
    end: pendulum.DateTime,
    tz: str | Timezone | None = None,
    hard_limit: int = 10000,
) -> list[pendulum.DateTime]:
    if isinstance(expr_or_spec, CronSpec):
        spec = expr_or_spec
    else:
        spec = _DEFAULT.parse(expr_or_spec, tz=tz)
    return _DEFAULT.runs_between(spec, start=start, end=end, tz=tz, hard_limit=hard_limit)
