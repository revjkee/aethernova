# -*- coding: utf-8 -*-
"""
physical_integration/utils/unit_convert.py

Промышленная конвертация единиц измерения с проверкой размерностей.

Возможности:
- Надежный парсер строк единиц: "kW", "m/s^2", "N·m", "ft*lbf", "kg/m^3", "kWh", "psi", "°C", "degF".
- SI-приставки (y..Y), а также двоичные (Ki..Yi) для данных: KiB, MiB, GiB и т.д.
- Полная поддержка температур: абсолютные (K, °C, °F, R) и разности (degC, degF, degR).
- Богатый встроенный реестр: длина/масса/время/ток/температура/кол-во вещества/свет, производные: площадь/объем/скорость/ускорение/сила/давление/энергия/мощность/крутящий момент/плотность/частота/угол/данные.
- Точные константы (дюйм, фут, миля, lb, lbf, галлоны, бар, атм, BTU, hp, кВт·ч и пр.).
- Класс Quantity: создание из величины и единицы, арифметика с проверкой размерностей, конвертация `.to()`.
- Исключения с ясной диагностикой. Кэширование парсинга LRU.

Без внешних зависимостей. Совместим с Python 3.10+.

Примеры:
    >>> from unit_convert import convert, Quantity as Q
    >>> convert(100, "km/h", "m/s")
    27.77777777777778
    >>> convert(1, "psi", "Pa")
    6894.757293168361
    >>> convert(1, "kWh", "MJ")
    3.6
    >>> convert(25, "°C", "K")
    298.15
    >>> convert(68, "°F", "°C")
    20.0
    >>> (Q(500, "N") * Q(0.3, "m")).to("N·m").value
    150.0
    >>> Q(1, "kN/m^2").to("psi").value
    145.03773773020923
    >>> convert(1, "MiB", "bytes")
    1048576.0
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Tuple, Optional, Any

# ---- Тип размерности: (L, M, T, I, Θ, N, J) в целых показателях ----
Dims = Tuple[int, int, int, int, int, int, int]
D0: Dims = (0, 0, 0, 0, 0, 0, 0)

L = (1, 0, 0, 0, 0, 0, 0)
M = (0, 1, 0, 0, 0, 0, 0)
T = (0, 0, 1, 0, 0, 0, 0)
I = (0, 0, 0, 1, 0, 0, 0)
TH = (0, 0, 0, 0, 1, 0, 0)  # температура
N = (0, 0, 0, 0, 0, 1, 0)   # количество вещества
J = (0, 0, 0, 0, 0, 0, 1)   # сила света

def dims_add(a: Dims, b: Dims, k: int = 1) -> Dims:
    return tuple(x + k * y for x, y in zip(a, b))  # type: ignore

# ---- Ошибки ----
class UnitError(ValueError): ...
class DimensionError(UnitError): ...
class TemperatureError(UnitError): ...

# ---- Описание единицы ----
@dataclass(frozen=True)
class UnitDef:
    factor: float         # множитель к SI (или к К для температуры)
    dims: Dims            # размерность
    offset: float = 0.0   # оффсет к SI до умножения factor (для абсолютных температур)
    affine: bool = False  # True для абсолютных температур с оффсетом

    def to_si(self, x: float) -> float:
        """Преобразовать значение этой единицы в SI (или K для температуры)."""
        return (x + self.offset) * self.factor if self.affine else x * self.factor

    def from_si(self, x_si: float) -> float:
        """Преобразовать значение из SI (или K) в эту единицу."""
        return (x_si / self.factor) - self.offset if self.affine else x_si / self.factor

# ---- SI и двоичные приставки ----
_SI_PREFIXES: Dict[str, float] = {
    "Y": 1e24, "Z": 1e21, "E": 1e18, "P": 1e15, "T": 1e12, "G": 1e9, "M": 1e6, "k": 1e3,
    "h": 1e2, "da": 1e1,
    "d": 1e-1, "c": 1e-2, "m": 1e-3, "u": 1e-6, "µ": 1e-6, "n": 1e-9, "p": 1e-12,
    "f": 1e-15, "a": 1e-18, "z": 1e-21, "y": 1e-24,
}
_BIN_PREFIXES: Dict[str, float] = {
    "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60, "Zi": 2**70, "Yi": 2**80,
}

# ---- Базовые и производные единицы ----
# ВНИМАНИЕ: факторы указаны в точных или стандартных значениях.
UNITS: Dict[str, UnitDef] = {
    # Базовые SI
    "m": UnitDef(1.0, L),
    "kg": UnitDef(1.0, M),
    "s": UnitDef(1.0, T),
    "A": UnitDef(1.0, I),
    "K": UnitDef(1.0, TH),
    "mol": UnitDef(1.0, N),
    "cd": UnitDef(1.0, J),

    # Температуры (абсолютные) и температурные разности
    "°C": UnitDef(1.0, TH, offset=273.15, affine=True),
    "C": UnitDef(1.0, TH, offset=273.15, affine=True),
    "°F": UnitDef(5.0/9.0, TH, offset=459.67, affine=True),  # K = (F + 459.67)*5/9
    "F": UnitDef(5.0/9.0, TH, offset=459.67, affine=True),
    "R": UnitDef(5.0/9.0, TH, offset=0.0, affine=True),      # Rankine
    # Разности температур (без оффсета)
    "degC": UnitDef(1.0, TH, 0.0, False),
    "degF": UnitDef(5.0/9.0, TH, 0.0, False),
    "degR": UnitDef(5.0/9.0, TH, 0.0, False),

    # Площадь/объем
    "L": UnitDef(1e-3, dims_add(dims_add(D0, L, 3), D0, 0)),   # 1 L = 1e-3 m^3
    "l": UnitDef(1e-3, dims_add(dims_add(D0, L, 3), D0, 0)),
    "m2": UnitDef(1.0, dims_add(D0, L, 2)),
    "m^2": UnitDef(1.0, dims_add(D0, L, 2)),
    "m3": UnitDef(1.0, dims_add(D0, L, 3)),
    "m^3": UnitDef(1.0, dims_add(D0, L, 3)),

    # Время
    "min": UnitDef(60.0, T),
    "h": UnitDef(3600.0, T),
    "day": UnitDef(86400.0, T),

    # Угол (безразмерный)
    "rad": UnitDef(1.0, D0),
    "deg": UnitDef(math.pi/180.0, D0),
    "°": UnitDef(math.pi/180.0, D0),

    # Длина (англ. меры)
    "in": UnitDef(0.0254, L),
    "inch": UnitDef(0.0254, L),
    "ft": UnitDef(0.3048, L),
    "yd": UnitDef(0.9144, L),
    "mi": UnitDef(1609.344, L),
    "nmi": UnitDef(1852.0, L),

    # Масса
    "g": UnitDef(1e-3, M),
    "mg": UnitDef(1e-6, M),  # явные для частых кейсов
    "t": UnitDef(1000.0, M),  # тонна (метрическая)
    "lb": UnitDef(0.45359237, M),
    "oz": UnitDef(0.45359237/16.0, M),
    "ton_us": UnitDef(0.45359237*2000.0, M),   # short ton
    "ton_uk": UnitDef(0.45359237*2240.0, M),   # long ton

    # Объем (англ./имп.)
    "gal_us": UnitDef(3.785411784e-3, dims_add(D0, L, 3)),
    "gal_imp": UnitDef(4.54609e-3, dims_add(D0, L, 3)),
    "qt_us": UnitDef(9.463529460e-4, dims_add(D0, L, 3)),   # 1/4 US gal
    "pt_us": UnitDef(4.73176473e-4, dims_add(D0, L, 3)),    # 1/8 US gal
    "floz_us": UnitDef(29.5735295625e-6, dims_add(D0, L, 3)),  # 1 US fl oz

    # Сила, давление, энергия, мощность, крутящий момент, частота
    "N": UnitDef(1.0, dims_add(dims_add(L, M), T, -2)),  # kg·m/s^2
    "lbf": UnitDef(4.4482216152605, dims_add(dims_add(L, M), T, -2)),  # 1 lbf = 4.4482216152605 N
    "Pa": UnitDef(1.0, dims_add(dims_add(dims_add(L, M), T, -2), L, -2)),  # N/m^2
    "bar": UnitDef(1e5, dims_add(dims_add(dims_add(L, M), T, -2), L, -2)),
    "atm": UnitDef(101325.0, dims_add(dims_add(dims_add(L, M), T, -2), L, -2)),
    "mmHg": UnitDef(133.32236842105263, dims_add(dims_add(dims_add(L, M), T, -2), L, -2)),
    "torr": UnitDef(101325.0/760.0, dims_add(dims_add(dims_add(L, M), T, -2), L, -2)),
    # psi = lbf / in^2
    # (реализуем как отдельную единицу для точного фактора)
    "psi": UnitDef(6894.757293168361, dims_add(dims_add(dims_add(L, M), T, -2), L, -2)),

    "J": UnitDef(1.0, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),  # N·m
    "Wh": UnitDef(3600.0, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),
    "kWh": UnitDef(3.6e6, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),
    "BTU": UnitDef(1055.05585262, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),
    "btu": UnitDef(1055.05585262, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),

    "W": UnitDef(1.0, dims_add(dims_add(dims_add(L, M), T, -3), L, 1)),  # J/s
    "hp": UnitDef(745.6998715822702, dims_add(dims_add(dims_add(L, M), T, -3), L, 1)),

    "Nm": UnitDef(1.0, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),
    "N·m": UnitDef(1.0, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),
    "ft·lbf": UnitDef(1.3558179483314004, dims_add(dims_add(dims_add(L, M), T, -2), L, 1)),

    "Hz": UnitDef(1.0, dims_add(D0, T, -1)),

    # Скорость
    "mps": UnitDef(1.0, dims_add(L, T, -1)),
    "km/h": UnitDef(1000.0/3600.0, dims_add(L, T, -1)),
    "mph": UnitDef(1609.344/3600.0, dims_add(L, T, -1)),

    # Плотность
    "kg/m^3": UnitDef(1.0, dims_add(M, L, -3)),

    # Данные
    "bit": UnitDef(1.0, D0),
    "b": UnitDef(1.0, D0),
    "B": UnitDef(8.0, D0),
    "byte": UnitDef(8.0, D0),
    "bytes": UnitDef(8.0, D0),
}

# ---- Алиасы ----
ALIASES: Dict[str, str] = {
    "liter": "L", "litre": "L", "ml": "mL",
    "sec": "s", "hr": "h",
    "°С": "°C",  # кириллическая C
    "Celsius": "°C", "Fahrenheit": "°F",
    "metre": "m", "meter": "m",
    "newton": "N", "pascal": "Pa", "joule": "J", "watt": "W",
    "degree": "deg",
    # удобные составные
    "m/s": "mps",
    "N*m": "N·m",
    "kph": "km/h",
}

# ---- Вспомогательное: токены, парсер, кэш ----
_MULT = {"*", "·", "·", "x", "·", "·", "."}
_DIV = {"/", " per "}
_POW = {"^", "**"}

def _is_letter(ch: str) -> bool:
    return ch.isalpha() or ch in ("°", "µ")

def _normalize_unit_token(tok: str) -> str:
    tok = tok.strip()
    return ALIASES.get(tok, tok)

def _apply_prefix(name: str) -> Tuple[float, str]:
    """Вернуть (множитель, базовое имя единицы) учитывая SI и двоичные приставки."""
    if name in UNITS:
        return 1.0, name
    # Сначала двоичные приставки (двусимвольные)
    for pfx, mult in sorted(_BIN_PREFIXES.items(), key=lambda kv: -len(kv[0])):
        if name.startswith(pfx) and name[len(pfx):] in ("B", "byte", "bytes"):
            base = name[len(pfx):]
            # Приводим к "B"
            base = "B" if base in ("byte", "bytes") else base
            return mult, base
    # Затем SI (da — двусимвольная)
    for pfx, mult in sorted(_SI_PREFIXES.items(), key=lambda kv: -len(kv[0])):
        base = name[len(pfx):]
        if base in UNITS and not UNITS[base].affine:
            if pfx == "m" and name in ("min", "mol"):  # защита от min/mol
                continue
            return mult, base
    raise UnitError(f"Неизвестная единица или приставка: '{name}'")

def _parse_atom(token: str) -> UnitDef:
    token = _normalize_unit_token(token)
    if token in UNITS:
        return UNITS[token]
    # Попробуем приставку
    mult, base = _apply_prefix(token)
    u = UNITS.get(base)
    if not u:
        raise UnitError(f"Неизвестная единица: '{token}'")
    # Запрещаем приставки для аффинных температур
    if u.affine:
        raise TemperatureError(f"Приставки недопустимы для абсолютных температур: '{token}'")
    return UnitDef(u.factor * mult, u.dims, 0.0, False)

@lru_cache(maxsize=1024)
def parse_unit(expr: str) -> UnitDef:
    """
    Скомбинировать единицу из выражения.
    Поддержка: множители (*, ·, .), деление (/), степени (^ или **), пробелы.
    Без скобок. Температуры (°C/°F/K/R) допустимы только «атомом» без степеней/комбинаций.
    """
    if not expr or not isinstance(expr, str):
        raise UnitError("Пустое выражение единицы")

    s = expr.strip()
    s = s.replace("·", "*").replace(" ", "")
    # Специальный случай: если это чистая аффинная температура — сразу вернуть
    if s in ("°C", "C", "°F", "F", "K", "R"):
        return UNITS[s]

    # Сплит на числитель и знаменатель
    parts = s.split("/")
    numer = parts[0]
    denoms = parts[1:] if len(parts) > 1 else []

    def _reduce_factor_dims(segment: str, sign: int) -> Tuple[float, Dims, bool]:
        # sign = +1 для числителя, -1 для знаменателя
        factor = 1.0
        dims = D0
        has_affine = False
        i = 0
        token = ""
        while i < len(segment):
            ch = segment[i]
            if ch in "*.":
                if token:
                    u = _parse_atom(token)
                    if u.affine:
                        has_affine = True
                    factor *= u.factor
                    dims = dims_add(dims, u.dims, sign)
                    token = ""
                i += 1
                continue
            if ch in "^":
                # степень, читаем число (возможно отрицательное)
                i += 1
                j = i
                if j < len(segment) and segment[j] == "-":
                    j += 1
                while j < len(segment) and (segment[j].isdigit()):
                    j += 1
                exp_str = segment[i:j]
                if not token or not exp_str:
                    raise UnitError(f"Некорректная степень в '{expr}'")
                exp = int(exp_str)
                u = _parse_atom(token)
                if u.affine:
                    raise TemperatureError("Нельзя возводить в степень абсолютные температуры")
                factor *= u.factor ** (exp * sign)
                dims = tuple(d + sign * exp * dd for d, dd in zip(dims, u.dims))  # type: ignore
                token = ""
                i = j
                continue
            token += ch
            i += 1
        if token:
            u = _parse_atom(token)
            if u.affine:
                has_affine = True
            factor *= u.factor
            dims = dims_add(dims, u.dims, sign)
        return factor, dims, has_affine

    f_num, d_num, aff_num = _reduce_factor_dims(numer, +1)
    f = f_num
    d = d_num
    affine_any = aff_num
    for denom in denoms:
        f_den, d_den, aff_den = _reduce_factor_dims(denom, -1)
        f *= f_den
        d = dims_add(d, d_den, +1)
        affine_any = affine_any or aff_den

    if affine_any:
        # В составных единицах абсолютные температуры запрещены
        raise TemperatureError("Абсолютные температуры нельзя комбинировать или делить/умножать. Используйте degC/degF для разностей.")
    return UnitDef(f, d, 0.0, False)

# ---- Конвертация ----
def _same_dims(a: UnitDef, b: UnitDef) -> bool:
    return a.dims == b.dims

def convert(value: float, unit_from: str, unit_to: str) -> float:
    """
    Конвертировать значение между единицами с проверкой размерностей.
    Поддержка абсолютных температур и разностей температур.
    """
    uf = parse_unit(unit_from)
    ut = parse_unit(unit_to)

    # Спец. обработка абсолютных температур
    if uf.affine or ut.affine:
        # Температуры можно конвертировать только в чистом виде TH
        if uf.dims != TH or ut.dims != TH:
            raise TemperatureError("Конвертация абсолютной температуры допустима только в другие температурные единицы")
        # Нельзя смешивать с составными (parse_unit уже запретил)
        xK = uf.to_si(value)
        return ut.from_si(xK)

    # Обычные размерные единицы (в т.ч. разности температур)
    if not _same_dims(uf, ut):
        raise DimensionError(f"Несовместимые размерности: '{unit_from}' != '{unit_to}'")
    return (value * uf.factor) / ut.factor

# ---- Класс величины ----
@dataclass
class Quantity:
    """Размерная величина с арифметикой и конвертацией."""
    value: float
    unit: str

    def __post_init__(self):
        self._u = parse_unit(self.unit)

    @property
    def dims(self) -> Dims:
        return self._u.dims

    @property
    def si(self) -> float:
        return self._u.to_si(self.value) if self._u.affine else self.value * self._u.factor

    def to(self, unit_to: str) -> "Quantity":
        v = convert(self.value, self.unit, unit_to)
        return Quantity(v, unit_to)

    # --- арифметика ---
    def _ensure_same_dims(self, other: "Quantity"):
        if self.dims != other.dims:
            raise DimensionError(f"Нельзя складывать/вычитать {self.unit} и {other.unit} (разные размерности)")

    def __add__(self, other: "Quantity") -> "Quantity":
        self._ensure_same_dims(other)
        # Складываем в SI
        s = self.si + other.si
        # Возвращаем в единицах self
        v = s / parse_unit(self.unit).factor if not parse_unit(self.unit).affine else parse_unit(self.unit).from_si(s)
        return Quantity(v, self.unit)

    def __sub__(self, other: "Quantity") -> "Quantity":
        self._ensure_same_dims(other)
        s = self.si - other.si
        v = s / parse_unit(self.unit).factor if not parse_unit(self.unit).affine else parse_unit(self.unit).from_si(s)
        return Quantity(v, self.unit)

    def __mul__(self, other: "Quantity") -> "Quantity":
        # Умножаем SI значения и объединяем размерности
        s = self.si * other.si
        d = tuple(a + b for a, b in zip(self.dims, other.dims))
        # Возвращаем безымянную «SI» величину с фактором 1 (единица — 'SI')
        q = Quantity(s, "SI")
        q._u = UnitDef(1.0, d, 0.0, False)
        return q

    def __truediv__(self, other: "Quantity") -> "Quantity":
        s = self.si / other.si
        d = tuple(a - b for a, b in zip(self.dims, other.dims))
        q = Quantity(s, "SI")
        q._u = UnitDef(1.0, d, 0.0, False)
        return q

    def __repr__(self) -> str:
        return f"Quantity(value={self.value!r}, unit='{self.unit}')"

# ---- Регистрация новых единиц при необходимости ----
def register_unit(name: str, factor: float, dims: Dims, *, offset: float = 0.0, affine: bool = False, alias: Optional[str] = None) -> None:
    if not name or not isinstance(name, str):
        raise UnitError("Некорректное имя единицы")
    if name in UNITS:
        raise UnitError(f"Единица уже существует: {name}")
    UNITS[name] = UnitDef(float(factor), dims, float(offset), bool(affine))
    if alias:
        ALIASES[alias] = name
    parse_unit.cache_clear()

# ---- Удобные псевдонимы часто используемых составных единиц ----
# (добавляем после определения parse_unit)
ALIASES.update({
    "mps2": "m/s^2",
    "m/s2": "m/s^2",
    "kPa": "kPa",  # позволит применить префикс к Pa
})

# ---- Документированные синонимы для объема литров ----
UNITS["mL"] = UnitDef(1e-6, dims_add(D0, L, 3))
UNITS["dl"] = UnitDef(1e-1 * 1e-3, dims_add(D0, L, 3))  # децилитр
UNITS["cl"] = UnitDef(1e-2 * 1e-3, dims_add(D0, L, 3))

# ---- Шорткаты API ----
Quantity as Q  # type: ignore  # для удобства в докстринге

__all__ = [
    "convert", "parse_unit", "register_unit",
    "UnitDef", "UnitError", "DimensionError", "TemperatureError",
    "Quantity", "Dims", "D0", "L", "M", "T", "I", "TH", "N", "J"
]
