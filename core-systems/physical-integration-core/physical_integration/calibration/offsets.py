# physical_integration/calibration/offsets.py
# Промышленный движок калибровок: модели (affine/poly/piecewise), термокомпенсация,
# дрейф во времени, неопределенность, обратная калибровка, сериализация JSON/YAML.
from __future__ import annotations

import bisect
import dataclasses
import datetime as dt
import json
import math
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

# ---- Опциональные зависимости для YAML ----
try:
    import yaml  # PyYAML
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False

Number = Union[int, float]

# =========================
# Модели и параметры
# =========================

ModelType = Literal["affine", "poly", "pwl"]

@dataclass(frozen=True)
class AffineModel:
    """y = gain * x + offset"""
    gain: float = 1.0
    offset: float = 0.0

@dataclass(frozen=True)
class PolyModel:
    """y = a0 + a1*x + a2*x^2 + ...  (coeffs[k] = a_k)"""
    coeffs: Tuple[float, ...] = (0.0, 1.0)  # по умолчанию y=x

    def degree(self) -> int:
        return max(0, len(self.coeffs) - 1)

@dataclass(frozen=True)
class PWLModel:
    """
    Piecewise-linear: точки (x_raw, y_true) в порядке возрастания x_raw.
    Между точками — линейная интерполяция, вне — экстраполяция по краям.
    """
    points: Tuple[Tuple[float, float], ...]


@dataclass(frozen=True)
class TempComp:
    """
    Темпокомпенсация:
    type='none'|'linear'|'poly'
      linear: y += b1*(T- T0)
      poly:   y += b1*dT + b2*dT^2 + ...
    """
    type: Literal["none", "linear", "poly"] = "none"
    t0_c: float = 25.0
    coeffs: Tuple[float, ...] = ()  # (b1, b2, ...)


@dataclass(frozen=True)
class Drift:
    """
    Дрейф во времени относительно точки отсчёта (ref_time):
      gain_ppm_per_day — относительный дрейф коэффициента усиления (ppm/сутки)
      offset_per_day   — абсолютный дрейф смещения (ед/сутки)
    """
    gain_ppm_per_day: float = 0.0
    offset_per_day: float = 0.0


@dataclass(frozen=True)
class Uncertainty:
    """
    Стандартные неопределенности модели (1σ):
      u_gain, u_offset — для affine; для poly/PWL используйте u_model.
      u_model — агрегированная модельная составляющая.
      u_meas  — неопределенность входного измерения (сырое, 1σ).
    """
    u_gain: float = 0.0
    u_offset: float = 0.0
    u_model: float = 0.0
    u_meas: float = 0.0


@dataclass(frozen=True)
class Validity:
    """Окно валидности калибровки."""
    valid_from: dt.datetime
    valid_to: Optional[dt.datetime] = None  # None = до отмены

@dataclass(frozen=True)
class CalibrationEntry:
    sensor_id: str
    unit_in: str
    unit_out: str
    model_type: ModelType
    model: Union[AffineModel, PolyModel, PWLModel]
    temp_comp: TempComp = TempComp()
    drift: Drift = Drift()
    uncertainty: Uncertainty = Uncertainty()
    validity: Validity = field(default_factory=lambda: Validity(valid_from=dt.datetime.now(dt.timezone.utc)))
    metadata: Dict[str, Any] = field(default_factory=dict)
    version: str = "1.0.0"

    def is_active(self, ts: Optional[dt.datetime]) -> bool:
        ts = ts or dt.datetime.now(dt.timezone.utc)
        start = self.validity.valid_from
        end = self.validity.valid_to
        return (ts >= start) and (end is None or ts < end)


@dataclass
class CalibrationResult:
    value: float
    unit: str
    u_std: float
    components: Dict[str, float]  # decomposition of u
    used_entry: CalibrationEntry

# =========================
# Вычисление модели
# =========================

def _eval_model(model: Union[AffineModel, PolyModel, PWLModel], x: float) -> float:
    if isinstance(model, AffineModel):
        return model.gain * x + model.offset
    if isinstance(model, PolyModel):
        # Горнер
        y = 0.0
        for a in reversed(model.coeffs):
            y = a + x * y
        return y
    if isinstance(model, PWLModel):
        pts = model.points
        xs = [p[0] for p in pts]
        i = bisect.bisect_left(xs, x)
        if i == 0:
            x0, y0 = pts[0]
            x1, y1 = pts[1] if len(pts) > 1 else (x0 + 1e-9, y0)
        elif i >= len(pts):
            x0, y0 = pts[-2] if len(pts) > 1 else (pts[-1][0] - 1e-9, pts[-1][1])
            x1, y1 = pts[-1]
        else:
            x0, y0 = pts[i - 1]; x1, y1 = pts[i]
        if abs(x1 - x0) < 1e-12:
            return y0
        alpha = (x - x0) / (x1 - x0)
        return y0 + alpha * (y1 - y0)
    raise TypeError("Unknown model type")

def _apply_temp_comp(y: float, comp: TempComp, t_c: Optional[float]) -> float:
    if comp.type == "none" or t_c is None:
        return y
    dT = (t_c - comp.t0_c)
    if comp.type == "linear":
        b1 = comp.coeffs[0] if comp.coeffs else 0.0
        return y + b1 * dT
    # poly
    acc = 0.0
    for k, b in enumerate(comp.coeffs, start=1):
        acc += b * (dT ** k)
    return y + acc

def _apply_drift(y: float, base: AffineModel, drift: Drift, ref_time: dt.datetime, ts: Optional[dt.datetime]) -> Tuple[float, AffineModel]:
    """
    Применяет дрейф к gain/offset относительно ref_time (обычно validity.valid_from).
    Возвращает новое значение и «эффективную» affine‑модель после дрейфа.
    Для poly/PWL дрейф применяем к эквивалентной affine аппроксимации локально (для u/оценки).
    """
    if ts is None:
        return y, base
    days = (ts - ref_time).total_seconds() / 86400.0
    g = base.gain * (1.0 + drift.gain_ppm_per_day * 1e-6 * days)
    o = base.offset + drift.offset_per_day * days
    # Пересчитать выход:
    # y' = g/g0*(y - o0) + o
    if abs(base.gain) > 1e-30:
        y_prime = (g / base.gain) * (y - base.offset) + o
    else:
        y_prime = y + (o - base.offset)
    return y_prime, AffineModel(gain=g, offset=o)

def _poly_derivative_at(poly: PolyModel, x: float) -> float:
    """dy/dx для полинома."""
    deg = poly.degree()
    if deg <= 0:
        return 0.0
    s = 0.0; p = 1.0
    for k in range(1, deg + 1):
        p *= x  # x^k
        s += k * poly.coeffs[k] * (x ** (k - 1))  # стабильней без p накопления
    return s

# =========================
# Неопределенность (1σ)
# =========================

def _uncertainty_affine(x: float, model: AffineModel, u: Uncertainty) -> Tuple[float, Dict[str, float]]:
    """
    y = g*x + o
    var(y) ~ (g^2 u_x^2) + (x^2 u_g^2) + (1^2 u_o^2) + u_model^2
    """
    ug2 = (u.u_gain ** 2) * (x ** 2)
    uo2 = (u.u_offset ** 2)
    # u_meas относится к x: g^2 * u_x^2
    ux2 = (model.gain ** 2) * (u.u_meas ** 2)
    um2 = (u.u_model ** 2)
    var = ug2 + uo2 + ux2 + um2
    comp = {"u_g": math.sqrt(ug2), "u_o": math.sqrt(uo2), "u_x": math.sqrt(ux2), "u_model": math.sqrt(um2)}
    return math.sqrt(max(var, 0.0)), comp

def _uncertainty_poly(x: float, poly: PolyModel, u: Uncertainty) -> Tuple[float, Dict[str, float]]:
    """
    y = f(x), var(y) ~ (f'(x)^2 u_x^2) + u_model^2
    (не учитываем дисперсию коэффициентов — они сагрегированы в u_model)
    """
    dydx = _poly_derivative_at(poly, x)
    ux2 = (dydx ** 2) * (u.u_meas ** 2)
    um2 = (u.u_model ** 2)
    var = ux2 + um2
    comp = {"u_x": math.sqrt(ux2), "u_model": math.sqrt(um2)}
    return math.sqrt(max(var, 0.0)), comp

def _uncertainty_pwl(x: float, pwl: PWLModel, u: Uncertainty) -> Tuple[float, Dict[str, float]]:
    """
    Для кусочно-линейной модели используем локальный наклон и u_model.
    """
    pts = pwl.points
    xs = [p[0] for p in pts]
    i = bisect.bisect_left(xs, x)
    if i == 0:
        x0, y0 = pts[0]; x1, y1 = pts[min(1, len(pts)-1)]
    elif i >= len(pts):
        x0, y0 = pts[max(len(pts)-2, 0)]; x1, y1 = pts[-1]
    else:
        x0, y0 = pts[i-1]; x1, y1 = pts[i]
    slope = 0.0 if abs(x1 - x0) < 1e-12 else (y1 - y0) / (x1 - x0)
    ux2 = (slope ** 2) * (u.u_meas ** 2)
    um2 = (u.u_model ** 2)
    var = ux2 + um2
    comp = {"u_x": math.sqrt(ux2), "u_model": math.sqrt(um2)}
    return math.sqrt(max(var, 0.0)), comp

# =========================
# Применение калибровки
# =========================

def _to_utc(ts: Optional[dt.datetime]) -> Optional[dt.datetime]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc)

def apply_entry(entry: CalibrationEntry, raw_value: Number, t_c: Optional[float] = None, ts: Optional[dt.datetime] = None) -> CalibrationResult:
    """
    Применить конкретную запись калибровки к сырому значению.
    """
    ts = _to_utc(ts)
    x = float(raw_value)

    # 1) Базовая модель
    if isinstance(entry.model, AffineModel):
        y0 = _eval_model(entry.model, x)
        # 2) Термокомпенсация
        y1 = _apply_temp_comp(y0, entry.temp_comp, t_c)
        # 3) Дрейф
        y2, eff_affine = _apply_drift(y1, entry.model, entry.drift, entry.validity.valid_from, ts)
        # 4) Неопределенность
        u_std, comp = _uncertainty_affine(x, eff_affine, entry.uncertainty)
        return CalibrationResult(value=y2, unit=entry.unit_out, u_std=u_std, components=comp, used_entry=entry)

    if isinstance(entry.model, PolyModel):
        y0 = _eval_model(entry.model, x)
        y1 = _apply_temp_comp(y0, entry.temp_comp, t_c)
        # аппроксимация дрейфа: применим к эквивалентной affine локально в точке x
        dydx = _poly_derivative_at(entry.model, x)
        local_affine = AffineModel(gain=dydx if abs(dydx) > 1e-30 else 1.0, offset=y1 - dydx * x)
        y2, _ = _apply_drift(y1, local_affine, entry.drift, entry.validity.valid_from, ts)
        u_std, comp = _uncertainty_poly(x, entry.model, entry.uncertainty)
        return CalibrationResult(value=y2, unit=entry.unit_out, u_std=u_std, components=comp, used_entry=entry)

    if isinstance(entry.model, PWLModel):
        y0 = _eval_model(entry.model, x)
        y1 = _apply_temp_comp(y0, entry.temp_comp, t_c)
        # локальный наклон
        pts = entry.model.points
        xs = [p[0] for p in pts]
        i = bisect.bisect_left(xs, x)
        if i == 0:
            x0, y0p = pts[0]; x1, y1p = pts[min(1, len(pts)-1)]
        elif i >= len(pts):
            x0, y0p = pts[max(len(pts)-2, 0)]; x1, y1p = pts[-1]
        else:
            x0, y0p = pts[i-1]; x1, y1p = pts[i]
        slope = 0.0 if abs(x1 - x0) < 1e-12 else (y1p - y0p) / (x1 - x0)
        local_affine = AffineModel(gain=slope if abs(slope) > 1e-30 else 1.0, offset=y1 - slope * x)
        y2, _ = _apply_drift(y1, local_affine, entry.drift, entry.validity.valid_from, ts)
        u_std, comp = _uncertainty_pwl(x, entry.model, entry.uncertainty)
        return CalibrationResult(value=y2, unit=entry.unit_out, u_std=u_std, components=comp, used_entry=entry)

    raise TypeError("Unsupported model in entry")

def invert_entry(entry: CalibrationEntry, true_value: Number, t_c: Optional[float] = None, ts: Optional[dt.datetime] = None) -> float:
    """
    Обратная калибровка: оценить сырое значение из истинного.
    Для poly/PWL используется численное решение (Ньютон/секущих).
    """
    ts = _to_utc(ts)
    y_target = float(true_value)

    def f(x: float) -> float:
        return apply_entry(entry, x, t_c=t_c, ts=ts).value

    # Для affine можем решить аналитически по «эффективной» модели:
    if isinstance(entry.model, AffineModel):
        # обратим термокомпенсацию и дрейф приблизительно (итерация)
        # быстрый метод: численный поиск вокруг линейной оценки
        g = entry.model.gain if abs(entry.model.gain) > 1e-30 else 1.0
        x0 = (y_target - entry.model.offset) / g
        return _solve_scalar(f, y_target, x0)

    # Poly/PWL — численно
    # выберем разумную стартовую точку
    x0 = y_target
    return _solve_scalar(f, y_target, x0)

def _solve_scalar(f, y_target: float, x0: float) -> float:
    """
    Решение f(x)=y_target методом секущих с ограничением итераций.
    """
    x_prev = x0 - 1.0 if x0 != 0.0 else -1.0
    y_prev = f(x_prev) - y_target
    x_curr = x0
    y_curr = f(x_curr) - y_target
    for _ in range(20):
        denom = (y_curr - y_prev)
        if abs(denom) < 1e-12:
            break
        x_next = x_curr - y_curr * (x_curr - x_prev) / denom
        x_prev, y_prev = x_curr, y_curr
        x_curr, y_curr = x_next, f(x_next) - y_target
        if abs(y_curr) < 1e-6:
            break
    return float(x_curr)

# =========================
# Хранилище калибровок
# =========================

class CalibrationStore:
    """
    Потокобезопасное хранилище калибровок с версионированием и сериализацией.
    """
    def __init__(self):
        self._by_sensor: Dict[str, List[CalibrationEntry]] = {}
        self._lock = threading.RLock()

    def add(self, entry: CalibrationEntry) -> None:
        with self._lock:
            seq = self._by_sensor.setdefault(entry.sensor_id, [])
            seq.append(entry)
            seq.sort(key=lambda e: e.validity.valid_from)

    def active(self, sensor_id: str, ts: Optional[dt.datetime] = None) -> Optional[CalibrationEntry]:
        with self._lock:
            if sensor_id not in self._by_sensor:
                return None
            ts = _to_utc(ts) or dt.datetime.now(dt.timezone.utc)
            for e in reversed(self._by_sensor[sensor_id]):
                if e.is_active(ts):
                    return e
            return None

    def apply(self, sensor_id: str, raw_value: Number, t_c: Optional[float] = None, ts: Optional[dt.datetime] = None) -> CalibrationResult:
        e = self.active(sensor_id, ts)
        if e is None:
            raise KeyError(f"No active calibration for sensor_id={sensor_id}")
        return apply_entry(e, raw_value, t_c=t_c, ts=ts)

    # ----- Сериализация -----
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            def ser_model(m):
                if isinstance(m, AffineModel):  return {"type": "affine", "gain": m.gain, "offset": m.offset}
                if isinstance(m, PolyModel):    return {"type": "poly", "coeffs": list(m.coeffs)}
                if isinstance(m, PWLModel):     return {"type": "pwl", "points": [list(p) for p in m.points]}
                raise TypeError("unknown model")
            out: Dict[str, Any] = {"calibrations": []}
            for sid, entries in self._by_sensor.items():
                for e in entries:
                    out["calibrations"].append({
                        "sensor_id": e.sensor_id,
                        "unit_in": e.unit_in,
                        "unit_out": e.unit_out,
                        "version": e.version,
                        "model": ser_model(e.model),
                        "temp_comp": {
                            "type": e.temp_comp.type,
                            "t0_c": e.temp_comp.t0_c,
                            "coeffs": list(e.temp_comp.coeffs),
                        },
                        "drift": {
                            "gain_ppm_per_day": e.drift.gain_ppm_per_day,
                            "offset_per_day": e.drift.offset_per_day,
                        },
                        "uncertainty": {
                            "u_gain": e.uncertainty.u_gain,
                            "u_offset": e.uncertainty.u_offset,
                            "u_model": e.uncertainty.u_model,
                            "u_meas": e.uncertainty.u_meas,
                        },
                        "validity": {
                            "valid_from": e.validity.valid_from.astimezone(dt.timezone.utc).isoformat(),
                            "valid_to": e.validity.valid_to.astimezone(dt.timezone.utc).isoformat() if e.validity.valid_to else None,
                        },
                        "metadata": e.metadata,
                    })
            return out

    @staticmethod
    def _parse_model(obj: Dict[str, Any]) -> Union[AffineModel, PolyModel, PWLModel]:
        t = obj.get("type")
        if t == "affine":
            return AffineModel(gain=float(obj.get("gain", 1.0)), offset=float(obj.get("offset", 0.0)))
        if t == "poly":
            coeffs = tuple(float(c) for c in obj.get("coeffs", [0.0, 1.0]))
            return PolyModel(coeffs=coeffs)
        if t == "pwl":
            pts = tuple((float(a), float(b)) for a, b in obj.get("points", []))
            if len(pts) < 2:
                raise ValueError("PWL requires >=2 points")
            xs = [p[0] for p in pts]
            if xs != sorted(xs):
                raise ValueError("PWL points must be sorted by x")
            return PWLModel(points=pts)
        raise ValueError(f"Unknown model type: {t}")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CalibrationStore":
        store = cls()
        for row in data.get("calibrations", []):
            vf = row["validity"]["valid_from"]
            vt = row["validity"]["valid_to"]
            entry = CalibrationEntry(
                sensor_id=row["sensor_id"],
                unit_in=row["unit_in"],
                unit_out=row["unit_out"],
                model_type=row["model"].get("type"),
                model=cls._parse_model(row["model"]),
                temp_comp=TempComp(
                    type=row["temp_comp"].get("type", "none"),
                    t0_c=float(row["temp_comp"].get("t0_c", 25.0)),
                    coeffs=tuple(float(c) for c in row["temp_comp"].get("coeffs", [])),
                ),
                drift=Drift(
                    gain_ppm_per_day=float(row["drift"].get("gain_ppm_per_day", 0.0)),
                    offset_per_day=float(row["drift"].get("offset_per_day", 0.0)),
                ),
                uncertainty=Uncertainty(
                    u_gain=float(row["uncertainty"].get("u_gain", 0.0)),
                    u_offset=float(row["uncertainty"].get("u_offset", 0.0)),
                    u_model=float(row["uncertainty"].get("u_model", 0.0)),
                    u_meas=float(row["uncertainty"].get("u_meas", 0.0)),
                ),
                validity=Validity(
                    valid_from=_parse_dt(vf),
                    valid_to=_parse_dt(vt) if vt else None,
                ),
                metadata=row.get("metadata", {}),
                version=row.get("version", "1.0.0"),
            )
            store.add(entry)
        return store

    # ----- Файлы -----
    def save_json(self, path: Union[str, Path]) -> None:
        data = self.to_dict()
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2))

    @classmethod
    def load_json(cls, path: Union[str, Path]) -> "CalibrationStore":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)

    def save_yaml(self, path: Union[str, Path]) -> None:
        if not _HAS_YAML:
            raise RuntimeError("PyYAML is not installed")
        data = self.to_dict()
        Path(path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))

    @classmethod
    def load_yaml(cls, path: Union[str, Path]) -> "CalibrationStore":
        if not _HAS_YAML:
            raise RuntimeError("PyYAML is not installed")
        data = yaml.safe_load(Path(path).read_text())
        return cls.from_dict(data)


# =========================
# Утилиты
# =========================

def _parse_dt(s: str) -> dt.datetime:
    # Поддержка ISO 8601 с таймзоной/без — по умолчанию UTC
    d = dt.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else dt.datetime.now(dt.timezone.utc)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)

# =========================
# Пример использования
# =========================
if __name__ == "__main__":
    # Пример калибровки для тензодатчика: y = 2.0005 * x + 0.12, b1 = 0.01 ед/°C, дрейф +5 ppm/день по gain, +0.0002 ед/день по offset
    entry = CalibrationEntry(
        sensor_id="loadcell-123",
        unit_in="raw_counts",
        unit_out="kg",
        model_type="affine",
        model=AffineModel(gain=2.0005, offset=0.12),
        temp_comp=TempComp(type="linear", t0_c=25.0, coeffs=(0.01,)),
        drift=Drift(gain_ppm_per_day=5.0, offset_per_day=0.0002),
        uncertainty=Uncertainty(u_gain=0.0005, u_offset=0.02, u_model=0.01, u_meas=0.5),
        validity=Validity(valid_from=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)),
        metadata={"operator": "QA", "bench": "M1"},
    )

    store = CalibrationStore()
    store.add(entry)

    # Применение
    now = dt.datetime.now(dt.timezone.utc)
    res = store.apply("loadcell-123", raw_value=1234.5, t_c=30.0, ts=now)
    print(f"value={res.value:.4f} {res.unit}, u={res.u_std:.4f}, components={res.components}")

    # Сохранение/загрузка
    tmp = Path("./calibrations.json")
    store.save_json(tmp)
    loaded = CalibrationStore.load_json(tmp)
    res2 = loaded.apply("loadcell-123", raw_value=1234.5, t_c=30.0, ts=now)
    print(f"loaded value={res2.value:.4f} {res2.unit}, u={res2.u_std:.4f}")
