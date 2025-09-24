# zero-trust-core/zero_trust/risk_engine/scorer.py
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

__all__ = [
    "RiskLevel",
    "RiskFactorResult",
    "RiskScore",
    "RiskConfig",
    "TelemetryProvider",
    "RiskFactor",
    "RiskScorer",
    # bundled factors
    "GeoVelocityFactor",
    "ImpossibleTravelFactor",
    "DevicePostureFactor",
    "AuthFailuresLastHourFactor",
]

# =========================
# Enums / core models
# =========================

class RiskLevel(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class RiskFactorResult:
    """
    Результат вычисления одного фактора.
    raw_score: нормализованный штраф фактора (чем выше, тем хуже), >= 0
    weighted_score: raw_score * weight (заполняется агрегатором)
    reason: короткий код причины/пояснение (логируется, безопасно)
    details: не-PHI/не-PII вспомогательная информация для отладки/аудита
    missing: сигнал отсутствует и применена политика штрафа за отсутствие
    """
    factor_id: str
    raw_score: float
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)
    missing: bool = False
    weighted_score: float = 0.0


@dataclass
class RiskScore:
    """
    Итоговая оценка риска.
    total: суммарный взвешенный штраф
    level: уровень риска по порогам
    factors: список результатов факторов
    """
    subject: Optional[str]
    device_id: Optional[str]
    total: float
    level: str
    factors: List[RiskFactorResult]
    ts: int = field(default_factory=lambda: int(time.time()))


# =========================
# Configuration
# =========================

@dataclass
class RiskConfig:
    """
    Конфигурация риск‑движка.
    weights: веса факторов (id -> weight)
    thresholds: пороги итогового балла для уровней MEDIUM/HIGH/CRITICAL
    missing_signal_penalty: штраф raw_score, если сигнал отсутствует (по умолчанию 1.0)
    cache_ttl_seconds: TTL кэша вычислений для одного (subject, device_id)
    factor_params: произвольные параметры для факторов (словарь словарей)
    """
    weights: Mapping[str, float] = field(default_factory=lambda: {
        "geovelocity": 2.0,
        "impossible_travel": 3.0,
        "device_posture": 2.5,
        "auth_failures_1h": 1.5,
    })
    thresholds: Mapping[str, float] = field(default_factory=lambda: {
        "MEDIUM": 5.0,
        "HIGH": 8.0,
        "CRITICAL": 12.0,
    })
    missing_signal_penalty: float = 1.0
    cache_ttl_seconds: int = 60
    factor_params: Mapping[str, Mapping[str, Any]] = field(default_factory=lambda: {
        "geovelocity": {
            "ok_kmh": 500.0,      # до этой скорости штраф 0
            "warn_kmh": 700.0,    # от ok до warn — растущий штраф
            "crit_kmh": 900.0,    # >= crit_kmh — максимальный штраф фактора
            "max_raw": 4.0,
            "window_seconds": 3600,  # окно анализа последней активности
        },
        "impossible_travel": {
            "threshold_kmh": 900.0,
            "window_seconds": 3600,
            "score": 3.0,
        },
        "device_posture": {
            "map_score": {        # штрафы за доверительные уровни
                "HIGH": 0.0,
                "MEDIUM": 1.5,
                "LOW": 3.0,
                "QUARANTINE": 6.0,
                "UNKNOWN": 2.0,
            },
            "threat_level_bumps": {  # надбавка при повышенной угрозе EDR
                ">=3": 2.0,
                ">=2": 1.0
            },
            "max_raw": 8.0,
        },
        "auth_failures_1h": {
            "buckets": [3, 5, 10],   # границы корзин по кол-ву фейлов
            "scores":  [0.5, 1.0, 2.0, 4.0],  # штрафы по корзинам
            "window_seconds": 3600,
        },
    })


# =========================
# Telemetry provider contract
# =========================

class TelemetryProvider(Protocol):
    """
    Контракт источника телеметрии. Реализуется интеграциями вашей платформы.
    Все методы должны быть НЕблокирующими с точки зрения длительных сетевых вызовов
    (используйте внутренний кэш или быстрый доступ к данным).
    """

    def recent_logins_geo(
        self, subject: str, window_seconds: int
    ) -> List[Tuple[float, float, int]]:
        """
        Возвращает список (lat, lon, ts) за окно, отсортированный по времени (возрастание).
        Достаточно 2-3 последних точек. Пустой список, если данных нет.
        """

    def device_posture(self, device_id: str) -> Tuple[str, int]:
        """
        Возвращает (trust_tier, threat_level), где trust_tier ∈ {"HIGH","MEDIUM","LOW","QUARANTINE","UNKNOWN"},
        threat_level — целое (0..n).
        Если данных нет — верните ("UNKNOWN", 0).
        """

    def auth_failures(
        self, subject: str, window_seconds: int
    ) -> int:
        """
        Возвращает число неуспешных аутентификаций за окно.
        Если данных нет — 0.
        """


# =========================
# Factor interface
# =========================

class RiskFactor(Protocol):
    """
    Интерфейс фактора. Идентификатор фактора (id) должен совпадать с ключом в weights и factor_params.
    """
    id: str

    def compute(
        self,
        subject: Optional[str],
        device_id: Optional[str],
        provider: TelemetryProvider,
        cfg: RiskConfig,
        now: Optional[int] = None,
    ) -> RiskFactorResult:
        ...


# =========================
# Utilities
# =========================

def _now() -> int:
    return int(time.time())


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Расстояние по сфере (км).
    """
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def _cap(x: float, min_v: float = 0.0, max_v: float = 1e9) -> float:
    return max(min_v, min(max_v, x))


# =========================
# Default factors
# =========================

@dataclass
class GeoVelocityFactor:
    """
    Вычисляет максимальную требуемую скорость перемещения между последними событиями входа.
    Нормирует штраф:
      - <= ok_kmh: 0
      - ok_kmh..warn_kmh: линейная шкала до 50% max_raw
      - warn_kmh..crit_kmh: линейная шкала до 100% max_raw
      - >= crit_kmh: max_raw
    """
    id: str = "geovelocity"

    def compute(
        self,
        subject: Optional[str],
        device_id: Optional[str],
        provider: TelemetryProvider,
        cfg: RiskConfig,
        now: Optional[int] = None,
    ) -> RiskFactorResult:
        params = dict(cfg.factor_params.get(self.id, {}))
        win = int(params.get("window_seconds", 3600))
        ok_kmh = float(params.get("ok_kmh", 500.0))
        warn_kmh = float(params.get("warn_kmh", 700.0))
        crit_kmh = float(params.get("crit_kmh", 900.0))
        max_raw = float(params.get("max_raw", 4.0))

        if not subject:
            return RiskFactorResult(self.id, cfg.missing_signal_penalty, "no_subject", missing=True)

        pts = provider.recent_logins_geo(subject, win)
        if len(pts) < 2:
            return RiskFactorResult(self.id, 0.0, "insufficient_points", {"points": len(pts)})

        # Рассчитываем максимальную скорость между соседними точками
        max_kmh = 0.0
        for (lat1, lon1, t1), (lat2, lon2, t2) in zip(pts[:-1], pts[1:]):
            dt_h = max(1e-9, abs(t2 - t1) / 3600.0)
            d_km = _haversine_km(lat1, lon1, lat2, lon2)
            kmh = d_km / dt_h
            if kmh > max_kmh:
                max_kmh = kmh

        if max_kmh <= ok_kmh:
            raw = 0.0
            reason = "velocity_ok"
        elif max_kmh <= warn_kmh:
            part = (max_kmh - ok_kmh) / max(1.0, warn_kmh - ok_kmh)
            raw = part * (max_raw * 0.5)
            reason = "velocity_warn_band"
        elif max_kmh < crit_kmh:
            part = (max_kmh - warn_kmh) / max(1.0, crit_kmh - warn_kmh)
            raw = (max_raw * 0.5) + part * (max_raw * 0.5)
            reason = "velocity_high_band"
        else:
            raw = max_raw
            reason = "velocity_critical"

        return RiskFactorResult(
            factor_id=self.id,
            raw_score=_cap(raw, 0.0, max_raw),
            reason=reason,
            details={"max_kmh": round(max_kmh, 2), "ok": ok_kmh, "warn": warn_kmh, "crit": crit_kmh},
        )


@dataclass
class ImpossibleTravelFactor:
    """
    Бинарный фактор невозможного путешествия: если требуется скорость >= threshold_kmh между
    двумя последними входами в окне — начисляет фиксированный штраф.
    """
    id: str = "impossible_travel"

    def compute(
        self,
        subject: Optional[str],
        device_id: Optional[str],
        provider: TelemetryProvider,
        cfg: RiskConfig,
        now: Optional[int] = None,
    ) -> RiskFactorResult:
        params = dict(cfg.factor_params.get(self.id, {}))
        win = int(params.get("window_seconds", 3600))
        thr = float(params.get("threshold_kmh", 900.0))
        score = float(params.get("score", 3.0))

        if not subject:
            return RiskFactorResult(self.id, cfg.missing_signal_penalty, "no_subject", missing=True)

        pts = provider.recent_logins_geo(subject, win)
        if len(pts) < 2:
            return RiskFactorResult(self.id, 0.0, "insufficient_points", {"points": len(pts)})

        # Берем две последние точки
        (lat1, lon1, t1), (lat2, lon2, t2) = pts[-2], pts[-1]
        dt_h = max(1e-9, abs(t2 - t1) / 3600.0)
        kmh = _haversine_km(lat1, lon1, lat2, lon2) / dt_h
        if kmh >= thr:
            return RiskFactorResult(self.id, score, "impossible_travel", {"kmh": round(kmh, 2), "thr": thr})
        return RiskFactorResult(self.id, 0.0, "ok", {"kmh": round(kmh, 2), "thr": thr})


@dataclass
class DevicePostureFactor:
    """
    Фактор постуры устройства: штраф в зависимости от trust_tier и threat_level EDR.
    """
    id: str = "device_posture"

    def compute(
        self,
        subject: Optional[str],
        device_id: Optional[str],
        provider: TelemetryProvider,
        cfg: RiskConfig,
        now: Optional[int] = None,
    ) -> RiskFactorResult:
        params = dict(cfg.factor_params.get(self.id, {}))
        map_score: Mapping[str, float] = params.get("map_score", {})
        bumps: Mapping[str, float] = params.get("threat_level_bumps", {})
        max_raw = float(params.get("max_raw", 8.0))

        if not device_id:
            return RiskFactorResult(self.id, cfg.missing_signal_penalty, "no_device", missing=True)

        tier, threat = provider.device_posture(device_id)
        base = float(map_score.get(tier or "UNKNOWN", map_score.get("UNKNOWN", 2.0)))
        bump = 0.0
        # простая интерпретация правил надбавок
        if threat >= 3 and ">=3" in bumps:
            bump = float(bumps[">=3"])
        elif threat >= 2 and ">=2" in bumps:
            bump = float(bumps[">=2"])

        raw = _cap(base + bump, 0.0, max_raw)
        return RiskFactorResult(
            self.id,
            raw,
            "device_posture",
            {"tier": tier, "threat": threat, "base": base, "bump": bump, "max": max_raw},
        )


@dataclass
class AuthFailuresLastHourFactor:
    """
    Фактор по числу неуспешных аутентификаций в последнем окне (по умолчанию 1ч).
    Использует ступенчатую шкалу штрафов (buckets/scores).
    """
    id: str = "auth_failures_1h"

    def compute(
        self,
        subject: Optional[str],
        device_id: Optional[str],
        provider: TelemetryProvider,
        cfg: RiskConfig,
        now: Optional[int] = None,
    ) -> RiskFactorResult:
        params = dict(cfg.factor_params.get(self.id, {}))
        win = int(params.get("window_seconds", 3600))
        buckets: List[int] = list(params.get("buckets", [3, 5, 10]))
        scores: List[float] = list(params.get("scores", [0.5, 1.0, 2.0, 4.0]))

        if not subject:
            return RiskFactorResult(self.id, cfg.missing_signal_penalty, "no_subject", missing=True)

        n = int(provider.auth_failures(subject, win))
        # ступенчатое сопоставление
        idx = 0
        while idx < len(buckets) and n >= buckets[idx]:
            idx += 1
        raw = float(scores[min(idx, len(scores) - 1)])
        reason = f"auth_failures_{n}"
        return RiskFactorResult(self.id, raw if n > 0 else 0.0, reason, {"failures": n, "buckets": buckets})


# =========================
# Scorer / Aggregator
# =========================

@dataclass
class _CacheEntry:
    score: RiskScore
    exp: int


class RiskScorer:
    """
    Агрегатор риск‑балла по множеству факторов.

    Использование:
        scorer = RiskScorer(provider=my_provider, config=RiskConfig())
        result = scorer.score(subject="user-123", device_id="dev-1")

    Расширение:
        class MyFactor:
            id = "custom"
            def compute(...): return RiskFactorResult(...)
        scorer.register_factor(MyFactor())

    Контракт провайдера см. TelemetryProvider.
    """

    def __init__(self, provider: TelemetryProvider, config: Optional[RiskConfig] = None):
        self.provider = provider
        self.config = config or RiskConfig()
        self._factors: Dict[str, RiskFactor] = {}
        self._cache: Dict[Tuple[Optional[str], Optional[str]], _CacheEntry] = {}
        # Регистрируем дефолтные факторы
        self.register_factor(GeoVelocityFactor())
        self.register_factor(ImpossibleTravelFactor())
        self.register_factor(DevicePostureFactor())
        self.register_factor(AuthFailuresLastHourFactor())

    # -------- registry --------

    def register_factor(self, factor: RiskFactor) -> None:
        self._factors[factor.id] = factor

    def unregister_factor(self, factor_id: str) -> None:
        self._factors.pop(factor_id, None)

    def list_factors(self) -> List[str]:
        return list(self._factors.keys())

    # -------- scoring --------

    def score(
        self,
        subject: Optional[str],
        device_id: Optional[str],
        include: Optional[Iterable[str]] = None,
        now: Optional[int] = None,
        use_cache: bool = True,
    ) -> RiskScore:
        """
        Вычисляет итоговый риск.
        include — ограничить набор факторов по id.
        use_cache — использовать кэш на TTL.
        """
        ts = now or _now()
        cache_key = (subject, device_id)
        if use_cache:
            ce = self._cache.get(cache_key)
            if ce and ts < ce.exp:
                return ce.score

        # Выберем активные факторы
        if include:
            active_ids = [fid for fid in include if fid in self._factors]
        else:
            active_ids = list(self._factors.keys())

        results: List[RiskFactorResult] = []
        total = 0.0
        for fid in active_ids:
            factor = self._factors[fid]
            res = factor.compute(subject, device_id, self.provider, self.config, now=ts)
            weight = float(self.config.weights.get(fid, 0.0))
            res.weighted_score = res.raw_score * weight
            results.append(res)
            total += res.weighted_score

        level = self._to_level(total)

        out = RiskScore(subject=subject, device_id=device_id, total=round(total, 3), level=level, factors=results, ts=ts)
        if use_cache and self.config.cache_ttl_seconds > 0:
            self._cache[cache_key] = _CacheEntry(score=out, exp=ts + int(self.config.cache_ttl_seconds))
        return out

    # -------- helpers --------

    def _to_level(self, total: float) -> str:
        thr = self.config.thresholds
        # CRITICAL имеет наибольший порог
        critical = float(thr.get("CRITICAL", 12.0))
        high = float(thr.get("HIGH", 8.0))
        medium = float(thr.get("MEDIUM", 5.0))
        if total >= critical:
            return RiskLevel.CRITICAL
        if total >= high:
            return RiskLevel.HIGH
        if total >= medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    # -------- maintenance --------

    def clear_cache(self) -> None:
        self._cache.clear()
