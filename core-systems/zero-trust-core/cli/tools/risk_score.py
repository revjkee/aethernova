# zero-trust-core/cli/tools/risk_score.py
"""
Zero-Trust Risk Scoring CLI
===========================

Назначение:
- Расчёт риск-скоринга (0..100) для событий доступа в Zero Trust.
- Объяснимость (per-factor contribution).
- Политические решения: ALLOW / MFA / DENY / QUARANTINE по порогам и жёстким правилам.
- Потоковая обработка NDJSON.
- Опциональное поддержание состояния в SQLite для детекции "невозможных поездок".
- Конфигурирование весов и правил через JSON (без внешних зависимостей).
- Трассировка через ULID/UUID, без утечек PII в логи.

Зависимости: стандартная библиотека Python 3.10+
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import glob
import io
import ipaddress
import json
import logging
import math
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, MutableMapping, Optional, Tuple

# Опционально: ULID из ранее созданного модуля crypto_random
def _gen_correlation_id() -> str:
    try:
        from zero_trust.utils.crypto_random import ulid as _ulid  # type: ignore
        return _ulid()
    except Exception:
        # Fallback: UUIDv4 без дефисов
        return uuid.uuid4().hex


# --------------------------
# Константы и схемы
# --------------------------

DEFAULT_THRESHOLDS = {
    "allow": 40.0,       # <= 40 -> allow
    "mfa": 70.0,         # (40, 70] -> step-up/MFA
    "deny": 85.0,        # (70, 85] -> high risk, может быть block или require approval
    "quarantine": 95.0,  # > 95 -> полная блокировка/изоляция
}

DEFAULT_WEIGHTS = {
    "version": 1,
    "aggregator": "weighted_sum",  # weighted_sum | pnorm | softmax
    "pnorm": 2.0,  # для p-norm
    "factors": {
        # Каждое значение нормализуется в 0..100 до агрегации
        "identity_risk": 0.18,
        "device_posture": 0.16,
        "network_risk": 0.10,
        "resource_sensitivity": 0.12,
        "behavior_risk": 0.14,
        "geo_velocity_risk": 0.10,
        "threat_intel": 0.14,
        "time_risk": 0.06,
    },
    "hard_rules": {
        # Жёсткие правила перекрывают агрегацию
        "deny_if_threat_intel_ge": 90.0,
        "deny_if_geo_velocity_ge": 98.0,
        "mfa_if_device_posture_ge": 70.0,
    },
    "thresholds": DEFAULT_THRESHOLDS,
    "calibration": {
        # Параметры логистической калибровки итогового балла
        "enabled": True,
        "k": 0.08,   # крутизна
        "x0": 60.0,  # середина
        "min": 0.0,
        "max": 100.0,
    },
}

# Поля входного события (все необязательные, по умолчанию 0/None)
INPUT_FIELDS = {
    "actor_id": str,                # строковый ID пользователя/актора
    "device_id": str,               # строковый ID устройства
    "timestamp": (int, float, str), # unix_ts (сек/мс) или ISO8601
    "identity_risk": (int, float),  # 0..100
    "device_posture": (int, float), # 0..100
    "network_risk": (int, float),   # 0..100
    "resource_sensitivity": (int, float), # 0..100
    "behavior_risk": (int, float),  # 0..100
    "threat_intel": (int, float),   # 0..100
    "time_risk": (int, float),      # 0..100 (если не дано — вычислим)
    # Геопараметры для "невозможной поездки"
    "geo": dict,                    # {"lat": float, "lon": float}
    "ip": str,                      # исходный IP (для валидации/гео, если нужно расширить)
}

SAFE_LOG_KEYS = {"actor_id", "device_id"}  # допускаем в логах только эти идентификаторы


# --------------------------
# Утилиты
# --------------------------

def _now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)

def _parse_timestamp(ts: Any) -> dt.datetime:
    if ts is None:
        return _now_utc()
    if isinstance(ts, (int, float)):
        # поддержка секунд или миллисекунд
        if ts > 10_000_000_000:  # миллисекунды
            return dt.datetime.fromtimestamp(ts / 1000.0, tz=dt.timezone.utc)
        return dt.datetime.fromtimestamp(float(ts), tz=dt.timezone.utc)
    if isinstance(ts, str):
        # простой разбор ISO8601
        try:
            return dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
        except Exception:
            raise ValueError("Invalid ISO8601 timestamp")
    raise ValueError("Unsupported timestamp type")

def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))

def _clamp100(x: float) -> float:
    return max(0.0, min(100.0, x))

def _sigmoid(x: float, k: float = 0.08, x0: float = 60.0) -> float:
    return 1.0 / (1.0 + math.exp(-k * (x - x0)))

def _calibrate(score: float, params: Dict[str, Any]) -> float:
    if not params.get("enabled", False):
        return _clamp100(score)
    k = float(params.get("k", 0.08))
    x0 = float(params.get("x0", 60.0))
    out_min = float(params.get("min", 0.0))
    out_max = float(params.get("max", 100.0))
    s = _sigmoid(score, k=k, x0=x0)
    return _clamp100(out_min + (out_max - out_min) * s)

def _safe_log_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if k in SAFE_LOG_KEYS}

def _km_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Haversine
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))

def _extract_ip(ip_str: Optional[str]) -> Optional[str]:
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
        return str(ip)
    except ValueError:
        return None

def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and math.isfinite(x)

def _norm_0_100(v: Any) -> float:
    return _clamp100(float(v)) if _is_number(v) else 0.0


# --------------------------
# SQLite состояние для geo-velocity
# --------------------------

class StateStore:
    """
    Простое хранилище (SQLite) последнего наблюдения по actor_id:
    - timestamp (UTC)
    - lat/lon
    Используется для расчёта скорости перемещения между запросами.
    """
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(self.path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS actor_state(
                   actor_id TEXT PRIMARY KEY,
                   ts INTEGER NOT NULL,
                   lat REAL,
                   lon REAL
               ) WITHOUT ROWID;"""
        )
        self._conn.commit()

    def get(self, actor_id: str) -> Optional[Tuple[int, Optional[float], Optional[float]]]:
        cur = self._conn.execute(
            "SELECT ts, lat, lon FROM actor_state WHERE actor_id = ?",
            (actor_id,),
        )
        row = cur.fetchone()
        return (row[0], row[1], row[2]) if row else None

    def put(self, actor_id: str, ts_unix_ms: int, lat: Optional[float], lon: Optional[float]) -> None:
        self._conn.execute(
            "INSERT INTO actor_state(actor_id, ts, lat, lon) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(actor_id) DO UPDATE SET ts=excluded.ts, lat=excluded.lat, lon=excluded.lon",
            (actor_id, ts_unix_ms, lat, lon),
        )
        self._conn.commit()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()


# --------------------------
# Счётчики риска по факторам
# --------------------------

@dataclass
class FactorOutput:
    name: str
    value: float  # нормализованный 0..100
    weight: float
    contribution: float  # value*weight (для weighted_sum) или эквивалент агрегатора

@dataclass
class RiskResult:
    correlation_id: str
    score_raw: float
    score: float
    decision: str
    factors: List[FactorOutput] = field(default_factory=list)
    hard_rule_triggered: Optional[str] = None
    thresholds: Dict[str, float] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: _now_utc().isoformat())

class RiskScorer:
    def __init__(self, weights_config: Dict[str, Any]):
        self.cfg = self._validate_config(weights_config)
        self.weights = self.cfg["factors"]
        self.aggregator = self.cfg.get("aggregator", "weighted_sum")
        self.pnorm = float(self.cfg.get("pnorm", 2.0))
        self.hard_rules = self.cfg.get("hard_rules", {})
        self.thresholds = self.cfg.get("thresholds", DEFAULT_THRESHOLDS)
        self.calibration = self.cfg.get("calibration", {"enabled": False})

    @staticmethod
    def _validate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(cfg, dict):
            raise ValueError("Weights config must be a dict")
        if "factors" not in cfg or not isinstance(cfg["factors"], dict):
            raise ValueError("Weights config must contain 'factors'")
        total_w = sum(float(w) for w in cfg["factors"].values())
        if total_w <= 0:
            raise ValueError("Sum of factor weights must be > 0")
        # Нормализуем веса до суммы 1.0
        norm = {k: float(v) / total_w for k, v in cfg["factors"].items()}
        cfg = dict(cfg)
        cfg["factors"] = norm
        return cfg

    def _compute_time_risk(self, ts: dt.datetime) -> float:
        # Пример: ночные обращения выше риск (локально по UTC; при необходимости — подать локальный offset в событии)
        hour = ts.hour
        # 0..4 и 22..23 — повышенный риск
        if 0 <= hour <= 4 or 22 <= hour <= 23:
            return 70.0
        if 5 <= hour <= 7 or 20 <= hour <= 21:
            return 40.0
        return 15.0  # рабочие часы

    def _compute_geo_velocity(self, actor_id: Optional[str], ts: dt.datetime,
                              geo: Optional[Dict[str, Any]], state: Optional[StateStore]) -> float:
        if not actor_id or not state:
            return 0.0
        lat = lon = None
        if isinstance(geo, dict):
            try:
                lat = float(geo.get("lat"))
                lon = float(geo.get("lon"))
            except Exception:
                lat = lon = None
        prev = state.get(actor_id)
        ts_ms = int(ts.timestamp() * 1000)
        if lat is not None and lon is not None:
            state.put(actor_id, ts_ms, lat, lon)
        else:
            state.put(actor_id, ts_ms, None, None)
        if not prev or prev[1] is None or prev[2] is None or lat is None or lon is None:
            return 0.0
        prev_ts_ms, prev_lat, prev_lon = prev
        dt_hours = max(0.001, (ts_ms - prev_ts_ms) / 3600_000.0)
        dist_km = _km_distance(prev_lat, prev_lon, lat, lon)
        v = dist_km / dt_hours  # км/ч
        # Маппинг скорости в риск: <150 км/ч -> ~0; 900 км/ч -> ~90; >1200 -> ~99
        if v <= 150.0:
            return 0.0
        if v >= 1200.0:
            return 99.0
        # кусочно-линейно
        return _clamp100( (v - 150.0) * (90.0 / (900.0 - 150.0)) )

    def _apply_hard_rules(self, factors: Dict[str, float]) -> Optional[str]:
        ti = factors.get("threat_intel", 0.0)
        if ti >= float(self.hard_rules.get("deny_if_threat_intel_ge", 10_000.0)):
            return "deny_if_threat_intel_ge"
        gv = factors.get("geo_velocity_risk", 0.0)
        if gv >= float(self.hard_rules.get("deny_if_geo_velocity_ge", 10_000.0)):
            return "deny_if_geo_velocity_ge"
        dp = factors.get("device_posture", 0.0)
        if dp >= float(self.hard_rules.get("mfa_if_device_posture_ge", 10_000.0)):
            return "mfa_if_device_posture_ge"
        return None

    def _aggregate(self, values: Dict[str, float]) -> Tuple[float, List[FactorOutput]]:
        # values: уже нормализованы 0..100
        contributions: List[FactorOutput] = []
        if self.aggregator == "weighted_sum":
            s = 0.0
            for k, v in values.items():
                w = float(self.weights.get(k, 0.0))
                c = v * w
                contributions.append(FactorOutput(k, v, w, c))
                s += c
            raw = s
        elif self.aggregator == "pnorm":
            p = max(1e-6, float(self.pnorm))
            # нормируем 0..1, применяем p-норму, масштабируем до 0..100
            acc = 0.0
            for k, v in values.items():
                w = float(self.weights.get(k, 0.0))
                vv = _clamp01(v / 100.0)
                acc += w * (vv ** p)
            raw = 100.0 * (acc ** (1.0 / p))
            # contribution как w*v (для согласованности отображения)
            for k, v in values.items():
                w = float(self.weights.get(k, 0.0))
                contributions.append(FactorOutput(k, v, w, v * w))
        elif self.aggregator == "softmax":
            # softmax по v/100, затем взвешенная сумма
            exps: Dict[str, float] = {}
            mx = max(values.values() or [0.0])
            for k, v in values.items():
                exps[k] = math.exp((v - mx) / 15.0)  # температура 15
            z = sum(exps.values()) or 1.0
            s = 0.0
            for k, v in values.items():
                w = float(self.weights.get(k, 0.0))
                sm = exps[k] / z
                c = 100.0 * sm * w
                contributions.append(FactorOutput(k, v, w, c))
                s += c
            raw = s
        else:
            raise ValueError(f"Unknown aggregator: {self.aggregator}")
        return _clamp100(raw), contributions

    def score_event(self, event: Dict[str, Any], state: Optional[StateStore] = None) -> RiskResult:
        # Извлечение и нормализация входа
        actor_id = str(event.get("actor_id") or "")
        device_id = str(event.get("device_id") or "")
        ts = _parse_timestamp(event.get("timestamp"))
        # Базовые факторы
        vals: Dict[str, float] = {
            "identity_risk": _norm_0_100(event.get("identity_risk")),
            "device_posture": _norm_0_100(event.get("device_posture")),
            "network_risk": _norm_0_100(event.get("network_risk")),
            "resource_sensitivity": _norm_0_100(event.get("resource_sensitivity")),
            "behavior_risk": _norm_0_100(event.get("behavior_risk")),
            "threat_intel": _norm_0_100(event.get("threat_intel")),
        }
        # time_risk
        if _is_number(event.get("time_risk")):
            vals["time_risk"] = _norm_0_100(event.get("time_risk"))
        else:
            vals["time_risk"] = self._compute_time_risk(ts)

        # geo_velocity_risk
        geo = event.get("geo") if isinstance(event.get("geo"), dict) else None
        vals["geo_velocity_risk"] = self._compute_geo_velocity(actor_id or device_id, ts, geo, state)

        # Жёсткие правила
        hard_rule = self._apply_hard_rules(vals)

        # Агрегация
        raw, contribs = self._aggregate(vals)

        # Калибровка
        calibrated = _calibrate(raw, self.calibration)

        # Решение по порогам и правилу
        decision = self._decision(calibrated, hard_rule)

        return RiskResult(
            correlation_id=_gen_correlation_id(),
            score_raw=raw,
            score=calibrated,
            decision=decision,
            factors=contribs,
            hard_rule_triggered=hard_rule,
            thresholds=dict(self.thresholds),
            ts=_now_utc().isoformat(),
        )

    def _decision(self, score: float, hard_rule: Optional[str]) -> str:
        thr = self.thresholds
        if hard_rule in ("deny_if_threat_intel_ge", "deny_if_geo_velocity_ge"):
            return "DENY"
        if hard_rule == "mfa_if_device_posture_ge":
            # Минимум MFA, но если очень высокий скор — DENY
            if score > float(thr.get("quarantine", 95.0)):
                return "QUARANTINE"
            if score > float(thr.get("deny", 85.0)):
                return "DENY"
            return "MFA"
        if score <= float(thr.get("allow", 40.0)):
            return "ALLOW"
        if score <= float(thr.get("mfa", 70.0)):
            return "MFA"
        if score <= float(thr.get("deny", 85.0)):
            return "LIMITED"  # ограниченный доступ/контейнеризация
        if score <= float(thr.get("quarantine", 95.0)):
            return "DENY"
        return "QUARANTINE"


# --------------------------
# Ввод/вывод
# --------------------------

def _read_json_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _write_json_file(path: str, obj: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _load_weights(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return json.loads(json.dumps(DEFAULT_WEIGHTS))
    data = _read_json_file(path)
    return data

def _result_to_json(res: RiskResult, explain: bool = True) -> Dict[str, Any]:
    out = {
        "correlation_id": res.correlation_id,
        "score_raw": round(res.score_raw, 2),
        "score": round(res.score, 2),
        "decision": res.decision,
        "hard_rule_triggered": res.hard_rule_triggered,
        "thresholds": res.thresholds,
        "ts": res.ts,
    }
    if explain:
        out["factors"] = [
            {
                "name": f.name,
                "value": round(f.value, 2),
                "weight": round(f.weight, 4),
                "contribution": round(f.contribution, 2),
            }
            for f in res.factors
        ]
    return out

def _print_table(res: RiskResult) -> None:
    print(f"Correlation: {res.correlation_id}")
    print(f"Score: {res.score:.2f} (raw {res.score_raw:.2f})  Decision: {res.decision}")
    if res.hard_rule_triggered:
        print(f"Hard rule triggered: {res.hard_rule_triggered}")
    print("Factors (value, weight, contribution):")
    for f in sorted(res.factors, key=lambda x: x.contribution, reverse=True):
        print(f"  - {f.name:22s} {f.value:6.2f}  {f.weight:6.3f}  -> {f.contribution:7.2f}")

# --------------------------
# Команды CLI
# --------------------------

def cmd_evaluate(args: argparse.Namespace) -> int:
    log = logging.getLogger("risk_score")
    weights = _load_weights(args.weights)
    scorer = RiskScorer(weights)
    state: Optional[StateStore] = StateStore(args.state) if args.state else None
    try:
        if args.input and args.input != "-":
            event = _read_json_file(args.input)
        else:
            event = json.load(sys.stdin)

        res = scorer.score_event(event, state=state)

        if args.format == "json":
            out = _result_to_json(res, explain=not args.no_explain)
            if args.output:
                _write_json_file(args.output, out)
            else:
                json.dump(out, sys.stdout, ensure_ascii=False)
                sys.stdout.write("\n")
        else:
            _print_table(res)
        log.info("evaluated %s", _safe_log_dict({"actor_id": event.get("actor_id"), "device_id": event.get("device_id")}))
        return 0
    finally:
        if state:
            state.close()

def cmd_batch(args: argparse.Namespace) -> int:
    """
    Обрабатывает NDJSON (по строке на событие). Вывод — NDJSON.
    """
    log = logging.getLogger("risk_score")
    weights = _load_weights(args.weights)
    scorer = RiskScorer(weights)
    state: Optional[StateStore] = StateStore(args.state) if args.state else None
    try:
        inp: io.TextIOBase
        out: io.TextIOBase
        inp = open(args.input, "r", encoding="utf-8") if args.input != "-" else sys.stdin
        out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
        count_ok = 0
        count_err = 0
        with contextlib.ExitStack() as stack:
            if inp not in (sys.stdin,):
                stack.enter_context(inp)
            if out not in (sys.stdout,):
                stack.enter_context(out)
            for line in inp:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    res = scorer.score_event(event, state=state)
                    obj = _result_to_json(res, explain=not args.no_explain)
                    out.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    count_ok += 1
                except Exception as e:
                    count_err += 1
                    log.warning("failed to process line: %s", str(e))
        log.info("batch done ok=%d err=%d", count_ok, count_err)
        return 0 if count_err == 0 else 2
    finally:
        if state:
            state.close()

def cmd_gen_defaults(args: argparse.Namespace) -> int:
    if args.output:
        _write_json_file(args.output, DEFAULT_WEIGHTS)
    else:
        json.dump(DEFAULT_WEIGHTS, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return 0

def cmd_self_test(args: argparse.Namespace) -> int:
    # Простейший self-test для верификации основных путей
    weights = _load_weights(None)
    scorer = RiskScorer(weights)
    state: Optional[StateStore] = None
    try:
        # Один "обычный" и один с высоким Threat Intel
        events = [
            {
                "actor_id": "u123",
                "device_id": "d1",
                "timestamp": _now_utc().isoformat(),
                "identity_risk": 20,
                "device_posture": 35,
                "network_risk": 25,
                "resource_sensitivity": 50,
                "behavior_risk": 30,
                "threat_intel": 10,
                "geo": {"lat": 59.3293, "lon": 18.0686},  # Stockholm
            },
            {
                "actor_id": "u999",
                "device_id": "d9",
                "timestamp": _now_utc().isoformat(),
                "identity_risk": 30,
                "device_posture": 55,
                "network_risk": 50,
                "resource_sensitivity": 80,
                "behavior_risk": 60,
                "threat_intel": 99,  # триггер deny
                "geo": {"lat": 40.7128, "lon": -74.0060},  # NYC
            },
        ]
        # Имитируем второе событие того же актора для geo-velocity
        state = StateStore(":memory:")
        res1 = scorer.score_event(events[0], state=state)
        time.sleep(0.01)
        ev2 = dict(events[0])
        ev2["timestamp"] = (_now_utc() + dt.timedelta(seconds=10)).isoformat()
        ev2["geo"] = {"lat": 52.5200, "lon": 13.4050}  # Berlin через 10 секунд => высокая скорость
        res2 = scorer.score_event(ev2, state=state)
        res3 = scorer.score_event(events[1], state=state)

        # Базовые утверждения самопроверки
        assert res1.decision in ("ALLOW", "MFA", "LIMITED", "DENY", "QUARANTINE")
        assert res3.decision == "DENY", "Threat Intel >= 99 должен вести к DENY (жёсткое правило)"
        assert res2.score >= res1.score, "Geo-velocity должен повышать риск"
        # Итог
        sys.stdout.write(json.dumps({
            "ok": True,
            "cases": [
                {"id": res1.correlation_id, "decision": res1.decision, "score": res1.score},
                {"id": res2.correlation_id, "decision": res2.decision, "score": res2.score},
                {"id": res3.correlation_id, "decision": res3.decision, "score": res3.score},
            ]
        }, ensure_ascii=False) + "\n")
        return 0
    except Exception as e:
        sys.stdout.write(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False) + "\n")
        return 3
    finally:
        if state:
            state.close()


# --------------------------
# Аргументы
# --------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="risk_score.py",
        description="Zero-Trust Risk Scoring CLI (industrial)",
    )
    p.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("evaluate", help="Оценить одно событие (JSON)")
    pe.add_argument("--input", "-i", default="-", help="Путь к JSON событию или '-' для stdin")
    pe.add_argument("--weights", "-w", help="Путь к JSON с весами/правилами")
    pe.add_argument("--state", help="Путь к SQLite файлу состояния (для geo-velocity)")
    pe.add_argument("--output", "-o", help="Путь для JSON вывода (по умолчанию stdout)")
    pe.add_argument("--format", "-f", choices=("json", "table"), default="json")
    pe.add_argument("--no-explain", action="store_true", help="Не включать факторы в вывод")
    pe.set_defaults(func=cmd_evaluate)

    pb = sub.add_parser("batch", help="Обработать NDJSON поток")
    pb.add_argument("--input", "-i", default="-", help="Путь к NDJSON или '-' для stdin")
    pb.add_argument("--output", "-o", help="Путь к NDJSON выводу (по умолчанию stdout)")
    pb.add_argument("--weights", "-w", help="Путь к JSON с весами/правилами")
    pb.add_argument("--state", help="Путь к SQLite файлу состояния")
    pb.add_argument("--no-explain", action="store_true", help="Не включать факторы в вывод")
    pb.set_defaults(func=cmd_batch)

    pg = sub.add_parser("gen-defaults", help="Сгенерировать дефолтный JSON конфиг весов")
    pg.add_argument("--output", "-o", help="куда сохранить (stdout по умолчанию)")
    pg.set_defaults(func=cmd_gen_defaults)

    ps = sub.add_parser("self-test", help="Самопроверка функционала")
    ps.set_defaults(func=cmd_self_test)

    return p


# --------------------------
# main
# --------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s risk_score %(message)s",
    )
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
