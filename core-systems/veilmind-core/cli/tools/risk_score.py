# -*- coding: utf-8 -*-
"""
Veilmind-core CLI: Risk Score Tool

Назначение:
  Потоковый и пакетный расчёт риск-скоринга по событиям Zero Trust/IAA/Access.
  Конфигурация — YAML/JSON. Вход — JSON (массив или JSON Lines). Выход — JSON/JSON Lines.

Особенности:
  - Извлечение признаков по path ("auth.mfa_passed") с типами boolean/number/string;
  - Трансформации: clip, scale, invert, bucket, logistic;
  - Взвешивание: score = bias + Σ weight_i * feature_i;
  - Калибровка: linear/logistic/piecewise -> нормализация в [0..100];
  - Пороги и классы риска: low/medium/high/critical;
  - Overrides: набор условий (when) => изменить severity/минимальный балл/финализировать;
  - Объяснимость: вклад признаков (top-K по |weight*value|), audit-поле reasons;
  - Режимы ввода: auto (определяется по первому символу), jsonl, json;
  - Безопасные дефолты, детерминированные вычисления, нулевая зависимость (PyYAML — опционально).

Пример минимального конфига (YAML/JSON семантика):
  version: 1
  bias: 0.0
  features:
    ip_risk: { path: "ip.risk", type: "number", transform: { kind: "clip", min: 0.0, max: 1.0 }, default: 0 }
    no_mfa:  { path: "auth.mfa_passed", type: "boolean", transform: { kind: "invert" }, default: false }
    anomaly: { path: "anomaly.score", type: "number", transform: { kind: "scale", min: 0, max: 100 }, default: 0 }
  weights: { ip_risk: 2.0, no_mfa: 1.5, anomaly: 1.0 }
  calibration: { method: "logistic", k: 1.2, x0: 1.5 }   # настраивается под данные
  thresholds: { low: 25, medium: 50, high: 75, critical: 90 }
  overrides:
    - when:
        - { path: "auth.device_posture", op: "eq", value: "noncompliant" }
      then: { set_score_min: 60 }
    - when:
        - { path: "ip.asn", op: "in", value: [ "TOR", "ANON" ] }
      then: { set_severity: "high" }

Запуск:
  echo '{"ip":{"risk":0.8},"auth":{"mfa_passed":false},"anomaly":{"score":47}}' | \
    python risk_score.py --config config.yaml --mode jsonl --topk 3

Выход (JSONL):
  {"score":87.1,"severity":"high","reasons":[...],"contrib":{"ip_risk":...}, "calibration":"logistic", ...}
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Опционально поддержим YAML, если установлен PyYAML
try:  # pragma: no cover
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    yaml = None  # type: ignore
    _HAS_YAML = False


# -----------------------------
# Типы и утилиты
# -----------------------------

Number = Union[int, float]

@dataclass(frozen=True)
class Transform:
    kind: str  # "clip" | "scale" | "invert" | "bucket" | "logistic"
    # параметры — в произвольном словаре


@dataclass(frozen=True)
class FeatureDef:
    name: str
    path: str
    ftype: str  # "boolean" | "number" | "string"
    transform: Optional[Dict[str, Any]]
    default: Any = 0


def _get_path(obj: Any, path: str, default: Any = None) -> Any:
    """Безопасное извлечение по пути 'a.b.c'."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _to_number(v: Any) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    try:
        return float(str(v))
    except Exception:
        return None


def _bool_to_number(v: Any) -> float:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    # трактуем "true"/"false"
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "y", "on"):
            return 1.0
        if s in ("false", "0", "no", "n", "off"):
            return 0.0
    # как наличие значения
    return 1.0 if v is not None else 0.0


def _apply_transform(x: float, t: Optional[Dict[str, Any]]) -> float:
    if t is None:
        return float(x)
    kind = str(t.get("kind", "clip")).lower()
    if kind == "clip":
        lo = float(t.get("min", 0.0))
        hi = float(t.get("max", 1.0))
        return float(min(max(x, lo), hi))
    if kind == "scale":
        # нормализация из [min,max] -> [0,1]
        lo = float(t.get("min", 0.0))
        hi = float(t.get("max", 1.0))
        if hi == lo:
            return 0.0
        return float(min(max((x - lo) / (hi - lo), 0.0), 1.0))
    if kind == "invert":
        # инверсия для булевого/нормированного признака
        y = 1.0 - float(x)
        return float(min(max(y, 0.0), 1.0))
    if kind == "bucket":
        # дискретизация: edges: [a,b,c,...], values: [v1,v2,...] длиной len(edges)+1
        edges = list(t.get("edges") or [])
        values = list(t.get("values") or [])
        if len(values) != len(edges) + 1 or len(values) == 0:
            return float(x)
        # найдём интервал
        for i, e in enumerate(edges):
            if x < float(e):
                return float(values[i])
        return float(values[-1])
    if kind == "logistic":
        # σ(k*(x - x0))
        k = float(t.get("k", 1.0))
        x0 = float(t.get("x0", 0.0))
        z = k * (x - x0)
        try:
            y = 1.0 / (1.0 + math.exp(-z))
        except OverflowError:
            y = 0.0 if z < 0 else 1.0
        return float(y)
    # неизвестная трансформация — вернём как есть
    return float(x)


def _calibrate(raw: float, calib: Dict[str, Any]) -> float:
    """
    Нормирует суммарный raw‑скор в диапазон [0..100].
    Поддерживает:
      - linear: raw_min/raw_max -> [0,100]
      - logistic: y=σ(k*(raw-x0)) -> [0,100]
      - piecewise: точки (x,y) с линейной интерполяцией (y в [0..100])
    """
    method = str(calib.get("method", "linear")).lower()
    if method == "linear":
        lo = float(calib.get("min", 0.0))
        hi = float(calib.get("max", 10.0))
        if hi == lo:
            return 0.0
        y = (raw - lo) / (hi - lo)
        return float(min(max(y, 0.0), 1.0) * 100.0)
    if method == "logistic":
        k = float(calib.get("k", 1.0))
        x0 = float(calib.get("x0", 0.0))
        z = k * (raw - x0)
        try:
            y = 1.0 / (1.0 + math.exp(-z))
        except OverflowError:
            y = 0.0 if z < 0 else 1.0
        return float(y * 100.0)
    if method == "piecewise":
        # nodes: [{"x":0,"y":0},{"x":2,"y":50},{"x":5,"y":90},{"x":10,"y":100}]
        nodes = calib.get("nodes") or []
        if not nodes:
            return float(min(max(raw, 0.0), 1.0) * 100.0)
        nodes = sorted(nodes, key=lambda p: float(p["x"]))
        if raw <= float(nodes[0]["x"]):
            return float(nodes[0]["y"])
        if raw >= float(nodes[-1]["x"]):
            return float(nodes[-1]["y"])
        for i in range(1, len(nodes)):
            x0, y0 = float(nodes[i - 1]["x"]), float(nodes[i - 1]["y"])
            x1, y1 = float(nodes[i]["x"]), float(nodes[i]["y"])
            if x0 <= raw <= x1:
                # линейная интерполяция
                t = 0.0 if x1 == x0 else (raw - x0) / (x1 - x0)
                return float(y0 + t * (y1 - y0))
    # по умолчанию — клип 0..100
    return float(min(max(raw, 0.0), 1.0) * 100.0)


def _severity(score: float, thresholds: Dict[str, Any]) -> str:
    """
    Присваивает уровень по числовым порогам.
      thresholds: { low: 25, medium: 50, high: 75, critical: 90 }
    """
    low = float(thresholds.get("low", 25.0))
    med = float(thresholds.get("medium", 50.0))
    high = float(thresholds.get("high", 75.0))
    crit = float(thresholds.get("critical", 90.0))
    if score >= crit:
        return "critical"
    if score >= high:
        return "high"
    if score >= med:
        return "medium"
    if score >= low:
        return "low"
    return "info"


def _compare(op: str, left: Any, right: Any) -> bool:
    op = op.lower()
    if op == "exists":
        return left is not None
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "gt":
        try:
            return float(left) > float(right)
        except Exception:
            return False
    if op == "ge":
        try:
            return float(left) >= float(right)
        except Exception:
            return False
    if op == "lt":
        try:
            return float(left) < float(right)
        except Exception:
            return False
    if op == "le":
        try:
            return float(left) <= float(right)
        except Exception:
            return False
    if op == "in":
        try:
            return left in right
        except Exception:
            return False
    if op == "contains":
        try:
            return right in left
        except Exception:
            return False
    return False


# -----------------------------
# Конфиг и извлечение признаков
# -----------------------------

DEFAULT_THRESHOLDS = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 90.0}
DEFAULT_CALIBRATION = {"method": "linear", "min": 0.0, "max": 5.0}

def _load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    # простая эвристика: YAML чаще начинается с буквы/ключа с двоеточием на первых строках
    if path.endswith((".yaml", ".yml")) and _HAS_YAML:
        return yaml.safe_load(txt)  # type: ignore
    # пробуем JSON
    try:
        return json.loads(txt)
    except Exception:
        if _HAS_YAML:
            return yaml.safe_load(txt)  # type: ignore
        raise ValueError("Config is not valid JSON and PyYAML is not installed")

def _parse_feature_defs(cfg: Dict[str, Any]) -> List[FeatureDef]:
    feats = cfg.get("features") or {}
    out: List[FeatureDef] = []
    for name, spec in feats.items():
        path = str(spec.get("path", name))
        ftype = str(spec.get("type", "number")).lower()
        transform = spec.get("transform")
        default = spec.get("default", 0)
        out.append(FeatureDef(name=name, path=path, ftype=ftype, transform=transform, default=default))
    return out

def _extract_features(event: Dict[str, Any], defs: List[FeatureDef], strict: bool) -> Tuple[Dict[str, float], List[str]]:
    values: Dict[str, float] = {}
    notes: List[str] = []
    for fd in defs:
        raw = _get_path(event, fd.path, fd.default)
        if fd.ftype == "boolean":
            v = _bool_to_number(raw)
        elif fd.ftype == "number":
            num = _to_number(raw)
            if num is None:
                if strict:
                    notes.append(f"feature:{fd.name} missing or non-numeric")
                    v = 0.0
                else:
                    v = _bool_to_number(raw)  # как fallback
            else:
                v = float(num)
        else:
            # string -> индикатор наличия
            v = 1.0 if (raw is not None and str(raw) != "") else 0.0
        v = _apply_transform(v, fd.transform)
        values[fd.name] = float(min(max(v, 0.0), 1.0))
    return values, notes


# -----------------------------
# Основной расчёт
# -----------------------------

def compute_risk(event: Dict[str, Any], cfg: Dict[str, Any], *, topk: int = 5, strict: bool = False) -> Dict[str, Any]:
    """
    Возвращает структуру:
      {
        "score": 87.1,
        "severity": "high",
        "raw": 2.73,
        "calibration": "logistic",
        "contrib": { "ip_risk": 1.60, "no_mfa": 1.50, ... },
        "reasons": [ "no_mfa=1.00 * w=1.50 -> +1.50", ... ],
        "notes": [...],
        "overrides": [ {"rule": 0, "action": "..."} ]
      }
    """
    feat_defs = _parse_feature_defs(cfg)
    weights: Dict[str, Number] = cfg.get("weights") or {}
    bias = float(cfg.get("bias", 0.0))
    calib = cfg.get("calibration") or DEFAULT_CALIBRATION
    thresholds = cfg.get("thresholds") or DEFAULT_THRESHOLDS

    # Если определения признаков не заданы — используем ключи весов напрямую
    if not feat_defs:
        feat_defs = [FeatureDef(name=k, path=k, ftype="number", transform={"kind": "clip", "min": 0.0, "max": 1.0}, default=0) for k in weights.keys()]

    feats, notes = _extract_features(event, feat_defs, strict)
    # вклад признаков
    contrib: Dict[str, float] = {}
    reasons: List[str] = []
    raw = float(bias)
    for name, val in feats.items():
        w = float(weights.get(name, 0.0))
        c = w * val
        if w != 0.0:
            contrib[name] = c
            reasons.append(f"{name}={val:.2f} * w={w:.2f} -> {c:+.2f}")
        raw += c

    score = _calibrate(raw, calib)
    sev = _severity(score, thresholds)

    # Применим overrides
    overrides_applied: List[Dict[str, Any]] = []
    for idx, rule in enumerate(cfg.get("overrides") or []):
        when = rule.get("when") or []
        ok = True
        for cond in when:
            p = cond.get("path")
            op = str(cond.get("op", "exists"))
            val = cond.get("value") if "value" in cond else None
            left = _get_path(event, p, None)
            ok = ok and _compare(op, left, val)
            if not ok:
                break
        if ok:
            then = rule.get("then") or {}
            action_desc = []
            if "set_score_min" in then:
                mn = float(then["set_score_min"])
                if score < mn:
                    score = mn
                    sev = _severity(score, thresholds)
                action_desc.append(f"set_score_min={mn}")
            if "set_score_max" in then:
                mx = float(then["set_score_max"])
                if score > mx:
                    score = mx
                    sev = _severity(score, thresholds)
                action_desc.append(f"set_score_max={mx}")
            if "set_severity" in then:
                sev = str(then["set_severity"])
                action_desc.append(f"set_severity={sev}")
            overrides_applied.append({"rule": idx, "actions": ", ".join(action_desc)})

    # Топ-K вкладов
    top_items = sorted(contrib.items(), key=lambda kv: abs(kv[1]), reverse=True)[: max(0, int(topk))]
    top_contrib = {k: float(v) for k, v in top_items}

    result = {
        "score": round(float(score), 3),
        "severity": sev,
        "raw": round(float(raw), 6),
        "calibration": str(calib.get("method", "linear")),
        "contrib": top_contrib,
        "reasons": reasons[: max(0, int(topk))],
    }
    if notes:
        result["notes"] = notes
    if overrides_applied:
        result["overrides"] = overrides_applied
    return result


# -----------------------------
# Ввод/вывод
# -----------------------------

def _iter_jsonl(stream: Iterable[str]) -> Iterable[Dict[str, Any]]:
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            # пропускаем некорректные строки
            continue


def _read_input_auto(data: str) -> Tuple[str, Iterable[Dict[str, Any]]]:
    s = data.lstrip()
    if s.startswith("["):
        try:
            arr = json.loads(data)
            if isinstance(arr, list):
                return "json", (x for x in arr if isinstance(x, dict))
        except Exception:
            pass
    # иначе предполагаем JSONL
    return "jsonl", _iter_jsonl(data.splitlines())


def _load_input(path: Optional[str], mode: str) -> Tuple[str, Iterable[Dict[str, Any]]]:
    if not path or path == "-":
        data = sys.stdin.read()
        if mode == "auto":
            return _read_input_auto(data)
        if mode == "json":
            arr = json.loads(data)
            return "json", (x for x in arr if isinstance(x, dict))
        return "jsonl", _iter_jsonl(data.splitlines())

    with open(path, "r", encoding="utf-8") as f:
        if mode == "jsonl":
            return "jsonl", _iter_jsonl(f)
        data = f.read()
        if mode == "auto":
            return _read_input_auto(data)
        if mode == "json":
            arr = json.loads(data)
            return "json", (x for x in arr if isinstance(x, dict))
        return "jsonl", _iter_jsonl(data.splitlines())


def _write_output(results: List[Dict[str, Any]], out_path: Optional[str], mode: str) -> None:
    if not out_path or out_path == "-":
        out = sys.stdout
        if mode == "jsonl":
            for r in results:
                out.write(json.dumps(r, ensure_ascii=False) + "\n")
        else:
            out.write(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
        out.flush()
        return
    with open(out_path, "w", encoding="utf-8") as f:
        if mode == "jsonl":
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        else:
            f.write(json.dumps(results, ensure_ascii=False, indent=2))


# -----------------------------
# CLI
# -----------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="veilmind-core risk score tool")
    p.add_argument("--config", required=True, help="Путь к конфигу (YAML/JSON)")
    p.add_argument("--input", default="-", help="Входной JSON: путь или '-' для STDIN")
    p.add_argument("--output", default="-", help="Выход: путь или '-' для STDOUT")
    p.add_argument("--mode", default="auto", choices=["auto", "json", "jsonl"], help="Формат входа")
    p.add_argument("--topk", type=int, default=5, help="Сколько топ-вкладов вернуть")
    p.add_argument("--strict", action="store_true", help="Жёстко требовать числовые признаки")
    p.add_argument("--merge", action="store_true", help="Сливать результат в исходные события вместо отдельного вывода")
    p.add_argument("--result-key", default="risk", help="Ключ для результата при --merge")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    cfg = _load_config(args.config)
    in_mode, iterator = _load_input(args.input, args.mode)

    results: List[Dict[str, Any]] = []
    if args.merge:
        # возвращаем исходные события, дополненные полем result-key
        for ev in iterator:
            res = compute_risk(ev, cfg, topk=args.topk, strict=args.strict)
            ev = dict(ev)  # защитная копия
            ev[args.result_key] = res
            results.append(ev)
    else:
        for ev in iterator:
            res = compute_risk(ev, cfg, topk=args.topk, strict=args.strict)
            results.append(res)

    # Выбор формата вывода:
    out_mode = "jsonl" if in_mode == "jsonl" else "json"
    _write_output(results, args.output, out_mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
