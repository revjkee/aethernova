#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
dp_epsilon.py — Industrial CLI for Differential Privacy calibration & composition

Features
- Laplace mechanism:
    * Calibrate scale 'b' from (epsilon, sensitivity)
    * Infer epsilon from (b, sensitivity)
- Gaussian mechanism via strict zCDP bound:
    * ρ = Δ^2 / (2 σ^2)
    * (ε, δ) from ρ: ε(δ) = ρ + 2 * sqrt(ρ * ln(1/δ))
    * Invert to σ from (ε, δ) and Δ
- Composition:
    * Basic composition: ε_total = Σ ε_i, δ_total = Σ δ_i
    * Advanced composition (heterogeneous): for any δ' > 0
        ε_total = sqrt(2 * ln(1/δ') * Σ ε_i^2) + Σ ε_i * (exp(ε_i) - 1)
        δ_total = Σ δ_i + δ'
- zCDP utilities:
    * Compose ρ's additively; convert to (ε, δ) and back for Gaussian
- IO:
    * Read mechanisms list from JSON/YAML (if PyYAML installed) policy file
    * Output human-readable or --json machine format
- Pure stdlib (PyYAML optional)

Caveats
- Gaussian calculations use zCDP bound (conservative vs Analytic Gaussian Mechanism).
- DP-SGD with subsampling is NOT implemented here. Using subsampling/amplification
  bounds would require additional accountants. If нужно — расширяйте отдельно.

Examples
--------
1) Laplace: scale for ε=1.0, Δ=1
    dp_epsilon.py laplace --epsilon 1.0 --sensitivity 1

2) Gaussian: σ for ε=2, δ=1e-6, Δ=1 (zCDP)
    dp_epsilon.py gaussian calibrate --epsilon 2 --delta 1e-6 --sensitivity 1

3) Gaussian: ε for given σ=1.2, δ=1e-6, Δ=1
    dp_epsilon.py gaussian epsilon --sigma 1.2 --delta 1e-6 --sensitivity 1

4) Basic composition of three mechanisms:
    dp_epsilon.py compose basic --mech '[{"epsilon":0.5,"delta":1e-6},{"epsilon":1.0,"delta":1e-7}]'

5) Advanced composition with δ' = 1e-9:
    dp_epsilon.py compose advanced --mech-file policy.json --delta_prime 1e-9

6) zCDP composition for Gaussian mechanisms:
    dp_epsilon.py zcdp compose --gaussian '[{"sigma":1.2,"sensitivity":1},{"sigma":0.8,"sensitivity":2}]' --delta 1e-6

Policy file (JSON/YAML)
-----------------------
{
  "mechanisms": [
    {"kind":"laplace","epsilon":0.5,"delta":0.0},
    {"kind":"gaussian","epsilon":1.2,"delta":1e-7}
  ]
}
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False


# ------------------------------- Data classes ---------------------------------

@dataclass
class Mechanism:
    epsilon: float
    delta: float = 0.0
    kind: str = "generic"  # informational


@dataclass
class ZCDP:
    rho: float  # zCDP parameter


# ------------------------------- Validators -----------------------------------

def _require(cond: bool, msg: str) -> None:
    if not cond:
        sys.stderr.write(f"error: {msg}\n")
        sys.exit(2)


def _pos(name: str, v: float) -> None:
    _require(v > 0, f"{name} must be > 0")


def _nonneg(name: str, v: float) -> None:
    _require(v >= 0, f"{name} must be >= 0")


def _in_01(name: str, v: float) -> None:
    _require(0 < v < 1, f"{name} must be in (0,1)")


# ------------------------------- Laplace --------------------------------------

def laplace_scale_from_epsilon(epsilon: float, sensitivity: float) -> float:
    """
    Laplace mechanism with L1-sensitivity Δ: add Lap(b) with b = Δ/ε to achieve ε-DP.
    """
    _pos("epsilon", epsilon)
    _pos("sensitivity", sensitivity)
    return sensitivity / epsilon


def laplace_epsilon_from_scale(scale: float, sensitivity: float) -> float:
    _pos("scale", scale)
    _pos("sensitivity", sensitivity)
    return sensitivity / scale


# ------------------------------- Gaussian via zCDP ----------------------------

def gaussian_rho_from_sigma(sigma: float, sensitivity_l2: float) -> float:
    """
    For Gaussian mechanism with L2-sensitivity Δ and noise std σ:
    It satisfies ρ-zCDP with ρ = Δ^2 / (2 σ^2).
    """
    _pos("sigma", sigma)
    _pos("sensitivity", sensitivity_l2)
    return (sensitivity_l2 ** 2) / (2.0 * sigma * sigma)


def gaussian_sigma_from_rho(rho: float, sensitivity_l2: float) -> float:
    _pos("rho", rho)
    _pos("sensitivity", sensitivity_l2)
    return (sensitivity_l2 / math.sqrt(2.0 * rho))


def eps_from_rho_delta(rho: float, delta: float) -> float:
    """
    Convert zCDP(ρ) to (ε, δ) guarantee:
        ε(δ) = ρ + 2 sqrt(ρ * ln(1/δ))
    """
    _pos("rho", rho)
    _in_01("delta", delta)
    return rho + 2.0 * math.sqrt(rho * math.log(1.0 / delta))


def rho_from_eps_delta(epsilon: float, delta: float) -> float:
    """
    Invert ε(δ) = ρ + 2 sqrt(ρ L), L = ln(1/δ), for ρ ≥ 0.
    Let t = sqrt(ρ) => t^2 + 2 t sqrt(L) - ε = 0 -> take non-negative root:
        t = -sqrt(L) + sqrt(L + ε) ;  ρ = t^2
    This yields the minimal ρ that satisfies ε at given δ under zCDP bound.
    """
    _pos("epsilon", epsilon)
    _in_01("delta", delta)
    L = math.log(1.0 / delta)
    t = -math.sqrt(L) + math.sqrt(L + epsilon)
    t = max(0.0, t)
    return t * t


def gaussian_sigma_from_eps_delta(epsilon: float, delta: float, sensitivity_l2: float) -> float:
    """
    Calibrate σ for Gaussian via zCDP bound. Conservative but rigorous.
    """
    rho = rho_from_eps_delta(epsilon, delta)
    return gaussian_sigma_from_rho(rho, sensitivity_l2)


def gaussian_eps_from_sigma_delta(sigma: float, delta: float, sensitivity_l2: float) -> float:
    rho = gaussian_rho_from_sigma(sigma, sensitivity_l2)
    return eps_from_rho_delta(rho, delta)


# ------------------------------- Composition ----------------------------------

def compose_basic(mechanisms: Sequence[Mechanism]) -> Mechanism:
    eps = sum(max(0.0, m.epsilon) for m in mechanisms)
    delt = sum(max(0.0, m.delta) for m in mechanisms)
    return Mechanism(epsilon=eps, delta=delt, kind="composition_basic")


def compose_advanced(mechanisms: Sequence[Mechanism], delta_prime: float) -> Mechanism:
    """
    Heterogeneous Advanced Composition (Dwork et al.):
        ε' = sqrt(2 ln(1/δ') * Σ ε_i^2) + Σ ε_i (e^{ε_i} - 1)
        δ' = Σ δ_i + δ'
    Valid for ε_i >= 0, δ' in (0,1).
    """
    _in_01("delta_prime", delta_prime)
    sum_sq = 0.0
    sum_lin = 0.0
    delt = 0.0
    for m in mechanisms:
        _nonneg("epsilon", m.epsilon)
        _nonneg("delta", m.delta)
        sum_sq += m.epsilon * m.epsilon
        sum_lin += m.epsilon * (math.exp(m.epsilon) - 1.0)
        delt += m.delta
    eps = math.sqrt(2.0 * math.log(1.0 / delta_prime) * sum_sq) + sum_lin
    return Mechanism(epsilon=eps, delta=delt + delta_prime, kind="composition_advanced")


# ------------------------------- zCDP utilities -------------------------------

def zcdp_compose(rhos: Sequence[float]) -> float:
    for r in rhos:
        _nonneg("rho", r)
    return float(sum(rhos))


# ------------------------------- IO helpers -----------------------------------

def _load_mechanisms_from_json_str(s: str) -> List[Mechanism]:
    data = json.loads(s)
    if isinstance(data, dict) and "mechanisms" in data:
        data = data["mechanisms"]
    _require(isinstance(data, list), "Expected a list of mechanisms")
    mechs: List[Mechanism] = []
    for i, m in enumerate(data):
        _require(isinstance(m, dict), f"mechanism[{i}] must be an object")
        eps = float(m.get("epsilon", 0.0))
        delt = float(m.get("delta", 0.0))
        kind = str(m.get("kind", "generic"))
        mechs.append(Mechanism(epsilon=eps, delta=delt, kind=kind))
    return mechs


def _load_from_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        _require(_HAS_YAML, "PyYAML is not installed to read YAML files")
        return yaml.safe_load(txt) or {}
    return json.loads(txt)


def _print(obj: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    else:
        # human-readable
        lines = []
        for k, v in obj.items():
            lines.append(f"{k}: {v}")
        sys.stdout.write("\n".join(lines) + "\n")


# ------------------------------- CLI wiring -----------------------------------

def _cli() -> int:
    p = argparse.ArgumentParser(prog="dp_epsilon.py", description="DP calibration & composition (industrial, zCDP-backed)")
    p.add_argument("--json", action="store_true", help="print JSON output")

    sub = p.add_subparsers(dest="cmd", required=True)

    # Laplace
    lap = sub.add_parser("laplace", help="Laplace mechanism utilities")
    lap_sub = lap.add_subparsers(dest="lap_cmd", required=True)

    lap_c = lap_sub.add_parser("calibrate", help="compute scale b from epsilon and sensitivity")
    lap_c.add_argument("--epsilon", type=float, required=True)
    lap_c.add_argument("--sensitivity", type=float, required=True)

    lap_e = lap_sub.add_parser("epsilon", help="compute epsilon from scale b and sensitivity")
    lap_e.add_argument("--scale", type=float, required=True)
    lap_e.add_argument("--sensitivity", type=float, required=True)

    # Gaussian via zCDP
    gau = sub.add_parser("gaussian", help="Gaussian mechanism via zCDP")
    gau_sub = gau.add_subparsers(dest="gau_cmd", required=True)

    gau_c = gau_sub.add_parser("calibrate", help="compute sigma from epsilon, delta and L2-sensitivity")
    gau_c.add_argument("--epsilon", type=float, required=True)
    gau_c.add_argument("--delta", type=float, required=True)
    gau_c.add_argument("--sensitivity", type=float, required=True)

    gau_e = gau_sub.add_parser("epsilon", help="compute epsilon from sigma, delta and L2-sensitivity")
    gau_e.add_argument("--sigma", type=float, required=True)
    gau_e.add_argument("--delta", type=float, required=True)
    gau_e.add_argument("--sensitivity", type=float, required=True)

    gau_r = gau_sub.add_parser("rho", help="convert sigma<->rho or rho->(epsilon,delta)")
    gau_r.add_argument("--sigma", type=float, help="std of Gaussian noise")
    gau_r.add_argument("--rho", type=float, help="zCDP rho")
    gau_r.add_argument("--delta", type=float, help="delta for eps(delta)")
    gau_r.add_argument("--sensitivity", type=float, default=1.0, help="L2-sensitivity (default 1.0)")

    # Composition
    comp = sub.add_parser("compose", help="Compose (epsilon, delta) mechanisms")
    comp_sub = comp.add_subparsers(dest="comp_cmd", required=True)

    comp_b = comp_sub.add_parser("basic", help="basic composition (sum)")
    comp_b.add_argument("--mech", type=str, help="JSON list of mechanisms", default=None)
    comp_b.add_argument("--mech-file", type=str, help="JSON/YAML file with mechanisms", default=None)

    comp_a = comp_sub.add_parser("advanced", help="advanced composition (heterogeneous)")
    comp_a.add_argument("--delta_prime", type=float, required=True)
    comp_a.add_argument("--mech", type=str, help="JSON list of mechanisms", default=None)
    comp_a.add_argument("--mech-file", type=str, help="JSON/YAML file with mechanisms", default=None)

    # zCDP compose
    zc = sub.add_parser("zcdp", help="zCDP utilities")
    zc_sub = zc.add_subparsers(dest="zc_cmd", required=True)

    zc_comp = zc_sub.add_parser("compose", help="compose rhos and convert to (epsilon, delta)")
    zc_comp.add_argument("--rho", type=str, help="JSON list of rho values", default=None)
    zc_comp.add_argument("--gaussian", type=str, help="JSON list of {sigma,sensitivity} to convert to rho first", default=None)
    zc_comp.add_argument("--delta", type=float, required=True)

    # Policy file (mixed helper)
    pol = sub.add_parser("policy", help="Load mechanisms from a policy file and compute composition")
    pol.add_argument("--file", type=str, required=True)
    pol.add_argument("--mode", choices=["basic", "advanced"], default="advanced")
    pol.add_argument("--delta_prime", type=float, default=1e-12, help="δ' for advanced mode")

    args = p.parse_args()

    as_json = bool(args.json)

    if args.cmd == "laplace":
        if args.lap_cmd == "calibrate":
            b = laplace_scale_from_epsilon(args.epsilon, args.sensitivity)
            _print({"mechanism": "laplace", "epsilon": args.epsilon, "sensitivity": args.sensitivity, "scale": b}, as_json)
            return 0
        elif args.lap_cmd == "epsilon":
            eps = laplace_epsilon_from_scale(args.scale, args.sensitivity)
            _print({"mechanism": "laplace", "scale": args.scale, "sensitivity": args.sensitivity, "epsilon": eps}, as_json)
            return 0

    if args.cmd == "gaussian":
        if args.gau_cmd == "calibrate":
            sigma = gaussian_sigma_from_eps_delta(args.epsilon, args.delta, args.sensitivity)
            rho = gaussian_rho_from_sigma(sigma, args.sensitivity)
            _print({
                "mechanism": "gaussian_zcdp",
                "epsilon": args.epsilon,
                "delta": args.delta,
                "sensitivity_l2": args.sensitivity,
                "sigma": sigma,
                "rho": rho
            }, as_json)
            return 0
        elif args.gau_cmd == "epsilon":
            eps = gaussian_eps_from_sigma_delta(args.sigma, args.delta, args.sensitivity)
            rho = gaussian_rho_from_sigma(args.sigma, args.sensitivity)
            _print({
                "mechanism": "gaussian_zcdp",
                "sigma": args.sigma,
                "delta": args.delta,
                "sensitivity_l2": args.sensitivity,
                "epsilon": eps,
                "rho": rho
            }, as_json)
            return 0
        elif args.gau_cmd == "rho":
            if args.rho is not None and args.sigma is None:
                _pos("rho", args.rho)
                sigma = gaussian_sigma_from_rho(args.rho, args.sensitivity)
                out = {"rho": args.rho, "sensitivity_l2": args.sensitivity, "sigma": sigma}
                if args.delta is not None:
                    _in_01("delta", args.delta)
                    out["epsilon"] = eps_from_rho_delta(args.rho, args.delta)
                    out["delta"] = args.delta
                _print(out, as_json)
                return 0
            elif args.sigma is not None and args.rho is None:
                rho = gaussian_rho_from_sigma(args.sigma, args.sensitivity)
                out = {"sigma": args.sigma, "sensitivity_l2": args.sensitivity, "rho": rho}
                if args.delta is not None:
                    _in_01("delta", args.delta)
                    out["epsilon"] = eps_from_rho_delta(rho, args.delta)
                    out["delta"] = args.delta
                _print(out, as_json)
                return 0
            else:
                _require(False, "Provide either --rho or --sigma (but not both)")

    if args.cmd == "compose":
        # Load mechanisms
        mechs: List[Mechanism] = []
        if args.comp_cmd in ("basic", "advanced"):
            src = args.mech or None
            if args.mech_file:
                data = _load_from_file(args.mech_file)
                if isinstance(data, dict) and "mechanisms" in data:
                    data = data["mechanisms"]
                src = json.dumps(data)
            _require(src is not None, "Provide --mech JSON or --mech-file")
            mechs = _load_mechanisms_from_json_str(src)

        if args.comp_cmd == "basic":
            res = compose_basic(mechs)
            _print({"mode": "basic", "epsilon": res.epsilon, "delta": res.delta}, as_json)
            return 0
        elif args.comp_cmd == "advanced":
            res = compose_advanced(mechs, args.delta_prime)
            _print({"mode": "advanced", "epsilon": res.epsilon, "delta": res.delta, "delta_prime": args.delta_prime}, as_json)
            return 0

    if args.cmd == "zcdp":
        if args.zc_cmd == "compose":
            rhos: List[float] = []
            if args.rho:
                rhos = [float(x) for x in json.loads(args.rho)]
            if args.gaussian:
                gs = json.loads(args.gaussian)
                _require(isinstance(gs, list), "--gaussian must be a JSON list of objects with sigma and sensitivity")
                for g in gs:
                    sigma = float(g["sigma"])
                    sens = float(g.get("sensitivity", 1.0))
                    rhos.append(gaussian_rho_from_sigma(sigma, sens))
            _require(len(rhos) > 0, "Provide at least one rho via --rho or --gaussian")
            R = zcdp_compose(rhos)
            _in_01("delta", args.delta)
            eps = eps_from_rho_delta(R, args.delta)
            _print({"rho_total": R, "delta": args.delta, "epsilon": eps}, as_json)
            return 0

    if args.cmd == "policy":
        data = _load_from_file(args.file)
        mechs = _load_mechanisms_from_json_str(json.dumps(data))
        if args.mode == "basic":
            res = compose_basic(mechs)
            _print({"mode": "basic", "epsilon": res.epsilon, "delta": res.delta}, as_json)
        else:
            res = compose_advanced(mechs, args.delta_prime)
            _print({"mode": "advanced", "epsilon": res.epsilon, "delta": res.delta, "delta_prime": args.delta_prime}, as_json)
        return 0

    return 1


# ------------------------------- Entry point -----------------------------------

if __name__ == "__main__":
    try:
        sys.exit(_cli())
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        sys.exit(130)
