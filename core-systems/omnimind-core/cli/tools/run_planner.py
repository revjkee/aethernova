#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Omnimind Planner CLI — run_planner.py

Python: 3.11+
Deps: stdlib only

Features:
- Read plans from JSON, TOML (tomllib), or NDJSON (one plan per line)
- Parallel evaluation with deterministic seeding
- Configurable evaluator suite from JSON/TOML config (or default production suite)
- Thresholds: min score, require ok, and severity gating
- Outputs: pretty text, JSON summary, NDJSON per-plan, optional JUnit XML for CI
- Optional audit logging if omnimind.security.auditor is available
- Robust error handling with clear exit codes

Exit codes:
 0 success
 2 invalid input or file errors
 3 threshold failure (any plan fails gates)
 4 internal error

Input plan schema (JSON/TOML keys):
{
  "task_id": "string",
  "instructions": "string",
  "context": {...},                (optional)
  "max_steps": 10,                 (optional)
  "max_tokens_approx": 1200,       (optional)
  "time_budget_ms": 600000,        (optional)
  "cost_budget": 1.0,              (optional)
  "seed": 42,                      (optional)
  "steps": [
    {
      "id": "extract",
      "action": "api_call...",
      "inputs": {...},             (optional)
      "outputs": {...},            (optional)
      "depends_on": ["..."],       (optional)
      "estimated_duration_ms": 1200, (optional)
      "cost": 0.001,               (optional)
      "meta": {...}                (optional)
    },
    ...
  ]
}
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# --------- dynamic imports (evaluators, optional auditor) ---------

# Try preferred module path
_eval_mod = None
with contextlib.suppress(Exception):
    import omnimind.planner.evaluators as _eval_mod  # type: ignore

# Fallback path used earlier in some repos
if _eval_mod is None:
    with contextlib.suppress(Exception):
        import ops.omnimind.planner.evaluators as _eval_mod  # type: ignore

if _eval_mod is None:
    print("FATAL: cannot import evaluators module (omnimind.planner.evaluators)", file=sys.stderr)
    sys.exit(4)

PlanStep = _eval_mod.PlanStep
EvaluationInput = _eval_mod.EvaluationInput
EvaluationResult = _eval_mod.EvaluationResult
build_evaluator_from_config = _eval_mod.build_evaluator_from_config
default_production_suite = _eval_mod.default_production_suite

# Optional audit
_aud_mod = None
with contextlib.suppress(Exception):
    import omnimind.security.auditor as _aud_mod  # type: ignore


# --------- io helpers ---------

def load_config(path: Optional[Path]) -> Optional[Mapping[str, Any]]:
    if not path:
        return None
    data = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix in (".json", ".ndjson"):
        return json.loads(data.decode("utf-8"))
    if suffix in (".toml",):
        import tomllib
        return tomllib.loads(data.decode("utf-8"))
    raise ValueError(f"unsupported config format: {path.suffix}")

def _detect_format(path: Path, cli_format: str) -> str:
    if cli_format != "auto":
        return cli_format
    s = path.suffix.lower()
    if s in (".json", ".ndjson"):
        return "json" if s == ".json" else "ndjson"
    if s == ".toml":
        return "toml"
    return "json"

def load_plans_from_path(path: Path, fmt: str) -> List[Mapping[str, Any]]:
    data = path.read_bytes()
    if fmt == "json":
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            return [obj]
        if isinstance(obj, list):
            return obj
        raise ValueError("JSON must be an object or array of objects")
    if fmt == "ndjson":
        plans: List[Mapping[str, Any]] = []
        for i, line in enumerate(data.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line.decode("utf-8") if isinstance(line, (bytes, bytearray)) else line)
                if not isinstance(obj, dict):
                    raise ValueError("each NDJSON line must be an object")
                plans.append(obj)
            except Exception as e:
                raise ValueError(f"invalid NDJSON at line {i+1}: {e}") from e
        return plans
    if fmt == "toml":
        import tomllib
        obj = tomllib.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            return [obj]
        raise ValueError("TOML must be a single document")
    raise ValueError(f"unsupported input format: {fmt}")

def _to_planstep(d: Mapping[str, Any]) -> PlanStep:
    return PlanStep(
        id=str(d["id"]),
        action=str(d.get("action", "")),
        inputs=dict(d.get("inputs", {})),
        outputs=dict(d.get("outputs", {})),
        depends_on=tuple(d.get("depends_on", ()) or ()),
        estimated_duration_ms=d.get("estimated_duration_ms"),
        cost=d.get("cost"),
        meta=dict(d.get("meta", {})),
    )

def _to_eval_input(d: Mapping[str, Any]) -> EvaluationInput:
    steps = tuple(_to_planstep(s) for s in d.get("steps", []) or [])
    return EvaluationInput(
        task_id=str(d.get("task_id") or d.get("id") or f"task-{int(time.time()*1000)}"),
        instructions=str(d.get("instructions", "")),
        steps=steps,
        context=dict(d.get("context", {})),
        max_steps=d.get("max_steps"),
        max_tokens_approx=d.get("max_tokens_approx"),
        time_budget_ms=d.get("time_budget_ms"),
        cost_budget=d.get("cost_budget"),
        seed=d.get("seed"),
    )

# --------- pretty printing ---------

def _colorize(s: str, color: Optional[str], enable: bool) -> str:
    if not enable or not sys.stdout.isatty():
        return s
    codes = {
        "red": "\x1b[31m", "green": "\x1b[32m", "yellow": "\x1b[33m",
        "blue": "\x1b[34m", "reset": "\x1b[0m",
    }
    return f"{codes.get(color,'')}{s}{codes['reset'] if color else ''}"

def print_result(res: EvaluationResult, name: str, color: bool) -> None:
    ok = res.ok
    sc = f"{res.score:.4f}"
    lbl = res.label
    line = f"[{name}] ok={ok} score={sc} label={lbl} duration_ms={res.duration_ms}"
    line = _colorize(line, "green" if ok else "red", color)
    print(line)
    # subresults (if composite)
    metrics = dict(res.metrics or {})
    subs = metrics.get("subresults")
    if isinstance(subs, list) and subs:
        for sr in subs:
            try:
                sname = sr.get("evaluator")
                sscore = sr.get("score")
                sok = sr.get("ok")
                sdur = sr.get("duration_ms")
                lab = sr.get("label")
                l2 = f"  - {sname}: ok={sok} score={sscore:.4f} label={lab} duration_ms={sdur}"
                l2 = _colorize(l2, "yellow" if sok else "red", color)
                print(l2)
            except Exception:
                pass
    # reasons
    if res.reasons:
        for r in res.reasons:
            print(f"    reason: {r}")

# --------- junit xml ---------

def write_junit_xml(path: Path, results: List[Tuple[str, EvaluationResult]]) -> None:
    from xml.etree.ElementTree import Element, SubElement, tostring
    testsuite = Element("testsuite", attrib={"name": "omnimind-planner", "tests": str(len(results))})
    for name, res in results:
        tc = SubElement(testsuite, "testcase", attrib={"classname": "planner", "name": name, "time": f"{res.duration_ms/1000.0:.3f}"})
        if not res.ok:
            fail = SubElement(tc, "failure", attrib={"message": res.label or "fail"})
            # keep it short
            fail.text = "\n".join(res.reasons or ())[:4096]
    xml = tostring(testsuite, encoding="utf-8", xml_declaration=True)
    path.write_bytes(xml)

# --------- audit integration ---------

def maybe_audit(enabled: bool, ctx: Dict[str, Any], name: str, res: EvaluationResult) -> None:
    if not enabled or _aud_mod is None:
        return
    try:
        auditor = _AUD_SINGLETON  # set in main
    except NameError:
        return
    if auditor is None:
        return
    ac = _aud_mod.AuditContext(
        request_id=ctx.get("request_id", name),
        actor=ctx.get("actor"),
        subject=name,
        ip=ctx.get("ip"),
        user_agent="planner-cli",
        tenant=ctx.get("tenant"),
        scopes=tuple()
    )
    data = {
        "score": res.score,
        "label": res.label,
        "ok": res.ok,
        "duration_ms": res.duration_ms,
    }
    try:
        auditor.log_access(ac, action="planner.evaluate", resource="plan", allowed=res.ok, reason=None, data=data)
    except Exception:
        pass

_AUD_SINGLETON = None

# --------- evaluation worker ---------

def evaluate_one(evaluator, plan_obj: Mapping[str, Any], color: bool, audit: bool) -> Tuple[str, Dict[str, Any]]:
    name = str(plan_obj.get("task_id") or plan_obj.get("id") or f"task-{int(time.time()*1000)}")
    try:
        evin = _to_eval_input(plan_obj)
        res: EvaluationResult = evaluator(evin)
        print_result(res, name, color)
        maybe_audit(audit, plan_obj.get("context", {}), name, res)
        return name, dataclasses.asdict(res)
    except Exception as e:
        err = {
            "evaluator": "fatal",
            "version": "n/a",
            "ok": False,
            "score": 0.0,
            "label": "error",
            "reasons": [f"{type(e).__name__}: {e}"],
            "metrics": {},
            "duration_ms": 0,
            "seed": plan_obj.get("seed"),
            "error": "exception",
        }
        print(_colorize(f"[{name}] EXCEPTION: {e}", "red", color), file=sys.stderr)
        return name, err

# --------- main ---------

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Omnimind Planner CLI")
    p.add_argument("inputs", nargs="+", help="Input files (JSON/TOML/NDJSON). Use '-' to read a JSON object from stdin.")
    p.add_argument("--format", choices=["auto", "json", "toml", "ndjson"], default="auto", help="Input format (auto by extension).")
    p.add_argument("--suite-config", type=str, default=os.getenv("OMNIMIND_PLANNER_SUITE"), help="Path to suite config (JSON/TOML).")
    p.add_argument("--concurrency", type=int, default=int(os.getenv("OMNIMIND_PLANNER_CONCURRENCY", "4")), help="Max concurrent evaluations.")
    p.add_argument("--min-score", type=float, default=float(os.getenv("OMNIMIND_PLANNER_MIN_SCORE", "0")), help="Fail if score < min-score.")
    p.add_argument("--require-ok", action="store_true", help="Fail if any plan result ok=False.")
    p.add_argument("--json-out", type=str, help="Write JSON summary to this file.")
    p.add_argument("--ndjson-out", type=str, help="Write NDJSON (one result per line) to this file.")
    p.add_argument("--junit-out", type=str, help="Write JUnit XML to this file for CI.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--audit", action="store_true", help="Send audit events if auditor is available.")
    args = p.parse_args(argv)

    color = not args.no_color

    # Build evaluator suite
    suite_cfg = None
    if args.suite_config:
        suite_cfg = load_config(Path(args.suite_config))
    if suite_cfg:
        evaluator = build_evaluator_from_config(suite_cfg)
    else:
        evaluator = default_production_suite()

    # Optional auditor
    global _AUD_SINGLETON
    _AUD_SINGLETON = None
    if args.audit and _aud_mod is not None:
        try:
            cfg = _aud_mod.AuditorConfig(to_stdout=False, file_path=os.getenv("AUDIT_FILE", "/tmp/omnimind_audit.ndjson"))
            _AUD_SINGLETON = _aud_mod.SecurityAuditor(cfg)
        except Exception:
            _AUD_SINGLETON = None

    # Collect plans
    plans: List[Mapping[str, Any]] = []
    for path_str in args.inputs:
        if path_str == "-":
            try:
                plans.append(json.loads(sys.stdin.read()))
            except Exception as e:
                print(f"invalid JSON from stdin: {e}", file=sys.stderr)
                if _AUD_SINGLETON:
                    with contextlib.suppress(Exception):
                        _AUD_SINGLETON.close()
                return 2
            continue

        path = Path(path_str)
        if not path.exists():
            print(f"input not found: {path}", file=sys.stderr)
            if _AUD_SINGLETON:
                with contextlib.suppress(Exception):
                    _AUD_SINGLETON.close()
            return 2

        fmt = _detect_format(path, args.format)
        try:
            items = load_plans_from_path(path, fmt)
            plans.extend(items)
        except Exception as e:
            print(f"failed to load {path}: {e}", file=sys.stderr)
            if _AUD_SINGLETON:
                with contextlib.suppress(Exception):
                    _AUD_SINGLETON.close()
            return 2

    if not plans:
        print("no plans to evaluate", file=sys.stderr)
        if _AUD_SINGLETON:
            with contextlib.suppress(Exception):
                _AUD_SINGLETON.close()
        return 2

    # Evaluate in parallel
    results: List[Tuple[str, Dict[str, Any]]] = []
    fail_gate = False

    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(args.concurrency))) as tp:
        futs = [tp.submit(evaluate_one, evaluator, plan, color, bool(args.audit)) for plan in plans]
        for f in concurrent.futures.as_completed(futs):
            name, res = f.result()
            results.append((name, res))
            if res.get("score", 0.0) < args.min_score or (args.require_ok and not res.get("ok", False)):
                fail_gate = True

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    ok_count = sum(1 for _, r in results if r.get("ok"))
    total = len(results)
    print(_colorize(f"Completed {total} plan(s) in {elapsed_ms} ms. OK {ok_count}/{total}.", "blue", color))

    # Outputs
    if args.json_out:
        out = {
            "completed_ms": elapsed_ms,
            "total": total,
            "ok": ok_count,
            "results": {name: res for name, res in results},
        }
        Path(args.json_out).write_text(json.dumps(out, ensure_ascii=False, indent=2))

    if args.ndjson_out:
        with open(args.ndjson_out, "wb") as fo:
            for name, res in results:
                rec = {"name": name, **res}
                line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                fo.write(line + b"\n")

    if args.junit_out:
        write_junit_xml(Path(args.junit_out), [(n, _from_dict_to_evalres(n, d)) for n, d in results])

    # Close auditor
    if _AUD_SINGLETON:
        with contextlib.suppress(Exception):
            _AUD_SINGLETON.close()

    if fail_gate:
        return 3
    return 0

def _from_dict_to_evalres(name: str, d: Dict[str, Any]) -> EvaluationResult:
    # Minimal adapter for JUnit writing when we only have dicts
    return EvaluationResult(
        evaluator=d.get("evaluator","composite"),
        version=d.get("version",""),
        ok=bool(d.get("ok", False)),
        score=float(d.get("score", 0.0)),
        label=d.get("label",""),
        reasons=tuple(d.get("reasons", ())),
        metrics=d.get("metrics", {}),
        duration_ms=int(d.get("duration_ms", 0)),
        seed=d.get("seed"),
        error=d.get("error"),
    )

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(4)
    except Exception:
        traceback.print_exc()
        sys.exit(4)
