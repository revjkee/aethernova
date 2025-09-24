# -*- coding: utf-8 -*-
"""
Zero Trust Posture CLI
Кроссплатформенный промышленный аудит устройства перед выдачей доступа.
Без внешних зависимостей. Python 3.10+.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from hashlib import blake2b
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------- Политика по умолчанию -----------------------------

DEFAULT_POLICY: Dict[str, Any] = {
    "min_os": {  # минимальные версии ОС (сравнение лексикографически по числам)
        "Windows": "10.0.19045",
        "Darwin": "13.0",
        "Linux": "4.15",
    },
    "require_firewall": True,
    "require_disk_encryption": True,
    "require_secure_boot": True,
    "require_tpm": False,  # включайте при жёстких требованиях
    "disallow_root": True,
    "ntp_required": True,
    "vpn_required": False,
    "max_time_drift_seconds": 120,
    "timeout_seconds": 6,  # таймаут одной проверки
}

# ----------------------------- Модель результата -----------------------------

@dataclass
class CheckResult:
    name: str
    status: str  # PASS | FAIL | WARN | UNKNOWN | ERROR
    evidence: str = ""
    remediation: str = ""
    time_ms: int = 0

@dataclass
class Summary:
    overall_status: str
    passed: int
    failed: int
    warned: int
    unknown: int
    errored: int

@dataclass
class Report:
    policy: Dict[str, Any]
    results: List[CheckResult]
    summary: Summary
    created_at: str
    node: str
    platform: Dict[str, str]
    hash_blake2b_256: str

# ----------------------------- Утилиты -----------------------------

def _harden_json(o: Any) -> str:
    return json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _calc_hash(payload: str) -> str:
    h = blake2b(digest_size=32)
    h.update(payload.encode("utf-8"))
    return h.hexdigest()

def _platform_info() -> Dict[str, str]:
    import platform
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }

def _version_tuple(s: str) -> Tuple[int, ...]:
    parts = []
    for p in str(s).replace("_", ".").split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)

def _load_policy(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return dict(DEFAULT_POLICY)
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # слияние с умолчаниями
    merged = dict(DEFAULT_POLICY)
    merged.update(data or {})
    return merged

# ----------------------------- Загрузка плагинов -----------------------------

def _discover_plugins(plugins_dir: Path) -> List[Any]:
    modules: List[Any] = []
    for file in sorted(plugins_dir.glob("*.py")):
        if file.name == "__init__.py":
            continue
        spec = importlib.util.spec_from_file_location(f"zt.plugins.{file.stem}", file)
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore
            modules.append(mod)
        except Exception:
            print(f"[WARN] Failed to load plugin {file.name}:\n{traceback.format_exc()}", file=sys.stderr)
    return modules

def _collect_checks(policy: Dict[str, Any], plugins: List[Any]) -> List[Any]:
    checks = []
    for m in plugins:
        # контракт: плагин должен экспортировать get_checks(policy) -> list[PostureCheck]
        fn = getattr(m, "get_checks", None)
        if callable(fn):
            try:
                checks.extend(fn(policy))
            except Exception:
                print(f"[WARN] Plugin get_checks() error in {m}:\n{traceback.format_exc()}", file=sys.stderr)
    return checks

# ----------------------------- Исполнение -----------------------------

def _run_checks(checks: List[Any], policy: Dict[str, Any], timeout: int) -> List[CheckResult]:
    results: List[CheckResult] = []
    with ThreadPoolExecutor(max_workers=min(16, max(4, os.cpu_count() or 4))) as ex:
        fut_map = {ex.submit(ch.run_safe, policy, timeout): ch for ch in checks}
        for fut in as_completed(fut_map):
            ch = fut_map[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = CheckResult(
                    name=getattr(ch, "name", "unknown"),
                    status="ERROR",
                    evidence=f"Unhandled exception: {e}",
                    remediation="Contact security administrator and check plugin logs.",
                    time_ms=0,
                )
            results.append(res)
    return results

def _summarize(results: List[CheckResult]) -> Summary:
    c = {"PASS":0,"FAIL":0,"WARN":0,"UNKNOWN":0,"ERROR":0}
    for r in results:
        c[r.status] = c.get(r.status, 0) + 1
    overall = "PASS"
    if c["FAIL"] > 0:
        overall = "FAIL"
    elif c["ERROR"] > 0:
        overall = "WARN"
    elif c["WARN"] > 0:
        overall = "WARN"
    elif c["UNKNOWN"] > 0 and c["PASS"] == 0:
        overall = "UNKNOWN"
    return Summary(
        overall_status=overall,
        passed=c["PASS"],
        failed=c["FAIL"],
        warned=c["WARN"],
        unknown=c["UNKNOWN"],
        errored=c["ERROR"],
    )

def _exit_code(summary: Summary) -> int:
    if summary.failed > 0:
        return 2
    if summary.errored > 0 or summary.warned > 0:
        return 1
    return 0

# ----------------------------- CLI -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Zero Trust Posture Check CLI")
    parser.add_argument("--policy", type=str, help="JSON policy file path", default=None)
    parser.add_argument("--plugins-dir", type=str, default=str(Path(__file__).parent / "tools"),
                        help="Directory with posture check plugins")
    parser.add_argument("--pretty", action="store_true", help="Pretty JSON output")
    parser.add_argument("--node", type=str, default=os.uname().nodename if hasattr(os, "uname") else os.getenv("COMPUTERNAME","unknown"),
                        help="Logical node name to include in report")
    args = parser.parse_args()

    try:
        policy = _load_policy(args.policy)
    except Exception as e:
        print(json.dumps({"error":"Failed to load policy","detail":str(e)} , ensure_ascii=False), file=sys.stderr)
        return 2

    plugins_dir = Path(args.plugins_dir).resolve()
    if not plugins_dir.exists():
        print(json.dumps({"error":"Plugins directory not found","detail":str(plugins_dir)}, ensure_ascii=False), file=sys.stderr)
        return 2

    modules = _discover_plugins(plugins_dir)
    checks = _collect_checks(policy, modules)

    if not checks:
        print(json.dumps({"error":"No checks discovered","detail":str(plugins_dir)}, ensure_ascii=False), file=sys.stderr)
        return 2

    started = time.time()
    results = _run_checks(checks, policy, int(policy.get("timeout_seconds", 6)))
    summary = _summarize(results)

    report_body = {
        "policy": policy,
        "results": [asdict(r) for r in results],
        "summary": asdict(summary),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "node": args.node,
        "platform": _platform_info(),
    }
    payload = _harden_json(report_body)
    digest = _calc_hash(payload)

    full_report = dict(report_body)
    full_report["hash_blake2b_256"] = digest

    if args.pretty:
        print(json.dumps(full_report, ensure_ascii=False, indent=2))
    else:
        print(_harden_json(full_report))

    return _exit_code(summary)

if __name__ == "__main__":
    sys.exit(main())
