# cybersecurity-core/cli/tools/attack_simulator.py
# -*- coding: utf-8 -*-
"""
Attack Simulator CLI

Назначение:
- Последовательный запуск шагов плана эмуляции противника (TTP) через AttackSandbox.
- Переопределение лимитов и таймаута на уровне шага.
- Маркировка MITRE ATT&CK (technique_id/desc).
- Потоковый JSONL-отчет по шагам и финальный JSON-отчет.

Формат плана (JSON/YAML):
---
version: 1
meta:
  campaign: "sample-campaign"
  author: "aethernova"
steps:
  - id: "s1"
    cmd: ["/usr/bin/echo", "hello"]
    technique_id: "T1059.003"
    desc: "Shell echo as benign stand-in"
    stdin: null            # строка или base64:<...>
    timeout: 15            # опционально, сек
    limits:                # опционально, переопределение
      cpu_time_seconds: 3
      memory_bytes: 134217728
      open_files: 64
      file_size_bytes: 8388608
      max_processes: 8
  - id: "s2"
    cmd: ["/usr/bin/id"]
    technique_id: "T1033"
    desc: "Account discovery"
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# Опциональная поддержка YAML
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

# Импортируем промышленный Sandbox
try:
    from cybersecurity.adversary_emulation.attack_simulator.sandbox import (
        AttackSandbox,
        SandboxConfig,
        SandboxLimits,
    )
except Exception as e:  # pragma: no cover
    print(f"Import error: {e}", file=sys.stderr)
    sys.exit(2)


def _load_plan(path: Path) -> Dict[str, Any]:
    data = path.read_text(encoding="utf-8")
    # YAML, если доступен модуль и имеются типичные признаки; иначе JSON
    if yaml is not None and any(k in data for k in ("steps:", "version:", "meta:")):
        return yaml.safe_load(data)  # type: ignore[no-any-return]
    return json.loads(data)


def _b64_or_text(s: Optional[str]) -> Optional[bytes]:
    if s is None:
        return None
    if s.startswith("base64:"):
        payload = s.split("base64:", 1)[1]
        return base64.b64decode(payload.encode("utf-8"), validate=True)
    return s.encode("utf-8")


def _parse_id_list(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


def _merge_limits(defaults: SandboxLimits, override: Optional[Dict[str, Any]]) -> SandboxLimits:
    if not override:
        return defaults
    return SandboxLimits(
        cpu_time_seconds=override.get("cpu_time_seconds", defaults.cpu_time_seconds),
        memory_bytes=override.get("memory_bytes", defaults.memory_bytes),
        open_files=override.get("open_files", defaults.open_files),
        file_size_bytes=override.get("file_size_bytes", defaults.file_size_bytes),
        max_processes=override.get("max_processes", defaults.max_processes),
        allow_core_dump=override.get("allow_core_dump", defaults.allow_core_dump),
    )


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack-simulator",
        description="Execute adversary emulation plan via AttackSandbox",
    )
    p.add_argument("--plan", required=True, type=Path, help="Path to plan file (JSON or YAML)")
    p.add_argument("--only", type=str, default=None, help="Comma-separated step IDs to include")
    p.add_argument("--skip", type=str, default=None, help="Comma-separated step IDs to skip")
    p.add_argument("--dry-run", action="store_true", help="Validate plan, do not execute")
    p.add_argument("--report-jsonl", type=Path, default=Path("attack_report.jsonl"),
                   help="Path to per-step JSONL report")
    p.add_argument("--report-json", type=Path, default=Path("attack_report.json"),
                   help="Path to final JSON report")
    p.add_argument("--default-timeout", type=int, default=30, help="Default per-step wall clock timeout (sec)")
    p.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    # Базовые лимиты по умолчанию (могут быть переопределены в шаге)
    p.add_argument("--cpu", type=int, default=5, help="Default RLIMIT_CPU (sec)")
    p.add_argument("--mem", type=int, default=256 * 1024 * 1024, help="Default RLIMIT_AS (bytes)")
    p.add_argument("--nofile", type=int, default=64, help="Default RLIMIT_NOFILE")
    p.add_argument("--fsize", type=int, default=32 * 1024 * 1024, help="Default RLIMIT_FSIZE (bytes)")
    p.add_argument("--nproc", type=int, default=16, help="Default RLIMIT_NPROC")
    p.add_argument("--allow-core", action="store_true", help="Allow core dumps (default: disabled)")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    plan_path: Path = args.plan
    if not plan_path.exists():
        print(f"Plan file not found: {plan_path}", file=sys.stderr)
        return 2

    try:
        plan = _load_plan(plan_path)
    except Exception as e:
        print(f"Failed to load plan: {e}", file=sys.stderr)
        return 2

    steps: List[Dict[str, Any]] = plan.get("steps") or []
    meta: Dict[str, Any] = plan.get("meta") or {}
    version = plan.get("version")

    if not isinstance(steps, list) or not steps:
        print("Plan must contain non-empty 'steps' list", file=sys.stderr)
        return 2

    only_ids = set(_parse_id_list(args.only) or [])
    skip_ids = set(_parse_id_list(args.skip) or [])

    # Валидация ID
    seen_ids = set()
    for s in steps:
        sid = s.get("id")
        if not sid or not isinstance(sid, str):
            print("Each step must have string 'id'", file=sys.stderr)
            return 2
        if sid in seen_ids:
            print(f"Duplicate step id: {sid}", file=sys.stderr)
            return 2
        seen_ids.add(sid)

    if args.dry_run:
        print(f"Plan OK: {len(steps)} steps. Dry-run, nothing executed.")
        return 0

    report_jsonl: Path = args.report_jsonl
    report_json: Path = args.report_json

    # Базовые лимиты по умолчанию
    default_limits = SandboxLimits(
        cpu_time_seconds=args.cpu,
        memory_bytes=args.mem,
        open_files=args.nofile,
        file_size_bytes=args.fsize,
        max_processes=args.nproc,
        allow_core_dump=bool(args.allow_core),
    )

    # Настройки SandboxConfig по умолчанию
    base_cfg = dict(
        inherit_env=False,
        allowed_env_keys=("LANG", "LC_ALL", "TZ", "PATH"),
        base_path="/usr/bin:/bin",
        collect_artifacts=True,
        artifacts_max_files=200,
        artifacts_max_total_bytes=64 * 1024 * 1024,
        stdout_tail_bytes=64 * 1024,
        stderr_tail_bytes=64 * 1024,
    )

    # Потоковый JSONL
    f_jsonl = report_jsonl.open("w", encoding="utf-8")

    total = 0
    failed = 0
    started_at = int(time.time())
    campaign = str(meta.get("campaign") or "")

    for s in steps:
        sid = s["id"]
        if only_ids and sid not in only_ids:
            continue
        if sid in skip_ids:
            continue

        cmd = s.get("cmd")
        if not isinstance(cmd, list) or not cmd:
            print(f"[{sid}] invalid 'cmd'", file=sys.stderr)
            failed += 1
            total += 1
            continue

        technique_id = s.get("technique_id")
        technique_desc = s.get("desc")
        timeout = int(s.get("timeout") or args.default_timeout)
        stdin_b = _b64_or_text(s.get("stdin"))

        # Переопределение лимитов на уровне шага
        limits = _merge_limits(default_limits, s.get("limits"))

        # Создаем песочницу с конфигом
        sbx = AttackSandbox(
            SandboxConfig(
                wall_clock_timeout_seconds=timeout,
                limits=limits,
                log_level={"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}[args.log_level],
                **base_cfg,  # type: ignore[arg-type]
            )
        )

        total += 1
        try:
            result = sbx.run_command(
                cmd,
                technique_id=technique_id,
                technique_desc=technique_desc,
                input_bytes=stdin_b,
            )
            ok = bool(result.success)
        except Exception as e:
            # Непредвиденная ошибка исполнения шага
            ok = False
            result = None
            err_payload = {
                "step": sid,
                "cmd": cmd,
                "error": str(e),
            }
            f_jsonl.write(json.dumps({"type": "execution_error", **err_payload}, ensure_ascii=False) + "\n")
            f_jsonl.flush()

        # Запись результата шага
        if result is not None:
            rec = {
                "type": "step_result",
                "campaign": campaign,
                "version": version,
                "step": sid,
                "cmd": cmd,
                "technique_id": result.technique_id,
                "technique_desc": result.technique_desc,
                "success": result.success,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "duration_seconds": result.duration_seconds,
                "rusage": result.rusage,
                "stdout_tail_b64": base64.b64encode(result.stdout_tail).decode("ascii"),
                "stderr_tail_b64": base64.b64encode(result.stderr_tail).decode("ascii"),
                "artifacts": [asdict(a) for a in result.artifacts],
                # ВНИМАНИЕ: result.workdir/лог-файлы находятся во временном каталоге и могут быть удалены.
                "stdout_path": result.stdout_path,
                "stderr_path": result.stderr_path,
                "workdir": result.workdir,
                "limits": {
                    "cpu_time_seconds": limits.cpu_time_seconds,
                    "memory_bytes": limits.memory_bytes,
                    "open_files": limits.open_files,
                    "file_size_bytes": limits.file_size_bytes,
                    "max_processes": limits.max_processes,
                    "allow_core_dump": limits.allow_core_dump,
                },
                "timeout": timeout,
                "ts": int(time.time()),
            }
            f_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f_jsonl.flush()

        if not ok:
            failed += 1

    f_jsonl.close()

    # Финальный сводный отчет
    summary = {
        "campaign": campaign,
        "version": version,
        "started_at": started_at,
        "finished_at": int(time.time()),
        "total_steps_processed": total,
        "failed_steps": failed,
        "report_jsonl": str(report_jsonl),
    }
    report_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # Код возврата = числу неуспешных шагов (удобно для CI)
    return failed


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
