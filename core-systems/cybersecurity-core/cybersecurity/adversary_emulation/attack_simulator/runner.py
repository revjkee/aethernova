from __future__ import annotations

"""
cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/runner.py

Industrial-grade, safety-first adversary emulation runner (simulation mode).
This runner is intentionally designed to *avoid* executing harmful or system-wide
actions. All effects are constrained to a dedicated sandbox directory and a limited
set of benign, deterministic actions. No external network calls, privilege changes,
or arbitrary shell commands are performed.

Compatibility: Python 3.11+
Standard library only. No third-party dependencies.
"""

import argparse
import asyncio
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable, Coroutine, Union
import traceback
import zipfile
import platform
import itertools
import tomllib

JSONDict = Dict[str, Any]


# ------------------------------ Structured JSON logging ------------------------------

class _JsonLogger:
    """
    Simple JSON logger writing to stdout and optional file (JSON Lines).
    Ensures logs are single-line JSON for easy ingestion by ELK/OTel collectors.
    """

    def __init__(self, logfile: Optional[Path] = None) -> None:
        self._logfile = logfile
        if logfile:
            logfile.parent.mkdir(parents=True, exist_ok=True)
            self._fp = logfile.open("a", encoding="utf-8")
        else:
            self._fp = None

    def _emit(self, level: str, event: str, **kwargs: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "event": event,
            **kwargs,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        print(line, flush=True)
        if self._fp:
            self._fp.write(line + "\n")
            self._fp.flush()

    def info(self, event: str, **kwargs: Any) -> None:
        self._emit("INFO", event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._emit("WARN", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._emit("ERROR", event, **kwargs)

    def close(self) -> None:
        if self._fp:
            self._fp.close()


# ------------------------------ Models ------------------------------

class ActionType(str, Enum):
    CREATE_DIR = "create_dir"
    CREATE_FILE = "create_file"
    APPEND_FILE = "append_file"
    DELETE_PATH = "delete_path"
    LIST_DIR = "list_dir"
    SLEEP = "sleep"
    GENERATE_RANDOM = "generate_random"
    COMPUTE_HASH = "compute_hash"
    COMPRESS_DIR = "compress_dir"
    SIMULATE_NETWORK = "simulate_network"
    READ_FILE = "read_file"


@dataclass(frozen=True)
class Step:
    id: str
    name: str
    action: ActionType
    params: JSONDict = field(default_factory=dict)
    timeout_sec: Optional[float] = None
    continue_on_error: bool = False


@dataclass
class Scenario:
    name: str
    version: str = "1.0"
    steps: List[Step] = field(default_factory=list)
    seed: Optional[int] = None
    concurrency: int = 1  # 1 = sequential
    environment: JSONDict = field(default_factory=dict)

    @staticmethod
    def from_dict(d: JSONDict) -> "Scenario":
        steps = [
            Step(
                id=str(s["id"]),
                name=str(s.get("name", s["id"])),
                action=ActionType(s["action"]),
                params=dict(s.get("params", {})),
                timeout_sec=float(s["timeout_sec"]) if s.get("timeout_sec") is not None else None,
                continue_on_error=bool(s.get("continue_on_error", False)),
            )
            for s in d.get("steps", [])
        ]
        return Scenario(
            name=str(d["name"]),
            version=str(d.get("version", "1.0")),
            steps=steps,
            seed=int(d["seed"]) if d.get("seed") is not None else None,
            concurrency=int(d.get("concurrency", 1)),
            environment=dict(d.get("environment", {})),
        )


# ------------------------------ Utilities ------------------------------

def _hash_file(path: Path) -> str:
    h = sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _ensure_within(base: Path, target: Path) -> None:
    """
    Ensure that `target` is within `base`. Raises ValueError otherwise.
    """
    try:
        target.relative_to(base.resolve())
    except Exception:
        raise ValueError(f"Unsafe path outside sandbox: {target}")


def _safe_write(path: Path, data: bytes, *, exist_ok: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not exist_ok and path.exists():
        raise FileExistsError(f"File exists: {path}")
    with path.open("wb") as fp:
        fp.write(data)


def _truncate(s: str, limit: int = 2048) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"...[truncated {len(s)-limit} chars]"

# ------------------------------ Action Handlers ------------------------------

class ActionContext:
    def __init__(self, sandbox: Path, logger: _JsonLogger, env: JSONDict) -> None:
        self.sandbox = sandbox
        self.logger = logger
        self.env = dict(env)  # shallow copy


class ActionRegistry:
    def __init__(self) -> None:
        self._handlers: Dict[ActionType, Callable[[ActionContext, Step], Coroutine[Any, Any, JSONDict]]] = {}

    def register(self, action: ActionType):
        def decorator(func: Callable[[ActionContext, Step], Coroutine[Any, Any, JSONDict]]):
            self._handlers[action] = func
            return func
        return decorator

    def get(self, action: ActionType) -> Callable[[ActionContext, Step], Coroutine[Any, Any, JSONDict]]:
        if action not in self._handlers:
            raise KeyError(f"No handler registered for action: {action}")
        return self._handlers[action]


registry = ActionRegistry()


@registry.register(ActionType.CREATE_DIR)
async def _create_dir(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    if not rel:
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    mode = int(step.params.get("mode", 0o755))
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, mode)
    return {"created": str(target), "mode": oct(mode)}


@registry.register(ActionType.CREATE_FILE)
async def _create_file(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    content = step.params.get("content", "")
    if rel == Path(""):
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    overwrite = bool(step.params.get("overwrite", True))
    data = content.encode("utf-8")
    _safe_write(target, data, exist_ok=overwrite)
    return {"created": str(target), "bytes": len(data), "preview": _truncate(content)}


@registry.register(ActionType.APPEND_FILE)
async def _append_file(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    text = step.params.get("text", "")
    if rel == Path(""):
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fp:
        fp.write(text)
    return {"appended": str(target), "bytes": len(text)}


@registry.register(ActionType.DELETE_PATH)
async def _delete_path(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    if rel == Path(""):
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    if target.is_file() or target.is_symlink():
        target.unlink(missing_ok=True)
        kind = "file"
    elif target.is_dir():
        # Remove directory contents safely
        for child in sorted(target.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                child.rmdir()
        target.rmdir()
        kind = "dir"
    else:
        kind = "missing"
    return {"deleted": str(target), "kind": kind}


@registry.register(ActionType.LIST_DIR)
async def _list_dir(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", "."))
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    if not target.exists():
        return {"path": str(target), "entries": [], "missing": True}
    entries = []
    for p in sorted(target.iterdir()):
        entries.append({"name": p.name, "is_dir": p.is_dir(), "size": p.stat().st_size if p.exists() else 0})
    return {"path": str(target), "entries": entries, "count": len(entries)}


@registry.register(ActionType.SLEEP)
async def _sleep(ctx: ActionContext, step: Step) -> JSONDict:
    sec = float(step.params.get("seconds", 1.0))
    # Cap sleep to prevent long stalls
    sec = max(0.0, min(sec, 60.0))
    await asyncio.sleep(sec)
    return {"slept_seconds": sec}


@registry.register(ActionType.GENERATE_RANDOM)
async def _generate_random(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    bytes_len = int(step.params.get("bytes", 1024))
    if rel == Path(""):
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    bytes_len = max(1, min(bytes_len, 10_000_000))  # cap at 10MB
    rng = random.Random()
    seed = int(step.params.get("seed")) if step.params.get("seed") is not None else None
    if seed is not None:
        rng.seed(seed)
    data = rng.randbytes(bytes_len) if hasattr(rng, "randbytes") else bytes(rng.getrandbits(8) for _ in range(bytes_len))
    _safe_write(target, data, exist_ok=True)
    return {"generated": str(target), "bytes": bytes_len, "sha256": sha256(data).hexdigest()}


@registry.register(ActionType.COMPUTE_HASH)
async def _compute_hash(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    if rel == Path(""):
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Expected file: {target}")
    return {"path": str(target), "sha256": _hash_file(target)}


@registry.register(ActionType.COMPRESS_DIR)
async def _compress_dir(ctx: ActionContext, step: Step) -> JSONDict:
    src_rel = Path(step.params.get("src", ""))
    dst_rel = Path(step.params.get("dst", ""))
    if not src_rel or not dst_rel:
        raise ValueError("params 'src' and 'dst' are required")
    src = (ctx.sandbox / src_rel).resolve()
    dst = (ctx.sandbox / dst_rel).resolve()
    _ensure_within(ctx.sandbox, src)
    _ensure_within(ctx.sandbox, dst)
    if not src.exists() or not src.is_dir():
        raise NotADirectoryError(f"Expected directory: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in src.rglob("*"):
            if file.is_file():
                arcname = file.relative_to(src)
                zf.write(file, arcname)
    return {"src": str(src), "archive": str(dst), "bytes": Path(dst).stat().st_size}


@registry.register(ActionType.SIMULATE_NETWORK)
async def _simulate_network(ctx: ActionContext, step: Step) -> JSONDict:
    """
    Simulate a network event without generating real network traffic.
    Useful for pipeline testing and telemetry inferences without risk.
    """
    direction = str(step.params.get("direction", "egress"))
    endpoint = str(step.params.get("endpoint", "example.internal:443"))
    protocol = str(step.params.get("protocol", "tcp"))
    size = int(step.params.get("bytes", 512))
    size = max(0, min(size, 10_000_000))
    # Produce a synthetic payload artifact (not transmitted)
    payload_path = (ctx.sandbox / "artifacts" / f"net_{int(time.time()*1000)}.bin").resolve()
    _ensure_within(ctx.sandbox, payload_path)
    random_bytes = os.urandom(min(size, 4096))  # cap actual disk
    _safe_write(payload_path, random_bytes, exist_ok=True)
    return {
        "simulated": True,
        "direction": direction,
        "endpoint": endpoint,
        "protocol": protocol,
        "payload_artifact": str(payload_path),
        "logged_bytes": len(random_bytes),
    }


@registry.register(ActionType.READ_FILE)
async def _read_file(ctx: ActionContext, step: Step) -> JSONDict:
    rel = Path(step.params.get("path", ""))
    limit = int(step.params.get("limit", 2048))
    if rel == Path(""):
        raise ValueError("param 'path' is required")
    target = (ctx.sandbox / rel).resolve()
    _ensure_within(ctx.sandbox, target)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Expected file: {target}")
    with target.open("r", encoding="utf-8", errors="replace") as fp:
        data = fp.read(limit + 1)
    truncated = len(data) > limit
    preview = data[:limit]
    return {"path": str(target), "preview": preview, "truncated": truncated}


# ------------------------------ Runner ------------------------------

@dataclass
class StepResult:
    id: str
    name: str
    action: str
    status: str
    started: str
    finished: str
    duration_ms: int
    output: Optional[JSONDict] = None
    error: Optional[str] = None


class SimulatorRunner:
    def __init__(self, scenario: Scenario, sandbox: Path, logger: _JsonLogger, dry_run: bool = False) -> None:
        self.scenario = scenario
        self.sandbox = sandbox.resolve()
        self.logger = logger
        self.dry_run = dry_run
        self.results: List[StepResult] = []

    def _validate_sandbox(self) -> None:
        if str(self.sandbox) in ("/", "C:\\", "C:/"):
            raise ValueError("Refusing to use root as sandbox")
        self.sandbox.mkdir(parents=True, exist_ok=True)

    async def _run_step(self, ctx: ActionContext, step: Step, sem: asyncio.Semaphore) -> None:
        started = datetime.now(timezone.utc)
        status = "success"
        output: Optional[JSONDict] = None
        error: Optional[str] = None

        handler = registry.get(step.action)
        self.logger.info("step_started", step_id=step.id, action=step.action.value, name=step.name)

        async def _invoke() -> JSONDict:
            if self.dry_run:
                return {"dry_run": True, "action": step.action.value, "params": step.params}
            return await handler(ctx, step)

        try:
            async with sem:
                if step.timeout_sec:
                    output = await asyncio.wait_for(_invoke(), timeout=step.timeout_sec)
                else:
                    output = await _invoke()
        except Exception as ex:
            status = "error"
            tb = traceback.format_exc(limit=6)
            error = f"{ex.__class__.__name__}: {ex}"
            self.logger.error("step_failed", step_id=step.id, error=error, traceback=_truncate(tb, 4000))
            if not step.continue_on_error:
                raise
        finally:
            finished = datetime.now(timezone.utc)
            duration_ms = int((finished - started).total_seconds() * 1000)
            result = StepResult(
                id=step.id,
                name=step.name,
                action=step.action.value,
                status=status,
                started=started.isoformat(),
                finished=finished.isoformat(),
                duration_ms=duration_ms,
                output=output,
                error=error,
            )
            self.results.append(result)
            self.logger.info("step_finished", step_id=step.id, status=status, duration_ms=duration_ms)

    async def run(self) -> List[StepResult]:
        self._validate_sandbox()

        # Deterministic seed if provided
        if self.scenario.seed is not None:
            random.seed(self.scenario.seed)

        # Create context
        ctx = ActionContext(self.sandbox, self.logger, self.scenario.environment)

        sem = asyncio.Semaphore(max(1, int(self.scenario.concurrency)))
        for step in self.scenario.steps:
            try:
                await self._run_step(ctx, step, sem)
            except Exception as ex:
                # Stop execution on fatal step unless continue_on_error
                self.logger.error("execution_halted", reason=str(ex))
                break
        return self.results


# ------------------------------ Scenario loader ------------------------------

def load_scenario(path: Path) -> Tuple[Scenario, JSONDict]:
    if not path.exists():
        raise FileNotFoundError(path)
    raw: JSONDict
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
    elif path.suffix.lower() in (".toml", ".tml"):
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    else:
        raise ValueError("Unsupported scenario format. Use .json or .toml")
    scenario = Scenario.from_dict(raw)
    meta = {
        "scenario_path": str(path.resolve()),
        "scenario_sha256": _hash_file(path),
    }
    return scenario, meta


# ------------------------------ Reporting ------------------------------

def build_report(
    scenario: Scenario,
    results: List[StepResult],
    meta: JSONDict,
    started_ts: float,
    finished_ts: float,
) -> JSONDict:
    return {
        "schema": "aethernova.cybersecurity.attack_simulator.report/1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario": {
            "name": scenario.name,
            "version": scenario.version,
            "steps": [s.id for s in scenario.steps],
            "seed": scenario.seed,
            "concurrency": scenario.concurrency,
            "environment_keys": sorted(list(scenario.environment.keys())),
        },
        "system": {
            "platform": platform.platform(),
            "python_version": sys.version.split()[0],
        },
        "meta": meta,
        "timing": {
            "started": datetime.fromtimestamp(started_ts, tz=timezone.utc).isoformat(),
            "finished": datetime.fromtimestamp(finished_ts, tz=timezone.utc).isoformat(),
            "duration_ms": int((finished_ts - started_ts) * 1000),
        },
        "results": [
            {
                "id": r.id,
                "name": r.name,
                "action": r.action,
                "status": r.status,
                "started": r.started,
                "finished": r.finished,
                "duration_ms": r.duration_ms,
                "output": r.output,
                "error": r.error,
            }
            for r in results
        ],
        "stats": {
            "total": len(results),
            "success": sum(1 for r in results if r.status == "success"),
            "error": sum(1 for r in results if r.status != "success"),
        },
    }


# ------------------------------ CLI ------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="attack-simulator-runner",
        description=(
            "Safety-first adversary emulation runner (simulation mode). "
            "All actions are constrained to a sandbox directory; no real attacks are performed."
        ),
    )
    p.add_argument("--scenario", required=True, help="Path to scenario file (.json or .toml)")
    p.add_argument("--sandbox", default="./.attack_sim_sandbox", help="Sandbox directory (created if missing)")
    p.add_argument("--report", default="./attack_sim_report.json", help="Path to write JSON report")
    p.add_argument("--log", default="./attack_simulator.log.jsonl", help="Path to write JSONL logs")
    p.add_argument("--dry-run", action="store_true", help="Do not execute actions; log intention only")
    p.add_argument("--strict", action="store_true", help="Fail if scenario uses unknown fields")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    scenario_path = Path(args.scenario)
    sandbox = Path(args.sandbox)

    logger = _JsonLogger(Path(args.log))
    started = time.time()
    try:
        scenario, meta = load_scenario(scenario_path)

        if args.strict:
            # Basic structural checks
            allowed_step_keys = {"id", "name", "action", "params", "timeout_sec", "continue_on_error"}
            raw = json.loads(scenario_path.read_text(encoding="utf-8")) if scenario_path.suffix.lower() == ".json" else None
            if raw is not None:
                for s in raw.get("steps", []):
                    unknown = set(s.keys()) - allowed_step_keys
                    if unknown:
                        raise ValueError(f"Unknown step keys: {unknown} in {s.get('id')}")

        runner = SimulatorRunner(scenario, sandbox, logger, dry_run=bool(args.dry_run))

        logger.info("runner_started", scenario=scenario.name, version=scenario.version, sandbox=str(sandbox.resolve()))
        results = asyncio.run(runner.run())
        finished = time.time()

        report = build_report(scenario, results, meta, started, finished)
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("runner_finished", report=str(Path(args.report).resolve()), status="ok")
        return 0
    except Exception as ex:
        finished = time.time()
        err = f"{ex.__class__.__name__}: {ex}"
        tb = traceback.format_exc(limit=8)
        logger.error("runner_failed", error=err, traceback=_truncate(tb, 4000))
        # Still write a minimal failure report for auditability
        try:
            minimal = {
                "schema": "aethernova.cybersecurity.attack_simulator.report/1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "error": err,
                "timing": {
                    "started": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
                    "finished": datetime.fromtimestamp(finished, tz=timezone.utc).isoformat(),
                    "duration_ms": int((finished - started) * 1000),
                },
            }
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(json.dumps(minimal, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        return 1
    finally:
        logger.close()


if __name__ == "__main__":
    raise SystemExit(main())
