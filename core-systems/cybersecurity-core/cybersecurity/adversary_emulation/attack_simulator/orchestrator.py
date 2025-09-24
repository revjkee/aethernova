# cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/orchestrator.py
# Industrial-grade adversary emulation orchestrator.
# Features:
# - Scenario validation (Pydantic)
# - DAG planning with dependency checks (cycle detection)
# - Async orchestration with bounded concurrency
# - RBAC allow-list for MITRE ATT&CK techniques
# - Process isolation per step with POSIX RLIMITs (CPU, AS, NOFILE, NPROC)
# - Per-step timeouts, retries with exponential backoff
# - Structured JSON logging
# - Deterministic result artifacts (JSON, stdout/stderr capture, SHA256)
# - Optional OpenTelemetry tracing (if opentelemetry installed)
# - CLI interface with dry-run support
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import functools
import hashlib
import importlib
import inspect
import json
import logging
import os
import pathlib
import signal
import sys
import tempfile
import time
import traceback
import types
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml  # type: ignore
except ImportError as e:
    raise SystemExit("Missing dependency: pyyaml. Install with: pip install pyyaml") from e

try:
    from pydantic import BaseModel, Field, validator
except ImportError as e:
    raise SystemExit("Missing dependency: pydantic. Install with: pip install pydantic") from e

# OpenTelemetry is optional
try:
    from opentelemetry import trace  # type: ignore
    from opentelemetry.trace import Tracer  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:
    trace = None  # type: ignore
    Tracer = Any  # type: ignore
    _OTEL_AVAILABLE = False

# RLIMITs are POSIX; on Windows we degrade gracefully.
try:
    import resource  # type: ignore
    _POSIX_LIMITS = True
except Exception:  # pragma: no cover - Windows
    _POSIX_LIMITS = False


# -----------------------------
# Structured JSON logging
# -----------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]


log = logging.getLogger("attack_sim.orchestrator")


# -----------------------------
# Models
# -----------------------------
class ProcessLimits(BaseModel):
    cpu_seconds: int = Field(5, ge=1)
    memory_mb: int = Field(256, ge=32)
    open_files: int = Field(256, ge=64)
    nproc: int = Field(64, ge=8)


class RbacPolicy(BaseModel):
    enabled: bool = True
    permitted_techniques: Set[str] = Field(default_factory=set)  # e.g., {"T1059.003", "T1047"}


class StepSpec(BaseModel):
    id: str = Field(..., regex=r"^[a-zA-Z0-9_\-\.]{1,64}$")
    name: str
    plugin: str  # python module path, e.g. "cybersecurity.adversary_emulation.attack_simulator.plugins.cmd_exec"
    technique_id: Optional[str] = Field(None, regex=r"^T[0-9]{4}(\.[0-9]{3})?$")
    params: Dict[str, Any] = Field(default_factory=dict)
    depends_on: List[str] = Field(default_factory=list)
    timeout_sec: Optional[int] = Field(None, ge=1)
    retries: int = Field(0, ge=0, le=5)
    critical: bool = True

    @validator("depends_on", always=True)
    def unique_deps(cls, v: List[str]) -> List[str]:
        if len(v) != len(set(v)):
            raise ValueError("depends_on must not contain duplicates")
        return v


class ScenarioSpec(BaseModel):
    scenario_id: str = Field(..., regex=r"^[a-zA-Z0-9_\-\.]{1,64}$")
    description: Optional[str] = None
    steps: List[StepSpec]

    @validator("steps")
    def unique_step_ids(cls, v: List[StepSpec]) -> List[StepSpec]:
        seen: Set[str] = set()
        for s in v:
            if s.id in seen:
                raise ValueError(f"Duplicate step id: {s.id}")
            seen.add(s.id)
        return v


class OrchestratorConfig(BaseModel):
    scenario_path: pathlib.Path
    result_dir: pathlib.Path
    max_concurrency: int = Field(3, ge=1, le=64)
    default_timeout_sec: int = Field(300, ge=5)
    global_timeout_sec: Optional[int] = Field(None, ge=10)
    log_level: str = "INFO"
    dry_run: bool = False
    rbac: RbacPolicy = Field(default_factory=RbacPolicy)
    process_limits: ProcessLimits = Field(default_factory=ProcessLimits)


@dataclasses.dataclass
class StepContext:
    run_id: str
    scenario_id: str
    step_id: str
    work_dir: pathlib.Path
    result_dir: pathlib.Path
    start_time: float
    tracer: Optional[Tracer]
    env: Dict[str, str]


@dataclasses.dataclass
class StepResult:
    step_id: str
    status: str  # "success" | "failed" | "skipped"
    started_at: str
    ended_at: str
    duration_ms: int
    attempt: int
    technique_id: Optional[str]
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    artifacts: List[str] = dataclasses.field(default_factory=list)
    error: Optional[str] = None
    plugin_hash: Optional[str] = None


# -----------------------------
# Utilities
# -----------------------------
def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(p: pathlib.Path) -> pathlib.Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def now_iso() -> str:
    return dt.datetime.utcnow().isoformat() + "Z"


def backoff(attempt: int) -> float:
    # 0 -> 0s, 1 -> 1s, 2 -> 2s, 3 -> 4s, ...
    return float((2 ** max(0, attempt - 1)) if attempt > 0 else 0)


# -----------------------------
# DAG Planning
# -----------------------------
class DagPlan:
    def __init__(self, steps: List[StepSpec]) -> None:
        self.steps_map: Dict[str, StepSpec] = {s.id: s for s in steps}
        self.edges: Dict[str, Set[str]] = {s.id: set(s.depends_on) for s in steps}
        self._validate()

    def _validate(self) -> None:
        # Unknown dependencies
        for s in self.steps_map.values():
            for dep in s.depends_on:
                if dep not in self.steps_map:
                    raise ValueError(f"Step '{s.id}' depends on unknown step '{dep}'")
        # Cycle detection via Kahn's algorithm
        in_deg = {k: len(v) for k, v in self.edges.items()}
        q = [k for k, d in in_deg.items() if d == 0]
        visited = 0
        adj: Dict[str, Set[str]] = {k: set() for k in self.steps_map.keys()}
        for s in self.steps_map.values():
            for dep in s.depends_on:
                adj[dep].add(s.id)
        while q:
            n = q.pop()
            visited += 1
            for m in adj[n]:
                in_deg[m] -= 1
                if in_deg[m] == 0:
                    q.append(m)
        if visited != len(self.steps_map):
            raise ValueError("Cyclic dependency detected in steps")

    def roots(self) -> List[str]:
        return [k for k, deps in self.edges.items() if not deps]

    def ready(self, completed: Set[str]) -> List[str]:
        ready = []
        for k, deps in self.edges.items():
            if k in completed:
                continue
            if all(d in completed for d in deps):
                ready.append(k)
        return ready


# -----------------------------
# Plugin loader
# -----------------------------
class PluginLoader:
    @staticmethod
    def import_module(module_path: str) -> types.ModuleType:
        return importlib.import_module(module_path)

    @staticmethod
    def plugin_hash(module: types.ModuleType) -> Optional[str]:
        path = getattr(module, "__file__", None)
        if not path:
            return None
        p = pathlib.Path(path)
        if p.exists():
            return sha256_file(p)
        return None

    @staticmethod
    def get_callable(module: types.ModuleType):
        """
        Expected plugin API:
          async def run(params: dict, ctx: dict|None=None) -> dict
        or:
          def run(params: dict, ctx: dict|None=None) -> dict
        Return value is optional; any artifacts should be written under ctx["work_dir"].
        """
        fn = getattr(module, "run", None)
        if fn is None or not callable(fn):
            raise RuntimeError("Plugin must expose a callable 'run(params, ctx=None)'")
        return fn


# -----------------------------
# Process isolation
# -----------------------------
def _apply_posix_limits(lim: ProcessLimits) -> None:  # runs inside child process
    if not _POSIX_LIMITS:
        return
    # CPU seconds
    resource.setrlimit(resource.RLIMIT_CPU, (lim.cpu_seconds, lim.cpu_seconds))
    # Virtual memory (address space) in bytes
    mem_bytes = lim.memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    # Open files
    resource.setrlimit(resource.RLIMIT_NOFILE, (lim.open_files, lim.open_files))
    # Processes/threads
    resource.setrlimit(resource.RLIMIT_NPROC, (lim.nproc, lim.nproc))


def _run_plugin_in_subprocess(
    module_path: str,
    params: Dict[str, Any],
    ctx_dict: Dict[str, Any],
    limits: ProcessLimits,
) -> Dict[str, Any]:
    """
    Executed in a separate process by ProcessPoolExecutor.
    Imports the plugin module and calls run(params, ctx).
    """
    if _POSIX_LIMITS:
        _apply_posix_limits(limits)
    module = PluginLoader.import_module(module_path)
    fn = PluginLoader.get_callable(module)
    # prepare coroutine/sync call
    if inspect.iscoroutinefunction(fn):
        # run a minimal event loop in child
        return asyncio.run(fn(params, ctx_dict))  # type: ignore
    else:
        return fn(params, ctx_dict)  # type: ignore


# -----------------------------
# Orchestrator
# -----------------------------
class Orchestrator:
    def __init__(self, cfg: OrchestratorConfig) -> None:
        self.cfg = cfg
        ensure_dir(self.cfg.result_dir)
        self.run_id = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
        self.tracer: Optional[Tracer] = trace.get_tracer(__name__) if _OTEL_AVAILABLE else None
        self._executor = concurrent.futures.ProcessPoolExecutor(max_workers=self.cfg.max_concurrency)

    def _load_scenario(self) -> ScenarioSpec:
        content = self.cfg.scenario_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content) if self.cfg.scenario_path.suffix.lower() in (".yaml", ".yml") else json.loads(content)
        scenario = ScenarioSpec.parse_obj(data)
        return scenario

    def _write_manifest(self, scenario: ScenarioSpec) -> pathlib.Path:
        run_dir = ensure_dir(self.cfg.result_dir / self.run_id)
        manifest = {
            "run_id": self.run_id,
            "scenario_id": scenario.scenario_id,
            "scenario_file": str(self.cfg.scenario_path.resolve()),
            "scenario_sha256": sha256_file(self.cfg.scenario_path),
            "started_at": now_iso(),
            "limits": json.loads(self.cfg.process_limits.json()),
            "rbac_enabled": self.cfg.rbac.enabled,
            "permitted_techniques": sorted(list(self.cfg.rbac.permitted_techniques)),
            "max_concurrency": self.cfg.max_concurrency,
            "default_timeout_sec": self.cfg.default_timeout_sec,
            "global_timeout_sec": self.cfg.global_timeout_sec,
            "otel_enabled": _OTEL_AVAILABLE,
        }
        path = run_dir / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        return run_dir

    async def _execute_step(
        self,
        scenario: ScenarioSpec,
        step: StepSpec,
        run_dir: pathlib.Path,
        attempt: int,
        sem: asyncio.Semaphore,
        cancel_event: asyncio.Event,
    ) -> StepResult:
        started = time.time()
        stdout_path = run_dir / f"{step.id}.stdout"
        stderr_path = run_dir / f"{step.id}.stderr"
        work_dir = ensure_dir(run_dir / f"work_{step.id}_attempt{attempt}")
        ctx = StepContext(
            run_id=self.run_id,
            scenario_id=scenario.scenario_id,
            step_id=step.id,
            work_dir=work_dir,
            result_dir=run_dir,
            start_time=started,
            tracer=self.tracer,
            env={
                "ATTACK_SIM_RUN_ID": self.run_id,
                "ATTACK_SIM_STEP_ID": step.id,
                "ATTACK_SCENARIO_ID": scenario.scenario_id,
            },
        )

        # RBAC check
        if self.cfg.rbac.enabled and step.technique_id:
            if step.technique_id not in self.cfg.rbac.permitted_techniques:
                msg = f"RBAC: technique {step.technique_id} is not permitted"
                log.warning(msg, extra={"extra": {"step": step.id, "technique": step.technique_id}})
                return StepResult(
                    step_id=step.id,
                    status="skipped",
                    started_at=now_iso(),
                    ended_at=now_iso(),
                    duration_ms=0,
                    attempt=attempt,
                    technique_id=step.technique_id,
                    error=msg,
                )

        # Dry-run
        if self.cfg.dry_run:
            log.info("Dry-run: skipping execution", extra={"extra": {"step": step.id}})
            return StepResult(
                step_id=step.id,
                status="skipped",
                started_at=now_iso(),
                ended_at=now_iso(),
                duration_ms=0,
                attempt=attempt,
                technique_id=step.technique_id,
            )

        # Resolve plugin
        try:
            module = PluginLoader.import_module(step.plugin)
            plugin_fn = PluginLoader.get_callable(module)
            plugin_sha = PluginLoader.plugin_hash(module)
        except Exception as e:
            err = f"Plugin load error: {e}"
            log.error(err, extra={"extra": {"step": step.id, "trace": traceback.format_exc()}})
            return StepResult(
                step_id=step.id,
                status="failed",
                started_at=now_iso(),
                ended_at=now_iso(),
                duration_ms=0,
                attempt=attempt,
                technique_id=step.technique_id,
                error=err,
            )

        # Prepare context dict portable across process boundary
        ctx_dict = {
            "run_id": ctx.run_id,
            "scenario_id": ctx.scenario_id,
            "step_id": ctx.step_id,
            "work_dir": str(ctx.work_dir.resolve()),
            "result_dir": str(ctx.result_dir.resolve()),
            "env": ctx.env,
            "trace_enabled": bool(self.tracer),
        }

        # Compute timeout
        timeout = step.timeout_sec or self.cfg.default_timeout_sec

        async def _call() -> Dict[str, Any]:
            loop = asyncio.get_running_loop()
            # Process isolation per step
            return await loop.run_in_executor(
                self._executor,
                functools.partial(
                    _run_plugin_in_subprocess,
                    step.plugin,
                    step.params,
                    ctx_dict,
                    self.cfg.process_limits,
                ),
            )

        # Attach tracing if available
        if self.tracer is not None:
            span_ctx = self.tracer.start_as_current_span(f"step:{step.id}")
        else:
            span_ctx = contextlib.nullcontext()

        with span_ctx:
            try:
                # Bounded concurrency
                async with sem:
                    # Respect global cancel
                    if cancel_event.is_set():
                        raise asyncio.CancelledError("Global cancel triggered")
                    # Execute with timeout
                    result: Dict[str, Any] = await asyncio.wait_for(_call(), timeout=timeout)
                    # Persist optional stdout/stderr if provided
                    if "stdout" in result:
                        stdout_path.write_text(str(result["stdout"]), encoding="utf-8")
                    if "stderr" in result:
                        stderr_path.write_text(str(result["stderr"]), encoding="utf-8")

                    artifacts: List[str] = []
                    for maybe_path in result.get("artifacts", []):
                        try:
                            ap = pathlib.Path(maybe_path)
                            if ap.exists():
                                artifacts.append(str(ap.resolve()))
                        except Exception:
                            continue

                    ended = time.time()
                    return StepResult(
                        step_id=step.id,
                        status="success",
                        started_at=dt.datetime.utcfromtimestamp(started).isoformat() + "Z",
                        ended_at=dt.datetime.utcfromtimestamp(ended).isoformat() + "Z",
                        duration_ms=int((ended - started) * 1000),
                        attempt=attempt,
                        technique_id=step.technique_id,
                        stdout_path=str(stdout_path.resolve()) if stdout_path.exists() else None,
                        stderr_path=str(stderr_path.resolve()) if stderr_path.exists() else None,
                        artifacts=artifacts,
                        error=None,
                        plugin_hash=plugin_sha,
                    )
            except asyncio.TimeoutError:
                ended = time.time()
                msg = f"Step timeout after {timeout}s"
                log.error(msg, extra={"extra": {"step": step.id}})
                return StepResult(
                    step_id=step.id,
                    status="failed",
                    started_at=dt.datetime.utcfromtimestamp(started).isoformat() + "Z",
                    ended_at=dt.datetime.utcfromtimestamp(ended).isoformat() + "Z",
                    duration_ms=int((ended - started) * 1000),
                    attempt=attempt,
                    technique_id=step.technique_id,
                    error=msg,
                    plugin_hash=plugin_sha,
                )
            except asyncio.CancelledError:
                ended = time.time()
                msg = "Step cancelled"
                log.warning(msg, extra={"extra": {"step": step.id}})
                return StepResult(
                    step_id=step.id,
                    status="failed",
                    started_at=dt.datetime.utcfromtimestamp(started).isoformat() + "Z",
                    ended_at=dt.datetime.utcfromtimestamp(ended).isoformat() + "Z",
                    duration_ms=int((ended - started) * 1000),
                    attempt=attempt,
                    technique_id=step.technique_id,
                    error=msg,
                    plugin_hash=plugin_sha,
                )
            except Exception as e:
                ended = time.time()
                msg = f"Step error: {e}"
                log.error(msg, extra={"extra": {"step": step.id, "trace": traceback.format_exc()}})
                return StepResult(
                    step_id=step.id,
                    status="failed",
                    started_at=dt.datetime.utcfromtimestamp(started).isoformat() + "Z",
                    ended_at=dt.datetime.utcfromtimestamp(ended).isoformat() + "Z",
                    duration_ms=int((ended - started) * 1000),
                    attempt=attempt,
                    technique_id=step.technique_id,
                    error=msg,
                    plugin_hash=plugin_sha,
                )

    async def run(self) -> int:
        scenario = self._load_scenario()
        run_dir = self._write_manifest(scenario)
        plan = DagPlan(scenario.steps)

        # Save planned order (level order)
        (run_dir / "plan.json").write_text(
            json.dumps({"roots": plan.roots()}, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        global_deadline: Optional[float] = None
        if self.cfg.global_timeout_sec:
            global_deadline = time.time() + self.cfg.global_timeout_sec

        sem = asyncio.Semaphore(self.cfg.max_concurrency)
        cancel_event = asyncio.Event()

        # Execution bookkeeping
        completed: Set[str] = set()
        failed_critical = False
        results: Dict[str, StepResult] = {}

        # Ready queue management
        pending_tasks: Dict[str, asyncio.Task[StepResult]] = {}

        def maybe_cancel_all():
            if global_deadline and time.time() >= global_deadline:
                cancel_event.set()
                for t in list(pending_tasks.values()):
                    t.cancel()

        # Submit function with retries
        async def submit_with_retries(step: StepSpec) -> StepResult:
            att = 0
            while True:
                if cancel_event.is_set():
                    return StepResult(
                        step_id=step.id,
                        status="failed",
                        started_at=now_iso(),
                        ended_at=now_iso(),
                        duration_ms=0,
                        attempt=att,
                        technique_id=step.technique_id,
                        error="Global cancel",
                    )
                await asyncio.sleep(backoff(att))
                res = await self._execute_step(scenario, step, run_dir, att, sem, cancel_event)
                if res.status == "success":
                    return res
                att += 1
                if att > step.retries:
                    return res

        # Main loop
        while True:
            maybe_cancel_all()
            if failed_critical:
                break
            # Enqueue newly ready steps
            for step_id in plan.ready(completed):
                if step_id in pending_tasks:
                    continue
                step = plan.steps_map[step_id]
                task = asyncio.create_task(submit_with_retries(step))
                pending_tasks[step_id] = task
                log.info("Step scheduled", extra={"extra": {"step": step_id}})

            if not pending_tasks:
                # No tasks left; either done or blocked
                remaining = set(plan.steps_map.keys()) - completed
                if not remaining:
                    break
                else:
                    # Shouldn't happen due to cycle check; but guard anyway
                    raise RuntimeError(f"Deadlock: no runnable steps, remaining: {sorted(remaining)}")

            # Wait for any task to finish
            done, _ = await asyncio.wait(pending_tasks.values(), return_when=asyncio.FIRST_COMPLETED)

            # Consume finished steps
            for finished in done:
                # Find key by task
                sid = None
                for k, v in list(pending_tasks.items()):
                    if v is finished:
                        sid = k
                        del pending_tasks[k]
                        break
                if sid is None:
                    continue
                res = await finished
                results[sid] = res
                # Persist step result
                (run_dir / f"{sid}.result.json").write_text(
                    json.dumps(dataclasses.asdict(res), indent=2, ensure_ascii=False), encoding="utf-8"
                )

                if res.status == "success":
                    completed.add(sid)
                    log.info("Step completed", extra={"extra": {"step": sid, "status": res.status}})
                else:
                    if plan.steps_map[sid].critical:
                        failed_critical = True
                        cancel_event.set()
                        # Cancel other tasks
                        for t in list(pending_tasks.values()):
                            t.cancel()
                        log.error("Critical step failed — cancelling remaining", extra={"extra": {"step": sid}})
                    else:
                        # Non-critical: mark as completed to unblock dependents
                        completed.add(sid)
                        log.warning("Non-critical step failed — continuing", extra={"extra": {"step": sid}})

            # Global timeout check
            maybe_cancel_all()

        # Finalize
        summary = {
            "run_id": self.run_id,
            "scenario_id": scenario.scenario_id,
            "ended_at": now_iso(),
            "status": "failed" if failed_critical or cancel_event.is_set() else "success",
            "completed_steps": sorted(list(completed)),
            "failed_steps": sorted([sid for sid, r in results.items() if r.status != "success"]),
        }
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

        log.info("Run finished", extra={"extra": summary})
        return 0 if summary["status"] == "success" else 1

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)


# -----------------------------
# CLI
# -----------------------------
def parse_args(argv: Optional[List[str]] = None) -> OrchestratorConfig:
    parser = argparse.ArgumentParser(description="Adversary Emulation Attack Simulator Orchestrator")
    parser.add_argument("--scenario", required=True, type=pathlib.Path, help="Path to scenario (.yaml|.json)")
    parser.add_argument("--results", required=True, type=pathlib.Path, help="Directory to store run artifacts")
    parser.add_argument("--max-concurrency", type=int, default=3)
    parser.add_argument("--default-timeout", type=int, default=300)
    parser.add_argument("--global-timeout", type=int, default=None)
    parser.add_argument("--log-level", type=str, default="INFO")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rbac", type=str, default="", help="Comma-separated ATT&CK techniques allow-list (e.g., T1059.003,T1047)")
    parser.add_argument("--cpu-sec", type=int, default=5)
    parser.add_argument("--mem-mb", type=int, default=256)
    parser.add_argument("--nofile", type=int, default=256)
    parser.add_argument("--nproc", type=int, default=64)
    args = parser.parse_args(argv)

    cfg = OrchestratorConfig(
        scenario_path=args.scenario.resolve(),
        result_dir=args.results.resolve(),
        max_concurrency=args.max_concurrency,
        default_timeout_sec=args.default_timeout,
        global_timeout_sec=args.global_timeout,
        log_level=args.log_level,
        dry_run=bool(args.dry_run),
        rbac=RbacPolicy(
            enabled=bool(args.rbac),
            permitted_techniques=set([t.strip() for t in args.rbac.split(",") if t.strip()]) if args.rbac else set(),
        ),
        process_limits=ProcessLimits(
            cpu_seconds=args.cpu_sec,
            memory_mb=args.mem_mb,
            open_files=args.nofile,
            nproc=args.nproc,
        ),
    )
    return cfg


async def _amain(cfg: OrchestratorConfig) -> int:
    configure_logging(cfg.log_level)
    orch = Orchestrator(cfg)
    try:
        return await orch.run()
    finally:
        orch.close()


def main() -> None:
    cfg = parse_args()
    try:
        exit_code = asyncio.run(_amain(cfg))
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
