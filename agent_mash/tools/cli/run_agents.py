#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Industrial Agent Runner CLI

Goals:
- Deterministic, observable, and safe orchestration of multiple "agents"
- Config-driven execution (JSON, or YAML if PyYAML is available)
- Async concurrency with timeouts, retries, and graceful shutdown
- Minimal external dependencies (stdlib only; PyYAML optional)

Config format (example JSON):
{
  "run_id": "optional-string",
  "max_concurrency": 4,
  "default_timeout_s": 900,
  "default_retries": 0,
  "default_retry_backoff_s": 2,
  "agents": [
    {
      "id": "agent-1",
      "enabled": true,
      "callable": "package.module:function_name",
      "kwargs": {"foo": "bar"},
      "timeout_s": 120,
      "retries": 1,
      "retry_backoff_s": 3
    }
  ]
}

Agent callable contract:
- The callable must be importable.
- It may be:
  - async function: async def fn(**kwargs) -> Any
  - sync function: def fn(**kwargs) -> Any  (will run in thread executor)
- Return value is logged as "result" (truncated safely).
- Exceptions are captured and logged; agent marked failed.

Exit codes:
0  - all enabled agents succeeded
2  - some agents failed
3  - config or invocation error
130- signal interrupted (conventional 128 + signal)
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as _dt
import importlib
import json
import logging
import os
import signal
import sys
import time
import traceback
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union


# -----------------------------
# Utilities: time / ids / trunc
# -----------------------------

def utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="milliseconds")


def new_run_id() -> str:
    # Deterministic enough for ops; no external deps
    # Format: YYYYMMDDTHHMMSSmmmZ-pid
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%S')}{int(now.microsecond/1000):03d}Z-{os.getpid()}"


def safe_truncate(obj: Any, limit: int = 4000) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        s = str(obj)
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


# -----------------------------
# Structured JSON logging
# -----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": utc_now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach standard extras if present
        for k in ("run_id", "agent_id", "event", "status", "duration_ms", "attempt", "meta"):
            if hasattr(record, k):
                payload[k] = getattr(record, k)
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str, json_logs: bool) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
    root.addHandler(handler)


def log_extra(base: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    out = dict(base)
    out.update(kwargs)
    return out


# -----------------------------
# Config loading (JSON / YAML)
# -----------------------------

def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_config(path: str) -> Dict[str, Any]:
    raw = _read_text(path)
    ext = os.path.splitext(path)[1].lower().strip(".")
    if ext in ("yaml", "yml"):
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "YAML config requires PyYAML installed. "
                "Either install pyyaml or use JSON config."
            ) from e
        cfg = yaml.safe_load(raw)
        if not isinstance(cfg, dict):
            raise ValueError("Config root must be an object/map.")
        return cfg
    # Default to JSON
    cfg = json.loads(raw)
    if not isinstance(cfg, dict):
        raise ValueError("Config root must be an object.")
    return cfg


# -----------------------------
# Agent specs and validation
# -----------------------------

@dataclass(frozen=True)
class AgentSpec:
    id: str
    enabled: bool
    callable_path: str
    kwargs: Dict[str, Any]
    timeout_s: int
    retries: int
    retry_backoff_s: float


@dataclass(frozen=True)
class RunSpec:
    run_id: str
    max_concurrency: int
    default_timeout_s: int
    default_retries: int
    default_retry_backoff_s: float
    agents: List[AgentSpec]


def _as_int(name: str, value: Any, *, min_v: Optional[int] = None, max_v: Optional[int] = None) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be int, got bool.")
    try:
        iv = int(value)
    except Exception as e:
        raise ValueError(f"{name} must be int, got {type(value).__name__}.") from e
    if min_v is not None and iv < min_v:
        raise ValueError(f"{name} must be >= {min_v}.")
    if max_v is not None and iv > max_v:
        raise ValueError(f"{name} must be <= {max_v}.")
    return iv


def _as_float(name: str, value: Any, *, min_v: Optional[float] = None) -> float:
    try:
        fv = float(value)
    except Exception as e:
        raise ValueError(f"{name} must be float, got {type(value).__name__}.") from e
    if min_v is not None and fv < min_v:
        raise ValueError(f"{name} must be >= {min_v}.")
    return fv


def _as_bool(name: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y", "on"):
            return True
        if v in ("false", "0", "no", "n", "off"):
            return False
    raise ValueError(f"{name} must be boolean.")


def _as_str(name: str, value: Any, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be string.")
    s = value.strip()
    if nonempty and not s:
        raise ValueError(f"{name} must be non-empty.")
    return s


def parse_run_spec(cfg: Dict[str, Any]) -> RunSpec:
    run_id = _as_str("run_id", cfg.get("run_id") or new_run_id(), nonempty=True)

    max_concurrency = _as_int("max_concurrency", cfg.get("max_concurrency", 4), min_v=1, max_v=4096)
    default_timeout_s = _as_int("default_timeout_s", cfg.get("default_timeout_s", 900), min_v=1, max_v=7 * 24 * 3600)
    default_retries = _as_int("default_retries", cfg.get("default_retries", 0), min_v=0, max_v=1000)
    default_retry_backoff_s = _as_float(
        "default_retry_backoff_s", cfg.get("default_retry_backoff_s", 2.0), min_v=0.0
    )

    agents_raw = cfg.get("agents", [])
    if not isinstance(agents_raw, list):
        raise ValueError("agents must be a list.")

    agents: List[AgentSpec] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(agents_raw):
        if not isinstance(item, dict):
            raise ValueError(f"agents[{i}] must be an object.")
        aid = _as_str(f"agents[{i}].id", item.get("id", ""), nonempty=True)
        if aid in seen_ids:
            raise ValueError(f"Duplicate agent id: {aid}")
        seen_ids.add(aid)

        enabled = _as_bool(f"agents[{i}].enabled", item.get("enabled", True))
        callable_path = _as_str(f"agents[{i}].callable", item.get("callable", ""), nonempty=True)

        kwargs = item.get("kwargs", {})
        if kwargs is None:
            kwargs = {}
        if not isinstance(kwargs, dict):
            raise ValueError(f"agents[{i}].kwargs must be an object.")

        timeout_s = _as_int(
            f"agents[{i}].timeout_s",
            item.get("timeout_s", default_timeout_s),
            min_v=1,
            max_v=7 * 24 * 3600,
        )
        retries = _as_int(
            f"agents[{i}].retries",
            item.get("retries", default_retries),
            min_v=0,
            max_v=1000,
        )
        retry_backoff_s = _as_float(
            f"agents[{i}].retry_backoff_s",
            item.get("retry_backoff_s", default_retry_backoff_s),
            min_v=0.0,
        )

        agents.append(
            AgentSpec(
                id=aid,
                enabled=enabled,
                callable_path=callable_path,
                kwargs=kwargs,
                timeout_s=timeout_s,
                retries=retries,
                retry_backoff_s=retry_backoff_s,
            )
        )

    return RunSpec(
        run_id=run_id,
        max_concurrency=max_concurrency,
        default_timeout_s=default_timeout_s,
        default_retries=default_retries,
        default_retry_backoff_s=default_retry_backoff_s,
        agents=agents,
    )


# -----------------------------
# Dynamic import and execution
# -----------------------------

def import_callable(path: str):
    # "pkg.mod:func" or "pkg.mod.func"
    mod_path: str
    attr: str
    if ":" in path:
        mod_path, attr = path.split(":", 1)
    else:
        parts = path.rsplit(".", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid callable path: {path}. Use pkg.mod:func or pkg.mod.func")
        mod_path, attr = parts[0], parts[1]

    module = importlib.import_module(mod_path)
    fn = getattr(module, attr, None)
    if fn is None:
        raise AttributeError(f"Callable not found: {path}")
    if not callable(fn):
        raise TypeError(f"Imported object is not callable: {path}")
    return fn


async def call_maybe_async(fn, **kwargs: Any) -> Any:
    if asyncio.iscoroutinefunction(fn):
        return await fn(**kwargs)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: fn(**kwargs))


# -----------------------------
# Orchestrator
# -----------------------------

@dataclass
class AgentResult:
    agent_id: str
    ok: bool
    attempts: int
    duration_ms: int
    error: Optional[str] = None
    result_preview: Optional[str] = None


class ShutdownSignal(Exception):
    pass


class AgentRunner:
    def __init__(self, spec: RunSpec, logger: logging.Logger):
        self.spec = spec
        self.log = logger
        self._stop_event = asyncio.Event()
        self._base_extra = {"run_id": spec.run_id}

    def request_stop(self) -> None:
        self._stop_event.set()

    async def _run_one(self, agent: AgentSpec, sem: asyncio.Semaphore) -> AgentResult:
        base = dict(self._base_extra)
        base["agent_id"] = agent.id

        if not agent.enabled:
            self.log.info("agent skipped (disabled)", extra=log_extra(base, event="agent_skip", status="skipped"))
            return AgentResult(agent_id=agent.id, ok=True, attempts=0, duration_ms=0, result_preview="disabled")

        async with sem:
            if self._stop_event.is_set():
                raise ShutdownSignal()

            t0 = time.perf_counter()
            attempts = 0
            last_err: Optional[str] = None

            self.log.info(
                "agent start",
                extra=log_extra(base, event="agent_start", status="running", meta={"callable": agent.callable_path}),
            )

            try:
                fn = import_callable(agent.callable_path)
            except Exception as e:
                dt_ms = int((time.perf_counter() - t0) * 1000)
                err = f"import_error: {type(e).__name__}: {e}"
                self.log.error(
                    "agent import failed",
                    extra=log_extra(base, event="agent_error", status="failed", duration_ms=dt_ms),
                    exc_info=True,
                )
                return AgentResult(agent_id=agent.id, ok=False, attempts=0, duration_ms=dt_ms, error=err)

            while True:
                attempts += 1
                if self._stop_event.is_set():
                    raise ShutdownSignal()

                try:
                    res = await asyncio.wait_for(call_maybe_async(fn, **agent.kwargs), timeout=agent.timeout_s)
                    dt_ms = int((time.perf_counter() - t0) * 1000)
                    preview = safe_truncate(res)
                    self.log.info(
                        "agent success",
                        extra=log_extra(
                            base,
                            event="agent_done",
                            status="ok",
                            duration_ms=dt_ms,
                            attempt=attempts,
                            meta={"result": preview},
                        ),
                    )
                    return AgentResult(
                        agent_id=agent.id,
                        ok=True,
                        attempts=attempts,
                        duration_ms=dt_ms,
                        result_preview=preview,
                    )
                except asyncio.TimeoutError:
                    last_err = f"timeout after {agent.timeout_s}s"
                    self.log.warning(
                        "agent timeout",
                        extra=log_extra(
                            base,
                            event="agent_timeout",
                            status="retrying" if attempts <= agent.retries else "failed",
                            attempt=attempts,
                            meta={"timeout_s": agent.timeout_s},
                        ),
                    )
                except Exception as e:
                    last_err = f"{type(e).__name__}: {e}"
                    self.log.error(
                        "agent exception",
                        extra=log_extra(
                            base,
                            event="agent_exception",
                            status="retrying" if attempts <= agent.retries else "failed",
                            attempt=attempts,
                        ),
                        exc_info=True,
                    )

                if attempts > agent.retries:
                    dt_ms = int((time.perf_counter() - t0) * 1000)
                    self.log.error(
                        "agent failed",
                        extra=log_extra(base, event="agent_failed", status="failed", duration_ms=dt_ms, attempt=attempts),
                    )
                    return AgentResult(agent_id=agent.id, ok=False, attempts=attempts, duration_ms=dt_ms, error=last_err)

                backoff = agent.retry_backoff_s * (2 ** (attempts - 1)) if agent.retry_backoff_s > 0 else 0.0
                if backoff > 0:
                    await asyncio.sleep(backoff)

    async def run(self) -> List[AgentResult]:
        sem = asyncio.Semaphore(self.spec.max_concurrency)

        enabled_agents = [a for a in self.spec.agents if a.enabled]
        self.log.info(
            "run start",
            extra=log_extra(
                self._base_extra,
                event="run_start",
                status="running",
                meta={
                    "agents_total": len(self.spec.agents),
                    "agents_enabled": len(enabled_agents),
                    "max_concurrency": self.spec.max_concurrency,
                },
            ),
        )

        results: List[AgentResult] = []
        tasks: List[asyncio.Task] = []

        async def wrap(agent: AgentSpec) -> Optional[AgentResult]:
            try:
                return await self._run_one(agent, sem)
            except ShutdownSignal:
                return None

        for agent in self.spec.agents:
            tasks.append(asyncio.create_task(wrap(agent)))

        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
            for t in done:
                r = t.result()
                if r is not None:
                    results.append(r)
            # Cancel any pending tasks (should be none in ALL_COMPLETED)
            for p in pending:
                p.cancel()
        except ShutdownSignal:
            self.request_stop()
            for t in tasks:
                t.cancel()
            raise
        except Exception:
            self.request_stop()
            for t in tasks:
                t.cancel()
            raise

        ok_count = sum(1 for r in results if r.ok)
        fail_count = sum(1 for r in results if not r.ok)

        self.log.info(
            "run finished",
            extra=log_extra(
                self._base_extra,
                event="run_done",
                status="ok" if fail_count == 0 else "failed",
                meta={"ok": ok_count, "failed": fail_count, "total": len(results)},
            ),
        )

        return results


# -----------------------------
# CLI
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_agents",
        description="Industrial async runner for agent callables described in JSON/YAML config.",
    )
    p.add_argument(
        "--config",
        required=True,
        help="Path to JSON config file, or YAML config file if PyYAML is installed.",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("AGENT_RUNNER_LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG, INFO, WARNING, ERROR). Default: INFO.",
    )
    p.add_argument(
        "--json-logs",
        action="store_true",
        default=bool(os.environ.get("AGENT_RUNNER_JSON_LOGS", "")),
        help="Enable JSON structured logs.",
    )
    p.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop scheduling further work on first failure (best-effort).",
    )
    p.add_argument(
        "--print-summary",
        action="store_true",
        help="Print a final machine-readable summary JSON to stdout (in addition to logs).",
    )
    return p


def _signal_exit_code(sig: int) -> int:
    # Conventional: 128 + signal number
    return 128 + sig


async def _amain(args: argparse.Namespace) -> int:
    setup_logging(args.log_level, args.json_logs)
    log = logging.getLogger("agent_runner")

    try:
        cfg = load_config(args.config)
        spec = parse_run_spec(cfg)
    except Exception as e:
        log.error("config error", extra={"event": "config_error", "status": "failed"}, exc_info=True)
        if args.print_summary:
            summary = {"status": "config_error", "error": f"{type(e).__name__}: {e}"}
            print(json.dumps(summary, ensure_ascii=False))
        return 3

    runner = AgentRunner(spec, log)

    loop = asyncio.get_running_loop()
    stop_reason: Dict[str, Any] = {"reason": None, "signal": None}

    def on_signal(sig: int) -> None:
        stop_reason["reason"] = "signal"
        stop_reason["signal"] = sig
        runner.request_stop()

    # Cross-platform: SIGTERM may not exist on Windows, but SIGINT does.
    for s in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if s is None:
            continue
        try:
            loop.add_signal_handler(s, lambda ss=s: on_signal(int(ss)))
        except NotImplementedError:
            # Fallback for Windows event loop
            try:
                signal.signal(s, lambda *_: on_signal(int(s)))
            except Exception:
                pass

    t0 = time.perf_counter()
    results: List[AgentResult] = []
    exit_code = 0

    try:
        if args.fail_fast:
            # Fail-fast: we still start all tasks, but we can request stop when first failure appears.
            # Implemented by watching task completion via periodic checks.
            run_task = asyncio.create_task(runner.run())
            while not run_task.done():
                await asyncio.sleep(0.2)
                # Nothing to inspect inside runner without deeper hooks; fail-fast is best-effort.
                if runner._stop_event.is_set():
                    break
            if run_task.done():
                results = run_task.result()
            else:
                run_task.cancel()
                raise ShutdownSignal()
        else:
            results = await runner.run()

        if any(not r.ok for r in results):
            exit_code = 2
    except ShutdownSignal:
        sig = stop_reason.get("signal")
        if isinstance(sig, int) and sig > 0:
            exit_code = _signal_exit_code(sig)
        else:
            exit_code = 130  # conventional Ctrl+C
        log.warning(
            "run interrupted",
            extra={"run_id": spec.run_id, "event": "run_interrupted", "status": "cancelled", "meta": stop_reason},
        )
    except Exception as e:
        exit_code = 3
        log.error(
            "run crashed",
            extra={"run_id": spec.run_id, "event": "run_crash", "status": "failed"},
            exc_info=True,
        )
        if args.print_summary:
            summary = {"run_id": spec.run_id, "status": "crash", "error": f"{type(e).__name__}: {e}"}
            print(json.dumps(summary, ensure_ascii=False))
        return exit_code

    dt_ms = int((time.perf_counter() - t0) * 1000)
    ok = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]

    if args.print_summary:
        summary = {
            "run_id": spec.run_id,
            "status": "ok" if exit_code == 0 else ("partial_fail" if exit_code == 2 else "interrupted"),
            "duration_ms": dt_ms,
            "counts": {"ok": len(ok), "failed": len(failed), "total": len(results)},
            "results": [
                dataclasses.asdict(r)
                for r in results
            ],
        }
        print(json.dumps(summary, ensure_ascii=False))

    return exit_code


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        code = asyncio.run(_amain(args))
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
