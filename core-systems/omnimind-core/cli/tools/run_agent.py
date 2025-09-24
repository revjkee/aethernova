# omnimind-core/cli/tools/run_agent.py
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import json
import logging
import os
import signal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# Взаимодействие с реестром инструментов
try:
    from omnimind.tools.registry import (
        tools,
        ExecutionContext,
        ToolNotFound,
        ToolTimeoutError,
        ToolValidationError,
        ToolPermissionError,
        ToolRateLimitError,
        ToolUnavailableError,
    )
except Exception as e:  # упрощённая деградация при отсутствии модуля
    print("FATAL: omnimind.tools.registry is not importable: ", e, file=sys.stderr)
    sys.exit(101)


JSON = Union[dict, list, str, int, float, bool, None]

LOG = logging.getLogger("omnimind.cli.run_agent")


# ----------------------------- Модель плана -----------------------------

@dataclass
class PlanStep:
    # Тип шага: "call" (вызов инструмента) или "set" (установить переменные)
    kind: str
    name: Optional[str] = None          # для call: имя инструмента
    version: Optional[str] = None       # опционально
    payload: Optional[JSON] = None      # dict/list/str...
    timeout_s: Optional[float] = None
    save_as: Optional[str] = None       # имя переменной для результата
    on_error: str = "fail"              # "fail" | "continue" | "set_null"
    vars: Dict[str, Any] = field(default_factory=dict)  # для set: пары ключ=значение
    description: str = ""

@dataclass
class Plan:
    steps: List[PlanStep]
    env_scopes: List[str] = field(default_factory=list)  # списком: ["tool.read", "tool.write"]
    principal: Optional[str] = None
    default_timeout_s: Optional[float] = None


# ----------------------------- Утилиты -----------------------------

def _now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def _read_text_or_stdin(path_or_dash: str) -> str:
    if path_or_dash == "-":
        return sys.stdin.read()
    return Path(path_or_dash).read_text(encoding="utf-8")

def _try_load_yaml_or_json(text: str) -> JSON:
    # Сначала JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Затем YAML, если есть pyyaml
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception as e:
        raise ValueError(f"Input is neither valid JSON nor YAML: {e}")

def _load_plan(path: str) -> Plan:
    raw = _try_load_yaml_or_json(_read_text_or_stdin(path))
    if not isinstance(raw, Mapping) or "steps" not in raw:
        raise ValueError("Plan must be a mapping with 'steps' list")
    steps: List[PlanStep] = []
    for i, s in enumerate(raw.get("steps") or []):
        if not isinstance(s, Mapping):
            raise ValueError(f"Step #{i} must be a mapping")
        kind = str(s.get("kind") or "call")
        step = PlanStep(
            kind=kind,
            name=s.get("name"),
            version=s.get("version"),
            payload=s.get("payload"),
            timeout_s=s.get("timeout_s"),
            save_as=s.get("save_as"),
            on_error=str(s.get("on_error") or "fail"),
            vars=dict(s.get("vars") or {}),
            description=str(s.get("description") or ""),
        )
        steps.append(step)
    plan = Plan(
        steps=steps,
        env_scopes=list(raw.get("env_scopes") or []),
        principal=raw.get("principal"),
        default_timeout_s=raw.get("default_timeout_s"),
    )
    return plan

def _setup_logging(level: str, json_logs: bool = False) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    h = logging.StreamHandler()
    if json_logs:
        fmt = '{"ts":"%(asctime)s","lvl":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    h.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(h)
    root.setLevel(lvl)

def _event(kind: str, **fields: Any) -> Dict[str, Any]:
    ev = {"ts": _now_iso(), "event": kind}
    ev.update(fields)
    return ev

def _emit_jsonl(ev: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(ev, ensure_ascii=False) + "\n")
    sys.stdout.flush()

def _apply_template(value: Any, ctx: Mapping[str, Any]) -> Any:
    # Простая подстановка $var через string.Template (безопасно)
    if isinstance(value, str):
        try:
            return Template(value).safe_substitute(**ctx)
        except Exception:
            return value
    if isinstance(value, list):
        return [_apply_template(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: _apply_template(v, ctx) for k, v in value.items()}
    return value

def _merge_vars(dst: Dict[str, Any], src: Mapping[str, Any]) -> None:
    for k, v in src.items():
        dst[k] = v

def _exit_code_from_exc(exc: BaseException) -> int:
    if isinstance(exc, ToolNotFound):
        return 5
    if isinstance(exc, ToolPermissionError):
        return 6
    if isinstance(exc, ToolRateLimitError):
        return 7
    if isinstance(exc, ToolTimeoutError):
        return 8
    if isinstance(exc, ToolUnavailableError):
        return 9
    if isinstance(exc, ToolValidationError):
        return 10
    return 2  # generic tool error


# ----------------------------- Выполнение -----------------------------

class GracefulCancel:
    def __init__(self) -> None:
        self.cancelled = False

    def install(self) -> None:
        loop = asyncio.get_event_loop()

        def _handler(sig: int, _frame: Any) -> None:
            self.cancelled = True
            _emit_jsonl(_event("signal", signal=sig, note="cancellation requested"))
            for task in asyncio.all_tasks(loop):
                if task is not asyncio.current_task(loop):
                    task.cancel()

        for name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), _handler)  # type: ignore[arg-type]


async def _call_tool(
    name: str,
    payload: JSON,
    *,
    version: Optional[str],
    principal: Optional[str],
    scopes: Iterable[str],
    timeout_s: Optional[float],
    trace_id: Optional[str],
) -> Any:
    ctx = ExecutionContext(
        principal_id=principal,
        scopes=set(scopes or []),
        trace_id=trace_id,
        deadline_ts=(dt.datetime.utcnow().timestamp() + timeout_s) if timeout_s else None,
        metadata={},
    )
    return await tools.call(name, payload, version=version, context=ctx, timeout_s=timeout_s)


async def run_plan(
    plan: Plan,
    *,
    state_file: Optional[Path],
    trace_id: Optional[str],
) -> Tuple[Dict[str, Any], int]:
    vars_ctx: Dict[str, Any] = {}
    # восстановление состояния
    if state_file and state_file.exists():
        try:
            prior = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(prior, Mapping):
                vars_ctx.update(prior)
        except Exception:
            pass

    principal = plan.principal or os.getenv("AGENT_PRINCIPAL") or None
    scopes = plan.env_scopes or (os.getenv("AGENT_SCOPES", "").split(",") if os.getenv("AGENT_SCOPES") else [])

    # Исполнение шагов
    for idx, step in enumerate(plan.steps, 1):
        if step.kind == "set":
            # прямое присваивание с подстановкой
            values = _apply_template(step.vars, vars_ctx)
            if not isinstance(values, Mapping):
                raise ValueError(f"Step {idx} 'set' must provide mapping in 'vars'")
            _merge_vars(vars_ctx, values)
            _emit_jsonl(_event("set", step=idx, vars=list(values.keys())))
            continue

        if step.kind != "call":
            raise ValueError(f"Step {idx}: unknown kind '{step.kind}'")

        if not step.name:
            raise ValueError(f"Step {idx}: 'name' is required for call")

        timeout = step.timeout_s if step.timeout_s is not None else plan.default_timeout_s
        payload_templated = _apply_template(step.payload, vars_ctx)
        _emit_jsonl(
            _event(
                "call.begin",
                step=idx,
                tool=step.name,
                version=step.version,
                timeout_s=timeout,
                has_payload=payload_templated is not None,
            )
        )
        try:
            result = await _call_tool(
                step.name,
                payload_templated,
                version=step.version,
                principal=principal,
                scopes=scopes,
                timeout_s=timeout,
                trace_id=trace_id,
            )
            # pydantic-модели красиво сериализуем
            if hasattr(result, "model_dump"):
                serializable = result.model_dump()  # type: ignore[attr-defined]
            elif dataclasses.is_dataclass(result):
                serializable = dataclasses.asdict(result)  # type: ignore[arg-type]
            else:
                serializable = result
            if step.save_as:
                vars_ctx[step.save_as] = serializable
            _emit_jsonl(
                _event(
                    "call.ok",
                    step=idx,
                    tool=step.name,
                    version=step.version,
                    saved_as=step.save_as,
                )
            )
        except Exception as e:
            _emit_jsonl(
                _event(
                    "call.error",
                    step=idx,
                    tool=step.name,
                    version=step.version,
                    error=type(e).__name__,
                    message=str(e),
                )
            )
            if step.on_error == "continue":
                continue
            if step.on_error == "set_null" and step.save_as:
                vars_ctx[step.save_as] = None
                continue
            return vars_ctx, _exit_code_from_exc(e)

    # сохранить состояние
    if state_file:
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text(json.dumps(vars_ctx, ensure_ascii=False, indent=2), encoding="utf-8")
            _emit_jsonl(_event("state.saved", path=str(state_file)))
        except Exception as e:
            _emit_jsonl(_event("state.error", error=str(e)))

    return vars_ctx, 0


async def run_repl(
    *,
    principal: Optional[str],
    scopes: List[str],
    trace_id: Optional[str],
) -> int:
    _emit_jsonl(_event("repl.start", principal=principal, scopes=scopes))
    help_text = (
        "Commands:\n"
        "  :q | :quit           exit\n"
        "  :ls                  list tools\n"
        "  :scopes a,b,c        set scopes\n"
        "  :who am_i            show principal\n"
        "  call <name> <json>   invoke tool with JSON payload\n"
    )
    vars_ctx: Dict[str, Any] = {}
    print(help_text, file=sys.stderr)

    while True:
        sys.stderr.write("> ")
        sys.stderr.flush()
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        if line in (":q", ":quit", "exit"):
            break
        if line == ":ls":
            for t in tools.list_tools():
                print(f"- {t['name']}@{t['version']} :: {t['description']}")
            continue
        if line.startswith(":scopes"):
            _, _, rest = line.partition(" ")
            scopes[:] = [s for s in rest.split(",") if s]
            print(f"scopes set: {scopes}")
            continue
        if line.startswith(":who"):
            print(f"principal={principal or '-'} scopes={scopes}")
            continue
        if line.startswith("call "):
            try:
                _, _, tail = line.partition(" ")
                name, _, json_str = tail.strip().partition(" ")
                payload = json.loads(json_str) if json_str.strip() else None
                payload = _apply_template(payload, vars_ctx)
                res = await _call_tool(
                    name,
                    payload,
                    version=None,
                    principal=principal,
                    scopes=scopes,
                    timeout_s=None,
                    trace_id=trace_id,
                )
                if hasattr(res, "model_dump"):
                    res = res.model_dump()  # type: ignore[attr-defined]
                print(json.dumps(res, ensure_ascii=False, indent=2))
            except Exception as e:
                print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        print("Unknown command. Type :ls or :q", file=sys.stderr)

    _emit_jsonl(_event("repl.end"))
    return 0


# ----------------------------- CLI -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="omnimind-agent",
        description="Run OmniMind agent over registered tools (single call, plan, or REPL)",
    )
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    p.add_argument("--json-logs", action="store_true", default=bool(os.getenv("JSON_LOGS")))
    p.add_argument("--discover", default=os.getenv("TOOLS_PKG", "omnimind.tools"),
                   help="Python package to import for tools discovery")
    sub = p.add_subparsers(dest="mode", required=True)

    # single call
    c = sub.add_parser("call", help="Single tool invocation")
    c.add_argument("--tool", required=True)
    c.add_argument("--version")
    c.add_argument("--payload", help="JSON string or @/path/to/file.json or '-' for stdin")
    c.add_argument("--principal", default=os.getenv("AGENT_PRINCIPAL"))
    c.add_argument("--scopes", default=os.getenv("AGENT_SCOPES", ""))
    c.add_argument("--timeout", type=float, default=None)
    c.add_argument("--trace-id", default=os.getenv("TRACE_ID"))

    # plan
    pl = sub.add_parser("plan", help="Run plan (JSON/YAML)")
    pl.add_argument("--file", required=True, help="Path to plan file or '-' for stdin")
    pl.add_argument("--state-file", default=os.getenv("AGENT_STATE_FILE"))
    pl.add_argument("--principal", default=os.getenv("AGENT_PRINCIPAL"))
    pl.add_argument("--scopes", default=os.getenv("AGENT_SCOPES", ""))
    pl.add_argument("--trace-id", default=os.getenv("TRACE_ID"))

    # repl
    r = sub.add_parser("repl", help="Interactive REPL")
    r.add_argument("--principal", default=os.getenv("AGENT_PRINCIPAL"))
    r.add_argument("--scopes", default=os.getenv("AGENT_SCOPES", ""))
    r.add_argument("--trace-id", default=os.getenv("TRACE_ID"))

    return p


def _parse_payload_arg(arg: Optional[str]) -> JSON:
    if arg is None or arg == "":
        return None
    s = arg
    if arg.startswith("@"):
        s = _read_text_or_stdin(arg[1:])
    elif arg == "-":
        s = sys.stdin.read()
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        raise ValueError(f"--payload must be a JSON or @file or '-': {e}") from e


async def _main_async(argv: List[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.log_level, json_logs=args.json_logs)
    LOG.debug("argv=%s", argv)

    # discovery инструментов
    if args.discover:
        try:
            tools.discover(args.discover)
        except Exception as e:
            LOG.warning("Tools discovery failed: %s", e)

    cancel = GracefulCancel()
    cancel.install()

    if args.mode == "call":
        payload = _parse_payload_arg(args.payload)
        scopes = [s for s in (args.scopes or "").split(",") if s]
        _emit_jsonl(
            _event(
                "call.begin",
                tool=args.tool,
                version=args.version,
                timeout_s=args.timeout,
                has_payload=payload is not None,
            )
        )
        try:
            res = await _call_tool(
                args.tool,
                payload,
                version=args.version,
                principal=args.principal,
                scopes=scopes,
                timeout_s=args.timeout,
                trace_id=args.trace_id,
            )
            if hasattr(res, "model_dump"):
                res = res.model_dump()  # type: ignore[attr-defined]
            elif dataclasses.is_dataclass(res):
                res = dataclasses.asdict(res)
            _emit_jsonl(_event("call.ok", tool=args.tool, version=args.version))
            sys.stdout.write(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
            return 0
        except Exception as e:
            _emit_jsonl(_event("call.error", tool=args.tool, version=args.version, error=type(e).__name__, message=str(e)))
            return _exit_code_from_exc(e)

    if args.mode == "plan":
        plan = _load_plan(args.file)
        state_path = Path(args.state_file) if args.state_file else None
        vars_ctx, code = await run_plan(plan, state_file=state_path, trace_id=args.trace_id)
        # для пайплайна выводим финальное состояние
        sys.stdout.write(json.dumps({"vars": vars_ctx}, ensure_ascii=False, indent=2) + "\n")
        return code

    if args.mode == "repl":
        scopes = [s for s in (args.scopes or "").split(",") if s]
        return await run_repl(principal=args.principal, scopes=scopes, trace_id=args.trace_id)

    return 1


def main() -> None:
    try:
        code = asyncio.run(_main_async(sys.argv[1:]))
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
