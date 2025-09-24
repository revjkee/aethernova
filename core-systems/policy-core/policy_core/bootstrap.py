from __future__ import annotations

import argparse
import asyncio
import contextlib
import fnmatch
import ipaddress
import json
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple, Union

# -----------------------------
# Utilities: YAML optional
# -----------------------------
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # Fallback to JSON only


# -----------------------------
# Logging setup
# -----------------------------
def _setup_logging(level: str = "INFO", fmt: str = "text") -> logging.Logger:
    logger = logging.getLogger("policy_core")
    logger.setLevel(level.upper() if level else "INFO")
    handler = logging.StreamHandler(sys.stdout)
    if fmt.lower() == "json":
        formatter = _JsonLogFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    handler.setFormatter(formatter)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# -----------------------------
# Configuration
# -----------------------------
@dataclass
class AppConfig:
    log_level: str = "INFO"
    log_format: str = "text"  # "text"|"json"
    policy_path: str = "policies"
    reload_seconds: int = 5  # 0 = no hot reload
    audit_log_path: Optional[str] = None
    default_decision: Literal["deny", "allow"] = "deny"
    metrics_prometheus: bool = False
    metrics_addr: str = "127.0.0.1"
    metrics_port: int = 9109

    @staticmethod
    def load(
        env: Mapping[str, str] = os.environ, config_file: Optional[str] = None
    ) -> "AppConfig":
        # 1) base from file (yaml/json) if provided
        base = {}
        path = (
            config_file
            or env.get("POLICY_CONFIG")
            or env.get("POLICYCORE_CONFIG")
            or ""
        )
        if path:
            base = _load_mapping_file(path)

        # 2) env overrides
        def getenv(k: str, default: Any) -> Any:
            return env.get(k, env.get(k.upper(), base.get(k, default)))

        cfg = AppConfig(
            log_level=str(getenv("log_level", "INFO")),
            log_format=str(getenv("log_format", "text")),
            policy_path=str(getenv("policy_path", base.get("policy_path", "policies"))),
            reload_seconds=int(getenv("reload_seconds", base.get("reload_seconds", 5))),
            audit_log_path=getenv("audit_log_path", base.get("audit_log_path", None)),
            default_decision=str(
                getenv("default_decision", base.get("default_decision", "deny"))
            ).lower()
            in ["deny", "allow"] and str(
                getenv("default_decision", base.get("default_decision", "deny"))
            ).lower()
            or "deny",
            metrics_prometheus=str(getenv("metrics_prometheus", base.get("metrics_prometheus", "false"))).lower()
            in ("1", "true", "yes"),
            metrics_addr=str(getenv("metrics_addr", base.get("metrics_addr", "127.0.0.1"))),
            metrics_port=int(getenv("metrics_port", base.get("metrics_port", 9109))),
        )
        return cfg


def _load_mapping_file(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    data: Dict[str, Any]
    if p.suffix.lower() in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML is required to read YAML config files")
        with p.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    elif p.suffix.lower() == ".json":
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f) or {}
    else:
        # Try YAML then JSON
        if yaml:
            with p.open("r", encoding="utf-8") as f:
                try:
                    data = yaml.safe_load(f) or {}
                except Exception:
                    f.seek(0)
                    data = json.load(f) or {}
        else:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Top-level config must be a mapping")
    return data


# -----------------------------
# Policy model
# -----------------------------
@dataclass(frozen=True)
class ConditionNode:
    # Either a logical node (all/any/not) or a leaf with fn/args
    all: Optional[List["ConditionNode"]] = None
    any: Optional[List["ConditionNode"]] = None
    not_: Optional["ConditionNode"] = field(default=None, metadata={"name": "not"})
    fn: Optional[str] = None
    args: Optional[List[Any]] = None

    @staticmethod
    def from_obj(obj: Any) -> "ConditionNode":
        if obj is None:
            return ConditionNode()
        if isinstance(obj, dict):
            if "all" in obj:
                return ConditionNode(all=[ConditionNode.from_obj(x) for x in obj["all"]])
            if "any" in obj:
                return ConditionNode(any=[ConditionNode.from_obj(x) for x in obj["any"]])
            if "not" in obj:
                return ConditionNode(not_=ConditionNode.from_obj(obj["not"]))
            if "fn" in obj:
                return ConditionNode(fn=str(obj["fn"]), args=list(obj.get("args", [])))
        raise ValueError("Invalid condition node structure")


@dataclass(frozen=True)
class PolicyRule:
    id: str
    effect: Literal["allow", "deny"]
    actions: List[str]
    resources: List[str]
    subjects: List[str]
    priority: int = 100
    condition: Optional[ConditionNode] = None
    tags: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_obj(obj: Mapping[str, Any]) -> "PolicyRule":
        try:
            rid = str(obj["id"])
            effect = str(obj["effect"]).lower()
            if effect not in ("allow", "deny"):
                raise ValueError("effect must be 'allow' or 'deny'")
            actions = _ensure_list_str(obj.get("actions"))
            resources = _ensure_list_str(obj.get("resources"))
            subjects = _ensure_list_str(obj.get("subjects"))
            priority = int(obj.get("priority", 100))
            cond = ConditionNode.from_obj(obj.get("condition")) if "condition" in obj else None
            tags = dict(obj.get("tags", {}))
            return PolicyRule(
                id=rid,
                effect=effect,  # type: ignore
                actions=actions,
                resources=resources,
                subjects=subjects,
                priority=priority,
                condition=cond,
                tags=tags,
            )
        except Exception as e:
            raise ValueError(f"Invalid rule: {e}") from e


@dataclass(frozen=True)
class PolicySet:
    version: str
    rules: List[PolicyRule]

    @staticmethod
    def from_obj(obj: Mapping[str, Any]) -> "PolicySet":
        version = str(obj.get("version", "1"))
        raw_rules = obj.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise ValueError("policy set must contain non-empty 'rules' array")
        rules = [PolicyRule.from_obj(r) for r in raw_rules]
        rules_sorted = sorted(rules, key=lambda r: (r.priority, r.id))
        return PolicySet(version=version, rules=rules_sorted)


def _ensure_list_str(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, Iterable):
        return [str(x) for x in val]
    raise ValueError("Expected list or string")


# -----------------------------
# Conditions registry
# -----------------------------
ConditionFunc = Callable[[Mapping[str, Any], List[Any]], bool]


class ConditionRegistry:
    def __init__(self) -> None:
        self._fns: Dict[str, ConditionFunc] = {}

    def register(self, name: str, fn: ConditionFunc) -> None:
        if not name or not callable(fn):
            raise ValueError("Invalid condition registration")
        self._fns[name] = fn

    def get(self, name: str) -> ConditionFunc:
        fn = self._fns.get(name)
        if not fn:
            raise KeyError(f"Condition '{name}' is not registered")
        return fn

    def names(self) -> List[str]:
        return sorted(self._fns.keys())


conditions = ConditionRegistry()


def _cond_time_between(ctx: Mapping[str, Any], args: List[Any]) -> bool:
    # args: ["HH:MM", "HH:MM", [optional] tz_naive_minutes_offset]
    if len(args) < 2:
        return False
    now_epoch_ms = int(ctx.get("now_ms", time.time() * 1000))
    # Convert to minutes since midnight in provided offset
    offset_min = int(args[2]) if len(args) >= 3 else 0
    local_minutes = ((now_epoch_ms // 1000) // 60 + offset_min) % (24 * 60)

    def to_minutes(hhmm: str) -> int:
        hh, mm = hhmm.split(":")
        return int(hh) * 60 + int(mm)

    start = to_minutes(str(args[0]))
    end = to_minutes(str(args[1]))
    if start <= end:
        return start <= local_minutes <= end
    # Overnight window
    return local_minutes >= start or local_minutes <= end


def _cond_ip_in_cidr(ctx: Mapping[str, Any], args: List[Any]) -> bool:
    # args: [ip_or_ctx_key, "cidr"] ; if ip_or_ctx_key is "$.ip" it will read ctx["ip"]
    if len(args) < 2:
        return False
    ip_val = str(args[0])
    if ip_val.startswith("$."):
        ip_val = _ctx_get(ctx, ip_val[2:])
    if not ip_val:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_val)
        net = ipaddress.ip_network(str(args[1]), strict=False)
        return ip_obj in net
    except Exception:
        return False


def _cond_eq(ctx: Mapping[str, Any], args: List[Any]) -> bool:
    # args: [path_or_literal, value]
    if len(args) < 2:
        return False
    left = args[0]
    if isinstance(left, str) and left.startswith("$."):
        left = _ctx_get(ctx, left[2:])
    return left == args[1]


conditions.register("time_between", _cond_time_between)
conditions.register("ip_in_cidr", _cond_ip_in_cidr)
conditions.register("eq", _cond_eq)


def _ctx_get(ctx: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = ctx
    for part in dotted.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# -----------------------------
# Policy evaluation
# -----------------------------
@dataclass(frozen=True)
class AccessRequest:
    subject: str
    action: str
    resource: str
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    effect: Literal["allow", "deny"]
    rule_id: Optional[str]
    reason: str
    used_conditions: List[str] = field(default_factory=list)


class PolicyEvaluator:
    def __init__(self, policy: PolicySet, default_decision: Literal["deny", "allow"] = "deny") -> None:
        self.policy = policy
        self.default_decision = default_decision

    def evaluate(self, req: AccessRequest) -> Decision:
        used_conditions: List[str] = []
        for rule in self.policy.rules:
            if not _match_any(req.action, rule.actions):
                continue
            if not _match_any(req.resource, rule.resources):
                continue
            if not _match_any(req.subject, rule.subjects):
                continue
            if rule.condition:
                if not _eval_condition(rule.condition, req.context, used_conditions):
                    continue
            return Decision(effect=rule.effect, rule_id=rule.id, reason="matched", used_conditions=used_conditions)
        return Decision(effect=self.default_decision, rule_id=None, reason="no_rule", used_conditions=used_conditions)


def _match_any(value: str, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    for p in patterns:
        if p == "*" or fnmatch.fnmatchcase(value, p):
            return True
    return False


def _eval_condition(node: ConditionNode, ctx: Mapping[str, Any], used: List[str]) -> bool:
    # Empty node equals True
    if node.all is None and node.any is None and node.not_ is None and node.fn is None:
        return True
    if node.all is not None:
        return all(_eval_condition(n, ctx, used) for n in node.all)
    if node.any is not None:
        return any(_eval_condition(n, ctx, used) for n in node.any)
    if node.not_ is not None:
        return not _eval_condition(node.not_, ctx, used)
    if node.fn:
        try:
            fn = conditions.get(node.fn)
            args = node.args or []
            used.append(node.fn)
            return bool(fn(ctx, args))
        except Exception:
            return False
    return False


# -----------------------------
# Policy sources (file/dir) + hot reload
# -----------------------------
class PolicySource:
    async def load(self) -> PolicySet:
        raise NotImplementedError

    async def watch(self) -> Iterable[PolicySet]:
        # Async generator of updates; default: no updates
        yield await self.load()


class FilePolicySource(PolicySource):
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self._last_mtime: float = 0.0

    def _read_single(self, p: Path) -> Dict[str, Any]:
        if p.suffix.lower() in (".yaml", ".yml"):
            if not yaml:
                raise RuntimeError("PyYAML is required for YAML policies")
            with p.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        with p.open("r", encoding="utf-8") as f:
            return json.load(f) or {}

    async def load(self) -> PolicySet:
        if self.path.is_dir():
            merged: Dict[str, Any] = {"version": "1", "rules": []}
            for p in sorted(self.path.glob("**/*")):
                if not p.is_file():
                    continue
                if p.suffix.lower() not in (".yaml", ".yml", ".json"):
                    continue
                data = self._read_single(p)
                # allow both full objects and "rules" list
                if "rules" in data:
                    merged["rules"].extend(data["rules"] or [])
                else:
                    merged["rules"].append(data)
            return PolicySet.from_obj(merged)
        else:
            data = self._read_single(self.path)
            return PolicySet.from_obj(data)

    async def watch(self, poll_seconds: int = 5) -> Iterable[PolicySet]:
        # First immediate load
        yield await self.load()
        if poll_seconds <= 0:
            return
        while True:
            await asyncio.sleep(poll_seconds)
            try:
                mtime = self._compute_mtime()
                if mtime != self._last_mtime:
                    self._last_mtime = mtime
                    yield await self.load()
            except Exception:
                # swallow errors to keep watcher alive; logging is done by app
                continue

    def _compute_mtime(self) -> float:
        if self.path.is_dir():
            mt = 0.0
            for p in self.path.glob("**/*"):
                if p.is_file():
                    mt = max(mt, p.stat().st_mtime)
            return mt
        return self.path.stat().st_mtime


# -----------------------------
# Audit logger
# -----------------------------
class AuditLogger:
    def __init__(self, logger: logging.Logger, path: Optional[str]) -> None:
        self.logger = logger
        self.path = Path(path) if path else None
        self._fh: Optional[Any] = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")

    def record(self, req: AccessRequest, decision: Decision) -> None:
        entry = {
            "ts": int(time.time() * 1000),
            "event": "access_decision",
            "request": {
                "subject": req.subject,
                "action": req.action,
                "resource": req.resource,
                "context_hash": _stable_hash(req.context),
            },
            "decision": {
                "effect": decision.effect,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "used_conditions": decision.used_conditions,
            },
            "id": str(uuid.uuid4()),
        }
        line = json.dumps(entry, ensure_ascii=False)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        else:
            self.logger.info(f"AUDIT {line}")

    async def aclose(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass


def _stable_hash(obj: Any) -> str:
    try:
        blob = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    except Exception:
        blob = str(obj)
    return f"{abs(hash(blob))}"


# -----------------------------
# Metrics (optional Prometheus)
# -----------------------------
class Metrics:
    def __init__(self, use_prom: bool, addr: str, port: int, logger: logging.Logger) -> None:
        self.use_prom = use_prom
        self.addr = addr
        self.port = port
        self.logger = logger
        self._counts: Dict[str, int] = {"allow": 0, "deny": 0, "errors": 0}
        self._prom_started = False
        self._prom = None

    def inc(self, key: str, n: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + n
        if self.use_prom and self._prom:
            try:
                self._prom["decisions"].labels(key).inc(n)
            except Exception:
                pass

    def snapshot(self) -> Dict[str, int]:
        return dict(self._counts)

    def try_start_prometheus(self) -> None:
        if not self.use_prom or self._prom_started:
            return
        try:
            from prometheus_client import Counter, start_http_server  # type: ignore

            self._prom = {
                "decisions": Counter("policy_decisions_total", "Total decisions by effect", ["effect"]),
                "errors": Counter("policy_errors_total", "Total policy errors", []),
            }
            start_http_server(self.port, addr=self.addr)
            self._prom_started = True
            self.logger.info(f"Prometheus metrics on http://{self.addr}:{self.port}/")
        except Exception as e:
            self.logger.warning(f"Prometheus disabled: {e}")
            self._prom = None
            self._prom_started = False


# -----------------------------
# App wiring / lifecycle
# -----------------------------
class PolicyApp:
    def __init__(
        self,
        cfg: AppConfig,
        logger: logging.Logger,
        source: PolicySource,
        metrics: Metrics,
        auditor: AuditLogger,
    ) -> None:
        self.cfg = cfg
        self.logger = logger
        self.source = source
        self.metrics = metrics
        self.auditor = auditor
        self._policy: Optional[PolicySet] = None
        self._evaluator: Optional[PolicyEvaluator] = None
        self._reload_task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        # initial load
        await self._reload_once()
        # Prometheus if enabled
        self.metrics.try_start_prometheus()
        # hot reload loop
        if self.cfg.reload_seconds > 0:
            self._reload_task = asyncio.create_task(self._reload_loop(self.cfg.reload_seconds))
        self.logger.info("PolicyApp started")

    async def stop(self) -> None:
        self._stop.set()
        if self._reload_task:
            self._reload_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reload_task
        await self.auditor.aclose()
        self.logger.info("PolicyApp stopped")

    async def _reload_loop(self, seconds: int) -> None:
        async for ps in self.source.watch(poll_seconds=seconds):
            try:
                self._install_policy(ps)
                self.logger.info(f"Policy reloaded: version={ps.version}, rules={len(ps.rules)}")
            except Exception as e:
                self.metrics.inc("errors")
                self.logger.error(f"Policy reload failed: {e}")

    async def _reload_once(self) -> None:
        ps = await self.source.load()
        self._install_policy(ps)
        self.logger.info(f"Policy loaded: version={ps.version}, rules={len(ps.rules)}")

    def _install_policy(self, ps: PolicySet) -> None:
        self._policy = ps
        self._evaluator = PolicyEvaluator(ps, default_decision=self.cfg.default_decision)

    def evaluate(self, req: AccessRequest) -> Decision:
        if not self._evaluator:
            raise RuntimeError("Policy evaluator is not ready")
        d = self._evaluator.evaluate(req)
        try:
            self.auditor.record(req, d)
        finally:
            self.metrics.inc(d.effect)
        return d


class Bootstrap:
    @staticmethod
    def build(config_file: Optional[str] = None) -> PolicyApp:
        cfg = AppConfig.load(os.environ, config_file=config_file)
        logger = _setup_logging(cfg.log_level, cfg.log_format)
        source = FilePolicySource(cfg.policy_path)
        metrics = Metrics(cfg.metrics_prometheus, cfg.metrics_addr, cfg.metrics_port, logger)
        auditor = AuditLogger(logger, cfg.audit_log_path)
        app = PolicyApp(cfg, logger, source, metrics, auditor)
        return app


# -----------------------------
# CLI
# -----------------------------
def _read_json_stdin() -> Dict[str, Any]:
    data = sys.stdin.read()
    if not data.strip():
        return {}
    return json.loads(data)


def cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="policy-core")
    parser.add_argument("--config", help="Path to YAML/JSON config", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("print-config", help="Print resolved configuration")

    p_run = sub.add_parser("run", help="Run app with hot reload")
    p_run.add_argument("--once", action="store_true", help="Load once and stay idle (for smoke checks)")

    p_eval = sub.add_parser("eval", help="Evaluate single request from args or stdin JSON")
    p_eval.add_argument("--subject", default=None)
    p_eval.add_argument("--action", default=None)
    p_eval.add_argument("--resource", default=None)
    p_eval.add_argument("--context", default=None, help='JSON string; if omitted, read stdin')

    sub.add_parser("validate", help="Validate policy files and exit")

    args = parser.parse_args(argv)

    if args.cmd == "print-config":
        cfg = AppConfig.load(os.environ, config_file=args.config)
        print(json.dumps(cfg.__dict__, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "validate":
        try:
            app = Bootstrap.build(args.config)
            loop = asyncio.get_event_loop()
            loop.run_until_complete(app._reload_once())
            print("OK: policy valid")
            return 0
        except Exception as e:
            print(f"INVALID: {e}", file=sys.stderr)
            return 2

    if args.cmd == "eval":
        ctx: Dict[str, Any] = {}
        if args.context:
            ctx = json.loads(args.context)
        else:
            # if not provided, read full JSON object from stdin
            if not sys.stdin.isatty():
                payload = _read_json_stdin()
                ctx = payload.get("context", {})
                args.subject = args.subject or payload.get("subject")
                args.action = args.action or payload.get("action")
                args.resource = args.resource or payload.get("resource")

        missing = [k for k, v in [("subject", args.subject), ("action", args.action), ("resource", args.resource)] if not v]
        if missing:
            print(f"Missing required fields: {', '.join(missing)}", file=sys.stderr)
            return 2

        app = Bootstrap.build(args.config)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(app.start())
        try:
            req = AccessRequest(subject=str(args.subject), action=str(args.action), resource=str(args.resource), context=ctx or {})
            dec = app.evaluate(req)
            print(json.dumps(dec.__dict__, ensure_ascii=False))
            return 0
        finally:
            loop.run_until_complete(app.stop())

    if args.cmd == "run":
        app = Bootstrap.build(args.config)

        async def _main() -> None:
            await app.start()
            stop = asyncio.Event()

            def _sig(*_: Any) -> None:
                stop.set()

            loop = asyncio.get_running_loop()
            for s in (signal.SIGINT, signal.SIGTERM):
                with contextlib.suppress(NotImplementedError):
                    loop.add_signal_handler(s, _sig)

            if args.once:
                await asyncio.sleep(0.1)
                return

            await stop.wait()
            await app.stop()

        asyncio.run(_main())
        return 0

    return 1


# -----------------------------
# Helpers
# -----------------------------
def load_policy_from_path(path: str) -> PolicySet:
    return asyncio.get_event_loop().run_until_complete(FilePolicySource(path).load())


# -----------------------------
# Entrypoint
# -----------------------------
if __name__ == "__main__":
    sys.exit(cli())
