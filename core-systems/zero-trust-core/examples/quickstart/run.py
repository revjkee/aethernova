# zero-trust-core/examples/quickstart/run.py
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Мягкая загрузка python-dotenv (необязательно)
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    def load_dotenv(*_args: Any, **_kwargs: Any) -> None:  # type: ignore
        return

# Внутренние зависимости проекта (должны существовать в zero_trust/)
# Если в вашем репо иные пути — скорректируйте импорты ниже.
try:
    from zero_trust.workers.session_reaper import build_default_worker  # type: ignore
except Exception as e:
    build_default_worker = None  # type: ignore

try:
    from zero_trust.adapters.cilium_adapter import (
        CiliumAdapter,
        HubbleFilter,
        KubernetesConfig as KubeCfg,
    )  # type: ignore
except Exception:
    CiliumAdapter = None  # type: ignore
    HubbleFilter = None  # type: ignore
    KubeCfg = None  # type: ignore


# ------------------------------
# Логирование
# ------------------------------
def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(level.upper() if isinstance(level, str) else level)

    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        formatter = JsonLogFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# ------------------------------
# Утилиты окружения
# ------------------------------
def set_env_if_arg(env_name: str, value: Optional[str]) -> None:
    if value is None:
        return
    os.environ[env_name] = str(value)


def bool_flag(v: Optional[bool]) -> Optional[str]:
    if v is None:
        return None
    return "1" if v else "0"


def require_module(obj: Any, msg: str) -> None:
    if obj is None:
        raise SystemExit(f"Missing dependency/context: {msg}")


# ------------------------------
# Команды: Session Reaper
# ------------------------------
def cmd_reaper(args: argparse.Namespace) -> int:
    require_module(build_default_worker, "zero_trust.workers.session_reaper is unavailable")

    # Проброс CLI -> ENV (worker читает из ENV)
    set_env_if_arg("STORE_BACKEND", args.store_backend)
    set_env_if_arg("REDIS_DSN", args.redis_dsn)
    set_env_if_arg("REDIS_NS", args.redis_ns)
    set_env_if_arg("PG_DSN", args.pg_dsn)

    set_env_if_arg("BATCH_LIMIT", args.batch_limit)
    set_env_if_arg("IDLE_TIMEOUT_SEC", args.idle_timeout_sec)
    set_env_if_arg("GRACE_PERIOD_SEC", args.grace_period_sec)
    set_env_if_arg("REVOKE_TIMEOUT_SEC", args.revoke_timeout_sec)
    set_env_if_arg("RATE_LIMIT_RPS", args.rate_limit_rps)

    set_env_if_arg("DRY_RUN", bool_flag(args.dry_run))
    set_env_if_arg("QUARANTINE_ON_FAILURE", bool_flag(args.quarantine_on_failure))
    set_env_if_arg("ENABLE_K8S_SA_REVOKER", bool_flag(args.enable_k8s_sa_revoker))

    set_env_if_arg("AUDIT_LOG_PATH", args.audit_log_path)
    set_env_if_arg("ENABLE_REDIS_LOCK", bool_flag(args.enable_redis_lock))
    set_env_if_arg("REDIS_LOCK_KEY", args.redis_lock_key)
    set_env_if_arg("REDIS_LOCK_TTL_MS", args.redis_lock_ttl_ms)
    set_env_if_arg("ENABLE_FILE_LOCK", bool_flag(args.enable_file_lock))

    set_env_if_arg("KUBECONFIG", args.kubeconfig)
    set_env_if_arg("K8S_CONTEXT", args.k8s_context)
    set_env_if_arg("K8S_IN_CLUSTER", bool_flag(args.k8s_in_cluster))

    # Лог‑уровень для самого воркера
    set_env_if_arg("LOG_LEVEL", args.log_level)
    set_env_if_arg("RUN_INTERVAL_SEC", args.interval_sec)

    worker = build_default_worker()  # type: ignore

    if args.mode == "once":
        result = worker.run_once()
        print(json.dumps(result, ensure_ascii=False))
        return 0
    else:
        worker.run_forever(interval_sec=float(args.interval_sec or 30))
        return 0


# ------------------------------
# Команды: Cilium Policies
# ------------------------------
def _cilium_adapter_from_args(args: argparse.Namespace) -> "CiliumAdapter":  # type: ignore
    require_module(CiliumAdapter, "zero_trust.adapters.cilium_adapter is unavailable")
    require_module(KubeCfg, "KubernetesConfig class is unavailable")

    cfg = KubeCfg(
        kubeconfig=args.kubeconfig,
        context=args.context,
        namespace=args.namespace,
        in_cluster=bool(args.in_cluster),
    )
    adapter = CiliumAdapter(k8s=cfg, request_timeout=float(args.timeout))
    adapter.connect()
    return adapter


def cmd_cilium_status(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    status = adapter.status()
    print(json.dumps(status, ensure_ascii=False, indent=2))
    return 0


def cmd_cilium_apply_default_deny(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    policy = adapter.build_default_deny(namespace=args.namespace, name=args.name)
    res = adapter.apply_policy(policy, validate=not args.no_validate)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def _parse_http_rules(rules: List[str]) -> List[Dict[str, str]]:
    """
    Принимает ["GET:/healthz", "POST:/login"] -> [{"method":"GET", "path":"/healthz"}, ...]
    """
    parsed: List[Dict[str, str]] = []
    for r in rules:
        if ":" not in r:
            raise SystemExit(f"Invalid http rule '{r}', expected METHOD:/path")
        method, path = r.split(":", 1)
        parsed.append({"method": method.strip().upper(), "path": path.strip()})
    return parsed


def _parse_selector(kv: List[str]) -> Dict[str, Any]:
    """
    Принимает ["app=api", "tier=frontend"] -> {"app":"api", "tier":"frontend"}
    """
    out: Dict[str, Any] = {}
    for item in kv:
        if "=" not in item:
            raise SystemExit(f"Invalid selector '{item}', expected key=value")
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def cmd_cilium_apply_http_allow(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    http_rules = _parse_http_rules(args.http)
    pod_sel = _parse_selector(args.selector or [])
    policy = adapter.build_http_allowlist(
        namespace=args.namespace,
        name=args.name,
        pod_selector=pod_sel,
        http_rules=http_rules,
    )
    res = adapter.apply_policy(policy, validate=not args.no_validate)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_cilium_apply_path(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    policies = adapter.load_policies_from_path(args.path)
    out: List[Dict[str, Any]] = []
    for p in policies:
        res = adapter.apply_policy(p, validate=not args.no_validate)
        out.append(res)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_cilium_delete(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    adapter.delete_policy(
        name=args.name,
        namespaced=not args.clusterwide,
        namespace=args.namespace if not args.clusterwide else None,
    )
    print(json.dumps({"deleted": args.name, "clusterwide": bool(args.clusterwide)}, ensure_ascii=False))
    return 0


def cmd_cilium_get(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    obj = adapter.get_policy(
        name=args.name,
        namespaced=not args.clusterwide,
        namespace=args.namespace if not args.clusterwide else None,
    )
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0


def cmd_cilium_list(args: argparse.Namespace) -> int:
    adapter = _cilium_adapter_from_args(args)
    obj = adapter.list_policies(namespace=None if args.clusterwide else args.namespace)
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0


# ------------------------------
# Команда: Hubble observe
# ------------------------------
def cmd_observe(args: argparse.Namespace) -> int:
    require_module(HubbleFilter, "HubbleFilter is unavailable")
    adapter = _cilium_adapter_from_args(args)
    filt = HubbleFilter(
        namespace=args.namespace,
        pod=args.pod,
        identity=args.identity,
        verdict=args.verdict,
        http_method=args.http_method,
        http_path=args.http_path,
        l4_port=args.port,
        l4_protocol=args.protocol,
        since=args.since,
        follow=bool(args.follow),
        limit=args.limit,
    )
    try:
        count = 0
        for evt in adapter.observe_flows(filt):
            print(json.dumps(evt, ensure_ascii=False))
            count += 1
            if not args.follow and args.limit and count >= args.limit:
                break
    except Exception as e:
        logging.getLogger("observe").error("observe error: %s", e)
        return 1
    return 0


# ------------------------------
# Bootstrap (набор типовых шагов)
# ------------------------------
def cmd_bootstrap_namespace(args: argparse.Namespace) -> int:
    """
    Создаёт default-deny для namespace и (опционально) минимальный allowlist для /healthz.
    """
    adapter = _cilium_adapter_from_args(args)
    results: Dict[str, Any] = {}

    dd = adapter.build_default_deny(namespace=args.namespace, name=args.name_default_deny)
    results["default_deny"] = adapter.apply_policy(dd, validate=not args.no_validate)

    if args.with_health_allow:
        allow = adapter.build_http_allowlist(
            namespace=args.namespace,
            name=args.name_health_allow,
            pod_selector=_parse_selector(args.selector or []),
            http_rules=[{"method": "GET", "path": "/healthz"}],
        )
        results["health_allow"] = adapter.apply_policy(allow, validate=not args.no_validate)

    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


# ------------------------------
# Генератор примеров YAML
# ------------------------------
def cmd_generate_example(args: argparse.Namespace) -> int:
    """
    Печатает в stdout пример CiliumNetworkPolicy (default-deny + http-allowlist).
    """
    doc = [
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "ztp-default-deny", "namespace": args.namespace},
            "spec": {"endpointSelector": {"matchLabels": {}}, "ingress": [], "egress": []},
        },
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "ztp-http-allow", "namespace": args.namespace},
            "spec": {
                "endpointSelector": {"matchLabels": {"app": "api"}},
                "ingress": [
                    {
                        "fromEntities": ["all"],
                        "toPorts": [
                            {"ports": [{"port": "80", "protocol": "TCP"}], "rules": {"http": [{"method": "GET", "path": "/healthz"}]}},
                            {"ports": [{"port": "443", "protocol": "TCP"}], "rules": {"http": [{"method": "GET", "path": "/healthz"}]}},
                        ],
                    }
                ],
            },
        },
    ]
    print(json.dumps(doc, ensure_ascii=False, indent=2))
    return 0


# ------------------------------
# Аргументы CLI
# ------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zt-quickstart", description="Zero Trust Quickstart CLI")
    p.add_argument("--env-file", default=None, help="Path to .env file")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level")
    p.add_argument("--json-logs", action="store_true", help="Enable JSON logs")

    sub = p.add_subparsers(dest="command", required=True)

    # reaper
    pr = sub.add_parser("reaper", help="Run Session Reaper once or in a loop")
    pr.add_argument("--mode", choices=["once", "loop"], default=os.getenv("RUN_MODE", "loop"))
    pr.add_argument("--interval-sec", default=os.getenv("RUN_INTERVAL_SEC", "30"))
    pr.add_argument("--store-backend", choices=["redis", "postgres"], default=os.getenv("STORE_BACKEND", "redis"))
    pr.add_argument("--redis-dsn", default=os.getenv("REDIS_DSN"))
    pr.add_argument("--redis-ns", default=os.getenv("REDIS_NS", "zt:sessions"))
    pr.add_argument("--pg-dsn", default=os.getenv("PG_DSN"))
    pr.add_argument("--batch-limit", default=os.getenv("BATCH_LIMIT"))
    pr.add_argument("--idle-timeout-sec", default=os.getenv("IDLE_TIMEOUT_SEC"))
    pr.add_argument("--grace-period-sec", default=os.getenv("GRACE_PERIOD_SEC"))
    pr.add_argument("--revoke-timeout-sec", default=os.getenv("REVOKE_TIMEOUT_SEC", "5"))
    pr.add_argument("--rate-limit-rps", default=os.getenv("RATE_LIMIT_RPS", "25"))
    pr.add_argument("--dry-run", action="store_true", default=os.getenv("DRY_RUN") in ("1", "true", "True"))
    pr.add_argument("--quarantine-on-failure", action="store_true", default=os.getenv("QUARANTINE_ON_FAILURE") in ("1", "true", "True"))
    pr.add_argument("--enable-k8s-sa-revoker", action="store_true", default=True)
    pr.add_argument("--audit-log-path", default=os.getenv("AUDIT_LOG_PATH", "/var/log/zt/session_reaper_audit.jsonl"))

    pr.add_argument("--enable-redis-lock", action="store_true", default=os.getenv("ENABLE_REDIS_LOCK") in ("1", "true", "True"))
    pr.add_argument("--redis-lock-key", default=os.getenv("REDIS_LOCK_KEY", "zt:locks:session_reaper"))
    pr.add_argument("--redis-lock-ttl-ms", default=os.getenv("REDIS_LOCK_TTL_MS", "60000"))
    pr.add_argument("--enable-file-lock", action="store_true", default=os.getenv("ENABLE_FILE_LOCK", "1") in ("1", "true", "True"))

    pr.add_argument("--kubeconfig", default=os.getenv("KUBECONFIG"))
    pr.add_argument("--k8s-context", default=os.getenv("K8S_CONTEXT"))
    pr.add_argument("--k8s-in-cluster", action="store_true", default=os.getenv("K8S_IN_CLUSTER") in ("1", "true", "True"))
    pr.set_defaults(func=cmd_reaper)

    # cilium common
    def add_cilium_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--kubeconfig", default=os.getenv("KUBECONFIG"))
        sp.add_argument("--context", default=os.getenv("K8S_CONTEXT"))
        sp.add_argument("--namespace", default=os.getenv("CILIUM_NS", "default"))
        sp.add_argument("--in-cluster", action="store_true", default=os.getenv("K8S_IN_CLUSTER") in ("1", "true", "True"))
        sp.add_argument("--timeout", default=os.getenv("K8S_TIMEOUT", "30"))
        sp.add_argument("--no-validate", action="store_true", help="Skip server-side/CLI validation")

    pc = sub.add_parser("cilium", help="Manage Cilium policies")
    sc = pc.add_subparsers(dest="cilium_cmd", required=True)

    pstatus = sc.add_parser("status", help="Show Cilium status")
    add_cilium_common(pstatus)
    pstatus.set_defaults(func=cmd_cilium_status)

    padd = sc.add_parser("apply-default-deny", help="Apply default-deny policy")
    add_cilium_common(padd)
    padd.add_argument("--name", default="ztp-default-deny")
    padd.set_defaults(func=cmd_cilium_apply_default_deny)

    pall = sc.add_parser("apply-http-allow", help="Apply HTTP allowlist policy for selector")
    add_cilium_common(pall)
    pall.add_argument("--name", required=True)
    pall.add_argument("--selector", nargs="*", default=[], help="Label selector key=value list")
    pall.add_argument("--http", nargs="+", required=True, help="HTTP rules METHOD:/path")
    pall.set_defaults(func=cmd_cilium_apply_http_allow)

    ppath = sc.add_parser("apply-path", help="Apply policies from YAML file or directory")
    add_cilium_common(ppath)
    ppath.add_argument("path", help="Path to YAML file/dir")
    ppath.set_defaults(func=cmd_cilium_apply_path)

    pdel = sc.add_parser("delete", help="Delete policy by name")
    add_cilium_common(pdel)
    pdel.add_argument("--name", required=True)
    pdel.add_argument("--clusterwide", action="store_true")
    pdel.set_defaults(func=cmd_cilium_delete)

    pget = sc.add_parser("get", help="Get policy by name")
    add_cilium_common(pget)
    pget.add_argument("--name", required=True)
    pget.add_argument("--clusterwide", action="store_true")
    pget.set_defaults(func=cmd_cilium_get)

    plist = sc.add_parser("list", help="List policies")
    add_cilium_common(plist)
    plist.add_argument("--clusterwide", action="store_true")
    plist.set_defaults(func=cmd_cilium_list)

    # observe
    pob = sub.add_parser("observe", help="Stream flows via Hubble")
    add_cilium_common(pob)
    pob.add_argument("--pod", default=None)
    pob.add_argument("--identity", type=int, default=None)
    pob.add_argument("--verdict", default=None, help="FORWARDED|DROPPED|... ")
    pob.add_argument("--http-method", default=None)
    pob.add_argument("--http-path", default=None)
    pob.add_argument("--port", type=int, default=None)
    pob.add_argument("--protocol", default=None, help="TCP|UDP")
    pob.add_argument("--since", default=None, help="5m, 1h, ...")
    pob.add_argument("--follow", action="store_true", help="Follow stream")
    pob.add_argument("--limit", type=int, default=100)
    pob.set_defaults(func=cmd_observe)

    # bootstrap
    pbs = sub.add_parser("bootstrap-ns", help="Bootstrap namespace with default-deny and optional health allow")
    add_cilium_common(pbs)
    pbs.add_argument("--name-default-deny", default="ztp-default-deny")
    pbs.add_argument("--with-health-allow", action="store_true")
    pbs.add_argument("--name-health-allow", default="ztp-health-allow")
    pbs.add_argument("--selector", nargs="*", default=[], help="Label selector for health allow")
    pbs.set_defaults(func=cmd_bootstrap_namespace)

    # generate-example
    pge = sub.add_parser("generate-example", help="Print example Cilium YAML (JSON form)")
    pge.add_argument("--namespace", default="default")
    pge.set_defaults(func=cmd_generate_example)

    return p


# ------------------------------
# main
# ------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.env_file:
        env_path = Path(args.env_file)
        if env_path.exists():
            load_dotenv(dotenv_path=str(env_path))
        else:
            print(f"Warning: env file not found: {env_path}", file=sys.stderr)

    configure_logging(level=args.log_level, json_logs=bool(args.json_logs))

    try:
        return int(args.func(args))  # type: ignore[attr-defined]
    except SystemExit as e:
        raise
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        logging.getLogger("quickstart").exception("Fatal error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
