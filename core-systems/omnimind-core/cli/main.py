# path: omnimind-core/cli/main.py
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import signal
import textwrap
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# -------------------------
# Exit codes
# -------------------------
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_RUNTIME = 10
EXIT_UNAVAILABLE = 20

# -------------------------
# Optional integrations
# -------------------------
# Telemetry logging (optional but preferred)
try:
    from omnimind.telemetry.logging import (
        setup_logging,
        LoggingConfig,
        get_logger,
        log_extra,
        log_context,
    )
except Exception:  # fallback stubs
    import logging

    def setup_logging(cfg: Any) -> None:
        logging.basicConfig(level=getattr(logging, str(cfg.level).upper(), logging.INFO))

    @dataclass
    class LoggingConfig:
        service_name: str = "omnimind-core"
        service_version: str = os.getenv("OMNIMIND_VERSION", "0.0.0")
        environment: str = os.getenv("ENVIRONMENT", "dev")
        level: str = os.getenv("LOG_LEVEL", "INFO")
        json: bool = True
        console: bool = True
        color: bool = False
        file_path: Optional[str] = None
        file_rotate_when: str = "midnight"
        file_backup_count: int = 7
        syslog_address: Optional[str] = None
        syslog_facility: int = 1
        journald: bool = False
        rate_limit_per_key_per_minute: int = 0
        suppress_health_access: bool = False
        use_queue_handler: bool = False
        queue_capacity: int = 1000
        redact_patterns: Iterable[Any] = ()

    def get_logger(name: Optional[str] = None):
        return logging.getLogger(name or "omnimind")

    def log_extra(**fields: Any) -> Dict[str, Any]:
        return {"extra": {"extra_fields": fields}}

    from contextlib import contextmanager
    @contextmanager
    def log_context(**kwargs: Any):
        yield

# OpenAI adapter (optional)
try:
    from omnimind.adapters.llm.openai_adapter import (
        OpenAIAdapter,
        AdapterConfig,
        ChatMessage,
        JsonResponseSpec,
    )
    _HAS_OAI = True
except Exception:
    _HAS_OAI = False

# Orchestrator (optional)
try:
    from ops.omnimind.orchestrator.execution_graph import (
        Orchestrator,
        Graph,
        Node,
        RetryPolicy,
        TimeoutPolicy,
        ConcurrencyPolicy,
    )
    _HAS_ORCH = True
except Exception:
    _HAS_ORCH = False

# Chroma store (optional)
try:
    from omnimind.memory.stores.chroma_store import (
        ChromaStore,
        Memory,
        Chunk,
        Embedding,
        QueryRequest,
        QueryFilters,
    )
    _HAS_CHROMA = True
except Exception:
    _HAS_CHROMA = False

# -------------------------
# Utilities
# -------------------------

LOG = get_logger("omnimind.cli")

def _print_json(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")

def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _load_config(path: str) -> Dict[str, Any]:
    """
    Load JSON or TOML config (TOML requires Python 3.11+ tomllib).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if path.endswith(".json"):
        return json.loads(_read_text(path))
    if path.endswith(".toml"):
        try:
            import tomllib  # Python 3.11+
        except Exception as e:
            raise RuntimeError("TOML config requires Python 3.11+ (tomllib)") from e
        return tomllib.loads(_read_text(path))
    raise ValueError("Unsupported config type. Use .json or .toml")

def _install_signal_handlers(loop: asyncio.AbstractEventLoop, cancel: asyncio.Event) -> None:
    def _cancel():
        cancel.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _cancel)
        except NotImplementedError:
            pass

def _env_flag(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")

# -------------------------
# CLI commands
# -------------------------

def cmd_version(args: argparse.Namespace) -> int:
    # Try package metadata; fallback to env
    version = os.getenv("OMNIMIND_VERSION", "0.0.0")
    try:
        import importlib.metadata as im
        version = im.version("omnimind-core")  # package name, adjust if needed
    except Exception:
        pass
    _print_json({"service": "omnimind-core", "version": version, "env": os.getenv("ENVIRONMENT", "dev")})
    return EXIT_OK

def cmd_config_show(args: argparse.Namespace) -> int:
    cfg = _load_config(args.path)
    _print_json(cfg)
    return EXIT_OK

def cmd_config_validate(args: argparse.Namespace) -> int:
    cfg = _load_config(args.path)
    # Minimal validation example (extend per your schema)
    required = args.required or []
    missing = [k for k in required if k not in cfg]
    ok = len(missing) == 0
    _print_json({"ok": ok, "missing": missing, "path": args.path})
    return EXIT_OK if ok else EXIT_CONFIG

async def _llm_chat_async(args: argparse.Namespace) -> int:
    if not _HAS_OAI:
        LOG.error("OpenAI adapter is not available. Install provider or ensure module path is correct.")
        _print_json({"ok": False, "error": "openai_adapter_unavailable"})
        return EXIT_UNAVAILABLE

    cfg = AdapterConfig(
        model=args.model,
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        organization=os.getenv("OPENAI_ORG"),
        project=os.getenv("OPENAI_PROJECT"),
        azure_api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
        request_timeout_s=float(args.timeout),
        max_retries=int(args.retries),
        rate_limit_rps=float(args.rps) if args.rps else None,
        logger_name="omnimind.llm",
    )
    adapter = OpenAIAdapter(cfg)

    messages: List[ChatMessage] = []
    if args.system:
        messages.append(ChatMessage(role="system", content=args.system))
    messages.append(ChatMessage(role="user", content=args.prompt))

    json_spec = None
    if args.json_mode:
        json_spec = JsonResponseSpec(mode="json_object")
    elif args.json_schema:
        schema = json.loads(_read_text(args.json_schema))
        json_spec = JsonResponseSpec(mode="json_schema", schema_name="cli_schema", json_schema=schema)

    start = time.perf_counter()

    if args.stream:
        events: List[Dict[str, Any]] = []
        async for evt in await adapter.async_chat(
            messages,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            top_p=args.top_p,
            response_format=json_spec,
            stream=True,
        ):
            events.append(evt)
            if evt.get("type") == "delta" and not args.quiet:
                # Print streaming text to stdout for interactive mode
                sys.stdout.write(evt["content"])
                sys.stdout.flush()
        if not args.quiet:
            sys.stdout.write("\n")
        _print_json({"ok": True, "mode": "stream", "elapsed_ms": int((time.perf_counter() - start) * 1000)})
        return EXIT_OK

    res = await adapter.async_chat(
        messages,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        top_p=args.top_p,
        response_format=json_spec,
        stream=False,
    )
    _print_json(
        {
            "ok": True,
            "text": res.text,
            "json": res.json,
            "usage": res.usage,
            "model": res.model,
            "latency_ms": res.latency_ms,
            "finish_reason": res.finish_reason,
            "tool_calls": res.tool_calls,
        }
    )
    return EXIT_OK

def cmd_llm_chat(args: argparse.Namespace) -> int:
    return asyncio.run(_llm_chat_async(args))

async def _memory_upsert_async(args: argparse.Namespace) -> int:
    if not _HAS_CHROMA:
        LOG.error("Chroma store is not available.")
        _print_json({"ok": False, "error": "chroma_unavailable"})
        return EXIT_UNAVAILABLE

    # Lazy import chromadb client to avoid hard dependency on CLI startup
    try:
        import chromadb  # type: ignore
    except Exception:
        LOG.error("chromadb package is not installed.")
        _print_json({"ok": False, "error": "chromadb_not_installed"})
        return EXIT_UNAVAILABLE

    client = chromadb.PersistentClient(path=args.path)
    store = ChromaStore(client)

    data = json.loads(_read_text(args.input))
    mem = Memory(
        id=data["id"],
        namespace=data["namespace"],
        owner_id=data.get("owner_id", "unknown"),
        kind=data["kind"],
        attributes=data.get("attributes", {}),
        labels=data.get("labels", []),
        chunks=[
            Chunk(
                id=c["id"],
                index=int(c.get("index", i)),
                text=c["text"],
                tags=c.get("tags", {}),
                embeddings=[
                    Embedding(space=e["space"], vector=e["vector"]) for e in c.get("embeddings", [])
                ],
            )
            for i, c in enumerate(data["chunks"])
        ],
    )
    store.upsert(mem)
    _print_json({"ok": True, "memory_id": mem.id})
    return EXIT_OK

def cmd_memory_upsert(args: argparse.Namespace) -> int:
    return asyncio.run(_memory_upsert_async(args))

async def _memory_query_async(args: argparse.Namespace) -> int:
    if not _HAS_CHROMA:
        LOG.error("Chroma store is not available.")
        _print_json({"ok": False, "error": "chroma_unavailable"})
        return EXIT_UNAVAILABLE

    try:
        import chromadb  # type: ignore
    except Exception:
        LOG.error("chromadb package is not installed.")
        _print_json({"ok": False, "error": "chromadb_not_installed"})
        return EXIT_UNAVAILABLE

    client = chromadb.PersistentClient(path=args.path)
    store = ChromaStore(client)

    req = QueryRequest(
        text_query=args.query,
        embedding_space=args.space,
        embedding_vector=json.loads(args.vector) if args.vector else None,
        top_k=args.top_k,
        vector_weight=args.vector_weight,
        text_weight=args.text_weight,
        filters=QueryFilters(namespace=args.namespace, kinds=args.kinds),
    )
    resp = store.query(req)
    _print_json({"ok": True, "hits": [h.__dict__ for h in resp.hits]})
    return EXIT_OK

def cmd_memory_query(args: argparse.Namespace) -> int:
    return asyncio.run(_memory_query_async(args))

async def _orch_run_async(args: argparse.Namespace) -> int:
    if not _HAS_ORCH:
        LOG.error("Orchestrator is not available.")
        _print_json({"ok": False, "error": "orchestrator_unavailable"})
        return EXIT_UNAVAILABLE

    conc = ConcurrencyPolicy(global_limit=args.global_limit)
    orch = Orchestrator(concurrency=conc, fail_fast=not args.keep_going)

    # Demo graph if no module provided: two tasks with dependency
    async def t_prepare(ctx):
        await asyncio.sleep(0.1)
        return {"ready": True}

    async def t_work(ctx, upstream, inputs):
        await asyncio.sleep(0.2)
        n = int(inputs.get("n", 1))
        return {"result": n * 2, "dep": upstream["prepare"]}

    g = Graph()
    g.add(Node("prepare", t_prepare, cacheable=True, cache_ttl_seconds=30))
    g.add(Node("work", t_work, needs={"prepare"}, timeout=TimeoutPolicy(seconds=5)))

    cancel = asyncio.Event()
    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop, cancel)

    with log_context(request_id=os.getenv("REQUEST_ID", "cli")):
        res = await orch.run(g, inputs={"n": args.n})
    _print_json(
        {
            "ok": True,
            "run_id": res.run_id,
            "status": res.status,
            "results": {k: v.__dict__ for k, v in res.results.items()},
        }
    )
    return EXIT_OK

def cmd_orch_run(args: argparse.Namespace) -> int:
    return asyncio.run(_orch_run_async(args))

# -------------------------
# Plugin hook
# -------------------------

def _load_plugins(parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction) -> None:
    """
    Lightweight plugin loader.
    Set OMNIMIND_CLI_PLUGINS="module1,module2" where each module exposes:
      def register_cli(subparsers) -> None: ...
    """
    mods = os.getenv("OMNIMIND_CLI_PLUGINS", "")
    for name in [m.strip() for m in mods.split(",") if m.strip()]:
        try:
            mod = __import__(name, fromlist=["register_cli"])
            if hasattr(mod, "register_cli"):
                mod.register_cli(subparsers)
                LOG.info("Plugin loaded", extra=log_extra(plugin=name))
        except Exception as e:
            LOG.error("Failed to load plugin", extra=log_extra(plugin=name, error=repr(e)))

# -------------------------
# Parser
# -------------------------

def build_parser() -> argparse.ArgumentParser:
    epilog = textwrap.dedent(
        """
        Examples:
          omnimind version
          omnimind config show ./config.json
          omnimind config validate ./config.toml --required '["openai","model"]'
          omnimind llm chat --model gpt-4o-mini --prompt "Hello" --stream
          omnimind memory upsert --path /var/lib/chroma --input ./memory.json
          omnimind memory query --path /var/lib/chroma --namespace prod --kinds conversation --query "hello" --space text-emb-3-large
          omnimind orch run -n 21
        """
    )
    p = argparse.ArgumentParser(
        prog="omnimind",
        description="Omnimind Core CLI",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Global logging options
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level")
    p.add_argument("--log-json", action="store_true", default=_env_flag("LOG_JSON", True), help="JSON logs")
    p.add_argument("--log-file", default=os.getenv("LOG_FILE"), help="Path to log file")
    p.add_argument("--env", default=os.getenv("ENVIRONMENT", "dev"), help="Environment name")

    sub = p.add_subparsers(dest="cmd", required=True)

    # version
    sp = sub.add_parser("version", help="Show version")
    sp.set_defaults(func=cmd_version)

    # config show
    sp = sub.add_parser("config", help="Configuration utilities")
    cfg_sub = sp.add_subparsers(dest="action", required=True)

    sp_show = cfg_sub.add_parser("show", help="Show config file")
    sp_show.add_argument("path", help="Path to JSON/TOML config")
    sp_show.set_defaults(func=cmd_config_show)

    sp_val = cfg_sub.add_parser("validate", help="Validate config keys")
    sp_val.add_argument("path", help="Path to JSON/TOML config")
    sp_val.add_argument("--required", type=lambda s: json.loads(s), default=[], help='JSON array of required keys')
    sp_val.set_defaults(func=cmd_config_validate)

    # llm chat
    sp = sub.add_parser("llm", help="LLM operations")
    llm_sub = sp.add_subparsers(dest="action", required=True)

    sp_chat = llm_sub.add_parser("chat", help="Chat completion")
    sp_chat.add_argument("--model", required=True, help="Model name or deployment")
    sp_chat.add_argument("--prompt", required=True, help="User prompt")
    sp_chat.add_argument("--system", default=None, help="System prompt")
    sp_chat.add_argument("--temperature", type=float, default=None)
    sp_chat.add_argument("--top-p", dest="top_p", type=float, default=None)
    sp_chat.add_argument("--max-tokens", dest="max_tokens", type=int, default=None)
    sp_chat.add_argument("--timeout", type=float, default=float(os.getenv("LLM_TIMEOUT", "60")))
    sp_chat.add_argument("--retries", type=int, default=int(os.getenv("LLM_RETRIES", "5")))
    sp_chat.add_argument("--rps", type=float, default=None, help="Rate limit RPS")
    sp_chat.add_argument("--stream", action="store_true", help="Stream tokens")
    sp_chat.add_argument("--json-mode", action="store_true", help="Force JSON object mode")
    sp_chat.add_argument("--json-schema", default=None, help="Path to JSON schema for structured output")
    sp_chat.add_argument("--quiet", action="store_true", help="Suppress streaming stdout text")
    sp_chat.set_defaults(func=cmd_llm_chat)

    # memory
    sp = sub.add_parser("memory", help="Memory store operations")
    mem_sub = sp.add_subparsers(dest="action", required=True)

    sp_up = mem_sub.add_parser("upsert", help="Upsert memory from JSON file")
    sp_up.add_argument("--path", required=True, help="Chroma persistent path")
    sp_up.add_argument("--input", required=True, help="Memory JSON file")
    sp_up.set_defaults(func=cmd_memory_upsert)

    sp_q = mem_sub.add_parser("query", help="Query memory")
    sp_q.add_argument("--path", required=True, help="Chroma persistent path")
    sp_q.add_argument("--namespace", required=True, help="Namespace")
    sp_q.add_argument("--kinds", nargs="+", required=True, help="One or more kinds")
    sp_q.add_argument("--query", default=None, help="Text query")
    sp_q.add_argument("--space", default=None, help="Embedding space")
    sp_q.add_argument("--vector", default=None, help="Embedding vector JSON")
    sp_q.add_argument("--top-k", dest="top_k", type=int, default=10)
    sp_q.add_argument("--vector-weight", type=float, default=0.5)
    sp_q.add_argument("--text-weight", type=float, default=0.5)
    sp_q.set_defaults(func=cmd_memory_query)

    # orchestrator
    sp = sub.add_parser("orch", help="Orchestrator")
    orch_sub = sp.add_subparsers(dest="action", required=True)

    sp_run = orch_sub.add_parser("run", help="Run demo DAG")
    sp_run.add_argument("-n", type=int, default=2, help="Input parameter n")
    sp_run.add_argument("--keep-going", action="store_true", help="Do not fail-fast on first error")
    sp_run.add_argument("--global-limit", type=int, default=4, help="Global concurrency")
    sp_run.set_defaults(func=cmd_orch_run)

    # plugins
    _load_plugins(p, sub)

    return p

# -------------------------
# Entry
# -------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()

    # Setup logging once
    cfg = LoggingConfig(
        service_name="omnimind-core",
        environment=os.getenv("ENVIRONMENT", "dev"),
        level=parser.parse_known_args(argv)[0].log_level if argv else os.getenv("LOG_LEVEL", "INFO"),
        json=parser.parse_known_args(argv)[0].log_json if argv else _env_flag("LOG_JSON", True),
        file_path=parser.parse_known_args(argv)[0].log_file if argv else os.getenv("LOG_FILE"),
    )
    setup_logging(cfg)

    try:
        args = parser.parse_args(argv)
        with log_context(request_id=os.getenv("REQUEST_ID", "cli")):
            return int(args.func(args))
    except FileNotFoundError as e:
        LOG.error("file_not_found", extra=log_extra(path=str(e)))
        _print_json({"ok": False, "error": "file_not_found", "path": str(e)})
        return EXIT_CONFIG
    except ValueError as e:
        LOG.error("value_error", extra=log_extra(error=str(e)))
        _print_json({"ok": False, "error": "value_error", "message": str(e)})
        return EXIT_CONFIG
    except KeyboardInterrupt:
        LOG.warning("interrupted")
        _print_json({"ok": False, "error": "interrupted"})
        return EXIT_RUNTIME
    except Exception as e:
        LOG.exception("unhandled_error", extra=log_extra(error=repr(e)))
        _print_json({"ok": False, "error": "unhandled", "message": repr(e)})
        return EXIT_RUNTIME

if __name__ == "__main__":
    sys.exit(main())
