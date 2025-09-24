# policy-core/cli/tools/test_policy.py
"""
Policy-Core: Industrial CLI for evaluating and testing access policies.

Subcommands:
  eval              Evaluate policies (by ids or search) against a context
  warmup            Pre-compile policies into adapter cache
  get               Get a single policy
  search            Search policies with filters + pagination
  create            Create a policy
  update            Update a policy (OCC expected_version)
  delete            Delete a policy (optional expected_version)
  history           Show policy history
  activate          Set is_active=True (OCC)
  deactivate        Set is_active=False (OCC)
  import-json       Import policies from a JSON file into repository

Backends:
  - In-Memory (default) via --policies-file (JSON).
  - SQLAlchemy Async (optional) via --db-url (e.g. postgresql+asyncpg://... or sqlite+aiosqlite:///file.db)

Plugins:
  - PolicyCompiler(s):   --compiler module:Class  (repeatable)
  - Attribute Provider:  --attr-provider module:Class
  - Obligation Sink:     --obligation-sink module:Class

Evaluation options:
  --algorithm, --merge-obligations, --concurrency, --timeout-per-policy,
  --max-policies, --search-* options, --ids, --context-file/--context-json

Outputs:
  JSON responses to stdout. Non-zero exit on fatal errors.

Requires:
  Python 3.11+. SQL features require SQLAlchemy 2.x (+ async driver) if used.

Copyright:
  (c) policy-core project. Licensed for internal use.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import importlib
import json
import logging
import os
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Type

# ---- policy-core imports -----------------------------------------------------

# PDP / Combiner is used via EngineCoreAdapter
from policy_core.adapters.engine_core_adapter import (
    EngineCoreAdapter,
    EngineOptions,
    PolicySelector,
    MinimalDefaultCompiler,
    PolicyCompiler,
    AsyncAttributeProvider,
    ObligationSink,
    InMemoryTTLCache,
)
from policy_core.store.repository import (
    PolicyRepository,
    InMemoryPolicyRepository,
    AsyncSQLPolicyRepository,
    PolicyCreate,
    PolicyUpdate,
    SearchQuery,
    Page,
    NotFound,
    AlreadyExists,
    VersionConflict,
    BackendNotAvailable,
)

# Optional SQLAlchemy import (only when --db-url is provided)
try:
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession  # type: ignore
except Exception:  # pragma: no cover
    create_async_engine = None  # type: ignore
    async_sessionmaker = None  # type: ignore
    AsyncSession = None  # type: ignore

# ---- logging -----------------------------------------------------------------

LOG = logging.getLogger("policy_core.cli.test_policy")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)


# ---- utilities ---------------------------------------------------------------

def _load_json_obj(path_or_dash: str) -> Any:
    if path_or_dash == "-" or path_or_dash == "/dev/stdin":
        return json.load(sys.stdin)
    with open(path_or_dash, "r", encoding="utf-8") as f:
        return json.load(f)

def _dumps(o: Any) -> str:
    def _default(x: Any):
        if isinstance(x, datetime):
            return x.isoformat()
        if dataclasses.is_dataclass(x):
            return dataclasses.asdict(x)
        return str(x)
    return json.dumps(o, default=_default, ensure_ascii=False, indent=2, separators=(",", ": "))

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _die(msg: str, code: int = 2) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


# ---- backend wiring ----------------------------------------------------------

async def _build_repository(args: argparse.Namespace) -> PolicyRepository:
    """
    Build repository from args.
    If --db-url provided -> SQL backend; else In-Memory backend.
    If --policies-file provided with In-Memory -> pre-load.
    """
    if args.db_url:
        if create_async_engine is None or async_sessionmaker is None:
            raise BackendNotAvailable("SQLAlchemy is not available. Install sqlalchemy + async driver.")
        engine = create_async_engine(args.db_url, echo=args.sql_echo)
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        repo = AsyncSQLPolicyRepository(session_factory=session_factory)

        if args.sql_ensure_schema:
            await repo.ensure_schema(engine)  # type: ignore[arg-type]
        return repo

    # In-Memory
    repo = InMemoryPolicyRepository()
    if args.policies_file:
        await _import_json_into_repo(repo, args.policies_file, tenant_id=args.tenant_id or "default")
    return repo


async def _import_json_into_repo(repo: PolicyRepository, json_path: str, *, tenant_id: str) -> int:
    """
    Import policies from JSON into repository.
    Supported shapes:
      - [{"id": "...","type":"...","document":{...}, "description":"", "tags":[...], "is_active":true, "tenant_id":"..."}]
      - {"policies":[... as above ...]}
      - {"<id>": {"type":"...", "document":{...}, ...}}  (tenant_id may be inherited from CLI)
    """
    data = _load_json_obj(json_path)

    if isinstance(data, dict) and "policies" in data and isinstance(data["policies"], list):
        items = data["policies"]
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        # dict-of-id
        items = [{"id": k, **v} for k, v in data.items()]
    else:
        _die("Unsupported JSON format for policies import")

    created = 0
    for raw in items:
        if not isinstance(raw, dict):
            continue
        pid = raw.get("id")
        ptype = raw.get("type", "generic")
        pdoc = raw.get("document", {})
        desc = raw.get("description", "")
        tags = raw.get("tags", [])
        active = raw.get("is_active", True)
        ten = raw.get("tenant_id", tenant_id)
        if not pid:
            _die(f"Policy without 'id' in import item: {raw!r}")
        pc = PolicyCreate(
            id=str(pid),
            tenant_id=str(ten),
            type=str(ptype),
            document=pdoc,
            description=str(desc),
            tags=list(tags) if isinstance(tags, (list, tuple)) else [str(tags)],
            is_active=bool(active),
        )
        try:
            await repo.create(pc)
            created += 1
        except AlreadyExists:
            # Overwrite flag?
            LOG.warning("Policy already exists, skipping id=%s", pid)
    return created


# ---- plugins -----------------------------------------------------------------

def _load_class(spec: Optional[str], base_iface: Optional[Type] = None):
    """
    Load class from 'module:Class' spec.
    """
    if not spec:
        return None
    if ":" not in spec:
        _die(f"Invalid spec '{spec}'. Expected 'module:Class'.")
    mod_name, cls_name = spec.split(":", 1)
    mod = importlib.import_module(mod_name)
    cls = getattr(mod, cls_name, None)
    if cls is None:
        _die(f"Class '{cls_name}' not found in module '{mod_name}'.")
    if base_iface and not issubclass(cls, base_iface):  # type: ignore[arg-type]
        # For Protocols/runtime_checkable this check is best-effort
        LOG.warning("Loaded class does not subclass expected interface: %s", base_iface.__name__)
    return cls


def _build_compilers(specs: Sequence[str]) -> List[PolicyCompiler]:
    if not specs:
        return [MinimalDefaultCompiler()]
    out: List[PolicyCompiler] = []
    for s in specs:
        cls = _load_class(s)
        out.append(cls())  # type: ignore[call-arg]
    return out


def _build_attr_provider(spec: Optional[str]) -> AsyncAttributeProvider:
    if not spec:
        from policy_core.adapters.engine_core_adapter import NullAttributeProvider
        return NullAttributeProvider()
    cls = _load_class(spec)
    return cls()  # type: ignore[call-arg]


def _build_obligation_sink(spec: Optional[str]) -> ObligationSink:
    if not spec:
        from policy_core.adapters.engine_core_adapter import NullObligationSink
        return NullObligationSink()
    cls = _load_class(spec)
    return cls()  # type: ignore[call-arg]


# ---- adapter -----------------------------------------------------------------

def _build_adapter(repo: PolicyRepository, args: argparse.Namespace) -> EngineCoreAdapter:
    opts = EngineOptions(
        algorithm=args.algorithm,
        merge_obligations=not args.no_merge_obligations,
        max_policies=args.max_policies,
        concurrency=args.concurrency,
        timeout_per_policy=args.timeout_per_policy,
        compile_cache_ttl_seconds=args.compile_cache_ttl,
        compile_cache_capacity=args.compile_cache_capacity,
        search_page_size=args.search_page_size,
        search_order_by=args.search_order_by,
        search_desc=args.search_desc,
    )
    adapter = EngineCoreAdapter(
        repository=repo,
        compiler_chain=_build_compilers(args.compiler or []),
        attribute_provider=_build_attr_provider(args.attr_provider),
        obligation_sink=_build_obligation_sink(args.obligation_sink),
        options=opts,
        compile_cache=InMemoryTTLCache(capacity=args.compile_cache_capacity),
    )
    return adapter


# ---- argument parsing --------------------------------------------------------

def _add_common_repo_args(p: argparse.ArgumentParser):
    p.add_argument("--db-url", help="SQLAlchemy async DB URL (if omitted, uses In-Memory repository)")
    p.add_argument("--sql-ensure-schema", action="store_true", help="Create tables if absent (dev/test)")
    p.add_argument("--sql-echo", action="store_true", help="SQLAlchemy echo")
    p.add_argument("--policies-file", help="JSON file with policies for In-Memory repository")
    p.add_argument("--tenant-id", help="Tenant id (default: 'default')", default="default")


def _add_common_eval_args(p: argparse.ArgumentParser):
    p.add_argument("--algorithm", default="permit-overrides", help="Combining algorithm name")
    p.add_argument("--no-merge-obligations", action="store_true", help="Do not merge obligations/advice")
    p.add_argument("--concurrency", type=int, default=16, help="Async concurrency")
    p.add_argument("--timeout-per-policy", type=float, default=None, help="Per policy timeout (sec)")
    p.add_argument("--max-policies", type=int, default=1000, help="Max policies per evaluation")
    p.add_argument("--compile-cache-ttl", type=int, default=900, help="Compile cache TTL (sec)")
    p.add_argument("--compile-cache-capacity", type=int, default=10000, help="Compile cache capacity (entries)")
    p.add_argument("--compiler", action="append", help="PolicyCompiler spec 'module:Class' (repeatable)")
    p.add_argument("--attr-provider", help="AttributeProvider spec 'module:Class'")
    p.add_argument("--obligation-sink", help="ObligationSink spec 'module:Class'")
    p.add_argument("--search-page-size", type=int, default=500)
    p.add_argument("--search-order-by", default="id", choices=["id", "created_at", "updated_at", "type"])
    p.add_argument("--search-desc", action="store_true")


def _add_selector_args(p: argparse.ArgumentParser):
    p.add_argument("--ids", nargs="+", help="Explicit policy ids to evaluate")
    p.add_argument("--types", nargs="+", help="Filter by types (used if --ids omitted)")
    p.add_argument("--text", help="Search text in id/description (if --ids omitted)")
    p.add_argument("--tag-any", nargs="+", help="Match any of tags (if --ids omitted)")
    p.add_argument("--tag-all", nargs="+", help="Require all tags (if --ids omitted)")
    act = p.add_mutually_exclusive_group()
    act.add_argument("--active", dest="active", action="store_true", help="Filter active policies (default)")
    act.add_argument("--inactive", dest="active", action="store_false", help="Filter inactive policies")
    p.set_defaults(active=True)


def _add_context_args(p: argparse.ArgumentParser):
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--context-file", help="JSON context file path or '-' for stdin")
    g.add_argument("--context-json", help="Inline JSON string with context")


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="policy-core-test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(__doc__ or ""),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # eval
    p_eval = sub.add_parser("eval", help="Evaluate policies against context")
    _add_common_repo_args(p_eval)
    _add_common_eval_args(p_eval)
    _add_selector_args(p_eval)
    _add_context_args(p_eval)

    # warmup
    p_warm = sub.add_parser("warmup", help="Pre-compile policies into cache")
    _add_common_repo_args(p_warm)
    _add_common_eval_args(p_warm)
    p_warm.add_argument("--ids", nargs="+", required=True, help="Policy ids to warmup")

    # get
    p_get = sub.add_parser("get", help="Get a policy by id")
    _add_common_repo_args(p_get)
    p_get.add_argument("--id", required=True)

    # search
    p_search = sub.add_parser("search", help="Search policies")
    _add_common_repo_args(p_search)
    p_search.add_argument("--types", nargs="+")
    p_search.add_argument("--text")
    p_search.add_argument("--tag-any", nargs="+")
    p_search.add_argument("--tag-all", nargs="+")
    p_search.add_argument("--active", action="store_true", default=None)
    p_search.add_argument("--inactive", action="store_true", default=None)
    p_search.add_argument("--limit", type=int, default=50)
    p_search.add_argument("--offset", type=int, default=0)
    p_search.add_argument("--order-by", default="id", choices=["id", "created_at", "updated_at", "type"])
    p_search.add_argument("--desc", action="store_true")

    # CRUD
    p_create = sub.add_parser("create", help="Create policy from JSON")
    _add_common_repo_args(p_create)
    p_create.add_argument("--json-file", required=True, help="JSON file with a single policy object")
    p_create.add_argument("--override-tenant", help="Override tenant id")

    p_update = sub.add_parser("update", help="Update policy (OCC)")
    _add_common_repo_args(p_update)
    p_update.add_argument("--id", required=True)
    p_update.add_argument("--expected-version", type=int, required=True)
    p_update.add_argument("--json-file", required=True, help="Partial fields: document/description/tags/is_active/type")

    p_delete = sub.add_parser("delete", help="Delete policy (optional OCC)")
    _add_common_repo_args(p_delete)
    p_delete.add_argument("--id", required=True)
    p_delete.add_argument("--expected-version", type=int)

    p_hist = sub.add_parser("history", help="Show policy history")
    _add_common_repo_args(p_hist)
    p_hist.add_argument("--id", required=True)

    p_act = sub.add_parser("activate", help="Activate policy (OCC)")
    _add_common_repo_args(p_act)
    p_act.add_argument("--id", required=True)
    p_act.add_argument("--expected-version", type=int, required=True)

    p_deact = sub.add_parser("deactivate", help="Deactivate policy (OCC)")
    _add_common_repo_args(p_deact)
    p_deact.add_argument("--id", required=True)
    p_deact.add_argument("--expected-version", type=int, required=True)

    # import-json
    p_imp = sub.add_parser("import-json", help="Import policies from JSON into repository")
    _add_common_repo_args(p_imp)
    p_imp.add_argument("--json-file", required=True, help="JSON file with policies list/object")
    return parser.parse_args(argv)


# ---- command handlers --------------------------------------------------------

async def _cmd_eval(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    adapter = _build_adapter(repo, args)

    # selector
    selector = PolicySelector(
        tenant_id=args.tenant_id or "default",
        ids=args.ids,
        types=args.types,
        is_active=args.active,
        text=args.text,
        tag_any=args.tag_any,
        tag_all=args.tag_all,
    )

    # context
    if args.context_file:
        ctx = _load_json_obj(args.context_file)
    else:
        try:
            ctx = json.loads(args.context_json)
        except json.JSONDecodeError as e:
            _die(f"Invalid --context-json: {e}")

    decision = await adapter.evaluate_async(selector, ctx)
    print(_dumps({
        "effect": getattr(decision.effect, "name", str(decision.effect)),
        "obligations": [dataclasses.asdict(o) for o in decision.obligations],
        "advice": [dataclasses.asdict(a) for a in decision.advice],
        "status": dataclasses.asdict(decision.status),
        "errors": decision.errors,
        "attributes": decision.attributes,
    }))
    # exit code: 0 for PERMIT/NOT_APPLICABLE, 3 for DENY, 4 for INDETERMINATE
    eff = getattr(decision.effect, "name", "")
    if eff == "DENY":
        return 3
    if eff == "INDETERMINATE":
        return 4
    return 0


async def _cmd_warmup(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    adapter = _build_adapter(repo, args)
    count = await adapter.warmup_async(args.tenant_id or "default", args.ids)
    print(_dumps({"warmed": count}))
    return 0


async def _cmd_get(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    p = await repo.get(args.tenant_id or "default", args.id)
    print(_dumps(dataclasses.asdict(p)))
    return 0


async def _cmd_search(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    is_active = None
    if args.active and not args.inactive:
        is_active = True
    elif args.inactive and not args.active:
        is_active = False

    q = SearchQuery(
        tenant_id=args.tenant_id or "default",
        types=args.types,
        is_active=is_active,
        text=args.text,
        tag_any=args.tag_any,
        tag_all=args.tag_all,
    )
    page = Page(limit=args.limit, offset=args.offset, order_by=args.order_by, desc=args.desc)
    items, total = await repo.search(q, page)
    print(_dumps({"total": total, "items": [dataclasses.asdict(i) for i in items]}))
    return 0


async def _cmd_create(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    raw = _load_json_obj(args.json_file)
    if not isinstance(raw, dict):
        _die("create: JSON must be an object")
    pid = raw.get("id")
    ten = args.tenant_id or raw.get("tenant_id") or "default"
    if not pid:
        _die("create: missing 'id'")
    pc = PolicyCreate(
        id=str(pid),
        tenant_id=str(ten),
        type=str(raw.get("type", "generic")),
        document=raw.get("document", {}),
        description=str(raw.get("description", "")),
        tags=list(raw.get("tags", [])),
        is_active=bool(raw.get("is_active", True)),
    )
    try:
        p = await repo.create(pc)
    except AlreadyExists as e:
        _die(f"create: already exists: {e}", code=1)
    print(_dumps(dataclasses.asdict(p)))
    return 0


async def _cmd_update(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    raw = _load_json_obj(args.json_file)
    if not isinstance(raw, dict):
        _die("update: JSON must be an object with fields to update")
    pu = PolicyUpdate(
        id=args.id,
        tenant_id=args.tenant_id or "default",
        expected_version=args.expected_version,
        document=raw.get("document"),
        description=raw.get("description"),
        tags=raw.get("tags"),
        is_active=raw.get("is_active"),
        type=raw.get("type"),
    )
    try:
        p = await repo.update(pu)
    except NotFound as e:
        _die(f"update: not found: {e}", code=1)
    except VersionConflict as e:
        _die(f"update: version conflict: {e}", code=1)
    print(_dumps(dataclasses.asdict(p)))
    return 0


async def _cmd_delete(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    try:
        await repo.delete(args.tenant_id or "default", args.id, expected_version=args.expected_version)
    except NotFound as e:
        _die(f"delete: not found: {e}", code=1)
    except VersionConflict as e:
        _die(f"delete: version conflict: {e}", code=1)
    print(_dumps({"deleted": args.id}))
    return 0


async def _cmd_history(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    items = await repo.history(args.tenant_id or "default", args.id)
    print(_dumps([dataclasses.asdict(i) for i in items]))
    return 0


async def _cmd_activate(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    try:
        p = await repo.activate(args.tenant_id or "default", args.id, expected_version=args.expected_version)
    except (NotFound, VersionConflict) as e:
        _die(f"activate: {e}", code=1)
    print(_dumps(dataclasses.asdict(p)))
    return 0


async def _cmd_deactivate(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    try:
        p = await repo.deactivate(args.tenant_id or "default", args.id, expected_version=args.expected_version)
    except (NotFound, VersionConflict) as e:
        _die(f"deactivate: {e}", code=1)
    print(_dumps(dataclasses.asdict(p)))
    return 0


async def _cmd_import(args: argparse.Namespace) -> int:
    repo = await _build_repository(args)
    count = await _import_json_into_repo(repo, args.json_file, tenant_id=args.tenant_id or "default")
    print(_dumps({"imported": count}))
    return 0


# ---- main --------------------------------------------------------------------

async def _amain(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        if args.cmd == "eval":
            return await _cmd_eval(args)
        if args.cmd == "warmup":
            return await _cmd_warmup(args)
        if args.cmd == "get":
            return await _cmd_get(args)
        if args.cmd == "search":
            return await _cmd_search(args)
        if args.cmd == "create":
            return await _cmd_create(args)
        if args.cmd == "update":
            return await _cmd_update(args)
        if args.cmd == "delete":
            return await _cmd_delete(args)
        if args.cmd == "history":
            return await _cmd_history(args)
        if args.cmd == "activate":
            return await _cmd_activate(args)
        if args.cmd == "deactivate":
            return await _cmd_deactivate(args)
        if args.cmd == "import-json":
            return await _cmd_import(args)
        _die(f"Unknown command: {args.cmd}")
    except BackendNotAvailable as e:
        _die(f"Backend not available: {e}")
    except Exception as e:
        # Last-resort failure (unexpected)
        LOG.exception("Fatal error")
        _die(f"Fatal: {e}")
    return 0


def main() -> None:
    exit_code = asyncio.run(_amain())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
