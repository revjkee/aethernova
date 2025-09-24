# path: oblivionvault-core/cli/tools/set_legal_hold.py
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------- Project deps (must exist in repo) ----------
try:
    # Data Fabric adapter (промышленная версия предоставлялась ранее)
    from oblivionvault.adapters.datafabric_adapter import (
        DataFabricAdapter,
        DataEnvelope,
        QuerySpec,
        AccessContext as DFContext,
        RetryPolicy as DFRetryPolicy,
        CircuitBreaker as DFCircuitBreaker,
        DataFabricTransport,
        DataFabricError,
    )
except Exception as e:
    print("FATAL: cannot import DataFabricAdapter. Ensure PYTHONPATH to oblivionvault-core.", file=sys.stderr)
    raise

try:
    # OPA/Rego evaluator (промышленная версия предоставлялась ранее)
    from oblivionvault.policy.evaluator_rego import (
        RegoPolicyEvaluator,
        OPAHttpBackend,
        AccessContext as PolicyContext,
        RetryPolicy as PolicyRetryPolicy,
        CircuitBreaker as PolicyCircuitBreaker,
        PolicyError,
    )
except Exception as e:
    print("FATAL: cannot import RegoPolicyEvaluator. Ensure PYTHONPATH to oblivionvault-core.", file=sys.stderr)
    raise


# ---------- Logging ----------
LOG = logging.getLogger("cli.set_legal_hold")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)


# ---------- Helpers ----------
def _parse_expires_at(s: Optional[str]) -> Optional[float]:
    """
    Парсит ISO8601/UNIX строку в UNIX-время (секунды).
    """
    if not s:
        return None
    s = s.strip()
    # UNIX seconds
    if s.isdigit():
        v = int(s)
        # допускаем миллисекунды
        return float(v) / (1000.0 if v > 10_000_000_000 else 1.0)
    # ISO8601
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        raise argparse.ArgumentTypeError(f"Invalid expires-at value: {s}")


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


def _stable_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _load_json_file(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dynamic_import(path: str):
    """
    Импортирует класс по строке вида 'package.module:ClassName'
    """
    if ":" not in path:
        raise ValueError("transport must be 'module.path:ClassName'")
    mod_name, cls_name = path.split(":", 1)
    module = importlib.import_module(mod_name)
    cls = getattr(module, cls_name)
    return cls


@dataclass
class CLIConfig:
    tenant_id: str
    principal_id: str
    scopes: Set[str]
    holds_dataset: str
    action: str  # "set" | "release"
    dataset: str
    keys: List[str]
    filter_json: Optional[Dict[str, Any]]
    limit: Optional[int]
    label: str
    reason: Optional[str]
    expires_at: Optional[float]
    dry_run: bool
    yes: bool
    concurrency: int
    read_timeout_s: float
    write_timeout_s: float
    opa_url: str
    opa_token: Optional[str]
    opa_package: str
    opa_rule: str
    transport_path: str
    transport_config: Optional[Dict[str, Any]]
    df_retry: DFRetryPolicy
    df_breaker: DFCircuitBreaker
    hmac_secret: Optional[str]


# ---------- Core logic ----------
class SetLegalHoldCLI:
    def __init__(self, cfg: CLIConfig):
        self.cfg = cfg
        self._df: Optional[DataFabricAdapter] = None
        self._opa: Optional[RegoPolicyEvaluator] = None

    async def __aenter__(self):
        self._df = await self._build_df()
        self._opa = await self._build_opa()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # закрывать тут особо нечего — HTTP-сессии закрываются в бэкендах, если нужно
        pass

    async def _build_df(self) -> DataFabricAdapter:
        # Динамически поднимаем транспорт DataFabric
        TransportCls = _dynamic_import(self.cfg.transport_path)
        if not issubclass(TransportCls, DataFabricTransport):
            LOG.warning("Transport class does not subclass DataFabricTransport; proceeding anyway.")
        transport = TransportCls(**(self.cfg.transport_config or {}))
        return DataFabricAdapter(
            transport=transport,
            retry_policy=self.cfg.df_retry,
            breaker=self.cfg.df_breaker,
            default_timeout_s=max(self.cfg.read_timeout_s, self.cfg.write_timeout_s),
            hmac_secret=self.cfg.hmac_secret,
        )

    async def _build_opa(self) -> RegoPolicyEvaluator:
        headers = {}
        if self.cfg.opa_token:
            headers["Authorization"] = f"Bearer {self.cfg.opa_token}"
        backend = OPAHttpBackend(base_url=self.cfg.opa_url, timeout_s=5.0, headers=headers)
        return RegoPolicyEvaluator(
            backend=backend,
            retry_policy=PolicyRetryPolicy(),
            breaker=PolicyCircuitBreaker(),
            default_timeout_s=5.0,
            max_concurrency=max(8, self.cfg.concurrency),
            decision_cache_ttl_s=15.0,
        )

    def _build_df_context(self) -> DFContext:
        base_scopes = set(self.cfg.scopes) | {"df:read", "df:write", "policy:evaluate"}
        # управление политикой может потребоваться внешне; здесь достаточно evaluate
        return DFContext(
            tenant_id=self.cfg.tenant_id,
            principal_id=self.cfg.principal_id,
            scopes=base_scopes,
            trace_id=os.getenv("TRACE_ID"),
        )

    async def _collect_targets(self, df: DataFabricAdapter, ctx: DFContext) -> List[Tuple[str, str]]:
        """
        Возвращает список (dataset, key) для применения действия.
        Если указаны --keys -> используем их.
        Если указан --filter -> стримим query и собираем ключи.
        """
        if self.cfg.keys:
            return [(self.cfg.dataset, k) for k in self.cfg.keys]

        if self.cfg.filter_json is None:
            raise ValueError("Provide either --keys or --filter")

        spec = QuerySpec(
            dataset=self.cfg.dataset,
            filter=self.cfg.filter_json,
            limit=self.cfg.limit,
            order_by=None,
        )
        out: List[Tuple[str, str]] = []
        async for env in await df.query(ctx, spec, timeout_s=self.cfg.read_timeout_s):
            out.append((env.dataset, env.key))
            if self.cfg.limit and len(out) >= self.cfg.limit:
                break
        return out

    async def _opa_allow(self, opa: RegoPolicyEvaluator, ctx: DFContext, dataset: str, key: str) -> bool:
        pctx = PolicyContext(
            tenant_id=ctx.tenant_id,
            principal_id=ctx.principal_id,
            scopes=set(ctx.scopes or set()) | {"policy:evaluate"},
            trace_id=ctx.trace_id,
        )
        input_doc = {
            "tenant": ctx.tenant_id,
            "principal": ctx.principal_id,
            "action": self.cfg.action,  # "set"|"release"
            "dataset": dataset,
            "key": key,
            "label": self.cfg.label,
            "reason": self.cfg.reason,
            "expires_at": self.cfg.expires_at,
        }
        try:
            decision = await opa.evaluate(
                pctx,
                package=self.cfg.opa_package,
                rule=self.cfg.opa_rule,
                input_doc=input_doc,
                timeout_s=5.0,
                cache=True,
            )
            # допускаем allow==True или result==True
            return bool((decision.allow is True) or (decision.result is True))
        except PolicyError:
            LOG.exception("OPA evaluation failed dataset=%s key=%s", dataset, key)
            return False

    async def _upsert_hold_record(self, df: DataFabricAdapter, ctx: DFContext, dataset: str, key: str, active: bool) -> None:
        now = time.time()
        body = {
            "id": f"{dataset}:{key}",           # стабильный ID
            "dataset": dataset,
            "key": key,
            "label": self.cfg.label,
            "reason": self.cfg.reason,
            "active": active,
            "set_by": ctx.principal_id,
            "set_at": now if active else None,
            "released_at": None if active else now,
            "expires_at": self.cfg.expires_at,
            "updated_at": now,
        }
        await df.upsert_records(
            ctx,
            dataset=self.cfg.holds_dataset,
            records=[body],
            schema_version="1.0",
            id_key="id",
            idempotency_key=f"lhold:{'set' if active else 'rel'}:{dataset}:{key}:{int(now)}",
            timeout_s=self.cfg.write_timeout_s,
        )

    async def run(self) -> int:
        df = self._df
        opa = self._opa
        assert df and opa

        ctx = self._build_df_context()
        targets = await self._collect_targets(df, ctx)

        if not targets:
            LOG.info("No targets matched. Nothing to do.")
            print(_stable_json({"ok": True, "processed": 0, "matched": 0, "set": 0, "released": 0, "denied": 0, "skipped": 0}))
            return 0

        if not self.cfg.yes and not self.cfg.dry_run:
            # Подтверждение
            print(f"About to {self.cfg.action} legal hold for {len(targets)} record(s) in dataset '{self.cfg.dataset}'. Proceed? [y/N] ", end="", flush=True)
            ans = sys.stdin.readline().strip().lower()
            if ans not in ("y", "yes"):
                print("Aborted.")
                return 1

        # Параллельная обработка
        sem = asyncio.Semaphore(self.cfg.concurrency)

        stats = {
            "matched": len(targets),
            "set": 0,
            "released": 0,
            "denied": 0,
            "skipped": 0,
            "errors": 0,
        }

        async def _one(ds: str, k: str):
            async with sem:
                allow = await self._opa_allow(opa, ctx, ds, k)
                if not allow:
                    stats["denied"] += 1
                    return
                if self.cfg.dry_run:
                    # Только считаем
                    if self.cfg.action == "set":
                        stats["set"] += 1
                    else:
                        stats["released"] += 1
                    return
                try:
                    await self._upsert_hold_record(df, ctx, ds, k, active=(self.cfg.action == "set"))
                    if self.cfg.action == "set":
                        stats["set"] += 1
                    else:
                        stats["released"] += 1
                except DataFabricError:
                    LOG.exception("DataFabric error on %s:%s", ds, k)
                    stats["errors"] += 1

        await asyncio.gather(*[_one(ds, k) for ds, k in targets])

        result = {
            "ok": stats["errors"] == 0,
            "processed": stats["set"] + stats["released"] + stats["denied"] + stats["skipped"],
            **stats,
            "holds_dataset": self.cfg.holds_dataset,
            "dataset": self.cfg.dataset,
            "action": self.cfg.action,
        }
        print(_stable_json(result))
        return 0 if result["ok"] else 2


# ---------- CLI parsing ----------
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="set_legal_hold",
        description="Set or release Legal Hold in oblivionvault via DataFabric+OPA.",
    )

    # Identity / scopes
    p.add_argument("--tenant-id", required=True, help="Tenant identifier")
    p.add_argument("--principal-id", required=True, help="Principal/actor identifier")
    p.add_argument("--scope", action="append", default=[], help="Additional scopes (repeatable)")

    # Action & selection
    p.add_argument("--action", choices=["set", "release"], required=True, help="Action to apply")
    p.add_argument("--dataset", required=True, help="Target dataset for keys/query")
    p.add_argument("--key", dest="keys", action="append", default=[], help="Record key (repeatable)")
    p.add_argument("--keys-file", help="Path to file with keys (one per line)")
    p.add_argument("--filter", help="JSON string for QuerySpec.filter when selecting by query")
    p.add_argument("--filter-file", help="Path to JSON file for QuerySpec.filter")
    p.add_argument("--limit", type=int, help="Limit number of matched records (for query selection)")

    # Hold metadata
    p.add_argument("--label", default="legal_hold", help="Hold label")
    p.add_argument("--reason", help="Reason/comment")
    p.add_argument("--expires-at", type=_parse_expires_at, help="ISO8601 or UNIX seconds (optional)")

    # Datasets / plumbing
    p.add_argument("--holds-dataset", default="_legal_holds", help="Dataset where hold records are stored")

    # OPA
    p.add_argument("--opa-url", default=os.getenv("OPA_URL", "http://127.0.0.1:8181"), help="OPA base URL")
    p.add_argument("--opa-token", default=os.getenv("OPA_TOKEN"), help="OPA bearer token (optional)")
    p.add_argument("--opa-package", default="oblivionvault.legalhold", help="OPA package for decision")
    p.add_argument("--opa-rule", default="allow", help="OPA rule in package")

    # DataFabric transport
    p.add_argument("--transport", required=True, help="Transport class 'module.path:ClassName'")
    p.add_argument("--transport-config", help="JSON file with transport kwargs")
    p.add_argument("--hmac-secret", help="HMAC secret for DataFabricAdapter (optional)")

    # Reliability / perf
    p.add_argument("--concurrency", type=int, default=32, help="Parallelism for applying holds")
    p.add_argument("--read-timeout-s", type=float, default=15.0)
    p.add_argument("--write-timeout-s", type=float, default=20.0)

    # Safety
    p.add_argument("--dry-run", action="store_true", help="Do nothing, only compute")
    p.add_argument("-y", "--yes", action="store_true", help="Do not prompt for confirmation")

    # Verbosity
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity (-v, -vv)")
    return p


def _load_selection(args: argparse.Namespace) -> Tuple[List[str], Optional[Dict[str, Any]]]:
    keys: List[str] = list(args.keys or [])
    if args.keys_file:
        with open(args.keys_file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    keys.append(s)

    filter_json: Optional[Dict[str, Any]] = None
    if args.filter:
        try:
            filter_json = json.loads(args.filter)
        except Exception:
            raise SystemExit("Invalid --filter JSON string")
    if args.filter_file:
        try:
            with open(args.filter_file, "r", encoding="utf-8") as f:
                filter_json = json.load(f)
        except Exception:
            raise SystemExit("Invalid --filter-file JSON")

    if not keys and not filter_json:
        raise SystemExit("Provide either --key/--keys-file or --filter/--filter-file")

    return keys, filter_json


def _verbosity_to_level(v: int) -> int:
    if v >= 2:
        return logging.DEBUG
    if v == 1:
        return logging.INFO
    return logging.WARNING


def _build_cli_config(args: argparse.Namespace) -> CLIConfig:
    keys, filter_json = _load_selection(args)

    # DF Retry/Breaker defaults
    df_retry = DFRetryPolicy()
    df_breaker = DFCircuitBreaker()

    scopes = set(args.scope or [])
    # минимально нужны df:read/df:write/policy:evaluate — CLI добавит их сам

    return CLIConfig(
        tenant_id=args.tenant_id,
        principal_id=args.principal_id,
        scopes=scopes,
        holds_dataset=args.holds_dataset,
        action=args.action,
        dataset=args.dataset,
        keys=keys,
        filter_json=filter_json,
        limit=args.limit,
        label=args.label,
        reason=args.reason,
        expires_at=args.expires_at,
        dry_run=bool(args.dry_run),
        yes=bool(args.yes),
        concurrency=max(1, int(args.concurrency)),
        read_timeout_s=float(args.read_timeout_s),
        write_timeout_s=float(args.write_timeout_s),
        opa_url=args.opa_url,
        opa_token=args.opa_token,
        opa_package=args.opa_package,
        opa_rule=args.opa_rule,
        transport_path=args.transport,
        transport_config=_load_json_file(args.transport_config),
        df_retry=df_retry,
        df_breaker=df_breaker,
        hmac_secret=args.hmac_secret,
    )


async def _amain(cfg: CLIConfig) -> int:
    async with SetLegalHoldCLI(cfg) as app:
        try:
            return await app.run()
        except KeyboardInterrupt:
            print("Interrupted.", file=sys.stderr)
            return 130


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()
    LOG.setLevel(_verbosity_to_level(args.verbose))
    cfg = _build_cli_config(args)
    rc = asyncio.run(_amain(cfg))
    sys.exit(rc)


if __name__ == "__main__":
    main()
