# mythos-core/cli/main.py
"""
Mythos Core — промышленный CLI.

Команды:
  version
  config show --file PATH
  metrics exporter [--port 9100] [--addr 0.0.0.0]
  graph index --entities FILE [--relations FILE] [--backend neo4j|dryrun] [backend opts...]
  timeline build --rules FILE --candidates FILE [--user-id ...] [--locale ...] [--channel ...] [--timezone ...]
                  [--max-size N] [--diagnostics-out FILE]

Входные форматы:
  - JSON массив   (*.json)
  - NDJSON/JSONL  (*.ndjson|*.jsonl|stdin) — по одному JSON-объекту в строке
  - Gzip поддерживается (расширение .gz)

Коды выхода:
  0 — успех
  1 — ошибка пользователя (аргументы/валидация/файлы)
  2 — ошибка среды или зависимостей (импорт, сеть, драйверы)
  3 — внутренняя ошибка во время выполнения

ENV (частично):
  APP_VERSION, GRAPH_BACKEND, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DB
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import io
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, Iterator, List, Optional, Tuple, Union

# ------------------------ Логирование ------------------------

def setup_logging(verbosity: int = 0, json_mode: bool = False) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    handler = logging.StreamHandler()
    if json_mode:
        class _JSONFmt(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                payload = {
                    "ts": int(time.time() * 1000),
                    "lvl": record.levelname,
                    "msg": record.getMessage(),
                    "logger": record.name,
                }
                if record.exc_info:
                    payload["exc"] = self.formatException(record.exc_info)
                return json.dumps(payload, ensure_ascii=False)
        fmt = _JSONFmt()
    else:
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

LOG = logging.getLogger("mythos.cli")

# ------------------------ Утилиты файлов/ввода ------------------------

def _open_maybe_gzip(path: Union[str, Path, None]) -> io.TextIOBase:
    if path is None or str(path) == "-":
        data = sys.stdin.buffer.read()
        # пробуем как gzip, иначе обычный текст
        try:
            return io.TextIOWrapper(io.BytesIO(gzip.decompress(data)), encoding="utf-8")
        except Exception:
            return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"file not found: {p}")
    if str(p).endswith(".gz"):
        return io.TextIOWrapper(gzip.open(p, "rb"), encoding="utf-8")
    return open(p, "r", encoding="utf-8")

def _detect_stream_kind(path: Union[str, Path, None]) -> str:
    if path is None or str(path) == "-":
        return "ndjson"
    s = str(path).lower()
    if s.endswith(".ndjson") or s.endswith(".jsonl"):
        return "ndjson"
    return "json"

def _iter_json(fp: io.TextIOBase) -> Iterator[Dict[str, Any]]:
    """Читает один JSON массив целиком."""
    data = json.load(fp)
    if isinstance(data, list):
        for obj in data:
            if isinstance(obj, dict):
                yield obj
            else:
                raise ValueError("array element is not an object")
    elif isinstance(data, dict):
        yield data
    else:
        raise ValueError("unsupported json root")

def _iter_ndjson(fp: io.TextIOBase) -> Iterator[Dict[str, Any]]:
    for i, line in enumerate(fp, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception as e:
            raise ValueError(f"invalid JSON at line {i}: {e}") from e
        if not isinstance(obj, dict):
            raise ValueError(f"line {i}: not an object")
        yield obj

def _iter_input(path: Union[str, Path, None]) -> Iterator[Dict[str, Any]]:
    with _open_maybe_gzip(path) as fp:
        kind = _detect_stream_kind(path)
        if kind == "ndjson":
            yield from _iter_ndjson(fp)
        else:
            yield from _iter_json(fp)

async def _aiter_from_iter(it: Iterable[Dict[str, Any]]) -> AsyncIterator[Dict[str, Any]]:
    for obj in it:
        yield obj
        await asyncio.sleep(0)

# ------------------------ Команда: version ------------------------

def cmd_version(args: argparse.Namespace) -> int:
    ver = os.getenv("APP_VERSION") or "0.0.0"
    print(ver)
    return 0

# ------------------------ Команда: config show ------------------------

def cmd_config_show(args: argparse.Namespace) -> int:
    path = args.file
    try:
        with _open_maybe_gzip(path) as fp:
            text = fp.read()
        # Если это YAML, печатаем как есть; если JSON — pretty-print
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            data = json.loads(text)
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            # YAML не парсим намеренно (без внешних зависимостей)
            print(text)
        return 0
    except Exception as e:
        LOG.error("config show failed: %s", e)
        return 1

# ------------------------ Команда: metrics exporter ------------------------

def cmd_metrics_exporter(args: argparse.Namespace) -> int:
    try:
        # Ленивая загрузка
        from mythos.observability.metrics import get_metrics
    except Exception as e:
        LOG.error("metrics exporter requires mythos.observability.metrics: %s", e)
        return 2

    try:
        m = get_metrics()
        m.start_standalone_http(port=args.port, addr=args.addr)
        LOG.info("Prometheus exporter started on %s:%d", args.addr, args.port)
        # Блокируемся
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        LOG.info("stopping metrics exporter")
        return 0
    except Exception as e:
        LOG.error("metrics exporter failed: %s", e, exc_info=True)
        return 3

# ------------------------ Команда: graph index ------------------------

@dataclass
class GraphOpts:
    backend: str
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_db: Optional[str]

async def _graph_index_impl(args: argparse.Namespace) -> int:
    try:
        from mythos.graph.indexer import (
            AsyncGraphIndexer,
            IndexerConfig,
            DryRunBackend,
            Neo4jBackend,
        )
    except Exception as e:
        LOG.error("graph index requires mythos.graph.indexer: %s", e)
        return 2

    backend_name = (args.backend or os.getenv("GRAPH_BACKEND", "dryrun")).lower()
    if backend_name not in ("dryrun", "neo4j"):
        LOG.error("unsupported backend: %s", backend_name)
        return 1

    # Настройка backend
    if backend_name == "neo4j":
        uri = args.neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = args.neo4j_user or os.getenv("NEO4J_USER", "neo4j")
        password = args.neo4j_password or os.getenv("NEO4J_PASSWORD", "neo4j")
        database = args.neo4j_db or os.getenv("NEO4J_DB") or None
        backend = Neo4jBackend(uri=uri, user=user, password=password, database=database)
    else:
        backend = DryRunBackend()

    cfg = IndexerConfig(
        batch_size_nodes=args.batch_size_nodes,
        batch_size_edges=args.batch_size_edges,
        concurrency=args.concurrency,
        validate=not args.no_validate,
        create_schema_on_start=not args.no_schema,
        stop_on_validation_error=not args.no_stop_on_validation_error is False,
    )

    indexer = AsyncGraphIndexer(backend, config=cfg, schema_path=Path(args.schema) if args.schema else None)

    # Streams
    entities_iter = _iter_input(args.entities) if args.entities else []
    rel_iter = _iter_input(args.relations) if args.relations else []

    try:
        await indexer.start()
        upn = skn = upe = ske = 0
        if args.entities:
            upn, skn = await indexer.index_entities(_aiter_from_iter(entities_iter))
        if args.relations:
            upe, ske = await indexer.index_relations(_aiter_from_iter(rel_iter))
        await indexer.close()
        result = {"nodes_upserted": upn, "nodes_skipped": skn, "edges_upserted": upe, "edges_skipped": ske}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as e:
        LOG.error("graph index failed: %s", e, exc_info=True)
        try:
            await indexer.close()
        except Exception:
            pass
        return 3

def cmd_graph_index(args: argparse.Namespace) -> int:
    return asyncio.run(_graph_index_impl(args))

# ------------------------ Команда: timeline build ------------------------

async def _timeline_build_impl(args: argparse.Namespace) -> int:
    try:
        from mythos.timeline.chronology import ChronologyEngine, Candidate, FeedRequest
    except Exception as e:
        LOG.error("timeline build requires mythos.timeline.chronology: %s", e)
        return 2

    # Загружаем rules (требуется PyYAML только при использовании .from_yaml, поэтому парсим вручную)
    rules_text = None
    with _open_maybe_gzip(args.rules) as fp:
        rules_text = fp.read()

    # Если есть PyYAML — используем from_yaml; иначе пробуем JSON
    try:
        import yaml  # type: ignore
        engine = ChronologyEngine.from_yaml(rules_text)
    except Exception:
        # возможно, rules в JSON
        try:
            engine = ChronologyEngine(json.loads(rules_text))
        except Exception as e:
            LOG.error("failed to parse rules (YAML or JSON required): %s", e)
            return 1

    # Кандидаты
    cands_raw = list(_iter_input(args.candidates))
    candidates: List[Candidate] = []
    for obj in cands_raw:
        candidates.append(Candidate(
            id=str(obj.get("id") or obj.get("content_id") or obj.get("uuid") or f"c{len(candidates)+1}"),
            content=obj.get("content") or obj,
            event=obj.get("event") or {},
            publisher=obj.get("publisher") or {}
        ))

    req = FeedRequest(
        user={"id": args.user_id or "anon"},
        locale=args.locale or "en",
        channel=args.channel or "web",
        timezone=args.timezone or "UTC",
        max_feed_size=int(args.max_size or 50),
        request_id=args.request_id or None,
    )

    try:
        res = engine.build_feed(req, candidates)
        payload = {
            "items": [c.content for c in res.items],
            "count": len(res.items),
        }
        print(json.dumps(payload, ensure_ascii=False))
        if args.diagnostics_out:
            Path(args.diagnostics_out).write_text(json.dumps(res.diagnostics, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0
    except Exception as e:
        LOG.error("timeline build failed: %s", e, exc_info=True)
        return 3

def cmd_timeline_build(args: argparse.Namespace) -> int:
    return asyncio.run(_timeline_build_impl(args))

# ------------------------ Парсер аргументов ------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mythos", description="Mythos Core CLI")
    p.add_argument("-v", action="count", default=0, help="verbosity (-v|-vv)")
    p.add_argument("--log-json", action="store_true", default=False, help="log in JSON")

    sub = p.add_subparsers(dest="cmd", required=True)

    # version
    sp_v = sub.add_parser("version", help="print version")
    sp_v.set_defaults(func=cmd_version)

    # config show
    sp_conf = sub.add_parser("config", help="configuration commands")
    sub_conf = sp_conf.add_subparsers(dest="subcmd", required=True)
    sp_conf_show = sub_conf.add_parser("show", help="show config file (YAML/JSON, supports .gz)")
    sp_conf_show.add_argument("--file", "-f", required=True, help="path to config file or '-' for stdin")
    sp_conf_show.set_defaults(func=cmd_config_show)

    # metrics exporter
    sp_m = sub.add_parser("metrics", help="metrics commands")
    sub_m = sp_m.add_subparsers(dest="subcmd", required=True)
    sp_m_exp = sub_m.add_parser("exporter", help="start standalone Prometheus exporter")
    sp_m_exp.add_argument("--port", type=int, default=9100)
    sp_m_exp.add_argument("--addr", type=str, default="0.0.0.0")
    sp_m_exp.set_defaults(func=cmd_metrics_exporter)

    # graph index
    sp_g = sub.add_parser("graph", help="graph indexing commands")
    sub_g = sp_g.add_subparsers(dest="subcmd", required=True)
    sp_g_idx = sub_g.add_parser("index", help="index entities and relations into graph backend")
    sp_g_idx.add_argument("--entities", "-e", required=False, help="file with entities (JSON/NDJSON/JSONL; .gz ok). Use '-' for stdin.")
    sp_g_idx.add_argument("--relations", "-r", required=False, help="file with relations (JSON/NDJSON/JSONL; .gz ok)")
    sp_g_idx.add_argument("--backend", choices=["neo4j", "dryrun"], default=os.getenv("GRAPH_BACKEND", "dryrun"))
    sp_g_idx.add_argument("--neo4j-uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    sp_g_idx.add_argument("--neo4j-user", default=os.getenv("NEO4J_USER", "neo4j"))
    sp_g_idx.add_argument("--neo4j-password", default=os.getenv("NEO4J_PASSWORD", "neo4j"))
    sp_g_idx.add_argument("--neo4j-db", default=os.getenv("NEO4J_DB"))
    sp_g_idx.add_argument("--batch-size-nodes", type=int, default=500)
    sp_g_idx.add_argument("--batch-size-edges", type=int, default=1000)
    sp_g_idx.add_argument("--concurrency", type=int, default=4)
    sp_g_idx.add_argument("--no-validate", action="store_true", help="disable JSON Schema validation")
    sp_g_idx.add_argument("--no-schema", action="store_true", help="do not create/ensure schema on start")
    sp_g_idx.add_argument("--no-stop-on-validation-error", action="store_true", help="do not stop on validation errors")
    sp_g_idx.add_argument("--schema", help="path to entity JSON Schema (optional)")
    sp_g_idx.set_defaults(func=cmd_graph_index)

    # timeline build
    sp_t = sub.add_parser("timeline", help="timeline commands")
    sub_t = sp_t.add_subparsers(dest="subcmd", required=True)
    sp_t_build = sub_t.add_parser("build", help="build feed from rules and candidates")
    sp_t_build.add_argument("--rules", "-R", required=True, help="rules file (YAML or JSON; .gz ok)")
    sp_t_build.add_argument("--candidates", "-C", required=True, help="candidates file (JSON/NDJSON/JSONL; .gz ok)")
    sp_t_build.add_argument("--user-id", default="anon")
    sp_t_build.add_argument("--locale", default="en")
    sp_t_build.add_argument("--channel", default="web")
    sp_t_build.add_argument("--timezone", default="UTC")
    sp_t_build.add_argument("--max-size", type=int, default=50)
    sp_t_build.add_argument("--request-id", default=None)
    sp_t_build.add_argument("--diagnostics-out", default=None, help="path to write diagnostics JSON")
    sp_t_build.set_defaults(func=cmd_timeline_build)

    return p

# ------------------------ Entry Point ------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.v, json_mode=args.log_json)
    # Диспетчер
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return int(args.func(args))

if __name__ == "__main__":
    sys.exit(main())
