# cli/tools/emit_lineage.py
# -*- coding: utf-8 -*-
"""
DataFabric-Core | CLI: emit_lineage

Назначение:
  Универсальный инструмент для эмиссии lineage в различных форматах и бэкендах:
   - OpenTelemetry (OTLP gRPC/HTTP) через datafabric.lineage.exporters.opentelemetry_exporter
   - stdout (читаемый JSON)
   - файл (append JSONL)

Возможности:
  - Режимы: graph, edge, ndjson (построчный поток с объектами graph/edge)
  - Парсинг датасетов из JSON, пары ключ=значение, короткой формы system:name@namespace
  - Атрибуты и props через --attr/--prop многократно
  - Детерминированные или случайные run_id (uuid7/ulid/hmac)
  - Таймстемпы start_ms/end_ms/ts_ms (ms, автозаполнение)
  - Dry-run и строгая валидация
  - Метрики (через datafabric.observability.metrics; graceful при отсутствии)
  - Надежное завершение и отчеты об ошибках

Примеры:
  1) Полный граф:
     python -m cli.tools.emit_lineage graph \
       --pipeline etl.orders --run-id uuid7 \
       --input system=db,name=orders_raw,namespace=lake \
       --output db:orders_curated@warehouse \
       --attr env=prod --attr owner=team-data

  2) Одно ребро:
     python -m cli.tools.emit_lineage edge \
       --pipeline etl.orders --run-id ulid \
       --source db:orders_raw@lake \
       --target db:orders_curated@warehouse \
       --transformation "cleanse+dedupe"

  3) NDJSON поток:
     cat lineage.ndjson | python -m cli.tools.emit_lineage ndjson --backend stdout

ENV (дополнительно к OTel):
  DF_LINEAGE_BACKEND=otel|stdout|file         (по умолчанию: otel)
  DF_LINEAGE_OUT_FILE=/path/to/output.ndjson  (для backend=file)
  DF_LINEAGE_DEFAULT_SYSTEM, DF_LINEAGE_DEFAULT_NAMESPACE

Зависимости:
  - Обязательных внешних нет. Для OTel-экспорта требуется OpenTelemetry SDK
    (используется через модуль экспортера).
© DataFabric-Core.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Наблюдаемость (не жёсткая)
try:
    from datafabric.observability.metrics import get_metrics
    _METRICS = get_metrics()
    M_SENT = _METRICS.counter("lineage_cli_emitted_total", "Emitted lineage items", labels=("mode","backend","status"))
    M_LAT = _METRICS.histogram("lineage_cli_latency_seconds", "Emit latency", labels=("mode","backend","status"))
except Exception:
    class _N:
        def inc(self, *a, **k): ...
        def observe(self, *a, **k): ...
    M_SENT = _N()
    M_LAT = _N()

# Экспортёр OTel (опционально)
try:
    from datafabric.lineage.exporters.opentelemetry_exporter import (
        LineageOpenTelemetryExporter,
        ExporterConfig,
        DatasetRef,
        LineageEdge,
        LineageGraph,
    )
    _HAS_OTEL_EXPORTER = True
except Exception:
    _HAS_OTEL_EXPORTER = False
    # Минимальные заглушки типов для статической проверки
    DatasetRef = Any  # type: ignore
    LineageEdge = Any  # type: ignore
    LineageGraph = Any  # type: ignore
    ExporterConfig = Any  # type: ignore
    LineageOpenTelemetryExporter = Any  # type: ignore

# Генераторы id (опционально)
try:
    from datafabric.utils.idgen import new_uuid7, new_ulid, hmac_id
    _HAS_IDGEN = True
except Exception:
    import uuid as _uuid
    _HAS_IDGEN = False
    def new_uuid7() -> str: return str(_uuid.uuid4())
    def new_ulid() -> str: return _uuid.uuid4().hex
    def hmac_id(data: str, secret: Optional[str] = None, out: str = "hex", size: int = 16) -> str:
        import hashlib
        s = (secret or "df-default").encode("utf-8")
        d = hashlib.sha256(s + data.encode("utf-8")).hexdigest()
        return d[: size * 2]

LOG = logging.getLogger("datafabric.cli.emit_lineage")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s emit_lineage:%(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)

# ---------------------------------------
# Вспомогательные структуры и парсинг
# ---------------------------------------

@dataclass
class CLIConfig:
    backend: str = os.getenv("DF_LINEAGE_BACKEND", "otel").lower()  # otel|stdout|file
    out_file: Optional[str] = os.getenv("DF_LINEAGE_OUT_FILE") or None
    default_system: Optional[str] = os.getenv("DF_LINEAGE_DEFAULT_SYSTEM") or None
    default_namespace: Optional[str] = os.getenv("DF_LINEAGE_DEFAULT_NAMESPACE") or None
    dry_run: bool = False
    verbose: int = 0

# Без внешних зависимостей — парсим вручную
def parse_kv_pairs(pairs: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for p in pairs or []:
        if "=" not in p:
            raise ValueError(f"Ожидалась пара ключ=значение: {p}")
        k, v = p.split("=", 1)
        out[k.strip()] = _auto_cast(v.strip())
    return out

def _auto_cast(v: str) -> Any:
    if v.lower() in ("true","false"):
        return v.lower() == "true"
    try:
        if "." in v: return float(v)
        return int(v)
    except Exception:
        return v

def parse_dataset(spec: str, cfg: CLIConfig) -> DatasetRef:
    """
    Поддерживаем форматы:
      1) JSON: {"system":"db","name":"orders","namespace":"lake", "schema":{...}, "facets":{...}}
      2) Короткий: system:name@namespace
      3) KV: system=db,name=orders,namespace=lake
    """
    spec = spec.strip()
    if spec.startswith("{"):
        data = json.loads(spec)
        return DatasetRef(
            system=data["system"],
            name=data["name"],
            namespace=data.get("namespace"),
            schema=data.get("schema"),
            facets=data.get("facets"),
        )
    if "=" in spec:
        kv = parse_kv_pairs([x.strip() for x in spec.split(",") if x.strip()])
        return DatasetRef(
            system=str(kv.get("system") or cfg.default_system or _require("system", kv)),
            name=str(kv.get("name") or _require("name", kv)),
            namespace=str(kv.get("namespace") or cfg.default_namespace) if (kv.get("namespace") or cfg.default_namespace) else None,
            schema=kv.get("schema"),
            facets=kv.get("facets"),
        )
    # короткая форма: system:name@namespace
    sys_name, ns = spec, None
    if "@" in spec:
        sys_name, ns = spec.split("@", 1)
    if ":" in sys_name:
        system, name = sys_name.split(":", 1)
    elif cfg.default_system:
        system, name = cfg.default_system, sys_name
    else:
        raise ValueError("Короткая форма требует system:name или задайте DF_LINEAGE_DEFAULT_SYSTEM")
    return DatasetRef(system=system, name=name, namespace=(ns or cfg.default_namespace))

def _require(key: str, d: Dict[str, Any]) -> Any:
    if key not in d:
        raise ValueError(f"Отсутствует обязательный ключ: {key}")
    return d[key]

def parse_repeated_kv(items: List[str]) -> Dict[str, Any]:
    """
    --attr k=v --attr a=b → {"k":"v","a":"b"}
    """
    out: Dict[str, Any] = {}
    for x in items or []:
        k, v = x.split("=", 1)
        out[k.strip()] = _auto_cast(v.strip())
    return out

def make_run_id(kind: str, seed: Optional[str] = None) -> str:
    kind = (kind or "uuid7").lower()
    if kind == "uuid7":
        return new_uuid7()
    if kind == "ulid":
        return new_ulid()
    if kind == "hmac":
        return hmac_id(seed or f"seed:{time.time_ns()}", out="hex", size=16)
    # raw: использовать как есть
    return kind

# ---------------------------------------
# Бэкенды эмиссии
# ---------------------------------------

class Backend:
    async def emit_graph(self, g: LineageGraph) -> str: raise NotImplementedError
    async def emit_edge(self, pipeline: str, run_id: str, e: LineageEdge, parent_trace: Optional[str]) -> str: raise NotImplementedError
    async def flush(self) -> None: ...

class StdoutBackend(Backend):
    def __init__(self, out_file: Optional[str] = None):
        self.out_file = out_file
        self._fh = None
        if self.out_file:
            self._fh = open(self.out_file, "a", encoding="utf-8")
    def _write(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        else:
            print(line)
    async def emit_graph(self, g: LineageGraph) -> str:
        self._write({"type":"graph", "data": _graph_to_json(g)})
        return "stdout"
    async def emit_edge(self, pipeline: str, run_id: str, e: LineageEdge, parent_trace: Optional[str]) -> str:
        self._write({"type":"edge", "data": _edge_to_json(e, pipeline, run_id, parent_trace)})
        return "stdout"
    async def flush(self) -> None:
        if self._fh:
            self._fh.flush()

class OTelBackend(Backend):
    def __init__(self):
        if not _HAS_OTEL_EXPORTER:
            raise RuntimeError("OTel exporter недоступен: отсутствует модуль или зависимости")
        self.exp = LineageOpenTelemetryExporter(ExporterConfig())
    async def emit_graph(self, g: LineageGraph) -> str:
        return await self.exp.export_graph(g)
    async def emit_edge(self, pipeline: str, run_id: str, e: LineageEdge, parent_trace: Optional[str]) -> str:
        return await self.exp.export_edge(pipeline=pipeline, run_id=run_id, edge=e, parent_trace=parent_trace)
    async def flush(self) -> None:
        await self.exp.shutdown()

def build_backend(cfg: CLIConfig) -> Backend:
    b = cfg.backend
    if b == "otel":
        return OTelBackend()
    if b == "stdout":
        return StdoutBackend()
    if b == "file":
        path = cfg.out_file or os.getenv("DF_LINEAGE_OUT_FILE") or "lineage.out.ndjson"
        return StdoutBackend(out_file=path)
    raise SystemExit(f"Неизвестный backend: {b}")

# ---------------------------------------
# Преобразование в модели экспортера
# ---------------------------------------

def _graph_to_json(g: LineageGraph) -> Dict[str, Any]:
    def dsj(d: DatasetRef) -> Dict[str, Any]:
        return {
            "system": d.system, "name": d.name,
            **({"namespace": d.namespace} if getattr(d, "namespace", None) else {}),
            **({"schema": d.schema} if getattr(d, "schema", None) else {}),
            **({"facets": d.facets} if getattr(d, "facets", None) else {}),
        }
    return {
        "pipeline": g.pipeline, "run_id": g.run_id,
        "inputs": [dsj(x) for x in g.inputs],
        "outputs": [dsj(x) for x in g.outputs],
        "edges": [ _edge_body_json(e) for e in g.edges ],
        "attrs": g.attrs, "start_ms": g.start_ms, "end_ms": g.end_ms,
        "parent_context": g.parent_context,
    }

def _edge_body_json(e: LineageEdge) -> Dict[str, Any]:
    def dsj(d: DatasetRef) -> Dict[str, Any]:
        return {"system": d.system, "name": d.name, **({"namespace": d.namespace} if getattr(d, "namespace", None) else {})}
    return {
        "source": dsj(e.source), "target": dsj(e.target),
        **({"transformation": e.transformation} if e.transformation else {}),
        **({"run_id": e.run_id} if e.run_id else {}),
        **({"ts_ms": e.ts_ms} if e.ts_ms else {}),
        **({"props": e.props} if e.props else {}),
        **({"idempotency_key": e.idempotency_key} if e.idempotency_key else {}),
    }

def _edge_to_json(e: LineageEdge, pipeline: str, run_id: str, parent_trace: Optional[str]) -> Dict[str, Any]:
    body = _edge_body_json(e)
    body.update({"pipeline": pipeline, "run_id": run_id, **({"parent_trace": parent_trace} if parent_trace else {})})
    return body

# ---------------------------------------
# Основная логика CLI
# ---------------------------------------

async def do_graph(args: argparse.Namespace, cfg: CLIConfig) -> int:
    t0 = time.perf_counter()
    backend = build_backend(cfg)
    try:
        run_id = args.run_id if args.run_id and args.run_id not in ("uuid7","ulid","hmac") else make_run_id(args.run_id, seed=args.run_id_seed)
        inputs = [parse_dataset(x, cfg) for x in (args.input or [])]
        outputs = [parse_dataset(x, cfg) for x in (args.output or [])]
        if args.edge_source or args.edge_target:
            # дополнительно формируем ребро из --edge-source/--edge-target
            e = LineageEdge(
                source=parse_dataset(args.edge_source, cfg),
                target=parse_dataset(args.edge_target, cfg),
                transformation=args.transformation,
                run_id=run_id,
                ts_ms=args.ts_ms,
                props=parse_repeated_kv(args.prop),
                idempotency_key=args.idempotency_key,
            )
            edges = [e]
        else:
            edges = []
        g = LineageGraph(
            pipeline=args.pipeline,
            run_id=run_id,
            inputs=inputs,
            outputs=outputs,
            edges=edges,
            attrs=parse_repeated_kv(args.attr),
            start_ms=args.start_ms,
            end_ms=args.end_ms,
            parent_context=args.parent_trace,
        )
        if cfg.dry_run:
            StdoutBackend()._write({"type":"graph","data": _graph_to_json(g)})  # type: ignore
            status = "dry_run"
            trace_id = "dry-run"
        else:
            trace_id = await backend.emit_graph(g)
            status = "ok"
        M_SENT.inc(1, mode="graph", backend=cfg.backend, status=status)
        M_LAT.observe((time.perf_counter()-t0), mode="graph", backend=cfg.backend, status=status)
        if not cfg.dry_run and cfg.backend == "otel":
            LOG.info("Lineage graph emitted, trace_id=%s", trace_id)
        return 0
    except Exception as e:
        LOG.error("Graph emit error: %s", e)
        M_SENT.inc(1, mode="graph", backend=cfg.backend, status="error")
        return 2
    finally:
        try:
            await backend.flush()
        except Exception:
            ...

async def do_edge(args: argparse.Namespace, cfg: CLIConfig) -> int:
    t0 = time.perf_counter()
    backend = build_backend(cfg)
    try:
        run_id = args.run_id if args.run_id and args.run_id not in ("uuid7","ulid","hmac") else make_run_id(args.run_id, seed=args.run_id_seed)
        e = LineageEdge(
            source=parse_dataset(args.source, cfg),
            target=parse_dataset(args.target, cfg),
            transformation=args.transformation,
            run_id=run_id,
            ts_ms=args.ts_ms,
            props=parse_repeated_kv(args.prop),
            idempotency_key=args.idempotency_key,
        )
        if cfg.dry_run:
            StdoutBackend()._write({"type":"edge","data": _edge_to_json(e, args.pipeline, run_id, args.parent_trace)})  # type: ignore
            status = "dry_run"
            trace_id = "dry-run"
        else:
            trace_id = await backend.emit_edge(args.pipeline, run_id, e, args.parent_trace)
            status = "ok"
        M_SENT.inc(1, mode="edge", backend=cfg.backend, status=status)
        M_LAT.observe((time.perf_counter()-t0), mode="edge", backend=cfg.backend, status=status)
        if not cfg.dry_run and cfg.backend == "otel":
            LOG.info("Lineage edge emitted, trace_id=%s", trace_id)
        return 0
    except Exception as e:
        LOG.error("Edge emit error: %s", e)
        M_SENT.inc(1, mode="edge", backend=cfg.backend, status="error")
        return 2
    finally:
        try:
            await backend.flush()
        except Exception:
            ...

async def do_ndjson(args: argparse.Namespace, cfg: CLIConfig) -> int:
    """
    Ожидается NDJSON на stdin. Каждая строка — объект:
      {"type":"graph", ...как в _graph_to_json...}
      {"type":"edge",  ...как в _edge_to_json...}
    Минимальная валидация; при ошибке строка пропускается.
    """
    t0 = time.perf_counter()
    backend = build_backend(cfg)
    ok = 0
    err = 0
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                typ = obj.get("type")
                if typ == "graph":
                    g = _json_to_graph(obj["data"])
                    if cfg.dry_run or cfg.backend in ("stdout","file"):
                        StdoutBackend(cfg.out_file)._write({"type":"graph","data": obj["data"]})  # type: ignore
                    else:
                        await backend.emit_graph(g)
                    ok += 1
                elif typ == "edge":
                    data = obj["data"]
                    e, pipeline, run_id, parent = _json_to_edge_and_meta(data)
                    if cfg.dry_run or cfg.backend in ("stdout","file"):
                        StdoutBackend(cfg.out_file)._write({"type":"edge","data": data})  # type: ignore
                    else:
                        await backend.emit_edge(pipeline, run_id, e, parent)
                    ok += 1
                else:
                    raise ValueError("unknown type")
            except Exception as ie:
                err += 1
                LOG.error("NDJSON line error: %s; line=%s", ie, line[:512])
        status = "ok" if err == 0 else "partial"
        M_SENT.inc(ok, mode="ndjson", backend=cfg.backend, status=status)
        M_LAT.observe((time.perf_counter()-t0), mode="ndjson", backend=cfg.backend, status=status)
        if err:
            LOG.warning("NDJSON done: ok=%d, err=%d", ok, err)
        return 0 if err == 0 else 3
    finally:
        try:
            await backend.flush()
        except Exception:
            ...

def _json_to_graph(d: Dict[str, Any]) -> LineageGraph:
    def ds(o: Dict[str, Any]) -> DatasetRef:
        return DatasetRef(system=o["system"], name=o["name"], namespace=o.get("namespace"), schema=o.get("schema"), facets=o.get("facets"))
    edges = []
    for e in d.get("edges", []):
        edges.append(LineageEdge(
            source=ds(e["source"]),
            target=ds(e["target"]),
            transformation=e.get("transformation"),
            run_id=e.get("run_id"),
            ts_ms=e.get("ts_ms"),
            props=e.get("props", {}),
            idempotency_key=e.get("idempotency_key"),
        ))
    return LineageGraph(
        pipeline=d["pipeline"], run_id=d["run_id"],
        inputs=[ds(x) for x in d.get("inputs", [])],
        outputs=[ds(x) for x in d.get("outputs", [])],
        edges=edges, attrs=d.get("attrs", {}),
        start_ms=d.get("start_ms"), end_ms=d.get("end_ms"),
        parent_context=d.get("parent_context"),
    )

def _json_to_edge_and_meta(d: Dict[str, Any]) -> Tuple[LineageEdge, str, str, Optional[str]]:
    def ds(o: Dict[str, Any]) -> DatasetRef:
        return DatasetRef(system=o["system"], name=o["name"], namespace=o.get("namespace"))
    e = LineageEdge(
        source=ds(d["source"]), target=ds(d["target"]),
        transformation=d.get("transformation"), run_id=d.get("run_id"),
        ts_ms=d.get("ts_ms"), props=d.get("props", {}), idempotency_key=d.get("idempotency_key")
    )
    pipeline = d["pipeline"]
    run_id = d.get("run_id") or d["run_id"] if "run_id" in d else make_run_id("uuid7")
    parent = d.get("parent_trace")
    return e, pipeline, run_id, parent

# ---------------------------------------
# Аргументы командной строки
# ---------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DataFabric emit_lineage CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Общие
    for sp_name in ("graph","edge","ndjson"):
        sp = sub.add_parser(sp_name)
        sp.add_argument("--backend", choices=["otel","stdout","file"], default=os.getenv("DF_LINEAGE_BACKEND","otel"))
        sp.add_argument("--out-file", help="Путь для backend=file (ndjson append)")
        sp.add_argument("--dry-run", action="store_true")
        sp.add_argument("--verbose","-v", action="count", default=0)

    g = sub.choices["graph"]
    g.add_argument("--pipeline", required=True)
    g.add_argument("--run-id", default="uuid7", help="uuid7|ulid|hmac|<raw-string>")
    g.add_argument("--run-id-seed", help="seed для hmac режима")
    g.add_argument("--input", action="append", help="DatasetRef: JSON | system:name@ns | system=,name=,namespace=", default=[])
    g.add_argument("--output", action="append", help="DatasetRef: см. --input", default=[])
    g.add_argument("--edge-source", help="Доп. ребро: источник")
    g.add_argument("--edge-target", help="Доп. ребро: цель")
    g.add_argument("--transformation", help="Описание трансформации")
    g.add_argument("--prop", action="append", default=[], help="Кастомное свойство ребра k=v (повторяемо)")
    g.add_argument("--idempotency-key", help="Ключ де-дупликации ребра")
    g.add_argument("--attr", action="append", default=[], help="Атрибут графа k=v (повторяемо)")
    g.add_argument("--start-ms", type=int)
    g.add_argument("--end-ms", type=int)
    g.add_argument("--ts-ms", type=int, help="Время ребра при edge-source/edge-target")
    g.add_argument("--parent-trace", help="W3C traceparent")

    e = sub.choices["edge"]
    e.add_argument("--pipeline", required=True)
    e.add_argument("--run-id", default="uuid7")
    e.add_argument("--run-id-seed")
    e.add_argument("--source", required=True, help="DatasetRef")
    e.add_argument("--target", required=True, help="DatasetRef")
    e.add_argument("--transformation")
    e.add_argument("--prop", action="append", default=[])
    e.add_argument("--idempotency-key")
    e.add_argument("--ts-ms", type=int)
    e.add_argument("--parent-trace")

    n = sub.choices["ndjson"]
    n.add_argument("--backend", choices=["otel","stdout","file"], default=os.getenv("DF_LINEAGE_BACKEND","otel"))
    n.add_argument("--out-file")
    n.add_argument("--dry-run", action="store_true")
    n.add_argument("--verbose","-v", action="count", default=0)

    return p

def _cfg_from_args(args: argparse.Namespace) -> CLIConfig:
    cfg = CLIConfig()
    cfg.backend = (getattr(args, "backend", None) or cfg.backend).lower()
    cfg.out_file = getattr(args, "out_file", None) or cfg.out_file
    cfg.dry_run = bool(getattr(args, "dry_run", False))
    cfg.verbose = int(getattr(args, "verbose", 0))
    if cfg.verbose >= 2: LOG.setLevel(logging.DEBUG)
    elif cfg.verbose == 1: LOG.setLevel(logging.INFO)
    return cfg

# ---------------------------------------
# Entrypoint
# ---------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = _cfg_from_args(args)
    if cfg.backend == "otel" and not _HAS_OTEL_EXPORTER:
        LOG.error("Выбран backend=otel, но OTel-экспортёр недоступен. Установите зависимости или используйте --backend stdout|file.")
        return 2
    try:
        if args.cmd == "graph":
            return asyncio.run(do_graph(args, cfg))
        if args.cmd == "edge":
            return asyncio.run(do_edge(args, cfg))
        if args.cmd == "ndjson":
            return asyncio.run(do_ndjson(args, cfg))
        parser.print_help()
        return 1
    except KeyboardInterrupt:
        return 130

if __name__ == "__main__":
    sys.exit(main())
