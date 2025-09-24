#!/usr/bin/env python3
# mythos-core/cli/tools/generate_questline.py
# -*- coding: utf-8 -*-
"""
Генератор квестлайнов Mythos Core.

Функции:
- Генерация версионированного графа (совместим с relations.Graph.to_json): nodes[], edges[], schema_version=1.
- Описание узлов (nodes.{yaml|json}) с типом, текстом, вариантами выбора и исходами.
- Манифест пакета (manifest.{yaml|json}) с метаданными генерации.
- Опциональный экспорт Graphviz DOT.
- Детерминированность по --seed, строгая валидация (CHOICE prob суммируется в 1), отсутствие циклов по NEXT/TRANSITION.
- Структурные логи (structlog -> logging fallback), четкие коды выхода.

Пример:
  python -m mythos_core.cli.tools.generate_questline \
    --title "Пролог: Зов приключений" --locale ru-RU \
    --depth 4 --branching 3 --seed 42 \
    --out ./build/questline_demo --dot

Шаблон YAML (опционально, передается через --template):
  title: "Имя квеста"
  locale: "ru-RU"
  tags: ["intro","demo"]
  root_text: "Вы просыпаетесь в незнакомом месте..."
  styles:
    dialogue_prefix: "Герой: "
    narration_prefix: "Система: "
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import random
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable

# ---------- Логи: structlog -> logging fallback ----------
try:
    import structlog

    def _configure_logging():
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ]
        )
        return structlog.get_logger("mythos.cli.generate_questline")

    log = _configure_logging()
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("mythos.cli.generate_questline")

# ---------- Опциональный YAML ----------
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

GRAPH_SCHEMA_VERSION = 1

# Совместимость по типам отношений с mythos.core.graph.relations.RelationKind
class RelationKind:
    NEXT = "NEXT"
    CHOICE = "CHOICE"
    DEPENDS_ON = "DEPENDS_ON"
    CONFLICTS_WITH = "CONFLICTS_WITH"
    EMITS_OUTCOME = "EMITS_OUTCOME"
    REFERENCES = "REFERENCES"
    TAGGED = "TAGGED"
    TRANSITION = "TRANSITION"


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    label: Optional[str] = None
    prob: Optional[float] = None
    weight: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: time.time())

    def identity(self) -> Tuple[str, str, str, Optional[str]]:
        return (self.src, self.dst, self.kind, self.label)


@dataclass
class NodeSpec:
    node_id: str
    node_type: str  # dialogue | choice | ending | system | action
    text: Optional[str] = None
    # только для choice
    choices: List[Dict[str, Any]] = field(default_factory=list)
    # только для ending/outcome
    outcome: Optional[Dict[str, Any]] = None
    # доп. атрибуты
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GenParams:
    title: str
    locale: str
    depth: int
    branching: int
    seed: int
    allow_loops: bool
    ensure_endings: int
    max_choices: int
    next_density: float
    choice_density: float
    out_dir: Path
    emit_dot: bool
    template: Dict[str, Any] = field(default_factory=dict)
    narrative_key: str = "questline"
    narrative_version: int = 1
    tags: List[str] = field(default_factory=list)


@dataclass
class Package:
    nodes: Dict[str, NodeSpec]
    edges: List[Edge]
    params: GenParams
    root_node_id: str


# ---------- Утилиты вывода ----------

def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_yaml_or_json(path_base: Path, obj: Any, prefer_yaml: bool = True) -> Path:
    if yaml is not None and prefer_yaml:
        path = path_base.with_suffix(".yaml")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(obj, allow_unicode=True, sort_keys=False), encoding="utf-8")
        return path
    else:
        path = path_base.with_suffix(".json")
        _write_json(path, obj)
        return path


# ---------- Генерация текста ----------

def _prefix(template: Dict[str, Any], key: str, default: str) -> str:
    return str(template.get("styles", {}).get(key, default))


def _dialogue_line(template: Dict[str, Any], content: str, locale: str) -> str:
    p = _prefix(template, "dialogue_prefix", "Герой: " if locale.startswith("ru") else "Hero: ")
    return f"{p}{content}"


def _narration_line(template: Dict[str, Any], content: str, locale: str) -> str:
    p = _prefix(template, "narration_prefix", "Система: " if locale.startswith("ru") else "System: ")
    return f"{p}{content}"


# ---------- Генератор квестлайна ----------

def generate_questline(params: GenParams) -> Package:
    rnd = random.Random(params.seed)
    nodes: Dict[str, NodeSpec] = {}
    edges: List[Edge] = []

    # Корневой узел
    root_id = "N0000"
    root_text = params.template.get("root_text") or _narration_line(
        params.template, "Вы просыпаетесь в незнакомом месте.", params.locale
    )
    nodes[root_id] = NodeSpec(node_id=root_id, node_type="dialogue", text=root_text)

    # Строим послойно
    cur_level: List[str] = [root_id]
    node_counter = 1
    endings_created = 0

    for depth in range(1, max(1, params.depth) + 1):
        next_level: List[str] = []
        for nid in cur_level:
            # Решаем: CHOICE или NEXT
            make_choice = rnd.random() < max(0.0, min(1.0, params.choice_density))
            if make_choice:
                # Создаем CHOICE-узел
                choice_id = f"N{node_counter:04d}"
                node_counter += 1
                nodes[choice_id] = NodeSpec(node_id=choice_id, node_type="choice", text=_narration_line(
                    params.template, "Перед вами выбор.", params.locale
                ))
                # Соединяем текущий узел с CHOICE через NEXT (или TRANSITION)
                edges.append(Edge(src=nid, dst=choice_id, kind=RelationKind.NEXT, label=None))

                # Сколько веток
                branches = rnd.randint(2, max(2, min(params.branching, params.max_choices)))
                probs = _random_probs(rnd, branches)
                # Ветки CHOICE
                for b in range(branches):
                    target_id = f"N{node_counter:04d}"
                    node_counter += 1
                    text = _dialogue_line(params.template, f"Вариант {b+1} выбран.", params.locale)
                    nodes[target_id] = NodeSpec(node_id=target_id, node_type="dialogue", text=text)
                    label = f"choice_{b+1}"
                    edges.append(
                        Edge(
                            src=choice_id,
                            dst=target_id,
                            kind=RelationKind.CHOICE,
                            label=label,
                            prob=probs[b],
                            metadata={"choice_label": f"Вариант {b+1}", "generated": True},
                        )
                    )
                    # Также отразим варианты в NodeSpec выбора
                    nodes[choice_id].choices.append({"choice_id": label, "label": f"Вариант {b+1}", "prob": probs[b]})
                    next_level.append(target_id)
            else:
                # Обычный NEXT на 1..branching узлов
                fanout = max(1, int(round(params.branching * params.next_density)))
                fanout = max(1, min(fanout, params.branching))
                for _ in range(fanout):
                    target_id = f"N{node_counter:04d}"
                    node_counter += 1
                    text = _dialogue_line(params.template, "Вы продвигаетесь дальше.", params.locale)
                    nodes[target_id] = NodeSpec(node_id=target_id, node_type="dialogue", text=text)
                    edges.append(Edge(src=nid, dst=target_id, kind=RelationKind.NEXT, label=None))
                    next_level.append(target_id)
        cur_level = next_level

    # Завершаем концовками
    if params.ensure_endings > 0 and cur_level:
        ends_to_make = min(params.ensure_endings, len(cur_level))
        for nid in rnd.sample(cur_level, ends_to_make):
            end_id = f"N{node_counter:04d}"
            node_counter += 1
            nodes[end_id] = NodeSpec(
                node_id=end_id,
                node_type="ending",
                text=_narration_line(params.template, "История подходит к развязке.", params.locale),
                outcome={"type": "END", "text": "Конец главы." if params.locale.startswith("ru") else "The end of the chapter."},
            )
            edges.append(Edge(src=nid, dst=end_id, kind=RelationKind.NEXT, label=None))
            endings_created += 1

    # Валидация
    _validate_graph(nodes, edges, allow_loops=params.allow_loops)

    return Package(nodes=nodes, edges=edges, params=params, root_node_id=root_id)


def _random_probs(rnd: random.Random, n: int) -> List[float]:
    assert n >= 2
    raw = [rnd.random() + 1e-9 for _ in range(n)]
    s = sum(raw)
    probs = [round(x / s, 6) for x in raw]
    # Корректируем последнюю, чтобы сумма была ровно 1.0 с учетом округления
    diff = round(1.0 - sum(probs), 6)
    probs[-1] = round(probs[-1] + diff, 6)
    return probs


# ---------- Валидация ----------

class GenError(RuntimeError):
    pass


def _validate_graph(nodes: Dict[str, NodeSpec], edges: List[Edge], *, allow_loops: bool) -> None:
    ids = set(nodes.keys())
    # Узлы должны существовать
    for e in edges:
        if e.src not in ids or e.dst not in ids:
            raise GenError(f"edge references unknown node: {e.src}->{e.dst}")

    # Самосвязи запрещены (кроме REFERENCES/TAGGED, которых мы не используем)
    if not allow_loops:
        for e in edges:
            if e.src == e.dst:
                raise GenError(f"self-loop detected at {e.src}")

    # CHOICE: prob в (0,1] и сумма по исходящим
    out_by_src: Dict[str, List[Edge]] = {}
    for e in edges:
        out_by_src.setdefault(e.src, []).append(e)

    for src, outs in out_by_src.items():
        choice_edges = [e for e in outs if e.kind == RelationKind.CHOICE]
        if choice_edges:
            s = 0.0
            for e in choice_edges:
                if e.prob is None or not (0.0 < e.prob <= 1.0):
                    raise GenError(f"invalid CHOICE prob at {e.src}->{e.dst}: {e.prob}")
                s += float(e.prob)
            if abs(s - 1.0) > 1e-6:
                raise GenError(f"sum of CHOICE probs from {src} != 1: {s}")

    # Циклы по NEXT/TRANSITION запрещены (для типичной линии квеста)
    if not allow_loops:
        if _has_cycle(ids, edges, kinds={RelationKind.NEXT, RelationKind.TRANSITION}):
            raise GenError("cycle detected across NEXT/TRANSITION")


def _has_cycle(nodes: Iterable[str], edges: List[Edge], *, kinds: Optional[set] = None) -> bool:
    kinds = kinds or {RelationKind.NEXT, RelationKind.TRANSITION, RelationKind.CHOICE}
    adj: Dict[str, List[str]] = {}
    for e in edges:
        if e.kind in kinds:
            adj.setdefault(e.src, []).append(e.dst)

    visited: set = set()
    stack: set = set()

    def dfs(u: str) -> bool:
        visited.add(u)
        stack.add(u)
        for v in adj.get(u, []):
            if v not in visited:
                if dfs(v):
                    return True
            elif v in stack:
                return True
        stack.remove(u)
        return False

    for n in nodes:
        if n not in visited:
            if dfs(n):
                return True
    return False


# ---------- Экспорт ----------

def export_package(pkg: Package) -> Dict[str, Path]:
    out = pkg.params.out_dir
    out.mkdir(parents=True, exist_ok=True)

    # graph.json (совместим с relations.Graph)
    graph_obj = {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "nodes": sorted(pkg.nodes.keys()),
        "edges": [
            {
                "src": e.src,
                "dst": e.dst,
                "kind": e.kind,
                "label": e.label,
                "prob": e.prob,
                "weight": e.weight,
                "metadata": e.metadata,
                "created_at": e.created_at,
            }
            for e in pkg.edges
        ],
    }
    graph_path = out / "graph.json"
    _write_json(graph_path, graph_obj)

    # nodes.(yaml|json)
    nodes_obj = {
        nid: {
            "type": ns.node_type,
            "text": ns.text,
            "choices": ns.choices or None,
            "outcome": ns.outcome,
            "attributes": ns.attributes or None,
        }
        for nid, ns in pkg.nodes.items()
    }
    nodes_path = _write_yaml_or_json(out / "nodes", nodes_obj, prefer_yaml=True)

    # manifest.(yaml|json)
    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()
    manifest_obj = {
        "title": pkg.params.title,
        "locale": pkg.params.locale,
        "narrative_key": pkg.params.narrative_key,
        "narrative_version": pkg.params.narrative_version,
        "root_node_id": pkg.root_node_id,
        "created_at": now,
        "generator": {
            "name": "generate_questline",
            "version": 1,
            "seed": pkg.params.seed,
            "params": {
                "depth": pkg.params.depth,
                "branching": pkg.params.branching,
                "allow_loops": pkg.params.allow_loops,
                "ensure_endings": pkg.params.ensure_endings,
                "max_choices": pkg.params.max_choices,
                "next_density": pkg.params.next_density,
                "choice_density": pkg.params.choice_density,
                "tags": pkg.params.tags,
            },
        },
    }
    manifest_path = _write_yaml_or_json(out / "manifest", manifest_obj, prefer_yaml=True)

    # DOT (опционально)
    dot_path = None
    if pkg.params.emit_dot:
        dot_path = out / "graph.dot"
        dot_path.write_text(_to_dot(pkg), encoding="utf-8")

    return {
        "graph": graph_path,
        "nodes": nodes_path,
        "manifest": manifest_path,
        "dot": dot_path if dot_path else Path(),
    }


def _to_dot(pkg: Package) -> str:
    lines = ["digraph questline {", '  rankdir=LR;', '  node [shape=box, fontname="Helvetica"];']
    for nid, ns in pkg.nodes.items():
        shape = {
            "dialogue": "box",
            "choice": "diamond",
            "ending": "doubleoctagon",
            "system": "ellipse",
            "action": "parallelogram",
        }.get(ns.node_type, "box")
        label = ns.text or ns.node_type
        label = label.replace('"', '\\"')
        lines.append(f'  "{nid}" [label="{nid}\\n{label[:60]}", shape={shape}];')
    for e in pkg.edges:
        attrs = []
        if e.kind == RelationKind.CHOICE:
            attrs.append('color="blue"')
            if e.label:
                attrs.append(f'label="{e.label} ({e.prob})"')
        elif e.kind == RelationKind.NEXT:
            if e.label:
                attrs.append(f'label="{e.label}"')
        else:
            attrs.append('style="dashed"')
            attrs.append(f'label="{e.kind}"')
        lines.append(f'  "{e.src}" -> "{e.dst}" [{", ".join(attrs)}];')
    lines.append("}")
    return "\n".join(lines)


# ---------- CLI ----------

def _parse_args(argv: Optional[List[str]] = None) -> GenParams:
    ap = argparse.ArgumentParser(
        prog="generate_questline",
        description="Генератор квестлайна Mythos Core (граф + узлы + манифест + DOT).",
    )
    ap.add_argument("--title", required=True, help="Название квестлайна.")
    ap.add_argument("--locale", default="ru-RU", help="BCP-47 локаль (по умолчанию ru-RU).")
    ap.add_argument("--depth", type=int, default=4, help="Глубина уровней (по умолчанию 4).")
    ap.add_argument("--branching", type=int, default=3, help="Максимальная ширина ветвления (по умолчанию 3).")
    ap.add_argument("--seed", type=int, default=0, help="Seed генератора случайных чисел (0 = авто).")
    ap.add_argument("--allow-loops", action="store_true", help="Разрешить циклы по NEXT/TRANSITION (по умолчанию запрещены).")
    ap.add_argument("--ensure-endings", type=int, default=2, help="Сколько финалов создать на последнем уровне (по умолчанию 2).")
    ap.add_argument("--max-choices", type=int, default=4, help="Максимум вариантов в CHOICE (по умолчанию 4).")
    ap.add_argument("--next-density", type=float, default=0.8, help="Доля NEXT разветвлений при генерации (0..1).")
    ap.add_argument("--choice-density", type=float, default=0.5, help="Вероятность создавать CHOICE на узле (0..1).")
    ap.add_argument("--out", required=True, help="Каталог для вывода пакета.")
    ap.add_argument("--dot", action="store_true", help="Экспортировать Graphviz DOT.")
    ap.add_argument("--template", help="Путь к YAML/JSON шаблону для текста/стилей.")
    ap.add_argument("--narrative-key", default="questline", help="Ключ нарратива (по умолчанию questline).")
    ap.add_argument("--narrative-version", type=int, default=1, help="Версия нарратива (по умолчанию 1).")
    ap.add_argument("--tags", nargs="*", default=[], help="Теги для манифеста.")
    args = ap.parse_args(argv)

    if args.seed == 0:
        # деривация из времени
        args.seed = int(time.time()) & 0xFFFFFFFF

    template: Dict[str, Any] = {}
    if args.template:
        p = Path(args.template)
        if not p.exists():
            raise SystemExit(f"--template not found: {p}")
        template = _load_template(p)

    out_dir = Path(args.out)

    return GenParams(
        title=args.title,
        locale=args.locale,
        depth=max(1, int(args.depth)),
        branching=max(2, int(args.branching)),
        seed=int(args.seed),
        allow_loops=bool(args.allow_loops),
        ensure_endings=max(0, int(args.ensure_endings)),
        max_choices=max(2, int(args.max_choices)),
        next_density=float(args.next_density),
        choice_density=float(args.choice_density),
        out_dir=out_dir,
        emit_dot=bool(args.dot),
        template=template,
        narrative_key=str(args.narrative_key),
        narrative_version=int(args.narrative_version),
        tags=list(args.tags or []),
    )


def _load_template(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    # Попытка YAML, затем JSON
    if yaml is not None:
        try:
            obj = yaml.safe_load(text)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    raise SystemExit(f"Unsupported template format: {path}")


def main(argv: Optional[List[str]] = None) -> int:
    try:
        params = _parse_args(argv)
        log.info("questline.generate.start", title=params.title, seed=params.seed, out=str(params.out_dir))
        pkg = generate_questline(params)
        paths = export_package(pkg)
        log.info(
            "questline.generate.done",
            graph=str(paths["graph"]),
            nodes=str(paths["nodes"]),
            manifest=str(paths["manifest"]),
            dot=(str(paths["dot"]) if paths["dot"] else None),
        )
        print(str(paths["manifest"]))
        return 0
    except GenError as e:
        log.error("questline.generate.invalid", error=str(e))
        print(f"INVALID: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        log.error("questline.generate.error", error=str(e), exc_info=True)
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
