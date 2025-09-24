# mythos-core/mythos/graph/relations.py
# -*- coding: utf-8 -*-
"""
Граф отношений Mythos Core.

Особенности:
- Типизированные связи RelationKind.
- Консистентные индексы входящих/исходящих ребер.
- Потокобезопасность (RLock) для мутаций/чтений.
- Валидация вероятностей на ветвлениях CHOICE.
- Алгоритмы: цикл/топосорт/BFS кратчайший/перечисление путей/reachability.
- JSON-снапшоты и транзакции с откатом.

Совместимость: Python 3.10+
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Iterator, List, MutableMapping, Optional, Sequence, Set, Tuple
import json
import time
from threading import RLock

__all__ = [
    "RelationKind",
    "Edge",
    "GraphError",
    "DuplicateEdgeError",
    "CycleError",
    "ValidationIssue",
    "Graph",
]

GRAPH_SCHEMA_VERSION = 1


class RelationKind(str, Enum):
    """
    Типы отношений между узлами нарратива/графа.

    NEXT          — последовательный переход (линейный).
    CHOICE        — ветвление выбора; допускает вероятности (prob).
    DEPENDS_ON    — зависимость A зависит от B (ребро B -> A).
    CONFLICTS_WITH— конфликт/взаимоисключение.
    EMITS_OUTCOME — узел порождает исход/результат.
    REFERENCES    — справочная/неструктурная ссылка (разрешаем self для тегов).
    TAGGED        — привязка к метке/категории (node -> tag-node).
    TRANSITION    — произвольный переход состояний (FSM).
    """

    NEXT = "NEXT"
    CHOICE = "CHOICE"
    DEPENDS_ON = "DEPENDS_ON"
    CONFLICTS_WITH = "CONFLICTS_WITH"
    EMITS_OUTCOME = "EMITS_OUTCOME"
    REFERENCES = "REFERENCES"
    TAGGED = "TAGGED"
    TRANSITION = "TRANSITION"


@dataclass(frozen=True)
class Edge:
    """
    Ребро графа.
    - label: человекочитаемый маркер (например, текст варианта выбора).
    - prob: вероятность (0..1) для CHOICE; None для остальных.
    - weight: вес ребра для алгоритмов (не используется в BFS; зарезервировано).
    - metadata: малые метаданные (строки/числа/булевы значения).
    - created_at: unix time (сек) создания ребра.
    """

    src: str
    dst: str
    kind: RelationKind
    label: Optional[str] = None
    prob: Optional[float] = None
    weight: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: time.time())

    def identity(self) -> Tuple[str, str, RelationKind, Optional[str]]:
        """Устойчивый ключ ребра для дедупликации."""
        return (self.src, self.dst, self.kind, self.label)


# ---------- Ошибки/валидация ----------

class GraphError(RuntimeError):
    pass


class DuplicateEdgeError(GraphError):
    pass


class CycleError(GraphError):
    pass


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    node_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ---------- Хранилище графа ----------

class Graph:
    """
    Основной контейнер графа.

    Инварианты:
    - Индексы adj_out/adj_in консистентны с реестром edges.
    - (src,dst,kind,label) уникален, если allow_parallel_edges=False.
    - Самосвязи запрещены для большинства типов (см. _allow_self_loop).

    Потокобезопасность:
    - RLock на все операции. Для чтений используются те же секции,
      чтобы гарантировать моментальные консистентные срезы.
    """

    def __init__(
        self,
        *,
        allow_parallel_edges: bool = False,
    ) -> None:
        self._lock = RLock()
        self._edges: Dict[Tuple[str, str, RelationKind, Optional[str]], Edge] = {}
        # Индексы вида: out[src][kind] = set[(dst,label)], in[dst][kind] = set[(src,label)]
        self._adj_out: Dict[str, Dict[RelationKind, Set[Tuple[str, Optional[str]]]]] = {}
        self._adj_in: Dict[str, Dict[RelationKind, Set[Tuple[str, Optional[str]]]]] = {}
        self._allow_parallel = allow_parallel_edges
        self._nodes: Set[str] = set()

    # --------- базовые операции ---------

    def add_node(self, node_id: str) -> None:
        """Добавляет узел (идемпотентно)."""
        if not node_id:
            raise GraphError("empty node_id")
        with self._lock:
            self._nodes.add(node_id)

    def remove_node(self, node_id: str) -> None:
        """Удаляет узел и все инцидентные ребра."""
        with self._lock:
            if node_id not in self._nodes:
                return
            # собираем ключи ребер на удаление
            to_delete = [
                k for k, e in self._edges.items() if e.src == node_id or e.dst == node_id
            ]
            for k in to_delete:
                self._remove_edge_nolock(self._edges[k])
            self._nodes.discard(node_id)

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: RelationKind,
        *,
        label: Optional[str] = None,
        prob: Optional[float] = None,
        weight: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
        created_at: Optional[float] = None,
    ) -> Edge:
        """
        Добавляет ребро. Создает отсутствующие узлы автоматически.

        Ограничения:
        - self-loop запрещен, кроме REFERENCES/TAGGED (см. _allow_self_loop).
        - Для CHOICE prob ∈ (0,1]; None недопустим.
        - Дубликаты запрещены, если allow_parallel_edges=False.
        """
        edge = Edge(
            src=src,
            dst=dst,
            kind=kind,
            label=label,
            prob=prob,
            weight=weight,
            metadata=metadata or {},
            created_at=created_at or time.time(),
        )
        self._validate_edge(edge)

        with self._lock:
            self._nodes.add(src)
            self._nodes.add(dst)
            key = edge.identity()
            if (not self._allow_parallel) and key in self._edges:
                raise DuplicateEdgeError(f"duplicate edge: {key}")
            # если параллельные допустимы — добавляем уникализатор по времени в ключ?
            if self._allow_parallel and key in self._edges:
                # Для параллельных — уникализируем label (если None) штампом времени
                # чтобы не затереть существующее
                unique_label = f"{label or ''}#{int(edge.created_at*1000)}"
                edge = Edge(**{**edge.__dict__, "label": unique_label})  # type: ignore[arg-type]
                key = edge.identity()

            self._edges[key] = edge
            self._adj_out.setdefault(src, {}).setdefault(kind, set()).add((dst, edge.label))
            self._adj_in.setdefault(dst, {}).setdefault(kind, set()).add((src, edge.label))
            return edge

    def remove_edge(
        self,
        src: str,
        dst: str,
        kind: RelationKind,
        label: Optional[str] = None,
    ) -> None:
        """Удаляет ребро по идентичности."""
        with self._lock:
            key = (src, dst, kind, label)
            edge = self._edges.get(key)
            if not edge:
                return
            self._remove_edge_nolock(edge)

    def _remove_edge_nolock(self, edge: Edge) -> None:
        key = edge.identity()
        self._edges.pop(key, None)
        out_k = self._adj_out.get(edge.src, {}).get(edge.kind)
        if out_k:
            out_k.discard((edge.dst, edge.label))
            if not out_k:
                self._adj_out[edge.src].pop(edge.kind, None)
        in_k = self._adj_in.get(edge.dst, {}).get(edge.kind)
        if in_k:
            in_k.discard((edge.src, edge.label))
            if not in_k:
                self._adj_in[edge.dst].pop(edge.kind, None)

    # --------- запросы/инспекция ---------

    def nodes(self) -> Set[str]:
        with self._lock:
            return set(self._nodes)

    def edges(self) -> List[Edge]:
        with self._lock:
            return list(self._edges.values())

    def neighbors(
        self,
        node_id: str,
        *,
        direction: str = "out",
        kinds: Optional[Iterable[RelationKind]] = None,
    ) -> Set[str]:
        """
        Возвращает соседние узлы по направлению:
        - out: все dst из node_id
        - in: все src в node_id
        - both: объединение
        """
        with self._lock:
            kinds_set = set(kinds) if kinds else None
            result: Set[str] = set()
            if direction in ("out", "both"):
                for k, pairs in self._adj_out.get(node_id, {}).items():
                    if kinds_set is None or k in kinds_set:
                        result.update(dst for dst, _ in pairs)
            if direction in ("in", "both"):
                for k, pairs in self._adj_in.get(node_id, {}).items():
                    if kinds_set is None or k in kinds_set:
                        result.update(src for src, _ in pairs)
            return result

    def out_edges(
        self,
        node_id: str,
        kinds: Optional[Iterable[RelationKind]] = None,
    ) -> List[Edge]:
        with self._lock:
            kinds_set = set(kinds) if kinds else None
            result: List[Edge] = []
            for k, pairs in self._adj_out.get(node_id, {}).items():
                if kinds_set is None or k in kinds_set:
                    for dst, label in pairs:
                        e = self._edges.get((node_id, dst, k, label))
                        if e:
                            result.append(e)
            return result

    def in_edges(
        self,
        node_id: str,
        kinds: Optional[Iterable[RelationKind]] = None,
    ) -> List[Edge]:
        with self._lock:
            kinds_set = set(kinds) if kinds else None
            result: List[Edge] = []
            for k, pairs in self._adj_in.get(node_id, {}).items():
                if kinds_set is None or k in kinds_set:
                    for src, label in pairs:
                        e = self._edges.get((src, node_id, k, label))
                        if e:
                            result.append(e)
            return result

    # --------- алгоритмы ---------

    def detect_cycles(self, *, kinds: Optional[Iterable[RelationKind]] = None) -> List[List[str]]:
        """
        Обнаруживает циклы (списки узлов) по заданным типам ребер (default: все).
        Используется DFS со стеком. Возвращает список уникальных циклов.
        """
        with self._lock:
            kinds_set = set(kinds) if kinds else set(RelationKind)
            visited: Set[str] = set()
            in_stack: Set[str] = set()
            stack: List[str] = []
            cycles: List[List[str]] = []

            def dfs(u: str):
                visited.add(u)
                in_stack.add(u)
                stack.append(u)
                for k, pairs in self._adj_out.get(u, {}).items():
                    if k not in kinds_set:
                        continue
                    for v, _lbl in pairs:
                        if v not in visited:
                            dfs(v)
                        elif v in in_stack:
                            # нашли цикл; выделяем suffix из стека
                            try:
                                idx = stack.index(v)
                                cyc = stack[idx:].copy()
                                if cyc and cyc not in cycles:
                                    cycles.append(cyc)
                            except ValueError:
                                pass
                stack.pop()
                in_stack.discard(u)

            for n in self._nodes:
                if n not in visited:
                    dfs(n)

            return cycles

    def toposort(self, *, kinds: Optional[Iterable[RelationKind]] = None) -> List[str]:
        """
        Топологическая сортировка по заданным типам ребер (default: NEXT/DEPENDS_ON/TRANSITION).
        Бросает CycleError при наличии циклов.
        """
        if kinds is None:
            kinds = (RelationKind.NEXT, RelationKind.DEPENDS_ON, RelationKind.TRANSITION)
        with self._lock:
            kinds_set = set(kinds)
            indeg: Dict[str, int] = {n: 0 for n in self._nodes}
            for dst, m in self._adj_in.items():
                deg = 0
                for k, pairs in m.items():
                    if k in kinds_set:
                        deg += len(pairs)
                indeg[dst] = deg
            # Kahn's algorithm
            queue: List[str] = [n for n, d in indeg.items() if d == 0]
            order: List[str] = []
            i = 0
            while i < len(queue):
                u = queue[i]
                i += 1
                order.append(u)
                for k, pairs in self._adj_out.get(u, {}).items():
                    if k not in kinds_set:
                        continue
                    for v, _lbl in list(pairs):
                        indeg[v] -= 1
                        if indeg[v] == 0:
                            queue.append(v)
            if len(order) != len(self._nodes):
                raise CycleError("graph has cycles for selected kinds")
            return order

    def shortest_path(
        self,
        src: str,
        dst: str,
        *,
        kinds: Optional[Iterable[RelationKind]] = None,
        max_hops: Optional[int] = None,
    ) -> Optional[List[str]]:
        """
        Кратчайший путь (по числу ребер). BFS, опционально ограничение по длине.
        Возвращает список узлов или None, если нет пути.
        """
        with self._lock:
            if src not in self._nodes or dst not in self._nodes:
                return None
            kinds_set = set(kinds) if kinds else None
            from collections import deque
            q = deque([src])
            prev: Dict[str, Optional[str]] = {src: None}
            depth: Dict[str, int] = {src: 0}
            while q:
                u = q.popleft()
                if max_hops is not None and depth[u] >= max_hops:
                    continue
                for k, pairs in self._adj_out.get(u, {}).items():
                    if kinds_set is not None and k not in kinds_set:
                        continue
                    for v, _lbl in pairs:
                        if v in prev:
                            continue
                        prev[v] = u
                        depth[v] = depth[u] + 1
                        if v == dst:
                            # восстановление
                            path: List[str] = [v]
                            while prev[path[-1]] is not None:
                                path.append(prev[path[-1]])  # type: ignore[index]
                            path.reverse()
                            return path
                        q.append(v)
            return None

    def find_paths(
        self,
        src: str,
        dst: str,
        *,
        kinds: Optional[Iterable[RelationKind]] = None,
        max_hops: int = 10,
        max_paths: int = 100,
    ) -> List[List[str]]:
        """
        Перечисляет пути src->dst глубиной не более max_hops (без повторов узлов).
        Ограничивает число путей max_paths, чтобы избежать взрыва.
        """
        with self._lock:
            kinds_set = set(kinds) if kinds else None
            results: List[List[str]] = []
            path: List[str] = []

            def dfs(u: str, depth: int) -> None:
                if len(results) >= max_paths:
                    return
                if depth > max_hops:
                    return
                path.append(u)
                if u == dst:
                    results.append(path.copy())
                    path.pop()
                    return
                for k, pairs in self._adj_out.get(u, {}).items():
                    if kinds_set is not None and k not in kinds_set:
                        continue
                    for v, _lbl in pairs:
                        if v in path:
                            continue
                        dfs(v, depth + 1)
                        if len(results) >= max_paths:
                            break
                path.pop()

            if src in self._nodes and dst in self._nodes:
                dfs(src, 0)
            return results

    def reachable_from(
        self,
        sources: Iterable[str],
        *,
        kinds: Optional[Iterable[RelationKind]] = None,
        direction: str = "out",
    ) -> Set[str]:
        """
        Множество достижимых узлов из `sources` по заданным ребрам и направлению.
        """
        with self._lock:
            kinds_set = set(kinds) if kinds else None
            seen: Set[str] = set()
            from collections import deque
            dq = deque(s for s in sources if s in self._nodes)
            seen.update(dq)
            while dq:
                u = dq.popleft()
                iterator: Iterable[Tuple[str, Optional[str]]] = ()
                if direction in ("out", "both"):
                    for k, pairs in self._adj_out.get(u, {}).items():
                        if kinds_set is None or k in kinds_set:
                            for v in pairs:
                                yield_v = v[0]
                                if yield_v not in seen:
                                    seen.add(yield_v)
                                    dq.append(yield_v)
                if direction in ("in", "both"):
                    for k, pairs in self._adj_in.get(u, {}).items():
                        if kinds_set is None or k in kinds_set:
                            for v in pairs:
                                yield_v = v[0]
                                if yield_v not in seen:
                                    seen.add(yield_v)
                                    dq.append(yield_v)
            return seen

    # --------- валидация модели ---------

    def validate(self, *, choice_tol: float = 1e-6) -> List[ValidationIssue]:
        """
        Полная валидация графа:
        - CHOICE: сумма prob по исходящим ребрам узла ∈ [1 - tol; 1 + tol] и prob ∈ (0,1].
        - Самосвязи недопустимы для большинства типов.
        - Пустые узлы.
        """
        issues: List[ValidationIssue] = []

        with self._lock:
            # Самосвязи
            for e in self._edges.values():
                if not self._allow_self_loop(e):
                    if e.src == e.dst:
                        issues.append(
                            ValidationIssue(
                                code="SELF_LOOP",
                                message=f"self-loop not allowed for {e.kind}",
                                node_id=e.src,
                                details={"edge": e.identity()},
                            )
                        )

            # CHOICE вероятности
            for node in self._nodes:
                outs = [e for e in self.out_edges(node, kinds=[RelationKind.CHOICE])]
                if not outs:
                    continue
                s = 0.0
                for e in outs:
                    if e.prob is None or not (0.0 < e.prob <= 1.0):
                        issues.append(
                            ValidationIssue(
                                code="CHOICE_PROB_INVALID",
                                message="prob must be in (0,1] for CHOICE",
                                node_id=node,
                                details={"edge": e.identity(), "prob": e.prob},
                            )
                        )
                    else:
                        s += float(e.prob)
                if abs(s - 1.0) > choice_tol:
                    issues.append(
                        ValidationIssue(
                            code="CHOICE_PROB_SUM_MISMATCH",
                            message="sum(prob) of CHOICE out-edges must be 1±tol",
                            node_id=node,
                            details={"sum": s, "tol": choice_tol, "count": len(outs)},
                        )
                    )

            # Одинарный NEXT (на усмотрение домена; можно ослабить)
            for node in self._nodes:
                outs = self.out_edges(node, kinds=[RelationKind.NEXT])
                if len(outs) > 1:
                    issues.append(
                        ValidationIssue(
                            code="MULTIPLE_NEXT",
                            message="multiple NEXT edges from node",
                            node_id=node,
                            details={"count": len(outs)},
                        )
                    )

        return issues

    # --------- сервисные операции ---------

    def transaction(self):
        """
        Контекст-менеджер транзакции: атомарный набор изменений.
        При исключении — откат к снимку до транзакции.
        """
        graph = self

        class _Tx:
            def __enter__(self_nonlocal):
                with graph._lock:
                    self_nonlocal._snap = (
                        dict(graph._edges),
                        json.loads(json.dumps(graph._adj_out, default=list)),
                        json.loads(json.dumps(graph._adj_in, default=list)),
                        set(graph._nodes),
                    )
                return graph

            def __exit__(self_nonlocal, exc_type, exc, tb):
                if exc is not None:
                    with graph._lock:
                        edges, adj_out, adj_in, nodes = self_nonlocal._snap  # type: ignore[attr-defined]
                        graph._edges = edges
                        # восстановление индексов
                        graph._adj_out = {k: {RelationKind(kk): set(map(tuple, vv)) for kk, vv in v.items()} for k, v in adj_out.items()}  # type: ignore[arg-type]
                        graph._adj_in = {k: {RelationKind(kk): set(map(tuple, vv)) for kk, vv in v.items()} for k, v in adj_in.items()}   # type: ignore[arg-type]
                        graph._nodes = nodes
                return False  # не подавлять исключение

        return _Tx()

    def prune(self, predicate: Callable[[Edge], bool]) -> int:
        """
        Удаляет ребра, для которых predicate(edge) == False.
        Возвращает число удаленных ребер.
        """
        removed = 0
        with self._lock:
            to_delete = [e for e in self._edges.values() if not predicate(e)]
            for e in to_delete:
                self._remove_edge_nolock(e)
                removed += 1
        return removed

    # --------- сериализация ---------

    def to_json(self) -> str:
        """Серилизует граф в JSON-строку (версионированный формат)."""
        with self._lock:
            payload = {
                "schema_version": GRAPH_SCHEMA_VERSION,
                "nodes": sorted(self._nodes),
                "edges": [
                    {
                        "src": e.src,
                        "dst": e.dst,
                        "kind": e.kind.value,
                        "label": e.label,
                        "prob": e.prob,
                        "weight": e.weight,
                        "metadata": e.metadata,
                        "created_at": e.created_at,
                    }
                    for e in self._edges.values()
                ],
            }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, data: str) -> "Graph":
        """Читает граф из JSON (совместим с текущей версией)."""
        obj = json.loads(data)
        if int(obj.get("schema_version", 0)) != GRAPH_SCHEMA_VERSION:
            # В рамках мажорной эволюции можно ввести миграции
            raise GraphError("unsupported schema_version")
        g = cls()
        for n in obj.get("nodes", []):
            g.add_node(str(n))
        for e in obj.get("edges", []):
            g.add_edge(
                src=str(e["src"]),
                dst=str(e["dst"]),
                kind=RelationKind(str(e["kind"])),
                label=e.get("label"),
                prob=e.get("prob"),
                weight=e.get("weight"),
                metadata=e.get("metadata") or {},
                created_at=e.get("created_at"),
            )
        return g

    # --------- приватные ---------

    @staticmethod
    def _allow_self_loop(edge: Edge) -> bool:
        # Разрешаем self-loop только для "мягких" типов ссылок
        return edge.kind in {RelationKind.REFERENCES, RelationKind.TAGGED}

    @staticmethod
    def _is_finite_probability(p: Optional[float]) -> bool:
        return p is not None and (0.0 < float(p) <= 1.0)

    def _validate_edge(self, edge: Edge) -> None:
        if not edge.src or not edge.dst:
            raise GraphError("edge src/dst must be non-empty")
        if (edge.src == edge.dst) and (not self._allow_self_loop(edge)):
            raise GraphError(f"self-loop not allowed for {edge.kind}")
        if edge.kind == RelationKind.CHOICE:
            if not self._is_finite_probability(edge.prob):
                raise GraphError("prob must be in (0,1] for CHOICE")
        else:
            if edge.prob is not None:
                raise GraphError("prob allowed only for CHOICE edges")

    # --------- представление ---------

    def __len__(self) -> int:
        with self._lock:
            return len(self._edges)

    def __repr__(self) -> str:  # краткий обзор
        with self._lock:
            return f"<Graph nodes={len(self._nodes)} edges={len(self._edges)}>"
