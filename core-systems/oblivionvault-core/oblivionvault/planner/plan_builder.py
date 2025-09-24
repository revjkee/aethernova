"""
OblivionVault Core — Industrial Plan Builder
--------------------------------------------
Назначение:
  - Превращает декларативную спецификацию (DSL) в исполнимый план (DAG) с
    развертыванием фан-аутов, проверками целостности и расчетом временных
    характеристик.

Особенности:
  - Pydantic v1/v2 совместимость без внешних зависимостей, кроме pyyaml (опц.).
  - Детерминированные ID задач и хеш плана по каноническому JSON.
  - Шаблонизация параметров ({{path.to.value}}) без Jinja — безопасный подстановщик.
  - Фан-аут по коллекциям (map), условные задачи (when), гейты (approval).
  - Ретраи: экспоненциальный backoff, cap, jitter; дедлайны и таймауты.
  - Ресурсные группы: ограничение параллелизма, простая симуляция для оценки ETA.
  - Контроль качества: цикл-детектор, лимиты на размер графа, валидация ссылок.
  - Экспорт: JSON, YAML, Graphviz DOT, критический путь и топологическая сортировка.

Интеграция:
  from oblivionvault.planner.plan_builder import PlanSpec, PlannerContext, PlanBuilder
  plan = PlanBuilder().build(spec, ctx)
  print(plan.to_json())

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

# --- Pydantic v1/v2 compatibility ---------------------------------------------
try:  # Pydantic v1
    from pydantic import BaseModel, Field, ValidationError, root_validator, validator
    PYD_VER = 1
except Exception:  # pragma: no cover - Pydantic v2
    from pydantic import BaseModel, Field, ValidationError
    from pydantic import model_validator as root_validator  # type: ignore
    from pydantic import field_validator as validator  # type: ignore
    PYD_VER = 2

try:
    import yaml  # optional pretty YAML export
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


# -------------------------- Errors ---------------------------------------------

class PlanError(RuntimeError):
    pass

class ValidationFailed(PlanError):
    pass

class CycleDetected(PlanError):
    def __init__(self, cycle: List[str]) -> None:
        super().__init__(f"Cycle detected: {' -> '.join(cycle)}")
        self.cycle = cycle

class ResourceError(PlanError):
    pass


# -------------------------- Models (Spec) --------------------------------------

class RetryPolicy(BaseModel):
    max_attempts: int = Field(3, ge=1, le=50)
    backoff_initial_ms: int = Field(500, ge=0)
    backoff_multiplier: float = Field(2.0, ge=1.0, le=10.0)
    backoff_cap_ms: int = Field(30_000, ge=0)
    jitter_ms: int = Field(250, ge=0)

    def schedule_ms(self) -> List[int]:
        """Return list of sleep milliseconds between attempts (len = max_attempts-1)."""
        sleeps: List[int] = []
        delay = self.backoff_initial_ms
        for _ in range(self.max_attempts - 1):
            sleeps.append(min(int(delay), self.backoff_cap_ms))
            delay *= self.backoff_multiplier
        return sleeps

class Deadline(BaseModel):
    timeout_ms: int = Field(30_000, ge=1, le=3_600_000)  # per-attempt timeout
    hard_deadline_ms: Optional[int] = Field(None, ge=1, le=21_600_000)  # absolute cap for all retries

class ResourceBinding(BaseModel):
    group: str = Field(..., description="Имя ресурсной группы, напр. 'io', 'cpu', 'db'")
    weight: int = Field(1, ge=1, le=100, description="Вес слота в группе")
    concurrency_key: Optional[str] = Field(
        None, description="Если задан — сериализация по ключу (напр. один аккаунт/tenant)"
    )

class ApprovalGate(BaseModel):
    required: bool = Field(False)
    approvers: List[str] = Field(default_factory=list)
    min_approvals: int = Field(1, ge=1, le=10)

class FanoutSpec(BaseModel):
    over: str = Field(..., description="Путь в контексте до списка для маппинга (dot.notation)")
    as_var: str = Field("item", description="Имя переменной для элемента коллекции")
    concurrency: Optional[int] = Field(None, ge=1, le=512, description="Ограничение параллелизма внутри фан-аута")

class TaskSpec(BaseModel):
    id: Optional[str] = Field(None, description="Человекочитаемый ID. Если не задан — будет сгенерирован.")
    name: str = Field(..., description="Понятное имя задачи")
    kind: Literal["noop", "http", "rpc", "sql", "shell", "custom"] = "noop"
    params: Dict[str, Any] = Field(default_factory=dict)
    depends_on: List[str] = Field(default_factory=list)
    when: Optional[str] = Field(None, description="Булево выражение на контекст/аргументы ('ctx.env == \"prod\"')")
    fanout: Optional[FanoutSpec] = None
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    deadline: Deadline = Field(default_factory=Deadline)
    resources: List[ResourceBinding] = Field(default_factory=list)
    approval: ApprovalGate = Field(default_factory=ApprovalGate)
    estimate_ms: int = Field(1000, ge=0, description="Оценка длительности для планирования (не влияет на таймеры)")
    produces: Dict[str, str] = Field(default_factory=dict, description="Артефакты (имя->путь) для каталога артефактов")
    consumes: Dict[str, str] = Field(default_factory=dict, description="Зависимости от артефактов предыдущих задач")

    @validator("depends_on", each_item=True)
    def _dep_nonempty(cls, v: str) -> str:  # type: ignore
        if not v or not v.strip():
            raise ValueError("depends_on must contain non-empty ids")
        return v.strip()

class ResourceGroup(BaseModel):
    name: str
    max_concurrency: int = Field(4, ge=1, le=4096)

class Constraints(BaseModel):
    max_tasks: int = Field(50_000, ge=1)
    max_edges: int = Field(200_000, ge=0)
    forbid_shell_by_default: bool = Field(True)
    forbid_custom_by_default: bool = Field(False)

class Defaults(BaseModel):
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    deadline: Deadline = Field(default_factory=Deadline)
    resources: List[ResourceBinding] = Field(default_factory=list)

class PlanSpec(BaseModel):
    version: str = Field("1.0")
    name: str
    description: Optional[str] = None
    resources: List[ResourceGroup] = Field(default_factory=lambda: [
        ResourceGroup(name="cpu", max_concurrency=8),
        ResourceGroup(name="io", max_concurrency=16),
        ResourceGroup(name="db", max_concurrency=8),
    ])
    defaults: Defaults = Field(default_factory=Defaults)
    constraints: Constraints = Field(default_factory=Constraints)
    tasks: List[TaskSpec]

    @root_validator  # type: ignore
    def _validate_shell(cls, values):  # type: ignore
        cons: Constraints = values.get("constraints")  # type: ignore
        tasks: List[TaskSpec] = values.get("tasks", [])  # type: ignore
        if cons and cons.forbid_shell_by_default:
            for t in tasks:
                if t.kind == "shell":
                    raise ValidationFailed("Shell tasks are forbidden by constraints")
        if cons and cons.forbid_custom_by_default:
            for t in tasks:
                if t.kind == "custom":
                    raise ValidationFailed("Custom tasks are forbidden by constraints")
        return values


# -------------------------- Models (Plan) ---------------------------------------

@dataclass
class Node:
    id: str
    spec: TaskSpec
    params_resolved: Dict[str, Any]
    deps: List[str]
    retry: RetryPolicy
    deadline: Deadline
    resources: List[ResourceBinding]
    estimate_ms: int

@dataclass
class ExecutionPlan:
    plan_id: str
    plan_hash: str
    name: str
    version: str
    created_ts: int
    nodes: Dict[str, Node]
    edges: List[Tuple[str, str]]  # (from, to)
    topological_order: List[str]
    critical_path_ms: int
    resource_groups: Dict[str, int]  # name -> max_concurrency
    meta: Dict[str, Any] = field(default_factory=dict)

    # -------- Exports --------
    def to_json(self, indent: Optional[int] = 2) -> str:
        def node_to_dict(n: Node) -> Dict[str, Any]:
            return {
                "id": n.id,
                "name": n.spec.name,
                "kind": n.spec.kind,
                "deps": n.deps,
                "retry": n.retry.dict() if hasattr(n.retry, "dict") else n.retry.__dict__,
                "deadline": n.deadline.dict() if hasattr(n.deadline, "dict") else n.deadline.__dict__,
                "resources": [r.dict() if hasattr(r, "dict") else r.__dict__ for r in n.resources],
                "estimate_ms": n.estimate_ms,
                "params": n.params_resolved,
                "produces": n.spec.produces,
                "consumes": n.spec.consumes,
            }

        data = {
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "name": self.name,
            "version": self.version,
            "created_ts": self.created_ts,
            "resource_groups": self.resource_groups,
            "nodes": {k: node_to_dict(v) for k, v in self.nodes.items()},
            "edges": self.edges,
            "order": self.topological_order,
            "critical_path_ms": self.critical_path_ms,
            "meta": self.meta,
        }
        return json.dumps(data, ensure_ascii=False, indent=indent)

    def to_yaml(self) -> str:
        if yaml is None:
            return self.to_json()
        data = json.loads(self.to_json(indent=None))
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)

    def to_dot(self) -> str:
        lines = ['digraph plan {', '  rankdir=LR;', '  node [shape=box, style=rounded];']
        for node_id, node in self.nodes.items():
            label = f"{node.spec.name}\\n[{node.spec.kind}]"
            lines.append(f'  "{node_id}" [label="{label}"];')
        for u, v in self.edges:
            lines.append(f'  "{u}" -> "{v}";')
        lines.append('}')
        return "\n".join(lines)


# -------------------------- Planner Context & Utils -----------------------------

class PlannerContext(BaseModel):
    env: str = Field("dev")
    workspace: str = Field("default")
    actor: Optional[str] = None
    now_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    params: Dict[str, Any] = Field(default_factory=dict)

    def flatten(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ctx.env": self.env,
            "ctx.workspace": self.workspace,
            "ctx.actor": self.actor,
            "ctx.now_ms": self.now_ms,
        }
        def rec(prefix: str, obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    rec(f"{prefix}.{k}", v)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    rec(f"{prefix}[{i}]", v)
            else:
                out[prefix] = obj
        rec("params", self.params)
        return out


class SafeTemplate:
    """
    Мини-шаблонизатор: заменяет {{path.to.value}} значениями из словаря (flatten).
    Не выполняет никаких выражений.
    """
    RE = re.compile(r"{{\s*([a-zA-Z0-9_.\[\]-]+)\s*}}")

    @staticmethod
    def render(obj: Any, values: Dict[str, Any]) -> Any:
        if isinstance(obj, str):
            def _sub(m: re.Match) -> str:
                key = m.group(1)
                return str(values.get(key, m.group(0)))
            return SafeTemplate.RE.sub(_sub, obj)
        if isinstance(obj, list):
            return [SafeTemplate.render(x, values) for x in obj]
        if isinstance(obj, dict):
            return {k: SafeTemplate.render(v, values) for k, v in obj.items()}
        return obj


def canonical_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# -------------------------- Core Builder ----------------------------------------

class PlanBuilder:
    def __init__(self) -> None:
        pass

    # -------- Public API --------
    def build(self, spec: PlanSpec, ctx: PlannerContext) -> ExecutionPlan:
        # 1) Validate sizes early
        if len(spec.tasks) > spec.constraints.max_tasks:
            raise ValidationFailed(f"Too many tasks: {len(spec.tasks)} > {spec.constraints.max_tasks}")

        # 2) Expand tasks (fanouts + when)
        expanded = self._expand_tasks(spec, ctx)

        # 3) Build nodes and edges
        nodes, edges = self._materialize(spec, ctx, expanded)

        # 4) Validate graph: cycles, edges count
        if len(edges) > spec.constraints.max_edges:
            raise ValidationFailed(f"Too many edges: {len(edges)} > {spec.constraints.max_edges}")
        order = self._toposort(nodes, edges)

        # 5) Critical path (by estimate_ms)
        cpath_ms = self._critical_path_ms(nodes, edges)

        # 6) Resource groups & simulation (ETA)
        rg = {rg.name: rg.max_concurrency for rg in spec.resources}
        self._validate_resources(nodes, rg)

        # 7) Hash the plan
        plan_meta = {
            "ctx": ctx.dict() if hasattr(ctx, "dict") else ctx.__dict__,
            "spec_version": spec.version,
        }
        plan_hash = self._hash_plan(nodes, edges, rg, plan_meta)
        plan_id = f"{spec.name}-{plan_hash[:12]}"

        return ExecutionPlan(
            plan_id=plan_id,
            plan_hash=plan_hash,
            name=spec.name,
            version=spec.version,
            created_ts=int(time.time() * 1000),
            nodes=nodes,
            edges=edges,
            topological_order=order,
            critical_path_ms=cpath_ms,
            resource_groups=rg,
            meta={"eta_simulation_ms": self._simulate_eta(nodes, edges, rg)},
        )

    # -------- Expansion / Materialization --------
    def _expand_tasks(self, spec: PlanSpec, ctx: PlannerContext) -> List[TaskSpec]:
        """
        Разворачивает фан-ауты и фильтрует по when. Генерирует стабильные ID.
        """
        flat_ctx = ctx.flatten()
        result: List[TaskSpec] = []
        for idx, t in enumerate(spec.tasks):
            # Evaluate 'when' (very simple: True/False/null)
            if t.when:
                cond = self._eval_condition(t.when, flat_ctx)
                if not cond:
                    continue

            if t.fanout:
                collection = self._get_path(flat_ctx, t.fanout.over)
                if not isinstance(collection, list):
                    raise ValidationFailed(f"Fanout over '{t.fanout.over}' is not a list")
                for i, item in enumerate(collection):
                    # extend context with fanout var
                    local_ctx = dict(flat_ctx)
                    local_ctx[f"{t.fanout.as_var}"] = item
                    local_ctx[f"{t.fanout.as_var}.index"] = i
                    clone = t.copy(deep=True)
                    # Stable ID: base or auto + hash(item)
                    base_id = t.id or f"t{idx}_{t.name.lower().replace(' ', '_')}"
                    suffix = sha256_hex(canonical_json(item))[:8]
                    clone.id = f"{base_id}.{suffix}"
                    # Params will be templated later using local_ctx
                    # Annotate resources with concurrency key if set
                    if t.fanout.concurrency is not None:
                        # we do not modify resource groups limit here; executor may enforce per-fanout concurrency
                        pass
                    # Stash local context for template (attached via params key)
                    clone.params = {"__fanout__": item, **clone.params}
                    # Track dependency rewrite: keep original depends_on as-is (will resolve by expanded ids if needed)
                    # Add to result with stored local context in a side-car list
                    result.append(clone)
            else:
                clone = t.copy(deep=True)
                clone.id = t.id or f"t{idx}_{t.name.lower().replace(' ', '_')}"
                result.append(clone)
        return result

    def _materialize(
        self,
        spec: PlanSpec,
        ctx: PlannerContext,
        tasks: List[TaskSpec],
    ) -> Tuple[Dict[str, Node], List[Tuple[str, str]]]:
        # Prepare map id->spec and uniqueness
        id_set: set[str] = set()
        for t in tasks:
            if not t.id:
                raise ValidationFailed("Task id must be assigned during expansion")
            if t.id in id_set:
                raise ValidationFailed(f"Duplicate task id after expansion: {t.id}")
            id_set.add(t.id)

        # Build nodes with templated params & applied defaults
        nodes: Dict[str, Node] = {}
        edges: List[Tuple[str, str]] = []

        for t in tasks:
            merged_retry = t.retry or spec.defaults.retry
            merged_deadline = t.deadline or spec.defaults.deadline
            merged_resources = t.resources or spec.defaults.resources

            # Compose template values
            flat = ctx.flatten()
            # propagate fanout local object, if present
            if "__fanout__" in t.params:
                fan = t.params["__fanout__"]
                # flatten fanout item under "item.*" and also at root of template for convenience
                flat["item"] = fan
                # also expose as params.item for compatibility
                flat["params.item"] = fan

            params_src = {k: v for k, v in t.params.items() if k != "__fanout__"}
            params_resolved = SafeTemplate.render(params_src, _flatten_for_template(flat))

            node = Node(
                id=t.id,  # type: ignore
                spec=t,
                params_resolved=params_resolved,
                deps=list(t.depends_on),
                retry=merged_retry,
                deadline=merged_deadline,
                resources=merged_resources,
                estimate_ms=t.estimate_ms,
            )
            nodes[node.id] = node

        # Build edges; validate that deps exist
        for n in nodes.values():
            for dep in n.deps:
                if dep not in nodes:
                    raise ValidationFailed(f"Task '{n.id}' depends on unknown '{dep}'")
                edges.append((dep, n.id))

        return nodes, edges

    # -------- Graph Algorithms --------
    def _toposort(self, nodes: Dict[str, Node], edges: List[Tuple[str, str]]) -> List[str]:
        # Kahn's algorithm
        incoming = {k: 0 for k in nodes}
        adj: Dict[str, List[str]] = {k: [] for k in nodes}
        for u, v in edges:
            incoming[v] += 1
            adj[u].append(v)
        q: List[str] = [n for n, deg in incoming.items() if deg == 0]
        order: List[str] = []
        while q:
            u = q.pop()
            order.append(u)
            for v in adj[u]:
                incoming[v] -= 1
                if incoming[v] == 0:
                    q.append(v)
        if len(order) != len(nodes):
            cycle = self._find_cycle(nodes, edges)
            raise CycleDetected(cycle)
        return order

    def _find_cycle(self, nodes: Dict[str, Node], edges: List[Tuple[str, str]]) -> List[str]:
        # DFS cycle finder to construct an example cycle
        adj: Dict[str, List[str]] = {k: [] for k in nodes}
        for u, v in edges:
            adj[u].append(v)

        visited: Dict[str, int] = {k: 0 for k in nodes}  # 0=unseen,1=visiting,2=done
        stack: List[str] = []

        def dfs(u: str) -> Optional[List[str]]:
            visited[u] = 1
            stack.append(u)
            for v in adj[u]:
                if visited[v] == 0:
                    res = dfs(v)
                    if res:
                        return res
                elif visited[v] == 1:
                    # cycle found, extract
                    ci = stack.index(v)
                    return stack[ci:] + [v]
            stack.pop()
            visited[u] = 2
            return None

        for n in nodes:
            if visited[n] == 0:
                res = dfs(n)
                if res:
                    return res
        return []

    def _critical_path_ms(self, nodes: Dict[str, Node], edges: List[Tuple[str, str]]) -> int:
        # Longest path in DAG with node weights = estimate_ms
        order = self._toposort(nodes, edges)
        weight = {k: n.estimate_ms for k, n in nodes.items()}
        best: Dict[str, int] = {k: weight[k] for k in nodes}
        preds: Dict[str, List[str]] = {k: [] for k in nodes}
        for u, v in edges:
            preds[v].append(u)
        for v in order:
            for u in preds[v]:
                best[v] = max(best[v], best[u] + weight[v])
        return max(best.values()) if best else 0

    # -------- Resources / Simulation --------
    def _validate_resources(self, nodes: Dict[str, Node], rg: Dict[str, int]) -> None:
        # Ensure all referenced groups exist
        for n in nodes.values():
            for r in n.resources:
                if r.group not in rg:
                    raise ResourceError(f"Unknown resource group '{r.group}' in task '{n.id}'")

    def _simulate_eta(self, nodes: Dict[str, Node], edges: List[Tuple[str, str]], rg: Dict[str, int]) -> int:
        """
        Простейшая симуляция: для каждого resource.group поддерживаем счетчик занятых слотов,
        задачи запускаем при готовности предков и наличии слотов. Возвращаем ориентировочную длительность.
        """
        order = self._toposort(nodes, edges)
        preds: Dict[str, List[str]] = {k: [] for k in nodes}
        for u, v in edges:
            preds[v].append(u)

        t_start: Dict[str, int] = {}
        t_finish: Dict[str, int] = {}
        # текущее "время" симуляции у каждой группы
        group_free_at: Dict[str, List[int]] = {g: [0] * cap for g, cap in rg.items()}

        for v in order:
            # готовность по зависимостям
            ready_at = 0
            if preds[v]:
                ready_at = max(t_finish[p] for p in preds[v])
            # учтём все биндинги ресурса; если не задано — считаем как "cpu" с 1 весом
            bindings = nodes[v].resources or [ResourceBinding(group="cpu", weight=1)]
            start_time = ready_at
            # для каждой группы найдём слот
            for b in bindings:
                slots = group_free_at[b.group]
                # найдем самый ранний слот
                idx = min(range(len(slots)), key=lambda i: slots[i])
                slot_ready = slots[idx]
                start_time = max(start_time, slot_ready)
            # стартуем и обновляем финиш
            t_start[v] = start_time
            t_finish[v] = start_time + nodes[v].estimate_ms
            # обновим занятость слотов для всех групп
            for b in bindings:
                slots = group_free_at[b.group]
                idx = min(range(len(slots)), key=lambda i: slots[i])
                slots[idx] = t_finish[v]

        return max(t_finish.values()) if t_finish else 0

    # -------- Misc helpers --------
    def _eval_condition(self, expr: str, flat: Dict[str, Any]) -> bool:
        """
        Безопасная оценка очень ограниченных выражений:
          - допускаем только литералы, ==, !=, in, not in, and/or/() и обращения к ключам из flat.
        """
        # Подменяем ключи на значения (строки в кавычках)
        # Пример: ctx.env == "prod"  ->  "prod" == "prod"
        # Упрощение: допускаем только ctx.* и params.* токены
        token_re = re.compile(r"(ctx\.[a-zA-Z0-9_.]+|params\.[a-zA-Z0-9_.]+)")
        def repl(m: re.Match) -> str:
            key = m.group(1)
            v = flat.get(key)
            if isinstance(v, str):
                return json.dumps(v, ensure_ascii=False)
            return str(v)
        safe = token_re.sub(repl, expr)
        # Удаляем запрещённые символы
        if re.search(r"[^\s\w\.\=\!\(\)\"\'\,\[\]\:<>\-&|inotrfad]", safe):
            # слишком параноидно, но лучше не выполнять
            raise ValidationFailed(f"Unsafe characters in expression: {expr!r}")
        try:
            # eval в песочнице с пустыми builtins
            return bool(eval(safe, {"__builtins__": {}}, {}))
        except Exception:
            raise ValidationFailed(f"Failed to evaluate condition: {expr!r}")

    def _hash_plan(
        self,
        nodes: Dict[str, Node],
        edges: List[Tuple[str, str]],
        rg: Dict[str, int],
        meta: Dict[str, Any],
    ) -> str:
        # Канонический снимок для хеша
        snapshot = {
            "nodes": {
                nid: {
                    "name": n.spec.name,
                    "kind": n.spec.kind,
                    "deps": sorted(n.deps),
                    "params": n.params_resolved,
                    "retry": n.retry.dict() if hasattr(n.retry, "dict") else n.retry.__dict__,
                    "deadline": n.deadline.dict() if hasattr(n.deadline, "dict") else n.deadline.__dict__,
                    "resources": [r.dict() if hasattr(r, "dict") else r.__dict__ for r in n.resources],
                    "estimate_ms": n.estimate_ms,
                }
                for nid, n in sorted(nodes.items(), key=lambda x: x[0])
            },
            "edges": sorted(edges),
            "rg": rg,
            "meta": meta,
        }
        return sha256_hex(canonical_json(snapshot))

    def _get_path(self, flat: Dict[str, Any], path: str) -> Any:
        # Поддерживаем "params.foo" и "params[0].bar" и "ctx.env"
        if path in flat:
            return flat[path]
        # Пробуем собрать по точкам и индексам
        def deref(root: Any, parts: List[str]) -> Any:
            cur = root
            for p in parts:
                m = re.match(r"([a-zA-Z0-9_]+)(\[(\d+)\])?", p)
                if not m:
                    return None
                key = m.group(1)
                idx = m.group(3)
                if isinstance(cur, dict):
                    cur = cur.get(key)
                else:
                    return None
                if idx is not None:
                    if not isinstance(cur, list):
                        return None
                    i = int(idx)
                    if i >= len(cur):
                        return None
                    cur = cur[i]
            return cur
        if path.startswith("params"):
            return deref({"params": flat.get("params", {})}, path.split("."))
        if path.startswith("ctx"):
            return deref({"ctx": {
                "env": flat.get("ctx.env"),
                "workspace": flat.get("ctx.workspace"),
                "actor": flat.get("ctx.actor"),
                "now_ms": flat.get("ctx.now_ms"),
            }}, path.split("."))
        return flat.get(path)

# ------------- Helper to flatten context for template ---------------------------

def _flatten_for_template(flat_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Выдает словарь для шаблона: напрямую ключи 'ctx.*', 'params.*', 'item.*' доступны как
    'ctx.xxx', 'params.xxx', 'item.xxx'. Вложенные объекты тоже оставляются как есть.
    """
    out: Dict[str, Any] = {}
    # перенесем всё как есть; шаблон SafeTemplate умеет брать по точечному пути
    for k, v in flat_ctx.items():
        out[k] = v
    # а также предоставим 'ctx' и 'params' как объекты (чтобы можно было {{ctx.env}})
    out["ctx"] = {
        "env": flat_ctx.get("ctx.env"),
        "workspace": flat_ctx.get("ctx.workspace"),
        "actor": flat_ctx.get("ctx.actor"),
        "now_ms": flat_ctx.get("ctx.now_ms"),
    }
    # reconstruct params tree best-effort
    if "params" in flat_ctx:
        out["params"] = flat_ctx["params"]
    if "item" in flat_ctx:
        out["item"] = flat_ctx["item"]
    return out


# -------------------------- Example main (dev) ----------------------------------

if __name__ == "__main__":
    # Демонстрация: простой план из 3 задач с фан-аутом
    spec = PlanSpec(
        name="ledger_bridge_daily",
        description="Daily pipeline for ledger bridge",
        tasks=[
            TaskSpec(
                name="Fetch manifests",
                id="fetch",
                kind="http",
                params={"url": "{{params.base_url}}/manifests?date={{params.date}}"},
                estimate_ms=800,
                resources=[ResourceBinding(group="io")],
            ),
            TaskSpec(
                name="Process shards",
                id="process",
                kind="rpc",
                depends_on=["fetch"],
                fanout=FanoutSpec(over="params.shards", as_var="item"),
                params={
                    "shard_id": "{{item.id}}",
                    "range": "{{item.range}}",
                },
                estimate_ms=1500,
                resources=[ResourceBinding(group="cpu")],
                retry=RetryPolicy(max_attempts=4, backoff_initial_ms=300, backoff_multiplier=2.5, backoff_cap_ms=5000, jitter_ms=200),
            ),
            TaskSpec(
                name="Write summaries",
                id="summarize",
                kind="sql",
                depends_on=["process"],
                params={"dsn": "{{params.pg_dsn}}", "table": "daily_summary_{{params.date}}"},
                estimate_ms=1200,
                resources=[ResourceBinding(group="db")],
                when='ctx.env != "dev"',  # пропустим на dev
            ),
        ],
    )

    ctx = PlannerContext(
        env=os.getenv("ENV", "dev"),
        workspace="ov-core",
        actor="system",
        params={
            "base_url": "https://api.internal",
            "date": "2025-08-24",
            "pg_dsn": "postgres://user:pass@db/oblivion",
            "shards": [{"id": "a", "range": "0-99"}, {"id": "b", "range": "100-199"}],
        },
    )

    plan = PlanBuilder().build(spec, ctx)
    print(plan.to_json())
    if yaml:
        print("--- YAML ---")
        print(plan.to_yaml())
    print("--- DOT ---")
    print(plan.to_dot())
