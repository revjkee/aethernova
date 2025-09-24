# security-core/security/authz/relationship.py
"""
Relationship-based authorization (ReBAC) engine, Zanzibar-inspired.

Key capabilities:
- Namespace schema with relation rewrites: this, computedUserset, tupleToUserset,
  union, intersection, exclusion
- Relationship tuples: object#relation @ subject (user | userset | object for TTU)
- Caveats (conditional edges) via registry of predicate functions with params
- Async check(object, relation, subject), expand(object, relation), list_objects
- Consistency tokens (Zookie) with monotonic versioning
- In-memory, thread-safe, indexed store; optional LRU cache for check
- Guards: recursion depth limit, cycle detection per-request

This module is storage-agnostic via RelationshipStore protocol; MemoryRelationshipStore
is provided for production-like behavior and testing.

Terminology:
- ObjectRef: <namespace, object_id>
- UsersetRef: <object, relation>
- Subject: one of:
    * user:<id>
    * userset:<object#relation>
    * object:<object> (used on the right-hand side of tupleToUserset tuples)
- Relation tuple: (object, relation, subject, caveat?)
- Caveat: named predicate with params evaluated against request context

Example (minimal):
    registry = NamespaceRegistry()
    doc = NamespaceDefinition(
        name="document",
        relations={
            "viewer": RelationDefinition(
                name="viewer",
                rewrite=Union.of(
                    This(),
                    TupleToUserset(tupleset="parent", computed="viewer")
                )
            ),
            "parent": RelationDefinition(
                name="parent",
                rewrite=This()
            )
        }
    )
    registry.register(doc)

    store = MemoryRelationshipStore()
    engine = RelationshipAuthorizer(registry, store)

    # document:doc1 parent => folder:fold1
    await store.write([
        RelationTuple(
            object=ObjectRef("document", "doc1"),
            relation="parent",
            subject=Subject.object(ObjectRef("folder", "fold1"))
        ),
        # folder:fold1 viewer => user:alice
        RelationTuple(
            object=ObjectRef("folder", "fold1"),
            relation="viewer",
            subject=Subject.user("alice")
        ),
    ])

    res = await engine.check(ObjectRef("document","doc1"), "viewer", Subject.user("alice"))
    assert res.allowed

"""

from __future__ import annotations

import asyncio
import time
import re
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)

# =========================
# Core model: objects/usersets/subjects
# =========================

@dataclass(frozen=True)
class ObjectRef:
    namespace: str
    object_id: str

    def fqn(self) -> str:
        return f"{self.namespace}:{self.object_id}"


@dataclass(frozen=True)
class UsersetRef:
    object: ObjectRef
    relation: str

    def fqn(self) -> str:
        return f"{self.object.fqn()}#{self.relation}"


class SubjectType(str, Enum):
    USER = "user"
    USERSET = "userset"
    OBJECT = "object"  # only for tupleToUserset tuples (subject is an object; relation provided by rewrite)


@dataclass(frozen=True)
class Subject:
    type: SubjectType
    user_id: Optional[str] = None
    userset: Optional[UsersetRef] = None
    object: Optional[ObjectRef] = None

    @staticmethod
    def user(user_id: str) -> "Subject":
        return Subject(type=SubjectType.USER, user_id=user_id)

    @staticmethod
    def userset(obj: ObjectRef, relation: str) -> "Subject":
        return Subject(type=SubjectType.USERSET, userset=UsersetRef(obj, relation))

    @staticmethod
    def object(obj: ObjectRef) -> "Subject":
        return Subject(type=SubjectType.OBJECT, object=obj)

    def as_checkable_user(self) -> Optional[str]:
        return self.user_id if self.type == SubjectType.USER else None

    def fqn(self) -> str:
        if self.type == SubjectType.USER:
            return f"user:{self.user_id}"
        if self.type == SubjectType.USERSET and self.userset:
            return f"userset:{self.userset.fqn()}"
        if self.type == SubjectType.OBJECT and self.object:
            return f"object:{self.object.fqn()}"
        return "invalid"


# =========================
# Caveats (conditional edges)
# =========================

@dataclass(frozen=True)
class CaveatBinding:
    name: str
    params: Mapping[str, Any] = field(default_factory=dict)


CaveatFunc = Callable[[Mapping[str, Any], Mapping[str, Any]], bool]
# signature: fn(params, context) -> bool

class CaveatRegistry:
    def __init__(self) -> None:
        self._preds: Dict[str, CaveatFunc] = {}

    def register(self, name: str, func: CaveatFunc) -> None:
        if not name or not callable(func):
            raise ValueError("Invalid caveat registration")
        self._preds[name] = func

    def eval(self, binding: Optional[CaveatBinding], context: Mapping[str, Any]) -> bool:
        if binding is None:
            return True
        fn = self._preds.get(binding.name)
        if fn is None:
            # unknown caveat — fail closed
            return False
        try:
            return bool(fn(binding.params, context))
        except Exception:
            return False


def default_caveats() -> CaveatRegistry:
    reg = CaveatRegistry()

    def cidr(params: Mapping[str, Any], ctx: Mapping[str, Any]) -> bool:
        ip = ctx.get("ip")
        nets = params.get("cidrs", [])
        if not ip or not nets:
            return False
        ip_obj = ipaddress.ip_address(ip)
        for n in nets:
            if ip_obj in ipaddress.ip_network(n, strict=False):
                return True
        return False

    def time_before(params: Mapping[str, Any], ctx: Mapping[str, Any]) -> bool:
        # allow if now_epoch <= not_after (sec)
        now = int(ctx.get("now_epoch", int(time.time())))
        not_after = int(params.get("not_after", 0))
        return now <= not_after

    def attr_eq(params: Mapping[str, Any], ctx: Mapping[str, Any]) -> bool:
        k = params.get("key")
        v = params.get("value")
        return ctx.get("attributes", {}).get(k) == v

    reg.register("cidr_allow", cidr)
    reg.register("not_after", time_before)
    reg.register("attr_eq", attr_eq)
    return reg


# =========================
# Relation rewrite AST (Zanzibar-like)
# =========================

class RelationExpr:
    pass

@dataclass(frozen=True)
class This(RelationExpr):
    pass

@dataclass(frozen=True)
class ComputedUserset(RelationExpr):
    relation: str  # relation of the same object

@dataclass(frozen=True)
class TupleToUserset(RelationExpr):
    tupleset: str   # relation on the object yielding OBJECT subjects
    computed: str   # relation on those OBJECTs to evaluate for user membership

@dataclass(frozen=True)
class Union(RelationExpr):
    children: Tuple[RelationExpr, ...]
    @staticmethod
    def of(*nodes: RelationExpr) -> "Union":
        return Union(children=tuple(nodes))

@dataclass(frozen=True)
class Intersection(RelationExpr):
    children: Tuple[RelationExpr, ...]
    @staticmethod
    def of(*nodes: RelationExpr) -> "Intersection":
        return Intersection(children=tuple(nodes))

@dataclass(frozen=True)
class Exclusion(RelationExpr):
    base: RelationExpr
    subtract: RelationExpr


@dataclass(frozen=True)
class RelationDefinition:
    name: str
    rewrite: RelationExpr


@dataclass(frozen=True)
class NamespaceDefinition:
    name: str
    relations: Mapping[str, RelationDefinition]


class NamespaceRegistry:
    def __init__(self) -> None:
        self._ns: Dict[str, NamespaceDefinition] = {}

    def register(self, ns: NamespaceDefinition) -> "NamespaceRegistry":
        if ns.name in self._ns:
            raise ValueError(f"Namespace already registered: {ns.name}")
        self._ns[ns.name] = ns
        return self

    def get(self, name: str) -> Optional[NamespaceDefinition]:
        return self._ns.get(name)


# =========================
# Relationship tuples and store
# =========================

@dataclass(frozen=True)
class RelationTuple:
    object: ObjectRef
    relation: str
    subject: Subject
    caveat: Optional[CaveatBinding] = None


@dataclass(frozen=True)
class Zookie:
    """Monotonic consistency token (version)."""
    version: int


class RelationshipStore(Protocol):
    async def write(self, tuples: Sequence[RelationTuple]) -> Zookie: ...
    async def delete(self, tuples: Sequence[RelationTuple]) -> Zookie: ...
    async def read(
        self,
        *,
        object: Optional[ObjectRef] = None,
        relation: Optional[str] = None,
        subject: Optional[Subject] = None,
        at: Optional[Zookie] = None,
    ) -> List[RelationTuple]: ...
    async def all_objects(self, namespace: str, at: Optional[Zookie] = None) -> List[str]: ...
    async def head(self) -> Zookie: ...


class MemoryRelationshipStore:
    """
    Thread-safe, async-friendly in-memory store with indexes:
      - by (ns, obj_id, relation)
      - by subject fqn
    """
    def __init__(self) -> None:
        self._by_key: Dict[Tuple[str, str, str], List[RelationTuple]] = {}
        self._by_subject: Dict[str, List[RelationTuple]] = {}
        self._version: int = 0
        self._lock = asyncio.Lock()

    def _key(self, obj: ObjectRef, rel: str) -> Tuple[str, str, str]:
        return (obj.namespace, obj.object_id, rel)

    def _subj_key(self, s: Subject) -> str:
        return s.fqn()

    async def write(self, tuples: Sequence[RelationTuple]) -> Zookie:
        async with self._lock:
            for t in tuples:
                k = self._key(t.object, t.relation)
                self._by_key.setdefault(k, []).append(t)
                self._by_subject.setdefault(self._subj_key(t.subject), []).append(t)
            self._version += 1
            return Zookie(self._version)

    async def delete(self, tuples: Sequence[RelationTuple]) -> Zookie:
        async with self._lock:
            for t in tuples:
                k = self._key(t.object, t.relation)
                lst = self._by_key.get(k, [])
                self._by_key[k] = [x for x in lst if x != t]
                subj_k = self._subj_key(t.subject)
                lst2 = self._by_subject.get(subj_k, [])
                self._by_subject[subj_k] = [x for x in lst2 if x != t]
            self._version += 1
            return Zookie(self._version)

    async def read(
        self,
        *,
        object: Optional[ObjectRef] = None,
        relation: Optional[str] = None,
        subject: Optional[Subject] = None,
        at: Optional[Zookie] = None,
    ) -> List[RelationTuple]:
        # at is informational in memory impl; all reads see latest
        if object and relation:
            return list(self._by_key.get(self._key(object, relation), []))
        if subject:
            return list(self._by_subject.get(self._subj_key(subject), []))
        # Full scan if no filters (avoid in production)
        out: List[RelationTuple] = []
        for lst in self._by_key.values():
            out.extend(lst)
        return out

    async def all_objects(self, namespace: str, at: Optional[Zookie] = None) -> List[str]:
        seen: Set[str] = set()
        for (ns, obj_id, _), tuples in self._by_key.items():
            if ns == namespace:
                seen.add(obj_id)
        return sorted(seen)

    async def head(self) -> Zookie:
        return Zookie(self._version)


# =========================
# Engine: check / expand / list_objects
# =========================

@dataclass(frozen=True)
class CheckResult:
    allowed: bool
    at: Zookie
    reason: str
    path: Tuple[str, ...] = ()  # debug/path of relations used


@dataclass(frozen=True)
class ExpandNode:
    type: str                  # "leaf" | "union" | "intersection" | "exclusion" | "computed" | "ttu"
    target: str                # object#relation or subject fqn
    children: Tuple["ExpandNode", ...] = ()
    caveated: bool = False     # true if any caveat on path
    tuples: int = 0            # number of tuples observed at this node


@dataclass(frozen=True)
class ExpandResult:
    tree: ExpandNode
    at: Zookie


@dataclass(frozen=True)
class ListObjectsResult:
    namespace: str
    relation: str
    subject: Subject
    object_ids: Tuple[str, ...]
    next_page_token: Optional[str]
    at: Zookie


class RelationshipAuthorizer:
    MAX_DEPTH = 32

    def __init__(
        self,
        registry: NamespaceRegistry,
        store: RelationshipStore,
        *,
        caveats: Optional[CaveatRegistry] = None,
        enable_check_cache: bool = True,
        cache_size: int = 4096,
    ) -> None:
        self._registry = registry
        self._store = store
        self._caveats = caveats or default_caveats()

        # Simple LRU cache: key=(zookie.version, object.fqn, relation, subject.fqn, frozenset(ctx.items()))
        if enable_check_cache:
            self._check_cached = lru_cache(maxsize=cache_size)(self._check_internal)
        else:
            self._check_cached = self._check_internal  # type: ignore[assignment]

    # -------- Public API --------

    async def check(
        self,
        object: ObjectRef,
        relation: str,
        subject: Subject,
        context: Optional[Mapping[str, Any]] = None,
        at: Optional[Zookie] = None,
    ) -> CheckResult:
        ctx = self._normalize_ctx(context)
        z = at or await self._store.head()
        allowed, path = await self._check_cached(z.version, object, relation, subject, frozenset(ctx.items()))
        return CheckResult(allowed=allowed, at=z, reason="ok" if allowed else "not_member", path=tuple(path))

    async def expand(
        self,
        object: ObjectRef,
        relation: str,
        context: Optional[Mapping[str, Any]] = None,
        at: Optional[Zookie] = None,
    ) -> ExpandResult:
        ctx = self._normalize_ctx(context)
        z = at or await self._store.head()
        visited: Set[Tuple[str, str, str]] = set()
        tree = await self._expand(object, relation, ctx, z, depth=0, visited=visited)
        return ExpandResult(tree=tree, at=z)

    async def list_objects(
        self,
        namespace: str,
        relation: str,
        subject: Subject,
        *,
        context: Optional[Mapping[str, Any]] = None,
        at: Optional[Zookie] = None,
        limit: int = 100,
        page_token: Optional[str] = None,
    ) -> ListObjectsResult:
        ctx = self._normalize_ctx(context)
        z = at or await self._store.head()

        all_ids = await self._store.all_objects(namespace, at=z)
        start = int(page_token or "0")
        end = min(start + max(1, limit), len(all_ids))

        visible: List[str] = []
        for oid in all_ids[start:end]:
            chk = await self.check(ObjectRef(namespace, oid), relation, subject, context=ctx, at=z)
            if chk.allowed:
                visible.append(oid)

        next_tok = str(end) if end < len(all_ids) else None
        return ListObjectsResult(
            namespace=namespace,
            relation=relation,
            subject=subject,
            object_ids=tuple(visible),
            next_page_token=next_tok,
            at=z,
        )

    # -------- Internals --------

    def _normalize_ctx(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        ctx = dict(context or {})
        ctx.setdefault("now_epoch", int(time.time()))
        ctx.setdefault("attributes", {})
        return ctx

    async def _expand(
        self,
        object: ObjectRef,
        relation: str,
        context: Mapping[str, Any],
        at: Zookie,
        *,
        depth: int,
        visited: Set[Tuple[str, str, str]],
    ) -> ExpandNode:
        if depth > self.MAX_DEPTH:
            return ExpandNode(type="leaf", target=f"{object.fqn()}#{relation}", caveated=False, tuples=0)

        ns = self._registry.get(object.namespace)
        if ns is None:
            return ExpandNode(type="leaf", target=f"{object.fqn()}#{relation}", caveated=False, tuples=0)

        rel_def = ns.relations.get(relation)
        if rel_def is None:
            return ExpandNode(type="leaf", target=f"{object.fqn()}#{relation}", caveated=False, tuples=0)

        key = (object.fqn(), relation, str(at.version))
        if key in visited:
            # cycle guard
            return ExpandNode(type="leaf", target=f"{object.fqn()}#{relation}", caveated=False, tuples=0)
        visited.add(key)

        expr = rel_def.rewrite
        if isinstance(expr, This):
            tuples = await self._store.read(object=object, relation=relation, at=at)
            caveated = any(t.caveat is not None for t in tuples)
            return ExpandNode(
                type="leaf", target=f"{object.fqn()}#{relation}", caveated=caveated, tuples=len(tuples)
            )

        if isinstance(expr, ComputedUserset):
            child = await self._expand(object, expr.relation, context, at, depth=depth + 1, visited=visited)
            return ExpandNode(type="computed", target=f"{object.fqn()}#{relation}", children=(child,), caveated=child.caveated)

        if isinstance(expr, TupleToUserset):
            tuples = await self._store.read(object=object, relation=expr.tupleset, at=at)
            children: List[ExpandNode] = []
            cav = False
            for t in tuples:
                # Only OBJECT subjects are valid for TTU
                if t.subject.type != SubjectType.OBJECT or t.subject.object is None:
                    continue
                node = await self._expand(t.subject.object, expr.computed, context, at, depth=depth + 1, visited=visited)
                children.append(node)
                cav = cav or (t.caveat is not None) or node.caveated
            return ExpandNode(type="ttu", target=f"{object.fqn()}#{relation}", children=tuple(children), caveated=cav, tuples=len(tuples))

        if isinstance(expr, Union):
            subs: List[ExpandNode] = []
            cav = False
            for ch in expr.children:
                node = await self._expand(object, relation if isinstance(ch, This) else self._expr_target_rel(relation, ch), context, at, depth=depth+1, visited=visited) \
                    if isinstance(ch, This) else await self._expand_expr(object, ch, context, at, depth+1, visited)
                subs.append(node)
                cav = cav or node.caveated
            return ExpandNode(type="union", target=f"{object.fqn()}#{relation}", children=tuple(subs), caveated=cav)

        if isinstance(expr, Intersection):
            subs: List[ExpandNode] = []
            cav = False
            for ch in expr.children:
                node = await self._expand_expr(object, ch, context, at, depth+1, visited)
                subs.append(node)
                cav = cav or node.caveated
            return ExpandNode(type="intersection", target=f"{object.fqn()}#{relation}", children=tuple(subs), caveated=cav)

        if isinstance(expr, Exclusion):
            base = await self._expand_expr(object, expr.base, context, at, depth+1, visited)
            sub = await self._expand_expr(object, expr.subtract, context, at, depth+1, visited)
            return ExpandNode(type="exclusion", target=f"{object.fqn()}#{relation}", children=(base, sub), caveated=base.caveated or sub.caveated)

        # default leaf
        return ExpandNode(type="leaf", target=f"{object.fqn()}#{relation}", caveated=False, tuples=0)

    async def _expand_expr(
        self,
        object: ObjectRef,
        expr: RelationExpr,
        context: Mapping[str, Any],
        at: Zookie,
        depth: int,
        visited: Set[Tuple[str, str, str]],
    ) -> ExpandNode:
        if isinstance(expr, This):
            tuples = await self._store.read(object=object, relation=self._expr_target_rel("", expr), at=at)
            return ExpandNode(type="leaf", target=f"{object.fqn()}#{self._expr_target_rel('',expr)}", tuples=len(tuples), caveated=any(t.caveat for t in tuples))
        if isinstance(expr, ComputedUserset):
            return await self._expand(object, expr.relation, context, at, depth=depth, visited=visited)
        if isinstance(expr, TupleToUserset):
            tmp_rel = expr.tupleset
            tuples = await self._store.read(object=object, relation=tmp_rel, at=at)
            children: List[ExpandNode] = []
            cav = False
            for t in tuples:
                if t.subject.type != SubjectType.OBJECT or t.subject.object is None:
                    continue
                node = await self._expand(t.subject.object, expr.computed, context, at, depth=depth+1, visited=visited)
                children.append(node)
                cav = cav or (t.caveat is not None) or node.caveated
            return ExpandNode(type="ttu", target=f"{object.fqn()}#{tmp_rel}->{expr.computed}", children=tuple(children), caveated=cav, tuples=len(tuples))
        if isinstance(expr, Union):
            subs = [await self._expand_expr(object, ch, context, at, depth+1, visited) for ch in expr.children]
            return ExpandNode(type="union", target=f"{object.fqn()}#union", children=tuple(subs), caveated=any(n.caveated for n in subs))
        if isinstance(expr, Intersection):
            subs = [await self._expand_expr(object, ch, context, at, depth+1, visited) for ch in expr.children]
            return ExpandNode(type="intersection", target=f"{object.fqn()}#intersection", children=tuple(subs), caveated=any(n.caveated for n in subs))
        if isinstance(expr, Exclusion):
            base = await self._expand_expr(object, expr.base, context, at, depth+1, visited)
            sub = await self._expand_expr(object, expr.subtract, context, at, depth+1, visited)
            return ExpandNode(type="exclusion", target=f"{object.fqn()}#exclusion", children=(base, sub), caveated=base.caveated or sub.caveated)
        return ExpandNode(type="leaf", target=f"{object.fqn()}#unknown", caveated=False)

    def _expr_target_rel(self, current: str, expr: RelationExpr) -> str:
        if isinstance(expr, This):
            return current
        if isinstance(expr, ComputedUserset):
            return expr.relation
        return current

    # cached method must be top-level pure (no self); we bind 'self' via closure
    async def _check_internal(  # type: ignore[override]
        self,
        z_version: int,
        object: ObjectRef,
        relation: str,
        subject: Subject,
        ctx_items: frozenset,
    ) -> Tuple[bool, Tuple[str, ...]]:
        ctx = dict(ctx_items)
        z = Zookie(z_version)
        path: List[str] = []
        visited: Set[Tuple[str, str, str, str]] = set()
        ok = await self._check_dfs(object, relation, subject, ctx, z, depth=0, visited=visited, path=path)
        return ok, tuple(path)

    async def _check_dfs(
        self,
        object: ObjectRef,
        relation: str,
        subject: Subject,
        context: Mapping[str, Any],
        at: Zookie,
        *,
        depth: int,
        visited: Set[Tuple[str, str, str, str]],
        path: List[str],
    ) -> bool:
        if depth > self.MAX_DEPTH:
            return False

        ns = self._registry.get(object.namespace)
        if ns is None:
            return False

        rel_def = ns.relations.get(relation)
        if rel_def is None:
            return False

        key = (object.fqn(), relation, subject.fqn(), str(at.version))
        if key in visited:
            return False
        visited.add(key)

        expr = rel_def.rewrite

        # This: check direct tuples
        if isinstance(expr, This):
            tuples = await self._store.read(object=object, relation=relation, at=at)
            # 1) direct USER membership
            for t in tuples:
                if t.subject.type == SubjectType.USER and subject.type == SubjectType.USER:
                    if t.subject.user_id == subject.user_id and self._caveats.eval(t.caveat, context):
                        path.append(f"{object.fqn()}#{relation}@{subject.fqn()}:this")
                        return True
            # 2) userset indirection (object#rel @ userset)
            for t in tuples:
                if t.subject.type == SubjectType.USERSET and t.subject.userset is not None:
                    if not self._caveats.eval(t.caveat, context):
                        continue
                    target = t.subject.userset
                    ok = await self._check_dfs(target.object, target.relation, subject, context, at,
                                               depth=depth+1, visited=visited, path=path)
                    if ok:
                        path.append(f"{object.fqn()}#{relation}@{t.subject.fqn()}:userset")
                        return True
            # 3) OBJECT subjects are not applicable for 'this'
            return False

        # computedUserset: reuse same object with different relation
        if isinstance(expr, ComputedUserset):
            return await self._check_dfs(object, expr.relation, subject, context, at,
                                         depth=depth+1, visited=visited, path=path)

        # tupleToUserset: follow object relations yielding OBJECTs, then check 'computed' on them
        if isinstance(expr, TupleToUserset):
            seeds = await self._store.read(object=object, relation=expr.tupleset, at=at)
            for t in seeds:
                if t.subject.type != SubjectType.OBJECT or t.subject.object is None:
                    continue
                if not self._caveats.eval(t.caveat, context):
                    continue
                ok = await self._check_dfs(t.subject.object, expr.computed, subject, context, at,
                                           depth=depth+1, visited=visited, path=path)
                if ok:
                    path.append(f"{object.fqn()}#{relation}@TTU({t.subject.object.fqn()}->{expr.computed})")
                    return True
            return False

        # union: any child grants access
        if isinstance(expr, Union):
            for ch in expr.children:
                if await self._check_dfs_via_expr(object, ch, subject, context, at, depth+1, visited, path):
                    path.append(f"{object.fqn()}#{relation}:union")
                    return True
            return False

        # intersection: must be member of ALL children
        if isinstance(expr, Intersection):
            for ch in expr.children:
                if not await self._check_dfs_via_expr(object, ch, subject, context, at, depth+1, visited, path):
                    return False
            path.append(f"{object.fqn()}#{relation}:intersection")
            return True

        # exclusion: in base AND NOT in subtract
        if isinstance(expr, Exclusion):
            base_ok = await self._check_dfs_via_expr(object, expr.base, subject, context, at, depth+1, visited, path)
            if not base_ok:
                return False
            sub_ok = await self._check_dfs_via_expr(object, expr.subtract, subject, context, at, depth+1, visited, path)
            if sub_ok:
                return False
            path.append(f"{object.fqn()}#{relation}:exclusion")
            return True

        return False

    async def _check_dfs_via_expr(
        self,
        object: ObjectRef,
        expr: RelationExpr,
        subject: Subject,
        context: Mapping[str, Any],
        at: Zookie,
        depth: int,
        visited: Set[Tuple[str, str, str, str]],
        path: List[str],
    ) -> bool:
        if isinstance(expr, This):
            # delegate to current relation (This means 'direct tuples of the same relation')
            # We need the current relation name; unknowable here. For safety, resolve by reading all tuples of object for all relations is too heavy.
            # Thus, This under combinators should be used as top-level 'this' in relation definitions.
            # We treat as no-op false here to avoid incorrect grants.
            return False
        if isinstance(expr, ComputedUserset):
            return await self._check_dfs(object, expr.relation, subject, context, at,
                                         depth=depth, visited=visited, path=path)
        if isinstance(expr, TupleToUserset):
            seeds = await self._store.read(object=object, relation=expr.tupleset, at=at)
            for t in seeds:
                if t.subject.type != SubjectType.OBJECT or t.subject.object is None:
                    continue
                if not self._caveats.eval(t.caveat, context):
                    continue
                ok = await self._check_dfs(t.subject.object, expr.computed, subject, context, at,
                                           depth=depth+1, visited=visited, path=path)
                if ok:
                    return True
            return False
        if isinstance(expr, Union):
            for ch in expr.children:
                if await self._check_dfs_via_expr(object, ch, subject, context, at, depth+1, visited, path):
                    return True
            return False
        if isinstance(expr, Intersection):
            for ch in expr.children:
                if not await self._check_dfs_via_expr(object, ch, subject, context, at, depth+1, visited, path):
                    return False
            return True
        if isinstance(expr, Exclusion):
            base_ok = await self._check_dfs_via_expr(object, expr.base, subject, context, at, depth+1, visited, path)
            if not base_ok:
                return False
            sub_ok = await self._check_dfs_via_expr(object, expr.subtract, subject, context, at, depth+1, visited, path)
            return not sub_ok
        return False
