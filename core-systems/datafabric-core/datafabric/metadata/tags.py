# path: datafabric-core/datafabric/metadata/tags.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Tagging Module for Data Fabric

Key capabilities:
- Strongly-typed tag model: namespace:key[=value] with typed values (str,int,float,bool,null)
- Validation & normalization with configurable policies
- Immutable revisions with ETag (content hash) and monotonic version
- Protected namespaces and keys, deny-by-default for mutations
- Tag expressions: AND/OR/NOT, parentheses, ==, !=, IN, HAS, EXISTS, prefix match "starts_with"
- Async-first TagStore with thread-safe InMemoryTagStore
- Batch assign/remove with idempotency and optimistic concurrency
- Structured audit sink and snapshots export
- Deterministic parser for tag expressions (recursive-descent)

No external dependencies. Python 3.10+.
"""

from __future__ import annotations

import abc
import asyncio
import dataclasses
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

__all__ = [
    "TagType",
    "TagValue",
    "TagKey",
    "Tag",
    "TagAssignment",
    "TagSet",
    "TagMutation",
    "TagDiff",
    "TagQueryAst",
    "TagQueryOp",
    "TagExpressionParser",
    "TagPolicy",
    "TagValidationError",
    "TagConcurrencyError",
    "TagNotFound",
    "AuditSink",
    "LoggingAuditSink",
    "TagStore",
    "InMemoryTagStore",
    "compute_etag",
    "normalize_key",
    "normalize_value",
]

# ---------- Errors ----------

class TagValidationError(Exception):
    """Invalid tag or key/value."""


class TagConcurrencyError(Exception):
    """Version/ETag mismatch on mutation."""


class TagNotFound(Exception):
    """Entity not found in tag store."""


# ---------- Models ----------

class TagType(Enum):
    STRING = auto()
    INT = auto()
    FLOAT = auto()
    BOOL = auto()
    NULL = auto()


Primitive = Union[str, int, float, bool, None]


@dataclass(frozen=True)
class TagValue:
    """
    Typed value wrapper for tag values.
    """
    type: TagType
    value: Primitive

    def as_primitive(self) -> Primitive:
        return self.value

    def to_json_value(self) -> Primitive:
        return self.value


_KEY_RE = re.compile(r"^(?P<ns>[a-z][a-z0-9_.-]{1,62})[:/](?P<key>[a-z][a-z0-9_.-]{1,62})$")


@dataclass(frozen=True)
class TagKey:
    """
    Fully-qualified key: "<namespace>:<key>" or "<namespace>/<key>".
    """
    namespace: str
    key: str

    @property
    def fq(self) -> str:
        return f"{self.namespace}:{self.key}"

    def __str__(self) -> str:
        return self.fq


@dataclass(frozen=True)
class Tag:
    """
    Concrete tag: key + optional typed value + synthetic id.
    """
    key: TagKey
    value: Optional[TagValue] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class TagAssignment:
    """
    Assignment of tags to a resource (entity).
    Version is monotonic. ETag computed from canonical JSON.
    """
    entity_id: str
    tags: Tuple[Tag, ...]
    version: int
    etag: str
    updated_at: datetime
    updated_by: str
    immutable_rev_id: str


@dataclass(frozen=True)
class TagSet:
    """
    Mutable-free view used by clients.
    """
    entity_id: str
    tags: Mapping[str, Primitive]  # fq key -> primitive
    version: int
    etag: str
    updated_at: datetime


@dataclass(frozen=True)
class TagMutation:
    """
    Declarative mutation: add/remove/replace for idempotent operations.
    If etag is supplied, optimistic concurrency is enforced.
    """
    entity_id: str
    adds: Mapping[str, Primitive] = field(default_factory=dict)      # fq -> value (or None)
    removes: Sequence[str] = field(default_factory=tuple)            # fq keys to remove
    replace: bool = False
    expected_etag: Optional[str] = None
    actor: str = "system"


@dataclass(frozen=True)
class TagDiff:
    added: Mapping[str, Primitive]
    removed: Mapping[str, Primitive]
    changed: Mapping[str, Tuple[Primitive, Primitive]]  # old, new


# ---------- Audit ----------

class AuditSink(abc.ABC):
    @abc.abstractmethod
    async def emit(self, event: Mapping[str, Any]) -> None:
        ...


class LoggingAuditSink(AuditSink):
    def __init__(self, logger: Optional[logging.Logger] = None, level: int = logging.INFO) -> None:
        self._logger = logger or logging.getLogger("datafabric.metadata.tags.audit")
        self._level = level

    async def emit(self, event: Mapping[str, Any]) -> None:
        self._logger.log(self._level, "TAGS_AUDIT %s", event)


# ---------- Validation & Normalization ----------

_RESERVED_NAMESPACES = frozenset({
    "df.sys", "df.sec", "pii", "sox", "gdpr", "iso27001", "hipaa", "phi", "pci",
})

_PROTECTED_KEYS = frozenset({
    "classification", "sensitivity", "owner", "retention", "legal_hold",
})

def normalize_key(s: str) -> TagKey:
    """
    Validate and normalize a fully-qualified key.
    Supports separators ":" and "/".
    """
    if not isinstance(s, str):
        raise TagValidationError("Key must be string")
    s = s.strip()
    s = s.replace("/", ":", 1)  # normalize first separator
    m = _KEY_RE.match(s)
    if not m:
        raise TagValidationError(f"Invalid key: {s}")
    ns = m.group("ns")
    key = m.group("key")
    return TagKey(namespace=ns, key=key)


def _coerce_value(v: Primitive) -> TagValue:
    if v is None:
        return TagValue(TagType.NULL, None)
    if isinstance(v, bool):
        return TagValue(TagType.BOOL, v)
    if isinstance(v, int) and not isinstance(v, bool):
        return TagValue(TagType.INT, int(v))
    if isinstance(v, float):
        if not (float("-inf") < v < float("inf")):
            raise TagValidationError("Float value must be finite")
        return TagValue(TagType.FLOAT, float(v))
    if isinstance(v, str):
        if len(v) > 1024:
            raise TagValidationError("String value too long")
        return TagValue(TagType.STRING, v)
    raise TagValidationError(f"Unsupported value type: {type(v)}")


def normalize_value(v: Primitive) -> TagValue:
    return _coerce_value(v)


@dataclass(frozen=True)
class TagPolicy:
    """
    Policy defining mutability and namespace/key protections.
    """
    protected_namespaces: frozenset[str] = _RESERVED_NAMESPACES
    protected_keys: frozenset[str] = _PROTECTED_KEYS
    allow_unset_null: bool = True   # allow writing key with NULL to indicate presence without value
    deny_mutations: bool = False    # global freeze


# ---------- ETag / hashing ----------

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_etag(entity_id: str, mapping: Mapping[str, Primitive], version: int) -> str:
    payload = {
        "entity": entity_id,
        "version": version,
        "tags": {k: mapping[k] for k in sorted(mapping.keys())},
    }
    raw = _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ---------- Tag query language ----------

class TagQueryOp(Enum):
    AND = auto()
    OR = auto()
    NOT = auto()
    CMP = auto()   # comparison: ==, !=
    IN = auto()
    HAS = auto()   # has key (presence)
    EXISTS = auto()  # alias to HAS
    STARTS_WITH = auto()


@dataclass(frozen=True)
class TagQueryAst:
    op: TagQueryOp
    left: Optional["TagQueryAst"] = None
    right: Optional["TagQueryAst"] = None
    key: Optional[TagKey] = None
    value: Optional[Primitive] = None
    values: Optional[Tuple[Primitive, ...]] = None
    cmp: Optional[str] = None  # '==' or '!='


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)|
    (?P<lpar>\()|(?P<rpar>\))|
    (?P<op_and>\bAND\b)|(?P<op_or>\bOR\b)|(?P<op_not>\bNOT\b)|
    (?P<cmp_eq>==)|(?P<cmp_ne>!=)|
    (?P<in>\bIN\b)|(?P<has>\bHAS\b)|(?P<exists>\bEXISTS\b)|(?P<starts>\bSTARTS_WITH\b)|
    (?P<comma>,)|
    (?P<string>'[^']*'|"[^"]*")|
    (?P<number>-?\d+(?:\.\d+)?)|
    (?P<key>[a-z][a-z0-9_.-]{1,62}[:/][a-z][a-z0-9_.-]{1,62})
    """,
    re.VERBOSE | re.IGNORECASE,
)

class _Lexer:
    def __init__(self, s: str) -> None:
        self.s = s
        self.pos = 0
        self.tokens: List[Tuple[str, str]] = []
        self._tokenize()

    def _tokenize(self) -> None:
        while self.pos < len(self.s):
            m = _TOKEN_RE.match(self.s, self.pos)
            if not m:
                raise TagValidationError(f"Unexpected token near: {self.s[self.pos:self.pos+16]}")
            self.pos = m.end()
            kind = m.lastgroup or ""
            text = m.group(kind)
            if kind == "ws":
                continue
            if kind == "string":
                # strip quotes
                if text[0] == "'" and text[-1] == "'":
                    text = text[1:-1]
                elif text[0] == '"' and text[-1] == '"':
                    text = text[1:-1]
            self.tokens.append((kind, text))

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[0] if self.tokens else None

    def pop(self, expect: Optional[str] = None) -> Tuple[str, str]:
        if not self.tokens:
            raise TagValidationError("Unexpected end of expression")
        tok = self.tokens.pop(0)
        if expect and tok[0] != expect:
            raise TagValidationError(f"Expected {expect}, got {tok[0]}")
        return tok


class TagExpressionParser:
    """
    Recursive-descent parser: supports precedence NOT > AND > OR.
    """

    def parse(self, expr: str) -> TagQueryAst:
        lx = _Lexer(expr)
        node = self._parse_or(lx)
        if lx.peek() is not None:
            raise TagValidationError("Extra tokens at end of expression")
        return node

    def _parse_or(self, lx: _Lexer) -> TagQueryAst:
        node = self._parse_and(lx)
        while lx.peek() and lx.peek()[0] == "op_or":
            lx.pop()
            rhs = self._parse_and(lx)
            node = TagQueryAst(TagQueryOp.OR, left=node, right=rhs)
        return node

    def _parse_and(self, lx: _Lexer) -> TagQueryAst:
        node = self._parse_unary(lx)
        while lx.peek() and lx.peek()[0] == "op_and":
            lx.pop()
            rhs = self._parse_unary(lx)
            node = TagQueryAst(TagQueryOp.AND, left=node, right=rhs)
        return node

    def _parse_unary(self, lx: _Lexer) -> TagQueryAst:
        tok = lx.peek()
        if tok and tok[0] == "op_not":
            lx.pop()
            inner = self._parse_unary(lx)
            return TagQueryAst(TagQueryOp.NOT, left=inner)
        if tok and tok[0] == "lpar":
            lx.pop()
            node = self._parse_or(lx)
            lx.pop("rpar")
            return node
        return self._parse_atom(lx)

    def _parse_atom(self, lx: _Lexer) -> TagQueryAst:
        # forms:
        # key HAS
        # key EXISTS
        # key STARTS_WITH 'prefix'
        # key == value
        # key != value
        # key IN (v1, v2, ...)
        kind, text = lx.pop()
        if kind != "key":
            raise TagValidationError("Expected key")
        key = normalize_key(text)

        nxt = lx.peek()
        if not nxt:
            # presence
            return TagQueryAst(TagQueryOp.HAS, key=key)

        if nxt[0] in ("has", "exists"):
            lx.pop()
            return TagQueryAst(TagQueryOp.HAS, key=key)

        if nxt[0] == "starts":
            lx.pop()
            k, v = lx.pop()
            if k not in ("string",):
                raise TagValidationError("STARTS_WITH expects string")
            return TagQueryAst(TagQueryOp.STARTS_WITH, key=key, value=v)

        if nxt[0] in ("cmp_eq", "cmp_ne"):
            cmp_tok = lx.pop()[0]
            val = self._parse_value(lx)
            return TagQueryAst(TagQueryOp.CMP, key=key, value=val, cmp="==" if cmp_tok == "cmp_eq" else "!=")

        if nxt[0] == "in":
            lx.pop()
            lx.pop("lpar")
            values: List[Primitive] = []
            while True:
                values.append(self._parse_value(lx))
                if lx.peek() and lx.peek()[0] == "comma":
                    lx.pop()
                    continue
                break
            lx.pop("rpar")
            return TagQueryAst(TagQueryOp.IN, key=key, values=tuple(values))

        raise TagValidationError("Unsupported operator")

    def _parse_value(self, lx: _Lexer) -> Primitive:
        kind, text = lx.pop()
        if kind == "string":
            return text
        if kind == "number":
            if "." in text:
                return float(text)
            return int(text)
        if kind == "key":
            # allow value referencing other key string representation
            return normalize_key(text).fq
        # allow bare keywords true/false/null via lexer? Not tokenized; accept string forms
        if kind.upper() in ("TRUE", "FALSE", "NULL"):
            if text.lower() == "true":
                return True
            if text.lower() == "false":
                return False
            return None
        raise TagValidationError(f"Unsupported value token: {kind}")


# ---------- Evaluation of expressions ----------

def _eval_ast(astn: TagQueryAst, mapping: Mapping[str, Primitive]) -> bool:
    if astn.op == TagQueryOp.AND:
        return _eval_ast(astn.left, mapping) and _eval_ast(astn.right, mapping)  # type: ignore
    if astn.op == TagQueryOp.OR:
        return _eval_ast(astn.left, mapping) or _eval_ast(astn.right, mapping)  # type: ignore
    if astn.op == TagQueryOp.NOT:
        return not _eval_ast(astn.left, mapping)  # type: ignore
    fq = astn.key.fq if astn.key else ""
    if astn.op in (TagQueryOp.HAS, TagQueryOp.EXISTS):
        return fq in mapping
    if astn.op == TagQueryOp.STARTS_WITH:
        v = mapping.get(fq)
        return isinstance(v, str) and isinstance(astn.value, str) and v.startswith(astn.value)
    if astn.op == TagQueryOp.CMP:
        left = mapping.get(fq, None)
        if astn.cmp == "==":
            return left == astn.value
        return left != astn.value
    if astn.op == TagQueryOp.IN:
        left = mapping.get(fq, None)
        return left in (astn.values or ())
    return False


# ---------- Store interfaces ----------

class TagStore(abc.ABC):
    """
    Async-first store for tag assignments.
    """

    @abc.abstractmethod
    async def get(self, entity_id: str) -> TagSet:
        ...

    @abc.abstractmethod
    async def mutate(self, mutation: TagMutation, *, policy: Optional[TagPolicy] = None) -> Tuple[TagSet, TagDiff]:
        ...

    @abc.abstractmethod
    async def query(self, expr: str, *, limit: int = 1000) -> Sequence[TagSet]:
        ...

    @abc.abstractmethod
    async def snapshot(self) -> Sequence[TagSet]:
        ...


class InMemoryTagStore(TagStore):
    """
    Thread-safe in-memory implementation with optimistic concurrency.
    """

    def __init__(self, *, audit_sink: Optional[AuditSink] = None, policy: Optional[TagPolicy] = None) -> None:
        self._items: Dict[str, TagAssignment] = {}
        self._lock = threading.RLock()
        self._audit = audit_sink or LoggingAuditSink()
        self._policy = policy or TagPolicy()

    async def get(self, entity_id: str) -> TagSet:
        with self._lock:
            current = self._items.get(entity_id)
            if not current:
                raise TagNotFound(entity_id)
            return _assignment_to_view(current)

    async def mutate(self, mutation: TagMutation, *, policy: Optional[TagPolicy] = None) -> Tuple[TagSet, TagDiff]:
        pol = policy or self._policy
        if pol.deny_mutations:
            raise TagValidationError("Mutations are disabled by policy")

        with self._lock:
            current = self._items.get(mutation.entity_id)
            # current view
            cur_map: Dict[str, Primitive] = {}
            cur_version = 0
            if current:
                cur_map = {t.key.fq: (t.value.as_primitive() if t.value else None) for t in current.tags}
                cur_version = current.version
            if mutation.expected_etag and current and mutation.expected_etag != current.etag:
                raise TagConcurrencyError("ETag mismatch")

            # start from either empty or replace
            new_map: Dict[str, Primitive] = {} if mutation.replace else dict(cur_map)

            # apply removes
            for fq in mutation.removes:
                k = normalize_key(fq)
                _enforce_protection(pol, k)
                new_map.pop(k.fq, None)

            # apply adds
            for fq, pv in mutation.adds.items():
                k = normalize_key(fq)
                _enforce_protection(pol, k)
                val = normalize_value(pv) if pv is not None else (TagValue(TagType.NULL, None) if pol.allow_unset_null else None)
                if val is None:
                    raise TagValidationError("NULL values disabled by policy")
                new_map[k.fq] = val.as_primitive()

            # compute diff
            added: Dict[str, Primitive] = {}
            removed: Dict[str, Primitive] = {}
            changed: Dict[str, Tuple[Primitive, Primitive]] = {}
            for k in new_map.keys() - cur_map.keys():
                added[k] = new_map[k]
            for k in cur_map.keys() - new_map.keys():
                removed[k] = cur_map[k]
            for k in new_map.keys() & cur_map.keys():
                if new_map[k] != cur_map[k]:
                    changed[k] = (cur_map[k], new_map[k])

            new_version = cur_version + 1
            etag = compute_etag(mutation.entity_id, new_map, new_version)
            assignment = _map_to_assignment(
                mutation.entity_id,
                new_map,
                version=new_version,
                etag=etag,
                actor=mutation.actor,
            )
            self._items[mutation.entity_id] = assignment

        await self._audit.emit({
            "ts": datetime.now(timezone.utc).isoformat(),
            "entity": mutation.entity_id,
            "version": new_version,
            "etag": etag,
            "actor": mutation.actor,
            "added": added,
            "removed": removed,
            "changed": changed,
        })
        return _assignment_to_view(assignment), TagDiff(added=added, removed=removed, changed=changed)

    async def query(self, expr: str, *, limit: int = 1000) -> Sequence[TagSet]:
        parser = TagExpressionParser()
        astn = parser.parse(expr)
        out: List[TagSet] = []
        with self._lock:
            for entity_id, assign in self._items.items():
                mapping = {t.key.fq: (t.value.as_primitive() if t.value else None) for t in assign.tags}
                if _eval_ast(astn, mapping):
                    out.append(_assignment_to_view(assign))
                if len(out) >= max(1, limit):
                    break
        return out

    async def snapshot(self) -> Sequence[TagSet]:
        with self._lock:
            return [_assignment_to_view(a) for a in self._items.values()]


# ---------- Helpers ----------

def _enforce_protection(policy: TagPolicy, key: TagKey) -> None:
    if key.namespace in policy.protected_namespaces or key.key in policy.protected_keys:
        raise TagValidationError(f"Key is protected: {key.fq}")


def _assignment_to_view(assign: TagAssignment) -> TagSet:
    mapping = {t.key.fq: (t.value.as_primitive() if t.value else None) for t in assign.tags}
    return TagSet(
        entity_id=assign.entity_id,
        tags=mapping,
        version=assign.version,
        etag=assign.etag,
        updated_at=assign.updated_at,
    )


def _map_to_assignment(entity_id: str, mapping: Mapping[str, Primitive], *, version: int, etag: str, actor: str) -> TagAssignment:
    tags: List[Tag] = []
    for fq in sorted(mapping.keys()):
        k = normalize_key(fq)
        v = normalize_value(mapping[fq])
        tags.append(Tag(key=k, value=v))
    return TagAssignment(
        entity_id=entity_id,
        tags=tuple(tags),
        version=version,
        etag=etag,
        updated_at=datetime.now(timezone.utc),
        updated_by=actor,
        immutable_rev_id=uuid.uuid4().hex,
    )


# ---------- Module self-check ----------

async def _self_check() -> bool:
    """
    Sanity run: create store, assign, query and mutate.
    """
    store = InMemoryTagStore()
    ent = "dataset:123"
    v1, _ = await store.mutate(TagMutation(entity_id=ent, adds={
        "df.meta:owner": "team-ml",
        "df.meta:domain": "sales",
        "df.meta:records": 100,
    }))
    # Query
    res = await store.query("df.meta:owner == 'team-ml' AND df.meta:records IN (100,200)")
    ok1 = len(res) == 1 and res[0].entity_id == ent
    # Concurrency
    try:
        await store.mutate(TagMutation(entity_id=ent, adds={"df.meta:quality": "gold"}, expected_etag="bad"))
        return False
    except TagConcurrencyError:
        pass
    v2, diff = await store.mutate(TagMutation(entity_id=ent, adds={"df.meta:quality": "gold"}, expected_etag=v1.etag))
    ok2 = "df.meta:quality" in v2.tags and "df.meta:quality" in diff.added
    return ok1 and ok2


# ---------- Export guard ----------

def _export_guard() -> None:
    names = set(__all__)
    must = {
        "TagType","TagValue","TagKey","Tag","TagAssignment","TagSet","TagMutation","TagDiff",
        "TagQueryAst","TagQueryOp","TagExpressionParser","TagPolicy",
        "TagValidationError","TagConcurrencyError","TagNotFound",
        "AuditSink","LoggingAuditSink","TagStore","InMemoryTagStore",
        "compute_etag","normalize_key","normalize_value",
    }
    missing = sorted(must - names)
    if missing:
        raise RuntimeError(f"Missing exports: {missing}")


_export_guard()
