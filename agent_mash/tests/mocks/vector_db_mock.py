# agent_mash/tests/mocks/vector_db_mock.py
from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class VectorDBMockError(Exception):
    pass


class VectorValidationError(VectorDBMockError):
    pass


class NotFoundError(VectorDBMockError):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _validate_vector(vec: Sequence[float], dim: Optional[int]) -> Tuple[int, List[float]]:
    if not isinstance(vec, (list, tuple)):
        raise VectorValidationError("vector must be a list or tuple of numbers")
    if len(vec) == 0:
        raise VectorValidationError("vector must be non-empty")
    out: List[float] = []
    for v in vec:
        if not _is_number(v):
            raise VectorValidationError("vector must contain only numbers")
        fv = float(v)
        if math.isnan(fv) or math.isinf(fv):
            raise VectorValidationError("vector must not contain NaN or Inf")
        out.append(fv)

    if dim is not None and len(out) != dim:
        raise VectorValidationError(f"vector dim mismatch: expected {dim}, got {len(out)}")
    return len(out), out


def _l2_norm(vec: Sequence[float]) -> float:
    s = 0.0
    for v in vec:
        s += v * v
    return math.sqrt(s)


def _normalize(vec: Sequence[float]) -> List[float]:
    n = _l2_norm(vec)
    if n == 0.0:
        raise VectorValidationError("zero vector is not allowed for cosine similarity")
    return [v / n for v in vec]


def _cosine(a_norm: Sequence[float], b_norm: Sequence[float]) -> float:
    # both must be normalized
    s = 0.0
    for av, bv in zip(a_norm, b_norm):
        s += av * bv
    # Clamp for numeric safety
    if s > 1.0:
        return 1.0
    if s < -1.0:
        return -1.0
    return s



def _stable_topk(scored: List[Tuple[str, float]], k: int) -> List[Tuple[str, float]]:
    # Sort by score desc, then id asc to keep deterministic order.
    scored.sort(key=lambda t: (-t[1], t[0]))
    return scored[:k]


def _metadata_match(metadata: Mapping[str, Any], flt: Mapping[str, Any]) -> bool:
    """
    Minimal deterministic filter language:
    - equality: {"key": "value"}
    - inclusion: {"key": {"$in": [..]}}
    - not-in: {"key": {"$nin": [..]}}
    - exists: {"key": {"$exists": true/false}}
    """
    for k, cond in flt.items():
        if isinstance(cond, dict):
            if "$in" in cond:
                seq = cond["$in"]
                if not isinstance(seq, (list, tuple, set)):
                    return False
                if metadata.get(k) not in seq:
                    return False
            elif "$nin" in cond:
                seq = cond["$nin"]
                if not isinstance(seq, (list, tuple, set)):
                    return False
                if metadata.get(k) in seq:
                    return False
            elif "$exists" in cond:
                ex = cond["$exists"]
                if not isinstance(ex, bool):
                    return False
                if ex and k not in metadata:
                    return False
                if (not ex) and k in metadata:
                    return False
            else:
                # Unsupported operator -> strict false
                return False
        else:
            if metadata.get(k) != cond:
                return False
    return True


@dataclass(frozen=True, slots=True)
class VectorRecord:
    id: str
    vector: Tuple[float, ...]
    vector_norm: Tuple[float, ...]
    metadata: Dict[str, Any] = field(default_factory=dict)
    namespace: str = "default"
    created_at_ms: int = field(default_factory=_now_ms)
    updated_at_ms: int = field(default_factory=_now_ms)


@dataclass(frozen=True, slots=True)
class QueryMatch:
    id: str
    score: float
    metadata: Dict[str, Any]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ts_ms: int
    op: str
    namespace: str
    details: Dict[str, Any]


class VectorDBMock:
    """
    Industrial in-memory vector DB mock.

    Goals:
    - Deterministic behavior for CI.
    - Strong validation and explicit errors.
    - Typical operations: upsert, delete, get, query (cosine), list_ids.
    - Namespaces + metadata filtering.
    - Audit trail for debugging test failures.

    Thread-safety:
    - Uses a re-entrant lock; safe for parallel test execution within a process.
    """

    def __init__(self, *, dim: Optional[int] = None, default_namespace: str = "default", keep_audit: int = 5000) -> None:
        if dim is not None and (not isinstance(dim, int) or dim <= 0):
            raise ValueError("dim must be a positive int or None")
        if not default_namespace:
            raise ValueError("default_namespace must be non-empty")
        if keep_audit <= 0:
            raise ValueError("keep_audit must be > 0")

        self._dim = dim
        self._default_ns = default_namespace
        self._lock = threading.RLock()

        # Storage: namespace -> id -> record
        self._store: Dict[str, Dict[str, VectorRecord]] = {}

        # Audit: append-only ring buffer
        self._keep_audit = int(keep_audit)
        self._audit: List[AuditEvent] = []

    @property
    def dim(self) -> Optional[int]:
        return self._dim

    def _audit_add(self, op: str, namespace: str, **details: Any) -> None:
        ev = AuditEvent(ts_ms=_now_ms(), op=op, namespace=namespace, details=dict(details))
        self._audit.append(ev)
        if len(self._audit) > self._keep_audit:
            self._audit = self._audit[-self._keep_audit :]

    def audit_tail(self, limit: int = 50) -> List[AuditEvent]:
        if limit <= 0:
            return []
        with self._lock:
            return list(self._audit[-limit:])

    def reset(self) -> None:
        with self._lock:
            self._store.clear()
            self._audit.clear()
            self._audit_add("reset", self._default_ns)

    def snapshot(self) -> Dict[str, Dict[str, VectorRecord]]:
        with self._lock:
            return {ns: dict(items) for ns, items in self._store.items()}

    def list_namespaces(self) -> List[str]:
        with self._lock:
            return sorted(self._store.keys())

    def list_ids(self, *, namespace: Optional[str] = None) -> List[str]:
        ns = namespace or self._default_ns
        with self._lock:
            ids = list(self._store.get(ns, {}).keys())
        ids.sort()
        return ids

    def get(self, record_id: str, *, namespace: Optional[str] = None) -> VectorRecord:
        if not record_id:
            raise ValueError("record_id must be non-empty")
        ns = namespace or self._default_ns
        with self._lock:
            bucket = self._store.get(ns, {})
            rec = bucket.get(record_id)
            if rec is None:
                raise NotFoundError(f"record not found: {record_id}")
            self._audit_add("get", ns, id=record_id)
            return rec

    def upsert(
        self,
        items: Iterable[Mapping[str, Any]],
        *,
        namespace: Optional[str] = None,
    ) -> int:
        """
        Items format:
        {"id": str, "vector": [..], "metadata": {...}}.
        """
        ns = namespace or self._default_ns
        with self._lock:
            bucket = self._store.setdefault(ns, {})
            n = 0
            for it in items:
                if not isinstance(it, Mapping):
                    raise ValueError("each item must be a mapping")
                rid = it.get("id")
                if not isinstance(rid, str) or not rid:
                    raise ValueError("item.id must be non-empty str")
                vec = it.get("vector")
                if vec is None:
                    raise ValueError("item.vector is required")
                _, vec_f = _validate_vector(vec, self._dim)
                vec_n = _normalize(vec_f)

                meta = it.get("metadata") or {}
                if not isinstance(meta, Mapping):
                    raise ValueError("item.metadata must be a mapping if provided")
                meta_d = dict(meta)

                now = _now_ms()
                existing = bucket.get(rid)
                if existing is None:
                    rec = VectorRecord(
                        id=rid,
                        vector=tuple(vec_f),
                        vector_norm=tuple(vec_n),
                        metadata=meta_d,
                        namespace=ns,
                        created_at_ms=now,
                        updated_at_ms=now,
                    )
                else:
                    # Upsert semantics: replace vector, merge metadata (new keys overwrite)
                    merged = dict(existing.metadata)
                    merged.update(meta_d)
                    rec = VectorRecord(
                        id=rid,
                        vector=tuple(vec_f),
                        vector_norm=tuple(vec_n),
                        metadata=merged,
                        namespace=ns,
                        created_at_ms=existing.created_at_ms,
                        updated_at_ms=now,
                    )
                bucket[rid] = rec
                n += 1
            self._audit_add("upsert", ns, count=n)
            return n

    def delete(self, ids: Iterable[str], *, namespace: Optional[str] = None, ignore_missing: bool = True) -> int:
        ns = namespace or self._default_ns
        with self._lock:
            bucket = self._store.get(ns, {})
            removed = 0
            for rid in ids:
                if not isinstance(rid, str) or not rid:
                    raise ValueError("id must be non-empty str")
                if rid in bucket:
                    del bucket[rid]
                    removed += 1
                else:
                    if not ignore_missing:
                        raise NotFoundError(f"record not found: {rid}")
            if bucket and ns in self._store:
                self._store[ns] = bucket
            elif not bucket and ns in self._store:
                # drop empty namespace
                del self._store[ns]
            self._audit_add("delete", ns, removed=removed)
            return removed

    def query(
        self,
        vector: Sequence[float],
        *,
        top_k: int = 10,
        namespace: Optional[str] = None,
        metadata_filter: Optional[Mapping[str, Any]] = None,
        include_metadata: bool = True,
        min_score: Optional[float] = None,
    ) -> List[QueryMatch]:
        if not isinstance(top_k, int) or top_k <= 0:
            raise ValueError("top_k must be a positive int")
        ns = namespace or self._default_ns

        _, vec_f = _validate_vector(vector, self._dim)
        qn = _normalize(vec_f)

        flt = dict(metadata_filter) if metadata_filter else None
        if flt is not None and not isinstance(metadata_filter, Mapping):
            raise ValueError("metadata_filter must be a mapping if provided")

        with self._lock:
            bucket = self._store.get(ns, {})
            scored: List[Tuple[str, float]] = []
            for rid, rec in bucket.items():
                if flt is not None and not _metadata_match(rec.metadata, flt):
                    continue
                score = _cosine(qn, rec.vector_norm)
                if min_score is not None and score < float(min_score):
                    continue
                scored.append((rid, score))

            top = _stable_topk(scored, top_k)
            out: List[QueryMatch] = []
            for rid, score in top:
                rec = bucket[rid]
                meta = dict(rec.metadata) if include_metadata else {}
                out.append(QueryMatch(id=rid, score=float(score), metadata=meta))

            self._audit_add(
                "query",
                ns,
                top_k=top_k,
                filter=flt if flt is not None else {},
                returned=len(out),
                min_score=min_score,
            )
            return out

    def count(self, *, namespace: Optional[str] = None) -> int:
        ns = namespace or self._default_ns
        with self._lock:
            return len(self._store.get(ns, {}))

    def ensure_dim(self, dim: int) -> None:
        """
        Locks the dimensionality after first known dim.
        Useful when dim is unknown at init but becomes known later in tests.
        """
        if not isinstance(dim, int) or dim <= 0:
            raise ValueError("dim must be positive int")
        with self._lock:
            if self._dim is None:
                self._dim = dim
                self._audit_add("ensure_dim", self._default_ns, dim=dim)
            elif self._dim != dim:
                raise VectorValidationError(f"dim mismatch: mock has dim={self._dim}, attempted set dim={dim}")


def make_vector_db_mock(*, dim: Optional[int] = None, default_namespace: str = "default") -> VectorDBMock:
    return VectorDBMock(dim=dim, default_namespace=default_namespace)
