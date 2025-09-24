# policy-core/policy_core/models/policies.py
"""
Industrial policy models for Zero-Trust policy-core.

Contents:
- Enums: Effect, CombiningAlgo
- Dataclasses (frozen): Obligation, Advice, Rule, Policy, PolicyBundle
- Validation (schema + semantic) with rich errors
- Canonical serialization, revision/ETag hashing
- JSON Schema generators for Policy and PolicyBundle
- ID normalization and metadata redaction
- Optional HMAC signature for bundle integrity
- Backward-compatible migrations (v1 -> v2)

No third-party dependencies. Python 3.9+.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ---------------------------- Constants & Regex ----------------------------

CURRENT_SCHEMA_VERSION = "2.0"
# IDs: letters, digits, underscore, dash, dot, colon; 1..128
_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
# Keys that should be redacted in metadata/resource sets, if ever present here
_DEFAULT_REDACT_KEYS = ("password", "secret", "token", "authorization", "cookie", "apikey", "api_key")


# ---------------------------- Errors ----------------------------

class ModelError(Exception):
    """Base error for model layer."""


class ValidationError(ModelError):
    """Raised when validation fails."""
    def __init__(self, message: str, path: Optional[str] = None, details: Optional[Mapping[str, Any]] = None):
        super().__init__(message)
        self.path = path
        self.details = dict(details or {})

    def to_dict(self) -> Dict[str, Any]:
        return {"message": str(self), "path": self.path, "details": self.details}


class SchemaError(ModelError):
    """Raised when schema version/shape is unsupported."""


# ---------------------------- Enums ----------------------------

class Effect(enum.Enum):
    PERMIT = "permit"
    DENY = "deny"


class CombiningAlgo(enum.Enum):
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"
    ORDERED_DENY_OVERRIDES = "ordered_deny_overrides"


# ---------------------------- Dataclasses ----------------------------

@dataclass(frozen=True)
class Obligation:
    id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        _ensure_id(self.id, "obligation.id")
        _ensure_mapping(self.attributes, "obligation.attributes")


@dataclass(frozen=True)
class Advice:
    id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        _ensure_id(self.id, "advice.id")
        _ensure_mapping(self.attributes, "advice.attributes")


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    # Safe expression in PDP. Models keep it as a string; evaluation occurs in PDP layer.
    condition: Optional[str] = None
    obligations: Tuple[Obligation, ...] = field(default_factory=tuple)
    advice: Tuple[Advice, ...] = field(default_factory=tuple)
    annotations: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        _ensure_id(self.id, "rule.id")
        if not isinstance(self.effect, Effect):
            raise ValidationError("rule.effect must be Effect enum", path="rule.effect", details={"value": self.effect})
        if self.condition is not None and not isinstance(self.condition, str):
            raise ValidationError("rule.condition must be a string or None", path="rule.condition")
        _ensure_sequence(self.obligations, Obligation, "rule.obligations")
        _ensure_sequence(self.advice, Advice, "rule.advice")
        _ensure_mapping(self.annotations, "rule.annotations")


@dataclass(frozen=True)
class Policy:
    id: str
    version: Union[int, str] = "1"
    algo: CombiningAlgo = CombiningAlgo.DENY_OVERRIDES
    target: Optional[str] = None
    rules: Tuple[Rule, ...] = field(default_factory=tuple)
    priority: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _now_iso())
    updated_at: str = field(default_factory=lambda: _now_iso())

    def __post_init__(self):
        _ensure_id(self.id, "policy.id")
        if not isinstance(self.version, (int, str)):
            raise ValidationError("policy.version must be int or str", path="policy.version")
        if not isinstance(self.algo, CombiningAlgo):
            raise ValidationError("policy.algo must be CombiningAlgo", path="policy.algo")
        if self.target is not None and not isinstance(self.target, str):
            raise ValidationError("policy.target must be string or None", path="policy.target")
        _ensure_sequence(self.rules, Rule, "policy.rules")
        _ensure_int(self.priority, "policy.priority")
        _ensure_mapping(self.metadata, "policy.metadata")
        # Unique rule IDs
        _ensure_unique([r.id for r in self.rules], "policy.rules[*].id", owner=self.id)

    # ------- Serialization -------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "algo": self.algo.value,
            "target": self.target,
            "rules": [rule_to_dict(r) for r in self.rules],
            "priority": self.priority,
            "metadata": redact(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def from_dict(doc: Mapping[str, Any]) -> "Policy":
        try:
            _ensure_required(doc, ["id"])
            pid = normalize_id(doc["id"])
            algo = _enum_parse(CombiningAlgo, doc.get("algo", CombiningAlgo.DENY_OVERRIDES.value), "policy.algo")
            rules = tuple(rule_from_dict(x, path=f"policy[{pid}].rules") for x in doc.get("rules", []))
            return Policy(
                id=pid,
                version=doc.get("version", "1"),
                algo=algo,
                target=doc.get("target"),
                rules=rules,
                priority=int(doc.get("priority", 0)),
                metadata=dict(doc.get("metadata", {})),
                created_at=doc.get("created_at", _now_iso()),
                updated_at=doc.get("updated_at", _now_iso()),
            )
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"invalid policy: {e}", path="policy") from e

    # ------- Hashing / ETag -------

    def etag(self) -> str:
        """ETag for a single policy (canonical)."""
        can = _canonical_json(self.to_dict())
        return hashlib.sha256(can).hexdigest()


@dataclass(frozen=True)
class PolicyBundle:
    policies: Tuple[Policy, ...]
    schema_version: str = CURRENT_SCHEMA_VERSION
    created_at: str = field(default_factory=lambda: _now_iso())
    revision: str = field(default_factory=str)  # computed if empty
    signature: Optional[str] = None  # HMAC(hex) over canonical content (without signature)

    def __post_init__(self):
        _ensure_sequence(self.policies, Policy, "bundle.policies")
        _ensure_unique([p.id for p in self.policies], "bundle.policies[*].id")
        if not isinstance(self.schema_version, str):
            raise ValidationError("bundle.schema_version must be string", path="bundle.schema_version")
        if not self.revision:
            object.__setattr__(self, "revision", self.compute_revision())

    # ------- Serialization -------

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        d = {
            "policies": [p.to_dict() for p in sorted(self.policies, key=lambda x: (x.priority * -1, x.id))],
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "revision": self.revision,
        }
        if include_signature:
            d["signature"] = self.signature
        return d

    @staticmethod
    def from_dict(doc: Mapping[str, Any]) -> "PolicyBundle":
        try:
            schema_version = str(doc.get("schema_version", CURRENT_SCHEMA_VERSION))
            if schema_version not in ("1.0", "2.0"):
                raise SchemaError(f"unsupported schema_version: {schema_version}")
            raw_policies = doc.get("policies", [])
            if not isinstance(raw_policies, list):
                raise ValidationError("bundle.policies must be list", path="bundle.policies")
            # Migrate if needed
            migrated = [migrate_policy(x, schema_version) for x in raw_policies]
            policies = tuple(Policy.from_dict(x) for x in migrated)
            b = PolicyBundle(
                policies=policies,
                schema_version=CURRENT_SCHEMA_VERSION,
                created_at=doc.get("created_at", _now_iso()),
                revision=doc.get("revision", ""),
                signature=doc.get("signature"),
            )
            return b
        except ModelError:
            raise
        except Exception as e:
            raise ValidationError(f"invalid bundle: {e}", path="bundle") from e

    # ------- Revision / Signature -------

    def compute_revision(self) -> str:
        """Stable revision hash for the bundle content (without signature)."""
        body = _canonical_json(self.to_dict(include_signature=False))
        return hashlib.sha256(body).hexdigest()

    def sign(self, secret: Union[str, bytes]) -> "PolicyBundle":
        """Return a new bundle with HMAC signature set."""
        key = _as_bytes(secret)
        body = _canonical_json(self.to_dict(include_signature=False))
        mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        return dataclasses.replace(self, signature=mac)

    def verify_signature(self, secret: Union[str, bytes]) -> bool:
        """Verify HMAC signature; returns False if absent."""
        if not self.signature:
            return False
        key = _as_bytes(secret)
        body = _canonical_json(self.to_dict(include_signature=False))
        mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, self.signature)


# ---------------------------- Builders & Parsing ----------------------------

def rule_to_dict(r: Rule) -> Dict[str, Any]:
    return {
        "id": r.id,
        "effect": r.effect.value,
        "condition": r.condition,
        "obligations": [{"id": o.id, "attributes": dict(o.attributes)} for o in r.obligations],
        "advice": [{"id": a.id, "attributes": dict(a.attributes)} for a in r.advice],
        "annotations": dict(r.annotations),
    }


def rule_from_dict(doc: Mapping[str, Any], path: str = "rule") -> Rule:
    _ensure_required(doc, ["id", "effect"], path=path)
    rid = normalize_id(doc["id"], path=f"{path}.id")
    eff = _enum_parse(Effect, doc.get("effect"), f"{path}.effect")
    cond = doc.get("condition")
    if cond is not None and not isinstance(cond, str):
        raise ValidationError("condition must be string or None", path=f"{path}.condition")
    obs = tuple(Obligation(id=normalize_id(o.get("id", "obligation")), attributes=dict(o.get("attributes", {})))
                for o in doc.get("obligations", []))
    adv = tuple(Advice(id=normalize_id(a.get("id", "advice")), attributes=dict(a.get("attributes", {})))
                for a in doc.get("advice", []))
    annotations = dict(doc.get("annotations", {}))
    _ensure_mapping(annotations, f"{path}.annotations")
    return Rule(id=rid, effect=eff, condition=cond, obligations=obs, advice=adv, annotations=annotations)


# ---------------------------- Validation helpers ----------------------------

def normalize_id(value: Any, path: str = "id") -> str:
    if not isinstance(value, str):
        raise ValidationError("id must be string", path=path, details={"value": value})
    value = value.strip()
    if not _ID_RE.match(value):
        raise ValidationError("id contains forbidden characters or wrong length", path=path, details={"id": value})
    return value


def _ensure_id(value: Any, path: str) -> None:
    if not isinstance(value, str) or not _ID_RE.match(value.strip()):
        raise ValidationError("invalid id format", path=path, details={"id": value})


def _ensure_required(doc: Mapping[str, Any], keys: Iterable[str], path: str = "") -> None:
    for k in keys:
        if k not in doc:
            raise ValidationError(f"required key missing: {k}", path=f"{path}.{k}" if path else k)


def _ensure_sequence(seq: Any, item_type: Any, path: str) -> None:
    if not isinstance(seq, (list, tuple)):
        raise ValidationError("must be sequence", path=path)
    for idx, it in enumerate(seq):
        if not isinstance(it, item_type):
            raise ValidationError(f"invalid item type at index {idx}", path=f"{path}[{idx}]")


def _ensure_mapping(m: Any, path: str) -> None:
    if not isinstance(m, Mapping):
        raise ValidationError("must be mapping", path=path)


def _ensure_int(v: Any, path: str) -> None:
    if not isinstance(v, int):
        raise ValidationError("must be int", path=path)


def _ensure_unique(ids: Sequence[str], path: str, owner: Optional[str] = None) -> None:
    dup = _find_duplicate(ids)
    if dup:
        details = {"duplicate_id": dup}
        if owner:
            details["owner"] = owner
        raise ValidationError("duplicate ids are not allowed", path=path, details=details)


def _find_duplicate(values: Sequence[str]) -> Optional[str]:
    seen = set()
    for v in values:
        if v in seen:
            return v
        seen.add(v)
    return None


# ---------------------------- Canonical JSON / Hashing ----------------------------

def _canonical_json(obj: Any) -> bytes:
    """Canonical JSON for stable hashing (sorted keys, no spaces, no floats quirks)."""
    return json.dumps(_stable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stable(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {k: _stable(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_stable(x) for x in obj]
    if isinstance(obj, tuple):
        return [_stable(x) for x in obj]  # tuples to lists
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    if isinstance(obj, float):
        # Normalize float to repr with 15 significant digits
        return float(f"{obj:.15g}")
    # Fallback to string
    return str(obj)


def _as_bytes(secret: Union[str, bytes]) -> bytes:
    return secret if isinstance(secret, bytes) else secret.encode("utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(obj: Any, keys: Tuple[str, ...] = _DEFAULT_REDACT_KEYS) -> Any:
    """Redact sensitive keys in nested mappings/lists."""
    if isinstance(obj, Mapping):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in keys:
                out[k] = "***"
            else:
                out[k] = redact(v, keys)
        return out
    if isinstance(obj, list):
        return [redact(x, keys) for x in obj]
    if isinstance(obj, tuple):
        return tuple(redact(x, keys) for x in obj)
    return obj


# ---------------------------- JSON Schema ----------------------------

def policy_json_schema() -> Dict[str, Any]:
    """Draft-07 compatible JSON Schema for a single Policy document."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Policy",
        "type": "object",
        "required": ["id", "rules"],
        "additionalProperties": False,
        "properties": {
            "id": {"type": "string", "pattern": _ID_RE.pattern},
            "version": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
            "algo": {"type": "string", "enum": [a.value for a in CombiningAlgo]},
            "target": {"type": ["string", "null"]},
            "priority": {"type": "integer"},
            "metadata": {"type": "object"},
            "created_at": {"type": "string"},
            "updated_at": {"type": "string"},
            "rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "effect"],
                    "additionalProperties": False,
                    "properties": {
                        "id": {"type": "string", "pattern": _ID_RE.pattern},
                        "effect": {"type": "string", "enum": [e.value for e in Effect]},
                        "condition": {"type": ["string", "null"]},
                        "annotations": {"type": "object"},
                        "obligations": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["id"],
                                "additionalProperties": False,
                                "properties": {
                                    "id": {"type": "string", "pattern": _ID_RE.pattern},
                                    "attributes": {"type": "object"},
                                },
                            },
                        },
                        "advice": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["id"],
                                "additionalProperties": False,
                                "properties": {
                                    "id": {"type": "string", "pattern": _ID_RE.pattern},
                                    "attributes": {"type": "object"},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def bundle_json_schema() -> Dict[str, Any]:
    """Draft-07 compatible JSON Schema for a PolicyBundle."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "PolicyBundle",
        "type": "object",
        "required": ["policies"],
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "string"},
            "created_at": {"type": "string"},
            "revision": {"type": "string"},
            "signature": {"type": ["string", "null"]},
            "policies": {"type": "array", "items": policy_json_schema()},
        },
    }


# ---------------------------- Migrations ----------------------------

def migrate_policy(doc: Mapping[str, Any], schema_version: str) -> Dict[str, Any]:
    """
    Migrate a single policy document from given schema_version to CURRENT_SCHEMA_VERSION shape.
    v1.0 -> v2.0 changes:
      - 'algorithm' renamed to 'algo'
      - default algo = 'deny_overrides'
      - ensure 'rules' present (empty list if absent)
    """
    if schema_version == "2.0":
        # Already v2 shape (or close). Normalize keys.
        d = dict(doc)
        if "algorithm" in d and "algo" not in d:
            d["algo"] = d.pop("algorithm")
        d.setdefault("rules", d.get("rules", []))
        return d
    if schema_version == "1.0":
        d = dict(doc)
        if "algorithm" in d:
            d["algo"] = d.pop("algorithm")
        d.setdefault("algo", CombiningAlgo.DENY_OVERRIDES.value)
        d.setdefault("rules", d.get("rules", []))
        return d
    # Unknown version: attempt best-effort normalization
    d = dict(doc)
    d.setdefault("algo", d.get("algorithm", CombiningAlgo.DENY_OVERRIDES.value))
    d.pop("algorithm", None)
    d.setdefault("rules", d.get("rules", []))
    return d


# ---------------------------- Convenience API ----------------------------

def compute_bundle_revision_from_docs(policy_docs: Sequence[Mapping[str, Any]]) -> str:
    """Compute revision directly from raw dict policies (bypassing dataclass construction)."""
    normalized = [migrate_policy(d, str(d.get("schema_version", CURRENT_SCHEMA_VERSION))) for d in policy_docs]
    body = _canonical_json({
        "policies": normalized,
        "schema_version": CURRENT_SCHEMA_VERSION,
    })
    return hashlib.sha256(body).hexdigest()


def merge_bundles(*bundles: PolicyBundle) -> PolicyBundle:
    """Merge multiple bundles; latter bundles override policies by id."""
    combined: Dict[str, Policy] = {}
    for b in bundles:
        for p in b.policies:
            combined[p.id] = p
    merged = PolicyBundle(policies=tuple(sorted(combined.values(), key=lambda p: (-p.priority, p.id))))
    return dataclasses.replace(merged, revision=merged.compute_revision())


# ---------------------------- __all__ ----------------------------

__all__ = [
    "Effect",
    "CombiningAlgo",
    "Obligation",
    "Advice",
    "Rule",
    "Policy",
    "PolicyBundle",
    "ValidationError",
    "SchemaError",
    "policy_json_schema",
    "bundle_json_schema",
    "compute_bundle_revision_from_docs",
    "merge_bundles",
    "redact",
]
