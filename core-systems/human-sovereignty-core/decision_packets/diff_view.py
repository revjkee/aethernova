# human-sovereignty-core/decision_packets/diff_view.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

__all__ = [
    "DiffViewError",
    "DiffSizeLimitError",
    "DiffRenderError",
    "DiffConfig",
    "DiffEntry",
    "DiffSummary",
    "DiffResult",
    "build_diff",
    "render_diff_text",
    "render_diff_markdown",
]


class DiffViewError(Exception):
    """Base error for diff view."""


class DiffSizeLimitError(DiffViewError):
    """Raised when input or produced diff exceeds configured limits."""


class DiffRenderError(DiffViewError):
    """Raised when rendering fails."""


_JSONScalar = Union[str, int, float, bool, None]
_JSONValue = Union[_JSONScalar, List["__JSONValue"], Dict[str, "___JSONValue"]]  # type: ignore[name-defined]


SENSITIVE_KEY_RE = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|private[_-]?key|seed|mnemonic|credential|bearer|authorization|cookie|session)",
    re.IGNORECASE,
)

DEFAULT_MASK = "[REDACTED]"


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat()


def _is_nan_inf(x: Any) -> bool:
    return isinstance(x, float) and (math.isnan(x) or math.isinf(x))


def _stable_json_dumps(obj: Any, max_len: int) -> str:
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    if len(s) > max_len:
        raise DiffSizeLimitError("canonical json exceeds max length")
    return s


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="strict")).hexdigest()


def _path_join(parent: str, key: str) -> str:
    if parent == "":
        return key
    return f"{parent}.{key}"


def _truncate(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 12)] + "…[TRUNCATED]"


@dataclass(frozen=True, slots=True)
class DiffConfig:
    # Hard limits to prevent UI/log DoS.
    max_input_bytes: int = 256_000
    max_canonical_json_chars: int = 256_000
    max_paths: int = 50_000
    max_diff_entries: int = 2_000
    max_string_value_chars: int = 2_000

    # Masking
    mask_sensitive: bool = True
    sensitive_key_regex: str = SENSITIVE_KEY_RE.pattern
    mask_value: str = DEFAULT_MASK

    # Render options
    context_lines: int = 0  # kept for parity; path-diff has no line context
    show_hash_for_masked: bool = True  # if masked, show hash of original to detect change without leak
    include_summary: bool = True
    include_metadata: bool = True

    # Risk markers: label certain paths as high risk for approvals UX
    high_risk_path_prefixes: Tuple[str, ...] = (
        "secrets",
        "credentials",
        "auth",
        "identity",
        "keyvault",
        "tokens",
        "policies",
        "rbac",
        "permissions",
    )

    def compiled_sensitive_re(self) -> re.Pattern[str]:
        return re.compile(self.sensitive_key_regex, re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class DiffEntry:
    path: str
    op: str  # "add" | "remove" | "change"
    before: Optional[str]
    after: Optional[str]
    sensitive: bool
    high_risk: bool


@dataclass(frozen=True, slots=True)
class DiffSummary:
    adds: int
    removes: int
    changes: int
    sensitive_touched: int
    high_risk_touched: int
    # Fingerprints allow quick equality checks in audit trails.
    before_fingerprint: str
    after_fingerprint: str


@dataclass(frozen=True, slots=True)
class DiffResult:
    created_at_utc: str
    entries: Tuple[DiffEntry, ...]
    summary: Optional[DiffSummary]
    metadata: Dict[str, str]


def _estimate_size_bytes(obj: Any) -> int:
    try:
        b = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8", errors="strict")
        return len(b)
    except Exception:
        # Worst-case: treat as large if cannot estimate safely.
        return 10**9


def _is_sensitive_key(key: str, sensitive_re: re.Pattern[str]) -> bool:
    return sensitive_re.search(key) is not None


def _is_high_risk_path(path: str, prefixes: Sequence[str]) -> bool:
    for p in prefixes:
        if path == p or path.startswith(p + "."):
            return True
    return False


def _sanitize_value(value: Any, cfg: DiffConfig) -> Any:
    # Normalize floats (NaN/Inf) to strings to keep JSON stable and safe.
    if _is_nan_inf(value):
        return str(value)
    if isinstance(value, (str, int, bool)) or value is None:
        if isinstance(value, str):
            return _truncate(value, cfg.max_string_value_chars)
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, bytes):
        # Never render raw bytes.
        return f"<bytes:{len(value)}>"
    if dataclasses.is_dataclass(value):
        return _sanitize_value(dataclasses.asdict(value), cfg)
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            ks = str(k)
            out[ks] = _sanitize_value(v, cfg)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize_value(v, cfg) for v in value]
    # Fallback: stringize
    return _truncate(str(value), cfg.max_string_value_chars)


def _mask_tree(value: Any, cfg: DiffConfig, sensitive_re: re.Pattern[str], path: str = "") -> Any:
    if not cfg.mask_sensitive:
        return value

    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            ks = str(k)
            child_path = _path_join(path, ks) if path else ks
            if _is_sensitive_key(ks, sensitive_re):
                # Replace sensitive subtree entirely.
                if cfg.show_hash_for_masked:
                    canon = _stable_json_dumps(_sanitize_value(v, cfg), cfg.max_canonical_json_chars)
                    out[ks] = {"masked": cfg.mask_value, "sha256": _sha256_hex(canon)}
                else:
                    out[ks] = cfg.mask_value
            else:
                out[ks] = _mask_tree(v, cfg, sensitive_re, child_path)
        return out

    if isinstance(value, list):
        return [_mask_tree(v, cfg, sensitive_re, path) for v in value]

    return value


def _flatten_paths(value: Any, cfg: DiffConfig, base: str = "") -> Iterator[Tuple[str, Any]]:
    # Flatten tree into (path, scalar_or_container_repr) for stable path diff.
    # Lists use bracket indices for deterministic paths.
    stack: List[Tuple[str, Any]] = [(base, value)]
    produced = 0

    while stack:
        path, node = stack.pop()
        produced += 1
        if produced > cfg.max_paths:
            raise DiffSizeLimitError("max_paths exceeded")

        if isinstance(node, Mapping):
            # Represent container node itself
            yield (path, {"__type__": "object", "__len__": len(node)})
            # Deterministic order: sorted keys
            for k in sorted(node.keys(), key=lambda x: str(x)):
                ks = str(k)
                child_path = _path_join(path, ks) if path else ks
                stack.append((child_path, node[k]))
            continue

        if isinstance(node, list):
            yield (path, {"__type__": "array", "__len__": len(node)})
            # Deterministic indices
            for i in range(len(node) - 1, -1, -1):
                child_path = f"{path}[{i}]" if path else f"[{i}]"
                stack.append((child_path, node[i]))
            continue

        # Scalar
        yield (path, node)


def _stringify_leaf(v: Any, cfg: DiffConfig) -> str:
    if isinstance(v, (dict, list)):
        # For containers we stringify the container marker in stable way.
        return _truncate(_stable_json_dumps(v, cfg.max_canonical_json_chars), cfg.max_string_value_chars)
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return _truncate(str(v), cfg.max_string_value_chars)


def _detect_sensitive_path(path: str, sensitive_re: re.Pattern[str]) -> bool:
    # If any token segment indicates sensitive field.
    # path segments: dot tokens and bracket indices.
    tokens = re.split(r"[.\[\]]+", path)
    for t in tokens:
        if not t:
            continue
        if sensitive_re.search(t):
            return True
    return False


def build_diff(before: Any, after: Any, cfg: Optional[DiffConfig] = None) -> DiffResult:
    cfg = cfg or DiffConfig()
    sensitive_re = cfg.compiled_sensitive_re()

    # Enforce input size budget
    before_size = _estimate_size_bytes(before)
    after_size = _estimate_size_bytes(after)
    if before_size > cfg.max_input_bytes or after_size > cfg.max_input_bytes:
        raise DiffSizeLimitError("input exceeds max_input_bytes")

    # Sanitize (normalize types, truncate strings)
    before_s = _sanitize_value(before, cfg)
    after_s = _sanitize_value(after, cfg)

    # Mask
    before_m = _mask_tree(before_s, cfg, sensitive_re)
    after_m = _mask_tree(after_s, cfg, sensitive_re)

    # Fingerprints based on canonical JSON
    before_json = _stable_json_dumps(before_m, cfg.max_canonical_json_chars)
    after_json = _stable_json_dumps(after_m, cfg.max_canonical_json_chars)
    before_fp = _sha256_hex(before_json)
    after_fp = _sha256_hex(after_json)

    # Flatten to path maps
    before_map: Dict[str, str] = {}
    after_map: Dict[str, str] = {}

    for p, v in _flatten_paths(before_m, cfg):
        before_map[p] = _stringify_leaf(v, cfg)
    for p, v in _flatten_paths(after_m, cfg):
        after_map[p] = _stringify_leaf(v, cfg)

    # Compute diff
    all_paths = sorted(set(before_map.keys()) | set(after_map.keys()))
    entries: List[DiffEntry] = []

    adds = removes = changes = 0
    sensitive_touched = 0
    high_risk_touched = 0

    for path in all_paths:
        b = before_map.get(path)
        a = after_map.get(path)
        if b is None and a is None:
            continue

        if b is None:
            op = "add"
            adds += 1
        elif a is None:
            op = "remove"
            removes += 1
        elif b != a:
            op = "change"
            changes += 1
        else:
            continue

        sensitive = _detect_sensitive_path(path, sensitive_re)
        high_risk = _is_high_risk_path(path, cfg.high_risk_path_prefixes)

        if sensitive:
            sensitive_touched += 1
        if high_risk:
            high_risk_touched += 1

        entries.append(
            DiffEntry(
                path=path,
                op=op,
                before=b,
                after=a,
                sensitive=sensitive,
                high_risk=high_risk,
            )
        )

        if len(entries) >= cfg.max_diff_entries:
            raise DiffSizeLimitError("max_diff_entries exceeded")

    summary: Optional[DiffSummary] = None
    if cfg.include_summary:
        summary = DiffSummary(
            adds=adds,
            removes=removes,
            changes=changes,
            sensitive_touched=sensitive_touched,
            high_risk_touched=high_risk_touched,
            before_fingerprint=before_fp,
            after_fingerprint=after_fp,
        )

    metadata: Dict[str, str] = {}
    if cfg.include_metadata:
        metadata = {
            "created_at_utc": _utc_now_iso(),
            "before_size_bytes": str(before_size),
            "after_size_bytes": str(after_size),
            "before_fingerprint_sha256": before_fp,
            "after_fingerprint_sha256": after_fp,
            "mask_sensitive": "true" if cfg.mask_sensitive else "false",
            "max_diff_entries": str(cfg.max_diff_entries),
        }

    return DiffResult(
        created_at_utc=_utc_now_iso(),
        entries=tuple(entries),
        summary=summary,
        metadata=metadata,
    )


def _format_entry_line(e: DiffEntry) -> str:
    # Deterministic concise line for logs/UI.
    flags = []
    if e.sensitive:
        flags.append("SENSITIVE")
    if e.high_risk:
        flags.append("HIGH_RISK")
    flag_str = f" [{'|'.join(flags)}]" if flags else ""
    return f"{e.op.upper():6} {e.path}{flag_str}"


def render_diff_text(result: DiffResult, max_chars: int = 120_000) -> str:
    try:
        lines: List[str] = []
        lines.append("DIFF VIEW")
        lines.append(f"created_at_utc: {result.created_at_utc}")

        if result.summary is not None:
            s = result.summary
            lines.append(
                f"summary: adds={s.adds} removes={s.removes} changes={s.changes} "
                f"sensitive_touched={s.sensitive_touched} high_risk_touched={s.high_risk_touched}"
            )
            lines.append(f"before_fingerprint_sha256: {s.before_fingerprint}")
            lines.append(f"after_fingerprint_sha256: {s.after_fingerprint}")

        if result.metadata:
            lines.append("metadata:")
            for k in sorted(result.metadata.keys()):
                lines.append(f"  {k}: {result.metadata[k]}")

        lines.append("entries:")
        for e in result.entries:
            lines.append(f"- {_format_entry_line(e)}")
            if e.before is not None:
                lines.append(f"    before: {e.before}")
            if e.after is not None:
                lines.append(f"    after:  {e.after}")

        out = "\n".join(lines)
        if len(out) > max_chars:
            raise DiffSizeLimitError("rendered text exceeds max_chars")
        return out
    except DiffViewError:
        raise
    except Exception as exc:
        raise DiffRenderError(str(exc)) from exc


def render_diff_markdown(result: DiffResult, max_chars: int = 160_000) -> str:
    try:
        lines: List[str] = []
        lines.append("# Diff View")
        lines.append("")
        lines.append(f"- created_at_utc: `{result.created_at_utc}`")

        if result.summary is not None:
            s = result.summary
            lines.append(f"- summary: adds={s.adds}, removes={s.removes}, changes={s.changes}")
            lines.append(f"- sensitive_touched: {s.sensitive_touched}")
            lines.append(f"- high_risk_touched: {s.high_risk_touched}")
            lines.append(f"- before_fingerprint_sha256: `{s.before_fingerprint}`")
            lines.append(f"- after_fingerprint_sha256: `{s.after_fingerprint}`")

        if result.metadata:
            lines.append("")
            lines.append("## Metadata")
            for k in sorted(result.metadata.keys()):
                lines.append(f"- `{k}`: `{result.metadata[k]}`")

        lines.append("")
        lines.append("## Entries")
        for e in result.entries:
            flags = []
            if e.sensitive:
                flags.append("SENSITIVE")
            if e.high_risk:
                flags.append("HIGH_RISK")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            lines.append(f"- **{e.op.upper()}** `{e.path}`{flag_str}")
            if e.before is not None:
                lines.append(f"  - before: `{e.before}`")
            if e.after is not None:
                lines.append(f"  - after: `{e.after}`")

        out = "\n".join(lines)
        if len(out) > max_chars:
            raise DiffSizeLimitError("rendered markdown exceeds max_chars")
        return out
    except DiffViewError:
        raise
    except Exception as exc:
        raise DiffRenderError(str(exc)) from exc
