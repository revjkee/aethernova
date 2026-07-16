# agent_mash/pmo/reports.py
"""
PMO Reporting (industrial-grade)

Design goals:
- Strongly-typed report model with deterministic IDs
- Multiple renderers (JSON, Markdown, plain text)
- Safe-by-default redaction of secrets/tokens/keys
- Atomic, durable file writes (optionally gzip-compressed)
- Extensible architecture (Renderer/Store protocols)
- Zero mandatory third-party dependencies (stdlib only)

This module is intentionally self-contained and production-oriented.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import gzip
import hashlib
import json
import os
import re
import tempfile
import typing as t
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Public exports
__all__ = [
    "Severity",
    "FindingStatus",
    "ReportKind",
    "ReportMeta",
    "Finding",
    "Table",
    "Section",
    "Report",
    "ReportBuilder",
    "Renderer",
    "JsonRenderer",
    "MarkdownRenderer",
    "TextRenderer",
    "ReportStore",
    "FileReportStore",
    "Redactor",
    "DefaultRedactor",
    "ReportsError",
    "ReportValidationError",
    "ReportIOError",
]


class ReportsError(RuntimeError):
    """Base error for report subsystem."""


class ReportValidationError(ReportsError, ValueError):
    """Raised when report model fails validation."""


class ReportIOError(ReportsError, OSError):
    """Raised for I/O failures in stores."""


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, Enum):
    open = "open"
    in_progress = "in_progress"
    blocked = "blocked"
    done = "done"
    wont_fix = "wont_fix"


class ReportKind(str, Enum):
    pmo_weekly = "pmo_weekly"
    pmo_daily = "pmo_daily"
    migration_plan = "migration_plan"
    routing_overview = "routing_overview"
    audit = "audit"
    other = "other"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _require_non_empty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _require_len_at_most(name: str, value: str, max_len: int) -> str:
    if len(value) > max_len:
        raise ReportValidationError(f"{name} length must be <= {max_len}")
    return value


def _as_utc(dt: _dt.datetime) -> _dt.datetime:
    if not isinstance(dt, _dt.datetime):
        raise ReportValidationError("timestamp must be a datetime")
    if dt.tzinfo is None:
        raise ReportValidationError("timestamp must be timezone-aware (UTC recommended)")
    return dt.astimezone(_dt.timezone.utc)


def _stable_hash(payload: str) -> str:
    """
    Stable short identifier for payloads (sha256 -> first 16 hex).
    Deterministic across processes and machines.
    """
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return h[:16]


def _json_dumps(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True, slots=True)
class ReportMeta:
    """
    Report metadata. Keep it small and stable; use tags/context for additional info.
    """
    kind: ReportKind
    title: str
    created_at: _dt.datetime = field(default_factory=_utc_now)
    report_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    source: str = "agent_mash.pmo"
    version: str = "1.0"
    tags: tuple[str, ...] = ()
    context: dict[str, t.Any] = field(default_factory=dict)

    def validate(self) -> "ReportMeta":
        _ = _require_non_empty("title", self.title)
        _ = _require_len_at_most("title", self.title, 160)
        _ = _as_utc(self.created_at)
        _ = _require_non_empty("report_id", self.report_id)
        _ = _require_non_empty("trace_id", self.trace_id)
        _ = _require_non_empty("source", self.source)
        _ = _require_len_at_most("source", self.source, 120)
        _ = _require_non_empty("version", self.version)
        if not isinstance(self.tags, tuple):
            raise ReportValidationError("tags must be a tuple[str, ...]")
        if not isinstance(self.context, dict):
            raise ReportValidationError("context must be a dict")
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "kind": self.kind.value,
            "title": self.title,
            "created_at": self.created_at.isoformat(),
            "report_id": self.report_id,
            "trace_id": self.trace_id,
            "source": self.source,
            "version": self.version,
            "tags": list(self.tags),
            "context": self.context,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """
    A normalized issue/decision/actionable item in PMO outputs.
    """
    title: str
    description: str = ""
    severity: Severity = Severity.info
    status: FindingStatus = FindingStatus.open
    owner: str = ""
    references: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    created_at: _dt.datetime = field(default_factory=_utc_now)
    finding_id: str = field(init=False)

    def __post_init__(self) -> None:
        # deterministic id derived from stable payload fields
        payload = _json_dumps(
            {
                "title": self.title.strip() if isinstance(self.title, str) else self.title,
                "description": self.description.strip() if isinstance(self.description, str) else self.description,
                "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
                "owner": self.owner.strip() if isinstance(self.owner, str) else self.owner,
                "references": list(self.references) if isinstance(self.references, tuple) else self.references,
                "labels": list(self.labels) if isinstance(self.labels, tuple) else self.labels,
            }
        )
        object.__setattr__(self, "finding_id", _stable_hash(payload))

    def validate(self) -> "Finding":
        _ = _require_non_empty("finding.title", self.title)
        _ = _require_len_at_most("finding.title", self.title, 200)
        _ = _require_len_at_most("finding.description", self.description or "", 20_000)
        _ = _as_utc(self.created_at)
        if not isinstance(self.references, tuple):
            raise ReportValidationError("finding.references must be a tuple[str, ...]")
        if not isinstance(self.labels, tuple):
            raise ReportValidationError("finding.labels must be a tuple[str, ...]")
        if not isinstance(self.severity, Severity):
            raise ReportValidationError("finding.severity must be Severity")
        if not isinstance(self.status, FindingStatus):
            raise ReportValidationError("finding.status must be FindingStatus")
        if self.owner and not isinstance(self.owner, str):
            raise ReportValidationError("finding.owner must be str")
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "owner": self.owner,
            "references": list(self.references),
            "labels": list(self.labels),
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class Table:
    """
    A small tabular structure for reports (safe for Markdown & text rendering).
    """
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[t.Any, ...], ...]
    notes: str = ""

    def validate(self) -> "Table":
        _ = _require_non_empty("table.title", self.title)
        if not isinstance(self.columns, tuple) or not self.columns:
            raise ReportValidationError("table.columns must be a non-empty tuple[str, ...]")
        for c in self.columns:
            if not isinstance(c, str) or not c.strip():
                raise ReportValidationError("table.columns must contain non-empty strings")
        if not isinstance(self.rows, tuple):
            raise ReportValidationError("table.rows must be a tuple[tuple[Any,...],...]")
        for r in self.rows:
            if not isinstance(r, tuple):
                raise ReportValidationError("table.rows must be tuple rows")
            if len(r) != len(self.columns):
                raise ReportValidationError("table row length must match columns length")
        _ = _require_len_at_most("table.notes", self.notes or "", 10_000)
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "title": self.title,
            "columns": list(self.columns),
            "rows": [list(r) for r in self.rows],
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class Section:
    """
    A report section: narrative + findings + tables + nested sections.
    """
    title: str
    summary: str = ""
    body: str = ""
    findings: tuple[Finding, ...] = ()
    tables: tuple[Table, ...] = ()
    subsections: tuple["Section", ...] = ()

    def validate(self) -> "Section":
        _ = _require_non_empty("section.title", self.title)
        _ = _require_len_at_most("section.title", self.title, 200)
        _ = _require_len_at_most("section.summary", self.summary or "", 20_000)
        _ = _require_len_at_most("section.body", self.body or "", 200_000)

        if not isinstance(self.findings, tuple):
            raise ReportValidationError("section.findings must be a tuple[Finding, ...]")
        for f in self.findings:
            if not isinstance(f, Finding):
                raise ReportValidationError("section.findings must contain Finding")
            f.validate()

        if not isinstance(self.tables, tuple):
            raise ReportValidationError("section.tables must be a tuple[Table, ...]")
        for tbl in self.tables:
            if not isinstance(tbl, Table):
                raise ReportValidationError("section.tables must contain Table")
            tbl.validate()

        if not isinstance(self.subsections, tuple):
            raise ReportValidationError("section.subsections must be a tuple[Section, ...]")
        for s in self.subsections:
            if not isinstance(s, Section):
                raise ReportValidationError("section.subsections must contain Section")
            s.validate()

        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "title": self.title,
            "summary": self.summary,
            "body": self.body,
            "findings": [f.to_dict() for f in self.findings],
            "tables": [t_.to_dict() for t_ in self.tables],
            "subsections": [s.to_dict() for s in self.subsections],
        }


@dataclass(frozen=True, slots=True)
class Report:
    """
    A complete PMO report document.
    """
    meta: ReportMeta
    sections: tuple[Section, ...] = ()
    highlights: tuple[str, ...] = ()
    risks: tuple[str, ...] = ()
    decisions: tuple[str, ...] = ()
    metrics: dict[str, t.Any] = field(default_factory=dict)
    report_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        payload = _json_dumps(
            {
                "meta": self.meta.to_dict(),
                "sections": [s.to_dict() for s in self.sections],
                "highlights": list(self.highlights),
                "risks": list(self.risks),
                "decisions": list(self.decisions),
                "metrics": self.metrics,
            }
        )
        object.__setattr__(self, "report_fingerprint", _stable_hash(payload))

    def validate(self) -> "Report":
        if not isinstance(self.meta, ReportMeta):
            raise ReportValidationError("report.meta must be ReportMeta")
        self.meta.validate()

        if not isinstance(self.sections, tuple):
            raise ReportValidationError("report.sections must be a tuple[Section, ...]")
        for s in self.sections:
            if not isinstance(s, Section):
                raise ReportValidationError("report.sections must contain Section")
            s.validate()

        for name, seq in (("highlights", self.highlights), ("risks", self.risks), ("decisions", self.decisions)):
            if not isinstance(seq, tuple):
                raise ReportValidationError(f"report.{name} must be a tuple[str, ...]")
            for item in seq:
                if not isinstance(item, str) or not item.strip():
                    raise ReportValidationError(f"report.{name} items must be non-empty strings")

        if not isinstance(self.metrics, dict):
            raise ReportValidationError("report.metrics must be dict[str, Any]")

        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "meta": self.meta.to_dict(),
            "report_fingerprint": self.report_fingerprint,
            "sections": [s.to_dict() for s in self.sections],
            "highlights": list(self.highlights),
            "risks": list(self.risks),
            "decisions": list(self.decisions),
            "metrics": self.metrics,
        }

    def to_json(self) -> str:
        self.validate()
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)


class Redactor(t.Protocol):
    def redact(self, obj: t.Any) -> t.Any:
        """Return a redacted deep copy suitable for serialization."""


class DefaultRedactor:
    """
    Conservative redactor for secrets in dict-like payloads.
    This redactor is format-agnostic and operates on Python objects.

    Rules:
    - redact by key names (token, secret, password, api_key, private_key, etc.)
    - redact inline patterns that resemble credentials
    """

    _SENSITIVE_KEY_RE = re.compile(
        r"(?i)^(.*_)?(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|refresh[_-]?token|session|cookie)(_.+)?$"
    )
    _INLINE_CRED_RE = re.compile(
        r"(?i)\b("
        r"sk-[a-z0-9]{16,}"  # common API key prefix patterns
        r"|ghp_[a-z0-9]{20,}"
        r"|xox[baprs]-[a-z0-9-]{10,}"
        r"|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"  # JWT-like
        r")\b"
    )

    def __init__(self, redaction: str = "[REDACTED]") -> None:
        self._redaction = redaction

    def redact(self, obj: t.Any) -> t.Any:
        return self._redact_any(obj)

    def _redact_any(self, obj: t.Any) -> t.Any:
        if obj is None:
            return None
        if isinstance(obj, (bool, int, float)):
            return obj
        if isinstance(obj, str):
            return self._INLINE_CRED_RE.sub(self._redaction, obj)
        if isinstance(obj, (list, tuple)):
            red = [self._redact_any(x) for x in obj]
            return tuple(red) if isinstance(obj, tuple) else red
        if isinstance(obj, dict):
            out: dict[t.Any, t.Any] = {}
            for k, v in obj.items():
                ks = str(k)
                if self._SENSITIVE_KEY_RE.match(ks.strip()):
                    out[k] = self._redaction
                else:
                    out[k] = self._redact_any(v)
            return out
        if dataclasses.is_dataclass(obj):
            return self._redact_any(dataclasses.asdict(obj))
        return obj


class Renderer(t.Protocol):
    content_type: str
    file_ext: str

    def render(self, report: Report, *, redactor: Redactor | None = None) -> str:
        """Render report to a string."""


class JsonRenderer:
    content_type = "application/json; charset=utf-8"
    file_ext = ".json"

    def render(self, report: Report, *, redactor: Redactor | None = None) -> str:
        report.validate()
        payload = report.to_dict()
        if redactor is not None:
            payload = t.cast(dict[str, t.Any], redactor.redact(payload))
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _md_escape(text: str) -> str:
    # Minimal escaping for Markdown tables/text
    return text.replace("|", "\\|").replace("\r\n", "\n").replace("\r", "\n")


class MarkdownRenderer:
    content_type = "text/markdown; charset=utf-8"
    file_ext = ".md"

    def render(self, report: Report, *, redactor: Redactor | None = None) -> str:
        report.validate()
        payload = report.to_dict()
        if redactor is not None:
            payload = t.cast(dict[str, t.Any], redactor.redact(payload))

        meta = payload["meta"]
        lines: list[str] = []
        lines.append(f"# {_md_escape(meta['title'])}")
        lines.append("")
        lines.append(f"- Kind: `{meta['kind']}`")
        lines.append(f"- Created: `{meta['created_at']}`")
        lines.append(f"- Report ID: `{meta['report_id']}`")
        lines.append(f"- Trace ID: `{meta['trace_id']}`")
        lines.append(f"- Fingerprint: `{payload['report_fingerprint']}`")
        if meta.get("tags"):
            lines.append(f"- Tags: {', '.join(f'`{_md_escape(str(x))}`' for x in meta['tags'])}")
        lines.append("")

        def bullet_block(title: str, items: list[str]) -> None:
            if not items:
                return
            lines.append(f"## {title}")
            for it in items:
                lines.append(f"- {_md_escape(str(it))}")
            lines.append("")

        bullet_block("Highlights", payload.get("highlights", []))
        bullet_block("Risks", payload.get("risks", []))
        bullet_block("Decisions", payload.get("decisions", []))

        metrics = payload.get("metrics") or {}
        if metrics:
            lines.append("## Metrics")
            lines.append("```json")
            lines.append(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True))
            lines.append("```")
            lines.append("")

        def render_table(tbl: dict[str, t.Any]) -> None:
            title = _md_escape(str(tbl.get("title", "")))
            cols = [str(c) for c in (tbl.get("columns") or [])]
            rows = tbl.get("rows") or []
            lines.append(f"### {title}")
            lines.append("")
            if cols:
                lines.append("| " + " | ".join(_md_escape(c) for c in cols) + " |")
                lines.append("| " + " | ".join("---" for _ in cols) + " |")
                for r in rows:
                    r2 = ["" if x is None else str(x) for x in r]
                    lines.append("| " + " | ".join(_md_escape(x) for x in r2) + " |")
                lines.append("")
            notes = (tbl.get("notes") or "").strip()
            if notes:
                lines.append(_md_escape(notes))
                lines.append("")

        def render_findings(findings: list[dict[str, t.Any]]) -> None:
            if not findings:
                return
            lines.append("### Findings")
            lines.append("")
            for f in findings:
                lines.append(f"- `{f.get('severity')}` `{f.get('status')}` `{f.get('finding_id')}` {_md_escape(str(f.get('title','')))}")
                desc = (f.get("description") or "").strip()
                if desc:
                    lines.append(f"  - {_md_escape(desc)}")
                owner = (f.get("owner") or "").strip()
                if owner:
                    lines.append(f"  - Owner: `{_md_escape(owner)}`")
                refs = f.get("references") or []
                if refs:
                    lines.append("  - References:")
                    for r in refs:
                        lines.append(f"    - {_md_escape(str(r))}")
                labels = f.get("labels") or []
                if labels:
                    lines.append("  - Labels: " + ", ".join(f"`{_md_escape(str(x))}`" for x in labels))
            lines.append("")

        def render_section(sec: dict[str, t.Any], depth: int) -> None:
            h = "#" * min(6, max(2, depth))
            lines.append(f"{h} {_md_escape(str(sec.get('title','')))}")
            lines.append("")
            summary = (sec.get("summary") or "").strip()
            if summary:
                lines.append(_md_escape(summary))
                lines.append("")
            body = (sec.get("body") or "").strip()
            if body:
                lines.append(_md_escape(body))
                lines.append("")
            render_findings(sec.get("findings") or [])
            for tbl in (sec.get("tables") or []):
                render_table(tbl)
            for sub in (sec.get("subsections") or []):
                render_section(sub, depth + 1)

        for s in payload.get("sections") or []:
            render_section(s, 2)

        return "\n".join(lines).rstrip() + "\n"


class TextRenderer:
    content_type = "text/plain; charset=utf-8"
    file_ext = ".txt"

    def render(self, report: Report, *, redactor: Redactor | None = None) -> str:
        report.validate()
        payload = report.to_dict()
        if redactor is not None:
            payload = t.cast(dict[str, t.Any], redactor.redact(payload))

        meta = payload["meta"]
        out: list[str] = []
        out.append(meta["title"])
        out.append("=" * min(120, max(10, len(meta["title"]))))
        out.append(f"Kind: {meta['kind']}")
        out.append(f"Created: {meta['created_at']}")
        out.append(f"Report ID: {meta['report_id']}")
        out.append(f"Trace ID: {meta['trace_id']}")
        out.append(f"Fingerprint: {payload['report_fingerprint']}")
        if meta.get("tags"):
            out.append("Tags: " + ", ".join(str(x) for x in meta["tags"]))
        out.append("")

        def block(title: str, items: list[str]) -> None:
            if not items:
                return
            out.append(title)
            out.append("-" * min(120, max(5, len(title))))
            for it in items:
                out.append(f"* {str(it)}")
            out.append("")

        block("Highlights", payload.get("highlights", []))
        block("Risks", payload.get("risks", []))
        block("Decisions", payload.get("decisions", []))

        metrics = payload.get("metrics") or {}
        if metrics:
            out.append("Metrics")
            out.append("-" * 7)
            out.append(_json_dumps(metrics))
            out.append("")

        def render_table(tbl: dict[str, t.Any]) -> None:
            title = str(tbl.get("title", ""))
            cols = [str(c) for c in (tbl.get("columns") or [])]
            rows = tbl.get("rows") or []
            out.append(f"Table: {title}")
            out.append("-" * min(120, max(6, len(title) + 7)))
            if not cols:
                out.append("(no columns)")
                out.append("")
                return
            widths = [len(c) for c in cols]
            for r in rows:
                for i, cell in enumerate(r):
                    s = "" if cell is None else str(cell)
                    widths[i] = max(widths[i], len(s))
            header = " | ".join(cols[i].ljust(widths[i]) for i in range(len(cols)))
            sep = "-+-".join("-" * widths[i] for i in range(len(cols)))
            out.append(header)
            out.append(sep)
            for r in rows:
                r2 = ["" if x is None else str(x) for x in r]
                out.append(" | ".join(r2[i].ljust(widths[i]) for i in range(len(cols))))
            notes = (tbl.get("notes") or "").strip()
            if notes:
                out.append("")
                out.append(notes)
            out.append("")

        def render_findings(findings: list[dict[str, t.Any]]) -> None:
            if not findings:
                return
            out.append("Findings")
            out.append("-" * 8)
            for f in findings:
                out.append(f"[{f.get('severity')}/{f.get('status')}] {f.get('finding_id')} {f.get('title')}")
                desc = (f.get("description") or "").strip()
                if desc:
                    out.append(f"  - {desc}")
                owner = (f.get("owner") or "").strip()
                if owner:
                    out.append(f"  - Owner: {owner}")
                refs = f.get("references") or []
                if refs:
                    out.append("  - References:")
                    for r in refs:
                        out.append(f"    - {r}")
                labels = f.get("labels") or []
                if labels:
                    out.append("  - Labels: " + ", ".join(str(x) for x in labels))
            out.append("")

        def render_section(sec: dict[str, t.Any], indent: int) -> None:
            pad = " " * indent
            out.append(f"{pad}{sec.get('title','')}")
            out.append(f"{pad}" + "-" * min(120 - indent, max(3, len(str(sec.get('title',''))))))
            summary = (sec.get("summary") or "").strip()
            if summary:
                out.append(f"{pad}{summary}")
                out.append("")
            body = (sec.get("body") or "").strip()
            if body:
                for line in body.splitlines():
                    out.append(f"{pad}{line}")
                out.append("")
            render_findings(sec.get("findings") or [])
            for tbl in (sec.get("tables") or []):
                render_table(tbl)
            for sub in (sec.get("subsections") or []):
                render_section(sub, indent + 2)

        for s in payload.get("sections") or []:
            render_section(s, 0)

        return "\n".join(out).rstrip() + "\n"


class ReportStore(t.Protocol):
    """
    Store interface for report artifacts.
    """
    def save(
        self,
        report: Report,
        *,
        renderer: Renderer,
        redactor: Redactor | None = None,
        compress_gzip: bool = False,
        filename_hint: str | None = None,
    ) -> Path:
        ...


class FileReportStore:
    """
    Durable report artifact store on filesystem.

    Features:
    - atomic write (tempfile -> os.replace)
    - optional gzip compression
    - directory creation
    - safe filenames
    """

    _SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")

    def __init__(self, base_dir: str | os.PathLike[str]) -> None:
        self.base_dir = Path(base_dir)

    def save(
        self,
        report: Report,
        *,
        renderer: Renderer,
        redactor: Redactor | None = None,
        compress_gzip: bool = False,
        filename_hint: str | None = None,
    ) -> Path:
        report.validate()

        self.base_dir.mkdir(parents=True, exist_ok=True)

        safe_hint = self._safe_name(filename_hint) if filename_hint else None
        meta = report.meta
        ts = meta.created_at.strftime("%Y%m%dT%H%M%SZ")
        kind = meta.kind.value
        stem = safe_hint or f"{kind}_{ts}_{meta.report_id}_{report.report_fingerprint}"
        ext = renderer.file_ext + (".gz" if compress_gzip else "")
        out_path = (self.base_dir / (stem + ext)).resolve()

        try:
            content = renderer.render(report, redactor=redactor)
            self._atomic_write(out_path, content.encode("utf-8"), gzip_compress=compress_gzip)
            return out_path
        except Exception as e:
            raise ReportIOError(f"failed to save report to {out_path}: {e}") from e

    @classmethod
    def _safe_name(cls, name: str) -> str:
        name = name.strip()
        name = cls._SAFE_NAME_RE.sub("_", name)
        name = name.strip("._-")
        return name[:180] if name else "report"

    @staticmethod
    def _atomic_write(path: Path, data: bytes, *, gzip_compress: bool) -> None:
        """
        Atomic write to final path.
        If gzip_compress=True, data is written as gzip stream.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        fd: int | None = None
        tmp_path: str | None = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
            with os.fdopen(fd, "wb") as f:
                if gzip_compress:
                    with gzip.GzipFile(filename=path.name, mode="wb", fileobj=f, compresslevel=6) as gz:
                        gz.write(data)
                else:
                    f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(path))
        finally:
            if tmp_path is not None:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    # best-effort cleanup
                    pass


class ReportBuilder:
    """
    Ergonomic builder to create validated reports without mutable dataclasses leakage.
    """

    def __init__(
        self,
        *,
        kind: ReportKind,
        title: str,
        source: str = "agent_mash.pmo",
        version: str = "1.0",
        tags: t.Iterable[str] = (),
        context: dict[str, t.Any] | None = None,
        created_at: _dt.datetime | None = None,
        report_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        self._meta = ReportMeta(
            kind=kind,
            title=title,
            source=source,
            version=version,
            tags=tuple(str(x) for x in tags),
            context=dict(context or {}),
            created_at=_as_utc(created_at) if created_at is not None else _utc_now(),
            report_id=report_id or uuid.uuid4().hex,
            trace_id=trace_id or uuid.uuid4().hex,
        ).validate()

        self._sections: list[Section] = []
        self._highlights: list[str] = []
        self._risks: list[str] = []
        self._decisions: list[str] = []
        self._metrics: dict[str, t.Any] = {}

    def add_highlight(self, text: str) -> "ReportBuilder":
        self._highlights.append(_require_non_empty("highlight", text))
        return self

    def add_risk(self, text: str) -> "ReportBuilder":
        self._risks.append(_require_non_empty("risk", text))
        return self

    def add_decision(self, text: str) -> "ReportBuilder":
        self._decisions.append(_require_non_empty("decision", text))
        return self

    def metric(self, key: str, value: t.Any) -> "ReportBuilder":
        key = _require_non_empty("metric.key", key)
        _require_len_at_most("metric.key", key, 120)
        self._metrics[key] = value
        return self

    def add_section(self, section: Section) -> "ReportBuilder":
        if not isinstance(section, Section):
            raise ReportValidationError("add_section expects Section")
        section.validate()
        self._sections.append(section)
        return self

    def section(
        self,
        *,
        title: str,
        summary: str = "",
        body: str = "",
        findings: t.Iterable[Finding] = (),
        tables: t.Iterable[Table] = (),
        subsections: t.Iterable[Section] = (),
    ) -> "ReportBuilder":
        sec = Section(
            title=title,
            summary=summary,
            body=body,
            findings=tuple(findings),
            tables=tuple(tables),
            subsections=tuple(subsections),
        ).validate()
        self._sections.append(sec)
        return self

    def build(self) -> Report:
        rep = Report(
            meta=self._meta,
            sections=tuple(self._sections),
            highlights=tuple(self._highlights),
            risks=tuple(self._risks),
            decisions=tuple(self._decisions),
            metrics=dict(self._metrics),
        ).validate()
        return rep
