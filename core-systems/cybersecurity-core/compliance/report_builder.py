# cybersecurity/compliance/report_builder.py
# Industrial-grade compliance report builder for Aethernova cybersecurity-core
from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import hmac
import json
import logging
import os
import re
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from uuid import UUID, uuid4

logger = logging.getLogger("cybersecurity.compliance.report_builder")

# Optional deps
try:
    from jinja2 import Environment, Template, FileSystemLoader, StrictUndefined, select_autoescape  # type: ignore
    _HAS_JINJA = True
except Exception:  # pragma: no cover
    _HAS_JINJA = False

try:
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

# ========= Exceptions =========

class ReportError(Exception):
    pass

class ValidationError(ReportError):
    pass

class SigningError(ReportError):
    pass

# ========= Enums & helpers =========

class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

_SEV_ORDER = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.informational: 1,
}

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _stable_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:100] or "section"

# ========= Data models =========

@dataclass
class FrameworkRef:
    name: str                     # e.g., "ISO/IEC 27001:2022"
    domain: Optional[str] = None  # e.g., "A.5", "AC-2"
    control_id: Optional[str] = None  # e.g., "A.5.1", "CM-6"
    link: Optional[str] = None

    def key(self) -> Tuple[str, str, str]:
        return (
            (self.name or "").lower(),
            (self.domain or "").lower(),
            (self.control_id or "").lower(),
        )

@dataclass
class Evidence:
    title: str
    description: Optional[str] = None
    collected_at: str = field(default_factory=_now_iso)
    content_b64: Optional[str] = None         # inline base64 content
    file_path: Optional[str] = None           # path to external file (read at build-time if embed=True)
    media_type: Optional[str] = None          # e.g., "application/pdf", "image/png"
    sha256: Optional[str] = None
    size: Optional[int] = None

    def compute_hashes(self, embed: bool = False) -> None:
        if self.content_b64:
            raw = base64.b64decode(self.content_b64)
            self.sha256 = _sha256_hex(raw)
            self.size = len(raw)
        elif embed and self.file_path:
            p = Path(self.file_path)
            data = p.read_bytes()
            self.content_b64 = base64.b64encode(data).decode("ascii")
            self.sha256 = _sha256_hex(data)
            self.size = len(data)
        elif self.file_path:
            p = Path(self.file_path)
            self.size = p.stat().st_size
            # Hash without loading entire huge file into memory
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            self.sha256 = h.hexdigest()

@dataclass
class Control:
    control_id: str
    title: str
    description: Optional[str] = None
    framework_refs: List[FrameworkRef] = field(default_factory=list)
    implemented: bool = False
    owner: Optional[str] = None
    tags: List[str] = field(default_factory=list)

@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    control_id: Optional[str] = None
    framework_refs: List[FrameworkRef] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    status: str = "open"  # open | in_progress | risk_accepted | remediated

@dataclass
class ReportMeta:
    report_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = "Compliance Report"
    organization: str = "Organization"
    environment: str = "prod"
    period_start: Optional[str] = None
    period_end: Optional[str] = None
    generated_at: str = field(default_factory=_now_iso)
    generator_version: str = "1.0.0"
    tlp: Optional[str] = None  # TLP:CLEAR|GREEN|AMBER|AMBER+STRICT|RED

@dataclass
class ReportData:
    meta: ReportMeta
    controls: List[Control] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence_inline_limit_kb: int = 256
    # Calculated fields
    aggregates: Dict[str, Any] = field(default_factory=dict)
    content_hash: Optional[str] = None
    signature: Optional[str] = None
    signature_alg: Optional[str] = None

# ========= Renderer interfaces =========

class Renderer:
    def render(self, data: ReportData, *, template_dir: Optional[Path] = None) -> str:
        raise NotImplementedError

class MarkdownRenderer(Renderer):
    def __init__(self, include_toc: bool = True) -> None:
        self.include_toc = include_toc

    def render(self, data: ReportData, *, template_dir: Optional[Path] = None) -> str:
        if _HAS_JINJA:
            env = Environment(
                loader=FileSystemLoader(str(template_dir)) if template_dir else None,
                autoescape=select_autoescape(enabled_extensions=("html",), default=False),
                undefined=StrictUndefined,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            template_text = _DEFAULT_MD_TEMPLATE
            tmpl = env.from_string(template_text)
            return tmpl.render(d=dataclasses.asdict(data))
        # Fallback without Jinja
        return _fallback_markdown(data)

class HTMLRenderer(Renderer):
    def __init__(self, inline_css: bool = True) -> None:
        self.inline_css = inline_css

    def render(self, data: ReportData, *, template_dir: Optional[Path] = None) -> str:
        css = _DEFAULT_CSS if self.inline_css else ""
        if _HAS_JINJA:
            env = Environment(
                loader=FileSystemLoader(str(template_dir)) if template_dir else None,
                autoescape=select_autoescape(enabled_extensions=("html",), default=True),
                undefined=StrictUndefined,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            tmpl = env.from_string(_DEFAULT_HTML_TEMPLATE)
            return tmpl.render(d=dataclasses.asdict(data), css=css)
        # Fallback assemble
        md = _fallback_markdown(data)
        body = f"<pre>{_html_escape(md)}</pre>"
        return f"<!DOCTYPE html><html><head><meta charset='utf-8'><style>{css}</style></head><body>{body}</body></html>"

# ========= ReportBuilder =========

class ReportBuilder:
    """
    Industrial builder:
    - add controls/findings/evidence
    - validate cross-links
    - compute aggregates and coverage
    - render to Markdown/HTML (JSON via to_dict)
    - integrity hash and optional signature
    """

    def __init__(self, meta: ReportMeta) -> None:
        self._data = ReportData(meta=meta)
        self._controls_idx: Dict[str, Control] = {}
        self._framework_index: Dict[Tuple[str, str, str], List[str]] = {}

    # ---- mutators ----

    def add_control(self, control: Control) -> None:
        self._assert_nonempty(control.control_id, "control_id")
        if control.control_id in self._controls_idx:
            raise ValidationError(f"duplicate control_id: {control.control_id}")
        self._data.controls.append(control)
        self._controls_idx[control.control_id] = control
        for fr in control.framework_refs:
            self._framework_index.setdefault(fr.key(), []).append(control.control_id)

    def add_finding(self, finding: Finding) -> None:
        self._assert_nonempty(finding.id, "finding.id")
        if any(f.id == finding.id for f in self._data.findings):
            raise ValidationError(f"duplicate finding id: {finding.id}")
        # bind to existing control if specified
        if finding.control_id and finding.control_id not in self._controls_idx:
            raise ValidationError(f"unknown control_id in finding {finding.id}: {finding.control_id}")
        self._data.findings.append(finding)

    def add_evidence_to_finding(self, finding_id: str, evidence: Evidence, *, embed: bool = False) -> None:
        f = next((x for x in self._data.findings if x.id == finding_id), None)
        if not f:
            raise ValidationError(f"finding not found: {finding_id}")
        evidence.compute_hashes(embed=embed)
        if evidence.content_b64 and (len(evidence.content_b64) * 3) // 4 > self._data.evidence_inline_limit_kb * 1024:
            logger.info("Evidence too large for inline, keeping by path only: %s", evidence.title)
            # Keep only metadata and hash
            evidence.content_b64 = None
        f.evidence.append(evidence)

    # ---- build & validation ----

    def validate(self) -> None:
        if not self._data.controls and not self._data.findings:
            raise ValidationError("report is empty")
        # ensure all findings have framework refs or control binding
        for f in self._data.findings:
            if not f.control_id and not f.framework_refs:
                raise ValidationError(f"finding {f.id} must reference control_id or framework_refs")
            # evidence size sanity
            for ev in f.evidence:
                if ev.size is not None and ev.size < 0:
                    raise ValidationError(f"evidence size is invalid for {ev.title}")
        # time sanity (optional)
        ps, pe = self._data.meta.period_start, self._data.meta.period_end
        if ps and pe and ps > pe:
            raise ValidationError("period_start must be <= period_end")

    def compute_aggregates(self) -> None:
        # Coverage: implemented vs total
        total_controls = len(self._data.controls)
        implemented = sum(1 for c in self._data.controls if c.implemented)
        # Severity distribution
        sev_counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._data.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        # Framework coverage (unique control_ids per framework ref key)
        fw_cov: Dict[str, int] = {}
        for key, ctrl_ids in self._framework_index.items():
            fw = key[0] or "unknown"
            fw_cov[fw] = fw_cov.get(fw, 0) + len(set(ctrl_ids))

        aggregates = {
            "controls": {
                "total": total_controls,
                "implemented": implemented,
                "coverage_pct": round(100.0 * implemented / total_controls, 2) if total_controls else 0.0,
            },
            "findings": {
                "total": len(self._data.findings),
                "by_severity": sev_counts,
                "open": sum(1 for f in self._data.findings if f.status in ("open", "in_progress")),
                "closed": sum(1 for f in self._data.findings if f.status in ("remediated", "risk_accepted")),
            },
            "framework": fw_cov,
        }
        self._data.aggregates = aggregates

    def seal(self, *, hmac_secret: Optional[bytes] = None,
             rsa_private_key_pem: Optional[bytes] = None) -> None:
        """
        Compute deterministic content hash and optional signature.
        - If rsa_private_key_pem provided and cryptography available -> RSA-PSS-SHA256 signature
        - Else if hmac_secret provided -> HMAC-SHA256
        """
        payload = self.to_dict(include_signature=False)
        payload["__template_version__"] = "md:v1;html:v1"
        normalized = _stable_json(payload)
        content_hash = _sha256_hex(normalized)
        self._data.content_hash = content_hash

        if rsa_private_key_pem and _HAS_CRYPTO:
            try:
                key = load_pem_private_key(rsa_private_key_pem, password=None)
                sig = key.sign(
                    normalized,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
                self._data.signature = base64.b64encode(sig).decode("ascii")
                self._data.signature_alg = "RSA-PSS-SHA256"
            except Exception as e:
                raise SigningError(f"RSA signing failed: {e}") from e
        elif hmac_secret:
            sig = hmac.new(hmac_secret, normalized, hashlib.sha256).digest()
            self._data.signature = base64.b64encode(sig).decode("ascii")
            self._data.signature_alg = "HMAC-SHA256"

    # ---- renderers ----

    def render_markdown(self, *, template_dir: Optional[Union[str, Path]] = None) -> str:
        self.validate()
        self.compute_aggregates()
        return MarkdownRenderer().render(self._data, template_dir=Path(template_dir) if template_dir else None)

    def render_html(self, *, template_dir: Optional[Union[str, Path]] = None, inline_css: bool = True) -> str:
        self.validate()
        self.compute_aggregates()
        return HTMLRenderer(inline_css=inline_css).render(self._data, template_dir=Path(template_dir) if template_dir else None)

    # ---- exports ----

    def to_dict(self, *, include_signature: bool = True) -> Dict[str, Any]:
        d = dataclasses.asdict(self._data)
        if not include_signature:
            d.pop("signature", None)
            d.pop("signature_alg", None)
        return d

    def to_json(self, *, include_signature: bool = True) -> str:
        return _stable_json(self.to_dict(include_signature=include_signature)).decode("utf-8")

    # ---- utils ----

    @staticmethod
    def _assert_nonempty(value: Optional[str], name: str) -> None:
        if not value or not str(value).strip():
            raise ValidationError(f"{name} is required")

# ========= Fallback markdown (no Jinja) =========

def _fallback_markdown(data: ReportData) -> str:
    d = dataclasses.asdict(data)
    meta = d["meta"]
    aggr = d.get("aggregates") or {}
    lines: List[str] = []
    lines.append(f"# {meta['title']}")
    if meta.get("tlp"):
        lines.append(f"**TLP:** {meta['tlp']}")
    lines.append("")
    lines.append(f"Generated at: {meta['generated_at']} | Report ID: {meta['report_id']}")
    lines.append(f"Organization: {meta['organization']} | Environment: {meta['environment']}")
    if meta.get("period_start") or meta.get("period_end"):
        lines.append(f"Period: {meta.get('period_start') or '-'} — {meta.get('period_end') or '-'}")
    lines.append("")
    # Summary
    lines.append("## Summary")
    if aggr:
        c = aggr.get("controls", {})
        f = aggr.get("findings", {})
        lines.append(f"- Controls: {c.get('implemented', 0)}/{c.get('total', 0)} implemented ({c.get('coverage_pct', 0)}%)")
        lines.append(f"- Findings total: {f.get('total', 0)}; open={f.get('open', 0)}, closed={f.get('closed', 0)}")
        sev = f.get("by_severity", {})
        if sev:
            lines.append(f"- Severity: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
    lines.append("")
    # Controls
    controls: List[Dict[str, Any]] = d["controls"]
    if controls:
        lines.append("## Controls")
        for c in sorted(controls, key=lambda x: (not x["implemented"], x["control_id"])):
            mark = "✅" if c["implemented"] else "❌"
            lines.append(f"### {mark} {c['control_id']} — {c['title']}")
            if c.get("description"):
                lines.append(c["description"])
            if c.get("owner"):
                lines.append(f"_Owner: {c['owner']}_")
            if c.get("framework_refs"):
                refs = []
                for fr in c["framework_refs"]:
                    part = " / ".join(filter(None, [fr.get("name"), fr.get("domain"), fr.get("control_id")]))
                    if fr.get("link"):
                        part += f" ({fr['link']})"
                    refs.append(part)
                lines.append("Refs: " + "; ".join(refs))
            lines.append("")
    # Findings
    findings: List[Dict[str, Any]] = d["findings"]
    if findings:
        lines.append("## Findings")
        for f in sorted(findings, key=lambda x: (_SEV_ORDER[Severity(x["severity"])], x["title"]), reverse=True):
            lines.append(f"### [{f['severity'].upper()}] {f['title']} (id: {f['id']})")
            lines.append(f"Status: {f['status']} | Created: {f['created_at']}")
            if f.get("control_id"):
                lines.append(f"Control: {f['control_id']}")
            if f.get("framework_refs"):
                refs = []
                for fr in f["framework_refs"]:
                    refs.append(" / ".join(filter(None, [fr.get("name"), fr.get("domain"), fr.get("control_id")])))
                lines.append("Framework: " + "; ".join(refs))
            lines.append("")
            lines.append(f["description"])
            if f.get("affected_assets"):
                lines.append("")
                lines.append("Affected assets:")
                for a in f["affected_assets"]:
                    lines.append(f"- {a}")
            if f.get("recommendation"):
                lines.append("")
                lines.append("Recommendation:")
                lines.append(f["recommendation"])
            if f.get("evidence"):
                lines.append("")
                lines.append("Evidence:")
                for ev in f["evidence"]:
                    sz = f"{ev.get('size', 0)} B" if ev.get("size") else "-"
                    lines.append(f"- {ev['title']} (sha256={ev.get('sha256') or '-'}, size={sz})")
            lines.append("")
    # Integrity
    if d.get("content_hash"):
        lines.append("---")
        lines.append(f"Content-Hash-SHA256: `{d['content_hash']}`")
    if d.get("signature"):
        lines.append(f"Signature ({d.get('signature_alg','-')}): `{d['signature']}`")
    return "\n".join(lines)

# ========= HTML helpers/templates =========

_DEFAULT_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial,'Noto Sans',sans-serif;line-height:1.5;color:#111}
h1,h2,h3{line-height:1.2}
code,pre{font-family:ui-monospace,Consolas,Menlo,monospace}
.table{width:100%;border-collapse:collapse;margin:1rem 0}
.table th,.table td{border:1px solid #ddd;padding:.5rem;text-align:left}
.badge{display:inline-block;padding:.15rem .4rem;border-radius:.25rem;background:#eee}
.sev-critical{background:#b71c1c;color:#fff}
.sev-high{background:#e53935;color:#fff}
.sev-medium{background:#fb8c00;color:#fff}
.sev-low{background:#43a047;color:#fff}
.sev-informational{background:#546e7a;color:#fff}
.footer{margin-top:2rem;color:#555;font-size:.9rem}
"""

_DEFAULT_HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ d.meta.title }}</title>
<style>{{ css }}</style>
</head>
<body>
<h1>{{ d.meta.title }}</h1>
{% if d.meta.tlp %}<p><strong>TLP:</strong> {{ d.meta.tlp }}</p>{% endif %}
<p>Generated at: {{ d.meta.generated_at }} | Report ID: {{ d.meta.report_id }}</p>
<p>Organization: {{ d.meta.organization }} | Environment: {{ d.meta.environment }}</p>
{% if d.meta.period_start or d.meta.period_end -%}
<p>Period: {{ d.meta.period_start or '-' }} — {{ d.meta.period_end or '-' }}</p>
{%- endif %}

<h2>Summary</h2>
<table class="table">
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Controls implemented</td><td>{{ d.aggregates.controls.implemented }}/{{ d.aggregates.controls.total }} ({{ d.aggregates.controls.coverage_pct }}%)</td></tr>
<tr><td>Findings total</td><td>{{ d.aggregates.findings.total }}</td></tr>
<tr><td>Open findings</td><td>{{ d.aggregates.findings.open }}</td></tr>
<tr><td>Closed findings</td><td>{{ d.aggregates.findings.closed }}</td></tr>
</table>

{% if d.controls %}
<h2>Controls</h2>
{% for c in d.controls %}
<h3>{{ "✅" if c.implemented else "❌" }} {{ c.control_id }} — {{ c.title }}</h3>
{% if c.description %}<p>{{ c.description }}</p>{% endif %}
{% if c.owner %}<p><em>Owner: {{ c.owner }}</em></p>{% endif %}
{% if c.framework_refs %}
<p>Refs:
{% for fr in c.framework_refs -%}
{{ fr.name }}{% if fr.domain %}/{{ fr.domain }}{% endif %}{% if fr.control_id %}/{{ fr.control_id }}{% endif %}{% if fr.link %} ({{ fr.link }}){% endif %}{% if not loop.last %}; {% endif %}
{%- endfor %}
</p>
{% endif %}
{% endfor %}
{% endif %}

{% if d.findings %}
<h2>Findings</h2>
{% for f in d.findings %}
<h3><span class="badge sev-{{ f.severity }}">{{ f.severity.upper() }}</span> {{ f.title }} <small>(id: {{ f.id }})</small></h3>
<p>Status: {{ f.status }} | Created: {{ f.created_at }}</p>
{% if f.control_id %}<p>Control: {{ f.control_id }}</p>{% endif %}
{% if f.framework_refs %}
<p>Framework:
{% for fr in f.framework_refs -%}
{{ fr.name }}{% if fr.domain %}/{{ fr.domain }}{% endif %}{% if fr.control_id %}/{{ fr.control_id }}{% endif %}{% if not loop.last %}; {% endif %}
{%- endfor %}
</p>
{% endif %}
<p>{{ f.description }}</p>
{% if f.affected_assets %}
<p><strong>Affected assets:</strong></p>
<ul>
{% for a in f.affected_assets %}<li>{{ a }}</li>{% endfor %}
</ul>
{% endif %}
{% if f.recommendation %}
<p><strong>Recommendation:</strong> {{ f.recommendation }}</p>
{% endif %}
{% if f.evidence %}
<p><strong>Evidence:</strong></p>
<ul>
{% for ev in f.evidence %}
<li>{{ ev.title }} — sha256={{ ev.sha256 or "-" }}, size={{ ev.size or "-" }}{% if ev.media_type %} ({{ ev.media_type }}){% endif %}</li>
{% endfor %}
</ul>
{% endif %}
{% endfor %}
{% endif %}

<hr>
<div class="footer">
{% if d.content_hash %}<div>Content-Hash-SHA256: <code>{{ d.content_hash }}</code></div>{% endif %}
{% if d.signature %}<div>Signature ({{ d.signature_alg or "-" }}): <code>{{ d.signature }}</code></div>{% endif %}
<div>Generator: v{{ d.meta.generator_version }}</div>
</div>

</body>
</html>
"""

_DEFAULT_MD_TEMPLATE = r"""
# {{ d.meta.title }}
{% if d.meta.tlp -%}
**TLP:** {{ d.meta.tlp }}
{%- endif %}

Generated at: {{ d.meta.generated_at }} | Report ID: {{ d.meta.report_id }}
Organization: {{ d.meta.organization }} | Environment: {{ d.meta.environment }}
{% if d.meta.period_start or d.meta.period_end -%}
Period: {{ d.meta.period_start or '-' }} — {{ d.meta.period_end or '-' }}
{%- endif %}

## Summary
- Controls: {{ d.aggregates.controls.implemented }}/{{ d.aggregates.controls.total }} implemented ({{ d.aggregates.controls.coverage_pct }}%)
- Findings total: {{ d.aggregates.findings.total }}; open={{ d.aggregates.findings.open }}, closed={{ d.aggregates.findings.closed }}
- Severity: {% for k,v in d.aggregates.findings.by_severity.items() %}{{ k }}={{ v }}{% if not loop.last %}, {% endif %}{% endfor %}

{% if d.controls %}
## Controls
{% for c in d.controls %}
### {{ "✅" if c.implemented else "❌" }} {{ c.control_id }} — {{ c.title }}
{% if c.description %}{{ c.description }}{% endif %}
{% if c.owner %}_Owner: {{ c.owner }}_{% endif %}
{% if c.framework_refs %}
Refs: {% for fr in c.framework_refs -%}
{{ fr.name }}{% if fr.domain %}/{{ fr.domain }}{% endif %}{% if fr.control_id %}/{{ fr.control_id }}{% endif %}{% if fr.link %} ({{ fr.link }}){% endif %}{% if not loop.last %}; {% endif %}
{%- endfor %}
{% endif %}

{% endfor %}
{% endif %}

{% if d.findings %}
## Findings
{% for f in d.findings %}
### [{{ f.severity.upper() }}] {{ f.title }} (id: {{ f.id }})
Status: {{ f.status }} | Created: {{ f.created_at }}
{% if f.control_id %}Control: {{ f.control_id }}{% endif %}
{% if f.framework_refs %}Framework: {% for fr in f.framework_refs -%}
{{ fr.name }}{% if fr.domain %}/{{ fr.domain }}{% endif %}{% if fr.control_id %}/{{ fr.control_id }}{% endif %}{% if not loop.last %}; {% endif %}
{%- endfor %}{% endif %}

{{ f.description }}
{% if f.affected_assets %}
Affected assets:
{% for a in f.affected_assets -%}
- {{ a }}
{%- endfor %}
{% endif %}
{% if f.recommendation %}
Recommendation:
{{ f.recommendation }}
{% endif %}
{% if f.evidence %}
Evidence:
{% for ev in f.evidence -%}
- {{ ev.title }} (sha256={{ ev.sha256 or "-" }}, size={{ ev.size or "-" }}){% if ev.media_type %} [{{ ev.media_type }}]{% endif %}
{%- endfor %}
{% endif %}

{% endfor %}
{% endif %}

---
{% if d.content_hash %}Content-Hash-SHA256: `{{ d.content_hash }}`{% endif %}
{% if d.signature %}Signature ({{ d.signature_alg or "-" }}): `{{ d.signature }}`{% endif %}
"""

def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ========= End of file =========
