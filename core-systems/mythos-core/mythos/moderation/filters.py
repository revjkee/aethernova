from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# =========================
# Core enums and models
# =========================

class Severity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(enum.Enum):
    ALLOW = "allow"
    REVIEW = "review"
    MASK_PII = "mask_pii"
    QUARANTINE_ATTACHMENTS = "quarantine_attachments"
    BLOCK = "block"


@dataclass
class AttachmentIn:
    filename: str
    mime: str
    size: int  # bytes


@dataclass
class ClassifierScores:
    toxicity: float = 0.0
    hate: float = 0.0
    sexual: float = 0.0
    violence: float = 0.0
    threat: float = 0.0
    self_harm: float = 0.0
    spam: float = 0.0


@dataclass
class SignalsIn:
    classifiers: ClassifierScores = field(default_factory=ClassifierScores)
    url_domains: List[str] = field(default_factory=list)
    url_risk: Dict[str, str] = field(default_factory=dict)  # domain -> low|medium|high


@dataclass
class ContentIn:
    text: Optional[str] = None
    html: Optional[str] = None
    attachments: List[AttachmentIn] = field(default_factory=list)


@dataclass
class UserIn:
    id: Optional[str] = None
    role: Optional[str] = None  # admin/editor/user
    trust: Optional[str] = None  # low|normal|high


@dataclass
class ContextIn:
    resource: Optional[str] = None  # lore|chat|profile
    action: Optional[str] = None    # create|update
    path: Optional[str] = None      # /api/v1/...


@dataclass
class ModerationInput:
    tenant: Optional[str] = None
    user: UserIn = field(default_factory=UserIn)
    context: ContextIn = field(default_factory=ContextIn)
    content: ContentIn = field(default_factory=ContentIn)
    signals: SignalsIn = field(default_factory=SignalsIn)
    tenant_overrides: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Reason:
    code: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    weight: int = 1
    block: bool = False
    span: Optional[Tuple[int, int]] = None  # start, end offsets in text


@dataclass
class Decision:
    allow: bool
    severity: Severity
    actions: List[Action]
    reasons: List[Reason]
    tags: Dict[str, bool]
    applied: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(
            {
                "allow": self.allow,
                "severity": self.severity.value,
                "actions": [a.value for a in self.actions],
                "reasons": [asdict(r) for r in self.reasons],
                "tags": self.tags,
                "applied": self.applied,
            },
            ensure_ascii=False,
        )


# =========================
# Configuration (defaults + overrides)
# =========================

@dataclass
class Thresholds:
    toxicity: float = 0.85
    hate: float = 0.80
    sexual: float = 0.80
    violence: float = 0.80
    threat: float = 0.70
    self_harm: float = 0.70
    spam: float = 0.90
    max_len_text: int = 20000
    max_attach_mb: int = 25
    max_attachments: int = 16


@dataclass
class FeatureFlags:
    pii_masking_enabled: bool = True
    allow_trusted_high: bool = False  # allow bypass for non-blocking violations only


@dataclass
class Weights:
    PII_EMAIL: int = 1
    PII_PHONE: int = 1
    PII_CARD: int = 3
    CLASS_TOXICITY: int = 3
    CLASS_HATE: int = 4
    CLASS_SEXUAL: int = 3
    CLASS_VIOLENCE: int = 3
    CLASS_THREAT: int = 4
    CLASS_SELF_HARM: int = 4
    CLASS_SPAM: int = 2
    URL_BAD_REPUTATION: int = 3
    URL_BANNED_TLD: int = 2
    ATTACH_DANGEROUS_MIME: int = 4
    ATTACH_TOO_LARGE: int = 2
    ATTACH_TOO_MANY: int = 1
    LEN_TOO_LONG: int = 1
    LEXICON_MATCH: int = 3


@dataclass
class Lists:
    banned_tlds: List[str] = field(default_factory=lambda: ["zip", "mov", "country", "click"])
    dangerous_mime_prefixes: List[str] = field(default_factory=lambda: [
        "application/x-dosexec",
        "application/x-msdownload",
        "application/x-sh",
        "application/java-archive",
    ])
    banned_ext: List[str] = field(default_factory=lambda: [".exe", ".bat", ".cmd", ".com", ".js", ".jar", ".scr", ".ps1", ".vbs"])
    bad_domains: List[str] = field(default_factory=list)
    denylist: List[str] = field(default_factory=list)
    allowlist: List[str] = field(default_factory=list)
    sensitive_terms: List[str] = field(default_factory=list)


@dataclass
class ModerationConfig:
    thresholds: Thresholds = field(default_factory=Thresholds)
    features: FeatureFlags = field(default_factory=FeatureFlags)
    weights: Weights = field(default_factory=Weights)
    lists: Lists = field(default_factory=Lists)

    @staticmethod
    def from_overrides(overrides: Dict[str, Any]) -> "ModerationConfig":
        cfg = ModerationConfig()
        # apply shallow overrides
        def update_dataclass(dc, data):
            for k, v in (data or {}).items():
                if hasattr(dc, k):
                    setattr(dc, k, v if not isinstance(getattr(dc, k), (Thresholds, FeatureFlags, Weights, Lists)) else getattr(dc, k))
        # granular overrides
        t = overrides.get("thresholds") or {}
        for k, v in t.items():
            if hasattr(cfg.thresholds, k):
                setattr(cfg.thresholds, k, v)
        f = overrides.get("features") or {}
        for k, v in f.items():
            if hasattr(cfg.features, k):
                setattr(cfg.features, k, v)
        w = overrides.get("weights") or {}
        for k, v in w.items():
            if hasattr(cfg.weights, k):
                setattr(cfg.weights, k, v)
        l = overrides.get("lists") or {}
        for k, v in l.items():
            if hasattr(cfg.lists, k) and isinstance(v, list):
                setattr(cfg.lists, k, v)
        return cfg


# =========================
# Utilities
# =========================

def _mb_to_bytes(mb: int) -> int:
    return mb * 1024 * 1024


def _lower(s: Optional[str]) -> str:
    return (s or "").lower()


def _tld_of(domain: str) -> str:
    parts = domain.lower().split(".")
    return parts[-1] if parts else ""


class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out: List[str] = []

    def handle_data(self, d: str) -> None:
        self.out.append(d)

    def get(self) -> str:
        return "".join(self.out)


def strip_html(html: str) -> str:
    p = _HTMLStripper()
    p.feed(html or "")
    return p.get()


# =========================
# Filter base and helpers
# =========================

class Filter:
    code_prefix = "GEN"

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        raise NotImplementedError

    @staticmethod
    def _reason(code: str, message: str, *, details: Dict[str, Any] | None = None, weight: int = 1, block: bool = False, span: Tuple[int, int] | None = None) -> Reason:
        return Reason(code=code, message=message, details=details or {}, weight=weight, block=block, span=span)


# =========================
# Concrete filters
# =========================

class NormalizeFilter(Filter):
    code_prefix = "NORM"

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        # produce normalized text in ctx
        if inp.content.text is not None:
            ctx["plain_text"] = inp.content.text
        elif inp.content.html:
            ctx["plain_text"] = strip_html(inp.content.html)
        else:
            ctx["plain_text"] = ""
        ctx["lower_text"] = ctx["plain_text"].lower()
        return []


class PIIFilter(Filter):
    code_prefix = "PII"

    EMAIL_RE = re.compile(r"(?i)(?:[a-z0-9._%+\-]+)@(?:[a-z0-9\-]+\.)+[a-z]{2,}")
    PHONE_RE = re.compile(r"(?:(?:\+?\d[\s\-()]*){7,}\d)")
    CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        txt = ctx.get("plain_text", "")
        reasons: List[Reason] = []
        for m in self.EMAIL_RE.finditer(txt):
            reasons.append(self._reason("PII_EMAIL", "Email detected in text", weight=cfg.weights.PII_EMAIL, block=False, span=(m.start(), m.end())))
        for m in self.PHONE_RE.finditer(txt):
            reasons.append(self._reason("PII_PHONE", "Phone number detected in text", weight=cfg.weights.PII_PHONE, block=False, span=(m.start(), m.end())))
        for m in self.CARD_RE.finditer(txt):
            reasons.append(self._reason("PII_CARD", "Possible payment card detected", weight=cfg.weights.PII_CARD, block=True, span=(m.start(), m.end())))
        # prepare mask ranges
        if cfg.features.pii_masking_enabled and reasons:
            ctx["pii_spans"] = [(r.span[0], r.span[1]) for r in reasons if r.span]
        return reasons


class LengthFilter(Filter):
    code_prefix = "LEN"

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        lt = ctx.get("lower_text", "")
        if len(lt) > cfg.thresholds.max_len_text:
            return [self._reason(
                "LEN_TOO_LONG",
                f"Text exceeds max length: {len(lt)}",
                details={"limit": cfg.thresholds.max_len_text},
                weight=cfg.weights.LEN_TOO_LONG,
                block=False,
            )]
        return []


class URLFilter(Filter):
    code_prefix = "URL"

    URL_RE = re.compile(r"\b((?:https?://|www\.)[^\s<>\"]+)", re.IGNORECASE)

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        txt = ctx.get("plain_text", "")
        domains = set(inp.signals.url_domains or [])
        for m in self.URL_RE.finditer(txt):
            url = m.group(1)
            # crude domain extract
            dom = url.split("//")[-1].split("/")[0].split(":")[0]
            if dom.startswith("www."):
                dom = dom[4:]
            domains.add(dom.lower())
        ctx["domains"] = sorted(domains)
        reasons: List[Reason] = []
        # banned TLD
        for d in domains:
            tld = _tld_of(d)
            if tld in set(cfg.lists.banned_tlds):
                reasons.append(self._reason(
                    "URL_BANNED_TLD",
                    f"Banned TLD: {tld}",
                    details={"domain": d},
                    weight=cfg.weights.URL_BANNED_TLD,
                    block=False,
                ))
        # bad reputation
        bad = set(cfg.lists.bad_domains) | set((inp.tenant_overrides.get("bad_domains") or []))
        for d in domains:
            if d in bad or (inp.signals.url_risk.get(d) == "high"):
                reasons.append(self._reason(
                    "URL_BAD_REPUTATION",
                    f"Domain flagged: {d}",
                    details={"domain": d},
                    weight=cfg.weights.URL_BAD_REPUTATION,
                    block=True,
                ))
        return reasons


class AttachmentsFilter(Filter):
    code_prefix = "ATTACH"

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        rs: List[Reason] = []
        att = inp.content.attachments or []
        # count
        if len(att) > cfg.thresholds.max_attachments:
            rs.append(self._reason(
                "ATTACH_TOO_MANY",
                "Too many attachments",
                details={"limit": cfg.thresholds.max_attachments},
                weight=cfg.weights.ATTACH_TOO_MANY,
                block=False,
            ))
        # size, mime, ext
        dangerous_prefixes = tuple([p.lower() for p in cfg.lists.dangerous_mime_prefixes])
        banned_ext = set([e.lower() for e in cfg.lists.banned_ext])
        max_bytes = _mb_to_bytes(cfg.thresholds.max_attach_mb)
        for a in att:
            mime = (a.mime or "").lower()
            fname = (a.filename or "").lower()
            size = int(getattr(a, "size", 0))
            if mime.startswith(dangerous_prefixes) or any(fname.endswith(e) for e in banned_ext):
                rs.append(self._reason(
                    "ATTACH_DANGEROUS_MIME",
                    "Attachment has dangerous MIME or extension",
                    details={"filename": a.filename, "mime": a.mime},
                    weight=cfg.weights.ATTACH_DANGEROUS_MIME,
                    block=True,
                ))
            if size > max_bytes:
                rs.append(self._reason(
                    "ATTACH_TOO_LARGE",
                    "Attachment exceeds size limit",
                    details={"filename": a.filename, "limit_mb": cfg.thresholds.max_attach_mb},
                    weight=cfg.weights.ATTACH_TOO_LARGE,
                    block=False,
                ))
        if rs:
            ctx["attachments_violation"] = True
        return rs


class ClassifierThresholdsFilter(Filter):
    code_prefix = "CLASS"

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        sc = inp.signals.classifiers or ClassifierScores()
        rs: List[Reason] = []

        def over(name: str, prob: float, code: str, weight: int, block: bool) -> None:
            thr = getattr(cfg.thresholds, name)
            if prob >= thr:
                rs.append(self._reason(
                    code,
                    f"Classifier {name} over threshold ({prob:.2f})",
                    details={"score": prob, "threshold": thr},
                    weight=weight,
                    block=block,
                ))

        over("toxicity", sc.toxicity, "CLASS_TOXICITY", cfg.weights.CLASS_TOXICITY, False)
        over("hate", sc.hate, "CLASS_HATE", cfg.weights.CLASS_HATE, True)
        over("sexual", sc.sexual, "CLASS_SEXUAL", cfg.weights.CLASS_SEXUAL, False)
        over("violence", sc.violence, "CLASS_VIOLENCE", cfg.weights.CLASS_VIOLENCE, False)
        over("threat", sc.threat, "CLASS_THREAT", cfg.weights.CLASS_THREAT, True)
        over("self_harm", sc.self_harm, "CLASS_SELF_HARM", cfg.weights.CLASS_SELF_HARM, True)
        over("spam", sc.spam, "CLASS_SPAM", cfg.weights.CLASS_SPAM, False)
        return rs


class LexiconFilter(Filter):
    code_prefix = "LEX"

    def apply(self, inp: ModerationInput, cfg: ModerationConfig, ctx: Dict[str, Any]) -> List[Reason]:
        txt = ctx.get("lower_text", "")
        deny = [t.lower() for t in cfg.lists.denylist]
        allow = [t.lower() for t in cfg.lists.allowlist]
        sens = [t.lower() for t in cfg.lists.sensitive_terms]
        rs: List[Reason] = []

        def contains(term: str) -> bool:
            return term and term in txt

        # denylist blocks
        for t in deny:
            if contains(t):
                rs.append(self._reason(
                    "LEXICON_MATCH",
                    f"Term is denied: {t}",
                    weight=cfg.weights.LEXICON_MATCH,
                    block=True,
                ))
        # sensitive marks review (unless allowlisted also present)
        allow_hit = any(contains(t) for t in allow)
        for t in sens:
            if contains(t) and not allow_hit:
                rs.append(self._reason(
                    "LEXICON_MATCH",
                    f"Sensitive term flagged: {t}",
                    weight=cfg.weights.LEXICON_MATCH,
                    block=False,
                ))
        return rs


# =========================
# Pipeline and decision logic
# =========================

class ModerationPipeline:
    def __init__(self, filters: Optional[Sequence[Filter]] = None):
        self.filters: List[Filter] = list(filters) if filters is not None else [
            NormalizeFilter(),
            PIIFilter(),
            LengthFilter(),
            URLFilter(),
            AttachmentsFilter(),
            ClassifierThresholdsFilter(),
            LexiconFilter(),
        ]

    def run(self, inp: ModerationInput, cfg: ModerationConfig | None = None) -> Decision:
        cfg = cfg or ModerationConfig()
        # merge tenant overrides
        if inp.tenant_overrides:
            cfg = ModerationConfig.from_overrides(inp.tenant_overrides)

        ctx: Dict[str, Any] = {}
        all_reasons: List[Reason] = []
        for f in self.filters:
            try:
                all_reasons.extend(f.apply(inp, cfg, ctx))
            except Exception as e:
                all_reasons.append(Reason(
                    code=f"{f.code_prefix}_ERROR",
                    message=f"Filter {f.__class__.__name__} failed",
                    details={"error": str(e)},
                    weight=1,
                    block=False,
                ))

        tags = {
            "pii": any(r.code.startswith("PII_") for r in all_reasons),
            "length": any(r.code == "LEN_TOO_LONG" for r in all_reasons),
            "attachments": bool(ctx.get("attachments_violation", False)),
            "urls": bool(ctx.get("domains")),
        }

        score = sum(r.weight for r in all_reasons)
        severity = self._severity_from_score(score)

        block_required = any(r.block for r in all_reasons)
        only_pii = self._only_pii(all_reasons)

        trusted_bypass = (
            (inp.user.role == "admin" or inp.user.trust == "high")
            and not block_required
            and cfg.features.allow_trusted_high
        )

        allow = (not block_required) and (len(all_reasons) == 0 or only_pii or trusted_bypass)

        actions = self._decide_actions(
            block_required=block_required,
            allow_after_mask=only_pii and cfg.features.pii_masking_enabled,
            attach_viols=bool(ctx.get("attachments_violation", False)),
            has_reasons=len(all_reasons) > 0,
        )

        applied = {
            "thresholds": asdict(cfg.thresholds),
            "feature_flags": asdict(cfg.features),
        }

        return Decision(
            allow=allow,
            severity=severity,
            actions=actions,
            reasons=all_reasons,
            tags=tags,
            applied=applied,
        )

    @staticmethod
    def _severity_from_score(score: int) -> Severity:
        if score < 3:
            return Severity.LOW
        if score < 6:
            return Severity.MEDIUM
        if score < 10:
            return Severity.HIGH
        return Severity.CRITICAL

    @staticmethod
    def _only_pii(reasons: List[Reason]) -> bool:
        has_pii = any(r.code.startswith("PII_") for r in reasons)
        if not has_pii:
            return False
        return all(r.code.startswith("PII_") for r in reasons)

    @staticmethod
    def _decide_actions(block_required: bool, allow_after_mask: bool, attach_viols: bool, has_reasons: bool) -> List[Action]:
        if block_required:
            return [Action.BLOCK]
        if allow_after_mask and attach_viols:
            return [Action.MASK_PII, Action.QUARANTINE_ATTACHMENTS, Action.REVIEW]
        if allow_after_mask and not attach_viols:
            return [Action.MASK_PII, Action.ALLOW]
        if not block_required and has_reasons:
            return [Action.REVIEW]
        return [Action.ALLOW]


# =========================
# Public helpers
# =========================

def run_moderation(
    tenant: Optional[str],
    text: Optional[str] = None,
    html: Optional[str] = None,
    attachments: Optional[Iterable[Dict[str, Any]]] = None,
    classifiers: Optional[Dict[str, float]] = None,
    url_domains: Optional[Iterable[str]] = None,
    url_risk: Optional[Dict[str, str]] = None,
    user: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    tenant_overrides: Optional[Dict[str, Any]] = None,
    config: Optional[ModerationConfig] = None,
) -> Decision:
    att_objs = [AttachmentIn(filename=a["filename"], mime=a["mime"], size=int(a["size"])) for a in (attachments or [])]
    cls = ClassifierScores(**(classifiers or {}))
    sig = SignalsIn(classifiers=cls, url_domains=list(url_domains or []), url_risk=url_risk or {})
    cnt = ContentIn(text=text, html=html, attachments=att_objs)
    usr = UserIn(**(user or {}))
    ctx = ContextIn(**(context or {}))
    inp = ModerationInput(
        tenant=tenant,
        user=usr,
        context=ctx,
        content=cnt,
        signals=sig,
        tenant_overrides=tenant_overrides or {},
    )
    pipe = ModerationPipeline()
    return pipe.run(inp, config)


def mask_pii(text: str, spans: List[Tuple[int, int]], mask_char: str = "•") -> str:
    """Deterministic in-place masking by spans."""
    if not text or not spans:
        return text
    # merge overlaps
    spans = sorted(spans, key=lambda x: x[0])
    merged: List[Tuple[int, int]] = []
    for s, e in spans:
        if not merged or s > merged[-1][1]:
            merged.append((s, e))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    out = []
    last = 0
    for s, e in merged:
        out.append(text[last:s])
        out.append(mask_char * max(0, e - s))
        last = e
    out.append(text[last:])
    return "".join(out)
