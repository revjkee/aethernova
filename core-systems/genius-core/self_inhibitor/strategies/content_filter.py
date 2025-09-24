# path: core-systems/genius_core/security/self_inhibitor/strategies/content_filter.py
# License: MIT
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# Optional latency tracker (best-effort)
try:
    from observability_core.logging.latency.latency_tracker import track_latency  # type: ignore
except Exception:  # graceful fallback
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def track_latency(*args, **kwargs):
        yield


LOG = logging.getLogger("genius_core.content_filter")


# =========================
# Core types and decisions
# =========================

class Category(Enum):
    PII = auto()
    TOXICITY = auto()
    SEXUAL = auto()
    VIOLENCE = auto()
    SELF_HARM = auto()
    ILLEGAL = auto()
    WEAPONS = auto()
    DRUGS = auto()
    EXTREMISM = auto()
    MEDICAL = auto()
    FINANCIAL_ADVICE = auto()
    LINKS = auto()


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Action(Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    category: Category
    severity: Severity
    start: int
    end: int
    match: str
    label: str
    score: float = 1.0


@dataclass
class Decision:
    action: Action
    score: float
    severity: Severity
    categories: Dict[str, float]
    findings: List[Finding] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    reason: str = ""
    trace_id: Optional[str] = None
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class FilterConfig:
    mode: str = field(default_factory=lambda: os.getenv("CONTENT_FILTER_MODE", "balanced"))
    # thresholds by mode
    threshold_allow: float = 0.4
    threshold_redact: float = 0.8
    # weights per category
    weights: Dict[Category, float] = field(default_factory=lambda: {
        Category.PII: 1.0,
        Category.TOXICITY: 0.8,
        Category.SEXUAL: 0.9,
        Category.VIOLENCE: 0.8,
        Category.SELF_HARM: 1.0,
        Category.ILLEGAL: 1.0,
        Category.WEAPONS: 0.7,
        Category.DRUGS: 0.8,
        Category.EXTREMISM: 1.0,
        Category.MEDICAL: 0.5,
        Category.FINANCIAL_ADVICE: 0.5,
        Category.LINKS: 0.2,
    })
    # redact settings
    redact_piis: bool = True
    redact_placeholder: str = "[REDACTED]"
    # auditing
    audit_jsonl_path: Optional[str] = field(default_factory=lambda: os.getenv("CONTENT_FILTER_AUDIT"))
    # custom dictionaries
    profanity_path: Optional[str] = field(default_factory=lambda: os.getenv("CONTENT_FILTER_PROFANITY"))
    extra_rules_path: Optional[str] = field(default_factory=lambda: os.getenv("CONTENT_FILTER_RULES"))
    # streaming
    stream_tail: int = 32
    # max findings to avoid log blowups
    max_findings: int = 256

    def tuned(self) -> "FilterConfig":
        m = (self.mode or "balanced").lower()
        tuned = FilterConfig(
            mode=self.mode,
            threshold_allow=self.threshold_allow,
            threshold_redact=self.threshold_redact,
            weights=dict(self.weights),
            redact_piis=self.redact_piis,
            redact_placeholder=self.redact_placeholder,
            audit_jsonl_path=self.audit_jsonl_path,
            profanity_path=self.profanity_path,
            extra_rules_path=self.extra_rules_path,
            stream_tail=self.stream_tail,
            max_findings=self.max_findings,
        )
        if m == "strict":
            tuned.threshold_allow = 0.25
            tuned.threshold_redact = 0.55
            tuned.weights[Category.LINKS] = 0.4
        elif m == "permissive":
            tuned.threshold_allow = 0.6
            tuned.threshold_redact = 0.9
            tuned.weights[Category.TOXICITY] = 0.6
            tuned.weights[Category.SEXUAL] = 0.7
        return tuned


# =========================
# Utilities
# =========================

def _norm_text(s: str) -> str:
    """Lowercase and normalize common obfuscations (leet speak)."""
    s = s.lower()
    table = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "+": "t",
    })
    return s.translate(table)


def _clamp(n: float, a: float, b: float) -> float:
    return max(a, min(b, n))


def _severity_max(a: Severity, b: Severity) -> Severity:
    return a if a.value >= b.value else b


# =========================
# Regex patterns
# =========================

# PII
RE_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
RE_PHONE = re.compile(r"(?:\+?\d{1,3}[\s\-\.]?)?(?:\(?\d{2,4}\)?[\s\-\.]?){2,4}\d{2,4}")
RE_URL = re.compile(r"\bhttps?://[^\s<>{}|\^`\\\[\]]+\b", re.I)

RE_CC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
RE_IBAN = re.compile(r"\b[A-Z]{2}[0-9A-Z]{13,34}\b")
# US SSN-like (generic)
RE_SSN = re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b")

# Toxicity/profanity (seed list kept minimal; extend via dictionary file)
_PROFANITY_SEEDS = [
    r"\bidiot\b",
    r"\bstupid\b",
    r"\bjerk\b",
]
RE_PROFANITY = re.compile("|".join(_PROFANITY_SEEDS), re.I) if _PROFANITY_SEEDS else None

# Thematic risk keywords (kept general; extend via external rules)
RISK_SETS = {
    Category.SELF_HARM: [r"\bkill myself\b", r"\bsuicide\b", r"\bself harm\b"],
    Category.VIOLENCE: [r"\bkill\b", r"\bviolence\b", r"\bassault\b"],
    Category.ILLEGAL: [r"\bmake bomb\b", r"\bcredit card fraud\b", r"\bcheat\b"],
    Category.WEAPONS: [r"\bghost gun\b", r"\b3d printed gun\b"],
    Category.DRUGS: [r"\bmake meth\b", r"\bhow to cook drugs\b"],
    Category.SEXUAL: [r"\bexplicit sexual content\b", r"\bsexual act\b"],
    Category.EXTREMISM: [r"\bextremist\b", r"\bterror\b"],
    Category.MEDICAL: [r"\bdiagnose\b", r"\bprescribe\b"],
    Category.FINANCIAL_ADVICE: [r"\bguaranteed profit\b", r"\binsider trading\b"],
}
RE_RISKS = {cat: re.compile("|".join(pats), re.I) for cat, pats in RISK_SETS.items()}


# =========================
# Validators
# =========================

def _luhn_ok(s: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", s)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _looks_credit_card(s: str) -> bool:
    return _luhn_ok(s)


def _looks_iban(s: str) -> bool:
    if not RE_IBAN.match(s):
        return False
    # Basic IBAN checksum
    rearr = s[4:] + s[:4]
    num = ""
    for ch in rearr:
        if ch.isdigit():
            num += ch
        else:
            num += str(ord(ch.upper()) - 55)
    try:
        return int(num) % 97 == 1
    except Exception:
        return False


# =========================
# Rule engine
# =========================

class ContentFilter:
    def __init__(self, cfg: Optional[FilterConfig] = None) -> None:
        self.cfg = (cfg or FilterConfig()).tuned()
        self._dict_loaded = False
        self._extra_rules: List[Tuple[re.Pattern, Category, Severity, float, str]] = []
        self._load_dicts()

    def _load_dicts(self) -> None:
        if self._dict_loaded:
            return
        self._dict_loaded = True
        if self.cfg.profanity_path and os.path.exists(self.cfg.profanity_path):
            try:
                words = []
                with open(self.cfg.profanity_path, "r", encoding="utf-8") as f:
                    for line in f:
                        w = line.strip()
                        if w and not w.startswith("#"):
                            words.append(re.escape(w))
                if words:
                    pat = re.compile(r"\b(" + "|".join(words) + r")\b", re.I)
                    globals()["RE_PROFANITY"] = pat  # type: ignore
            except Exception as e:
                LOG.warning("Failed to load profanity list: %s", e)
        if self.cfg.extra_rules_path and os.path.exists(self.cfg.extra_rules_path):
            try:
                import yaml  # optional
                with open(self.cfg.extra_rules_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or []
                for item in data:
                    pattern = re.compile(item["pattern"], re.I)
                    cat = Category[item.get("category", "TOXICITY")]
                    sev = Severity[item.get("severity", "MEDIUM")] if isinstance(item.get("severity"), str) else Severity(item.get("severity", 2))
                    w = float(item.get("weight", 1.0))
                    label = item.get("label", "custom")
                    self._extra_rules.append((pattern, cat, sev, w, label))
            except Exception as e:
                LOG.warning("Failed to load extra rules: %s", e)

    def evaluate(self, text: str, *, trace_id: Optional[str] = None) -> Decision:
        with self._audit_span("evaluate", trace_id):
            findings: List[Finding] = []
            norm = _norm_text(text)

            # PII rules
            findings += self._scan_regex(text, RE_EMAIL, Category.PII, Severity.MEDIUM, "email")
            findings += self._scan_regex(text, RE_PHONE, Category.PII, Severity.MEDIUM, "phone")
            findings += self._scan_regex(text, RE_URL, Category.LINKS, Severity.LOW, "url")
            # Credit card with Luhn verification
            for m in RE_CC.finditer(text):
                s = m.group(0)
                if _looks_credit_card(s):
                    findings.append(Finding(Category.PII, Severity.CRITICAL, m.start(), m.end(), s, "credit_card", score=1.0))
            # IBAN and SSN-like
            for m in RE_IBAN.finditer(text):
                s = m.group(0).replace(" ", "")
                if _looks_iban(s):
                    findings.append(Finding(Category.PII, Severity.HIGH, m.start(), m.end(), s, "iban", score=0.9))
            findings += self._scan_regex(text, RE_SSN, Category.PII, Severity.HIGH, "ssn_like")

            # Profanity/toxicity
            if "RE_PROFANITY" in globals() and globals()["RE_PROFANITY"] is not None:  # type: ignore
                findings += self._scan_regex(norm, globals()["RE_PROFANITY"], Category.TOXICITY, Severity.MEDIUM, "profanity")  # type: ignore

            # Thematic risks
            for cat, rx in RE_RISKS.items():
                sev = Severity.HIGH if cat in (Category.SELF_HARM, Category.EXTREMISM, Category.ILLEGAL) else Severity.MEDIUM
                findings += self._scan_regex(norm, rx, cat, sev, f"{cat.name.lower()}_keywords")

            # Custom extra rules
            for pat, cat, sev, w, label in self._extra_rules:
                for m in pat.finditer(text):
                    findings.append(Finding(cat, sev, m.start(), m.end(), m.group(0), f"extra:{label}", score=w))

            # Cap findings
            if len(findings) > self.cfg.max_findings:
                findings = findings[: self.cfg.max_findings]

            # Aggregate
            decision = self._aggregate(text, findings, trace_id=trace_id)

            # Redaction
            if decision.action in (Action.REDACT, Action.ALLOW) and self.cfg.redact_piis:
                decision.sanitized_text = self._redact(text, findings)

            # Audit
            self._audit(decision, text)

            return decision

    def _scan_regex(self, text: str, rx: Optional[re.Pattern], cat: Category, sev: Severity, label: str) -> List[Finding]:
        if not rx:
            return []
        out: List[Finding] = []
        for m in rx.finditer(text):
            out.append(Finding(cat, sev, m.start(), m.end(), m.group(0), label))
        return out

    def _aggregate(self, text: str, findings: List[Finding], *, trace_id: Optional[str]) -> Decision:
        if not findings:
            return Decision(action=Action.ALLOW, score=0.0, severity=Severity.LOW, categories={}, findings=[], sanitized_text=text, reason="no_findings", trace_id=trace_id)

        weights = self.cfg.weights
        cat_scores: Dict[Category, float] = {}
        top_sev = Severity.LOW
        for f in findings:
            w = weights.get(f.category, 1.0)
            cat_scores[f.category] = cat_scores.get(f.category, 0.0) + f.score * w * (f.severity.value / Severity.CRITICAL.value)
            top_sev = _severity_max(top_sev, f.severity)

        total = sum(cat_scores.values())
        # normalize to 0..1
        score = _clamp(total / (total + 5.0), 0.0, 1.0)

        # Decision by thresholds
        if score < self.cfg.threshold_allow:
            action = Action.ALLOW
        elif score < self.cfg.threshold_redact:
            action = Action.REDACT
        else:
            action = Action.BLOCK

        # Enforce hard blocks for specific high-severity categories
        hard_block = any(
            f.category in (Category.SELF_HARM, Category.ILLEGAL, Category.EXTREMISM)
            and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )
        if hard_block:
            action = Action.BLOCK

        reason = f"score={score:.3f} sev={top_sev.name} cats=" + ",".join(f"{c.name}:{cat_scores[c]:.2f}" for c in sorted(cat_scores.keys(), key=lambda k: -cat_scores[k]))

        return Decision(
            action=action,
            score=score,
            severity=top_sev,
            categories={c.name: v for c, v in cat_scores.items()},
            findings=findings,
            sanitized_text=None,
            reason=reason,
            trace_id=trace_id,
        )

    def _redact(self, text: str, findings: List[Finding]) -> str:
        """Redact PII-like findings; leave others intact unless action is BLOCK."""
        pii_spans = [(f.start, f.end) for f in findings if f.category == Category.PII]
        if not pii_spans:
            return text
        # Merge overlaps
        pii_spans.sort()
        merged: List[Tuple[int, int]] = []
        cs, ce = pii_spans[0]
        for s, e in pii_spans[1:]:
            if s <= ce:
                ce = max(ce, e)
            else:
                merged.append((cs, ce))
                cs, ce = s, e
        merged.append((cs, ce))
        # Build result
        out = []
        last = 0
        for s, e in merged:
            out.append(text[last:s])
            out.append(self.cfg.redact_placeholder)
            last = e
        out.append(text[last:])
        return "".join(out)

    # ============ Auditing ============

    def _audit(self, decision: Decision, text: str) -> None:
        if not self.cfg.audit_jsonl_path:
            return
        try:
            record = {
                "ts": decision.ts,
                "trace_id": decision.trace_id,
                "mode": self.cfg.mode,
                "action": decision.action.value,
                "score": decision.score,
                "severity": decision.severity.name,
                "categories": decision.categories,
                "reason": decision.reason,
                "findings": [
                    {"category": f.category.name, "severity": f.severity.name, "start": f.start, "end": f.end, "label": f.label}
                    for f in decision.findings[:50]
                ],
                "length": len(text),
            }
            with open(self.cfg.audit_jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            LOG.warning("Audit write failed: %s", e)

    from contextlib import contextmanager

    @contextmanager
    def _audit_span(self, name: str, trace_id: Optional[str]):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            dt = (time.perf_counter() - t0) * 1000.0
            LOG.debug("content_filter.%s trace=%s took=%.2fms", name, trace_id, dt)


# =========================
# Streaming support
# =========================

@dataclass
class StreamState:
    tail: str = ""
    last_decision: Optional[Decision] = None


class StreamingFilter:
    """Keeps small tail to detect patterns split across chunks."""
    def __init__(self, base: Optional[ContentFilter] = None) -> None:
        self.base = base or ContentFilter()
        self.state = StreamState()

    def filter_chunk(self, chunk: str, *, trace_id: Optional[str] = None) -> Decision:
        prefix = self.state.tail
        combined = prefix + chunk
        decision = self.base.evaluate(combined, trace_id=trace_id)
        # update tail
        tail_len = self.base.cfg.stream_tail
        self.state.tail = combined[-tail_len:]
        self.state.last_decision = decision
        # sanitize returned text to only current chunk span
        if decision.sanitized_text is not None:
            # we recompute sanitized text for chunk only to avoid leaking prefix
            d2 = self.base.evaluate(chunk, trace_id=trace_id)
            decision.sanitized_text = d2.sanitized_text or chunk
        return decision


# =========================
# Public API
# =========================

_default_filter: Optional[ContentFilter] = None

def get_filter() -> ContentFilter:
    global _default_filter
    if _default_filter is None:
        _default_filter = ContentFilter()
    return _default_filter


async def filter_text(text: str, *, trace_id: Optional[str] = None) -> Decision:
    async with track_latency("content_filter_ms", {"phase": "eval"}):
        return get_filter().evaluate(text, trace_id=trace_id)


# =========================
# Example (manual run)
# =========================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cf = ContentFilter()
    samples = [
        "My email is john.doe@example.com and card 4111 1111 1111 1111.",
        "How to make bomb at home?",
        "This is stupid.",
        "Visit https://example.com for more info.",
        "I want to kill myself.",
    ]
    for s in samples:
        d = cf.evaluate(s, trace_id="demo")
        print(s)
        print(d.action, d.severity.name, f"score={d.score:.3f}", d.reason)
        if d.sanitized_text and d.sanitized_text != s:
            print("SANITIZED:", d.sanitized_text)
        print("-" * 40)
