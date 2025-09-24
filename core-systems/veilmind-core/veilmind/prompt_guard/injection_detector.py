# SPDX-License-Identifier: MIT
"""
Injection Detector for Prompt Guard
Industrial, dependency-free detector for prompt-injection, system prompt disclosure,
guardrail bypass attempts and related exfil cues (multi-language: en/ru/es).

Public API:
    det = InjectionDetector()                 # optional thresholds in ctor
    result = det.detect(text)                 # -> DetectionResult
    print(result.risk_score, result.findings) # findings: list[Finding]

Design goals:
- Deterministic offsets (no text reformatting that shifts indices).
- Multi-rule, multi-language coverage.
- Tunable thresholds; weights and severities per rule.
- Minimal deps (stdlib only), easy to unit test.

Note:
- This module focuses on injection/exfil. PII/secret detection should be handled
  by dedicated modules (see prompt_guard router for integration).
"""

from __future__ import annotations

import dataclasses
import enum
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


# --------------------------------- Models -------------------------------------


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Kind(str, enum.Enum):
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_DISCLOSURE = "system_disclosure"
    GUARDRAIL_BYPASS = "guardrail_bypass"
    ROLEPLAY_JAILBREAK = "roleplay_jailbreak"
    URL_POLICY = "url_violation"
    EXFIL = "exfil"


@dataclasses.dataclass(frozen=True)
class Finding:
    kind: str
    rule_id: str
    severity: str
    score: float
    start: int
    end: int
    excerpt: str


@dataclasses.dataclass(frozen=True)
class DetectionResult:
    risk_score: float
    findings: List[Finding]


@dataclasses.dataclass
class DetectorConfig:
    # Decision thresholds (consumer may map to ALLOW/SANITIZE/BLOCK)
    sanitize_score: float = 0.50
    block_score: float = 0.85
    challenge_score: float = 0.75  # optional step-up threshold (used by caller)

    # Max excerpt length around a hit
    excerpt_ctx: int = 24

    # When merging overlapping matches, keep the one with higher score
    merge_overlaps: bool = True


@dataclasses.dataclass(frozen=True)
class RegexRule:
    id: str
    kind: str
    pattern: re.Pattern
    base_score: float  # 0..1
    severity: Severity
    description: str


# ------------------------------- Rule factory ---------------------------------


def _rx(pat: str) -> re.Pattern:
    return re.compile(pat, re.IGNORECASE | re.DOTALL | re.MULTILINE)


def default_rules() -> List[RegexRule]:
    """
    Curated multi-language rules:
    - English, Russian, Spanish variants for core intents
    - Structural tags (BEGIN SYSTEM PROMPT, role markers)
    """
    rules: List[RegexRule] = []

    # --- Ignore previous / override instructions ---
    rules += [
        RegexRule(
            id="inj_ignore_prev_en",
            kind=Kind.PROMPT_INJECTION.value,
            pattern=_rx(r"\b(ignore|disregard)\s+(all\s+)?(previous|prior)\s+(instructions?|messages?|rules)\b"),
            base_score=0.95,
            severity=Severity.HIGH,
            description="Explicit request to ignore previous instructions (EN)",
        ),
        RegexRule(
            id="inj_ignore_prev_ru",
            kind=Kind.PROMPT_INJECTION.value,
            pattern=_rx(r"\b(игнориру(?:й|йте)|не\s+учитывай(?:те)?)\s+(все\s+)?(предыдущие|ранние)\s+(инструкции|правила|сообщения)\b"),
            base_score=0.95,
            severity=Severity.HIGH,
            description="Explicit request to ignore previous instructions (RU)",
        ),
        RegexRule(
            id="inj_ignore_prev_es",
            kind=Kind.PROMPT_INJECTION.value,
            pattern=_rx(r"\b(ignora|omitir|desatiende)\s+(todas?\s+)?(las\s+)?(instrucciones|mensajes)\s+(anteriores|previas)\b"),
            base_score=0.9,
            severity=Severity.HIGH,
            description="Explicit request to ignore previous instructions (ES)",
        ),
    ]

    # --- Reveal/print system/developer prompt ---
    rules += [
        RegexRule(
            id="sys_disclose_en",
            kind=Kind.SYSTEM_DISCLOSURE.value,
            pattern=_rx(r"\b(reveal|show|print|display|dump)\b.{0,40}\b(system|developer|hidden)\s+(prompt|message|instructions?)\b"),
            base_score=0.95,
            severity=Severity.HIGH,
            description="Ask to reveal system/developer prompt (EN)",
        ),
        RegexRule(
            id="sys_disclose_ru",
            kind=Kind.SYSTEM_DISCLOSURE.value,
            pattern=_rx(r"\b(покажи|раскрой|выведи|покажи\s+полностью)\b.{0,30}\b(системн\w+|скрыт\w+)\s+(промпт|инструкц\w+|сообщен\w+)\b"),
            base_score=0.95,
            severity=Severity.HIGH,
            description="Ask to reveal system/developer prompt (RU)",
        ),
        RegexRule(
            id="sys_disclose_es",
            kind=Kind.SYSTEM_DISCLOSURE.value,
            pattern=_rx(r"\b(muestra|revela|imprime|enseña)\b.{0,40}\b(prompt|mensaje)\s+(del\s+)?(sistema|desarrollador)\b"),
            base_score=0.9,
            severity=Severity.HIGH,
            description="Ask to reveal system/developer prompt (ES)",
        ),
        # Structural tags often used in leaks
        RegexRule(
            id="sys_tag_block",
            kind=Kind.SYSTEM_DISCLOSURE.value,
            pattern=_rx(r"\b(BEGIN|END)\s+(SYSTEM|DEVELOPER)\s+PROMPT\b|^\s*(system|developer)\s*:\s"),
            base_score=0.8,
            severity=Severity.MEDIUM,
            description="Structural system/developer markers",
        ),
        RegexRule(
            id="sys_md_header",
            kind=Kind.SYSTEM_DISCLOSURE.value,
            pattern=_rx(r"^#{1,6}\s*(system|developer|assistant)\b"),
            base_score=0.65,
            severity=Severity.MEDIUM,
            description="Markdown header masquerading as role marker",
        ),
    ]

    # --- Guardrail bypass / disable safety ---
    rules += [
        RegexRule(
            id="bypass_guard_en",
            kind=Kind.GUARDRAIL_BYPASS.value,
            pattern=_rx(r"\b(bypass|disable|turn\s*off|circumvent|override)\b.{0,40}\b(safety|guardrails?|filters?|polic(y|ies))\b"),
            base_score=0.9,
            severity=Severity.HIGH,
            description="Disable or bypass safety/guardrails (EN)",
        ),
        RegexRule(
            id="bypass_guard_ru",
            kind=Kind.GUARDRAIL_BYPASS.value,
            pattern=_rx(r"\b(обойти|отключи(?:ть)?)\b.{0,30}\b(защиту|ограничения|фильтр(ы)?|политик(у|и))\b"),
            base_score=0.9,
            severity=Severity.HIGH,
            description="Disable or bypass safety/guardrails (RU)",
        ),
        RegexRule(
            id="bypass_guard_es",
            kind=Kind.GUARDRAIL_BYPASS.value,
            pattern=_rx(r"\b(omitir|eludir|desactivar)\b.{0,30}\b(seguridad|filtros|pol[ií]ticas|guardarrailes)\b"),
            base_score=0.85,
            severity=Severity.HIGH,
            description="Disable or bypass safety/guardrails (ES)",
        ),
    ]

    # --- Roleplay / impersonation / jailbreak cues ---
    rules += [
        RegexRule(
            id="roleplay_root_en",
            kind=Kind.ROLEPLAY_JAILBREAK.value,
            pattern=_rx(r"\b(act|pretend)\s+as\b.{0,40}\b(system|root|developer|god|admin)\b"),
            base_score=0.7,
            severity=Severity.MEDIUM,
            description="Roleplay as system/root/developer (EN)",
        ),
        RegexRule(
            id="roleplay_ru",
            kind=Kind.ROLEPLAY_JAILBREAK.value,
            pattern=_rx(r"\b(притворись|сыграй\s+роль)\b.{0,40}\b(системой|root|разработчиком|админом|богом)\b"),
            base_score=0.7,
            severity=Severity.MEDIUM,
            description="Roleplay as system/root/developer (RU)",
        ),
        RegexRule(
            id="dan_en",
            kind=Kind.ROLEPLAY_JAILBREAK.value,
            pattern=_rx(r"\b(DAN|do\s+anything\s+now|jailbreak)\b"),
            base_score=0.8,
            severity=Severity.HIGH,
            description="Classic DAN/jailbreak trigger (EN)",
        ),
        RegexRule(
            id="from_now_on",
            kind=Kind.ROLEPLAY_JAILBREAK.value,
            pattern=_rx(r"\b(from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+conversation)\b.{0,40}\b(you\s+are|act\s+as)\b"),
            base_score=0.7,
            severity=Severity.MEDIUM,
            description="Conversation re-framing to override role (EN)",
        ),
    ]

    # --- Exfil / dump hidden or training data ---
    rules += [
        RegexRule(
            id="exfil_dump_en",
            kind=Kind.EXFIL.value,
            pattern=_rx(r"\b(exfiltrate|dump|leak|export)\b.{0,40}\b(secrets?|credentials?|training\s+data|system\s+prompt)\b"),
            base_score=0.9,
            severity=Severity.HIGH,
            description="Exfiltrate/dump secrets or training data (EN)",
        ),
        RegexRule(
            id="exfil_dump_ru",
            kind=Kind.EXFIL.value,
            pattern=_rx(r"\b(слей|сдамп\w*|выгрузи|экспортируй)\b.{0,30}\b(секрет\w*|учебн\w+\s+данн\w+|системн\w+\s+промпт)\b"),
            base_score=0.9,
            severity=Severity.HIGH,
            description="Exfiltrate/dump secrets or training data (RU)",
        ),
    ]

    return rules


# ------------------------------- Core detector --------------------------------


class InjectionDetector:
    def __init__(self, config: Optional[DetectorConfig] = None, rules: Optional[Iterable[RegexRule]] = None) -> None:
        self.config = config or DetectorConfig()
        self.rules: List[RegexRule] = list(rules) if rules is not None else default_rules()

    # Public API
    def detect(self, text: str) -> DetectionResult:
        """
        Run detection pipeline. Returns risk score and findings.
        Offsets refer to original text (we only lowercase for matching).
        """
        if not text:
            return DetectionResult(risk_score=0.0, findings=[])

        norm = text.lower()  # offsets preserved
        raw_hits: List[Finding] = []

        for rule in self.rules:
            for m in rule.pattern.finditer(norm):
                start, end = m.start(), m.end()
                excerpt = _excerpt(text, start, end, self.config.excerpt_ctx)
                raw_hits.append(
                    Finding(
                        kind=rule.kind,
                        rule_id=rule.id,
                        severity=rule.severity.value,
                        score=float(_clip(rule.base_score, 0.0, 1.0)),
                        start=start,
                        end=end,
                        excerpt=excerpt,
                    )
                )

        # Merge overlaps if configured
        findings = self._merge_overlaps(raw_hits) if self.config.merge_overlaps else raw_hits

        # Aggregate risk
        risk = _aggregate_risk(findings)

        return DetectionResult(risk_score=risk, findings=findings)

    # Internal helpers

    def _merge_overlaps(self, items: List[Finding]) -> List[Finding]:
        if not items:
            return []

        # Sort by start, then keep higher score on overlaps
        items_sorted = sorted(items, key=lambda f: (f.start, -f.score))
        merged: List[Finding] = []
        for f in items_sorted:
            if not merged:
                merged.append(f)
                continue
            last = merged[-1]
            if f.start <= last.end:  # overlap
                # keep the one with higher score; if equal, prefer HIGH severity
                if f.score > last.score or (math.isclose(f.score, last.score) and f.severity == Severity.HIGH.value):
                    merged[-1] = f
                # else drop f
            else:
                merged.append(f)
        return merged


# ------------------------------- Math helpers ---------------------------------


def _aggregate_risk(findings: List[Finding]) -> float:
    """
    Combine multiple findings into a single risk score in [0,1] using
    a complementary probability approach with mild accumulation:

        risk = 1 - Π (1 - s_i * w_i)

    where w_i depends on kind and severity.
    """
    if not findings:
        return 0.0

    # Base weights per kind
    kind_w = {
        Kind.PROMPT_INJECTION.value: 1.00,
        Kind.SYSTEM_DISCLOSURE.value: 1.00,
        Kind.GUARDRAIL_BYPASS.value: 0.95,
        Kind.ROLEPLAY_JAILBREAK.value: 0.80,
        Kind.EXFIL.value: 1.00,
        Kind.URL_POLICY.value: 0.50,
    }

    # Severity multipliers
    sev_w = {
        Severity.LOW.value: 0.6,
        Severity.MEDIUM.value: 0.85,
        Severity.HIGH.value: 1.0,
    }

    prod = 1.0
    for f in findings:
        kw = kind_w.get(f.kind, 0.7)
        sw = sev_w.get(f.severity, 0.85)
        contrib = _clip(f.score * kw * sw, 0.0, 1.0)
        prod *= (1.0 - contrib)

    risk = 1.0 - prod

    # Smoothly cap in [0,1] with tiny logistic stabilization
    risk = 1.0 / (1.0 + math.exp(-10.0 * (risk - 0.5)))
    return round(_clip(risk, 0.0, 1.0), 3)


def _clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _excerpt(s: str, start: int, end: int, ctx: int) -> str:
    a = max(0, start - ctx)
    b = min(len(s), end + ctx)
    out = s[a:b].replace("\n", " ")
    return out[:160]


# --------------------------------- __all__ ------------------------------------


__all__ = [
    "InjectionDetector",
    "DetectorConfig",
    "RegexRule",
    "Finding",
    "DetectionResult",
    "Severity",
    "Kind",
    "default_rules",
]
