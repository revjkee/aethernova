# -*- coding: utf-8 -*-
"""
Prompt Shield — промышленный барьер безопасности для LLM:
- защита от prompt-инъекций и попыток «обойти» системные инструкции;
- предотвращение утечек секретов/PII в запросах и ответах инструментов;
- политика допуска для URL/доменов и "indirect injection" (поручения перейти по ссылкам и выполнить скрытые инструкции);
- решения ALLOW/SANITIZE/BLOCK/REVIEW с аккуратной редакцией текста и смещений;
- интеграция с OPA (опционально) и метриками (increment/observe).

Unverified: используемые шаблоны/регекспы/интеграции следует сверить под вашу среду. I cannot verify this.
"""
from __future__ import annotations

import dataclasses
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# =========================
# Модели данных и результаты
# =========================

class DecisionKind(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    REVIEW = "review"  # вручную проверить (например, высокий риск, но сомнительная эвристика)


@dataclass(slots=True, frozen=True)
class Finding:
    category: str
    severity: int                 # 1..100
    message: str
    span: Tuple[int, int]         # [start, end)
    snippet: str


@dataclass(slots=True, frozen=True)
class AnalysisResult:
    findings: Tuple[Finding, ...]
    risk_score: int               # агрегированный 0..100
    normalized_text: str


@dataclass(slots=True, frozen=True)
class Redaction:
    span: Tuple[int, int]
    replacement: str
    kind: str                     # "secret", "pii", "url", "control", etc.


@dataclass(slots=True, frozen=True)
class EnforcementResult:
    decision: DecisionKind
    text: str
    applied_redactions: Tuple[Redaction, ...]
    findings: Tuple[Finding, ...]
    risk_score: int
    reason: str


# =========================
# Конфигурация
# =========================

@dataclass(slots=True)
class DetectorToggles:
    injections: bool = True
    secrets: bool = True
    pii_basic: bool = True
    urls: bool = True
    tool_indirection: bool = True
    jailbreaks: bool = True


@dataclass(slots=True)
class PolicyThresholds:
    block_at: int = 80
    sanitize_at: int = 40
    review_at: int = 60  # если >= review_at и < block_at — REVIEW, иначе SANITIZE (если >= sanitize_at)


@dataclass(slots=True)
class URLPolicy:
    allow_domains: Sequence[str] = field(default_factory=lambda: ["example.com"])
    deny_domains: Sequence[str] = field(default_factory=tuple)
    allow_schemes: Sequence[str] = field(default_factory=lambda: ("http", "https"))
    max_url_length: int = 2048


@dataclass(slots=True)
class PromptShieldConfig:
    toggles: DetectorToggles = field(default_factory=DetectorToggles)
    thresholds: PolicyThresholds = field(default_factory=PolicyThresholds)
    url_policy: URLPolicy = field(default_factory=URLPolicy)
    redact_placeholder: str = "[REDACTED]"
    # Категории/веса: можно тонко тюнинговать вклад в итоговый риск
    category_weights: Mapping[str, int] = field(default_factory=lambda: {
        "injection.override": 60,
        "injection.roleplay": 40,
        "injection.system_leak": 70,
        "indirect.tool_prompt": 55,
        "url.deny": 65,
        "url.suspicious": 45,
        "secret.key": 90,
        "secret.credential": 90,
        "secret.token": 90,
        "pii.email": 35,
        "pii.phone": 35,
        "control.invisible": 30,
    })
    # Метрики/OPA
    metrics_emitter: Optional[Any] = None
    opa_client: Optional[Any] = None  # должен уметь .evaluate(package=..., rule=..., input=...)


# =========================
# Нормализация
# =========================

def normalize_text(s: str) -> str:
    """
    NFKC + удаление управ. невидимых символов и «обфускаторов».
    Сохраняем только печатные + базовые пробелы/табуляции/переводы строк.
    """
    s = unicodedata.normalize("NFKC", s)
    # Удаляем невидимые control chars (кроме \t \n \r)
    s = "".join(ch for ch in s if (ch.isprintable() or ch in "\t\n\r"))
    # Коллапсируем повторяющиеся пробелы по 3+ в 1
    s = re.sub(r"[ \u00A0]{3,}", " ", s)
    return s


# =========================
# Регекспы/детекторы
# =========================

# — Prompt injection / jailbreak фразы
_RX_INJECTION = re.compile(
    r"""
    (?ix)
    \b(?:ignore|disregard|forget)\s+(?:previous|prior)\s+(?:instructions|messages)\b
    | \bpretend\s+to\s+be\b
    | \bDAN\b
    | \b(jailbreak|unfilter|uncensor)\b
    | \b(as\s+a\s+system|you\s+are\s+system|system\s+prompt)\b
    | \b(reveal|show)\s+(?:hidden|internal|system)\s+(?:rules|prompt|instructions)\b
    """,
)

# — Попытки утечки системных инструкций
_RX_SYSTEM_LEAK = re.compile(r"(?i)\b(show|print|reveal)\s+(system|developer)\s+(prompt|instructions|message)\b")

# — Indirect prompt injection через инструменты/браузинг
_RX_INDIRECT_TOOL = re.compile(
    r"(?is)\b(open|download|fetch|click|navigate|browse|visit)\b.*\b(and|then)\b.*\b(copy|paste|summarize|follow\s+instructions)\b"
)

# — Базовые PII/секреты (добавьте свои шаблоны)
_RX_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_RX_PHONE = re.compile(r"(?x)\b(?:\+?\d{1,3}[\s\-\.])?(?:\(?\d{2,4}\)?[\s\-\.])?\d{3,4}[\s\-\.]?\d{3,4}\b")

# — Секреты: (примеры распространённых форматов)
_RX_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RX_AWS_SECRET_KEY = re.compile(r"\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b")
_RX_GCP_API_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_RX_SLACK_TOKEN = re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,48}\b")
_RX_GITHUB_TOKEN = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
_RX_PEM_PRIVATE = re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----")

# — URL (проверяется и политикой)
_RX_URL = re.compile(
    r"(?i)\b((?:https?|ftp)://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{3,})"
)

# — Невидимые/управляющие, маскирующие инструктаж
_RX_INVISIBLE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069]+")


# =========================
# Подсчёт риска
# =========================

def _aggregate_risk(findings: Iterable[Finding], weights: Mapping[str, int]) -> int:
    score = 0
    for f in findings:
        w = int(weights.get(f.category, 10))
        score += min(100, int(f.severity * w / 100))
    return max(0, min(score, 100))


# =========================
# Основной класс
# =========================

class PromptShield:
    def __init__(self, cfg: Optional[PromptShieldConfig] = None) -> None:
        self.cfg = cfg or PromptShieldConfig()

    # ---------- Публичные методы ----------

    def analyze(self, text: str) -> AnalysisResult:
        norm = normalize_text(text)
        findings: List[Finding] = []
        if self.cfg.toggles.injections:
            findings += self._detect_injections(norm)
        if self.cfg.toggles.jailbreaks:
            findings += self._detect_jailbreaks(norm)
        if self.cfg.toggles.tool_indirection:
            findings += self._detect_indirect_tooling(norm)
        if self.cfg.toggles.secrets:
            findings += self._detect_secrets(norm)
        if self.cfg.toggles.pii_basic:
            findings += self._detect_basic_pii(norm)
        if self.cfg.toggles.urls:
            findings += self._detect_urls(norm)

        risk = _aggregate_risk(findings, self.cfg.category_weights)
        return AnalysisResult(findings=tuple(findings), risk_score=risk, normalized_text=norm)

    def sanitize(self, text: str) -> Tuple[str, Tuple[Redaction, ...], Tuple[Finding, ...], int]:
        """
        Редактирует текст: скрывает секреты/PII, удаляет невидимые управляющие, нейтрализует опасные URL.
        Возвращает (sanitized_text, redactions, findings, risk_score).
        """
        analysis = self.analyze(text)
        s = analysis.normalized_text
        redactions: List[Redaction] = []

        # Невидимые управляющие
        for m in _RX_INVISIBLE.finditer(s):
            redactions.append(Redaction(span=(m.start(), m.end()), replacement="", kind="control"))

        # Секреты/PII
        patterns = [
            (_RX_PEM_PRIVATE, "secret"),
            (_RX_AWS_ACCESS_KEY, "secret"),
            (_RX_AWS_SECRET_KEY, "secret"),
            (_RX_GCP_API_KEY, "secret"),
            (_RX_SLACK_TOKEN, "secret"),
            (_RX_GITHUB_TOKEN, "secret"),
            (_RX_EMAIL, "pii"),
            (_RX_PHONE, "pii"),
        ]
        for rx, kind in patterns:
            for m in rx.finditer(s):
                redactions.append(Redaction(span=(m.start(), m.end()), replacement=self.cfg.redact_placeholder, kind=kind))

        # URL-политика: deny-домены/схемы либо чрезмерная длина
        for m in _RX_URL.finditer(s):
            url = m.group(1)
            if not self._url_allowed(url):
                redactions.append(Redaction(span=(m.start(1), m.end(1)), replacement="[URL_BLOCKED]", kind="url"))

        sanitized = _apply_redactions(s, redactions)
        return sanitized, tuple(redactions), analysis.findings, analysis.risk_score

    def enforce(self, text: str, *, channel: str = "user") -> EnforcementResult:
        """
        Основной метод принятия решения.
        channel: "user" | "tool" | "model_output"
        """
        analysis = self.analyze(text)
        risk = analysis.risk_score
        thr = self.cfg.thresholds

        # OPA (опционально): если вернёт deny — блокируем независимо от локального решения
        if self.cfg.opa_client is not None:
            try:
                allowed = self.cfg.opa_client.evaluate(
                    package="neuroforge.safety.prompt_shield",
                    rule="allow",
                    input={"channel": channel, "risk": risk, "findings": [dataclasses.asdict(f) for f in analysis.findings]},
                )
                if hasattr(allowed, "__await__"):
                    allowed = __import__("asyncio").get_event_loop().run_until_complete(allowed)  # sync вызов
            except Exception as e:
                logger.warning("OPA evaluation failed: %s", e)
                allowed = True
            if not allowed:
                self._metric("increment", "ps_blocked_opa", labels={"channel": channel})
                return EnforcementResult(DecisionKind.BLOCK, "", tuple(), analysis.findings, risk, reason="opa_deny")

        # Локальная политика
        if risk >= thr.block_at:
            self._metric("increment", "ps_blocked", labels={"channel": channel})
            return EnforcementResult(DecisionKind.BLOCK, "", tuple(), analysis.findings, risk, reason="risk_ge_block")

        if risk >= thr.sanitize_at:
            sanitized, reds, _, _ = self.sanitize(text)
            if risk >= thr.review_at:
                decision = DecisionKind.REVIEW
                reason = "risk_ge_review"
            else:
                decision = DecisionKind.SANITIZE
                reason = "risk_ge_sanitize"
            self._metric("increment", "ps_sanitized", labels={"channel": channel})
            return EnforcementResult(decision, sanitized, reds, analysis.findings, risk, reason=reason)

        # Разрешаем
        return EnforcementResult(DecisionKind.ALLOW, analysis.normalized_text, tuple(), analysis.findings, risk, reason="ok")

    # ---------- Детекторы ----------

    def _detect_injections(self, s: str) -> List[Finding]:
        findings: List[Finding] = []
        for m in _RX_INJECTION.finditer(s):
            findings.append(Finding(
                category="injection.override",
                severity=85,
                message="Обнаружена попытка переопределить инструкции (override/ignore/pretend/DAN).",
                span=(m.start(), m.end()),
                snippet=s[max(0, m.start()-20):m.end()+20]
            ))
        for m in _RX_SYSTEM_LEAK.finditer(s):
            findings.append(Finding(
                category="injection.system_leak",
                severity=90,
                message="Попытка получить системные/внутренние инструкции.",
                span=(m.start(), m.end()),
                snippet=s[max(0, m.start()-20):m.end()+20]
            ))
        return findings

    def _detect_jailbreaks(self, s: str) -> List[Finding]:
        # Примитивно: метим упоминания "jailbreak/unfilter/uncensor"
        out: List[Finding] = []
        for m in re.finditer(r"(?i)\b(jailbreak|unfilter|uncensor|bypass\s+safety)\b", s):
            out.append(Finding(
                category="injection.roleplay",
                severity=60,
                message="Обнаружены маркеры jailbreak/снятия фильтров.",
                span=(m.start(), m.end()),
                snippet=s[max(0, m.start()-20):m.end()+20]
            ))
        return out

    def _detect_indirect_tooling(self, s: str) -> List[Finding]:
        out: List[Finding] = []
        for m in _RX_INDIRECT_TOOL.finditer(s):
            out.append(Finding(
                category="indirect.tool_prompt",
                severity=70,
                message="Запрос на непрямую инъекцию через инструменты/веб (follow/copy hidden instructions).",
                span=(m.start(), m.end()),
                snippet=s[max(0, m.start()-40):m.end()+40]
            ))
        return out

    def _detect_secrets(self, s: str) -> List[Finding]:
        pats = [
            (_RX_PEM_PRIVATE, "secret.key"),
            (_RX_AWS_ACCESS_KEY, "secret.credential"),
            (_RX_AWS_SECRET_KEY, "secret.credential"),
            (_RX_GCP_API_KEY, "secret.token"),
            (_RX_SLACK_TOKEN, "secret.token"),
            (_RX_GITHUB_TOKEN, "secret.token"),
        ]
        out: List[Finding] = []
        for rx, cat in pats:
            for m in rx.finditer(s):
                out.append(Finding(
                    category=cat,
                    severity=95,
                    message="Похоже на секрет/ключ/токен.",
                    span=(m.start(), m.end()),
                    snippet=s[max(0, m.start()-6):m.end()+6]
                ))
        return out

    def _detect_basic_pii(self, s: str) -> List[Finding]:
        out: List[Finding] = []
        for m in _RX_EMAIL.finditer(s):
            out.append(Finding(
                category="pii.email",
                severity=45,
                message="Найден email (PII).",
                span=(m.start(), m.end()),
                snippet=m.group(0)
            ))
        for m in _RX_PHONE.finditer(s):
            out.append(Finding(
                category="pii.phone",
                severity=40,
                message="Найден телефон (PII).",
                span=(m.start(), m.end()),
                snippet=m.group(0)
            ))
        return out

    def _detect_urls(self, s: str) -> List[Finding]:
        out: List[Finding] = []
        for m in _RX_URL.finditer(s):
            url = m.group(1)
            if len(url) > self.cfg.url_policy.max_url_length:
                out.append(Finding(
                    category="url.suspicious",
                    severity=50,
                    message="URL слишком длинный.",
                    span=(m.start(1), m.end(1)),
                    snippet=url[:64] + "..."
                ))
                continue
            if not self._url_allowed(url):
                out.append(Finding(
                    category="url.deny",
                    severity=70,
                    message="Домен/схема не разрешены политикой.",
                    span=(m.start(1), m.end(1)),
                    snippet=url
                ))
        # Невидимые символы, маскирующие инструкции
        for m in _RX_INVISIBLE.finditer(s):
            out.append(Finding(
                category="control.invisible",
                severity=35,
                message="Обнаружены невидимые управляющие символы.",
                span=(m.start(), m.end()),
                snippet=""
            ))
        return out

    # ---------- Вспомогательное ----------

    def _url_allowed(self, url: str) -> bool:
        m = re.match(r"(?i)^(?P<scheme>[a-z][a-z0-9+\-.]*):\/\/(?P<host>[^\/:\s]+)", url.strip())
        if not m:
            return False
        scheme = m.group("scheme").lower()
        host = m.group("host").lower().strip("[]")
        if scheme not in set(map(str.lower, self.cfg.url_policy.allow_schemes)):
            return False
        if any(host.endswith("." + d.lower()) or host == d.lower() for d in self.cfg.url_policy.deny_domains):
            return False
        if self.cfg.url_policy.allow_domains:
            if not any(host.endswith("." + d.lower()) or host == d.lower() for d in self.cfg.url_policy.allow_domains):
                return False
        return True

    def _metric(self, kind: str, name: str, value: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        em = self.cfg.metrics_emitter
        if not em:
            return
        try:
            if kind == "increment" and hasattr(em, "increment"):
                em.increment(name, value=value, **(labels or {}))
            elif kind == "observe" and hasattr(em, "observe"):
                em.observe(name, value=value, **(labels or {}))
        except Exception:
            pass


# =========================
# Редактирование текста
# =========================

def _apply_redactions(s: str, redactions: Sequence[Redaction]) -> str:
    """
    Применяет замены, учитывая смещения; редакции сортируются по start, затем применяются слева направо.
    Пересекающиеся отрезки объединяются с приоритетом: secret > pii > url > control.
    """
    if not redactions:
        return s
    priority = {"secret": 4, "pii": 3, "url": 2, "control": 1}
    # Нормализуем и мерджим пересечения
    reds = sorted(redactions, key=lambda r: (r.span[0], -priority.get(r.kind, 0)))
    merged: List[Redaction] = []
    cur: Optional[Redaction] = None
    for r in reds:
        if cur is None:
            cur = r
            continue
        if r.span[0] <= cur.span[1]:  # пересечение/стык
            if priority.get(r.kind, 0) >= priority.get(cur.kind, 0):
                # расширяем диапазон и обновляем replacement/kind по приоритетному
                cur = Redaction(span=(cur.span[0], max(cur.span[1], r.span[1])), replacement=r.replacement, kind=r.kind)
            else:
                cur = Redaction(span=(cur.span[0], max(cur.span[1], r.span[1])), replacement=cur.replacement, kind=cur.kind)
        else:
            merged.append(cur)
            cur = r
    if cur:
        merged.append(cur)
    # Применяем
    out = []
    idx = 0
    for r in merged:
        s0, s1 = r.span
        out.append(s[idx:s0])
        out.append(r.replacement)
        idx = s1
    out.append(s[idx:])
    return "".join(out)


# =========================
# Примитивные хелперы для контекстов
# =========================

def guard_user_input(shield: PromptShield, text: str) -> EnforcementResult:
    """
    Охрана пользовательского ввода до передачи в LLM.
    """
    return shield.enforce(text, channel="user")


def guard_tool_output(shield: PromptShield, text: str) -> EnforcementResult:
    """
    Охрана ответов инструментов (браузинг/выполнение кода) перед прокидыванием в LLM.
    """
    return shield.enforce(text, channel="tool")


def guard_model_output(shield: PromptShield, text: str) -> EnforcementResult:
    """
    Охрана исходящих ответов LLM перед отправкой пользователю (например, чтобы не утекли секреты).
    """
    return shield.enforce(text, channel="model_output")
