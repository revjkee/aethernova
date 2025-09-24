# neuroforge-core/neuroforge/safety/guardrails.py
from __future__ import annotations

import dataclasses
import enum
import html
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

# ============================ Исключения ============================

class GuardError(Exception):
    ...

class BlockedByPolicy(GuardError):
    def __init__(self, message: str, decision: "Decision") -> None:
        super().__init__(message)
        self.decision = decision

# ============================ Типы и конфиг ============================

class DecisionAction(str, enum.Enum):
    ALLOW = "allow"
    ALLOW_WITH_REDACTIONS = "allow_with_redactions"
    BLOCK = "block"

@dataclass
class Span:
    start: int
    end: int
    label: str
    value_preview: str

@dataclass
class Finding:
    label: str
    severity: float  # 0..1
    spans: List[Span] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Decision:
    action: DecisionAction
    score: float
    reasons: List[str]
    findings: List[Finding]
    redactions: List[Span] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    duration_ms: int = 0

class ModerationAdapter(Protocol):
    def score(self, text: str) -> Optional[float]:
        """
        Возвращает риск 0..1 или None, если не применимо.
        Можно подключить внешние сервисы модерации; вызывать синхронно на коротких текстах.
        """

@dataclass
class UrlPolicy:
    allowed_domains: List[str] = field(default_factory=list)  # пусто = разрешить любые
    denied_domains: List[str] = field(default_factory=list)
    strip_utm_params: bool = True

@dataclass
class GuardConfig:
    # Общие
    max_input_chars: int = 20000
    max_output_chars: int = 40000
    block_threshold: float = 0.80
    redact_threshold: float = 0.40
    weight_map: Dict[str, float] = field(default_factory=lambda: {
        "pii": 0.30, "secret": 0.90, "prompt_injection": 0.70, "jailbreak": 0.70,
        "toxicity": 0.60, "self_harm": 0.85, "violence": 0.70, "sexual": 0.70,
        "malware": 0.85, "unsafe_links": 0.50
    })
    # Включение детекторов
    enable_pii: bool = True
    enable_secrets: bool = True
    enable_prompt_injection: bool = True
    enable_toxicity: bool = True
    enable_policy_sexual: bool = True
    enable_policy_violence: bool = True
    enable_policy_self_harm: bool = True
    enable_malware: bool = True
    enable_links: bool = True
    # Редакция
    redaction_token: str = "[REDACTED]"
    keep_last_digits_for_numeric: int = 4  # для телефонов/карт
    # Ссылки
    url_policy: UrlPolicy = field(default_factory=UrlPolicy)
    # Внешняя модерация (опционально)
    moderation: Optional[ModerationAdapter] = None

# ============================ Регулярные выражения и словари ============================

_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_RE_PHONE = re.compile(r"(?:(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)\d{2,4}[\s-]?\d{2,4}[\s-]?\d{0,4})")
_RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?!$)|$)){4}\b")
_RE_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b")
_RE_URL = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>()]+)")
_RE_CC_CANDIDATE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_AWS_SECRET = re.compile(r"(?i)\baws(.{0,20})?(secret|access)[-_ ]?key\b[:=]\s*([A-Za-z0-9/+=]{40})")
_RE_GCP_KEY = re.compile(r"(?i)\"type\"\s*:\s*\"service_account\"")
_RE_SLACK_TOKEN = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b")
_RE_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

# Примитивные словари для нежелательного контента
_TOXIC_WORDS = {"idiot", "stupid", "moron", "trash", "die"}
_SELF_HARM = {"kill myself", "suicide", "self harm", "end my life"}
_VIOLENCE = {"kill", "shoot", "stab", "bomb"}
_SEXUAL = {"explicit", "porn", "sexual act"}
_MALWARE = {"write ransomware", "zero-day exploit", "undetectable malware", "ddos script"}

# Prompt injection / jailbreak маркеры
_INJECTION_PATTERNS = [
    r"(?i)\bignore (all|previous) (instructions|rules)\b",
    r"(?i)\boverride (system|developer) prompt\b",
    r"(?i)\bact as (?:a|an)? (?:developer|system)\b",
    r"(?i)\bthis is a test\b.*\bdisregard\b",
    r"(?i)\bprompt injection\b",
]
_JAILBREAK_PATTERNS = [
    r"(?i)\bDAN\b",
    r"(?i)\buncensored mode\b",
    r"(?i)\bbypass (?:policy|safety)\b",
    r"(?i)\bignore your safety rules\b",
    r"(?i)\brole[- ]?play as\b",
]

# ============================ Вспомогательные ============================

def _clip_preview(s: str, max_len: int = 32) -> str:
    s = s.replace("\n", " ")
    return s[:max_len]

def _luhn_ok(digits_only: str) -> bool:
    s = [int(c) for c in digits_only if c.isdigit()]
    if len(s) < 13:
        return False
    checksum = 0
    parity = (len(s) - 2) % 2
    for i, n in enumerate(s[:-1]):
        d = n * 2 if i % 2 == parity else n
        checksum += d - 9 if d > 9 else d
    return (checksum + s[-1]) % 10 == 0

def _domain(host: str) -> str:
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def _url_domain(url: str) -> Optional[str]:
    m = re.match(r"(?i)https?://([^/\s]+)", url)
    return _domain(m.group(1)) if m else None

def _strip_utm(url: str) -> str:
    if "?" not in url:
        return url
    base, qs = url.split("?", 1)
    keep = []
    for kv in qs.split("&"):
        k = kv.split("=")[0].lower()
        if not k.startswith("utm_"):
            keep.append(kv)
    return base + ("?" + "&".join(keep) if keep else "")

# ============================ Детекторы ============================

def detect_pii(text: str) -> List[Finding]:
    findings: List[Finding] = []

    for r, label in [(_RE_EMAIL, "pii.email"), (_RE_IP, "pii.ipv4"), (_RE_IPV6, "pii.ipv6")]:
        for m in r.finditer(text):
            findings.append(Finding(label=label, severity=0.6, spans=[Span(m.start(), m.end(), label, _clip_preview(m.group()))]))

    # Телефоны: фильтруем слишком короткие
    for m in _RE_PHONE.finditer(text):
        s = re.sub(r"[^\d]", "", m.group())
        if 7 <= len(s) <= 16:
            findings.append(Finding(label="pii.phone", severity=0.55, spans=[Span(m.start(), m.end(), "pii.phone", _clip_preview(m.group()))]))

    # Карты
    for m in _RE_CC_CANDIDATE.finditer(text):
        raw = re.sub(r"[^\d]", "", m.group())
        if 13 <= len(raw) <= 19 and _luhn_ok(raw):
            findings.append(Finding(label="pii.credit_card", severity=0.95, spans=[Span(m.start(), m.end(), "pii.credit_card", _clip_preview(m.group()))]))

    return findings

def detect_secrets(text: str) -> List[Finding]:
    f: List[Finding] = []
    for pat, label, sev in [
        (_RE_AWS_KEY, "secret.aws_access_key", 0.95),
        (_RE_AWS_SECRET, "secret.aws_secret_key", 0.99),
        (_RE_SLACK_TOKEN, "secret.slack_token", 0.95),
        (_RE_PRIVATE_KEY, "secret.private_key", 1.0),
        (_RE_JWT, "secret.jwt", 0.85),
    ]:
        for m in pat.finditer(text):
            f.append(Finding(label=label, severity=sev, spans=[Span(m.start(), m.end(), label, _clip_preview(m.group()))]))

    # GCP JSON ключи по сигнатуре
    if _RE_GCP_KEY.search(text):
        f.append(Finding(label="secret.gcp_service_account", severity=0.98, spans=[]))
    return f

def detect_links(text: str, policy: UrlPolicy) -> List[Finding]:
    findings: List[Finding] = []
    for m in _RE_URL.finditer(text):
        url = m.group(1)
        dom = _url_domain(url)
        if not dom:
            continue
        sev = 0.0
        reason = None
        if policy.denied_domains and any(dom.endswith(d) for d in policy.denied_domains):
            sev = 0.9
            reason = "denied_domain"
        elif policy.allowed_domains and not any(dom.endswith(d) for d in policy.allowed_domains):
            sev = 0.6
            reason = "not_in_allowlist"
        if sev > 0:
            findings.append(Finding(label=f"link.{reason}", severity=sev, spans=[Span(m.start(), m.end(), "url", _clip_preview(url))], details={"url": url, "domain": dom}))
    return findings

def detect_prompt_injection(text: str) -> List[Finding]:
    out: List[Finding] = []
    for pat in _INJECTION_PATTERNS:
        for m in re.finditer(pat, text):
            out.append(Finding(label="prompt_injection", severity=0.8, spans=[Span(m.start(), m.end(), "prompt_injection", _clip_preview(m.group()))]))
    for pat in _JAILBREAK_PATTERNS:
        for m in re.finditer(pat, text):
            out.append(Finding(label="jailbreak", severity=0.8, spans=[Span(m.start(), m.end(), "jailbreak", _clip_preview(m.group()))]))
    return out

def detect_dictionary(text: str, vocab: Sequence[str], label: str, severity: float) -> List[Finding]:
    out: List[Finding] = []
    for w in vocab:
        for m in re.finditer(rf"(?i)\b{re.escape(w)}\b", text):
            out.append(Finding(label=label, severity=severity, spans=[Span(m.start(), m.end(), label, _clip_preview(m.group()))]))
    return out

# ============================ Редакция ============================

def redact(text: str, spans: Sequence[Span], token: str, keep_last_digits: int = 0) -> Tuple[str, List[Span]]:
    """
    Возвращает отредактированный текст и новые спаны (после сдвигов).
    """
    if not spans:
        return text, []
    # Сортируем по началу
    spans_sorted = sorted(spans, key=lambda s: s.start)
    out = []
    redacted_spans: List[Span] = []
    last = 0
    shift = 0
    for sp in spans_sorted:
        if sp.start < last:
            # пересечение, пропустим
            continue
        out.append(text[last:sp.start])
        original = text[sp.start:sp.end]
        repl = token
        if keep_last_digits and any(c.isdigit() for c in original):
            digits = "".join([c for c in original if c.isdigit()])
            tail = digits[-keep_last_digits:] if len(digits) >= keep_last_digits else digits
            repl = f"{token}…{tail}"
        out.append(repl)
        new_start = (sp.start - shift)
        new_end = new_start + len(repl)
        redacted_spans.append(Span(new_start, new_end, sp.label, sp.value_preview))
        shift += (sp.end - sp.start) - len(repl)
        last = sp.end
    out.append(text[last:])
    return "".join(out), redacted_spans

# ============================ Агрегация и решение ============================

def _aggregate(findings: List[Finding], cfg: GuardConfig) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    # Максимум взвешенных рисков по категориям
    by_label: Dict[str, float] = {}
    for f in findings:
        cat = f.label.split(".")[0]
        by_label[cat] = max(by_label.get(cat, 0.0), f.severity)
    for cat, sev in by_label.items():
        w = cfg.weight_map.get(cat, 0.0)
        s = sev * w
        if s > 0:
            reasons.append(f"{cat}:{sev:.2f}*{w:.2f}={s:.2f}")
        score = max(score, s)
    return score, reasons

def evaluate_text(text: str, cfg: GuardConfig, for_output: bool = False) -> Decision:
    t0 = time.perf_counter()
    findings: List[Finding] = []

    if len(text) > (cfg.max_output_chars if for_output else cfg.max_input_chars):
        findings.append(Finding(label="length", severity=0.7))

    if cfg.enable_pii:
        findings.extend(detect_pii(text))
    if cfg.enable_secrets:
        findings.extend(detect_secrets(text))
    if cfg.enable_links and (cfg.url_policy.allowed_domains or cfg.url_policy.denied_domains):
        findings.extend(detect_links(text, cfg.url_policy))
    if cfg.enable_prompt_injection:
        findings.extend(detect_prompt_injection(text))
    if cfg.enable_toxicity:
        findings.extend(detect_dictionary(text, _TOXIC_WORDS, "toxicity", 0.6))
    if cfg.enable_policy_self_harm:
        findings.extend(detect_dictionary(text, _SELF_HARM, "self_harm", 0.9))
    if cfg.enable_policy_violence:
        findings.extend(detect_dictionary(text, _VIOLENCE, "violence", 0.7))
    if cfg.enable_policy_sexual:
        findings.extend(detect_dictionary(text, _SEXUAL, "sexual", 0.7))
    if cfg.enable_malware:
        findings.extend(detect_dictionary(text, _MALWARE, "malware", 0.9))

    # Внешняя модерация (если есть)
    if cfg.moderation is not None:
        try:
            ext = cfg.moderation.score(text)
            if ext is not None:
                findings.append(Finding(label="moderation_external", severity=float(ext)))
        except Exception:
            # не считаем это ошибкой
            pass

    score, reasons = _aggregate(findings, cfg)

    # Определяем, что редактировать
    redact_spans: List[Span] = []
    if cfg.enable_pii or cfg.enable_secrets:
        for f in findings:
            if f.label.startswith(("pii.", "secret.")):
                redact_spans.extend(f.spans)

    sanitized = text
    action = DecisionAction.ALLOW
    if score >= cfg.block_threshold:
        action = DecisionAction.BLOCK
    elif score >= cfg.redact_threshold or redact_spans:
        sanitized, redacted_spans = redact(
            text,
            redact_spans,
            token=cfg.redaction_token,
            keep_last_digits=cfg.keep_last_digits_for_numeric,
        )
        # Политика ссылок: чистим UTM
        if cfg.enable_links and cfg.url_policy.strip_utm_params:
            def _strip(match: re.Match) -> str:
                url = match.group(1)
                return _strip_utm(url)
            sanitized = _RE_URL.sub(lambda m: _strip(m), sanitized)
        action = DecisionAction.ALLOW_WITH_REDACTIONS
        redact_result = redacted_spans
    else:
        redact_result = []

    dt = int((time.perf_counter() - t0) * 1000)
    return Decision(
        action=action,
        score=score,
        reasons=reasons,
        findings=findings,
        redactions=redact_result,
        sanitized_text=sanitized if action != DecisionAction.ALLOW else text,
        duration_ms=dt,
    )

# ============================ Потоковая защита (SSE/WS) ============================

@dataclass
class StreamingState:
    """
    Минимальная реализация защиты для стриминга: накапливает небольшой контекст,
    сканирует инкрементально и редактирует опасные участки.
    """
    cfg: GuardConfig
    tail: str = ""
    blocked: bool = False

    def scan_chunk(self, chunk: str) -> Tuple[str, Optional[Decision]]:
        """
        Возвращает безопасный chunk (возможно отредактированный) и опциональное решение,
        если произошёл блок или существенная редакция.
        """
        if self.blocked:
            return "", None
        window = (self.tail + chunk)[-8000:]  # ограничиваем окно анализа
        decision = evaluate_text(window, self.cfg, for_output=True)

        if decision.action == DecisionAction.BLOCK:
            self.blocked = True
            raise BlockedByPolicy("Streaming blocked by policy", decision)

        safe_chunk = chunk
        if decision.redactions:
            # Пересчитать редакции на актуальный чанк: берём только пересечения в хвосте
            base = max(0, len(window) - len(chunk))
            local_spans = []
            for sp in decision.redactions:
                # глобальные индексы относительно window
                if sp.end <= base:
                    continue
                if sp.start >= len(window):
                    continue
                start = max(0, sp.start - base)
                end = min(len(chunk), sp.end - base)
                if start < end:
                    local_spans.append(Span(start, end, sp.label, sp.value_preview))
            if local_spans:
                safe_chunk, _ = redact(chunk, local_spans, token=self.cfg.redaction_token, keep_last_digits=self.cfg.keep_last_digits_for_numeric)

        # Чистим UTM в ссылках на лету
        if self.cfg.enable_links and self.cfg.url_policy.strip_utm_params:
            safe_chunk = _RE_URL.sub(lambda m: _strip_utm(m.group(1)), safe_chunk)

        # Обновляем хвост
        self.tail = (self.tail + chunk)[-4000:]
        return safe_chunk, (decision if decision.action != DecisionAction.ALLOW else None)

# ============================ Публичный API ============================

class Guardrails:
    def __init__(self, cfg: Optional[GuardConfig] = None) -> None:
        self.cfg = cfg or GuardConfig()

    def evaluate_input(self, text: str) -> Decision:
        return evaluate_text(text, self.cfg, for_output=False)

    def evaluate_output(self, text: str) -> Decision:
        return evaluate_text(text, self.cfg, for_output=True)

    def streaming(self) -> StreamingState:
        return StreamingState(cfg=self.cfg)

# ============================ Примеры интеграции (docstring) ============================

"""
Интеграция с FastAPI (синхронный ответ):

    from neuroforge.safety.guardrails import Guardrails, GuardConfig, UrlPolicy
    guards = Guardrails(GuardConfig(url_policy=UrlPolicy(denied_domains=["evil.com", "bad.site"])))

    @router.post("/v1/infer")
    async def infer(...):
        # Вход
        dec_in = guards.evaluate_input(payload.input_text or "")
        if dec_in.action == DecisionAction.BLOCK:
            return _error_response(400, "policy_block", ";".join(dec_in.reasons), req_id)
        # Инференс ...
        out_text = result.text
        dec_out = guards.evaluate_output(out_text)
        if dec_out.action == DecisionAction.BLOCK:
            return _error_response(400, "policy_block", ";".join(dec_out.reasons), req_id)
        return {**result.model_dump(), "text": dec_out.sanitized_text}

Интеграция с WS/SSE (поток):

    guards = Guardrails()
    state = guards.streaming()
    async for chunk in engine.stream(...):
        try:
            safe, decision = state.scan_chunk(chunk["delta"])
            await session.send(_ok({"id": req_id, "type": "delta", "data": {"delta": safe}}))
        except BlockedByPolicy as ex:
            await session.send(_ok({"id": req_id, "type": "error", "data": {"code": "policy_block", "message": str(ex)}}))
            break
"""
