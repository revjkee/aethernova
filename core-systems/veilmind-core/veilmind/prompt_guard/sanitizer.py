# -*- coding: utf-8 -*-
"""
Veilmind Prompt Guard - Sanitizer
=================================

Назначение:
  Промышленный санитайзер промптов/ответов LLM со следующими возможностями:
    - Нормализация: Unicode NFKC, удаление управляющих символов, свертка пробелов,
      тримминг, ограничение повторов символов.
    - Быстрые блок-листы (regex-паттерны раннего стопа).
    - Детекторы секретов и PII с редактированием (mask/hash/remove/tokenize).
    - Jailbreak / Prompt-Injection детектирование с каноникализацией (удаление
      разделителей, маппинг гомоглифов, понижение регистра).
    - Эвристики эксфильтрации и злоупотребления инструментами.
    - Агрегация риска, пороги deny/review, набор действий.
    - Опциональные внешние ML-скореры (интерфейс).
    - Структурные метрики по шагам, пригодные для Prometheus/логов.
    - Совместимость по структуре с configs/prompt_guard.yaml (см. описанные поля).
    - Без жестких внешних зависимостей (PyYAML опционально).

Ограничения:
  - Реализация ML-скореров не входит; вместо этого предусмотрен интерфейс Scorer.
  - Если вы используете YAML-файлы, потребуется PyYAML (иначе используйте dict).

Автор: Veilmind Core
Лицензия: Apache-2.0 (пример)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# Опциональная интеграция с контекстом (если библиотека присутствует)
try:
    from veilmind.context import get_logger, get_current
except Exception:
    def get_logger(name: str = "veilmind.sanitizer") -> logging.Logger:
        return logging.getLogger(name)
    def get_current():
        return None

log = get_logger("veilmind.sanitizer")

# -----------------------------------------------------------------------------
# Типы данных
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    id: str
    category: str           # например: "secret", "pii.email", "jailbreak", "injection"
    severity: str           # low|medium|high|critical
    start: int              # индекс в нормализованном тексте
    end: int
    matched: Optional[str]  # часть текста; может быть None по политике
    replacement: Optional[str]
    rule_id: Optional[str]
    confidence: float
    detector: str           # regex|heuristic|ml|composite
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class StepMetric:
    name: str
    took_ms: int
    hits: int = 0
    extras: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class SanitizationResult:
    sanitized_text: str
    decision: str           # allow|review|deny
    risk: float             # 0..1
    actions: List[str]      # список действий: redact, block, safe_completion_...
    findings: List[Finding]
    metrics: List[StepMetric]
    reason_codes: List[str] # например: ["secrets", "jailbreak"]
    route: Optional[str] = None
    annotations: Dict[str, Any] = field(default_factory=dict)

# -----------------------------------------------------------------------------
# Конфигурация
# -----------------------------------------------------------------------------

@dataclass
class RedactPolicy:
    mask: str = "[REDACTED]"
    annotate: bool = True
    annotation_prefix: str = "[REDACTED:"
    annotation_suffix: str = "]"
    preserve_length_hint: bool = False

@dataclass
class RiskPolicy:
    weights: Dict[str, float] = field(default_factory=lambda: {
        "secrets": 1.0,
        "pii": 0.6,
        "jailbreak": 0.8,
        "injection": 0.9,
        "safety": 1.0,
        "exfiltration": 1.0,
        "tools_abuse": 0.9,
    })
    thresholds: Dict[str, float] = field(default_factory=lambda: {
        "deny": 0.8,
        "review": 0.6,
    })
    tie_breaker: str = "deny"  # при равенстве

@dataclass
class NormalizeConfig:
    unicode_nfkc: bool = True
    strip_control_chars: bool = True
    collapse_whitespace: bool = True
    trim: bool = True
    lowercase_for_matchers: bool = True
    max_repeated_chars: int = 8

@dataclass
class DetectorConfig:
    fast_blocklist: List[str] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list) # [{id, pattern, severity, deny_immediately}]
    pii: List[Dict[str, Any]] = field(default_factory=list)     # [{id, pattern, severity}]
    jailbreak: List[str] = field(default_factory=list)
    injection: List[str] = field(default_factory=list)
    exfiltration: List[str] = field(default_factory=list)
    tools_abuse: List[str] = field(default_factory=list)

@dataclass
class RoutePolicy:
    routes: List[Tuple[str, str]] = field(default_factory=lambda: [
        ("risk<0.3", "gpt-safe-highspeed"),
        ("0.3<=risk<0.6", "gpt-safe-standard"),
        ("risk>=0.6", "gpt-safe-constrained"),
    ])
    safe_prompt_prefix: Optional[str] = None

@dataclass
class SanitizerConfig:
    normalize: NormalizeConfig = field(default_factory=NormalizeConfig)
    redact: RedactPolicy = field(default_factory=RedactPolicy)
    risk: RiskPolicy = field(default_factory=RiskPolicy)
    detectors: DetectorConfig = field(default_factory=DetectorConfig)
    route: RoutePolicy = field(default_factory=RoutePolicy)
    language_detection: bool = False  # заглушка под будущую реализацию
    fail_mode: str = "fail_closed"    # fail_open|fail_closed

# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
def _ulid() -> str:
    import os, time
    ts = int(time.time() * 1000)
    ts_b = ts.to_bytes(6, "big")
    rnd = os.urandom(10)
    v = int.from_bytes(ts_b + rnd, "big")
    out = []
    for _ in range(26):
        out.append(_B32[v & 31]); v >>= 5
    return "".join(reversed(out))

def _collapse_repeats(s: str, max_rep: int) -> str:
    if max_rep <= 0:
        return s
    # Схлопываем повторы одного и того же символа
    out = []
    prev = None
    run = 0
    for ch in s:
        if ch == prev:
            run += 1
            if run <= max_rep:
                out.append(ch)
        else:
            prev = ch; run = 1; out.append(ch)
    return "".join(out)

def _strip_control(s: str) -> str:
    return "".join(ch for ch in s if ch == "\n" or ch == "\t" or (unicodedata.category(ch)[0] != "C"))

def _collapse_ws(s: str) -> str:
    # Сохраняем перевод строки, схлопываем последовательности пробелов/табов
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    # Удаляем пробелы возле переводов строк
    s = re.sub(r"[ ]*\n[ ]*", "\n", s)
    return s

# Каноникализация для jailbreak/injection: убираем разделители и маппим гомоглифы
_HOMO = {
    "’": "'", "‘": "'", "ˈ": "'", "´": "'", "`": "'",
    "•": "", "·": "", "•": "", "—": "-", "–": "-", "_": "",
    "|": "", "¦": "", "‖": "", "︱": "", "︳": "", "—": "-",
    "ⅰ":"i","Ⅰ":"I","Ι":"I","і":"i","¡":"i","ı":"i","Ｉ":"I","ｉ":"i",
    "А":"A","а":"a","В":"B","Е":"E","е":"e","К":"K","М":"M","Н":"H","О":"O","о":"o","Р":"P","С":"C","с":"c","Т":"T","Х":"X","х":"x","Υ":"Y"
}
_SEP_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]+")

def _canonicalize_for_attack(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = _SEP_RE.sub("", s)
    s = "".join(_HOMO.get(ch, ch) for ch in s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _mask(text: str, start: int, end: int, token: str, *, annotate: bool, prefix: str, suffix: str, preserve_len: bool) -> Tuple[str, int, int]:
    """
    Возвращает новый текст и смещение дельт после замены.
    """
    repl = token
    if preserve_len:
        length = end - start
        if len(token) == 0:
            repl = "*" * length
        else:
            repl = (token * ((length + len(token) - 1)//len(token)))[:length]
    if annotate:
        repl = f"{prefix}{token}{suffix}"
    new_text = text[:start] + repl + text[end:]
    delta = len(repl) - (end - start)
    return new_text, delta, len(repl)

# -----------------------------------------------------------------------------
# Внешние скореры (опционально)
# -----------------------------------------------------------------------------

class Scorer:
    """
    Интерфейс внешнего скорера:
      name() -> str
      score(text: str) -> Dict[str, float]  (напр. {"toxicity": 0.12})
    """
    def name(self) -> str:
        return "noop"
    def score(self, text: str) -> Dict[str, float]:
        return {}

# -----------------------------------------------------------------------------
# Основной класс санитайзера
# -----------------------------------------------------------------------------

class PromptSanitizer:
    def __init__(self, cfg: SanitizerConfig, scorers: Optional[List[Scorer]] = None) -> None:
        self.cfg = cfg
        self.scorers = scorers or []
        # Предкомпилируем паттерны
        self._fast = [re.compile(p, re.IGNORECASE) for p in (cfg.detectors.fast_blocklist or [])]
        self._secrets = [(d.get("id") or f"secret-{i}", re.compile(d["pattern"], re.IGNORECASE), bool(d.get("deny_immediately")), d.get("severity","high")) for i, d in enumerate(cfg.detectors.secrets or [])]
        self._pii = [(d.get("id") or f"pii-{i}", re.compile(d["pattern"], re.IGNORECASE), d.get("severity","medium")) for i, d in enumerate(cfg.detectors.pii or [])]
        self._jailbreak = [re.compile(p, re.IGNORECASE) for p in (cfg.detectors.jailbreak or [])]
        self._injection = [re.compile(p, re.IGNORECASE) for p in (cfg.detectors.injection or [])]
        self._exfil = [re.compile(p, re.IGNORECASE) for p in (cfg.detectors.exfiltration or [])]
        self._tools = [re.compile(p, re.IGNORECASE) for p in (cfg.detectors.tools_abuse or [])]

    # ----------------------------- Публичные методы -----------------------------

    @classmethod
    def from_yaml(cls, path: str, *, scorers: Optional[List[Scorer]] = None) -> "PromptSanitizer":
        if not _HAS_YAML:
            raise RuntimeError("PyYAML is required to load config from YAML")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        cfg = _cfg_from_dict(data)
        return cls(cfg, scorers=scorers)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, scorers: Optional[List[Scorer]] = None) -> "PromptSanitizer":
        cfg = _cfg_from_dict(data)
        return cls(cfg, scorers=scorers)

    def sanitize_input(self, text: str, *, locale: Optional[str] = None) -> SanitizationResult:
        """
        Санитайзинг входного промпта.
        """
        return self._run_pipeline(text, is_output=False, locale=locale)

    def sanitize_output(self, text: str, *, locale: Optional[str] = None) -> SanitizationResult:
        """
        Санитайзинг выхода модели (напр. для защиты от утечек секретов/PII).
        """
        return self._run_pipeline(text, is_output=True, locale=locale)

    # ----------------------------- Внутренняя логика ---------------------------

    def _run_pipeline(self, text: str, *, is_output: bool, locale: Optional[str]) -> SanitizationResult:
        start_total = time.time()
        metrics: List[StepMetric] = []
        findings: List[Finding] = []
        actions: List[str] = []
        reason_codes: List[str] = []
        risk_acc: Dict[str, float] = {"secrets": 0.0, "pii": 0.0, "jailbreak": 0.0, "injection": 0.0, "safety": 0.0, "exfiltration": 0.0, "tools_abuse": 0.0}

        try:
            # 1) Normalize
            t0 = time.time()
            norm = self._normalize(text)
            metrics.append(StepMetric("normalize", int((time.time()-t0)*1000)))
            # 2) Fast blocklist (early stop)
            t0 = time.time()
            fb_hits = self._scan_fast_blocklist(norm)
            metrics.append(StepMetric("fast_blocklist", int((time.time()-t0)*1000), hits=len(fb_hits)))
            if fb_hits:
                # Поведение: увеличиваем риск и добавляем reason, но не выходим сразу — пусть дальнейшие шаги доредактируют текст
                risk_acc["injection"] = max(risk_acc["injection"], 0.9)
                reason_codes.append("fast_blocklist")
                findings.extend(fb_hits)
            # 3) Secrets redact (always)
            t0 = time.time()
            norm, f_sec, any_deny = self._redact_by_rules(norm, self._secrets, category_prefix="secret", default_mask="[REDACTED-SECRET]")
            metrics.append(StepMetric("secrets", int((time.time()-t0)*1000), hits=len(f_sec)))
            if f_sec:
                findings.extend(f_sec); actions.append("redact")
                risk_acc["secrets"] = max(risk_acc["secrets"], 1.0 if any_deny else 0.7)
                reason_codes.append("secrets")
            # 4) PII redact
            t0 = time.time()
            norm, f_pii, _ = self._redact_by_rules(norm, self._pii, category_prefix="pii", default_mask="[REDACTED-PII]")
            metrics.append(StepMetric("pii", int((time.time()-t0)*1000), hits=len(f_pii)))
            if f_pii:
                findings.extend(f_pii); actions.append("redact")
                risk_acc["pii"] = max(risk_acc["pii"], 0.6)
                reason_codes.append("pii")
            # 5) Jailbreak / Injection heuristics
            t0 = time.time()
            f_jb, f_inj = self._scan_attacks(norm)
            metrics.append(StepMetric("attacks", int((time.time()-t0)*1000), hits=len(f_jb)+len(f_inj)))
            if f_jb:
                findings.extend(f_jb); risk_acc["jailbreak"] = max(risk_acc["jailbreak"], 0.8); reason_codes.append("jailbreak")
            if f_inj:
                findings.extend(f_inj); risk_acc["injection"] = max(risk_acc["injection"], 0.9); reason_codes.append("injection")
            # 6) Exfil / tools abuse
            t0 = time.time()
            f_ex, f_tools = self._scan_exfil_and_tools(norm)
            metrics.append(StepMetric("exfil_tools", int((time.time()-t0)*1000), hits=len(f_ex)+len(f_tools)))
            if f_ex:
                findings.extend(f_ex); risk_acc["exfiltration"] = max(risk_acc["exfiltration"], 1.0); reason_codes.append("exfiltration")
            if f_tools:
                findings.extend(f_tools); risk_acc["tools_abuse"] = max(risk_acc["tools_abuse"], 0.9); reason_codes.append("tools_abuse")
            # 7) External scorers (optional)
            t0 = time.time()
            safety_risk = 0.0
            for scorer in self.scorers:
                try:
                    scores = scorer.score(norm)
                    # Пример: toxicity -> safety
                    if "toxicity" in scores:
                        safety_risk = max(safety_risk, float(scores["toxicity"]))
                except Exception as e:
                    log.warning("scorer %s failed: %s", getattr(scorer, "name", lambda: "unknown")(), e)
            if safety_risk > 0.0:
                risk_acc["safety"] = max(risk_acc["safety"], safety_risk)
                reason_codes.append("safety")
            metrics.append(StepMetric("scorers", int((time.time()-t0)*1000), hits=1 if safety_risk>0 else 0, extras={"safety_risk": safety_risk}))
            # 8) Decision
            risk, decision = self._decide(risk_acc)
            actions = sorted(set(actions))
            route = self._route(risk)
            annotations = {
                "risk_components": risk_acc,
                "route": route,
            }
            metrics.append(StepMetric("total", int((time.time()-start_total)*1000)))

            # В случае deny можно вернуть отредактированный текст или пустой, оставляем отредактированный norm
            return SanitizationResult(
                sanitized_text=norm,
                decision=decision,
                risk=risk,
                actions=actions if decision != "deny" else ["block"] + actions,
                findings=findings,
                metrics=metrics,
                reason_codes=sorted(set(reason_codes)),
                route=route,
                annotations=annotations,
            )
        except Exception as e:
            log.exception("sanitization failed: %s", e)
            # fail_open/closed
            if self.cfg.fail_mode == "fail_open":
                return SanitizationResult(
                    sanitized_text=text,
                    decision="allow",
                    risk=0.0,
                    actions=[],
                    findings=[],
                    metrics=[StepMetric("error", 0, hits=0, extras={"error": str(e)})],
                    reason_codes=["error"],
                )
            return SanitizationResult(
                sanitized_text="",
                decision="deny",
                risk=1.0,
                actions=["block"],
                findings=[],
                metrics=[StepMetric("error", 0, hits=0, extras={"error": str(e)})],
                reason_codes=["error"],
            )

    # ----------------------------- Частные методы ------------------------------

    def _normalize(self, text: str) -> str:
        cfg = self.cfg.normalize
        s = text
        if cfg.unicode_nfkc:
            s = unicodedata.normalize("NFKC", s)
        if cfg.strip_control_chars:
            s = _strip_control(s)
        if cfg.collapse_whitespace:
            s = _collapse_ws(s)
        if cfg.trim:
            s = s.strip()
        if cfg.max_repeated_chars and cfg.max_repeated_chars > 0:
            s = _collapse_repeats(s, cfg.max_repeated_chars)
        return s

    def _scan_fast_blocklist(self, text: str) -> List[Finding]:
        hits: List[Finding] = []
        for rx in self._fast:
            for m in rx.finditer(text):
                hits.append(Finding(
                    id=_ulid(), category="fast_blocklist", severity="high",
                    start=m.start(), end=m.end(), matched=text[m.start():m.end()],
                    replacement=None, rule_id=rx.pattern, confidence=0.9, detector="regex"
                ))
        return hits

    def _redact_by_rules(self, text: str, rules: Sequence[Tuple[str, re.Pattern, bool, str]] | Sequence[Tuple[str, re.Pattern, str]], *, category_prefix: str, default_mask: str) -> Tuple[str, List[Finding], bool]:
        """
        Применяет набор правил с редактированием.
        Возвращает (новый_текст, находки, был_ли_deny_иммедиатли).
        """
        findings: List[Finding] = []
        any_deny = False
        # Пройдемся слева направо, применяя замены с учетом смещений
        i = 0
        cfg_r = self.cfg.redact
        s = text
        while i < len(s):
            earliest = None
            rule = None
            # Найдем ближайшее совпадение по всем правилам
            for r in rules:
                rid = r[0]; rx = r[1]
                m = rx.search(s, i)
                if m and (earliest is None or m.start() < earliest.start()):
                    earliest = m; rule = r
            if not earliest:
                break
            start, end = earliest.start(), earliest.end()
            deny_immediately = False
            severity = "high"
            if len(rule) == 4:
                deny_immediately = bool(rule[2])
                severity = str(rule[3])
            # Строим находку
            matched = s[start:end]
            token = default_mask
            s, delta, repl_len = _mask(
                s, start, end, token,
                annotate=cfg_r.annotate,
                prefix=cfg_r.annotation_prefix,
                suffix=cfg_r.annotation_suffix,
                preserve_len=cfg_r.preserve_length_hint,
            )
            finding = Finding(
                id=_ulid(),
                category=f"{category_prefix}",
                severity=severity,
                start=start,
                end=start+repl_len,
                matched=matched if category_prefix != "secret" else None,  # не логируем исходный секрет
                replacement=token,
                rule_id=rule[0],
                confidence=0.99,
                detector="regex",
                metadata={"deny_immediately": deny_immediately},
            )
            findings.append(finding)
            if deny_immediately:
                any_deny = True
            i = start + repl_len
        return s, findings, any_deny

    def _scan_attacks(self, text: str) -> Tuple[List[Finding], List[Finding]]:
        """
        Возвращает (jailbreak_findings, injection_findings).
        """
        jb: List[Finding] = []
        inj: List[Finding] = []
        canon = _canonicalize_for_attack(text)
        # Jailbreak
        for rx in self._jailbreak:
            if rx.search(canon):
                jb.append(Finding(
                    id=_ulid(), category="jailbreak", severity="high",
                    start=0, end=0, matched=None, replacement=None,
                    rule_id=rx.pattern, confidence=0.8, detector="heuristic",
                    metadata={"canonicalized": True}
                ))
        # Injection
        for rx in self._injection:
            if rx.search(canon):
                inj.append(Finding(
                    id=_ulid(), category="injection", severity="high",
                    start=0, end=0, matched=None, replacement=None,
                    rule_id=rx.pattern, confidence=0.85, detector="heuristic",
                    metadata={"canonicalized": True}
                ))
        return jb, inj

    def _scan_exfil_and_tools(self, text: str) -> Tuple[List[Finding], List[Finding]]:
        exf: List[Finding] = []
        tls: List[Finding] = []
        for rx in self._exfil:
            for m in rx.finditer(text):
                exf.append(Finding(
                    id=_ulid(), category="exfiltration", severity="critical",
                    start=m.start(), end=m.end(), matched=text[m.start():m.end()],
                    replacement=None, rule_id=rx.pattern, confidence=0.9, detector="regex"
                ))
        for rx in self._tools:
            if rx.search(text):
                tls.append(Finding(
                    id=_ulid(), category="tools_abuse", severity="high",
                    start=0, end=0, matched=None, replacement=None, rule_id=rx.pattern,
                    confidence=0.9, detector="regex"
                ))
        return exf, tls

    def _decide(self, risk_components: Mapping[str, float]) -> Tuple[float, str]:
        w = self.cfg.risk.weights
        r = 0.0
        for k, v in risk_components.items():
            r = max(r, min(1.0, float(w.get(k, 0.0)) * float(v)))
        thr = self.cfg.risk.thresholds
        if r >= float(thr.get("deny", 0.8)):
            return r, "deny"
        if r >= float(thr.get("review", 0.6)):
            return r, "review"
        return r, "allow"

    def _route(self, risk: float) -> Optional[str]:
        for cond, model in self.cfg.route.routes:
            cond = cond.replace("risk", str(risk))
            try:
                if self._eval_cond(cond):
                    return model
            except Exception:
                continue
        return None

    @staticmethod
    def _eval_cond(expr: str) -> bool:
        """
        Мини-вырезка для условий вида "risk<0.3", "0.3<=risk<0.6", "risk>=0.6".
        """
        expr = expr.strip()
        # поддержка диапазона a<=x<b
        m = re.match(r"^\s*([0-9.]+)\s*<=\s*([a-z]+)\s*<\s*([0-9.]+)\s*$", expr)
        if m:
            a = float(m.group(1)); var = m.group(2); b = float(m.group(3))
            val = float(expr.split(var)[0] or 0.0)  # не используется
            # фактическое значение подставляется до вызова. Для простоты округлим к сравнению:
            # мы уже заменили "risk" на число, выше.
        # после подстановки risk, выражение вида "0.3<=0.41<0.6"
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            return False

# -----------------------------------------------------------------------------
# Вспомогательный конструктор конфига из словаря
# -----------------------------------------------------------------------------

def _cfg_from_dict(data: Mapping[str, Any]) -> SanitizerConfig:
    # Безопасный парсер, с дефолтами
    def _list_of_patterns(seq: Optional[Iterable[str]]) -> List[str]:
        return [str(x) for x in (seq or [])]

    det = data.get("detectors", {}) or {}
    secrets = det.get("secrets") or []
    pii = det.get("pii") or []

    cfg = SanitizerConfig(
        normalize=NormalizeConfig(
            unicode_nfkc=bool(_deep_get(data, ["normalize", "unicode_nfkc"], True)),
            strip_control_chars=bool(_deep_get(data, ["normalize", "strip_control_chars"], True)),
            collapse_whitespace=bool(_deep_get(data, ["normalize", "collapse_whitespace"], True)),
            trim=bool(_deep_get(data, ["normalize", "trim"], True)),
            lowercase_for_matchers=bool(_deep_get(data, ["normalize", "lowercase_for_matchers"], True)),
            max_repeated_chars=int(_deep_get(data, ["normalize", "max_repeated_chars"], 8)),
        ),
        redact=RedactPolicy(
            mask=str(_deep_get(data, ["redact_transform", "default_mask"], "[REDACTED]")),
            annotate=bool(_deep_get(data, ["redact_transform", "annotate_redactions"], True)),
            annotation_prefix=str(_deep_get(data, ["redact_transform", "annotations", "prefix"], "[REDACTED:"])),
            annotation_suffix=str(_deep_get(data, ["redact_transform", "annotations", "suffix"], "]")),
            preserve_length_hint=bool(_deep_get(data, ["redact_transform", "preserve_length_hint"], False)),
        ),
        risk=RiskPolicy(
            weights=dict(_deep_get(data, ["policy_decision", "risk_weights"], {
                "secrets": 1.0, "pii": 0.6, "jailbreak": 0.8, "injection": 0.9, "safety": 1.0, "exfiltration": 1.0, "tools_abuse": 0.9
            })),
            thresholds=dict(_deep_get(data, ["policy_decision", "thresholds"], {"deny": 0.8, "review": 0.6})),
            tie_breaker=str(_deep_get(data, ["policy_decision", "tie_breaker"], "deny")),
        ),
        detectors=DetectorConfig(
            fast_blocklist=_list_of_patterns(_deep_get(data, ["fast_blocklists", "patterns"], [])),
            secrets=[{
                "id": d.get("id") or f"secret-{i}",
                "pattern": d.get("pattern"),
                "deny_immediately": bool(d.get("deny_immediately", True)),
                "severity": d.get("severity", "high"),
            } for i, d in enumerate(secrets)],
            pii=[{
                "id": d.get("id") or f"pii-{i}",
                "pattern": d.get("regex") or d.get("pattern"),
                "severity": d.get("severity", "medium"),
            } for i, d in enumerate(pii)],
            jailbreak=_list_of_patterns(_deep_get(data, ["jailbreak", "heuristics", "signals"], [])),
            injection=_list_of_patterns(_deep_get(data, ["prompt_injection", "detectors", "outputs_leakage", "patterns"], [])) +
                      _list_of_patterns(_deep_get(data, ["prompt_injection", "detectors", "tool_coercion", "patterns"], [])),
            exfiltration=_list_of_patterns(_deep_get(data, ["exfiltration", "sinks"], [])),
            tools_abuse=_list_of_patterns(_deep_get(data, ["tools_abuse", "forbidden_tools"], [])),
        ),
        route=RoutePolicy(
            routes=[("risk<0.3", "gpt-safe-highspeed"),
                    ("0.3<=risk<0.6", "gpt-safe-standard"),
                    ("risk>=0.6", "gpt-safe-constrained")],
            safe_prompt_prefix=str(_deep_get(data, ["route_model", "safe_prompt_prefix", "text"], "")) or None
        ),
        language_detection=bool(_deep_get(data, ["normalize", "language_detection", "enabled"], False)),
        fail_mode=str(_deep_get(data, ["runtime", "fail_mode"], "fail_closed")),
    )
    return cfg

def _deep_get(m: Mapping[str, Any], path: Sequence[str], default: Any = None) -> Any:
    cur: Any = m
    for k in path:
        if not isinstance(cur, Mapping) or k not in cur:
            return default
        cur = cur[k]
    return cur
