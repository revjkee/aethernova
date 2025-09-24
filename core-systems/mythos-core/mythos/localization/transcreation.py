# mythos-core/mythos/localization/transcreation.py
# -*- coding: utf-8 -*-
"""
Transcreation engine (industrial-grade) for Mythos Core.

Функциональность:
- Адаптерная архитектура генерации (rule-based по умолчанию, LLM-адаптеры можно подключать).
- PII redaction/restore (email, телефон, номера карт/паспортов).
- Бренд-гайд: голос, тон, запреты, "do/don't", регистр.
- Ограничения: длина (символы/слова), обязательные/запрещённые термины, сохранение сущностей.
- Глоссарий: принудительное применение терминов (с приоритетом).
- Вариативная генерация, скоринг, отчёт о качестве.
- CLI: быстрый запуск из консоли.

Зависимости: только стандартная библиотека (typing, dataclasses, logging, re, json, argparse).
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import random
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "Tone",
    "Register",
    "Strategy",
    "LocaleSpec",
    "GlossaryTerm",
    "BrandGuidelines",
    "ConstraintSet",
    "StrategyConfig",
    "TranscreationRequest",
    "TranscreationResult",
    "QualityReport",
    "TranscreationEngine",
    "BaseAdapter",
    "RuleBasedAdapter",
    "TranscreationError",
    "ConstraintViolation",
]

# -------------------------------
# Логирование
# -------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    # Нейтральная настройка: не ломаем root, только базовый формат для standalone
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# -------------------------------
# Типы и модели
# -------------------------------

class Tone(Enum):
    NEUTRAL = "neutral"
    FRIENDLY = "friendly"
    CONFIDENT = "confident"
    PLAYFUL = "playful"
    FORMAL = "formal"
    EMPATHETIC = "empathetic"


class Register(Enum):
    INFORMAL = "informal"
    NEUTRAL = "neutral"
    FORMAL = "formal"


class Strategy(Enum):
    LITERAL = "literal"         # ближе к переводу
    CREATIVE = "creative"       # допускает перефразирование/локализацию
    TRANSCREATION = "transcreation"  # глубокая адаптация под целевую культуру


@dataclass(frozen=True)
class LocaleSpec:
    lang: str         # "ru", "en", "de"
    region: str = ""  # "RU", "US", ...

    @property
    def code(self) -> str:
        return f"{self.lang}-{self.region}" if self.region else self.lang


@dataclass(frozen=True)
class GlossaryTerm:
    source: str
    target: str
    case_sensitive: bool = False
    enforce: bool = True  # если True — жёсткая подмена
    comment: str = ""


@dataclass
class BrandGuidelines:
    voice_keywords: List[str] = field(default_factory=list)  # слова/тезисы голоса бренда
    do: List[str] = field(default_factory=list)              # что желательно
    dont: List[str] = field(default_factory=list)            # что нельзя
    taboo: List[str] = field(default_factory=list)           # табу-слова (усиление бан-листов)
    preferred_spelling: Dict[str, str] = field(default_factory=dict)  # "e-mail"->"email", "онлайн"->"онлайн"


@dataclass
class ConstraintSet:
    max_chars: Optional[int] = None
    max_words: Optional[int] = None
    required_terms: List[str] = field(default_factory=list)
    banned_terms: List[str] = field(default_factory=list)
    keep_entities: bool = True  # восстанавливать PII после генерации
    tone: Tone = Tone.NEUTRAL
    register: Register = Register.NEUTRAL


@dataclass
class StrategyConfig:
    adapter_name: str = "rule"
    n_candidates: int = 3
    temperature: float = 0.3
    diversity: float = 0.35
    deterministic: bool = True
    seed: Optional[int] = 42


@dataclass
class TranscreationRequest:
    source_text: str
    source_locale: LocaleSpec
    target_locale: LocaleSpec
    strategy: Strategy = Strategy.TRANSCREATION
    constraints: ConstraintSet = field(default_factory=ConstraintSet)
    brand: BrandGuidelines = field(default_factory=BrandGuidelines)
    glossary: List[GlossaryTerm] = field(default_factory=list)
    context: Dict[str, str] = field(default_factory=dict)  # продукт, аудитория, платформа
    metadata: Dict[str, str] = field(default_factory=dict) # trace-id, campaign-id, etc.


@dataclass
class QualityReport:
    length_ok: bool
    required_terms_covered: bool
    banned_terms_absent: bool
    tone_match_score: float
    register_match: bool
    pii_restored: bool
    word_count: int
    char_count: int
    penalties: List[str] = field(default_factory=list)


@dataclass
class TranscreationResult:
    text: str
    report: QualityReport
    debug: Dict[str, str] = field(default_factory=dict)


# -------------------------------
# Исключения
# -------------------------------

class TranscreationError(Exception):
    pass


class ConstraintViolation(TranscreationError):
    pass


# -------------------------------
# Утилиты текста
# -------------------------------

_WHITESPACE_RE = re.compile(r"[ \t\u00A0]+")
_MULTI_NL_RE = re.compile(r"\n{3,}")
_QUOTES_REPLACERS = {
    "“": "\"", "”": "\"", "„": "\"", "«": "\"", "»": "\"",
    "’": "'", "‘": "'", "‚": "'",
}


def normalize_text(s: str) -> str:
    s = s.strip()
    for k, v in _QUOTES_REPLACERS.items():
        s = s.replace(k, v)
    s = _WHITESPACE_RE.sub(" ", s)
    s = _MULTI_NL_RE.sub("\n\n", s)
    return s


def count_words(s: str) -> int:
    return len([w for w in re.findall(r"[^\W_]+", s, flags=re.UNICODE) if w])


def truncate_to_chars(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    # Пытаемся обрезать по границе предложения/слова
    trimmed = text[:limit].rsplit(" ", 1)[0]
    if not trimmed:
        trimmed = text[:limit]
    return trimmed + "…"


def truncate_to_words(text: str, max_words: int) -> str:
    words = re.findall(r"\S+", text)
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]) + "…"


def readability_score(s: str) -> float:
    """
    Проксискиор читаемости (языконейтральный): ниже — легче, выше — тяжелее.
    Основано на средней длине слова и предложений.
    """
    sentences = [x for x in re.split(r"[.!?]+", s) if x.strip()]
    words = re.findall(r"[^\W_]+", s, flags=re.UNICODE)
    if not words:
        return 0.0
    avg_word_len = sum(len(w) for w in words) / len(words)
    avg_sent_len = (len(words) / max(1, len(sentences)))
    return 0.6 * avg_word_len + 0.4 * math.log1p(avg_sent_len)


# -------------------------------
# PII Redaction/Restore
# -------------------------------

PII_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"(?:(?<!\d)\+?\d[\d\-\s().]{7,}\d)"),
    "CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "PASSPORT": re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b"),  # пример для некоторых стран
}

def mask_pii(text: str) -> Tuple[str, Dict[str, List[str]]]:
    mapping: Dict[str, List[str]] = {}
    masked = text
    for tag, pat in PII_PATTERNS.items():
        found = pat.findall(masked)
        if found:
            mapping[tag] = found
            for i, val in enumerate(found, start=1):
                masked = masked.replace(val, f"{{{tag}_{i}}}")
    return masked, mapping


def restore_pii(text: str, mapping: Dict[str, List[str]]) -> str:
    restored = text
    for tag, vals in mapping.items():
        for i, val in enumerate(vals, start=1):
            restored = restored.replace(f"{{{tag}_{i}}}", val)
    return restored


# -------------------------------
# Глоссарий и фильтры
# -------------------------------

def apply_glossary(text: str, terms: Sequence[GlossaryTerm]) -> str:
    out = text
    for t in terms:
        if not t.source:
            continue
        flags = 0 if t.case_sensitive else re.IGNORECASE
        pattern = re.compile(rf"\b{re.escape(t.source)}\b", flags)
        out = pattern.sub(t.target, out)
    return out


def enforce_banned_terms(text: str, banned: Sequence[str]) -> Tuple[str, List[str]]:
    violations = []
    out = text
    for w in banned:
        if not w:
            continue
        pat = re.compile(re.escape(w), re.IGNORECASE)
        if pat.search(out):
            violations.append(w)
            out = pat.sub("—", out)  # мягкая замена
    return out, violations


def ensure_required_terms(text: str, required: Sequence[str]) -> Tuple[str, List[str]]:
    missing = []
    for w in required:
        if w and re.search(re.escape(w), text, re.IGNORECASE) is None:
            missing.append(w)
    return text, missing


def apply_brand_spelling(text: str, mapping: Dict[str, str]) -> str:
    out = text
    for src, tgt in mapping.items():
        pat = re.compile(rf"\b{re.escape(src)}\b", re.IGNORECASE)
        out = pat.sub(tgt, out)
    return out


# -------------------------------
# Адаптеры генерации
# -------------------------------

class BaseAdapter:
    """Интерфейс адаптера генерации. Реализуйте generate_variants под свой LLM/сервис."""
    name: str = "base"

    def generate_variants(
        self,
        prompt: str,
        n: int,
        temperature: float = 0.3,
        diversity: float = 0.35,
        deterministic: bool = True,
        seed: Optional[int] = None,
        meta: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        raise NotImplementedError


class RuleBasedAdapter(BaseAdapter):
    """
    Запасной 'offline' адаптер без внешних зависимостей.
    Делает безопасные перефразирования и тон-адаптацию простыми правилами.
    """
    name: str = "rule"

    _SYNONYMS: Dict[Tone, List[Tuple[re.Pattern, str]]] = {
        Tone.FRIENDLY: [
            (re.compile(r"\bпокупайте\b", re.IGNORECASE), "загляните"),
            (re.compile(r"\bкупите\b", re.IGNORECASE), "берите с удовольствием"),
            (re.compile(r"\bклиент(ы|ам|ам|у)?\b", re.IGNORECASE), "друзья"),
        ],
        Tone.CONFIDENT: [
            (re.compile(r"\bвозможно\b", re.IGNORECASE), "определённо"),
            (re.compile(r"\bпопробуйте\b", re.IGNORECASE), "выбирайте"),
        ],
        Tone.FORMAL: [
            (re.compile(r"\bвы\b", re.IGNORECASE), "Вы"),
            (re.compile(r"\bспасибо\b", re.IGNORECASE), "благодарим"),
        ],
        Tone.EMPATHETIC: [
            (re.compile(r"\bпонимаем\b", re.IGNORECASE), "мы понимаем и рядом"),
        ],
        Tone.PLAYFUL: [
            (re.compile(r"\bсегодня\b", re.IGNORECASE), "уже сейчас — по-настоящему"),
        ],
        Tone.NEUTRAL: [],
    }

    def _apply_tone(self, text: str, tone: Tone) -> str:
        out = text
        for pat, repl in self._SYNONYMS.get(tone, []):
            out = pat.sub(repl, out)
        return out

    def _apply_register(self, text: str, register: Register) -> str:
        if register == Register.FORMAL:
            # примитивная капитализация "Вы"
            out = re.sub(r"\bвы\b", "Вы", text)
            return out
        if register == Register.INFORMAL:
            # немного разговорных маркеров (аккуратно, без перегиба)
            out = text.replace("пожалуйста", "плиз").replace("Здравствуйте", "Привет")
            return out
        return text

    def _diversify(self, text: str, diversity: float, seed: Optional[int]) -> str:
        rnd = random.Random(seed)
        out = text
        # Безопасные перестановки запятых и вводных — чтобы слегка варьировать
        variants = [
            lambda s: s,
            lambda s: s.replace("например,", "например"),
            lambda s: s.replace("в том числе", "включая"),
            lambda s: s.replace("также", "к тому же"),
        ]
        f = rnd.choice(variants if rnd.random() < diversity else variants[:1])
        out = f(out)
        return out

    def generate_variants(
        self,
        prompt: str,
        n: int,
        temperature: float = 0.3,
        diversity: float = 0.35,
        deterministic: bool = True,
        seed: Optional[int] = None,
        meta: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """
        prompt: уже сформированный целевой текст/инструкция.
        Здесь мы интерпретируем prompt как исходный нормализованный текст,
        применяем тон/регистр из meta.
        """
        tone = Tone(meta.get("tone")) if meta and meta.get("tone") in Tone._value2member_map_ else Tone.NEUTRAL
        register = Register(meta.get("register")) if meta and meta.get("register") in Register._value2member_map_ else Register.NEUTRAL

        base_text = prompt
        if not base_text.strip():
            return [""] * n

        rng = random.Random(seed if deterministic else None)
        variants: List[str] = []
        for i in range(n):
            t = base_text
            # лёгкое перемешивание предложений как имитация креативности
            sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", t) if s.strip()]
            if len(sentences) > 1 and rng.random() < max(0.1, temperature):
                rng.shuffle(sentences)
            t = " ".join(sentences)

            # тон и регистр
            t = self._apply_tone(t, tone)
            t = self._apply_register(t, register)

            # диверсификация
            t = self._diversify(t, diversity, (seed or 0) + i if deterministic else None)

            variants.append(t)

        return variants


# -------------------------------
# Ядро движка
# -------------------------------

class TranscreationEngine:
    def __init__(self, adapters: Optional[Dict[str, BaseAdapter]] = None):
        self.adapters = adapters or {"rule": RuleBasedAdapter()}

    # ---------- Публичный API ----------

    def transcreate(self, req: TranscreationRequest, strat: Optional[StrategyConfig] = None) -> TranscreationResult:
        self._validate_request(req)
        strat = strat or StrategyConfig()

        # 1) Нормализация и PII
        normalized = normalize_text(req.source_text)
        masked_src, pii_map = mask_pii(normalized)
        logger.debug("Masked source: %s", masked_src)

        # 2) Формируем "инструкцию" для адаптера
        prompt = self._build_prompt(masked_src, req)

        # 3) Генерация кандидатов
        adapter = self._get_adapter(strat.adapter_name)
        candidates = adapter.generate_variants(
            prompt=prompt,
            n=max(1, strat.n_candidates),
            temperature=max(0.0, min(1.0, strat.temperature)),
            diversity=max(0.0, min(1.0, strat.diversity)),
            deterministic=strat.deterministic,
            seed=strat.seed,
            meta={
                "tone": req.constraints.tone.value,
                "register": req.constraints.register.value,
                "target_locale": req.target_locale.code,
                "strategy": req.strategy.value,
            },
        )
        logger.debug("Raw candidates: %r", candidates)

        # 4) Постобработка: глоссарий, бренд-правила, фильтры/ограничения
        scored: List[Tuple[str, QualityReport]] = []
        for cand in candidates:
            c = apply_brand_spelling(cand, req.brand.preferred_spelling)
            c = apply_glossary(c, req.glossary)
            c, banned_hits = enforce_banned_terms(c, req.constraints.banned_terms + req.brand.taboo)

            # Длина
            c = self._apply_length_constraints(c, req.constraints)

            # Обязательные термины
            _, missing = ensure_required_terms(c, req.constraints.required_terms)

            # Восстановить PII?
            pii_restored = False
            if req.constraints.keep_entities:
                c = restore_pii(c, pii_map)
                pii_restored = True

            # Оценки/метрики
            report = self._build_quality_report(
                text=c,
                constraints=req.constraints,
                banned_hits=banned_hits,
                missing_required=missing,
                pii_restored=pii_restored,
            )
            scored.append((c, report))

        # 5) Ранжирование и выбор лучшего
        best_text, best_report = self._select_best(scored)
        debug = {
            "adapter": adapter.name,
            "strategy": req.strategy.value,
            "target_locale": req.target_locale.code,
            "candidates": str(len(candidates)),
        }
        return TranscreationResult(text=best_text, report=best_report, debug=debug)

    # ---------- Внутренние методы ----------

    def _validate_request(self, req: TranscreationRequest) -> None:
        if not req.source_text or not req.source_text.strip():
            raise TranscreationError("source_text is empty")
        if not req.target_locale or not req.target_locale.lang:
            raise TranscreationError("target_locale is required")
        if req.constraints.max_chars is not None and req.constraints.max_chars <= 0:
            raise TranscreationError("max_chars must be positive")
        if req.constraints.max_words is not None and req.constraints.max_words <= 0:
            raise TranscreationError("max_words must be positive")

    def _get_adapter(self, name: str) -> BaseAdapter:
        if name not in self.adapters:
            raise TranscreationError(f"Adapter '{name}' not registered")
        return self.adapters[name]

    def _build_prompt(self, masked_src: str, req: TranscreationRequest) -> str:
        """
        Для rule-based адаптера prompt = уже целевая основа.
        Для LLM-адаптера здесь можно собрать инструкцию в system/user стиле.
        """
        base = masked_src

        # Стратегия: если CREATIVE/TRANSCREATION — можно чутка "освободить" текст
        if req.strategy in (Strategy.CREATIVE, Strategy.TRANSCREATION):
            # Небольшой приём: подсказка на повышение ясности и пользы
            base = self._clarify_for_target(base, req)

        # Мини-приведение к регистру/тону через текстовые подсказки (мягкие маркеры)
        tone_marker = {
            Tone.NEUTRAL: "",
            Tone.FRIENDLY: " (мягко, дружелюбно)",
            Tone.CONFIDENT: " (уверенно)",
            Tone.PLAYFUL: " (игрово)",
            Tone.FORMAL: " (официально)",
            Tone.EMPATHETIC: " (с эмпатией)",
        }[req.constraints.tone]

        reg_marker = {
            Register.NEUTRAL: "",
            Register.FORMAL: " (на «Вы»; деловой стиль)",
            Register.INFORMAL: " (разговорно; допустимы простые обороты)",
        }[req.constraints.register]

        # Включим ключевые слова бренда как target cues
        brand_cues = ""
        if req.brand.voice_keywords:
            brand_cues = " | ключевые акценты: " + ", ".join(req.brand.voice_keywords)

        prompt = f"{base}{tone_marker}{reg_marker}{brand_cues}"
        return prompt

    def _clarify_for_target(self, text: str, req: TranscreationRequest) -> str:
        """
        Лёгкая нормализация для целевой аудитории (без внешнего ИИ):
        - убираем сложные канцеляризмы;
        - делаем предложения короче.
        """
        t = text

        # Упростим некоторые канцеляризмы
        replacements = {
            "в целях": "чтобы",
            "осуществляется": "делается",
            "настоящий": "этот",
            "данный": "этот",
            "в рамках": "в",
            "направленный на": "для",
        }
        for k, v in replacements.items():
            t = re.sub(rf"\b{re.escape(k)}\b", v, t, flags=re.IGNORECASE)

        # Расщепим слишком длинные предложения по запятым (очень осторожно)
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", t) if s.strip()]
        new_sentences: List[str] = []
        for s in sentences:
            if len(s) > 180 and "," in s:
                parts = [p.strip() for p in s.split(",")]
                chunk = []
                for p in parts:
                    chunk.append(p)
                    if sum(len(x) for x in chunk) > 120:
                        new_sentences.append(", ".join(chunk) + ".")
                        chunk = []
                if chunk:
                    new_sentences.append(", ".join(chunk) + ".")
            else:
                new_sentences.append(s)
        return " ".join(new_sentences)

    def _apply_length_constraints(self, text: str, c: ConstraintSet) -> str:
        out = text
        if c.max_chars is not None:
            out = truncate_to_chars(out, c.max_chars)
        if c.max_words is not None:
            out = truncate_to_words(out, c.max_words)
        return out

    def _tone_match_score(self, text: str, tone: Tone, brand: BrandGuidelines) -> float:
        """
        Примитивный скоринг по наличию/отсутствию некоторых маркеров.
        0..1, где 1 — наилучшее соответствие.
        """
        s = text.lower()
        score = 0.5  # базовый
        if tone == Tone.FRIENDLY and any(w in s for w in ["давайте", "загляните", "привет", "рады"]):
            score += 0.2
        if tone == Tone.CONFIDENT and any(w in s for w in ["определённо", "точно", "выбирайте"]):
            score += 0.2
        if tone == Tone.FORMAL and any(w in s for w in ["благодарим", "уважаемые", "приглашаем"]):
            score += 0.2
        if tone == Tone.EMPATHETIC and any(w in s for w in ["понимаем", "с вами", "поддержим"]):
            score += 0.2
        if tone == Tone.PLAYFUL and any(w in s for w in ["уже сейчас", "по-настоящему", "игрово"]):
            score += 0.2

        # голос бренда — бонус за ключевые слова
        if brand.voice_keywords:
            hits = sum(1 for kw in brand.voice_keywords if kw.lower() in s)
            score += min(0.3, 0.05 * hits)

        return max(0.0, min(1.0, score))

    def _build_quality_report(
        self,
        text: str,
        constraints: ConstraintSet,
        banned_hits: List[str],
        missing_required: List[str],
        pii_restored: bool,
    ) -> QualityReport:
        length_ok = True
        wc = count_words(text)
        cc = len(text)
        if constraints.max_chars is not None and cc > constraints.max_chars:
            length_ok = False
        if constraints.max_words is not None and wc > constraints.max_words:
            length_ok = False

        penalties: List[str] = []
        if banned_hits:
            penalties.append(f"banned_terms: {', '.join(sorted(set(banned_hits)))}")
        if missing_required:
            penalties.append(f"missing_required: {', '.join(sorted(set(missing_required)))}")

        tone_score = self._tone_match_score(text, constraints.tone, BrandGuidelines())
        reg_ok = (
            (constraints.register != Register.FORMAL)
            or (" вы " not in (" " + text.lower() + " "))  # в формальном стиле ожидается «Вы» с прописной (см. адаптер)
        )

        return QualityReport(
            length_ok=length_ok,
            required_terms_covered=(len(missing_required) == 0),
            banned_terms_absent=(len(banned_hits) == 0),
            tone_match_score=tone_score,
            register_match=reg_ok,
            pii_restored=pii_restored,
            word_count=wc,
            char_count=cc,
            penalties=penalties,
        )

    def _score(self, report: QualityReport) -> float:
        """
        Интегральный скоринг кандидата.
        """
        score = 0.0
        score += 0.35 if report.length_ok else -0.5
        score += 0.25 if report.required_terms_covered else -0.6
        score += 0.15 if report.banned_terms_absent else -0.7
        score += 0.15 * report.tone_match_score
        score += 0.1 if report.register_match else -0.1
        score += 0.05 if report.pii_restored else -0.05
        score -= 0.01 * max(0, report.word_count - 200)  # лёгкая регуляризация длины
        return score

    def _select_best(self, scored: List[Tuple[str, QualityReport]]) -> Tuple[str, QualityReport]:
        if not scored:
            raise TranscreationError("no candidates produced")
        ranked = sorted(scored, key=lambda x: self._score(x[1]), reverse=True)
        best = ranked[0]
        logger.debug("Selected best score=%.4f", self._score(best[1]))
        return best


# -------------------------------
# CLI
# -------------------------------

def _cli() -> int:
    p = argparse.ArgumentParser(description="Mythos Transcreation CLI")
    p.add_argument("--from", dest="src", default="ru", help="source locale (e.g., ru, en-US)")
    p.add_argument("--to", dest="tgt", default="ru", help="target locale (e.g., ru, en-US)")
    p.add_argument("--text", dest="text", required=True, help="source text")
    p.add_argument("--max-chars", dest="max_chars", type=int, default=None)
    p.add_argument("--max-words", dest="max_words", type=int, default=None)
    p.add_argument("--tone", dest="tone", choices=[t.value for t in Tone], default="neutral")
    p.add_argument("--register", dest="register", choices=[r.value for r in Register], default="neutral")
    p.add_argument("--adapter", dest="adapter", default="rule")
    p.add_argument("--n", dest="n", type=int, default=3)
    p.add_argument("--seed", dest="seed", type=int, default=42)
    p.add_argument("--json", dest="as_json", action="store_true")
    args = p.parse_args()

    req = TranscreationRequest(
        source_text=args.text,
        source_locale=_parse_locale(args.src),
        target_locale=_parse_locale(args.tgt),
        strategy=Strategy.TRANSCREATION,
        constraints=ConstraintSet(
            max_chars=args.max_chars,
            max_words=args.max_words,
            tone=Tone(args.tone),
            register=Register(args.register),
            keep_entities=True,
        ),
        brand=BrandGuidelines(
            voice_keywords=["ясность", "польза", "безопасность"],
            preferred_spelling={"email": "email"},
        ),
        glossary=[
            GlossaryTerm(source="клиенты", target="клиенты", enforce=True),
            GlossaryTerm(source="скидка", target="скидка", enforce=True),
        ],
    )

    engine = TranscreationEngine()
    result = engine.transcreate(req, StrategyConfig(adapter_name=args.adapter, n_candidates=args.n, seed=args.seed))

    if args.as_json:
        print(json.dumps({
            "text": result.text,
            "report": {
                "length_ok": result.report.length_ok,
                "required_terms_covered": result.report.required_terms_covered,
                "banned_terms_absent": result.report.banned_terms_absent,
                "tone_match_score": result.report.tone_match_score,
                "register_match": result.report.register_match,
                "pii_restored": result.report.pii_restored,
                "word_count": result.report.word_count,
                "char_count": result.report.char_count,
                "penalties": result.report.penalties,
            },
            "debug": result.debug,
        }, ensure_ascii=False, indent=2))
    else:
        print(result.text)
        print("\n--- REPORT ---")
        for k, v in result.report.__dict__.items():
            print(f"{k}: {v}")
    return 0


def _parse_locale(s: str) -> LocaleSpec:
    parts = s.split("-", 1)
    if len(parts) == 1:
        return LocaleSpec(lang=parts[0])
    return LocaleSpec(lang=parts[0], region=parts[1])


# -------------------------------
# Пример использования из кода
# -------------------------------

def example_usage() -> None:
    engine = TranscreationEngine()
    req = TranscreationRequest(
        source_text="Здравствуйте! Пожалуйста, купите наш продукт. Свяжитесь по email: demo@example.com.",
        source_locale=LocaleSpec("ru", "RU"),
        target_locale=LocaleSpec("ru", "RU"),
        strategy=Strategy.TRANSCREATION,
        constraints=ConstraintSet(
            max_chars=160,
            tone=Tone.FRIENDLY,
            register=Register.FORMAL,
            required_terms=["продукт"],
            banned_terms=["бесплатно!!!", "срочно"],
            keep_entities=True,
        ),
        brand=BrandGuidelines(
            voice_keywords=["надёжность", "ясность"],
            do=["говорим просто", "ценим время"],
            dont=["давление на покупку"],
            taboo=["агрессия"],
            preferred_spelling={"e-mail": "email"},
        ),
        glossary=[GlossaryTerm("email", "email", enforce=True)],
        context={"platform": "push", "audience": "retail"},
    )
    result = engine.transcreate(req, StrategyConfig(adapter_name="rule", n_candidates=3, seed=123))
    print(result.text)
    print(result.report)


if __name__ == "__main__":
    # CLI entrypoint
    try:
        sys.exit(_cli())
    except KeyboardInterrupt:
        sys.exit(130)
