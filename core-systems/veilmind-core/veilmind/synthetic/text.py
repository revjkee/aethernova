# -*- coding: utf-8 -*-
"""
VeilMind Synthetic Text — промышленный генератор синтетических текстов.

Возможности:
- Детерминированная генерация (seed) с консистентными сущностями (IdentityPool).
- Шаблоны c плейсхолдерами: {name}, {email}, {phone}, {company}, {uuid},
  {date:%Y-%m-%d}, {number:1..100}, {choice:a|b|c}, {pick:key}, {word}, {words:3..7},
  {sentence}, {paragraph}.
- Компактная Markov-модель (порядок 2) из пользовательского корпуса или встроенного словаря.
- Локали en/ru (минимальные встроенные словари), расширяемые словарями пользователя.
- Инъекция шума: опечатки (QWERTY/RU), случайный регистр, дрейф пробелов, unicode confusables.
- Ограничения и валидация: пределы длины/слов, regex-валидатор, запрет терминов.
- Режимы: sentence(), paragraph(), document(), stream().
- Безопасные defaulты: никакой реальной PII, только синтетика.

Зависимости:
- Только стандартная библиотека. Если установлен `faker`, он используется для сущностей.
"""

from __future__ import annotations

import dataclasses
import json
import os
import random
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Опциональная интеграция с faker (если есть — используем; нет — не требуется)
# ---------------------------------------------------------------------------
try:
    import faker  # type: ignore
    _FAKER_AVAILABLE = True
except Exception:
    faker = None  # type: ignore
    _FAKER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Настройки шума
# ---------------------------------------------------------------------------
@dataclass
class NoiseSpec:
    """Параметры инъекции шума в текст."""
    typo_rate: float = 0.0               # вероятность опечатки на символ
    case_flip_rate: float = 0.0          # вероятность смены регистра на символ
    whitespace_jitter: float = 0.0       # вероятность вставки/удаления пробела между словами
    confusable_rate: float = 0.0         # вероятность подмены символа на визуальный аналог
    max_typos_per_text: int = 5          # максимум опечаток на текст


# ---------------------------------------------------------------------------
# Спецификация генерации
# ---------------------------------------------------------------------------
@dataclass
class TextSpec:
    """Полная спецификация генерации текста."""
    locale: str = "en"                                 # "en" или "ru"
    style: str = "lorem"                               # "lorem", "support", "review", "bug"
    target_sentences: int = 1                          # для sentence/paragraph/document
    target_paragraphs: int = 1
    min_words_per_sentence: int = 6
    max_words_per_sentence: int = 16
    corpus: Optional[str] = None                       # пользовательский корпус для Markov
    templates: Optional[List[str]] = None              # пользовательские шаблоны строк
    placeholders: Dict[str, List[str]] = field(default_factory=dict)  # {key: [values]}
    forbid_terms: List[str] = field(default_factory=list)
    enforce_regex: Optional[str] = None                # регекс, которому должен соответствовать результат (иначе трим)
    seed: Optional[int] = None
    noise: NoiseSpec = field(default_factory=NoiseSpec)
    # Ограничения итоговой строки
    max_chars: int = 800
    max_words: int = 160
    # Управление Markov-моделью
    markov_order: int = 2
    markov_weight: float = 0.5                          # доля слов, приходящих из Markov (0..1)
    # Разделители предложений
    sentence_endings: Tuple[str, ...] = (".", "!", "?")


# ---------------------------------------------------------------------------
# Пул сущностей с консистентными значениями на основе seed
# ---------------------------------------------------------------------------
class IdentityPool:
    """
    Генерирует синтетические сущности (имя, email, телефон, компания) детерминированно.
    Если faker не доступен, использует встроенные генераторы.
    """
    def __init__(self, locale: str = "en", seed: Optional[int] = None) -> None:
        self.locale = locale
        self._rnd = random.Random(seed)
        self._cache: Dict[str, Dict[str, str]] = {}
        self._fk = faker.Faker(locale) if _FAKER_AVAILABLE else None  # type: ignore

    def get(self, entity_id: str) -> Dict[str, str]:
        if entity_id in self._cache:
            return self._cache[entity_id]
        data = {
            "name": self._gen_name(),
            "email": self._gen_email(),
            "phone": self._gen_phone(),
            "company": self._gen_company(),
        }
        self._cache[entity_id] = data
        return data

    def _gen_name(self) -> str:
        if self._fk:
            try:
                return self._fk.name()
            except Exception:
                pass
        if self.locale.startswith("ru"):
            first = self._rnd.choice(["Алексей", "Мария", "Иван", "Ольга", "Дмитрий", "Екатерина"])
            last = self._rnd.choice(["Иванов", "Смирнова", "Кузнецов", "Попова", "Соколов", "Петрова"])
            return f"{first} {last}"
        first = self._rnd.choice(["Alex", "Maria", "John", "Olivia", "Daniel", "Kate"])
        last = self._rnd.choice(["Smith", "Johnson", "Brown", "Williams", "Davis", "Miller"])
        return f"{first} {last}"

    def _gen_company(self) -> str:
        if self._fk:
            try:
                return self._fk.company()
            except Exception:
                pass
        root = self._rnd.choice(["VeilMind", "NovaCore", "SkyLabs", "DataForge", "CloudWay"])
        suffix = self._rnd.choice(["LLC", "Inc.", "Ltd.", "GmbH", "AB"])
        return f"{root} {suffix}"

    def _gen_email(self) -> str:
        if self._fk:
            try:
                return self._fk.email()
            except Exception:
                pass
        user = "".join(self._rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8))
        domain = self._rnd.choice(["example.com", "test.local", "synthetic.io"])
        return f"{user}@{domain}"

    def _gen_phone(self) -> str:
        if self._fk:
            try:
                return self._fk.phone_number()
            except Exception:
                pass
        if self.locale.startswith("ru"):
            return f"+7{self._rnd.randint(900, 999)}{self._rnd.randint(1000000, 9999999)}"
        return f"+1{self._rnd.randint(200, 999)}{self._rnd.randint(1000000, 9999999)}"


# ---------------------------------------------------------------------------
# Словари по умолчанию (минимальные безопасные токены)
# ---------------------------------------------------------------------------
_WORDS_EN = (
    "system service request data core module network client server monitor state api cache"
    " queue worker storage task security policy token access version deploy metrics log"
    " latency throughput failure success change update release snapshot job pipeline"
).split()

_WORDS_RU = (
    "система сервис запрос данные ядро модуль сеть клиент сервер мониторинг состояние api кэш"
    " очередь воркер хранилище задача безопасность политика токен доступ версия релиз метрики лог"
    " задержка пропускная способность отказ успех изменение обновление снапшот задание конвейер"
).split()

_TEMPLATES_EN = [
    "User {name} from {company} reports an issue: {sentence}",
    "Request {uuid} processed with status {choice:ok|warning|error} in {number:5..500} ms",
    "Contact {name} at {email} or {phone} regarding {sentence}",
    "Release note: {sentence} {sentence}",
    "Support ticket: {paragraph}",
]

_TEMPLATES_RU = [
    "Пользователь {name} из {company} сообщил о проблеме: {sentence}",
    "Запрос {uuid} обработан со статусом {choice:ok|warning|error} за {number:5..500} мс",
    "Контакт {name}: {email} или {phone} по вопросу: {sentence}",
    "Заметка релиза: {sentence} {sentence}",
    "Тикет поддержки: {paragraph}",
]


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def _wchoice(rnd: random.Random, items: Sequence[Tuple[Any, float]]) -> Any:
    total = sum(max(0.0, w) for _, w in items) or 1.0
    x = rnd.random() * total
    acc = 0.0
    for v, w in items:
        acc += max(0.0, w)
        if x <= acc:
            return v
    return items[-1][0]


def _tokenize(text: str) -> List[str]:
    return [t for t in re.split(r"\s+", text.strip()) if t]


# ---------------------------------------------------------------------------
# Markov-модель (n=2 по умолчанию)
# ---------------------------------------------------------------------------
class Markov2:
    """Простая Markov-модель второго порядка для генерации предложений."""
    def __init__(self, rnd: random.Random) -> None:
        self.rnd = rnd
        self.table: Dict[Tuple[str, str], List[str]] = {}

    def train(self, corpus: str) -> None:
        tokens = _tokenize(re.sub(r"[^\w\s\-]+", " ", corpus))
        if len(tokens) < 3:
            return
        for a, b, c in zip(tokens, tokens[1:], tokens[2:]):
            self.table.setdefault((a.lower(), b.lower()), []).append(c)

    def next_word(self, a: str, b: str) -> Optional[str]:
        choices = self.table.get((a.lower(), b.lower()))
        if not choices:
            return None
        return self.rnd.choice(choices)


# ---------------------------------------------------------------------------
# Инъекция шума
# ---------------------------------------------------------------------------
# Наборы клавиатурных соседей для en/ru (минимально необходимое покрытие)
_NEIGH_EN = {
    "q": "was", "w": "qes", "e": "wrd", "r": "etf", "t": "rfy", "y": "tug", "u": "yih", "i": "uoj", "o": "ipk", "p": "ol",
    "a": "qsz", "s": "adwx", "d": "sfec", "f": "drtg", "g": "ftyh", "h": "gyuj", "j": "huik", "k": "jiol", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk"
}
_NEIGH_RU = {
    "й": "цы", "ц": "йуы", "у": "цк", "к": "уве", "е": "кнр", "н": "егт", "г": "нш", "ш": "гщ", "щ": "шз", "з": "щх",
    "ф": "ы", "ы": "фв", "в": "ыа", "а": "вп", "п": "ар", "р": "пш", "о": "л", "л": "о", "д": "жэ", "ж": "дэ"
}
_CONFUSABLES = {
    "A": "Α", "B": "Β", "E": "Ε", "H": "Η", "K": "Κ", "M": "Μ", "O": "Ο", "P": "Ρ", "T": "Τ", "X": "Χ",
    "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х"
}

def _inject_noise(rnd: random.Random, text: str, ns: NoiseSpec, locale: str) -> str:
    if (ns.typo_rate <= 0 and ns.case_flip_rate <= 0 and ns.whitespace_jitter <= 0 and ns.confusable_rate <= 0):
        return text

    chars = list(text)
    typo_budget = ns.max_typos_per_text
    for i, ch in enumerate(chars):
        # confusable
        if ns.confusable_rate > 0 and ch in _CONFUSABLES and rnd.random() < ns.confusable_rate:
            chars[i] = _CONFUSABLES[ch]
            continue
        # case flip
        if ns.case_flip_rate > 0 and ch.isalpha() and rnd.random() < ns.case_flip_rate:
            chars[i] = ch.upper() if ch.islower() else ch.lower()
            continue
        # typos
        if typo_budget > 0 and ns.typo_rate > 0 and rnd.random() < ns.typo_rate and ch.isalpha():
            neigh = _NEIGH_RU if locale.startswith("ru") else _NEIGH_EN
            c = ch.lower()
            repl = rnd.choice(neigh.get(c, c) or c)
            chars[i] = repl.upper() if ch.isupper() else repl
            typo_budget -= 1

    noisy = "".join(chars)
    if ns.whitespace_jitter > 0:
        noisy = re.sub(r"\s+", " ", noisy).strip()
        tokens = noisy.split(" ")
        out = []
        for t in tokens:
            out.append(t)
            if rnd.random() < ns.whitespace_jitter:
                # вставить лишний пробел или удалить
                if rnd.random() < 0.5 and out:
                    out.append("")  # двойной пробел
                # иначе просто пропустим вставку
        noisy = " ".join(out)
    return noisy


# ---------------------------------------------------------------------------
# Шаблонный движок
# ---------------------------------------------------------------------------
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(?::([^}]+))?\}")

class TemplateEngine:
    def __init__(self, rnd: random.Random, idp: IdentityPool, spec: TextSpec) -> None:
        self.rnd = rnd
        self.idp = idp
        self.spec = spec

    def render(self, tpl: str, context: Optional[Dict[str, Any]] = None) -> str:
        ctx = dict(context or {})

        def repl(m: re.Match) -> str:
            key = m.group(1)
            arg = m.group(2)
            return self._expand(key, arg, ctx)

        return _PLACEHOLDER_RE.sub(repl, tpl)

    def _expand(self, key: str, arg: Optional[str], ctx: Dict[str, Any]) -> str:
        if key == "name":
            return self.idp.get(ctx.get("entity_id", "default"))["name"]
        if key == "email":
            return self.idp.get(ctx.get("entity_id", "default"))["email"]
        if key == "phone":
            return self.idp.get(ctx.get("entity_id", "default"))["phone"]
        if key == "company":
            return self.idp.get(ctx.get("entity_id", "default"))["company"]
        if key == "uuid":
            return str(uuid.uuid4())
        if key == "date":
            fmt = arg or "%Y-%m-%d"
            return datetime.now(timezone.utc).strftime(fmt)
        if key == "number":
            # формат "a..b"
            if arg and ".." in arg:
                a, b = arg.split("..", 1)
                try:
                    return str(self.rnd.randint(int(a), int(b)))
                except Exception:
                    pass
            return str(self.rnd.randint(0, 100))
        if key == "choice":
            # "a|b|c"
            if arg:
                opts = [s.strip() for s in arg.split("|")]
                return self.rnd.choice([o for o in opts if o != ""])
            return ""
        if key == "pick":
            # взять из пользовательского словаря placeholders по ключу
            if arg and arg in self.spec.placeholders and self.spec.placeholders[arg]:
                return self.rnd.choice(self.spec.placeholders[arg])
            return ""
        if key == "word":
            return self._word()
        if key == "words":
            # "3..7"
            n = 3
            if arg and ".." in arg:
                a, b = arg.split("..", 1)
                try:
                    n = self.rnd.randint(int(a), int(b))
                except Exception:
                    n = 3
            return " ".join(self._word() for _ in range(n))
        if key == "sentence":
            return self._sentence()
        if key == "paragraph":
            return self._paragraph()
        return ""

    def _words_base(self) -> Sequence[str]:
        if self.spec.locale.startswith("ru"):
            return _WORDS_RU
        return _WORDS_EN

    def _word(self) -> str:
        base = self._words_base()
        return self.rnd.choice(base)

    def _sentence(self) -> str:
        n_min = max(2, self.spec.min_words_per_sentence)
        n_max = max(n_min, self.spec.max_words_per_sentence)
        n = self.rnd.randint(n_min, n_max)

        # Смешиваем слова из Markov и базовый словарь
        words: List[str] = []
        if hasattr(self, "_mk"):
            mk: Markov2 = getattr(self, "_mk")
        else:
            mk = Markov2(self.rnd)
            corpus = self.spec.corpus or " ".join(self._words_base() * 8)
            mk.train(corpus)
            setattr(self, "_mk", mk)

        base = self._words_base()
        if len(base) == 0:
            base = ["text"]

        # стартовые два слова
        a = self.rnd.choice(base)
        b = self.rnd.choice(base)
        words.extend([a, b])

        for _ in range(n - 2):
            use_markov = self.rnd.random() < self.spec.markov_weight
            nxt = mk.next_word(a, b) if use_markov else None
            if not nxt:
                nxt = self.rnd.choice(base)
            words.append(nxt)
            a, b = b, nxt

        # Капитализация и пунктуация
        sent = " ".join(words)
        sent = sent[:1].upper() + sent[1:]
        ending = self.rnd.choice(self.spec.sentence_endings)
        return f"{sent}{ending}"

    def _paragraph(self) -> str:
        sents = [self._sentence() for _ in range(self.spec.target_sentences)]
        return " ".join(sents)


# ---------------------------------------------------------------------------
# Главный движок
# ---------------------------------------------------------------------------
class TextSynthEngine:
    """Высокоуровневый генератор синтетических текстов."""
    def __init__(self, spec: TextSpec) -> None:
        self.spec = spec
        self.rnd = random.Random(spec.seed)
        self.idp = IdentityPool(locale=spec.locale, seed=spec.seed)
        self.tpl = TemplateEngine(self.rnd, self.idp, spec)

        if not self.spec.templates:
            self.spec.templates = list(_TEMPLATES_RU if self.spec.locale.startswith("ru") else _TEMPLATES_EN)

    # -------- Публичные методы --------
    def sentence(self, entity_id: str = "default") -> str:
        return self._finalize(self._generate_sentence(entity_id))

    def paragraph(self, entity_id: str = "default") -> str:
        sentences = [self._generate_sentence(entity_id) for _ in range(self.spec.target_sentences)]
        text = " ".join(sentences)
        return self._finalize(text)

    def document(self, entity_id: str = "default") -> str:
        paragraphs = [self.paragraph(entity_id) for _ in range(self.spec.target_paragraphs)]
        return "\n\n".join(paragraphs)

    def stream(self, count: int = 10, entity_id: str = "default") -> Generator[str, None, None]:
        """Генерирует последовательность предложений."""
        for _ in range(max(0, count)):
            yield self.sentence(entity_id)

    # -------- Внутреннее --------
    def _generate_sentence(self, entity_id: str) -> str:
        # С вероятностью 0.5 используем шаблон, иначе чистую Markov-фразу
        if self.rnd.random() < 0.5 and self.spec.templates:
            tpl = self.rnd.choice(self.spec.templates)
            return self.tpl.render(tpl, {"entity_id": entity_id})
        return self.tpl._sentence()

    def _finalize(self, text: str) -> str:
        # Ограничить слова
        words = _tokenize(text)
        if len(words) > self.spec.max_words:
            words = words[: self.spec.max_words]
            text = " ".join(words)
            if not text.endswith(tuple(self.spec.sentence_endings)):
                text += "."
        # Ограничить символы
        if len(text) > self.spec.max_chars:
            text = text[: self.spec.max_chars].rstrip()
        # Запрет терминов: если встречаются, заменяем на безопасные токены
        for bad in self.spec.forbid_terms:
            if not bad:
                continue
            safe = "[REDACTED]"
            try:
                text = re.sub(re.escape(bad), safe, text, flags=re.IGNORECASE)
            except re.error:
                # если плохой паттерн — игнорируем
                pass
        # Регекс-валидатор: если не проходит — пытаемся слегка упростить/обрезать
        if self.spec.enforce_regex:
            try:
                pat = re.compile(self.spec.enforce_regex)
                if not pat.search(text):
                    # Попробуем взять одну Markov-фразу
                    alt = self.tpl._sentence()
                    if pat.search(alt):
                        text = alt
            except re.error:
                # неверный регекс — пропускаем
                pass
        # Инъекция шума
        text = _inject_noise(self.rnd, text, self.spec.noise, self.spec.locale)
        return text


# ---------------------------------------------------------------------------
# Утилитарные функции верхнего уровня
# ---------------------------------------------------------------------------
def generate_sentence(spec: TextSpec, entity_id: str = "default") -> str:
    return TextSynthEngine(spec).sentence(entity_id)

def generate_paragraph(spec: TextSpec, entity_id: str = "default") -> str:
    return TextSynthEngine(spec).paragraph(entity_id)

def generate_document(spec: TextSpec, entity_id: str = "default") -> str:
    return TextSynthEngine(spec).document(entity_id)

def generate_batch(spec: TextSpec, count: int = 10, entity_id: str = "default") -> List[str]:
    eng = TextSynthEngine(spec)
    return [eng.sentence(entity_id) for _ in range(max(0, count))]


# ---------------------------------------------------------------------------
# Пример использования
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Демонстрация: детерминированность и локали
    spec_en = TextSpec(locale="en", style="support", target_sentences=2, seed=42,
                       noise=NoiseSpec(typo_rate=0.02, case_flip_rate=0.01, whitespace_jitter=0.02, confusable_rate=0.0),
                       placeholders={"product": ["Core", "Gateway", "Agent"]})
    print("EN paragraph:")
    print(generate_paragraph(spec_en))

    spec_ru = TextSpec(locale="ru", style="support", target_sentences=2, seed=42)
    print("\nRU sentence:")
    print(generate_sentence(spec_ru))
