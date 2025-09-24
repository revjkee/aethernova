from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable, Iterator, List, Literal, Optional, Sequence, Tuple

# Опционально: тоньше парсинг дат и детект языка
try:  # pragma: no cover
    from dateutil import parser as dateutil_parser
except Exception:  # pragma: no cover
    dateutil_parser = None

try:  # pragma: no cover
    from langdetect import detect as _langdetect
except Exception:  # pragma: no cover
    _langdetect = None

# ============================================================================
# МОДЕЛИ
# ============================================================================

@dataclass(frozen=True)
class Span:
    start: int
    end: int

    def slice(self, text: str) -> str:
        return text[self.start:self.end]

@dataclass(frozen=True)
class Sentence:
    span: Span
    text: str

@dataclass(frozen=True)
class Token:
    span: Span
    text: str
    kind: Literal["word", "number", "punct", "space", "symbol", "url", "email", "hashtag", "mention"]

@dataclass(frozen=True)
class Entity:
    span: Span
    text: str
    label: Literal["URL", "EMAIL", "MONEY", "PERCENT", "PHONE", "DATE"]

# ============================================================================
# НОРМАЛИЗАЦИЯ
# ============================================================================

_DEFAULT_QUOTE_MAP = {
    "\u2018": "'", "\u2019": "'", "\u201B": "'", "\u2032": "'",
    "\u201C": '"', "\u201D": '"', "\u2033": '"',
}
_DEFAULT_DASH_MAP = {
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
    "\u2212": "-",  # minus
}

_CONTROL_CHARS_RE = re.compile(r"[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]")
_MULTISPACE_RE = re.compile(r"[ \t\u00A0\u1680\u180E\u2000-\u200B\u202F\u205F\u3000]+")

def normalize_text(
    text: str,
    *,
    nf: Literal["NFC", "NFKC"] = "NFKC",
    keep_linebreaks: bool = True,
    collapse_spaces: bool = True,
    strip: bool = True,
    replace_quotes: bool = True,
    replace_dashes: bool = True,
    unescape_html: bool = True,
    remove_controls: bool = True,
) -> str:
    """
    Универсальная нормализация:
    - Unicode NFKC/NFC
    - замена «фигурных» кавычек и длинных тире
    - удаление управляющих символов
    - HTML unescape
    - схлопывание пробелов
    """
    s = text or ""
    if unescape_html:
        s = html.unescape(s)
    # normalize unicode
    s = unicodedata.normalize(nf, s)
    # quotes/dashes
    if replace_quotes:
        for k, v in _DEFAULT_QUOTE_MAP.items():
            s = s.replace(k, v)
    if replace_dashes:
        for k, v in _DEFAULT_DASH_MAP.items():
            s = s.replace(k, v)
    # remove control chars
    if remove_controls:
        s = _CONTROL_CHARS_RE.sub("", s)
    # normalize spaces
    if collapse_spaces:
        s = _MULTISPACE_RE.sub(" ", s)
    if not keep_linebreaks:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = re.sub(r"[ \t]*\n[ \t]*", "\n", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
    if strip:
        s = s.strip()
    return s

def safe_casefold(s: str) -> str:
    """Нормализованное casefold для языконезависимого сравнения."""
    return unicodedata.normalize("NFKC", s).casefold()

# ============================================================================
# РАЗБИЕНИЕ НА АБЗАЦЫ/ПРЕДЛОЖЕНИЯ
# ============================================================================

# Частые аббревиатуры (рус/англ), которые не должны завершать предложение
_ABBR = {
    "англ.", "им.", "ул.", "пер.", "стр.", "т.д.", "т.п.", "т.е.", "т.к.", "т.н.", "т.ч.", "рис.", "см.",
    "г.", "д.", "кв.", "к.", "с.", "стр.", "пр.", "акад.",
    "mr.", "mrs.", "ms.", "dr.", "prof.", "sr.", "jr.", "vs.", "etc.", "e.g.", "i.e.", "fig.", "no.", "pp.", "vol."
}
_ABBR = {safe_casefold(x) for x in _ABBR}

_SENT_BOUNDARY_RE = re.compile(
    r"""
    (?P<pat>
        [.!?]+            # терминальные знаки
        (?:["')\]]+)?     # закрывающие кавычки/скобки после них
        (?:\s+|$)         # пробел или конец строки
    )
    """,
    re.VERBOSE,
)

def split_paragraphs(text: str) -> List[Span]:
    """Абзацы — непустые блоки, разделённые >= 1 пустой строкой."""
    spans: List[Span] = []
    idx = 0
    for m in re.finditer(r"(?:[^\S\r\n]*\n){2,}", text):  # два и более переводов строки (с пробелами)
        end = m.start()
        if end > idx:
            # trim пробелы/переводы по краям спана, сохраняя offsets
            start = _skip_ws_left(text, idx, end)
            end2 = _skip_ws_right(text, idx, end)
            if end2 > start:
                spans.append(Span(start, end2))
        idx = m.end()
    # остаток
    if idx < len(text):
        start = _skip_ws_left(text, idx, len(text))
        end = _skip_ws_right(text, idx, len(text))
        if end > start:
            spans.append(Span(start, end))
    return spans

def _skip_ws_left(s: str, a: int, b: int) -> int:
    i = a
    while i < b and s[i] in " \t":
        i += 1
    return i

def _skip_ws_right(s: str, a: int, b: int) -> int:
    j = b
    while j > a and s[j-1] in " \t":
        j -= 1
    return j

def split_sentences(text: str, *, paragraph_aware: bool = True) -> List[Sentence]:
    """
    Правило-ориентированное разбиение на предложения.
    Учитывает аббревиатуры и лапки/скобки, сохраняет смещения.
    """
    sentences: List[Sentence] = []
    para_spans = split_paragraphs(text) if paragraph_aware else [Span(0, len(text))]

    for pspan in para_spans:
        ptxt = text[pspan.start:pspan.end]
        if not ptxt.strip():
            continue
        start = pspan.start
        last = start
        for m in _SENT_BOUNDARY_RE.finditer(text, pspan.start, pspan.end):
            end = m.end()
            cand = text[last:end]
            if _looks_like_abbrev_end(cand):
                continue
            seg = cand.strip()
            if seg:
                # точная подрезка пробелов с сохранением оффсетов
                a = _skip_ws_left(text, last, end)
                b = _skip_ws_right(text, last, end)
                sentences.append(Sentence(Span(a, b), text[a:b]))
            last = end
        if last < pspan.end:
            a = _skip_ws_left(text, last, pspan.end)
            b = _skip_ws_right(text, last, pspan.end)
            if b > a:
                sentences.append(Sentence(Span(a, b), text[a:b]))
    return sentences

def _looks_like_abbrev_end(segment: str) -> bool:
    """
    Возвращает True, если конец segment похож на аббревиатуру вида "рис.", "т.д.", "Dr." и т.п.
    """
    seg = segment.rstrip()
    # Найдём последнее слово с точкой
    m = re.search(r"(\b[\w\p{L}]{1,10}\.)\s*$", seg, flags=re.UNICODE)
    if not m:
        return False
    token = safe_casefold(m.group(1))
    return token in _ABBR

# ============================================================================
# ТОКЕНИЗАЦИЯ
# ============================================================================

_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [\w\-]+(\.[\w\-]+)+
    (?::\d{2,5})?
    (?:/[^\s<>"'`)]*)?
    """
)
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
_HASHTAG_RE = re.compile(r"(?i)(?<!\w)#([a-z0-9_]{1,64})")
_MENTION_RE = re.compile(r"(?i)(?<!\w)@([a-z0-9_]{1,64})")
_NUMBER_RE = re.compile(r"(?x)(?<!\w)(?:[\+\-]?\d{1,3}(?:[\s,\u00A0]\d{3})+|\d+)(?:[.,]\d+)?(?!\w)")
_WORD_RE = re.compile(r"(?u)\b\w+\b")

def tokenize(text: str) -> List[Token]:
    """
    Лёгкая, но промышленная токенизация с сохранением смещений:
      - URL, email, hashtag, mention выделяются первыми
      - числа (включая разделители тысяч и дробные части)
      - слова по \b\w+\b
      - знаки пунктуации и пробелы как отдельные токены
    """
    taken = [False] * len(text)
    tokens: List[Token] = []

    def mark_span(a: int, b: int) -> bool:
        if a < 0 or b > len(text) or a >= b:
            return False
        if any(taken[a:b]):
            return False
        for i in range(a, b):
            taken[i] = True
        return True

    def add_tokens_by_regex(regex: re.Pattern, kind: Token["kind"]):
        for m in regex.finditer(text):
            a, b = m.start(), m.end()
            if mark_span(a, b):
                tokens.append(Token(Span(a, b), text[a:b], kind))

    # 1) приоритетные классы
    add_tokens_by_regex(_URL_RE, "url")
    add_tokens_by_regex(_EMAIL_RE, "email")
    add_tokens_by_regex(_HASHTAG_RE, "hashtag")
    add_tokens_by_regex(_MENTION_RE, "mention")
    add_tokens_by_regex(_NUMBER_RE, "number")

    # 2) слова
    add_tokens_by_regex(_WORD_RE, "word")

    # 3) оставшееся — пунктуация/пробелы/символы
    i = 0
    while i < len(text):
        if taken[i]:
            i += 1
            continue
        j = i + 1
        ch = text[i]
        if ch.isspace():
            while j < len(text) and (not taken[j]) and text[j].isspace():
                j += 1
            kind = "space"
        elif re.match(r"\p{P}|\p{S}", ch, flags=re.UNICODE):
            # знаки пунктуации/символы — по одному
            kind = "punct" if re.match(r"\p{P}", ch, flags=re.UNICODE) else "symbol"
        else:
            # одиночный символ
            kind = "symbol"
        if mark_span(i, j):
            tokens.append(Token(Span(i, j), text[i:j], kind))
        i = j

    tokens.sort(key=lambda t: (t.span.start, t.span.end))
    return tokens

# ============================================================================
# ШАБЛОННЫЕ СУЩНОСТИ (rule-based)
# ============================================================================

_MONEY_RE = re.compile(
    r"""(?xi)
    (?P<sign>[-+])?
    (?P<amount>(?:\d{1,3}(?:[ ,\u00A0]\d{3})+|\d+)(?:[.,]\d+)?)
    [\s\u00A0]?
    (?P<currency>
        (?:(?:USD|EUR|RUB|RUR|GBP|JPY|CNY|KZT|UAH|BYN|CAD|AUD)\b)|
        (?:\$|€|₽|£|¥|₸|₴|Br)
    )
    """
)
_PERCENT_RE = re.compile(r"(?i)\b([+-]?(?:\d+(?:[.,]\d+)?))\s?%")
_PHONE_RE = re.compile(
    r"""(?x)
    (?:
      (?:\+?\d{1,3}[\s\-]?)?            # страна
      (?:\(?\d{3}\)?[\s\-]?)            # код
      (?:\d{3}[\s\-]?\d{2}[\s\-]?\d{2}) # номер
    )
    """
)
# даты: грубо YYYY-MM-DD, DD.MM.YYYY, DD/MM/YYYY, ISO-варианты
_DATE_RE = re.compile(
    r"""(?x)
    \b(
      \d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:Z|[+\-]\d{2}:\d{2})? |
      \d{4}-\d{2}-\d{2} |
      \d{2}[./]\d{2}[./]\d{4}
    )\b
    """
)

def detect_entities(text: str) -> List[Entity]:
    ents: List[Entity] = []
    def _collect(regex: re.Pattern, label: Entity["label"]):
        for m in regex.finditer(text):
            ents.append(Entity(Span(m.start(), m.end()), text[m.start():m.end()], label))
    _collect(_URL_RE, "URL")
    _collect(_EMAIL_RE, "EMAIL")
    _collect(_MONEY_RE, "MONEY")
    _collect(_PERCENT_RE, "PERCENT")
    _collect(_PHONE_RE, "PHONE")
    _collect(_DATE_RE, "DATE")
    ents.sort(key=lambda e: (e.span.start, e.span.end))
    return _dedup_overlaps(ents)

def _dedup_overlaps(ents: List[Entity]) -> List[Entity]:
    out: List[Entity] = []
    last_end = -1
    for e in ents:
        if e.span.start < last_end:
            # Перекрытие — оставляем более длинную сущность (обычно URL/email длиннее)
            if out and (e.span.end - e.span.start) > (out[-1].span.end - out[-1].span.start):
                out[-1] = e
                last_end = e.span.end
            continue
        out.append(e)
        last_end = e.span.end
    return out

# ============================================================================
# ПАРСИНГ ЧИСЕЛ И ДАТ
# ============================================================================

def parse_number(text: str, *, decimal_sep: str = ",", thousand_sep: str = "\u00A0") -> Optional[Decimal]:
    """
    Безопасный парсинг числа:
      - удаляет неразрывные/обычные пробелы и указанный разделитель тысяч
      - принимает как ',' так и '.' в качестве десятичного разделителя (можно переопределить)
    """
    s = text.strip()
    s = s.replace(" ", "").replace("\u00A0", "")
    if decimal_sep == "," and s.count(",") == 1 and s.count(".") == 0:
        s = s.replace(",", ".")
    try:
        return Decimal(s)
    except InvalidOperation:
        return None

def parse_money(text: str) -> Optional[Tuple[Decimal, str]]:
    m = _MONEY_RE.search(text)
    if not m:
        return None
    amount = parse_number(m.group("amount"))
    if amount is None:
        return None
    if m.group("sign") == "-":
        amount = -amount
    cur = m.group("currency").upper()
    # символы → код
    sym_map = {"$": "USD", "€": "EUR", "₽": "RUB", "£": "GBP", "¥": "JPY", "₸": "KZT", "₴": "UAH", "BR": "BYN"}
    cur = sym_map.get(cur, cur)
    return amount, cur

def parse_date(text: str, *, day_first: bool = True, assume_utc: bool = True) -> Optional[datetime]:
    """
    Парсит дату из строки. Если установлен python-dateutil — используется он.
    Иначе — примитивные форматы ISO и DD.MM.YYYY.
    """
    s = text.strip()
    if dateutil_parser is not None:  # pragma: no cover
        try:
            dt = dateutil_parser.parse(s, dayfirst=day_first)
            if assume_utc and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    # Fallback: ISO 8601 и DD.MM.YYYY / DD/MM/YYYY
    m = _DATE_RE.search(s)
    if not m:
        return None
    frag = m.group(1)
    try:
        if re.match(r"^\d{4}-\d{2}-\d{2}T", frag):
            # упрощённый ISO
            return datetime.fromisoformat(frag.replace("Z", "+00:00"))
        if re.match(r"^\d{4}-\d{2}-\d{2}$", frag):
            return datetime.fromisoformat(f"{frag}T00:00:00+00:00")
        if re.match(r"^\d{2}[./]\d{2}[./]\d{4}$", frag):
            dd, mm, yy = re.split(r"[./]", frag)
            return datetime(int(yy), int(mm), int(dd), tzinfo=timezone.utc)
    except Exception:
        return None
    return None

def detect_language(text: str) -> Optional[str]:
    """
    Определяет язык (двухбуквенный код ISO 639-1), если установлен langdetect.
    Возвращает None при недоступности/неуверенности.
    """
    if _langdetect is None:  # pragma: no cover
        return None
    try:
        return _langdetect(text)
    except Exception:
        return None

# ============================================================================
# ЧАНКИНГ ПОД RAG
# ============================================================================

def rag_chunks(
    text: str,
    *,
    target_chars: int = 900,
    max_chars: int = 1200,
    overlap_chars: int = 120,
    respect_sentences: bool = True,
) -> List[Span]:
    """
    «Умный» чанкер:
      - строит абзацы → предложения (опционально)
      - собирает чанки около target_chars, но не превышая max_chars
      - добавляет overlap меж чанками для контекста
    Возвращает список Span с точными смещениями оригинального текста.
    """
    if not text.strip():
        return []
    # базовые блоки
    blocks: List[Span] = []
    if respect_sentences:
        for par in split_paragraphs(text):
            sents = split_sentences(text[par.start:par.end], paragraph_aware=False)
            # смещаем в глобальные координаты
            for s in sents:
                blocks.append(Span(par.start + s.span.start, par.start + s.span.end))
    else:
        for par in split_paragraphs(text):
            blocks.append(par)

    chunks: List[Span] = []
    if not blocks:
        return chunks

    cur_a = blocks[0].start
    cur_b = blocks[0].end
    for sp in blocks[1:]:
        block_len = sp.end - sp.start
        cur_len = cur_b - cur_a
        if cur_len + 1 + block_len <= max_chars:
            # расширяем текущий чанк
            cur_b = sp.end
        else:
            # завершаем чанк с overlap
            a = cur_a
            b = cur_b
            chunks.append(Span(a, b))
            # новый чанк: перекрытие
            a2 = max(a, b - overlap_chars)
            cur_a, cur_b = a2, sp.end
    chunks.append(Span(cur_a, cur_b))
    # Подрезаем слишком короткие хвосты, если можно сливать безопасно
    merged: List[Span] = []
    for sp in chunks:
        if merged and (sp.end - sp.start) < (target_chars // 3):
            prev = merged[-1]
            if (sp.end - prev.start) <= max_chars:
                merged[-1] = Span(prev.start, sp.end)
                continue
        merged.append(sp)
    return merged

# ============================================================================
# ПУБЛИЧНЫЙ API (вспомогательные пайплайны)
# ============================================================================

def normalize_and_segment(text: str) -> List[Sentence]:
    """
    Быстрый пайплайн: нормализация + разбиение на предложения.
    """
    norm = normalize_text(text)
    return split_sentences(norm)

def tokens_and_entities(text: str) -> Tuple[List[Token], List[Entity]]:
    """
    Токенизация + rule-based сущности в одном вызове.
    """
    toks = tokenize(text)
    ents = detect_entities(text)
    return toks, ents

# ============================================================================
# КОНСТАНТЫ И ЭКСПОРТ
# ============================================================================

__all__ = [
    "Span", "Sentence", "Token", "Entity",
    "normalize_text", "safe_casefold",
    "split_paragraphs", "split_sentences",
    "tokenize", "detect_entities",
    "parse_number", "parse_money", "parse_date", "detect_language",
    "rag_chunks",
    "normalize_and_segment", "tokens_and_entities",
]
