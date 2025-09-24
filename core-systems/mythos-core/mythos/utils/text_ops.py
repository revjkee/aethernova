# mythos-core/mythos/utils/text_ops.py
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets
import textwrap
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

# Опциональные ускорители/улучшатели
try:  # расширенный Unicode и графемы через \X
    import regex as re2  # type: ignore
except Exception:  # pragma: no cover
    re2 = None

try:  # быстрая дистанция Левенштейна
    import Levenshtein as _lev  # type: ignore
except Exception:  # pragma: no cover
    _lev = None


# ======================================================================================
# Константы и предкомпилированные шаблоны
# ======================================================================================

# Невидимые/служебные символы (некоторые ZW*, управляющие, Bidi-метки, вариационные селекторы)
_INVISIBLE_CODEPOINTS = {
    "\u200B",  # ZERO WIDTH SPACE
    "\u200C",  # ZERO WIDTH NON-JOINER
    "\u200D",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\uFEFF",  # BOM / ZERO WIDTH NO-BREAK SPACE
}
# Диапазоны bidi/контрольных отметок
_BIDI_RANGES = [
    (0x202A, 0x202E),  # LRE..RLE..PDF.. etc.
    (0x2066, 0x2069),  # LRI..PDI
]
_VARIATION_SELECTORS = [(0xFE00, 0xFE0F), (0xE0100, 0xE01EF)]

# Простые классы символов (fallback на re; при наличии regex используем \p{...})
_WORD_RE = re2.compile(r"\b\p{L}[\p{L}\p{N}_’'-]*\b", re2.UNICODE) if re2 else re.compile(r"\b\w+\b", re.UNICODE)
_SENT_SPLIT_RE = (
    re2.compile(r"(?<=\S[.!?])\s+(?=[“\"(\[]*[A-ZА-ЯЁ0-9])", re2.UNICODE)
    if re2
    else re.compile(r"(?<=\S[.!?])\s+(?=[\"(\[]*[A-ZА-ЯЁ0-9])", re.UNICODE)
)

_NON_ALNUM_RE = re2.compile(r"[^\p{L}\p{N}]+", re2.UNICODE) if re2 else re.compile(r"[^A-Za-z0-9]+", re.UNICODE)
_MULTIHYPHEN_RE = re.compile(r"-{2,}")
_LEADING_TRAILING_HYPHEN_RE = re.compile(r"(^-+)|(-+$)")

# PII / секреты (редакция)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b", re.IGNORECASE)
# Международный телефон: +CCC NNN... (простая эвристика)
_PHONE_RE = re.compile(r"\b(?:\+|00)\d{6,15}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}\b", re.IGNORECASE)
# Примитивный JWT: header.payload.signature (base64url)
_JWT_RE = re.compile(r"\beyJ[0-9A-Za-z_\-]+=*\.[0-9A-Za-z_\-]+=*\.[0-9A-Za-z_\-]+=*\b")
# AWS Access Key ID: AKIA.. или ASIA..
_AWS_KEY_RE = re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b")
# Карта (с промежутками/дефисами) — проверим Луна затем
_CC_CAND_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Графемы (если есть regex)
_GRAPHEME_RE = re2.compile(r"\X", re2.UNICODE) if re2 else None

# Типичные аббревиатуры для безопасного split предложений
_ABBREVIATIONS = {
    "e.g.", "i.e.", "mr.", "mrs.", "ms.", "dr.", "prof.", "inc.", "ltd.", "jr.", "sr.",
    "т.е.", "т.к.", "др.", "г.", "ул.", "пр.", "рис.", "илл.", "см.", "стр.",
}


# ======================================================================================
# Нормализация и базовые операции
# ======================================================================================

@dataclass(frozen=True)
class NormalizeConfig:
    """
    Конфигурация нормализации текста.
    """
    nfkc: bool = True
    strip: bool = True
    collapse_ws: bool = True
    lowercase: bool = False
    remove_invisible: bool = True
    remove_control: bool = True
    remove_bidi_marks: bool = True
    transliterate: bool = False  # только для slugify по умолчанию
    keep_newlines: bool = True


_DEFAULT_NORM = NormalizeConfig()


def normalize(text: str, cfg: NormalizeConfig = _DEFAULT_NORM) -> str:
    """
    Универсальная нормализация: NFKC, удаление невидимых/управляющих, свёртка пробелов, регистр.

    >>> normalize("ＡＢC  \\u200B  test")
    'ABC test'
    """
    if text is None:
        return ""

    s = text
    if cfg.nfkc:
        s = unicodedata.normalize("NFKC", s)

    if cfg.remove_invisible:
        s = remove_invisible(s)

    if cfg.remove_control:
        s = "".join(ch for ch in s if unicodedata.category(ch)[0] != "C" or ch in ("\n", "\t"))

    if cfg.collapse_ws:
        if cfg.keep_newlines:
            lines = [re.sub(r"\s+", " ", ln).strip() for ln in s.splitlines()]
            s = "\n".join(ln for ln in lines if ln or not cfg.strip)
        else:
            s = re.sub(r"\s+", " ", s)

    if cfg.strip:
        s = s.strip()

    if cfg.lowercase:
        s = s.lower()

    return s


def remove_invisible(text: str) -> str:
    """
    Удаляет невидимые/форматирующие символы (ZW*, BiDi, variation selectors).

    >>> remove_invisible("a\u200Bb")
    'ab'
    """
    def visible(ch: str) -> bool:
        cp = ord(ch)
        if ch in _INVISIBLE_CODEPOINTS:
            return False
        for a, b in _BIDI_RANGES + _VARIATION_SELECTORS:
            if a <= cp <= b:
                return False
        return True

    return "".join(ch for ch in text if visible(ch))


def strip_accents(text: str) -> str:
    """
    Удаляет диакритики (NFKD → отбросить комбинируемые знаки).

    >>> strip_accents("Crème Brûlée")
    'Creme Brulee'
    """
    if not text:
        return text
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def slugify(text: str, max_len: int = 80) -> str:
    """
    Генерирует URL-слуг: латиница/цифры и дефисы. Транслитерация через NFKD/strip_accents.

    >>> slugify("Пример: Тестовый заголовок!")
    'primer-testovyi-zagolovok'
    """
    if not text:
        return ""
    base = strip_accents(unicodedata.normalize("NFKC", text)).lower()
    base = _NON_ALNUM_RE.sub("-", base)
    base = _MULTIHYPHEN_RE.sub("-", base)
    base = _LEADING_TRAILING_HYPHEN_RE.sub("", base)
    return base[:max_len]


# ======================================================================================
# Графемно-устойчивые операции
# ======================================================================================

def _graphemes(s: str) -> List[str]:
    if not s:
        return []
    if _GRAPHEME_RE:
        return _GRAPHEME_RE.findall(s)
    # Fallback: грубая аппроксимация — символ + последующие комбинируемые
    out: List[str] = []
    buf = ""
    for ch in s:
        if not buf:
            buf = ch
        else:
            if unicodedata.combining(ch):
                buf += ch
            else:
                out.append(buf)
                buf = ch
    if buf:
        out.append(buf)
    return out


def safe_truncate_chars(text: str, max_len: int, ellipsis: str = "…", prefer_ws: bool = True) -> str:
    """
    Безопасное усечение по кол-ву графемных кластеров с мягким переносом по пробелу.

    >>> safe_truncate_chars("Здравствуйте, мир!", 10)
    'Здравствуйте…'
    """
    if max_len <= 0:
        return ""
    g = _graphemes(text)
    if len(g) <= max_len:
        return text
    cut = g[:max_len]
    s = "".join(cut)
    if prefer_ws:
        # если последнее слово было разорвано, откатиться до пробела
        idx = s.rfind(" ")
        if 0 < idx < len(s) - 1:
            s = s[:idx]
    return s + ellipsis


def safe_truncate_words(text: str, max_words: int, ellipsis: str = "…") -> str:
    """
    Усечение по словам (Unicode-слова), добавляет многоточие при отрезании.

    >>> safe_truncate_words("один два три четыре", 3)
    'один два три…'
    """
    if max_words <= 0:
        return ""
    words = [m.group(0) for m in _WORD_RE.finditer(text)]
    if len(words) <= max_words:
        return text
    # найдём индекс окончания N-го слова в исходной строке
    count, pos = 0, 0
    for m in _WORD_RE.finditer(text):
        count += 1
        pos = m.end()
        if count == max_words:
            break
    return text[:pos] + ellipsis


# ======================================================================================
# Токенизация и предложения
# ======================================================================================

def tokenize_words(text: str) -> List[str]:
    """
    Простейшая токенизация слов (Unicode). Нормализовать при необходимости отдельно.

    >>> tokenize_words("Hello, мир! it's fine")
    ['Hello', 'мир', "it's", 'fine']
    """
    return [m.group(0) for m in _WORD_RE.finditer(text)]


def split_sentences(text: str) -> List[str]:
    """
    Грубое разбиение на предложения. Учитывает типичные аббревиатуры.

    >>> split_sentences("Это тест. А это — пример, см. рис. 1. Всё ок?")
    ['Это тест.', 'А это — пример, см. рис. 1.', 'Всё ок?']
    """
    if not text:
        return []
    s = normalize(text, NormalizeConfig(nfkc=True, strip=True, collapse_ws=True, keep_newlines=False))
    # защищаем аббревиатуры: временно заменим финальную точку на маркер
    marker = "§§DOT§§"
    for abbr in _ABBREVIATIONS:
        s = s.replace(abbr, abbr.replace(".", marker))
    parts = _SENT_SPLIT_RE.split(s) if _SENT_SPLIT_RE else re.split(r"(?<=\S[.!?])\s+", s)
    out = [p.replace(marker, ".").strip() for p in parts if p.strip()]
    return out


# ======================================================================================
# n-граммы и похожесть
# ======================================================================================

def ngrams(tokens: Sequence[str], n: int) -> List[Tuple[str, ...]]:
    """
    n-граммы из последовательности токенов/графем.

    >>> ngrams(["a","b","c","d"], 2)
    [('a', 'b'), ('b', 'c'), ('c', 'd')]
    """
    if n <= 0:
        return []
    return [tuple(tokens[i : i + n]) for i in range(0, max(0, len(tokens) - n + 1))]


def jaccard_similarity(a: Set[Any], b: Set[Any]) -> float:
    """
    Коэффициент Жаккара для множеств.
    """
    if not a and not b:
        return 1.0
    return len(a & b) / float(len(a | b))


def text_jaccard(s1: str, s2: str, n: int = 3) -> float:
    """
    Жаккар по символьным n-граммам (графемам).

    >>> text_jaccard("кот", "котик", 2) > 0.5
    True
    """
    g1 = _graphemes(s1)
    g2 = _graphemes(s2)
    ng1 = set(ngrams(g1, n))
    ng2 = set(ngrams(g2, n))
    return jaccard_similarity(ng1, ng2)


def levenshtein(a: str, b: str, max_distance: Optional[int] = None) -> int:
    """
    Дистанция Левенштейна, опционально с отсечкой (Ukkonen).
    Использует python-Levenshtein при наличии.

    >>> levenshtein("кот", "кит")
    1
    """
    if _lev:
        d = _lev.distance(a, b)
        if max_distance is not None and d > max_distance:
            return max_distance + 1
        return d

    # Fallback: ограниченная диагональная матрица (Ukkonen band)
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    n, m = len(a), len(b)
    if max_distance is None:
        max_distance = max(n, m)

    # Диапазон диагонали
    band = max_distance
    prev = [i if i <= band else math.inf for i in range(m + 1)]
    for i in range(1, n + 1):
        cur = [math.inf] * (m + 1)
        low = max(1, i - band)
        high = min(m, i + band)
        cur[low - 1] = math.inf
        for j in range(low, high + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
        if min(prev[low:high + 1]) > max_distance:
            return max_distance + 1
    d = int(prev[m])
    return d


def jaro_winkler(s1: str, s2: str, prefix_weight: float = 0.1) -> float:
    """
    Похожесть Яро–Винклера (0..1).

    >>> jaro_winkler("MARTHA", "MARHTA") > 0.95
    True
    """
    if s1 == s2:
        return 1.0
    s1_len, s2_len = len(s1), len(s2)
    if not s1_len or not s2_len:
        return 0.0

    match_distance = max(s1_len, s2_len) // 2 - 1
    s1_matches = [False] * s1_len
    s2_matches = [False] * s2_len

    matches = 0
    transpositions = 0

    for i in range(s1_len):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, s2_len)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = s2_matches[j] = True
            matches += 1
            break

    if not matches:
        return 0.0

    k = 0
    for i in range(s1_len):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    m = matches
    jaro = (m / s1_len + m / s2_len + (m - transpositions / 2) / m) / 3.0

    # Winkler prefix
    prefix = 0
    for i in range(min(4, s1_len, s2_len)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + prefix * prefix_weight * (1 - jaro)


def simhash(text: str, n: int = 3, hashbits: int = 64) -> int:
    """
    SimHash текста по графемным n-граммам.

    >>> isinstance(simhash("пример"), int)
    True
    """
    g = _graphemes(normalize(text))
    grams = ngrams(g, n) if n > 1 else [(x,) for x in g]
    v = [0] * hashbits
    for gram in grams:
        h = int(hashlib.blake2b("".join(gram).encode("utf-8"), digest_size=8).hexdigest(), 16)
        for i in range(hashbits):
            bit = 1 if (h >> i) & 1 else -1
            v[i] += bit
    out = 0
    for i in range(hashbits):
        if v[i] > 0:
            out |= (1 << i)
    return out


# ======================================================================================
# Редакция/маскирование PII и секретов
# ======================================================================================

@dataclass(frozen=True)
class RedactPolicy:
    email: bool = True
    phone: bool = True
    ip: bool = True
    jwt: bool = True
    aws_key: bool = True
    credit_card: bool = True
    replacement: str = "[REDACTED]"
    preserve_last4_cc: bool = True


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    s, alt = 0, False
    for d in reversed(digits):
        d2 = d * 2 if alt else d
        s += d2 - 9 if d2 > 9 else d2
        alt = not alt
    return s % 10 == 0


def redact(text: str, policy: RedactPolicy = RedactPolicy()) -> str:
    """
    Маскирование типовых PII/секретов. Корректность карт проверяется алгоритмом Луна.

    >>> redact("email a@b.com, jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb")
    '[REDACTED], jwt [REDACTED]'
    """
    s = text

    def rep_cc(m: re.Match) -> str:
        raw = m.group(0)
        if not _luhn_ok(raw):
            return raw
        if policy.preserve_last4_cc:
            digits = re.sub(r"\D", "", raw)
            return policy.replacement[:-1] + ":" + digits[-4:]  # '[REDACTED':last4]
        return policy.replacement

    if policy.email:
        s = _EMAIL_RE.sub(policy.replacement, s)
    if policy.phone:
        s = _PHONE_RE.sub(policy.replacement, s)
    if policy.ip:
        s = _IPV4_RE.sub(policy.replacement, s)
        s = _IPV6_RE.sub(policy.replacement, s)
    if policy.jwt:
        s = _JWT_RE.sub(policy.replacement, s)
    if policy.aws_key:
        s = _AWS_KEY_RE.sub(policy.replacement, s)
    if policy.credit_card:
        s = _CC_CAND_RE.sub(rep_cc, s)

    return s


# ======================================================================================
# Отпечатки/хеши и утилиты
# ======================================================================================

def fingerprint(text: str) -> str:
    """
    Детерминированный отпечаток нормализованного текста (SHA-256 hex).

    >>> fingerprint(" Hello\\u200B World ")
    '9f' in fingerprint(" Hello\\u200B World ")
    """
    norm = normalize(text)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def hmac_digest(text: str, key: bytes, algo: str = "sha256") -> str:
    """
    HMAC отпечаток (hex).
    """
    return hmac.new(key, text.encode("utf-8"), getattr(hashlib, algo)).hexdigest()


def ensure_text(x: Any, encoding: str = "utf-8", errors: str = "strict") -> str:
    """
    Гарантирует str из bytes/bytearray/str.
    """
    if isinstance(x, str):
        return x
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x).decode(encoding, errors=errors)
    return str(x)


def dedent_preserve(text: str) -> str:
    """
    Аккуратная де-индентация с сохранением пустых строк.
    """
    if text is None:
        return ""
    lines = text.splitlines(True)
    return textwrap.dedent("".join(lines))


# ======================================================================================
# Экспорт API
# ======================================================================================

__all__ = [
    # Конфигурация/нормализация
    "NormalizeConfig",
    "normalize",
    "remove_invisible",
    "strip_accents",
    "slugify",
    # Графемы/усечение
    "safe_truncate_chars",
    "safe_truncate_words",
    # Токенизация/предложения
    "tokenize_words",
    "split_sentences",
    # n-граммы/похожесть
    "ngrams",
    "jaccard_similarity",
    "text_jaccard",
    "levenshtein",
    "jaro_winkler",
    "simhash",
    # Редакция/секреты
    "RedactPolicy",
    "redact",
    # Отпечатки/хеши/утилиты
    "fingerprint",
    "hmac_digest",
    "ensure_text",
    "dedent_preserve",
]
