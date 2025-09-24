# SPDX-License-Identifier: MIT
"""
veilmind.utils.text_ops
Industrial-grade text utilities for Unicode-safe normalization, sanitization,
redaction, URL/email extraction, slugification, safe truncation, and more.

Design goals:
- Pure stdlib; optionally uses 'regex' if available for grapheme clusters (\X)
- Deterministic offsets and robust Unicode handling
- Security-first sanitization with minimal false negatives

Public highlights:
- normalize_text, strip_markdown
- safe_truncate (grapheme-aware), excerpt, highlight_spans
- redact_secrets, find_urls, find_emails, find_phones, find_credit_cards
- slugify, to_ascii (with Cyrillic transliteration), detect_script
- idna_normalize_url
- hash_text, uuid5_for_text, estimate_tokens, similarity, unified_diff
"""

from __future__ import annotations

import difflib
import hashlib
import html
import re
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit, SplitResult

# Optional: third-party 'regex' for \X grapheme clusters (if present)
try:  # pragma: no cover
    import regex as _regex  # type: ignore

    _HAS_REGEX = True
    _RE_GRAPHEME = _regex.compile(r"\X")
except Exception:  # pragma: no cover
    _HAS_REGEX = False
    _RE_GRAPHEME = None  # type: ignore


# ------------------------------- Normalization --------------------------------


def normalize_text(
    text: str,
    *,
    form: str = "NFKC",
    strip: bool = True,
    collapse_ws: bool = False,
    keep_lines: bool = True,
    unify_newlines: bool = True,
) -> str:
    """
    Unicode-normalize text with optional whitespace processing.

    - form: NFC/NFKC recommended (NFKC for security/compat)
    - strip: trim leading/trailing whitespace
    - collapse_ws: replace runs of whitespace with single space (or single newline if keep_lines)
    - keep_lines: if True, preserve single newlines; otherwise collapse to spaces
    - unify_newlines: convert CRLF/CR to LF
    """
    if not isinstance(text, str):
        text = str(text)

    if unify_newlines:
        text = text.replace("\r\n", "\n").replace("\r", "\n")

    text = unicodedata.normalize(form, text)

    if collapse_ws:
        if keep_lines:
            # Collapse spaces/tabs; keep single LF
            text = re.sub(r"[ \t\f\v]+", " ", text)
            text = re.sub(r"\n{3,}", "\n\n", text)
        else:
            text = re.sub(r"\s+", " ", text)

    if strip:
        text = text.strip()

    return text


# ------------------------------- Markdown strip -------------------------------

_MD_CODEBLOCK = re.compile(r"```.*?```", re.S)
_MD_INLINE_CODE = re.compile(r"`([^`]+)`")
_MD_LINK = re.compile(r"\[([^\]]+)]\(([^)]+)\)")
_MD_IMG = re.compile(r"!\[([^\]]*)]\(([^)]+)\)")
_MD_HEADERS = re.compile(r"^\s{0,3}#{1,6}\s*", re.M)
_MD_BLOCKQUOTE = re.compile(r"^\s{0,3}>\s?", re.M)
_MD_LIST = re.compile(r"^\s{0,3}([-*+]|\d+\.)\s+", re.M)


def strip_markdown(text: str) -> str:
    """
    Best-effort Markdown → plain text, preserving content where possible.
    Safe for untrusted input; avoids executing links/images.

    - Code blocks removed entirely (to avoid large payloads)
    - Inline code unwrapped
    - Links "[label](url)" -> "label"
    - Images "![alt](url)" -> "alt"
    - Headers/list markers/quotes stripped
    """
    s = _MD_CODEBLOCK.sub("", text)
    s = _MD_IMG.sub(r"\1", s)
    s = _MD_LINK.sub(r"\1", s)
    s = _MD_INLINE_CODE.sub(r"\1", s)
    s = _MD_HEADERS.sub("", s)
    s = _MD_BLOCKQUOTE.sub("", s)
    s = _MD_LIST.sub("", s)
    return normalize_text(s, collapse_ws=True, keep_lines=True)


# ------------------------------- Grapheme utils -------------------------------

def _split_graphemes(text: str) -> List[str]:
    """
    Split text into grapheme clusters. Uses 'regex' if available; otherwise
    falls back to a conservative splitter that avoids cutting combining marks.
    """
    if _HAS_REGEX and _RE_GRAPHEME:
        return _RE_GRAPHEME.findall(text)

    # Fallback: split by code points but merge combining marks with their base
    out: List[str] = []
    buff = ""
    for ch in text:
        if not buff:
            buff = ch
            continue
        if unicodedata.combining(ch) != 0:
            buff += ch
            continue
        # Regional Indicator pairs (emoji flags) — crude handling:
        # if previous was RI (U+1F1E6..U+1F1FF) and current is RI, keep together
        prev = buff[-1]
        if 0x1F1E6 <= ord(prev) <= 0x1F1FF and 0x1F1E6 <= ord(ch) <= 0x1F1FF:
            buff += ch
            continue
        out.append(buff)
        buff = ch
    if buff:
        out.append(buff)
    return out


def safe_truncate(
    text: str,
    max_chars: int,
    *,
    suffix: str = "…",
    prefer_word_boundary: bool = True,
) -> str:
    """
    Truncate text without breaking grapheme clusters; optionally prefer word boundaries.

    - max_chars counts visible characters (graphemes), not code points where possible.
    - If truncated, suffix is appended (counted against the limit).
    """
    if max_chars <= 0:
        return "" if max_chars == 0 else ""

    graphemes = _split_graphemes(text)
    if len(graphemes) <= max_chars:
        return text

    take = max(0, max_chars - len(_split_graphemes(suffix)))
    truncated = "".join(graphemes[:take])

    if prefer_word_boundary:
        m = re.search(r".*\b", truncated, re.S)
        if m and len(m.group(0)) >= max(0, len(truncated) - 8):
            truncated = m.group(0)

    return truncated + suffix


# -------------------------------- Excerpts/markup ------------------------------

def excerpt(text: str, start: int, end: int, *, ctx: int = 32) -> Tuple[str, Tuple[int, int]]:
    """
    Return a safe excerpt around [start:end] with context 'ctx'.
    Returns (snippet, (new_start, new_end)) where new_* are indices within snippet.
    """
    start = max(0, min(start, len(text)))
    end = max(start, min(end, len(text)))
    a = max(0, start - ctx)
    b = min(len(text), end + ctx)
    snippet = text[a:b]
    new_start = start - a
    new_end = new_start + (end - start)
    return snippet, (new_start, new_end)


def highlight_spans(
    text: str,
    spans: Sequence[Tuple[int, int]],
    *,
    start_tag: str = "<mark>",
    end_tag: str = "</mark>",
    escape_html: bool = True,
) -> str:
    """
    Inject HTML tags around spans. Spans must be non-overlapping and sorted.
    If escape_html=True, escapes text outside tags.
    """
    out: List[str] = []
    last = 0
    for s, e in spans:
        s = max(last, min(s, len(text)))
        e = max(s, min(e, len(text)))
        if escape_html:
            out.append(html.escape(text[last:s]))
            out.append(start_tag + html.escape(text[s:e]) + end_tag)
        else:
            out.append(text[last:s])
            out.append(start_tag + text[s:e] + end_tag)
        last = e
    tail = html.escape(text[last:]) if escape_html else text[last:]
    out.append(tail)
    return "".join(out)


# --------------------------------- Redaction ----------------------------------

# Carefully curated patterns
_RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
_RE_PHONE = re.compile(r"(?<!\d)(?:\+?\d[\s\-()]?){7,15}(?:\d)(?!\d)")
_RE_IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_RE_IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I)
_RE_JWT = re.compile(r"\b[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
_RE_AWS = re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b")
_RE_GCP = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
_RE_SLACK = re.compile(r"xox[abpr]-[0-9A-Za-z\-]{10,48}")
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b")
_RE_PK = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END .*? KEY-----", re.I)
_RE_URL = re.compile(r"\bhttps?://[^\s)]+", re.I)
_RE_B64_BULK = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")

# Credit-card digits (13–19) with optional separators
_RE_CC = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


@dataclass(frozen=True)
class RedactionHit:
    kind: str
    start: int
    end: int
    value: str


def _collect_hits(text: str) -> List[RedactionHit]:
    hits: List[RedactionHit] = []
    for kind, rx in [
        ("email", _RE_EMAIL),
        ("phone", _RE_PHONE),
        ("ipv4", _RE_IPV4),
        ("ipv6", _RE_IPV6),
        ("jwt", _RE_JWT),
        ("aws_key", _RE_AWS),
        ("gcp_key", _RE_GCP),
        ("slack_token", _RE_SLACK),
        ("sha256", _RE_SHA256),
        ("private_key", _RE_PK),
        ("url", _RE_URL),
        ("b64", _RE_B64_BULK),
    ]:
        for m in rx.finditer(text):
            hits.append(RedactionHit(kind, m.start(), m.end(), m.group(0)))

    # Credit cards with Luhn filter
    for m in _RE_CC.finditer(text):
        val = m.group(0)
        if _luhn_ok(val):
            hits.append(RedactionHit("credit_card", m.start(), m.end(), val))

    # Merge overlaps: keep broader or earlier
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    merged: List[RedactionHit] = []
    for h in hits:
        if not merged or h.start >= merged[-1].end:
            merged.append(h)
            continue
        # overlap — prefer longer span
        last = merged[-1]
        if (h.end - h.start) > (last.end - last.start):
            merged[-1] = h
    return merged


def redact_secrets(
    text: str,
    *,
    kinds: Optional[Iterable[str]] = None,
    replacement: str = "[REDACTED:{kind}]",
) -> Tuple[str, int, List[RedactionHit]]:
    """
    Redact secrets/PII. Returns (redacted_text, count, hits).
    'kinds' may restrict which categories to redact.
    """
    allowed = set(kinds or [])
    restrict = bool(kinds)

    hits = [h for h in _collect_hits(text) if (h.kind in allowed if restrict else True)]
    if not hits:
        return text, 0, []

    # Apply from end to start
    buf = text
    for h in sorted(hits, key=lambda x: x.start, reverse=True):
        repl = replacement.format(kind=h.kind.upper())
        buf = buf[:h.start] + repl + buf[h.end:]
    return buf, len(hits), hits


# ------------------------------- Finders --------------------------------------

def find_urls(text: str) -> List[Tuple[Tuple[int, int], str]]:
    return [((m.start(), m.end()), m.group(0)) for m in _RE_URL.finditer(text)]


def find_emails(text: str) -> List[Tuple[Tuple[int, int], str]]:
    return [((m.start(), m.end()), m.group(0)) for m in _RE_EMAIL.finditer(text)]


def find_phones(text: str) -> List[Tuple[Tuple[int, int], str]]:
    return [((m.start(), m.end()), m.group(0)) for m in _RE_PHONE.finditer(text)]


def find_credit_cards(text: str) -> List[Tuple[Tuple[int, int], str]]:
    out: List[Tuple[Tuple[int, int], str]] = []
    for m in _RE_CC.finditer(text):
        s = m.group(0)
        if _luhn_ok(s):
            out.append(((m.start(), m.end()), s))
    return out


# ------------------------------- Slug/ASCII -----------------------------------

_CYR_TO_LAT = {
    # Basic Cyrillic transliteration (RU/UA/BG close enough)
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
    "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "ts",
    "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}
_CYR_TO_LAT.update({k.upper(): v.title() for k, v in list(_CYR_TO_LAT.items())})


def to_ascii(text: str, *, transliterate_cyrillic: bool = True, keep: str = "") -> str:
    """
    Convert text to ASCII:
    - optional Cyrillic→Latin transliteration (simple map)
    - strip accents via NFD and remove combining marks
    - drop non-ASCII except characters in 'keep'
    """
    s = text
    if transliterate_cyrillic:
        s = "".join(_CYR_TO_LAT.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    out = []
    for ch in s:
        if ord(ch) < 128 or ch in keep:
            out.append(ch)
    return "".join(out)


def slugify(text: str, max_len: int = 64, delim: str = "-") -> str:
    """
    ASCII slug: lowercase, alnum + delim, collapse runs, trim length.
    """
    s = to_ascii(text, transliterate_cyrillic=True, keep=delim).lower()
    s = re.sub(rf"[^a-z0-9{re.escape(delim)}]+", delim, s)
    s = re.sub(rf"{re.escape(delim)}{{2,}}", delim, s).strip(delim)
    if max_len and len(s) > max_len:
        s = s[:max_len].rstrip(delim)
    return s


# ------------------------------- Script detect --------------------------------

def detect_script(text: str) -> str:
    """
    Crude script detector for routing: 'latin', 'cyrillic', 'other'.
    """
    latin = cyr = 0
    for ch in text:
        o = ord(ch)
        if 0x0041 <= o <= 0x024F:
            latin += 1
        elif 0x0400 <= o <= 0x052F:
            cyr += 1
    if cyr > latin and cyr > 0:
        return "cyrillic"
    if latin > 0:
        return "latin"
    return "other"


# ------------------------------- URL IDNA --------------------------------------

def idna_normalize_url(url: str) -> str:
    """
    Normalize URL host with IDNA (punycode). Returns normalized URL string.
    """
    try:
        parts: SplitResult = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            return url
        port = f":{parts.port}" if parts.port else ""
        # Preserve case for path/query/fragment, but normalize host
        host_idna = host.encode("idna").decode("ascii")
        netloc = (parts.username + "@" if parts.username else "") + host_idna + port
        if parts.password:
            # user:pass@host — rebuild safely
            creds = (parts.username or "") + ":" + (parts.password or "")
            netloc = creds + "@" + host_idna + port
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return url  # be conservative


# ------------------------------- Hashing/IDs ----------------------------------

def hash_text(text: str, *, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def uuid5_for_text(text: str, *, namespace: uuid.UUID = uuid.UUID("12345678-1234-5678-1234-567812345678")) -> uuid.UUID:
    """
    Deterministic UUIDv5 from normalized text.
    """
    norm = normalize_text(text, form="NFKC", strip=True, collapse_ws=True, keep_lines=False)
    return uuid.uuid5(namespace, norm)


# ------------------------------- Tokens/metrics --------------------------------

def estimate_tokens(text: str) -> int:
    """
    Heuristic: ~4 chars per token (English-like). For Cyrillic-rich texts use ~3.
    """
    script = detect_script(text)
    denom = 3 if script == "cyrillic" else 4
    return max(1, (len(text) // denom) + 1)


def similarity(a: str, b: str) -> float:
    """
    Ratcliff-Obershelp (difflib.SequenceMatcher) ratio in [0,1].
    """
    return difflib.SequenceMatcher(None, a, b).ratio()


def unified_diff(a: str, b: str, *, n: int = 3, fromfile: str = "a", tofile: str = "b") -> str:
    """
    Unified diff for diagnostic logs or UI.
    """
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile, tofile, n=n))


# ------------------------------- Safe formatting -------------------------------

_FMT_FIELD = re.compile(r"{([a-zA-Z_][a-zA-Z0-9_]*)}")


def safe_format(template: str, values: Mapping[str, Any]) -> str:
    """
    Format with missing keys left intact: 'Hello {name}' -> if name absent, keep as-is.
    """
    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        if key in values:
            return str(values[key])
        return m.group(0)
    return _FMT_FIELD.sub(repl, template)


# ---------------------------------- __all__ -----------------------------------

__all__ = [
    "normalize_text",
    "strip_markdown",
    "safe_truncate",
    "excerpt",
    "highlight_spans",
    "redact_secrets",
    "find_urls",
    "find_emails",
    "find_phones",
    "find_credit_cards",
    "to_ascii",
    "slugify",
    "detect_script",
    "idna_normalize_url",
    "hash_text",
    "uuid5_for_text",
    "estimate_tokens",
    "similarity",
    "unified_diff",
    "safe_format",
    "RedactionHit",
]
