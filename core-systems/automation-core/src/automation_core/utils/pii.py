# -*- coding: utf-8 -*-
"""
PII utilities: detection, validation, normalization, redaction, pseudonymization.

This module focuses on globally standardised identifiers:
- Email addresses
- International phone numbers (E.164-like normalisation)
- IPv4 / IPv6 addresses
- MAC addresses
- Payment card numbers (Luhn / MOD-10)
- IBAN (MOD-97)
- UUID (RFC 4122 variants 1-5)

Design goals:
- No third-party runtime deps (stdlib only)
- Deterministic pseudonymization via HMAC-SHA256
- Configurable redaction strategies with stable output
- Overlap resolution (prefer longer/specific matches)
- Safe defaults and explicit types

Author: automation-core
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import ipaddress
import os
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------- Types & data model ---------------------------- #

class PIIType(Enum):
    EMAIL = auto()
    PHONE = auto()
    IP = auto()
    MAC = auto()
    CREDIT_CARD = auto()
    IBAN = auto()
    UUID = auto()


@dataclass(frozen=True)
class PIIEntity:
    type: PIIType
    value: str
    start: int
    end: int
    normalized: Optional[str] = None
    score: float = 1.0
    detector: str = "regex+validator"
    ctx_left: str = ""
    ctx_right: str = ""

    def span(self) -> Tuple[int, int]:
        return (self.start, self.end)


@dataclass
class RedactConfig:
    strategy: str = "mask"          # mask | placeholder | hash
    mask_char: str = "*"
    keep_last: int = 4              # for mask strategy
    placeholder_map: Dict[PIIType, str] = dataclasses.field(default_factory=lambda: {
        PIIType.EMAIL: "<EMAIL>",
        PIIType.PHONE: "<PHONE>",
        PIIType.IP: "<IP>",
        PIIType.MAC: "<MAC>",
        PIIType.CREDIT_CARD: "<CARD>",
        PIIType.IBAN: "<IBAN>",
        PIIType.UUID: "<UUID>",
    })
    hash_salt: Optional[bytes] = None  # if None, read from PII_HASH_SALT env (base64/hex/plain)


# ------------------------------ Regex patterns ------------------------------ #

# E-mail (conservative, practical)
_RE_EMAIL = re.compile(
    r"""
    (?P<email>
        [A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+
        @
        [A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
        (?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+
    )
    """,
    re.VERBOSE,
)

# Phone: tolerant capture of international numbers; normalization enforces E.164 limits (8..15 digits)
_RE_PHONE = re.compile(
    r"""
    (?P<phone>
        (?:
            \+?\s*(?:\d[\s\-\(\)]*){8,20}
        )
    )
    """,
    re.VERBOSE,
)

# IPv4 candidate (validate with ipaddress)
_RE_IPV4 = re.compile(r"(?P<ipv4>(?:\d{1,3}\.){3}\d{1,3})")

# IPv6 candidate (validate with ipaddress)
_RE_IPV6 = re.compile(r"(?P<ipv6>\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b)")

# MAC addresses (colon or hyphen)
_RE_MAC = re.compile(r"(?P<mac>\b[0-9A-Fa-f]{2}(?:(?:\:|\-)[0-9A-Fa-f]{2}){5}\b)")

# Payment card: 13–19 digits with common separators; validated by Luhn
_RE_CARD = re.compile(
    r"""
    (?P<card>
        (?:
            \d[\-\s]?){13,23}  # allow separators; validate digits count after strip
    )
    """,
    re.VERBOSE,
)

# IBAN: 2 letters + 2 digits + up to 30 alnum, with optional spaces; validated by MOD-97
_RE_IBAN = re.compile(
    r"(?P<iban>\b[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]\s*){10,30}\b)"
)

# UUID v1-5 (canonical with hyphens)
_RE_UUID = re.compile(
    r"(?P<uuid>\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[1-5][0-9a-fA-F]{3}\-[89abAB][0-9a-fA-F]{3}\-[0-9a-fA-F]{12}\b)"
)

_CTX_RADIUS = 16  # capture a bit of surrounding text for context scoring


# ------------------------------ Validators ---------------------------------- #

def _norm_phone_to_e164(raw: str) -> Optional[str]:
    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("+"):
        cc_and_nsn = re.sub(r"[^\d]", "", digits)  # strip plus for length check
        if 8 <= len(cc_and_nsn) <= 15:
            return "+" + cc_and_nsn
        return None
    # try to interpret as international without '+'
    just_digits = re.sub(r"\D", "", raw)
    if 8 <= len(just_digits) <= 15:
        return "+" + just_digits
    return None


def _valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def _valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False


def _luhn_ok(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _iban_ok(raw: str) -> bool:
    s = re.sub(r"\s+", "", raw).upper()
    # Basic structure check
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$", s):
        return False
    # MOD-97 per ISO 13616
    # Move first 4 chars to the end, convert letters A=10..Z=35, then mod 97 == 1
    rearr = s[4:] + s[:4]
    num = []
    for ch in rearr:
        if ch.isdigit():
            num.append(ch)
        else:
            num.append(str(ord(ch) - 55))  # 'A'->10
    big = "".join(num)
    # compute mod 97 on chunks to avoid huge ints
    rem = 0
    for i in range(0, len(big), 9):
        rem = (rem * (10 ** (len(big[i:i+9]))) + int(big[i:i+9])) % 97
    return rem == 1


def _uuid_ok(s: str) -> bool:
    return bool(_RE_UUID.fullmatch(s))


# ------------------------------ Detection core ------------------------------ #

@dataclass
class DetectorConfig:
    enabled: Sequence[PIIType] = (
        PIIType.EMAIL,
        PIIType.PHONE,
        PIIType.IP,
        PIIType.MAC,
        PIIType.CREDIT_CARD,
        PIIType.IBAN,
        PIIType.UUID,
    )
    # prefer specific/stricter types for overlap resolution
    priority: Sequence[PIIType] = (
        PIIType.CREDIT_CARD,
        PIIType.IBAN,
        PIIType.EMAIL,
        PIIType.PHONE,
        PIIType.UUID,
        PIIType.IP,
        PIIType.MAC,
    )


class PIIDetector:
    def __init__(self, config: Optional[DetectorConfig] = None):
        self.cfg = config or DetectorConfig()

    def detect(self, text: str, types: Optional[Sequence[PIIType]] = None) -> List[PIIEntity]:
        wanted = set(types or self.cfg.enabled)
        candidates: List[PIIEntity] = []

        def add(kind: PIIType, m: re.Match, norm: Optional[str], score: float) -> None:
            if kind not in wanted:
                return
            s, e = m.span()
            ctx_l = text[max(0, s - _CTX_RADIUS):s]
            ctx_r = text[e:min(len(text), e + _CTX_RADIUS)]
            candidates.append(PIIEntity(
                type=kind,
                value=m.group(0),
                start=s,
                end=e,
                normalized=norm,
                score=score,
                ctx_left=ctx_l,
                ctx_right=ctx_r,
            ))

        # EMAIL
        for m in _RE_EMAIL.finditer(text):
            add(PIIType.EMAIL, m, m.group("email").lower(), 0.99)

        # PHONE (normalize to E.164-like)
        for m in _RE_PHONE.finditer(text):
            norm = _norm_phone_to_e164(m.group("phone"))
            if norm:
                add(PIIType.PHONE, m, norm, 0.85)

        # IPv4 / IPv6
        for m in _RE_IPV4.finditer(text):
            val = m.group("ipv4")
            if _valid_ipv4(val):
                add(PIIType.IP, m, val, 0.95)

        for m in _RE_IPV6.finditer(text):
            val = m.group("ipv6")
            if _valid_ipv6(val):
                add(PIIType.IP, m, val, 0.95)

        # MAC
        for m in _RE_MAC.finditer(text):
            add(PIIType.MAC, m, m.group("mac").lower(), 0.9)

        # CREDIT CARD
        for m in _RE_CARD.finditer(text):
            raw = re.sub(r"\D", "", m.group("card"))
            if _luhn_ok(raw):
                add(PIIType.CREDIT_CARD, m, raw, 0.98)

        # IBAN
        for m in _RE_IBAN.finditer(text):
            raw = m.group("iban")
            if _iban_ok(raw):
                add(PIIType.IBAN, m, re.sub(r"\s+", "", raw).upper(), 0.97)

        # UUID
        for m in _RE_UUID.finditer(text):
            add(PIIType.UUID, m, m.group("uuid").lower(), 0.9)

        return self._resolve_overlaps(candidates)

    def _resolve_overlaps(self, items: List[PIIEntity]) -> List[PIIEntity]:
        # Sort by: start, then by priority order, then length desc, then score desc
        prio = {t: i for i, t in enumerate(self.cfg.priority)}
        def key(it: PIIEntity):
            return (it.start, prio.get(it.type, 999), -(it.end - it.start), -it.score)

        items_sorted = sorted(items, key=key)
        accepted: List[PIIEntity] = []
        last_end = -1

        for it in items_sorted:
            conflict = False
            for acc in accepted:
                if not (it.end <= acc.start or it.start >= acc.end):
                    # overlap: prefer higher-priority (already ordered)
                    conflict = True
                    break
            if not conflict:
                accepted.append(it)
        return accepted


# -------------------------- Redaction & pseudonymization --------------------- #

def _get_salt_bytes(salt: Optional[bytes]) -> bytes:
    if salt:
        return salt
    env = os.environ.get("PII_HASH_SALT", "")
    if not env:
        # zero-length salt is allowed but discouraged; keep deterministic anyway
        return b""
    # try base64
    try:
        return base64.b64decode(env, validate=True)
    except Exception:
        pass
    # try hex
    try:
        return bytes.fromhex(env)
    except Exception:
        pass
    # raw utf-8
    return env.encode("utf-8")


def pseudonymize(value: str, *, salt: Optional[bytes] = None, context: str = "") -> str:
    """
    Deterministic HMAC-SHA256 pseudonym with optional context binding.
    Output is base32 (no padding) for readability.
    """
    key = _get_salt_bytes(salt)
    mac = hmac.new(key, msg=(context + "||" + value).encode("utf-8"), digestmod=hashlib.sha256).digest()
    # base32 without padding, shorter prefix
    return base64.b32encode(mac).decode("ascii").rstrip("=").lower()[:52]


def _mask_tail(value: str, keep: int, mask_char: str) -> str:
    if keep <= 0:
        return mask_char * len(value)
    n = max(0, len(value) - keep)
    return (mask_char * n) + value[-keep:]


def redact(text: str, entities: Sequence[PIIEntity], cfg: Optional[RedactConfig] = None) -> str:
    cfg = cfg or RedactConfig()
    # Replace from end to start to avoid offset shifts
    repls: List[Tuple[int, int, str]] = []
    for ent in entities:
        original = text[ent.start:ent.end]
        if cfg.strategy == "mask":
            if ent.type in (PIIType.CREDIT_CARD, PIIType.PHONE, PIIType.IBAN):
                norm = ent.normalized or original
                replacement = _mask_tail(norm, cfg.keep_last, cfg.mask_char)
            else:
                replacement = cfg.mask_char * len(original)
        elif cfg.strategy == "placeholder":
            replacement = cfg.placeholder_map.get(ent.type, "<PII>")
        elif cfg.strategy == "hash":
            replacement = pseudonymize(ent.normalized or original, salt=cfg.hash_salt, context=ent.type.name)
        else:
            raise ValueError(f"Unknown redaction strategy: {cfg.strategy}")
        repls.append((ent.start, ent.end, replacement))

    repls.sort(key=lambda x: x[0], reverse=True)
    out = list(text)
    for s, e, r in repls:
        out[s:e] = list(r)
    return "".join(out)


# ------------------------------- Public API --------------------------------- #

_default_detector = PIIDetector()

def detect_pii(text: str, *, types: Optional[Sequence[PIIType]] = None) -> List[PIIEntity]:
    """
    Detect PII entities in text. Returns non-overlapping, validated entities.
    """
    return _default_detector.detect(text, types=types)


def redact_pii(text: str,
               *,
               types: Optional[Sequence[PIIType]] = None,
               redact_config: Optional[RedactConfig] = None) -> Tuple[str, List[PIIEntity]]:
    """
    Detect and redact PII in a single pass. Returns (redacted_text, entities).
    """
    ents = detect_pii(text, types=types)
    return redact(text, ents, redact_config), ents


# ------------------------------- __all__ ------------------------------------ #

__all__ = [
    "PIIType",
    "PIIEntity",
    "DetectorConfig",
    "RedactConfig",
    "PIIDetector",
    "detect_pii",
    "redact_pii",
    "pseudonymize",
]
