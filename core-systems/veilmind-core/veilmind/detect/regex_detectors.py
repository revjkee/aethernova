# -*- coding: utf-8 -*-
"""
veilmind-core — regex_detectors
Промышленная библиотека детекции PII/секретов/токенов на основе безопасных регулярок
и пост-валидации. Только стандартная библиотека Python.

Особенности:
- Безопасные регулярки (ограниченные квантификаторы, отсутствие экспоненциального бэктрекинга);
- Пост-валидация: Luhn (карты), мод-97 (IBAN), энтропия (секреты), проверка структуры JWT;
- Маскирование по стратегиям DLP: email hash-prefix-6, phone last4, ip truncate-24;
- Конфигурируемые allowlist/ignore-правила, лимиты, категории и уровни severities;
- Потоковый скан больших текстов по чанкам, JSON-совместимый вывод;
- CLI: скан файлов/STDIN с JSON Lines результатом.

Совместимость: Python 3.9+
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Tuple


# =========================
# Модель и конфигурация
# =========================

Category = str  # 'PII' | 'CREDENTIAL' | 'TOKEN' | 'FINANCIAL' | 'NETWORK' | 'OTHER'
Severity = str  # 'low' | 'medium' | 'high' | 'critical'


@dataclass(frozen=True)
class Finding:
    detector: str
    category: Category
    severity: Severity
    start: int
    end: int
    match: str
    redacted: str
    context: str
    extra: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False)


@dataclass(frozen=True)
class Detector:
    name: str
    category: Category
    severity: Severity
    pattern: Pattern[str]
    post_validate: Optional[Callable[[re.Match[str]], Optional[Dict[str, str]]]] = None
    masker: Optional[Callable[[str, Dict[str, str]], str]] = None

    def finditer(self, text: str) -> Iterator[Finding]:
        for m in self.pattern.finditer(text):
            extra: Dict[str, str] = {}
            if self.post_validate is not None:
                validated = self.post_validate(m)
                if validated is None:
                    continue
                extra = validated
            s, e = m.start(), m.end()
            raw = text[s:e]
            redacted = self.masker(raw, extra) if self.masker else "*" * min(8, len(raw))
            ctx = _safe_context(text, s, e)
            yield Finding(
                detector=self.name,
                category=self.category,
                severity=self.severity,
                start=s,
                end=e,
                match=raw,
                redacted=redacted,
                context=ctx,
                extra=extra,
            )


@dataclass
class ScanConfig:
    detectors: Sequence[Detector]
    allowlist: Sequence[Pattern[str]] = field(default_factory=tuple)
    max_findings: int = 10000
    max_per_detector: int = 2000
    # Потоковый скан больших текстов
    chunk_size: int = 512 * 1024
    chunk_overlap: int = 128

    def is_allowed(self, s: str) -> bool:
        return any(p.search(s) for p in self.allowlist)


# =========================
# Утилиты маскирования DLP
# =========================

def mask_email_hash_prefix6(value: str, _: Dict[str, str]) -> str:
    # user@example.com -> h:<sha256(email)>[:6]@example.com
    try:
        local, domain = value.split("@", 1)
    except Exception:
        return "h:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:6]
    h = hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:6]
    return f"h:{h}@{domain}"


def mask_phone_last4(value: str, _: Dict[str, str]) -> str:
    digits = [c for c in value if c.isdigit()]
    last4 = "".join(digits[-4:]) if len(digits) >= 4 else "".join(digits)
    return f"+**{len(digits)-4 if len(digits) > 4 else 0}**-{last4}"


def mask_ip_truncate24(value: str, _: Dict[str, str]) -> str:
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv4Address):
            parts = value.split(".")
            return ".".join(parts[:3]) + ".0"
        # IPv6 — нулим последние 80 бит (~/48)
        hextets = value.split(":")
        if len(hextets) >= 3:
            return ":".join(hextets[:3] + ["0"] * (8 - 3))
    except Exception:
        pass
    return value


def mask_partial_keep_last4(value: str, _: Dict[str, str]) -> str:
    # Общий дефолт для секретов: оставить последние 4 символа.
    tail = value[-4:]
    return "*" * max(0, len(value) - 4) + tail


# =========================
# Пост-валидация
# =========================

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not (12 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) < 15 or len(s) > 34:
        return False
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", s):
        return False
    # mod-97
    rearranged = s[4:] + s[:4]
    trans = "".join(str(int(ch, 36)) for ch in rearranged)
    rem = 0
    for i in range(0, len(trans), 9):
        rem = (rem * (10 ** (len(trans[i:i+9]))) + int(trans[i:i+9])) % 97
    return rem == 1


def _bic_ok(bic: str) -> bool:
    return re.match(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$", bic) is not None


def _jwt_ok(token: str) -> Optional[Dict[str, str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_pad(header_b64))
        payload = json.loads(_b64url_pad(payload_b64))
    except Exception:
        return None
    # Минимальная проверка: alg, typ JWT; exp/iats — числовые
    alg = str(header.get("alg", ""))
    if not alg or len(alg) > 10:
        return None
    if header.get("typ") not in (None, "JWT", "jwt"):
        return None
    extra: Dict[str, str] = {}
    for k in ("iss", "sub", "aud"):
        if k in payload and isinstance(payload[k], str):
            extra[k] = payload[k]
    for ts_k in ("iat", "exp", "nbf"):
        v = payload.get(ts_k)
        if v is not None and not isinstance(v, (int, float)):
            return None
    extra["alg"] = alg
    return extra


def _entropy_bits_per_char(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return h


def _safe_context(text: str, start: int, end: int, radius: int = 30) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    snippet = text[a:b].replace("\n", " ")
    return snippet


def _b64url_pad(chunk: str) -> str:
    # Возвращает декодированную строку JSON либо бросает исключение вверх по стеку
    rem = len(chunk) % 4
    if rem:
        chunk += "=" * (4 - rem)
    return base64.urlsafe_b64decode(chunk.encode("ascii")).decode("utf-8")


# =========================
# Регулярные выражения (безопасные)
# =========================

# Email: локальная часть упрощена для промышленного баланса FP/FN
RE_EMAIL = re.compile(r"""
    (?P<email>
        [A-Za-z0-9._%+\-]{1,64}
        @
        [A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}
    )
""", re.X)

# Телефон (E.164‑подобный): + и 8–15 цифр, допускаем разделители
RE_PHONE = re.compile(r"""
    (?P<phone>
        (?:\+|00)\d{1,3}      # код страны
        [\s\-().]*\d{2,4}
        (?:[\s\-().]*\d){4,10}
    )
""", re.X)

# IPv4 и IPv6 (простая форма)
RE_IPV4 = re.compile(r"\b(?P<ip>(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
RE_IPV6 = re.compile(r"\b(?P<ip>(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})\b")

# Номер карты (16±3, с разделителями), последующая Luhn‑валидация
RE_CARD = re.compile(r"""
    (?P<card>
        (?:\d[ -]?){12,19}
    )
""", re.X)

# IBAN и BIC
RE_IBAN = re.compile(r"\b(?P<iban>[A-Z]{2}\d{2}[A-Z0-9]{11,30})\b")
RE_BIC  = re.compile(r"\b(?P<bic>[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b")

# JWT компактная форма
RE_JWT = re.compile(r"\b(?P<jwt>eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b")

# AWS Access Key ID
RE_AWS_ACCESS_KEY = re.compile(r"\b(?P<ak>AKIA[0-9A-Z]{16})\b")

# GitHub PAT
RE_GITHUB_PAT = re.compile(r"\b(?P<token>ghp_[A-Za-z0-9]{36})\b")

# Google API Key
RE_GOOGLE_API = re.compile(r"\b(?P<key>AIza[0-9A-Za-z_\-]{35})\b")

# Slack tokens (основные виды)
RE_SLACK = re.compile(r"\b(?P<token>xox[baprs]-[A-Za-z0-9\-]{10,48})\b")

# Stripe secret keys
RE_STRIPE = re.compile(r"\b(?P<key>sk_(live|test)_[A-Za-z0-9]{24,99})\b")

# Twilio Account SID
RE_TWILIO_SID = re.compile(r"\b(?P<sid>AC[0-9a-fA-F]{32})\b")

# High-entropy base64url/hex blobs (общий ловец секретов) — строгие ограничения длины
RE_HIGH_ENTROPY = re.compile(r"\b(?P<blob>(?:[A-Za-z0-9+/]{24,}|[A-Fa-f0-9]{32,}))\b")


# =========================
# Пост‑валидации для детекторов
# =========================

def _validate_email(m: re.Match[str]) -> Dict[str, str]:
    email = m.group("email")
    # Отсекаем возможные 'noreply' FP — можно оставить как PII низкой важности
    domain = email.split("@", 1)[1].lower()
    return {"domain": domain}


def _validate_phone(m: re.Match[str]) -> Optional[Dict[str, str]]:
    digits = "".join(ch for ch in m.group("phone") if ch.isdigit())
    if len(digits) < 8 or len(digits) > 15:
        return None
    return {"digits": str(len(digits))}


def _validate_ip(m: re.Match[str]) -> Optional[Dict[str, str]]:
    ip = m.group("ip")
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return None
    return {}


def _validate_card(m: re.Match[str]) -> Optional[Dict[str, str]]:
    raw = m.group("card")
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not _luhn_ok(digits):
        return None
    # Отфильтровать общеизвестные тестовые карты можно в Application слое при необходимости
    brand = _guess_card_brand(digits)
    return {"brand": brand, "length": str(len(digits))}


def _guess_card_brand(digits: str) -> str:
    if digits.startswith("4"):
        return "visa"
    if digits[:2] in {str(i) for i in range(51, 56)}:
        return "mastercard"
    if digits.startswith(("34", "37")):
        return "amex"
    if digits.startswith("35"):
        return "jcb"
    if digits.startswith("6011") or digits.startswith("65"):
        return "discover"
    return "unknown"


def _validate_iban(m: re.Match[str]) -> Optional[Dict[str, str]]:
    iban = m.group("iban")
    if not _iban_ok(iban):
        return None
    return {"country": iban[:2]}


def _validate_bic(m: re.Match[str]) -> Optional[Dict[str, str]]:
    bic = m.group("bic")
    if not _bic_ok(bic):
        return None
    return {"country": bic[4:6]}


def _validate_jwt(m: re.Match[str]) -> Optional[Dict[str, str]]:
    token = m.group("jwt")
    return _jwt_ok(token)


def _validate_high_entropy(m: re.Match[str]) -> Optional[Dict[str, str]]:
    s = m.group("blob")
    # Игнорировать UUID/групповые паттерны, выглядящие как hex c дефисами (здесь уже без дефисов)
    if len(s) in (32, 36) and re.fullmatch(r"[A-Fa-f0-9]{32,36}", s):
        return None
    # Рассчитываем энтропию на подстроке без символов '=' (могут быть base64 паддинги)
    ss = s.strip("=")
    # Отрежем слишком однородные (например, одни и те же символы)
    h = _entropy_bits_per_char(ss)
    # Порог эмпирический: base64/hex с высокой энтропией > 3.5 бита/символ (из ~log2(|alphabet|))
    if len(ss) >= 24 and h >= 3.5:
        return {"entropy": f"{h:.2f}", "len": str(len(ss))}
    return None


# =========================
# Сборка детекторов
# =========================

def build_default_detectors() -> List[Detector]:
    return [
        Detector("email", "PII", "medium", RE_EMAIL, _validate_email, mask_email_hash_prefix6),
        Detector("phone", "PII", "medium", RE_PHONE, _validate_phone, mask_phone_last4),
        Detector("ipv4", "NETWORK", "low", RE_IPV4, _validate_ip, mask_ip_truncate24),
        Detector("ipv6", "NETWORK", "low", RE_IPV6, _validate_ip, mask_ip_truncate24),
        Detector("credit_card", "FINANCIAL", "high", RE_CARD, _validate_card, mask_partial_keep_last4),
        Detector("iban", "FINANCIAL", "high", RE_IBAN, _validate_iban, mask_partial_keep_last4),
        Detector("bic", "FINANCIAL", "medium", RE_BIC, _validate_bic, mask_partial_keep_last4),
        Detector("jwt", "TOKEN", "high", RE_JWT, _validate_jwt, mask_partial_keep_last4),
        Detector("aws_access_key", "CREDENTIAL", "critical", RE_AWS_ACCESS_KEY, lambda m: {}, mask_partial_keep_last4),
        Detector("github_pat", "CREDENTIAL", "critical", RE_GITHUB_PAT, lambda m: {}, mask_partial_keep_last4),
        Detector("google_api_key", "CREDENTIAL", "high", RE_GOOGLE_API, lambda m: {}, mask_partial_keep_last4),
        Detector("slack_token", "CREDENTIAL", "high", RE_SLACK, lambda m: {}, mask_partial_keep_last4),
        Detector("stripe_secret", "CREDENTIAL", "critical", RE_STRIPE, lambda m: {}, mask_partial_keep_last4),
        Detector("twilio_sid", "CREDENTIAL", "high", RE_TWILIO_SID, lambda m: {}, mask_partial_keep_last4),
        Detector("high_entropy", "CREDENTIAL", "high", RE_HIGH_ENTROPY, _validate_high_entropy, mask_partial_keep_last4),
    ]


# =========================
# Сканер
# =========================

def scan_text(text: str, config: Optional[ScanConfig] = None) -> List[Finding]:
    cfg = config or ScanConfig(detectors=build_default_detectors())
    results: List[Finding] = []
    per_detector: Dict[str, int] = {}

    # Быстрая allowlist — если вся строка целиком разрешена, возвращаем пусто
    if cfg.is_allowed(text):
        return results

    for det in cfg.detectors:
        if per_detector.get(det.name, 0) >= cfg.max_per_detector:
            continue
        cnt_before = len(results)
        for finding in det.finditer(text):
            if cfg.is_allowed(finding.match):
                continue
            results.append(finding)
            per_detector[det.name] = per_detector.get(det.name, 0) + 1
            if len(results) >= cfg.max_findings or per_detector[det.name] >= cfg.max_per_detector:
                break
        # Мелкая оптимизация: если ничего не нашли, идём дальше
        if len(results) >= cfg.max_findings:
            break

    # Детеминированная сортировка: по началу, потом по длине и имени детектора
    results.sort(key=lambda f: (f.start, f.end - f.start, f.detector))
    return results


def scan_stream(stream: Iterable[str], config: Optional[ScanConfig] = None) -> Iterator[Finding]:
    """
    Потоковый скан по чанкам (строки или куски текста).
    Обеспечивает overlap для матчей через границы.
    """
    cfg = config or ScanConfig(detectors=build_default_detectors())
    buf = ""
    for chunk in stream:
        if not isinstance(chunk, str):
            chunk = chunk.decode("utf-8", errors="replace")
        buf += chunk
        if len(buf) >= cfg.chunk_size:
            window = buf[: cfg.chunk_size]
            for f in scan_text(window, cfg):
                yield f
            # перекрытие
            buf = buf[cfg.chunk_size - cfg.chunk_overlap :]
    if buf:
        for f in scan_text(buf, cfg):
            yield f


# =========================
# CLI
# =========================

def _build_allowlist(patterns: Sequence[str]) -> Sequence[Pattern[str]]:
    out: List[Pattern[str]] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error:
            # пропускаем невалидную маску
            continue
    return tuple(out)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="veilmind-core regex detectors")
    parser.add_argument("paths", nargs="*", help="Файлы для сканирования; без аргументов — STDIN")
    parser.add_argument("--allow", action="append", default=[], help="Regex allowlist для подавления находок (многоразово)")
    parser.add_argument("--max-findings", type=int, default=10000)
    parser.add_argument("--max-per-detector", type=int, default=2000)
    parser.add_argument("--json", action="store_true", help="Вывод JSON Lines (по умолчанию включён)")
    args = parser.parse_args(argv)

    cfg = ScanConfig(detectors=build_default_detectors(),
                     allowlist=_build_allowlist(args.allow),
                     max_findings=args.max_findings,
                     max_per_detector=args.max_per_detector)

    def emit(f: Finding) -> None:
        print(f.to_json())

    if not args.paths:
        data = sys.stdin.read()
        for f in scan_text(data, cfg):
            emit(f)
        return 0

    for path in args.paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for f in scan_stream(_iter_file_chunks(fh), cfg):
                    emit(f)
        except FileNotFoundError:
            print(json.dumps({"error": "file_not_found", "path": path}), file=sys.stderr)
            continue
    return 0


def _iter_file_chunks(fh, chunk_size: int = 512 * 1024) -> Iterator[str]:
    while True:
        data = fh.read(chunk_size)
        if not data:
            break
        yield data


# =========================
# Пример использования (программно)
# =========================
if __name__ == "__main__":
    sys.exit(main())
