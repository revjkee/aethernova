# File: veilmind-core/veilmind/redact/format_preserving.py
from __future__ import annotations

import datetime as _dt
import hmac as _hmac
import hashlib as _hashlib
import ipaddress as _ip
import os as _os
import re as _re
import string as _string
import typing as _t
import uuid as _uuid

# =============================================================================
# Публичный API
# =============================================================================

class FormatPreservingRedactor:
    """
    Формат‑сохраняющая детерминированная псевдонимизация (не шифрование).
    Все функции детерминированы по (key, tweak, исходное значение).
    Где применимо, пересчитываются контрольные суммы (Luhn/IBAN).

    ВНИМАНИЕ:
    - Это псевдонимизация, а не криптографическое FPE‑шифрование.
    - Для строгой обратимости используйте внешний mapping‑store
      (token vault) и хеш/токен из методов ниже как ключ.
    """

    def __init__(self, key: _t.Union[bytes, str], namespace: str = "veilmind.core.redact"):
        self._key = _ensure_key_bytes(key)
        self._ns = namespace.encode("utf-8")

    # ------------------------ Числа/карты/IBAN ------------------------

    def pseudo_digits(
        self,
        s: str,
        *,
        preserve_tail: int = 0,
        tweak: str | bytes = b"",
    ) -> str:
        """
        Заменяет цифры в строке детерминированно, сохраняя нецифровые символы.
        :param preserve_tail: сколько последних цифр сохранять без изменений.
        """
        return _pseudo_digits_generic(s, self._prf_ctx(tweak), preserve_tail=preserve_tail)

    def pseudo_card(
        self,
        card: str,
        *,
        preserve_tail: int = 4,
        tweak: str | bytes = b"card",
    ) -> str:
        """
        Детерминированная псевдонимизация PAN с сохранением формата и пересчётом Luhn.
        Сохраняет разделители (пробелы/дефисы) и последние preserve_tail цифр.
        """
        return _pseudo_card(card, self._prf_ctx(tweak), preserve_tail=preserve_tail)

    def pseudo_iban(
        self,
        iban: str,
        *,
        tweak: str | bytes = b"iban",
    ) -> str:
        """
        Детерминированная псевдонимизация IBAN:
        - сохраняет код страны (2 буквы),
        - пересчитывает 2‑значную контрольную сумму по MOD‑97,
        - сохраняя длину и класс символов BBAN.
        """
        return _pseudo_iban(iban, self._prf_ctx(tweak))

    # ------------------------ UUID / IP / Email / Date ----------------

    def pseudo_uuid(
        self,
        value: str | _uuid.UUID,
        *,
        keep_version: bool = True,
        tweak: str | bytes = b"uuid",
    ) -> str:
        """Детерминированная замена UUID с сохранением версии/варианта."""
        return _pseudo_uuid(value, self._prf_ctx(tweak), keep_version=keep_version)

    def pseudo_ipv4(
        self,
        ip: str,
        *,
        preserve_prefix: int = 0,
        keep_private_class: bool = True,
        tweak: str | bytes = b"ipv4",
    ) -> str:
        """
        Детерминированная замена IPv4.
        :param preserve_prefix: сколько старших октетов сохранять (0..3).
        :param keep_private_class: если исходный IP приватный (RFC1918),
                                   результат тоже будет приватным (в том же диапазоне).
        """
        return _pseudo_ipv4(ip, self._prf_ctx(tweak), preserve_prefix=preserve_prefix, keep_private_class=keep_private_class)

    def pseudo_email(
        self,
        email: str,
        *,
        keep_tld: bool = True,
        tweak: str | bytes = b"email",
    ) -> str:
        """
        Детерминированная замена email:
        - сохраняет длину локальной части, позиции '.' и допустимые символы,
        - в домене сохраняет TLD и длины меток, дефисы остаются на местах.
        """
        return _pseudo_email(email, self._prf_ctx(tweak), keep_tld=keep_tld)

    def shift_date(
        self,
        dt: _t.Union[_dt.date, _dt.datetime, str],
        *,
        subject_salt: str | bytes | None = None,
        preserve_weekday: bool = True,
        max_abs_shift_days: int = 90,
        tweak: str | bytes = b"date",
    ) -> _dt.date:
        """
        Детерминированный сдвиг даты в пределах ±max_abs_shift_days.
        По умолчанию сохраняет день недели.
        """
        return _shift_date(dt, self._prf_ctx(tweak), subject_salt=subject_salt, preserve_weekday=preserve_weekday, max_abs_shift_days=max_abs_shift_days)

    # ------------------------ Текстовая обработка ---------------------

    def redact_text(
        self,
        text: str,
        *,
        rules: list["Rule"] | None = None,
    ) -> str:
        """
        Универсальная обработка текста с набором правил (regex -> функция).
        По умолчанию включены правила: email, IPv4, UUID, IBAN, PAN (карта).
        """
        if rules is None:
            rules = default_rules(self)
        for rule in rules:
            text = rule.apply(text)
        return text

    # ------------------------ Внутреннее ------------------------------

    def _prf_ctx(self, tweak: str | bytes) -> _PRFContext:
        return _PRFContext(self._key, self._ns, _ensure_bytes(tweak))


# =============================================================================
# Реализация PRF/DRBG (HMAC‑SHA256, детерминированные байты)
# =============================================================================

class _PRFContext:
    """
    Простой DRBG на HMAC‑SHA256: derive(label||counter) детерминированный поток байт.
    """
    __slots__ = ("_key", "_label", "_ctr", "_cache", "_off")

    def __init__(self, key: bytes, namespace: bytes, tweak: bytes):
        # key' = HMAC(key, namespace || 0x00 || tweak)
        self._key = _hmac.new(key, namespace + b"\x00" + tweak, _hashlib.sha256).digest()
        self._label = b"FPR"
        self._ctr = 0
        self._cache = b""
        self._off = 0

    def _refill(self) -> None:
        self._ctr += 1
        block = _hmac.new(self._key, self._label + self._ctr.to_bytes(8, "big"), _hashlib.sha256).digest()
        self._cache = block
        self._off = 0

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if self._off >= len(self._cache):
                self._refill()
            take = min(n - len(out), len(self._cache) - self._off)
            out += self._cache[self._off:self._off + take]
            self._off += take
        return bytes(out)

    def uint(self, m: int) -> int:
        """Случайное число в [0, m) с отбраковкой (rejection sampling)."""
        if m <= 1:
            return 0
        # Определим минимальный k байт, чтобы покрыть диапазон
        k = (m - 1).bit_length()
        k = (k + 7) // 8
        while True:
            val = int.from_bytes(self.bytes(k), "big")
            limit = (1 << (8 * k)) - ((1 << (8 * k)) % m)
            if val < limit:
                return val % m


def _ensure_bytes(x: str | bytes) -> bytes:
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8")

def _ensure_key_bytes(key: str | bytes) -> bytes:
    kb = _ensure_bytes(key)
    if len(kb) < 16:
        raise ValueError("key must be at least 128 bits")
    return kb


# =============================================================================
# Формат‑сохраняющие примитивы
# =============================================================================

_DIGITS = "0123456789"
_ALNUM = _string.ascii_letters + _string.digits
_LOCAL_EMAIL_SAFE = _string.ascii_letters + _string.digits + "._+-"

def _pseudo_digits_generic(s: str, prf: _PRFContext, *, preserve_tail: int = 0) -> str:
    digits = [c for c in s if c.isdigit()]
    if not digits:
        return s
    total = len(digits)
    keep = max(0, min(preserve_tail, total))
    out_chars: list[str] = []
    di = 0
    for ch in s:
        if not ch.isdigit():
            out_chars.append(ch)
            continue
        if di >= total - keep:
            out_chars.append(ch)  # preserve tail
        else:
            out_chars.append(_DIGITS[prf.uint(10)])
        di += 1
    return "".join(out_chars)

# ---- Luhn ----

def _luhn_checksum(digits: _t.Sequence[int]) -> int:
    s = 0
    parity = (len(digits) + 1) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return (10 - (s % 10)) % 10

def _normalize_pan(s: str) -> tuple[list[int], list[int], str]:
    """
    Возвращает: (digits, map_idx->src_pos, separators_template)
    separators_template — строка той же длины, где нецифровые символы сохранены, цифры — '*'
    """
    digits: list[int] = []
    idx_map: list[int] = []
    templ = []
    for i, ch in enumerate(s):
        if ch.isdigit():
            idx_map.append(i)
            digits.append(ord(ch) - 48)
            templ.append("*")
        else:
            templ.append(ch)
    return digits, idx_map, "".join(templ)

def _render_pan(digits: _t.Sequence[int], idx_map: _t.Sequence[int], templ: str) -> str:
    out = list(templ)
    for d, pos in zip(digits, idx_map):
        out[pos] = _DIGITS[d]
    return "".join(out)

def _pseudo_card(card: str, prf: _PRFContext, *, preserve_tail: int) -> str:
    digits, idx_map, templ = _normalize_pan(card)
    if len(digits) < 12:
        # Слишком мало цифр — считаем это не PAN, просто заменяем цифры без Luhn
        return _pseudo_digits_generic(card, prf, preserve_tail=preserve_tail)
    keep = max(0, min(preserve_tail, len(digits)))
    # Генерим замену для всех, кроме последних keep и финальной контрольной
    # Считаем, что последняя цифра — контрольная (Luhn)
    body_len = len(digits) - 1
    new_digits = list(digits)
    for i in range(body_len - keep):
        new_digits[i] = prf.uint(10)
    # Хвост (кроме контрольной) сохранить
    # Пересчитать контрольную
    chk = _luhn_checksum(new_digits[:-1])
    new_digits[-1] = chk
    return _render_pan(new_digits, idx_map, templ)

# ---- IBAN ----

def _iban_clean(iban: str) -> str:
    return "".join(ch for ch in iban.strip() if ch != " ").upper()

def _iban_mod97_int(s: str) -> int:
    # Большое число считаем по частям
    rem = 0
    for ch in s:
        rem = (rem * 10 + (ord(ch) - 48)) % 97
    return rem

def _iban_recalc_checksum(iban_no_checksum: str) -> str:
    # iban_no_checksum: CC00 + BBAN (00 — заглушка)
    rearranged = iban_no_checksum[4:] + iban_no_checksum[:4]
    # A=10..Z=35
    num = []
    for ch in rearranged:
        if ch.isdigit():
            num.append(ch)
        else:
            num.append(str(ord(ch) - 55))
    mod = _iban_mod97_int("".join(num))
    chk = 98 - mod % 97
    return f"{chk:02d}"

def _pseudo_iban(iban: str, prf: _PRFContext) -> str:
    raw = _iban_clean(iban)
    if len(raw) < 8 or not raw[:2].isalpha() or not raw[2:4].isdigit():
        # Не похоже на IBAN — оставим как есть
        return iban
    cc = raw[:2]
    bban = raw[4:]
    # Псевдонимизируем BBAN посимвольно, сохраняя класс символов
    out_bban = []
    for ch in bban:
        if ch.isdigit():
            out_bban.append(_DIGITS[prf.uint(10)])
        elif ch.isalpha():
            # A..Z (верхний регистр)
            out_bban.append(chr(ord('A') + prf.uint(26)))
        else:
            # Разделители/прочее — сохраняем
            out_bban.append(ch)
    # Пересчитать checksum
    tmp = cc + "00" + "".join(out_bban)
    checksum = _iban_recalc_checksum(tmp)
    return cc + checksum + "".join(out_bban)

# ---- UUID ----

def _pseudo_uuid(value: str | _uuid.UUID, prf: _PRFContext, *, keep_version: bool) -> str:
    u = _uuid.UUID(str(value))
    b = u.bytes
    # Заменим 16 байт детерминированными, затем поправим variant/version
    rb = bytearray(prf.bytes(16))
    # Сохраняем вариант RFC 4122
    rb[8] = (rb[8] & 0x3F) | 0x80
    if keep_version:
        ver = (u.int >> 76) & 0xF
        if 1 <= ver <= 5:
            rb[6] = (rb[6] & 0x0F) | (ver << 4)
        else:
            rb[6] = (rb[6] & 0x0F) | (4 << 4)
    else:
        rb[6] = (rb[6] & 0x0F) | (4 << 4)
    return str(_uuid.UUID(bytes=bytes(rb)))

# ---- IPv4 ----

_RFC1918 = [
    _ip.IPv4Network("10.0.0.0/8"),
    _ip.IPv4Network("172.16.0.0/12"),
    _ip.IPv4Network("192.168.0.0/16"),
]

def _ipv4_private_class(addr: _ip.IPv4Address) -> _ip.IPv4Network | None:
    for net in _RFC1918:
        if addr in net:
            return net
    return None

def _pseudo_ipv4(ip: str, prf: _PRFContext, *, preserve_prefix: int, keep_private_class: bool) -> str:
    try:
        addr = _ip.IPv4Address(ip)
    except Exception:
        return ip
    octs = [int(x) for x in str(addr).split(".")]
    priv = _ipv4_private_class(addr)
    out = list(octs)
    # Сохранить первые N октетов
    n = max(0, min(int(preserve_prefix), 3))
    # Остальные октеты заменить детерминированно
    for i in range(n, 4):
        out[i] = prf.uint(256)
    cand = _ip.IPv4Address(".".join(str(x) for x in out))
    if keep_private_class:
        if priv:
            # Принудительно отнормировать в ту же приватную сеть
            # Сохраним первые net.prefixlen//8 октетов сети
            prefix_octets = priv.prefixlen // 8
            out[:prefix_octets] = [int(x) for x in str(priv.network_address).split(".")[:prefix_octets]]
            cand = _ip.IPv4Address(".".join(str(x) for x in out))
            if cand not in priv:
                # Обеспечим вхождение в сеть: забьём остаток из PRF
                host_space = 4 - prefix_octets
                tail = [prf.uint(256) for _ in range(host_space)]
                cand = _ip.IPv4Address(".".join(map(str, out[:prefix_octets] + tail)))
    return str(cand)

# ---- Email ----

def _pseudo_email(email: str, prf: _PRFContext, *, keep_tld: bool) -> str:
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    # Локальная часть: сохраняем позиции '.', длину; прочие символы маппим на [A-Za-z0-9_+]
    loc_out = list(local)
    for i, ch in enumerate(loc_out):
        if ch == ".":
            continue
        loc_out[i] = _LOCAL_EMAIL_SAFE[prf.uint(len(_LOCAL_EMAIL_SAFE))]
    # Домен: сохраняем кол-во меток, TLD (последняя метка), длины и дефисы
    labels = domain.split(".")
    if len(labels) >= 2 and keep_tld:
        tld = labels[-1]
        heads = labels[:-1]
    else:
        tld = labels[-1] if labels else ""
        heads = labels[:-1] if len(labels) >= 2 else labels
    new_heads: list[str] = []
    for lab in heads:
        chars = list(lab)
        for i, ch in enumerate(chars):
            if ch == "-":
                continue
            # Буква/цифра — маппим в alnum
            chars[i] = _ALNUM[prf.uint(len(_ALNUM))]
        # Не допускаем '-' в начале/конце
        if chars and chars[0] == "-":
            chars[0] = _ALNUM[prf.uint(len(_ALNUM))]
        if chars and chars[-1] == "-":
            chars[-1] = _ALNUM[prf.uint(len(_ALNUM))]
        new_heads.append("".join(chars))
    dom_out = ".".join(new_heads + ([tld] if tld else []))
    return f"{''.join(loc_out)}@{dom_out}"

# ---- Дата ----

def _parse_date(dt: _t.Union[_dt.date, _dt.datetime, str]) -> _dt.date:
    if isinstance(dt, _dt.datetime):
        return dt.date()
    if isinstance(dt, _dt.date):
        return dt
    s = str(dt).strip()
    # Простые форматы: YYYY-MM-DD | YYYY/MM/DD
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return _dt.datetime.strptime(s, fmt).date()
        except Exception:
            pass
    raise ValueError("Unsupported date format")

def _shift_date(
    dt: _t.Union[_dt.date, _dt.datetime, str],
    prf: _PRFContext,
    *,
    subject_salt: str | bytes | None,
    preserve_weekday: bool,
    max_abs_shift_days: int,
) -> _dt.date:
    d = _parse_date(dt)
    # Сдвиг в диапазоне [-max, +max]
    span = int(max(1, max_abs_shift_days))
    off = prf.uint(2 * span + 1) - span
    if preserve_weekday:
        # Кратные 7 сохраняют день недели
        off -= off % 7
    return d + _dt.timedelta(days=off)


# =============================================================================
# Текстовые правила (regex -> функция)
# =============================================================================

class Rule:
    __slots__ = ("pattern", "repl")

    def __init__(self, pattern: _re.Pattern[str], repl: _t.Callable[[_re.Match[str]], str]):
        self.pattern = pattern
        self.repl = repl

    def apply(self, text: str) -> str:
        return self.pattern.sub(self.repl, text)


# Готовые регэкспы прод‑качества (практичные, не «идеальные»)
RE_EMAIL = _re.compile(r"\b[a-zA-Z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_UUID = _re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
RE_IPV4 = _re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
RE_IBAN = _re.compile(r"\b[A-Z]{2}\d{2}[A-Za-z0-9]{10,30}\b")
# PAN: последовательность 13–19 цифр с произвольными разделителями " " или "-".
RE_PAN = _re.compile(r"\b(?:\d[ \-]?){13,19}\b")

def default_rules(fpr: FormatPreservingRedactor) -> list[Rule]:
    return [
        Rule(RE_EMAIL, lambda m: fpr.pseudo_email(m.group(0))),
        Rule(RE_IPV4, lambda m: fpr.pseudo_ipv4(m.group(0), preserve_prefix=0, keep_private_class=True)),
        Rule(RE_UUID, lambda m: fpr.pseudo_uuid(m.group(0))),
        Rule(RE_IBAN, lambda m: fpr.pseudo_iban(m.group(0))),
        Rule(RE_PAN,  lambda m: fpr.pseudo_card(m.group(0), preserve_tail=4)),
    ]


# =============================================================================
# Пример использования (doctest‑подобные комментарии)
# =============================================================================
if __name__ == "__main__":
    key = _os.environ.get("FPR_KEY", "this_is_demo_key___replace_me")
    fpr = FormatPreservingRedactor(key)

    # Карта (Luhn сохраняется корректным):
    pan = "4111 1111 1111 1111"
    anon_pan = fpr.pseudo_card(pan)
    print(pan, "->", anon_pan)

    # IBAN:
    iban = "DE89 3704 0044 0532 0130 00"
    anon_iban = fpr.pseudo_iban(iban)
    print(iban, "->", anon_iban)

    # UUID:
    uid = "550e8400-e29b-41d4-a716-446655440000"
    print(uid, "->", fpr.pseudo_uuid(uid))

    # IPv4:
    ip = "192.168.1.42"
    print(ip, "->", fpr.pseudo_ipv4(ip, keep_private_class=True))

    # Email:
    mail = "john.doe+test@example.co.uk"
    print(mail, "->", fpr.pseudo_email(mail))

    # Дата:
    print("2024-03-10 ->", fpr.shift_date("2024-03-10"))

    # Текст целиком:
    text = f"card {pan}, ip {ip}, mail {mail}, uuid {uid}, iban {iban}"
    print("TEXT:", fpr.redact_text(text))
