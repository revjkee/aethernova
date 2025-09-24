# veilmind-core/veilmind/redact/tokenization.py
# -*- coding: utf-8 -*-
"""
Industrial tokenization module for veilmind-core.

Features:
- Tokenizer interface with sync API
- Local deterministic (irreversible) tokenization using HMAC-SHA256 + HKDF
  * format-preserving mapping for PAN/IBAN/email/alphanumeric
  * Luhn checksum recomputation for PAN
  * IBAN check digits recomputation (mod 97)
- Optional reversible tokenization via external HTTP provider (VaultTokenizer)
- Key management via KeyProvider (Env -> HKDF per-purpose subkeys)
- Strict validation, safe logging (no secrets in logs), input size limits
- Optional OpenTelemetry propagation (if installed)

No plaintext secrets are logged. All configuration via environment variables
or explicit parameters. Designed for Zero Trust environments.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:
    import httpx  # optional, only for VaultTokenizer
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

# Optional OpenTelemetry propagation
try:  # pragma: no cover
    from opentelemetry.propagate import inject as otel_inject  # type: ignore
except Exception:  # pragma: no cover
    otel_inject = None

__all__ = [
    "TokenizerConfig",
    "TokenizationError",
    "DetokenizationError",
    "KeyProvider",
    "EnvKeyProvider",
    "Tokenizer",
    "LocalDeterministicTokenizer",
    "VaultTokenizer",
    "from_env",
]

# ---------------------------------------------------------------------
# Logging (secret-safe)
# ---------------------------------------------------------------------

_LOG = logging.getLogger("veilmind.tokenization")
if not _LOG.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    _LOG.addHandler(_handler)
_LOG.setLevel(logging.INFO)

_REDACT_MASK = "[REDACTED]"
_DENY_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token", "id_token",
    "authorization", "api_key", "apikey", "cookie", "set-cookie", "private_key",
    "client_secret", "db_password", "jwt", "otp", "session"
}
_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),
    re.compile(r"\b\d{13,19}\b"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(r"(?i)\+?[0-9][0-9\-\s()]{7,}"),
    re.compile(r"(?i)\b(pwd|pass(word)?|secret|token|key)\b\s*[:=]\s*\S+"),
]


def _redact_text(s: str, max_len: int = 1024) -> str:
    out = s
    for rx in _PATTERNS:
        out = rx.sub(_REDACT_MASK, out)
    if len(out) > max_len:
        out = out[:max_len] + "...(truncated)"
    return out


def _safe_log_kv(k: str, v: str) -> str:
    if k.lower() in _DENY_KEYS or k.lower() in {"authorization", "cookie", "set-cookie"}:
        return f"{k}={_REDACT_MASK}"
    return f"{k}={_redact_text(v)}"


# ---------------------------------------------------------------------
# Exceptions and config
# ---------------------------------------------------------------------

class TokenizationError(Exception):
    pass


class DetokenizationError(Exception):
    pass


@dataclass
class TokenizerConfig:
    """
    Config for tokenization.
    """
    # general
    max_input_len: int = 4096
    # key provider
    key_provider: "KeyProvider" | None = None
    # domain separation (feeds HKDF info)
    domain_tag: str = "veilmind-core/tokenization"
    # email tokenization options
    email_local_keep: int = 1  # characters to keep in local part prefix
    # http provider (for VaultTokenizer)
    provider_url: Optional[str] = None
    provider_timeout_s: float = 5.0
    provider_verify: bool | str = True  # TLS verification
    provider_cert: Optional[str | Tuple[str, str]] = None
    provider_headers: Dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.provider_headers is None:
            self.provider_headers = {}


# ---------------------------------------------------------------------
# Key management (HKDF derivation per purpose)
# ---------------------------------------------------------------------

class KeyProvider:
    def get_key(self, purpose: str) -> bytes:
        raise NotImplementedError


class EnvKeyProvider(KeyProvider):
    """
    Reads a base64-encoded master key from environment var VEILMIND_TOKENIZATION_KEY
    and derives subkeys using HKDF-SHA256 for each 'purpose'.
    """
    def __init__(self, env_var: str = "VEILMIND_TOKENIZATION_KEY", salt_env: str = "VEILMIND_TOKENIZATION_SALT"):
        self.env_var = env_var
        self.salt_env = salt_env

    def _get_master(self) -> Tuple[bytes, bytes]:
        raw = os.getenv(self.env_var, "")
        if not raw:
            raise TokenizationError(f"master key env var {self.env_var} is not set")
        try:
            master = base64.b64decode(raw, validate=True)
        except Exception as e:
            raise TokenizationError("failed to decode master key (base64)") from e
        if len(master) < 32:
            raise TokenizationError("master key must be at least 32 bytes (after base64 decode)")
        salt_raw = os.getenv(self.salt_env, "")
        salt = base64.b64decode(salt_raw, validate=True) if salt_raw else b"\x00" * 16
        return master, salt

    def get_key(self, purpose: str) -> bytes:
        master, salt = self._get_master()
        # HKDF-Extract
        prk = hmac.new(salt, master, hashlib.sha256).digest()
        # HKDF-Expand (single block sufficient for 32 bytes)
        info = f"veilmind-hkdf:{purpose}".encode("utf-8")
        t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        return t  # 32 bytes


# ---------------------------------------------------------------------
# Utilities: Luhn and IBAN
# ---------------------------------------------------------------------

def luhn_checksum(number: str) -> int:
    s = 0
    alt = False
    for ch in reversed(number):
        d = ord(ch) - 48
        if d < 0 or d > 9:
            raise ValueError("non-digit in PAN body")
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10


def luhn_is_valid(pan: str) -> bool:
    pan_digits = re.sub(r"\D", "", pan)
    if len(pan_digits) < 13 or len(pan_digits) > 19:
        return False
    return luhn_checksum(pan_digits) == 0


def luhn_add_check_digit(body: str) -> str:
    # body must be digits without check
    chk = (10 - luhn_checksum(body + "0")) % 10
    return body + str(chk)


_IBAN_ALPHA = {c: i for i, c in enumerate(string.ascii_uppercase, start=10)}
_IBAN_ALLOWED = set(string.ascii_uppercase + string.digits)


def iban_normalize(iban: str) -> str:
    s = re.sub(r"\s+", "", iban).upper()
    if not s or any(ch not in _IBAN_ALLOWED for ch in s):
        raise ValueError("invalid IBAN characters")
    return s


def iban_compute_check_digits(iban_no_check: str) -> str:
    # iban_no_check is like "CC" + "rest" without 2-digit check
    # IBAN check computed on rearranged string
    tmp = iban_no_check[4:] + iban_no_check[:4]
    conv = ""
    for ch in tmp:
        if ch.isdigit():
            conv += ch
        else:
            conv += str(_IBAN_ALPHA[ch])
    mod = int(conv) % 97
    chk = 98 - mod
    return f"{chk:02d}"


# ---------------------------------------------------------------------
# Core mapping: HMAC to format-preserving projection (irreversible)
# ---------------------------------------------------------------------

_BASE36 = string.digits + string.ascii_uppercase
_BASE10 = string.digits


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _project_to_alphabet(digest: bytes, length: int, alphabet: str) -> str:
    """
    Deterministically project digest to string over given alphabet with fixed length.
    Not a PRP; suitable for irreversible deterministic tokenization.
    """
    if length <= 0:
        return ""
    base = len(alphabet)
    if base < 2:
        raise ValueError("alphabet too small")
    # Expand digest if needed using counter-mode HMAC
    stream = bytearray()
    counter = 0
    while len(stream) < length * 2:
        block = _hmac_sha256(digest, counter.to_bytes(4, "big"))
        stream.extend(block)
        counter += 1
    # Convert bytes to digits in given base
    out = []
    acc = int.from_bytes(stream, "big")
    for _ in range(length):
        acc, rem = divmod(acc, base)
        out.append(alphabet[rem])
    return "".join(out)


def _tokenize_digits_preserve_length(value_digits: str, key: bytes, tweak: str = "") -> str:
    """
    Irreversible deterministic mapping of digits preserving length.
    Recomputes Luhn elsewhere when needed (PAN).
    """
    dig = _hmac_sha256(key, (tweak + ":" + value_digits).encode("utf-8"))
    return _project_to_alphabet(dig, len(value_digits), _BASE10)


def _tokenize_base36_preserve(value: str, key: bytes, tweak: str = "") -> str:
    dig = _hmac_sha256(key, (tweak + ":" + value).encode("utf-8"))
    return _project_to_alphabet(dig, len(value), _BASE36)


# ---------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------

class Tokenizer:
    """
    Tokenization interface. Implementations may be irreversible (deterministic)
    or reversible (via external provider). All methods must be side-effect free.
    """
    def tokenize_pan(self, pan: str) -> str:
        raise NotImplementedError

    def tokenize_iban(self, iban: str) -> str:
        raise NotImplementedError

    def tokenize_email(self, email: str) -> str:
        raise NotImplementedError

    def tokenize_text(self, value: str, *, alphabet: str = _BASE36) -> str:
        raise NotImplementedError

    # Reversible contracts (optional)
    def detokenize_text(self, token: str) -> str:
        raise DetokenizationError("detokenization is not supported by this tokenizer")


# ---------------------------------------------------------------------
# Local deterministic tokenizer (irreversible, format-preserving)
# ---------------------------------------------------------------------

class LocalDeterministicTokenizer(Tokenizer):
    """
    Irreversible deterministic tokenizer with format preservation.
    Uses HMAC-SHA256 with HKDF-derived subkeys per field type to avoid
    cross-domain correlation. No secrets are logged.
    """
    def __init__(self, cfg: TokenizerConfig):
        if cfg.key_provider is None:
            cfg.key_provider = EnvKeyProvider()
        self.cfg = cfg
        self._k_pan = cfg.key_provider.get_key(cfg.domain_tag + "/pan")
        self._k_iban = cfg.key_provider.get_key(cfg.domain_tag + "/iban")
        self._k_email = cfg.key_provider.get_key(cfg.domain_tag + "/email")
        self._k_text = cfg.key_provider.get_key(cfg.domain_tag + "/text")

    def _ensure_len(self, s: str) -> None:
        if len(s) > self.cfg.max_input_len:
            raise TokenizationError("input too large")

    # ---- PAN ----
    def tokenize_pan(self, pan: str) -> str:
        """
        Tokenizes Primary Account Number preserving length and formatting.
        Recomputes Luhn check digit.
        """
        self._ensure_len(pan)
        # Keep original separators
        digits = re.sub(r"\D", "", pan)
        if len(digits) < 13 or len(digits) > 19:
            raise TokenizationError("PAN length is invalid")
        body, check = digits[:-1], digits[-1]
        tok_body = _tokenize_digits_preserve_length(body, self._k_pan, tweak="pan-body")
        tok = luhn_add_check_digit(tok_body)
        # reinsert separators
        out = []
        di = 0
        for ch in pan:
            if ch.isdigit():
                out.append(tok[di])
                di += 1
            else:
                out.append(ch)
        token = "".join(out)
        # best-effort validation
        if not luhn_is_valid(token):
            # Should not happen due to recomputation
            raise TokenizationError("internal luhn error")
        return token

    # ---- IBAN ----
    def tokenize_iban(self, iban: str) -> str:
        """
        Tokenizes IBAN keeping country code and length, recomputes check digits.
        """
        self._ensure_len(iban)
        s = iban_normalize(iban)  # no spaces, upper
        if len(s) < 8 or len(s) > 34:
            raise TokenizationError("IBAN length is invalid")
        country = s[:2]
        if not country.isalpha():
            raise TokenizationError("invalid IBAN country code")
        # Replace body after 4 chars, recompute 2-digit check
        no_check = s[:2] + "00" + s[4:]
        body = s[4:]
        # map body using base36 preserve
        mapped = _tokenize_base36_preserve(body, self._k_iban, tweak=f"iban:{country}")
        rebuilt = country + iban_compute_check_digits(no_check[:2] + "00" + mapped) + mapped
        # keep original spacing
        grp = " ".join(re.findall(".{1,4}", rebuilt))
        return grp

    # ---- Email ----
    def tokenize_email(self, email: str) -> str:
        """
        Tokenizes or masks email: keeps a prefix of local-part and full domain,
        replaces the remainder with deterministic base36 token.
        """
        self._ensure_len(email)
        m = re.match(r"^(?P<local>[^@]+)@(?P<domain>[^@]+)$", email.strip())
        if not m:
            raise TokenizationError("invalid email format")
        local = m.group("local")
        domain = m.group("domain")
        keep = max(0, min(self.cfg.email_local_keep, len(local)))
        prefix = local[:keep]
        rest = local[keep:]
        token_rest = _tokenize_base36_preserve(rest or "x", self._k_email, tweak=f"email:{domain}")
        # limit length of token to original rest length
        token_rest = token_rest[: len(rest)] if rest else token_rest[:1]
        return f"{prefix}{token_rest}@{domain}"

    # ---- Generic text ----
    def tokenize_text(self, value: str, *, alphabet: str = _BASE36) -> str:
        self._ensure_len(value)
        dig = _hmac_sha256(self._k_text, f"text:{value}".encode("utf-8"))
        return _project_to_alphabet(dig, len(value), alphabet)


# ---------------------------------------------------------------------
# Reversible tokenizer via HTTP provider (optional)
# ---------------------------------------------------------------------

class VaultTokenizer(Tokenizer):
    """
    Reversible tokenizer that delegates to an external provider over HTTPS.
    Requires `httpx`. The provider must implement endpoints:
      POST /v1/tokenize  { "type": "...", "value": "...", "options": {...} } -> { "token": "..." }
      POST /v1/detokenize { "type": "...", "token": "...", "options": {...} } -> { "value": "..." }
    All requests include Content-SHA256 integrity header and OTEL propagation (if available).
    """
    def __init__(self, cfg: TokenizerConfig, *, auth_token: Optional[str] = None):
        if httpx is None:  # pragma: no cover
            raise TokenizationError("httpx is required for VaultTokenizer")
        if not cfg.provider_url:
            raise TokenizationError("provider_url is required for VaultTokenizer")
        self.cfg = cfg
        self.auth_token = auth_token
        self._client = httpx.Client(
            base_url=cfg.provider_url.rstrip("/"),
            timeout=cfg.provider_timeout_s,
            verify=cfg.provider_verify,
            headers=dict(cfg.provider_headers),
            cert=cfg.provider_cert,
        )
        if auth_token:
            self._client.headers["Authorization"] = f"Bearer {auth_token}"

    def _headers(self, payload: Mapping[str, Any]) -> Dict[str, str]:
        hdrs: Dict[str, str] = {"Accept": "application/json"}
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        hdrs["Content-SHA256"] = hashlib.sha256(raw).hexdigest()
        if otel_inject is not None:  # pragma: no cover
            try:
                otel_inject(lambda k, v: hdrs.__setitem__(k, v))  # type: ignore
            except Exception:
                pass
        return hdrs

    def _post(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        hdrs = self._headers(payload)
        try:
            resp = self._client.post(path, json=payload, headers=hdrs)
        except Exception as e:
            raise TokenizationError(f"provider request failed: {e}") from e
        if resp.status_code == 401:
            raise DetokenizationError("unauthorized from provider")
        if resp.status_code == 404:
            raise DetokenizationError("operation not supported by provider")
        if resp.status_code >= 400:
            body = resp.text
            msg = f"provider error {resp.status_code}"
            raise TokenizationError(msg + f" body={_redact_text(body)}")
        try:
            return resp.json()
        except Exception as e:
            raise TokenizationError("invalid provider JSON") from e

    # --- Tokenize ---
    def tokenize_pan(self, pan: str) -> str:
        payload = {"type": "pan", "value": pan}
        data = self._post("/v1/tokenize", payload)
        return str(data.get("token"))

    def tokenize_iban(self, iban: str) -> str:
        payload = {"type": "iban", "value": iban}
        data = self._post("/v1/tokenize", payload)
        return str(data.get("token"))

    def tokenize_email(self, email: str) -> str:
        payload = {"type": "email", "value": email, "options": {"keep": self.cfg.email_local_keep}}
        data = self._post("/v1/tokenize", payload)
        return str(data.get("token"))

    def tokenize_text(self, value: str, *, alphabet: str = _BASE36) -> str:
        payload = {"type": "text", "value": value, "options": {"alphabet": alphabet}}
        data = self._post("/v1/tokenize", payload)
        return str(data.get("token"))

    # --- Detokenize ---
    def detokenize_text(self, token: str) -> str:
        payload = {"type": "text", "token": token}
        data = self._post("/v1/detokenize", payload)
        return str(data.get("value"))


# ---------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------

def from_env() -> Tokenizer:
    """
    Factory that returns a Tokenizer based on environment variables.

    VEILMIND_TOKENIZATION_MODE = local | vault
    VEILMIND_TOKENIZATION_KEY = base64 master key (for 'local')
    VEILMIND_TOKENIZATION_SALT = base64 salt (optional, for 'local')

    For 'vault':
      VEILMIND_TOKENIZATION_PROVIDER_URL = https://provider.example
      VEILMIND_TOKENIZATION_PROVIDER_TOKEN = bearer token (optional)
      VEILMIND_TOKENIZATION_PROVIDER_VERIFY = true|false|/path/to/ca.pem
    """
    mode = os.getenv("VEILMIND_TOKENIZATION_MODE", "local").lower()
    if mode not in {"local", "vault"}:
        raise TokenizationError("unsupported tokenization mode")

    if mode == "local":
        cfg = TokenizerConfig(key_provider=EnvKeyProvider())
        _LOG.info("Tokenizer mode=local")
        return LocalDeterministicTokenizer(cfg)

    # vault mode
    url = os.getenv("VEILMIND_TOKENIZATION_PROVIDER_URL", "")
    if not url:
        raise TokenizationError("VEILMIND_TOKENIZATION_PROVIDER_URL is required for vault mode")
    verify_env = os.getenv("VEILMIND_TOKENIZATION_PROVIDER_VERIFY", "true").lower()
    if verify_env in {"true", "1", "yes"}:
        verify: bool | str = True
    elif verify_env in {"false", "0", "no"}:
        verify = False
    else:
        verify = verify_env  # path to CA bundle
    cfg = TokenizerConfig(
        provider_url=url,
        provider_verify=verify,
        provider_timeout_s=float(os.getenv("VEILMIND_TOKENIZATION_PROVIDER_TIMEOUT", "5")),
        provider_headers={},
    )
    token = os.getenv("VEILMIND_TOKENIZATION_PROVIDER_TOKEN")
    _LOG.info("Tokenizer mode=vault")
    return VaultTokenizer(cfg, auth_token=token)
