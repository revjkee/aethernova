# datafabric-core/datafabric/processing/transforms/masking.py
# Industrial-grade data masking & tokenization for DataFabric
# Features:
# - Declarative masking policies per field and by PII type
# - Strategies: redact, partial, hash, hmac_token (deterministic), encrypt (AES-GCM optional),
#               generalize (date), noise (DP-lite), bucketize (numeric)
# - Deterministic tokens with key versioning & namespace
# - PII detector (email/phone/cc/iban/ssn/ip) with safe auditing
# - Spark UDF integration + Pandas/vanilla Python
# - Pluggable KeyProviders and CipherAdapters
# - Safe logging (no raw values), strict type handling
#
# NOTE: For reversible encryption, install 'cryptography' on Spark executors (optional).
#       Exactly-once semantics are managed by upstream streaming engine.

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hmac
import hashlib
import json
import math
import os
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Callable, Iterable, Mapping, Tuple, List, Union

try:
    # optional dependency for AES-GCM
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _CRYPTO_AVAILABLE = True
except Exception:
    AESGCM = None  # type: ignore
    _CRYPTO_AVAILABLE = False

# --------- Key Providers ---------

class KeyProvider:
    """Abstract key provider with versioning support."""
    def get_key(self, purpose: str, version: Optional[str] = None) -> Tuple[bytes, str]:
        raise NotImplementedError

class EnvKeyProvider(KeyProvider):
    """
    Fetch keys from environment variables (e.g. DF_KEY_TOKEN_V1, DF_KEY_ENC_V1).
    Keys are base64url or hex; version picked from DF_KEY_VERSION_{PURPOSE} or explicit arg.
    """
    def __init__(self, prefix: str = "DF_KEY_"):
        self.prefix = prefix

    def _decode(self, raw: str) -> bytes:
        raw = raw.strip()
        # try base64url then hex
        try:
            return base64.urlsafe_b64decode(raw + "==")
        except Exception:
            return bytes.fromhex(raw)

    def get_key(self, purpose: str, version: Optional[str] = None) -> Tuple[bytes, str]:
        purpose = purpose.upper()
        v = version or os.getenv(f"{self.prefix}VERSION_{purpose}", "V1")
        env_name = f"{self.prefix}{purpose}_{v}"
        raw = os.getenv(env_name)
        if not raw:
            raise RuntimeError(f"Missing key in env: {env_name}")
        return self._decode(raw), v

class StaticKeyProvider(KeyProvider):
    """In-memory keys (useful for tests)."""
    def __init__(self, keys: Mapping[Tuple[str, str], bytes]):
        self._keys = dict(keys)

    def get_key(self, purpose: str, version: Optional[str] = None) -> Tuple[bytes, str]:
        purpose = purpose.upper()
        if version is None:
            # pick first matching version
            for (p, v), k in self._keys.items():
                if p == purpose:
                    return k, v
            raise RuntimeError(f"No key for purpose={purpose}")
        k = self._keys.get((purpose, version))
        if not k:
            raise RuntimeError(f"No key for purpose={purpose}, version={version}")
        return k, version

# --------- Cipher Adapters ---------

class CipherAdapter:
    def encrypt(self, key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        raise NotImplementedError

    def decrypt(self, key: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        raise NotImplementedError

class AESGCMAdapter(CipherAdapter):
    """AES-GCM with 12-byte nonce: outputs nonce||ciphertext."""
    def __init__(self):
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography is not available for AES-GCM")

    def encrypt(self, key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        nonce = secrets.token_bytes(12)
        aes = AESGCM(key)
        ct = aes.encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, key: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        nonce, ct = ciphertext[:12], ciphertext[12:]
        aes = AESGCM(key)
        return aes.decrypt(nonce, ct, aad)

# --------- PII Patterns ---------

PII_REGEX = {
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b"),
    "cc": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I),
}

def detect_pii_types(s: str) -> List[str]:
    if not s:
        return []
    found = []
    for name, rgx in PII_REGEX.items():
        if rgx.search(s):
            found.append(name)
    return found

# --------- Policies & Strategies ---------

@dataclass
class StrategyContext:
    namespace: str
    token_version: str
    provider: KeyProvider
    cipher: Optional[CipherAdapter] = None

# Redaction
def _redact(_: StrategyContext, value: Any, **kw) -> Any:
    return kw.get("replacement", "REDACTED")

# Partial keep
def _partial(_: StrategyContext, value: Any, **kw) -> Any:
    if value is None:
        return None
    s = str(value)
    keep_left = int(kw.get("keep_left", 0))
    keep_right = int(kw.get("keep_right", 4))
    fill = kw.get("fill", "*")
    mid = max(0, len(s) - keep_left - keep_right)
    return s[:keep_left] + (fill * mid) + s[-keep_right:] if len(s) > keep_left + keep_right else s

# SHA256 (salted, non-reversible)
def _hash(_: StrategyContext, value: Any, **kw) -> str:
    if value is None:
        return None
    salt = kw.get("salt", "").encode("utf-8")
    return hashlib.sha256(salt + str(value).encode("utf-8")).hexdigest()

# Deterministic HMAC token (non-reversible)
def _hmac_token(ctx: StrategyContext, value: Any, **kw) -> str:
    if value is None:
        return None
    key, ver = ctx.provider.get_key("TOKEN", ctx.token_version)
    msg = f"{ctx.namespace}|{ver}|{kw.get('label','field')}|{str(value)}".encode("utf-8")
    tag = hmac.new(key, msg, hashlib.sha256).digest()
    # shorten to requested length but keep collision resistance reasonable
    ln = int(kw.get("length", 22))
    return base64.urlsafe_b64encode(tag).decode("ascii").rstrip("=").[:ln]

# Reversible encryption (AES-GCM)
def _encrypt(ctx: StrategyContext, value: Any, **kw) -> str:
    if value is None:
        return None
    if not ctx.cipher:
        raise RuntimeError("Cipher adapter is not configured")
    key, ver = ctx.provider.get_key("ENC", kw.get("version", ctx.token_version))
    aad = f"{ctx.namespace}|{ver}|{kw.get('label','field')}".encode("utf-8")
    ct = ctx.cipher.encrypt(key, str(value).encode("utf-8"), aad)
    return "enc:" + base64.urlsafe_b64encode(ct).decode("ascii").rstrip("=")

def _decrypt(ctx: StrategyContext, token: str, **kw) -> Optional[str]:
    if not token:
        return None
    if not token.startswith("enc:"):
        return None
    if not ctx.cipher:
        raise RuntimeError("Cipher adapter is not configured")
    b64 = token[4:]
    raw = base64.urlsafe_b64decode(b64 + "==")
    key, ver = ctx.provider.get_key("ENC", kw.get("version", ctx.token_version))
    aad = f"{ctx.namespace}|{ver}|{kw.get('label','field')}".encode("utf-8")
    pt = ctx.cipher.decrypt(key, raw, aad)
    return pt.decode("utf-8")

# Date generalization
def _generalize_date(_: StrategyContext, value: Any, **kw) -> Any:
    if value is None:
        return None
    gran = kw.get("granularity", "month")  # day|week|month|quarter|year
    if isinstance(value, str):
        try:
            value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return value  # cannot parse, return original
    if isinstance(value, dt.datetime):
        d = value.date()
    elif isinstance(value, dt.date):
        d = value
    else:
        return value
    if gran == "day":
        return d.isoformat()
    if gran == "week":
        y, w, _ = d.isocalendar()
        return f"{y}-W{w:02d}"
    if gran == "quarter":
        q = (d.month - 1) // 3 + 1
        return f"{d.year}-Q{q}"
    if gran == "year":
        return str(d.year)
    # month default
    return f"{d.year}-{d.month:02d}"

# Numeric noise (DP-lite; independent noise)
def _noise(_: StrategyContext, value: Any, **kw) -> Any:
    if value is None:
        return None
    try:
        x = float(value)
    except Exception:
        return value
    epsilon = float(kw.get("epsilon", 5.0))
    if epsilon <= 0:
        return value
    # Laplace-like from Python stdlib: inverse transform using secrets for seed entropy
    u = (secrets.randbits(32) / 2**32) - 0.5
    scale = 1.0 / epsilon
    noise = -scale * math.copysign(math.log(1 - 2 * abs(u)), u)
    return type(value)(x + noise) if isinstance(value, int) else x + noise

# Bucketize numeric
def _bucketize(_: StrategyContext, value: Any, **kw) -> str:
    if value is None:
        return None
    try:
        x = float(value)
    except Exception:
        return "unknown"
    bins: List[float] = kw.get("bins") or [-math.inf, 0, 100, 1000, 10000, math.inf]
    labels: List[str] = kw.get("labels") or ["neg", "0-100", "100-1k", "1k-10k", "10k+"]
    # find right bin
    for i in range(len(bins) - 1):
        if bins[i] <= x < bins[i+1]:
            return labels[i] if i < len(labels) else f"{bins[i]}..{bins[i+1]}"
    return labels[-1]

STRATEGIES: Dict[str, Callable[..., Any]] = {
    "redact": _redact,
    "partial": _partial,
    "hash": _hash,
    "hmac_token": _hmac_token,
    "encrypt": _encrypt,
    "decrypt": _decrypt,  # rarely exposed; for service-side unmasking
    "generalize_date": _generalize_date,
    "noise": _noise,
    "bucketize": _bucketize,
}

# --------- Policy Model ---------

@dataclass
class FieldRule:
    strategy: str
    params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MaskingPolicy:
    """
    Example:
    {
      "namespace": "datafabric.customer",
      "token_version": "V1",
      "fields": {
        "email": {"strategy": "hmac_token", "params": {"length": 20, "label": "email"}},
        "phone": {"strategy": "partial", "params": {"keep_left": 0, "keep_right": 4}},
        "ssn":   {"strategy": "encrypt", "params": {"label": "ssn"}},
        "birth_date": {"strategy": "generalize_date", "params": {"granularity": "year"}},
        "income": {"strategy": "bucketize", "params": {"bins": [0, 1000, 5000, 10000, 999999], "labels": ["0-1k","1-5k","5-10k","10k+"]}}
      },
      "pii_defaults": {
        "email": {"strategy": "partial", "params": {"keep_left": 1, "keep_right": 3}},
        "cc": {"strategy": "partial", "params": {"keep_right": 4}},
        "iban": {"strategy": "partial", "params": {"keep_right": 4}},
        "phone": {"strategy": "partial", "params": {"keep_right": 4}}
      }
    }
    """
    namespace: str
    token_version: str = "V1"
    fields: Dict[str, FieldRule] = field(default_factory=dict)
    pii_defaults: Dict[str, FieldRule] = field(default_factory=dict)

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "MaskingPolicy":
        fields = {k: FieldRule(**v) for k, v in (d.get("fields") or {}).items()}
        pii = {k: FieldRule(**v) for k, v in (d.get("pii_defaults") or {}).items()}
        return MaskingPolicy(
            namespace=d.get("namespace", "datafabric"),
            token_version=d.get("token_version", "V1"),
            fields=fields,
            pii_defaults=pii,
        )

# --------- Masker Core ---------

class Masker:
    def __init__(
        self,
        policy: MaskingPolicy,
        provider: Optional[KeyProvider] = None,
        cipher: Optional[CipherAdapter] = None,
        safe_audit: bool = True,
    ):
        self.policy = policy
        self.provider = provider or EnvKeyProvider()
        self.cipher = cipher
        self.safe_audit = safe_audit

    def _ctx(self) -> StrategyContext:
        return StrategyContext(
            namespace=self.policy.namespace,
            token_version=self.policy.token_version,
            provider=self.provider,
            cipher=self.cipher,
        )

    def apply_value(self, field: str, value: Any) -> Any:
        rule = self.policy.fields.get(field)
        if rule is None:
            # fallback by PII detection (strings only)
            if isinstance(value, str):
                for t in detect_pii_types(value):
                    r = self.policy.pii_defaults.get(t)
                    if r:
                        fn = STRATEGIES[r.strategy]
                        return fn(self._ctx(), value, label=field, **(r.params or {}))
            return value  # no masking
        fn = STRATEGIES.get(rule.strategy)
        if not fn:
            raise ValueError(f"Unknown strategy: {rule.strategy}")
        return fn(self._ctx(), value, label=field, **(rule.params or {}))

    def mask_record(self, rec: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in rec.items():
            try:
                out[k] = self.apply_value(k, v)
            except Exception as e:
                # fail-safe: redact on error, add minimal audit hint
                out[k] = "REDACTED"
                if not self.safe_audit:
                    out[f"__mask_error_{k}"] = str(e)
        return out

    # ----- Pandas helpers -----
    def mask_pandas_df(self, df) -> "pandas.DataFrame":  # noqa
        import pandas as pd  # lazy import
        def _mask_series(col: pd.Series, name: str) -> pd.Series:
            rule = self.policy.fields.get(name)
            if rule is None and col.dtype == object:
                return col.apply(lambda x: self.apply_value(name, x))
            if rule is None:
                return col
            fn = STRATEGIES[rule.strategy]
            return col.apply(lambda x: fn(self._ctx(), x, label=name, **(rule.params or {})))
        for c in df.columns:
            df[c] = _mask_series(df[c], c)
        return df

    # ----- Spark helpers -----
    def spark_udf_for_field(self, field: str):
        """
        Returns a Spark UDF for masking a single field according to policy.
        Usage:
            df = df.withColumn("email", masker.spark_udf_for_field("email")(F.col("email")))
        """
        from pyspark.sql import functions as F  # type: ignore

        rule = self.policy.fields.get(field)
        if rule is None:
            # apply PII defaults opportunistically
            def _fn(v):
                return self.apply_value(field, v)
        else:
            fn = STRATEGIES[rule.strategy]
            params = rule.params or {}
            def _fn(v):
                return fn(self._ctx(), v, label=field, **params)
        return F.udf(_fn)

    def spark_mask_columns(self, sdf, columns: Optional[Iterable[str]] = None):
        """
        Apply masking to selected columns in a Spark DataFrame.
        """
        from pyspark.sql import functions as F  # type: ignore
        cols = list(columns) if columns is not None else sdf.columns
        out = sdf
        for c in cols:
            out = out.withColumn(c, self.spark_udf_for_field(c)(F.col(c)))
        return out

# --------- Default Policy Loader ---------

def load_policy_from_env(env_var: str = "DF_MASKING_POLICY_JSON") -> MaskingPolicy:
    raw = os.getenv(env_var)
    if not raw:
        # minimal sane default
        d = {
            "namespace": os.getenv("DF_MASKING_NAMESPACE", "datafabric"),
            "token_version": os.getenv("DF_MASKING_TOKEN_VERSION", "V1"),
            "fields": {
                "email": {"strategy": "hmac_token", "params": {"length": 20, "label": "email"}},
                "phone": {"strategy": "partial", "params": {"keep_right": 4}},
                "credit_card": {"strategy": "partial", "params": {"keep_right": 4}},
                "ssn": {"strategy": "encrypt", "params": {"label": "ssn"}},
                "birth_date": {"strategy": "generalize_date", "params": {"granularity": "year"}}
            },
            "pii_defaults": {
                "email": {"strategy": "partial", "params": {"keep_left": 1, "keep_right": 3}},
                "phone": {"strategy": "partial", "params": {"keep_right": 4}},
                "cc": {"strategy": "partial", "params": {"keep_right": 4}},
                "iban": {"strategy": "partial", "params": {"keep_right": 4}}
            }
        }
        return MaskingPolicy.from_dict(d)
    try:
        return MaskingPolicy.from_dict(json.loads(raw))
    except Exception as e:
        raise ValueError(f"Invalid {env_var}: {e}")

# --------- Factory ---------

def build_default_masker() -> Masker:
    # cipher optional
    cipher: Optional[CipherAdapter] = None
    if os.getenv("DF_ENCRYPTION_ENABLED", "false").lower() in ("1", "true", "yes"):
        cipher = AESGCMAdapter() if _CRYPTO_AVAILABLE else None
        if cipher is None:
            raise RuntimeError("Encryption enabled but 'cryptography' is not installed on executors")
    policy = load_policy_from_env()
    return Masker(policy=policy, provider=EnvKeyProvider(), cipher=cipher, safe_audit=True)

# --------- Self-test (optional) ---------

if __name__ == "__main__":
    # Lightweight smoke test with static keys (do NOT log raw values)
    token_key = hashlib.sha256(b"test-token-key").digest()
    enc_key = hashlib.sha256(b"test-enc-key").digest()
    provider = StaticKeyProvider({("TOKEN", "V1"): token_key, ("ENC", "V1"): enc_key})
    cipher = AESGCMAdapter() if _CRYPTO_AVAILABLE else None

    policy = MaskingPolicy.from_dict({
        "namespace": "datafabric.demo",
        "token_version": "V1",
        "fields": {
            "email": {"strategy": "hmac_token", "params": {"length": 18}},
            "phone": {"strategy": "partial", "params": {"keep_right": 4}},
            "ssn": {"strategy": "encrypt", "params": {}},
            "birth_date": {"strategy": "generalize_date", "params": {"granularity": "year"}},
            "income": {"strategy": "bucketize", "params": {"bins":[0,3e3,1e4,5e4,1e6], "labels": ["0-3k","3-10k","10-50k","50k+"]}},
        },
        "pii_defaults": {
            "email": {"strategy": "partial", "params": {"keep_left": 1, "keep_right": 3}},
            "phone": {"strategy": "partial", "params": {"keep_right": 4}},
            "cc": {"strategy": "partial", "params": {"keep_right": 4}},
        }
    })
    m = Masker(policy, provider=provider, cipher=cipher)
    record = {
        "email": "user@example.com",
        "phone": "+1-202-555-0101",
        "ssn": "123-45-6789",
        "birth_date": "1990-05-20",
        "income": 12500,
        "note": "call me at +1 415 555 2671 or write user@example.com",
    }
    masked = m.mask_record(record)
    print(json.dumps(masked, ensure_ascii=False, indent=2))
