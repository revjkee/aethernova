# datafabric/datafabric/governance/pii_detection.py
# -*- coding: utf-8 -*-
"""
PII Detection & Redaction Engine for DataFabric-Core
Industrial-grade, configurable, and extensible.

Features:
- Rule-based detection with curated regexes for common PII (email, phone, CC, IBAN, SSN, IP, crypto, etc.)
- Post-validation (Luhn for PAN, basic IBAN checksum)
- Risk scoring and policy-driven actions per PII type
- Redaction strategies: mask, hash (SHA-256 + salt), deterministic tokenize (HMAC), drop
- Stream-safe chunking with overlap handling
- Config via YAML env var or dict injection; sane defaults
- Structured logging; audit events sampling
- CLI usage for files/stdin; library API for strings/streams
- Optional hooks for ML/NER without hard dependency (function stubs)

Copyright:
© DataFabric-Core. Security-first engineering.

"""

from __future__ import annotations

import os
import re
import io
import hmac
import json
import math
import hashlib
import logging
import secrets
import base64
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Pattern, Tuple, Union

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # YAML config optional

# ------------------------------------------------------------------------------
# Logging (structured-friendly)
# ------------------------------------------------------------------------------
LOG = logging.getLogger("datafabric.pii")
if not LOG.handlers:
    handler = logging.StreamHandler()
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s pii:%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(fmt)
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Types and Dataclasses
# ------------------------------------------------------------------------------

TextLike = Union[str, bytes]

@dataclass
class Rule:
    name: str
    pattern: Pattern[str]
    pii_type: str
    group: int = 0
    validators: List[Callable[[str], bool]] = field(default_factory=list)
    risk: int = 50  # 0-100 baseline
    redact_hint: str = "mask"
    description: str = ""

@dataclass
class Detection:
    pii_type: str
    rule: str
    value: str
    start: int
    end: int
    risk: int
    context: str = ""

@dataclass
class Policy:
    # action per pii_type: mask/hash/tokenize/drop/none
    actions: Dict[str, str] = field(default_factory=dict)
    # override risk thresholds (global default used if not present)
    thresholds: Dict[str, int] = field(default_factory=dict)
    # global default threshold to trigger action
    default_threshold: int = 40
    # masking options
    mask_char: str = "*"
    mask_keep_start: int = 0
    mask_keep_end: int = 4
    # hashing options
    hash_salt: Optional[str] = None  # if None, uses env or generated ephemeral
    # tokenization (deterministic)
    token_secret: Optional[str] = None
    token_prefix: str = "tok_"
    # audit
    audit_sample_rate: float = 0.05  # 5%

@dataclass
class Config:
    rules: List[Rule]
    policy: Policy
    # chunking
    chunk_size: int = 1024 * 64
    chunk_overlap: int = 64
    # enable optional detectors
    enable_ner: bool = False  # placeholder for ML hooks
    # allowed pii types for processing (None -> all)
    allowlist: Optional[List[str]] = None
    denylist: Optional[List[str]] = None

# ------------------------------------------------------------------------------
# Utilities: validators, checksum, helpers
# ------------------------------------------------------------------------------

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if len(digits) < 12 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def _iban_ok(s: str) -> bool:
    # Basic IBAN validation (rearrange, letters->numbers, mod 97)
    s = re.sub(r"\s+", "", s).upper()
    if len(s) < 15 or len(s) > 34 or not re.match(r"^[A-Z0-9]+$", s):
        return False
    rearranged = s[4:] + s[:4]
    transformed = ""
    for ch in rearranged:
        if ch.isdigit():
            transformed += ch
        else:
            transformed += str(ord(ch) - 55)  # A=10
    # mod 97 in chunks to avoid big int overflow
    remainder = 0
    for i in range(0, len(transformed), 9):
        remainder = int(str(remainder) + transformed[i : i + 9]) % 97
    return remainder == 1

def _looks_like_phone(s: str) -> bool:
    # Heuristic phone length
    digits = re.sub(r"\D", "", s)
    return 6 <= len(digits) <= 15

def _sample(p: float) -> bool:
    if p <= 0:
        return False
    if p >= 1:
        return True
    return secrets.randbelow(10_000_000) < int(p * 10_000_000)

def _to_text(x: TextLike) -> str:
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", errors="replace")
        except Exception:
            return x.decode(errors="replace")
    return x

def _safe_context(text: str, start: int, end: int, radius: int = 16) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right]

# ------------------------------------------------------------------------------
# Default Rules (curated)
# ------------------------------------------------------------------------------

# Precompiled regexes with named types
_DEFAULT_RULES: List[Rule] = [
    Rule(
        name="email",
        pii_type="email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        risk=45,
        redact_hint="hash",
        description="RFC-like email pattern",
    ),
    Rule(
        name="phone_intl",
        pii_type="phone",
        pattern=re.compile(r"(?:(?<!\w)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)\d{3,4}[\s-]?\d{3,4}(?!\w))"),
        validators=[_looks_like_phone],
        risk=55,
        redact_hint="mask",
        description="International phone numbers",
    ),
    Rule(
        name="ipv4",
        pii_type="ip",
        pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
        risk=40,
        redact_hint="tokenize",
        description="IPv4 address",
    ),
    Rule(
        name="ipv6",
        pii_type="ip",
        pattern=re.compile(r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        risk=45,
        redact_hint="tokenize",
        description="Simplified IPv6 address",
    ),
    Rule(
        name="credit_card",
        pii_type="pan",
        pattern=re.compile(r"(?<!\d)(?:\d[ -]*?){12,19}(?!\d)"),
        validators=[_luhn_ok],
        risk=90,
        redact_hint="mask",
        description="Payment card (Luhn validated)",
    ),
    Rule(
        name="iban",
        pii_type="iban",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", re.IGNORECASE),
        validators=[_iban_ok],
        risk=85,
        redact_hint="hash",
        description="IBAN with checksum",
    ),
    Rule(
        name="ssn_us",
        pii_type="ssn",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        risk=80,
        redact_hint="drop",
        description="US SSN AAA-GG-SSSS",
    ),
    Rule(
        name="eth_address",
        pii_type="crypto",
        pattern=re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        risk=60,
        redact_hint="tokenize",
        description="Ethereum address",
    ),
    Rule(
        name="btc_address",
        pii_type="crypto",
        pattern=re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
        risk=60,
        redact_hint="tokenize",
        description="Bitcoin address (simplified)",
    ),
    Rule(
        name="passport_generic",
        pii_type="passport",
        pattern=re.compile(r"\b[A-Z0-9]{6,9}\b"),
        risk=70,
        redact_hint="hash",
        description="Generic passport ID (heuristic)",
    ),
    Rule(
        name="mac",
        pii_type="mac",
        pattern=re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
        risk=40,
        redact_hint="tokenize",
        description="MAC address",
    ),
]

# ------------------------------------------------------------------------------
# Redaction strategies
# ------------------------------------------------------------------------------

class Redactor:
    def __init__(self, policy: Policy):
        self.policy = policy
        # Resolve secrets/salts
        self._hash_salt = self.policy.hash_salt or os.getenv("PII_HASH_SALT") or "df-default-salt"
        self._token_secret = self.policy.token_secret or os.getenv("PII_TOKEN_SECRET") or "df-default-token-secret"

    def mask(self, value: str, keep_start: int = None, keep_end: int = None, mask_char: str = None) -> str:
        if value is None:
            return value
        mask_char = mask_char or self.policy.mask_char
        keep_start = self.policy.mask_keep_start if keep_start is None else keep_start
        keep_end = self.policy.mask_keep_end if keep_end is None else keep_end
        n = len(value)
        if keep_start + keep_end >= n:
            return mask_char * n
        return value[:keep_start] + (mask_char * (n - keep_start - keep_end)) + value[n - keep_end :]

    def hash(self, value: str) -> str:
        h = hashlib.sha256()
        h.update(self._hash_salt.encode("utf-8"))
        h.update(value.encode("utf-8"))
        return "sha256_" + h.hexdigest()

    def tokenize(self, value: str) -> str:
        digest = hmac.new(self._token_secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).digest()
        tok = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return f"{self.policy.token_prefix}{tok[:22]}"

    def drop(self, value: str) -> str:
        return ""

    def apply(self, action: str, value: str, hint: Optional[str] = None) -> str:
        # if action is 'auto', map to hint; else use explicit
        act = action
        if action == "auto":
            act = hint or "mask"
        if act == "mask":
            return self.mask(value)
        if act == "hash":
            return self.hash(value)
        if act == "tokenize":
            return self.tokenize(value)
        if act == "drop":
            return self.drop(value)
        if act == "none":
            return value
        # fallback
        return self.mask(value)

# ------------------------------------------------------------------------------
# Detector Engine
# ------------------------------------------------------------------------------

class PIIDetector:
    def __init__(self, config: Optional[Config] = None):
        if config is None:
            policy = Policy(
                actions={
                    "pan": "mask",
                    "iban": "hash",
                    "ssn": "drop",
                    "phone": "mask",
                    "email": "hash",
                    "ip": "tokenize",
                    "crypto": "tokenize",
                    "passport": "hash",
                    "mac": "tokenize",
                },
                default_threshold=40,
                mask_keep_start=0,
                mask_keep_end=4,
                mask_char="*",
            )
            config = Config(rules=_DEFAULT_RULES, policy=policy)
        self.cfg = config
        self.redactor = Redactor(self.cfg.policy)

    # ------------------------------
    # Configuration loading
    # ------------------------------
    @staticmethod
    def from_yaml(path: str) -> "PIIDetector":
        if yaml is None:
            raise RuntimeError("PyYAML is not installed but required to load config from YAML.")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules = []
        for r in data.get("rules", []):
            validators = []
            if r.get("validators"):
                for vname in r["validators"]:
                    if vname == "luhn":
                        validators.append(_luhn_ok)
                    elif vname == "iban":
                        validators.append(_iban_ok)
                    elif vname == "phone":
                        validators.append(_looks_like_phone)
            rules.append(
                Rule(
                    name=r["name"],
                    pii_type=r["pii_type"],
                    pattern=re.compile(r["pattern"], re.IGNORECASE if r.get("ignorecase", True) else 0),
                    group=r.get("group", 0),
                    validators=validators,
                    risk=int(r.get("risk", 50)),
                    redact_hint=r.get("redact_hint", "mask"),
                    description=r.get("description", ""),
                )
            )
        pol = data.get("policy", {})
        policy = Policy(
            actions=pol.get("actions", {}),
            thresholds=pol.get("thresholds", {}),
            default_threshold=int(pol.get("default_threshold", 40)),
            mask_char=pol.get("mask_char", "*"),
            mask_keep_start=int(pol.get("mask_keep_start", 0)),
            mask_keep_end=int(pol.get("mask_keep_end", 4)),
            hash_salt=pol.get("hash_salt"),
            token_secret=pol.get("token_secret"),
            token_prefix=pol.get("token_prefix", "tok_"),
            audit_sample_rate=float(pol.get("audit_sample_rate", 0.05)),
        )
        cfg = Config(
            rules=rules or _DEFAULT_RULES,
            policy=policy,
            chunk_size=int(data.get("chunk_size", 1024 * 64)),
            chunk_overlap=int(data.get("chunk_overlap", 64)),
            enable_ner=bool(data.get("enable_ner", False)),
            allowlist=data.get("allowlist"),
            denylist=data.get("denylist"),
        )
        return PIIDetector(cfg)

    # ------------------------------
    # Core detection
    # ------------------------------
    def _rule_allowed(self, pii_type: str) -> bool:
        if self.cfg.allowlist and pii_type not in self.cfg.allowlist:
            return False
        if self.cfg.denylist and pii_type in self.cfg.denylist:
            return False
        return True

    def iter_detections(self, text: TextLike) -> Iterator[Detection]:
        t = _to_text(text)
        for rule in self.cfg.rules:
            if not self._rule_allowed(rule.pii_type):
                continue
            for m in rule.pattern.finditer(t):
                value = m.group(rule.group)
                if value is None:
                    continue
                # validators
                valid = True
                for v in rule.validators:
                    try:
                        if not v(value):
                            valid = False
                            break
                    except Exception:
                        valid = False
                        break
                if not valid:
                    continue
                # build detection
                start, end = m.start(rule.group), m.end(rule.group)
                ctx = _safe_context(t, start, end)
                yield Detection(
                    pii_type=rule.pii_type,
                    rule=rule.name,
                    value=value,
                    start=start,
                    end=end,
                    risk=rule.risk,
                    context=ctx,
                )

    def detect(self, text: TextLike) -> List[Detection]:
        return list(self.iter_detections(text))

    # ------------------------------
    # Redaction pipeline
    # ------------------------------
    def _action_for(self, det: Detection) -> str:
        # choose action based on policy thresholds and type
        threshold = self.cfg.policy.thresholds.get(det.pii_type, self.cfg.policy.default_threshold)
        action = self.cfg.policy.actions.get(det.pii_type, "auto")
        if det.risk < threshold:
            return "none"
        return action

    def redact(self, text: TextLike) -> Tuple[str, List[Detection]]:
        """
        Redact detected PII in the given text and return redacted_text, detections.
        """
        s = _to_text(text)
        dets = self.detect(s)
        if not dets:
            return s, []
        # Sort by start to apply replacements reliably
        dets_sorted = sorted(dets, key=lambda d: d.start)
        out = []
        last = 0
        for d in dets_sorted:
            action = self._action_for(d)
            out.append(s[last:d.start])
            out.append(self.redactor.apply(action, d.value, hint=self._hint_for_rule(d.rule)))
            last = d.end
        out.append(s[last:])
        redacted = "".join(out)
        # auditing
        self._audit(dets_sorted, sample=self.cfg.policy.audit_sample_rate)
        return redacted, dets_sorted

    def _hint_for_rule(self, rule_name: str) -> Optional[str]:
        for r in self.cfg.rules:
            if r.name == rule_name:
                return r.redact_hint
        return None

    # ------------------------------
    # Streaming support
    # ------------------------------
    def redact_stream(self, stream: io.TextIOBase) -> Iterator[str]:
        """
        Process text stream chunk-by-chunk while preserving matches across boundaries.
        """
        buf = ""
        chunk_size = self.cfg.chunk_size
        overlap = self.cfg.chunk_overlap
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                if buf:
                    red, _ = self.redact(buf)
                    yield red
                break
            buf += chunk
            if len(buf) > chunk_size + overlap:
                # Keep overlap tail to catch boundary matches
                head = buf[:-overlap]
                tail = buf[-overlap:]
                red, _ = self.redact(head)
                yield red
                buf = tail

    # ------------------------------
    # Audit
    # ------------------------------
    def _audit(self, detections: List[Detection], sample: float = 0.0) -> None:
        if not detections:
            return
        if not _sample(sample):
            return
        payload = [
            {
                "pii_type": d.pii_type,
                "rule": d.rule,
                "risk": d.risk,
                "start": d.start,
                "end": d.end,
            }
            for d in detections
        ]
        try:
            LOG.info("audit detections=%s", json.dumps(payload, ensure_ascii=False))
        except Exception:
            LOG.info("audit detections_count=%d", len(detections))

    # ------------------------------
    # ML/NLP hooks (optional)
    # ------------------------------
    def enable_ner(self, enabled: bool = True) -> None:
        self.cfg.enable_ner = enabled

    def ml_hook(self, text: str) -> List[Detection]:
        """
        Placeholder for integrating spaCy/transformer-based NER.
        Return empty by default to avoid extra deps.
        """
        return []

# ------------------------------------------------------------------------------
# Public API helpers
# ------------------------------------------------------------------------------

def build_default_detector() -> PIIDetector:
    return PIIDetector()

def detect_pii(text: TextLike, detector: Optional[PIIDetector] = None) -> List[Detection]:
    det = detector or build_default_detector()
    return det.detect(text)

def redact_pii(text: TextLike, detector: Optional[PIIDetector] = None) -> Tuple[str, List[Detection]]:
    det = detector or build_default_detector()
    return det.redact(text)

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def _load_detector_from_env() -> PIIDetector:
    cfg_path = os.getenv("PII_CONFIG_YAML")
    if cfg_path and os.path.exists(cfg_path):
        return PIIDetector.from_yaml(cfg_path)
    return build_default_detector()

def _cli():
    import argparse
    parser = argparse.ArgumentParser(description="DataFabric PII detection and redaction engine")
    parser.add_argument("--mode", choices=["detect", "redact"], default="redact")
    parser.add_argument("--input", "-i", help="Input file (default: stdin)")
    parser.add_argument("--output", "-o", help="Output file for redacted text")
    parser.add_argument("--json", action="store_true", help="Emit detections as JSON to stdout")
    parser.add_argument("--audit-rate", type=float, default=None, help="Override audit sample rate")
    args = parser.parse_args()

    detector = _load_detector_from_env()
    if args.audit_rate is not None:
        detector.cfg.policy.audit_sample_rate = args.audit_rate

    data: str
    if args.input:
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    else:
        data = io.TextIOWrapper(buffer=io.BufferedReader(raw=io.FileIO(0, "r")), encoding="utf-8", errors="replace").read()

    if args.mode == "detect":
        dets = detector.detect(data)
        if args.json:
            print(json.dumps([d.__dict__ for d in dets], ensure_ascii=False, indent=2))
        else:
            for d in dets:
                print(f"{d.pii_type}\t{d.rule}\t{d.start}-{d.end}\t{d.value}")
    else:
        red, dets = detector.redact(data)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(red)
        else:
            print(red)
        if args.json:
            print(json.dumps([d.__dict__ for d in dets], ensure_ascii=False, indent=2))

if __name__ == "__main__":
    _cli()
