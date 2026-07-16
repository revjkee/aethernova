# decision_packets/hasher.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Final, Iterable, Mapping, Optional, Sequence, Tuple, Union

JsonPrimitive = Union[str, int, float, bool, None]
JsonLike = Union[
    JsonPrimitive,
    Mapping[str, Any],
    Sequence[Any],
]


class PacketHashError(Exception):
    """Base exception for packet hashing errors."""


class UnsupportedAlgorithmError(PacketHashError):
    """Raised when an unsupported hashing algorithm is requested."""


class CanonicalizationError(PacketHashError):
    """Raised when object canonicalization fails or is not representable."""


class InvalidDigestError(PacketHashError):
    """Raised when a digest format/value is invalid."""


@dataclass(frozen=True, slots=True)
class HasherConfig:
    """
    Configuration for packet hashing.

    algorithm:
        Hash algorithm for digest. Recommended: "sha256" (default).
        Allowed: sha256, sha512, blake2b, blake2s, sha3_256, sha3_512.
    digest_encoding:
        Output encoding for digest. Allowed: "hex" or "base64".
    domain:
        Domain separation label (context tag). Must be stable across the system.
        Example: "aethernova.decision_packet".
    canonical_json:
        If True, dict/list inputs are canonicalized to stable JSON bytes.
    strict_json:
        If True, rejects NaN/Infinity and non-JSON-safe values.
    max_canonical_bytes:
        Safety limit for canonical JSON output size.
    """
    algorithm: str = "sha256"
    digest_encoding: str = "hex"
    domain: str = "aethernova.decision_packet"
    canonical_json: bool = True
    strict_json: bool = True
    max_canonical_bytes: int = 8 * 1024 * 1024  # 8 MiB


_SUPPORTED_ALGOS: Final[Tuple[str, ...]] = (
    "sha256",
    "sha512",
    "blake2b",
    "blake2s",
    "sha3_256",
    "sha3_512",
)

_ALLOWED_ENCODINGS: Final[Tuple[str, ...]] = ("hex", "base64")


def _ensure_bytes(data: Union[bytes, bytearray, memoryview]) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"Expected bytes-like, got {type(data)!r}")


def _domain_prefix(domain: str) -> bytes:
    if not isinstance(domain, str) or not domain:
        raise ValueError("domain must be a non-empty string")
    # Domain separation prefix format:
    #   b"DPH1:" + domain + b"\n"
    # DPH1 = Decision Packet Hasher v1
    return b"DPH1:" + domain.encode("utf-8") + b"\n"


def _make_hasher(algorithm: str):
    algo = (algorithm or "").strip().lower()
    if algo not in _SUPPORTED_ALGOS:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {algorithm!r}. Supported: {', '.join(_SUPPORTED_ALGOS)}"
        )
    # hashlib supports these names directly.
    return hashlib.new(algo)


def _json_default_strict(obj: Any) -> Any:
    # Refuse unknown objects in strict mode.
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _canonicalize_json(
    obj: JsonLike,
    *,
    strict: bool,
    max_bytes: int,
) -> bytes:
    try:
        dumped = json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=not strict,
            default=_json_default_strict if strict else None,
        )
    except (TypeError, ValueError) as e:
        raise CanonicalizationError(str(e)) from e

    b = dumped.encode("utf-8")
    if max_bytes > 0 and len(b) > max_bytes:
        raise CanonicalizationError(
            f"Canonical JSON exceeds max_canonical_bytes: {len(b)} > {max_bytes}"
        )
    return b


def _encode_digest(raw: bytes, encoding: str) -> str:
    enc = (encoding or "").strip().lower()
    if enc not in _ALLOWED_ENCODINGS:
        raise ValueError(f"Unsupported digest encoding: {encoding!r}. Allowed: {', '.join(_ALLOWED_ENCODINGS)}")
    if enc == "hex":
        return raw.hex()
    # base64 urlsafe without padding for compact transport
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_digest(digest: str, encoding: str) -> bytes:
    enc = (encoding or "").strip().lower()
    if enc not in _ALLOWED_ENCODINGS:
        raise ValueError(f"Unsupported digest encoding: {encoding!r}. Allowed: {', '.join(_ALLOWED_ENCODINGS)}")

    if not isinstance(digest, str) or not digest:
        raise InvalidDigestError("Digest must be a non-empty string")

    if enc == "hex":
        try:
            return bytes.fromhex(digest)
        except ValueError as e:
            raise InvalidDigestError("Invalid hex digest") from e

    # base64 urlsafe without padding
    padded = digest + "=" * ((4 - (len(digest) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as e:  # type: ignore[name-defined]
        raise InvalidDigestError("Invalid base64 digest") from e


class PacketHasher:
    """
    Industrial-grade hasher for decision packets (immutability).

    Features:
    - Deterministic hashing for bytes/str and canonicalized JSON for dict/list
    - Domain separation (prevents cross-context collisions)
    - Optional HMAC mode (authenticity if a shared secret is configured)
    - Streaming support for large payloads
    - Constant-time digest comparison
    """

    __slots__ = ("_cfg", "_hmac_key")

    def __init__(self, config: Optional[HasherConfig] = None, *, hmac_key: Optional[bytes] = None) -> None:
        cfg = config or HasherConfig()
        if (cfg.algorithm or "").strip().lower() not in _SUPPORTED_ALGOS:
            raise UnsupportedAlgorithmError(
                f"Unsupported algorithm: {cfg.algorithm!r}. Supported: {', '.join(_SUPPORTED_ALGOS)}"
            )
        if (cfg.digest_encoding or "").strip().lower() not in _ALLOWED_ENCODINGS:
            raise ValueError(
                f"Unsupported digest encoding: {cfg.digest_encoding!r}. Allowed: {', '.join(_ALLOWED_ENCODINGS)}"
            )
        if not isinstance(cfg.domain, str) or not cfg.domain:
            raise ValueError("config.domain must be a non-empty string")
        if cfg.max_canonical_bytes < 0:
            raise ValueError("config.max_canonical_bytes must be >= 0")

        self._cfg = cfg
        self._hmac_key = _ensure_bytes(hmac_key) if hmac_key is not None else None

    @property
    def config(self) -> HasherConfig:
        return self._cfg

    @property
    def is_hmac(self) -> bool:
        return self._hmac_key is not None

    def hash_packet(self, packet: Union[bytes, bytearray, memoryview, str, JsonLike]) -> str:
        """
        Hash a packet into a stable digest string (hex or base64).

        - bytes-like: hashed as-is
        - str: utf-8 bytes
        - dict/list/JSON-like: canonical JSON bytes (if enabled)
        """
        payload = self._to_payload_bytes(packet)
        raw = self._hash_bytes(payload)
        return _encode_digest(raw, self._cfg.digest_encoding)

    def hash_packet_raw(self, packet: Union[bytes, bytearray, memoryview, str, JsonLike]) -> bytes:
        """Same as hash_packet, but returns raw digest bytes."""
        payload = self._to_payload_bytes(packet)
        return self._hash_bytes(payload)

    def verify_packet(self, packet: Union[bytes, bytearray, memoryview, str, JsonLike], expected_digest: str) -> bool:
        """Verify packet digest using constant-time comparison."""
        raw_expected = _decode_digest(expected_digest, self._cfg.digest_encoding)
        raw_actual = self.hash_packet_raw(packet)
        return hmac.compare_digest(raw_actual, raw_expected)

    def stream_hasher(self):
        """
        Create a streaming hasher object (supports update()).

        Use this for very large raw payloads where you already control byte encoding.
        """
        return _StreamingPacketHasher(self._cfg, self._hmac_key)

    def _hash_bytes(self, payload: bytes) -> bytes:
        prefix = _domain_prefix(self._cfg.domain)
        algo = self._cfg.algorithm.strip().lower()

        if self._hmac_key is not None:
            # HMAC provides authenticity (shared key), while domain prefix provides context separation.
            mac = hmac.new(self._hmac_key, digestmod=algo)
            mac.update(prefix)
            mac.update(payload)
            return mac.digest()

        h = _make_hasher(algo)
        h.update(prefix)
        h.update(payload)
        return h.digest()

    def _to_payload_bytes(self, packet: Union[bytes, bytearray, memoryview, str, JsonLike]) -> bytes:
        if isinstance(packet, (bytes, bytearray, memoryview)):
            return _ensure_bytes(packet)

        if isinstance(packet, str):
            return packet.encode("utf-8")

        if self._cfg.canonical_json:
            return _canonicalize_json(
                packet,  # type: ignore[arg-type]
                strict=self._cfg.strict_json,
                max_bytes=self._cfg.max_canonical_bytes,
            )

        raise CanonicalizationError(
            "Non-bytes packet provided, but canonical_json is disabled. "
            "Provide bytes/str, or enable canonical_json."
        )


class _StreamingPacketHasher:
    """
    Internal streaming hasher.

    Guarantees:
    - Domain prefix is applied once on creation
    - update() only accepts bytes-like chunks
    - digest() / hexdigest() / digest_text() finalize current state
    """

    __slots__ = ("_cfg", "_algo", "_hmac_key", "_inner")

    def __init__(self, cfg: HasherConfig, hmac_key: Optional[bytes]) -> None:
        self._cfg = cfg
        self._algo = cfg.algorithm.strip().lower()
        self._hmac_key = hmac_key

        prefix = _domain_prefix(cfg.domain)
        if hmac_key is not None:
            inner = hmac.new(hmac_key, digestmod=self._algo)
            inner.update(prefix)
            self._inner = inner
        else:
            inner = _make_hasher(self._algo)
            inner.update(prefix)
            self._inner = inner

    def update(self, chunk: Union[bytes, bytearray, memoryview]) -> "_StreamingPacketHasher":
        self._inner.update(_ensure_bytes(chunk))
        return self

    def digest(self) -> bytes:
        # hashlib objects support copy(); hmac.HMAC also supports copy().
        return self._inner.copy().digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def digest_text(self) -> str:
        return _encode_digest(self.digest(), self._cfg.digest_encoding)

    def verify(self, expected_digest: str) -> bool:
        raw_expected = _decode_digest(expected_digest, self._cfg.digest_encoding)
        return hmac.compare_digest(self.digest(), raw_expected)
