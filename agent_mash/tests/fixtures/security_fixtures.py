# agent_mash/tests/fixtures/security_fixtures.py
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple

import pytest


class Clock(Protocol):
    def __call__(self) -> int: ...


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def _json_dumps_compact(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class PasswordHash:
    scheme: str
    iterations: int
    salt_b64: str
    digest_b64: str

    def to_string(self) -> str:
        return f"{self.scheme}${self.iterations}${self.salt_b64}${self.digest_b64}"

    @staticmethod
    def from_string(s: str) -> "PasswordHash":
        parts = s.split("$")
        if len(parts) != 4:
            raise ValueError("Invalid password hash encoding")
        scheme, it_s, salt_b64, digest_b64 = parts
        it = int(it_s)
        if scheme != "pbkdf2_sha256":
            raise ValueError("Unsupported scheme")
        return PasswordHash(scheme=scheme, iterations=it, salt_b64=salt_b64, digest_b64=digest_b64)


class PasswordHasher:
    """
    PBKDF2-HMAC-SHA256 hasher suitable for deterministic, dependency-free test fixtures.
    This is designed for tests and fixtures; production systems may choose Argon2/scrypt.
    """

    __slots__ = ("_pepper", "_iterations", "_salt_bytes", "_dklen")

    def __init__(self, *, pepper: bytes, iterations: int = 310_000, salt_bytes: int = 16, dklen: int = 32) -> None:
        if not isinstance(pepper, (bytes, bytearray)) or len(pepper) < 16:
            raise ValueError("pepper must be bytes and at least 16 bytes long")
        if iterations < 100_000:
            raise ValueError("iterations too low for fixture hardening")
        if salt_bytes < 16:
            raise ValueError("salt_bytes too low")
        if dklen < 32:
            raise ValueError("dklen too low")
        self._pepper = bytes(pepper)
        self._iterations = int(iterations)
        self._salt_bytes = int(salt_bytes)
        self._dklen = int(dklen)

    @property
    def iterations(self) -> int:
        return self._iterations

    def hash(self, password: str) -> str:
        if not isinstance(password, str) or not password:
            raise ValueError("password must be non-empty str")
        salt = secrets.token_bytes(self._salt_bytes)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt + self._pepper,
            self._iterations,
            dklen=self._dklen,
        )
        ph = PasswordHash(
            scheme="pbkdf2_sha256",
            iterations=self._iterations,
            salt_b64=_b64url_encode(salt),
            digest_b64=_b64url_encode(dk),
        )
        return ph.to_string()

    def verify(self, password: str, encoded: str) -> bool:
        if not isinstance(password, str) or not password:
            return False
        try:
            ph = PasswordHash.from_string(encoded)
        except Exception:
            return False
        salt = _b64url_decode(ph.salt_b64)
        expected = _b64url_decode(ph.digest_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt + self._pepper,
            ph.iterations,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)

    def needs_rehash(self, encoded: str) -> bool:
        try:
            ph = PasswordHash.from_string(encoded)
        except Exception:
            return True
        return ph.iterations != self._iterations


@dataclass(frozen=True, slots=True)
class WalletKeypair:
    """
    Wallet keypair fixture.

    Contract of the project (as stated in chat history):
    - private key shown once
    - private key must not be stored in plaintext
    This fixture keeps raw private key bytes in-memory only for the duration of a test.
    """

    public_key_b64: str
    _private_key_raw: bytes

    def private_key_bytes_once(self) -> bytes:
        return self._private_key_raw

    def wipe_private_key(self) -> "WalletKeypair":
        return WalletKeypair(public_key_b64=self.public_key_b64, _private_key_raw=b"")


class _Ed25519Provider:
    __slots__ = ("_available",)

    def __init__(self) -> None:
        self._available = False
        try:
            import cryptography  # noqa: F401

            self._available = True
        except Exception:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def generate(self) -> WalletKeypair:
        if not self._available:
            raise RuntimeError("cryptography is required for Ed25519 wallet fixtures but is not available")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return WalletKeypair(public_key_b64=_b64url_encode(pub_raw), _private_key_raw=priv_raw)


class TokenError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    claims: Mapping[str, Any]


class HMACTokenService:
    """
    Minimal signed token service for tests.
    Format: base64url(header).base64url(payload).base64url(signature)
    signature = HMAC-SHA256(secret, header.payload)
    """

    __slots__ = ("_secret", "_clock", "_issuer", "_aud", "_ttl_seconds")

    def __init__(
        self,
        *,
        secret: bytes,
        clock: Clock,
        issuer: str = "agent_mash",
        audience: str = "agent_mash_tests",
        ttl_seconds: int = 3600,
    ) -> None:
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("secret must be bytes and at least 32 bytes long")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._secret = bytes(secret)
        self._clock = clock
        self._issuer = issuer
        self._aud = audience
        self._ttl_seconds = int(ttl_seconds)

    def issue(self, *, subject: str, extra: Optional[Mapping[str, Any]] = None, ttl_seconds: Optional[int] = None) -> IssuedToken:
        if not subject:
            raise ValueError("subject required")
        now = int(self._clock())
        ttl = int(ttl_seconds) if ttl_seconds is not None else self._ttl_seconds
        if ttl <= 0:
            raise ValueError("ttl_seconds must be > 0")

        header = {"alg": "HS256", "typ": "JWT"}
        payload: Dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._aud,
            "sub": subject,
            "iat": now,
            "exp": now + ttl,
            "jti": _b64url_encode(secrets.token_bytes(16)),
        }
        if extra:
            for k, v in extra.items():
                if k in payload:
                    raise ValueError(f"extra claim collides with reserved claim: {k}")
                payload[k] = v

        header_b64 = _b64url_encode(_json_dumps_compact(header))
        payload_b64 = _b64url_encode(_json_dumps_compact(payload))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        token = f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"
        return IssuedToken(token=token, claims=payload)

    def verify(self, token: str) -> Mapping[str, Any]:
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except Exception as e:
            raise TokenError("invalid token format") from e

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        actual = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected, actual):
            raise TokenError("invalid token signature")

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))

        now = int(self._clock())
        if payload.get("iss") != self._issuer:
            raise TokenError("invalid issuer")
        if payload.get("aud") != self._aud:
            raise TokenError("invalid audience")
        exp = int(payload.get("exp", 0))
        if exp <= now:
            raise TokenError("token expired")

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            raise TokenError("invalid subject")

        return payload


@dataclass(frozen=True, slots=True)
class TestUser:
    user_id: str
    username: str
    password_hash: str
    wallet_public_key_b64: str
    roles: Tuple[str, ...] = dataclasses.field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class AuthContext:
    user: TestUser
    token: str
    claims: Mapping[str, Any]


@pytest.fixture(scope="session")
def security_pepper() -> bytes:
    # Stable for the test session; can be overridden via env in CI.
    raw = os.environ.get("AGENT_MASH_TEST_PEPPER")
    if raw:
        b = raw.encode("utf-8")
        if len(b) < 16:
            raise RuntimeError("AGENT_MASH_TEST_PEPPER must be at least 16 bytes")
        return b
    return b"agent_mash_test_pepper__32bytes_min__OK"


@pytest.fixture(scope="session")
def token_secret() -> bytes:
    raw = os.environ.get("AGENT_MASH_TEST_TOKEN_SECRET")
    if raw:
        b = raw.encode("utf-8")
        if len(b) < 32:
            raise RuntimeError("AGENT_MASH_TEST_TOKEN_SECRET must be at least 32 bytes")
        return b
    return b"agent_mash_test_token_secret__32bytes_min__OK"


@pytest.fixture()
def clock() -> Clock:
    # Uses wall time; tests can monkeypatch this fixture if needed.
    return lambda: int(time.time())


@pytest.fixture(scope="session")
def ed25519_provider() -> _Ed25519Provider:
    return _Ed25519Provider()


@pytest.fixture()
def password_hasher(security_pepper: bytes) -> PasswordHasher:
    return PasswordHasher(pepper=security_pepper, iterations=310_000, salt_bytes=16, dklen=32)


@pytest.fixture()
def token_service(token_secret: bytes, clock: Clock) -> HMACTokenService:
    return HMACTokenService(secret=token_secret, clock=clock, issuer="agent_mash", audience="agent_mash_tests", ttl_seconds=3600)


@pytest.fixture()
def wallet_factory(ed25519_provider: _Ed25519Provider) -> Callable[[], WalletKeypair]:
    def _make() -> WalletKeypair:
        return ed25519_provider.generate()

    return _make


@pytest.fixture()
def user_factory(password_hasher: PasswordHasher, wallet_factory: Callable[[], WalletKeypair]) -> Callable[..., TestUser]:
    def _make(
        *,
        username: Optional[str] = None,
        password: str = "CorrectHorseBatteryStaple!",
        roles: Tuple[str, ...] = ("user",),
        user_id: Optional[str] = None,
    ) -> TestUser:
        uname = username or f"user_{_b64url_encode(secrets.token_bytes(6))}"
        uid = user_id or _b64url_encode(secrets.token_bytes(12))

        wallet = wallet_factory()
        ph = password_hasher.hash(password)

        return TestUser(
            user_id=uid,
            username=uname,
            password_hash=ph,
            wallet_public_key_b64=wallet.public_key_b64,
            roles=tuple(roles),
        )

    return _make


@pytest.fixture()
def auth_context_factory(token_service: HMACTokenService) -> Callable[..., AuthContext]:
    def _make(*, user: TestUser, ttl_seconds: int = 3600, extra: Optional[Mapping[str, Any]] = None) -> AuthContext:
        base_extra: Dict[str, Any] = {"roles": list(user.roles), "uid": user.user_id}
        if extra:
            for k, v in extra.items():
                if k in base_extra:
                    raise ValueError(f"extra claim collides with reserved claim: {k}")
                base_extra[k] = v
        issued = token_service.issue(subject=user.username, ttl_seconds=ttl_seconds, extra=base_extra)
        claims = token_service.verify(issued.token)
        return AuthContext(user=user, token=issued.token, claims=claims)

    return _make


@pytest.fixture()
def test_user(user_factory: Callable[..., TestUser]) -> TestUser:
    return user_factory()


@pytest.fixture()
def admin_user(user_factory: Callable[..., TestUser]) -> TestUser:
    return user_factory(username="admin", roles=("admin", "user"))


@pytest.fixture()
def auth_context(test_user: TestUser, auth_context_factory: Callable[..., AuthContext]) -> AuthContext:
    return auth_context_factory(user=test_user)


@pytest.fixture()
def admin_auth_context(admin_user: TestUser, auth_context_factory: Callable[..., AuthContext]) -> AuthContext:
    return auth_context_factory(user=admin_user)


@pytest.fixture()
def assert_password_ok(password_hasher: PasswordHasher) -> Callable[[str, str], None]:
    def _assert(password: str, encoded: str) -> None:
        ok = password_hasher.verify(password, encoded)
        if not ok:
            raise AssertionError("password verification failed")

    return _assert


@pytest.fixture()
def assert_token_ok(token_service: HMACTokenService) -> Callable[[str], Mapping[str, Any]]:
    def _assert(token: str) -> Mapping[str, Any]:
        return token_service.verify(token)

    return
