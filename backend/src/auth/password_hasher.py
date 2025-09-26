# backend/src/auth/password_hasher.py
from __future__ import annotations

import asyncio
import base64
import hmac
import os
import secrets
import typing as t
from dataclasses import dataclass

try:
    # argon2-cffi
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.low_level import Type as _Argon2Type
    from argon2.exceptions import VerifyMismatchError as _VerifyMismatchError
    from argon2.exceptions import InvalidHash as _InvalidHash
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "argon2-cffi is required: pip install argon2-cffi"
    ) from e


class PasswordHashError(Exception):
    """Base hashing error."""


class PasswordVerifyError(PasswordHashError):
    """Raised when password verification fails."""


class PasswordRehashRequired(PasswordHashError):
    """Raised when hash requires upgrade (parameters policy changed)."""


@dataclass(frozen=True)
class HasherPolicy:
    """
    Policy for Argon2id parameters.

    Notes:
      - Use Argon2id (hybrid of Argon2i/d). This is the recommended variant for
        password hashing in modern guidance (OWASP, PHC).
      - time_cost: number of iterations
      - memory_cost: KiB of memory
      - parallelism: lanes/threads
    """
    time_cost: int = int(os.getenv("AUTH_ARGON2_TIME_COST", "3"))
    memory_cost: int = int(os.getenv("AUTH_ARGON2_MEMORY_KIB", str(64 * 1024)))  # 64 MiB
    parallelism: int = int(os.getenv("AUTH_ARGON2_PARALLELISM", "2"))
    hash_len: int = int(os.getenv("AUTH_ARGON2_HASH_LEN", "32"))
    salt_len: int = int(os.getenv("AUTH_ARGON2_SALT_LEN", "16"))
    # Allow legacy hashes to verify but enforce upgrade on mismatch with policy
    enforce_rehash: bool = os.getenv("AUTH_ENFORCE_REHASH", "true").lower() in {"1", "true", "yes"}


class PasswordHasher:
    """
    Industrial-grade Argon2id password hasher with:
      - Application-level 'pepper' (HMAC-SHA256) support
      - Constant-time verification
      - Auto rehash/upgrade policy
      - Async wrappers for thread offloading
      - Side-channel conscious error discipline
      - Format-preserving: returns standard Argon2 hash string
    """

    __slots__ = ("_argon2", "_policy", "_pepper", "_pepper_id")

    def __init__(self, policy: HasherPolicy | None = None) -> None:
        policy = policy or HasherPolicy()
        object.__setattr__(self, "_policy", policy)

        # Prepare Argon2id hasher with explicit parameters
        argon2 = _Argon2Hasher(
            time_cost=policy.time_cost,
            memory_cost=policy.memory_cost,
            parallelism=policy.parallelism,
            hash_len=policy.hash_len,
            salt_len=policy.salt_len,
            type=_Argon2Type.ID,  # Argon2id
        )
        object.__setattr__(self, "_argon2", argon2)

        # Application-level pepper (optional but recommended)
        # Keep pepper out of DB; load from env/secret manager.
        # If not set, peppering is transparently disabled.
        pepper_raw = os.getenv("AUTH_PEPPER", "")  # bytes after UTF-8
        pepper_id = os.getenv("AUTH_PEPPER_ID", "v1")
        object.__setattr__(self, "_pepper", pepper_raw.encode("utf-8") if pepper_raw else b"")
        object.__setattr__(self, "_pepper_id", pepper_id)

    # ---------------------------
    # Public sync API
    # ---------------------------

    def hash(self, password: str) -> str:
        """
        Hash the password with Argon2id and optional pepper.

        Returns:
            Argon2 hash string (standard PHC format, plus pepper id in custom tag if set).
        """
        if not isinstance(password, str):
            raise TypeError("password must be str")

        material = self._pre_hash_material(password)
        h = self._argon2.hash(material)

        # If pepper is enabled, append a stable, URL-safe tag with pepper id
        # without breaking Argon2 verifier (we add opaque suffix after a '|').
        if self._pepper:
            tag = self._encode_pepper_tag(self._pepper_id)
            return f"{h}|{tag}"
        return h

    def verify(self, password: str, hashed: str, *, raise_on_rehash: bool = False) -> bool:
        """
        Verify password against hash. Returns True on success.

        If policy.enforce_rehash or raise_on_rehash=True and hash is under-provisioned,
        raises PasswordRehashRequired to let caller upgrade stored hash.
        """
        if not isinstance(password, str):
            raise TypeError("password must be str")
        if not isinstance(hashed, str):
            raise TypeError("hashed must be str")

        stored_hash, stored_pepper_id = self._split_hash_and_tag(hashed)

        material = self._pre_hash_material(password, stored_pepper_id)
        try:
            self._argon2.verify(stored_hash, material)
        except _VerifyMismatchError:
            # Constant-time style final decision with dummy compare to reduce timing oracle
            # (still dominated by Argon2 verify). This makes early exits uniform.
            secrets.compare_digest("x", "y")
            raise PasswordVerifyError("Invalid credentials")
        except _InvalidHash:
            raise PasswordHashError("Stored hash format is invalid")

        # If Argon2 parameters changed or pepper id rotated, request rehash
        needs_rehash = self._argon2.check_needs_rehash(stored_hash) or (
            bool(self._pepper) and (stored_pepper_id != self._pepper_id)
        )

        if needs_rehash and (self._policy.enforce_rehash or raise_on_rehash):
            raise PasswordRehashRequired("Hash requires upgrade")

        return True

    def needs_rehash(self, hashed: str) -> bool:
        """
        Check whether the stored hash requires upgrade under current policy or pepper id.
        """
        stored_hash, stored_pepper_id = self._split_hash_and_tag(hashed)
        return self._argon2.check_needs_rehash(stored_hash) or (
            bool(self._pepper) and (stored_pepper_id != self._pepper_id)
        )

    def upgrade_hash(self, password: str, hashed: str) -> str:
        """
        Verify and return upgraded hash if needed; otherwise returns the original hash.
        """
        self.verify(password, hashed, raise_on_rehash=False)
        if self.needs_rehash(hashed):
            return self.hash(password)
        return hashed

    # ---------------------------
    # Public async API
    # ---------------------------

    async def a_hash(self, password: str) -> str:
        return await asyncio.to_thread(self.hash, password)

    async def a_verify(self, password: str, hashed: str, *, raise_on_rehash: bool = False) -> bool:
        return await asyncio.to_thread(self.verify, password, hashed, raise_on_rehash=raise_on_rehash)

    async def a_needs_rehash(self, hashed: str) -> bool:
        return await asyncio.to_thread(self.needs_rehash, hashed)

    async def a_upgrade_hash(self, password: str, hashed: str) -> str:
        return await asyncio.to_thread(self.upgrade_hash, password, hashed)

    # ---------------------------
    # Internals
    # ---------------------------

    def _pre_hash_material(self, password: str, pepper_id_override: str | None = None) -> str:
        """
        Build pre-hash material. If pepper is enabled, compute:
          material = base64url(HMAC_SHA256(pepper, UTF8(password)))
        Otherwise, return password unchanged.

        We encode as base64url to keep printable input for argon2 verifier.
        """
        if not self._pepper:
            return password

        pid = (pepper_id_override or self._pepper_id).encode("utf-8")
        # Include pepper id in the MAC to safely rotate peppers over time.
        mac_key = hmac.new(self._pepper, pid, digestmod="sha256").digest()
        mac = hmac.new(mac_key, password.encode("utf-8"), digestmod="sha256").digest()
        return base64.urlsafe_b64encode(mac).decode("ascii")

    @staticmethod
    def _encode_pepper_tag(pepper_id: str) -> str:
        # Tag format: p=<base64url(pepper_id)>
        raw = pepper_id.encode("utf-8")
        return f"p={base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')}"

    @staticmethod
    def _decode_pepper_tag(tag: str) -> str | None:
        # Expect "p=<...>"
        if not tag.startswith("p="):
            return None
        data = tag[2:]
        # Add padding back if stripped
        padding = "=" * (-len(data) % 4)
        try:
            return base64.urlsafe_b64decode(data + padding).decode("utf-8")
        except Exception:
            return None

    def _split_hash_and_tag(self, hashed: str) -> tuple[str, str | None]:
        """
        Split stored value into (<argon2-hash>, pepper_id or None).
        We support optional suffix "|p=..." for pepper identification.
        """
        if "|" not in hashed:
            return hashed, None
        base, tag = hashed.rsplit("|", 1)
        return base, self._decode_pepper_tag(tag)


# ------------
# Factory / Singleton (optional)
# ------------

_default_hasher: PasswordHasher | None = None


def get_password_hasher() -> PasswordHasher:
    """
    Lazy singleton factory to reuse configured hasher in the app.
    Reads env-configured policy and pepper once per process.
    """
    global _default_hasher
    if _default_hasher is None:
        _default_hasher = PasswordHasher()
    return _default_hasher


# ------------
# Convenience top-level functions
# ------------

def hash_password(password: str) -> str:
    return get_password_hasher().hash(password)


def verify_password(password: str, hashed: str, *, raise_on_rehash: bool = False) -> bool:
    return get_password_hasher().verify(password, hashed, raise_on_rehash=raise_on_rehash)


def needs_rehash(hashed: str) -> bool:
    return get_password_hasher().needs_rehash(hashed)


def upgrade_hash(password: str, hashed: str) -> str:
    return get_password_hasher().upgrade_hash(password, hashed)


async def a_hash_password(password: str) -> str:
    return await get_password_hasher().a_hash(password)


async def a_verify_password(password: str, hashed: str, *, raise_on_rehash: bool = False) -> bool:
    return await get_password_hasher().a_verify(password, hashed, raise_on_rehash=raise_on_rehash)


async def a_needs_rehash(hashed: str) -> bool:
    return await get_password_hasher().a_needs_rehash(hashed)


async def a_upgrade_hash(password: str, hashed: str) -> str:
    return await get_password_hasher().a_upgrade_hash(password, hashed)


# ------------
# Defensive defaults documentation (kept inline for audits)
# ------------
"""
Operational guidance (summary):
- Set AUTH_PEPPER (random 32+ bytes) via secret manager or env for each environment.
- Optional AUTH_PEPPER_ID for rotation (e.g., v1, v2...). Old hashes verify and are upgraded on next login.
- Tune memory/time costs per hardware:
  * AUTH_ARGON2_MEMORY_KIB default 65536 (64 MiB) — increase on servers if feasible.
  * AUTH_ARGON2_TIME_COST default 3.
  * AUTH_ARGON2_PARALLELISM default 2.
- Store only returned string (includes optional "|p=..." tag). Do not store the pepper.

Exceptions contract:
- PasswordVerifyError -> invalid credentials
- PasswordRehashRequired -> verification succeeded but parameters/pepper changed and an upgrade is advised
- PasswordHashError -> other issues (invalid stored hash etc.)

Threading/async:
- Argon2 is CPU-bound; async API offloads to threads via asyncio.to_thread to keep event loop responsive.

Testing:
- For tests, set a small policy via env (e.g., MEMORY_KIB=8192, TIME_COST=2) to speed up CI.

Security notes:
- Do NOT log passwords or hash outputs.
- Keep process environment (AUTH_PEPPER) out of debug dumps and crash reports.
"""
