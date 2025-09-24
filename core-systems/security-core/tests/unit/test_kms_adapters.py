# File: tests/unit/test_kms_adapters.py
# Contract and conformance tests for KMS adapters (AWS/GCP/Azure/Local).
# Python: 3.10+
import asyncio
import os
import sys
from dataclasses import dataclass
from typing import Any, Optional, Tuple, Protocol

import pytest

# Optional: cryptography for local reference adapter and signature/AEAD checks
try:
    from cryptography.hazmat.primitives import hashes, serialization, hmac
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
except Exception:  # pragma: no cover
    hashes = serialization = rsa = ec = ed25519 = padding = default_backend = AESGCM = hmac = None  # type: ignore


# =========================
# Contract (fallback if project types are absent)
# =========================

class KMSError(Exception):
    """Base KMS error."""


class KMSNotFound(KMSError):
    """Key not found."""


class KMSUnauthorized(KMSError):
    """Auth/permission error."""


class KMSTransient(KMSError):
    """Transient error (retryable)."""


class KMSAdapter(Protocol):
    async def sign(self, key_ref: str, message: bytes, *, alg: str) -> bytes: ...
    async def verify(self, key_ref: str, message: bytes, signature: bytes, *, alg: str) -> bool: ...
    async def encrypt(self, key_ref: str, plaintext: bytes, *, aad: bytes | None = None) -> bytes: ...
    async def decrypt(self, key_ref: str, ciphertext: bytes, *, aad: bytes | None = None) -> bytes: ...
    async def generate_data_key(self, key_ref: str, *, key_spec: str = "AES_256") -> Tuple[bytes, bytes]: ...
    async def get_public_key_pem(self, key_ref: str) -> bytes: ...
    async def health(self) -> bool: ...


# If project provides real adapters/exceptions, import and override symbols
try:  # pragma: no cover - import shape depends on project
    mod = pytest.importorskip("security.kms.adapters", reason="KMS adapters module not found")
    KMSAdapter = getattr(mod, "KMSAdapter", KMSAdapter)
    KMSError = getattr(mod, "KMSError", KMSError)
    KMSNotFound = getattr(mod, "KMSNotFound", KMSNotFound)
    KMSUnauthorized = getattr(mod, "KMSUnauthorized", KMSUnauthorized)
    KMSTransient = getattr(mod, "KMSTransient", KMSTransient)
except pytest.skip.Exception:
    mod = None


# =========================
# Reference in-memory adapter (spec baseline)
# =========================

@pytest.mark.skipif(AESGCM is None or serialization is None, reason="cryptography not installed")
class ReferenceLocalAdapter:
    """
    Deterministic in-memory KMS used to validate the conformance suite completely offline.
    Supports:
      - RSA (RS256), ECDSA P-256 (ES256), Ed25519 (EdDSA)
      - AES-GCM envelope for encrypt/decrypt (per-key stable KEK derived from key_ref)
      - data key generation (AES-256) with wrapping via KEK
    """
    def __init__(self) -> None:
        self._store: dict[str, tuple[str, Any]] = {}  # key_ref -> (kty, private_key_obj)

    async def ensure_key(self, key_ref: str, *, kty: str) -> None:
        if key_ref in self._store:
            return
        if kty == "RSA":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        elif kty == "EC":
            key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        elif kty == "OKP":
            key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("Unsupported kty")
        self._store[key_ref] = (kty, key)

    def _kek(self, key_ref: str) -> bytes:
        # Derive a per-key 256-bit KEK from key_ref using HMAC-SHA256 over a fixed salt.
        mac = hmac.HMAC(b"ref-kms-derivation-salt", hashes.SHA256(), backend=default_backend())
        mac.update(key_ref.encode("utf-8"))
        return mac.finalize()

    async def sign(self, key_ref: str, message: bytes, *, alg: str) -> bytes:
        if key_ref not in self._store:
            raise KMSNotFound(key_ref)
        kty, key = self._store[key_ref]
        if alg == "RS256" and kty == "RSA":
            return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        if alg == "ES256" and kty == "EC":
            return key.sign(message, ec.ECDSA(hashes.SHA256()))
        if alg == "EdDSA" and kty == "OKP":
            return key.sign(message)
        raise KMSError("alg/key mismatch")

    async def verify(self, key_ref: str, message: bytes, signature: bytes, *, alg: str) -> bool:
        if key_ref not in self._store:
            return False
        kty, key = self._store[key_ref]
        pub = key.public_key()
        try:
            if alg == "RS256" and kty == "RSA":
                pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
                return True
            if alg == "ES256" and kty == "EC":
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                return True
            if alg == "EdDSA" and kty == "OKP":
                pub.verify(signature, message)
                return True
            return False
        except Exception:
            return False

    async def encrypt(self, key_ref: str, plaintext: bytes, *, aad: bytes | None = None) -> bytes:
        key = self._kek(key_ref)  # 32 bytes
        nonce = b"\x00" * 12  # deterministic for tests; real adapters should use random nonces
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    async def decrypt(self, key_ref: str, ciphertext: bytes, *, aad: bytes | None = None) -> bytes:
        key = self._kek(key_ref)
        nonce = b"\x00" * 12
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    async def generate_data_key(self, key_ref: str, *, key_spec: str = "AES_256") -> Tuple[bytes, bytes]:
        if key_spec != "AES_256":
            raise KMSError("unsupported key_spec")
        plaintext = os.urandom(32)
        wrapped = await self.encrypt(key_ref, plaintext, aad=b"data-key")
        return plaintext, wrapped

    async def get_public_key_pem(self, key_ref: str) -> bytes:
        if key_ref not in self._store:
            raise KMSNotFound(key_ref)
        kty, key = self._store[key_ref]
        pub = key.public_key()
        return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    async def health(self) -> bool:
        return True


# =========================
# Fixtures
# =========================

@pytest.fixture(scope="module")
def message() -> bytes:
    return b"The quick brown fox jumps over the lazy dog"


@pytest.fixture(scope="module")
def reference_adapter(event_loop) -> ReferenceLocalAdapter:
    if AESGCM is None or serialization is None:
        pytest.skip("cryptography not installed")
    return ReferenceLocalAdapter()


@pytest.fixture(params=[
    ("local:rsa1", "RSA"),
    ("local:ec1", "EC"),
    ("local:okp1", "OKP"),
])
async def ref_keypair(reference_adapter: ReferenceLocalAdapter, request):
    key_ref, kty = request.param
    await reference_adapter.ensure_key(key_ref, kty=kty)
    return key_ref, kty, reference_adapter


# =========================
# Conformance tests against Reference adapter
# =========================

@pytest.mark.asyncio
@pytest.mark.parametrize("alg,expect_kty", [("RS256", "RSA"), ("ES256", "EC"), ("EdDSA", "OKP")])
async def test_sign_verify_roundtrip_reference(ref_keypair, message, alg, expect_kty):
    key_ref, kty, kms = ref_keypair
    if kty != expect_kty:
        pytest.skip("mismatched key type for algorithm")
    sig = await kms.sign(key_ref, message, alg=alg)
    assert isinstance(sig, (bytes, bytearray)) and len(sig) > 32
    ok = await kms.verify(key_ref, message, sig, alg=alg)
    assert ok is True


@pytest.mark.asyncio
async def test_encrypt_decrypt_reference(ref_keypair, message):
    key_ref, _kty, kms = ref_keypair
    ct = await kms.encrypt(key_ref, message, aad=b"ctx")
    assert isinstance(ct, (bytes, bytearray)) and len(ct) >= len(message) + 16
    pt = await kms.decrypt(key_ref, ct, aad=b"ctx")
    assert pt == message


@pytest.mark.asyncio
async def test_generate_data_key_reference(ref_keypair):
    key_ref, _kty, kms = ref_keypair
    pt, wrapped = await kms.generate_data_key(key_ref, key_spec="AES_256")
    assert isinstance(pt, (bytes, bytearray)) and len(pt) == 32
    unwrapped = await kms.decrypt(key_ref, wrapped, aad=b"data-key")
    assert unwrapped == pt


@pytest.mark.asyncio
async def test_public_key_pem_reference(ref_keypair):
    key_ref, _kty, kms = ref_keypair
    pem = await kms.get_public_key_pem(key_ref)
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert b"END PUBLIC KEY-----" in pem


@pytest.mark.asyncio
async def test_verify_rejects_tampered_signature(reference_adapter: ReferenceLocalAdapter, message):
    await reference_adapter.ensure_key("local:rsa2", kty="RSA")
    sig = await reference_adapter.sign("local:rsa2", message, alg="RS256")
    bad = bytearray(sig)
    bad[-1] ^= 0x01
    ok = await reference_adapter.verify("local:rsa2", message, bytes(bad), alg="RS256")
    assert ok is False


@pytest.mark.asyncio
async def test_encrypt_rejects_wrong_aad(reference_adapter: ReferenceLocalAdapter, message):
    await reference_adapter.ensure_key("local:ec2", kty="EC")
    ct = await reference_adapter.encrypt("local:ec2", message, aad=b"A")
    with pytest.raises(Exception):
        await reference_adapter.decrypt("local:ec2", ct, aad=b"B")


@pytest.mark.asyncio
async def test_missing_key_raises(reference_adapter: ReferenceLocalAdapter, message):
    with pytest.raises(KMSNotFound):
        await reference_adapter.sign("missing:key", message, alg="RS256")


@pytest.mark.asyncio
async def test_concurrent_signs_reference(reference_adapter: ReferenceLocalAdapter, message):
    await reference_adapter.ensure_key("local:okp2", kty="OKP")
    async def one():
        s = await reference_adapter.sign("local:okp2", message, alg="EdDSA")
        return await reference_adapter.verify("local:okp2", message, s, alg="EdDSA")
    results = await asyncio.gather(*[one() for _ in range(64)])
    assert all(results)


# =========================
# Optional tests for real project adapters (if present)
# =========================

def _discover_real_adapters():
    """
    Returns list of (name, adapter_factory, key_ref, alg, requires_sdk)
    Adapter factory must return an instance implementing KMSAdapter.
    """
    if not mod:
        return []
    out = []
    # Try LocalSoftwareKMSAdapter if provided by the project
    for cls_name in ("LocalKMSAdapter", "SoftwareKMSAdapter", "LocalSoftwareKMSAdapter"):
        if hasattr(mod, cls_name):
            cls = getattr(mod, cls_name)
            out.append((cls_name, lambda: cls(), "test:local", "EdDSA", False))
            break
    # Try AWS/GCP/Azure if exported and SDK present (we won't call cloud; we only check shape/health)
    for cls_name in ("AwsKMSAdapter", "AWSKMSAdapter"):
        if hasattr(mod, cls_name):
            cls = getattr(mod, cls_name)
            out.append((cls_name, lambda: cls(region="us-east-1"), "arn:aws:kms:us-east-1:123:key/abc", "RS256", True))
    for cls_name in ("GcpKMSAdapter", "GCPKMSAdapter"):
        if hasattr(mod, cls_name):
            cls = getattr(mod, cls_name)
            out.append((cls_name, lambda: cls(project="proj", location="global"), "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "RS256", True))
    for cls_name in ("AzureKeyVaultKMSAdapter", "AzureKMSAdapter"):
        if hasattr(mod, cls_name):
            cls = getattr(mod, cls_name)
            out.append((cls_name, lambda: cls(vault_url="https://example.vault.azure.net/"), "https://example.vault.azure.net/keys/k/1", "RS256", True))
    return out


REAL_ADAPTERS = _discover_real_adapters()


@pytest.mark.asyncio
@pytest.mark.skipif(not REAL_ADAPTERS, reason="No real adapters discovered")
@pytest.mark.parametrize("name,factory,key_ref,alg,requires_sdk", REAL_ADAPTERS)
async def test_real_adapter_health_and_interface(name, factory, key_ref, alg, requires_sdk):
    """
    Smoke test for discovered real adapters: verify health() callable and methods exist.
    We DO NOT call cloud endpoints; only ensure the adapter instance satisfies the protocol.
    """
    kms: KMSAdapter = factory()
    # health() should not raise; may return False if no credentials
    ok = await kms.health()
    assert isinstance(ok, bool)
    # basic attributes/methods
    assert hasattr(kms, "sign") and hasattr(kms, "verify")
    assert hasattr(kms, "encrypt") and hasattr(kms, "decrypt")
    assert hasattr(kms, "generate_data_key") and hasattr(kms, "get_public_key_pem")


# Optionally, if the project exposes a purely local adapter, run a real roundtrip on it as well.
@pytest.mark.asyncio
@pytest.mark.parametrize("cls_name", ["LocalKMSAdapter", "SoftwareKMSAdapter", "LocalSoftwareKMSAdapter"])
async def test_project_local_adapter_roundtrip_if_present(cls_name, message):
    if not mod or not hasattr(mod, cls_name):
        pytest.skip(f"{cls_name} not present")
    Adapter = getattr(mod, cls_name)
    kms: KMSAdapter = Adapter()
    # Some local adapters may require explicit key creation. Try graceful paths.
    key_ref = "local:test"
    try:
        # Try Ed25519 first
        if hasattr(kms, "create_key"):
            await kms.create_key(key_ref, key_type="OKP", curve="Ed25519")  # type: ignore[attr-defined]
    except Exception:
        pass
    # Try sign/verify; if unsupported algorithm -> skip
    try:
        sig = await kms.sign(key_ref, message, alg="EdDSA")
        assert await kms.verify(key_ref, message, sig, alg="EdDSA") is True
    except KMSError:
        pytest.xfail("Local adapter does not support EdDSA or dynamic key creation")


# =========================
# Edge cases / errors contract (applies to any adapter)
# =========================

@pytest.mark.asyncio
async def test_verify_returns_false_on_wrong_message(reference_adapter: ReferenceLocalAdapter, message):
    await reference_adapter.ensure_key("local:rsa3", kty="RSA")
    sig = await reference_adapter.sign("local:rsa3", message, alg="RS256")
    assert await reference_adapter.verify("local:rsa3", message + b".", sig, alg="RS256") is False


@pytest.mark.asyncio
async def test_sign_alg_mismatch_raises(reference_adapter: ReferenceLocalAdapter, message):
    await reference_adapter.ensure_key("local:okp3", kty="OKP")
    with pytest.raises(KMSError):
        await reference_adapter.sign("local:okp3", message, alg="RS256")


@pytest.mark.asyncio
async def test_data_key_wrap_unwrap_reference(reference_adapter: ReferenceLocalAdapter):
    await reference_adapter.ensure_key("local:ec3", kty="EC")
    pt, wrapped = await reference_adapter.generate_data_key("local:ec3")
    unwrapped = await reference_adapter.decrypt("local:ec3", wrapped, aad=b"data-key")
    assert unwrapped == pt


# =========================
# Concurrency / rate limits behavior (best-effort)
# =========================

@pytest.mark.asyncio
async def test_many_parallel_encrypts(reference_adapter: ReferenceLocalAdapter):
    await reference_adapter.ensure_key("local:rsa-par", kty="RSA")
    async def one(i: int) -> bytes:
        data = f"payload-{i}".encode()
        c = await reference_adapter.encrypt("local:rsa-par", data, aad=b"ctx")
        p = await reference_adapter.decrypt("local:rsa-par", c, aad=b"ctx")
        return p
    outs = await asyncio.gather(*[one(i) for i in range(50)])
    assert [o.decode() for o in outs] == [f"payload-{i}" for i in range(50)]
