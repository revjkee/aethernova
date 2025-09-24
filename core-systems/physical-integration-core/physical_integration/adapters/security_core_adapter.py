# physical-integration-core/physical_integration/adapters/security_core_adapter.py
from __future__ import annotations

import abc
import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

LOG = logging.getLogger("security.core.adapter")

# -----------------------------
# Опциональные зависимости
# -----------------------------
try:
    from cryptography.hazmat.primitives import serialization, hashes  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding  # type: ignore
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False
    serialization = hashes = ed25519 = ec = rsa = padding = AESGCM = XChaCha20Poly1305 = default_backend = None  # type: ignore

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import boto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None
    BotoConfig = None  # type: ignore


# -----------------------------
# Исключения
# -----------------------------
class SecurityCoreError(Exception):
    pass


class NotAvailableError(SecurityCoreError):
    pass


class VerificationError(SecurityCoreError):
    pass


class ProviderError(SecurityCoreError):
    pass


# -----------------------------
# Утилиты и общие структуры
# -----------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _now_posix() -> int:
    return int(time.time())


def _sha256(b: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b)
    return h.digest()


def _kid_from_der(der: bytes) -> str:
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _prefixed_msg_from_digest_hex(digest_hex: str) -> bytes:
    # Единая каноника для подписи: не само содержимое, а префиксованный SHA256 хеш.
    return b"SHA256:" + digest_hex.encode("ascii")


@dataclass
class SignResult:
    alg: str
    kid: str
    signature_b64url: str
    signed_at: int


@dataclass
class Jwk:
    kty: str
    crv: Optional[str]
    n: Optional[str]
    e: Optional[str]
    x: Optional[str]
    y: Optional[str]
    alg: str
    kid: str

    def to_dict(self) -> Dict[str, Any]:
        d = {"kty": self.kty, "alg": self.alg, "kid": self.kid}
        if self.crv:
            d["crv"] = self.crv
        if self.n:
            d["n"] = self.n
            d["e"] = self.e
        if self.x:
            d["x"] = self.x
        if self.y:
            d["y"] = self.y
        return d


# -----------------------------
# Базовый интерфейс
# -----------------------------
class SecurityCoreAdapter(abc.ABC):
    """Единый интерфейс для крипто-операций и материалов."""

    @abc.abstractmethod
    async def sign_digest(self, digest_hex: str, *, key_id: Optional[str] = None) -> SignResult:
        ...

    @abc.abstractmethod
    async def verify_digest(self, digest_hex: str, signature_b64url: str, *, key_id: Optional[str] = None, jwk: Optional[Jwk] = None) -> None:
        ...

    @abc.abstractmethod
    async def mint_jwt(self, claims: Dict[str, Any], *, ttl_s: int, key_id: Optional[str] = None, hdr_extra: Optional[Dict[str, Any]] = None) -> str:
        ...

    @abc.abstractmethod
    async def verify_jwt(self, token: str, *, audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    async def encrypt_aead(self, plaintext: bytes, *, aad: bytes = b"", alg: str = "AES256-GCM") -> Dict[str, str]:
        ...

    @abc.abstractmethod
    async def decrypt_aead(self, obj: Dict[str, str], *, aad: bytes = b"") -> bytes:
        ...

    @abc.abstractmethod
    async def get_jwk(self, *, key_id: Optional[str] = None) -> Jwk:
        ...

    @abc.abstractmethod
    async def get_jwks(self) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    async def mtls_context(self) -> Optional[ssl.SSLContext]:
        ...

    @abc.abstractmethod
    async def rotate_key(self, *, key_id: Optional[str] = None) -> str:
        ...


# -----------------------------
# Local provider (PEM на ФС)
# -----------------------------
class LocalSecurityCore(SecurityCoreAdapter):
    """
    Локальный провайдер: приватные ключи в PEM, деривация JWK из публичного DER,
    AEAD ключ для шифрования хранится в файле keyset.json (или берётся из ENV).
    ENV:
      SEC_KEYS_DIR=/etc/physical-integration/keys
      SEC_SIGN_KEY=<basename без .key> (по умолчанию выбирается первый доступный)
      SEC_AEAD_KEY_B64 (32 bytes для AES-GCM) или файл keyset.json с {"aead_key_b64": "..."}
      SEC_MTLS_CERT=/path/to/client.crt
      SEC_MTLS_KEY=/path/to/client.key
      SEC_JWT_ISS=<iss>, SEC_JWT_AUD=<aud> (опционально)
    """

    def __init__(self, *, keys_dir: Optional[str] = None, default_key_id: Optional[str] = None):
        self.keys_dir = Path(keys_dir or os.getenv("SEC_KEYS_DIR", "/etc/physical-integration/keys"))
        self.default_key_id = default_key_id or os.getenv("SEC_SIGN_KEY") or ""
        self._priv_cache: Dict[str, Any] = {}
        self._pub_cache: Dict[str, Tuple[bytes, Jwk]] = {}
        self._aead_key: Optional[bytes] = None
        self._jwt_iss = os.getenv("SEC_JWT_ISS")
        self._jwt_aud = os.getenv("SEC_JWT_AUD")
        self._lock = asyncio.Lock()
        if not self.keys_dir.exists():
            self.keys_dir.mkdir(parents=True, exist_ok=True)

    # ---- helpers ----
    def _load_first_key_id(self) -> str:
        for f in self.keys_dir.glob("*.key"):
            return f.stem
        raise ProviderError(f"No *.key in {self.keys_dir}")

    def _priv_path(self, key_id: str) -> Path:
        return self.keys_dir / f"{key_id}.key"

    def _load_priv(self, key_id: str) -> Any:
        if not _CRYPTO:
            raise NotAvailableError("cryptography is not available")
        if key_id in self._priv_cache:
            return self._priv_cache[key_id]
        pem = self._priv_path(key_id).read_bytes()
        priv = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
        self._priv_cache[key_id] = priv
        return priv

    def _pub_from_priv(self, priv: Any) -> Tuple[bytes, Jwk]:
        if not _CRYPTO:
            raise NotAvailableError("cryptography is not available")
        pub = priv.public_key()
        der = pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        kid = _kid_from_der(der)
        # JWK
        if isinstance(priv, ed25519.Ed25519PrivateKey):
            raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            jwk = Jwk(kty="OKP", crv="Ed25519", n=None, e=None, x=_b64url(raw), y=None, alg="EdDSA", kid=kid)
        elif isinstance(priv, ec.EllipticCurvePrivateKey) and isinstance(priv.curve, ec.SECP256R1):
            nums = pub.public_numbers()
            jwk = Jwk(
                kty="EC",
                crv="P-256",
                n=None,
                e=None,
                x=_b64url(nums.x.to_bytes(32, "big")),
                y=_b64url(nums.y.to_bytes(32, "big")),
                alg="ES256",
                kid=kid,
            )
        elif isinstance(priv, rsa.RSAPrivateKey):
            nums = pub.public_numbers()
            n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
            jwk = Jwk(kty="RSA", crv=None, n=_b64url(n), e=_b64url(e), x=None, y=None, alg="PS256", kid=kid)
        else:
            raise ProviderError("Unsupported private key type")
        return der, jwk

    def _resolve_key_id(self, key_id: Optional[str]) -> str:
        if key_id:
            return key_id
        if self.default_key_id:
            return self.default_key_id
        return self._load_first_key_id()

    def _ensure_aead_key(self) -> bytes:
        if self._aead_key:
            return self._aead_key
        env = os.getenv("SEC_AEAD_KEY_B64")
        if env:
            self._aead_key = base64.b64decode(env)
            if len(self._aead_key) not in (16, 24, 32):
                raise ProviderError("SEC_AEAD_KEY_B64 must be 16/24/32 bytes")
            return self._aead_key
        keyset = self.keys_dir / "keyset.json"
        if keyset.exists():
            data = json.loads(keyset.read_text(encoding="utf-8"))
            self._aead_key = base64.b64decode(data["aead_key_b64"])
            return self._aead_key
        # Генерируем новый 32-байтовый ключ и сохраняем
        rnd = os.urandom(32)
        keyset.write_text(json.dumps({"aead_key_b64": base64.b64encode(rnd).decode("ascii")}, indent=2), encoding="utf-8")
        self._aead_key = rnd
        return self._aead_key

    # ---- API ----
    async def sign_digest(self, digest_hex: str, *, key_id: Optional[str] = None) -> SignResult:
        kid = self._resolve_key_id(key_id)
        priv = self._load_priv(kid)
        msg = _prefixed_msg_from_digest_hex(digest_hex)
        if isinstance(priv, ed25519.Ed25519PrivateKey):
            sig = priv.sign(msg)
            alg = "EdDSA"
        elif isinstance(priv, ec.EllipticCurvePrivateKey):
            sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
            alg = "ES256"
        elif isinstance(priv, rsa.RSAPrivateKey):
            sig = priv.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            alg = "PS256"
        else:
            raise ProviderError("Unsupported key type")
        # KID из DER
        if kid not in self._pub_cache:
            der, jwk = self._pub_from_priv(priv)
            self._pub_cache[kid] = (der, jwk)
        return SignResult(alg=alg, kid=self._pub_cache[kid][1].kid, signature_b64url=_b64url(sig), signed_at=_now_posix())

    async def verify_digest(self, digest_hex: str, signature_b64url: str, *, key_id: Optional[str] = None, jwk: Optional[Jwk] = None) -> None:
        msg = _prefixed_msg_from_digest_hex(digest_hex)
        sig = _b64url_dec(signature_b64url)
        if jwk is None:
            kid = self._resolve_key_id(key_id)
            priv = self._load_priv(kid)
            der, jwk = self._pub_from_priv(priv)
        # Верификация по JWK
        if jwk.kty == "OKP" and jwk.crv == "Ed25519":
            pk = ed25519.Ed25519PublicKey.from_public_bytes(_b64url_dec(jwk.x))  # type: ignore
            pk.verify(sig, msg)  # type: ignore
            return
        if jwk.kty == "EC" and jwk.crv == "P-256":
            x = int.from_bytes(_b64url_dec(jwk.x), "big")
            y = int.from_bytes(_b64url_dec(jwk.y), "big")
            pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())  # type: ignore
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))  # type: ignore
            return
        if jwk.kty == "RSA":
            n = int.from_bytes(_b64url_dec(jwk.n), "big")
            e = int.from_bytes(_b64url_dec(jwk.e), "big")
            pub = rsa.RSAPublicNumbers(e, n).public_key(default_backend())  # type: ignore
            pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())  # type: ignore
            return
        raise VerificationError("Unsupported JWK for verification")

    async def mint_jwt(self, claims: Dict[str, Any], *, ttl_s: int, key_id: Optional[str] = None, hdr_extra: Optional[Dict[str, Any]] = None) -> str:
        kid = self._resolve_key_id(key_id)
        priv = self._load_priv(kid)
        # Заголовок
        if isinstance(priv, ed25519.Ed25519PrivateKey):
            alg = "EdDSA"
        elif isinstance(priv, ec.EllipticCurvePrivateKey):
            alg = "ES256"
        elif isinstance(priv, rsa.RSAPrivateKey):
            alg = "PS256"
        else:
            raise ProviderError("Unsupported key type")
        header = {"alg": alg, "typ": "JWT"}
        if hdr_extra:
            header.update(hdr_extra)
        # KID
        if kid not in self._pub_cache:
            der, jwk = self._pub_from_priv(priv)
            self._pub_cache[kid] = (der, jwk)
        header["kid"] = self._pub_cache[kid][1].kid
        # Клеймы
        now = _now_posix()
        body = dict(claims)
        body.setdefault("iat", now)
        body.setdefault("nbf", now)
        body.setdefault("exp", now + int(ttl_s))
        if self._jwt_iss:
            body.setdefault("iss", self._jwt_iss)
        if self._jwt_aud:
            body.setdefault("aud", self._jwt_aud)
        token_unsigned = ".".join(_b64url(json.dumps(x, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) for x in (header, body))
        sig_res = await self.sign_digest(digest_hex=_sha256(token_unsigned.encode("ascii")).hex(), key_id=kid)
        return token_unsigned + "." + sig_res.signature_b64url

    async def verify_jwt(self, token: str, *, audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict[str, Any]:
        try:
            b64h, b64p, b64s = token.split(".")
        except ValueError:
            raise VerificationError("Malformed JWT")
        header = json.loads(_b64url_dec(b64h))
        payload = json.loads(_b64url_dec(b64p))
        sig = b64s
        # Верификация подписи
        digest_hex = _sha256((b64h + "." + b64p).encode("ascii")).hex()
        jwk = await self.get_jwk()  # по умолчанию — активный ключ
        await self.verify_digest(digest_hex, sig, jwk=jwk)
        # Проверки времени/аудитории/эмитента
        now = _now_posix()
        if "nbf" in payload and now < int(payload["nbf"]):
            raise VerificationError("Token not yet valid")
        if "exp" in payload and now >= int(payload["exp"]):
            raise VerificationError("Token expired")
        if audience and "aud" in payload and payload["aud"] != audience:
            raise VerificationError("Audience mismatch")
        if issuer and "iss" in payload and payload["iss"] != issuer:
            raise VerificationError("Issuer mismatch")
        return payload

    async def encrypt_aead(self, plaintext: bytes, *, aad: bytes = b"", alg: str = "AES256-GCM") -> Dict[str, str]:
        key = self._ensure_aead_key()
        if alg.upper().startswith("AES"):
            if not _CRYPTO:
                raise NotAvailableError("cryptography is not available")
            nonce = os.urandom(12)
            ct = AESGCM(key).encrypt(nonce, plaintext, aad)  # type: ignore
            return {"alg": "AES-GCM", "klen": str(len(key)), "nonce": _b64url(nonce), "ct": _b64url(ct)}
        if alg.upper().startswith("XCHACHA20"):
            if not _CRYPTO:
                raise NotAvailableError("cryptography is not available")
            nonce = os.urandom(24)
            ct = XChaCha20Poly1305(key if len(key) == 32 else _sha256(key)).encrypt(nonce, plaintext, aad)  # type: ignore
            return {"alg": "XCHACHA20-POLY1305", "klen": "32", "nonce": _b64url(nonce), "ct": _b64url(ct)}
        raise ProviderError("Unsupported AEAD alg")

    async def decrypt_aead(self, obj: Dict[str, str], *, aad: bytes = b"") -> bytes:
        key = self._ensure_aead_key()
        alg = obj["alg"].upper()
        nonce = _b64url_dec(obj["nonce"])
        ct = _b64url_dec(obj["ct"])
        if alg == "AES-GCM":
            if not _CRYPTO:
                raise NotAvailableError("cryptography is not available")
            return AESGCM(key).decrypt(nonce, ct, aad)  # type: ignore
        if alg == "XCHACHA20-POLY1305":
            if not _CRYPTO:
                raise NotAvailableError("cryptography is not available")
            return XChaCha20Poly1305(key if len(key) == 32 else _sha256(key)).decrypt(nonce, ct, aad)  # type: ignore
        raise ProviderError("Unsupported AEAD alg")

    async def get_jwk(self, *, key_id: Optional[str] = None) -> Jwk:
        kid = self._resolve_key_id(key_id)
        priv = self._load_priv(kid)
        if kid in self._pub_cache:
            return self._pub_cache[kid][1]
        der, jwk = self._pub_from_priv(priv)
        self._pub_cache[kid] = (der, jwk)
        return jwk

    async def get_jwks(self) -> Dict[str, Any]:
        # JWKS из всех *.key
        keys: List[Dict[str, Any]] = []
        for f in self.keys_dir.glob("*.key"):
            try:
                priv = self._load_priv(f.stem)
                _, jwk = self._pub_from_priv(priv)
                keys.append(jwk.to_dict())
            except Exception as ex:
                LOG.warning("Skip key %s: %s", f, ex)
        return {"keys": keys}

    async def mtls_context(self) -> Optional[ssl.SSLContext]:
        cert = os.getenv("SEC_MTLS_CERT")
        key = os.getenv("SEC_MTLS_KEY")
        if not cert or not key:
            return None
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    async def rotate_key(self, *, key_id: Optional[str] = None) -> str:
        # В локальном провайдере ротация — оффлайн-операция (создать новый PEM).
        # Здесь просто возвращаем текущий активный key_id.
        return self._resolve_key_id(key_id)


# -----------------------------
# Vault Transit provider (HTTP API)
# -----------------------------
class VaultTransitSecurityCore(SecurityCoreAdapter):
    """
    HashiCorp Vault Transit.
    ENV:
      VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE (опц.), VAULT_MOUNT=transit
      VAULT_KEY=signing (ключ Transit для подписи)
      SEC_AEAD_KEY_B64 / keyset.json — как в Local для AEAD.
    Поддержаны: sign/verify по digest, JWKS формируется из /keys/<name> (public_key).
    """
    def __init__(self):
        if httpx is None:
            raise NotAvailableError("httpx not available for Vault provider")
        self.addr = os.getenv("VAULT_ADDR")
        self.token = os.getenv("VAULT_TOKEN")
        self.ns = os.getenv("VAULT_NAMESPACE")
        self.mount = os.getenv("VAULT_MOUNT", "transit")
        self.key_name = os.getenv("VAULT_KEY", "signing")
        if not self.addr or not self.token:
            raise ProviderError("VAULT_ADDR and VAULT_TOKEN are required")
        self._client = httpx.AsyncClient(base_url=self.addr, headers=self._headers(), timeout=10.0, verify=True)
        self._local = LocalSecurityCore()  # AEAD/JWT по локальному ключу при необходимости

    def _headers(self) -> Dict[str, str]:
        h = {"X-Vault-Token": self.token, "Content-Type": "application/json"}
        if self.ns:
            h["X-Vault-Namespace"] = self.ns
        return h

    async def _get_pub_jwk(self) -> Jwk:
        # Transit: /v1/<mount>/keys/<name>
        r = await self._client.get(f"/v1/{self.mount}/keys/{self.key_name}")
        r.raise_for_status()
        data = r.json()
        # Берём последний активный public_key (PEM). Конвертируем в JWK через Local.
        pem = data["data"]["keys"][str(max(map(int, data["data"]["keys"].keys())))]["public_key"]
        if not _CRYPTO:
            raise NotAvailableError("cryptography is not available for JWK conversion")
        pub = serialization.load_pem_public_key(pem.encode("ascii"), backend=default_backend())
        if isinstance(pub, ed25519.Ed25519PublicKey):
            raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            kid = _kid_from_der(pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            return Jwk(kty="OKP", crv="Ed25519", n=None, e=None, x=_b64url(raw), y=None, alg="EdDSA", kid=kid)
        if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1):
            nums = pub.public_numbers()
            kid = _kid_from_der(pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            return Jwk(kty="EC", crv="P-256", n=None, e=None, x=_b64url(nums.x.to_bytes(32, "big")), y=_b64url(nums.y.to_bytes(32, "big")), alg="ES256", kid=kid)
        if isinstance(pub, rsa.RSAPublicKey):
            nums = pub.public_numbers()
            n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
            kid = _kid_from_der(pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            return Jwk(kty="RSA", crv=None, n=_b64url(n), e=_b64url(e), x=None, y=None, alg="PS256", kid=kid)
        raise ProviderError("Unsupported Vault public key type")

    async def sign_digest(self, digest_hex: str, *, key_id: Optional[str] = None) -> SignResult:
        payload = {"input": _b64url(_prefixed_msg_from_digest_hex(digest_hex))}
        r = await self._client.post(f"/v1/{self.mount}/sign/{self.key_name}/sha2-256", json=payload)
        r.raise_for_status()
        sig_b64 = r.json()["data"]["signature"].split(":")[-1]  # vault: <algo>:<base64>
        # Определяем alg по ключу
        jwk = await self._get_pub_jwk()
        alg = jwk.alg
        return SignResult(alg=alg, kid=jwk.kid, signature_b64url=_b64url(base64.b64decode(sig_b64)), signed_at=_now_posix())

    async def verify_digest(self, digest_hex: str, signature_b64url: str, *, key_id: Optional[str] = None, jwk: Optional[Jwk] = None) -> None:
        jwk = jwk or await self._get_pub_jwk()
        await LocalSecurityCore().verify_digest(digest_hex, signature_b64url, jwk=jwk)

    async def mint_jwt(self, claims: Dict[str, Any], *, ttl_s: int, key_id: Optional[str] = None, hdr_extra: Optional[Dict[str, Any]] = None) -> str:
        # Упрощённо: делаем локальный JWT с проверкой подписи Vault при необходимости.
        return await self._local.mint_jwt(claims, ttl_s=ttl_s, hdr_extra=hdr_extra)

    async def verify_jwt(self, token: str, *, audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict[str, Any]:
        # Верификация с использованием JWK из Transit
        try:
            b64h, b64p, b64s = token.split(".")
        except ValueError:
            raise VerificationError("Malformed JWT")
        header = json.loads(_b64url_dec(b64h))
        digest_hex = _sha256((b64h + "." + b64p).encode("ascii")).hex()
        jwk = await self._get_pub_jwk()
        await self.verify_digest(digest_hex, b64s, jwk=jwk)
        payload = json.loads(_b64url_dec(b64p))
        now = _now_posix()
        if "nbf" in payload and now < int(payload["nbf"]):
            raise VerificationError("Token not yet valid")
        if "exp" in payload and now >= int(payload["exp"]):
            raise VerificationError("Token expired")
        if audience and "aud" in payload and payload["aud"] != audience:
            raise VerificationError("Audience mismatch")
        if issuer and "iss" in payload and payload["iss"] != issuer:
            raise VerificationError("Issuer mismatch")
        return payload

    async def encrypt_aead(self, plaintext: bytes, *, aad: bytes = b"", alg: str = "AES256-GCM") -> Dict[str, str]:
        return await self._local.encrypt_aead(plaintext, aad=aad, alg=alg)

    async def decrypt_aead(self, obj: Dict[str, str], *, aad: bytes = b"") -> bytes:
        return await self._local.decrypt_aead(obj, aad=aad)

    async def get_jwk(self, *, key_id: Optional[str] = None) -> Jwk:
        return await self._get_pub_jwk()

    async def get_jwks(self) -> Dict[str, Any]:
        return {"keys": [ (await self._get_pub_jwk()).to_dict() ]}

    async def mtls_context(self) -> Optional[ssl.SSLContext]:
        return await self._local.mtls_context()

    async def rotate_key(self, *, key_id: Optional[str] = None) -> str:
        # Реальная ротация в Vault выполняется админом (keys/<name>/rotate).
        return (await self._get_pub_jwk()).kid


# -----------------------------
# AWS KMS provider (подпись/верификация)
# -----------------------------
class AwsKmsSecurityCore(SecurityCoreAdapter):
    """
    AWS KMS асимметричный ключ для подписи (RSA_PSS_2048_SHA256 или ECC_NIST_P256).
    ENV:
      AWS_REGION, KMS_KEY_ID (arn или alias/...)
    AEAD и JWT — через LocalSecurityCore (симметричный ключ локально).
    """
    def __init__(self):
        if boto3 is None:
            raise NotAvailableError("boto3 not available for AWS KMS provider")
        self.region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self.key_id = os.getenv("KMS_KEY_ID")
        if not self.region or not self.key_id:
            raise ProviderError("AWS_REGION and KMS_KEY_ID are required")
        self.kms = boto3.client("kms", region_name=self.region, config=BotoConfig(retries={"max_attempts": 5}))  # type: ignore
        self._local = LocalSecurityCore()
        self._jwk_cache: Optional[Jwk] = None

    async def _get_pub_jwk(self) -> Jwk:
        if self._jwk_cache:
            return self._jwk_cache
        resp = self.kms.get_public_key(KeyId=self.key_id)
        der = resp["PublicKey"]
        if not _CRYPTO:
            raise NotAvailableError("cryptography is not available for JWK conversion")
        pub = serialization.load_der_public_key(der, backend=default_backend())
        if isinstance(pub, rsa.RSAPublicKey):
            nums = pub.public_numbers()
            n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
            jwk = Jwk(kty="RSA", crv=None, n=_b64url(n), e=_b64url(e), x=None, y=None, alg="PS256", kid=_kid_from_der(der))
        elif isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1):
            nums = pub.public_numbers()
            jwk = Jwk(kty="EC", crv="P-256", n=None, e=None, x=_b64url(nums.x.to_bytes(32, "big")), y=_b64url(nums.y.to_bytes(32, "big")), alg="ES256", kid=_kid_from_der(der))
        else:
            raise ProviderError("Unsupported KMS public key type")
        self._jwk_cache = jwk
        return jwk

    async def sign_digest(self, digest_hex: str, *, key_id: Optional[str] = None) -> SignResult:
        msg = _prefixed_msg_from_digest_hex(digest_hex)
        jwk = await self._get_pub_jwk()
        if jwk.alg == "PS256":
            sig = self.kms.sign(KeyId=self.key_id, Message=msg, MessageType="RAW", SigningAlgorithm="RSASSA_PSS_SHA_256")["Signature"]
        elif jwk.alg == "ES256":
            sig = self.kms.sign(KeyId=self.key_id, Message=msg, MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256")["Signature"]
        else:
            raise ProviderError("Unsupported KMS alg")
        return SignResult(alg=jwk.alg, kid=jwk.kid, signature_b64url=_b64url(sig), signed_at=_now_posix())

    async def verify_digest(self, digest_hex: str, signature_b64url: str, *, key_id: Optional[str] = None, jwk: Optional[Jwk] = None) -> None:
        sig = _b64url_dec(signature_b64url)
        msg = _prefixed_msg_from_digest_hex(digest_hex)
        jwk = jwk or await self._get_pub_jwk()
        if jwk.alg == "PS256":
            ok = self.kms.verify(KeyId=self.key_id, Message=msg, Signature=sig, MessageType="RAW", SigningAlgorithm="RSASSA_PSS_SHA_256")["SignatureValid"]
        elif jwk.alg == "ES256":
            ok = self.kms.verify(KeyId=self.key_id, Message=msg, Signature=sig, MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256")["SignatureValid"]
        else:
            raise ProviderError("Unsupported KMS alg")
        if not ok:
            raise VerificationError("KMS verification failed")

    async def mint_jwt(self, claims: Dict[str, Any], *, ttl_s: int, key_id: Optional[str] = None, hdr_extra: Optional[Dict[str, Any]] = None) -> str:
        jwk = await self._get_pub_jwk()
        alg = jwk.alg
        header = {"alg": alg, "typ": "JWT", "kid": jwk.kid}
        if hdr_extra:
            header.update(hdr_extra)
        now = _now_posix()
        body = dict(claims)
        body.setdefault("iat", now)
        body.setdefault("nbf", now)
        body.setdefault("exp", now + int(ttl_s))
        token_unsigned = ".".join(_b64url(json.dumps(x, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) for x in (header, body))
        sig = await self.sign_digest(_sha256(token_unsigned.encode("ascii")).hex())
        return token_unsigned + "." + sig.signature_b64url

    async def verify_jwt(self, token: str, *, audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict[str, Any]:
        try:
            b64h, b64p, b64s = token.split(".")
        except ValueError:
            raise VerificationError("Malformed JWT")
        digest_hex = _sha256((b64h + "." + b64p).encode("ascii")).hex()
        await self.verify_digest(digest_hex, b64s)
        payload = json.loads(_b64url_dec(b64p))
        now = _now_posix()
        if "nbf" in payload and now < int(payload["nbf"]):
            raise VerificationError("Token not yet valid")
        if "exp" in payload and now >= int(payload["exp"]):
            raise VerificationError("Token expired")
        if audience and "aud" in payload and payload["aud"] != audience:
            raise VerificationError("Audience mismatch")
        if issuer and "iss" in payload and payload["iss"] != issuer:
            raise VerificationError("Issuer mismatch")
        return payload

    async def encrypt_aead(self, plaintext: bytes, *, aad: bytes = b"", alg: str = "AES256-GCM") -> Dict[str, str]:
        return await self._local.encrypt_aead(plaintext, aad=aad, alg=alg)

    async def decrypt_aead(self, obj: Dict[str, str], *, aad: bytes = b"") -> bytes:
        return await self._local.decrypt_aead(obj, aad=aad)

    async def get_jwk(self, *, key_id: Optional[str] = None) -> Jwk:
        return await self._get_pub_jwk()

    async def get_jwks(self) -> Dict[str, Any]:
        return {"keys": [ (await self._get_pub_jwk()).to_dict() ]}

    async def mtls_context(self) -> Optional[ssl.SSLContext]:
        return await self._local.mtls_context()

    async def rotate_key(self, *, key_id: Optional[str] = None) -> str:
        return (await self._get_pub_jwk()).kid


# -----------------------------
# Фабрика по окружению
# -----------------------------
def get_adapter_from_env() -> SecurityCoreAdapter:
    """
    SECURITY_CORE_PROVIDER=local|vault|aws-kms
    """
    provider = os.getenv("SECURITY_CORE_PROVIDER", "local").lower()
    if provider == "local":
        return LocalSecurityCore()
    if provider == "vault":
        return VaultTransitSecurityCore()
    if provider == "aws-kms":
        return AwsKmsSecurityCore()
    raise ProviderError(f"Unknown SECURITY_CORE_PROVIDER: {provider}")
