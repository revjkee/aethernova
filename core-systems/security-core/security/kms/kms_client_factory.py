# security-core/security/kms/kms_client_factory.py
from __future__ import annotations

import asyncio
import base64
import functools
import json
import logging
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Protocol, Tuple, Union
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("security_core.kms.factory")


# ============================== Исключения ==============================

class KmsClientError(Exception):
    pass

class KmsUnavailable(KmsClientError):
    pass

class KmsUnsupported(KmsClientError):
    pass

class KmsBadUri(KmsClientError):
    pass


# ============================== Утилиты ==============================

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def _now_ms() -> int:
    return int(time.time() * 1000)

def _with_jitter(base_ms: int, factor: float = 0.2) -> int:
    delta = int(base_ms * factor)
    return base_ms - delta + random.randint(0, 2 * delta)


# ============================== Алгоритмы (нормализация) ==============================

SIGN_ALGS = {
    "RS256": ("RSA", "SHA256"),
    "RS384": ("RSA", "SHA384"),
    "RS512": ("RSA", "SHA512"),
    "PS256": ("RSA_PSS", "SHA256"),
    "PS384": ("RSA_PSS", "SHA384"),
    "PS512": ("RSA_PSS", "SHA512"),
    "ES256": ("ECDSA", "SHA256"),
    "ES384": ("ECDSA", "SHA384"),
    "ES512": ("ECDSA", "SHA512"),
    "EdDSA": ("EDDSA", None),
    "HS256": ("HMAC", "SHA256"),
    "HS384": ("HMAC", "SHA384"),
    "HS512": ("HMAC", "SHA512"),
}

ENC_ALGS = {
    "RSA_OAEP_SHA256": ("RSA_OAEP", "SHA256"),
    "AES_GCM_128": ("AES_GCM", 16),
    "AES_GCM_256": ("AES_GCM", 32),
}

WRAP_ALGS = {
    "AES_KW_256_RFC3394": ("AES_KW", 32, False),
    "AES_KWP_256_RFC5649": ("AES_KW", 32, True),
}

# ============================== Протокол клиента KMS ==============================

class KmsClient(Protocol):
    """
    Унифицированное асинхронное API. name_ref — провайдер‑специфичная ссылка на ключ/версию.
    Все байты в/из — base64url‑строки для удобства сериализации.
    """
    async def get_public_key(self, name_ref: str, *, encoding: str = "SPKI-PEM") -> str: ...
    async def sign(self, name_ref: str, *, algorithm: str, digest_b64u: Optional[str] = None, message_b64u: Optional[str] = None, salt_b64u: Optional[str] = None, context: Optional[Mapping[str, str]] = None) -> str: ...
    async def verify(self, name_ref: str, *, algorithm: str, signature_b64u: str, digest_b64u: Optional[str] = None, message_b64u: Optional[str] = None) -> bool: ...
    async def encrypt(self, name_ref: str, *, algorithm: str, plaintext_b64u: str, aad_b64u: Optional[str] = None) -> Mapping[str, str]: ...
    async def decrypt(self, name_ref: str, *, algorithm: str, ciphertext_b64u: str, iv_b64u: Optional[str] = None, tag_b64u: Optional[str] = None, aad_b64u: Optional[str] = None) -> str: ...
    async def wrap_key(self, name_ref: str, *, algorithm: str, target_key_b64u: str, aad_b64u: Optional[str] = None) -> str: ...
    async def unwrap_key(self, name_ref: str, *, algorithm: str, wrapped_key_b64u: str, aad_b64u: Optional[str] = None) -> str: ...
    async def close(self) -> None: ...


# ============================== Soft (локальный) KMS клиент ==============================

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap, aes_key_wrap_with_padding, aes_key_unwrap_with_padding
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

class SoftKmsClient:
    """
    Реальная локальная реализация через cryptography:
    - RSA: RS*/PS*, RSA‑OAEP
    - EC: ES*
    - OKP: EdDSA
    - HMAC: HS*
    - AES‑GCM (128/256)
    - AES‑KW/KWP (RFC3394/5649)
    Ключи загружаются из PEM/JWK, name_ref='local:<alias>'
    """
    def __init__(self, key_store: Mapping[str, Any]) -> None:
        if not _HAVE_CRYPTO:
            raise KmsUnsupported("cryptography is required for SoftKmsClient")
        self._keys = dict(key_store)  # alias -> crypto key/bytes

    async def get_public_key(self, name_ref: str, *, encoding: str = "SPKI-PEM") -> str:
        key = self._get(name_ref)
        if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            pub = key.public_key()
        elif isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub = key
        elif isinstance(key, (bytes, bytearray)):  # symmetric не имеет публичного
            raise KmsUnsupported("symmetric key has no public part")
        else:
            raise KmsUnsupported("unsupported key type")
        if encoding == "SPKI-PEM":
            pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            return pem.decode()
        if encoding == "SPKI-DER":
            der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return b64u(der)
        raise KmsUnsupported(f"unsupported encoding {encoding}")

    async def sign(self, name_ref: str, *, algorithm: str, digest_b64u: Optional[str] = None, message_b64u: Optional[str] = None, salt_b64u: Optional[str] = None, context: Optional[Mapping[str, str]] = None) -> str:
        key = self._get(name_ref)
        fam, hname = SIGN_ALGS.get(algorithm, (None, None))
        if fam is None:
            raise KmsUnsupported(f"algorithm {algorithm} not supported")
        msg = b""
        if digest_b64u:
            msg = b64u_d(digest_b64u)
        elif message_b64u:
            msg = b64u_d(message_b64u)
        else:
            raise KmsClientError("either digest_b64u or message_b64u must be provided")

        if fam == "HMAC":
            if not isinstance(key, (bytes, bytearray)):
                raise KmsUnsupported("HMAC requires symmetric bytes key")
            import hashlib, hmac as _h
            digest = getattr(hashlib, hname.lower())
            sig = _h.new(key, msg, digest).digest()
            return b64u(sig)

        if fam == "RSA":
            if not isinstance(key, rsa.RSAPrivateKey):
                raise KmsUnsupported("RS* requires RSA private key")
            h = getattr(hashes, hname)()
            sig = key.sign(msg, padding.PKCS1v15(), h)
            return b64u(sig)

        if fam == "RSA_PSS":
            if not isinstance(key, rsa.RSAPrivateKey):
                raise KmsUnsupported("PS* requires RSA private key")
            h = getattr(hashes, hname)()
            sig = key.sign(msg, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
            return b64u(sig)

        if fam == "ECDSA":
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise KmsUnsupported("ES* requires EC private key")
            h = getattr(hashes, hname)()
            der = key.sign(msg, ec.ECDSA(h))
            # JWS использует raw(R||S), но мы оставляем DER: консюмер должен знать формат
            return b64u(der)

        if fam == "EDDSA":
            if isinstance(key, ed25519.Ed25519PrivateKey) or isinstance(key, ed448.Ed448PrivateKey):
                return b64u(key.sign(msg))
            raise KmsUnsupported("EdDSA requires Ed25519/Ed448 private key")

        raise KmsUnsupported(f"unsupported family {fam}")

    async def verify(self, name_ref: str, *, algorithm: str, signature_b64u: str, digest_b64u: Optional[str] = None, message_b64u: Optional[str] = None) -> bool:
        key = self._get(name_ref)
        fam, hname = SIGN_ALGS.get(algorithm, (None, None))
        if fam is None:
            raise KmsUnsupported(f"algorithm {algorithm} not supported")
        msg = b64u_d(digest_b64u) if digest_b64u else b64u_d(message_b64u or "")
        sig = b64u_d(signature_b64u)

        try:
            if fam == "HMAC":
                if not isinstance(key, (bytes, bytearray)):
                    return False
                import hashlib, hmac as _h
                digest = getattr(hashlib, hname.lower())
                exp = _h.new(key, msg, digest).digest()
                import hmac as _hh
                return _hh.compare_digest(exp, sig)

            if fam == "RSA":
                if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
                    return False
                pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
                h = getattr(hashes, hname)()
                pub.verify(sig, msg, padding.PKCS1v15(), h)
                return True

            if fam == "RSA_PSS":
                if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
                    return False
                pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
                h = getattr(hashes, hname)()
                pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
                return True

            if fam == "ECDSA":
                if not isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
                    return False
                pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
                h = getattr(hashes, hname)()
                pub.verify(sig, msg, ec.ECDSA(h))
                return True

            if fam == "EDDSA":
                if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey, ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
                    pub = key.public_key() if hasattr(key, "public_key") else key
                    pub.verify(sig, msg)
                    return True
                return False
        except InvalidSignature:
            return False
        return False

    async def encrypt(self, name_ref: str, *, algorithm: str, plaintext_b64u: str, aad_b64u: Optional[str] = None) -> Mapping[str, str]:
        key = self._get(name_ref)
        fam, param = ENC_ALGS.get(algorithm, (None, None))
        pt = b64u_d(plaintext_b64u)
        aad = b64u_d(aad_b64u) if aad_b64u else None

        if fam == "RSA_OAEP":
            if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
                raise KmsUnsupported("RSA_OAEP requires RSA key")
            pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
            h = hashes.SHA256()
            ct = pub.encrypt(pt, padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None))
            return {"ciphertext": b64u(ct)}
        if fam == "AES_GCM":
            if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 32):
                raise KmsUnsupported("AES_GCM requires 16/32 byte key")
            import os
            iv = os.urandom(12)
            aes = AESGCM(bytes(key))
            ct = aes.encrypt(iv, pt, aad)
            # ct = ciphertext || tag
            ciphertext, tag = ct[:-16], ct[-16:]
            return {"ciphertext": b64u(ciphertext), "iv": b64u(iv), "tag": b64u(tag)}
        raise KmsUnsupported(f"algorithm {algorithm} not supported for encrypt")

    async def decrypt(self, name_ref: str, *, algorithm: str, ciphertext_b64u: str, iv_b64u: Optional[str] = None, tag_b64u: Optional[str] = None, aad_b64u: Optional[str] = None) -> str:
        key = self._get(name_ref)
        fam, _ = ENC_ALGS.get(algorithm, (None, None))

        if fam == "RSA_OAEP":
            if not isinstance(key, rsa.RSAPrivateKey):
                raise KmsUnsupported("RSA_OAEP decrypt requires RSA private key")
            h = hashes.SHA256()
            pt = key.decrypt(b64u_d(ciphertext_b64u), padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None))
            return b64u(pt)

        if fam == "AES_GCM":
            if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 32):
                raise KmsUnsupported("AES_GCM requires 16/32 byte key")
            if iv_b64u is None or tag_b64u is None:
                raise KmsClientError("AES_GCM requires iv and tag")
            iv = b64u_d(iv_b64u)
            aad = b64u_d(aad_b64u) if aad_b64u else None
            ct = b64u_d(ciphertext_b64u) + b64u_d(tag_b64u)
            aes = AESGCM(bytes(key))
            pt = aes.decrypt(iv, ct, aad)
            return b64u(pt)

        raise KmsUnsupported(f"algorithm {algorithm} not supported for decrypt")

    async def wrap_key(self, name_ref: str, *, algorithm: str, target_key_b64u: str, aad_b64u: Optional[str] = None) -> str:
        key = self._get(name_ref)
        fam, size, padded = WRAP_ALGS.get(algorithm, (None, None, None))
        if fam != "AES_KW":
            raise KmsUnsupported(f"algorithm {algorithm} not supported for wrap")
        kek = bytes(key) if isinstance(key, (bytes, bytearray)) else None
        if not kek or len(kek) != size:
            raise KmsUnsupported(f"AES_KW requires {size}‑byte KEK")
        kid = b64u_d(target_key_b64u)
        if padded:
            return b64u(aes_key_wrap_with_padding(kek, kid))
        return b64u(aes_key_wrap(kek, kid))

    async def unwrap_key(self, name_ref: str, *, algorithm: str, wrapped_key_b64u: str, aad_b64u: Optional[str] = None) -> str:
        key = self._get(name_ref)
        fam, size, padded = WRAP_ALGS.get(algorithm, (None, None, None))
        if fam != "AES_KW":
            raise KmsUnsupported(f"algorithm {algorithm} not supported for unwrap")
        kek = bytes(key) if isinstance(key, (bytes, bytearray)) else None
        if not kek or len(kek) != size:
            raise KmsUnsupported(f"AES_KW requires {size}‑byte KEK")
        wk = b64u_d(wrapped_key_b64u)
        if padded:
            return b64u(aes_key_unwrap_with_padding(kek, wk))
        return b64u(aes_key_unwrap(kek, wk))

    async def close(self) -> None:
        return

    def _get(self, name_ref: str) -> Any:
        # name_ref ожидается как "local:<alias>"
        if not name_ref.startswith("local:"):
            raise KmsBadUri("SoftKmsClient expects name_ref starting with 'local:'")
        alias = name_ref.split(":", 1)[1]
        if alias not in self._keys:
            raise KmsClientError(f"key alias not found: {alias}")
        return self._keys[alias]


# ============================== Другие адаптеры (SDK‑зависимые заглушки) ==============================

class _SdkStub:
    def __init__(self, provider: str, reason: str) -> None:
        self.provider = provider
        self.reason = reason

    def __getattr__(self, name: str) -> Any:
        async def _err(*_a, **_kw):
            raise KmsUnavailable(f"{self.provider} client is not available: {self.reason}")
        return _err

# AWS
def _make_aws_client(**kw) -> KmsClient:
    try:
        import boto3  # type: ignore
        # Здесь можно инициализировать boto3.client("kms", region_name=...)
        # Реализацию операций подписи/шифрования добавьте при подключении SDK.
        return _SdkStub("aws-kms", "implement integration with boto3.client('kms')")  # type: ignore
    except Exception as e:
        return _SdkStub("aws-kms", f"boto3 missing or init failed: {e}")  # type: ignore

# GCP
def _make_gcp_client(**kw) -> KmsClient:
    try:
        from google.cloud import kms  # type: ignore
        return _SdkStub("gcp-kms", "implement integration with google.cloud.kms")  # type: ignore
    except Exception as e:
        return _SdkStub("gcp-kms", f"google-cloud-kms missing or init failed: {e}")  # type: ignore

# Azure
def _make_azure_client(**kw) -> KmsClient:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.keyvault.keys.crypto import CryptographyClient  # type: ignore
        return _SdkStub("azure-kv", "implement integration with azure-keyvault-keys")  # type: ignore
    except Exception as e:
        return _SdkStub("azure-kv", f"azure sdk missing or init failed: {e}")  # type: ignore

# Vault transit
def _make_vault_client(**kw) -> KmsClient:
    try:
        import hvac  # type: ignore
        return _SdkStub("vault-transit", "implement integration with hvac.Client().secrets.transit")  # type: ignore
    except Exception as e:
        return _SdkStub("vault-transit", f"hvac missing or init failed: {e}")  # type: ignore

# PKCS#11
def _make_pkcs11_client(**kw) -> KmsClient:
    try:
        import pkcs11  # type: ignore
        return _SdkStub("pkcs11", "implement integration with python-pkcs11")  # type: ignore
    except Exception as e:
        return _SdkStub("pkcs11", f"python-pkcs11 missing or init failed: {e}")  # type: ignore

# Внутренний сервис security-core по HTTP(S)
def _make_seckms_http_client(base_url: str, token: Optional[str]) -> KmsClient:
    try:
        import httpx  # type: ignore
    except Exception as e:
        return _SdkStub("sec-kms", f"httpx missing: {e}")  # type: ignore

    class _SecKmsHttpClient:
        def __init__(self, base_url: str, token: Optional[str]) -> None:
            self.base = base_url.rstrip("/")
            self.token = token
            self._cli = httpx.AsyncClient(timeout=5.0)

        def _hdr(self) -> Dict[str, str]:
            h = {"accept": "application/json"}
            if self.token:
                h["authorization"] = f"Bearer {self.token}"
            return h

        async def get_public_key(self, name_ref: str, *, encoding: str = "SPKI-PEM") -> str:
            # name_ref: keys/{key} или keys/{key}/versions/{v}
            url = f"{self.base}/{name_ref}/public"
            r = await self._cli.get(url, headers=self._hdr(), params={"preferred_encoding": "PEM" if encoding == "SPKI-PEM" else "DER"})
            r.raise_for_status()
            return r.json().get("pem") or r.json().get("key_bytes")

        async def sign(self, name_ref: str, *, algorithm: str, digest_b64u: Optional[str] = None, message_b64u: Optional[str] = None, salt_b64u: Optional[str] = None, context: Optional[Mapping[str, str]] = None) -> str:
            url = f"{self.base}/{name_ref}:sign"
            body = {"signature_algorithm": algorithm, "digest": digest_b64u, "plaintext": message_b64u, "salt": salt_b64u, "context": dict(context or {})}
            r = await self._cli.post(url, headers=self._hdr(), json=body)
            r.raise_for_status()
            return r.json()["signature"]

        async def verify(self, name_ref: str, *, algorithm: str, signature_b64u: str, digest_b64u: Optional[str] = None, message_b64u: Optional[str] = None) -> bool:
            url = f"{self.base}/keys:verify"
            body = {"signature_algorithm": algorithm, "digest": digest_b64u, "plaintext": message_b64u, "signature": signature_b64u}
            r = await self._cli.post(url, headers=self._hdr(), params={"name_ref": name_ref}, json=body)
            r.raise_for_status()
            return bool(r.json().get("valid", False))

        async def encrypt(self, name_ref: str, *, algorithm: str, plaintext_b64u: str, aad_b64u: Optional[str] = None) -> Mapping[str, str]:
            url = f"{self.base}/{name_ref}:encrypt"
            body = {"encryption_algorithm": algorithm, "plaintext": plaintext_b64u, "aad": aad_b64u}
            r = await self._cli.post(url, headers=self._hdr(), json=body)
            r.raise_for_status()
            return r.json()

        async def decrypt(self, name_ref: str, *, algorithm: str, ciphertext_b64u: str, iv_b64u: Optional[str] = None, tag_b64u: Optional[str] = None, aad_b64u: Optional[str] = None) -> str:
            url = f"{self.base}/{name_ref}:decrypt"
            body = {"encryption_algorithm": algorithm, "ciphertext": ciphertext_b64u, "iv": iv_b64u, "tag": tag_b64u, "aad": aad_b64u}
            r = await self._cli.post(url, headers=self._hdr(), json=body)
            r.raise_for_status()
            return r.json()["plaintext"]

        async def wrap_key(self, name_ref: str, *, algorithm: str, target_key_b64u: str, aad_b64u: Optional[str] = None) -> str:
            url = f"{self.base}/{name_ref}:wrap"
            body = {"algorithm": algorithm, "target_key_material": target_key_b64u, "aad": aad_b64u}
            r = await self._cli.post(url, headers=self._hdr(), json=body)
            r.raise_for_status()
            return r.json()["wrapped_key"]

        async def unwrap_key(self, name_ref: str, *, algorithm: str, wrapped_key_b64u: str, aad_b64u: Optional[str] = None) -> str:
            url = f"{self.base}/{name_ref}:unwrap"
            body = {"algorithm": algorithm, "wrapped_key": wrapped_key_b64u, "aad": aad_b64u}
            r = await self._cli.post(url, headers=self._hdr(), json=body)
            r.raise_for_status()
            return r.json()["key_material"]

        async def close(self) -> None:
            await self._cli.aclose()

    return _SecKmsHttpClient(base_url=base_url, token=token)  # type: ignore


# ============================== URI парсинг и фабрика ==============================

@dataclass(frozen=True)
class KmsTarget:
    scheme: str
    # canonical name_ref для операций, без схемы (напр., 'keys/mykey/versions/1' или 'local:alias')
    name_ref: str
    # вспомогательные параметры из URI
    params: Dict[str, str]

def parse_kms_uri(uri: str) -> KmsTarget:
    """
    Поддерживаемые схемы:
      - soft://local/<alias>?keyfile=... (локальный alias из заранее загруженного key_store)
      - file://... (PEM/JWK путь; alias из имени файла)
      - sec-kms://<host>/tenants/{tenant}/keys/{key}[/versions/{v}]
      - aws-kms://<region>/<key-id>|arn:aws:kms:...
      - gcp-kms://projects/.../cryptoKeys/<k>[/cryptoKeyVersions/<v>]
      - azure-kv://<vault-host>/keys/<name>/<version>
      - vault-transit://<addr>/transit/keys/<name>
      - pkcs11://slot/<n>/id/<hex> или label/<lbl>
    """
    if not uri:
        raise KmsBadUri("empty uri")
    u = urlparse(uri)
    scheme = u.scheme.lower()
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    # Нормализуем name_ref для конкретных провайдеров
    if scheme == "soft":
        # soft://local/alias -> name_ref='local:alias'
        seg = u.path.lstrip("/").split("/")
        if len(seg) != 2 or seg[0] != "local" or not seg[1]:
            raise KmsBadUri("soft://local/<alias> expected")
        return KmsTarget(scheme=scheme, name_ref=f"local:{seg[1]}", params=q)

    if scheme == "file":
        path = (u.netloc + u.path) or ""
        if not path:
            raise KmsBadUri("file path is empty")
        alias = os.path.splitext(os.path.basename(path))[0]
        return KmsTarget(scheme=scheme, name_ref=f"local:{alias}", params={"path": path, **q})

    if scheme == "sec-kms":
        # sec-kms://api.example/api/v1/tenants/t/keys/k[/versions/v]
        host = u.netloc
        path = u.path.lstrip("/")
        if not host or not path:
            raise KmsBadUri("sec-kms requires host and path")
        base = f"https://{host}/api/v1/tenants" if q.get("base") is None else q["base"].rstrip("/")
        token = q.get("token")
        # name_ref — хвост начиная с 'keys/...'
        parts = path.split("/")
        try:
            keys_idx = parts.index("keys")
        except ValueError as e:
            raise KmsBadUri("sec-kms path must contain /keys/") from e
        name_ref = "/".join(parts[keys_idx:])  # keys/{key}[...]
        return KmsTarget(scheme=scheme, name_ref=name_ref, params={"base": base, "token": token})

    # Остальные схемы: сохраняем path как name_ref, провайдер адаптер сам разберётся
    return KmsTarget(scheme=scheme, name_ref=(u.netloc + u.path), params=q)


# ============================== Retry / backoff ==============================

async def _retry_async(fn: Callable[[], Awaitable[Any]], *, attempts: int = 5, base_backoff_ms: int = 50, retriable: Optional[Callable[[Exception], bool]] = None) -> Any:
    last = None
    for i in range(attempts):
        try:
            return await fn()
        except Exception as e:  # pragma: no cover
            last = e
            if retriable and not retriable(e):
                break
            await asyncio.sleep(_with_jitter(base_backoff_ms * (2 ** i)) / 1000.0)
    assert last is not None
    raise last


# ============================== Фабрика и кэш клиентов ==============================

class KmsClientFactory:
    """
    Потокобезопасная фабрика/кэш клиентов KMS с разрешением по URI.
    """
    def __init__(
        self,
        *,
        metrics_hook: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
        soft_key_store: Optional[Mapping[str, Any]] = None,  # alias -> key object/bytes
    ) -> None:
        self._lock = threading.RLock()
        self._clients: Dict[Tuple[str, str], KmsClient] = {}  # (scheme, tenant/host bucket) -> client
        self._metrics = metrics_hook
        self._soft_keys = dict(soft_key_store or {})

    def _metric(self, name: str, tags: Mapping[str, Any]) -> None:
        try:
            if self._metrics:
                self._metrics(name, tags)
        except Exception:
            pass

    async def get(self, uri: str) -> Tuple[KmsClient, str]:
        """
        Возвращает (client, name_ref) для данного KMS URI.
        """
        tgt = parse_kms_uri(uri)
        key = self._cache_key(tgt)
        with self._lock:
            cli = self._clients.get(key)
            if cli:
                return cli, tgt.name_ref

        cli = await self._create_client(tgt)
        with self._lock:
            self._clients[key] = cli
        self._metric("kms_client_created", {"scheme": tgt.scheme})
        return cli, tgt.name_ref

    def _cache_key(self, tgt: KmsTarget) -> Tuple[str, str]:
        # Бакетизируем по схеме и «хосту»/базе, чтобы переиспользовать соединения.
        if tgt.scheme == "sec-kms":
            return (tgt.scheme, tgt.params.get("base", ""))
        if tgt.scheme in ("aws-kms", "gcp-kms", "azure-kv", "vault-transit", "pkcs11"):
            return (tgt.scheme, tgt.name_ref.split("/")[0] or "")
        if tgt.scheme in ("soft", "file"):
            return (tgt.scheme, "local")
        return (tgt.scheme, "")

    async def _create_client(self, tgt: KmsTarget) -> KmsClient:
        if tgt.scheme == "soft":
            return SoftKmsClient(self._soft_keys)
        if tgt.scheme == "file":
            # Загрузим ключ в soft_key_store один раз
            path = tgt.params.get("path")
            if not path:
                raise KmsBadUri("file path missing")
            keyobj = _load_key_from_file(path)
            alias = _alias_from_path(path)
            with self._lock:
                self._soft_keys.setdefault(alias, keyobj)
            return SoftKmsClient(self._soft_keys)
        if tgt.scheme == "sec-kms":
            base = tgt.params.get("base")
            token = tgt.params.get("token")
            if not base:
                raise KmsBadUri("sec-kms base url missing")
            return _make_seckms_http_client(base_url=base, token=token)

        if tgt.scheme == "aws-kms":
            return _make_aws_client()
        if tgt.scheme == "gcp-kms":
            return _make_gcp_client()
        if tgt.scheme == "azure-kv":
            return _make_azure_client()
        if tgt.scheme == "vault-transit":
            return _make_vault_client()
        if tgt.scheme == "pkcs11":
            return _make_pkcs11_client()

        raise KmsUnsupported(f"unsupported KMS scheme: {tgt.scheme}")

    async def close(self) -> None:
        with self._lock:
            items = list(self._clients.items())
            self._clients.clear()
        for (_, _), cli in items:
            try:
                await cli.close()
            except Exception:
                pass


# ============================== Загрузка ключей из файла (PEM/JWK) ==============================

def _alias_from_path(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]

def _load_key_from_file(path: str) -> Any:
    if not _HAVE_CRYPTO:
        raise KmsUnsupported("cryptography is required to load keys from file")
    from cryptography.hazmat.primitives import serialization
    data = open(path, "rb").read()
    # Попробуем JWK
    try:
        j = json.loads(data.decode("utf-8"))
        if "kty" in j:
            return _load_key_from_jwk(j)
    except Exception:
        pass
    # PEM/DER
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception:
        try:
            return serialization.load_pem_public_key(data)
        except Exception:
            try:
                return serialization.load_der_private_key(data, password=None)
            except Exception:
                return serialization.load_der_public_key(data)

def _load_key_from_jwk(jwk: Mapping[str, Any]) -> Any:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
    from cryptography.hazmat.primitives.serialization import load_pem_private_key  # noqa: F401
    kty = jwk.get("kty")
    if kty == "oct":
        return b64u_d(jwk["k"])
    if kty == "RSA":
        n = int.from_bytes(b64u_d(jwk["n"]), "big")
        e = int.from_bytes(b64u_d(jwk["e"]), "big")
        if "d" in jwk:
            d = int.from_bytes(b64u_d(jwk["d"]), "big")
            p = int.from_bytes(b64u_d(jwk["p"]), "big") if "p" in jwk else None
            q = int.from_bytes(b64u_d(jwk["q"]), "big") if "q" in jwk else None
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            pub = _rsa.RSAPublicNumbers(e, n)
            if p and q:
                priv = _rsa.RSAPrivateNumbers(
                    p=p, q=q, d=d,
                    dmp1=int.from_bytes(b64u_d(jwk["dp"]), "big") if "dp" in jwk else 0,
                    dmq1=int.from_bytes(b64u_d(jwk["dq"]), "big") if "dq" in jwk else 0,
                    iqmp=int.from_bytes(b64u_d(jwk["qi"]), "big") if "qi" in jwk else 0,
                    public_numbers=pub
                ).private_key()
            else:
                # минимальная сборка без CRT
                priv = rsa.RSAPrivateNumbers(
                    p=0, q=0, d=d, dmp1=0, dmq1=0, iqmp=0, public_numbers=pub
                ).private_key()
            return priv
        else:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            return _rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        curve = {"P-256": _ec.SECP256R1(), "P-384": _ec.SECP384R1(), "P-521": _ec.SECP521R1()}[jwk["crv"]]
        x = int.from_bytes(b64u_d(jwk["x"]), "big")
        y = int.from_bytes(b64u_d(jwk["y"]), "big")
        if "d" in jwk:
            d = int.from_bytes(b64u_d(jwk["d"]), "big")
            pub = _ec.EllipticCurvePublicNumbers(x, y, curve)
            return _ec.EllipticCurvePrivateNumbers(d, pub).private_key()
        else:
            return _ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    if kty == "OKP":
        crv = jwk["crv"]
        if crv == "Ed25519":
            if "d" in jwk:
                return ed25519.Ed25519PrivateKey.from_private_bytes(b64u_d(jwk["d"]))
            return ed25519.Ed25519PublicKey.from_public_bytes(b64u_d(jwk["x"]))
        if crv == "Ed448":
            if "d" in jwk:
                return ed448.Ed448PrivateKey.from_private_bytes(b64u_d(jwk["d"]))
            return ed448.Ed448PublicKey.from_public_bytes(b64u_d(jwk["x"]))
    raise KmsUnsupported(f"unsupported JWK kty {kty}")


# ============================== Пример использования ==============================

"""
# 1) SoftKmsClient с локальными ключами:
from cryptography.hazmat.primitives.asymmetric import rsa
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
factory = KmsClientFactory(soft_key_store={"rsa1": priv})
client, ref = asyncio.run(factory.get("soft://local/rsa1"))
sig = asyncio.run(client.sign(ref, algorithm="RS256", message_b64u=b64u(b"hello")))
ok = asyncio.run(client.verify(ref, algorithm="RS256", signature_b64u=sig, message_b64u=b64u(b"hello")))

# 2) Загрузка из файла:
client2, ref2 = asyncio.run(factory.get("file:///etc/keys/ed25519_private.pem"))

# 3) Внутренний HTTP сервис security-core (см. routers/v1/keys.py):
uri = "sec-kms://kms.internal/api/v1/tenants/tenantA/keys/mykey/versions/1?token=...&base=https://kms.internal/api/v1/tenants"
client3, ref3 = asyncio.run(factory.get(uri))
sig = asyncio.run(client3.sign(ref3, algorithm="EdDSA", message_b64u=b64u(b"abc")))
"""
