# security-core/security/crypto/signer.py
from __future__ import annotations

import asyncio
import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256, sha384, sha512
from typing import Any, Dict, Iterable, Optional, Tuple, Union

from cryptography import exceptions as cx_exceptions
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ============================= Enums & Options ===============================

class SignatureAlgorithm(str, Enum):
    RSA_PSS = "RSA_PSS"
    RSA_PKCS1v15 = "RSA_PKCS1v15"
    ECDSA = "ECDSA"
    ED25519 = "ED25519"

class HashAlgorithm(str, Enum):
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"

class SignatureEncoding(str, Enum):
    # Для ECDSA: DER (ASN.1 SEQUENCE{r,s}) или RAW (r||s, фикс. длина)
    DER = "DER"
    RAW = "RAW"

DEFAULT_HASH = HashAlgorithm.SHA384  # безопасный дефолт

@dataclass(frozen=True)
class SignOptions:
    algorithm: SignatureAlgorithm = SignatureAlgorithm.RSA_PSS
    hash_alg: HashAlgorithm = DEFAULT_HASH
    ecdsa_encoding: SignatureEncoding = SignatureEncoding.DER
    rsa_pss_salt_len: Optional[int] = None  # по умолчанию = длине хэша
    # Для Ed25519 параметров нет; сообщение подписывается целиком.
    # Для JSON‑подписи:
    json_canonicalization: str = "sorted"  # "sorted" | "none"
    json_ensure_ascii: bool = False  # чтобы байты соответствовали визуальному JSON в UTF‑8

# ============================= Exceptions ====================================

class SignerError(Exception):
    pass

class UnsupportedAlgorithm(SignerError):
    pass

class VerificationError(SignerError):
    pass

# ============================= Utilities =====================================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unb64u(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def _hash_ctx(hash_alg: HashAlgorithm):
    if hash_alg == HashAlgorithm.SHA256:
        return hashes.Hash(hashes.SHA256())
    if hash_alg == HashAlgorithm.SHA384:
        return hashes.Hash(hashes.SHA384())
    if hash_alg == HashAlgorithm.SHA512:
        return hashes.Hash(hashes.SHA512())
    raise UnsupportedAlgorithm(f"Unsupported hash: {hash_alg}")

def _hash_module(hash_alg: HashAlgorithm):
    return {HashAlgorithm.SHA256: sha256, HashAlgorithm.SHA384: sha384, HashAlgorithm.SHA512: sha512}[hash_alg]

def _hash_len_bytes(hash_alg: HashAlgorithm) -> int:
    return {HashAlgorithm.SHA256: 32, HashAlgorithm.SHA384: 48, HashAlgorithm.SHA512: 64}[hash_alg]

def _ecdsa_der_to_raw(der_sig: bytes, curve: ec.EllipticCurve) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der_sig)
    size = (curve.key_size + 7) // 8
    return int.to_bytes(r, size, "big") + int.to_bytes(s, size, "big")

def _ecdsa_raw_to_der(raw_sig: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    half = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:half], "big")
    s = int.from_bytes(raw_sig[half:], "big")
    return encode_dss_signature(r, s)

def _canonicalize_json(obj: Any, ensure_ascii: bool = False) -> bytes:
    """
    Детерминистская канонизация JSON для целей подписи:
    - сортировка ключей (sort_keys=True)
    - минимальные разделители (separators=(',', ':'))
    - двойные кавычки, escape по JSON
    Важно: это НЕ полная реализация RFC 8785 (JCS).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=ensure_ascii).encode("utf-8")

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ============================= Key Providers =================================

class KeyProvider:
    """
    Абстракция поставщика ключа. Реализации: SoftKeyProvider, интеграции с KMS/HSM.
    """

    def sign(self, data: bytes, opts: SignOptions) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def verify(self, data: bytes, signature: bytes, opts: SignOptions) -> bool:  # pragma: no cover
        raise NotImplementedError

    def public_key_pem(self) -> str:  # pragma: no cover
        raise NotImplementedError

    def key_id(self) -> str:
        """
        KID: base64url(SHA-256(SPKI)). Стабильный идентификатор ключа.
        """
        pub = self.public_key_pem().encode()
        pub_obj = serialization.load_pem_public_key(pub)
        spki = pub_obj.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return _b64u(sha256(spki).digest())

    def algorithm_family(self) -> SignatureAlgorithm:  # pragma: no cover
        raise NotImplementedError


class SoftKeyProvider(KeyProvider):
    """
    Хранение ключа в памяти/на диске (PEM/PKCS#8). Поддержка RSA, EC, Ed25519.
    """

    def __init__(self, private_key, public_key=None):
        self._priv = private_key
        if public_key is None:
            self._pub = private_key.public_key()
        else:
            self._pub = public_key

    @staticmethod
    def from_pem(
        pem_private: Union[str, bytes],
        passphrase: Optional[Union[str, bytes]] = None,
    ) -> "SoftKeyProvider":
        password_bytes = None
        if passphrase is not None:
            password_bytes = passphrase.encode() if isinstance(passphrase, str) else passphrase
        priv = serialization.load_pem_private_key(
            pem_private.encode() if isinstance(pem_private, str) else pem_private,
            password=password_bytes,
        )
        return SoftKeyProvider(priv)

    @staticmethod
    def generate(algorithm: SignatureAlgorithm = SignatureAlgorithm.RSA_PSS, bits: int = 4096, curve: str = "secp384r1") -> "SoftKeyProvider":
        if algorithm in (SignatureAlgorithm.RSA_PSS, SignatureAlgorithm.RSA_PKCS1v15):
            priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            return SoftKeyProvider(priv)
        if algorithm == SignatureAlgorithm.ECDSA:
            curve_map = {"secp256r1": ec.SECP256R1(), "secp384r1": ec.SECP384R1(), "secp521r1": ec.SECP521R1()}
            priv = ec.generate_private_key(curve_map[curve])
            return SoftKeyProvider(priv)
        if algorithm == SignatureAlgorithm.ED25519:
            priv = ed25519.Ed25519PrivateKey.generate()
            return SoftKeyProvider(priv)
        raise UnsupportedAlgorithm(f"Generate not supported for {algorithm}")

    def algorithm_family(self) -> SignatureAlgorithm:
        if isinstance(self._priv, rsa.RSAPrivateKey):
            # Конкретная схема зависит от opts; семейство — RSA
            return SignatureAlgorithm.RSA_PSS
        if isinstance(self._priv, ec.EllipticCurvePrivateKey):
            return SignatureAlgorithm.ECDSA
        if isinstance(self._priv, ed25519.Ed25519PrivateKey):
            return SignatureAlgorithm.ED25519
        raise UnsupportedAlgorithm("Unknown key type")

    def sign(self, data: bytes, opts: SignOptions) -> bytes:
        if isinstance(self._priv, rsa.RSAPrivateKey):
            # RSA: PSS или PKCS#1 v1.5 (по opts)
            chosen_hash = {
                HashAlgorithm.SHA256: hashes.SHA256(),
                HashAlgorithm.SHA384: hashes.SHA384(),
                HashAlgorithm.SHA512: hashes.SHA512(),
            }[opts.hash_alg]
            if opts.algorithm == SignatureAlgorithm.RSA_PSS:
                salt_len = opts.rsa_pss_salt_len or _hash_len_bytes(opts.hash_alg)
                pad = padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=salt_len)
                return self._priv.sign(data, pad, chosen_hash)
            if opts.algorithm == SignatureAlgorithm.RSA_PKCS1v15:
                return self._priv.sign(data, padding.PKCS1v15(), chosen_hash)
            raise UnsupportedAlgorithm(f"RSA scheme not supported: {opts.algorithm}")

        if isinstance(self._priv, ec.EllipticCurvePrivateKey):
            chosen_hash = {
                HashAlgorithm.SHA256: hashes.SHA256(),
                HashAlgorithm.SHA384: hashes.SHA384(),
                HashAlgorithm.SHA512: hashes.SHA512(),
            }[opts.hash_alg]
            sig_der = self._priv.sign(data, ec.ECDSA(chosen_hash))
            if opts.ecdsa_encoding == SignatureEncoding.DER:
                return sig_der
            return _ecdsa_der_to_raw(sig_der, self._priv.curve)

        if isinstance(self._priv, ed25519.Ed25519PrivateKey):
            # Ed25519 подписывает само сообщение, без пред‑хэширования
            return self._priv.sign(data)

        raise UnsupportedAlgorithm("Unsupported key type for signing")

    def verify(self, data: bytes, signature: bytes, opts: SignOptions) -> bool:
        try:
            if isinstance(self._pub, rsa.RSAPublicKey):
                chosen_hash = {
                    HashAlgorithm.SHA256: hashes.SHA256(),
                    HashAlgorithm.SHA384: hashes.SHA384(),
                    HashAlgorithm.SHA512: hashes.SHA512(),
                }[opts.hash_alg]
                if opts.algorithm == SignatureAlgorithm.RSA_PSS:
                    salt_len = opts.rsa_pss_salt_len or _hash_len_bytes(opts.hash_alg)
                    pad = padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=salt_len)
                    self._pub.verify(signature, data, pad, chosen_hash)
                elif opts.algorithm == SignatureAlgorithm.RSA_PKCS1v15:
                    self._pub.verify(signature, data, padding.PKCS1v15(), chosen_hash)
                else:
                    raise UnsupportedAlgorithm(f"RSA scheme not supported: {opts.algorithm}")
                return True

            if isinstance(self._pub, ec.EllipticCurvePublicKey):
                chosen_hash = {
                    HashAlgorithm.SHA256: hashes.SHA256(),
                    HashAlgorithm.SHA384: hashes.SHA384(),
                    HashAlgorithm.SHA512: hashes.SHA512(),
                }[opts.hash_alg]
                sig = signature
                if opts.ecdsa_encoding == SignatureEncoding.RAW:
                    sig = _ecdsa_raw_to_der(signature)
                self._pub.verify(sig, data, ec.ECDSA(chosen_hash))
                return True

            if isinstance(self._pub, ed25519.Ed25519PublicKey):
                self._pub.verify(signature, data)
                return True

            raise UnsupportedAlgorithm("Unsupported key type for verification")
        except cx_exceptions.InvalidSignature:
            return False

    def public_key_pem(self) -> str:
        return self._pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    def private_key_pem(self, passphrase: Optional[bytes] = None) -> str:
        enc = NoEncryption() if not passphrase else serialization.BestAvailableEncryption(passphrase)
        return self._priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc).decode()


class KMSKeyProvider(KeyProvider):
    """
    Заглушка для KMS/HSM. Реализуйте sign/verify/public_key_pem, используя
    конкретный провайдер (AWS KMS, GCP KMS, Azure Key Vault, PKCS#11 и т.д.).
    """
    def __init__(self, kid: str, public_pem: str, family: SignatureAlgorithm):
        self._kid = kid
        self._public_pem = public_pem
        self._family = family

    def sign(self, data: bytes, opts: SignOptions) -> bytes:  # pragma: no cover
        raise NotImplementedError("Implement provider-specific sign()")

    def verify(self, data: bytes, signature: bytes, opts: SignOptions) -> bool:
        pub = serialization.load_pem_public_key(self._public_pem.encode())
        soft = SoftKeyProvider(private_key=None, public_key=pub)  # type: ignore[arg-type]
        # SoftKeyProvider.verify ожидает корректные типы — упрощенная переиспользуемость:
        if isinstance(pub, rsa.RSAPublicKey):
            tmp = SoftKeyProvider.generate(SignatureAlgorithm.RSA_PSS)  # dummy to get methods
            tmp._pub = pub
            return tmp.verify(data, signature, opts)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            tmp = SoftKeyProvider.generate(SignatureAlgorithm.ECDSA)
            tmp._pub = pub
            return tmp.verify(data, signature, opts)
        if isinstance(pub, ed25519.Ed25519PublicKey):
            tmp = SoftKeyProvider.generate(SignatureAlgorithm.ED25519)
            tmp._pub = pub
            return tmp.verify(data, signature, opts)
        raise UnsupportedAlgorithm("Unsupported KMS public key type")

    def public_key_pem(self) -> str:
        return self._public_pem

    def key_id(self) -> str:
        # Используем KMS‑идентификатор, если он устойчивый. Иначе — стандартный KID.
        try:
            return self._kid or super().key_id()
        except Exception:
            return super().key_id()

    def algorithm_family(self) -> SignatureAlgorithm:
        return self._family

# ============================= Signer =========================================

class Signer:
    """
    Высокоуровневый интерфейс подписи/проверки.
    Для RSA/ECDSA данные должны быть захэшированы (prehash) в соответствии с opts.hash_alg.
    Для Ed25519 — подписывается сообщение целиком (этот класс сам решит).
    """

    def __init__(self, provider: KeyProvider, opts: Optional[SignOptions] = None):
        self.provider = provider
        self.opts = opts or SignOptions()

    # ---------- Hashing helpers ----------

    def _digest(self, data: bytes) -> bytes:
        if self.opts.algorithm == SignatureAlgorithm.ED25519:
            # Ed25519 подписывает сообщение без хэша
            return data
        h = _hash_module(self.opts.hash_alg)()
        h.update(data)
        return h.digest()

    # ---------- Sign / Verify (bytes) ----------

    def sign(self, message: bytes) -> bytes:
        """
        Возвращает подпись (bytes). Для RSA/ECDSA выполняется prehash.
        """
        to_sign = self._digest(message)
        return self.provider.sign(to_sign, self.opts)

    async def sign_async(self, message: bytes) -> bytes:
        return await asyncio.to_thread(self.sign, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        to_verify = self._digest(message)
        return self.provider.verify(to_verify, signature, self.opts)

    async def verify_async(self, message: bytes, signature: bytes) -> bool:
        return await asyncio.to_thread(self.verify, message, signature)

    # ---------- Encoding helpers ----------

    def sign_b64u(self, message: bytes) -> str:
        return _b64u(self.sign(message))

    def verify_b64u(self, message: bytes, signature_b64u: str) -> bool:
        try:
            sig = _unb64u(signature_b64u)
        except binascii.Error:
            return False
        return self.verify(message, sig)

    # ---------- JSON signing ----------

    def sign_json(self, obj: Any) -> bytes:
        if self.opts.json_canonicalization == "sorted":
            payload = _canonicalize_json(obj, ensure_ascii=self.opts.json_ensure_ascii)
        else:
            payload = json.dumps(obj).encode("utf-8")
        return self.sign(payload)

    def verify_json(self, obj: Any, signature: bytes) -> bool:
        if self.opts.json_canonicalization == "sorted":
            payload = _canonicalize_json(obj, ensure_ascii=self.opts.json_ensure_ascii)
        else:
            payload = json.dumps(obj).encode("utf-8")
        return self.verify(payload, signature)

    # ---------- Streaming (for large payloads) ----------

    class Stream:
        """
        Потоковая подпись для RSA/ECDSA (prehash).
        Для Ed25519 стриминг недоступен (требуется весь message).
        """
        def __init__(self, outer: "Signer"):
            self._outer = outer
            self._ctx = None
            if outer.opts.algorithm == SignatureAlgorithm.ED25519:
                raise UnsupportedAlgorithm("Streaming not supported for Ed25519")
            self._ctx = _hash_ctx(outer.opts.hash_alg)

        def update(self, chunk: bytes) -> None:
            assert self._ctx is not None
            self._ctx.update(chunk)

        def finalize(self) -> bytes:
            assert self._ctx is not None
            digest = self._ctx.finalize()
            return self._outer.provider.sign(digest, self._outer.opts)

    def stream(self) -> "Signer.Stream":
        return Signer.Stream(self)

    # ---------- Key / metadata ----------

    def key_id(self) -> str:
        return self.provider.key_id()

    def public_key_pem(self) -> str:
        return self.provider.public_key_pem()

# ============================= Example factory ================================

def signer_from_pem(
    pem_private: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = None,
    opts: Optional[SignOptions] = None,
) -> Signer:
    prov = SoftKeyProvider.from_pem(pem_private, passphrase=passphrase)
    return Signer(prov, opts or SignOptions())

# ============================= Minimal self-test ==============================

if __name__ == "__main__":  # pragma: no cover
    # Быстрый прогон: RSA‑PSS, ECDSA, Ed25519
    msg = b"The quick brown fox jumps over the lazy dog"

    # RSA‑PSS
    rsa_signer = Signer(SoftKeyProvider.generate(SignatureAlgorithm.RSA_PSS, bits=3072),
                        SignOptions(algorithm=SignatureAlgorithm.RSA_PSS, hash_alg=HashAlgorithm.SHA384))
    sig = rsa_signer.sign(msg)
    assert rsa_signer.verify(msg, sig)
    print("RSA-PSS OK, kid=", rsa_signer.key_id())

    # ECDSA P-384, RAW
    ecdsa_signer = Signer(SoftKeyProvider.generate(SignatureAlgorithm.ECDSA, curve="secp384r1"),
                          SignOptions(algorithm=SignatureAlgorithm.ECDSA, hash_alg=HashAlgorithm.SHA384, ecdsa_encoding=SignatureEncoding.RAW))
    sig2 = ecdsa_signer.sign(msg)
    assert ecdsa_signer.verify(msg, sig2)
    print("ECDSA OK, kid=", ecdsa_signer.key_id())

    # Ed25519
    ed_signer = Signer(SoftKeyProvider.generate(SignatureAlgorithm.ED25519),
                       SignOptions(algorithm=SignatureAlgorithm.ED25519))
    sig3 = ed_signer.sign(msg)
    assert ed_signer.verify(msg, sig3)
    print("Ed25519 OK, kid=", ed_signer.key_id())
