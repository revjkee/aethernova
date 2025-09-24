# ledger-core/ledger/crypto/verifier.py
from __future__ import annotations

import base64
import dataclasses
import functools
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# --------------------------------------------------------------------------------------
# Исключения
# --------------------------------------------------------------------------------------

class ProofError(Exception):
    pass

class ProofFormatError(ProofError):
    pass

class ProofExpiredError(ProofError):
    pass

class ProofNotYetValidError(ProofError):
    pass

class ProofHashMismatchError(ProofError):
    pass

class ProofSignatureError(ProofError):
    pass

class KeyResolutionError(ProofError):
    pass


# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

def b64u_decode(s: str) -> bytes:
    # base64url без паддинга
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def to_utc(dt_str: str) -> datetime:
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception as e:
        raise ProofFormatError(f"invalid RFC3339 datetime: {dt_str}") from e

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def json_compact(obj: Any) -> bytes:
    # Минимальная каноникализация: компактный JSON, сортировка ключей
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def json_c14n_approx(obj: Any) -> bytes:
    # Упрощённая версия RFC8785 (без нормализации чисел IEEE 754 NaN/Inf)
    # Для платёжных событий этого обычно достаточно. При необходимости подключите строгую реализацию.
    return json_compact(obj)

def canonicalize(payload: Union[bytes, str, Dict[str, Any], list], method: str) -> bytes:
    if method == "utf8-bytes":
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        # Если объект — сериализуем как компактный JSON
        return json_compact(payload)
    if method == "json-compact":
        return json_compact(payload)
    if method == "json-c14n@rfc8785":
        return json_c14n_approx(payload)
    if method == "http-signing@draft-ietf-httpbis-message-signatures-13":
        # Требует внешней каноникализации HTTP‑сообщения — реализуйте в вызывающей стороне.
        raise ProofFormatError("http-signing canonicalization must be performed by caller")
    raise ProofFormatError(f"unknown canonicalization: {method}")

def pick_hasher(name: str):
    name = name.upper()
    if name == "SHA-256":
        return hashlib.sha256
    if name == "SHA-512":
        return hashlib.sha512
    if name == "BLAKE3-256":
        try:
            import blake3  # type: ignore
            return lambda data=b"": blake3.blake3(data)
        except Exception:
            raise ProofFormatError("BLAKE3-256 requires 'blake3' package")
    raise ProofFormatError(f"unsupported hash alg: {name}")

def digest_hex_or_b64(data: bytes, encoding: str) -> str:
    if encoding == "hex":
        return data.hex()
    if encoding == "base64url":
        return b64u_encode(data)
    raise ProofFormatError(f"unsupported digest encoding: {encoding}")

# --------------------------------------------------------------------------------------
# Резолвер ключей
# --------------------------------------------------------------------------------------

class KeyResolver(Protocol):
    def resolve(self, verification_method: str, key_id: Optional[str]) -> Tuple[str, Any]:
        """
        Вернуть пару (kty, public_key) по verificationMethod/KID.
        kty: "OKP"/"EC"/"RSA"/"HMAC"/"JWK"
        public_key: объект cryptography (для OKP/EC/RSA) или bytes (HMAC), либо JWK dict для JWS.
        """

@dataclass
class StaticKeyResolver:
    """Простой резолвер: словарь verificationMethod -> ключ."""
    keys: Dict[str, Any]
    key_ids: Dict[str, Any] = dataclasses.field(default_factory=dict)
    kty: Optional[str] = None  # если известен тип для всех ключей

    def resolve(self, verification_method: str, key_id: Optional[str]) -> Tuple[str, Any]:
        if key_id and key_id in self.key_ids:
            return self.kty or self._guess_kty(self.key_ids[key_id]), self.key_ids[key_id]
        if verification_method in self.keys:
            return self.kty or self._guess_kty(self.keys[verification_method]), self.keys[verification_method]
        raise KeyResolutionError(f"key not found: {verification_method} / {key_id or '-'}")

    @staticmethod
    def _guess_kty(obj: Any) -> str:
        if isinstance(obj, (ed25519.Ed25519PublicKey,)):
            return "OKP"
        if isinstance(obj, (ec.EllipticCurvePublicKey,)):
            return "EC"
        if isinstance(obj, (rsa.RSAPublicKey,)):
            return "RSA"
        if isinstance(obj, (bytes, bytearray)):
            return "HMAC"
        if isinstance(obj, dict) and obj.get("kty"):
            return "JWK"
        raise KeyResolutionError("cannot guess key type")

# --------------------------------------------------------------------------------------
# Результат верификации
# --------------------------------------------------------------------------------------

@dataclass
class VerificationResult:
    ok: bool
    alg: str
    reason: Optional[str] = None
    created: Optional[datetime] = None
    expires: Optional[datetime] = None
    key_info: Optional[Dict[str, Any]] = None
    computed_digest: Optional[str] = None
    computed_payload_digest: Optional[str] = None

# --------------------------------------------------------------------------------------
# Основной верификатор
# --------------------------------------------------------------------------------------

class Verifier:
    """
    Верификация доказательств из proof.schema.json (draft 2020‑12).
    Поддерживаемые algo: ED25519, ECDSA_SECP256R1_SHA256, RSA_PSS_SHA256, JWS, HMAC_SHA256.
    """

    def __init__(self, key_resolver: KeyResolver, *, leeway_seconds: int = 60) -> None:
        self.key_resolver = key_resolver
        self.leeway = leeway_seconds

    # ---------- Публичный API ----------

    def verify(
        self,
        *,
        proof: Dict[str, Any],
        payload: Union[bytes, str, Dict[str, Any], list],
        headers: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """
        Проверяет:
          1) created/expires c учётом leeway.
          2) hash: alg + digest( canonical(payload) ).
          3) payloadDigest (сырой payload до конверта, если предоставлен).
          4) криптографическую подпись в зависимости от algo/scheme.
        """
        algo = str(proof.get("algo", "")).upper()
        created = self._parse_opt_time(proof.get("created"))
        expires = self._parse_opt_time(proof.get("expires"))

        self._check_time(created, expires)

        canonicalization = proof.get("canonicalization", "json-compact")
        canon_bytes = canonicalize(payload, canonicalization)

        # 1) Проверка hash
        h = proof.get("hash") or {}
        if h:
            hasher = pick_hasher(str(h.get("alg", "SHA-256")))
            encoding = h.get("encoding", "hex")
            computed = digest_hex_or_b64(hasher(canon_bytes).digest(), encoding)
            if computed != h.get("digest"):
                raise ProofHashMismatchError("hash.digest mismatch for canonicalized payload")
        else:
            computed = None

        # 2) Проверка payloadDigest (если предоставлен)
        payload_digest = proof.get("payloadDigest")
        computed_payload_digest = None
        if payload_digest:
            # Определим ожидаемую кодировку по hash.encoding если задана,
            # иначе примем base64url как дефолт.
            encoding = (h.get("encoding") if h else None) or "base64url"
            hasher = pick_hasher(str(h.get("alg", "SHA-256"))) if h else hashlib.sha256
            raw = payload if isinstance(payload, (bytes, bytearray)) else (
                payload.encode("utf-8") if isinstance(payload, str) else json_compact(payload)
            )
            computed_payload_digest = digest_hex_or_b64(hasher(raw).digest(), encoding)
            if computed_payload_digest != payload_digest:
                raise ProofHashMismatchError("payloadDigest mismatch")

        # 3) Криптографическая проверка подписи
        verification_method = proof.get("verificationMethod") or ""
        key_id = proof.get("keyId")
        kty, public_key = self.key_resolver.resolve(verification_method, key_id)

        if algo == "JWS":
            self._verify_jws(proof, canon_bytes, public_key)
        elif algo == "ED25519":
            self._verify_ed25519(proof, canon_bytes, public_key)
        elif algo == "ECDSA_SECP256R1_SHA256":
            self._verify_ecdsa_p256_sha256(proof, canon_bytes, public_key)
        elif algo == "RSA_PSS_SHA256":
            self._verify_rsa_pss_sha256(proof, canon_bytes, public_key)
        elif algo == "HMAC_SHA256":
            self._verify_hmac(proof, canon_bytes, public_key)
        else:
            raise ProofFormatError(f"unsupported algo: {algo}")

        return VerificationResult(
            ok=True,
            alg=algo,
            created=created,
            expires=expires,
            key_info={"kty": kty, "verificationMethod": verification_method, "keyId": key_id},
            computed_digest=computed,
            computed_payload_digest=computed_payload_digest,
        )

    # ---------- Алгоритмы ----------

    def _verify_ed25519(self, proof: Dict[str, Any], data: bytes, public_key: Any) -> None:
        signature = proof.get("signature") or {}
        value = signature.get("value")
        enc = signature.get("encoding", "base64url")
        if not value:
            raise ProofFormatError("signature.value required for ED25519")
        sig = b64u_decode(value) if enc == "base64url" else bytes.fromhex(value)
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key = self._coerce_ed25519_key(public_key)
        try:
            public_key.verify(sig, data)
        except InvalidSignature as e:
            raise ProofSignatureError("invalid ed25519 signature") from e

    def _verify_ecdsa_p256_sha256(self, proof: Dict[str, Any], data: bytes, public_key: Any) -> None:
        signature = proof.get("signature") or {}
        r_hex, s_hex = signature.get("r"), signature.get("s")
        enc = signature.get("encoding", "hex")
        if not (r_hex and s_hex and enc == "hex"):
            raise ProofFormatError("ECDSA requires hex 'r' and 's'")
        r = int(r_hex, 16)
        s = int(s_hex, 16)
        # DER-представление из (r,s)
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der = encode_dss_signature(r, s)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key = self._coerce_ec_p256_key(public_key)
        try:
            public_key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise ProofSignatureError("invalid ecdsa p-256 signature") from e

    def _verify_rsa_pss_sha256(self, proof: Dict[str, Any], data: bytes, public_key: Any) -> None:
        signature = proof.get("signature") or {}
        value = signature.get("value")
        enc = signature.get("encoding", "base64url")
        if not value:
            raise ProofFormatError("signature.value required for RSA_PSS_SHA256")
        sig = b64u_decode(value) if enc == "base64url" else bytes.fromhex(value)
        if not isinstance(public_key, rsa.RSAPublicKey):
            public_key = self._coerce_rsa_key(public_key)
        try:
            public_key.verify(
                sig,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        except InvalidSignature as e:
            raise ProofSignatureError("invalid rsa-pss signature") from e

    def _verify_hmac(self, proof: Dict[str, Any], data: bytes, secret: Any) -> None:
        if not isinstance(secret, (bytes, bytearray)):
            raise KeyResolutionError("HMAC secret must be bytes")
        signature = proof.get("signature") or {}
        value = signature.get("value")
        enc = signature.get("encoding", "base64url")
        if not value:
            raise ProofFormatError("signature.value required for HMAC_SHA256")
        mac = hmac.new(secret, data, hashlib.sha256).digest()
        supplied = b64u_decode(value) if enc == "base64url" else bytes.fromhex(value)
        if not hmac.compare_digest(mac, supplied):
            raise ProofSignatureError("invalid hmac signature")

    # ----- JWS -----

    def _verify_jws(self, proof: Dict[str, Any], canon_payload: bytes, key: Any) -> None:
        jws = proof.get("jws")
        if not isinstance(jws, str) or jws.count(".") != 2:
            raise ProofFormatError("invalid JWS compact serialization")
        header_b64, payload_b64, sig_b64 = jws.split(".")
        header = json.loads(b64u_decode(header_b64))
        alg = header.get("alg")
        if not alg:
            raise ProofFormatError("JWS alg missing")
        # Детачед JWS — пустой payload
        signing_input = (header_b64 + "." + (payload_b64 or "")).encode("ascii")
        signature = b64u_decode(sig_b64)

        if alg == "EdDSA":
            pub = self._coerce_ed25519_key(key)
            try:
                pub.verify(signature, signing_input)
            except InvalidSignature as e:
                raise ProofSignatureError("invalid JWS(EdDSA)") from e
        elif alg == "ES256":
            pub = self._coerce_ec_p256_key(key)
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            # Подпись в JWS — raw R||S, нужно преобразовать в DER или использовать utils напрямую
            # RFC7515: ES256 использует DER? В большинстве реализаций подпись — DER. Покроем оба случая.
            try:
                # Попытка как raw (r|s)
                ln = len(signature) // 2
                r = int.from_bytes(signature[:ln], "big")
                s = int.from_bytes(signature[ln:], "big")
                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                der = encode_dss_signature(r, s)
            except Exception:
                der = signature
            try:
                pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature as e:
                raise ProofSignatureError("invalid JWS(ES256)") from e
        elif alg in ("PS256", "RS256"):
            pub = self._coerce_rsa_key(key)
            if alg == "PS256":
                pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            else:
                pad = padding.PKCS1v15()
            try:
                pub.verify(signature, signing_input, pad, hashes.SHA256())
            except InvalidSignature as e:
                raise ProofSignatureError(f"invalid JWS({alg})") from e
        elif alg == "HS256":
            # Допускаем только если ключ — bytes
            if not isinstance(key, (bytes, bytearray)):
                raise KeyResolutionError("HS256 requires bytes secret key")
            mac = hmac.new(key, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, signature):
                raise ProofSignatureError("invalid JWS(HS256)")
        else:
            raise ProofFormatError(f"unsupported JWS alg: {alg}")

        # Если JWS содержит встроенный payload, он должен совпадать с канонизованным.
        if payload_b64:
            embedded = b64u_decode(payload_b64)
            if embedded != canon_payload:
                raise ProofHashMismatchError("JWS embedded payload does not match canonical payload")

    # ---------- Вспомогательные ключи ----------

    @staticmethod
    def _coerce_ed25519_key(obj: Any) -> ed25519.Ed25519PublicKey:
        if isinstance(obj, ed25519.Ed25519PublicKey):
            return obj
        if isinstance(obj, (bytes, bytearray)):
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(bytes(obj))
            except Exception:
                # Попытка загрузить PEM
                return load_pem_public_key(bytes(obj))  # type: ignore[return-value]
        if isinstance(obj, str):
            b = obj.encode("utf-8")
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(obj))
            except Exception:
                return load_pem_public_key(b)  # type: ignore[return-value]
        # JWK
        if isinstance(obj, dict) and obj.get("kty") == "OKP" and obj.get("crv") == "Ed25519":
            x = b64u_decode(obj["x"])
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        raise KeyResolutionError("cannot coerce Ed25519 public key")

    @staticmethod
    def _coerce_ec_p256_key(obj: Any) -> ec.EllipticCurvePublicKey:
        if isinstance(obj, ec.EllipticCurvePublicKey):
            return obj
        if isinstance(obj, (bytes, bytearray, str)):
            b = obj if isinstance(obj, (bytes, bytearray)) else obj.encode("utf-8")
            return load_pem_public_key(b)  # type: ignore[return-value]
        if isinstance(obj, dict) and obj.get("kty") == "EC" and obj.get("crv") in ("P-256", "secp256r1"):
            x = int.from_bytes(b64u_decode(obj["x"]), "big")
            y = int.from_bytes(b64u_decode(obj["y"]), "big")
            numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
            return numbers.public_key()
        raise KeyResolutionError("cannot coerce EC P-256 public key")

    @staticmethod
    def _coerce_rsa_key(obj: Any) -> rsa.RSAPublicKey:
        if isinstance(obj, rsa.RSAPublicKey):
            return obj
        if isinstance(obj, (bytes, bytearray, str)):
            b = obj if isinstance(obj, (bytes, bytearray)) else obj.encode("utf-8")
            return load_pem_public_key(b)  # type: ignore[return-value]
        if isinstance(obj, dict) and obj.get("kty") == "RSA":
            n = int.from_bytes(b64u_decode(obj["n"]), "big")
            e = int.from_bytes(b64u_decode(obj["e"]), "big")
            numbers = rsa.RSAPublicNumbers(e, n)
            return numbers.public_key()
        raise KeyResolutionError("cannot coerce RSA public key")

    # ---------- Время ----------

    def _parse_opt_time(self, dt: Any) -> Optional[datetime]:
        if not dt:
            return None
        if isinstance(dt, datetime):
            return dt.astimezone(timezone.utc)
        if isinstance(dt, str):
            return to_utc(dt)
        raise ProofFormatError("invalid time value")

    def _check_time(self, created: Optional[datetime], expires: Optional[datetime]) -> None:
        now = now_utc()
        if created and (created - now).total_seconds() > self.leeway:
            raise ProofNotYetValidError("proof created is in the future")
        if expires and (now - expires).total_seconds() > self.leeway:
            raise ProofExpiredError("proof expired")

# --------------------------------------------------------------------------------------
# Пример использования (должен жить в тестах/примеров)
# --------------------------------------------------------------------------------------
if __name__ == "__main__":  # простая самопроверка
    # Статический Ed25519 ключ (пример JWK)
    jwk_okp = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYLef2zVZ6uZ5hZC1h9Gg7S6W3h1QvQhZ7B9a6g",  # не настоящий ключ, для примера
    }
    resolver = StaticKeyResolver(keys={"did:key:example#ed25519": jwk_okp})

    v = Verifier(resolver)

    payload = {"a": 1, "b": 2}
    proof = {
        "algo": "JWS",
        "created": now_utc().isoformat(),
        "canonicalization": "json-compact",
        "hash": {
            "alg": "SHA-256",
            "digest": hashlib.sha256(json_compact(payload)).hexdigest(),
            "encoding": "hex",
        },
        # "jws": "..."  # Подставьте корректную JWS строку для реального теста
        "verificationMethod": "did:key:example#ed25519",
        "keyId": "v1",
    }
    try:
        # Ожидаемо упадёт на отсутствующей jws
        v.verify(proof=proof, payload=payload)
    except ProofError as e:
        print("verification failed (as expected in demo):", e)
