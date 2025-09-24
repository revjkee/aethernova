# security-core/security/tokens/jwt.py
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

# Опциональные зависимости (модуль работает и без них, но часть фич будет неактивна)
try:  # JOSE-криптография
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_der_private_key,
        load_der_public_key,
        load_pem_private_key,
        load_pem_public_key,
    )
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False  # type: ignore

try:  # JWKS загрузка по HTTP с кешом/ETag
    import httpx  # type: ignore
    _HAVE_HTTPX = True
except Exception:  # pragma: no cover
    _HAVE_HTTPX = False  # type: ignore

try:  # Redis для анти-replay
    from redis.asyncio import Redis  # type: ignore
    _HAVE_REDIS = True
except Exception:  # pragma: no cover
    _HAVE_REDIS = False  # type: ignore

logger = logging.getLogger("security_core.tokens.jwt")


# ============================== Исключения ==============================

class JwtError(Exception):
    pass

class UnsupportedAlg(JwtError):
    pass

class InvalidToken(JwtError):
    pass

class InvalidSignatureErr(JwtError):
    pass

class KeyNotFound(JwtError):
    pass

class ClaimValidationError(JwtError):
    pass

class ReplayDetected(JwtError):
    pass


# ============================== Утилиты ==============================

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode((s + pad).encode("ascii"))
    except Exception as e:
        raise InvalidToken(f"invalid base64url: {e}")

def _json_dumps(obj: Any) -> bytes:
    # компактно и детерминированно для подписи
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=False).encode("utf-8")

def _now() -> int:
    return int(time.time())

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ===== ECDSA (DER <-> raw) для JWS ESxxx =====

def _int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, byteorder="big")

def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def _curve_size_bytes(curve: ec.EllipticCurve) -> int:
    if isinstance(curve, ec.SECP256R1):
        return 32
    if isinstance(curve, ec.SECP384R1):
        return 48
    if isinstance(curve, ec.SECP521R1):
        # В JWS ES512 длина каждого компонента — ceil(521/8)=66
        return 66
    raise UnsupportedAlg("Unsupported EC curve for ES alg")

def _ecdsa_der_to_raw(sig_der: bytes, size: int) -> bytes:
    # Минимальный парсер DER (r,s) для подписи
    # Используем cryptography для разбора через Asymmetric utils? Избежим лишних импорта.
    from asn1crypto import core  # type: ignore
    seq = core.Sequence.load(sig_der)
    r = int(seq[0].native)
    s = int(seq[1].native)
    return _int_to_bytes(r, size) + _int_to_bytes(s, size)

def _ecdsa_raw_to_der(sig_raw: bytes) -> bytes:
    from asn1crypto import core  # type: ignore
    half = len(sig_raw) // 2
    r = _bytes_to_int(sig_raw[:half])
    s = _bytes_to_int(sig_raw[half:])
    seq = core.Sequence([core.Integer(r), core.Integer(s)])
    return seq.dump()


# ============================== Алгоритмы ==============================

ALG_HS = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
ALG_RS = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
ALG_PS = {"PS256": hashes.SHA256, "PS384": hashes.SHA384, "PS512": hashes.SHA512}
ALG_ES = {"ES256": (hashes.SHA256, ec.SECP256R1), "ES384": (hashes.SHA384, ec.SECP384R1), "ES512": (hashes.SHA512, ec.SECP521R1)}
ALG_OKP = {"EdDSA": "EdDSA"}  # Ed25519 / Ed448


# ============================== Загрузка ключей (JWK/PEM) ==============================

def load_public_key_from_jwk(jwk: Mapping[str, Any]):
    if not _HAVE_CRYPTO:
        raise UnsupportedAlg("cryptography is required for public key operations")
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _b64url_decode(jwk["n"])
        e = _b64url_decode(jwk["e"])
        pub = rsa.RSAPublicNumbers(_bytes_to_int(e), _bytes_to_int(n)).public_key()
        return pub
    if kty == "EC":
        crv = jwk["crv"]
        x = _bytes_to_int(_b64url_decode(jwk["x"]))
        y = _bytes_to_int(_b64url_decode(jwk["y"]))
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[crv]
        pub = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        return pub
    if kty == "OKP":
        crv = jwk["crv"]
        x = _b64url_decode(jwk["x"])
        if crv == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        if crv == "Ed448":
            return ed448.Ed448PublicKey.from_public_bytes(x)
        raise UnsupportedAlg(f"Unsupported OKP crv: {crv}")
    if kty == "oct":
        # HMAC общий секрет (bytes)
        return _b64url_decode(jwk["k"])
    raise UnsupportedAlg(f"Unsupported kty: {kty}")

def load_private_key_from_jwk(jwk: Mapping[str, Any]):
    if not _HAVE_CRYPTO:
        raise UnsupportedAlg("cryptography is required for private key operations")
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _bytes_to_int(_b64url_decode(jwk["n"]))
        e = _bytes_to_int(_b64url_decode(jwk["e"]))
        d = _bytes_to_int(_b64url_decode(jwk["d"]))
        # Опциональные CRT параметры
        p = _bytes_to_int(_b64url_decode(jwk["p"])) if "p" in jwk else None
        q = _bytes_to_int(_b64url_decode(jwk["q"])) if "q" in jwk else None
        dmp1 = _bytes_to_int(_b64url_decode(jwk["dp"])) if "dp" in jwk else None
        dmq1 = _bytes_to_int(_b64url_decode(jwk["dq"])) if "dq" in jwk else None
        iqmp = _bytes_to_int(_b64url_decode(jwk["qi"])) if "qi" in jwk else None
        pub = rsa.RSAPublicNumbers(e, n)
        if all(v is not None for v in (p, q, dmp1, dmq1, iqmp)):
            priv = rsa.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, public_numbers=pub
            ).private_key()
        else:
            priv = rsa.RSAPrivateNumbers(
                p=0, q=0, d=d, dmp1=0, dmq1=0, iqmp=0, public_numbers=pub  # fallback без CRT (не оптимально)
            ).private_key()
        return priv
    if kty == "EC":
        crv = jwk["crv"]
        d = _bytes_to_int(_b64url_decode(jwk["d"]))
        curve_obj = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[crv]
        # Восстановим публичную часть, если её нет
        if "x" in jwk and "y" in jwk:
            x = _bytes_to_int(_b64url_decode(jwk["x"]))
            y = _bytes_to_int(_b64url_decode(jwk["y"]))
            pub = ec.EllipticCurvePublicNumbers(x, y, curve_obj)
            return ec.EllipticCurvePrivateNumbers(d, pub).private_key()
        else:
            # Генерация pub из d не поддерживается напрямую без дополнительных вычислений,
            # поэтому требуем x/y для EC.
            raise UnsupportedAlg("EC JWK requires x,y for private import")
    if kty == "OKP":
        crv = jwk["crv"]
        d = _b64url_decode(jwk["d"])
        if crv == "Ed25519":
            return ed25519.Ed25519PrivateKey.from_private_bytes(d)
        if crv == "Ed448":
            return ed448.Ed448PrivateKey.from_private_bytes(d)
        raise UnsupportedAlg(f"Unsupported OKP crv: {crv}")
    if kty == "oct":
        return _b64url_decode(jwk["k"])
    raise UnsupportedAlg(f"Unsupported kty: {kty}")

def load_public_key_pem(pem: Union[str, bytes]):
    if not _HAVE_CRYPTO:
        raise UnsupportedAlg("cryptography is required for PEM operations")
    if isinstance(pem, str):
        pem = pem.encode()
    try:
        return load_pem_public_key(pem)
    except Exception:
        return load_der_public_key(pem)

def load_private_key_pem(pem: Union[str, bytes], password: Optional[bytes] = None):
    if not _HAVE_CRYPTO:
        raise UnsupportedAlg("cryptography is required for PEM operations")
    if isinstance(pem, str):
        pem = pem.encode()
    try:
        return load_pem_private_key(pem, password=password)
    except Exception:
        return load_der_private_key(pem, password=password)


# ============================== kid / Thumbprint (RFC 7638) ==============================

def jwk_thumbprint_sha256(jwk: Mapping[str, Any]) -> str:
    """
    RFC 7638: каноническая сериализация подмножества параметров и SHA-256.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        obj = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        obj = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        obj = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "oct":
        obj = {"k": jwk["k"], "kty": "oct"}
    else:
        raise UnsupportedAlg(f"Unsupported kty for thumbprint: {kty}")
    canon = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_encode(hashlib.sha256(canon).digest())


# ============================== Резолверы ключей ==============================

class VerificationKeyResolver(Protocol):
    def resolve(self, kid: Optional[str], alg: str) -> Any: ...

class StaticJwksResolver:
    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self._by_kid: Dict[str, Any] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid") or jwk_thumbprint_sha256(jwk)
            self._by_kid[kid] = load_public_key_from_jwk(jwk)
        self._fallback: List[Any] = list(self._by_kid.values())

    def resolve(self, kid: Optional[str], alg: str) -> Any:
        if kid and kid in self._by_kid:
            return self._by_kid[kid]
        if kid and kid not in self._by_kid:
            raise KeyNotFound(f"kid {kid} not found")
        # Без kid: если ровно один — вернём его
        if len(self._fallback) == 1:
            return self._fallback[0]
        raise KeyNotFound("ambiguous key without kid")

class HttpJwksResolver:
    """
    JWKS по URL с кешем и ETag (требует httpx).
    """
    def __init__(self, url: str, cache_ttl: int = 300) -> None:
        if not _HAVE_HTTPX:
            raise RuntimeError("httpx is required for HttpJwksResolver")
        self.url = url
        self.cache_ttl = cache_ttl
        self._lock = threading.RLock()
        self._exp = 0
        self._etag: Optional[str] = None
        self._resolver: Optional[StaticJwksResolver] = None

    def _refresh_locked(self) -> None:
        headers = {"Accept": "application/json"}
        if self._etag:
            headers["If-None-Match"] = self._etag
        resp = httpx.get(self.url, headers=headers, timeout=5.0)
        if resp.status_code == 304 and self._resolver:
            self._exp = _now() + self.cache_ttl
            return
        resp.raise_for_status()
        jwks = resp.json()
        self._resolver = StaticJwksResolver(jwks)
        self._etag = resp.headers.get("ETag")
        self._exp = _now() + self.cache_ttl

    def resolve(self, kid: Optional[str], alg: str) -> Any:
        with self._lock:
            if self._resolver is None or _now() >= self._exp:
                self._refresh_locked()
            assert self._resolver is not None
            return self._resolver.resolve(kid, alg)


# ============================== Anti-replay JTI ==============================

class JtiStore(Protocol):
    async def seen(self, jti: str, expires_at: int) -> bool: ...

class InMemoryJtiStore:
    def __init__(self, capacity: int = 100_000) -> None:
        self._store: Dict[str, int] = {}
        self._cap = capacity
        self._lock = threading.RLock()

    async def seen(self, jti: str, expires_at: int) -> bool:
        with self._lock:
            now = _now()
            # очистка
            stale = [k for k, v in self._store.items() if v <= now]
            for k in stale:
                self._store.pop(k, None)
            if jti in self._store:
                return True
            if len(self._store) >= self._cap:
                # грубая эвикция
                for k in list(self._store.keys())[: self._cap // 10]:
                    self._store.pop(k, None)
            self._store[jti] = expires_at
            return False

class RedisJtiStore:
    def __init__(self, redis: "Redis", prefix: str = "jwt:jti") -> None:  # type: ignore[name-defined]
        if not _HAVE_REDIS:
            raise RuntimeError("redis.asyncio is required for RedisJtiStore")
        self.r = redis
        self.prefix = prefix

    async def seen(self, jti: str, expires_at: int) -> bool:
        ttl = max(1, expires_at - _now())
        key = f"{self.prefix}:{jti}"
        ok = await self.r.setnx(key, "1")
        if ok:
            await self.r.expire(key, ttl)
            return False
        return True


# ============================== JwtService ==============================

@dataclass
class VerifyOptions:
    issuer: Optional[str] = None
    audience: Optional[Union[str, Sequence[str]]] = None
    leeway: int = 60
    max_age: Optional[int] = None  # макс. возраст токена (exp-iat), сек
    required_claims: Tuple[str, ...] = ("iss", "sub", "iat", "exp")
    allowed_algs: Tuple[str, ...] = tuple(list(ALG_HS) + list(ALG_RS) + list(ALG_PS) + list(ALG_ES) + list(ALG_OKP))
    check_jti: bool = True

@dataclass
class SignOptions:
    algorithm: str
    kid: Optional[str] = None
    expires_in: int = 3600
    not_before: Optional[int] = None
    additional_headers: Optional[Mapping[str, Any]] = None


class JwtService:
    """
    Подпись/проверка JWT (JWS). Поддержаны HS*, RS*, PS*, ES*, EdDSA.
    """

    # ----------------------------- Подпись -----------------------------

    @staticmethod
    def sign(claims: Mapping[str, Any], key: Any, opts: SignOptions, issuer: Optional[str] = None, subject: Optional[str] = None, audience: Optional[Union[str, Sequence[str]]] = None) -> str:
        if opts.algorithm in ALG_HS:
            if not isinstance(key, (bytes, bytearray)):
                raise UnsupportedAlg("HS* requires bytes secret")
        else:
            if not _HAVE_CRYPTO:
                raise UnsupportedAlg("cryptography is required for non-HS algorithms")

        now = _now()
        payload: Dict[str, Any] = dict(claims)
        payload.setdefault("iat", now)
        payload.setdefault("exp", now + int(opts.expires_in))
        if opts.not_before is not None:
            payload.setdefault("nbf", int(opts.not_before))
        if issuer is not None:
            payload.setdefault("iss", issuer)
        if subject is not None:
            payload.setdefault("sub", subject)
        if audience is not None:
            payload.setdefault("aud", audience)

        header: Dict[str, Any] = {"typ": "JWT", "alg": opts.algorithm}
        if opts.kid:
            header["kid"] = opts.kid
        if opts.additional_headers:
            # критические заголовки не поддерживаем в этом бэкэнде
            if "crit" in opts.additional_headers:
                raise UnsupportedAlg("crit header not supported")
            header.update(opts.additional_headers)

        signing_input = _b64url_encode(_json_dumps(header)) + "." + _b64url_encode(_json_dumps(payload))
        sig = JwtService._sign_bytes(opts.algorithm, key, signing_input.encode("ascii"))
        return signing_input + "." + _b64url_encode(sig)

    @staticmethod
    def _sign_bytes(alg: str, key: Any, msg: bytes) -> bytes:
        if alg in ALG_HS:
            digest = getattr(hashlib, ALG_HS[alg])
            return hmac.new(key if isinstance(key, (bytes, bytearray)) else bytes(key), msg, digest).digest()
        if not _HAVE_CRYPTO:
            raise UnsupportedAlg("cryptography is required")
        if alg in ALG_RS:
            h = ALG_RS[alg]()
            return key.sign(msg, padding.PKCS1v15(), h)
        if alg in ALG_PS:
            h = ALG_PS[alg]()
            return key.sign(msg, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
        if alg in ALG_ES:
            h_cls, curve_cls = ALG_ES[alg]
            der = key.sign(msg, ec.ECDSA(h_cls()))
            size = _curve_size_bytes(key.curve)  # type: ignore[attr-defined]
            return _ecdsa_der_to_raw(der, size)
        if alg in ALG_OKP:
            # EdDSA: ключ Ed25519/Ed448
            return key.sign(msg)
        raise UnsupportedAlg(f"Unsupported alg: {alg}")

    # ----------------------------- Верификация -----------------------------

    @staticmethod
    async def verify(token: str, key_or_resolver: Union[Any, VerificationKeyResolver], options: VerifyOptions = VerifyOptions(), jti_store: Optional[JtiStore] = None) -> Mapping[str, Any]:
        header, payload, signature, signing_input = JwtService._split_compact(token)
        alg = header.get("alg")
        kid = header.get("kid")
        if not isinstance(alg, str):
            raise InvalidToken("missing alg")
        if alg not in options.allowed_algs:
            raise UnsupportedAlg(f"alg {alg} not allowed")

        # Разрешаем ключ
        key = key_or_resolver
        if hasattr(key_or_resolver, "resolve"):
            key = key_or_resolver.resolve(kid, alg)

        # Проверяем подпись
        JwtService._verify_signature(alg, key, signing_input, signature)

        # Валидация claim'ов
        JwtService._validate_claims(payload, options)

        # Anti-replay по jti
        if options.check_jti and jti_store is not None:
            jti = str(payload.get("jti") or "")
            if jti:
                exp = int(payload["exp"])
                if await jti_store.seen(jti, exp):
                    raise ReplayDetected("jti replay detected")

        return payload

    @staticmethod
    def _split_compact(token: str) -> Tuple[Mapping[str, Any], Mapping[str, Any], bytes, bytes]:
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidToken("not a compact JWS")
        h_b, p_b, s_b = parts
        header = json.loads(_b64url_decode(h_b).decode("utf-8"))
        if "crit" in header:
            raise UnsupportedAlg("crit header not supported")
        payload = json.loads(_b64url_decode(p_b).decode("utf-8"))
        signature = _b64url_decode(s_b)
        signing_input = (h_b + "." + p_b).encode("ascii")
        return header, payload, signature, signing_input

    @staticmethod
    def _verify_signature(alg: str, key: Any, signing_input: bytes, signature: bytes) -> None:
        if alg in ALG_HS:
            digest = getattr(hashlib, ALG_HS[alg])
            expected = hmac.new(key if isinstance(key, (bytes, bytearray)) else bytes(key), signing_input, digest).digest()
            if not _consteq(expected, signature):
                raise InvalidSignatureErr("HMAC verification failed")
            return
        if not _HAVE_CRYPTO:
            raise UnsupportedAlg("cryptography is required")
        try:
            if alg in ALG_RS:
                h = ALG_RS[alg]()
                key.verify(signature, signing_input, padding.PKCS1v15(), h)
                return
            if alg in ALG_PS:
                h = ALG_PS[alg]()
                key.verify(signature, signing_input, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
                return
            if alg in ALG_ES:
                h_cls, _ = ALG_ES[alg]
                # cryptography ждёт DER; имеем raw-R||S
                der = _ecdsa_raw_to_der(signature)
                key.verify(der, signing_input, ec.ECDSA(h_cls()))
                return
            if alg in ALG_OKP:
                key.verify(signature, signing_input)
                return
        except InvalidSignature as e:
            raise InvalidSignatureErr("signature verification failed") from e
        raise UnsupportedAlg(f"Unsupported alg: {alg}")

    @staticmethod
    def _validate_claims(claims: Mapping[str, Any], opt: VerifyOptions) -> None:
        now = _now()
        leeway = int(opt.leeway)

        # Обязательные клеймы
        for req in opt.required_claims:
            if req not in claims:
                raise ClaimValidationError(f"missing claim: {req}")

        # Время
        if "nbf" in claims and int(claims["nbf"]) > now + leeway:
            raise ClaimValidationError("token not yet valid (nbf)")

        if "iat" in claims:
            # допускаем час вперёд по часам клиента
            if int(claims["iat"]) > now + max(leeway, 3600):
                raise ClaimValidationError("iat in the future")

        if "exp" in claims and int(claims["exp"]) < now - leeway:
            raise ClaimValidationError("token expired")

        if opt.max_age is not None and "iat" in claims and "exp" in claims:
            if int(claims["exp"]) - int(claims["iat"]) > int(opt.max_age):
                raise ClaimValidationError("token exceeds max_age")

        # Issuer / Audience
        if opt.issuer is not None:
            if str(claims.get("iss")) != str(opt.issuer):
                raise ClaimValidationError("issuer mismatch")

        if opt.audience is not None:
            aud_claim = claims.get("aud")
            if isinstance(opt.audience, str):
                expected = {opt.audience}
            else:
                expected = set(str(x) for x in opt.audience)
            have = set()
            if isinstance(aud_claim, str):
                have = {aud_claim}
            elif isinstance(aud_claim, (list, tuple)):
                have = set(str(x) for x in aud_claim)
            else:
                raise ClaimValidationError("aud claim missing or invalid")
            if expected.isdisjoint(have):
                raise ClaimValidationError("audience mismatch")


# ============================== Пример использования (док) =============================

"""
# Подпись HS256:
token = JwtService.sign(
    {"sub": "user-123"},
    key=b"supersecret",
    opts=SignOptions(algorithm="HS256", kid="hs1", expires_in=900),
    issuer="https://issuer.example",
    audience="api://default",
)

# Верификация HS256 (без резолвера):
claims = asyncio.run(JwtService.verify(token, key_or_resolver=b"supersecret"))

# Подпись RS256 из PEM:
priv = load_private_key_pem(open("rsa_priv.pem","rb").read())
pub = load_public_key_pem(open("rsa_pub.pem","rb").read())
token = JwtService.sign({"sub":"alice"}, priv, SignOptions(algorithm="RS256", kid="rsa-2025"))

# Верификация RS256 с JWKS (статический):
jwks = {"keys":[<JWK pub>]}
resolver = StaticJwksResolver(jwks)
claims = asyncio.run(JwtService.verify(token, resolver, VerifyOptions(issuer="https://issuer.example", audience="api://default")))

# Anti-replay jti на Redis:
#   jti добавляете в payload при подписании. На верификации:
jti_store = RedisJtiStore(redis_client)   # redis.asyncio.Redis
claims = asyncio.run(JwtService.verify(token, resolver, VerifyOptions(check_jti=True), jti_store=jti_store))
"""
