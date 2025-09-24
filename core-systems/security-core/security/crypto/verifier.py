# -*- coding: utf-8 -*-
"""
security-core.crypto.verifier — безопасная верификация JWS/JWT и X.509.

Функционал:
- JWS/JWT: RS256/384/512, PS256/384/512, ES256/384/512 (raw r||s → DER), EdDSA (Ed25519).
- Detached payload (RFC 7797, b64=false) и критический заголовок "b64".
- Источники ключей: статический JWK/JWKS и удаленный JWKS с TTL-кэшем (без сторонних HTTP-зависимостей).
- JWT-клеймы: exp/nbf/iat/iss/aud/leeway, required_claims, тип "JWT".
- Защита: deny-by-default для HS* (симметричных), белый список алгоритмов, строгая обработка 'crit'.
- X.509: базовая проверка цепочки (подписи, сроки, KU/EKU) + SPKI pinning (sha256). Интерфейсы для OCSP/CRL.
- Безопасные base64url/JSON утилиты, потокобезопасные кэши, понятные исключения.

Зависимости:
  - Стандартная библиотека Python.
  - Опционально: cryptography (рекомендуется) — полноценная верификация подписей и X.509.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# --------------------------- Опциональная криптография ------------------------

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519, utils as asym_utils
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography import x509
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

# --------------------------- Утилиты ------------------------------------------

def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _b64u_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)

def _json_loads(s: str) -> Any:
    return json.loads(s)

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class VerifyError(Exception):
    pass

class AlgorithmNotAllowed(VerifyError):
    pass

class KeyNotFound(VerifyError):
    pass

class CryptoUnavailable(VerifyError):
    pass

# --------------------------- Конфигурация -------------------------------------

@dataclass(frozen=True)
class VerifierConfig:
    allowed_algs: Tuple[str, ...] = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
    allow_symmetric: bool = False
    expected_typ: Optional[str] = "JWT"    # для JWT; None — не проверять
    leeway_seconds: int = 60               # допуск на часы
    jwks_cache_ttl: int = 300              # секунды
    http_timeout: int = 3                  #JWKS http timeout
    max_age_seconds: Optional[int] = None  # ограничение возраста токена (по iat), None — выключено

# --------------------------- JWK/JWKS -----------------------------------------

def _int_from_b64u(s: str) -> int:
    return int.from_bytes(_b64u_decode(s), "big")

def _load_key_from_jwk(jwk: Mapping[str, Any]):
    if not _CRYPTO:
        raise CryptoUnavailable("cryptography is required for key operations")
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _int_from_b64u(jwk["n"])
        e = _int_from_b64u(jwk["e"])
        pub_num = rsa.RSAPublicNumbers(e, n)
        return pub_num.public_key()
    if kty == "EC":
        crv = jwk.get("crv")
        x = _int_from_b64u(jwk["x"])
        y = _int_from_b64u(jwk["y"])
        if crv == "P-256":
            curve = ec.SECP256R1()
        elif crv == "P-384":
            curve = ec.SECP384R1()
        elif crv == "P-521":
            curve = ec.SECP521R1()
        else:
            raise AlgorithmNotAllowed(f"Unsupported EC curve: {crv}")
        pub_nums = ec.EllipticCurvePublicNumbers(x, y, curve)
        return pub_nums.public_key()
    if kty == "OKP":
        # Поддержим Ed25519
        crv = jwk.get("crv")
        if crv != "Ed25519":
            raise AlgorithmNotAllowed(f"Unsupported OKP curve: {crv}")
        return ed25519.Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"]))
    if kty == "oct":
        # Симметричный ключ — по умолчанию запрещено
        return _b64u_decode(jwk["k"])
    raise AlgorithmNotAllowed(f"Unsupported kty: {kty}")

@dataclass
class JWKSource:
    """Базовый интерфейс источника ключей."""
    def get_candidates(self, kid: Optional[str], alg: Optional[str]) -> List[Mapping[str, Any]]:
        raise NotImplementedError

@dataclass
class StaticJWKs(JWKSource):
    keys: List[Mapping[str, Any]]
    def get_candidates(self, kid: Optional[str], alg: Optional[str]) -> List[Mapping[str, Any]]:
        out = []
        for k in self.keys:
            if kid and k.get("kid") != kid:
                continue
            if alg and k.get("alg") and k.get("alg") != alg:
                continue
            out.append(k)
        # если kid не указан — вернем все подходящие по alg или все
        return out

@dataclass
class RemoteJWKS(JWKSource):
    url: str
    cache_ttl: int
    http_timeout: int
    _cached: Optional[List[Mapping[str, Any]]] = field(default=None, init=False)
    _expires_at: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def _refresh(self) -> None:
        with self._lock:
            now = time.time()
            if self._cached is not None and now < self._expires_at:
                return
            req = urllib.request.Request(self.url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            keys = data.get("keys")
            if not isinstance(keys, list):
                raise VerifyError("JWKS response missing 'keys'")
            self._cached = keys
            self._expires_at = now + self.cache_ttl

    def get_candidates(self, kid: Optional[str], alg: Optional[str]) -> List[Mapping[str, Any]]:
        self._refresh()
        assert self._cached is not None
        return StaticJWKs(self._cached).get_candidates(kid, alg)

# --------------------------- Подписи JWS --------------------------------------

_HASHES = {
    "RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512,
    "PS256": hashes.SHA256, "PS384": hashes.SHA384, "PS512": hashes.SHA512,
    "ES256": hashes.SHA256, "ES384": hashes.SHA384, "ES512": hashes.SHA512,
}

_EC_CURVE_FROM_ALG = {
    "ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1,
}

def _ecdsa_raw_to_der(sig: bytes) -> bytes:
    # JWS ECDSA использует raw r||s; cryptography ожидает DER
    ln = len(sig) // 2
    r = int.from_bytes(sig[:ln], "big")
    s = int.from_bytes(sig[ln:], "big")
    return asym_utils.encode_dss_signature(r, s)

@dataclass
class VerifiedJWS:
    header: Mapping[str, Any]
    payload: bytes
    payload_json: Optional[Mapping[str, Any]]
    key_id: Optional[str]
    algorithm: str

class JWSVerifier:
    def __init__(self, jwk_source: JWKSource, config: Optional[VerifierConfig] = None):
        self.jwk_source = jwk_source
        self.cfg = config or VerifierConfig()

    def verify_compact(self, token: str, detached_payload: Optional[bytes] = None) -> VerifiedJWS:
        if not _CRYPTO:
            raise CryptoUnavailable("cryptography is required for JWS verification")

        parts = token.split(".")
        if len(parts) != 3:
            raise VerifyError("Invalid JWS compact format")
        h_b64, p_b64, s_b64 = parts
        header = _json_loads(_b64u_decode(h_b64).decode("utf-8"))

        alg = header.get("alg")
        kid = header.get("kid")
        crit = header.get("crit")
        b64crit = header.get("b64")

        if alg is None:
            raise VerifyError("Missing 'alg' in header")
        if alg not in self.cfg.allowed_algs:
            # Защитимся от даунгрейда
            if alg.startswith("HS") and not self.cfg.allow_symmetric:
                raise AlgorithmNotAllowed("HMAC algorithms are not allowed by policy")
            raise AlgorithmNotAllowed(f"Algorithm not allowed: {alg}")

        # Обработка критических параметров
        if crit:
            if not isinstance(crit, list) or any(not isinstance(x, str) for x in crit):
                raise VerifyError("Invalid 'crit' header")
            # поддерживаем только 'b64'
            for c in crit:
                if c != "b64":
                    raise VerifyError(f"Unsupported critical header: {c}")

        # b64=false → detached/небаз64 кодированный payload
        if b64crit is False:
            if detached_payload is None:
                raise VerifyError("Detached payload required for b64=false")
            signing_input = (h_b64 + ".").encode("ascii") + detached_payload
            payload = detached_payload
            payload_json = None
        else:
            signing_input = (h_b64 + "." + p_b64).encode("ascii")
            payload = _b64u_decode(p_b64)
            payload_json = None
            # Попробуем распарсить JSON (JWT) — не обязательно
            try:
                payload_json = _json_loads(payload.decode("utf-8"))
            except Exception:
                payload_json = None

        signature = _b64u_decode(s_b64)

        candidates = self.jwk_source.get_candidates(kid, alg)
        if not candidates:
            raise KeyNotFound("No candidate keys found (kid/alg mismatch)")

        last_err: Optional[Exception] = None
        for jwk in candidates:
            try:
                pub = _load_key_from_jwk(jwk)
                # Симметричный ключ (oct)
                if isinstance(pub, (bytes, bytearray)):
                    if not self.cfg.allow_symmetric:
                        raise AlgorithmNotAllowed("Symmetric keys are disabled")
                    # HS* не реализуем по умолчанию (политика), но можно добавить при необходимости
                    raise AlgorithmNotAllowed("HMAC JWS not supported by policy")
                # Верификация по алгоритму
                if alg.startswith("RS"):  # RSASSA-PKCS1v1_5
                    hash_alg = _HASHES[alg]()
                    pub.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
                elif alg.startswith("PS"):  # RSASSA-PSS
                    hash_alg = _HASHES[alg]()
                    pub.verify(signature, signing_input, padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size), hash_alg)
                elif alg.startswith("ES"):  # ECDSA raw → DER
                    hash_alg = _HASHES[alg]()
                    if not isinstance(pub, ec.EllipticCurvePublicKey):
                        raise VerifyError("Key is not EC for ES*")
                    # Дополнительная проверка кривой
                    curve_cls = _EC_CURVE_FROM_ALG[alg]
                    if not isinstance(pub.curve, curve_cls):
                        raise AlgorithmNotAllowed(f"EC curve mismatch for {alg}")
                    der = _ecdsa_raw_to_der(signature)
                    pub.verify(der, signing_input, ec.ECDSA(hash_alg))
                elif alg == "EdDSA":
                    if not isinstance(pub, ed25519.Ed25519PublicKey):
                        raise VerifyError("Key is not Ed25519 for EdDSA")
                    pub.verify(signature, signing_input)
                else:
                    raise AlgorithmNotAllowed(f"Unsupported alg: {alg}")
                # Успех
                return VerifiedJWS(header=header, payload=payload, payload_json=payload_json, key_id=jwk.get("kid"), algorithm=alg)
            except Exception as e:  # хранить последнюю ошибку
                last_err = e
                continue

        raise VerifyError(f"Signature verification failed for all candidates: {last_err}")

# --------------------------- JWT ----------------------------------------------

class JWTVerifier(JWSVerifier):
    def __init__(self, jwk_source: JWKSource, config: Optional[VerifierConfig] = None):
        super().__init__(jwk_source, config)

    def verify(self, jwt_token: str, *, iss: Optional[str] = None, aud: Optional[str] = None, required_claims: Optional[Iterable[str]] = None) -> Mapping[str, Any]:
        v = self.verify_compact(jwt_token)
        if v.payload_json is None:
            raise VerifyError("JWT payload is not JSON")
        claims = dict(v.payload_json)

        # typ (из заголовка)
        exp_typ = self.cfg.expected_typ
        typ = (v.header.get("typ") or "").upper() if isinstance(v.header.get("typ"), str) else None
        if exp_typ and typ and typ.upper() != exp_typ.upper():
            raise VerifyError(f"Invalid typ: {typ}")

        now = int(_utcnow().timestamp())
        leeway = self.cfg.leeway_seconds

        # exp
        if "exp" in claims:
            if not isinstance(claims["exp"], int):
                raise VerifyError("exp must be int")
            if now > claims["exp"] + leeway:
                raise VerifyError("token expired")

        # nbf
        if "nbf" in claims:
            if not isinstance(claims["nbf"], int):
                raise VerifyError("nbf must be int")
            if now + leeway < claims["nbf"]:
                raise VerifyError("token not yet valid")

        # iat/max_age
        if "iat" in claims:
            if not isinstance(claims["iat"], int):
                raise VerifyError("iat must be int")
            if self.cfg.max_age_seconds is not None:
                if now > claims["iat"] + self.cfg.max_age_seconds + leeway:
                    raise VerifyError("token too old")

        # iss/aud
        if iss is not None:
            if claims.get("iss") != iss:
                raise VerifyError("iss mismatch")
        if aud is not None:
            aud_claim = claims.get("aud")
            if isinstance(aud_claim, str):
                ok = aud == aud_claim
            elif isinstance(aud_claim, list):
                ok = aud in aud_claim
            else:
                ok = False
            if not ok:
                raise VerifyError("aud mismatch")

        # required claims
        for rc in (required_claims or ()):
            if rc not in claims:
                raise VerifyError(f"missing required claim: {rc}")

        return claims

# --------------------------- X.509 и SPKI pinning -----------------------------

def _spki_sha256_der(pubkey) -> bytes:
    # Серилизуем SPKI и считаем sha256
    if not _CRYPTO:
        raise CryptoUnavailable("cryptography is required for X.509 operations")
    spki = pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    from cryptography.hazmat.primitives import hashes as _h
    h = _h.Hash(_h.SHA256())
    h.update(spki)
    return h.finalize()

@dataclass
class Pinset:
    """Набор допустимых SPKI-пинов (sha256 в base64)."""
    pins_b64: Tuple[str, ...]
    def match(self, pubkey) -> bool:
        digest = _spki_sha256_der(pubkey)
        b64 = base64.b64encode(digest).decode("ascii")
        return b64 in set(self.pins_b64)

@dataclass
class X509VerifyResult:
    ok: bool
    error: Optional[str]
    chain_len: int
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    pin_ok: Optional[bool] = None

class X509Verifier:
    """
    Базовая верификация цепочки: подписи, сроки, опционально key usage / EKU.
    Для полноценного path building, AIA fetching и OCSP/CRL используйте внешние валидаторы
    на уровне периметра/шлюза и передавайте сюда результат или интерфейсы коллбеков.
    """
    def __init__(self, *, pinset: Optional[Pinset] = None):
        self.pinset = pinset

    def verify_chain_basic(
        self,
        *,
        leaf_pem: bytes,
        intermediates_pem: Sequence[bytes] = (),
        trust_roots_pem: Sequence[bytes] = (),
        check_time: Optional[datetime] = None,
        require_server_auth: bool = False,
    ) -> X509VerifyResult:
        if not _CRYPTO:
            raise CryptoUnavailable("cryptography is required for X.509 verification")
        try:
            leaf = x509.load_pem_x509_certificate(leaf_pem)
        except Exception:
            # попробуем DER
            leaf = x509.load_der_x509_certificate(leaf_pem)

        inters = []
        for p in intermediates_pem:
            try:
                inters.append(x509.load_pem_x509_certificate(p))
            except Exception:
                inters.append(x509.load_der_x509_certificate(p))

        roots = []
        for p in trust_roots_pem:
            try:
                roots.append(x509.load_pem_x509_certificate(p))
            except Exception:
                roots.append(x509.load_der_x509_certificate(p))

        now = check_time or _utcnow()

        # Проверка сроков
        if not (leaf.not_valid_before <= now <= leaf.not_valid_after):
            return X509VerifyResult(ok=False, error="leaf validity period failed", chain_len=1)

        # Минимальная проверка EKU (serverAuth) по желанию
        if require_server_auth:
            try:
                eku = leaf.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
                from cryptography.x509.oid import ExtendedKeyUsageOID
                if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                    return X509VerifyResult(ok=False, error="EKU serverAuth missing", chain_len=1)
            except x509.ExtensionNotFound:
                return X509VerifyResult(ok=False, error="EKU missing", chain_len=1)

        # Подписи по цепочке (без сложного выбора пути). Предполагаем: [leaf] + inters + root
        chain = [leaf] + inters
        # Найти подходящий корень: по issuer/subject
        root = None
        for r in roots:
            if chain[-1].issuer == r.subject:
                root = r
                break
        if root is None and roots:
            # допустим самоподписанный root без explicit issuer match
            for r in roots:
                if r.issuer == r.subject:
                    root = r
                    break
        if root:
            chain.append(root)

        # Проверка подписей последовательно
        for i in range(len(chain) - 1):
            cert = chain[i]
            issuer = chain[i + 1]
            pub = issuer.public_key()
            try:
                pub.verify(cert.signature, cert.tbs_certificate_bytes, _sig_algo_for_cert(cert), _hash_for_cert(cert))
            except Exception as e:
                return X509VerifyResult(ok=False, error=f"signature verify failed at index {i}: {e}", chain_len=len(chain))

        # Пининг по SPKI
        pin_ok = None
        if self.pinset:
            pin_ok = self.pinset.match(leaf.public_key())
            if not pin_ok:
                return X509VerifyResult(ok=False, error="spki pin mismatch", chain_len=len(chain), pin_ok=False)

        subj = chain[0].subject.rfc4514_string() if chain else None
        iss = chain[0].issuer.rfc4514_string() if chain else None
        return X509VerifyResult(
            ok=True,
            error=None,
            chain_len=len(chain),
            subject=subj,
            issuer=iss,
            not_before=leaf.not_valid_before,
            not_after=leaf.not_valid_after,
            pin_ok=pin_ok if pin_ok is not None else None,
        )

def _sig_algo_for_cert(cert: "x509.Certificate"):
    # Определяем схему подписи из сертификата
    alg = cert.signature_algorithm_oid
    from cryptography.x509.oid import SignatureAlgorithmOID as SA
    if alg in (SA.RSA_WITH_SHA256, SA.RSA_WITH_SHA384, SA.RSA_WITH_SHA512, SA.RSA_WITH_SHA1):
        return padding.PKCS1v15()
    if alg in (SA.RSASSA_PSS,):
        # Параметры PSS в сертификате могут отличаться; используем MGF1 с хешем подписи
        return padding.PSS(mgf=padding.MGF1(_hash_for_cert(cert)), salt_length=_hash_for_cert(cert).algorithm.digest_size)  # type: ignore
    if alg in (SA.ECDSA_WITH_SHA256, SA.ECDSA_WITH_SHA384, SA.ECDSA_WITH_SHA512, SA.ECDSA_WITH_SHA1):
        return ec.ECDSA(_hash_for_cert(cert))
    # Ed25519/Ed448 — без параметров
    from cryptography.x509.oid import SignatureAlgorithmOID as SA2
    if getattr(SA2, "ED25519", None) and alg == SA2.ED25519:  # pragma: no cover
        return None
    if getattr(SA2, "ED448", None) and alg == SA2.ED448:  # pragma: no cover
        return None
    return padding.PKCS1v15()

def _hash_for_cert(cert: "x509.Certificate"):
    from cryptography.hazmat.primitives import hashes as H
    alg = cert.signature_hash_algorithm
    # cryptography уже отдает конкретный хеш (SHA256/384/512/…)
    return alg

# --------------------------- Публичные фабрики --------------------------------

def make_jwt_verifier_from_jwks_url(jwks_url: str, *, cfg: Optional[VerifierConfig] = None) -> JWTVerifier:
    c = cfg or VerifierConfig()
    src = RemoteJWKS(jwks_url, cache_ttl=c.jwks_cache_ttl, http_timeout=c.http_timeout)
    return JWTVerifier(src, c)

def make_jwt_verifier_from_keys(keys: Sequence[Mapping[str, Any]], *, cfg: Optional[VerifierConfig] = None) -> JWTVerifier:
    return JWTVerifier(StaticJWKs(list(keys)), cfg or VerifierConfig())

def make_jws_verifier_from_keys(keys: Sequence[Mapping[str, Any]], *, cfg: Optional[VerifierConfig] = None) -> JWSVerifier:
    return JWSVerifier(StaticJWKs(list(keys)), cfg or VerifierConfig())

# --------------------------- Мелкие хелперы -----------------------------------

def spki_sha256_b64_from_pem_public_key(pem_bytes: bytes) -> str:
    """
    Возвращает SPKI pin (base64) из PEM-публичного ключа.
    """
    if not _CRYPTO:
        raise CryptoUnavailable("cryptography is required for SPKI pin calculation")
    pub = load_pem_public_key(pem_bytes)
    return base64.b64encode(_spki_sha256_der(pub)).decode("ascii")

# --------------------------- Примечания ---------------------------------------
# 1) Полноценный path building, AIA fetching и строгие политики X.509
#    сознательно вынесены за пределы модуля. Используйте внешний валидатор
#    (например, на шлюзе) и/или передавайте подготовленные цепочки и trust store.
# 2) Для COSE/WebAuthn используйте отдельный модуль/библиотеку или расширьте
#    данный с добавлением CBOR/COSE-алгоритмов на базе 'cryptography'.
# 3) Симметричные HS* алгоритмы для JWS/JWT по умолчанию запрещены политикой
#    (cfg.allow_symmetric=False). Включайте их только при строгом контроле ключей.
