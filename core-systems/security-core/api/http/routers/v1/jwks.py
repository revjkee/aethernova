# security-core/api/http/routers/v1/jwks.py
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from starlette.responses import JSONResponse

# cryptography for key material
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography import x509

# --------------------------------------------------------------------------------------
# Вспомогательные функции: base64url без паддинга, thumbprint RFC 7638, утилиты времени
# --------------------------------------------------------------------------------------

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _int_to_b64u(n: int) -> str:
    if n == 0:
        return _b64u(b"\x00")
    length = (n.bit_length() + 7) // 8
    return _b64u(n.to_bytes(length, "big"))

def _now_ts() -> datetime:
    return datetime.now(timezone.utc)

def _httpdate(dt: datetime) -> str:
    # RFC 7231 IMF-fixdate
    return dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

def _fingerprint_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# RFC 7638 kid: хэш от канонического подмножества полей публичного JWK
def _rfc7638_thumbprint(jwk: Dict[str, Any]) -> str:
    # Поля для каждого kty
    if jwk.get("kty") == "RSA":
        subset = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk.get("kty") == "EC":
        subset = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif jwk.get("kty") == "OKP":
        subset = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError("Unsupported kty for thumbprint")
    return _b64u(hashlib.sha256(_canonical_json(subset)).digest())

# --------------------------------------------------------------------------------------
# Модель ключа и интерфейс провайдера
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicKeyRecord:
    # Идентификатор (может быть пустым — тогда сгенерируем из thumbprint)
    kid: Optional[str]
    # Алгоритм на уровне JWS (RS256/PS256/ES256/EdDSA и т.д.)
    alg: Optional[str]
    # Назначение ключа ("sig" или "enc")
    use: str = "sig"
    # Набор операций (verify/encrypt/wrapKey и т.д.)
    key_ops: Optional[List[str]] = None
    # Сам публичный ключ (cryptography)
    public_key: Any = None
    # Необязательная цепочка сертификатов (PEM)
    x5c_pem_chain: Optional[List[str]] = None
    # Метаданные для инвалидации кэша
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None

class KeyProvider(Protocol):
    def list_public_keys(self, issuer: Optional[str] = None) -> Tuple[List[PublicKeyRecord], datetime]:
        """
        Возвращает список публичных ключей и метку времени "обновлено".
        issuer — опциональный фильтр многотенантности.
        """

# --------------------------------------------------------------------------------------
# Провайдер по каталогу: загружает .pem/.crt c автогенерацией kid и alg
# --------------------------------------------------------------------------------------

class EnvDirKeyProvider:
    """
    Простой производственный провайдер: читает публичные ключи и/или сертификаты из каталога.
    Переменные окружения:
      SEC_CORE_JWKS_PEM_DIR=/path/to/keys
      SEC_CORE_JWKS_ISSUER_SUBDIRS=true|false  (если true — issuer=имя подкаталога)
    Конвенции:
      - .pem с публичным ключом (BEGIN PUBLIC KEY)
      - .crt X.509 (цепочка возможна: *.crt, *.chain.pem)
      - имя файла может содержать kid и alg через точку: example.kid-XYZ.alg-RS256.pem
    """
    def __init__(self, root: Path, issuer_subdirs: bool = False) -> None:
        self.root = root
        self.issuer_subdirs = issuer_subdirs
        if not self.root.exists() or not self.root.is_dir():
            raise RuntimeError(f"JWKS PEM dir not found: {self.root}")

    def _parse_name_meta(self, p: Path) -> Tuple[Optional[str], Optional[str]]:
        kid = None
        alg = None
        parts = p.stem.split(".")
        for part in parts:
            if part.startswith("kid-"):
                kid = part[4:]
            elif part.startswith("alg-"):
                alg = part[4:]
        return kid, alg

    def _load_records_from_dir(self, d: Path) -> List[PublicKeyRecord]:
        records: List[PublicKeyRecord] = []
        for p in sorted(d.iterdir()):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".pem", ".crt"}:
                continue

            kid_hint, alg_hint = self._parse_name_meta(p)
            pem = p.read_bytes()

            # Попробуем как сертификат
            pub = None
            x5c_chain: Optional[List[str]] = None
            not_before: Optional[datetime] = None
            not_after: Optional[datetime] = None

            try:
                cert = x509.load_pem_x509_certificate(pem)
                pub = cert.public_key()
                x5c_chain = [_b64u(cert.public_bytes(serialization.Encoding.DER))]
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            except Exception:
                # Не сертификат — пробуем публичный ключ
                try:
                    pub = load_pem_public_key(pem)
                except Exception:
                    continue  # не поддерживаемый файл

            # Алгоритм по типу ключа, если не задан
            alg = alg_hint or _default_alg_for_public_key(pub)

            rec = PublicKeyRecord(
                kid=kid_hint,
                alg=alg,
                use="sig",
                key_ops=["verify"],
                public_key=pub,
                x5c_pem_chain=x5c_chain,
                not_before=not_before,
                not_after=not_after,
            )
            records.append(rec)
        return records

    def list_public_keys(self, issuer: Optional[str] = None) -> Tuple[List[PublicKeyRecord], datetime]:
        updated_at = datetime.fromtimestamp(int(self.root.stat().st_mtime), tz=timezone.utc)
        if self.issuer_subdirs and issuer:
            d = self.root / issuer
            if d.exists() and d.is_dir():
                return self._load_records_from_dir(d), updated_at
            return [], updated_at
        return self._load_records_from_dir(self.root), updated_at

def _default_alg_for_public_key(pub: Any) -> str:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RS256"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve = pub.curve.name.lower()
        if "secp256r1" in curve or "p-256" in curve:
            return "ES256"
        if "secp384r1" in curve or "p-384" in curve:
            return "ES384"
        if "secp521r1" in curve or "p-521" in curve:
            return "ES512"
        return "ES256"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "EdDSA"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "EdDSA"
    raise ValueError("Unsupported public key type")

# --------------------------------------------------------------------------------------
# Конвертация cryptography -> JWK
# --------------------------------------------------------------------------------------

def _ec_crv_name(pub: ec.EllipticCurvePublicKey) -> str:
    name = pub.curve.name
    mapping = {
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
        "secp256k1": "secp256k1",
    }
    return mapping.get(name, "P-256")

def _to_jwk(rec: PublicKeyRecord) -> Dict[str, Any]:
    pub = rec.public_key
    jwk: Dict[str, Any]
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _int_to_b64u(nums.n),
            "e": _int_to_b64u(nums.e),
        }
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        jwk = {
            "kty": "EC",
            "crv": _ec_crv_name(pub),
            "x": _int_to_b64u(nums.x),
            "y": _int_to_b64u(nums.y),
        }
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}
    elif isinstance(pub, ed448.Ed448PublicKey):
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        jwk = {"kty": "OKP", "crv": "Ed448", "x": _b64u(raw)}
    else:
        raise HTTPException(status_code=500, detail="Unsupported public key type")

    # Применяем метаданные
    jwk["use"] = rec.use or "sig"
    if rec.key_ops:
        jwk["key_ops"] = rec.key_ops
    if rec.alg:
        jwk["alg"] = rec.alg

    # kid: если не задан — по RFC 7638 от публичной части
    kid = rec.kid or _rfc7638_thumbprint(jwk)
    jwk["kid"] = kid

    # Цепочка x5c и отпечатки сертификатов (если есть)
    if rec.x5c_pem_chain:
        jwk["x5c"] = rec.x5c_pem_chain
        try:
            # первый сертификат как leaf
            der = base64.urlsafe_b64decode(jwk["x5c"][0] + "==")
            jwk["x5t"] = _b64u(hashlib.sha1(der).digest())
            jwk["x5t#S256"] = _b64u(hashlib.sha256(der).digest())
        except Exception:
            pass

    return jwk

# --------------------------------------------------------------------------------------
# Кэш JWKS: ключ по (issuer, algs, use, kid, minimal)
# --------------------------------------------------------------------------------------

@dataclass
class _CacheEntry:
    etag: str
    last_modified: datetime
    payload: bytes
    expires_at: float

_JWKS_CACHE: Dict[str, _CacheEntry] = {}

def _cache_key(issuer: Optional[str], algs: Tuple[str, ...], use: Optional[str], kid: Optional[str], minimal: bool) -> str:
    return "|".join([
        issuer or "*",
        ",".join(sorted(algs)) if algs else "*",
        use or "*",
        kid or "*",
        "min" if minimal else "full",
    ])

def _build_jwks(provider: KeyProvider, issuer: Optional[str], algs: Tuple[str, ...], use: Optional[str], kid: Optional[str], minimal: bool, max_age: int) -> Tuple[_CacheEntry, List[Dict[str, Any]]]:
    records, updated_at = provider.list_public_keys(issuer=issuer)
    keys: List[Dict[str, Any]] = []

    for rec in records:
        try:
            jwk = _to_jwk(rec)
        except HTTPException:
            continue

        if algs and jwk.get("alg") not in algs:
            continue
        if use and jwk.get("use") != use:
            continue
        if kid and jwk.get("kid") != kid:
            continue

        if minimal:
            # Только обязательные поля по kty + kid/use/alg
            kty = jwk["kty"]
            base = {"kty": kty, "kid": jwk["kid"], "use": jwk.get("use", "sig")}
            if "alg" in jwk:
                base["alg"] = jwk["alg"]
            if kty == "RSA":
                base.update({"n": jwk["n"], "e": jwk["e"]})
            elif kty == "EC":
                base.update({"crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]})
            elif kty == "OKP":
                base.update({"crv": jwk["crv"], "x": jwk["x"]})
            jwk = base

        keys.append(jwk)

    # Стабильная сортировка по kid
    keys.sort(key=lambda k: (k.get("kid", ""), k.get("kty", "")))

    body = {"keys": keys}
    payload = _canonical_json(body)
    etag = f'W/"{_fingerprint_sha256(payload)}"'
    last_modified = updated_at or _now_ts()
    expires_at = time.time() + max_age
    entry = _CacheEntry(etag=etag, last_modified=last_modified, payload=payload, expires_at=expires_at)
    return entry, keys

# --------------------------------------------------------------------------------------
# DI провайдера
# --------------------------------------------------------------------------------------

def _resolve_provider() -> KeyProvider:
    # По умолчанию читаем из каталога, если указан
    pem_dir = os.getenv("SEC_CORE_JWKS_PEM_DIR")
    use_subdirs = os.getenv("SEC_CORE_JWKS_ISSUER_SUBDIRS", "false").lower() in ("1", "true", "yes", "y", "on")
    if pem_dir:
        return EnvDirKeyProvider(Path(pem_dir), issuer_subdirs=use_subdirs)
    # В проде провайдер лучше внедрять через Depends
    raise RuntimeError("No JWKS provider configured. Set SEC_CORE_JWKS_PEM_DIR or inject a provider via Depends.")

# --------------------------------------------------------------------------------------
# Роутер: /.well-known/jwks.json и /jwks (эквивалент)
# --------------------------------------------------------------------------------------

router = APIRouter(tags=["jwks"])

def _max_age() -> int:
    try:
        return int(os.getenv("SEC_CORE_JWKS_MAX_AGE", "600"))
    except Exception:
        return 600

@router.get("/.well-known/jwks.json")
async def well_known_jwks(
    request: Request,
    response: Response,
    issuer: Optional[str] = Query(None, description="Идентификатор издателя (тенанта)"),
    alg: List[str] = Query(default=[],
                           description="Фильтр по alg (повторяемый параметр), например RS256, ES256, EdDSA"),
    use: Optional[str] = Query(None, description="Назначение ключа: sig|enc"),
    kid: Optional[str] = Query(None, description="Фильтр по kid"),
    prefer_minimal: bool = Query(False, description="Вернуть только обязательные поля JWK"),
    provider: KeyProvider = Depends(_resolve_provider),
) -> JSONResponse:
    return await _jwks_impl(request, response, issuer, tuple(alg), use, kid, prefer_minimal, provider)

@router.get("/jwks")
async def jwks_alias(
    request: Request,
    response: Response,
    issuer: Optional[str] = Query(None),
    alg: List[str] = Query(default=[]),
    use: Optional[str] = Query(None),
    kid: Optional[str] = Query(None),
    prefer_minimal: bool = Query(False),
    provider: KeyProvider = Depends(_resolve_provider),
) -> JSONResponse:
    return await _jwks_impl(request, response, issuer, tuple(alg), use, kid, prefer_minimal, provider)

async def _jwks_impl(
    request: Request,
    response: Response,
    issuer: Optional[str],
    algs: Tuple[str, ...],
    use: Optional[str],
    kid: Optional[str],
    minimal: bool,
    provider: KeyProvider,
) -> JSONResponse:
    cache_key = _cache_key(issuer, algs, use, kid, minimal)
    max_age = _max_age()

    entry = _JWKS_CACHE.get(cache_key)
    # In-memory cache TTL
    if entry and entry.expires_at > time.time():
        # Conditional GET: If-None-Match
        inm = request.headers.get("if-none-match")
        if inm and inm == entry.etag:
            # 304 Not Modified
            response.status_code = 304
            _set_cache_headers(response, entry, max_age)
            return JSONResponse(content=None)
        _set_cache_headers(response, entry, max_age)
        return JSONResponse(content=json.loads(entry.payload), media_type="application/json")

    # Rebuild JWKS
    try:
        new_entry, _ = _build_jwks(provider, issuer, algs, use, kid, minimal, max_age)
    except RuntimeError as e:
        # Неправильная конфигурация провайдера
        raise HTTPException(status_code=503, detail=str(e))

    _JWKS_CACHE[cache_key] = new_entry

    # Conditional GET вновь после пересборки
    inm = request.headers.get("if-none-match")
    if inm and inm == new_entry.etag:
        response.status_code = 304
        _set_cache_headers(response, new_entry, max_age)
        return JSONResponse(content=None)

    _set_cache_headers(response, new_entry, max_age)
    return JSONResponse(content=json.loads(new_entry.payload), media_type="application/json")

def _set_cache_headers(resp: Response, entry: _CacheEntry, max_age: int) -> None:
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Cache-Control"] = f"public, max-age={max_age}, must-revalidate"
    resp.headers["ETag"] = entry.etag
    resp.headers["Last-Modified"] = _httpdate(entry.last_modified)
    expires = datetime.fromtimestamp(time.time() + max_age, tz=timezone.utc)
    resp.headers["Expires"] = _httpdate(expires)
    # Безопасность
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")

__all__ = [
    "router",
    "KeyProvider",
    "PublicKeyRecord",
    "EnvDirKeyProvider",
]
