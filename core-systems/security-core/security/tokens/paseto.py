# security-core/security/tokens/paseto.py
from __future__ import annotations

import base64
import dataclasses
import json
import logging
import os
import secrets
import sys
import time
import hmac
import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

# Логгер
def _get_logger() -> logging.Logger:
    logger = logging.getLogger("security_core.tokens.paseto")
    if not logger.handlers:
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        logger.setLevel(os.getenv("SEC_CORE_PASETO_LOG_LEVEL", "INFO").upper())
    return logger

log = _get_logger()

# Опционально используем pyseto: https://pypi.org/project/pyseto/
_HAS_PYSETO = False
try:  # pragma: no cover
    import pyseto  # type: ignore
    from pyseto import Key as _PysetoKey  # type: ignore
    _HAS_PYSETO = True
except Exception:  # pragma: no cover
    _HAS_PYSETO = False

# -----------------------------
# Исключения и константы
# -----------------------------

class PasetoError(Exception):
    pass

class TokenInvalid(PasetoError):
    pass

class TokenExpired(PasetoError):
    pass

class TokenNotYetValid(PasetoError):
    pass

class TokenAudienceMismatch(PasetoError):
    pass

class TokenIssuerMismatch(PasetoError):
    pass

class TokenSubjectMismatch(PasetoError):
    pass

SUPPORTED_VERSIONS = (2, 4)
SUPPORTED_PURPOSES = ("local", "public")

# -----------------------------
# Утилиты времени/JSON/идов
# -----------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _to_ts(dt: datetime) -> int:
    return int(dt.timestamp())

def _parse_time(value: Any) -> datetime:
    """
    Принимаем int (unix seconds) или RFC3339 строку.
    """
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    if isinstance(value, str):
        # Пробуем RFC3339, допускаем 'Z'
        s = value.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    raise TokenInvalid("Invalid time claim type")

class _JSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, datetime):
            return o.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return super().default(o)

def _json_dumps(obj: Any) -> str:
    # Стабильная сериализация
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True, cls=_JSONEncoder)

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _hmac_kid_material(data: bytes) -> str:
    # Дет, стабильный KID на базе SHA-256 (безопасно для идентификации, не как основной ключ)
    return hashlib.sha256(data).hexdigest()[:16]

def _gen_jti() -> str:
    return str(uuid.uuid4())

# -----------------------------
# Модель ключа и KeyStore
# -----------------------------

@dataclass(frozen=True)
class PasetoKey:
    version: int                     # 2 или 4
    purpose: str                     # "local" | "public"
    kid: str                         # Идентификатор ключа
    material: Any                    # bytes (local) или объект приватного/публичного ключа провайдера
    is_private: bool                 # True для private (public purpose) / local secret
    created_at: datetime = field(default_factory=_utcnow)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    active: bool = True
    primary: bool = False            # Использовать по умолчанию для выдачи токенов

class KeyStore(Protocol):
    def get_primary(self, version: int, purpose: str) -> PasetoKey: ...
    def get_by_kid(self, kid: str) -> PasetoKey: ...
    def all_keys(self) -> Iterable[PasetoKey]: ...

class InMemoryKeyStore(KeyStore):
    """
    Простейшее безопасное хранилище ключей в памяти.
    Для продакшена подключите HSM/внешний KMS и имплементируйте интерфейс KeyStore.
    """
    def __init__(self, keys: Iterable[PasetoKey]) -> None:
        self._by_kid: Dict[str, PasetoKey] = {}
        for k in keys:
            if k.purpose not in SUPPORTED_PURPOSES or k.version not in SUPPORTED_VERSIONS:
                raise ValueError("Unsupported key")
            if k.kid in self._by_kid:
                raise ValueError(f"Duplicate KID {k.kid}")
            self._by_kid[k.kid] = k

        # Проверка ровно одного primary на связку (version,purpose)
        combos: Dict[Tuple[int, str], int] = {}
        for k in self._by_kid.values():
            if k.primary:
                combos[(k.version, k.purpose)] = combos.get((k.version, k.purpose), 0) + 1
        for (v, p), n in combos.items():
            if n > 1:
                raise ValueError(f"Multiple primary keys for v{v}.{p}")

    def get_primary(self, version: int, purpose: str) -> PasetoKey:
        for k in self._by_kid.values():
            if k.version == version and k.purpose == purpose and k.primary and k.active:
                return k
        raise PasetoError(f"No active primary key for v{version}.{purpose}")

    def get_by_kid(self, kid: str) -> PasetoKey:
        k = self._by_kid.get(kid)
        if not k:
            raise PasetoError("Unknown KID")
        return k

    def all_keys(self) -> Iterable[PasetoKey]:
        return list(self._by_kid.values())

# -----------------------------
# Провайдер операций (pyseto)
# -----------------------------

class Provider(Protocol):
    def encode_local(self, key: PasetoKey, payload: Mapping[str, Any], footer: Optional[bytes], implicit: Optional[bytes]) -> str: ...
    def decode_local(self, keys: Iterable[PasetoKey], token: str, implicit: Optional[bytes]) -> Tuple[Dict[str, Any], Optional[bytes]]: ...
    def sign_public(self, priv: PasetoKey, payload: Mapping[str, Any], footer: Optional[bytes], implicit: Optional[bytes]) -> str: ...
    def verify_public(self, pubs: Iterable[PasetoKey], token: str, implicit: Optional[bytes]) -> Tuple[Dict[str, Any], Optional[bytes]]: ...

class PysetoProvider(Provider):
    """
    Реализация на базе pyseto. Требует установленного пакета.
    """
    def __init__(self) -> None:
        if not _HAS_PYSETO:
            raise RuntimeError("pyseto is not installed")

    def _to_pyseto_key(self, k: PasetoKey) -> _PysetoKey:
        # Для 'local' ожидаем bytes секрета. Для 'public' — приватный (is_private=True) или публичный ключ.
        if k.purpose == "local":
            if not isinstance(k.material, (bytes, bytearray)):
                raise PasetoError("Local key material must be bytes")
            return _PysetoKey.new(version=k.version, purpose="local", key=bytes(k.material))  # type: ignore
        if k.purpose == "public":
            # material должен быть совместимым с pyseto.Key.*
            if isinstance(k.material, _PysetoKey):  # уже pyseto ключ (private или public)
                return k.material  # type: ignore
            # Иначе пытаемся создать из PEM/bytes, если это приватный/публичный ключ в формате провайдера
            # Оставим гибкость пользователю: material может быть  _PysetoKey либо bytes PEM.
            if isinstance(k.material, (bytes, bytearray)):
                return _PysetoKey.from_asymmetric_key_pem(  # type: ignore[attr-defined]
                    version=k.version, purpose="public" if not k.is_private else "public",  # pyseto сам определит тип
                    key=bytes(k.material),
                )
            raise PasetoError("Unsupported public key material")
        raise PasetoError("Unsupported purpose")

    def encode_local(self, key: PasetoKey, payload: Mapping[str, Any], footer: Optional[bytes], implicit: Optional[bytes]) -> str:
        pkey = self._to_pyseto_key(key)
        return pyseto.encode(pkey, payload, footer=footer, implicit_assertion=implicit)  # type: ignore

    def decode_local(self, keys: Iterable[PasetoKey], token: str, implicit: Optional[bytes]) -> Tuple[Dict[str, Any], Optional[bytes]]:
        pkeys = [self._to_pyseto_key(k) for k in keys]
        obj = pyseto.decode(pkeys, token, implicit_assertion=implicit)  # type: ignore
        # pyseto возвращает объект с payload/footer (в разных версиях API — dict/bytes)
        payload = obj.payload if hasattr(obj, "payload") else obj  # type: ignore
        footer = getattr(obj, "footer", None)
        if isinstance(payload, (bytes, bytearray)):
            payload = json.loads(payload.decode("utf-8"))
        return payload, (footer if isinstance(footer, (bytes, bytearray)) else None)

    def sign_public(self, priv: PasetoKey, payload: Mapping[str, Any], footer: Optional[bytes], implicit: Optional[bytes]) -> str:
        pkey = self._to_pyseto_key(priv)
        return pyseto.encode(pkey, payload, footer=footer, implicit_assertion=implicit)  # type: ignore

    def verify_public(self, pubs: Iterable[PasetoKey], token: str, implicit: Optional[bytes]) -> Tuple[Dict[str, Any], Optional[bytes]]:
        pkeys = [self._to_pyseto_key(k) for k in pubs]
        obj = pyseto.decode(pkeys, token, implicit_assertion=implicit)  # type: ignore
        payload = obj.payload if hasattr(obj, "payload") else obj  # type: ignore
        footer = getattr(obj, "footer", None)
        if isinstance(payload, (bytes, bytearray)):
            payload = json.loads(payload.decode("utf-8"))
        return payload, (footer if isinstance(footer, (bytes, bytearray)) else None)

# -----------------------------
# Валидация claims
# -----------------------------

@dataclass
class ValidationPolicy:
    issuer: Optional[str] = None
    audience: Optional[str] = None         # строка; если в токене список — должна присутствовать
    subject: Optional[str] = None
    leeway: int = 60                       # секунд
    max_age: Optional[int] = None          # секунд; если задано — проверяем iat
    require_sub: bool = False
    require_jti: bool = False

class ClaimsValidator:
    def __init__(self, policy: ValidationPolicy) -> None:
        self.policy = policy

    def validate(self, claims: Mapping[str, Any]) -> None:
        now = _utcnow()
        leeway = timedelta(seconds=max(0, self.policy.leeway))
        # exp
        exp = claims.get("exp")
        if exp is not None:
            exp_dt = _parse_time(exp)
            if now > exp_dt + leeway:
                raise TokenExpired("Token expired")
        # nbf
        nbf = claims.get("nbf")
        if nbf is not None:
            nbf_dt = _parse_time(nbf)
            if now + leeway < nbf_dt:
                raise TokenNotYetValid("Token not yet valid")
        # iat
        iat = claims.get("iat")
        if iat is not None:
            iat_dt = _parse_time(iat)
            if self.policy.max_age is not None:
                max_age_dt = iat_dt + timedelta(seconds=self.policy.max_age) + leeway
                if now > max_age_dt:
                    raise TokenExpired("Token too old")

        # iss
        if self.policy.issuer is not None:
            if str(claims.get("iss") or "") != self.policy.issuer:
                raise TokenIssuerMismatch("Issuer mismatch")

        # aud
        if self.policy.audience is not None:
            aud = claims.get("aud")
            if isinstance(aud, list):
                if self.policy.audience not in [str(x) for x in aud]:
                    raise TokenAudienceMismatch("Audience mismatch")
            else:
                if str(aud or "") != self.policy.audience:
                    raise TokenAudienceMismatch("Audience mismatch")

        # sub
        sub = claims.get("sub")
        if self.policy.require_sub and not sub:
            raise TokenSubjectMismatch("Subject required")
        if self.policy.subject is not None and str(sub or "") != self.policy.subject:
            raise TokenSubjectMismatch("Subject mismatch")

        # jti
        if self.policy.require_jti and not claims.get("jti"):
            raise TokenInvalid("jti required")

# -----------------------------
# Конфигурация сервиса
# -----------------------------

@dataclass
class PasetoConfig:
    default_version: int = int(os.getenv("SEC_CORE_PASETO_VERSION", "4"))
    default_purpose: str = os.getenv("SEC_CORE_PASETO_PURPOSE", "public")
    default_issuer: Optional[str] = os.getenv("SEC_CORE_PASETO_ISSUER") or None
    default_audience: Optional[str] = os.getenv("SEC_CORE_PASETO_AUDIENCE") or None
    default_leeway_sec: int = int(os.getenv("SEC_CORE_PASETO_LEEWAY", "60"))
    default_max_age_sec: Optional[int] = int(os.getenv("SEC_CORE_PASETO_MAX_AGE", "0")) or None
    add_iat: bool = os.getenv("SEC_CORE_PASETO_ADD_IAT", "true").lower() in ("1","true","yes","on")
    add_jti: bool = os.getenv("SEC_CORE_PASETO_ADD_JTI", "true").lower() in ("1","true","yes","on")

# -----------------------------
# Сервис токенов
# -----------------------------

@dataclass
class IssueOptions:
    version: Optional[int] = None
    purpose: Optional[str] = None
    kid: Optional[str] = None
    expires_in: Optional[int] = None            # seconds
    not_before_in: Optional[int] = None         # seconds
    issuer: Optional[str] = None
    audience: Optional[str] = None
    subject: Optional[str] = None
    footer: Optional[Mapping[str, Any]] = None
    implicit_assertion: Optional[bytes] = None  # bytes used in encode/decode

class PasetoService:
    def __init__(self, keystore: KeyStore, provider: Optional[Provider] = None, config: Optional[PasetoConfig] = None) -> None:
        self.keystore = keystore
        self.provider = provider or (PysetoProvider() if _HAS_PYSETO else None)
        if self.provider is None:
            raise RuntimeError("No PASETO provider configured (pyseto not installed)")
        self.config = config or PasetoConfig()

    # ---------- Issue ----------

    def issue(self, claims: Mapping[str, Any], *, options: Optional[IssueOptions] = None) -> str:
        opts = options or IssueOptions()
        version = opts.version or self.config.default_version
        purpose = (opts.purpose or self.config.default_purpose).lower()
        if version not in SUPPORTED_VERSIONS or purpose not in SUPPORTED_PURPOSES:
            raise PasetoError("Unsupported version/purpose")

        # Выбор ключа
        key = self._select_key(version, purpose, opts.kid)

        # Базовые claims
        now = _utcnow()
        out_claims: Dict[str, Any] = dict(claims)
        if self.config.add_iat and "iat" not in out_claims:
            out_claims["iat"] = now
        if self.config.add_jti and "jti" not in out_claims:
            out_claims["jti"] = _gen_jti()
        if opts.expires_in:
            out_claims.setdefault("exp", now + timedelta(seconds=opts.expires_in))
        if opts.not_before_in:
            out_claims.setdefault("nbf", now + timedelta(seconds=opts.not_before_in))
        if opts.issuer or self.config.default_issuer:
            out_claims.setdefault("iss", opts.issuer or self.config.default_issuer)
        if opts.audience or self.config.default_audience:
            out_claims.setdefault("aud", opts.audience or self.config.default_audience)
        if opts.subject:
            out_claims.setdefault("sub", opts.subject)

        footer_bytes = _encode_footer(opts.footer, kid=key.kid, version=version, purpose=purpose)
        implicit = opts.implicit_assertion

        # Кодирование
        if purpose == "local":
            token = self.provider.encode_local(key, out_claims, footer_bytes, implicit)
        else:
            if not key.is_private:
                raise PasetoError("Public purpose requires private signing key")
            token = self.provider.sign_public(key, out_claims, footer_bytes, implicit)

        log.debug(_event("token.issued", version=version, purpose=purpose, kid=key.kid, iss=out_claims.get("iss"), aud=out_claims.get("aud")))
        return token

    # ---------- Verify/Decrypt ----------

    def verify(self, token: str, *, policy: Optional[ValidationPolicy] = None, implicit_assertion: Optional[bytes] = None) -> Dict[str, Any]:
        version, purpose = parse_header(token)
        keys = self._candidate_keys(version, purpose)

        if purpose == "local":
            payload, _footer = self.provider.decode_local(keys, token, implicit_assertion)
        else:
            # Для public используем только публичные ключи
            pub_keys = [k for k in keys if not k.is_private]
            payload, _footer = self.provider.verify_public(pub_keys, token, implicit_assertion)

        # Валидация claim'ов
        pol = policy or ValidationPolicy(
            issuer=self.config.default_issuer,
            audience=self.config.default_audience,
            leeway=self.config.default_leeway_sec,
            max_age=self.config.default_max_age_sec,
        )
        ClaimsValidator(pol).validate(payload)
        return payload

    # ---------- Вспомогательное ----------

    def _select_key(self, version: int, purpose: str, kid: Optional[str]) -> PasetoKey:
        # Если указан KID — берём его; иначе — primary
        if kid:
            k = self.keystore.get_by_kid(kid)
            self._ensure_key_fits(k, version, purpose)
            self._ensure_active(k)
            return k
        k = self.keystore.get_primary(version, purpose)
        self._ensure_active(k)
        return k

    def _candidate_keys(self, version: int, purpose: str) -> List[PasetoKey]:
        now = _utcnow()
        out: List[PasetoKey] = []
        for k in self.keystore.all_keys():
            if k.version != version or k.purpose != purpose:
                continue
            if not k.active:
                continue
            if k.not_before and now < k.not_before:
                continue
            if k.not_after and now > k.not_after:
                continue
            out.append(k)
        if not out:
            raise PasetoError(f"No active keys available for v{version}.{purpose}")
        # сортируем по created_at — полезно при переборе
        out.sort(key=lambda x: x.created_at, reverse=True)
        return out

    @staticmethod
    def _ensure_key_fits(k: PasetoKey, version: int, purpose: str) -> None:
        if k.version != version or k.purpose != purpose:
            raise PasetoError("KID does not match version/purpose")

    @staticmethod
    def _ensure_active(k: PasetoKey) -> None:
        now = _utcnow()
        if not k.active:
            raise PasetoError("Key is inactive")
        if k.not_before and now < k.not_before:
            raise PasetoError("Key not yet valid")
        if k.not_after and now > k.not_after:
            raise PasetoError("Key expired")

# -----------------------------
# Footer helpers
# -----------------------------

def _encode_footer(footer: Optional[Mapping[str, Any]], *, kid: str, version: int, purpose: str) -> Optional[bytes]:
    # В footer всегда добавляем служебные поля kid/typ
    base: Dict[str, Any] = {"kid": kid, "typ": f"paseto;v{version}.{purpose}"}
    if footer:
        # Пользовательские ключи перетирают базовые только явно
        base.update(footer)
    return _json_dumps(base).encode("utf-8")

# -----------------------------
# Парсер заголовка токена
# -----------------------------

def parse_header(token: str) -> Tuple[int, str]:
    """
    Возвращает (version, purpose) по префиксу токена.
    Формат: v2.local..., v4.public..., ...
    """
    try:
        p1, p2, *_ = token.split(".")
    except ValueError:
        raise TokenInvalid("Malformed token")
    if not p1.startswith("v") or p2 not in SUPPORTED_PURPOSES:
        raise TokenInvalid("Unknown token header")
    try:
        version = int(p1[1:])
    except Exception:
        raise TokenInvalid("Invalid version")
    if version not in SUPPORTED_VERSIONS:
        raise TokenInvalid("Unsupported version")
    return version, p2

# -----------------------------
# Генерация ключей
# -----------------------------

def generate_local_key(*, version: int, kid: Optional[str] = None, primary: bool = False, not_after_days: Optional[int] = None) -> PasetoKey:
    if version not in SUPPORTED_VERSIONS:
        raise ValueError("Unsupported version")
    secret = secrets.token_bytes(32)
    _kid = kid or _hmac_kid_material(secret)
    return PasetoKey(
        version=version,
        purpose="local",
        kid=_kid,
        material=secret,
        is_private=True,
        primary=primary,
        not_after=(_utcnow() + timedelta(days=int(not_after_days))) if not_after_days else None,
    )

def import_public_key(*, version: int, kid: str, material: Any, is_private: bool, primary: bool = False, not_after_days: Optional[int] = None) -> PasetoKey:
    """
    Импорт асимметричного ключа (public purpose).
    material: для провайдера pyseto — это pyseto.Key или PEM в bytes (приватный либо публичный).
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError("Unsupported version")
    return PasetoKey(
        version=version,
        purpose="public",
        kid=kid,
        material=material,
        is_private=is_private,
        primary=primary,
        not_after=(_utcnow() + timedelta(days=int(not_after_days))) if not_after_days else None,
    )

# -----------------------------
# Вспомогательное логирование
# -----------------------------

def _event(name: str, **fields: Any) -> str:
    payload = {"event": name, **fields}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

# -----------------------------
# Пример использования (для справки)
# -----------------------------
# if __name__ == "__main__":
#     # Конфигурация
#     cfg = PasetoConfig(default_version=4, default_purpose="public", default_issuer="auth.example", default_audience="api://example")
#
#     # Ключи:
#     # 1) local v4
#     k_local = generate_local_key(version=4, primary=True)
#     # 2) public v4 (пример через pyseto генерацию приватного ключа)
#     if _HAS_PYSETO:
#         sk = _PysetoKey.generate(version=4, purpose="public")  # type: ignore[attr-defined]
#         # В некоторых версиях API generate возвращает приватный ключ; публичный можно получить из него
#         k_sign = import_public_key(version=4, kid="sign-v4", material=sk, is_private=True, primary=True)
#         k_verify = import_public_key(version=4, kid="sign-v4", material=sk.public_key(), is_private=False)  # type: ignore[attr-defined]
#         ks = InMemoryKeyStore([k_local, k_sign, k_verify])
#         svc = PasetoService(ks, provider=PysetoProvider(), config=cfg)
#
#         # Выпуск токена (public)
#         token = svc.issue({"sub": "user123"}, options=IssueOptions(expires_in=300, audience="api://example"))
#         print("token:", token)
#         # Проверка
#         claims = svc.verify(token)
#         print("claims:", claims)
#
#     else:
#         print("pyseto is not installed; provider unavailable")
