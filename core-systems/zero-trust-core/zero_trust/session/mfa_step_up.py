# zero-trust-core/zero_trust/session/mfa_step_up.py
from __future__ import annotations

import base64
import enum
import hmac
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Protocol, Tuple

# Опционально: PyOTP для TOTP. Если недоступен — используется встроенная реализация RFC 6238 (HMAC-SHA1/30s/6 digits).
try:
    import pyotp  # type: ignore
    _HAVE_PYOTP = True
except Exception:
    _HAVE_PYOTP = False


# ============================== Вспомогательные утилиты ==============================

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _now() -> int:
    return int(time.time())

def _ct_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ============================== Контракты расширения ==============================

class FactorProvider(Protocol):
    """Провайдер конкретного фактора step-up (TOTP, WebAuthn, Push и т.п.)."""

    name: str  # уникальное имя фактора (e.g. "totp", "webauthn")

    def start(self, principal: str, context: Mapping[str, Any]) -> Mapping[str, Any]:
        """
        Подготовить челлендж. Возвращает payload для клиента (например, webauthn challenge),
        а также может записать side-channel состояние через ChallengeStore (делает менеджер).
        """
        ...

    def verify(self, principal: str, context: Mapping[str, Any], client_response: Mapping[str, Any]) -> bool:
        """
        Проверить ответ клиента на ранее выданный челлендж.
        """
        ...


class CredentialStore(Protocol):
    """Хранилище пользовательских данных факторов (секреты TOTP, WebAuthn креды и т.д.)."""

    def get_totp_secret(self, principal: str) -> Optional[str]:
        """Вернуть Base32 секрет для TOTP или None, если фактор не подключен."""
        ...

    # Заготовка: можно расширить для WebAuthn/Passkeys
    def get_webauthn_credentials(self, principal: str) -> Iterable[Mapping[str, Any]]:
        """Список зарегистрированных WebAuthn кредов (AAGUID, public_key, sign_count, и пр.)."""
        return ()


class ChallengeStore(Protocol):
    """Хранилище челленджей step-up (в памяти/Redis/БД)."""

    def create(self, challenge: "Challenge") -> None: ...
    def get(self, challenge_id: str) -> Optional["Challenge"]: ...
    def update(self, challenge: "Challenge") -> None: ...
    def consume(self, challenge_id: str) -> bool:
        """Атомарно пометить челлендж использованным. Вернуть True, если удалось."""
        ...


class ProofSigner(Protocol):
    """Выдаёт краткоживущее подписанное доказательство прохождения step-up."""

    def mint(self, payload: Mapping[str, Any], ttl_s: int) -> str: ...
    def verify(self, token: str) -> Optional[Mapping[str, Any]]: ...


# ============================== Конфигурация/модели ==============================

class ChallengeStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    CANCELED = "canceled"


@dataclass
class StepUpConfig:
    enabled_factors: Tuple[str, ...] = ("webauthn", "totp")
    default_factor: str = "webauthn"
    challenge_ttl_s: int = 180
    max_parallel_challenges_per_principal: int = 3
    rate_limit_per_minute: int = 6
    bind_to_session: bool = True
    bind_to_token: bool = True
    bind_to_origin: bool = True  # проверка origin/referrer при браузерных потоках
    proof_ttl_s: int = 900
    # Секреты подписания (ротация поддерживается через список: первый — активный)
    proof_signing_keys: Tuple[str, ...] = (base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),)
    issuer: str = "zero-trust-core"
    audience: str = "zero-trust-enforcer"


@dataclass
class Challenge:
    id: str
    created_at: int
    expires_at: int
    status: ChallengeStatus
    principal: str
    factor: str
    # Привязки (anti-phishing/anti-replay)
    session_id: Optional[str] = None
    token_id: Optional[str] = None  # jti
    origin: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    # Доп. данные фактора (например, webauthn challenge)
    payload: Dict[str, Any] = field(default_factory=dict)
    verified_at: Optional[int] = None

    def is_expired(self, now: Optional[int] = None) -> bool:
        return (now or _now()) > self.expires_at


# ============================== Реализации по умолчанию ==============================

class InMemoryChallengeStore(ChallengeStore):
    """Промежуточная in-memory реализация. Для продакшена используйте Redis/БД."""

    def __init__(self) -> None:
        self._items: Dict[str, Challenge] = {}
        self._by_principal: Dict[str, set[str]] = {}

    def create(self, challenge: Challenge) -> None:
        self._items[challenge.id] = challenge
        self._by_principal.setdefault(challenge.principal, set()).add(challenge.id)

    def get(self, challenge_id: str) -> Optional[Challenge]:
        ch = self._items.get(challenge_id)
        if ch and ch.is_expired():
            ch.status = ChallengeStatus.EXPIRED
        return ch

    def update(self, challenge: Challenge) -> None:
        self._items[challenge.id] = challenge

    def consume(self, challenge_id: str) -> bool:
        ch = self._items.get(challenge_id)
        if not ch or ch.status not in (ChallengeStatus.VERIFIED,):
            return False
        ch.status = ChallengeStatus.CONSUMED
        self._items[challenge_id] = ch
        # очистим индекс
        if ch.principal in self._by_principal:
            self._by_principal[ch.principal].discard(challenge_id)
        return True

    # Вспомогательное:
    def count_open_for_principal(self, principal: str) -> int:
        ids = self._by_principal.get(principal, set())
        return sum(1 for cid in ids if (self._items.get(cid) and self._items[cid].status == ChallengeStatus.PENDING))


class HMACProofSigner(ProofSigner):
    """Подписывает proof через HMAC-SHA256; payload — JSON, токен — base64url(header).base64url(payload).base64url(sig)."""

    def __init__(self, keys: Tuple[str, ...], issuer: str, audience: str) -> None:
        assert keys and keys[0], "at least one signing key required"
        self._keys = tuple(_b64url_to_bytes(k) if isinstance(k, str) else k for k in keys)
        self._iss = issuer
        self._aud = audience

    def mint(self, payload: Mapping[str, Any], ttl_s: int) -> str:
        now = _now()
        body = dict(payload)
        body.update({"iss": self._iss, "aud": self._aud, "iat": now, "exp": now + int(ttl_s)})
        header = {"alg": "HS256", "typ": "JWT"}
        b64h = _b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        b64p = _b64url(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        sig = hmac.new(self._keys[0], f"{b64h}.{b64p}".encode(), hashlib.sha256).digest()
        return f"{b64h}.{b64p}.{_b64url(sig)}"

    def verify(self, token: str) -> Optional[Mapping[str, Any]]:
        try:
            b64h, b64p, b64s = token.split(".")
            msg = f"{b64h}.{b64p}".encode()
            sig = _b64url_to_bytes(b64s)
            valid = any(hmac.compare_digest(hmac.new(k, msg, hashlib.sha256).digest(), sig) for k in self._keys)
            if not valid:
                return None
            payload = json.loads(_b64url_to_bytes(b64p))
            now = _now()
            if payload.get("aud") != self._aud or payload.get("iss") != self._iss:
                return None
            if now < int(payload.get("iat", 0)) - 60 or now > int(payload.get("exp", 0)) + 60:
                return None
            return payload
        except Exception:
            return None


# ============================== Фактор TOTP (RFC 6238) ==============================

def _totp_now(secret_b32: str, step: int = 30, digits: int = 6, algo: str = "SHA1", at: Optional[int] = None) -> str:
    # Встроенная реализация для fallback (SHA1/6/30s)
    t = int((at or _now()) // step)
    key = base64.b32decode(secret_b32.upper())
    msg = t.to_bytes(8, "big")
    if algo.upper() == "SHA1":
        mac = hmac.new(key, msg, hashlib.sha1).digest()
    elif algo.upper() == "SHA256":
        mac = hmac.new(key, msg, hashlib.sha256).digest()
    elif algo.upper() == "SHA512":
        mac = hmac.new(key, msg, hashlib.sha512).digest()
    else:
        mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | (mac[offset + 3])
    return str(code % (10 ** digits)).zfill(digits)

class TOTPProvider(FactorProvider):
    name = "totp"

    def __init__(self, cred_store: CredentialStore, *, step: int = 30, digits: int = 6, algo: str = "SHA1", window: int = 1) -> None:
        self.store = cred_store
        self.step = step
        self.digits = digits
        self.algo = algo
        self.window = window  # количество соседних интервалов времени в обе стороны

    def start(self, principal: str, context: Mapping[str, Any]) -> Mapping[str, Any]:
        # Для TOTP челлендж дополнительный не нужен; возвращаем лишь подсказку и политику ввода.
        return {"factor": "totp", "digits": self.digits, "step": self.step}

    def verify(self, principal: str, context: Mapping[str, Any], client_response: Mapping[str, Any]) -> bool:
        code = str(client_response.get("code", ""))
        if not code.isdigit():
            return False
        secret = self.store.get_totp_secret(principal)
        if not secret:
            return False
        if _HAVE_PYOTP:
            try:
                totp = pyotp.TOTP(secret, interval=self.step, digits=self.digits)
                return bool(totp.verify(code, valid_window=self.window))
            except Exception:
                return False
        # Fallback: ручная валидация в окне ±window
        now = _now()
        for w in range(-self.window, self.window + 1):
            if _ct_eq(_totp_now(secret, step=self.step, digits=self.digits, algo=self.algo, at=now + w * self.step), code):
                return True
        return False


# ============================== WebAuthn (плагин-интерфейс) ==============================

class WebAuthnProvider(FactorProvider):
    name = "webauthn"

    def __init__(self, cred_store: CredentialStore) -> None:
        self.store = cred_store
        # Реальная реализация должна использовать библиотеку WebAuthn/Passkeys.
        # Здесь оставлен каркас интерфейса. Подключите свой провайдер через этот класс или замените его.

    def start(self, principal: str, context: Mapping[str, Any]) -> Mapping[str, Any]:
        # Возвращаем структуру PublicKeyCredentialRequestOptions (упрощённо)
        challenge = _b64url(secrets.token_bytes(32))
        rp_id = context.get("rp_id") or context.get("host") or "localhost"
        allow_creds = [{"id": c.get("credential_id"), "type": "public-key"} for c in self.store.get_webauthn_credentials(principal)]
        return {
            "factor": "webauthn",
            "publicKey": {
                "challenge": challenge,
                "rpId": rp_id,
                "timeout": 60000,
                "allowCredentials": allow_creds,
                "userVerification": "preferred",
            },
        }

    def verify(self, principal: str, context: Mapping[str, Any], client_response: Mapping[str, Any]) -> bool:
        # Подпись проверяется специализированной библиотекой;
        # здесь оставляем «заглушку», которая всегда проваливается, чтобы не создавать ложное чувство защиты.
        # Подключите реальную проверку и верните True/False.
        return False  # безопасный дефолт


# ============================== Менеджер Step-Up ==============================

@dataclass
class StepUpManager:
    config: StepUpConfig
    cred_store: CredentialStore
    challenge_store: ChallengeStore = field(default_factory=InMemoryChallengeStore)
    proof_signer: ProofSigner = field(init=False)

    def __post_init__(self) -> None:
        self.proof_signer = HMACProofSigner(self.config.proof_signing_keys, self.config.issuer, self.config.audience)
        # Инициализация провайдеров по умолчанию
        self._providers: Dict[str, FactorProvider] = {
            "totp": TOTPProvider(self.cred_store),
            # "webauthn": WebAuthnProvider(self.cred_store),  # оставлено как каркас — подключите свою реализацию
        }

    # --------- Регистрация/расширение факторов ---------

    def register_provider(self, provider: FactorProvider) -> None:
        self._providers[provider.name] = provider

    # --------- API жизненного цикла челленджа ---------

    def start_challenge(
        self,
        *,
        principal: str,
        preferred_factor: Optional[str],
        session_id: Optional[str],
        token_id: Optional[str],
        origin: Optional[str],
        ip: Optional[str],
        user_agent: Optional[str],
        extra_ctx: Optional[Mapping[str, Any]] = None,
    ) -> Mapping[str, Any]:
        """
        Создаёт челлендж для step-up, применяя лимиты и привязки.
        Возвращает {challenge_id, factor, payload, expires_at}.
        """
        factor = self._select_factor(principal, preferred_factor)
        provider = self._providers.get(factor)
        if not provider:
            raise ValueError("factor_not_supported")

        # Лимиты
        store = self._as_mem_store()
        if store and store.count_open_for_principal(principal) >= self.config.max_parallel_challenges_per_principal:
            raise RateLimitExceeded("too_many_open_challenges")

        # Контекст для провайдера
        ctx = {
            "session_id": session_id if self.config.bind_to_session else None,
            "token_id": token_id if self.config.bind_to_token else None,
            "origin": origin if self.config.bind_to_origin else None,
            "ip": ip,
            "user_agent": user_agent,
        }
        if extra_ctx:
            ctx.update(extra_ctx)

        payload = provider.start(principal, ctx)
        now = _now()
        ch = Challenge(
            id=str(uuid.uuid4()),
            created_at=now,
            expires_at=now + self.config.challenge_ttl_s,
            status=ChallengeStatus.PENDING,
            principal=principal,
            factor=factor,
            session_id=session_id if self.config.bind_to_session else None,
            token_id=token_id if self.config.bind_to_token else None,
            origin=origin if self.config.bind_to_origin else None,
            ip=ip,
            user_agent=user_agent,
            payload=dict(payload or {}),
        )
        self.challenge_store.create(ch)
        return {"challenge_id": ch.id, "factor": ch.factor, "payload": ch.payload, "expires_at": ch.expires_at}

    def verify_response(
        self,
        *,
        challenge_id: str,
        principal: str,
        client_response: Mapping[str, Any],
        session_id: Optional[str],
        token_id: Optional[str],
        origin: Optional[str],
        ip: Optional[str],
        user_agent: Optional[str],
    ) -> Mapping[str, Any]:
        """
        Проверяет ответ на челлендж и возвращает подписанное proof при успехе.
        """
        ch = self.challenge_store.get(challenge_id)
        if not ch or ch.status != ChallengeStatus.PENDING:
            raise InvalidChallenge("challenge_not_found_or_not_pending")
        if ch.is_expired():
            ch.status = ChallengeStatus.EXPIRED
            self.challenge_store.update(ch)
            raise InvalidChallenge("challenge_expired")
        if ch.principal != principal:
            raise InvalidChallenge("principal_mismatch")

        # Проверка привязок (препятствует фишингу/переносу)
        if self.config.bind_to_session and ch.session_id and ch.session_id != session_id:
            raise InvalidChallenge("session_mismatch")
        if self.config.bind_to_token and ch.token_id and ch.token_id != token_id:
            raise InvalidChallenge("token_mismatch")
        if self.config.bind_to_origin and ch.origin and ch.origin != origin:
            raise InvalidChallenge("origin_mismatch")

        provider = self._providers.get(ch.factor)
        if not provider:
            raise InvalidChallenge("provider_missing")

        # Контекст для верификации
        ctx = {
            "session_id": ch.session_id,
            "token_id": ch.token_id,
            "origin": ch.origin,
            "ip": ip,
            "user_agent": user_agent,
            "challenge_payload": ch.payload,
        }
        ok = provider.verify(principal, ctx, client_response)
        if not ok:
            raise VerificationFailed("verification_failed")

        ch.status = ChallengeStatus.VERIFIED
        ch.verified_at = _now()
        self.challenge_store.update(ch)

        # Подписываем proof (используйте его как «step-up маркер» в вашей авторизации)
        proof = self.proof_signer.mint(
            {
                "sub": principal,
                "sid": session_id,
                "jti": token_id,
                "cid": ch.id,
                "act": "step_up_mfa",
                "factor": ch.factor,
            },
            ttl_s=self.config.proof_ttl_s,
        )
        return {"challenge_id": ch.id, "status": "verified", "proof": proof, "exp": _now() + self.config.proof_ttl_s}

    def consume(self, challenge_id: str) -> bool:
        """Отметить proof/челлендж использованным (идемпотентно)."""
        return self.challenge_store.consume(challenge_id)

    def verify_proof(self, proof: str, *, principal: str, session_id: Optional[str], token_id: Optional[str]) -> bool:
        """
        Проверить подписанное proof (например, в /enforce перед выполнением действия).
        """
        payload = self.proof_signer.verify(proof)
        if not payload:
            return False
        if payload.get("sub") != principal:
            return False
        if self.config.bind_to_session and payload.get("sid") and payload.get("sid") != session_id:
            return False
        if self.config.bind_to_token and payload.get("jti") and payload.get("jti") != token_id:
            return False
        # Дополнительно можно потребовать consume(challenge_id), чтобы one-shot применять маркер.
        return True

    # --------- Внутреннее ---------

    def _select_factor(self, principal: str, preferred_factor: Optional[str]) -> str:
        cand = preferred_factor or self.config.default_factor
        if cand in self.config.enabled_factors and cand in self._providers:
            return cand
        # Фоллбек: используем первый доступный из enabled_factors
        for f in self.config.enabled_factors:
            if f in self._providers:
                return f
        raise ValueError("no_enabled_factors")

    def _as_mem_store(self) -> Optional[InMemoryChallengeStore]:
        return self.challenge_store if isinstance(self.challenge_store, InMemoryChallengeStore) else None


# ============================== Исключения ==============================

class StepUpError(RuntimeError): ...
class RateLimitExceeded(StepUpError): ...
class InvalidChallenge(StepUpError): ...
class VerificationFailed(StepUpError): ...


# ============================== Пример интеграции (док) ==============================
"""
Интеграция с роутером /api/v1/enforce:

from zero_trust.session.mfa_step_up import StepUpManager, StepUpConfig

stepup = StepUpManager(
    config=StepUpConfig(),
    cred_store=YourCredentialStore(),            # реализуйте CredentialStore
    # challenge_store=YourRedisChallengeStore(), # внедрите производство-грейд хранилище
)

# Когда policy вернула required_actions=["REQUIRE_MFA"]:
resp = stepup.start_challenge(
    principal=ctx.principal,
    preferred_factor="webauthn",  # или "totp"
    session_id=ctx.session_id,
    token_id=ctx.token_id,
    origin=request.headers.get("origin"),
    ip=request.headers.get("x-forwarded-for"),
    user_agent=request.headers.get("user-agent"),
)

# Затем клиент отправляет ответ на челлендж:
verify = stepup.verify_response(
    challenge_id=resp["challenge_id"],
    principal=ctx.principal,
    client_response=client_json,   # формат зависит от фактора (TOTP: {"code":"123456"})
    session_id=ctx.session_id,
    token_id=ctx.token_id,
    origin=request.headers.get("origin"),
    ip=request.headers.get("x-forwarded-for"),
    user_agent=request.headers.get("user-agent"),
)

# Сохраните verify["proof"] в сессии и проверяйте stepup.verify_proof(proof, ...) перед чувствительными действиями.
"""
