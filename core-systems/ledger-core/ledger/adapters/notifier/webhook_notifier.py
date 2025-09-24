# ledger-core/ledger/ledger/adapters/notifier/webhook_notifier.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import time
import typing as t
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding

# ======================================================================================
# Логирование
# ======================================================================================

LOG = logging.getLogger("ledger.notifier.webhook")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(_h)
LOG.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

# ======================================================================================
# Утилиты
# ======================================================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")

def json_compact(obj: t.Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def json_c14n_approx(obj: t.Any) -> bytes:
    # При необходимости замените строгой реализацией RFC 8785
    return json_compact(obj)

def canonicalize(payload: t.Union[bytes, str, dict, list], method: str) -> bytes:
    if method == "utf8-bytes":
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        return json_compact(payload)
    if method == "json-compact":
        return json_compact(payload)
    if method == "json-c14n@rfc8785":
        return json_c14n_approx(payload)
    raise ValueError(f"unknown canonicalization: {method}")

def pick_hash(name: str):
    n = name.upper()
    if n == "SHA-256":
        return hashlib.sha256
    if n == "SHA-512":
        return hashlib.sha512
    raise ValueError(f"unsupported hash alg: {name}")

# ======================================================================================
# Конфигурации получателей
# ======================================================================================

@dataclass(frozen=True)
class Destination:
    name: str
    url: str
    method: str = "POST"
    timeout_s: float = 10.0
    connect_timeout_s: float = 3.0
    # Ретраи
    max_retries: int = 6
    base_backoff_s: float = 0.25
    max_backoff_s: float = 15.0
    # Rate limit
    rate_limit_per_sec: float = 20.0
    rate_burst: int = 40
    # Circuit breaker
    cb_failure_threshold: int = 5
    cb_open_seconds: float = 30.0
    # Подпись
    algo: str = "HMAC_SHA256"  # "HMAC_SHA256" | "JWS"
    canonicalization: str = "json-compact"
    hash_alg: str = "SHA-256"
    include_proof_in_body: bool = True
    # HMAC
    hmac_secret: t.Optional[bytes] = None
    hmac_key_id: t.Optional[str] = None
    # JWS
    jws_alg: t.Optional[str] = None  # "EdDSA"|"ES256"|"RS256"|"PS256"|"HS256"
    jws_private_key_pem: t.Optional[bytes] = None
    jws_kid: t.Optional[str] = None
    jwk_verification_method: t.Optional[str] = None  # https://.../.well-known/jwks.json#kid=...
    # Идемпотентность
    idempotency_ttl_s: int = 3600

# ======================================================================================
# Троттлинг и circuit breaker
# ======================================================================================

@dataclass
class TokenBucket:
    rate: float
    burst: int
    _tokens: float = field(init=False)
    _ts: float = field(default_factory=time.monotonic, init=False)

    def __post_init__(self):
        self._tokens = float(self.burst)

    async def acquire(self, cost: float = 1.0):
        while True:
            now = time.monotonic()
            delta = now - self._ts
            self._ts = now
            self._tokens = min(self.burst, self._tokens + delta * self.rate)
            if self._tokens >= cost:
                self._tokens -= cost
                return
            # подождать недостающие токены
            wait = (cost - self._tokens) / self.rate
            await asyncio.sleep(min(wait, 0.1))

@dataclass
class CircuitBreaker:
    failure_threshold: int
    open_seconds: float
    _failures: int = 0
    _opened_at: float = 0.0

    def allow(self) -> bool:
        if self._opened_at <= 0:
            return True
        if (time.monotonic() - self._opened_at) >= self.open_seconds:
            # полувскрытый режим
            return True
        return False

    def on_success(self):
        self._failures = 0
        self._opened_at = 0.0

    def on_failure(self):
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = time.monotonic()

# ======================================================================================
# Стратегии подписи
# ======================================================================================

class Signer(t.Protocol):
    algo_name: str
    def sign(self, *, canonical_bytes: bytes) -> dict: ...
    def headers(self) -> dict: ...
    def key_info(self) -> dict: ...

class HmacSigner:
    algo_name = "HMAC_SHA256"
    def __init__(self, secret: bytes, key_id: t.Optional[str] = None, hash_alg: str = "SHA-256"):
        self._secret = secret
        self._kid = key_id
        self._hash_alg = hash_alg

    def sign(self, *, canonical_bytes: bytes) -> dict:
        mac = hmac.new(self._secret, canonical_bytes, pick_hash(self._hash_alg)).digest()
        return {
            "encoding": "base64url",
            "value": _b64u(mac),
        }

    def headers(self) -> dict:
        hdr = {}
        if self._kid:
            hdr["X-Signature-Key-Id"] = self._kid
        hdr["X-Signature-Alg"] = self.algo_name
        return hdr

    def key_info(self) -> dict:
        return {"algo": self.algo_name, "keyId": self._kid}

class JwsSigner:
    algo_name = "JWS"
    def __init__(self, *, private_key_pem: bytes, alg: str, kid: t.Optional[str] = None):
        self._alg = alg
        self._kid = kid
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        self._key = key

    def _sign(self, signing_input: bytes) -> bytes:
        if self._alg == "EdDSA":
            return self._key.sign(signing_input)
        if self._alg == "ES256":
            sig_der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            # преобразуем DER -> raw r||s
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            r, s = decode_dss_signature(sig_der)
            size = 32
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        if self._alg in ("RS256", "PS256"):
            if self._alg == "PS256":
                pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            else:
                pad = padding.PKCS1v15()
            return self._key.sign(signing_input, pad, hashes.SHA256())
        if self._alg == "HS256":
            # симметричный JWS — использовать с осторожностью
            return hmac.new(self._key, signing_input, hashlib.sha256).digest()  # type: ignore[arg-type]
        raise ValueError(f"unsupported JWS alg: {self._alg}")

    def sign(self, *, canonical_bytes: bytes) -> dict:
        # compact JWS (payload=canonical_bytes)
        header = {"alg": self._alg}
        if self._kid:
            header["kid"] = self._kid
        header_b64 = _b64u(json_compact(header))
        payload_b64 = _b64u(canonical_bytes)
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        sig = self._sign(signing_input)
        jws = header_b64 + "." + payload_b64 + "." + _b64u(sig)
        return {"jws": jws}

    def headers(self) -> dict:
        hdr = {"X-Signature-Alg": "JWS", "X-JWS-Alg": self._alg}
        if self._kid:
            hdr["X-JWS-Kid"] = self._kid
        return hdr

    def key_info(self) -> dict:
        return {"algo": "JWS", "jws_alg": self._alg, "kid": self._kid}

# ======================================================================================
# Результат и исключение
# ======================================================================================

@dataclass
class DeliveryResult:
    ok: bool
    status_code: int | None
    attempts: int
    duration_ms: int
    request_id: str
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    error: str | None = None

class DeliveryError(Exception):
    def __init__(self, result: DeliveryResult):
        super().__init__(result.error or "delivery failed")
        self.result = result

# ======================================================================================
# Основной класс нотификатора
# ======================================================================================

class WebhookNotifier:
    """
    Отправляет веб-хуки с подписью и надёжной доставкой.
    Суммарный формат тела: {"envelope": {...}, "proof": {...}} или только envelope (proof в заголовках).
    """

    def __init__(self, *, destination: Destination):
        self.dst = destination
        limits = httpx.Limits(
            max_keepalive_connections=int(os.getenv("WEBHOOK_MAX_KEEPALIVE", "100")),
            max_connections=int(os.getenv("WEBHOOK_MAX_CONN", "200")),
            keepalive_expiry=30.0,
        )
        timeout = httpx.Timeout(
            self.dst.timeout_s,
            connect=self.dst.connect_timeout_s,
            read=self.dst.timeout_s,
            write=self.dst.timeout_s,
        )
        self.client = httpx.AsyncClient(
            http2=True,
            limits=limits,
            timeout=timeout,
            headers={"User-Agent": os.getenv("USER_AGENT", "ledger-core-webhook/1.0")},
        )
        self.bucket = TokenBucket(rate=self.dst.rate_limit_per_sec, burst=self.dst.rate_burst)
        self.circuit = CircuitBreaker(
            failure_threshold=self.dst.cb_failure_threshold,
            open_seconds=self.dst.cb_open_seconds,
        )
        # Инициализация signer
        if self.dst.algo == "HMAC_SHA256":
            if not self.dst.hmac_secret:
                raise ValueError("hmac_secret is required for HMAC signing")
            self.signer: Signer = HmacSigner(self.dst.hmac_secret, self.dst.hmac_key_id, self.dst.hash_alg)
        elif self.dst.algo == "JWS":
            if not (self.dst.jws_private_key_pem and self.dst.jws_alg):
                raise ValueError("jws_private_key_pem and jws_alg are required for JWS signing")
            self.signer = JwsSigner(private_key_pem=self.dst.jws_private_key_pem, alg=self.dst.jws_alg, kid=self.dst.jws_kid)
        else:
            raise ValueError(f"unsupported signing algo: {self.dst.algo}")

        # Кэш идемпотентности (минимальный)
        self._idem_seen: dict[str, float] = {}

    async def aclose(self):
        await self.client.aclose()

    # -------------------- Публичный API --------------------

    async def send_envelope(self, *, envelope: dict) -> DeliveryResult:
        """
        Отправляет envelope (событие) на настроенный destination.
        Обязательные ключи envelope: message_id, topic, payload (dict), produced_at.
        """
        started = time.perf_counter()
        request_id = envelope.get("headers", {}).get("X-Request-Id") or str(uuid.uuid4())
        idem = envelope.get("idempotency_key") or str(uuid.uuid4())

        # Идемпотентность на стороне клиента — просто TTL‑кэш от повторных вызовов
        now = time.monotonic()
        self._cleanup_idem(now)
        if idem in self._idem_seen and self._idem_seen[idem] > now:
            LOG.info("skip duplicate by idempotency key: %s", idem)
            return DeliveryResult(ok=True, status_code=208, attempts=0, duration_ms=0, request_id=request_id)

        payload = envelope.get("payload", {})
        canonical = canonicalize(payload, self.dst.canonicalization)
        hasher = pick_hash(self.dst.hash_alg)
        digest = hasher(canonical).digest()
        digest_encoded = _b64u(digest)  # будем использовать base64url в заголовке

        proof = self._build_proof(envelope=envelope, canonical=canonical, digest=digest, digest_b64=digest_encoded)

        headers = {
            "Content-Type": "application/json",
            "X-Request-Id": request_id,
            "X-Idempotency-Key": idem,
            "X-Ledger-Message-Id": envelope.get("message_id", ""),
            "X-Ledger-Topic": envelope.get("topic", ""),
            "X-Ledger-Hash-Alg": self.dst.hash_alg,
            "X-Ledger-Canonicalization": self.dst.canonicalization,
            "X-Ledger-Hash": digest_encoded,
        }
        headers.update(self.signer.headers())
        if self.dst.algo == "JWS":
            headers["X-Proof-Type"] = "JWSProof/v1"
        else:
            headers["X-Proof-Type"] = "LedgerProof/v1"

        if self.dst.include_proof_in_body:
            body = {"envelope": envelope, "proof": proof}
        else:
            body = envelope

        attempts = 0
        error_txt: str | None = None
        resp_status: int | None = None
        resp_headers: dict[str, str] = {}
        resp_body: str | None = None

        # Троттлинг
        await self.bucket.acquire()

        if not self.circuit.allow():
            error_txt = "circuit_open"
            duration_ms = int((time.perf_counter() - started) * 1000)
            return DeliveryResult(False, None, attempts, duration_ms, request_id, error=error_txt)

        # Ретраи
        for attempt in range(1, self.dst.max_retries + 1):
            attempts = attempt
            backoff = self._compute_backoff(attempt)
            try:
                r = await self.client.request(
                    self.dst.method,
                    self.dst.url,
                    content=json_compact(body),
                    headers=headers,
                )
                resp_status = r.status_code
                resp_headers = {k: v for k, v in r.headers.items()}
                # читаем тело ограниченно
                resp_body = (await r.aread()).decode(errors="ignore")[:4096]
                if self._is_success(resp_status):
                    self.circuit.on_success()
                    self._idem_seen[idem] = time.monotonic() + self.dst.idempotency_ttl_s
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    return DeliveryResult(True, resp_status, attempts, duration_ms, request_id, resp_headers, resp_body)
                if not self._is_retryable(resp_status):
                    self.circuit.on_failure()
                    error_txt = f"http_{resp_status}"
                    break
                # уважаем Retry-After
                ra = self._retry_after_seconds(resp_headers)
                await asyncio.sleep(ra if ra is not None else backoff)
            except (httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError, httpx.HTTPError) as e:
                self.circuit.on_failure()
                error_txt = f"net_error:{e.__class__.__name__}"
                await asyncio.sleep(backoff)
            except Exception as e:
                self.circuit.on_failure()
                error_txt = f"unexpected:{e.__class__.__name__}"
                break

        duration_ms = int((time.perf_counter() - started) * 1000)
        result = DeliveryResult(False, resp_status, attempts, duration_ms, request_id, resp_headers, resp_body, error_txt)
        raise DeliveryError(result)

    # -------------------- Внутреннее --------------------

    def _build_proof(
        self,
        *,
        envelope: dict,
        canonical: bytes,
        digest: bytes,
        digest_b64: str,
    ) -> dict:
        created = _now_utc().isoformat()
        proof: dict = {
            "type": "LedgerProof/v1" if self.dst.algo != "JWS" else "JWSProof/v1",
            "algo": self.signer.algo_name if self.dst.algo != "JWS" else "JWS",
            "created": created,
            "proofPurpose": "webhook",
            "verificationMethod": self.dst.jwk_verification_method or self.dst.hmac_key_id or "internal",
            "keyId": self.dst.jws_kid or self.dst.hmac_key_id,
            "canonicalization": self.dst.canonicalization,
            "hash": {"alg": self.dst.hash_alg, "digest": digest_b64, "encoding": "base64url"},
            "payloadDigest": digest_b64,
            "headers": {
                "messageType": envelope.get("headers", {}).get("type") or envelope.get("topic", ""),
                "version": envelope.get("headers", {}).get("version", "1.0.0"),
            },
        }
        signed = self.signer.sign(canonical_bytes=canonical)
        proof.update(signed)
        return proof

    def _compute_backoff(self, attempt: int) -> float:
        base = self.dst.base_backoff_s * (2 ** (attempt - 1))
        base = min(base, self.dst.max_backoff_s)
        # полноэкспоненциальный джиттер
        return random.uniform(0, base)

    @staticmethod
    def _is_success(code: int) -> bool:
        return 200 <= code < 300

    @staticmethod
    def _is_retryable(code: int) -> bool:
        return code in (408, 425, 429, 500, 502, 503, 504)

    @staticmethod
    def _retry_after_seconds(headers: dict[str, str]) -> float | None:
        ra = headers.get("Retry-After") or headers.get("retry-after")
        if not ra:
            return None
        try:
            # секунды
            return float(ra)
        except ValueError:
            # формат даты — игнорируем для простоты
            return None

    def _cleanup_idem(self, now: float) -> None:
        if len(self._idem_seen) > 10_000:
            to_del = [k for k, exp in self._idem_seen.items() if exp < now]
            for k in to_del:
                self._idem_seen.pop(k, None)

# ======================================================================================
# Пример использования (должен жить в примерах/тестах)
# ======================================================================================

async def _demo():
    dst = Destination(
        name="example",
        url="https://webhook.site/your-endpoint",
        algo="HMAC_SHA256",
        hmac_secret=b"super-secret",
        hmac_key_id="whk-1",
        canonicalization="json-compact",
        hash_alg="SHA-256",
        max_retries=5,
    )
    notifier = WebhookNotifier(destination=dst)
    try:
        envelope = {
            "message_id": uuid.uuid4().hex,
            "topic": "ledger.v1.Transaction.Created",
            "payload": {"tx_id": "abc", "amount": {"currency": "EUR", "units": 10, "nanos": 0}},
            "produced_at": _now_utc().isoformat(),
            "idempotency_key": uuid.uuid4().hex,
            "headers": {"type": "ledger.v1.Transaction", "version": "1.2.3"},
        }
        res = await notifier.send_envelope(envelope=envelope)
        print("DELIVERED", res)
    except DeliveryError as e:
        LOG.error("delivery failed: %s", e.result.__dict__)
    finally:
        await notifier.aclose()

if __name__ == "__main__":
    asyncio.run(_demo())
