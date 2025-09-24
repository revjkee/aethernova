# file: security-core/security/pki/ocsp.py
from __future__ import annotations

import base64
import dataclasses
import logging
import os
import time
import typing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- cryptography ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asy_padding, ed25519, ed448
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

# --- HTTP (stdlib first, optional httpx) ---
try:
    import httpx  # type: ignore
    _HAVE_HTTPX = True
except Exception:
    import urllib.request
    import urllib.error
    _HAVE_HTTPX = False

logger = logging.getLogger("security_core.pki.ocsp")

# =============================================================================
# Конфигурация
# =============================================================================

@dataclass
class OcspClientConfig:
    request_hash_algorithm: str = "sha1"         # "sha1" (наибольшая совместимость) или "sha256"
    add_nonce: bool = True
    nonce_len: int = 16

    # HTTP
    timeout_sec: float = 5.0
    max_retries: int = 3
    backoff_initial_ms: int = 150
    backoff_max_ms: int = 1500
    allow_get: bool = True           # RFC 5019 — GET для коротких запросов (<255)
    user_agent: str = "aethernova-security-ocsp/1.0.0"

    # Валидация времени
    clock_skew_sec: int = 300        # допуск часов ±5 минут
    max_age_sec: int = 86400         # жёсткий предел возраста ответа (1 день), даже если nextUpdate далеко

    # Кэш
    enable_cache: bool = True
    cache_max_entries: int = 1024
    stale_while_error_sec: int = 600 # при сетевой ошибке разрешить использовать нестарший кэш до N секунд после nextUpdate (0 = запретить)

# =============================================================================
# Исключения и результат
# =============================================================================

class OcspError(Exception): ...
class OcspNetworkError(OcspError): ...
class OcspBadResponse(OcspError): ...
class OcspValidationError(OcspError): ...

@dataclass(frozen=True)
class OcspStatus:
    certificate_status: str           # "GOOD" | "REVOKED" | "UNKNOWN"
    revocation_time: Optional[datetime]
    revocation_reason: Optional[str]
    this_update: datetime
    next_update: Optional[datetime]
    produced_at: Optional[datetime]
    responder: Optional[str]          # CN/Name или keyHash
    response_bytes: bytes             # DER OCSP Response
    url: str

# =============================================================================
# Утилиты
# =============================================================================

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _redact(s: Optional[str], keep: int = 6) -> str:
    if not s:
        return ""
    return s if len(s) <= 2*keep else s[:keep] + "…" + s[-keep:]

def _hash_alg(name: str):
    name = (name or "sha1").lower()
    if name == "sha256":
        return hashes.SHA256()
    if name == "sha1":
        return hashes.SHA1()
    raise ValueError("Unsupported hash algorithm: " + name)

# =============================================================================
# Кэш ответов (по серийному номеру + URL)
# =============================================================================

class _OcspCache:
    def __init__(self, max_entries: int):
        self._store: Dict[Tuple[int, str], Tuple[bytes, float, float]] = {}
        self._max = max_entries

    def put(self, serial: int, url: str, der: bytes, next_update: Optional[datetime]):
        if len(self._store) >= self._max:
            # простое выталкивание самых старых по сроку годности
            oldest = sorted(self._store.items(), key=lambda kv: kv[1][1])[: len(self._store) - self._max + 1]
            for k, _ in oldest:
                self._store.pop(k, None)
        exp = next_update.timestamp() if next_update else _now().timestamp() + 600
        self._store[(serial, url)] = (der, exp, time.time())

    def get(self, serial: int, url: str) -> Optional[Tuple[bytes, float]]:
        v = self._store.get((serial, url))
        if not v:
            return None
        der, exp_ts, _ins_ts = v
        return der, exp_ts

# =============================================================================
# Основной клиент
# =============================================================================

class OcspClient:
    def __init__(self, cfg: Optional[OcspClientConfig] = None):
        self.cfg = cfg or OcspClientConfig()
        self._cache = _OcspCache(self.cfg.cache_max_entries) if self.cfg.enable_cache else None

    # ---------- Публичные методы ----------

    def check(self, cert: x509.Certificate, issuer: x509.Certificate, ocsp_urls: Optional[List[str]] = None) -> OcspStatus:
        """
        Выполняет полноценную проверку статуса через OCSP.
        Выборка URL из AIA, построение запроса с nonce, сетевой вызов (GET/POST),
        парсинг и криптопроверка ответа, валидация временных полей.
        """
        urls = ocsp_urls or self._extract_ocsp_urls(cert)
        if not urls:
            raise OcspError("No OCSP URLs in AIA and none provided")

        # при наличии валидного кэша — попробовать
        if self._cache:
            for url in urls:
                cached = self._cache.get(cert.serial_number, url)
                if cached:
                    der, exp_ts = cached
                    try:
                        st = self._validate_response(der, cert, issuer, url, expected_nonce=None)
                        # проверка срока
                        if st.next_update and _now() <= st.next_update + timedelta(seconds=self.cfg.stale_while_error_sec):
                            logger.info("ocsp.cache.hit", extra={"url": url, "serial": hex(cert.serial_number)})
                            return st
                    except Exception:
                        # игнорируем поломанный кэш и идём в сеть
                        pass

        # строим запрос
        req_der, expected_nonce = self._build_request(cert, issuer)

        last_err: Optional[Exception] = None
        for url in urls:
            try:
                resp_der = self._call_ocsp(url, req_der)
                st = self._validate_response(resp_der, cert, issuer, url, expected_nonce=expected_nonce)
                # положим в кэш до nextUpdate
                if self._cache:
                    self._cache.put(cert.serial_number, url, resp_der, st.next_update)
                logger.info("ocsp.ok", extra={"url": url, "serial": hex(cert.serial_number), "status": st.certificate_status})
                return st
            except (OcspNetworkError, OcspValidationError, OcspBadResponse) as e:
                logger.warning("ocsp.try.fail", extra={"url": url, "serial": hex(cert.serial_number), "err": str(e)})
                last_err = e
                continue

        # если есть кэш и разрешено stale_while_error — попытаться вернуть просроченный в разумных пределах
        if self._cache and self.cfg.stale_while_error_sec > 0:
            for url in urls:
                cached = self._cache.get(cert.serial_number, url)
                if cached:
                    der, exp_ts = cached
                    st = self._validate_response(der, cert, issuer, url, expected_nonce=None, allow_stale=True)
                    if st:
                        logger.info("ocsp.cache.stale_returned", extra={"url": url, "serial": hex(cert.serial_number)})
                        return st

        raise last_err or OcspError("OCSP check failed")

    def validate_stapled(self, stapled_der: bytes, cert: x509.Certificate, issuer: x509.Certificate, source: str = "tls-stapled") -> OcspStatus:
        """
        Валидация уже полученного DER‑ответа (например, TLS stapled).
        """
        return self._validate_response(stapled_der, cert, issuer, url=source, expected_nonce=None)

    # ---------- Вспомогательные ----------

    def _extract_ocsp_urls(self, cert: x509.Certificate) -> List[str]:
        urls: List[str] = []
        try:
            aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for a in aia:
                if a.access_method == AuthorityInformationAccessOID.OCSP and a.access_location.value:
                    urls.append(a.access_location.value)
        except x509.ExtensionNotFound:
            pass
        return urls

    def _build_request(self, cert: x509.Certificate, issuer: x509.Certificate) -> Tuple[bytes, Optional[bytes]]:
        from cryptography.x509 import ocsp

        h = _hash_alg(self.cfg.request_hash_algorithm)
        builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, h)
        nonce: Optional[bytes] = None
        if self.cfg.add_nonce:
            nonce = os.urandom(self.cfg.nonce_len)
            builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
        req = builder.build()
        der = req.public_bytes(serialization.Encoding.DER)
        return der, nonce

    def _call_ocsp(self, url: str, req_der: bytes) -> bytes:
        # RFC 5019 рекомендует GET, если путь не превосходит 255 байт
        if self.cfg.allow_get:
            b64 = _b64url(req_der)
            if len(b64) <= 255:
                get_url = url.rstrip("/") + "/" + b64
                return self._http_req(get_url, method="GET", body=None)

        # Иначе POST
        return self._http_req(
            url,
            method="POST",
            body=req_der,
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
            },
        )

    def _http_req(self, url: str, method: str, body: Optional[bytes], headers: Optional[Dict[str, str]] = None) -> bytes:
        headers = headers or {}
        headers.setdefault("User-Agent", self.cfg.user_agent)
        headers.setdefault("Accept", "application/ocsp-response")

        retries = max(0, self.cfg.max_retries)
        backoff_ms = self.cfg.backoff_initial_ms

        for attempt in range(retries + 1):
            try:
                if _HAVE_HTTPX:
                    with httpx.Client(timeout=self.cfg.timeout_sec) as client:  # type: ignore
                        if method == "GET":
                            r = client.get(url, headers=headers)
                        else:
                            r = client.post(url, content=body, headers=headers)
                        if r.status_code != 200:
                            raise OcspNetworkError(f"HTTP {r.status_code}")
                        return r.content
                else:
                    req = urllib.request.Request(url=url, data=body if method == "POST" else None, method=method, headers=headers)  # type: ignore
                    with urllib.request.urlopen(req, timeout=self.cfg.timeout_sec) as resp:  # type: ignore
                        if resp.status != 200:  # type: ignore
                            raise OcspNetworkError(f"HTTP {resp.status}")  # type: ignore
                        return resp.read()  # type: ignore
            except Exception as e:
                if attempt >= retries:
                    raise OcspNetworkError(str(e)) from e
                time.sleep(min(backoff_ms, self.cfg.backoff_max_ms) / 1000.0)
                backoff_ms = min(int(backoff_ms * 2), self.cfg.backoff_max_ms)
        raise OcspNetworkError("unreachable")

    def _validate_response(
        self,
        resp_der: bytes,
        cert: x509.Certificate,
        issuer: x509.Certificate,
        url: str,
        *,
        expected_nonce: Optional[bytes],
        allow_stale: bool = False,
    ) -> OcspStatus:
        from cryptography.x509 import ocsp

        ocsp_resp = ocsp.load_der_ocsp_response(resp_der)
        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise OcspBadResponse(f"OCSP response status: {ocsp_resp.response_status}")

        # Проверка что ответ про наш серийный номер
        if ocsp_resp.serial_number != cert.serial_number:
            raise OcspValidationError("OCSP response serial mismatch")

        # Временные поля
        skew = timedelta(seconds=self.cfg.clock_skew_sec)
        now = _now()
        this_update = ocsp_resp.this_update
        next_update = ocsp_resp.next_update
        produced_at = getattr(ocsp_resp, "produced_at", None)

        if this_update - skew > now:
            raise OcspValidationError("thisUpdate is in the future beyond allowed skew")
        if next_update:
            if now - skew > next_update:
                if not allow_stale:
                    raise OcspValidationError("nextUpdate is in the past")
                # при allow_stale даём продолжить (используется для stale_while_error)
        # жесткий предел возраста
        if produced_at and now - produced_at > timedelta(seconds=self.cfg.max_age_sec):
            raise OcspValidationError("OCSP response too old")

        # Nonce (если был в запросе) — отклонить, если не совпал или отсутствует
        if expected_nonce is not None:
            try:
                ext = ocsp_resp.extensions.get_extension_for_class(x509.OCSPNonce)  # type: ignore[attr-defined]
                nonce_resp = ext.value.nonce  # type: ignore[attr-defined]
            except Exception:
                raise OcspValidationError("OCSP nonce missing in response")
            if nonce_resp != expected_nonce:
                raise OcspValidationError("OCSP nonce mismatch")

        # Проверка подписи ответа
        responder_name = getattr(ocsp_resp, "responder_name", None)
        responder_key_hash = getattr(ocsp_resp, "responder_key_hash", None)

        responder_cert = None
        # 1) Если responder = сам issuer
        if responder_name and responder_name == issuer.subject:
            responder_cert = issuer
        else:
            # 2) Ищем включенный сертификат респондера (если библиотека это даёт)
            included = getattr(ocsp_resp, "certificates", []) or []
            for c in included:
                if responder_name and c.subject == responder_name:
                    responder_cert = c
                    break
                if responder_key_hash is not None:
                    try:
                        ski = c.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest  # type: ignore[attr-defined]
                        if ski == responder_key_hash:
                            responder_cert = c
                            break
                    except x509.ExtensionNotFound:
                        pass

        # 3) Если не нашли, допускаем, что подписал issuer
        if responder_cert is None:
            responder_cert = issuer

        # Если подписал не issuer — проверим, что его сертификат выпущен тем же CA и имеет EKU OCSP Signing
        if responder_cert != issuer:
            # EKU
            try:
                eku = responder_cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
                if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                    raise OcspValidationError("Responder certificate lacks id-kp-OCSPSigning EKU")
            except x509.ExtensionNotFound:
                raise OcspValidationError("Responder certificate has no EKU for OCSP signing")

            # Проверка подписи responder_cert ключом issuer
            try:
                issuer.public_key().verify(
                    responder_cert.signature,
                    responder_cert.tbs_certificate_bytes,
                    asy_padding.PKCS1v15() if isinstance(issuer.public_key(), rsa.RSAPublicKey) else ec.ECDSA(responder_cert.signature_hash_algorithm),
                    responder_cert.signature_hash_algorithm if isinstance(issuer.public_key(), (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)) else None,
                )
            except Exception as e:
                raise OcspValidationError("Responder certificate not signed by issuer") from e

        # Подпись самого OCSP BasicResponse
        self._verify_ocsp_signature(ocsp_resp, responder_cert)

        # Статус
        status_map = {
            ocsp.OCSPCertStatus.GOOD: "GOOD",
            ocsp.OCSPCertStatus.REVOKED: "REVOKED",
            ocsp.OCSPCertStatus.UNKNOWN: "UNKNOWN",
        }
        cert_status = status_map.get(ocsp_resp.certificate_status, "UNKNOWN")
        rev_time = getattr(ocsp_resp, "revocation_time", None)
        rev_reason = None
        try:
            rr = getattr(ocsp_resp, "revocation_reason", None)
            rev_reason = str(rr) if rr is not None else None
        except Exception:
            rev_reason = None

        return OcspStatus(
            certificate_status=cert_status,
            revocation_time=rev_time,
            revocation_reason=rev_reason,
            this_update=this_update,
            next_update=next_update,
            produced_at=produced_at,
            responder=responder_name.rfc4514_string() if responder_name else (_b64url(responder_key_hash) if responder_key_hash else None),
            response_bytes=resp_der,
            url=url,
        )

    def _verify_ocsp_signature(self, ocsp_resp, responder_cert: x509.Certificate) -> None:
        pub = responder_cert.public_key()
        data = ocsp_resp.tbs_response_bytes
        sig = ocsp_resp.signature
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(sig, data, asy_padding.PKCS1v15(), ocsp_resp.signature_hash_algorithm)
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(sig, data, ec.ECDSA(ocsp_resp.signature_hash_algorithm))
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                pub.verify(sig, data)
            elif isinstance(pub, ed448.Ed448PublicKey):
                pub.verify(sig, data)
            else:
                raise OcspValidationError("Unsupported responder key type")
        except Exception as e:
            raise OcspValidationError("OCSP response signature invalid") from e

# =============================================================================
# Загрузчики сертификатов
# =============================================================================

def load_certificate(path_or_bytes: typing.Union[str, bytes]) -> x509.Certificate:
    if isinstance(path_or_bytes, bytes):
        data = path_or_bytes
    else:
        with open(path_or_bytes, "rb") as f:
            data = f.read()
    # auto‑detect PEM/DER
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)

# =============================================================================
# Пример CLI (локальная проверка)
# =============================================================================

def _cli():
    import argparse
    parser = argparse.ArgumentParser(description="OCSP validator")
    parser.add_argument("--cert", required=True, help="end-entity cert (PEM/DER)")
    parser.add_argument("--issuer", required=True, help="issuer cert (PEM/DER)")
    parser.add_argument("--ocsp", help="override OCSP URL")
    parser.add_argument("--hash", default="sha1", choices=["sha1", "sha256"])
    parser.add_argument("--no-nonce", action="store_true")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--stapled", help="validate stapled DER response instead of querying")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    cfg = OcspClientConfig(
        request_hash_algorithm=args.hash,
        add_nonce=not args.no_nonce,
        timeout_sec=args.timeout,
        max_retries=args.retries,
    )
    client = OcspClient(cfg)

    cert = load_certificate(args.cert)
    issuer = load_certificate(args.issuer)

    if args.stapled:
        with open(args.stapled, "rb") as f:
            der = f.read()
        st = client.validate_stapled(der, cert, issuer)
    else:
        st = client.check(cert, issuer, [args.ocsp] if args.ocsp else None)

    print("status:", st.certificate_status)
    print("thisUpdate:", _iso(st.this_update), "nextUpdate:", _iso(st.next_update), "producedAt:", _iso(st.produced_at))
    print("responder:", st.responder)
    print("url:", st.url)

if __name__ == "__main__":
    _cli()
