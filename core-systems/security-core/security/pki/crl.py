# security-core/security/pki/crl.py
# Промышленный CRL-менеджер: PEM/DER, подпись, AKI/SKI, this/nextUpdate со сдвигом,
# delta-CRL (FreshestCRL), CRL DP fetch (HTTP/HTTPS) с ETag/If-Modified-Since,
# потокобезопасный in-memory + файловый кэш, Prometheus-метрики (опционально).

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# --- опциональные зависимости для сети и метрик ---
try:
    import httpx  # современный HTTP-клиент с тайм-аутами
except Exception:  # noqa: BLE001
    httpx = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram
except Exception:  # noqa: BLE001
    Counter = Histogram = None  # type: ignore

# --- криптография ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, CRLEntryExtensionOID


# =========================
# Исключения
# =========================

class CRLError(Exception):
    code: str = "CRL_ERROR"
    def __init__(self, msg: str, *, code: Optional[str] = None) -> None:
        super().__init__(msg)
        if code:
            self.code = code

class FetchError(CRLError):          code = "FETCH_ERROR"
class ValidationError(CRLError):     code = "VALIDATION_ERROR"
class NotConfigured(CRLError):       code = "NOT_CONFIGURED"
class StaleCRLError(CRLError):       code = "STALE_CRL"
class UnsupportedScheme(CRLError):   code = "UNSUPPORTED_SCHEME"


# =========================
# Метрики (опционально)
# =========================

if Counter and Histogram:
    _CRL_FETCHES = Counter("crl_fetch_total", "CRL fetches", ["scheme", "code"])
    _CRL_LAT = Histogram("crl_fetch_duration_seconds", "CRL fetch duration", ["scheme"])
    _CRL_VERIFIES = Counter("crl_verify_total", "CRL verify attempts", ["result"])
else:
    _CRL_FETCHES = _CRL_LAT = _CRL_VERIFIES = None  # type: ignore


# =========================
# Утилиты
# =========================

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


# =========================
# Модели
# =========================

@dataclass
class CRLSourceMeta:
    uri: Optional[str] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    fetched_at: datetime = field(default_factory=_now)

@dataclass
class LoadedCRL:
    crl: x509.CertificateRevocationList
    raw_der: bytes
    issuer_name: x509.Name
    aki: Optional[bytes]
    this_update: datetime
    next_update: Optional[datetime]
    is_delta: bool = False
    crl_number: Optional[int] = None
    delta_number: Optional[int] = None
    source: Optional[CRLSourceMeta] = None

    def expired(self, *, skew: timedelta) -> bool:
        if self.next_update is None:
            # редкий случай: без nextUpdate считаем «непросроченным», но доверяем только свежей загрузке
            return False
        return _now() > (self.next_update + skew)

@dataclass
class RevocationInfo:
    revoked: bool
    reason: Optional[str] = None
    revocation_date: Optional[datetime] = None
    invalidity_date: Optional[datetime] = None
    entry: Optional[x509.RevokedCertificate] = None
    source: Optional[str] = None  # base|delta


# =========================
# Настройки
# =========================

@dataclass
class CRLConfig:
    fetch_timeout: float = 7.5
    verify_tls: bool = True
    # Сдвиг времени (учёт рассинхронизации часов/задержек репликации)
    time_skew: timedelta = timedelta(minutes=5)
    # Директория файлового кэша (опционально)
    cache_dir: Optional[str] = None
    # TTL файлового кэша при отсутствии nextUpdate (напр., нестандартные CRL)
    cache_ttl_when_no_next_update: timedelta = timedelta(hours=12)
    # Включить Prometheus метрики (если prometheus_client установлен)
    metrics_enabled: bool = True
    # Пользовательский агент
    user_agent: str = "aethernova-security-core/CRL/1.0"


# =========================
# Дисковый кэш CRL
# =========================

class FileCRLCache:
    def __init__(self, cache_dir: str) -> None:
        self.dir = cache_dir
        os.makedirs(self.dir, exist_ok=True)
        self._lock = threading.RLock()

    def _paths(self, key: str) -> Tuple[str, str]:
        h = _sha256(key.encode("utf-8"))
        return os.path.join(self.dir, f"{h}.crl"), os.path.join(self.dir, f"{h}.json")

    def load(self, key: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        p_data, p_meta = self._paths(key)
        with self._lock:
            if not os.path.exists(p_data) or not os.path.exists(p_meta):
                return None
            try:
                with open(p_data, "rb") as f:
                    data = f.read()
                with open(p_meta, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                return data, meta
            except Exception:
                return None

    def save(self, key: str, data: bytes, meta: Mapping[str, Any]) -> None:
        p_data, p_meta = self._paths(key)
        tmp_data = p_data + ".tmp"
        tmp_meta = p_meta + ".tmp"
        with self._lock:
            with open(tmp_data, "wb") as f:
                f.write(data)
            with open(tmp_meta, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            os.replace(tmp_data, p_data)
            os.replace(tmp_meta, p_meta)


# =========================
# Основной менеджер CRL
# =========================

class CRLManager:
    """
    Менеджер CRL:
      - загрузка из сертификата (CRL DP) или по URI;
      - валидация (подпись, AKI↔SKI, сроки);
      - поддержка delta-CRL (FreshestCRL, объединение);
      - кэш в памяти и на диске;
      - потокобезопасность.
    """

    def __init__(self, cfg: Optional[CRLConfig] = None) -> None:
        self.cfg = cfg or CRLConfig()
        self._lock = threading.RLock()
        self._mem: Dict[str, LoadedCRL] = {}  # key -> LoadedCRL
        self._file_cache = FileCRLCache(self.cfg.cache_dir) if self.cfg.cache_dir else None

    # ---------- Публичное API ----------

    def prefetch_for_cert(self, cert: x509.Certificate) -> None:
        """
        Предварительная загрузка всех CRL из CRLDistributionPoints и FreshestCRL сертификата.
        Ошибки не выбрасываются (best-effort).
        """
        for uri in self._extract_crl_uris(cert, freshest=False) + self._extract_crl_uris(cert, freshest=True):
            try:
                self.fetch_and_store(uri)
            except Exception:
                # silent best-effort prefetch
                continue

    def check_certificate_revocation(
        self,
        *,
        certificate: x509.Certificate,
        issuer_certificate: x509.Certificate,
        at_time: Optional[datetime] = None,
    ) -> RevocationInfo:
        """
        Проверяет отзыв по всем доступным CRL‑точкам сертификата:
        - валидирует CRL подписью издателя;
        - учитывает base+delta CRL;
        - проверяет сроки this/nextUpdate с учётом time_skew;
        - возвращает структуру RevocationInfo.
        """
        at = at_time or _now()
        base_uris = self._extract_crl_uris(certificate, freshest=False)
        delta_uris = self._extract_crl_uris(certificate, freshest=True)

        if not base_uris and not delta_uris:
            raise NotConfigured("certificate has no CRL distribution points or freshest CRL")

        # Загрузим base CRL
        base_crls = [self.fetch_and_store(u) for u in base_uris] if base_uris else []
        # delta CRL
        delta_crls = [self.fetch_and_store(u) for u in delta_uris] if delta_uris else []

        # Отфильтруем и провалидируем подпись/AKI/issuer
        base_crls = [c for c in base_crls if self._validate_crl(c, issuer_certificate, at)]
        delta_crls = [c for c in delta_crls if self._validate_crl(c, issuer_certificate, at)]

        if not base_crls and not delta_crls:
            raise ValidationError("no valid CRL available after validation")

        # Соберём объединённую картину отзыва
        serial = certificate.serial_number
        # Начинаем с base: первый валидный (наиболее свежий по CRLNumber)
        base = self._select_most_recent(base_crls)
        base_entry = self._find_revoked(base.crl, serial)
        # Применим delta, если есть
        if delta_crls:
            delta = self._select_most_recent(delta_crls)
            merged = self._merge_delta(base, delta)
            entry = merged.get(serial)
            if entry is None:
                # возможно delta "сняла" отзыв (removeFromCRL)
                return RevocationInfo(revoked=False, source="delta")
            # иначе решаем по merged
            return RevocationInfo(
                revoked=True,
                reason=_extract_reason(entry),
                revocation_date=entry.revocation_date,
                invalidity_date=_extract_invalidity(entry),
                entry=entry,
                source="delta",
            )

        # Без delta — решение по base
        if base_entry is None:
            return RevocationInfo(revoked=False, source="base")
        return RevocationInfo(
            revoked=True,
            reason=_extract_reason(base_entry),
            revocation_date=base_entry.revocation_date,
            invalidity_date=_extract_invalidity(base_entry),
            entry=base_entry,
            source="base",
        )

    def fetch_and_store(self, uri: str) -> LoadedCRL:
        """
        Загружает CRL по URI (http/https/file), парсит и сохраняет в кэш.
        Возвращает LoadedCRL.
        """
        raw, meta = self._fetch(uri)
        loaded = self._parse_crl(raw, source=CRLSourceMeta(uri=uri, etag=meta.get("etag"), last_modified=meta.get("last_modified")))
        key = self._cache_key(uri)
        with self._lock:
            self._mem[key] = loaded
        # сохранить на диск
        if self._file_cache:
            self._file_cache.save(key, raw, meta)
        return loaded

    # ---------- Низкоуровневые операции ----------

    def _validate_crl(self, loaded: LoadedCRL, issuer_cert: x509.Certificate, at: datetime) -> bool:
        """
        Проверяет: соответствие issuer, AKI↔SKI, подпись CRL, актуальность this/nextUpdate.
        """
        try:
            # 1) issuer DN
            if loaded.issuer_name != issuer_cert.subject:
                # RFC 5280 допускает indirect CRL; в базовой реализации отвергаем
                return False

            # 2) AKI (CRL) ↔ SKI (issuer cert), если присутствуют
            try:
                crl_aki = loaded.aki
                ski = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest  # type: ignore[attr-defined]
                if crl_aki and ski and crl_aki != ski:
                    return False
            except x509.ExtensionNotFound:
                pass  # нет AKI/SKI — не считаем ошибкой

            # 3) подпись CRL
            self._verify_crl_signature(loaded.crl, issuer_cert.public_key())

            # 4) валидность по времени
            if loaded.this_update - self.cfg.time_skew > at:
                return False
            if loaded.next_update and at > loaded.next_update + self.cfg.time_skew:
                return False

            if _CRL_VERIFIES and self.cfg.metrics_enabled:
                _CRL_VERIFIES.labels(result="ok").inc()
            return True
        except Exception:
            if _CRL_VERIFIES and self.cfg.metrics_enabled:
                _CRL_VERIFIES.labels(result="fail").inc()
            return False

    @staticmethod
    def _find_revoked(crl: x509.CertificateRevocationList, serial: int) -> Optional[x509.RevokedCertificate]:
        try:
            # cryptography>=41 имеет get_revoked_certificate_by_serial_number
            return crl.get_revoked_certificate_by_serial_number(serial)  # type: ignore[attr-defined]
        except Exception:
            for rc in crl:
                if rc.serial_number == serial:
                    return rc
            return None

    def _merge_delta(self, base: LoadedCRL, delta: LoadedCRL) -> Dict[int, x509.RevokedCertificate]:
        """
        Возвращает словарь serial->RevokedCertificate после применения delta к base.
        Правила RFC 5280:
          - delta содержит новые/изменённые записи отзыва относительно base CRLNumber;
          - reason=removeFromCRL означает «удалить запись» (снять отзыв).
        """
        if not delta.is_delta:
            # delta может прийти без метки is_delta, если FreshestCRL указывает на обычный CRL — трактуем как base-only
            return {rc.serial_number: rc for rc in base.crl}

        base_map: Dict[int, x509.RevokedCertificate] = {rc.serial_number: rc for rc in base.crl}
        for rc in delta.crl:
            reason = _extract_reason(rc)
            if reason == "removeFromCRL":
                base_map.pop(rc.serial_number, None)
            else:
                base_map[rc.serial_number] = rc
        return base_map

    # ---------- загрузка/парсинг ----------

    def _fetch(self, uri: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Загружает данные CRL. Поддержка:
          - http/https с ETag/If-Modified-Since/timeout/tls-verify
          - file:// (локальный путь)
        Возвращает (raw_bytes, meta_dict). При 304 — возвращает данные из кэша.
        """
        scheme = uri.split(":", 1)[0].lower()
        key = self._cache_key(uri)

        # Попытка загрузить из файлового кэша
        if self._file_cache:
            cached = self._file_cache.load(key)
            cached_data, cached_meta = (cached or (None, {}))
        else:
            cached_data, cached_meta = (None, {})

        if scheme == "file":
            path = uri[7:] if uri.startswith("file://") else uri
            with open(path, "rb") as f:
                data = f.read()
            return data, {"etag": None, "last_modified": None, "fetched_at": _now().isoformat()}

        if scheme in ("http", "https"):
            if httpx is None:
                raise FetchError("httpx is not installed; HTTP(S) fetch unavailable")
            headers = {"User-Agent": self.cfg.user_agent}
            if cached_meta.get("etag"):
                headers["If-None-Match"] = cached_meta["etag"]
            if cached_meta.get("last_modified"):
                headers["If-Modified-Since"] = cached_meta["last_modified"]

            t0 = time.time()
            code = "OK"
            try:
                with httpx.Client(timeout=self.cfg.fetch_timeout, verify=self.cfg.verify_tls, headers=headers) as client:
                    r = client.get(uri)
                    if r.status_code == 304 and cached_data:
                        if _CRL_FETCHES and self.cfg.metrics_enabled:
                            _CRL_FETCHES.labels(scheme=scheme, code="304").inc()
                        return cached_data, cached_meta
                    if r.status_code != 200:
                        code = str(r.status_code)
                        raise FetchError(f"CRL fetch HTTP {r.status_code}")
                    data = r.content
                    meta = {
                        "etag": r.headers.get("ETag"),
                        "last_modified": r.headers.get("Last-Modified"),
                        "fetched_at": _now().isoformat(),
                        "content_type": r.headers.get("Content-Type"),
                        "content_length": _safe_int(r.headers.get("Content-Length")),
                    }
                    if _CRL_FETCHES and self.cfg.metrics_enabled:
                        _CRL_FETCHES.labels(scheme=scheme, code="200").inc()
                    return data, meta
            finally:
                if _CRL_LAT and self.cfg.metrics_enabled:
                    _CRL_LAT.labels(scheme=scheme).observe(time.time() - t0)

        raise UnsupportedScheme(f"unsupported CRL URI scheme: {scheme}")

    @staticmethod
    def _parse_crl(raw: bytes, *, source: Optional[CRLSourceMeta]) -> LoadedCRL:
        """
        Парсит CRL из PEM или DER. Определяет delta‑CRL, CRLNumber, AKI и т.д.
        """
        # Попробуем PEM
        try:
            crl = x509.load_pem_x509_crl(raw)
            raw_der = crl.public_bytes(serialization.Encoding.DER)
        except ValueError:
            # DER
            crl = x509.load_der_x509_crl(raw)
            raw_der = raw

        issuer = crl.issuer
        this_update = crl.last_update  # в cryptography это "last_update" (thisUpdate)
        next_update = crl.next_update

        # AKI
        aki_val: Optional[bytes] = None
        try:
            aki = crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value  # type: ignore[attr-defined]
            aki_val = aki.key_identifier
        except x509.ExtensionNotFound:
            aki_val = None

        # CRLNumber / DeltaCRLIndicator
        crl_number: Optional[int] = None
        delta_number: Optional[int] = None
        is_delta = False
        try:
            crln = crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER).value  # type: ignore[attr-defined]
            crl_number = _safe_int(crln.crl_number)
        except x509.ExtensionNotFound:
            pass
        try:
            dci = crl.extensions.get_extension_for_oid(ExtensionOID.DELTA_CRL_INDICATOR).value  # type: ignore[attr-defined]
            is_delta = True
            delta_number = _safe_int(dci.crl_number)
        except x509.ExtensionNotFound:
            pass

        return LoadedCRL(
            crl=crl,
            raw_der=raw_der,
            issuer_name=issuer,
            aki=aki_val,
            this_update=this_update,
            next_update=next_update,
            is_delta=is_delta,
            crl_number=crl_number,
            delta_number=delta_number,
            source=source,
        )

    # ---------- подпись CRL ----------

    @staticmethod
    def _verify_crl_signature(crl: x509.CertificateRevocationList, public_key) -> None:
        """
        Проверяет подпись CRL ключом издателя. Поддержка RSA/DSA/ECDSA/Ed25519/Ed448.
        """
        sig = crl.signature
        tbs = crl.tbs_certlist_bytes
        # hash для RSA/ECDSA/DSA
        hash_alg = crl.signature_hash_algorithm
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(sig, tbs, padding.PKCS1v15(), hash_alg)
            return
        if isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(sig, tbs, hash_alg)
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(sig, tbs, ec.ECDSA(hash_alg))
            return
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig, tbs)
            return
        if isinstance(public_key, ed448.Ed448PublicKey):
            public_key.verify(sig, tbs)
            return
        raise ValidationError("unsupported public key type for CRL verification")

    # ---------- вспомогательное ----------

    def _cache_key(self, uri: str) -> str:
        return f"uri:{uri}"

    @staticmethod
    def _select_most_recent(crls: List[LoadedCRL]) -> LoadedCRL:
        """
        Выбирает наиболее свежую CRL: по CRLNumber/DeltaCRLNumber, иначе по thisUpdate.
        """
        def key(c: LoadedCRL):
            num = c.delta_number if c.is_delta else c.crl_number
            return (0 if num is None else num, c.this_update)
        return sorted(crls, key=key, reverse=True)[0]

    @staticmethod
    def _extract_crl_uris(cert: x509.Certificate, *, freshest: bool) -> List[str]:
        """
        Извлекает URI из CRLDistributionPoints (freshest=False) или FreshestCRL (freshest=True).
        """
        uris: List[str] = []
        oid = ExtensionOID.FRESHEST_CRL if freshest else ExtensionOID.CRL_DISTRIBUTION_POINTS
        try:
            ext = cert.extensions.get_extension_for_oid(oid).value  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            return uris

        dps = ext  # CRLDistributionPoints или FreshestCRL: одинаковая структура списков DistributionPoint
        for dp in getattr(dps, "distribution_points", dps):
            full = getattr(dp, "full_name", None)
            if not full:
                continue
            for gn in full:
                if isinstance(gn, x509.UniformResourceIdentifier):
                    uri = gn.value.strip()
                    if uri.lower().startswith(("http://", "https://", "file://")):
                        uris.append(uri)
        return uris


# =========================
# Вспомогательные функции для RevokedCertificate
# =========================

def _extract_reason(rc: x509.RevokedCertificate) -> Optional[str]:
    try:
        reason = rc.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON).value  # type: ignore[attr-defined]
        # enum->строка
        return getattr(reason, "name", str(reason))
    except x509.ExtensionNotFound:
        return None

def _extract_invalidity(rc: x509.RevokedCertificate) -> Optional[datetime]:
    try:
        inv = rc.extensions.get_extension_for_oid(CRLEntryExtensionOID.INVALIDITY_DATE).value  # type: ignore[attr-defined]
        return inv
    except x509.ExtensionNotFound:
        return None


# =========================
# Пример использования (докстринг)
# =========================
"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Загрузка сертификатов
with open("end-entity.pem","rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
with open("issuer.pem","rb") as f:
    issuer = x509.load_pem_x509_certificate(f.read())

mgr = CRLManager(CRLConfig(cache_dir="/var/cache/security-core/crl"))

# Предзагрузка CRL (необязательно)
mgr.prefetch_for_cert(cert)

# Проверка отзыва
info = mgr.check_certificate_revocation(certificate=cert, issuer_certificate=issuer)
print(info.revoked, info.reason, info.revocation_date)
"""
