# security-core/security/mtls/validator.py
from __future__ import annotations

import base64
import fnmatch
import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, padding
    from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

try:
    import httpx  # optional for OCSP/CRL fetching
    _HAVE_HTTPX = True
except Exception:  # pragma: no cover
    _HAVE_HTTPX = False

try:
    import certifi  # optional for trust store
    _HAVE_CERTIFI = True
except Exception:  # pragma: no cover
    _HAVE_CERTIFI = False

logger = logging.getLogger("security_core.mtls.validator")


# ============================= Конфиг и результаты =============================

class RevocationMode:
    NONE = "none"
    OCSP = "ocsp"
    CRL = "crl"
    BOTH = "both"

@dataclass
class MtlsValidatorConfig:
    trust_bundle_paths: Sequence[str] = field(default_factory=tuple)   # .pem/.crt/.cer (можно пусто => системный)
    clock_skew_seconds: int = 300
    allow_expired: bool = False
    require_eku_client_auth: bool = True
    require_keyusage_digital_signature: bool = False  # включайте при жёсткой политике
    min_rsa_bits: int = 2048
    allow_sha1: bool = False
    allowed_signature_hashes: Sequence[str] = field(default_factory=lambda: ("sha256", "sha384", "sha512"))
    allowed_curves: Sequence[str] = field(default_factory=lambda: ("secp256r1", "secp384r1", "secp521r1"))
    allowed_dns_patterns: Sequence[str] = field(default_factory=tuple)  # например: ["svc.internal.*", "*.corp.local"]
    allowed_spiffe_trust_domains: Sequence[str] = field(default_factory=tuple)  # напр.: ["example.org", "corp.local"]
    expected_dns: Optional[str] = None  # точное имя хоста, если требуется
    spki_pins_sha256_hex: Sequence[str] = field(default_factory=tuple)  # pinning лист SPKI SHA-256 в hex
    allowed_issuer_dn_regex: Optional[str] = None  # ограничение на DN издателя
    check_name_constraints: bool = True
    revocation_mode: str = RevocationMode.NONE
    revocation_soft_fail: bool = True
    ocsp_timeout_sec: float = 3.0
    crl_timeout_sec: float = 5.0
    ocsp_cache_ttl_sec: int = 300
    crl_cache_ttl_sec: int = 1800
    decision_cache_ttl_sec: int = 5
    decision_cache_max_entries: int = 10000

@dataclass
class PeerIdentity:
    subject: str
    issuer: str
    serial_hex: str
    not_before: int
    not_after: int
    dns_sans: List[str]
    uri_sans: List[str]
    spiffe_id: Optional[str]
    fingerprint_sha256: str
    spki_sha256_hex: str

@dataclass
class ValidationResult:
    ok: bool
    reason: str
    peer: Optional[PeerIdentity] = None
    chain_depth: int = 0
    used_revocation: str = RevocationMode.NONE
    ocsp_status: Optional[str] = None  # good/revoked/unknown
    crl_checked: bool = False


# ============================= Исключения =============================

class MtlsValidationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ============================= Вспомогательные утилиты =============================

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _algo_name(cert: x509.Certificate) -> str:
    try:
        return cert.signature_hash_algorithm.name.lower()  # type: ignore[attr-defined]
    except Exception:
        return "unknown"

def _public_key_info(cert: x509.Certificate) -> Tuple[str, int]:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return ("rsa", pk.key_size)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return ("ec", pk.curve.name.lower())
    if isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return ("okp", 0)
    if isinstance(pk, dsa.DSAPublicKey):
        return ("dsa", pk.key_size)
    return ("unknown", 0)

def _spki_sha256_hex(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return _sha256_hex(spki)

def _name_to_str(name: x509.Name) -> str:
    parts = []
    for rdn in name.rdns:
        for attr in rdn:
            parts.append(f"{attr.oid._name}={attr.value}")  # noqa: SLF001
    return ", ".join(parts)

def _x509_from_bytes(b: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(b)
    except Exception:
        return x509.load_der_x509_certificate(b)

def _try_load_many(pem_or_der: bytes) -> List[x509.Certificate]:
    """
    Разбирает один PEM с пачкой сертификатов или одиночный DER/PEM.
    """
    out: List[x509.Certificate] = []
    text = pem_or_der.decode("utf-8", errors="ignore")
    if "-----BEGIN CERTIFICATE-----" in text:
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
        for blk in blocks:
            out.append(x509.load_pem_x509_certificate(blk.encode()))
    else:
        out.append(_x509_from_bytes(pem_or_der))
    return out


# ============================= Trust store =============================

class TrustStore:
    def __init__(self, paths: Sequence[str]) -> None:
        self._roots_by_subject: Dict[str, List[x509.Certificate]] = {}
        self._roots_by_ski: Dict[bytes, x509.Certificate] = {}
        self._load(paths)

    def _load(self, paths: Sequence[str]) -> None:
        roots: List[x509.Certificate] = []
        if paths:
            for p in paths:
                if not os.path.exists(p):
                    logger.warning("trust bundle path not found: %s", p)
                    continue
                data = open(p, "rb").read()
                roots.extend(_try_load_many(data))
        else:
            # системный (через certifi, если есть)
            if _HAVE_CERTIFI:
                data = open(certifi.where(), "rb").read()
                roots.extend(_try_load_many(data))
            else:
                logger.warning("no trust bundle specified and certifi not available")

        for cert in roots:
            subj = cert.subject.rfc4514_string()
            self._roots_by_subject.setdefault(subj, []).append(cert)
            try:
                ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                self._roots_by_ski[ski] = cert
            except Exception:
                pass

    def find_issuer(self, child: x509.Certificate) -> Optional[x509.Certificate]:
        # Поиск по AKI/SKI
        try:
            aki = child.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
            if aki and aki in self._roots_by_ski:
                return self._roots_by_ski[aki]
        except Exception:
            pass
        # Фоллбек по DN
        issuer_dn = child.issuer.rfc4514_string()
        cands = self._roots_by_subject.get(issuer_dn, [])
        return cands[0] if cands else None

    def is_trusted(self, cert: x509.Certificate) -> bool:
        # Корень самоподписан и содержится в сторе
        subj = cert.subject.rfc4514_string()
        cands = self._roots_by_subject.get(subj, [])
        for c in cands:
            if c.public_bytes(serialization.Encoding.DER) == cert.public_bytes(serialization.Encoding.DER):
                return True
        return False


# ============================= Кеши =============================

class _TTLCache:
    def __init__(self, ttl_sec: int, max_entries: int = 10000) -> None:
        self.ttl = ttl_sec
        self.max = max_entries
        self._lock = threading.RLock()
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, k: str) -> Optional[Any]:
        with self._lock:
            it = self._store.get(k)
            if not it:
                return None
            ts, v = it
            if time.time() - ts > self.ttl:
                self._store.pop(k, None)
                return None
            return v

    def set(self, k: str, v: Any) -> None:
        with self._lock:
            if len(self._store) >= self.max:
                # простая эвикция самых старых 10%
                items = sorted(self._store.items(), key=lambda kv: kv[1][0])
                for kk, _ in items[: max(1, len(items) // 10)]:
                    self._store.pop(kk, None)
            self._store[k] = (time.time(), v)


# ============================= Основной валидатор =============================

class MtlsValidator:
    def __init__(self, config: Optional[MtlsValidatorConfig] = None) -> None:
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography is required for mTLS validation")
        self.cfg = config or MtlsValidatorConfig()
        self.trust = TrustStore(self.cfg.trust_bundle_paths)
        self._decision_cache = _TTLCache(self.cfg.decision_cache_ttl_sec, self.cfg.decision_cache_max_entries)
        self._ocsp_cache = _TTLCache(self.cfg.ocsp_cache_ttl_sec, 20000)
        self._crl_cache = _TTLCache(self.cfg.crl_cache_ttl_sec, 1000)

    # -------------------- Публичный API --------------------

    def validate(self, peer_chain: Sequence[bytes]) -> ValidationResult:
        """
        peer_chain: список сертификатов клиента (DER или PEM). Первый — leaf.
        """
        key = self._cache_key(peer_chain)
        cached = self._decision_cache.get(key)
        if cached:
            return cached

        try:
            leaf, chain = self._parse_chain(peer_chain)
            path = self._build_path(leaf, chain)
            self._verify_path(path)
            self._verify_leaf_policies(leaf)
            spiffe_id, dns_sans, uri_sans = self._validate_san_spiffe(leaf)
            self._verify_hostname_policy(dns_sans)
            self._verify_pin(leaf)
            ocsp_status, crl_checked = self._revocation_check(path)

            peer = self._peer_identity(leaf, path, spiffe_id, dns_sans, uri_sans)
            res = ValidationResult(
                ok=True,
                reason="ok",
                peer=peer,
                chain_depth=len(path),
                used_revocation=self.cfg.revocation_mode,
                ocsp_status=ocsp_status,
                crl_checked=crl_checked,
            )
            self._decision_cache.set(key, res)
            return res
        except MtlsValidationError as e:
            res = ValidationResult(ok=False, reason=e.reason)
            self._decision_cache.set(key, res)
            return res

    # -------------------- Внутренние шаги --------------------

    def _parse_chain(self, peer_chain: Sequence[bytes]) -> Tuple[x509.Certificate, List[x509.Certificate]]:
        if not peer_chain:
            raise MtlsValidationError("empty_chain")
        certs: List[x509.Certificate] = []
        for blob in peer_chain:
            certs.extend(_try_load_many(blob if isinstance(blob, (bytes, bytearray)) else bytes(blob)))
        leaf = certs[0]
        rest = certs[1:]
        return leaf, rest

    def _build_path(self, leaf: x509.Certificate, provided: List[x509.Certificate]) -> List[x509.Certificate]:
        """
        Строим путь leaf -> ... -> root (доверенный).
        """
        path: List[x509.Certificate] = [leaf]
        pool: List[x509.Certificate] = list(provided)

        # добавим кандидата из стора, если непосредственный издатель — доверенный
        issuer = self.trust.find_issuer(leaf)
        if issuer:
            pool.append(issuer)

        while True:
            cur = path[-1]
            if self.trust.is_trusted(cur) and self._is_self_signed(cur):
                # leaf сам доверенный корень (редко для mTLS)
                break

            parent = self._find_parent(cur, pool)
            if parent is None:
                # попробовать найти в trust store
                parent = self.trust.find_issuer(cur)

            if parent is None:
                # если текущий уже trusted self-signed — готово
                if self.trust.is_trusted(cur) and self._is_self_signed(cur):
                    break
                raise MtlsValidationError("issuer_not_found")

            path.append(parent)
            if self.trust.is_trusted(parent) and self._is_self_signed(parent):
                break
            # расширим пул следующими кандидатами по AKI/SKI
            pool = [c for c in pool if c != parent]

            # защита от слишком длинных цепочек
            if len(path) > 12:
                raise MtlsValidationError("path_too_long")

        return path

    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        return cert.issuer == cert.subject

    def _find_parent(self, child: x509.Certificate, pool: List[x509.Certificate]) -> Optional[x509.Certificate]:
        # поиск по AKI->SKI
        try:
            aki = child.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
        except Exception:
            aki = None

        candidates = []
        for c in pool:
            if c.subject != child.issuer:
                continue
            if aki:
                try:
                    ski = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                    if ski != aki:
                        continue
                except Exception:
                    continue
            candidates.append(c)
        # вернём первого подходящего
        return candidates[0] if candidates else None

    def _verify_path(self, path: List[x509.Certificate]) -> None:
        now = _now()
        skew = timedelta(seconds=self.cfg.clock_skew_seconds)

        for idx, cert in enumerate(path):
            # 1) Время
            if not self.cfg.allow_expired:
                if cert.not_valid_before.replace(tzinfo=timezone.utc) - skew > now:
                    raise MtlsValidationError("cert_not_yet_valid")
                if cert.not_valid_after.replace(tzinfo=timezone.utc) + skew < now:
                    raise MtlsValidationError("cert_expired")

            # 2) Подпись
            if idx + 1 < len(path):
                issuer = path[idx + 1]
            else:
                issuer = cert  # self-signed root
            self._verify_signature(cert, issuer)

            # 3) CA/KeyUsage для промежуточных
            if idx > 0:  # все кроме leaf
                try:
                    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                    if not bc.ca:
                        raise MtlsValidationError("intermediate_not_ca")
                except x509.ExtensionNotFound:
                    raise MtlsValidationError("basic_constraints_missing")

                try:
                    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                    if not ku.key_cert_sign:
                        raise MtlsValidationError("intermediate_no_key_cert_sign")
                except x509.ExtensionNotFound:
                    # допускаем отсутствие (некоторые старые корни), но предупреждаем
                    pass

            # 4) Ограничения на алгоритмы подписи
            algo = _algo_name(cert)
            if (algo == "sha1" and not self.cfg.allow_sha1) or (algo not in self.cfg.allowed_signature_hashes and algo != "sha1"):
                raise MtlsValidationError("disallowed_signature_hash")

        # 5) NameConstraints (минимальная проверка)
        if self.cfg.check_name_constraints and len(path) > 1:
            for cert in path[1:]:  # применяем ограничения из CA
                try:
                    nc = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS).value
                    self._apply_name_constraints(nc, path[0])
                except x509.ExtensionNotFound:
                    continue

    def _verify_signature(self, cert: x509.Certificate, issuer: x509.Certificate) -> None:
        pub = issuer.public_key()
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15() if cert.signature_algorithm_oid._name != "rsassaPss" else padding.PSS(  # noqa: SLF001
                        mgf=padding.MGF1(cert.signature_hash_algorithm),  # type: ignore[arg-type]
                        salt_length=cert.signature_hash_algorithm.digest_size,  # type: ignore[attr-defined]
                    ),
                    cert.signature_hash_algorithm,  # type: ignore[arg-type]
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))  # type: ignore[arg-type]
            elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                pub.verify(cert.signature, cert.tbs_certificate_bytes)
            else:
                raise MtlsValidationError("unsupported_public_key")
        except Exception:
            raise MtlsValidationError("bad_signature")

    def _apply_name_constraints(self, nc: x509.NameConstraints, leaf: x509.Certificate) -> None:
        # very basic: проверяем DNS и URI SAN против permitted/excluded
        try:
            san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            dns = [x.value.lower() for x in san.get_values_for_type(x509.DNSName)]
            uris = [x.value for x in san.get_values_for_type(x509.UniformResourceIdentifier)]
        except Exception:
            dns, uris = [], []

        def match_dns(name: str, subtree: x509.GeneralName) -> bool:
            if isinstance(subtree, x509.DNSName):
                pat = subtree.value.lower()
                # Поддержка ведущего точки для поддоменов
                if pat.startswith("."):
                    return name.endswith(pat)
                return fnmatch.fnmatchcase(name, pat)
            return False

        def match_uri(uri: str, subtree: x509.GeneralName) -> bool:
            if isinstance(subtree, x509.UniformResourceIdentifier):
                # минимальная проверка: префиксное совпадение
                return uri.startswith(subtree.value)
            return False

        if nc.permitted_subtrees is not None:
            if dns:
                if not any(any(match_dns(n, s) for s in nc.permitted_subtrees) for n in dns):
                    raise MtlsValidationError("name_constraints_permitted_violation_dns")
            if uris:
                if not any(any(match_uri(u, s) for s in nc.permitted_subtrees) for u in uris):
                    raise MtlsValidationError("name_constraints_permitted_violation_uri")

        if nc.excluded_subtrees is not None:
            for n in dns:
                if any(match_dns(n, s) for s in nc.excluded_subtrees):
                    raise MtlsValidationError("name_constraints_excluded_dns")
            for u in uris:
                if any(match_uri(u, s) for s in nc.excluded_subtrees):
                    raise MtlsValidationError("name_constraints_excluded_uri")

    def _verify_leaf_policies(self, leaf: x509.Certificate) -> None:
        # EKU ClientAuth
        if self.cfg.require_eku_client_auth:
            try:
                eku = leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                    raise MtlsValidationError("eku_client_auth_missing")
            except x509.ExtensionNotFound:
                raise MtlsValidationError("eku_missing")

        # KeyUsage.digitalSignature (опционально)
        if self.cfg.require_keyusage_digital_signature:
            try:
                ku = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if not ku.digital_signature:
                    raise MtlsValidationError("keyusage_digital_signature_missing")
            except x509.ExtensionNotFound:
                raise MtlsValidationError("keyusage_missing")

        # Алгоритм и длина ключа
        fam, info = _public_key_info(leaf)
        if fam == "rsa" and int(info) < self.cfg.min_rsa_bits:
            raise MtlsValidationError("rsa_too_short")
        if fam == "ec" and str(info) not in set(self.cfg.allowed_curves):
            raise MtlsValidationError("ec_curve_not_allowed")

        # Issuer DN ограничение
        if self.cfg.allowed_issuer_dn_regex:
            pat = re.compile(self.cfg.allowed_issuer_dn_regex)
            if not pat.search(leaf.issuer.rfc4514_string()):
                raise MtlsValidationError("issuer_dn_not_allowed")

    def _validate_san_spiffe(self, leaf: x509.Certificate) -> Tuple[Optional[str], List[str], List[str]]:
        dns_sans: List[str] = []
        uri_sans: List[str] = []
        spiffe_id: Optional[str] = None
        try:
            san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            dns_sans = [x.value.lower() for x in san.get_values_for_type(x509.DNSName)]
            uri_sans = [x.value for x in san.get_values_for_type(x509.UniformResourceIdentifier)]
        except x509.ExtensionNotFound:
            dns_sans, uri_sans = [], []

        # SPIFFE
        for u in uri_sans:
            if u.startswith("spiffe://"):
                spiffe_id = u
                break

        # Политика SPIFFE trust domains
        if self.cfg.allowed_spiffe_trust_domains and spiffe_id:
            # spiffe://<trust-domain>/<path>
            m = re.match(r"^spiffe://([^/]+)/.*$", spiffe_id)
            if not m or m.group(1) not in set(self.cfg.allowed_spiffe_trust_domains):
                raise MtlsValidationError("spiffe_trust_domain_not_allowed")

        # Политика на SAN DNS
        if self.cfg.allowed_dns_patterns:
            if not dns_sans:
                raise MtlsValidationError("dns_san_required")
            ok = any(any(fnmatch.fnmatchcase(d, p) for p in self.cfg.allowed_dns_patterns) for d in dns_sans)
            if not ok:
                raise MtlsValidationError("dns_san_not_allowed")

        return spiffe_id, dns_sans, uri_sans

    def _verify_hostname_policy(self, dns_sans: List[str]) -> None:
        if self.cfg.expected_dns:
            host = self.cfg.expected_dns.lower()
            if not any(fnmatch.fnmatchcase(host, pat) or fnmatch.fnmatchcase(d, host) or d == host for d in dns_sans for pat in [host]):
                raise MtlsValidationError("hostname_mismatch")

    def _verify_pin(self, leaf: x509.Certificate) -> None:
        if not self.cfg.spki_pins_sha256_hex:
            return
        spki_hex = _spki_sha256_hex(leaf)
        if spki_hex not in set(h.lower() for h in self.cfg.spki_pins_sha256_hex):
            raise MtlsValidationError("spki_pin_mismatch")

    # -------------------- Ревокация --------------------

    def _revocation_check(self, path: List[x509.Certificate]) -> Tuple[Optional[str], bool]:
        mode = self.cfg.revocation_mode
        if mode == RevocationMode.NONE:
            return None, False

        ocsp_status: Optional[str] = None
        crl_checked = False

        issuer = path[1] if len(path) > 1 else path[0]
        leaf = path[0]

        # OCSP
        if mode in (RevocationMode.OCSP, RevocationMode.BOTH):
            try:
                ocsp_status = self._ocsp_check(leaf, issuer)
            except MtlsValidationError as e:
                if self.cfg.revocation_soft_fail:
                    logger.warning("OCSP soft-fail: %s", e.reason)
                else:
                    raise

        # CRL
        if mode in (RevocationMode.CRL, RevocationMode.BOTH):
            try:
                crl_checked = self._crl_check(leaf, issuer)
            except MtlsValidationError as e:
                if self.cfg.revocation_soft_fail:
                    logger.warning("CRL soft-fail: %s", e.reason)
                else:
                    raise

        # Жёсткая реакция на revoked
        if ocsp_status == "revoked":
            raise MtlsValidationError("revoked_by_ocsp")

        return ocsp_status, crl_checked

    def _ocsp_check(self, leaf: x509.Certificate, issuer: x509.Certificate) -> str:
        if not _HAVE_HTTPX:
            raise MtlsValidationError("ocsp_http_unavailable")

        # URL из AIA
        try:
            aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            urls = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP]
        except Exception:
            urls = []
        if not urls:
            raise MtlsValidationError("ocsp_url_missing")
        url = urls[0]

        # Ключ кеша
        kid = f"{leaf.serial_number:x}:{_sha256_hex(issuer.public_bytes(serialization.Encoding.DER))}"
        cached = self._ocsp_cache.get(kid)
        if cached:
            return cached

        from cryptography.x509 import ocsp as _ocsp

        builder = _ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA256())
        req = builder.build()
        hdrs = {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}
        try:
            r = httpx.post(url, content=req.public_bytes(serialization.Encoding.DER), headers=hdrs, timeout=self.cfg.ocsp_timeout_sec)
        except Exception:
            raise MtlsValidationError("ocsp_network_error")
        if r.status_code != 200:
            raise MtlsValidationError("ocsp_http_error")

        try:
            resp = _ocsp.load_der_ocsp_response(r.content)
        except Exception:
            raise MtlsValidationError("ocsp_response_invalid")

        if resp.response_status.name != "SUCCESSFUL":
            raise MtlsValidationError("ocsp_unsuccessful")

        single = resp.responses[0]
        st = single.cert_status
        if st == _ocsp.OCSPCertStatus.REVOKED:
            status = "revoked"
        elif st == _ocsp.OCSPCertStatus.GOOD:
            status = "good"
        else:
            status = "unknown"

        self._ocsp_cache.set(kid, status)
        return status

    def _crl_check(self, leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
        if not _HAVE_HTTPX:
            raise MtlsValidationError("crl_http_unavailable")

        # URL из CDP
        try:
            cdp = leaf.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            urls: List[str] = []
            for dp in cdp:
                for gn in dp.full_name or []:
                    if isinstance(gn, x509.UniformResourceIdentifier):
                        urls.append(gn.value)
        except Exception:
            urls = []
        if not urls:
            raise MtlsValidationError("crl_url_missing")
        url = urls[0]

        kid = f"crl:{_sha256_hex(issuer.public_bytes(serialization.Encoding.DER))}:{url}"
        cached = self._crl_cache.get(kid)
        if cached:
            crl = cached
        else:
            try:
                r = httpx.get(url, timeout=self.cfg.crl_timeout_sec)
            except Exception:
                raise MtlsValidationError("crl_network_error")
            if r.status_code != 200:
                raise MtlsValidationError("crl_http_error")
            data = r.content
            try:
                try:
                    crl = x509.load_der_x509_crl(data)
                except Exception:
                    crl = x509.load_pem_x509_crl(data)
            except Exception:
                raise MtlsValidationError("crl_parse_error")
            self._crl_cache.set(kid, crl)

        # Проверка подписи CRL издателем
        try:
            issuer.public_key().verify(
                crl.signature, crl.tbs_certlist_bytes,
                padding.PKCS1v15() if isinstance(issuer.public_key(), rsa.RSAPublicKey) else ec.ECDSA(crl.signature_hash_algorithm),  # type: ignore[arg-type]
                crl.signature_hash_algorithm  # type: ignore[arg-type]
            )
        except Exception:
            raise MtlsValidationError("crl_bad_signature")

        # Поиск серийника в CRL
        for revoked in crl:
            if revoked.serial_number == leaf.serial_number:
                raise MtlsValidationError("revoked_by_crl")

        return True

    # -------------------- Формирование результата --------------------

    def _peer_identity(self, leaf: x509.Certificate, path: List[x509.Certificate], spiffe_id: Optional[str], dns_sans: List[str], uri_sans: List[str]) -> PeerIdentity:
        subject = _name_to_str(leaf.subject)
        issuer = _name_to_str(leaf.issuer)
        serial_hex = f"{leaf.serial_number:x}"
        not_before = int(leaf.not_valid_before.replace(tzinfo=timezone.utc).timestamp())
        not_after = int(leaf.not_valid_after.replace(tzinfo=timezone.utc).timestamp())
        fp = _sha256_hex(leaf.public_bytes(serialization.Encoding.DER))
        spki_hex = _spki_sha256_hex(leaf)
        return PeerIdentity(
            subject=subject,
            issuer=issuer,
            serial_hex=serial_hex,
            not_before=not_before,
            not_after=not_after,
            dns_sans=dns_sans,
            uri_sans=uri_sans,
            spiffe_id=spiffe_id,
            fingerprint_sha256=fp,
            spki_sha256_hex=spki_hex,
        )

    def _cache_key(self, chain: Sequence[bytes]) -> str:
        h = hashlib.sha256()
        for c in chain:
            h.update(c if isinstance(c, (bytes, bytearray)) else bytes(c))
        h.update(str(self.cfg.__dict__).encode())
        return h.hexdigest()


# ============================= Утилита высокого уровня =============================

def validate_peer_chain(
    chain_blobs: Sequence[bytes],
    config: Optional[MtlsValidatorConfig] = None,
) -> ValidationResult:
    """
    Упрощенный вызов:
        res = validate_peer_chain([leaf_pem, inter_pem, ...], config)
    """
    v = MtlsValidator(config)
    return v.validate(chain_blobs)
