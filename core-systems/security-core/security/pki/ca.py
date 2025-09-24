# security-core/security/pki/ca.py
from __future__ import annotations

import asyncio
import base64
import os
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption,
    PublicFormat,
)
from cryptography.x509.oid import (
    NameOID, ExtensionOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID,
    ObjectIdentifier
)

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------
logger = logging.getLogger("security_core.pki.ca")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Типы и политики
# -----------------------------------------------------------------------------

class KeyAlg(str, Enum):
    RSA = "RSA"
    ECDSA = "ECDSA"
    ED25519 = "ED25519"  # допускается, но совместимость клиентов проверяйте

class HashAlg(str, Enum):
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"

_HASHES = {
    HashAlg.SHA256: hashes.SHA256(),
    HashAlg.SHA384: hashes.SHA384(),
    HashAlg.SHA512: hashes.SHA512(),
}

EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

class CRLReason(str, Enum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    CERTIFICATE_HOLD = "certificate_hold"
    REMOVE_FROM_CRL = "remove_from_crl"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    AA_COMPROMISE = "aa_compromise"

_REASON_MAP = {
    CRLReason.UNSPECIFIED: x509.ReasonFlags.unspecified,
    CRLReason.KEY_COMPROMISE: x509.ReasonFlags.key_compromise,
    CRLReason.CA_COMPROMISE: x509.ReasonFlags.ca_compromise,
    CRLReason.AFFILIATION_CHANGED: x509.ReasonFlags.affiliation_changed,
    CRLReason.SUPERSEDED: x509.ReasonFlags.superseded,
    CRLReason.CESSATION_OF_OPERATION: x509.ReasonFlags.cessation_of_operation,
    CRLReason.CERTIFICATE_HOLD: x509.ReasonFlags.certificate_hold,
    CRLReason.REMOVE_FROM_CRL: x509.ReasonFlags.remove_from_crl,
    CRLReason.PRIVILEGE_WITHDRAWN: x509.ReasonFlags.privilege_withdrawn,
    CRLReason.AA_COMPROMISE: x509.ReasonFlags.aa_compromise,
}

@dataclass
class CaUrls:
    aia_ca_issuers: List[str]  # http(s)://.../issuer.cer
    aia_ocsp: List[str]        # http(s)://.../ocsp
    crl_distribution_points: List[str]  # http(s)://.../ca.crl

@dataclass
class CaPolicy:
    # Разрешенные алгоритмы/кривые/размеры
    allowed_algs: List[KeyAlg] = (KeyAlg.ECDSA, KeyAlg.RSA, KeyAlg.ED25519)
    min_rsa_bits: int = 3072
    allowed_curves: List[str] = ("P-256", "P-384", "P-521")
    # Сроки
    max_leaf_days: int = 397               # лимит для TLS по современным политикам
    max_intermediate_days: int = 1825      # до 5 лет для внутренних PKI
    max_root_days: int = 3650              # до 10 лет при необходимости
    # Хэши
    default_hash: HashAlg = HashAlg.SHA384
    # Флаги
    require_san_dns_for_tls: bool = True
    enforce_basic_constraints: bool = True
    # Политики/профили
    policy_oids: List[str] = ()            # напр. ["2.23.140.1.2.2"] — CABF TLS BR
    # NameConstraints (для промежуточных)
    name_constraints_permitted_dns: List[str] = ()
    name_constraints_excluded_dns: List[str] = ()

@dataclass
class Subject:
    C: Optional[str] = None
    ST: Optional[str] = None
    L: Optional[str] = None
    O: Optional[str] = None
    OU: Optional[str] = None
    CN: Optional[str] = None
    email: Optional[str] = None

    def to_x509(self) -> x509.Name:
        attrs = []
        if self.C: attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.C))
        if self.ST: attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.ST))
        if self.L: attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.L))
        if self.O: attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.O))
        if self.OU: attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.OU))
        if self.CN: attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, self.CN))
        if self.email: attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email))
        return x509.Name(attrs)

@dataclass
class KeySpec:
    alg: KeyAlg
    rsa_bits: int = 3072
    ec_curve: str = "P-384"

@dataclass
class ExtensionsProfile:
    # Basic/EKU/KU
    is_ca: bool
    path_len: Optional[int]
    key_usage: List[str]  # digital_signature, key_encipherment, key_cert_sign, crl_sign, ...
    ext_key_usage: List[str]  # server_auth, client_auth, ocsp_signing, code_signing, email_protection, any
    # SAN
    san_dns: List[str] = ()
    san_ip: List[str] = ()
    san_uri: List[str] = ()
    # Policies/AIA/CRL
    policy_oids: List[str] = ()
    aia: Optional[CaUrls] = None
    # Name Constraints (для CA)
    nc_permitted_dns: List[str] = ()
    nc_excluded_dns: List[str] = ()
    # Дополнительные опции
    add_ski: bool = True
    add_aki: bool = True

@dataclass
class CertTemplate:
    subject: Subject
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    validity_days: Optional[int] = None
    serial: Optional[int] = None
    profile: Optional[ExtensionsProfile] = None

# -----------------------------------------------------------------------------
# Хранилища и сервисы (in-memory реализации)
# -----------------------------------------------------------------------------

class SerialManager:
    """Устойчивые серийные номера: случайные 128 бит, гарантированно > 0."""
    def __init__(self):
        self._used: set[int] = set()

    def new_serial(self) -> int:
        while True:
            # 16 байт = 128 бит; сбрасываем знак (ASN.1 положительное целое)
            n = int.from_bytes(os.urandom(16), "big")
            n |= 1  # исключить ноль
            if n not in self._used:
                self._used.add(n)
                return n

class IssuedIndexEntry:
    def __init__(self, cert: x509.Certificate, revoked: bool = False,
                 revocation_date: Optional[datetime] = None,
                 reason: Optional[CRLReason] = None):
        self.cert = cert
        self.revoked = revoked
        self.revocation_date = revocation_date
        self.reason = reason

class InMemoryIndex:
    def __init__(self):
        self._by_serial: Dict[int, IssuedIndexEntry] = {}
        self._crl_number: int = 0

    def add(self, cert: x509.Certificate):
        self._by_serial[cert.serial_number] = IssuedIndexEntry(cert)

    def get(self, serial: int) -> Optional[IssuedIndexEntry]:
        return self._by_serial.get(serial)

    def revoke(self, serial: int, reason: CRLReason, when: Optional[datetime] = None) -> bool:
        e = self._by_serial.get(serial)
        if not e or e.revoked:
            return False
        e.revoked = True
        e.revocation_date = when or datetime.now(timezone.utc)
        e.reason = reason
        return True

    def revoked_list(self) -> List[IssuedIndexEntry]:
        return [e for e in self._by_serial.values() if e.revoked]

    def next_crl_number(self) -> int:
        self._crl_number += 1
        return self._crl_number

# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------

def _ski_from_pub(pubkey) -> x509.SubjectKeyIdentifier:
    spki = pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    h = hashes.Hash(hashes.SHA1())  # SKI традиционно SHA-1 от SPKI (совместимость)
    h.update(spki)
    return x509.SubjectKeyIdentifier(h.finalize())

def _aki_from_issuer(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    try:
        ski = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        return x509.AuthorityKeyIdentifier(key_identifier=ski.digest, authority_cert_issuer=None, authority_cert_serial_number=None)
    except x509.ExtensionNotFound:
        # если у CA нет SKI — построим из его открытого ключа
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())

def _ku_from_list(usages: Iterable[str]) -> x509.KeyUsage:
    u = set(map(str.lower, usages))
    return x509.KeyUsage(
        digital_signature="digital_signature" in u,
        content_commitment="content_commitment" in u or "non_repudiation" in u,
        key_encipherment="key_encipherment" in u,
        data_encipherment="data_encipherment" in u,
        key_agreement="key_agreement" in u,
        key_cert_sign="key_cert_sign" in u,
        crl_sign="crl_sign" in u,
        encipher_only="encipher_only" in u,
        decipher_only="decipher_only" in u,
    )

def _eku_from_list(usages: Iterable[str]) -> x509.ExtendedKeyUsage:
    m = {
        "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
        "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
        "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
        "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
        "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
        "any": ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
    }
    oids = [m[u] for u in map(str.lower, usages) if u in m]
    return x509.ExtendedKeyUsage(oids)

def _policies_from_oids(oids: Iterable[str]) -> x509.CertificatePolicies:
    ids = [x509.PolicyInformation(ObjectIdentifier(oid), None) for oid in oids]
    return x509.CertificatePolicies(ids)

def _san_from_profile(p: ExtensionsProfile) -> Optional[x509.SubjectAlternativeName]:
    names: List[x509.GeneralName] = []
    names += [x509.DNSName(d) for d in p.san_dns]
    import ipaddress
    names += [x509.IPAddress(ipaddress.ip_address(i)) for i in p.san_ip]
    names += [x509.UniformResourceIdentifier(u) for u in p.san_uri]
    return x509.SubjectAlternativeName(names) if names else None

def _aia_from_urls(urls: CaUrls) -> x509.AuthorityInformationAccess:
    desc: List[x509.AccessDescription] = []
    for u in urls.aia_ca_issuers:
        desc.append(x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(u)))
    for u in urls.aia_ocsp:
        desc.append(x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(u)))
    return x509.AuthorityInformationAccess(desc)

def _crldp_from_urls(urls: CaUrls) -> x509.CRLDistributionPoints:
    dps = [
        x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(u)], relative_name=None,
                               reasons=None, crl_issuer=None)
        for u in urls.crl_distribution_points
    ]
    return x509.CRLDistributionPoints(dps)

def _name_constraints(permitted_dns: Iterable[str], excluded_dns: Iterable[str]) -> x509.NameConstraints:
    permitted = [x509.DNSName(d) for d in permitted_dns] if permitted_dns else None
    excluded = [x509.DNSName(d) for d in excluded_dns] if excluded_dns else None
    return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded)

def _default_validity(now: datetime, days: int) -> Tuple[datetime, datetime]:
    nb = now - timedelta(minutes=5)  # небольшой сдвиг на рассинхронизацию часов
    na = nb + timedelta(days=days)
    return nb, na

# -----------------------------------------------------------------------------
# Класс CA
# -----------------------------------------------------------------------------

class CertificateAuthority:
    """
    Промышленный CA с выпуском сертификатов/CRL и базовым OCSP.
    ВНИМАНИЕ: для HSM/KMS потребуется адаптация подписи (builder.sign требует объект ключа).
    """

    def __init__(self,
                 key_alg: KeyAlg,
                 private_key,
                 subject: Subject,
                 policy: Optional[CaPolicy] = None,
                 urls: Optional[CaUrls] = None,
                 is_root: bool = False,
                 issuer_cert: Optional[x509.Certificate] = None):
        self.policy = policy or CaPolicy()
        self.urls = urls
        self.is_root = is_root
        self._priv = private_key
        self._pub = private_key.public_key()
        self.subject = subject
        self.issuer_cert = issuer_cert  # для промежуточного CA хранится цепочка выше лежащая
        self.serials = SerialManager()
        self.index = InMemoryIndex()
        self.lock = asyncio.Lock()

        if isinstance(private_key, rsa.RSAPrivateKey) and self.policy.min_rsa_bits and private_key.key_size < self.policy.min_rsa_bits:
            raise ValueError("RSA key too small for policy")

    # ------------------------- Генерация ключа и self-signed -------------------

    @staticmethod
    def generate_root(subject: Subject,
                      key_spec: KeySpec = KeySpec(KeyAlg.ECDSA, ec_curve="P-384"),
                      policy: Optional[CaPolicy] = None,
                      urls: Optional[CaUrls] = None,
                      validity_days: Optional[int] = None,
                      hash_alg: HashAlg = HashAlg.SHA384) -> "CertificateAuthority":
        """Создать Root CA и самоподписанный сертификат."""
        if key_spec.alg == KeyAlg.RSA:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=key_spec.rsa_bits)
        elif key_spec.alg == KeyAlg.ECDSA:
            priv = ec.generate_private_key(EC_CURVES[key_spec.ec_curve])
        elif key_spec.alg == KeyAlg.ED25519:
            priv = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("Unsupported key algorithm")

        ca = CertificateAuthority(key_spec.alg, priv, subject, policy=policy, urls=urls, is_root=True)

        # Сборка сертификата
        now = datetime.now(timezone.utc)
        days = validity_days or (policy.max_root_days if policy else 3650)
        nb, na = _default_validity(now, days)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject.to_x509())
            .issuer_name(subject.to_x509())
            .public_key(priv.public_key())
            .serial_number(ca.serials.new_serial())
            .not_valid_before(nb)
            .not_valid_after(na)
        )
        # Extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            _ski_from_pub(priv.public_key()), critical=False
        ).add_extension(
            _ku_from_list(["key_cert_sign", "crl_sign"]), critical=True
        )
        if urls:
            builder = builder.add_extension(_crldp_from_urls(urls), critical=False)
        if policy and policy.policy_oids:
            builder = builder.add_extension(_policies_from_oids(policy.policy_oids), critical=False)

        # Подпись
        cert = _sign_with_key(builder, priv, hash_alg)
        ca.index.add(cert)
        ca.issuer_cert = cert  # self
        logger.info("root.ca.created subject=%s serial=%s", subject.CN, hex(cert.serial_number))
        return ca

    def issue_intermediate(self,
                           subject: Subject,
                           key_spec: KeySpec = KeySpec(KeyAlg.ECDSA, ec_curve="P-384"),
                           validity_days: Optional[int] = None,
                           path_len: Optional[int] = 0,
                           hash_alg: HashAlg = HashAlg.SHA384) -> Tuple[x509.Certificate, Any]:
        """Выпуск Intermediate CA: генерит ключ и сертификат, возвращает (cert, private_key)."""
        if not self.is_root:
            # Разрешено и промежуточному CA — выпуск следующего уровня
            pass

        if key_spec.alg == KeyAlg.RSA:
            if key_spec.rsa_bits < self.policy.min_rsa_bits:
                raise ValueError("RSA bits below policy")
            priv = rsa.generate_private_key(public_exponent=65537, key_size=key_spec.rsa_bits)
        elif key_spec.alg == KeyAlg.ECDSA:
            if key_spec.ec_curve not in self.policy.allowed_curves:
                raise ValueError("Curve not allowed by policy")
            priv = ec.generate_private_key(EC_CURVES[key_spec.ec_curve])
        elif key_spec.alg == KeyAlg.ED25519:
            priv = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("Unsupported key algorithm")

        now = datetime.now(timezone.utc)
        days = validity_days or self.policy.max_intermediate_days
        nb, na = _default_validity(now, days)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject.to_x509())
            .issuer_name(self.issuer_cert.subject if self.issuer_cert else subject.to_x509())
            .public_key(priv.public_key())
            .serial_number(self.serials.new_serial())
            .not_valid_before(nb)
            .not_valid_after(na)
        )
        # Extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True
        ).add_extension(
            _ski_from_pub(priv.public_key()), critical=False
        ).add_extension(
            _aki_from_issuer(self.issuer_cert), critical=False
        ).add_extension(
            _ku_from_list(["key_cert_sign", "crl_sign"]), critical=True
        )
        if self.policy.name_constraints_permitted_dns or self.policy.name_constraints_excluded_dns:
            builder = builder.add_extension(
                _name_constraints(self.policy.name_constraints_permitted_dns, self.policy.name_constraints_excluded_dns),
                critical=True
            )
        if self.urls:
            builder = builder.add_extension(_crldp_from_urls(self.urls), critical=False).add_extension(
                _aia_from_urls(self.urls), critical=False
            )
        if self.policy.policy_oids:
            builder = builder.add_extension(_policies_from_oids(self.policy.policy_oids), critical=False)

        cert = _sign_with_key(builder, self._priv, hash_alg)
        logger.info("intermediate.issued subject=%s serial=%s", subject.CN, hex(cert.serial_number))
        return cert, priv

    # ------------------------- Выпуск из CSR -----------------------------------

    def sign_csr(self,
                 csr_pem: Union[str, bytes],
                 template: CertTemplate,
                 hash_alg: HashAlg = HashAlg.SHA384) -> x509.Certificate:
        """
        Выпустить сертификат конечного субъекта (или сервисный) по CSR с учетом template/profile.
        """
        csr = x509.load_pem_x509_csr(csr_pem.encode() if isinstance(csr_pem, str) else csr_pem)

        # Проверка и политика
        self._validate_csr_against_policy(csr, template)

        now = datetime.now(timezone.utc)
        if template.not_before and template.not_after:
            nb, na = template.not_before, template.not_after
        else:
            days = template.validity_days or self.policy.max_leaf_days
            nb, na = _default_validity(now, days)

        serial = template.serial or self.serials.new_serial()

        builder = (
            x509.CertificateBuilder()
            .subject_name(template.subject.to_x509())
            .issuer_name(self.issuer_cert.subject if self.issuer_cert else template.subject.to_x509())
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(nb)
            .not_valid_after(na)
        )

        prof = template.profile or ExtensionsProfile(
            is_ca=False, path_len=None,
            key_usage=["digital_signature", "key_encipherment"],
            ext_key_usage=["server_auth", "client_auth"],
            san_dns=[],
        )

        # Basic constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=prof.is_ca, path_length=prof.path_len), critical=True
        )

        # SKI / AKI
        if prof.add_ski:
            builder = builder.add_extension(_ski_from_pub(csr.public_key()), critical=False)
        if prof.add_aki and self.issuer_cert is not None:
            builder = builder.add_extension(_aki_from_issuer(self.issuer_cert), critical=False)

        # KU / EKU
        builder = builder.add_extension(_ku_from_list(prof.key_usage), critical=True)
        if prof.ext_key_usage:
            builder = builder.add_extension(_eku_from_list(prof.ext_key_usage), critical=False)

        # SAN
        san = _san_from_profile(prof)
        if san:
            builder = builder.add_extension(san, critical=False)
        elif self.policy.require_san_dns_for_tls and "server_auth" in [e.lower() for e in prof.ext_key_usage]:
            raise ValueError("SAN is required by policy for TLS server_auth")

        # Policies
        if prof.policy_oids or self.policy.policy_oids:
            oids = prof.policy_oids or self.policy.policy_oids
            builder = builder.add_extension(_policies_from_oids(oids), critical=False)

        # AIA/CRLDP
        if self.urls:
            builder = builder.add_extension(_aia_from_urls(self.urls), critical=False)
            builder = builder.add_extension(_crldp_from_urls(self.urls), critical=False)

        # NameConstraints (если CA выдает под ограничения)
        if prof.is_ca and (prof.nc_permitted_dns or prof.nc_excluded_dns):
            builder = builder.add_extension(
                _name_constraints(prof.nc_permitted_dns, prof.nc_excluded_dns),
                critical=True
            )

        cert = _sign_with_key(builder, self._priv, hash_alg)
        self.index.add(cert)
        logger.info("leaf.issued cn=%s serial=%s not_after=%s", template.subject.CN, hex(serial), cert.not_valid_after.isoformat())
        return cert

    def _validate_csr_against_policy(self, csr: x509.CertificateSigningRequest, template: CertTemplate) -> None:
        pub = csr.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            if KeyAlg.RSA not in self.policy.allowed_algs:
                raise ValueError("RSA not allowed by policy")
            if pub.key_size < self.policy.min_rsa_bits:
                raise ValueError("RSA key too small")
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if KeyAlg.ECDSA not in self.policy.allowed_algs:
                raise ValueError("ECDSA not allowed by policy")
            name = getattr(pub.curve, "name", "")
            if name not in self.policy.allowed_curves:
                raise ValueError("EC curve not allowed")
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            if KeyAlg.ED25519 not in self.policy.allowed_algs:
                raise ValueError("Ed25519 not allowed by policy")
        else:
            raise ValueError("Unsupported public key type")

        # Проверка подписи CSR
        try:
            csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, csr.signature_hash_algorithm)
        except Exception as e:
            raise ValueError(f"CSR signature invalid: {e}")

    # ------------------------- CRL/отзыв ---------------------------------------

    def revoke(self, serial: int, reason: CRLReason = CRLReason.UNSPECIFIED,
               when: Optional[datetime] = None) -> bool:
        return self.index.revoke(serial, reason, when)

    def issue_crl(self, days_valid: int = 7, hash_alg: HashAlg = HashAlg.SHA384) -> x509.CertificateRevocationList:
        now = datetime.now(timezone.utc)
        last_update = now
        next_update = now + timedelta(days=days_valid)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            self.issuer_cert.subject if self.issuer_cert else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unknown CA")])
        ).last_update(last_update).next_update(next_update)

        crl_number = self.index.next_crl_number()
        revoked_entries = self.index.revoked_list()
        for e in revoked_entries:
            re = x509.RevokedCertificateBuilder().serial_number(
                e.cert.serial_number
            ).revocation_date(
                e.revocation_date or now
            ).add_extension(
                x509.CRLReason(_REASON_MAP[e.reason or CRLReason.UNSPECIFIED]), critical=False
            ).build()
            builder = builder.add_revoked_certificate(re)

        builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)
        if self.urls:
            # Иные CRL расширения могут добавляться здесь
            pass

        crl = _sign_crl_with_key(builder, self._priv, hash_alg)
        logger.info("crl.issued number=%s revoked=%d next_update=%s", crl_number, len(revoked_entries), next_update.isoformat())
        return crl

    # ------------------------- OCSP (базовый) ----------------------------------

    def ocsp_response(self,
                      cert: x509.Certificate,
                      issuer_cert: Optional[x509.Certificate] = None,
                      status: str = "good",
                      revocation_time: Optional[datetime] = None,
                      this_update: Optional[datetime] = None,
                      next_update: Optional[datetime] = None,
                      hash_alg: HashAlg = HashAlg.SHA256) -> x509.ocsp.OCSPResponse:
        """
        Сформировать подписанный OCSP ответ (GOOD/REVOKED/UNKNOWN).
        """
        issuer = issuer_cert or self.issuer_cert
        if issuer is None:
            raise ValueError("Issuer certificate is required for OCSP")

        from cryptography.x509 import ocsp
        h = _HASHES[hash_alg]
        b = ocsp.OCSPResponseBuilder()
        chi = ocsp.OCSPCertID(h, cert, issuer)
        this_update = this_update or datetime.now(timezone.utc)
        next_update = next_update or (this_update + timedelta(minutes=10))

        if status.lower() == "good":
            b = b.add_response(chi, ocsp.OCSPCertStatus.GOOD, this_update, next_update, None)
        elif status.lower() == "revoked":
            revocation_time = revocation_time or datetime.now(timezone.utc)
            b = b.add_response(chi, ocsp.OCSPCertStatus.REVOKED, this_update, next_update,
                               x509.ReasonFlags.unspecified, revocation_time)
        else:
            b = b.add_response(chi, ocsp.OCSPCertStatus.UNKNOWN, this_update, next_update, None)

        b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, self.issuer_cert.subject if self.issuer_cert else cert.subject)

        # EKU OCSP Signing желательно присутствует в сертификате ответчика
        alg = _HASHES[hash_alg]
        ocsp_resp = b.sign(private_key=self._priv, algorithm=alg, responder_cert=self.issuer_cert, certs=[self.issuer_cert])
        return ocsp_resp

    # ------------------------- Сериализация ключей/сертов ----------------------

    def certificate_pem(self) -> str:
        return self.issuer_cert.public_bytes(Encoding.PEM).decode()

    def private_key_pem(self, password: Optional[bytes] = None) -> str:
        enc = NoEncryption() if not password else BestAvailableEncryption(password)
        return self._priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc).decode()

# -----------------------------------------------------------------------------
# Подпись билдеров
# -----------------------------------------------------------------------------

def _sign_with_key(builder: x509.CertificateBuilder, private_key, hash_alg: HashAlg) -> x509.Certificate:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key=private_key, algorithm=None)  # EdDSA без хэша
    return builder.sign(private_key=private_key, algorithm=_HASHES[hash_alg])

def _sign_crl_with_key(builder: x509.CertificateRevocationListBuilder, private_key, hash_alg: HashAlg):
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key=private_key, algorithm=None)
    return builder.sign(private_key=private_key, algorithm=_HASHES[hash_alg])

# -----------------------------------------------------------------------------
# Асинхронные обертки (для удобной интеграции)
# -----------------------------------------------------------------------------

class AsyncCA:
    """Асинхронная обертка поверх CertificateAuthority (выполнение в thread pool)."""

    def __init__(self, ca: CertificateAuthority):
        self._ca = ca

    async def sign_csr(self, csr_pem: Union[str, bytes], template: CertTemplate, hash_alg: HashAlg = HashAlg.SHA384) -> x509.Certificate:
        return await asyncio.to_thread(self._ca.sign_csr, csr_pem, template, hash_alg)

    async def issue_crl(self, days_valid: int = 7, hash_alg: HashAlg = HashAlg.SHA384) -> x509.CertificateRevocationList:
        return await asyncio.to_thread(self._ca.issue_crl, days_valid, hash_alg)

    async def revoke(self, serial: int, reason: CRLReason = CRLReason.UNSPECIFIED, when: Optional[datetime] = None) -> bool:
        return await asyncio.to_thread(self._ca.revoke, serial, reason, when)

# -----------------------------------------------------------------------------
# Пример использования (не выполняется при импорте)
# -----------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    # 1) Root CA
    root = CertificateAuthority.generate_root(
        subject=Subject(C="SE", O="YourOrg", CN="YourOrg Root CA"),
        key_spec=KeySpec(KeyAlg.ECDSA, ec_curve="P-384"),
        policy=CaPolicy(),
        urls=CaUrls(
            aia_ca_issuers=["http://pki.yourorg/ca/root.cer"],
            aia_ocsp=["http://pki.yourorg/ocsp"],
            crl_distribution_points=["http://pki.yourorg/crl/root.crl"],
        ),
        validity_days=3650,
        hash_alg=HashAlg.SHA384,
    )
    print(root.certificate_pem())

    # 2) Intermediate
    inter_subject = Subject(C="SE", O="YourOrg", OU="Security", CN="YourOrg Issuing CA 1")
    inter_cert, inter_key = root.issue_intermediate(inter_subject, key_spec=KeySpec(KeyAlg.ECDSA, ec_curve="P-384"))
    print(inter_cert.public_bytes(Encoding.PEM).decode())

    # 3) CSR выпуск
    # Создадим ключ/CSR под leaf
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.yourorg.com")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.yourorg.com")]), critical=False)
        .sign(leaf_key, hashes.SHA256())
    )
    tmpl = CertTemplate(
        subject=Subject(CN="api.yourorg.com", O="YourOrg"),
        validity_days=365,
        profile=ExtensionsProfile(
            is_ca=False, path_len=None,
            key_usage=["digital_signature", "key_encipherment"],
            ext_key_usage=["server_auth"],
            san_dns=["api.yourorg.com"],
            policy_oids=[],
        ),
    )
    issued = root.sign_csr(csr.public_bytes(Encoding.PEM), tmpl)
    print(issued.public_bytes(Encoding.PEM).decode())

    # 4) Отзыв и CRL
    root.revoke(issued.serial_number, CRLReason.SUPERSEDED)
    crl = root.issue_crl()
    print(crl.public_bytes(Encoding.PEM).decode())
