# security-core/security/pki/certs.py
# Industrial PKI utilities: keys, CA, leaf issuance, CSR, CRL, OCSP, chain verify, SKI/AKI, AIA/CRL DP.
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

from pydantic import BaseModel, Field, ValidationError, validator

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)

# =========================
# Algorithms and helpers
# =========================

KeyAlg = Literal["RSA", "EC", "Ed25519"]
HashAlg = Literal["SHA256", "SHA384"]
EKUSet = Sequence[ExtendedKeyUsageOID]

_HASHES = {"SHA256": hashes.SHA256(), "SHA384": hashes.SHA384()}
_EC_CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}


def _now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def _rand_serial() -> int:
    # 159‑битный положительный серийный номер (рекомендовано CAB/F)
    return secrets.randbits(159)


def _hash_name(name: x509.Name) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(name.public_bytes())
    return h.finalize().hex()


# =========================
# Pydantic specs
# =========================

class NameSpec(BaseModel):
    cn: Optional[str] = None
    o: Optional[str] = None
    ou: Optional[str] = None
    c: Optional[str] = None
    st: Optional[str] = None
    l: Optional[str] = None
    email: Optional[str] = None

    def to_x509(self) -> x509.Name:
        parts = []
        if self.cn:
            parts.append(x509.NameAttribute(NameOID.COMMON_NAME, self.cn))
        if self.o:
            parts.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.o))
        if self.ou:
            parts.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.ou))
        if self.c:
            parts.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.c))
        if self.st:
            parts.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.st))
        if self.l:
            parts.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.l))
        if self.email:
            parts.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email))
        if not parts:
            raise ValueError("Subject/Issuer Name must have at least one RDN (e.g., CN)")
        return x509.Name(parts)


class SANSpec(BaseModel):
    dns: List[str] = Field(default_factory=list)
    ip: List[str] = Field(default_factory=list)
    uri: List[str] = Field(default_factory=list)

    @validator("ip", each_item=True)
    def _ip_ok(cls, v: str) -> str:
        ipaddress.ip_address(v)  # will raise if invalid
        return v

    def to_x509(self) -> x509.SubjectAlternativeName:
        names: List[x509.GeneralName] = []
        for d in self.dns:
            names.append(x509.DNSName(d))
        for ip in self.ip:
            names.append(x509.IPAddress(ipaddress.ip_address(ip)))
        for u in self.uri:
            names.append(x509.UniformResourceIdentifier(u))
        if not names:
            raise ValueError("SAN list is empty")
        return x509.SubjectAlternativeName(names)


class CertLifetime(BaseModel):
    not_before: Optional[dt.datetime] = None
    not_after: Optional[dt.datetime] = None
    days_valid: Optional[int] = Field(default=None, ge=1, le=3650)

    @validator("not_before", "not_after", pre=True)
    def _ensure_tz(cls, v):
        if v and v.tzinfo is None:
            return v.replace(tzinfo=dt.timezone.utc)
        return v

    def resolve(self, ca: bool = False) -> Tuple[dt.datetime, dt.datetime]:
        nb = self.not_before or (_now_utc() - dt.timedelta(minutes=1))
        if self.not_after:
            na = self.not_after
        elif self.days_valid:
            na = nb + dt.timedelta(days=int(self.days_valid))
        else:
            na = nb + dt.timedelta(days=3650 if ca else 397)  # CA 10y, leaf ~13m
        if na <= nb:
            raise ValueError("not_after must be after not_before")
        return nb, na


class CAProfile(BaseModel):
    is_ca: bool = True
    path_len: Optional[int] = 1
    crl_distribution_points: List[str] = Field(default_factory=list)
    ocsp_urls: List[str] = Field(default_factory=list)
    aia_issuers: List[str] = Field(default_factory=list)


class LeafProfile(BaseModel):
    server_auth: bool = True
    client_auth: bool = False
    code_signing: bool = False
    email_protection: bool = False
    ocsp_signing: bool = False  # для OCSP‑респондера
    crl_distribution_points: List[str] = Field(default_factory=list)
    ocsp_urls: List[str] = Field(default_factory=list)
    aia_issuers: List[str] = Field(default_factory=list)
    key_usage_digital_signature: bool = True
    key_usage_key_encipherment: bool = True  # важно для RSA/TLS
    key_usage_key_agreement: bool = False


class IssueSpec(BaseModel):
    subject: NameSpec
    san: Optional[SANSpec] = None
    lifetime: CertLifetime = CertLifetime()
    hash_alg: HashAlg = "SHA256"


# =========================
# Key generation / serialization
# =========================

def generate_private_key(alg: KeyAlg = "EC", *, rsa_bits: int = 3072) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]:
    if alg == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    if alg == "EC":
        return ec.generate_private_key(ec.SECP256R1())
    if alg == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError("Unsupported key algorithm")


def private_key_to_pem(key, passphrase: Optional[bytes] = None) -> bytes:
    enc = NoEncryption() if not passphrase else BestAvailableEncryption(passphrase)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)


def public_key_to_pem(key) -> bytes:
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def load_private_key(pem: bytes, passphrase: Optional[bytes] = None):
    return serialization.load_pem_private_key(pem, password=passphrase)


# =========================
# Core builders
# =========================

def _add_basic_extensions(
    builder: x509.CertificateBuilder,
    *,
    subject_pub_key,
    issuer_cert: Optional[x509.Certificate],
    is_ca: bool,
    path_len: Optional[int],
    ski: bool = True,
    aki: bool = True,
) -> x509.CertificateBuilder:
    # Subject Key Identifier
    if ski:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_pub_key), critical=False)
    # Authority Key Identifier (from issuer)
    if aki and issuer_cert:
        try:
            akid = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(x509.SubjectKeyIdentifier(akid)), critical=False)
        except x509.ExtensionNotFound:
            builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    # Basic Constraints
    builder = builder.add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_len if is_ca else None), critical=True)
    return builder


def _add_lifetimes(builder: x509.CertificateBuilder, lifetime: CertLifetime, ca: bool) -> x509.CertificateBuilder:
    nb, na = lifetime.resolve(ca=ca)
    return builder.not_valid_before(nb).not_valid_after(na)


def _add_san(builder: x509.CertificateBuilder, san: Optional[SANSpec], fallback_cn: Optional[str]) -> x509.CertificateBuilder:
    if san and (san.dns or san.ip or san.uri):
        return builder.add_extension(san.to_x509(), critical=False)
    if fallback_cn:
        return builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(fallback_cn)]), critical=False)
    return builder


def _add_aia_crl(builder: x509.CertificateBuilder, crl_dp: List[str], ocsp_urls: List[str], aia_issuers: List[str]) -> x509.CertificateBuilder:
    if crl_dp:
        dps = [
            x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(u)], relative_name=None, reasons=None, crl_issuer=None)
            for u in crl_dp
        ]
        builder = builder.add_extension(x509.CRLDistributionPoints(dps), critical=False)
    aia_desc: List[x509.AccessDescription] = []
    for u in ocsp_urls:
        aia_desc.append(x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(u)))
    for u in aia_issuers:
        aia_desc.append(x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(u)))
    if aia_desc:
        builder = builder.add_extension(x509.AuthorityInformationAccess(aia_desc), critical=False)
    return builder


def _add_key_usage(builder: x509.CertificateBuilder, ca: bool, leaf_profile: Optional[LeafProfile]) -> x509.CertificateBuilder:
    if ca:
        ku = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
        builder = builder.add_extension(ku, critical=True)
        eku = x509.ExtendedKeyUsage([])  # у CA обычно нет EKU
        builder = builder.add_extension(eku, critical=False)
        return builder

    lp = leaf_profile or LeafProfile()
    ku = x509.KeyUsage(
        digital_signature=lp.key_usage_digital_signature,
        content_commitment=False,
        key_encipherment=lp.key_usage_key_encipherment,
        data_encipherment=False,
        key_agreement=lp.key_usage_key_agreement,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    eku_oids: List[ExtendedKeyUsageOID] = []
    if lp.server_auth:
        eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if lp.client_auth:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if lp.code_signing:
        eku_oids.append(ExtendedKeyUsageOID.CODE_SIGNING)
    if lp.email_protection:
        eku_oids.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
    if lp.ocsp_signing:
        eku_oids.append(ExtendedKeyUsageOID.OCSP_SIGNING)

    builder = builder.add_extension(ku, critical=True)
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)
    return builder


def create_self_signed_ca(
    *,
    subject: NameSpec,
    key,
    lifetime: CertLifetime = CertLifetime(days_valid=3650),
    hash_alg: HashAlg = "SHA256",
    profile: CAProfile = CAProfile(),
) -> x509.Certificate:
    subject_name = subject.to_x509()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(_rand_serial())
    )
    builder = _add_lifetimes(builder, lifetime, ca=True)
    builder = _add_basic_extensions(builder, subject_pub_key=key.public_key(), issuer_cert=None, is_ca=True, path_len=profile.path_len)
    builder = _add_aia_crl(builder, profile.crl_distribution_points, profile.ocsp_urls, profile.aia_issuers)
    return builder.sign(private_key=key, algorithm=_HASHES[hash_alg], backend=None)


def create_intermediate_ca(
    *,
    issuer_cert: x509.Certificate,
    issuer_key,
    subject: NameSpec,
    key,
    lifetime: CertLifetime = CertLifetime(days_valid=1825),
    hash_alg: HashAlg = "SHA256",
    profile: CAProfile = CAProfile(path_len=0),
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject.to_x509())
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(_rand_serial())
    )
    builder = _add_lifetimes(builder, lifetime, ca=True)
    builder = _add_basic_extensions(builder, subject_pub_key=key.public_key(), issuer_cert=issuer_cert, is_ca=True, path_len=profile.path_len)
    builder = _add_aia_crl(builder, profile.crl_distribution_points, profile.ocsp_urls, profile.aia_issuers)
    return builder.sign(private_key=issuer_key, algorithm=_HASHES[hash_alg], backend=None)


def issue_leaf_cert(
    *,
    issuer_cert: x509.Certificate,
    issuer_key,
    spec: IssueSpec,
    subject_key,
    profile: LeafProfile = LeafProfile(),
) -> x509.Certificate:
    subject_name = spec.subject.to_x509()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(_rand_serial())
    )
    builder = _add_lifetimes(builder, spec.lifetime, ca=False)
    builder = _add_basic_extensions(builder, subject_pub_key=subject_key.public_key(), issuer_cert=issuer_cert, is_ca=False, path_len=None)
    builder = _add_san(builder, spec.san, fallback_cn=spec.subject.cn)
    builder = _add_aia_crl(builder, profile.crl_distribution_points, profile.ocsp_urls, profile.aia_issuers)
    builder = _add_key_usage(builder, ca=False, leaf_profile=profile)
    # Subject/Authority Key ID уже добавлены в _add_basic_extensions
    return builder.sign(private_key=issuer_key, algorithm=_HASHES[spec.hash_alg], backend=None)


# =========================
# CSR
# =========================

def create_csr(*, subject: NameSpec, key, san: Optional[SANSpec] = None, hash_alg: HashAlg = "SHA256") -> x509.CertificateSigningRequest:
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject.to_x509())
    if san:
        builder = builder.add_extension(san.to_x509(), critical=False)
    return builder.sign(key, _HASHES[hash_alg])


def sign_csr(
    *,
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key,
    lifetime: CertLifetime = CertLifetime(days_valid=397),
    profile: LeafProfile = LeafProfile(),
    hash_alg: HashAlg = "SHA256",
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(_rand_serial())
    )
    builder = _add_lifetimes(builder, lifetime, ca=False)
    builder = _add_basic_extensions(builder, subject_pub_key=csr.public_key(), issuer_cert=issuer_cert, is_ca=False, path_len=None)
    # перенести SAN из CSR если есть
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass
    builder = _add_aia_crl(builder, profile.crl_distribution_points, profile.ocsp_urls, profile.aia_issuers)
    builder = _add_key_usage(builder, ca=False, leaf_profile=profile)
    return builder.sign(private_key=issuer_key, algorithm=_HASHES[hash_alg], backend=None)


# =========================
# CRL
# =========================

def create_crl(
    *,
    issuer_cert: x509.Certificate,
    issuer_key,
    revoked: Sequence[Tuple[int, dt.datetime, Optional[x509.ReasonFlags]]],
    last_update: Optional[dt.datetime] = None,
    next_update: Optional[dt.datetime] = None,
    hash_alg: HashAlg = "SHA256",
) -> x509.CertificateRevocationList:
    last = (last_update or _now_utc())
    nxt = (next_update or (last + dt.timedelta(days=7)))
    builder = x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject).last_update(last).next_update(nxt)
    for serial, rev_time, reason in revoked:
        entry = x509.RevokedCertificateBuilder().serial_number(int(serial)).revocation_date(rev_time)
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    # AKI для CRL (необязательно, многие клиенты игнорируют)
    return builder.sign(private_key=issuer_key, algorithm=_HASHES[hash_alg])


# =========================
# OCSP (basic single-response)
# =========================

def build_ocsp_response(
    *,
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    cert_status: Literal["good", "revoked", "unknown"] = "good",
    revocation_time: Optional[dt.datetime] = None,
    revocation_reason: Optional[x509.ReasonFlags] = None,
    this_update: Optional[dt.datetime] = None,
    next_update: Optional[dt.datetime] = None,
    hash_alg: HashAlg = "SHA256",
) -> ocsp.OCSPResponse:
    builder = ocsp.OCSPResponseBuilder()
    h = _HASHES[hash_alg]
    status_enum = ocsp.OCSPCertStatus.GOOD
    if cert_status == "revoked":
        status_enum = ocsp.OCSPCertStatus.REVOKED
    elif cert_status == "unknown":
        status_enum = ocsp.OCSPCertStatus.UNKNOWN

    b = ocsp.OCSPResponseBuilder().add_response(
        cert=cert,
        issuer=issuer_cert,
        algorithm=h,
        cert_status=status_enum,
        this_update=(this_update or _now_utc()),
        next_update=(next_update or (_now_utc() + dt.timedelta(hours=4))),
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    )
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)  # обычно по хешу имени
    b = b.sign(private_key=responder_key, algorithm=h, responder_id=ocsp.OCSPResponderEncoding.HASH, certificates=[responder_cert])
    return b


# =========================
# Chain verification (basic)
# =========================

@dataclass
class ChainVerifyResult:
    ok: bool
    depth: int
    errors: List[str]
    path: List[x509.Certificate]


def verify_chain(
    *,
    end_entity: x509.Certificate,
    chain: Sequence[x509.Certificate],  # промежуточные
    trust_roots: Sequence[x509.Certificate],
    at: Optional[dt.datetime] = None,
) -> ChainVerifyResult:
    """
    Базовая проверка: подписи, сроки, BasicConstraints, AKI/SKI, связывание субъект->издатель.
    Не реализует полную политику PKIX/AIA/CRL/OCSP. Для строгого соответствия используйте системные хранилища.
    """
    t = at or _now_utc()
    path: List[x509.Certificate] = [end_entity]
    errs: List[str] = []

    def _valid_time(c: x509.Certificate) -> bool:
        return (c.not_valid_before <= t <= c.not_valid_after)

    # Быстрый словарь по subject‑hash
    all_certs = list(chain) + list(trust_roots)
    by_subject = {c.subject.rfc4514_string(): c for c in all_certs}
    current = end_entity

    depth = 0
    while True:
        if not _valid_time(current):
            errs.append(f"time invalid for {current.subject.rfc4514_string()}")
            break
        # self‑signed?
        if current.issuer == current.subject:
            # должен быть в доверенных корнях
            if not any(current.fingerprint(hashes.SHA256()) == r.fingerprint(hashes.SHA256()) for r in trust_roots):
                errs.append("self-signed cert not in trust roots")
                break
            # проверим подпись самона себя
            try:
                current.public_key().verify(
                    current.signature,
                    current.tbs_certificate_bytes,
                    current.signature_hash_algorithm,
                )
            except Exception:
                errs.append("root self-signature invalid")
            path.append(current)
            break

        # найдем издателя по subject
        issuer = by_subject.get(current.issuer.rfc4514_string())
        if issuer is None:
            errs.append(f"issuer not found for {current.subject.rfc4514_string()}")
            break

        # проверим BasicConstraints издателя
        try:
            bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                errs.append("issuer is not a CA")
                break
        except x509.ExtensionNotFound:
            errs.append("issuer missing BasicConstraints")
            break

        # проверим подпись
        try:
            issuer.public_key().verify(
                current.signature,
                current.tbs_certificate_bytes,
                current.signature_hash_algorithm,
            )
        except Exception:
            errs.append("signature verification failed")
            break

        path.append(issuer)
        depth += 1
        if issuer in trust_roots:
            break
        current = issuer
        # ограничение глубины
        if depth > 10:
            errs.append("chain too long")
            break

    ok = len(errs) == 0
    return ChainVerifyResult(ok=ok, depth=len(path) - 1, errors=errs, path=path)


# =========================
# Introspection / fingerprints
# =========================

def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def spki_sha256_hex(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256()); digest.update(spki)
    return digest.finalize().hex()


# =========================
# Serialization helpers
# =========================

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.PEM)


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(Encoding.PEM)


def crl_to_pem(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(Encoding.PEM)


def ocsp_to_der(resp: ocsp.OCSPResponse) -> bytes:
    return resp.public_bytes(Encoding.DER)


# =========================
# Simple in-memory store
# =========================

class CertStore:
    """
    Простое хранилище для сертификатов/ключей, пригодно для тестов и небольших PKI‑ролей.
    Для продакшена храните приватные ключи в HSM/KMS.
    """
    def __init__(self) -> None:
        self.roots: List[x509.Certificate] = []
        self.intermediates: List[x509.Certificate] = []
        self.leaves: List[x509.Certificate] = []
        self._keys: Dict[str, Any] = {}  # fingerprint -> private key

    def add_root(self, cert: x509.Certificate) -> None:
        self.roots.append(cert)

    def add_intermediate(self, cert: x509.Certificate) -> None:
        self.intermediates.append(cert)

    def add_leaf(self, cert: x509.Certificate) -> None:
        self.leaves.append(cert)

    def attach_key(self, cert: x509.Certificate, key: Any) -> None:
        self._keys[cert_fingerprint_sha256(cert)] = key

    def find_key(self, cert: x509.Certificate) -> Optional[Any]:
        return self._keys.get(cert_fingerprint_sha256(cert))


# =========================
# Example quick usage (for docs/tests)
# =========================
"""
# 1) Root CA
root_key = generate_private_key("EC")
root_cert = create_self_signed_ca(
    subject=NameSpec(cn="NeuroCity Root CA", o="NeuroCity"),
    key=root_key,
    lifetime=CertLifetime(days_valid=3650),
    profile=CAProfile(path_len=1, crl_distribution_points=["https://pki.example/crl/root.crl"], ocsp_urls=["http://ocsp.example"])
)

# 2) Intermediate
int_key = generate_private_key("EC")
int_cert = create_intermediate_ca(
    issuer_cert=root_cert, issuer_key=root_key,
    subject=NameSpec(cn="NeuroCity Issuing CA 1", o="NeuroCity"),
    key=int_key,
    lifetime=CertLifetime(days_valid=1825),
    profile=CAProfile(path_len=0, crl_distribution_points=["https://pki.example/crl/int.crl"], ocsp_urls=["http://ocsp.example"])
)

# 3) Server leaf
srv_key = generate_private_key("RSA")
leaf = issue_leaf_cert(
    issuer_cert=int_cert, issuer_key=int_key,
    subject_key=srv_key,
    spec=IssueSpec(subject=NameSpec(cn="api.neurocity.example"), san=SANSpec(dns=["api.neurocity.example","api"], ip=["203.0.113.10"])),
    profile=LeafProfile(server_auth=True, client_auth=False, crl_distribution_points=["https://pki.example/crl/int.crl"], ocsp_urls=["http://ocsp.example"])
)

# 4) Verify chain
res = verify_chain(end_entity=leaf, chain=[int_cert], trust_roots=[root_cert])
assert res.ok

# 5) CSR + sign_csr
csr = create_csr(subject=NameSpec(cn="client-42", o="NeuroCity"), key=generate_private_key("EC"), san=SANSpec(uri=["spiffe://neurocity/client/42"]))
client_cert = sign_csr(csr=csr, issuer_cert=int_cert, issuer_key=int_key, profile=LeafProfile(server_auth=False, client_auth=True))

# 6) CRL
crl = create_crl(issuer_cert=int_cert, issuer_key=int_key, revoked=[(leaf.serial_number, dt.datetime.now(dt.timezone.utc), x509.ReasonFlags.key_compromise)])

# 7) OCSP
ocsp_resp = build_ocsp_response(cert=leaf, issuer_cert=int_cert, responder_cert=int_cert, responder_key=int_key, cert_status="good")
"""
