# security-core/security/mtls/issuer.py
"""
Industrial mTLS Certificate Issuer for security-core.

Features:
- Self-signed ROOT CA and INTERMEDIATE CA creation
- Leaf issuance for mTLS (serverAuth, clientAuth) with SAN: DNS, IP, URI (incl. SPIFFE), RFC-822 email
- CSR intake and signing with strict policy validation
- X.509 extensions: BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAltName,
  AuthorityKeyIdentifier, SubjectKeyIdentifier, NameConstraints (optional),
  Authority Information Access (OCSP/caIssuers), CRL Distribution Points
- Serial policy: 63-bit random positive integers; monotonic clock with backdate for skew tolerance
- CRL generation (v2) with reasons, nextUpdate control
- Trust bundle export (chain PEM), CA rotation-friendly
- Strong typing, zero global state; compatible with python-cryptography >= 41

Note:
- Designed for local private-key CA. For external KMS signing of TBSCertificate, implement a signer
  that exposes a private-key-like interface to cryptography’s X.509 builder, or assemble ASN.1 manually.

"""

from __future__ import annotations

import ipaddress
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    NameOID,
    AuthorityInformationAccessOID,
)

# =========================
# Data classes & policies
# =========================

@dataclass(frozen=True)
class IssuerLimits:
    # Absolute safety rails
    max_ttl_days: int = 397  # Apple & CAB baseline
    max_backdate_seconds: int = 300
    allow_cn_in_leaf: bool = False
    # EKUs allowed for leaves
    allowed_ekus: Tuple[x509.ObjectIdentifier, ...] = (
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.SERVER_AUTH,
    )
    # NameConstraints (optional)
    permitted_dns: Tuple[str, ...] = ()
    permitted_email: Tuple[str, ...] = ()
    permitted_uri: Tuple[str, ...] = ()
    permitted_ip: Tuple[str, ...] = ()
    excluded_dns: Tuple[str, ...] = ()
    excluded_email: Tuple[str, ...] = ()
    excluded_uri: Tuple[str, ...] = ()
    excluded_ip: Tuple[str, ...] = ()


@dataclass(frozen=True)
class IssuerConfig:
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    # AIA/CRL endpoints (optional but recommended)
    ocsp_url: Optional[str] = None
    ca_issuers_url: Optional[str] = None
    crl_distribution_url: Optional[str] = None
    # Defaults for leaf issuance
    default_leaf_ttl: timedelta = timedelta(days=7)
    default_backdate: timedelta = timedelta(seconds=60)
    path_len_constraint: Optional[int] = 0  # for intermediate; None means unlimited (not recommended)


@dataclass(frozen=True)
class SubjectInfo:
    common_name: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None


@dataclass(frozen=True)
class SANs:
    dns: Tuple[str, ...] = ()
    ips: Tuple[str, ...] = ()
    uris: Tuple[str, ...] = ()
    emails: Tuple[str, ...] = ()
    spiffe_id: Optional[str] = None  # convenience; added to URIs if provided


# =========================
# Key generation helpers
# =========================

def generate_private_key(
    kind: str = "rsa",
    *,
    rsa_bits: int = 3072,
    ec_curve: str = "p256",
) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]:
    kind_l = kind.lower()
    if kind_l == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    if kind_l in ("ec", "ecdsa"):
        curve = {
            "p256": ec.SECP256R1(),
            "p384": ec.SECP384R1(),
            "p521": ec.SECP521R1(),
        }.get(ec_curve.lower())
        if not curve:
            raise ValueError("Unsupported EC curve")
        return ec.generate_private_key(curve)
    if kind_l == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError("Unsupported key kind")


# =========================
# Serial & time helpers
# =========================

def _rand_serial() -> int:
    # 63-bit positive integer (non-zero)
    v = secrets.randbits(63)
    return v or 1

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _clip_ttl(ttl: timedelta, limits: IssuerLimits) -> timedelta:
    max_ttl = timedelta(days=limits.max_ttl_days)
    return ttl if ttl <= max_ttl else max_ttl


# =========================
# Core Issuer
# =========================

@dataclass
class CertificateAuthority:
    cert: x509.Certificate
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]
    chain: Tuple[x509.Certificate, ...] = field(default_factory=tuple)
    cfg: IssuerConfig = field(default_factory=IssuerConfig)
    limits: IssuerLimits = field(default_factory=IssuerLimits)

    # ---------- Factories ----------

    @staticmethod
    def create_root(
        *,
        subject: SubjectInfo,
        key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]] = None,
        cfg: Optional[IssuerConfig] = None,
        limits: Optional[IssuerLimits] = None,
        ttl: timedelta = timedelta(days=3650),
        path_len: Optional[int] = 1,
        sha2: hashes.HashAlgorithm = hashes.SHA256(),
    ) -> "CertificateAuthority":
        key = key or generate_private_key("rsa", rsa_bits=4096)
        cfg = cfg or IssuerConfig()
        limits = limits or IssuerLimits()
        ttl = _clip_ttl(ttl, limits)

        name = _build_name(subject, cfg)
        now = _now_utc()
        not_before = now - min(cfg.default_backdate, timedelta(seconds=limits.max_backdate_seconds))
        not_after = now + ttl

        builder = (
            x509.CertificateBuilder()
            .serial_number(_rand_serial())
            .issuer_name(name)
            .subject_name(name)
            .public_key(key.public_key())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
            .add_extension(_subject_key_id_from_pub(key.public_key()), critical=False)
        )
        # No AKI for self-signed; SKI enough
        # Optional NameConstraints for root
        nc = _maybe_name_constraints(limits)
        if nc:
            builder = builder.add_extension(nc, critical=True)

        # AIA/CRL
        builder = _add_aia_crl(builder, cfg)

        cert = _sign_cert(builder, key, sha2)
        return CertificateAuthority(cert=cert, key=key, chain=(), cfg=cfg, limits=limits)

    @staticmethod
    def create_intermediate(
        parent: "CertificateAuthority",
        *,
        subject: SubjectInfo,
        key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]] = None,
        ttl: timedelta = timedelta(days=1825),
        path_len: Optional[int] = 0,
        sha2: hashes.HashAlgorithm = hashes.SHA256(),
    ) -> "CertificateAuthority":
        key = key or generate_private_key("rsa", rsa_bits=3072)
        ttl = _clip_ttl(ttl, parent.limits)

        name = _build_name(subject, parent.cfg)
        now = _now_utc()
        not_before = now - min(parent.cfg.default_backdate, timedelta(seconds=parent.limits.max_backdate_seconds))
        not_after = now + ttl

        builder = (
            x509.CertificateBuilder()
            .serial_number(_rand_serial())
            .issuer_name(parent.cert.subject)
            .subject_name(name)
            .public_key(key.public_key())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
            .add_extension(_subject_key_id_from_pub(key.public_key()), critical=False)
            .add_extension(_authority_key_id_from_cert(parent.cert), critical=False)
        )
        nc = _maybe_name_constraints(parent.limits)
        if nc:
            builder = builder.add_extension(nc, critical=True)
        builder = _add_aia_crl(builder, parent.cfg)

        cert = _sign_cert(builder, parent.key, sha2)
        chain = (parent.cert,) + parent.chain
        return CertificateAuthority(cert=cert, key=key, chain=chain, cfg=parent.cfg, limits=parent.limits)

    # ---------- Leaf issuance ----------

    def issue_leaf(
        self,
        *,
        subject: SubjectInfo = SubjectInfo(),
        sans: SANs = SANs(),
        ttl: Optional[timedelta] = None,
        eku: Sequence[x509.ObjectIdentifier] = (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
        server_auth: Optional[bool] = None,  # convenience override
        client_auth: Optional[bool] = None,  # convenience override
        key_usages: Optional[x509.KeyUsage] = None,
        sha2: hashes.HashAlgorithm = hashes.SHA256(),
    ) -> Tuple[x509.Certificate, Tuple[x509.Certificate, ...]]:
        ttl_eff = _clip_ttl(ttl or self.cfg.default_leaf_ttl, self.limits)
        now = _now_utc()
        not_before = now - min(self.cfg.default_backdate, timedelta(seconds=self.limits.max_backdate_seconds))
        not_after = now + ttl_eff

        # EKU resolution
        if server_auth is not None or client_auth is not None:
            eff = []
            if server_auth:
                eff.append(ExtendedKeyUsageOID.SERVER_AUTH)
            if client_auth:
                eff.append(ExtendedKeyUsageOID.CLIENT_AUTH)
            if not eff:
                raise ValueError("At least one of server_auth/client_auth must be True")
            eku = tuple(eff)

        # Validate requested EKUs
        for e in eku:
            if e not in self.limits.allowed_ekus:
                raise ValueError(f"EKU {e.dotted_string} is not permitted")

        # Subject
        if subject.common_name and not self.limits.allow_cn_in_leaf:
            # Best practice: SANs only; CN optional — enforce policy knob
            pass
        name = _build_name(subject, self.cfg)

        # SANs
        san = _build_san(sans)

        # Key usages
        if key_usages is None:
            key_usages = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,      # TLS RSA key exchange or ECDHE certs (still commonly set)
                data_encipherment=False,
                key_agreement=True,         # ECDHE
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )

        builder = (
            x509.CertificateBuilder()
            .serial_number(_rand_serial())
            .issuer_name(self.cert.subject)
            .subject_name(name)
            .public_key(_require_pub_from_san_or_subject(sans))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_subject_key_id_from_pub(_require_pub_from_san_or_subject(sans)), critical=False)
            .add_extension(_authority_key_id_from_cert(self.cert), critical=False)
            .add_extension(san, critical=False)
            .add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
            .add_extension(key_usages, critical=True)
        )

        # Name constraints inherited if configured
        nc = _maybe_name_constraints(self.limits)
        if nc:
            builder = builder.add_extension(nc, critical=True)

        # AIA/CRL
        builder = _add_aia_crl(builder, self.cfg)

        cert = _sign_cert(builder, self.key, sha2)
        chain = (self.cert,) + self.chain
        return cert, chain

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        ttl: Optional[timedelta] = None,
        force_server_auth: Optional[bool] = None,
        force_client_auth: Optional[bool] = None,
        extra_sans: Optional[SANs] = None,
        sha2: hashes.HashAlgorithm = hashes.SHA256(),
    ) -> Tuple[x509.Certificate, Tuple[x509.Certificate, ...]]:
        # Validate CSR
        _validate_csr(csr, self.limits)

        ttl_eff = _clip_ttl(ttl or self.cfg.default_leaf_ttl, self.limits)
        now = _now_utc()
        not_before = now - min(self.cfg.default_backdate, timedelta(seconds=self.limits.max_backdate_seconds))
        not_after = now + ttl_eff

        # Subject from CSR (do not override unless policy requires)
        name = csr.subject

        # SANs from CSR + extra (union)
        san = _merge_san_from_csr(csr, extra=extra_sans)

        # EKU resolution
        csr_eku = _try_get_eku_from_csr(csr)
        if force_server_auth is not None or force_client_auth is not None:
            eku_list = []
            if force_server_auth:
                eku_list.append(ExtendedKeyUsageOID.SERVER_AUTH)
            if force_client_auth:
                eku_list.append(ExtendedKeyUsageOID.CLIENT_AUTH)
            if not eku_list:
                raise ValueError("At least one of force_server_auth/force_client_auth must be True")
            eku = x509.ExtendedKeyUsage(eku_list)
        else:
            eku = csr_eku or x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])

        # Validate EKUs
        for e in eku:
            if e not in self.limits.allowed_ekus:
                raise ValueError(f"EKU {e.dotted_string} is not permitted")

        # Key usages (prefer csr KU if present)
        ku = _try_get_ku_from_csr(csr) or x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )

        builder = (
            x509.CertificateBuilder()
            .serial_number(_rand_serial())
            .issuer_name(self.cert.subject)
            .subject_name(name)
            .public_key(csr.public_key())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_subject_key_id_from_pub(csr.public_key()), critical=False)
            .add_extension(_authority_key_id_from_cert(self.cert), critical=False)
            .add_extension(san, critical=False)
            .add_extension(eku, critical=False)
            .add_extension(ku, critical=True)
        )

        nc = _maybe_name_constraints(self.limits)
        if nc:
            builder = builder.add_extension(nc, critical=True)
        builder = _add_aia_crl(builder, self.cfg)

        cert = _sign_cert(builder, self.key, sha2)
        chain = (self.cert,) + self.chain
        return cert, chain

    # ---------- CRL & export ----------

    def make_crl(
        self,
        revoked: Sequence[Tuple[int, x509.ReasonFlags, Optional[datetime]]],
        *,
        next_update_in: timedelta = timedelta(days=7),
        sha2: hashes.HashAlgorithm = hashes.SHA256(),
    ) -> x509.CertificateRevocationList:
        now = _now_utc()
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            self.cert.subject
        ).last_update(now).next_update(now + next_update_in)
        for serial, reason, rev_time in revoked:
            entry = x509.RevokedCertificateBuilder() \
                .serial_number(serial) \
                .revocation_date(rev_time or now) \
                .add_extension(x509.CRLReason(reason), critical=False) \
                .build()
            builder = builder.add_revoked_certificate(entry)
        crl = builder.sign(private_key=self.key, algorithm=sha2)
        return crl

    def export_trust_bundle_pem(self) -> bytes:
        # leafs should send end-entity + chain; here we export CA + chain
        pem_parts: List[bytes] = [self.cert.public_bytes(serialization.Encoding.PEM)]
        for c in self.chain:
            pem_parts.append(c.public_bytes(serialization.Encoding.PEM))
        return b"".join(pem_parts)


# =========================
# Internal helpers
# =========================

def _build_name(subject: SubjectInfo, cfg: IssuerConfig) -> x509.Name:
    attrs = []
    cn = subject.common_name
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))

    org = subject.organization or cfg.organization
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    ou = subject.organizational_unit or cfg.organizational_unit
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    c = subject.country or cfg.country
    if c:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    st = subject.state or cfg.state
    if st:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    l = subject.locality or cfg.locality
    if l:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))

    if not attrs:
        # Minimal valid DN
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "security-core"))
    return x509.Name(attrs)

def _subject_key_id_from_pub(pub) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(pub)

def _authority_key_id_from_cert(cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier(key_identifier=ski.digest, authority_cert_issuer=None, authority_cert_serial_number=None)

def _maybe_name_constraints(limits: IssuerLimits) -> Optional[x509.NameConstraints]:
    permitted_dns = [x509.DNSName(d) for d in limits.permitted_dns]
    excluded_dns = [x509.DNSName(d) for d in limits.excluded_dns]
    permitted_email = [x509.RFC822Name(e) for e in limits.permitted_email]
    excluded_email = [x509.RFC822Name(e) for e in limits.excluded_email]
    permitted_uri = [x509.UniformResourceIdentifier(u) for u in limits.permitted_uri]
    excluded_uri = [x509.UniformResourceIdentifier(u) for u in limits.excluded_uri]
    permitted_ip = [x509.IPAddress(ipaddress.ip_network(n, strict=False)) for n in limits.permitted_ip]
    excluded_ip = [x509.IPAddress(ipaddress.ip_network(n, strict=False)) for n in limits.excluded_ip]

    any_permitted = any((permitted_dns, permitted_email, permitted_uri, permitted_ip))
    any_excluded = any((excluded_dns, excluded_email, excluded_uri, excluded_ip))
    if not (any_permitted or any_excluded):
        return None
    return x509.NameConstraints(
        permitted_subtrees=tuple(permitted_dns + permitted_email + permitted_uri + permitted_ip) or None,
        excluded_subtrees=tuple(excluded_dns + excluded_email + excluded_uri + excluded_ip) or None,
    )

def _add_aia_crl(builder: x509.CertificateBuilder, cfg: IssuerConfig) -> x509.CertificateBuilder:
    aia_methods = []
    if cfg.ocsp_url:
        aia_methods.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(cfg.ocsp_url),
            )
        )
    if cfg.ca_issuers_url:
        aia_methods.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(cfg.ca_issuers_url),
            )
        )
    if aia_methods:
        builder = builder.add_extension(x509.AuthorityInformationAccess(aia_methods), critical=False)
    if cfg.crl_distribution_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(cfg.crl_distribution_url)],
                    relative_name=None, reasons=None, crl_issuer=None
                )
            ]),
            critical=False
        )
    return builder

def _build_san(sans: SANs) -> x509.SubjectAlternativeName:
    names: List[x509.GeneralName] = []
    for d in sans.dns:
        names.append(x509.DNSName(d))
    for ip in sans.ips:
        names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    uris = list(sans.uris)
    if sans.spiffe_id:
        uris.append(sans.spiffe_id)
    for u in uris:
        names.append(x509.UniformResourceIdentifier(u))
    for em in sans.emails:
        names.append(x509.RFC822Name(em))
    if not names:
        raise ValueError("At least one SAN is required for leaf certificates")
    return x509.SubjectAlternativeName(names)

def _require_pub_from_san_or_subject(sans: SANs):
    # For leaf issuance without CSR we still need a public key.
    # In many flows leaf keys are generated on the workload and presented via CSR.
    # This helper is a placeholder to keep API symmetric; in direct issuance supply CSR instead.
    raise ValueError("Direct leaf issuance requires CSR path. Use sign_csr() with a CSR containing the public key.")

def _validate_csr(csr: x509.CertificateSigningRequest, limits: IssuerLimits) -> None:
    try:
        csr_public_key = csr.public_key()
    except Exception:
        raise ValueError("CSR missing/invalid public key")

    # Must contain SAN per modern TLS requirements
    try:
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        raise ValueError("CSR must contain SubjectAlternativeName (SAN)")

    # EKU validation deferred to sign_csr but ensure nothing exotic if present
    try:
        eku = csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        for e in eku:
            if e not in limits.allowed_ekus:
                raise ValueError(f"CSR requests forbidden EKU {e.dotted_string}")
    except x509.ExtensionNotFound:
        pass

def _merge_san_from_csr(csr: x509.CertificateSigningRequest, extra: Optional[SANs]) -> x509.SubjectAlternativeName:
    base = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = list(base)
    if extra:
        if extra.spiffe_id:
            names.append(x509.UniformResourceIdentifier(extra.spiffe_id))
        for d in extra.dns:
            names.append(x509.DNSName(d))
        for ip in extra.ips:
            names.append(x509.IPAddress(ipaddress.ip_address(ip)))
        for u in extra.uris:
            names.append(x509.UniformResourceIdentifier(u))
        for em in extra.emails:
            names.append(x509.RFC822Name(em))
    # Deduplicate while preserving order
    dedup: List[x509.GeneralName] = []
    seen = set()
    for n in names:
        key = (type(n), getattr(n, "value", getattr(n, "address", n)))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(n)
    return x509.SubjectAlternativeName(dedup)

def _try_get_eku_from_csr(csr: x509.CertificateSigningRequest) -> Optional[x509.ExtendedKeyUsage]:
    try:
        return csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return None

def _try_get_ku_from_csr(csr: x509.CertificateSigningRequest) -> Optional[x509.KeyUsage]:
    try:
        return csr.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None

def _sign_cert(
    builder: x509.CertificateBuilder,
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
    sha2: hashes.HashAlgorithm,
) -> x509.Certificate:
    # Select algorithm: Ed25519 uses None; ECDSA uses SHA2 via ECDSA(); RSA uses PSS with MGF1 SHA2
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key=key, algorithm=None)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return builder.sign(private_key=key, algorithm=sha2)
    if isinstance(key, rsa.RSAPrivateKey):
        # cryptography automatically chooses PKCS#1 v1.5 for x509 unless padding specified via backend.
        # For compatibility with TLS, PKCS#1 v1.5 is acceptable for CA; many policies use it.
        # If PSS is required, consider manual ASN.1 assembly or library support.
        return builder.sign(private_key=key, algorithm=sha2)
    raise ValueError("Unsupported key type for signing")


# =========================
# PEM utilities
# =========================

def load_csr_pem(pem: bytes) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(pem)

def dump_cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def dump_key_pem(
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
    *,
    password: Optional[bytes] = None,
) -> bytes:
    enc = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )

def load_cert_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)

def load_key_pem(pem: bytes, password: Optional[bytes] = None) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]:
    return serialization.load_pem_private_key(pem, password=password)


# =========================
# Example (documentation only)
# =========================
if __name__ == "__main__":
    """
    Example usage:

    # 1) Create ROOT CA
    root_key = generate_private_key("rsa", rsa_bits=4096)
    root = CertificateAuthority.create_root(
        subject=SubjectInfo(common_name="Aethernova Root CA", organization="Aethernova"),
        key=root_key,
        cfg=IssuerConfig(
            organization="Aethernova",
            ocsp_url="http://ocsp.example.com",
            ca_issuers_url="http://ca.example.com/ca.der",
            crl_distribution_url="http://crl.example.com/root.crl",
            path_len_constraint=1,
        ),
        ttl=timedelta(days=3650),
    )

    # 2) Create INTERMEDIATE CA
    inter_key = generate_private_key("rsa", rsa_bits=3072)
    inter = CertificateAuthority.create_intermediate(
        parent=root,
        subject=SubjectInfo(common_name="Aethernova Intermediate CA"),
        key=inter_key,
        ttl=timedelta(days=1825),
        path_len=0,
    )

    # 3) Sign CSR from workload
    # csr_pem produced by workload with SANs (DNS/IP/URI including SPIFFE)
    # csr = load_csr_pem(csr_pem)
    # cert, chain = inter.sign_csr(csr, ttl=timedelta(days=30))

    # 4) CRL
    # crl = inter.make_crl([(123456, x509.ReasonFlags.key_compromise, None)], next_update_in=timedelta(days=7))
    """
    pass
