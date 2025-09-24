# -*- coding: utf-8 -*-
"""
security-core.security.pki.csr — генерация и верификация PKCS#10 CSR.

Возможности:
- Генерация ключей: RSA (>=2048), ECDSA (P-256/P-384/P-521), Ed25519.
- Сборка CSR с расширениями: SubjectAltName (DNS, IP, URI, Email), KeyUsage, ExtendedKeyUsage,
  BasicConstraints, SubjectKeyIdentifier, TLS Feature (OCSP Must-Staple).
- Детализированная валидация: подпись, алгоритм, размер/кривая ключа, SAN/Subject/KU/EKU/BC по политике.
- SPKI pin (sha256/base64) и детерминированная нормализация Subject/SAN.
- Парсинг CSR в структурированный вид для журналирования/аудита.
- Сериализация приватного ключа (PKCS#8, PEM) с паролем/без.

Зависимости:
  - cryptography>=41 (рекомендовано).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier, TLSFeatureType
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False


# =========================== Спецификации ввода ===============================

@dataclass(frozen=True)
class KeySpec:
    kind: str  # "RSA" | "EC" | "Ed25519"
    rsa_bits: int = 2048
    rsa_public_exponent: int = 65537
    ec_curve: str = "P-256"  # "P-256" | "P-384" | "P-521"

@dataclass(frozen=True)
class SubjectSpec:
    common_name: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    org_unit: Optional[str] = None
    serial_number: Optional[str] = None
    email: Optional[str] = None

@dataclass(frozen=True)
class ExtensionsSpec:
    dns_names: Tuple[str, ...] = ()
    ip_addrs: Tuple[str, ...] = ()
    uris: Tuple[str, ...] = ()
    emails: Tuple[str, ...] = ()
    basic_constraints_ca: bool = False
    basic_constraints_pathlen: Optional[int] = None
    key_usage: Mapping[str, bool] = field(default_factory=lambda: {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": True,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    })
    extended_key_usage: Tuple[str, ...] = ("serverAuth", "clientAuth")  # см. _EKU_MAP
    add_subject_key_id: bool = True
    tls_must_staple: bool = False  # TLS Feature status_request

@dataclass(frozen=True)
class CSRRequest:
    key: KeySpec
    subject: SubjectSpec
    extensions: ExtensionsSpec
    challenge_password: Optional[str] = None
    extra_attributes: Mapping[str, str] = field(default_factory=dict)  # nameOidStr -> utf8 string
    signing_hash: str = "SHA256"  # для RSA/ECDSA: "SHA256"/"SHA384"/"SHA512"

# ================================ Политика ====================================

@dataclass(frozen=True)
class CSRPolicy:
    allow_algs: Tuple[str, ...] = ("RSA", "EC", "Ed25519")
    min_rsa_bits: int = 2048
    allowed_ec_curves: Tuple[str, ...] = ("P-256", "P-384", "P-521")
    forbid_ca: bool = True
    require_san: bool = True
    require_cn_if_no_san: bool = False
    forbidden_hashes: Tuple[str, ...] = ("SHA1", "MD5")
    required_ekus: Tuple[str, ...] = ()  # например ("serverAuth",)
    allowed_ekus: Tuple[str, ...] = ("serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "OCSPSigning")
    allowed_ku_true: Tuple[str, ...] = ("digital_signature", "key_encipherment")
    san_dns_allow_patterns: Tuple[str, ...] = ("*",)  # шаблоны вида *.example.com
    san_ip_allow_subnets: Tuple[str, ...] = ("0.0.0.0/0", "::/0")
    max_san_total: int = 100
    allow_must_staple: bool = True

# =============================== Исключения ===================================

class CSRBuildError(Exception):
    pass

class CSRVerifyError(Exception):
    pass

# =============================== Хелперы ======================================

_EKU_MAP: Mapping[str, ExtendedKeyUsageOID] = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
}

_HASHES: Mapping[str, hashes.HashAlgorithm] = {
    "SHA256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
    "SHA512": hashes.SHA512(),
}

def _need_crypto():
    if not _CRYPTO:
        raise CSRBuildError("cryptography is required for CSR operations")

def _ec_curve(name: str):
    name = name.upper().replace("-", "")
    if name in ("P256", "SECP256R1"):
        return ec.SECP256R1()
    if name in ("P384", "SECP384R1"):
        return ec.SECP384R1()
    if name in ("P521", "SECP521R1"):
        return ec.SECP521R1()
    raise CSRBuildError(f"Unsupported EC curve: {name}")

def _normalize_dns(name: str) -> str:
    return name.strip().lower()

def _spki_sha256_b64(pub) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives import hashes as _h
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    h = _h.Hash(_h.SHA256())
    h.update(spki)
    import base64
    return base64.b64encode(h.finalize()).decode("ascii")

def _pattern_match(host: str, patterns: Iterable[str]) -> bool:
    import fnmatch
    for p in patterns:
        if fnmatch.fnmatch(host, p):
            return True
    return False

def _ip_in_subnets(ip: str, subnets: Iterable[str]) -> bool:
    ipaddr = ipaddress.ip_address(ip)
    for net in subnets:
        if ipaddr in ipaddress.ip_network(net, strict=False):
            return True
    return False

# =========================== Генерация ключей =================================

def generate_private_key(spec: KeySpec):
    _need_crypto()
    kind = spec.kind.upper()
    if kind == "RSA":
        if spec.rsa_bits < 2048:
            raise CSRBuildError("RSA key must be >= 2048 bits")
        return rsa.generate_private_key(public_exponent=spec.rsa_public_exponent, key_size=spec.rsa_bits)
    if kind == "EC":
        return ec.generate_private_key(_ec_curve(spec.ec_curve))
    if kind == "ED25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise CSRBuildError(f"Unsupported key kind: {spec.kind}")

def serialize_private_key_pem(private_key, password: Optional[bytes] = None) -> bytes:
    _need_crypto()
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )

# ============================== Сборка CSR ====================================

def build_csr_from_key(private_key, req: CSRRequest) -> bytes:
    """
    Строит PKCS#10 CSR (PEM) из готового приватного ключа и спецификаций.
    """
    _need_crypto()

    # Subject
    name_attrs: List[x509.NameAttribute] = []
    s = req.subject
    # детерминированный порядок
    if s.country:        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, s.country))
    if s.state:          name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s.state))
    if s.locality:       name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, s.locality))
    if s.organization:   name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, s.organization))
    if s.org_unit:       name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, s.org_unit))
    if s.common_name:    name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, s.common_name))
    if s.serial_number:  name_attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, s.serial_number))
    if s.email:          name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, s.email))
    subject = x509.Name(name_attrs)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    # Extensions (в CSR через extensionRequest)
    ext = req.extensions

    # SAN
    san_gns: List[x509.GeneralName] = []
    for d in sorted(set(_normalize_dns(x) for x in ext.dns_names)):
        san_gns.append(x509.DNSName(d))
    for ip in sorted(set(ext.ip_addrs)):
        san_gns.append(x509.IPAddress(ipaddress.ip_address(ip)))
    for u in sorted(set(ext.uris)):
        san_gns.append(x509.UniformResourceIdentifier(u))
    for e in sorted(set(ext.emails)):
        san_gns.append(x509.RFC822Name(e))
    if san_gns:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_gns), critical=False)

    # Basic Constraints
    builder = builder.add_extension(x509.BasicConstraints(ca=ext.basic_constraints_ca, path_length=ext.basic_constraints_pathlen), critical=True)

    # Key Usage
    ku = ext.key_usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=bool(ku.get("digital_signature", False)),
            content_commitment=bool(ku.get("content_commitment", False)),
            key_encipherment=bool(ku.get("key_encipherment", False)),
            data_encipherment=bool(ku.get("data_encipherment", False)),
            key_agreement=bool(ku.get("key_agreement", False)),
            key_cert_sign=bool(ku.get("key_cert_sign", False)),
            crl_sign=bool(ku.get("crl_sign", False)),
            encipher_only=bool(ku.get("encipher_only", False)),
            decipher_only=bool(ku.get("decipher_only", False)),
        ),
        critical=True,
    )

    # Extended Key Usage
    if ext.extended_key_usage:
        oids = []
        for n in ext.extended_key_usage:
            if n not in _EKU_MAP:
                raise CSRBuildError(f"Unsupported EKU: {n}")
            oids.append(_EKU_MAP[n])
        builder = builder.add_extension(x509.ExtendedKeyUsage(oids), critical=False)

    # SKI
    if ext.add_subject_key_id:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)

    # TLS Feature (OCSP Must-Staple)
    if ext.tls_must_staple:
        builder = builder.add_extension(x509.TLSFeature([TLSFeatureType.status_request]), critical=False)

    # Доп. атрибуты (challengePassword и произвольные PrintableString/UTF8String)
    attrs: List[x509.Attribute] = []
    if req.challenge_password:
        attrs.append(x509.Attribute(ObjectIdentifier("1.2.840.113549.1.9.7"), [x509.DirectoryString(req.challenge_password)]))
    for oid_str, val in (req.extra_attributes or {}).items():
        attrs.append(x509.Attribute(ObjectIdentifier(oid_str), [x509.DirectoryString(val)]))
    if attrs:
        builder = builder.add_attribute(x509.oid.AttributeOID.CHALLENGE_PASSWORD, attrs[0].values) if req.challenge_password else builder

    # Выбор хеш-алгоритма
    key = private_key
    alg = None
    if isinstance(key, rsa.RSAPrivateKey) or isinstance(key, ec.EllipticCurvePrivateKey):
        if req.signing_hash.upper() not in _HASHES:
            raise CSRBuildError(f"Unsupported signing hash: {req.signing_hash}")
        alg = _HASHES[req.signing_hash.upper()]
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        alg = None  # Ed25519 не использует хеш-параметр
    else:
        raise CSRBuildError("Unsupported private key type")

    csr = builder.sign(private_key=key, algorithm=alg)
    return csr.public_bytes(serialization.Encoding.PEM)

def generate_csr(req: CSRRequest, *, key_password: Optional[bytes] = None) -> Tuple[bytes, bytes, str]:
    """
    Генерирует приватный ключ и CSR. Возвращает (pk_pem, csr_pem, spki_pin_b64).
    """
    key = generate_private_key(req.key)
    pk_pem = serialize_private_key_pem(key, password=key_password)
    csr_pem = build_csr_from_key(key, req)
    spki_pin = _spki_sha256_b64(key.public_key())
    return pk_pem, csr_pem, spki_pin

# =============================== Парсинг CSR ==================================

@dataclass
class ParsedCSR:
    subject: Mapping[str, str]
    dns_names: Tuple[str, ...]
    ip_addrs: Tuple[str, ...]
    uris: Tuple[str, ...]
    emails: Tuple[str, ...]
    basic_constraints_ca: bool
    basic_constraints_pathlen: Optional[int]
    key_usage: Mapping[str, bool]
    extended_key_usage: Tuple[str, ...]
    has_ski: bool
    tls_must_staple: bool
    spki_pin_sha256_b64: str
    algorithm: str  # RSA/ECDSA/Ed25519
    signature_hash: Optional[str]  # SHA256/384/512 or None (Ed25519)
    raw: x509.CertificateSigningRequest

def _load_csr_pem_or_der(data: bytes) -> x509.CertificateSigningRequest:
    _need_crypto()
    try:
        if b"BEGIN CERTIFICATE REQUEST" in data or b"BEGIN NEW CERTIFICATE REQUEST" in data:
            return x509.load_pem_x509_csr(data)
        return x509.load_der_x509_csr(data)
    except Exception as e:
        raise CSRVerifyError(f"Failed to parse CSR: {e}")

def parse_csr(data: bytes) -> ParsedCSR:
    csr = _load_csr_pem_or_der(data)
    # Subject
    subj_map: Dict[str, str] = {}
    for rdn in csr.subject.rdns:
        for attr in rdn:
            oid = attr.oid
            if oid == NameOID.COMMON_NAME: subj_map["CN"] = attr.value
            elif oid == NameOID.COUNTRY_NAME: subj_map["C"] = attr.value
            elif oid == NameOID.STATE_OR_PROVINCE_NAME: subj_map["ST"] = attr.value
            elif oid == NameOID.LOCALITY_NAME: subj_map["L"] = attr.value
            elif oid == NameOID.ORGANIZATION_NAME: subj_map["O"] = attr.value
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME: subj_map["OU"] = attr.value
            elif oid == NameOID.SERIAL_NUMBER: subj_map["serialNumber"] = attr.value
            elif oid == NameOID.EMAIL_ADDRESS: subj_map["emailAddress"] = attr.value
            else:
                subj_map[oid.dotted_string] = attr.value

    def get_ext(oid):
        try:
            return csr.extensions.get_extension_for_oid(oid).value, csr.extensions.get_extension_for_oid(oid).critical
        except x509.ExtensionNotFound:
            return None, None

    # SAN
    dns, ips, uris, emails = [], [], [], []
    san_val, _ = get_ext(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san_val:
        for gn in san_val:
            if isinstance(gn, x509.DNSName): dns.append(gn.value.lower())
            elif isinstance(gn, x509.IPAddress): ips.append(str(gn.value))
            elif isinstance(gn, x509.UniformResourceIdentifier): uris.append(gn.value)
            elif isinstance(gn, x509.RFC822Name): emails.append(gn.value)

    # BC
    bc_val, bc_crit = get_ext(x509.ExtensionOID.BASIC_CONSTRAINTS)
    ca = bc_val.ca if bc_val else False
    path_len = bc_val.path_length if bc_val else None

    # KU
    ku_val, _ = get_ext(x509.ExtensionOID.KEY_USAGE)
    ku_map = {}
    if ku_val:
        ku_map = {
            "digital_signature": ku_val.digital_signature,
            "content_commitment": ku_val.content_commitment,
            "key_encipherment": ku_val.key_encipherment,
            "data_encipherment": ku_val.data_encipherment,
            "key_agreement": ku_val.key_agreement,
            "key_cert_sign": ku_val.key_cert_sign,
            "crl_sign": ku_val.crl_sign,
            "encipher_only": ku_val.encipher_only,
            "decipher_only": ku_val.decipher_only,
        }

    # EKU
    eku_val, _ = get_ext(x509.ExtensionOID.EXTENDED_KEY_USAGE)
    ekus = []
    if eku_val:
        rev = {v: k for k, v in _EKU_MAP.items()}
        for oid in eku_val:
            ekus.append(rev.get(oid, oid.dotted_string))

    # SKI
    ski_val, _ = get_ext(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    has_ski = ski_val is not None

    # TLS Feature (Must-Staple)
    tlsf_val, _ = get_ext(x509.ExtensionOID.TLS_FEATURE)
    must_staple = False
    if tlsf_val:
        for t in tlsf_val:
            if t == TLSFeatureType.status_request:
                must_staple = True

    # Алгоритм и хеш
    pub = csr.public_key()
    if hasattr(pub, "key_size"):  # RSA/ECDSA
        if pub.__class__.__name__.startswith("RSAPublicKey"):
            alg = "RSA"
        elif pub.__class__.__name__.startswith("EllipticCurvePublicKey"):
            alg = "ECDSA"
        else:
            alg = "UNKNOWN"
    else:
        alg = "Ed25519" if pub.__class__.__name__.startswith("Ed25519PublicKey") else "UNKNOWN"

    sig_hash = None
    try:
        sig_hash = csr.signature_hash_algorithm.name.upper()
    except Exception:
        sig_hash = None  # Ed25519

    return ParsedCSR(
        subject=subj_map,
        dns_names=tuple(dns),
        ip_addrs=tuple(ips),
        uris=tuple(uris),
        emails=tuple(emails),
        basic_constraints_ca=ca,
        basic_constraints_pathlen=path_len,
        key_usage=ku_map,
        extended_key_usage=tuple(ekus),
        has_ski=has_ski,
        tls_must_staple=must_staple,
        spki_pin_sha256_b64=_spki_sha256_b64(pub),
        algorithm=alg,
        signature_hash=sig_hash,
        raw=csr,
    )

# ============================ Верификация CSR =================================

@dataclass
class CSRVerifyResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    parsed: Optional[ParsedCSR] = None

def verify_csr(data: bytes, policy: Optional[CSRPolicy] = None) -> CSRVerifyResult:
    """
    Полная проверка CSR по политике. Возвращает подробный отчет.
    """
    policy = policy or CSRPolicy()
    parsed = parse_csr(data)
    errors: List[str] = []
    warnings: List[str] = []

    # 1) Базовая подпись
    csr = parsed.raw
    pub = csr.public_key()
    try:
        # cryptography самостоятельно определяет параметры верификации
        if parsed.algorithm == "RSA":
            csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, padding.PKCS1v15(), csr.signature_hash_algorithm)
        elif parsed.algorithm == "ECDSA":
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, _ec.ECDSA(csr.signature_hash_algorithm))
        elif parsed.algorithm == "Ed25519":
            csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes)
        else:
            errors.append("Unsupported public key algorithm")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")

    # 2) Алгоритмы, ключи, хеш
    if parsed.algorithm not in policy.allow_algs:
        errors.append(f"Algorithm not allowed: {parsed.algorithm}")

    if parsed.algorithm == "RSA":
        if getattr(pub, "key_size", 0) < policy.min_rsa_bits:
            errors.append(f"RSA key too small: {getattr(pub, 'key_size', 0)}")
        if parsed.signature_hash in policy.forbidden_hashes:
            errors.append(f"Weak hash forbidden: {parsed.signature_hash}")
    elif parsed.algorithm == "ECDSA":
        curve_name = pub.curve.name.upper().replace("-", "")
        curve_map = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
        mapped = curve_map.get(pub.curve.name.lower(), pub.curve.name)
        if mapped not in policy.allowed_ec_curves:
            errors.append(f"EC curve not allowed: {mapped}")
        if parsed.signature_hash in policy.forbidden_hashes:
            errors.append(f"Weak hash forbidden: {parsed.signature_hash}")
    elif parsed.algorithm == "Ed25519":
        # нет параметров хеша
        pass

    # 3) Basic Constraints
    if policy.forbid_ca and parsed.basic_constraints_ca:
        errors.append("CA=true is forbidden by policy")
    if parsed.basic_constraints_ca and parsed.basic_constraints_pathlen is None:
        warnings.append("CA=true without pathLen constraint")

    # 4) SAN/Subject
    total_san = len(parsed.dns_names) + len(parsed.ip_addrs) + len(parsed.uris) + len(parsed.emails)
    if policy.require_san and total_san == 0:
        errors.append("SubjectAltName required by policy")
    if not policy.require_san and policy.require_cn_if_no_san and total_san == 0 and "CN" not in parsed.subject:
        errors.append("CN required when SAN is empty")

    # Разрешенные паттерны DNS и подсети IP
    for d in parsed.dns_names:
        if not _pattern_match(d, policy.san_dns_allow_patterns):
            errors.append(f"DNS SAN not allowed: {d}")
    for ip in parsed.ip_addrs:
        if not _ip_in_subnets(ip, policy.san_ip_allow_subnets):
            errors.append(f"IP SAN not allowed: {ip}")
    if total_san > policy.max_san_total:
        errors.append(f"Too many SAN entries: {total_san} > {policy.max_san_total}")

    # 5) KU/EKU
    for required in policy.allowed_ku_true:
        if not parsed.key_usage.get(required, False):
            errors.append(f"Required KeyUsage missing or false: {required}")

    if policy.required_ekus:
        miss = set(policy.required_ekus) - set(parsed.extended_key_usage)
        if miss:
            errors.append(f"Required EKUs missing: {sorted(miss)}")

    # EKU superset check
    for eku in parsed.extended_key_usage:
        if eku not in policy.allowed_ekus and not re.fullmatch(r"(\d+\.)+\d+", eku):
            errors.append(f"EKU not allowed: {eku}")

    # 6) TLS Feature must-staple
    if parsed.tls_must_staple and not policy.allow_must_staple:
        errors.append("TLS Must-Staple not allowed by policy")

    return CSRVerifyResult(ok=(len(errors) == 0), errors=errors, warnings=warnings, parsed=parsed)

# ================================ Пример API ==================================

# Пример использования (оставлено как документация внутри модуля):
#
# from security.security.pki.csr import (
#     KeySpec, SubjectSpec, ExtensionsSpec, CSRRequest,
#     generate_csr, verify_csr, CSRPolicy
# )
#
# req = CSRRequest(
#     key=KeySpec(kind="EC", ec_curve="P-256"),
#     subject=SubjectSpec(common_name="api.example.com", organization="Example Corp", country="US"),
#     extensions=ExtensionsSpec(
#         dns_names=("api.example.com", "www.example.com"),
#         key_usage={"digital_signature": True, "key_encipherment": True},
#         extended_key_usage=("serverAuth", "clientAuth"),
#         tls_must_staple=False,
#     ),
#     signing_hash="SHA256",
# )
# pk_pem, csr_pem, spki = generate_csr(req, key_password=None)
# result = verify_csr(csr_pem, CSRPolicy(san_dns_allow_patterns=("*.example.com", "api.example.com")))
# assert result.ok, result.errors
#
# Примечание: для продакшена храните ключи в HSM/KMS; данный модуль не управляет хранением ключей.
