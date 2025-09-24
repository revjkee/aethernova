# security-core/tests/unit/test_pki_certs.py
# Требования: pytest, cryptography
# Тестируем модуль выпуска сертификатов: security.cli.tools.issue_cert
# и вычисление x5t#S256: security.tokens.bind_mtls

from __future__ import annotations

import math
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    AuthorityInformationAccessOID,
)

# Модули проекта
from security.cli.tools import issue_cert as ic
from security.tokens import bind_mtls as bmtls


# -----------------------------
# Вспомогательные функции
# -----------------------------

def _utcnow():
    return datetime.now(timezone.utc)

def _make_ca(key_type: str = "ec", rsa_bits: int = 3072, curve: str = "p256", days: int = 3650, path_length: int | None = 1):
    # Генерируем ключ CA
    key = ic.gen_key(key_type, rsa_bits, curve)
    subject = ic._parse_subject("CN=Test Root CA,O=SecCore,C=SE")
    # Построение self-signed CA: зеркалим логику init-ca
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(ic._rand_serial_128())
        .not_valid_before(_utcnow() - timedelta(minutes=5))
        .not_valid_after(_utcnow() + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(ic._subject_key_identifier(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False
            ),
            critical=True
        )
    )
    if isinstance(key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(private_key=key, algorithm=None)
    else:
        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return key, cert

def _issue_leaf(
    ca_key,
    ca_cert: x509.Certificate,
    *,
    key_type: str = "rsa",
    rsa_bits: int = 3072,
    curve: str = "p256",
    subject_str: str = "CN=api.example.test,O=SecCore,C=SE",
    san_str: str = "dns:api.example.test,dns:api,ip:10.0.0.10,email:admin@example.test,uri:https://api.example.test/health",
    days: int = 397,
    key_usage: str = "server",
    eku_server: bool = True,
    eku_client: bool = False,
    ocsp_url: str | None = "http://ocsp.example.test",
    ca_issuers_url: str | None = "http://ca.example.test/ca.crt",
    crl_urls: list[str] | None = None,
    not_before_skew_min: int = 5,
):
    crl_urls = crl_urls or ["http://ca.example.test/root.crl"]
    leaf_key = ic.gen_key(key_type, rsa_bits, curve)
    csr = ic.build_csr(
        key=leaf_key,
        subject=ic._parse_subject(subject_str),
        san=ic._parse_san_list(san_str),
        add_basic_constraints_ca=False,
    )
    cert = ic.issue_from_csr(
        csr=csr,
        issuer_cert=ca_cert,
        issuer_key=ca_key,
        days=days,
        is_ca=False,
        path_len=None,
        key_usage=key_usage,
        eku_server=eku_server,
        eku_client=eku_client,
        ocsp_url=ocsp_url,
        ca_issuers_url=ca_issuers_url,
        crl_urls=crl_urls,
        not_before_skew_min=not_before_skew_min,
    )
    return leaf_key, cert, csr


# -----------------------------
# Фикстуры
# -----------------------------

@pytest.fixture(params=["rsa", "ec", "ed25519"])
def ca_pair(request):
    key, cert = _make_ca(key_type=request.param)
    return request.param, key, cert


# -----------------------------
# Тесты
# -----------------------------

def test_serial_is_positive_128bit():
    for _ in range(64):
        s = ic._rand_serial_128()
        # 0 < s < 2^127 (старший бит очищен)
        assert s > 0
        assert s.bit_length() <= 127
        # Проверяем, что не «короткие» — статистически должны быть >= 96 бит
        assert s.bit_length() >= 96

def test_issue_server_cert_extensions(ca_pair):
    _, ca_key, ca_cert = ca_pair
    leaf_key, cert, csr = _issue_leaf(
        ca_key, ca_cert,
        key_type="rsa", key_usage="server", eku_server=True, eku_client=False
    )

    # Basic constraints
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    assert bc.path_length is None

    # KU server profile
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True
    assert ku.key_encipherment or ku.key_agreement  # для RSA включается encipherment, для EC — keyAgreement

    # EKU serverAuth
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    # SAN перенесён из CSR
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {type(x): x for x in san}
    assert any(getattr(x, "value", "").startswith("api.") for x in san)
    # есть IP и email
    assert any(x for x in san if isinstance(x, x509.IPAddress))
    assert any(x for x in san if isinstance(x, x509.RFC822Name))

    # AIA: OCSP и caIssuers при наличии
    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    methods = {d.access_method for d in aia}
    assert AuthorityInformationAccessOID.OCSP in methods
    assert AuthorityInformationAccessOID.CA_ISSUERS in methods

    # CRLDP
    crldp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    urls = []
    for dp in crldp:
        for n in (dp.full_name or []):
            if isinstance(n, x509.UniformResourceIdentifier):
                urls.append(n.value)
    assert urls and urls[0].startswith("http://")

def test_client_cert_eku_and_usage(ca_pair):
    _, ca_key, ca_cert = ca_pair
    _, cert, _ = _issue_leaf(
        ca_key, ca_cert,
        key_type="ec", key_usage="client", eku_server=False, eku_client=True
    )
    # KU client — без key_encipherment (EC), но digital_signature и key_agreement True
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True
    # EKU clientAuth
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

def test_code_signing_profile(ca_pair):
    _, ca_key, ca_cert = ca_pair
    _, cert, _ = _issue_leaf(
        ca_key, ca_cert,
        key_type="ec", key_usage="code", eku_server=False, eku_client=False
    )
    # EKU codeSigning
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CODE_SIGNING in eku
    # KU: digital_signature и content_commitment True
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True
    assert ku.content_commitment is True

def test_ski_aki_chain_link(ca_pair):
    _, ca_key, ca_cert = ca_pair
    _, cert, _ = _issue_leaf(ca_key, ca_cert, key_type="rsa")
    # SKI leaf
    leaf_ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    # AKI leaf
    leaf_aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    # SKI issuer
    issuer_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    # key_identifier в AKI совпадает с SKI issuer
    assert leaf_aki.key_identifier == issuer_ski.digest

def test_not_before_backdated(ca_pair):
    _, ca_key, ca_cert = ca_pair
    skew = 10
    _, cert, _ = _issue_leaf(ca_key, ca_cert, not_before_skew_min=skew)
    # NotBefore отодвинут назад >= skew-1 минут (допускаем небольшие расхождения по времени выполнения)
    delta = _utcnow() - cert.not_valid_before.replace(tzinfo=timezone.utc)
    assert delta >= timedelta(minutes=skew - 1)

@pytest.mark.parametrize("key_type,expected_oid", [
    ("ed25519", "1.3.101.112"),  # Ed25519
    ("rsa", None),               # OID проверять не будем, достаточно что не EdDSA
])
def test_signature_algorithm_oid_by_issuer_key(key_type, expected_oid):
    ca_key, ca_cert = _make_ca(key_type=key_type)
    _, cert, _ = _issue_leaf(ca_key, ca_cert, key_type="rsa")
    oid = cert.signature_algorithm_oid.dotted_string
    if expected_oid is None:
        assert oid != "1.3.101.112"
    else:
        assert oid == expected_oid

def test_x5t_s256_matches_bind_mtls(ca_pair):
    _, _, ca_cert = ca_pair
    der = ca_cert.public_bytes(serialization.Encoding.DER)
    # Из функции bind_mtls
    from_bind = bmtls.cert_thumbprint_sha256(der)
    # Прямой расчет: base64url(sha256(der))
    dig = hashes.Hash(hashes.SHA256()); dig.update(der)
    want = ic.b64url_encode(dig.finalize()) if hasattr(ic, "b64url_encode") else __import__("base64").urlsafe_b64encode(dig.finalize()).decode("ascii").rstrip("=")
    assert from_bind == want

@pytest.mark.parametrize("profile", ["server", "client", "ca", "code"])
def test_key_usage_profiles(profile, ca_pair):
    _, ca_key, ca_cert = ca_pair
    if profile == "ca":
        # Выпускаем промежуточный CA
        inter_key = ic.gen_key("ec", 3072, "p256")
        csr = ic.build_csr(inter_key, ic._parse_subject("CN=InterCA,O=SecCore,C=SE"), [], add_basic_constraints_ca=True)
        cert = ic.issue_from_csr(
            csr=csr, issuer_cert=ca_cert, issuer_key=ca_key,
            days=1825, is_ca=True, path_len=0, key_usage="ca",
            eku_server=False, eku_client=False, ocsp_url=None, ca_issuers_url=None, crl_urls=[]
        )
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True and bc.path_length == 0
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign and ku.crl_sign
    else:
        # Листовой профиль
        _, cert, _ = _issue_leaf(ca_key, ca_cert, key_type="rsa", key_usage=profile,
                                 eku_server=(profile=="server"), eku_client=(profile=="client"))
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if profile == "server":
            assert ku.digital_signature and (ku.key_encipherment or ku.key_agreement)
        if profile == "client":
            assert ku.digital_signature and ku.key_agreement
        if profile == "code":
            assert ku.digital_signature and ku.content_commitment

def test_pem_der_roundtrip_leaf(ca_pair):
    _, ca_key, ca_cert = ca_pair
    _, cert, _ = _issue_leaf(ca_key, ca_cert, key_type="ec")
    pem = cert.public_bytes(serialization.Encoding.PEM)
    der = cert.public_bytes(serialization.Encoding.DER)
    cert_from_pem = x509.load_pem_x509_certificate(pem)
    cert_from_der = x509.load_der_x509_certificate(der)
    assert cert_from_pem.fingerprint(hashes.SHA256()) == cert_from_der.fingerprint(hashes.SHA256())

def test_print_helpers_json(capsys, ca_pair):
    # Проверяем, что print_cert выводит валидный JSON с ключевыми полями
    _, ca_key, ca_cert = ca_pair
    _, cert, _ = _issue_leaf(ca_key, ca_cert)
    ic.print_cert(cert)
    out = capsys.readouterr().out
    assert '"subject"' in out and '"issuer"' in out and '"not_before"' in out and '"extensions"' in out
