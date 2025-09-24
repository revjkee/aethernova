# security-core/tests/chaos/test_key_compromise_drill.py
# Требования: pytest, cryptography
# Цель: смоделировать компрометацию ключа промежуточного CA, выпуск CRL, ротацию CA, проверку отказа старой цепочки и валидности новой.

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID

# Используем наши утилиты выпуска
from security.cli.tools import issue_cert as ic


# ---------------------------
# Вспомогательные утилиты
# ---------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _make_root_ca(days: int = 3650):
    key = ic.gen_key("ec", 3072, "p256")
    subject = ic._parse_subject("CN=RootCA,O=SecCore,C=SE")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(ic._rand_serial_128())
        .not_valid_before(_utcnow() - timedelta(minutes=5))
        .not_valid_after(_utcnow() + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
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
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return key, cert

def _issue_intermediate(root_key, root_cert, name: str = "IntCA", days: int = 1825, path_len: int = 1):
    int_key = ic.gen_key("ec", 3072, "p256")
    csr = ic.build_csr(
        key=int_key,
        subject=ic._parse_subject(f"CN={name},O=SecCore,C=SE"),
        san=[],  # для CA SAN не требуется
        add_basic_constraints_ca=True,
    )
    int_cert = ic.issue_from_csr(
        csr=csr, issuer_cert=root_cert, issuer_key=root_key,
        days=days, is_ca=True, path_len=path_len, key_usage="ca",
        eku_server=False, eku_client=False,
        ocsp_url=None, ca_issuers_url=None, crl_urls=[]
    )
    return int_key, int_cert

def _issue_leaf(int_key, int_cert, cn: str = "api.example.test"):
    csr = ic.build_csr(
        key=ic.gen_key("rsa", 3072, "p256"),  # генерируем отдельный ключ листового
        subject=ic._parse_subject(f"CN={cn},O=SecCore,C=SE"),
        san=ic._parse_san_list(f"dns:{cn},dns:api,ip:10.0.0.10,email:admin@{cn}"),
        add_basic_constraints_ca=False,
    )
    leaf_cert = ic.issue_from_csr(
        csr=csr, issuer_cert=int_cert, issuer_key=int_key,
        days=397, is_ca=False, path_len=None, key_usage="server",
        eku_server=True, eku_client=False,
        ocsp_url="http://ocsp.example.test", ca_issuers_url="http://ca.example.test/ca.crt",
        crl_urls=["http://ca.example.test/int.crl"], not_before_skew_min=5,
    )
    return leaf_cert

def _crl_build(
    issuer_key,
    issuer_cert: x509.Certificate,
    revoked: List[Tuple[int, x509.ReasonFlags]],
    crl_number: int,
    next_update_days: int = 7,
) -> x509.CertificateRevocationList:
    now = _utcnow()
    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=next_update_days))
    )
    # Authority Key Identifier для CRL (не обязателен, но полезен)
    try:
        ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        ski = None
    b = b.add_extension(
        x509.AuthorityKeyIdentifier(key_identifier=ski, authority_cert_issuer=None, authority_cert_serial_number=None),
        critical=False
    )
    b = b.add_extension(x509.CRLNumber(crl_number), critical=False)

    for serial, reason in revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now - timedelta(minutes=1))
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
        b = b.add_revoked_certificate(entry)

    # Подпись CRL ключом издателя (Root для IntCA, IntCA для своих листовых)
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        return b.sign(private_key=issuer_key, algorithm=None)
    return b.sign(private_key=issuer_key, algorithm=hashes.SHA256())

def _is_revoked(crl: x509.CertificateRevocationList, serial: int) -> Optional[x509.ReasonFlags]:
    try:
        entry = next(e for e in crl if e.serial_number == serial)
    except StopIteration:
        return None
    # Вернём причину если указана
    try:
        ext = entry.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON).value
        return ext.reason
    except x509.ExtensionNotFound:
        return x509.ReasonFlags.unspecified

def _verify_cert_sig(child: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    data = child.tbs_certificate_bytes
    sig = child.signature
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, data, padding.PKCS1v15(), child.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, data, ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(sig, data)
    else:
        raise AssertionError("Unsupported issuer key type")

def _assert_validity(cert: x509.Certificate) -> None:
    now = _utcnow()
    assert cert.not_valid_before <= now <= cert.not_valid_after, "certificate not within validity window"

def _validate_path_with_crls(
    leaf: x509.Certificate,
    intermediate: x509.Certificate,
    root: x509.Certificate,
    crls_by_issuer_subject: Dict[x509.Name, x509.CertificateRevocationList],
) -> None:
    # 1) Проверяем подпись и даты leaf <- IntCA
    _verify_cert_sig(leaf, intermediate)
    _assert_validity(leaf)
    # CRL от IntCA (для листовых) — если есть
    crl_int = crls_by_issuer_subject.get(intermediate.subject)
    if crl_int is not None:
        reason = _is_revoked(crl_int, leaf.serial_number)
        assert reason is None, f"leaf revoked (reason={reason})"

    # 2) Проверяем подпись и даты IntCA <- Root
    _verify_cert_sig(intermediate, root)
    _assert_validity(intermediate)
    # CRL от Root (для IntCA)
    crl_root = crls_by_issuer_subject.get(root.subject)
    if crl_root is not None:
        reason = _is_revoked(crl_root, intermediate.serial_number)
        assert reason is None, f"intermediate revoked (reason={reason})"

    # 3) Root самоподписан — проверим согласованность
    _verify_cert_sig(root, root)
    _assert_validity(root)

# ---------------------------
# Тест-дри́лл: компрометация IntCA
# ---------------------------

def test_key_compromise_drill_intermediate_revoked_and_rotated():
    # 0) Исходное состояние: Root -> IntCA1 -> Leaf1
    root_key, root_cert = _make_root_ca()
    int1_key, int1_cert = _issue_intermediate(root_key, root_cert, name="IntCA-1")
    leaf1_cert = _issue_leaf(int1_key, int1_cert, cn="api.pre.example.test")

    # Базовая валидация без CRL (должна проходить)
    _validate_path_with_crls(leaf1_cert, int1_cert, root_cert, crls_by_issuer_subject={})

    # 1) Инцидент: компрометация IntCA-1. Root выпускает CRL, отзывающий сертификат IntCA-1
    crl_root_v1 = _crl_build(
        issuer_key=root_key,
        issuer_cert=root_cert,
        revoked=[(int1_cert.serial_number, x509.ReasonFlags.key_compromise)],
        crl_number=1,
    )
    # Дополнительно IntCA-1 отзывает уже выданный листовой сертификат (опционально)
    crl_int1_v1 = _crl_build(
        issuer_key=int1_key,
        issuer_cert=int1_cert,
        revoked=[(leaf1_cert.serial_number, x509.ReasonFlags.cessation_of_operation)],
        crl_number=1,
    )

    # 2) Ротация: создаётся новая IntCA-2 и новый Leaf2
    int2_key, int2_cert = _issue_intermediate(root_key, root_cert, name="IntCA-2")
    leaf2_cert = _issue_leaf(int2_key, int2_cert, cn="api.post.example.test")

    # 3) Проверяем, что старая цепочка блокируется CRL Root (IntCA-1 отозван)
    with pytest.raises(AssertionError) as e1:
        _validate_path_with_crls(
            leaf1_cert, int1_cert, root_cert,
            crls_by_issuer_subject={root_cert.subject: crl_root_v1}
        )
    assert "intermediate revoked" in str(e1.value)

    # 4) Проверяем, что новая цепочка валидна под тем же Root, CRL указывает только на старую IntCA
    _validate_path_with_crls(
        leaf2_cert, int2_cert, root_cert,
        crls_by_issuer_subject={root_cert.subject: crl_root_v1}
    )

    # 5) При наличии CRL от IntCA-1 старая листовая тоже должна быть явно отозвана
    reason = _is_revoked(crl_int1_v1, leaf1_cert.serial_number)
    assert reason == x509.ReasonFlags.cessation_of_operation

    # 6) CRL-метаданные: номер CRL и AuthorityKeyIdentifier присутствуют
    crl_num = crl_root_v1.extensions.get_extension_for_class(x509.CRLNumber).value
    assert int(crl_num.crl_number) == 1
    aki = crl_root_v1.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    assert aki is not None

def test_chain_rejected_if_leaf_revoked_even_with_valid_intermediate():
    # 1) Строим Root -> IntCA -> Leaf, валидируем
    root_key, root_cert = _make_root_ca()
    int_key, int_cert = _issue_intermediate(root_key, root_cert, name="IntCA-A")
    leaf_cert = _issue_leaf(int_key, int_cert, cn="api.revoked.example.test")
    _validate_path_with_crls(leaf_cert, int_cert, root_cert, crls_by_issuer_subject={})

    # 2) IntCA отзывает листовой
    crl_int_v2 = _crl_build(
        issuer_key=int_key,
        issuer_cert=int_cert,
        revoked=[(leaf_cert.serial_number, x509.ReasonFlags.key_compromise)],
        crl_number=2,
    )

    # 3) Цепочка должна быть отклонена при проверке CRL IntCA
    with pytest.raises(AssertionError) as e2:
        _validate_path_with_crls(
            leaf_cert, int_cert, root_cert,
            crls_by_issuer_subject={int_cert.subject: crl_int_v2}
        )
    assert "leaf revoked" in str(e2.value)

def test_crl_signature_and_dates_are_valid():
    # Проверяем корректность подписи CRL и временных полей
    root_key, root_cert = _make_root_ca()
    int_key, int_cert = _issue_intermediate(root_key, root_cert, name="IntCA-B")
    crl = _crl_build(
        issuer_key=root_key, issuer_cert=root_cert,
        revoked=[(int_cert.serial_number, x509.ReasonFlags.key_compromise)],
        crl_number=10,
    )
    # Подпись CRL проверяем вручную через public_key.verify на TBSCertList
    pub = root_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm))
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(crl.signature, crl.tbs_certlist_bytes)
    else:
        pytest.skip("Unsupported key type for CRL verification")

    assert crl.last_update <= _utcnow() <= crl.next_update
    # CRLNumber присутствует и монотонно увеличивается (смоделируем новую версию)
    crl2 = _crl_build(
        issuer_key=root_key, issuer_cert=root_cert,
        revoked=[], crl_number=11
    )
    n1 = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    n2 = crl2.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert int(n2) > int(n1)
