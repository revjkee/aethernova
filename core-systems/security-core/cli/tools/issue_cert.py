# security-core/cli/tools/issue_cert.py
# Industrial X.509 issuance CLI for security-core.
# Requires: cryptography>=41
#
# Subcommands:
#   init-ca      - create new (root/intermediate) CA key+cert
#   gen-key      - generate private key (RSA/ECDSA/Ed25519)
#   gen-csr      - generate CSR from existing key and subject/SAN
#   issue        - issue certificate from CSR using CA key+cert, with full extensions
#   print        - print certificate/CSR/key details
#
# Secure defaults:
#   - RSA 3072, EC P-256, Ed25519
#   - Serial: 128-bit random (positive)
#   - BasicConstraints, KeyUsage, ExtendedKeyUsage
#   - SubjectKeyIdentifier, AuthorityKeyIdentifier
#   - AIA (OCSP, caIssuers) / CRL DP (optional)
#   - Files written atomically with 0o600 perms
#
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import secrets
import sys
import tempfile
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID

# --------------------------
# Utilities
# --------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _write_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(path.parent)) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)
    os.chmod(path, mode)

def _read_file(path: Path) -> bytes:
    return Path(path).read_bytes()

def _parse_password(pw_arg: Optional[str]) -> Optional[bytes]:
    if not pw_arg:
        return None
    if pw_arg.startswith("env:"):
        v = os.getenv(pw_arg[4:])
        return v.encode() if v is not None else None
    if pw_arg == "prompt":
        import getpass
        return getpass.getpass("Enter password: ").encode()
    return pw_arg.encode()

def _rand_serial_128() -> int:
    # Positive 128-bit integer (avoid MSB set to keep positive in ASN.1 INTEGER)
    b = bytearray(secrets.token_bytes(16))
    b[0] &= 0x7F
    return int.from_bytes(b, "big")

def _parse_subject(subject_str: str) -> x509.Name:
    """
    subject_str example: 'CN=example.com,O=Example Ltd,C=SE,L=Stockholm,OU=IT'
    """
    parts = []
    for item in subject_str.split(","):
        k, _, v = item.strip().partition("=")
        k = k.strip().upper()
        v = v.strip()
        if not k or not v:
            continue
        oid = {
            "CN": NameOID.COMMON_NAME,
            "C": NameOID.COUNTRY_NAME,
            "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "L": NameOID.LOCALITY_NAME,
            "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "EMAIL": NameOID.EMAIL_ADDRESS,
            "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
            "SN": NameOID.SURNAME,
            "GN": NameOID.GIVEN_NAME,
            "SERIALNUMBER": NameOID.SERIAL_NUMBER,
        }.get(k)
        if not oid:
            raise ValueError(f"Unsupported RDN: {k}")
        parts.append(x509.NameAttribute(oid, v))
    return x509.Name(parts)

def _parse_san_list(s: Optional[str]) -> List[x509.GeneralName]:
    """
    san string example: 'dns:example.com,dns:www.example.com,ip:10.0.0.1,email:admin@example.com,uri:https://a/b'
    """
    if not s:
        return []
    out: List[x509.GeneralName] = []
    for item in s.split(","):
        item = item.strip()
        if not item:
            continue
        kind, _, value = item.partition(":")
        k = kind.strip().lower()
        v = value.strip()
        if k == "dns":
            out.append(x509.DNSName(v))
        elif k == "ip":
            out.append(x509.IPAddress(ipaddress.ip_address(v)))
        elif k == "email":
            out.append(x509.RFC822Name(v))
        elif k == "uri":
            out.append(x509.UniformResourceIdentifier(v))
        else:
            raise ValueError(f"Unsupported SAN entry: {item}")
    return out

def _load_key(path: Path, password: Optional[bytes]) -> serialization.PrivateFormat:
    return load_pem_private_key(_read_file(path), password=password)

def _dump_key_private_pem(key, password: Optional[bytes]) -> bytes:
    enc = serialization.NoEncryption() if not password else serialization.BestAvailableEncryption(password)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )

def _dump_cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def _dump_csr_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)

def _subject_key_identifier(pubkey) -> x509.SubjectKeyIdentifier:
    spki = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA1())
    digest.update(spki)
    return x509.SubjectKeyIdentifier(digest.finalize())

def _authority_key_identifier(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest \
        if issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier) else None
    return x509.AuthorityKeyIdentifier(key_identifier=ski,
                                       authority_cert_issuer=[x509.DirectoryName(issuer_cert.subject)],
                                       authority_cert_serial_number=issuer_cert.serial_number)

# --------------------------
# Key generation
# --------------------------

def gen_key(ktype: str, rsa_bits: int, curve: str) -> serialization.PrivateFormat:
    ktype = ktype.lower()
    if ktype == "rsa":
        if rsa_bits not in (2048, 3072, 4096):
            raise ValueError("RSA bits must be 2048/3072/4096")
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    if ktype == "ec":
        c = {"p256": ec.SECP256R1(), "p384": ec.SECP384R1(), "p521": ec.SECP521R1()}.get(curve.lower())
        if not c:
            raise ValueError("Unsupported curve (use p256/p384/p521)")
        return ec.generate_private_key(c)
    if ktype == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError("Unsupported key type (rsa/ec/ed25519)")

# --------------------------
# CSR generation
# --------------------------

def build_csr(key, subject: x509.Name, san: List[x509.GeneralName], add_basic_constraints_ca: bool = False) -> x509.CertificateSigningRequest:
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if add_basic_constraints_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    # Sign CSR
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return builder.sign(key, algorithm=None)
    return builder.sign(key, hashes.SHA256())

# --------------------------
# Certificate issuance
# --------------------------

def issue_from_csr(
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key,
    *,
    days: int,
    is_ca: bool,
    path_len: Optional[int],
    key_usage: str,
    eku_server: bool,
    eku_client: bool,
    ocsp_url: Optional[str],
    ca_issuers_url: Optional[str],
    crl_urls: List[str],
    not_before_skew_min: int = 5,
) -> x509.Certificate:
    if not csr.is_signature_valid:
        raise ValueError("CSR signature invalid")

    subject = csr.subject
    san_ext = None
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san_ext = None

    # Validity
    not_before = _utcnow() - timedelta(minutes=max(0, not_before_skew_min))
    not_after = not_before + timedelta(days=days)

    serial = _rand_serial_128()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # BasicConstraints
    builder = builder.add_extension(x509.BasicConstraints(ca=is_ca, path_length=(path_len if is_ca else None)), critical=True)

    # SKI/AKI
    builder = builder.add_extension(_subject_key_identifier(csr.public_key()), critical=False)
    # Ensure issuer has SKI
    try:
        issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        # Add synthetic AKI without key id if absent
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(key_identifier=None,
                                        authority_cert_issuer=[x509.DirectoryName(issuer_cert.subject)],
                                        authority_cert_serial_number=issuer_cert.serial_number),
            critical=False,
        )
    else:
        builder = builder.add_extension(_authority_key_identifier(issuer_cert), critical=False)

    # SAN from CSR
    if san_ext:
        builder = builder.add_extension(san_ext, critical=False)

    # Key Usage
    ku_map = {
        "server": x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        "client": x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        "ca": x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        "code": x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
    }
    if key_usage not in ku_map:
        raise ValueError("Unsupported key_usage (server|client|ca|code)")
    builder = builder.add_extension(ku_map[key_usage], critical=True)

    # Extended Key Usage
    eku_oids = []
    if eku_server:
        eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if eku_client:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if key_usage == "code":
        eku_oids.append(ExtendedKeyUsageOID.CODE_SIGNING)
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)

    # AIA (OCSP, caIssuers)
    aia_list = []
    if ocsp_url:
        aia_list.append(x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)))
    if ca_issuers_url:
        aia_list.append(x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(ca_issuers_url)))
    if aia_list:
        builder = builder.add_extension(x509.AuthorityInformationAccess(aia_list), critical=False)

    # CRL Distribution Points
    if crl_urls:
        dps = [x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(u)], relative_name=None,
                                      reasons=None, crl_issuer=None) for u in crl_urls]
        builder = builder.add_extension(x509.CRLDistributionPoints(dps), critical=False)

    # Sign
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(private_key=issuer_key, algorithm=None)
    else:
        cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert

# --------------------------
# Printing helpers
# --------------------------

def print_cert(cert: x509.Certificate) -> None:
    data = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": f"{cert.serial_number:0x}",
        "not_before": cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat(),
        "not_after": cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat(),
        "version": int(cert.version.value),
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "extensions": [],
    }
    for ext in cert.extensions:
        try:
            v = ext.value
            data["extensions"].append({
                "oid": ext.oid.dotted_string,
                "name": ext.oid._name,  # type: ignore
                "critical": ext.critical,
                "value": str(v),
            })
        except Exception:
            pass
    print(json.dumps(data, indent=2, ensure_ascii=False))

def print_csr(csr: x509.CertificateSigningRequest) -> None:
    data = {
        "subject": csr.subject.rfc4514_string(),
        "extensions": [],
        "signature_valid": csr.is_signature_valid,
    }
    for ext in csr.extensions:
        data["extensions"].append({
            "oid": ext.oid.dotted_string,
            "name": ext.oid._name,  # type: ignore
            "critical": ext.critical,
            "value": str(ext.value),
        })
    print(json.dumps(data, indent=2, ensure_ascii=False))

# --------------------------
# CLI subcommands
# --------------------------

def cmd_init_ca(args: argparse.Namespace) -> int:
    key = gen_key(args.key_type, args.rsa_bits, args.curve)
    subject = _parse_subject(args.subject)
    is_root = args.is_root
    days = args.days
    pathlen = args.path_length

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed root or self-issued intermediate (temporary)
        .public_key(key.public_key())
        .serial_number(_rand_serial_128())
        .not_valid_before(_utcnow() - timedelta(minutes=5))
        .not_valid_after(_utcnow() + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        .add_extension(_subject_key_identifier(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False
        ), critical=True)
    )

    if isinstance(key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(private_key=key, algorithm=None)
    else:
        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    # Save
    if args.out_key:
        _write_atomic(Path(args.out_key), _dump_key_private_pem(key, _parse_password(args.key_passout)))
    if args.out_cert:
        _write_atomic(Path(args.out_cert), _dump_cert_pem(cert))

    # Print info if needed
    if not args.quiet:
        print("CA certificate created")
        print_cert(cert)
    return 0

def cmd_gen_key(args: argparse.Namespace) -> int:
    key = gen_key(args.key_type, args.rsa_bits, args.curve)
    pem = _dump_key_private_pem(key, _parse_password(args.passout))
    _write_atomic(Path(args.out_key), pem)
    if not args.quiet:
        print(f"Wrote private key: {args.out_key}")
    return 0

def cmd_gen_csr(args: argparse.Namespace) -> int:
    key = _load_key(Path(args.key), _parse_password(args.passin))
    subject = _parse_subject(args.subject)
    san = _parse_san_list(args.san)
    csr = build_csr(key, subject, san, add_basic_constraints_ca=args.add_ca_bc)
    _write_atomic(Path(args.out_csr), _dump_csr_pem(csr))
    if not args.quiet:
        print(f"Wrote CSR: {args.out_csr}")
    return 0

def cmd_issue(args: argparse.Namespace) -> int:
    csr = x509.load_pem_x509_csr(_read_file(Path(args.csr)))
    issuer_cert = x509.load_pem_x509_certificate(_read_file(Path(args.ca_cert)))
    issuer_key = _load_key(Path(args.ca_key), _parse_password(args.ca_passin))

    cert = issue_from_csr(
        csr=csr,
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        days=args.days,
        is_ca=args.is_ca,
        path_len=args.path_length,
        key_usage=args.key_usage,
        eku_server=args.eku_server,
        eku_client=args.eku_client,
        ocsp_url=args.ocsp_url,
        ca_issuers_url=args.ca_issuers_url,
        crl_urls=args.crl_url or [],
        not_before_skew_min=args.not_before_skew_min,
    )

    _write_atomic(Path(args.out_cert), _dump_cert_pem(cert))
    if args.chain and Path(args.chain).exists():
        # append chain file (issuer and above) if provided
        with open(args.out_cert, "ab") as f:
            f.write(_read_file(Path(args.chain)))

    if not args.quiet:
        print(f"Issued certificate to: {args.out_cert}")
        print_cert(cert)
    return 0

def cmd_print(args: argparse.Namespace) -> int:
    p = Path(args.input)
    data = _read_file(p)
    if b"BEGIN CERTIFICATE" in data:
        cert = x509.load_pem_x509_certificate(data)
        print_cert(cert)
        return 0
    if b"BEGIN CERTIFICATE REQUEST" in data or b"BEGIN NEW CERTIFICATE REQUEST" in data:
        csr = x509.load_pem_x509_csr(data)
        print_csr(csr)
        return 0
    if b"BEGIN PRIVATE KEY" in data or b"BEGIN RSA PRIVATE KEY" in data or b"BEGIN EC PRIVATE KEY" in data:
        try:
            key = load_pem_private_key(data, password=_parse_password(args.passin))
            pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            print(pub.decode().strip())
            return 0
        except Exception as e:
            print(f"Failed to parse key: {e}", file=sys.stderr)
            return 2
    print("Unrecognized input format", file=sys.stderr)
    return 2

# --------------------------
# Argparse
# --------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="issue_cert",
        description="PKI issuance tool for security-core",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Init root CA (P-256), valid 3650 days
              issue_cert init-ca --subject "CN=Root CA,O=Example,C=SE" --key-type ec --curve p256 --days 3650 --out-key root.key --out-cert root.crt

              # Generate RSA key and CSR with SAN
              issue_cert gen-key --key-type rsa --rsa-bits 3072 --out-key srv.key
              issue_cert gen-csr --key srv.key --subject "CN=api.example.com,O=Example" --san "dns:api.example.com,dns:api" --out-csr srv.csr

              # Issue server certificate for 397 days with AIA/CRL
              issue_cert issue --csr srv.csr --ca-cert root.crt --ca-key root.key --days 397 \
                --key-usage server --eku-server --ocsp-url "http://ocsp.example.com" --ca-issuers-url "http://ca.example.com/ca.crt" \
                --crl-url "http://ca.example.com/root.crl" --out-cert srv.crt
        """),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # init-ca
    sp = sub.add_parser("init-ca", help="Initialize new CA (root/intermediate)")
    sp.add_argument("--subject", required=True, help='e.g. "CN=Root CA,O=Org,C=SE"')
    sp.add_argument("--key-type", choices=["rsa", "ec", "ed25519"], default="ec")
    sp.add_argument("--rsa-bits", type=int, default=3072)
    sp.add_argument("--curve", choices=["p256", "p384", "p521"], default="p256")
    sp.add_argument("--days", type=int, default=3650)
    sp.add_argument("--path-length", type=int, default=None, help="Max path length for CA (None for unlimited)")
    sp.add_argument("--is-root", action="store_true", help="Mark as self-signed root (default true for self-signed)")
    sp.add_argument("--out-key", required=True)
    sp.add_argument("--out-cert", required=True)
    sp.add_argument("--key-passout", help="Password for private key: plain | env:VAR | prompt")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_init_ca)

    # gen-key
    sp = sub.add_parser("gen-key", help="Generate private key")
    sp.add_argument("--key-type", choices=["rsa", "ec", "ed25519"], default="rsa")
    sp.add_argument("--rsa-bits", type=int, default=3072)
    sp.add_argument("--curve", choices=["p256", "p384", "p521"], default="p256")
    sp.add_argument("--out-key", required=True)
    sp.add_argument("--passout", help="Password for private key: plain | env:VAR | prompt")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_gen_key)

    # gen-csr
    sp = sub.add_parser("gen-csr", help="Generate CSR")
    sp.add_argument("--key", required=True)
    sp.add_argument("--passin", help="Password to read private key: plain | env:VAR | prompt")
    sp.add_argument("--subject", required=True)
    sp.add_argument("--san", help='Comma-separated SAN entries, e.g. "dns:a,ip:1.2.3.4,email:u@e,uri:https://a"')
    sp.add_argument("--add-ca-bc", action="store_true", help="Add BasicConstraints CA=true to CSR (for intermediates)")
    sp.add_argument("--out-csr", required=True)
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_gen_csr)

    # issue
    sp = sub.add_parser("issue", help="Issue certificate from CSR")
    sp.add_argument("--csr", required=True)
    sp.add_argument("--ca-cert", required=True)
    sp.add_argument("--ca-key", required=True)
    sp.add_argument("--ca-passin", help="Password to read CA key: plain | env:VAR | prompt")
    sp.add_argument("--days", type=int, default=397, help="Validity days (<=398 recommended for browsers)")
    sp.add_argument("--is-ca", action="store_true", help="Issue a CA certificate (intermediate)")
    sp.add_argument("--path-length", type=int, default=None, help="Path length constraint when --is-ca")
    sp.add_argument("--key-usage", choices=["server", "client", "ca", "code"], default="server")
    sp.add_argument("--eku-server", action="store_true", help="Add EKU: serverAuth")
    sp.add_argument("--eku-client", action="store_true", help="Add EKU: clientAuth")
    sp.add_argument("--ocsp-url", help="AIA: OCSP URL")
    sp.add_argument("--ca-issuers-url", help="AIA: caIssuers URL")
    sp.add_argument("--crl-url", action="append", help="CRL Distribution Point URL (can repeat)")
    sp.add_argument("--not-before-skew-min", type=int, default=5, help="Backdate NotBefore by N minutes")
    sp.add_argument("--out-cert", required=True)
    sp.add_argument("--chain", help="Append chain PEM file to out-cert")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_issue)

    # print
    sp = sub.add_parser("print", help="Print information about CERT/CSR/KEY")
    sp.add_argument("--input", required=True)
    sp.add_argument("--passin", help="Password for key (if input is key): plain | env:VAR | prompt")
    sp.set_defaults(func=cmd_print)

    return p

def main(argv: Optional[List[str]] = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
