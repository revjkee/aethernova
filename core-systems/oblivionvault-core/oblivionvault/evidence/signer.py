# oblivionvault-core/oblivionvault/evidence/signer.py
# Industrial-grade signing and verification for OblivionVault evidence.
# Copyright (c) 2025 NeuroCity
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import dataclasses
import json
import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple, Union, List

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate, Certificate
    from cryptography.x509.base import load_pem_x509_certificates
    from cryptography.x509.oid import NameOID
except Exception as e:  # pragma: no cover
    _CRYPTO_ERR = e
    ed25519 = ec = rsa = hashes = serialization = padding = None  # type: ignore
else:
    _CRYPTO_ERR = None

# Local modules
from .digests import (
    HashAlgorithm,
    Digest,
    DigestManifest,
    canonical_json_dumps,
    hash_file,
    hash_dir,
    hash_bytes,
    compare_digests_ct,
)

__all__ = [
    "SignAlgorithm",
    "SignError",
    "VerifyError",
    "KeyProvider",
    "SoftKeyProvider",
    "Signer",
    "Verifier",
    "Envelope",
    "EnvelopeType",
    "load_pem_private_key",
    "load_pem_public_key",
    "load_pem_cert",
    "compute_kid_from_public_key",
]

__version__ = "1.0.0"


# ==============================
# Errors
# ==============================

class SignError(RuntimeError):
    pass


class VerifyError(RuntimeError):
    pass


# ==============================
# Utilities
# ==============================

def _require_crypto():
    if _CRYPTO_ERR is not None:
        raise SignError(
            "cryptography package is required for signer.py. "
            "Install with: pip install cryptography"
        ) from _CRYPTO_ERR


def _b64u(data: bytes, strip_padding: bool = True) -> str:
    s = base64.urlsafe_b64encode(data).decode("ascii")
    return s.rstrip("=") if strip_padding else s


def _b64u_decode(data: str) -> bytes:
    # Pad to multiple of 4
    pad = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + ("=" * pad))


def _now_seconds() -> int:
    return int(time.time())


def _domain_sep(context: str) -> bytes:
    # Domain separation for TBS (to-be-signed)
    return ("oblivionvault/v1/" + context).encode("utf-8")


# ==============================
# Algorithms
# ==============================

class SignAlgorithm(str, Enum):
    ED25519 = "Ed25519"
    ECDSA_P256_SHA256 = "ES256"      # NIST P-256, SHA-256
    ECDSA_SECP256K1_SHA256 = "ES256K"  # secp256k1, SHA-256
    RSA_PSS_SHA256 = "PS256"
    RSA_PSS_SHA512 = "PS512"


# Map for JOSE-like alg to hash
_HASH_BY_ALG: Dict[SignAlgorithm, hashes.HashAlgorithm] = {
    SignAlgorithm.ECDSA_P256_SHA256: hashes.SHA256(),
    SignAlgorithm.ECDSA_SECP256K1_SHA256: hashes.SHA256(),
    SignAlgorithm.RSA_PSS_SHA256: hashes.SHA256(),
    SignAlgorithm.RSA_PSS_SHA512: hashes.SHA512(),
}


# ==============================
# Key loading and KID
# ==============================

def load_pem_private_key(pem_data: Union[bytes, str], password: Optional[bytes] = None):
    _require_crypto()
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())


def load_pem_public_key(pem_data: Union[bytes, str]):
    _require_crypto()
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def load_pem_cert(pem_data: Union[bytes, str]) -> Certificate:
    _require_crypto()
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return load_pem_x509_certificate(pem_data, backend=default_backend())


def serialize_spki_public_key(pub) -> bytes:
    _require_crypto()
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def compute_kid_from_public_key(pub) -> str:
    # kid := sha256(SPKI-DER) base64url (8 bytes truncated for compactness)
    spki = serialize_spki_public_key(pub)
    d = hash_bytes(spki, algorithm=HashAlgorithm.SHA256)
    return _b64u(d.raw[:8])  # 64-bit identifier


# ==============================
# Envelope
# ==============================

class EnvelopeType(str, Enum):
    DETACHED = "detached"
    ATTACHED = "attached"


@dataclass
class Envelope:
    type: EnvelopeType
    alg: SignAlgorithm
    kid: str
    header: Dict[str, Any]
    payload_b64: Optional[str]  # None for detached
    signature_b64: str

    def to_json(self) -> str:
        obj = {
            "type": self.type.value,
            "alg": self.alg.value,
            "kid": self.kid,
            "header": self.header,
            "payload_b64": self.payload_b64,
            "signature_b64": self.signature_b64,
        }
        return canonical_json_dumps(obj, ensure_ascii=False)

    @staticmethod
    def from_json(s: Union[str, bytes]) -> "Envelope":
        if isinstance(s, bytes):
            s = s.decode("utf-8")
        obj = json.loads(s)
        return Envelope(
            type=EnvelopeType(obj["type"]),
            alg=SignAlgorithm(obj["alg"]),
            kid=obj["kid"],
            header=obj["header"],
            payload_b64=obj.get("payload_b64"),
            signature_b64=obj["signature_b64"],
        )


# ==============================
# Key Providers (SoftKey, HSM placeholder)
# ==============================

class KeyProvider:
    def algorithm(self) -> SignAlgorithm:
        raise NotImplementedError

    def kid(self) -> str:
        raise NotImplementedError

    def public_key(self):  # cryptography public key object
        raise NotImplementedError

    def sign(self, tbs: bytes) -> bytes:
        raise NotImplementedError


@dataclass
class SoftKeyProvider(KeyProvider):
    _alg: SignAlgorithm
    _private_key: Any
    _public_key: Any
    _kid: str

    @staticmethod
    def from_pem(private_pem: Union[str, bytes], password: Optional[bytes] = None,
                 alg: Optional[SignAlgorithm] = None) -> "SoftKeyProvider":
        _require_crypto()
        priv = load_pem_private_key(private_pem, password=password)
        # Infer alg when possible
        if alg is None:
            if isinstance(priv, ed25519.Ed25519PrivateKey):
                alg = SignAlgorithm.ED25519
            elif isinstance(priv, ec.EllipticCurvePrivateKey):
                curve = priv.curve
                if isinstance(curve, ec.SECP256R1):
                    alg = SignAlgorithm.ECDSA_P256_SHA256
                elif isinstance(curve, ec.SECP256K1):
                    alg = SignAlgorithm.ECDSA_SECP256K1_SHA256
                else:
                    raise SignError(f"Unsupported EC curve: {curve.name}")
            elif isinstance(priv, rsa.RSAPrivateKey):
                alg = SignAlgorithm.RSA_PSS_SHA256
            else:
                raise SignError("Unsupported private key type")
        pub = priv.public_key()
        kid = compute_kid_from_public_key(pub)
        return SoftKeyProvider(alg, priv, pub, kid)

    def algorithm(self) -> SignAlgorithm:
        return self._alg

    def kid(self) -> str:
        return self._kid

    def public_key(self):
        return self._public_key

    def sign(self, tbs: bytes) -> bytes:
        _require_crypto()
        alg = self._alg
        if alg == SignAlgorithm.ED25519:
            return self._private_key.sign(tbs)
        elif alg in (SignAlgorithm.ECDSA_P256_SHA256, SignAlgorithm.ECDSA_SECP256K1_SHA256):
            digest = hashes.Hash(_HASH_BY_ALG[alg], backend=default_backend())
            digest.update(tbs)
            h = digest.finalize()
            return self._private_key.sign(h, ec.ECDSA(Prehashed(_HASH_BY_ALG[alg])))
        elif alg in (SignAlgorithm.RSA_PSS_SHA256, SignAlgorithm.RSA_PSS_SHA512):
            hash_alg = _HASH_BY_ALG[alg]
            return self._private_key.sign(
                tbs,
                padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hash_alg,
            )
        else:
            raise SignError(f"Unsupported algorithm: {alg.value}")


# ==============================
# Signer / Verifier
# ==============================

@dataclass
class SignOptions:
    detached: bool = True
    context: str = "evidence"
    iat: Optional[int] = None
    nbf: Optional[int] = None
    exp: Optional[int] = None
    nonce: Optional[str] = None
    # For detached: include payload_digest metadata
    payload_hash_alg: HashAlgorithm = HashAlgorithm.SHA256


class Signer:
    def __init__(self, provider: KeyProvider):
        self._provider = provider

    def sign_bytes(self, payload: bytes, *, opts: Optional[SignOptions] = None) -> Envelope:
        opts = opts or SignOptions()
        header = self._build_header(opts, payload if not opts.detached else None, payload if opts.detached else None)
        tbs = self._to_be_signed(header, payload if not opts.detached else None)
        sig = self._provider.sign(tbs)
        env = Envelope(
            type=EnvelopeType.DETACHED if opts.detached else EnvelopeType.ATTACHED,
            alg=self._provider.algorithm(),
            kid=self._provider.kid(),
            header=header,
            payload_b64=None if opts.detached else _b64u(payload),
            signature_b64=_b64u(sig),
        )
        return env

    def sign_file(self, path: Union[str, Path], *, opts: Optional[SignOptions] = None) -> Envelope:
        p = Path(path)
        data = p.read_bytes()
        return self.sign_bytes(data, opts=opts)

    def sign_dir_manifest(self, manifest: DigestManifest, *, opts: Optional[SignOptions] = None) -> Envelope:
        opts = opts or SignOptions(detached=True, context="manifest")
        data = manifest.to_json().encode("utf-8")
        return self.sign_bytes(data, opts=opts)

    # Internal

    def _build_header(self, opts: SignOptions, attached_payload: Optional[bytes], detached_payload: Optional[bytes]) -> Dict[str, Any]:
        h: Dict[str, Any] = {
            "typ": "OV-JWS",
            "cty": "application/octet-stream" if attached_payload is not None else "OV-digest",
            "ctx": opts.context,
            "alg": self._provider.algorithm().value,
            "kid": self._provider.kid(),
            "iat": opts.iat if opts.iat is not None else _now_seconds(),
        }
        if opts.nbf is not None:
            h["nbf"] = opts.nbf
        if opts.exp is not None:
            h["exp"] = opts.exp
        if opts.nonce is not None:
            h["nonce"] = opts.nonce
        if detached_payload is not None:
            d = hash_bytes(detached_payload, algorithm=opts.payload_hash_alg)
            h["payload_digest"] = {"alg": d.algorithm.value, "hex": d.hex(), "len": len(detached_payload)}
        return h

    def _to_be_signed(self, header: Dict[str, Any], payload: Optional[bytes]) -> bytes:
        # JWS-like: base64url( canon(header) ) + "." + base64url(payload or empty)
        h_json = canonical_json_dumps(header, ensure_ascii=False).encode("utf-8")
        h_b64 = _b64u(h_json).encode("ascii")
        p_b64 = _b64u(payload or b"").encode("ascii")
        return h_b64 + b"." + p_b64


class Verifier:
    def __init__(self, public_key=None, cert: Optional[Certificate] = None, ca_certs: Optional[List[Certificate]] = None):
        self._public_key = public_key
        self._cert = cert
        self._ca_certs = ca_certs or []

    def verify_envelope(self, env: Envelope, *, expected_context: Optional[str] = None, now: Optional[int] = None,
                        detached_payload: Optional[bytes] = None) -> bool:
        _require_crypto()
        # Basic header checks
        hdr = env.header
        if expected_context is not None and hdr.get("ctx") != expected_context:
            raise VerifyError("Context mismatch")
        t = now if now is not None else _now_seconds()
        if "nbf" in hdr and t < int(hdr["nbf"]):
            raise VerifyError("Signature not yet valid (nbf)")
        if "exp" in hdr and t > int(hdr["exp"]):
            raise VerifyError("Signature expired (exp)")

        # Prepare TBS
        payload: Optional[bytes]
        if env.type == EnvelopeType.ATTACHED:
            if env.payload_b64 is None:
                raise VerifyError("Attached envelope missing payload")
            payload = _b64u_decode(env.payload_b64)
        else:
            payload = None

        tbs = self._to_be_signed(env.header, payload)
        sig = _b64u_decode(env.signature_b64)
        pub = self._resolve_public_key(env)

        # Verify signature according to alg
        alg = env.alg
        if alg == SignAlgorithm.ED25519:
            pub.verify(sig, tbs)
        elif alg in (SignAlgorithm.ECDSA_P256_SHA256, SignAlgorithm.ECDSA_SECP256K1_SHA256):
            digest = hashes.Hash(_HASH_BY_ALG[alg], backend=default_backend())
            digest.update(tbs)
            h = digest.finalize()
            pub.verify(sig, h, ec.ECDSA(Prehashed(_HASH_BY_ALG[alg])))
        elif alg in (SignAlgorithm.RSA_PSS_SHA256, SignAlgorithm.RSA_PSS_SHA512):
            hash_alg = _HASH_BY_ALG[alg]
            pub.verify(
                sig,
                tbs,
                padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
                hash_alg,
            )
        else:
            raise VerifyError(f"Unsupported algorithm: {alg.value}")

        # Detached payload integrity check if present
        if env.type == EnvelopeType.DETACHED:
            pd = hdr.get("payload_digest")
            if pd is None:
                raise VerifyError("Detached envelope missing payload_digest")
            if detached_payload is None:
                # Detached mode requires caller to provide bytes to check
                raise VerifyError("Detached payload required for verification")
            alg_name = pd["alg"]
            try:
                halg = HashAlgorithm(alg_name)
            except Exception:
                raise VerifyError(f"Unknown payload digest algorithm: {alg_name}")
            d = hash_bytes(detached_payload, algorithm=halg)
            if not compare_digests_ct(bytes.fromhex(pd["hex"]), d.raw):
                raise VerifyError("Payload digest mismatch")
            if int(pd.get("len", len(detached_payload))) != len(detached_payload):
                raise VerifyError("Payload length mismatch")

        # Optional: basic chain verification if cert provided
        if self._cert is not None and self._ca_certs:
            self._verify_chain(self._cert, self._ca_certs)

        return True

    def _resolve_public_key(self, env: Envelope):
        if self._public_key is not None:
            return self._public_key
        if self._cert is not None:
            return self._cert.public_key()
        raise VerifyError("No public key or certificate provided to Verifier")

    def _to_be_signed(self, header: Dict[str, Any], payload: Optional[bytes]) -> bytes:
        h_json = canonical_json_dumps(header, ensure_ascii=False).encode("utf-8")
        h_b64 = _b64u(h_json).encode("ascii")
        p_b64 = _b64u(payload or b"").encode("ascii")
        return h_b64 + b"." + p_b64

    def _verify_chain(self, leaf: Certificate, ca_certs: List[Certificate]) -> None:
        # Minimal chain check: issuer DN match and signature verification up to a provided CA.
        # This is not full PKIX path building; for production, integrate a full verifier if required.
        # Here we require a single issuer in ca_certs that signed leaf.
        issuer = leaf.issuer.rfc4514_string()
        for ca in ca_certs:
            subject = ca.subject.rfc4514_string()
            if subject == issuer:
                # Verify leaf signed by ca
                ca_pub = ca.public_key()
                try:
                    ca_pub.verify(leaf.signature, leaf.tbs_certificate_bytes,
                                  padding.PKCS1v15() if isinstance(ca_pub, rsa.RSAPublicKey) else ec.ECDSA(leaf.signature_hash_algorithm),
                                  leaf.signature_hash_algorithm)  # type: ignore
                except Exception as e:
                    raise VerifyError(f"Certificate signature invalid: {e}") from e
                return
        raise VerifyError("No matching issuer found in provided CA certs")


# ==============================
# High-level helpers
# ==============================

def sign_file_detached(private_pem: Union[str, bytes], path: Union[str, Path],
                       password: Optional[bytes] = None,
                       alg: Optional[SignAlgorithm] = None,
                       context: str = "evidence",
                       digest_alg: HashAlgorithm = HashAlgorithm.SHA256) -> Envelope:
    provider = SoftKeyProvider.from_pem(private_pem, password=password, alg=alg)
    signer = Signer(provider)
    data = Path(path).read_bytes()
    opts = SignOptions(detached=True, context=context, payload_hash_alg=digest_alg)
    return signer.sign_bytes(data, opts=opts)


def sign_manifest_detached(private_pem: Union[str, bytes], root_dir: Union[str, Path],
                           password: Optional[bytes] = None,
                           alg: Optional[SignAlgorithm] = None,
                           context: str = "manifest",
                           digest_alg: HashAlgorithm = HashAlgorithm.SHA256) -> Tuple[Envelope, DigestManifest]:
    provider = SoftKeyProvider.from_pem(private_pem, password=password, alg=alg)
    signer = Signer(provider)
    _, manifest = hash_dir(root_dir, algorithm=digest_alg)
    env = signer.sign_dir_manifest(manifest, opts=SignOptions(detached=True, context=context))
    return env, manifest


def verify_file_detached(env_json: Union[str, bytes],
                         public_pem: Optional[Union[str, bytes]] = None,
                         cert_pem: Optional[Union[str, bytes]] = None,
                         ca_pems: Optional[Sequence[Union[str, bytes]]] = None,
                         path: Optional[Union[str, Path]] = None,
                         context: Optional[str] = "evidence") -> bool:
    env = Envelope.from_json(env_json)
    # Load key material
    pub = None
    cert = None
    ca_certs: List[Certificate] = []
    if public_pem is not None:
        pub = load_pem_public_key(public_pem)
    if cert_pem is not None:
        cert = load_pem_cert(cert_pem)
    if ca_pems:
        for p in ca_pems:
            ca_certs.append(load_pem_cert(p))
    verifier = Verifier(public_key=pub, cert=cert, ca_certs=ca_certs)
    payload = None
    if env.type == EnvelopeType.DETACHED:
        if path is None:
            raise VerifyError("Path to payload required for detached verification")
        payload = Path(path).read_bytes()
    return verifier.verify_envelope(env, expected_context=context, detached_payload=payload)


# ==============================
# CLI
# ==============================

def _parse_args(argv: Sequence[str]) -> Tuple[str, Dict[str, Any]]:
    import argparse

    p = argparse.ArgumentParser(prog="oblivionvault-signer", description="Sign and verify OblivionVault evidence.")
    sub = p.add_subparsers(dest="cmd", required=True)

    # sign-file
    sf = sub.add_parser("sign-file", help="Sign a file (detached by default)")
    sf.add_argument("path")
    sf.add_argument("--key", required=True, help="PEM private key path")
    sf.add_argument("--alg", choices=[a.value for a in SignAlgorithm], help="Algorithm (auto-detect if omitted)")
    sf.add_argument("--pass", dest="password", help="Key password")
    sf.add_argument("--attached", action="store_true", help="Attached envelope (payload inside)")
    sf.add_argument("--ctx", default="evidence", help="Context label")
    sf.add_argument("--hash", dest="hash_alg", default=HashAlgorithm.SHA256.value,
                    choices=[a.value for a in HashAlgorithm], help="Payload digest (detached)")

    # sign-dir
    sd = sub.add_parser("sign-dir", help="Hash directory and sign manifest (detached)")
    sd.add_argument("path")
    sd.add_argument("--key", required=True)
    sd.add_argument("--alg", choices=[a.value for a in SignAlgorithm])
    sd.add_argument("--pass", dest="password")
    sd.add_argument("--ctx", default="manifest")
    sd.add_argument("--manifest-out", help="Write manifest JSON to this path")

    # verify
    v = sub.add_parser("verify", help="Verify an envelope")
    v.add_argument("envelope", help="Envelope JSON file")
    v.add_argument("--public", help="PEM public key")
    v.add_argument("--cert", help="PEM leaf certificate")
    v.add_argument("--ca", action="append", default=[], help="PEM CA cert (repeatable)")
    v.add_argument("--payload", help="Path to payload for detached envelope")
    v.add_argument("--ctx", default=None, help="Expected context label")

    args = p.parse_args(argv)
    opts: Dict[str, Any] = {"cmd": args.cmd}
    if args.cmd == "sign-file":
        opts.update({
            "path": args.path,
            "key": args.key,
            "alg": args.alg,
            "password": args.password.encode("utf-8") if args.password else None,
            "attached": bool(args.attached),
            "ctx": args.ctx,
            "hash_alg": HashAlgorithm(args.hash_alg),
        })
    elif args.cmd == "sign-dir":
        opts.update({
            "path": args.path,
            "key": args.key,
            "alg": args.alg,
            "password": args.password.encode("utf-8") if args.password else None,
            "ctx": args.ctx,
            "manifest_out": args.manifest_out,
        })
    elif args.cmd == "verify":
        opts.update({
            "envelope": args.envelope,
            "public": args.public,
            "cert": args.cert,
            "cas": args.ca,
            "payload": args.payload,
            "ctx": args.ctx,
        })
    return args.cmd, opts


def _cli(argv: Sequence[str]) -> int:
    try:
        cmd, o = _parse_args(argv)
        if cmd == "sign-file":
            priv = Path(o["key"]).read_bytes()
            provider = SoftKeyProvider.from_pem(priv, password=o["password"], alg=SignAlgorithm(o["alg"]) if o["alg"] else None)
            signer = Signer(provider)
            data = Path(o["path"]).read_bytes()
            env = signer.sign_bytes(
                data,
                opts=SignOptions(detached=not o["attached"], context=o["ctx"], payload_hash_alg=o["hash_alg"]),
            )
            print(env.to_json())
            return 0

        if cmd == "sign-dir":
            priv = Path(o["key"]).read_bytes()
            provider = SoftKeyProvider.from_pem(priv, password=o["password"], alg=SignAlgorithm(o["alg"]) if o["alg"] else None)
            signer = Signer(provider)
            _, manifest = hash_dir(o["path"])
            if o.get("manifest_out"):
                Path(o["manifest_out"]).write_text(manifest.to_json(), encoding="utf-8")
            env = signer.sign_dir_manifest(manifest, opts=SignOptions(detached=True, context=o["ctx"]))
            print(env.to_json())
            return 0

        if cmd == "verify":
            env_json = Path(o["envelope"]).read_text(encoding="utf-8")
            pub = Path(o["public"]).read_bytes() if o.get("public") else None
            crt = Path(o["cert"]).read_bytes() if o.get("cert") else None
            cas = [Path(p).read_bytes() for p in o.get("cas") or []]
            payload = Path(o["payload"]).read_bytes() if o.get("payload") else None
            pub_key = load_pem_public_key(pub) if pub else None
            cert = load_pem_cert(crt) if crt else None
            ca_certs = [load_pem_cert(ca) for ca in cas]
            verifier = Verifier(public_key=pub_key, cert=cert, ca_certs=ca_certs)
            ok = verifier.verify_envelope(Envelope.from_json(env_json), expected_context=o["ctx"], detached_payload=payload)
            print("OK" if ok else "FAIL")
            return 0 if ok else 2

        raise SignError("Unknown command")
    except (SignError, VerifyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
