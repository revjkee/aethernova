# physical-integration-core/physical_integration/ota/signer.py
from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Опциональные зависимости: cryptography для нативной подписи
try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding  # type: ignore
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

# Опциональный RFC3161 таймстамп-клиент
try:
    # pip install rfc3161-client
    from rfc3161_client import RFC3161TimestampClient  # type: ignore
except Exception:  # pragma: no cover
    RFC3161TimestampClient = None  # type: ignore

LOG = logging.getLogger("ota.signer")


# ========= Исключения =========

class SignerError(Exception):
    pass


class VerificationError(Exception):
    pass


# ========= Утилиты =========

def _now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sha256_file(path: Path, chunk: int = 2 * 1024 * 1024) -> Tuple[str, int]:
    """Потоковое хеширование артефакта."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            size += len(buf)
            h.update(buf)
    return h.hexdigest(), size


def load_pem_private_key(key_path: Path, password: Optional[str]) -> Any:
    if not _CRYPTO:
        raise SignerError("cryptography is not available for native signing")
    pem = key_path.read_bytes()
    pwd = password.encode("utf-8") if password else None
    try:
        return serialization.load_pem_private_key(pem, password=pwd, backend=default_backend())
    except Exception as ex:
        raise SignerError(f"failed to load private key: {ex}") from ex


def public_key_info(priv: Any) -> Tuple[bytes, str, str]:
    """
    Возвращает (DER публичного ключа, алгоритм, kid=sha256 дер).
    Алгоритм: Ed25519 | ES256 | RSASSA-PSS-SHA256
    """
    if not _CRYPTO:
        raise SignerError("cryptography is not available")
    pub = priv.public_key()
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = "sha256:" + hashlib.sha256(der).hexdigest()
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        alg = "Ed25519"
    elif isinstance(priv, ec.EllipticCurvePrivateKey) and isinstance(priv.curve, ec.SECP256R1):
        alg = "ES256"
    elif isinstance(priv, rsa.RSAPrivateKey):
        alg = "RSASSA-PSS-SHA256"
    else:
        raise SignerError("unsupported private key type")
    return der, alg, kid


def sign_digest(priv: Any, alg: str, digest_hex: str) -> bytes:
    if not _CRYPTO:
        raise SignerError("cryptography is not available")
    digest = bytes.fromhex(digest_hex)
    if alg == "Ed25519":
        # Ed25519 подписывает непосредственно сообщение; подписываем префиксованный контент.
        # Чтобы не раскрывать сам файл, подписываем структуру: "SHA256:" + hex
        msg = b"SHA256:" + digest_hex.encode("ascii")
        return priv.sign(msg)
    elif alg == "ES256":
        # Для ECDSA подписываем тот же "префиксованный" контент
        msg = b"SHA256:" + digest_hex.encode("ascii")
        return priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    elif alg == "RSASSA-PSS-SHA256":
        msg = b"SHA256:" + digest_hex.encode("ascii")
        return priv.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    else:
        raise SignerError(f"unsupported alg: {alg}")


def verify_signature(pub_der: bytes, alg: str, digest_hex: str, signature: bytes) -> None:
    if not _CRYPTO:
        raise VerificationError("cryptography is not available")
    pub = serialization.load_der_public_key(pub_der, backend=default_backend())
    msg = b"SHA256:" + digest_hex.encode("ascii")
    try:
        if alg == "Ed25519":
            pub.verify(signature, msg)  # type: ignore
        elif alg == "ES256":
            pub.verify(signature, msg, ec.ECDSA(hashes.SHA256()))  # type: ignore
        elif alg == "RSASSA-PSS-SHA256":
            pub.verify(  # type: ignore
                signature, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
            )
        else:
            raise VerificationError(f"unsupported alg: {alg}")
    except Exception as ex:
        raise VerificationError(f"signature verification failed: {ex}") from ex


# ========= Подписчики =========

@dataclass
class SignResult:
    alg: str
    kid: str
    digest_sha256: str
    signature_b64url: str
    signed_at: str
    pubkey_der_b64: str
    cert_chain_pem: Optional[str] = None
    tsa_token_b64: Optional[str] = None


class NativeSigner:
    def __init__(self, key_path: Path, key_password: Optional[str] = None, cert_chain_path: Optional[Path] = None):
        self.priv = load_pem_private_key(key_path, key_password)
        self.pub_der, self.alg, self.kid = public_key_info(self.priv)
        self.cert_chain_pem = cert_chain_path.read_text(encoding="utf-8") if cert_chain_path and cert_chain_path.exists() else None

    def sign_digest(self, digest_hex: str, tsa_url: Optional[str] = None, tsa_hash_algo: str = "sha256") -> SignResult:
        sig = sign_digest(self.priv, self.alg, digest_hex)
        tsa_b64 = None
        if tsa_url and RFC3161TimestampClient:
            try:
                client = RFC3161TimestampClient(tsa_url, hashname=tsa_hash_algo)
                token = client.timestamp(data=bytes.fromhex(digest_hex))
                tsa_b64 = base64.b64encode(token).decode("ascii")
            except Exception as ex:  # pragma: no cover
                LOG.warning("RFC3161 timestamp failed: %s", ex)
        return SignResult(
            alg=self.alg,
            kid=self.kid,
            digest_sha256=digest_hex,
            signature_b64url=_b64url(sig),
            signed_at=_now_iso(),
            pubkey_der_b64=base64.b64encode(self.pub_der).decode("ascii"),
            cert_chain_pem=self.cert_chain_pem,
            tsa_token_b64=tsa_b64,
        )


class CosignSigner:
    """
    Обертка над 'cosign sign-blob' при наличии бинаря cosign и переменных окружения COSIGN_*.
    """
    def __init__(self, cert_chain_path: Optional[Path] = None):
        self.cosign = shutil.which("cosign")
        if not self.cosign:
            raise SignerError("cosign binary not found in PATH")
        self.cert_chain_pem = cert_chain_path.read_text(encoding="utf-8") if cert_chain_path and cert_chain_path.exists() else None

    def sign_file(self, file_path: Path, digest_hex: Optional[str] = None, identity_token: Optional[str] = None) -> SignResult:
        # cosign генерирует подпись и может вернуть сертификат (OIDC Fulcio).
        # Здесь используем --output-signature - и читаем из файла/STDOUT.
        sig_path = file_path.with_suffix(file_path.suffix + ".sig.tmp")
        cmd = [self.cosign, "sign-blob", str(file_path), "--output-signature", str(sig_path), "--yes"]
        if identity_token:
            cmd += ["--identity-token", identity_token]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            sig_raw = sig_path.read_bytes()
            sig_b64url = _b64url(sig_raw)
        finally:
            with contextlib.suppress(Exception):
                sig_path.unlink(missing_ok=True)  # type: ignore

        # cosign не сообщает алгоритм/публичный ключ напрямую; оставляем разумные поля как 'cosign'
        digest_hex = digest_hex or sha256_file(file_path)[0]
        return SignResult(
            alg="cosign",
            kid="cosign",
            digest_sha256=digest_hex,
            signature_b64url=sig_b64url,
            signed_at=_now_iso(),
            pubkey_der_b64="",  # неизвестно
            cert_chain_pem=self.cert_chain_pem,
            tsa_token_b64=None,
        )


# ========= Основные операции =========

def sign_artifact(
    artifact: Path,
    *,
    out_sig: Optional[Path],
    out_manifest: Optional[Path],
    key_path: Optional[Path] = None,
    key_password: Optional[str] = None,
    cert_chain_path: Optional[Path] = None,
    use_cosign: bool = False,
    tsa_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Подписывает артефакт и, опционально, создаёт манифест для контроллера OTA.
    Возвращает dict сигнатуры.
    """
    if not artifact.exists():
        raise SignerError(f"file not found: {artifact}")
    digest, size = sha256_file(artifact)
    LOG.info("SHA256=%s size=%d path=%s", digest, size, artifact)

    if use_cosign:
        signer = CosignSigner(cert_chain_path)
        res = signer.sign_file(artifact, digest_hex=digest, identity_token=os.getenv("COSIGN_ID_TOKEN"))
    else:
        if not key_path:
            raise SignerError("key_path is required for native signer")
        signer = NativeSigner(key_path, key_password, cert_chain_path)
        res = signer.sign_digest(digest, tsa_url=tsa_url)

    sig_doc: Dict[str, Any] = {
        "schema": "aethernova.sig.v1",
        "alg": res.alg,
        "kid": res.kid,
        "digest": {"sha256": res.digest_sha256},
        "signature": res.signature_b64url,
        "signed_at": res.signed_at,
        "pubkey_der_b64": res.pubkey_der_b64,
    }
    if res.cert_chain_pem:
        sig_doc["cert_chain_pem"] = res.cert_chain_pem
    if res.tsa_token_b64:
        sig_doc["tsa_rfc3161_b64"] = res.tsa_token_b64

    if out_sig:
        out_sig.parent.mkdir(parents=True, exist_ok=True)
        out_sig.write_text(json.dumps(sig_doc, ensure_ascii=False, indent=2), encoding="utf-8")
        LOG.info("Signature written: %s", out_sig)

    if out_manifest:
        man = {
            "schema": "aethernova.manifest.v1",
            "artifact": {
                "name": artifact.name,
                "path": str(artifact),
                "size_bytes": size,
                "sha256": digest,
            },
            "signature": sig_doc,
            "created_at": _now_iso(),
        }
        out_manifest.parent.mkdir(parents=True, exist_ok=True)
        out_manifest.write_text(json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")
        LOG.info("Manifest written: %s", out_manifest)

    return sig_doc


def verify_artifact(artifact: Path, sig_path: Path, *, pubkey_der_path: Optional[Path] = None) -> None:
    """Проверяет, что подпись соответствует файлу и публичному ключу (если задан)."""
    if not sig_path.exists():
        raise VerificationError(f"signature file not found: {sig_path}")
    sig_doc = json.loads(sig_path.read_text(encoding="utf-8"))
    if sig_doc.get("schema") != "aethernova.sig.v1":
        raise VerificationError("unsupported signature schema")

    digest_calc, _ = sha256_file(artifact)
    digest_sig = sig_doc.get("digest", {}).get("sha256")
    if not digest_sig or digest_sig.lower() != digest_calc.lower():
        raise VerificationError("digest mismatch")

    alg = sig_doc.get("alg")
    sig_b64 = sig_doc.get("signature")
    pub_der_b64 = sig_doc.get("pubkey_der_b64")
    if not alg or not sig_b64:
        raise VerificationError("invalid signature document")

    # Источник публичного ключа: явный файл > документ
    if pubkey_der_path and pubkey_der_path.exists():
        pub_der = pubkey_der_path.read_bytes()
    else:
        if not pub_der_b64:
            # Для cosign без pubkey мы можем только подтвердить соответствие хеша и наличие подписи.
            # Полная криптопроверка невозможна без ключа.
            raise VerificationError("public key DER not provided; cannot verify signature crypto")
        pub_der = base64.b64decode(pub_der_b64)

    verify_signature(pub_der, alg, digest_calc, _from_b64url(sig_b64))


# ========= CLI =========

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="ota-signer", description="OTA artifact signer")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_sign = sub.add_parser("sign", help="Sign artifact")
    s_sign.add_argument("--file", required=True, type=Path)
    s_sign.add_argument("--out-sig", type=Path, required=True)
    s_sign.add_argument("--out-manifest", type=Path, required=False)
    s_sign.add_argument("--key", type=Path, help="PEM private key (native signer)")
    s_sign.add_argument("--key-pass", help="PEM password")
    s_sign.add_argument("--cert-chain", type=Path, help="PEM certificate chain to embed")
    s_sign.add_argument("--cosign", action="store_true", help="Use cosign sign-blob instead of native signer")
    s_sign.add_argument("--tsa-url", help="RFC3161 TSA URL (optional)")

    s_ver = sub.add_parser("verify", help="Verify artifact and signature")
    s_ver.add_argument("--file", required=True, type=Path)
    s_ver.add_argument("--sig", required=True, type=Path)
    s_ver.add_argument("--pub-der", type=Path, help="Public key in DER (overrides embedded)")

    s_man = sub.add_parser("manifest", help="Generate manifest from existing signature")
    s_man.add_argument("--file", required=True, type=Path)
    s_man.add_argument("--sig", required=True, type=Path)
    s_man.add_argument("--out", required=True, type=Path)

    return p.parse_args(argv)


def _setup_logging() -> None:
    lvl = os.getenv("LOG_LEVEL", "INFO").upper()
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(getattr(logging, lvl, logging.INFO))


def _cmd_sign(ns: argparse.Namespace) -> int:
    sig = sign_artifact(
        ns.file,
        out_sig=ns.out_sig,
        out_manifest=ns.out_manifest,
        key_path=ns.key if not ns.cosign else None,
        key_password=ns.key_pass,
        cert_chain_path=ns.cert_chain,
        use_cosign=ns.cosign,
        tsa_url=ns.tsa_url,
    )
    print(json.dumps(sig, ensure_ascii=False, indent=2))
    return 0


def _cmd_verify(ns: argparse.Namespace) -> int:
    verify_artifact(ns.file, ns.sig, pubkey_der_path=ns.pub_der)
    print("OK")
    return 0


def _cmd_manifest(ns: argparse.Namespace) -> int:
    digest, size = sha256_file(ns.file)
    sig_doc = json.loads(ns.sig.read_text(encoding="utf-8"))
    man = {
        "schema": "aethernova.manifest.v1",
        "artifact": {"name": ns.file.name, "path": str(ns.file), "size_bytes": size, "sha256": digest},
        "signature": sig_doc,
        "created_at": _now_iso(),
    }
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")
    print(str(ns.out))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    _setup_logging()
    ns = _parse_args(argv or sys.argv[1:])
    try:
        if ns.cmd == "sign":
            return _cmd_sign(ns)
        if ns.cmd == "verify":
            return _cmd_verify(ns)
        if ns.cmd == "manifest":
            return _cmd_manifest(ns)
        raise SignerError("unknown command")
    except (SignerError, VerificationError) as ex:
        LOG.error(str(ex))
        print(str(ex), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
