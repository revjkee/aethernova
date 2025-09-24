# policy-core/cli/tools/rotate_keys.py
# -*- coding: utf-8 -*-
"""
Policy-Core | Key Rotation CLI

Возможности:
- Генерация ключей: RSA-2048/3072 (RS256/RS384), EC P-256/P-384 (ES256/ES384), Ed25519 (EdDSA)
- Манивест и JWKS с атомарной записью и бэкапами (rollback-friendly)
- Активный/следующий/отозванные ключи, строгая модель kid
- Шифрование приватных ключей паролем (ENV: KEYSTORE_PASSPHRASE)
- Dry-run, журнал аудита JSON, права файлов 0o600, fsync/atomic replace
- Команды: init-store, generate, rotate, activate, revoke, status, export-jwks, sign-test, verify, cleanup
- Расширяемый Storage/KMS интерфейс (встроен FileKeyStore, заглушки KMS/Vault)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

# --- cryptography ---
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.backends import default_backend

# ----- Константы/параметры -----
DEFAULT_STORE = ".secrets/keys"
ENV_PASSPHRASE = "KEYSTORE_PASSPHRASE"
MANIFEST = "manifest.json"
JWKS = "jwks.json"
AUDIT_LOG = "audit.log"

SUPPORTED_ALGS = {"RS256", "RS384", "ES256", "ES384", "EdDSA"}
ALG_TO_KTY = {"RS256": "RSA", "RS384": "RSA", "ES256": "EC", "ES384": "EC", "EdDSA": "OKP"}
ALG_TO_CURVE = {"ES256": ec.SECP256R1(), "ES384": ec.SECP384R1()}
ALG_TO_HASH = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384()}
RSA_DEFAULT_SIZE = {"RS256": 2048, "RS384": 3072}

# ----- Утилиты -----
def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(path.parent)) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)

def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))

def write_json_atomic(path: Path, obj: Any) -> None:
    data = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    atomic_write(path, data)

def chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def log_audit(store: Path, event: str, **fields: Any) -> None:
    rec = {"ts": now_utc(), "event": event, **fields}
    line = json.dumps(rec, ensure_ascii=False)
    (store / AUDIT_LOG).parent.mkdir(parents=True, exist_ok=True)
    with open(store / AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def derive_kid(public_pem: bytes, alg: str) -> str:
    # kid = BLAKE2s-16(base64url(SPKI)) + короткий суффикс алгоритма
    spki = public_pem
    h = hashlib.blake2s(spki, digest_size=10).digest()
    return f"{b64u(h)}.{alg.lower()}"

def require(cond: bool, msg: str) -> None:
    if not cond:
        print(f"ERROR: {msg}", file=sys.stderr)
        sys.exit(2)

# ----- Модель манифеста -----
@dataclass
class Manifest:
    active_kid: Optional[str]
    next_kid: Optional[str]
    revoked: List[str]
    created_at: str
    updated_at: str
    revision: int

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Manifest":
        return Manifest(
            active_kid=d.get("active_kid"),
            next_kid=d.get("next_kid"),
            revoked=list(d.get("revoked") or []),
            created_at=d.get("created_at") or now_utc(),
            updated_at=d.get("updated_at") or now_utc(),
            revision=int(d.get("revision") or 0),
        )

# ----- Интерфейсы хранилища -----
class KeyStore:
    def init_store(self) -> None: ...
    def list_keys(self) -> List[str]: ...
    def save_private(self, kid: str, pem: bytes, passphrase: Optional[str]) -> None: ...
    def save_public(self, kid: str, pem: bytes) -> None: ...
    def load_private(self, kid: str, passphrase: Optional[str]) -> bytes: ...
    def load_public(self, kid: str) -> bytes: ...
    def delete_key(self, kid: str) -> None: ...
    def manifest_read(self) -> Manifest: ...
    def manifest_write(self, m: Manifest) -> None: ...
    def jwks_write(self, jwks: Dict[str, Any]) -> None: ...

class FileKeyStore(KeyStore):
    def __init__(self, root: Path):
        self.root = root
        self.dir_priv = root / "keys"
        self.dir_pub = root / "pub"
        self.manifest_path = root / MANIFEST
        self.jwks_path = root / JWKS

    def init_store(self) -> None:
        self.dir_priv.mkdir(parents=True, exist_ok=True)
        self.dir_pub.mkdir(parents=True, exist_ok=True)
        if not self.manifest_path.exists():
            m = Manifest(active_kid=None, next_kid=None, revoked=[], created_at=now_utc(), updated_at=now_utc(), revision=1)
            write_json_atomic(self.manifest_path, m.to_dict())
        if not self.jwks_path.exists():
            write_json_atomic(self.jwks_path, {"keys": []})
        chmod_600(self.manifest_path)
        chmod_600(self.jwks_path)

    def list_keys(self) -> List[str]:
        kids = set()
        if self.dir_priv.exists():
            for p in self.dir_priv.glob("*.pem"):
                kids.add(p.stem)
        if self.dir_pub.exists():
            for p in self.dir_pub.glob("*.pem"):
                kids.add(p.stem)
        return sorted(kids)

    def save_private(self, kid: str, pem: bytes, passphrase: Optional[str]) -> None:
        path = self.dir_priv / f"{kid}.pem"
        atomic_write(path, pem)
        chmod_600(path)

    def save_public(self, kid: str, pem: bytes) -> None:
        path = self.dir_pub / f"{kid}.pem"
        atomic_write(path, pem)

    def load_private(self, kid: str, passphrase: Optional[str]) -> bytes:
        return (self.dir_priv / f"{kid}.pem").read_bytes()

    def load_public(self, kid: str) -> bytes:
        return (self.dir_pub / f"{kid}.pem").read_bytes()

    def delete_key(self, kid: str) -> None:
        with contextlib.suppress(Exception):
            (self.dir_priv / f"{kid}.pem").unlink()
        with contextlib.suppress(Exception):
            (self.dir_pub / f"{kid}.pem").unlink()

    def manifest_read(self) -> Manifest:
        return Manifest.from_dict(read_json(self.manifest_path))

    def manifest_write(self, m: Manifest) -> None:
        # бэкап для отката
        backup = self.manifest_path.with_suffix(".json.bak")
        if self.manifest_path.exists():
            atomic_write(backup, self.manifest_path.read_bytes())
        write_json_atomic(self.manifest_path, m.to_dict())

    def jwks_write(self, jwks: Dict[str, Any]) -> None:
        write_json_atomic(self.jwks_path, jwks)

# ----- KMS/Vault заглушки (расширяемость) -----
class KMSKeyStore(FileKeyStore):
    """
    Заглушка: имитирует KMS, но использует файловое хранилище.
    Реальная интеграция может переопределить save/load, чтобы ключи никогда не покидали KMS.
    """
    pass

# ----- Генерация ключей -----
@dataclass
class GeneratedKey:
    kid: str
    alg: str
    private_pem: bytes
    public_pem: bytes
    jwk: Dict[str, Any]

def generate_key(alg: str, passphrase: Optional[str]) -> GeneratedKey:
    require(alg in SUPPORTED_ALGS, f"Unsupported alg: {alg}")

    if alg.startswith("RS"):
        size = RSA_DEFAULT_SIZE[alg]
        priv = rsa.generate_private_key(public_exponent=65537, key_size=size, backend=default_backend())
        pub = priv.public_key()
        # PEM
        enc = BestAvailableEncryption(passphrase.encode("utf-8")) if passphrase else NoEncryption()
        private_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
        public_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        # JWK
        n = pub.public_numbers().n
        e = pub.public_numbers().e
        jwk = {
            "kty": "RSA",
            "alg": alg,
            "use": "sig",
            "n": b64u(int_to_bytes(n)),
            "e": b64u(int_to_bytes(e)),
        }

    elif alg.startswith("ES"):
        curve = ALG_TO_CURVE[alg]
        priv = ec.generate_private_key(curve, backend=default_backend())
        pub = priv.public_key()
        enc = BestAvailableEncryption(passphrase.encode("utf-8")) if passphrase else NoEncryption()
        private_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
        public_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        numbers = pub.public_numbers()
        x = numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, "big")
        y = numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, "big")
        crv = "P-256" if alg == "ES256" else "P-384"
        jwk = {"kty": "EC", "alg": alg, "use": "sig", "crv": crv, "x": b64u(x), "y": b64u(y)}

    else:  # EdDSA
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        enc = BestAvailableEncryption(passphrase.encode("utf-8")) if passphrase else NoEncryption()
        private_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
        public_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        x = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwk = {"kty": "OKP", "alg": "EdDSA", "use": "sig", "crv": "Ed25519", "x": b64u(x)}

    kid = derive_kid(public_pem, alg)
    jwk["kid"] = kid
    return GeneratedKey(kid=kid, alg=alg, private_pem=private_pem, public_pem=public_pem, jwk=jwk)

def int_to_bytes(i: int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, "big")

# ----- JWKS сборка -----
def build_jwks(store: FileKeyStore, m: Manifest) -> Dict[str, Any]:
    keys: List[Dict[str, Any]] = []
    # Считываем pub ключи из хранилища и собираем JWK
    for kid in store.list_keys():
        # публикуем только active/next и неотозванные
        if kid not in {m.active_kid, m.next_kid}:
            continue
        try:
            pub_pem = store.load_public(kid)
            jwk = pem_to_jwk(pub_pem)  # без alg невозможно — kid кодирует alg, извлечём из kid
            # Восстановить alg по kid суффиксу
            alg = kid.split(".")[-1].upper()
            jwk["alg"] = "EdDSA" if alg == "EDDsa".upper() else alg
            jwk["kid"] = kid
            jwk["use"] = "sig"
            keys.append(jwk)
        except Exception:
            # пропускаем битые ключи
            continue
    return {"keys": keys}

def pem_to_jwk(pub_pem: bytes) -> Dict[str, Any]:
    from cryptography.hazmat.primitives import serialization as ser
    pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    if isinstance(pub, rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        return {"kty": "RSA", "n": b64u(int_to_bytes(numbers.n)), "e": b64u(int_to_bytes(numbers.e))}
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        numbers = pub.public_numbers()
        x = numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, "big")
        y = numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, "big")
        crv = {ec.SECP256R1().name: "P-256", ec.SECP384R1().name: "P-384"}.get(numbers.curve.name, numbers.curve.name)
        return {"kty": "EC", "crv": crv, "x": b64u(x), "y": b64u(y)}
    else:
        # Ed25519
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}

# ----- Операции с манифестом -----
def load_manifest(ks: FileKeyStore) -> Manifest:
    if not (ks.root / MANIFEST).exists():
        ks.init_store()
    return ks.manifest_read()

def save_manifest(ks: FileKeyStore, m: Manifest) -> None:
    m.updated_at = now_utc()
    m.revision += 1
    ks.manifest_write(m)
    # Перестроить JWKS
    ks.jwks_write(build_jwks(ks, m))

# ----- Команды -----
def cmd_init_store(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    ks.init_store()
    log_audit(Path(args.path), "init_store")
    print(f"Initialized key store at {args.path}")

def cmd_generate(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    ks.init_store()
    m = load_manifest(ks)
    passphrase = os.environ.get(ENV_PASSPHRASE) if not args.no_encrypt else None
    g = generate_key(args.alg, passphrase)
    if args.dry_run:
        print(json.dumps({"kid": g.kid, "alg": g.alg}, ensure_ascii=False, indent=2))
        return
    ks.save_private(g.kid, g.private_pem, passphrase)
    ks.save_public(g.kid, g.public_pem)
    # Заполняем manifest: если нет active/next — делаем next, либо по флагу as-active
    if args.as_active or not m.active_kid:
        m.active_kid = g.kid
    elif not m.next_kid:
        m.next_kid = g.kid
    log_audit(Path(args.path), "generate", kid=g.kid, alg=g.alg, as_active=args.as_active)
    save_manifest(ks, m)
    print(json.dumps({"kid": g.kid, "alg": g.alg}, ensure_ascii=False, indent=2))

def cmd_status(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    m = load_manifest(ks)
    out = m.to_dict()
    out["keys_present"] = ks.list_keys()
    print(json.dumps(out, ensure_ascii=False, indent=2))

def cmd_rotate(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    ks.init_store()
    m = load_manifest(ks)
    require(m.next_kid is not None, "No 'next' key to promote. Generate it first.")
    if args.dry_run:
        print(json.dumps({"promote": m.next_kid, "demote": m.active_kid}, ensure_ascii=False, indent=2))
        return
    prev_active = m.active_kid
    m.active_kid = m.next_kid
    m.next_kid = None
    if args.generate_next:
        passphrase = os.environ.get(ENV_PASSPHRASE) if not args.no_encrypt else None
        g = generate_key(args.alg, passphrase) if args.alg else generate_key(infer_alg_from_kid(m.active_kid), passphrase)
        ks.save_private(g.kid, g.private_pem, passphrase)
        ks.save_public(g.kid, g.public_pem)
        m.next_kid = g.kid
    save_manifest(ks, m)
    log_audit(Path(args.path), "rotate", new_active=m.active_kid, old_active=prev_active, new_next=m.next_kid)
    print(json.dumps({"active": m.active_kid, "next": m.next_kid}, ensure_ascii=False, indent=2))

def infer_alg_from_kid(kid: Optional[str]) -> str:
    if not kid:
        return "EdDSA"
    suffix = kid.split(".")[-1].upper()
    if suffix in SUPPORTED_ALGS:
        return suffix
    return "EdDSA"

def cmd_activate(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    m = load_manifest(ks)
    require(args.kid in ks.list_keys(), f"Unknown kid: {args.kid}")
    if args.dry_run:
        print(json.dumps({"activate": args.kid, "prev_active": m.active_kid}, ensure_ascii=False, indent=2))
        return
    prev = m.active_kid
    m.active_kid = args.kid
    save_manifest(ks, m)
    log_audit(Path(args.path), "activate", new_active=args.kid, old_active=prev)
    print(json.dumps({"active": m.active_kid}, ensure_ascii=False, indent=2))

def cmd_revoke(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    m = load_manifest(ks)
    require(args.kid in ks.list_keys(), f"Unknown kid: {args.kid}")
    if args.dry_run:
        print(json.dumps({"revoke": args.kid}, ensure_ascii=False, indent=2))
        return
    if m.active_kid == args.kid:
        m.active_kid = None
    if m.next_kid == args.kid:
        m.next_kid = None
    if args.kid not in m.revoked:
        m.revoked.append(args.kid)
    save_manifest(ks, m)
    log_audit(Path(args.path), "revoke", kid=args.kid)
    print(json.dumps({"revoked": args.kid}, ensure_ascii=False, indent=2))

def cmd_export_jwks(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    m = load_manifest(ks)
    jwks = build_jwks(ks, m)
    if args.out:
        write_json_atomic(Path(args.out), jwks)
        print(f"Wrote JWKS to {args.out}")
    else:
        print(json.dumps(jwks, ensure_ascii=False, indent=2))

def cmd_sign_test(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    m = load_manifest(ks)
    kid = args.kid or m.active_kid
    require(kid is not None, "No active key and no --kid provided.")
    passphrase = os.environ.get(ENV_PASSPHRASE)
    priv_pem = ks.load_private(kid, passphrase)
    priv = serialization.load_pem_private_key(priv_pem, password=(passphrase.encode("utf-8") if passphrase else None), backend=default_backend())
    data = read_data_arg(args.data)
    sig, alg = sign_raw(priv, data, kid)
    out = {"kid": kid, "alg": alg, "sig_b64u": b64u(sig)}
    print(json.dumps(out, ensure_ascii=False, indent=2))

def read_data_arg(arg: str) -> bytes:
    if arg == "-":
        return sys.stdin.buffer.read()
    p = Path(arg)
    if p.exists():
        return p.read_bytes()
    return arg.encode("utf-8")

def sign_raw(priv: Any, data: bytes, kid: str) -> Tuple[bytes, str]:
    # Определяем по типу ключа
    if isinstance(priv, rsa.RSAPrivateKey):
        # PKCS#1v1.5 подпись под SHA*; по умолчанию RS256
        from cryptography.hazmat.primitives.asymmetric import padding
        alg = "RS256" if kid.endswith(".rs256") else "RS384"
        h = ALG_TO_HASH[alg]
        hasher = hashes.Hash(h, backend=default_backend())
        hasher.update(data)
        digest = hasher.finalize()
        sig = priv.sign(digest, padding.PKCS1v15(), h)
        return sig, alg
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        # ECDSA
        curve_name = priv.curve.name
        alg = "ES256" if "256" in curve_name else "ES384"
        h = ALG_TO_HASH["RS256" if alg == "ES256" else "RS384"]
        sig_der = priv.sign(data, ec.ECDSA(h))
        # оставляем в DER (поскольку это тестовая подпись, формат не нормируем)
        return sig_der, alg
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        sig = priv.sign(data)
        return sig, "EdDSA"
    raise ValueError("Unsupported private key type")

def cmd_verify(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    kid = args.kid
    require(kid in ks.list_keys(), f"Unknown kid: {kid}")
    pub_pem = ks.load_public(kid)
    sig = b64u_decode(args.sig_b64u)
    data = read_data_arg(args.data)
    ok = verify_raw(pub_pem, data, sig)
    print(json.dumps({"kid": kid, "valid": ok}, ensure_ascii=False, indent=2))
    sys.exit(0 if ok else 3)

def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def verify_raw(pub_pem: bytes, data: bytes, sig: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            # попытаемся обе хеш-функции
            for h in (hashes.SHA256(), hashes.SHA384()):
                try:
                    pub.verify(sig, hashlib.new(h.name.lower(), data).digest(), padding.PKCS1v15(), h)
                    return True
                except Exception:
                    continue
            return False
        if isinstance(pub, ec.EllipticCurvePublicKey):
            for h in (hashes.SHA256(), hashes.SHA384()):
                try:
                    pub.verify(sig, data, ec.ECDSA(h))
                    return True
                except Exception:
                    continue
            return False
        if hasattr(pub, "verify"):  # Ed25519
            pub.verify(sig, data)
            return True
    except Exception:
        return False
    return False

def cmd_cleanup(args: argparse.Namespace) -> None:
    ks = FileKeyStore(Path(args.path))
    m = load_manifest(ks)
    # Не удаляем active/next; удаляем отозванные старше N дней
    cutoff = time.time() - args.retired_days * 86400
    removed = []
    for kid in list(m.revoked):
        kpath = ks.dir_priv / f"{kid}.pem"
        if kpath.exists() and kpath.stat().st_mtime < cutoff:
            ks.delete_key(kid)
            removed.append(kid)
            m.revoked.remove(kid)
    if not args.dry_run:
        save_manifest(ks, m)
    print(json.dumps({"removed": removed, "remaining_revoked": m.revoked}, ensure_ascii=False, indent=2))

# ----- Аргументы CLI -----
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Policy-Core Key Rotation CLI")
    p.add_argument("--path", default=DEFAULT_STORE, help="Key store directory (default: .secrets/keys)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-store", help="Initialize key store")
    s.set_defaults(func=cmd_init_store)

    s = sub.add_parser("generate", help="Generate a new key")
    s.add_argument("--alg", choices=sorted(SUPPORTED_ALGS), default="EdDSA", help="Signature algorithm")
    s.add_argument("--as-active", action="store_true", help="Make generated key active if no active present")
    s.add_argument("--no-encrypt", action="store_true", help="Do not encrypt private key at rest")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_generate)

    s = sub.add_parser("status", help="Show store status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("rotate", help="Promote next->active and optionally generate next")
    s.add_argument("--generate-next", action="store_true", help="Generate new 'next' key after rotation")
    s.add_argument("--alg", choices=sorted(SUPPORTED_ALGS), help="Alg for new 'next' (defaults to active alg)")
    s.add_argument("--no-encrypt", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_rotate)

    s = sub.add_parser("activate", help="Activate specific kid")
    s.add_argument("--kid", required=True)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_activate)

    s = sub.add_parser("revoke", help="Revoke specific kid")
    s.add_argument("--kid", required=True)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("export-jwks", help="Export JWKS (active/next only)")
    s.add_argument("--out", help="Output file (stdout if omitted)")
    s.set_defaults(func=cmd_export_jwks)

    s = sub.add_parser("sign-test", help="Sign data with selected key (debug)")
    s.add_argument("--kid", help="KID to use (defaults to active)")
    s.add_argument("--data", required=True, help="String, file path, or '-' for stdin")
    s.set_defaults(func=cmd_sign_test)

    s = sub.add_parser("verify", help="Verify signature with stored public key")
    s.add_argument("--kid", required=True)
    s.add_argument("--data", required=True)
    s.add_argument("--sig-b64u", required=True)
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("cleanup", help="Delete revoked private keys older than N days")
    s.add_argument("--retired-days", type=int, default=90)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_cleanup)

    return p

def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Безопасность: проверка папки
    store_path = Path(args.path).resolve()
    store_path.mkdir(parents=True, exist_ok=True)
    # Выполнение
    args.func(args)

if __name__ == "__main__":
    main()
