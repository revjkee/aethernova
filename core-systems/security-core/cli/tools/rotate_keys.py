# File: security-core/cli/tools/rotate_keys.py
# Industrial-grade JWKS key rotation CLI for JWT/JWE
# Python: 3.10+
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Optional dependency (fail closed with actionable error)
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except Exception:
    serialization = hashes = rsa = ec = ed25519 = padding = default_backend = InvalidSignature = None  # type: ignore


# =========================
# Errors
# =========================

class RotationError(Exception):
    pass


# =========================
# Utilities
# =========================

def _require_crypto() -> None:
    if serialization is None:
        raise RotationError("cryptography is not installed. Install with: pip install cryptography")

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _from_b64u(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def _writelines_atomic(path: str, data: bytes, mode: int = 0o600) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp.", suffix=".new")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # permissions (POSIX)
        try:
            os.chmod(tmp, mode)
        except Exception:
            pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _read_json(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return json.load(f)

def _write_json_atomic(path: str, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    # public JWKS world-readable by default; adjust as needed
    _writelines_atomic(path, data, mode=0o644)

def _backup_file(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    ts = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    bak = f"{path}.bak.{ts}"
    shutil.copy2(path, bak)
    return bak

def _file_lock_path(target: str) -> str:
    return f"{target}.lock"

def _acquire_lock(lock_path: str, ttl_seconds: int = 600) -> None:
    now = int(time.time())
    try:
        # exclusive create
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{os.getpid()} {now}\n")
        return
    except FileExistsError:
        try:
            st = os.stat(lock_path)
            # stale lock?
            if now - int(st.st_mtime) > ttl_seconds:
                os.remove(lock_path)
                return _acquire_lock(lock_path, ttl_seconds)
        except Exception:
            pass
        raise RotationError(f"Lock already held: {lock_path}")

def _release_lock(lock_path: str) -> None:
    try:
        os.remove(lock_path)
    except Exception:
        pass


# =========================
# Key generation and JWK mapping
# =========================

@dataclass(frozen=True)
class NewKey:
    kid: str
    use: str            # "sig"|"enc"
    alg: str            # "RS256"|"ES256"|"EdDSA"|...
    kty: str            # "RSA"|"EC"|"OKP"
    private_pem: bytes
    public_jwk: Dict[str, Any]

def _gen_kid(prefix: str, alg: str) -> str:
    ts = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    rnd = secrets.token_hex(6)
    return f"{prefix}{alg.lower()}-{ts}-{rnd}"

def _gen_rsa(bits: int) -> Tuple[bytes, Dict[str, str]]:
    _require_crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=max(2048, bits), backend=default_backend())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "n": _b64u(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")),
    }
    return priv_pem, jwk

def _gen_ec(curve_name: str) -> Tuple[bytes, Dict[str, str], str]:
    _require_crypto()
    curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}.get(curve_name, ec.SECP256R1)()
    key = ec.generate_private_key(curve, backend=default_backend())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_numbers()
    x = pub.x.to_bytes((pub.x.bit_length() + 7) // 8, "big")
    y = pub.y.to_bytes((pub.y.bit_length() + 7) // 8, "big")
    jwk = {"kty": "EC", "crv": curve_name, "x": _b64u(x), "y": _b64u(y)}
    return priv_pem, jwk, curve_name

def _gen_okp_ed25519() -> Tuple[bytes, Dict[str, str]]:
    _require_crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub_raw)}
    return priv_pem, jwk

def generate_key(alg: str, use: str, kid_prefix: str, rsa_bits: int, ec_curve: str) -> NewKey:
    alg = alg.upper()
    if alg == "RS256":
        priv, jwk = _gen_rsa(rsa_bits)
        jwk["alg"] = "RS256"
        jwk["use"] = use
        kid = _gen_kid(kid_prefix, alg)
        jwk["kid"] = kid
        return NewKey(kid=kid, use=use, alg="RS256", kty="RSA", private_pem=priv, public_jwk=jwk)
    if alg == "ES256":
        priv, jwk, crv = _gen_ec(ec_curve or "P-256")
        jwk["alg"] = "ES256"
        jwk["use"] = use
        kid = _gen_kid(kid_prefix, alg)
        jwk["kid"] = kid
        return NewKey(kid=kid, use=use, alg="ES256", kty="EC", private_pem=priv, public_jwk=jwk)
    if alg == "EDDSA":
        priv, jwk = _gen_okp_ed25519()
        jwk["alg"] = "EdDSA"
        jwk["use"] = use
        kid = _gen_kid(kid_prefix, alg)
        jwk["kid"] = kid
        return NewKey(kid=kid, use=use, alg="EdDSA", kty="OKP", private_pem=priv, public_jwk=jwk)
    raise RotationError(f"Unsupported alg: {alg}")


# =========================
# JWKS state helpers
# =========================

def _load_jwks(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"keys": [], "updated_at": _utc_now().isoformat(), "primary_kid": None}
    return _read_json(path)

def _save_jwks(path: str, jwks: Dict[str, Any]) -> None:
    jwks["updated_at"] = _utc_now().isoformat()
    _write_json_atomic(path, jwks)

def _mark_status(jwk: Dict[str, Any], status: str, exp_ts: Optional[int] = None) -> None:
    jwk["status"] = status  # "primary"|"retiring"|"revoked"
    if exp_ts is not None:
        jwk["exp"] = int(exp_ts)

def _find_primary(jwks: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for k in jwks.get("keys", []):
        if k.get("status") == "primary":
            return k
    return None

def _cleanup_expired(jwks: Dict[str, Any], now_ts: int) -> Tuple[int, int]:
    before = len(jwks.get("keys", []))
    jwks["keys"] = [k for k in jwks.get("keys", []) if not (k.get("status") in {"retiring", "revoked"} and int(k.get("exp", 0)) > 0 and now_ts >= int(k["exp"]))]
    after = len(jwks["keys"])
    return before, after


# =========================
# Signing self-test
# =========================

def _sign_and_verify_selftest(new_key: NewKey) -> None:
    """
    Create a small JWS-like object and verify with the freshly generated public key.
    """
    _require_crypto()
    header = {"alg": new_key.alg, "kid": new_key.kid, "typ": "JWT"}
    payload = {"iat": int(time.time()), "sub": "rotation-selftest"}
    msg = f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}.{_b64u(json.dumps(payload, separators=(',', ':')).encode())}".encode()

    if new_key.alg == "RS256":
        priv = serialization.load_pem_private_key(new_key.private_pem, password=None, backend=default_backend())
        sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        # Verify
        pub_nums_n = int.from_bytes(_from_b64u(new_key.public_jwk["n"]), "big")
        pub_nums_e = int.from_bytes(_from_b64u(new_key.public_jwk["e"]), "big")
        pub_key = rsa.RSAPublicNumbers(pub_nums_e, pub_nums_n).public_key(default_backend())
        try:
            pub_key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as e:
            raise RotationError(f"Self-test failed (RS256): {e}")
        return

    if new_key.alg == "ES256":
        priv = serialization.load_pem_private_key(new_key.private_pem, password=None, backend=default_backend())
        sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        # Verify
        x = int.from_bytes(_from_b64u(new_key.public_jwk["x"]), "big")
        y = int.from_bytes(_from_b64u(new_key.public_jwk["y"]), "big")
        pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
        try:
            pub_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise RotationError(f"Self-test failed (ES256): {e}")
        return

    if new_key.alg == "EdDSA":
        priv = serialization.load_pem_private_key(new_key.private_pem, password=None, backend=default_backend())
        sig = priv.sign(msg)
        pub_raw = _from_b64u(new_key.public_jwk["x"])
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
        try:
            pub_key.verify(sig, msg)
        except InvalidSignature as e:
            raise RotationError(f"Self-test failed (EdDSA): {e}")
        return

    raise RotationError(f"Self-test: unsupported alg {new_key.alg}")


# =========================
# Commands
# =========================

def cmd_rotate(args: argparse.Namespace) -> int:
    lock_path = _file_lock_path(args.jwks)
    _acquire_lock(lock_path, ttl_seconds=args.lock_ttl)
    try:
        jwks = _load_jwks(args.jwks)
        primary = _find_primary(jwks)
        now_ts = int(time.time())
        if primary and not args.force:
            # respect minimal interval (based on nbf of primary)
            last_ts = int(primary.get("nbf", args.min_interval_ts))
            if now_ts - last_ts < args.min_interval:
                raise RotationError(f"Minimal rotation interval not reached ({args.min_interval}s)")

        # generate
        new_key = generate_key(args.alg, args.use, args.kid_prefix, args.rsa_bits, args.ec_curve)
        # mark retiring previous primary
        if primary:
            _mark_status(primary, "retiring", exp_ts=now_ts + args.retire_after)

        # self-test
        if not args.no_selftest:
            _sign_and_verify_selftest(new_key)

        # write private key
        priv_dir = os.path.abspath(args.keys_dir)
        os.makedirs(priv_dir, exist_ok=True)
        priv_path = os.path.join(priv_dir, f"{new_key.kid}.pem")
        if os.path.exists(priv_path) and not args.overwrite:
            raise RotationError(f"Private key already exists: {priv_path}")
        if not args.dry_run:
            _writelines_atomic(priv_path, new_key.private_pem, mode=0o600)

        # update jwks
        new_jwk = dict(new_key.public_jwk)
        new_jwk["nbf"] = now_ts
        _mark_status(new_jwk, "primary")
        jwks.setdefault("keys", []).append(new_jwk)
        jwks["primary_kid"] = new_key.kid

        # backup and save
        if not args.dry_run:
            _backup_file(args.jwks)
            _save_jwks(args.jwks, jwks)

        # optional symlink/copy for convenience
        if args.active_link:
            try:
                link_path = os.path.join(priv_dir, "active.pem")
                tmp = link_path + ".tmp"
                if os.name != "nt":
                    # symlink if possible
                    if os.path.islink(link_path) or os.path.exists(link_path):
                        os.remove(link_path)
                    os.symlink(os.path.basename(priv_path), link_path)
                else:
                    # copy on Windows
                    shutil.copy2(priv_path, tmp)
                    os.replace(tmp, link_path)
            except Exception:
                pass

        # post-hook command
        if args.post_cmd and not args.dry_run:
            _run_post_cmd(args.post_cmd)

        _audit({"event": "rotate", "kid": new_key.kid, "alg": new_key.alg, "use": new_key.use, "jwks": args.jwks, "keys_dir": args.keys_dir, "dry_run": args.dry_run})
        print(new_key.kid)
        return 0
    finally:
        _release_lock(lock_path)

def cmd_list(args: argparse.Namespace) -> int:
    jwks = _load_jwks(args.jwks)
    keys = sorted(jwks.get("keys", []), key=lambda k: (k.get("status") != "primary", -k.get("nbf", 0))), reverse=False)
    for k in keys:
        print(json.dumps({
            "kid": k.get("kid"),
            "alg": k.get("alg"),
            "use": k.get("use"),
            "status": k.get("status"),
            "nbf": k.get("nbf"),
            "exp": k.get("exp"),
        }, ensure_ascii=False))
    return 0

def cmd_show_active(args: argparse.Namespace) -> int:
    jwks = _load_jwks(args.jwks)
    primary = _find_primary(jwks)
    if not primary:
        print("")
        return 1
    print(primary.get("kid", ""))
    return 0

def cmd_revoke(args: argparse.Namespace) -> int:
    jwks = _load_jwks(args.jwks)
    target = None
    for k in jwks.get("keys", []):
        if k.get("kid") == args.kid:
            target = k
            break
    if not target:
        raise RotationError(f"kid not found: {args.kid}")
    _mark_status(target, "revoked", exp_ts=int(time.time()) + args.ttl)
    _backup_file(args.jwks)
    _save_jwks(args.jwks, jwks)
    _audit({"event": "revoke", "kid": args.kid, "ttl": args.ttl})
    return 0

def cmd_cleanup(args: argparse.Namespace) -> int:
    jwks = _load_jwks(args.jwks)
    before, after = _cleanup_expired(jwks, int(time.time()))
    if before != after:
        _backup_file(args.jwks)
        _save_jwks(args.jwks, jwks)
    print(json.dumps({"removed": before - after, "remaining": after}, ensure_ascii=False))
    return 0

def cmd_verify(args: argparse.Namespace) -> int:
    jwks = _load_jwks(args.jwks)
    kid = args.kid or (jwks.get("primary_kid") or (_find_primary(jwks) or {}).get("kid"))
    if not kid:
        raise RotationError("No kid specified and no primary found")
    # Find private
    priv_path = os.path.join(args.keys_dir, f"{kid}.pem")
    if not os.path.exists(priv_path):
        raise RotationError(f"Private key not found for kid {kid}: {priv_path}")
    with open(priv_path, "rb") as f:
        priv_pem = f.read()
    # Build pseudo NewKey object from JWKS entry
    entry = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if not entry:
        raise RotationError(f"kid not present in JWKS: {kid}")
    new_key = NewKey(kid=kid, use=entry.get("use", "sig"), alg=entry.get("alg", "RS256"), kty=entry.get("kty", "RSA"), private_pem=priv_pem, public_jwk=entry)
    _sign_and_verify_selftest(new_key)
    print("ok")
    return 0


# =========================
# CLI and wiring
# =========================

def _run_post_cmd(cmd: str) -> None:
    import subprocess
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise RotationError(f"Post-command failed: {e.stderr.strip()[:500]}")

def _audit(event: Dict[str, Any]) -> None:
    event = dict(event)
    event["ts"] = _utc_now().isoformat()
    print(json.dumps(event, ensure_ascii=False), file=sys.stderr)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rotate_keys", description="JWKS key rotation tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    # rotate
    rp = sub.add_parser("rotate", help="Generate new key and update JWKS")
    rp.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    rp.add_argument("--keys-dir", required=True, help="Directory to store private keys (PEM)")
    rp.add_argument("--use", choices=["sig", "enc"], default="sig", help="Key use")
    rp.add_argument("--alg", choices=["RS256", "ES256", "EdDSA"], default="RS256", help="Algorithm")
    rp.add_argument("--rsa-bits", type=int, default=2048, help="RSA key size")
    rp.add_argument("--ec-curve", choices=["P-256", "P-384", "P-521"], default="P-256", help="EC curve for ES256")
    rp.add_argument("--kid-prefix", default="kid-", help="Prefix for generated kid")
    rp.add_argument("--retire-after", type=int, default=86400, help="Seconds to keep old primary in retiring state")
    rp.add_argument("--min-interval", type=int, default=3600, help="Minimal seconds between rotations")
    rp.add_argument("--force", action="store_true", help="Ignore minimal interval")
    rp.add_argument("--no-selftest", action="store_true", help="Skip sign/verify self-test")
    rp.add_argument("--dry-run", action="store_true", help="Do not write files")
    rp.add_argument("--overwrite", action="store_true", help="Overwrite existing private key file if present")
    rp.add_argument("--active-link", action="store_true", help="Create/update active.pem symlink/copy to new key")
    rp.add_argument("--post-cmd", default="", help="Command to run after successful rotation (e.g., 'systemctl reload nginx')")
    rp.add_argument("--lock-ttl", type=int, default=600, help="Seconds before stale lock is considered expired")
    rp.set_defaults(func=cmd_rotate)

    # list
    lp = sub.add_parser("list", help="List keys from JWKS")
    lp.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    lp.set_defaults(func=cmd_list)

    # show-active
    sp = sub.add_parser("show-active", help="Print current primary kid")
    sp.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    sp.set_defaults(func=cmd_show_active)

    # revoke
    rv = sub.add_parser("revoke", help="Mark key as revoked with TTL")
    rv.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    rv.add_argument("--kid", required=True, help="Key id to revoke")
    rv.add_argument("--ttl", type=int, default=3600, help="Seconds until revoked key removal on cleanup")
    rv.set_defaults(func=cmd_revoke)

    # cleanup
    cp = sub.add_parser("cleanup", help="Remove expired retiring/revoked keys")
    cp.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    cp.set_defaults(func=cmd_cleanup)

    # verify
    vf = sub.add_parser("verify", help="Self-verify signing with stored private key and JWKS public part")
    vf.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    vf.add_argument("--keys-dir", required=True, help="Directory with private keys")
    vf.add_argument("--kid", default="", help="kid to verify (defaults to primary)")
    vf.set_defaults(func=cmd_verify)

    return p

def main(argv: Optional[List[str]] = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)

        # Defaults influenced by environment
        if getattr(args, "kid_prefix", None) and args.kid_prefix == "kid-":
            args.kid_prefix = os.getenv("ROTATE_KID_PREFIX", args.kid_prefix)

        if getattr(args, "min_interval", None) is not None:
            env_min = os.getenv("ROTATE_MIN_INTERVAL")
            if env_min and env_min.isdigit():
                args.min_interval = int(env_min)

        return args.func(args)
    except RotationError as e:
        print(str(e), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

if __name__ == "__main__":
    sys.exit(main())
