# oblivionvault-core/cli/admin.py
# Unified administrative CLI for OblivionVault
# Python 3.10+
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

# Internal modules
try:
    from oblivionvault.adapters.kms_adapter import (
        load_kms_from_env,
        KmsAdapter,
        OpenSSLRSABackend,
        Envelope,
        KmsError,
        OpenSSLNotFound as KmsOpenSSLNotFound,
    )
except Exception as e:  # pragma: no cover
    print(json.dumps({"ok": False, "error": f"ImportError(kms_adapter): {e}"}), file=sys.stderr)
    sys.exit(3)

try:
    from oblivionvault.evidence.packager import EvidencePackager, EvidenceError
except Exception as e:  # pragma: no cover
    print(json.dumps({"ok": False, "error": f"ImportError(packager): {e}"}), file=sys.stderr)
    sys.exit(3)

# Logging: CLI prints only JSON on stdout; logs go to stderr.
logger = logging.getLogger("oblivionvault.cli.admin")
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)
logger.setLevel(logging.WARNING)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_DEP = 3

# --------------------------
# Helpers
# --------------------------
def _openssl_bin() -> Optional[str]:
    return os.getenv("OPENSSL_PATH") or shutil.which("openssl")

def _run_openssl(args: list[str], input_bytes: Optional[bytes] = None) -> bytes:
    bin_path = _openssl_bin()
    if not bin_path:
        raise KmsOpenSSLNotFound("OpenSSL not found in PATH or OPENSSL_PATH")
    proc = subprocess.run(
        [bin_path] + args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise KmsError(f"OpenSSL error ({' '.join(args)}): {proc.stderr.decode('utf-8', 'ignore')}")
    return proc.stdout

def _read_in(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()

def _write_out(path: str, data: bytes) -> None:
    if path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

def _kv_pairs_to_dict(pairs: list[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for s in pairs or []:
        if "=" not in s:
            raise argparse.ArgumentTypeError(f"Expected key=value, got: {s}")
        k, v = s.split("=", 1)
        out[k] = v
    return out

def _json_print(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True))

def _set_verbosity(verbosity: int) -> None:
    if verbosity == 0:
        logger.setLevel(logging.WARNING)
    elif verbosity == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)

# --------------------------
# info subcommands
# --------------------------
def cmd_info_system(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    info = {
        "ok": True,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "openssl": _openssl_bin() or "",
        "env": {
            "OPENSSL_PATH": os.getenv("OPENSSL_PATH") or "",
            "OBLIVIONVAULT_KMS_BACKEND": os.getenv("OBLIVIONVAULT_KMS_BACKEND") or "",
            "OBLIVIONVAULT_KMS_KEY_ID": os.getenv("OBLIVIONVAULT_KMS_KEY_ID") or "",
        },
    }
    _json_print(info)
    return EXIT_OK

def cmd_info_openssl(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        ver = _run_openssl(["version"]).decode().strip()
        ciphers = _run_openssl(["enc", "-ciphers"]).decode().strip().splitlines()
        _json_print({"ok": True, "version": ver, "enc_ciphers": ciphers})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_DEP

# --------------------------
# kms subcommands
# --------------------------
def cmd_kms_gen_keypair(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    priv = outdir / f"{args.key_id}.priv.pem"
    pub = outdir / f"{args.key_id}.pub.pem"
    try:
        _run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{args.bits}", "-out", str(priv)])
        _run_openssl(["rsa", "-in", str(priv), "-pubout", "-out", str(pub)])
        # fingerprint SPKI DER
        spki = _run_openssl(["pkey", "-in", str(pub), "-pubin", "-pubout", "-outform", "DER"])
        fp = __import__("hashlib").sha256(spki).hexdigest()
        _json_print({"ok": True, "key_id": args.key_id, "priv_pem": str(priv), "pub_pem": str(pub), "fingerprint": fp, "bits": args.bits})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_kms_fingerprint(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        spki = _run_openssl(["pkey", "-in", args.pub_pem, "-pubin", "-pubout", "-outform", "DER"])
        fp = __import__("hashlib").sha256(spki).hexdigest()
        _json_print({"ok": True, "pub_pem": args.pub_pem, "fingerprint": fp})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def _make_adapter_from_args(args: argparse.Namespace) -> KmsAdapter:
    # Prefer explicit key files if provided, else ENV
    if args.pub_pem:
        backend = OpenSSLRSABackend(key_id=args.key_id, pub_pem=args.pub_pem, priv_pem=args.priv_pem)
        return KmsAdapter(backend=backend, default_key_id=args.key_id)
    return load_kms_from_env()

def cmd_kms_wrap(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        adapter = _make_adapter_from_args(args)
        backend = adapter.backend  # type: ignore
        wrapped, fp = backend.wrap_key(args.key_id or adapter.default_key_id, base64.b64decode(args.data_b64))
        _json_print({"ok": True, "key_id": args.key_id or adapter.default_key_id, "fingerprint": fp, "wrapped_b64": base64.b64encode(wrapped).decode("ascii")})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_kms_unwrap(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        adapter = _make_adapter_from_args(args)
        backend = adapter.backend  # type: ignore
        pt = backend.unwrap_key(args.key_id or adapter.default_key_id, base64.b64decode(args.data_b64))
        _json_print({"ok": True, "key_id": args.key_id or adapter.default_key_id, "plaintext_b64": base64.b64encode(pt).decode("ascii")})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_kms_selfcheck(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        adapter = _make_adapter_from_args(args)
        sample = b"oblivionvault-kms-selfcheck"
        env = adapter.encrypt(sample, {"purpose": "self-check"})
        out = adapter.decrypt(env)
        ok = out == sample
        _json_print({"ok": ok, "key_id": env.meta.key_id, "fingerprint": env.meta.key_fingerprint})
        return EXIT_OK if ok else EXIT_FAIL
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

# --------------------------
# envelope subcommands
# --------------------------
def cmd_env_encrypt(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        adapter = _make_adapter_from_args(args)
        plaintext = _read_in(args.input)
        aad = _kv_pairs_to_dict(args.aad or [])
        env = adapter.encrypt(plaintext, aad, key_id=args.key_id or adapter.default_key_id)
        _write_out(args.output, env.to_bytes())
        _json_print({"ok": True, "key_id": env.meta.key_id, "fingerprint": env.meta.key_fingerprint, "output": args.output})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_env_decrypt(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        adapter = _make_adapter_from_args(args)
        data = _read_in(args.input)
        env = Envelope.from_bytes(data)
        pt = adapter.decrypt(env)
        _write_out(args.output, pt)
        _json_print({"ok": True, "key_id": env.meta.key_id, "output": args.output})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_env_rewrap(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        # Old adapter for unwrap
        old_adapter = _make_adapter_from_args(args)
        data = _read_in(args.input)
        env = Envelope.from_bytes(data)
        # New backend for rewrap
        if not args.new_pub_pem or not args.new_key_id:
            raise KmsError("new_key_id and new_pub_pem are required for rewrap")
        new_backend = OpenSSLRSABackend(key_id=args.new_key_id, pub_pem=args.new_pub_pem, priv_pem=None)
        new_adapter = KmsAdapter(backend=new_backend, default_key_id=args.new_key_id)
        rewrapped = old_adapter.rewrap(env, new_key_id=args.new_key_id)
        # Replace meta fingerprint to ensure new backend’s value (already set in rewrap)
        _write_out(args.output, rewrapped.to_bytes())
        _json_print({"ok": True, "old_key_id": env.meta.key_id, "new_key_id": args.new_key_id, "output": args.output})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

# --------------------------
# evidence subcommands
# --------------------------
def cmd_evd_pack(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        pkg = EvidencePackager(
            package_name=args.name,
            compression=args.compression,
            include_hidden=args.include_hidden,
            follow_symlinks=args.follow_symlinks,
            exclude=args.exclude or [],
            annotations=_kv_pairs_to_dict(args.annotation or []),
            policies=_kv_pairs_to_dict(args.policy or []),
            max_workers=args.workers,
        )
        pkg.add_chain_event("COLLECTION_STARTED")
        for src in args.input:
            p = Path(src)
            logical_prefix = args.prefix or (p.stem if p.is_dir() else "")
            pkg.add_path(p, logical_prefix=logical_prefix)
        for item in args.inline or []:
            name, data = item.split("=", 1)
            pkg.add_bytes(name=name, data=data.encode("utf-8"), mode=0o600)
        pkg.add_chain_event("PACKAGING", note="Finalizing package")

        sign_key = Path(args.sign_key) if args.sign_key else None
        sign_cert = Path(args.sign_cert) if args.sign_cert else None

        out = pkg.finalize(
            output_path=Path(args.output),
            sign_manifest_with_key=sign_key,
            sign_cert=sign_cert,
            encrypt_with_pass_env=args.encrypt_env,
            openssl_cipher=args.cipher,
            compute_sidecar_hash=not args.no_sidecar,
        )
        _json_print({"ok": True, "output": str(out)})
        return EXIT_OK
    except (EvidenceError, Exception) as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_evd_verify(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    try:
        report = EvidencePackager.verify_package(Path(args.package), pass_env=args.pass_env)
        report["ok"] = True
        _json_print(report)
        return EXIT_OK
    except (EvidenceError, Exception) as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

def cmd_evd_list(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    import tarfile
    try:
        names: list[str] = []
        with tarfile.open(args.package, mode="r:*") as tar:
            names = sorted(m.name for m in tar.getmembers())
        _json_print({"ok": True, "package": args.package, "members": names})
        return EXIT_OK
    except Exception as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL

# --------------------------
# doctor subcommand
# --------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    _set_verbosity(args.verbose)
    checks = []
    ok = True

    def add(name: str, passed: bool, detail: str = ""):
        nonlocal ok
        ok = ok and passed
        checks.append({"name": name, "ok": passed, "detail": detail})

    # OpenSSL
    binp = _openssl_bin()
    add("openssl_present", bool(binp), f"path={binp or ''}")
    if binp:
        try:
            ver = _run_openssl(["version"]).decode().strip()
            add("openssl_version", True, ver)
        except Exception as e:
            add("openssl_version", False, str(e))

    # KMS env
    have_pub = bool(os.getenv("OBLIVIONVAULT_KMS_PUB_PEM"))
    add("env_KMS_PUB", have_pub, os.getenv("OBLIVIONVAULT_KMS_PUB_PEM") or "")
    # Self-check if possible
    if have_pub:
        try:
            adapter = load_kms_from_env()
            sample = b"doctor-selfcheck"
            env = adapter.encrypt(sample, {"purpose": "doctor"})
            out = adapter.decrypt(env)
            add("kms_selfcheck", out == sample, f"key_id={env.meta.key_id}")
        except Exception as e:
            add("kms_selfcheck", False, str(e))
    else:
        add("kms_selfcheck", False, "OBLIVIONVAULT_KMS_PUB_PEM not set")

    # Tarfile capability smoke test
    try:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.txt"
            p.write_text("ok", encoding="utf-8")
            ev = EvidencePackager("doctor-check", compression="gz")
            ev.add_path(p, logical_prefix="")
            outp = ev.finalize(Path(td) / "pkg.tar.gz", compute_sidecar_hash=False)
            rep = EvidencePackager.verify_package(outp)
            add("evidence_pack_verify", rep.get("files_verified", 0) >= 1, f"merkle_root={rep.get('merkle_root','')}")
    except Exception as e:
        add("evidence_pack_verify", False, str(e))

    _json_print({"ok": ok, "checks": checks})
    return EXIT_OK if ok else EXIT_FAIL

# --------------------------
# Parser
# --------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oblivionvault-admin", description="OblivionVault Admin CLI")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    sub = p.add_subparsers(dest="cmd", required=True)

    # info
    p_info = sub.add_parser("info", help="Information utilities")
    sub_info = p_info.add_subparsers(dest="subcmd", required=True)

    si_sys = sub_info.add_parser("system", help="Print system info")
    si_sys.set_defaults(func=cmd_info_system)

    si_ssl = sub_info.add_parser("openssl", help="Print OpenSSL details")
    si_ssl.set_defaults(func=cmd_info_openssl)

    # kms
    p_kms = sub.add_parser("kms", help="KMS operations")
    sub_kms = p_kms.add_subparsers(dest="subcmd", required=True)

    k_gen = sub_kms.add_parser("gen-keypair", help="Generate RSA keypair (OpenSSL)")
    k_gen.add_argument("--outdir", required=True)
    k_gen.add_argument("--key-id", required=True)
    k_gen.add_argument("--bits", type=int, default=4096, choices=(2048, 3072, 4096))
    k_gen.set_defaults(func=cmd_kms_gen_keypair)

    k_fp = sub_kms.add_parser("fingerprint", help="Compute RSA public key fingerprint (SHA-256 of SPKI)")
    k_fp.add_argument("--pub-pem", required=True)
    k_fp.set_defaults(func=cmd_kms_fingerprint)

    k_wrap = sub_kms.add_parser("wrap", help="Wrap DEK (base64) with RSA-OAEP-SHA256")
    k_wrap.add_argument("--data-b64", required=True)
    k_wrap.add_argument("--key-id", help="Logical key id")
    k_wrap.add_argument("--pub-pem")
    k_wrap.add_argument("--priv-pem")
    k_wrap.set_defaults(func=cmd_kms_wrap)

    k_unwrap = sub_kms.add_parser("unwrap", help="Unwrap DEK (base64) with RSA-OAEP-SHA256")
    k_unwrap.add_argument("--data-b64", required=True)
    k_unwrap.add_argument("--key-id", help="Logical key id")
    k_unwrap.add_argument("--pub-pem")
    k_unwrap.add_argument("--priv-pem")
    k_unwrap.set_defaults(func=cmd_kms_unwrap)

    k_self = sub_kms.add_parser("self-check", help="KMS self-check encrypt/decrypt")
    k_self.add_argument("--key-id", help="Logical key id")
    k_self.add_argument("--pub-pem")
    k_self.add_argument("--priv-pem")
    k_self.set_defaults(func=cmd_kms_selfcheck)

    # envelope
    p_env = sub.add_parser("envelope", help="Envelope encryption using KMS")
    sub_env = p_env.add_subparsers(dest="subcmd", required=True)

    e_enc = sub_env.add_parser("encrypt", help="Encrypt data with envelope scheme")
    e_enc.add_argument("-i", "--input", required=True, help="Input file or '-' for stdin")
    e_enc.add_argument("-o", "--output", required=True, help="Output file or '-' for stdout (JSON envelope)")
    e_enc.add_argument("--key-id", help="Override logical key id")
    e_enc.add_argument("--pub-pem", help="RSA public key (overrides ENV)")
    e_enc.add_argument("--priv-pem", help="RSA private key (optional)")
    e_enc.add_argument("--aad", action="append", help="Additional authenticated data key=value", default=[])
    e_enc.set_defaults(func=cmd_env_encrypt)

    e_dec = sub_env.add_parser("decrypt", help="Decrypt data from envelope")
    e_dec.add_argument("-i", "--input", required=True, help="Input file or '-' for stdin (JSON envelope)")
    e_dec.add_argument("-o", "--output", required=True, help="Output file or '-' for stdout (plaintext)")
    e_dec.add_argument("--key-id", help="Logical key id")
    e_dec.add_argument("--pub-pem", help="RSA public key (optional)")
    e_dec.add_argument("--priv-pem", help="RSA private key for unwrap")
    e_dec.set_defaults(func=cmd_env_decrypt)

    e_rw = sub_env.add_parser("rewrap", help="Rewrap envelope to new RSA public key")
    e_rw.add_argument("-i", "--input", required=True, help="JSON envelope file or '-'")
    e_rw.add_argument("-o", "--output", required=True, help="Output file or '-'")
    e_rw.add_argument("--key-id", help="Current logical key id (optional)")
    e_rw.add_argument("--pub-pem", help="Current RSA public (optional)")
    e_rw.add_argument("--priv-pem", help="Current RSA private (for unwrap if needed)")
    e_rw.add_argument("--new-key-id", required=True, help="New logical key id")
    e_rw.add_argument("--new-pub-pem", required=True, help="New RSA public key pem")
    e_rw.set_defaults(func=cmd_env_rewrap)

    # evidence
    p_evd = sub.add_parser("evidence", help="Evidence package operations")
    sub_evd = p_evd.add_subparsers(dest="subcmd", required=True)

    ev_pack = sub_evd.add_parser("pack", help="Create evidence package")
    ev_pack.add_argument("-i", "--input", nargs="+", required=True)
    ev_pack.add_argument("-o", "--output", required=True)
    ev_pack.add_argument("-n", "--name", required=True)
    ev_pack.add_argument("--compression", choices=["xz", "gz", "bz2", "none"], default="xz")
    ev_pack.add_argument("--include-hidden", action="store_true")
    ev_pack.add_argument("--follow-symlinks", action="store_true")
    ev_pack.add_argument("--exclude", nargs="*", default=[])
    ev_pack.add_argument("--annotation", "-A", action="append", help="key=value")
    ev_pack.add_argument("--policy", "-P", action="append", help="key=value")
    ev_pack.add_argument("--inline", "-D", action="append", help="name=string")
    ev_pack.add_argument("--prefix", help="Logical prefix under DATA/ for directory inputs")
    ev_pack.add_argument("--workers", type=int, default=max(os.cpu_count() or 2, 2))
    ev_pack.add_argument("--sign-key", help="PEM private key to sign manifest")
    ev_pack.add_argument("--sign-cert", help="PEM certificate to embed")
    ev_pack.add_argument("--encrypt-env", help="Env var with passphrase for OpenSSL symmetric encryption")
    ev_pack.add_argument("--cipher", default="aes-256-cbc", help="OpenSSL symmetric cipher")
    ev_pack.add_argument("--no-sidecar", action="store_true")
    ev_pack.set_defaults(func=cmd_evd_pack)

    ev_ver = sub_evd.add_parser("verify", help="Verify evidence package")
    ev_ver.add_argument("package")
    ev_ver.add_argument("--pass-env", help="Env var with passphrase if encrypted .enc")
    ev_ver.set_defaults(func=cmd_evd_verify)

    ev_list = sub_evd.add_parser("list", help="List archive members")
    ev_list.add_argument("package")
    ev_list.set_defaults(func=cmd_evd_list)

    # doctor
    p_doc = sub.add_parser("doctor", help="Run environment diagnostics")
    p_doc.set_defaults(func=cmd_doctor)

    return p

# --------------------------
# Main
# --------------------------
def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except argparse.ArgumentError as e:
        _json_print({"ok": False, "error": f"usage error: {e}"})
        return EXIT_USAGE
    except (KmsError, EvidenceError) as e:
        _json_print({"ok": False, "error": str(e)})
        return EXIT_FAIL
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        _json_print({"ok": False, "error": f"unexpected: {e}"})
        return EXIT_FAIL

if __name__ == "__main__":
    raise SystemExit(main())
