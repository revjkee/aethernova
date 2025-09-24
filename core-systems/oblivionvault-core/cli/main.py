#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oblivionvault-core CLI
Стандартная точка входа для операций безопасности и утилит:
- Идентификаторы: ULID/UUIDv7 (монотонические)
- Токены: verify
- Авторизация: check
- Крипто: seal/unseal, sign/verify-sign
- Здоровье бекенда: probe

Зависимости: только стандартная библиотека.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import typing as _t
import datetime as dt
import logging

# Внутренние модули oblivionvault-core
try:
    from oblivionvault.adapters.security_core_adapter import (
        SecurityCoreSettings,
        SecurityCoreAdapter,
        SecurityCoreError,
        TransportError,
        TokenVerificationError,
        AuthorizationDenied,
        CryptoError,
        ConfigurationError,
    )
except Exception as _e:  # pragma: no cover
    print("FATAL: cannot import security_core_adapter: %r" % _e, file=sys.stderr)
    sys.exit(20)

try:
    from oblivionvault.utils.idgen import IdGenConfig, IdGenerator
except Exception as _e:  # pragma: no cover
    print("FATAL: cannot import idgen utils: %r" % _e, file=sys.stderr)
    sys.exit(21)


VERSION = "1.0.0"

# ------------------------- JSON Logging (stderr) -------------------------

class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Дополнительные поля из record.__dict__
        for k, v in record.__dict__.items():
            if k in ("msg", "args", "created", "levelname", "name", "exc_info"):
                continue
            if k.startswith("_"):
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except Exception:
                payload[k] = repr(v)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def _setup_logger(level: str, quiet: bool) -> logging.Logger:
    logger = logging.getLogger("oblivionvault.cli")
    logger.propagate = False
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers and not quiet:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_JsonLogFormatter())
        logger.addHandler(h)
    return logger

LOGGER = _setup_logger("INFO", False)

# ------------------------- Utils: IO & Encoding -------------------------

def _read_all_binary(path: str | None) -> bytes:
    if not path or path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()

def _write_all_binary(path: str | None, data: bytes) -> None:
    if not path or path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        with open(path, "wb") as f:
            f.write(data)

def _read_json(path: str | None) -> _t.Any:
    raw = _read_all_binary(path)
    return json.loads(raw.decode("utf-8"))

def _write_json(obj: _t.Any, compact: bool) -> None:
    if compact:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    else:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2))
    sys.stdout.write("\n")
    sys.stdout.flush()

def _to_bytes(data: str | bytes, encoding: str) -> bytes:
    """
    encoding: raw | utf8 | base64url
    """
    if isinstance(data, bytes):
        return data
    enc = encoding.lower()
    if enc == "raw":
        return data.encode("utf-8")  # трактуем как прямые байты из строки
    if enc == "utf8":
        return data.encode("utf-8")
    if enc == "base64url":
        pad = "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data + pad)
    raise ValueError("unsupported input encoding")

def _from_bytes(data: bytes, encoding: str) -> str:
    enc = encoding.lower()
    if enc == "raw":
        return data.decode("utf-8", errors="strict")
    if enc == "utf8":
        return data.decode("utf-8", errors="strict")
    if enc == "base64url":
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    raise ValueError("unsupported output encoding")

# ------------------------- Config from ENV/Args -------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

def _str_or_none(s: str | None) -> str | None:
    return s if s else None

def _build_settings(args: argparse.Namespace) -> SecurityCoreSettings:
    # ENV имеют префикс OV_*
    endpoint = args.endpoint or os.getenv("OV_ENDPOINT")
    api_key = args.api_key or os.getenv("OV_API_KEY")
    jwks_url = args.jwks_url or os.getenv("OV_JWKS_URL")
    issuer = args.issuer or os.getenv("OV_ISSUER")
    audience = args.audience or os.getenv("OV_AUDIENCE")
    kms_key_id = args.kms_key_id or os.getenv("OV_KMS_KEY_ID")
    mtls_cert = args.mtls_cert or os.getenv("OV_MTLS_CERT")
    mtls_key = args.mtls_key or os.getenv("OV_MTLS_KEY")
    verify_tls = args.verify_tls if args.verify_tls is not None else _env_bool("OV_VERIFY_TLS", True)
    audit_channel = args.audit_channel or os.getenv("OV_AUDIT_CHANNEL")

    timeout_s = args.timeout if args.timeout is not None else float(os.getenv("OV_TIMEOUT_S", "5.0"))
    retries = args.retries if args.retries is not None else int(os.getenv("OV_MAX_RETRIES", "3"))
    backoff = args.backoff if args.backoff is not None else int(os.getenv("OV_BACKOFF_MS", "100"))
    circ_thr = args.circuit_threshold if args.circuit_threshold is not None else int(os.getenv("OV_CIRCUIT_THRESHOLD", "8"))
    half_open = args.half_open if args.half_open is not None else float(os.getenv("OV_HALF_OPEN_S", "15.0"))
    cache_ttl = args.cache_ttl if args.cache_ttl is not None else int(os.getenv("OV_CACHE_TTL_S", "300"))

    settings = SecurityCoreSettings(
        endpoint=_str_or_none(endpoint),
        api_key=_str_or_none(api_key),
        jwks_url=_str_or_none(jwks_url),
        issuer=_str_or_none(issuer),
        audience=_str_or_none(audience),
        request_timeout_s=float(timeout_s),
        max_retries=int(retries),
        retry_backoff_base_ms=int(backoff),
        circuit_fail_threshold=int(circ_thr),
        circuit_half_open_after_s=float(half_open),
        cache_ttl_s=int(cache_ttl),
        kms_key_id=_str_or_none(kms_key_id),
        audit_channel=_str_or_none(audit_channel),
        mtls_cert=_str_or_none(mtls_cert),
        mtls_key=_str_or_none(mtls_key),
        verify_tls=bool(verify_tls),
    )
    return settings

# ------------------------- Subcommand Implementations -------------------------

async def _cmd_id_new(args: argparse.Namespace) -> int:
    cfg = IdGenConfig(
        strategy=args.strategy,
        encoding=args.encoding,
        prefix=args.prefix,
        sep=args.sep,
        uppercase=args.uppercase,
        fixed_len=not args.no_fixed_len,
        monotonic=not args.no_monotonic,
    )
    gen = IdGenerator(cfg)
    if args.with_ts:
        ident, ts = gen.new_raw_with_ts()
        _write_json({"id": ident, "ts_ms": ts}, compact=args.compact)
    else:
        ident = gen.new_id()
        _write_json({"id": ident}, compact=args.compact)
    return 0

async def _cmd_token_verify(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    token = args.token
    if not token:
        token = _read_all_binary(args.infile).decode("utf-8").strip()
    try:
        principal = await adapter.verify_token(token)
        out = {
            "sub": principal.sub,
            "roles": list(principal.roles),
            "attrs": dict(principal.attrs),
            "exp": principal.exp,
            "iat": principal.iat,
            "iss": principal.iss,
            "aud": principal.aud,
        }
        _write_json(out, compact=args.compact)
        return 0
    except TokenVerificationError as e:
        LOGGER.error("token_verify_failed", extra={"error": str(e)})
        return 3
    finally:
        await adapter.aclose()

async def _cmd_auth_check(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    try:
        token = args.token or _read_all_binary(args.infile).decode("utf-8").strip()
        principal = await adapter.verify_token(token)
        context = {}
        if args.context:
            context = json.loads(args.context)
        elif args.context_file:
            context = _read_json(args.context_file)
        decision = await adapter.authorize(principal, args.action, args.resource, context=context)
        _write_json(
            {
                "allow": decision.allow,
                "reason": decision.reason,
                "policy_id": decision.policy_id,
                "obligations": decision.obligations,
            },
            compact=args.compact,
        )
        return 0
    except AuthorizationDenied as e:
        _write_json({"allow": False, "reason": str(e)}, compact=args.compact)
        return 4
    except (TokenVerificationError, TransportError, SecurityCoreError) as e:
        LOGGER.error("auth_check_failed", extra={"error": str(e)})
        return 4
    finally:
        await adapter.aclose()

async def _cmd_seal(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    try:
        data = _read_all_binary(args.infile)
        if args.in_encoding != "raw":
            # если текст — сначала в bytes согласно указанию
            data = _to_bytes(data.decode("utf-8"), args.in_encoding)
        aad: bytes | None = None
        if args.aad:
            aad = _to_bytes(args.aad, args.aad_encoding)
        meta = {}
        if args.meta:
            meta = json.loads(args.meta)
        elif args.meta_file:
            meta = _read_json(args.meta_file)

        blob = await adapter.seal(data, aad=aad, meta=meta)
        out = {
            "v": blob.v,
            "alg": blob.alg,
            "kms_key_id": blob.kms_key_id,
            "iv": blob.iv,
            "tag": blob.tag,
            "wrapped_key": blob.wrapped_key,
            "aad": blob.aad,
            "ct": blob.ct,
            "created": blob.created,
            "meta": blob.meta,
        }
        _write_json(out, compact=args.compact)
        return 0
    except CryptoError as e:
        LOGGER.error("seal_failed", extra={"error": str(e)})
        return 5
    finally:
        await adapter.aclose()

async def _cmd_unseal(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    try:
        blob = _read_json(args.blob)
        # типизация по полям SealedBlob
        plaintext = await adapter.unseal(_dict_to_sealed(blob), aad=_to_bytes(args.aad, args.aad_encoding) if args.aad else None)
        out_data = _from_bytes(plaintext, args.out_encoding)
        if args.out_encoding in ("raw", "utf8"):
            _write_all_binary(args.outfile, out_data.encode("utf-8"))
        else:
            _write_all_binary(args.outfile, out_data.encode("ascii"))
        return 0
    except CryptoError as e:
        LOGGER.error("unseal_failed", extra={"error": str(e)})
        return 5
    finally:
        await adapter.aclose()

async def _cmd_sign(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    try:
        payload = _read_all_binary(args.infile)
        if args.in_encoding != "raw":
            payload = _to_bytes(payload.decode("utf-8"), args.in_encoding)
        sig = await adapter.sign(payload, key_id=args.key_id, alg=args.alg)
        _write_json({"signature": sig}, compact=args.compact)
        return 0
    except CryptoError as e:
        LOGGER.error("sign_failed", extra={"error": str(e)})
        return 5
    finally:
        await adapter.aclose()

async def _cmd_verify_sign(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    try:
        payload = _read_all_binary(args.infile)
        if args.in_encoding != "raw":
            payload = _to_bytes(payload.decode("utf-8"), args.in_encoding)
        ok = await adapter.verify(payload, signature=args.signature, key_id=args.key_id, alg=args.alg)
        _write_json({"valid": bool(ok)}, compact=args.compact)
        return 0 if ok else 3
    except CryptoError as e:
        LOGGER.error("verify_failed", extra={"error": str(e)})
        return 5
    finally:
        await adapter.aclose()

async def _cmd_probe(args: argparse.Namespace, settings: SecurityCoreSettings) -> int:
    adapter = SecurityCoreAdapter(settings)
    try:
        # Не все бэкенды имеют /v1/health; допускаем /health
        for path in ("/v1/health", "/health"):
            try:
                resp = await adapter.transport.get(path)
                _write_json({"ok": True, "endpoint": path, "response": resp}, compact=args.compact)
                return 0
            except Exception:
                continue
        _write_json({"ok": False, "error": "no health endpoint"}, compact=args.compact)
        return 6
    finally:
        await adapter.aclose()

# ------------------------- Helpers -------------------------

def _dict_to_sealed(d: dict) -> _t.Any:
    # Ленивая модель без прямого импорта dataclass (совместимо по ключам)
    class _SB(_t.Protocol):
        v: int; alg: str; kms_key_id: str; iv: str; tag: str; wrapped_key: str; aad: str | None; ct: str; created: str; meta: dict
    # Превращаем dict в объект с атрибутами через type()
    return _SimpleNamespace(**d)

class _SimpleNamespace:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# ------------------------- Argparse -------------------------

def _add_global_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--endpoint", help="Security Core base URL (or OV_ENDPOINT)")
    p.add_argument("--api-key", help="API key (or OV_API_KEY)")
    p.add_argument("--jwks-url", help="JWKS URL for JWT verification (or OV_JWKS_URL)")
    p.add_argument("--issuer", help="Expected token issuer (or OV_ISSUER)")
    p.add_argument("--audience", help="Expected token audience (or OV_AUDIENCE)")
    p.add_argument("--kms-key-id", help="KMS key id (or OV_KMS_KEY_ID)")
    p.add_argument("--verify-tls", type=lambda s: s.lower() in ("1", "true", "yes", "y", "on"), help="Verify TLS (default true or OV_VERIFY_TLS)")
    p.add_argument("--mtls-cert", help="Path to mTLS cert (or OV_MTLS_CERT)")
    p.add_argument("--mtls-key", help="Path to mTLS key (or OV_MTLS_KEY)")
    p.add_argument("--timeout", type=float, help="HTTP timeout seconds (or OV_TIMEOUT_S)")
    p.add_argument("--retries", type=int, help="Max retries (or OV_MAX_RETRIES)")
    p.add_argument("--backoff", type=int, help="Base backoff ms (or OV_BACKOFF_MS)")
    p.add_argument("--circuit-threshold", type=int, help="Circuit failure threshold (or OV_CIRCUIT_THRESHOLD)")
    p.add_argument("--half-open", type=float, help="Circuit half-open seconds (or OV_HALF_OPEN_S)")
    p.add_argument("--cache-ttl", type=int, help="Cache TTL seconds (or OV_CACHE_TTL_S)")
    p.add_argument("--audit-channel", help="Audit channel name (or OV_AUDIT_CHANNEL)")
    p.add_argument("--log-level", default="INFO", help="Logging level (INFO, WARN, ERROR)")
    p.add_argument("--quiet", action="store_true", help="Disable logs to stderr")
    p.add_argument("--compact", action="store_true", help="Compact JSON output to stdout")
    p.add_argument("--version", action="store_true", help="Show CLI version")

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oblivionvault", description="OblivionVault Core CLI")
    _add_global_options(p)
    sub = p.add_subparsers(dest="cmd", required=True)

    # id new
    p_id = sub.add_parser("id", help="ID utilities")
    sub_id = p_id.add_subparsers(dest="id_cmd", required=True)
    p_id_new = sub_id.add_parser("new", help="Generate new identifier")
    p_id_new.add_argument("--strategy", choices=("ulid", "uuid7"), default="uuid7")
    p_id_new.add_argument("--encoding", choices=("base32", "base62", "base64", "hex", "uuid"), default="base62")
    p_id_new.add_argument("--prefix", default=None)
    p_id_new.add_argument("--sep", default="_")
    p_id_new.add_argument("--uppercase", action="store_true")
    p_id_new.add_argument("--no-fixed-len", action="store_true", help="Disable fixed length encoding")
    p_id_new.add_argument("--no-monotonic", action="store_true", help="Disable monotonic increment")
    p_id_new.add_argument("--with-ts", action="store_true", help="Output id and timestamp")
    p_id_new.add_argument("--compact", action="store_true", help="Compact JSON output")
    p_id_new.set_defaults(func=lambda a, s: _cmd_id_new(a))

    # token verify
    p_tv = sub.add_parser("token", help="Token operations")
    sub_tv = p_tv.add_subparsers(dest="token_cmd", required=True)
    p_tv_v = sub_tv.add_parser("verify", help="Verify token")
    p_tv_v.add_argument("--token", help="JWT/Opaque token (if omitted, read from --in or stdin)")
    p_tv_v.add_argument("--in", dest="infile", default="-", help="Input file ('-' for stdin)")
    p_tv_v.add_argument("--compact", action="store_true")
    p_tv_v.set_defaults(func=lambda a, s: _cmd_token_verify(a, s))

    # auth check
    p_auth = sub.add_parser("auth", help="Authorization operations")
    sub_auth = p_auth.add_subparsers(dest="auth_cmd", required=True)
    p_auth_c = sub_auth.add_parser("check", help="Authorize action on resource")
    p_auth_c.add_argument("--token", help="Token (if omitted, read from --in or stdin)")
    p_auth_c.add_argument("--in", dest="infile", default="-", help="Input file for token")
    p_auth_c.add_argument("--action", required=True, help="Action name")
    p_auth_c.add_argument("--resource", required=True, help="Resource identifier")
    p_auth_c.add_argument("--context", help="Inline JSON context")
    p_auth_c.add_argument("--context-file", help="Path to JSON context")
    p_auth_c.add_argument("--compact", action="store_true")
    p_auth_c.set_defaults(func=lambda a, s: _cmd_auth_check(a, s))

    # seal
    p_seal = sub.add_parser("seal", help="Encrypt (envelope) data into sealed blob")
    p_seal.add_argument("--in", dest="infile", default="-", help="Input file ('-' for stdin)")
    p_seal.add_argument("--in-encoding", choices=("raw", "utf8", "base64url"), default="raw")
    p_seal.add_argument("--aad", help="AAD string")
    p_seal.add_argument("--aad-encoding", choices=("raw", "utf8", "base64url"), default="utf8")
    p_seal.add_argument("--meta", help="Inline JSON meta")
    p_seal.add_argument("--meta-file", help="Path to JSON meta")
    p_seal.add_argument("--compact", action="store_true")
    p_seal.set_defaults(func=lambda a, s: _cmd_seal(a, s))

    # unseal
    p_uns = sub.add_parser("unseal", help="Decrypt sealed blob back to plaintext")
    p_uns.add_argument("--blob", required=True, help="Path to blob JSON ('-' for stdin)")
    p_uns.add_argument("--out", dest="outfile", default="-", help="Output file ('-' for stdout)")
    p_uns.add_argument("--out-encoding", choices=("raw", "utf8", "base64url"), default="raw")
    p_uns.add_argument("--aad", help="AAD string")
    p_uns.add_argument("--aad-encoding", choices=("raw", "utf8", "base64url"), default="utf8")
    p_uns.set_defaults(func=lambda a, s: _cmd_unseal(a, s))

    # sign
    p_sign = sub.add_parser("sign", help="Sign payload via KMS")
    p_sign.add_argument("--in", dest="infile", default="-", help="Input file ('-' for stdin)")
    p_sign.add_argument("--in-encoding", choices=("raw", "utf8", "base64url"), default="raw")
    p_sign.add_argument("--key-id", help="Override KMS key id")
    p_sign.add_argument("--alg", default="EdDSA")
    p_sign.add_argument("--compact", action="store_true")
    p_sign.set_defaults(func=lambda a, s: _cmd_sign(a, s))

    # verify-sign
    p_vsig = sub.add_parser("verify-sign", help="Verify signature via KMS")
    p_vsig.add_argument("--in", dest="infile", default="-", help="Input file ('-' for stdin)")
    p_vsig.add_argument("--in-encoding", choices=("raw", "utf8", "base64url"), default="raw")
    p_vsig.add_argument("--signature", required=True, help="Signature string")
    p_vsig.add_argument("--key-id", help="Override KMS key id")
    p_vsig.add_argument("--alg", default="EdDSA")
    p_vsig.add_argument("--compact", action="store_true")
    p_vsig.set_defaults(func=lambda a, s: _cmd_verify_sign(a, s))

    # probe
    p_probe = sub.add_parser("probe", help="Probe backend health")
    p_probe.add_argument("--compact", action="store_true")
    p_probe.set_defaults(func=lambda a, s: _cmd_probe(a, s))

    return p

# ------------------------- Main -------------------------

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        sys.stdout.write(json.dumps({"version": VERSION}, ensure_ascii=False) + "\n")
        return 0

    # Логи
    global LOGGER
    LOGGER = _setup_logger(args.log_level, args.quiet)

    # Команды без настроек (локальные)
    if args.cmd == "id" and args.id_cmd == "new":
        return asyncio.run(_cmd_id_new(args))

    # Остальные команды требуют настроек
    try:
        settings = _build_settings(args)
    except ConfigurationError as e:
        LOGGER.error("config_error", extra={"error": str(e)})
        return 7

    # Диспетчеризация
    try:
        handler = getattr(args, "func", None)
        if handler is None:
            parser.print_help()
            return 2
        return asyncio.run(handler(args, settings))
    except KeyboardInterrupt:
        LOGGER.warning("interrupted")
        return 130
    except SystemExit as e:
        return int(e.code) if e.code is not None else 1
    except Exception as e:
        LOGGER.error("unhandled_exception", extra={"error": repr(e)})
        return 10

# Точка входа
if __name__ == "__main__":
    sys.exit(main())
