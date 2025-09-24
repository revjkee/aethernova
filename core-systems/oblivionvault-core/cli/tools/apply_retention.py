# oblivionvault-core/cli/tools/apply_retention.py
# -*- coding: utf-8 -*-
"""
OblivionVault — CLI: apply_retention

Назначение:
  - Резолв и применение политик хранения (Retention) к объектам архива.

Возможности:
  - Источники политик: файловая директория (JSON/TOML), переменная окружения (JSON/b64)
  - Поддержка HMAC-подписи политик (--policy-hmac-{hex,file})
  - Стратегии резолва: priority | most_restrictive
  - Применение к одному/множеству объектов (--object-id, --objects-file, stdin)
  - Теги для селектора политик (--tag)
  - created_at override (--created-at ISO8601)
  - Dry-run (без изменения состояния)
  - Governance override: --capability-token и --approval-token (повторяемый)
  - JSON-вывод и детерминированные exit codes

Exit codes:
  0  — все операции успешны
  1  — общая ошибка/исключение
  2  — не найдено ни одной подходящей политики (при --fail-on-missing)
  3  — нарушены правила ретенции/Legal Hold (частично/полностью)
  4  — валидация/подпись политики не прошла
  5  — ошибки применения (частичные отказы)

Пример:
  python -m oblivionvault_core.cli.tools.apply_retention \
    --state-dir ./state \
    --policy-dir ./policies \
    --require-signature \
    --resolution most_restrictive \
    --object-id sample/object/001 \
    --actor "ops@node-1"
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import logging
import os
import sys
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

# Импорт ядра OblivionVault
try:
    from oblivionvault.archive.retention_lock import (
        RetentionLockManager,
        RetentionPolicy,
        RetentionMode,
        FilesystemJSONBackend,
        RetentionError,
        PolicyViolation,
        LegalHoldActive,
        ComplianceLockActive,
    )
    from oblivionvault.policy.loader import (
        PolicyLoader,
        LoaderConfig,
        ResolutionStrategy,
        FSDirectorySource,
        EnvVarJSONSource,
        PolicyError,
        PolicyValidationError,
        PolicySignatureError,
    )
except Exception as e:  # pragma: no cover
    print(f"Import error: {e}", file=sys.stderr)
    sys.exit(1)


# -----------------------------
# УТИЛИТЫ
# -----------------------------

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _parse_iso8601(s: str) -> dt.datetime:
    # Допускаем 'Z' в конце и без TZ (тогда считаем UTC)
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1]
    try:
        d = dt.datetime.fromisoformat(s)
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid ISO8601 timestamp: {s}") from e
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)

def _read_bytes_arg(hex_str: Optional[str], file_path: Optional[str]) -> Optional[bytes]:
    """
    Читает ключ из hex-строки или бинарного файла (если указан).
    Возвращает None, если оба параметра не заданы.
    """
    if file_path:
        p = Path(file_path)
        data = p.read_bytes()
        return data
    if hex_str:
        s = hex_str.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        try:
            return bytes.fromhex(s)
        except Exception as e:
            raise argparse.ArgumentTypeError(f"Invalid hex data") from e
    return None

def _iter_objects(args: argparse.Namespace) -> Iterable[str]:
    yielded = False
    # --object-id (повторяемый)
    for oid in args.object_id or []:
        yielded = True
        yield oid
    # --objects-file
    if args.objects_file:
        for line in Path(args.objects_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                yielded = True
                yield line
    # stdin
    if not sys.stdin.isatty():
        for line in sys.stdin.read().splitlines():
            line = line.strip()
            if line:
                yielded = True
                yield line
    if not yielded:
        raise SystemExit("No objects provided. Use --object-id/--objects-file or pipe stdin.")

def _json_print(obj: Mapping, stream=sys.stdout) -> None:
    stream.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()

# -----------------------------
# ЛОГИРОВАНИЕ
# -----------------------------

def _init_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )

# -----------------------------
# ОСНОВНАЯ ЛОГИКА
# -----------------------------

async def _build_policy_loader(
    *,
    policy_dir: Optional[str],
    policy_env: Optional[str],
    policy_hmac: Optional[bytes],
    require_signature: bool,
    resolution: str,
    logger: logging.Logger,
) -> PolicyLoader:
    sources = []
    if policy_dir:
        sources.append(FSDirectorySource(policy_dir))
    if policy_env:
        sources.append(EnvVarJSONSource(policy_env))
    if not sources:
        raise SystemExit("At least one policy source is required (--policy-dir or --policy-env).")
    cfg = LoaderConfig(
        require_signature=require_signature,
        resolution_strategy=ResolutionStrategy(resolution),
    )
    loader = PolicyLoader(sources, hmac_key=policy_hmac, logger=logger, config=cfg)
    await loader.load()
    return loader

def _build_retention_manager(
    *,
    state_dir: str,
    state_hmac: Optional[bytes],
    capability_key: Optional[bytes],
    approver_keys: Sequence[bytes],
    logger: logging.Logger,
) -> Tuple[RetentionLockManager, FilesystemJSONBackend]:
    storage = FilesystemJSONBackend(state_dir)
    # storage.init() — sync в реализации; но вызовем в потоке для совместимости
    # (в реализации init создаёт директории)
    # Мы используем его напрямую — RetentionLockManager сам не вызывает init()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(storage.init())  # безопасно, т.к. мы в main asyncio уже будем после
    mgr = RetentionLockManager(
        storage=storage,
        state_hmac_key=state_hmac,
        capability_key=capability_key,
        approver_secrets=approver_keys,
    )
    return mgr, storage

async def _resolve_policy_for_object(
    *,
    loader: PolicyLoader,
    object_id: str,
    tags: Sequence[str],
    created_at: Optional[dt.datetime],
) -> Optional[RetentionPolicy]:
    return loader.resolve(object_id, tags, created_at=created_at)

async def _apply_one(
    *,
    mgr: RetentionLockManager,
    loader: PolicyLoader,
    object_id: str,
    actor: str,
    tags: Sequence[str],
    created_at: Optional[dt.datetime],
    dry_run: bool,
    capability_token: Optional[str],
    approval_tokens: Sequence[str],
    fail_on_missing: bool,
) -> Mapping:
    pol = await _resolve_policy_for_object(
        loader=loader,
        object_id=object_id,
        tags=tags,
        created_at=created_at,
    )
    if not pol:
        result = {
            "object_id": object_id,
            "status": "no_policy",
            "message": "no applicable policy found",
        }
        if fail_on_missing:
            result["error"] = True
        return result

    if dry_run:
        return {
            "object_id": object_id,
            "status": "dry_run",
            "policy": {
                "mode": pol.mode.value,
                "duration_seconds": pol.duration_seconds,
                "retention_until": pol.retention_until,
                "allow_extension_only": pol.allow_extension_only,
            },
        }

    # Применение политики
    st = await mgr.apply_policy(
        object_id=object_id,
        policy=pol,
        actor=actor,
        created_at=created_at,
        capability_token=capability_token,
        approvals=approval_tokens or None,
    )
    return {
        "object_id": object_id,
        "status": "applied",
        "policy_effective_until": st.retention_until,
        "policy_mode": st.policy.mode.value,
        "allow_extension_only": st.policy.allow_extension_only,
        "legal_hold": st.legal_hold,
        "version": st.version,
        "last_updated": st.last_updated,
    }

async def _cmd_show(args: argparse.Namespace) -> int:
    logger = logging.getLogger("apply_retention.show")
    policy_hmac = _read_bytes_arg(args.policy_hmac_hex, args.policy_hmac_file)
    loader = await _build_policy_loader(
        policy_dir=args.policy_dir,
        policy_env=args.policy_env,
        policy_hmac=policy_hmac,
        require_signature=args.require_signature,
        resolution=args.resolution,
        logger=logger,
    )

    created_at = _parse_iso8601(args.created_at) if args.created_at else None
    tags = tuple(args.tag or [])

    had_missing = False
    for oid in _iter_objects(args):
        pol = await _resolve_policy_for_object(
            loader=loader,
            object_id=oid,
            tags=tags,
            created_at=created_at,
        )
        if not pol:
            _json_print({"object_id": oid, "status": "no_policy"})
            had_missing = True
            continue
        _json_print({
            "object_id": oid,
            "status": "resolved",
            "policy": {
                "mode": pol.mode.value,
                "duration_seconds": pol.duration_seconds,
                "retention_until": pol.retention_until,
                "allow_extension_only": pol.allow_extension_only,
            },
        })
    return 2 if had_missing and args.fail_on_missing else 0

async def _cmd_apply(args: argparse.Namespace) -> int:
    logger = logging.getLogger("apply_retention.apply")

    # Политики
    policy_hmac = _read_bytes_arg(args.policy_hmac_hex, args.policy_hmac_file)
    loader = await _build_policy_loader(
        policy_dir=args.policy_dir,
        policy_env=args.policy_env,
        policy_hmac=policy_hmac,
        require_signature=args.require_signature,
        resolution=args.resolution,
        logger=logger,
    )

    # Менеджер ретенции
    state_hmac = _read_bytes_arg(args.state_hmac_hex, args.state_hmac_file)
    capability_key = _read_bytes_arg(args.capability_key_hex, args.capability_key_file)
    approver_keys: List[bytes] = []
    for s in args.approver_key_hex or []:
        b = _read_bytes_arg(s, None)
        if b:
            approver_keys.append(b)
    for fp in args.approver_key_file or []:
        b = _read_bytes_arg(None, fp)
        if b:
            approver_keys.append(b)

    mgr, _storage = _build_retention_manager(
        state_dir=args.state_dir,
        state_hmac=state_hmac,
        capability_key=capability_key,
        approver_keys=approver_keys,
        logger=logger,
    )

    created_at = _parse_iso8601(args.created_at) if args.created_at else None
    tags = tuple(args.tag or [])
    actor = args.actor or os.getenv("USER") or "cli@host"

    capability_token = args.capability_token
    approval_tokens = tuple(args.approval_token or [])

    # Последовательно (для простоты и предсказуемости аудита)
    had_errors = False
    had_missing = False
    retention_blocked = False

    for oid in _iter_objects(args):
        try:
            res = await _apply_one(
                mgr=mgr,
                loader=loader,
                object_id=oid,
                actor=actor,
                tags=tags,
                created_at=created_at,
                dry_run=args.dry_run,
                capability_token=capability_token,
                approval_tokens=approval_tokens,
                fail_on_missing=args.fail_on_missing,
            )
            _json_print(res)
            if res.get("status") == "no_policy":
                had_missing = True
        except (LegalHoldActive, ComplianceLockActive, PolicyViolation) as e:
            _json_print({"object_id": oid, "status": "blocked", "error": type(e).__name__, "message": str(e)})
            retention_blocked = True
        except (PolicyError, PolicyValidationError, PolicySignatureError) as e:
            _json_print({"object_id": oid, "status": "policy_error", "error": type(e).__name__, "message": str(e)})
            return 4
        except RetentionError as e:
            _json_print({"object_id": oid, "status": "retention_error", "error": type(e).__name__, "message": str(e)})
            had_errors = True
        except Exception as e:
            _json_print({"object_id": oid, "status": "error", "error": type(e).__name__, "message": str(e)})
            had_errors = True

    if retention_blocked:
        return 3
    if had_missing and args.fail_on_missing:
        return 2
    if had_errors:
        return 5
    return 0

# -----------------------------
# ARGPARSE
# -----------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apply_retention", description="Apply OblivionVault retention policies to objects.")
    p.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity (-v|-vv)")

    sub = p.add_subparsers(dest="cmd", required=True)

    # Общие аргументы для обоих сабкоманд
    def add_common(sp: argparse._SubParsersAction, name: str) -> argparse.ArgumentParser:
        s = sp.add_parser(name, help=f"{name} retention policy")
        s.add_argument("--state-dir", required=True, help="directory for retention state/audit backend")
        s.add_argument("--policy-dir", help="directory with policy documents (JSON/TOML)")
        s.add_argument("--policy-env", help="environment variable name containing JSON policy (or b64:...)")
        s.add_argument("--require-signature", action="store_true", help="require HMAC signature in policy documents")
        s.add_argument("--policy-hmac-hex", help="hex-encoded HMAC key for verifying policy signatures")
        s.add_argument("--policy-hmac-file", help="file with raw HMAC key for verifying policy signatures")
        s.add_argument("--resolution", choices=[e.value for e in ResolutionStrategy], default=ResolutionStrategy.PRIORITY.value, help="policy resolution strategy")
        s.add_argument("--tag", action="append", help="tag for policy selector (repeatable)")
        s.add_argument("--created-at", help="override object creation time (ISO8601, default=now)")
        s.add_argument("--actor", help="actor id for audit (default: $USER or cli@host)")
        s.add_argument("--object-id", action="append", help="object id to process (repeatable)")
        s.add_argument("--objects-file", help="file with newline-delimited object ids")
        s.add_argument("--fail-on-missing", action="store_true", help="return code 2 if no policy for some object")
        return s

    # show
    ps = add_common(sub, "show")
    # show специфичные
    # (ничего)

    # apply
    pa = add_common(sub, "apply")
    # ключи состояния/способности/апруверов
    pa.add_argument("--state-hmac-hex", help="hex-encoded HMAC key for state integrity (optional)")
    pa.add_argument("--state-hmac-file", help="file with raw HMAC key for state integrity (optional)")
    pa.add_argument("--capability-key-hex", help="hex-encoded HMAC key for capability tokens (optional)")
    pa.add_argument("--capability-key-file", help="file with raw HMAC key for capability tokens (optional)")
    pa.add_argument("--approver-key-hex", action="append", help="hex-encoded approver secret (repeatable)")
    pa.add_argument("--approver-key-file", action="append", help="file with raw approver secret (repeatable)")
    pa.add_argument("--capability-token", help="capability token for governance override (if needed)")
    pa.add_argument("--approval-token", action="append", help="approval token(s) for governance override (repeatable)")
    pa.add_argument("--dry-run", action="store_true", help="do not change state, just print decision")

    return p

# -----------------------------
# MAIN
# -----------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _init_logging(args.verbose)
    try:
        if args.cmd == "show":
            rc = asyncio.run(_cmd_show(args))
        elif args.cmd == "apply":
            rc = asyncio.run(_cmd_apply(args))
        else:
            parser.error("unknown command")
            return 1
        return rc
    except SystemExit as e:
        # Перехватываем явные завершения
        return int(e.code) if isinstance(e.code, int) else 1
    except Exception as e:
        logging.getLogger("apply_retention").exception("Unhandled error: %s", e)
        return 1

if __name__ == "__main__":
    sys.exit(main())
