# path: zero-trust-core/cli/tools/revoke_session.py
# -*- coding: utf-8 -*-
"""
Zero-Trust Core — Session Revocation CLI

Назначение:
- Массовая ревокация (блокировка) сессий пользователей через CASB‑адаптер.
- Поддержка чтения session_id из аргументов, файла, stdin.
- Подтверждение операций (--yes), dry-run, конкурентная отправка, JSON-отчет.

Зависимости:
- Python 3.11+
- zero_trust.adapters.casb_adapter (GenericRESTCASBAdapter, CASBConfig, исключения)

ENV (совместимы с CASBConfig.from_env):
  CASB_BASE_URL            (обязательно, если не указан --base-url)
  CASB_API_TOKEN | CASB_OAUTH_TOKEN
  CASB_WEBHOOK_SECRET      (не требуется для CLI)
  CASB_API_VERSION         (по умолчанию v1)
  CASB_TENANT_ID
  CASB_TIMEOUT_SEC
  CASB_VERIFY_SSL          ("true"/"false")
  CASB_MAX_RETRIES
  CASB_BACKOFF_FACTOR
  CASB_RATE_LIMIT_PER_MINUTE
  CASB_CB_FAIL_THRESHOLD
  CASB_CB_RECOVERY_TIME_SEC
  CASB_CACHE_TTL_SEC
  CASB_PROXIES_JSON
  CASB_EXTRA_HEADERS_JSON

Автор: Zero-Trust Core CLI
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple

# Адаптер и типы из ядра
try:
    from zero_trust.adapters.casb_adapter import (
        GenericRESTCASBAdapter,
        CASBConfig,
        CASBAdapter,
        CASBError,
        CASBRateLimitError,
        CASBCircuitOpenError,
    )
except Exception as e:  # pragma: no cover
    raise ImportError(
        "Не найден zero_trust.adapters.casb_adapter. Убедитесь, что ядро установлено и PYTHONPATH корректен."
    ) from e

_LOG = logging.getLogger("zero_trust.cli.revoke_session")
if not _LOG.handlers:
    h = logging.StreamHandler(sys.stderr)
    f = logging.Formatter(fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":%(message)s}', datefmt="%Y-%m-%dT%H:%M:%S%z")
    h.setFormatter(f)
    _LOG.addHandler(h)
_LOG.setLevel(logging.INFO)


# ------------------------- Helpers -------------------------

def _json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return json.dumps({"repr": repr(obj)}, ensure_ascii=False)


def read_session_ids(args: argparse.Namespace) -> List[str]:
    ids: list[str] = []

    # из аргументов
    if args.session:
        for s in args.session:
            # поддержка "a,b,c"
            ids.extend([x.strip() for x in s.split(",") if x.strip()])

    # из файла
    if args.file:
        p = Path(args.file)
        if not p.exists():
            raise FileNotFoundError(f"Файл не найден: {p}")
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ids.append(line)

    # из stdin
    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ids.append(line)

    # дедуп с сохранением порядка
    seen = set()
    uniq: list[str] = []
    for sid in ids:
        if sid not in seen:
            uniq.append(sid)
            seen.add(sid)
    return uniq


@dataclass
class CliConfig:
    base_url: Optional[str] = None
    api_version: str = "v1"
    api_token: Optional[str] = None
    oauth_token: Optional[str] = None
    tenant_id: Optional[str] = None
    verify_ssl: Optional[bool] = None
    timeout_sec: Optional[float] = None
    max_retries: Optional[int] = None
    backoff_factor: Optional[float] = None
    proxies_json: Optional[str] = None
    extra_headers_json: Optional[str] = None


def build_casb_config_from_args(args: argparse.Namespace) -> CASBConfig:
    # Приоритет: аргументы CLI > ENV > дефолты CASBConfig
    env_prefix = os.getenv("CASB_PREFIX", "CASB_")

    def getenv(name: str, default: Optional[str] = None) -> Optional[str]:
        return os.getenv(env_prefix + name, default)

    base_url = args.base_url or getenv("BASE_URL")
    if not base_url:
        raise SystemExit("Не задан base_url (флаг --base-url или переменная окружения CASB_BASE_URL).")

    api_version = args.api_version or getenv("API_VERSION", "v1")
    tenant_id = args.tenant_id or getenv("TENANT_ID")
    api_token = args.api_token or getenv("API_TOKEN")
    oauth_token = args.oauth_token or getenv("OAUTH_TOKEN")
    webhook_secret = getenv("WEBHOOK_SECRET")  # не используется, но не мешает
    timeout_sec = float(args.timeout_sec) if args.timeout_sec is not None else float(getenv("TIMEOUT_SEC", "15"))
    verify_ssl = (str(args.verify_ssl).lower() == "true") if args.verify_ssl is not None else (getenv("VERIFY_SSL", "true").lower() == "true")
    max_retries = int(args.max_retries) if args.max_retries is not None else int(getenv("MAX_RETRIES", "3"))
    backoff_factor = float(args.backoff_factor) if args.backoff_factor is not None else float(getenv("BACKOFF_FACTOR", "0.5"))
    rate_limit_per_minute = int(getenv("RATE_LIMIT_PER_MINUTE", "600"))
    cb_fail_threshold = int(getenv("CB_FAIL_THRESHOLD", "8"))
    cb_recovery_time_sec = float(getenv("CB_RECOVERY_TIME_SEC", "30"))
    cache_ttl_sec = float(getenv("CACHE_TTL_SEC", "15"))

    cfg = CASBConfig(
        base_url=base_url,
        api_version=api_version,
        tenant_id=tenant_id or None,
        api_token=api_token or None,
        oauth_token=oauth_token or None,
        webhook_secret=webhook_secret or None,
        timeout_sec=timeout_sec,
        verify_ssl=verify_ssl,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        rate_limit_per_minute=rate_limit_per_minute,
        cb_fail_threshold=cb_fail_threshold,
        cb_recovery_time_sec=cb_recovery_time_sec,
        cache_ttl_sec=cache_ttl_sec,
    )

    proxies_json = args.proxies_json or getenv("PROXIES_JSON")
    if proxies_json:
        try:
            cfg.proxies = json.loads(proxies_json)
        except Exception as e:
            raise SystemExit(f"Неверный --proxies-json/PROXIES_JSON: {e}")

    extra_headers_json = args.extra_headers_json or getenv("EXTRA_HEADERS_JSON")
    if extra_headers_json:
        try:
            cfg.extra_headers = json.loads(extra_headers_json)
        except Exception as e:
            raise SystemExit(f"Неверный --extra-headers-json/EXTRA_HEADERS_JSON: {e}")

    return cfg


async def revoke_sessions(adapter: CASBAdapter, session_ids: Sequence[str], reason: str, concurrency: int, mode: str, dry_run: bool) -> Tuple[list[str], list[Tuple[str, str]]]:
    """
    Возвращает (успешные, неуспешные( id, ошибка )).
    mode: "block" | "allow"
    """
    ok: list[str] = []
    failed: list[Tuple[str, str]] = []

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(sid: str) -> None:
        nonlocal ok, failed
        try:
            async with sem:
                if dry_run:
                    _LOG.info(_json_dumps({"event": "dry_run", "session_id": sid, "mode": mode}))
                    ok.append(sid)
                    return
                if mode == "block":
                    await adapter.block_session(sid, reason)
                else:
                    await adapter.allow_session(sid)
                ok.append(sid)
                _LOG.info(_json_dumps({"event": "session_processed", "mode": mode, "session_id": sid}))
        except (CASBRateLimitError, CASBCircuitOpenError) as e:
            _LOG.warning(_json_dumps({"event": "rate_or_circuit", "session_id": sid, "error": repr(e)}))
            failed.append((sid, f"{type(e).__name__}: {e}"))
        except (CASBError, Exception) as e:
            _LOG.error(_json_dumps({"event": "session_failed", "session_id": sid, "error": repr(e)}))
            failed.append((sid, f"{type(e).__name__}: {e}"))

    await asyncio.gather(*(_one(s) for s in session_ids))
    return ok, failed


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="revoke_session",
        description="Zero-Trust Core — массовая ревокация/блокировка сессий через CASB.",
    )
    src = p.add_argument_group("Источники session_id")
    src.add_argument("-s", "--session", action="append", help="ID сессии; можно указывать несколько раз или через запятую.")
    src.add_argument("-f", "--file", help="Путь к файлу со списком session_id (по одному в строке; строки с # игнорируются).")
    src.add_argument("--stdin", action="store_true", help="Читать session_id из stdin (по одному в строке).")

    act = p.add_argument_group("Действие")
    act.add_argument("--mode", choices=["block", "allow"], default="block", help="Режим операции: block (ревокация/блокировка) или allow (разблокировка). По умолчанию block.")
    act.add_argument("-r", "--reason", default="revoked via Zero-Trust CLI", help="Причина блокировки/разрешения.")
    act.add_argument("-y", "--yes", action="store_true", help="Не спрашивать подтверждение.")
    act.add_argument("--dry-run", action="store_true", help="Режим проверки без выполнения запросов в CASB.")
    act.add_argument("-c", "--concurrency", type=int, default=8, help="Максимальное число одновременных запросов (по умолчанию 8).")
    act.add_argument("--json", dest="json_out", action="store_true", help="Выводить результат в JSON.")

    casb = p.add_argument_group("CASB конфигурация (переопределяет ENV)")
    casb.add_argument("--base-url", help="Базовый URL CASB API (иначе CASB_BASE_URL).")
    casb.add_argument("--api-version", default=None, help="Версия API (иначе CASB_API_VERSION).")
    casb.add_argument("--api-token", default=None, help="API токен (иначе CASB_API_TOKEN).")
    casb.add_argument("--oauth-token", default=None, help="OAuth2 Bearer токен (иначе CASB_OAUTH_TOKEN).")
    casb.add_argument("--tenant-id", default=None, help="Tenant ID (иначе CASB_TENANT_ID).")
    casb.add_argument("--verify-ssl", choices=["true","false"], default=None, help="Проверять SSL (true/false).")
    casb.add_argument("--timeout-sec", type=float, default=None, help="Таймаут HTTP, сек.")
    casb.add_argument("--max-retries", type=int, default=None, help="Макс. число ретраев.")
    casb.add_argument("--backoff-factor", type=float, default=None, help="Коэффициент backoff.")
    casb.add_argument("--proxies-json", default=None, help="JSON объект прокси (как в httpx).")
    casb.add_argument("--extra-headers-json", default=None, help="JSON объект доп. заголовков.")

    misc = p.add_argument_group("Прочее")
    misc.add_argument("--log-level", default="INFO", help="Уровень логирования (DEBUG/INFO/WARN/ERROR).")

    return p


async def _amain(argv: Sequence[str]) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Логирование
    try:
        _LOG.setLevel(getattr(logging, args.log_level.upper()))
    except Exception:
        pass

    # Сбор session_id
    session_ids = read_session_ids(args)
    if not session_ids:
        parser.error("Не переданы идентификаторы сессий: используйте --session/-s, --file или --stdin.")

    # Подтверждение
    if not args.yes and not args.dry_run:
        print(f"Будет выполнено: {args.mode} для {len(session_ids)} сессий. Причина: {args.reason}", file=sys.stderr)
        confirm = input("Подтвердите (введите 'yes'): ").strip()
        if confirm.lower() != "yes":
            print("Отменено пользователем.", file=sys.stderr)
            return 130

    # Конфиг CASB и адаптер
    casb_cfg = build_casb_config_from_args(args)
    adapter = GenericRESTCASBAdapter(casb_cfg)

    try:
        # Проверка доступности CASB (не фатально)
        ok = await adapter.health_check()
        if not ok:
            _LOG.warning(_json_dumps({"event":"health_check","ok":False}))
        else:
            _LOG.info(_json_dumps({"event":"health_check","ok":True}))

        # Выполнение
        succeeded, failed = await revoke_sessions(
            adapter=adapter,
            session_ids=session_ids,
            reason=args.reason,
            concurrency=max(1, int(args.concurrency)),
            mode=args.mode,
            dry_run=bool(args.dry_run),
        )

        # Вывод результата
        if args.json_out:
            print(_json_dumps({
                "mode": args.mode,
                "requested": len(session_ids),
                "succeeded": succeeded,
                "failed": [{"id": i, "error": e} for i, e in failed],
            }))
        else:
            print(f"Режим: {args.mode}")
            print(f"Всего запрошено: {len(session_ids)}")
            print(f"Успешно: {len(succeeded)}")
            if succeeded:
                print("Успешные ID:")
                for sid in succeeded:
                    print(f"  {sid}")
            print(f"Неуспешно: {len(failed)}")
            if failed:
                print("Ошибки:")
                for sid, err in failed:
                    print(f"  {sid}: {err}")

        # Коды выхода: 0 — все ок; 2 — частичный успех; 1 — все неудачно
        if succeeded and not failed:
            return 0
        if succeeded and failed:
            return 2
        return 1
    finally:
        try:
            await adapter.close()
        except Exception:
            pass


def main() -> None:
    try:
        rc = asyncio.run(_amain(sys.argv[1:]))
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
