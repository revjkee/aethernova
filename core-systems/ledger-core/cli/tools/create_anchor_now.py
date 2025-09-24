# ledger-core/cli/tools/create_anchor_now.py
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional, Tuple

# --- Внутренние зависимости проекта (должны существовать в репо) ---
# utils.time: UTC/RFC3339, бэкофф, дедлайны
from ledger.utils.time import (
    utcnow,
    epoch_ms,
    from_epoch_ms,
    parse_rfc3339,
    parse_duration,
    format_rfc3339,
    BackoffMode,
    next_backoff,
)
# ProofRepository: хранилище доказательств
from ledger.storage.repositories.proof_repo import ProofRepository, ProofRecord

# Типы для плагинов
PayloadBuilder = Callable[[str, int, int], Awaitable[bytes]]

class AnchorBackendProto:
    async def anchor(self, *, namespace: str, period_start: int, period_end: int, payload: bytes) -> str:  # pragma: no cover - протокол
        raise NotImplementedError

# -------------------------
# Утиль
# -------------------------

def _floor_to_window(ts_s: int, window_s: int) -> int:
    return (ts_s // window_s) * window_s

def _parse_period_end(value: str) -> int:
    """
    Поддержка:
      - 'now'            -> округление произойдет позже
      - RFC3339          -> 2025-08-15T13:00:00Z
      - целое/float      -> epoch seconds
    """
    if value.lower() == "now":
        return -1
    # Попробуем как число (секунды)
    try:
        f = float(value)
        return int(f)
    except Exception:
        pass
    # Иначе RFC3339
    dt = parse_rfc3339(value)
    return int(dt.timestamp())

def _load_object(dotted: str) -> Any:
    """
    Загружает объект по dotted path: package.module:object либо package.module.object
    """
    if ":" in dotted:
        mod, attr = dotted.split(":", 1)
    else:
        parts = dotted.rsplit(".", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid dotted path: {dotted!r}")
        mod, attr = parts
    m = importlib.import_module(mod)
    try:
        return getattr(m, attr)
    except AttributeError as e:
        raise ValueError(f"object {attr!r} not found in module {mod!r}") from e

# -------------------------
# In‑repo fallback плагины
# -------------------------

async def _default_payload_builder(namespace: str, start_s: int, end_s: int) -> bytes:
    """
    Детерминированная полезная нагрузка по умолчанию (подходит для smoke/стендов).
    В проде передайте --payload-builder на реальную функцию сборки меркле‑корня.
    """
    return f"{namespace}:{start_s}-{end_s}".encode("utf-8")

class _EchoAnchorBackend(AnchorBackendProto):
    async def anchor(self, *, namespace: str, period_start: int, period_end: int, payload: bytes) -> str:
        # Имитация внешнего ID по детерминированному шаблону
        return f"{namespace}:{period_start}-{period_end}:{len(payload)}"

# -------------------------
# Redis‑lock (опционально)
# -------------------------

class _NoopLock:
    async def __aenter__(self): return True
    async def __aexit__(self, exc_type, exc, tb): return False

class _RedisLock:
    def __init__(self, redis, key: str, ttl: int) -> None:
        self._r = redis
        self._key = key
        self._ttl = ttl
        self._token = os.urandom(16).hex()

    async def __aenter__(self) -> bool:
        # SET key token NX EX ttl
        ok = await self._r.set(self._key, self._token, ex=self._ttl, nx=True)
        if ok:
            return True
        return False

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        # Lua CAS‑удаление
        script = """
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('del', KEYS[1])
        else
            return 0
        end
        """
        try:
            await self._r.eval(script, 1, self._key, self._token)
        except Exception:
            pass
        return False

# -------------------------
# Конфигурация CLI
# -------------------------

@dataclass
class CLIConfig:
    namespace: str
    window_seconds: int
    period_end: Optional[int]       # если None -> вычисляется как now floored
    payload_builder: PayloadBuilder
    backend: AnchorBackendProto
    postgres_dsn: str
    ensure_schema: bool
    dry_run: bool
    finalize: bool
    redis_url: Optional[str]
    lock_ttl: int
    retries: int
    backoff_base: float
    backoff_factor: float
    backoff_cap: float
    backoff_mode: str

# -------------------------
# Основная логика
# -------------------------

async def _maybe_get_lock(ctx: CLIConfig, lock_key: str):
    if not ctx.redis_url:
        return _NoopLock()
    try:
        import redis.asyncio as redis  # type: ignore
    except Exception:
        raise RuntimeError("aioredis (redis.asyncio) is required for --redis-url")

    r = redis.from_url(ctx.redis_url, encoding=None, decode_responses=False)
    return _RedisLock(r, lock_key, ctx.lock_ttl)

async def _with_retries(fn, *, ctx: CLIConfig):
    """
    Ретраи с экспоненциальным бэкоффом и джиттером на сетевые/временные ошибки.
    Любое исключение из fn ретраится до лимита, затем пробрасывается.
    """
    attempt = 0
    while True:
        try:
            return await fn()
        except Exception as e:
            attempt += 1
            if attempt >= ctx.retries:
                raise
            delay = next_backoff(
                attempt=attempt,
                base=ctx.backoff_base,
                factor=ctx.backoff_factor,
                cap=ctx.backoff_cap,
                mode=ctx.backoff_mode,
            )
            logging.warning("retrying after error (attempt=%d, delay=%.3fs): %s", attempt, delay, e)
            await asyncio.sleep(delay)

async def _run_once(ctx: CLIConfig) -> Mapping[str, Any]:
    # 1) Вычисляем окно
    now_s = int(utcnow().timestamp())
    if ctx.period_end is None or ctx.period_end < 0:
        end_s = _floor_to_window(now_s, ctx.window_seconds)
    else:
        end_s = _floor_to_window(ctx.period_end, ctx.window_seconds)
    start_s = end_s - ctx.window_seconds
    if end_s <= 0 or start_s < 0:
        raise ValueError("invalid computed period window")

    # 2) Лок (опционально)
    lock_key = f"anchor:{ctx.namespace}"
    async with (await _maybe_get_lock(ctx, lock_key)) as acquired:
        if not acquired:
            raise RuntimeError("another instance holds the lock; aborting")

        # 3) Сборка payload
        payload = await ctx.payload_builder(ctx.namespace, start_s, end_s)

        # 4) Публикация анкер‑артефакта
        async def do_anchor():
            return await ctx.backend.anchor(namespace=ctx.namespace, period_start=start_s, period_end=end_s, payload=payload)
        anchor_id = await _with_retries(do_anchor, ctx=ctx)

        # 5) Сохранение доказательства (идемпотентно)
        if ctx.dry_run:
            return {
                "namespace": ctx.namespace,
                "period_start": start_s,
                "period_end": end_s,
                "finalize": ctx.finalize,
                "anchor_id": anchor_id,
                "payload_len": len(payload),
                "dry_run": True,
            }

        # Подключаемся к БД
        try:
            import asyncpg  # type: ignore
        except Exception:
            raise RuntimeError("asyncpg is required; set DATABASE_URL or pass --postgres-dsn")

        pool = await asyncpg.create_pool(dsn=ctx.postgres_dsn, min_size=1, max_size=4)
        try:
            repo = ProofRepository(pool)  # type: ignore[arg-type]
            if ctx.ensure_schema:
                await repo.ensure_schema()
            rec = await repo.upsert_idempotent(
                namespace=ctx.namespace,
                period_start=start_s,
                period_end=end_s,
                anchor_id=anchor_id,
                payload=payload,
                merkle_root=None,
                extra={"source": "create_anchor_now"},
                status="finalized" if ctx.finalize else "pending",
            )
            # Гарантированное завершение при необходимости
            if ctx.finalize and rec.status != "finalized":
                rec = await repo.mark_finalized(namespace=ctx.namespace, period_start=start_s, period_end=end_s)

            return {
                "namespace": rec.namespace,
                "period_start": rec.period_start,
                "period_end": rec.period_end,
                "status": rec.status,
                "anchor_id": rec.anchor_id,
                "created_at": rec.created_at.isoformat(),
                "finalized_at": rec.finalized_at.isoformat() if rec.finalized_at else None,
            }
        finally:
            await pool.close()

# -------------------------
# Парсер аргументов
# -------------------------

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="create_anchor_now",
        description="Однократный анкеринг текущего окна для заданного namespace.",
    )
    p.add_argument("--namespace", required=True, help="Идентификатор пространства (ledger/shard).")
    p.add_argument("--window-seconds", type=int, required=True, help="Размер окна в секундах (например, 60, 3600).")
    p.add_argument("--period-end", default="now", help="RFC3339 или epoch seconds или 'now' (округляется к окну).")
    p.add_argument("--payload-builder", default=None, help="Dotted path функции payload_builder(namespace, start, end) -> await bytes.")
    p.add_argument("--backend", default=None, help="Dotted path класса AnchorBackend с методом anchor(...)->str.")
    p.add_argument("--postgres-dsn", default=os.getenv("DATABASE_URL", ""), help="DSN PostgreSQL (env DATABASE_URL).")
    p.add_argument("--ensure-schema", action="store_true", help="Создать схему таблицы доказательств при запуске.")
    p.add_argument("--finalize", action="store_true", help="Сразу пометить запись finalized.")
    p.add_argument("--dry-run", action="store_true", help="Не записывать в БД, только показать результат.")
    p.add_argument("--redis-url", default=os.getenv("REDIS_URL", ""), help="URL Redis для распределённой блокировки (опционально).")
    p.add_argument("--lock-ttl", type=int, default=60, help="TTL блокировки, сек.")
    p.add_argument("--retries", type=int, default=8, help="Количество попыток публикации анкер‑артефакта.")
    p.add_argument("--backoff-base", type=float, default=0.25, help="База экспоненциального бэкоффа (сек).")
    p.add_argument("--backoff-factor", type=float, default=2.0, help="Множитель экспоненты.")
    p.add_argument("--backoff-cap", type=float, default=5.0, help="Кеп задержки (сек).")
    p.add_argument("--backoff-mode", choices=[BackoffMode.FULL, BackoffMode.EQUAL, BackoffMode.DECORRELATED],
                   default=BackoffMode.FULL, help="Режим джиттера бэкоффа.")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Уровень логирования.")
    return p

# -------------------------
# Entry point
# -------------------------

def _init_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

def _resolve_plugins(args) -> Tuple[PayloadBuilder, AnchorBackendProto]:
    # payload‑builder
    if args.payload_builder:
        fn = _load_object(args.payload_builder)
        if not callable(fn):
            raise ValueError("--payload-builder must point to an async callable")
        payload_builder = fn  # type: ignore[assignment]
    else:
        payload_builder = _default_payload_builder

    # backend
    if args.backend:
        cls = _load_object(args.backend)
        backend = cls()  # type: ignore[call-arg]
        if not hasattr(backend, "anchor"):
            raise ValueError("--backend must provide anchor(...) coroutine")
    else:
        backend = _EchoAnchorBackend()
    return payload_builder, backend  # type: ignore[return-value]

def _validate_args(args) -> None:
    if args.window_seconds <= 0:
        raise SystemExit("--window-seconds must be positive")
    if not args.postgres_dsn and not args.dry_run:
        raise SystemExit("PostgreSQL DSN is required (DATABASE_URL or --postgres-dsn), or use --dry-run")

async def _amain() -> int:
    ap = _build_argparser()
    args = ap.parse_args()
    _init_logging(args.log_level)
    _validate_args(args)

    payload_builder, backend = _resolve_plugins(args)

    period_end = _parse_period_end(args.period_end)
    redis_url = args.redis_url or None

    cfg = CLIConfig(
        namespace=args.namespace,
        window_seconds=int(args.window_seconds),
        period_end=None if period_end == -1 else period_end,
        payload_builder=payload_builder,
        backend=backend,
        postgres_dsn=args.postgres_dsn,
        ensure_schema=bool(args.ensure_schema),
        dry_run=bool(args.dry_run),
        finalize=bool(args.finalize),
        redis_url=redis_url,
        lock_ttl=int(args.lock_ttl),
        retries=int(args.retries),
        backoff_base=float(args.backoff_base),
        backoff_factor=float(args.backoff_factor),
        backoff_cap=float(args.backoff_cap),
        backoff_mode=str(args.backoff_mode),
    )

    try:
        result = await _run_once(cfg)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as e:
        logging.error("anchor failed: %s", e, exc_info=True)
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2

def main() -> None:
    raise SystemExit(asyncio.run(_amain()))

if __name__ == "__main__":
    main()
