# path: veilmind-core/veilmind/workers/detector_warmup.py
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Опциональные зависимости
try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover
    asyncpg = None  # type: ignore

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server  # type: ignore
except Exception:  # pragma: no cover
    Counter = Gauge = Histogram = None  # type: ignore
    def start_http_server(*args, **kwargs):  # type: ignore
        pass

# Внутренние зависимости проекта
try:
    from veilmind.detect.validators import (
        validate_detectors_yaml,
        validate_expression_safe,
        validate_regex_safe,
        DetectorConfig,
    )
except Exception as e:
    print(json.dumps({"level": "error", "msg": "validators import failed", "err": str(e)}), file=sys.stderr)
    raise

# --------------------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    tenant_id: str = os.getenv("TENANT_ID", "global")
    detectors_yaml: str = os.getenv("DETECTORS_YAML", "configs/detectors.yaml")
    redis_url: Optional[str] = os.getenv("REDIS_URL")
    redis_prefix: str = os.getenv("REDIS_PREFIX", "vm")
    opa_url: Optional[str] = os.getenv("OPA_URL", "http://opa.policy:8181")
    opa_health_path: str = os.getenv("OPA_HEALTH_PATH", "/health")
    pg_dsn: Optional[str] = os.getenv("PG_DSN")  # postgres://user:pass@host:5432/db
    # SQL, возвращающий агрегаты для базлайна (кастомизируемо). Должен выдавать JSON объекты: {"detector_id": "...", "value": <float>}
    baseline_sql: Optional[str] = os.getenv("BASELINE_SQL")
    # Параллелизм/таймауты
    concurrency: int = int(os.getenv("WARMUP_CONCURRENCY", "8"))
    http_timeout_s: float = float(os.getenv("WARMUP_HTTP_TIMEOUT_S", "2.0"))
    op_retries: int = int(os.getenv("WARMUP_RETRIES", "3"))
    backoff_s: float = float(os.getenv("WARMUP_BACKOFF_S", "0.25"))
    # Метрики
    prometheus_bind: Optional[str] = os.getenv("PROM_BIND")  # например, "0:9106"
    # Поведение
    dry_run: bool = os.getenv("DRY_RUN", "0") == "1"
    validate_regexes: bool = os.getenv("VALIDATE_REGEX", "1") == "1"

# --------------------------------------------------------------------------------------
# Метрики
# --------------------------------------------------------------------------------------

if Counter is not None:
    M_WARMUP_TOTAL = Counter("detector_warmup_total", "Warmup runs total", ["stage"])
    M_WARMUP_FAILS = Counter("detector_warmup_failures_total", "Warmup failures", ["stage"])
    M_OP_LAT = Histogram("detector_warmup_op_latency_seconds", "Operation latency", ["op"])
    G_DETECTORS = Gauge("detector_warmup_detectors", "Detectors processed", ["result"])
    G_BASELINES = Gauge("detector_warmup_baselines", "Baselines seeded", ["result"])
else:
    # Заглушки
    class _N:
        def labels(self, *args): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    M_WARMUP_TOTAL = M_WARMUP_FAILS = M_OP_LAT = G_DETECTORS = G_BASELINES = _N()  # type: ignore

# --------------------------------------------------------------------------------------
# Логирование
# --------------------------------------------------------------------------------------

def log(level: str, msg: str, **fields: Any) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "level": level, "msg": msg, **fields}
    print(json.dumps(rec, ensure_ascii=False))

# --------------------------------------------------------------------------------------
# Вспомогательные утилиты
# --------------------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

async def _retry(op_name: str, retries: int, backoff_s: float, coro_factory):
    attempt = 0
    while True:
        with _latency(op_name):
            try:
                return await coro_factory()
            except Exception as e:  # pragma: no cover
                attempt += 1
                if attempt > retries:
                    M_WARMUP_FAILS.labels(op_name).inc()
                    raise
                await asyncio.sleep(backoff_s * (2 ** (attempt - 1)))

class _latency:
    def __init__(self, op: str): self.op = op
    def __enter__(self): self.t0 = time.perf_counter(); return self
    def __exit__(self, exc_type, exc, tb): M_OP_LAT.labels(self.op).observe(time.perf_counter() - self.t0)

# --------------------------------------------------------------------------------------
# Redis кэш
# --------------------------------------------------------------------------------------

class Cache:
    def __init__(self, url: Optional[str], prefix: str, dry_run: bool) -> None:
        self.url = url
        self.prefix = prefix.rstrip(":")
        self.dry = dry_run
        self.client = None

    async def connect(self) -> None:
        if not self.url:
            log("warn", "redis url not provided; cache disabled")
            return
        if aioredis is None:
            log("warn", "redis library not available; cache disabled")
            return
        self.client = aioredis.from_url(self.url, encoding="utf-8", decode_responses=True)
        try:
            pong = await self.client.ping()
            log("info", "redis connected", pong=pong)
        except Exception as e:
            log("error", "redis connection failed", err=str(e))
            self.client = None

    async def close(self) -> None:
        if self.client:
            try:
                await self.client.close()
            except Exception:
                pass

    def _k(self, *parts: str) -> str:
        return ":".join((self.prefix, *parts))

    async def store_detector(self, tenant: str, det: DetectorConfig) -> None:
        key = self._k("detectors", tenant, det.id)
        idx = self._k("detectors:index", tenant)
        payload = {
            "id": det.id,
            "name": det.name,
            "stream": det.stream,
            "window_s": det.window_s,
            "group_by": det.group_by or [],
            "threshold": det.threshold.model_dump() if det.threshold else None,
            "baseline": det.baseline.model_dump() if det.baseline else None,
            "correlation": det.correlation.model_dump() if det.correlation else None,
            "output_severity": det.output_severity,
            "compiled_at": _utcnow(),
        }
        if self.dry or not self.client:
            log("info", "cache skip store (dry or no redis)", key=key, detector=det.id)
            return
        pipe = self.client.pipeline()
        pipe.set(key, json.dumps(payload, ensure_ascii=False))
        pipe.sadd(idx, det.id)
        await pipe.execute()

    async def store_baseline(self, tenant: str, det_id: str, baseline: Dict[str, Any]) -> None:
        key = self._k("baseline", tenant, det_id)
        payload = {"seeded_at": _utcnow(), "data": baseline}
        if self.dry or not self.client:
            log("info", "cache skip baseline (dry or no redis)", key=key, detector=det_id)
            return
        await self.client.set(key, json.dumps(payload, ensure_ascii=False))

# --------------------------------------------------------------------------------------
# Валидатор/компилятор
# --------------------------------------------------------------------------------------

def _compile_detector(det: DetectorConfig, validate_regexes: bool) -> None:
    # Дополнительные проверки помимо validate_detectors_yaml
    for w in det.where or []:
        # validate_expression_safe уже вызывается внутри моделей; продублируем best‑effort
        validate_expression_safe(w.expr)
        if validate_regexes:
            # грубая эвристика: проверим строки вида r"...", /.../ и простые шаблоны в кавычках
            s = w.expr
            for pat in _extract_regex_candidates(s):
                validate_regex_safe(pat)

def _extract_regex_candidates(expr: str) -> List[str]:
    cands: List[str] = []
    # /.../
    i = 0
    while i < len(expr):
        if expr[i] == "/" and (i == 0 or expr[i-1] != "\\"):
            j = i + 1
            while j < len(expr) and not (expr[j] == "/" and expr[j-1] != "\\"):
                j += 1
            if j < len(expr):
                cands.append(expr[i+1:j])
                i = j + 1
                continue
        i += 1
    # "..." и '...' (может быть паттерном)
    import re as _re
    for m in _re.finditer(r'(?P<q>"|\')(?P<body>.*?)(?<!\\)(?P=q)', expr):
        body = m.group("body")
        if any(ch in body for ch in ".*+{}[]()|"):
            cands.append(body)
    return cands

# --------------------------------------------------------------------------------------
# Базлайны (опционально)
# --------------------------------------------------------------------------------------

async def seed_baseline_from_db(pool: Optional["asyncpg.Pool"], sql: Optional[str], dets: Sequence[DetectorConfig]) -> Dict[str, Dict[str, Any]]:
    """
    Выполняет настраиваемый SQL, который должен вернуть строки с detector_id и агрегатами для первичного базлайна.
    Возвращает map det_id -> baseline dict. В случае отсутствия пула/SQL — пусто.
    """
    if pool is None or not sql:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql)
            for r in rows:
                det_id = str(r.get("detector_id"))
                data = dict(r)
                data.pop("detector_id", None)
                if det_id:
                    out[det_id] = data
    except Exception as e:  # pragma: no cover
        log("warn", "baseline sql failed", err=str(e))
    # Заполним заглушки для детекторов без данных
    for d in dets:
        out.setdefault(d.id, {"count": 0, "ewma": None, "median": None})
    return out

# --------------------------------------------------------------------------------------
# OPA warmup (опционально)
# --------------------------------------------------------------------------------------

async def warmup_opa(settings: Settings) -> None:
    if not settings.opa_url or httpx is None:
        log("warn", "opa warmup skipped", reason="no url or httpx")
        return
    url = settings.opa_url.rstrip("/") + settings.opa_health_path
    async with httpx.AsyncClient(timeout=settings.http_timeout_s) as client:
        try:
            resp = await client.get(url)
            log("info", "opa health", status=resp.status_code)
        except Exception as e:  # pragma: no cover
            log("warn", "opa health failed", err=str(e))

# --------------------------------------------------------------------------------------
# Основной процесс прогрева
# --------------------------------------------------------------------------------------

async def run_warmup(settings: Settings) -> int:
    if settings.prometheus_bind:
        host, port = settings.prometheus_bind.split(":")
        start_http_server(addr=host, port=int(port))  # type: ignore
        log("info", "prometheus exporter started", bind=settings.prometheus_bind)

    # Загрузка и валидирование конфигов
    M_WARMUP_TOTAL.labels("load_yaml").inc()
    try:
        dets = validate_detectors_yaml(settings.detectors_yaml)
        G_DETECTORS.labels("loaded").set(len(dets))
        log("info", "detectors loaded", count=len(dets), file=settings.detectors_yaml)
    except Exception as e:
        M_WARMUP_FAILS.labels("load_yaml").inc()
        log("error", "failed to load detectors.yaml", err=str(e), file=settings.detectors_yaml)
        return 2

    # Дополнительно "скомпилируем" выражения/регекспы
    M_WARMUP_TOTAL.labels("compile").inc()
    comp_errors = 0
    for d in dets:
        try:
            _compile_detector(d, settings.validate_regexes)
        except Exception as e:
            comp_errors += 1
            log("error", "compile failed", detector=d.id, err=str(e))
    if comp_errors:
        M_WARMUP_FAILS.labels("compile").inc()
        log("error", "compilation errors present", errors=comp_errors)
        return 3

    # Redis
    cache = Cache(settings.redis_url, settings.redis_prefix, settings.dry_run)
    await cache.connect()

    # Postgres
    pool = None
    if settings.pg_dsn and asyncpg is not None:
        try:
            pool = await asyncpg.create_pool(settings.pg_dsn, min_size=1, max_size=max(2, settings.concurrency))
            log("info", "postgres pool created")
        except Exception as e:  # pragma: no cover
            log("warn", "postgres connection failed", err=str(e))

    # Параллельное сохранение детекторов в кэш
    M_WARMUP_TOTAL.labels("cache_store").inc()
    sem = asyncio.Semaphore(settings.concurrency)
    async def _store(d: DetectorConfig):
        async with sem:
            await cache.store_detector(settings.tenant_id, d)

    await asyncio.gather(*[_store(d) for d in dets])
    log("info", "detectors cached", count=len(dets), tenant=settings.tenant_id)

    # Базлайны (опционально)
    M_WARMUP_TOTAL.labels("baseline").inc()
    baselines = await seed_baseline_from_db(pool, settings.baseline_sql, dets)
    seed_ok = 0
    for d in dets:
        try:
            base = baselines.get(d.id, {"count": 0})
            await cache.store_baseline(settings.tenant_id, d.id, base)
            seed_ok += 1
        except Exception as e:  # pragma: no cover
            log("warn", "baseline seed failed", detector=d.id, err=str(e))
    G_BASELINES.labels("seeded").set(seed_ok)

    # OPA warmup
    M_WARMUP_TOTAL.labels("opa").inc()
    await warmup_opa(settings)

    # Завершение
    await cache.close()
    if pool:
        await pool.close()
    log("info", "warmup finished", detectors=len(dets), seeded=seed_ok, dry_run=settings.dry_run)
    return 0

# --------------------------------------------------------------------------------------
# CLI/entrypoint
# --------------------------------------------------------------------------------------

def _parse_args(argv: Optional[Sequence[str]] = None) -> Settings:
    p = argparse.ArgumentParser(description="Veilmind detector warmup worker")
    p.add_argument("--tenant-id", default=os.getenv("TENANT_ID", "global"))
    p.add_argument("--detectors-yaml", default=os.getenv("DETECTORS_YAML", "configs/detectors.yaml"))
    p.add_argument("--redis-url", default=os.getenv("REDIS_URL"))
    p.add_argument("--redis-prefix", default=os.getenv("REDIS_PREFIX", "vm"))
    p.add_argument("--opa-url", default=os.getenv("OPA_URL", "http://opa.policy:8181"))
    p.add_argument("--opa-health-path", default=os.getenv("OPA_HEALTH_PATH", "/health"))
    p.add_argument("--pg-dsn", default=os.getenv("PG_DSN"))
    p.add_argument("--baseline-sql", default=os.getenv("BASELINE_SQL"))
    p.add_argument("--concurrency", type=int, default=int(os.getenv("WARMUP_CONCURRENCY", "8")))
    p.add_argument("--http-timeout-s", type=float, default=float(os.getenv("WARMUP_HTTP_TIMEOUT_S", "2.0")))
    p.add_argument("--retries", type=int, default=int(os.getenv("WARMUP_RETRIES", "3")))
    p.add_argument("--backoff-s", type=float, default=float(os.getenv("WARMUP_BACKOFF_S", "0.25")))
    p.add_argument("--prom-bind", default=os.getenv("PROM_BIND"))
    p.add_argument("--dry-run", action="store_true", default=os.getenv("DRY_RUN", "0") == "1")
    p.add_argument("--no-validate-regex", action="store_true", help="disable aggressive regex safety checks")
    args = p.parse_args(argv)

    return Settings(
        tenant_id=args.tenant_id,
        detectors_yaml=args.detectors_yaml,
        redis_url=args.redis_url,
        redis_prefix=args.redis_prefix,
        opa_url=args.opa_url,
        opa_health_path=args.opa_health_path,
        pg_dsn=args.pg_dsn,
        baseline_sql=args.baseline_sql,
        concurrency=args.concurrency,
        http_timeout_s=args.http_timeout_s,
        op_retries=args.retries,
        backoff_s=args.backoff_s,
        prometheus_bind=args.prom_bind,
        dry_run=args.dry_run,
        validate_regexes=not args.no_validate_regex,
    )

async def _main_async(settings: Settings) -> int:
    # Graceful shutdown
    stop = asyncio.Event()
    def _handler(*_):
        stop.set()
    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, _handler)
    except Exception:
        pass
    rc = await run_warmup(settings)
    return rc

def main() -> None:
    settings = _parse_args()
    rc = asyncio.run(_main_async(settings))
    sys.exit(rc)

# Для импорта как модуля
if __name__ == "__main__":
    import contextlib  # локальный импорт для обработчика сигналов
    main()
