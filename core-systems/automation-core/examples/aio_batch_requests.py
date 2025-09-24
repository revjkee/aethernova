#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aio_batch_requests.py — промышленный асинхронный батч-клиент HTTP.

Требования:
  - Python 3.11+
  - httpx >= 0.27  (pip install httpx)

Форматы входа:
  1) Простой список URL'ов (по одному на строку)
  2) JSONL: объекты вида {
         "method": "GET",
         "url": "https://example.com",
         "headers": {"X-Trace": "1"},
         "params": {"q": "test"},
         "json": {"k": "v"},
         "data": "raw body"
     }

Примеры:
  cat urls.txt | python aio_batch_requests.py --max-concurrency 200 --rate 50 --ndjson out.ndjson
  python aio_batch_requests.py --input tasks.jsonl --save-bodies ./bodies --per-host 20 --timeout 5

Особенности:
  - Глобальный и по-хосту лимиты параллелизма (bulkhead)
  - Скользящий rate-limit (N запросов в окно T)
  - Экспоненциальный backoff с джиттером для 408/429/5xx/сетевых ошибок
  - Circuit breaker per-host (open -> half-open -> closed)
  - Жесткие таймауты (connect/read/write/pool)
  - Структурные логи в stderr, результаты в NDJSON
  - Корректная отмена по Ctrl+C / SIGTERM и финальные метрики в JSON

Авторский код; внешних утверждений нет.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import random
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Deque, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    sys.stderr.write("error: httpx is required. Install: pip install httpx\n")
    raise

# ----------------------------- ЛОГИ -------------------------------------------

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


log = logging.getLogger("aio_batch")


# ------------------------- RATE LIMIT (скользящее окно) -----------------------

class SlidingWindowRateLimiter:
    """
    Простой скользящий rate-limit: не более 'rate' событий за 'per' секунд.
    Реализация: deque с таймстампами выполненных acquire.
    """
    def __init__(self, rate: int, per: float = 1.0):
        if rate <= 0 or per <= 0:
            raise ValueError("rate and per must be positive")
        self.rate = rate
        self.per = per
        self._events: Deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            # чистим окно
            cutoff = now - self.per
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            if len(self._events) < self.rate:
                self._events.append(now)
                return
            # надо подождать до освобождения окна
            sleep_for = self._events[0] + self.per - now
        await asyncio.sleep(max(0.0, sleep_for))
        # рекурсивно не уходим — повторяем попытку
        await self.acquire()


# ---------------------------- CIRCUIT BREAKER ---------------------------------

@dataclass
class CircuitBreaker:
    """
    Простой per-host circuit breaker.
    - closed: пропускаем запросы
    - open: блокируем до cooldown
    - half-open: пропускаем 1 пробу, в зависимости от результата -> closed/open
    """
    fail_threshold: int = 5
    cooldown: float = 10.0

    state: str = "closed"
    failures: int = 0
    opened_at: float = 0.0

    def allow(self) -> bool:
        now = time.monotonic()
        if self.state == "open":
            if now - self.opened_at >= self.cooldown:
                # Переходим в half-open
                self.state = "half-open"
                self.failures = 0
                return True
            return False
        return True  # closed/half-open

    def on_success(self) -> None:
        # Любой успех закрывает
        self.state = "closed"
        self.failures = 0

    def on_failure(self) -> None:
        if self.state in ("closed", "half-open"):
            self.failures += 1
            if self.state == "half-open" or self.failures >= self.fail_threshold:
                self.state = "open"
                self.opened_at = time.monotonic()
        else:
            # open — ничего не делаем
            pass


# ----------------------------- РЕЗУЛЬТАТ --------------------------------------

@dataclass
class FetchTask:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    json_body: Optional[Any] = None
    data_body: Optional[str] = None
    id: Optional[str] = None  # для трассировки

    @staticmethod
    def from_line(line: str) -> "FetchTask":
        line = line.strip()
        if not line:
            raise ValueError("empty line")
        if line.startswith("{"):
            obj = json.loads(line)
            return FetchTask(
                method=str(obj.get("method", "GET")).upper(),
                url=obj["url"],
                headers=dict(obj.get("headers", {})),
                params=dict(obj.get("params", {})),
                json_body=obj.get("json"),
                data_body=obj.get("data"),
                id=obj.get("id"),
            )
        else:
            return FetchTask(method="GET", url=line)


@dataclass
class FetchResult:
    id: Optional[str]
    method: str
    url: str
    ok: bool
    status: Optional[int]
    error: Optional[str]
    elapsed_ms: int
    attempt: int
    body_path: Optional[str]
    body_len: Optional[int]
    headers: Dict[str, Any] = field(default_factory=dict)


# -------------------------- КЛАССИФИКАЦИЯ РЕТРАЕВ -----------------------------

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}

def is_retryable_exc(exc: Exception) -> bool:
    return isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.RemoteProtocolError))


# --------------------------- ОСНОВНОЙ ВЫПОЛНИТЕЛЬ -----------------------------

class BatchClient:
    def __init__(
        self,
        max_concurrency: int,
        per_host: int,
        rate: Optional[int],
        timeout: float,
        connect_timeout: Optional[float],
        retries: int,
        backoff_base: float,
        backoff_cap: float,
        jitter: float,
        verify_tls: bool,
        user_agent: Optional[str],
        save_bodies_dir: Optional[Path],
        ndjson_path: Optional[Path],
        max_body_bytes: int,
        cb_fail_threshold: int,
        cb_cooldown: float,
    ) -> None:
        self._global_sema = asyncio.Semaphore(max_concurrency)
        self._per_host_sema: Dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(per_host))
        self._rate = SlidingWindowRateLimiter(rate, 1.0) if rate else None

        self._retries = retries
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._jitter = jitter

        self._save_dir = save_bodies_dir
        self._ndjson = ndjson_path.open("a", encoding="utf-8") if ndjson_path else None
        self._max_body = max_body_bytes

        self._cb_by_host: Dict[str, CircuitBreaker] = defaultdict(
            lambda: CircuitBreaker(cb_fail_threshold, cb_cooldown)
        )

        # httpx client
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=connect_timeout or timeout, read=timeout, write=timeout, pool=timeout),
            verify=verify_tls,
            limits=httpx.Limits(max_connections=None, max_keepalive_connections=256),
            headers={"User-Agent": user_agent} if user_agent else None,
            follow_redirects=False,
            trust_env=True,  # прокси и т.п. из окружения
        )

        # метрики
        self._started = time.monotonic()
        self._ok = 0
        self._fail = 0
        self._written = 0
        self._total = 0

        self._stop = asyncio.Event()  # для graceful shutdown

    async def close(self) -> None:
        if self._ndjson:
            self._ndjson.flush()
            self._ndjson.close()
        await self._client.aclose()

    def stop(self) -> None:
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    def _host_of(self, url: str) -> str:
        return urlparse(url).netloc or "unknown"

    async def _maybe_rate(self) -> None:
        if self._rate:
            await self._rate.acquire()

    async def _write_ndjson(self, result: FetchResult) -> None:
        if not self._ndjson:
            return
        obj = dataclasses.asdict(result)
        self._ndjson.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._written += 1
        if self._written % 100 == 0:
            self._ndjson.flush()

    def _hash_path(self, method: str, url: str, attempt: int, status: Optional[int]) -> Path:
        h = hashlib.sha256(f"{method} {url} {attempt} {status}".encode("utf-8")).hexdigest()
        name = f"{h}.bin"
        assert self._save_dir is not None
        return self._save_dir / name

    async def _save_body(self, path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # не блокируем event loop надолго
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, path.write_bytes, content)

    def _backoff_sleep(self, attempt: int) -> float:
        # экспоненциальный backoff с ограничением и джиттером
        base = min(self._backoff_cap, self._backoff_base * (2 ** (attempt - 1)))
        if self._jitter > 0:
            base = base * (1 + random.uniform(-self._jitter, self._jitter))
        return max(0.0, base)

    async def fetch_one(self, task: FetchTask) -> FetchResult:
        method = task.method.upper()
        host = self._host_of(task.url)
        cb = self._cb_by_host[host]

        if not cb.allow():
            return FetchResult(
                id=task.id,
                method=method,
                url=task.url,
                ok=False,
                status=None,
                error="circuit_open",
                elapsed_ms=0,
                attempt=0,
                body_path=None,
                body_len=None,
            )

        async with self._global_sema:
            async with self._per_host_sema[host]:
                await self._maybe_rate()
                # Попытки запроса
                t0 = time.monotonic()
                last_err: Optional[str] = None
                status: Optional[int] = None
                body_path: Optional[str] = None
                body_len: Optional[int] = None

                for attempt in range(1, self._retries + 2):  # retries + 1 первичная
                    if self.stopped():
                        last_err = "stopped"
                        break
                    try:
                        resp = await self._client.request(
                            method=method,
                            url=task.url,
                            headers=task.headers or None,
                            params=task.params or None,
                            json=task.json_body if task.json_body is not None else None,
                            content=(task.data_body.encode("utf-8") if isinstance(task.data_body, str) else task.data_body),
                        )
                        status = resp.status_code

                        # Успех?
                        if 200 <= resp.status_code < 300:
                            content = await resp.aread()
                            if self._save_dir:
                                # урезаем запись по лимиту, но длину считаем фактическую
                                body_len = len(content)
                                if body_len > self._max_body:
                                    content = content[: self._max_body]
                                p = self._hash_path(method, task.url, attempt, status)
                                await self._save_body(p, content)
                                body_path = str(p)
                            else:
                                body_len = len(content)
                            cb.on_success()
                            elapsed = int((time.monotonic() - t0) * 1000)
                            self._ok += 1
                            return FetchResult(
                                id=task.id,
                                method=method,
                                url=task.url,
                                ok=True,
                                status=status,
                                error=None,
                                elapsed_ms=elapsed,
                                attempt=attempt,
                                body_path=body_path,
                                body_len=body_len,
                                headers=dict(resp.headers),
                            )

                        # Ретраебельные статусы?
                        if status in RETRYABLE_STATUS and attempt <= self._retries:
                            delay = self._backoff_sleep(attempt)
                            log.debug("retryable status=%s url=%s attempt=%d delay=%.3fs", status, task.url, attempt, delay)
                            await asyncio.sleep(delay)
                            continue

                        # Неретраебельный ответ
                        cb.on_failure()
                        elapsed = int((time.monotonic() - t0) * 1000)
                        self._fail += 1
                        return FetchResult(
                            id=task.id,
                            method=method,
                            url=task.url,
                            ok=False,
                            status=status,
                            error=f"http_{status}",
                            elapsed_ms=elapsed,
                            attempt=attempt,
                            body_path=None,
                            body_len=None,
                            headers=dict(resp.headers),
                        )

                    except Exception as e:
                        last_err = type(e).__name__
                        if is_retryable_exc(e) and attempt <= self._retries:
                            delay = self._backoff_sleep(attempt)
                            log.debug("retryable exc=%s url=%s attempt=%d delay=%.3fs", last_err, task.url, attempt, delay)
                            await asyncio.sleep(delay)
                            continue
                        cb.on_failure()
                        break

                elapsed = int((time.monotonic() - t0) * 1000)
                self._fail += 1
                return FetchResult(
                    id=task.id,
                    method=method,
                    url=task.url,
                    ok=False,
                    status=status,
                    error=last_err or "error",
                    elapsed_ms=elapsed,
                    attempt=self._retries + 1,
                    body_path=None,
                    body_len=None,
                )

    async def run(self, tasks: Iterable[FetchTask]) -> Dict[str, Any]:
        start = time.monotonic()
        self._total = 0

        async def _worker(t: FetchTask) -> None:
            res = await self.fetch_one(t)
            await self._write_ndjson(res)
            if not res.ok:
                # логируем кратко
                log.info("fail url=%s status=%s err=%s attempt=%d elapsed_ms=%d",
                         res.url, res.status, res.error, res.attempt, res.elapsed_ms)

        try:
            for t in tasks:
                if self.stopped():
                    break
                self._total += 1
                asyncio.create_task(_worker(t))
                # легкая рассрочка, чтобы не зажать event loop
                if self._total % 1000 == 0:
                    await asyncio.sleep(0)
            # ждём завершения запущенных задач
            while len(asyncio.all_tasks()) > 1:
                if self.stopped():
                    break
                await asyncio.sleep(0.05)
        finally:
            metrics = self.metrics()
            log.info("done: %s", metrics)
        return self.metrics()

    def metrics(self) -> Dict[str, Any]:
        elapsed = time.monotonic() - self._started
        return {
            "total": self._total,
            "ok": self._ok,
            "fail": self._fail,
            "written": self._written,
            "elapsed_sec": round(elapsed, 3),
        }


# ------------------------------- ВВОД ЗАДАНИЙ ---------------------------------

async def read_tasks(args: argparse.Namespace) -> AsyncIterator[FetchTask]:
    if args.input and args.input != "-":
        f = open(args.input, "r", encoding="utf-8")
        close = True
    else:
        f = sys.stdin
        close = False
    try:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield FetchTask.from_line(line)
            except Exception as e:
                log.warning("skip invalid line: %r (%s)", line[:160], e)
    finally:
        if close:
            f.close()


# --------------------------------- CLI ----------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Asynchronous batch HTTP client")
    io = p.add_argument_group("I/O")
    io.add_argument("--input", "-i", default="-", help="path to file with URLs/JSONL, or '-' for stdin")
    io.add_argument("--ndjson", dest="ndjson", default=None, help="path to NDJSON results file")
    io.add_argument("--save-bodies", dest="save_bodies", default=None, help="directory to save response bodies")
    io.add_argument("--max-body-bytes", type=int, default=2_000_000, help="limit bytes saved per body")

    perf = p.add_argument_group("Performance & limits")
    perf.add_argument("--max-concurrency", type=int, default=200, help="global concurrency")
    perf.add_argument("--per-host", type=int, default=50, help="per-host concurrency")
    perf.add_argument("--rate", type=int, default=None, help="requests per second (sliding window)")

    net = p.add_argument_group("Network")
    net.add_argument("--timeout", type=float, default=15.0, help="overall timeout seconds")
    net.add_argument("--connect-timeout", type=float, default=None, help="connect timeout seconds")
    net.add_argument("--retries", type=int, default=3, help="retry attempts for retryable errors")
    net.add_argument("--backoff-base", type=float, default=0.25, help="base backoff seconds")
    net.add_argument("--backoff-cap", type=float, default=3.0, help="max backoff seconds")
    net.add_argument("--jitter", type=float, default=0.25, help="relative jitter for backoff [0..1]")
    net.add_argument("--no-verify-tls", action="store_true", help="disable TLS verification (not recommended)")
    net.add_argument("--user-agent", default="aio-batch/1.0", help="custom User-Agent")

    cb = p.add_argument_group("Circuit breaker")
    cb.add_argument("--cb-fail-threshold", type=int, default=5, help="failures to open circuit")
    cb.add_argument("--cb-cooldown", type=float, default=10.0, help="cooldown seconds")

    misc = p.add_argument_group("Misc")
    misc.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity (repeatable)")

    return p


# ------------------------------ MAIN ------------------------------------------

async def main_async(args: argparse.Namespace) -> int:
    setup_logging(args.verbose)

    save_dir = Path(args.save_bodies).resolve() if args.save_bodies else None
    if save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)

    ndjson_path = Path(args.ndjson).resolve() if args.ndjson else None
    verify_tls = not args.no_verify_tls

    client = BatchClient(
        max_concurrency=args.max_concurrency,
        per_host=args.per_host,
        rate=args.rate,
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        retries=args.retries,
        backoff_base=args.backoff_base,
        backoff_cap=args.backoff_cap,
        jitter=args.jitter,
        verify_tls=verify_tls,
        user_agent=args.user_agent,
        save_bodies_dir=save_dir,
        ndjson_path=ndjson_path,
        max_body_bytes=args.max_body_bytes,
        cb_fail_threshold=args.cb_fail_threshold,
        cb_cooldown=args.cb_cooldown,
    )

    # обработка сигналов — мягкая остановка
    loop = asyncio.get_running_loop()

    def _handle_stop(sig: str):
        log.warning("received %s -> stopping...", sig)
        client.stop()

    for s in ("SIGINT", "SIGTERM"):
        if hasattr(signal, s):
            loop.add_signal_handler(getattr(signal, s), _handle_stop, s)

    try:
        tasks_iter = read_tasks(args)
        metrics = await client.run(tasks_iter)
        # финальный вывод метрик в stdout как JSON
        print(json.dumps({"metrics": metrics}, ensure_ascii=False))
        return 0
    finally:
        await client.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        # на случай раннего Ctrl+C до установки хэндлеров
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
