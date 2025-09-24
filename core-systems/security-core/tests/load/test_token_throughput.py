# security-core/tests/load/test_token_throughput.py
# Нагрузочный тест пропускной способности выпуска/верификации токенов.
# По умолчанию использует HMAC-SHA256 (JWT-подобный формат header.payload.signature).
# Управление через переменные окружения:
#   SECURITY_CORE_RUN_LOAD=1         — включить тест (иначе будет skipped)
#   DURATION_SEC=10                  — длительность, с
#   CONCURRENCY=8                    — количество потоков
#   TARGET_QPS=0                     — общий целевой QPS (0 = без троттлинга)
#   MIN_TPS=0                        — минимальный TPS для assert (0 = без проверки)
#   P95_MAX_MS=0                     — максимальный p95 issue/verify (мс, 0 = без проверки)
#   P99_MAX_MS=0                     — максимальный p99 issue/verify (мс, 0 = без проверки)
#   SECRET=                          — необязательный секрет в base64url; если пусто — сгенерируется
#   METRICS_OUT=token_throughput.json — путь для JSON-метрик (если не задано — не писать)
#
# Запуск:
#   SECURITY_CORE_RUN_LOAD=1 pytest -q tests/load/test_token_throughput.py::test_token_throughput
from __future__ import annotations

import base64
import json
import logging
import os
import queue
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from statistics import median
from typing import Dict, List, Tuple

import pytest

try:
    # Используем ваш модуль времени для RFC3339, если доступен
    from security.utils.time import now_utc, format_rfc3339
except Exception:  # fallback
    from datetime import datetime, timezone

    def now_utc():
        return datetime.now(timezone.utc)

    def format_rfc3339(dt):
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


LOG = logging.getLogger("tests.load.token_throughput")
LOG.setLevel(logging.INFO)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(raw)


def _b64url_to_bytes(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign_hs256(claims: dict, *, secret: bytes, headers: dict | None = None) -> str:
    """
    Формирует компактный токен вида header.payload.signature.
    Это не полноценный JWT, но полностью совместимый по формату для HMAC-SHA256.
    """
    import hmac
    import hashlib

    hdr = {"alg": "HS256", "typ": "JWT"}
    if headers:
        hdr.update(headers)

    h = _b64url_json(hdr)
    p = _b64url_json(claims)
    signing_input = f"{h}.{p}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_hs256(token: str, *, secret: bytes) -> bool:
    import hmac
    import hashlib

    try:
        h, p, s = token.split(".")
    except ValueError:
        return False
    signing_input = f"{h}.{p}".encode("ascii")
    sig = _b64url_to_bytes(s)

    mac = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(mac, sig)


def _percentile(sorted_values: List[float], p: float) -> float:
    """
    Простой перцентиль (p в [0,100]): на вход подавать уже отсортированный список миллисекунд.
    """
    if not sorted_values:
        return 0.0
    if p <= 0:
        return sorted_values[0]
    if p >= 100:
        return sorted_values[-1]
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


@dataclass
class RunCfg:
    duration_sec: float
    concurrency: int
    target_qps: float
    min_tps: float
    p95_max_ms: float
    p99_max_ms: float
    secret: bytes
    metrics_out: str | None


def _read_env() -> RunCfg:
    dur = float(os.getenv("DURATION_SEC", "10"))
    conc = int(os.getenv("CONCURRENCY", str(min(8, os.cpu_count() or 4))))
    qps = float(os.getenv("TARGET_QPS", "0"))
    min_tps = float(os.getenv("MIN_TPS", "0"))
    p95 = float(os.getenv("P95_MAX_MS", "0"))
    p99 = float(os.getenv("P99_MAX_MS", "0"))
    sec_env = os.getenv("SECRET", "")
    if sec_env:
        secret = _b64url_to_bytes(sec_env)
    else:
        secret = secrets.token_bytes(32)
    metrics_out = os.getenv("METRICS_OUT", "") or None
    return RunCfg(dur, conc, qps, min_tps, p95, p99, secret, metrics_out)


@dataclass
class ThreadStats:
    issued: int = 0
    verify_ok: int = 0
    errors: int = 0
    lat_issue_ms: List[float] = None  # type: ignore
    lat_verify_ms: List[float] = None  # type: ignore

    def __post_init__(self):
        if self.lat_issue_ms is None:
            self.lat_issue_ms = []
        if self.lat_verify_ms is None:
            self.lat_verify_ms = []


def _worker(idx: int, cfg: RunCfg, start_evt: threading.Event, end_deadline: float, out_q: queue.Queue) -> None:
    stats = ThreadStats()
    # Для троттлинга: делим общий TARGET_QPS на число потоков
    per_thread_qps = cfg.target_qps / cfg.concurrency if cfg.target_qps > 0 else 0.0
    next_tick = time.perf_counter()

    # Блокируемся до общего старта
    start_evt.wait()

    while True:
        now = time.perf_counter()
        if now >= end_deadline:
            break

        # Выпуск токена
        t0 = time.perf_counter()
        claims = {
            "iss": "loadtest",
            "sub": f"user-{idx}",
            "iat": int(time.time()),
            "exp": int(time.time() + 600),
            "tid": idx,
            "rnd": secrets.randbits(32),
        }
        try:
            token = sign_hs256(claims, secret=cfg.secret)
        except Exception:
            stats.errors += 1
            continue
        t1 = time.perf_counter()
        # Верификация
        ok = verify_hs256(token, secret=cfg.secret)
        t2 = time.perf_counter()

        stats.issued += 1
        stats.verify_ok += 1 if ok else 0
        stats.lat_issue_ms.append((t1 - t0) * 1000.0)
        stats.lat_verify_ms.append((t2 - t1) * 1000.0)

        # Троттлинг
        if per_thread_qps > 0:
            # следующий тик через 1/qps сек от последнего запланированного.
            next_tick += 1.0 / per_thread_qps
            sleep_for = next_tick - time.perf_counter()
            if sleep_for > 0:
                # короткий сон малыми порциями для отзывчивости
                end_sleep = time.perf_counter() + sleep_for
                while True:
                    rem = end_sleep - time.perf_counter()
                    if rem <= 0:
                        break
                    time.sleep(min(rem, 0.002))

    out_q.put(stats)


@pytest.mark.load
def test_token_throughput():
    if os.getenv("SECURITY_CORE_RUN_LOAD", "0") != "1":
        pytest.skip("SECURITY_CORE_RUN_LOAD != 1 — нагрузочный тест отключён по умолчанию")

    cfg = _read_env()
    LOG.info("Starting token throughput test: duration=%.1fs, conc=%d, qps=%.1f",
             cfg.duration_sec, cfg.concurrency, cfg.target_qps)

    start_evt = threading.Event()
    out_q: queue.Queue = queue.Queue()
    threads: List[threading.Thread] = []

    start_wall = now_utc()
    end_deadline = time.perf_counter() + cfg.duration_sec

    for i in range(cfg.concurrency):
        t = threading.Thread(target=_worker, args=(i, cfg, start_evt, end_deadline, out_q), daemon=True)
        threads.append(t)
        t.start()

    # Синхронный старт
    start_evt.set()

    # Сбор статистики
    all_stats: List[ThreadStats] = []
    for t in threads:
        t.join()
    while not out_q.empty():
        all_stats.append(out_q.get())

    end_wall = now_utc()

    total_issued = sum(s.issued for s in all_stats)
    total_ok = sum(s.verify_ok for s in all_stats)
    total_err = sum(s.errors for s in all_stats)
    elapsed = cfg.duration_sec  # мы измеряем дедлайном, потому используем запрошенную длительность
    tps = total_issued / elapsed if elapsed > 0 else 0.0

    issue_lat = sorted([x for s in all_stats for x in s.lat_issue_ms])
    verify_lat = sorted([x for s in all_stats for x in s.lat_verify_ms])

    metrics: Dict[str, object] = {
        "start": format_rfc3339(start_wall),
        "end": format_rfc3339(end_wall),
        "duration_sec": cfg.duration_sec,
        "concurrency": cfg.concurrency,
        "target_qps": cfg.target_qps,
        "issued": total_issued,
        "verified_ok": total_ok,
        "errors": total_err,
        "throughput_tps": tps,
        "latency_ms": {
            "issue": {
                "p50": _percentile(issue_lat, 50),
                "p95": _percentile(issue_lat, 95),
                "p99": _percentile(issue_lat, 99),
                "min": issue_lat[0] if issue_lat else 0.0,
                "max": issue_lat[-1] if issue_lat else 0.0,
            },
            "verify": {
                "p50": _percentile(verify_lat, 50),
                "p95": _percentile(verify_lat, 95),
                "p99": _percentile(verify_lat, 99),
                "min": verify_lat[0] if verify_lat else 0.0,
                "max": verify_lat[-1] if verify_lat else 0.0,
            },
        },
    }

    # Выводим в лог и при необходимости в файл
    LOG.info("TPS=%.0f, issued=%d, ok=%d, err=%d", tps, total_issued, total_ok, total_err)
    LOG.info("Issue p50=%.3f ms, p95=%.3f ms, p99=%.3f ms",
             metrics["latency_ms"]["issue"]["p50"], metrics["latency_ms"]["issue"]["p95"], metrics["latency_ms"]["issue"]["p99"])  # type: ignore[index]
    LOG.info("Verify p50=%.3f ms, p95=%.3f ms, p99=%.3f ms",
             metrics["latency_ms"]["verify"]["p50"], metrics["latency_ms"]["verify"]["p95"], metrics["latency_ms"]["verify"]["p99"])  # type: ignore[index]

    if cfg.metrics_out:
        try:
            with open(cfg.metrics_out, "w", encoding="utf-8") as f:
                json.dump(metrics, f, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception as e:  # noqa: BLE001
            LOG.warning("Не удалось сохранить метрики: %s", e)

    # Проверки
    assert total_err == 0, f"Ошибки при выпуске/верификации: {total_err}"
    assert total_ok == total_issued, "Часть токенов не прошла верификацию"

    # Порог по TPS (если задан)
    if cfg.min_tps > 0:
        assert tps >= cfg.min_tps, f"TPS {tps:.0f} < требуемого {cfg.min_tps:.0f}"

    # Пороги по перцентилям (если заданы)
    p95_issue = metrics["latency_ms"]["issue"]["p95"]  # type: ignore[index]
    p95_verify = metrics["latency_ms"]["verify"]["p95"]  # type: ignore[index]
    p99_issue = metrics["latency_ms"]["issue"]["p99"]  # type: ignore[index]
    p99_verify = metrics["latency_ms"]["verify"]["p99"]  # type: ignore[index]

    if cfg.p95_max_ms > 0:
        assert p95_issue <= cfg.p95_max_ms and p95_verify <= cfg.p95_max_ms, \
            f"P95 превышен: issue={p95_issue:.3f} ms, verify={p95_verify:.3f} ms, лимит={cfg.p95_max_ms:.3f} ms"
    if cfg.p99_max_ms > 0:
        assert p99_issue <= cfg.p99_max_ms and p99_verify <= cfg.p99_max_ms, \
            f"P99 превышен: issue={p99_issue:.3f} ms, verify={p99_verify:.3f} ms, лимит={cfg.p99_max_ms:.3f} ms"
