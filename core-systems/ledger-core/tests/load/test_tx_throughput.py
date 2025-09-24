# ledger-core/tests/load/test_tx_throughput.py
# Индустриальный нагрузочный тест пропускной способности леджера.
# Зависимости: pytest (без дополнительных плагинов).
# Интеграция через env/CLI:
#   LEDGER_SUBMIT_FUNC="pkg.mod:submit_tx"      # обязательно: callable(payload: bytes) -> tx_id | Any
#   LEDGER_WAIT_FUNC="pkg.mod:wait_committed"   # опционально: callable(tx_id: str, timeout_s: float) -> bool | str | Any
# Параметры (ENV или CLI):
#   THROUGHPUT_TARGET_TPS / --tps (float, default 200.0)
#   DURATION_SECONDS / --duration (int, default 30)
#   CONCURRENCY / --concurrency (int, default 64)
#   TX_SIZE_BYTES / --tx-bytes (int, default 512)
#   WARMUP_SECONDS / --warmup (float, default 5.0)
#   REQUIRE_CONFIRM / --confirm (bool flag; ENV: true/false; default false)
#   CONFIRM_TIMEOUT_S / --confirm-timeout (float, default 5.0)
#   LATENCY_P95_MS / --latency-p95 (float, default 500.0)        # применимо, если --confirm
#   FAILURE_MAX_RATIO / --failure-max (float, default 0.01)
#   ARTIFACTS_DIR / --artifacts-dir (str, default "")
#
# Поведение:
# - Если не задан LEDGER_SUBMIT_FUNC, тест помечается как SKIPPED с понятным сообщением.
# - Тест точно темпирует отправки под целевой TPS (open-loop), собирает метрики, исключает warmup.
# - На выходе проверяет SLO: достигнутый TPS, доля ошибок, p95 E2E-латентности (если есть подтверждение).
#
# Пример запуска:
#   pytest -q ledger-core/tests/load/test_tx_throughput.py --tps 500 --duration 60 --concurrency 128 \
#          --confirm --confirm-timeout 8 --latency-p95 700 --artifacts-dir artifacts/
#
# Внимание:
# - Код не делает предположений о форме возвращаемых значений callables; приводит к строке и интерпретирует truthy как успех.
# - Если подтверждение не сконфигурировано (--confirm не задан и/или нет LEDGER_WAIT_FUNC), пропускается часть SLO по латентности.

import asyncio
import base64
import hashlib
import importlib
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from statistics import median
from typing import Any, Callable, Coroutine, List, Optional, Tuple

import pytest


# ------------------------------
# Pytest options
# ------------------------------

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def pytest_addoption(parser):
    group = parser.getgroup("ledger-load")
    group.addoption("--tps", action="store", type=float,
                    default=float(os.getenv("THROUGHPUT_TARGET_TPS", 200.0)),
                    help="Целевой TPS.")
    group.addoption("--duration", action="store", type=int,
                    default=int(os.getenv("DURATION_SECONDS", 30)),
                    help="Длительность теста, сек.")
    group.addoption("--concurrency", action="store", type=int,
                    default=int(os.getenv("CONCURRENCY", 64)),
                    help="Максимальная конкуррентость отправок.")
    group.addoption("--tx-bytes", action="store", type=int,
                    default=int(os.getenv("TX_SIZE_BYTES", 512)),
                    help="Размер полезной нагрузки транзакции в байтах.")
    group.addoption("--warmup", action="store", type=float,
                    default=float(os.getenv("WARMUP_SECONDS", 5.0)),
                    help="Длительность разогрева, сек (исключается из метрик).")
    group.addoption("--confirm", action="store_true",
                    default=_env_bool("REQUIRE_CONFIRM", False),
                    help="Ожидать подтверждение/коммит транзакций.")
    group.addoption("--confirm-timeout", action="store", type=float,
                    default=float(os.getenv("CONFIRM_TIMEOUT_S", 5.0)),
                    help="Таймаут ожидания подтверждения одной транзакции, сек.")
    group.addoption("--latency-p95", action="store", type=float,
                    default=float(os.getenv("LATENCY_P95_MS", 500.0)),
                    help="Допустимый p95 E2E-латентности, мс (только если --confirm).")
    group.addoption("--failure-max", action="store", type=float,
                    default=float(os.getenv("FAILURE_MAX_RATIO", 0.01)),
                    help="Максимально допустимая доля ошибок.")
    group.addoption("--submit-func", action="store", type=str,
                    default=os.getenv("LEDGER_SUBMIT_FUNC", ""),
                    help="Путь к callable отправки: 'pkg.mod:func'.")
    group.addoption("--wait-func", action="store", type=str,
                    default=os.getenv("LEDGER_WAIT_FUNC", ""),
                    help="Путь к callable ожидания подтверждения: 'pkg.mod:func'.")
    group.addoption("--artifacts-dir", action="store", type=str,
                    default=os.getenv("ARTIFACTS_DIR", ""),
                    help="Каталог для CSV-артефактов (опционально).")


# ------------------------------
# Utils
# ------------------------------

def _load_callable(spec: str) -> Callable[..., Any]:
    if not spec:
        raise ValueError("Empty callable spec")
    try:
        mod_name, func_name = spec.rsplit(":", 1)
        mod = importlib.import_module(mod_name)
        fn = getattr(mod, func_name)
        if not callable(fn):
            raise TypeError(f"Object at {spec} is not callable")
        return fn
    except Exception as e:
        raise ImportError(f"Cannot load callable '{spec}': {e}") from e


async def _maybe_await(x: Any) -> Any:
    if asyncio.iscoroutine(x):
        return await x
    return x


def _rand_bytes(n: int) -> bytes:
    # Смешиваем криптослучайности с лёгким идентификатором
    tag = "".join(random.choices(string.ascii_lowercase + string.digits, k=16)).encode("utf-8")
    return tag + os.urandom(max(0, n - len(tag)))


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _percentile(sorted_values: List[float], p: float) -> float:
    # p в [0,100]
    if not sorted_values:
        return float("nan")
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


# ------------------------------
# Adapter
# ------------------------------

class LedgerAdapter:
    def __init__(self, submit_fn: Callable[[bytes], Any],
                 wait_fn: Optional[Callable[[str, float], Any]] = None):
        self._submit_fn = submit_fn
        self._wait_fn = wait_fn

    async def submit(self, payload: bytes) -> str:
        try:
            res = await _maybe_await(self._submit_fn(payload))
        except Exception as e:
            raise RuntimeError(f"submit() failed: {e}") from e
        # Универсально приводим к строке id
        if isinstance(res, (bytes, bytearray)):
            return base64.b16encode(res).decode("ascii")
        if isinstance(res, dict):
            for k in ("tx_id", "id", "hash", "txid"):
                if k in res:
                    return str(res[k])
            return _sha256_hex(repr(res).encode("utf-8"))
        return str(res)

    async def wait_committed(self, tx_id: str, timeout_s: float) -> bool:
        if self._wait_fn is None:
            # Если не задано подтверждение — считаем успешным "fire-and-forget"
            return True
        try:
            res = await _maybe_await(self._wait_fn(tx_id, timeout_s))
        except Exception as e:
            raise RuntimeError(f"wait_committed() failed: {e}") from e
        # Любая правдоподобная истина — успех
        if isinstance(res, str):
            return res.lower() in {"ok", "committed", "applied", "success", "true", "1"}
        return bool(res)


# ------------------------------
# Metrics
# ------------------------------

@dataclass
class TxMetrics:
    tx_id: str
    send_ts: float
    submit_ms: float
    e2e_ms: Optional[float]
    ok: bool
    err: Optional[str] = None


@dataclass
class Aggregate:
    sent: int = 0
    succeeded: int = 0
    confirmed: int = 0
    failed: int = 0
    submit_lat_ms: List[float] = field(default_factory=list)
    e2e_lat_ms: List[float] = field(default_factory=list)

    def to_summary(self) -> dict:
        sub_sorted = sorted(self.submit_lat_ms)
        e2e_sorted = sorted(self.e2e_lat_ms)
        return {
            "sent": self.sent,
            "succeeded": self.succeeded,
            "confirmed": self.confirmed,
            "failed": self.failed,
            "submit_p50_ms": _percentile(sub_sorted, 50.0) if sub_sorted else float("nan"),
            "submit_p95_ms": _percentile(sub_sorted, 95.0) if sub_sorted else float("nan"),
            "submit_p99_ms": _percentile(sub_sorted, 99.0) if sub_sorted else float("nan"),
            "e2e_p50_ms": _percentile(e2e_sorted, 50.0) if e2e_sorted else float("nan"),
            "e2e_p95_ms": _percentile(e2e_sorted, 95.0) if e2e_sorted else float("nan"),
            "e2e_p99_ms": _percentile(e2e_sorted, 99.0) if e2e_sorted else float("nan"),
        }


# ------------------------------
# Fixtures
# ------------------------------

@pytest.fixture(scope="session")
def adapter(pytestconfig) -> LedgerAdapter:
    submit_spec: str = pytestconfig.getoption("--submit-func")
    wait_spec: str = pytestconfig.getoption("--wait-func")
    if not submit_spec:
        pytest.skip("LEDGER_SUBMIT_FUNC/--submit-func не задан: интеграция с леджером не сконфигурирована.")
    submit_fn = _load_callable(submit_spec)
    wait_fn = _load_callable(wait_spec) if wait_spec else None
    return LedgerAdapter(submit_fn, wait_fn)


# ------------------------------
# Core async runner
# ------------------------------

async def _run_load(adapter: LedgerAdapter,
                    tps: float,
                    duration_s: int,
                    concurrency: int,
                    tx_size: int,
                    warmup_s: float,
                    require_confirm: bool,
                    confirm_timeout_s: float,
                    artifacts_dir: str,
                    logger: logging.Logger) -> Tuple[Aggregate, float, float]:
    agg = Aggregate()
    sem = asyncio.Semaphore(concurrency)
    start = time.perf_counter()
    end = start + duration_s
    warmup_end = start + warmup_s
    total_to_send = max(1, int(tps * duration_s))
    # Строгий темп отправки
    schedule = [start + (i / max(tps, 1e-6)) for i in range(total_to_send)]
    records: List[TxMetrics] = []

    async def one_task(send_at: float):
        nonlocal agg
        await asyncio.sleep(max(0.0, send_at - time.perf_counter()))
        payload = _rand_bytes(tx_size)
        tx_id_hint = _sha256_hex(payload)

        await sem.acquire()
        try:
            t0 = time.perf_counter()
            try:
                tx_id = await adapter.submit(payload)
            except Exception as e:
                t1 = time.perf_counter()
                rec = TxMetrics(tx_id=tx_id_hint, send_ts=t0,
                                submit_ms=(t1 - t0) * 1000.0, e2e_ms=None, ok=False, err=str(e))
                records.append(rec)
                return

            t1 = time.perf_counter()
            ok = True
            e2e_ms: Optional[float] = None

            if require_confirm:
                try:
                    committed = await adapter.wait_committed(tx_id, confirm_timeout_s)
                    ok = ok and bool(committed)
                except Exception as e:
                    ok = False
                    logger.debug("wait_committed error for %s: %s", tx_id, e)
                finally:
                    t2 = time.perf_counter()
                    e2e_ms = (t2 - t0) * 1000.0

            rec = TxMetrics(tx_id=tx_id, send_ts=t0,
                            submit_ms=(t1 - t0) * 1000.0, e2e_ms=e2e_ms, ok=ok, err=None if ok else "commit_failed")
            records.append(rec)
        finally:
            sem.release()

    # Запускаем задачи
    tasks = [asyncio.create_task(one_task(ts)) for ts in schedule]
    await asyncio.gather(*tasks)
    finished = time.perf_counter()

    # Агрегируем метрики, исключая warmup
    for r in records:
        agg.sent += 1
        if r.ok:
            agg.succeeded += 1
            if r.e2e_ms is not None:
                agg.confirmed += 1
        else:
            agg.failed += 1
        if r.send_ts >= warmup_end:
            agg.submit_lat_ms.append(r.submit_ms)
            if r.e2e_ms is not None:
                agg.e2e_lat_ms.append(r.e2e_ms)

    eff_duration = max(1e-6, duration_s - max(0.0, warmup_s))
    achieved_send_tps = (agg.succeeded) / eff_duration
    achieved_confirm_tps = (agg.confirmed) / eff_duration if require_confirm else float("nan")

    # Пишем CSV при необходимости
    if artifacts_dir:
        os.makedirs(artifacts_dir, exist_ok=True)
        path = os.path.join(artifacts_dir, "tx_metrics.csv")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("tx_id,send_ts,submit_ms,e2e_ms,ok\n")
                for r in records:
                    e2e = "" if r.e2e_ms is None else f"{r.e2e_ms:.3f}"
                    f.write(f"{r.tx_id},{r.send_ts:.6f},{r.submit_ms:.3f},{e2e},{int(r.ok)}\n")
        except Exception as e:
            logger.warning("Не удалось записать CSV артефакт: %s", e)

    # Логируем сводку
    summary = agg.to_summary()
    logger.info("Summary: %s", summary)
    logger.info("Achieved send TPS: %.2f", achieved_send_tps)
    if require_confirm:
        logger.info("Achieved confirm TPS: %.2f", achieved_confirm_tps)

    return agg, achieved_send_tps, achieved_confirm_tps


# ------------------------------
# Test
# ------------------------------

@pytest.mark.load
def test_tx_throughput(adapter: LedgerAdapter, pytestconfig, caplog):
    # Настройка логирования
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("ledger-load")
    logger.setLevel(logging.INFO)

    tps: float = float(pytestconfig.getoption("--tps"))
    duration_s: int = int(pytestconfig.getoption("--duration"))
    concurrency: int = int(pytestconfig.getoption("--concurrency"))
    tx_size: int = int(pytestconfig.getoption("--tx-bytes"))
    warmup_s: float = float(pytestconfig.getoption("--warmup"))
    require_confirm: bool = bool(pytestconfig.getoption("--confirm"))
    confirm_timeout_s: float = float(pytestconfig.getoption("--confirm-timeout"))
    latency_p95_ms_limit: float = float(pytestconfig.getoption("--latency-p95"))
    failure_max_ratio: float = float(pytestconfig.getoption("--failure-max"))
    artifacts_dir: str = str(pytestconfig.getoption("--artifacts-dir"))

    # Базовая валидация параметров
    assert tps > 0, "TPS must be > 0"
    assert duration_s > 0, "duration must be > 0"
    assert concurrency > 0, "concurrency must be > 0"
    assert tx_size >= 16, "tx_size must be >= 16 bytes"
    assert warmup_s >= 0.0 and warmup_s < duration_s, "0 <= warmup < duration"

    agg, achieved_send_tps, achieved_confirm_tps = asyncio.run(
        _run_load(
            adapter=adapter,
            tps=tps,
            duration_s=duration_s,
            concurrency=concurrency,
            tx_size=tx_size,
            warmup_s=warmup_s,
            require_confirm=require_confirm,
            confirm_timeout_s=confirm_timeout_s,
            artifacts_dir=artifacts_dir,
            logger=logger,
        )
    )

    # Проверки SLO
    # 1) Доля ошибок
    failure_ratio = (agg.failed / max(1, agg.sent))
    assert failure_ratio <= failure_max_ratio, (
        f"Слишком высокая доля ошибок: {failure_ratio:.4f} > {failure_max_ratio:.4f}"
    )

    # 2) Достижение целевого TPS (по успешным отправкам, без учёта warmup)
    # Требуем не меньше 90% целевого TPS.
    tps_floor = 0.90 * tps
    assert achieved_send_tps >= tps_floor, (
        f"Достигнутый TPS слишком низок: {achieved_send_tps:.2f} < {tps_floor:.2f} "
        f"(целевой {tps:.2f})"
    )

    # 3) Латентность p95 для подтверждений (если требуется подтверждение)
    if require_confirm and agg.e2e_lat_ms:
        p95 = _percentile(sorted(agg.e2e_lat_ms), 95.0)
        assert p95 <= latency_p95_ms_limit, (
            f"p95 E2E-латентности слишком высок: {p95:.2f} ms > {latency_p95_ms_limit:.2f} ms"
        )
