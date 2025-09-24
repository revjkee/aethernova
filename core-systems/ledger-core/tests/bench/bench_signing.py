# ledger-core/tests/bench/bench_signing.py
"""
Промышленный бенчмарк подписания и проверки подписи.

Запуск:
    LEDGER_BENCH=1 pytest -q tests/bench/bench_signing.py

Основные переменные окружения:
    LEDGER_BENCH                 = "1" включает бенчмарк; иначе тесты будут пропущены.
    BENCH_DURATION_SEC           = длительность каждой серии в секундах (по умолчанию 1.5).
    BENCH_REPEATS                = число повторов серий (по умолчанию 5).
    BENCH_WARMUP_SEC             = прогрев, сек (по умолчанию 0.5).
    BENCH_MSG_SIZE               = размер сообщения, байт (по умолчанию 256).
    BENCH_AFFINITY               = "1" пытаться закрепить на одном CPU (Linux).
    BENCH_EXPORT_JSON            = путь для JSON-отчета; если не задан, не сохраняем.
    BENCH_BACKENDS               = CSV-список для фильтрации, напр. "ed25519_nacl,secp256k1_coincurve".
                                   Если не задано — берем все доступные.

Поддерживаемые бекенды:
    - ed25519_nacl         (PyNaCl/libsodium)
    - ed25519_crypto       (cryptography)
    - secp256k1_coincurve  (coincurve/libsecp256k1)
    - secp256k1_ecdsa      (pure-python ecdsa)

Безопасность CI:
    По умолчанию пропускается, если LEDGER_BENCH != "1".
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import platform
import random
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import pytest

pytestmark = [pytest.mark.benchmark, pytest.mark.slow]

# ------------------------- Конфиг через ENV -------------------------

LEDGER_BENCH = os.getenv("LEDGER_BENCH", "0") == "1"
BENCH_DURATION_SEC = float(os.getenv("BENCH_DURATION_SEC", "1.5"))
BENCH_REPEATS = int(os.getenv("BENCH_REPEATS", "5"))
BENCH_WARMUP_SEC = float(os.getenv("BENCH_WARMUP_SEC", "0.5"))
BENCH_MSG_SIZE = int(os.getenv("BENCH_MSG_SIZE", "256"))
BENCH_AFFINITY = os.getenv("BENCH_AFFINITY", "1") == "1"
BENCH_EXPORT_JSON = os.getenv("BENCH_EXPORT_JSON", "").strip() or None
BENCH_BACKENDS_FILTER = {
    b.strip().lower()
    for b in os.getenv("BENCH_BACKENDS", "").split(",")
    if b.strip()
}

# ------------------------- Утилиты окружения -------------------------

def _maybe_pin_affinity() -> None:
    """Закрепляем процесс на одном CPU, если возможно (Linux)."""
    if not BENCH_AFFINITY:
        return
    try:
        if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
            cpus = list(os.sched_getaffinity(0))  # type: ignore[attr-defined]
            if cpus:
                os.sched_setaffinity(0, {cpus[0]})  # type: ignore[attr-defined]
    except Exception:
        # Игнорируем ошибки совместимости
        pass

def _env_metadata() -> Dict[str, str]:
    return {
        "python_version": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "bench_duration_sec": str(BENCH_DURATION_SEC),
        "bench_repeats": str(BENCH_REPEATS),
        "bench_warmup_sec": str(BENCH_WARMUP_SEC),
        "bench_msg_size": str(BENCH_MSG_SIZE),
        "affinity": str(BENCH_AFFINITY),
    }

# ------------------------- Интерфейсы бекендов -------------------------

@dataclass
class SignerSpec:
    name: str
    algo: str
    keygen: Callable[[], Tuple[object, object]]
    sign: Callable[[object, bytes], bytes]
    verify: Callable[[object, bytes, bytes], None]  # должен поднять исключение при неверной подписи

def _available_backends() -> List[SignerSpec]:
    specs: List[SignerSpec] = []

    # Ed25519 via PyNaCl
    try:
        from nacl.signing import SigningKey, VerifyKey  # type: ignore

        def _keygen_ed25519_nacl() -> Tuple[object, object]:
            sk = SigningKey.generate()
            vk = sk.verify_key
            return sk, vk

        def _sign_ed25519_nacl(sk: object, msg: bytes) -> bytes:
            sig = sk.sign(msg).signature  # type: ignore[attr-defined]
            return bytes(sig)

        def _verify_ed25519_nacl(vk: object, msg: bytes, sig: bytes) -> None:
            vk: VerifyKey
            vk.verify(msg, sig)  # raises if invalid

        specs.append(
            SignerSpec(
                name="ed25519_nacl",
                algo="ed25519",
                keygen=_keygen_ed25519_nacl,
                sign=_sign_ed25519_nacl,
                verify=_verify_ed25519_nacl,
            )
        )
    except Exception:
        pass

    # Ed25519 via cryptography
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # type: ignore

        def _keygen_ed25519_crypto() -> Tuple[object, object]:
            sk = ed25519.Ed25519PrivateKey.generate()
            vk = sk.public_key()
            return sk, vk

        def _sign_ed25519_crypto(sk: object, msg: bytes) -> bytes:
            return sk.sign(msg)  # type: ignore[attr-defined]

        def _verify_ed25519_crypto(vk: object, msg: bytes, sig: bytes) -> None:
            vk.verify(sig, msg)  # type: ignore[attr-defined]

        specs.append(
            SignerSpec(
                name="ed25519_crypto",
                algo="ed25519",
                keygen=_keygen_ed25519_crypto,
                sign=_sign_ed25519_crypto,
                verify=_verify_ed25519_crypto,
            )
        )
    except Exception:
        pass

    # secp256k1 via coincurve
    try:
        from coincurve import PrivateKey, PublicKey  # type: ignore

        def _keygen_secp256k1_cc() -> Tuple[object, object]:
            sk = PrivateKey()
            vk = sk.public_key
            return sk, vk

        def _sign_secp256k1_cc(sk: object, msg: bytes) -> bytes:
            # ЭЦП обычно по хешу
            digest = hashlib.sha256(msg).digest()
            return sk.sign(digest, hasher=None)  # type: ignore[attr-defined]

        def _verify_secp256k1_cc(vk: object, msg: bytes, sig: bytes) -> None:
            digest = hashlib.sha256(msg).digest()
            ok = vk.verify(sig, digest, hasher=None)  # type: ignore[attr-defined]
            if not ok:
                raise ValueError("Invalid signature")

        specs.append(
            SignerSpec(
                name="secp256k1_coincurve",
                algo="secp256k1",
                keygen=_keygen_secp256k1_cc,
                sign=_sign_secp256k1_cc,
                verify=_verify_secp256k1_cc,
            )
        )
    except Exception:
        pass

    # secp256k1 via ecdsa (pure python fallback)
    try:
        from ecdsa import SECP256k1, SigningKey, VerifyingKey, BadSignatureError  # type: ignore

        def _keygen_secp256k1_ecdsa() -> Tuple[object, object]:
            sk = SigningKey.generate(curve=SECP256k1)
            vk = sk.get_verifying_key()
            return sk, vk

        def _sign_secp256k1_ecdsa(sk: object, msg: bytes) -> bytes:
            return sk.sign_deterministic(msg, hashfunc=hashlib.sha256)  # type: ignore[attr-defined]

        def _verify_secp256k1_ecdsa(vk: object, msg: bytes, sig: bytes) -> None:
            try:
                vk.verify(sig, msg, hashfunc=hashlib.sha256)  # type: ignore[attr-defined]
            except BadSignatureError as e:  # type: ignore[name-defined]
                raise ValueError("Invalid signature") from e

        specs.append(
            SignerSpec(
                name="secp256k1_ecdsa",
                algo="secp256k1",
                keygen=_keygen_secp256k1_ecdsa,
                sign=_sign_secp256k1_ecdsa,
                verify=_verify_secp256k1_ecdsa,
            )
        )
    except Exception:
        pass

    # Фильтр, если задан BENCH_BACKENDS
    if BENCH_BACKENDS_FILTER:
        specs = [s for s in specs if s.name.lower() in BENCH_BACKENDS_FILTER]

    return specs

# ------------------------- Бенч-харнесс -------------------------

def _time_loop(fn: Callable[[], None], duration_sec: float) -> int:
    """Выполняет fn в цикле заданное время, возвращает число итераций."""
    end_t = time.perf_counter() + duration_sec
    iters = 0
    while True:
        fn()
        iters += 1
        if time.perf_counter() >= end_t:
            break
    return iters

def _run_series(
    fn: Callable[[], None],
    repeats: int,
    warmup_sec: float,
    duration_sec: float,
) -> Dict[str, List[float]]:
    """Выполняет прогрев и несколько серий измерений, возвращает ops/sec по сериям."""
    # Прогрев
    if warmup_sec > 0:
        _time_loop(fn, warmup_sec)

    # Отключаем GC на время замеров
    gc_enabled = gc.isenabled()
    if gc_enabled:
        gc.disable()
    try:
        series: List[float] = []
        for _ in range(repeats):
            start = time.perf_counter()
            n = _time_loop(fn, duration_sec)
            elapsed = time.perf_counter() - start
            ops = n / elapsed if elapsed > 0 else 0.0
            series.append(ops)
        return {"ops_per_sec": series}
    finally:
        if gc_enabled:
            gc.enable()

def _stats(values: Iterable[float]) -> Dict[str, float]:
    vals = list(values)
    if not vals:
        return {"mean": 0.0, "stdev": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": statistics.fmean(vals),
        "stdev": statistics.pstdev(vals) if len(vals) > 1 else 0.0,
        "min": min(vals),
        "max": max(vals),
    }

# ------------------------- Фикстуры pytest -------------------------

def _require_bench() -> None:
    if not LEDGER_BENCH:
        pytest.skip("LEDGER_BENCH != 1, бенчмарки отключены по умолчанию.")

@pytest.fixture(scope="session")
def backends() -> List[SignerSpec]:
    _require_bench()
    specs = _available_backends()
    if not specs:
        pytest.skip("Нет доступных криптобекендов для бенчмарка.")
    return specs

@pytest.fixture(scope="session")
def payloads() -> List[bytes]:
    _require_bench()
    random.seed(1337)
    # Генерируем набор сообщений для моделирования разнообразных входов
    return [bytes(random.getrandbits(8) for _ in range(BENCH_MSG_SIZE)) for _ in range(64)]

@pytest.fixture(scope="session", autouse=True)
def pin_affinity_once() -> None:
    _require_bench()
    _maybe_pin_affinity()

# ------------------------- Тесты-бенчмарки -------------------------

@pytest.mark.parametrize("backend", [pytest.param(b, id=b.name) for b in _available_backends()] or [])
def test_keygen_throughput(backend: SignerSpec):
    _require_bench()

    def _fn() -> None:
        sk, vk = backend.keygen()
        # используем объекты, чтобы не оптимизировались интерпретатором
        assert sk is not None and vk is not None

    results = _run_series(_fn, BENCH_REPEATS, BENCH_WARMUP_SEC, BENCH_DURATION_SEC)
    series = results["ops_per_sec"]
    s = _stats(series)

    _export_result(
        bench="keygen",
        backend=backend,
        series=series,
        msg_size=0,
        extra={"note": "keypair generation"},
    )

    # Минимальная проверка, что производительность не нулевая
    assert s["mean"] > 0.0

@pytest.mark.parametrize("backend", [pytest.param(b, id=b.name) for b in _available_backends()] or [])
def test_sign_throughput(backend: SignerSpec, payloads: List[bytes]):
    _require_bench()
    sk, vk = backend.keygen()
    idx = 0
    n_payloads = len(payloads)

    def _fn() -> None:
        nonlocal idx
        m = payloads[idx]
        sig = backend.sign(sk, m)
        # быстрый sanity – подпись не пустая
        assert sig and isinstance(sig, (bytes, bytearray))
        idx = (idx + 1) % n_payloads

    results = _run_series(_fn, BENCH_REPEATS, BENCH_WARMUP_SEC, BENCH_DURATION_SEC)
    series = results["ops_per_sec"]
    s = _stats(series)

    _export_result(
        bench="sign",
        backend=backend,
        series=series,
        msg_size=BENCH_MSG_SIZE,
        extra={"note": "sign throughput"},
    )

    assert s["mean"] > 0.0

@pytest.mark.parametrize("backend", [pytest.param(b, id=b.name) for b in _available_backends()] or [])
def test_verify_throughput(backend: SignerSpec, payloads: List[bytes]):
    _require_bench()
    sk, vk = backend.keygen()
    # заранее готовим подписи, чтобы измерять именно verify
    signatures: List[bytes] = [backend.sign(sk, m) for m in payloads]

    idx = 0
    n_payloads = len(payloads)

    def _fn() -> None:
        nonlocal idx
        m = payloads[idx]
        sig = signatures[idx]
        backend.verify(vk, m, sig)
        idx = (idx + 1) % n_payloads

    results = _run_series(_fn, BENCH_REPEATS, BENCH_WARMUP_SEC, BENCH_DURATION_SEC)
    series = results["ops_per_sec"]
    s = _stats(series)

    _export_result(
        bench="verify",
        backend=backend,
        series=series,
        msg_size=BENCH_MSG_SIZE,
        extra={"note": "verify throughput"},
    )

    assert s["mean"] > 0.0

# ------------------------- Экспорт результатов -------------------------

_RESULTS_BUFFER: List[Dict[str, object]] = []

def _export_result(
    bench: str,
    backend: SignerSpec,
    series: List[float],
    msg_size: int,
    extra: Optional[Dict[str, object]] = None,
) -> None:
    rec: Dict[str, object] = {
        "bench": bench,
        "backend": backend.name,
        "algo": backend.algo,
        "ops_per_sec": series,
        "stats": _stats(series),
        "msg_size": msg_size,
        "env": _env_metadata(),
    }
    if extra:
        rec.update(extra)
    _RESULTS_BUFFER.append(rec)

def pytest_sessionfinish(session, exitstatus):
    # В конце сессии сохраняем JSON, если задан путь
    if not LEDGER_BENCH:
        return
    if not BENCH_EXPORT_JSON:
        return
    try:
        out = {
            "meta": {
                "tool": "ledger-core bench_signing",
                "timestamp": time.time(),
            },
            "results": _RESULTS_BUFFER,
        }
        os.makedirs(os.path.dirname(BENCH_EXPORT_JSON), exist_ok=True)
        with open(BENCH_EXPORT_JSON, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    except Exception:
        # Не влияем на статус тестов при ошибках записи
        pass
