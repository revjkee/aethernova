# security-core/tests/bench/bench_sign_verify.py
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import secrets
import socket
import statistics as stats
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Используем ваш промышленный слой подписи
from security_core.security.crypto.signer import (
    Signer,
    SignOptions,
    SignatureAlgorithm,
    HashAlgorithm,
    SignatureEncoding,
    SoftKeyProvider,
)

# ------------------------------ Конфиг ----------------------------------------

@dataclass
class BenchConfig:
    algorithm: str = "RSA_PSS"                   # RSA_PSS | RSA_PKCS1v15 | ECDSA | ED25519
    hash_alg: str = "SHA384"                     # SHA256 | SHA384 | SHA512 (к RSA/ECDSA)
    rsa_bits: int = 3072
    ecdsa_curve: str = "secp384r1"               # secp256r1 | secp384r1 | secp521r1
    ecdsa_encoding: str = "DER"                  # DER | RAW
    rsa_pss_salt_len: Optional[int] = None       # по умолчанию = длине хэша
    message_size: int = 1024                     # байт
    unique_messages: bool = True                 # уникальный payload на операцию
    operations: int = 5000
    concurrency: int = 1
    warmup_ops: int = 200
    streaming: bool = False                      # доступно для RSA/ECDSA
    stream_chunk: int = 64 * 1024                # байт
    key_pem: Optional[str] = None                # путь к приватному PEM
    out_json: Optional[str] = None
    out_csv: Optional[str] = None
    pretty: bool = True                          # формат JSON
    verify_after_sign: bool = True               # проверять корректность сигнатур


@dataclass
class SystemInfo:
    python: str
    openssl: Optional[str]
    platform: str
    machine: str
    hostname: str


@dataclass
class CaseInfo:
    algorithm: str
    hash_alg: Optional[str]
    rsa_bits: Optional[int]
    ecdsa_curve: Optional[str]
    ecdsa_encoding: Optional[str]
    rsa_pss_salt_len: Optional[int]
    message_size: int
    streaming: bool
    stream_chunk: int
    concurrency: int
    operations: int
    unique_messages: bool
    key_source: str


@dataclass
class LatencyStats:
    count: int
    avg_ms: float
    p50_ms: float
    p90_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float


@dataclass
class BenchResult:
    sys: SystemInfo
    case: CaseInfo
    sign_ops_per_sec: float
    verify_ops_per_sec: float
    sign_latency: LatencyStats
    verify_latency: LatencyStats
    started_at: float
    finished_at: float
    duration_sec: float
    notes: List[str] = field(default_factory=list)


# ------------------------------ Утилиты ---------------------------------------

def _now_ns() -> int:
    return time.perf_counter_ns()

def _ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0

def _quantile(sorted_vals: List[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    if q <= 0:
        return sorted_vals[0]
    if q >= 1:
        return sorted_vals[-1]
    idx = (len(sorted_vals) - 1) * q
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac

def _lat_stats(lat_ms: List[float]) -> LatencyStats:
    if not lat_ms:
        return LatencyStats(0, float("nan"), float("nan"), float("nan"), float("nan"), float("nan"), float("nan"))
    s = sorted(lat_ms)
    return LatencyStats(
        count=len(lat_ms),
        avg_ms=(sum(lat_ms) / len(lat_ms)),
        p50_ms=_quantile(s, 0.50),
        p90_ms=_quantile(s, 0.90),
        p99_ms=_quantile(s, 0.99),
        min_ms=s[0],
        max_ms=s[-1],
    )

def _rand_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def _build_signer(cfg: BenchConfig) -> Tuple[Signer, SignOptions, str]:
    alg = SignatureAlgorithm[cfg.algorithm]
    if cfg.key_pem:
        pem = Path(cfg.key_pem).read_text(encoding="utf-8")
        prov = SoftKeyProvider.from_pem(pem)
    else:
        if alg in (SignatureAlgorithm.RSA_PSS, SignatureAlgorithm.RSA_PKCS1v15):
            prov = SoftKeyProvider.generate(SignatureAlgorithm.RSA_PSS, bits=cfg.rsa_bits)
        elif alg == SignatureAlgorithm.ECDSA:
            prov = SoftKeyProvider.generate(SignatureAlgorithm.ECDSA, curve=cfg.ecdsa_curve)
        elif alg == SignatureAlgorithm.ED25519:
            prov = SoftKeyProvider.generate(SignatureAlgorithm.ED25519)
        else:
            raise ValueError("Unsupported algorithm")
    opts = SignOptions(
        algorithm=alg,
        hash_alg=HashAlgorithm[cfg.hash_alg] if alg != SignatureAlgorithm.ED25519 else HashAlgorithm.SHA256,
        ecdsa_encoding=SignatureEncoding[cfg.ecdsa_encoding] if alg == SignatureAlgorithm.ECDSA else SignatureEncoding.DER,
        rsa_pss_salt_len=cfg.rsa_pss_salt_len,
    )
    return Signer(prov, opts), opts, ("pem" if cfg.key_pem else "generated")

def _gen_payloads(cfg: BenchConfig) -> List[bytes]:
    if not cfg.unique_messages:
        return [_rand_bytes(cfg.message_size)]
    return [_rand_bytes(cfg.message_size) for _ in range(cfg.operations)]

def _sign_one(signer: Signer, msg: bytes, streaming: bool, stream_chunk: int) -> bytes:
    if streaming and signer.opts.algorithm != SignatureAlgorithm.ED25519:
        st = signer.stream()
        # Разбиваем на куски; последний может быть короче
        for i in range(0, len(msg), stream_chunk):
            st.update(msg[i:i+stream_chunk])
        return st.finalize()
    return signer.sign(msg)

def _verify_one(signer: Signer, msg: bytes, sig: bytes, streaming: bool, stream_chunk: int) -> bool:
    # Верификация всегда по полному сообщению (streaming влияет на подготовку подписи у RSA/ECDSA)
    return signer.verify(msg, sig)

def _run_parallel(n_ops: int, concurrency: int, fn_make_task) -> Tuple[List[float], float]:
    """
    fn_make_task(i) -> callable returning latency_ms
    Возвращает список латентностей и длительность всего этапа.
    """
    latencies_ms: List[float] = []
    started = time.perf_counter()
    # Разбиваем на равные порции по воркерам
    per_worker = [n_ops // concurrency] * concurrency
    for i in range(n_ops % concurrency):
        per_worker[i] += 1

    def worker(work_idx: int, count: int) -> List[float]:
        out: List[float] = []
        for k in range(count):
            t0 = _now_ns()
            fn_make_task().__call__()
            t1 = _now_ns()
            out.append(_ns_to_ms(t1 - t0))
        return out

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(worker, i, c) for i, c in enumerate(per_worker) if c > 0]
        for f in futs:
            latencies_ms.extend(f.result())
    total_dur = time.perf_counter() - started
    return latencies_ms, total_dur

# ------------------------------ Бенч ------------------------------------------

def run_bench(cfg: BenchConfig) -> BenchResult:
    signer, _opts, key_src = _build_signer(cfg)
    sysinfo = SystemInfo(
        python=sys.version.split()[0],
        openssl=getattr(sys, "openssl_version", None),
        platform=f"{platform.system()} {platform.release()}",
        machine=platform.machine(),
        hostname=socket.gethostname(),
    )
    case = CaseInfo(
        algorithm=cfg.algorithm,
        hash_alg=cfg.hash_alg if cfg.algorithm != "ED25519" else None,
        rsa_bits=cfg.rsa_bits if "RSA" in cfg.algorithm else None,
        ecdsa_curve=cfg.ecdsa_curve if cfg.algorithm == "ECDSA" else None,
        ecdsa_encoding=cfg.ecdsa_encoding if cfg.algorithm == "ECDSA" else None,
        rsa_pss_salt_len=cfg.rsa_pss_salt_len if cfg.algorithm == "RSA_PSS" else None,
        message_size=cfg.message_size,
        streaming=cfg.streaming if cfg.algorithm != "ED25519" else False,
        stream_chunk=cfg.stream_chunk,
        concurrency=cfg.concurrency,
        operations=cfg.operations,
        unique_messages=cfg.unique_messages,
        key_source=key_src,
    )

    notes: List[str] = []
    if cfg.streaming and cfg.algorithm == "ED25519":
        notes.append("streaming недоступен для Ed25519 и был отключен")

    # Подготовка данных
    payloads = _gen_payloads(cfg)
    if not cfg.unique_messages:
        payloads = payloads * cfg.operations  # повторяем ссылку, чтобы индексы совпали

    # Разогрев
    warm = min(cfg.warmup_ops, max(10, cfg.operations // 20))
    for i in range(warm):
        msg = payloads[i % len(payloads)]
        _ = _sign_one(signer, msg, cfg.streaming, cfg.stream_chunk)

    # Подпись
    sigs: List[bytes] = [b""] * cfg.operations  # для последующей проверки
    idx_sign = {"i": 0}

    def make_sign_task():
        def task():
            i = idx_sign["i"]
            idx_sign["i"] = i + 1
            msg = payloads[i % len(payloads)]
            sig = _sign_one(signer, msg, cfg.streaming, cfg.stream_chunk)
            sigs[i] = sig
        return task

    t0 = time.time()
    sign_lat, sign_total = _run_parallel(cfg.operations, cfg.concurrency, make_sign_task)
    # Проверка корректности и подготовка к verify
    if cfg.verify_after_sign:
        for i in range(cfg.operations):
            if not signer.verify(payloads[i % len(payloads)], sigs[i]):
                raise AssertionError("verify failed after sign at index {}".format(i))

    # Verify
    idx_ver = {"i": 0}
    def make_verify_task():
        def task():
            i = idx_ver["i"]
            idx_ver["i"] = i + 1
            msg = payloads[i % len(payloads)]
            ok = _verify_one(signer, msg, sigs[i], cfg.streaming, cfg.stream_chunk)
            if not ok:
                raise AssertionError("verify failed during benchmark")
        return task

    verify_lat, verify_total = _run_parallel(cfg.operations, cfg.concurrency, make_verify_task)
    t1 = time.time()

    sign_ops_sec = cfg.operations / sign_total if sign_total > 0 else 0.0
    verify_ops_sec = cfg.operations / verify_total if verify_total > 0 else 0.0

    result = BenchResult(
        sys=sysinfo,
        case=case,
        sign_ops_per_sec=sign_ops_sec,
        verify_ops_per_sec=verify_ops_sec,
        sign_latency=_lat_stats(sign_lat),
        verify_latency=_lat_stats(verify_lat),
        started_at=t0,
        finished_at=t1,
        duration_sec=(t1 - t0),
        notes=notes,
    )
    return result

# ------------------------------ Вывод -----------------------------------------

def print_human(result: BenchResult) -> None:
    c = result.case
    print("=== bench_sign_verify ===")
    print(f"algo={c.algorithm} hash={c.hash_alg} rsa_bits={c.rsa_bits} curve={c.ecdsa_curve} enc={c.ecdsa_encoding}")
    print(f"msg={c.message_size}B streaming={c.streaming} chunk={c.stream_chunk} conc={c.concurrency} ops={c.operations}")
    print(f"key={c.key_source} unique_messages={c.unique_messages}")
    print(f"sign:  {result.sign_ops_per_sec:,.2f} ops/s  "
          f"avg={result.sign_latency.avg_ms:.3f} ms  p50={result.sign_latency.p50_ms:.3f}  "
          f"p90={result.sign_latency.p90_ms:.3f}  p99={result.sign_latency.p99_ms:.3f}  "
          f"min={result.sign_latency.min_ms:.3f}  max={result.sign_latency.max_ms:.3f}")
    print(f"verify:{result.verify_ops_per_sec:,.2f} ops/s  "
          f"avg={result.verify_latency.avg_ms:.3f} ms  p50={result.verify_latency.p50_ms:.3f}  "
          f"p90={result.verify_latency.p90_ms:.3f}  p99={result.verify_latency.p99_ms:.3f}  "
          f"min={result.verify_latency.min_ms:.3f}  max={result.verify_latency.max_ms:.3f}")
    if result.notes:
        for n in result.notes:
            print(f"note: {n}")

def dump_json(result: BenchResult, path: str, pretty: bool) -> None:
    data = {
        "system": asdict(result.sys),
        "case": asdict(result.case),
        "metrics": {
            "sign_ops_per_sec": result.sign_ops_per_sec,
            "verify_ops_per_sec": result.verify_ops_per_sec,
            "sign_latency": asdict(result.sign_latency),
            "verify_latency": asdict(result.verify_latency),
        },
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_sec": result.duration_sec,
        "notes": result.notes,
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2 if pretty else None)

def dump_csv(result: BenchResult, path: str) -> None:
    """
    Плоская строка для простого импорта в таблицы.
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "algo","hash","rsa_bits","curve","ecdsa_encoding","msg_bytes","streaming","chunk",
            "concurrency","operations","key_source",
            "sign_ops_per_sec","verify_ops_per_sec",
            "sign_avg_ms","sign_p50_ms","sign_p90_ms","sign_p99_ms","sign_min_ms","sign_max_ms",
            "verify_avg_ms","verify_p50_ms","verify_p90_ms","verify_p99_ms","verify_min_ms","verify_max_ms",
            "hostname","platform","machine","python","duration_sec"
        ])
        w.writerow([
            result.case.algorithm, result.case.hash_alg, result.case.rsa_bits, result.case.ecdsa_curve,
            result.case.ecdsa_encoding, result.case.message_size, result.case.streaming, result.case.stream_chunk,
            result.case.concurrency, result.case.operations, result.case.key_source,
            f"{result.sign_ops_per_sec:.6f}", f"{result.verify_ops_per_sec:.6f}",
            f"{result.sign_latency.avg_ms:.6f}", f"{result.sign_latency.p50_ms:.6f}",
            f"{result.sign_latency.p90_ms:.6f}", f"{result.sign_latency.p99_ms:.6f}",
            f"{result.sign_latency.min_ms:.6f}", f"{result.sign_latency.max_ms:.6f}",
            f"{result.verify_latency.avg_ms:.6f}", f"{result.verify_latency.p50_ms:.6f}",
            f"{result.verify_latency.p90_ms:.6f}", f"{result.verify_latency.p99_ms:.6f}",
            f"{result.verify_latency.min_ms:.6f}", f"{result.verify_latency.max_ms:.6f}",
            result.sys.hostname, result.sys.platform, result.sys.machine, result.sys.python,
            f"{result.duration_sec:.6f}",
        ])

# ------------------------------ CLI ------------------------------------------

def _parse_args(argv: Optional[List[str]] = None) -> BenchConfig:
    p = argparse.ArgumentParser(description="Benchmark for Signer.sign()/verify()")
    p.add_argument("--algorithm", choices=[a.name for a in SignatureAlgorithm], default="RSA_PSS")
    p.add_argument("--hash", dest="hash_alg", choices=[h.name for h in HashAlgorithm], default="SHA384")
    p.add_argument("--rsa-bits", type=int, default=3072)
    p.add_argument("--ecdsa-curve", choices=["secp256r1","secp384r1","secp521r1"], default="secp384r1")
    p.add_argument("--ecdsa-encoding", choices=["DER","RAW"], default="DER")
    p.add_argument("--rsa-pss-salt-len", type=int, default=None)
    p.add_argument("--message-size", type=int, default=1024)
    p.add_argument("--unique-messages", action="store_true", default=True)
    p.add_argument("--no-unique-messages", dest="unique_messages", action="store_false")
    p.add_argument("--operations", type=int, default=5000)
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--warmup-ops", type=int, default=200)
    p.add_argument("--streaming", action="store_true", help="streaming mode for RSA/ECDSA")
    p.add_argument("--stream-chunk", type=int, default=64*1024)
    p.add_argument("--key-pem", type=str, default=None, help="path to private key PEM")
    p.add_argument("--out-json", type=str, default=None)
    p.add_argument("--out-csv", type=str, default=None)
    p.add_argument("--pretty", action="store_true", default=True)
    p.add_argument("--no-pretty", dest="pretty", action="store_false")
    p.add_argument("--no-verify", dest="verify_after_sign", action="store_false")
    args = p.parse_args(argv)
    return BenchConfig(**vars(args))

def main(argv: Optional[List[str]] = None) -> int:
    cfg = _parse_args(argv)
    # Корректировки для Ed25519
    if cfg.algorithm == "ED25519":
        cfg.hash_alg = "SHA256"  # не используется, но оставим значение
        cfg.streaming = False

    res = run_bench(cfg)
    print_human(res)
    if cfg.out_json:
        dump_json(res, cfg.out_json, cfg.pretty)
    if cfg.out_csv:
        dump_csv(res, cfg.out_csv)
    return 0

if __name__ == "__main__":
    sys.exit(main())
