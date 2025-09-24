# SPDX-License-Identifier: MIT
# veilmind-core/tests/bench/bench_redaction.py
"""
Benchmark suite for veilmind.utils.text_ops redaction and finders.

Usage (CLI):
  python -m tests.bench.bench_redaction --docs 20000 --size-kb 256 --runs 3 --warmup 1 --workload redact-heavy --json
  python -m tests.bench.bench_redaction --workload finders --docs 5000 --size-kb 64

As pytest (with pytest-benchmark installed):
  pytest -q tests/bench/bench_redaction.py -k bench --benchmark-min-time=0.1

The benchmark generates synthetic but realistic documents mixing plain text with:
  - emails, phones, JWT, AWS access keys, SHA256, URLs, Base64 blobs, credit cards (Luhn-valid)
It then measures throughput and latency distribution for:
  - redact_secrets() (heavy/light)
  - find_urls()/find_emails()/find_phones()/find_credit_cards() (finders)

No external deps required. Results are reproducible given a seed.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
import string
import sys
import time
from dataclasses import dataclass, asdict
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

# Robust import regardless of project layout
def _import_text_ops():
    candidates = [
        "veilmind.utils.text_ops",
        "utils.text_ops",
        "veilmind_core.veilmind.utils.text_ops",
        "text_ops",
    ]
    for name in candidates:
        try:
            return __import__(name, fromlist=["*"])
        except Exception:
            continue
    # Fallback: add project root (two levels up from tests/)
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if root not in sys.path:
        sys.path.insert(0, root)
    return __import__("veilmind.utils.text_ops", fromlist=["*"])


tx = _import_text_ops()

# --------------------------- Synthetic corpus generator ---------------------------

_WORDS = [
    "lorem","ipsum","dolor","sit","amet","consectetur","adipiscing","elit",
    "sed","do","eiusmod","tempor","incididunt","ut","labore","et","dolore",
    "magna","aliqua","ut","enim","ad","minim","veniam","quis","nostrud",
    "exercitation","ullamco","laboris","nisi","aliquip","ex","ea","commodo",
    "consequat","duis","aute","irure","dolor","in","reprehenderit","voluptate"
]

DOMAINS = ["example.com", "corp.local", "mail.test", "demo.io", "service.net"]

def _luhn_complete(prefix_digits: str, total_len: int = 16) -> str:
    digits = [int(c) for c in prefix_digits if c.isdigit()]
    while len(digits) < total_len - 1:
        digits.append(random.randint(0, 9))
    # compute check
    parity = (total_len - 2) % 2
    checksum = 0
    for i, d in enumerate(digits):
        val = d * 2 if i % 2 == parity else d
        if val > 9:
            val -= 9
        checksum += val
    check = (10 - (checksum % 10)) % 10
    digits.append(check)
    s = "".join(str(d) for d in digits)
    # add separators randomly
    if random.random() < 0.5:
        return " ".join(s[i:i+4] for i in range(0, total_len, 4))
    elif random.random() < 0.5:
        return "-".join(s[i:i+4] for i in range(0, total_len, 4))
    return s

def _rand_email() -> str:
    user = "".join(random.choices(string.ascii_lowercase + string.digits + "._+-", k=random.randint(6, 14))).strip(".")
    domain = random.choice(DOMAINS)
    return f"{user}@{domain}"

def _rand_phone() -> str:
    parts = []
    if random.random() < 0.6:
        parts.append("+" + str(random.randint(1, 998)))
    parts.append(str(random.randint(100, 999)))
    parts.append(str(random.randint(100, 999)))
    parts.append(str(random.randint(1000, 9999)))
    sep = random.choice([" ", "-", ""])
    return sep.join(parts)

def _rand_jwt() -> str:
    def chunk(n):
        alphabet = string.ascii_letters + string.digits + "-_"
        return "".join(random.choices(alphabet, k=n))
    return f"{chunk(16)}.{chunk(24)}.{chunk(32)}"

def _rand_aws_key() -> str:
    prefix = random.choice(["AKIA", "ASIA"])
    return prefix + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))

def _rand_sha256() -> str:
    return "".join(random.choices("0123456789abcdef", k=64))

def _rand_url() -> str:
    scheme = random.choice(["http", "https"])
    host = random.choice(["api", "cdn", "app", "files", "auth"]) + "." + random.choice(DOMAINS)
    path = "/" + "/".join(random.choices(_WORDS, k=random.randint(1, 4)))
    qs = ""
    if random.random() < 0.6:
        qs = "?k=" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{scheme}://{host}{path}{qs}"

def _rand_b64(n: int = 120) -> str:
    alphabet = string.ascii_letters + string.digits + "+/"
    body = "".join(random.choices(alphabet, k=n))
    pad = random.choice(["", "=", "=="])
    return body + pad

def _rand_sentence(min_words=6, max_words=16) -> str:
    return " ".join(random.choices(_WORDS, k=random.randint(min_words, max_words))).capitalize() + "."

def make_document(target_kb: int, heavy: bool = True) -> str:
    """
    Create a synthetic document close to target_kb size, mixing plain text with PII/secrets.
    'heavy' inserts more sensitive tokens; 'light' inserts fewer.
    """
    chunks: List[str] = []
    size = 0
    while size < target_kb * 1024:
        # plain sentences
        for _ in range(random.randint(2, 5)):
            s = _rand_sentence()
            chunks.append(s)
            size += len(s) + 1
            if size >= target_kb * 1024:
                break
        # inject secrets/identifiers
        injects = [
            _rand_email(),
            _rand_phone(),
            _rand_url(),
            _rand_jwt() if random.random() < 0.5 else _rand_b64(),
            _rand_aws_key(),
            _rand_sha256(),
            _luhn_complete(str(random.randint(4000, 4999)), total_len=random.randint(13, 19)),
        ]
        # choose number based on heaviness
        k = random.randint(4, 7) if heavy else random.randint(1, 3)
        sample = random.sample(injects, k=k)
        sep = " " if random.random() < 0.7 else "\n"
        blob = sep.join(sample)
        chunks.append(blob)
        size += len(blob) + 1
    return "\n".join(chunks)[: target_kb * 1024]

def build_corpus(n_docs: int, size_kb: int, seed: int = 42, heavy: bool = True) -> List[str]:
    rnd = random.Random(seed)
    # reseed module-level random too for deterministic generators
    random.seed(seed)
    docs = []
    for i in range(n_docs):
        random.seed(rnd.randint(0, 2**31 - 1))
        docs.append(make_document(size_kb, heavy=heavy))
    return docs

# ------------------------------- Benchmark runner --------------------------------

@dataclass
class BenchResult:
    name: str
    docs: int
    total_bytes: int
    total_hits: int
    runs: int
    wall_time_sec: float
    throughput_mb_s: float
    doc_avg_us: float
    p50_ms: float
    p95_ms: float

def _measure_workload(name: str, docs: Sequence[str], fn: Callable[[str], int]) -> BenchResult:
    # Warmup inside calling code if needed
    per_doc_ms: List[float] = []
    total_hits = 0
    t0 = time.perf_counter()
    for d in docs:
        t1 = time.perf_counter()
        hits = fn(d)
        total_hits += int(hits)
        t2 = time.perf_counter()
        per_doc_ms.append((t2 - t1) * 1000.0)
    t_end = time.perf_counter()
    wall = t_end - t0
    total_bytes = sum(len(x) for x in docs)
    mb = total_bytes / (1024 * 1024)
    thr = mb / wall if wall > 0 else float("inf")
    p50 = statistics.median(per_doc_ms) if per_doc_ms else 0.0
    p95 = statistics.quantiles(per_doc_ms, n=100)[94] if len(per_doc_ms) >= 100 else max(per_doc_ms) if per_doc_ms else 0.0
    avg_us = (sum(per_doc_ms) / len(per_doc_ms) * 1000.0) if per_doc_ms else 0.0  # ms -> us
    return BenchResult(
        name=name,
        docs=len(docs),
        total_bytes=total_bytes,
        total_hits=total_hits,
        runs=1,
        wall_time_sec=round(wall, 6),
        throughput_mb_s=round(thr, 2),
        doc_avg_us=round(avg_us, 2),
        p50_ms=round(p50, 3),
        p95_ms=round(p95, 3),
    )

def run_bench(workload: str, docs: int, size_kb: int, warmup: int = 1, runs: int = 3, seed: int = 42) -> Dict[str, BenchResult]:
    heavy = workload == "redact-heavy"
    corpus = build_corpus(docs, size_kb, seed=seed, heavy=heavy)

    # Warmup (JIT of regex, cache, CPU turbo)
    for _ in range(max(0, warmup)):
        for d in corpus[: min(64, len(corpus))]:
            tx.redact_secrets(d)

    results: Dict[str, BenchResult] = {}

    def op_redact(s: str) -> int:
        _, count, _ = tx.redact_secrets(s)
        return count

    def op_finders(s: str) -> int:
        return (
            len(tx.find_urls(s))
            + len(tx.find_emails(s))
            + len(tx.find_phones(s))
            + len(tx.find_credit_cards(s))
        )

    to_run: List[Tuple[str, Callable[[str], int]]] = []
    if workload in ("redact-heavy", "redact-light", "redact"):
        to_run.append(("redact_secrets", op_redact))
    if workload in ("finders", "all"):
        to_run.append(("finders_sum", op_finders))
        to_run.append(("find_urls", lambda s: len(tx.find_urls(s))))
        to_run.append(("find_emails", lambda s: len(tx.find_emails(s))))
        to_run.append(("find_phones", lambda s: len(tx.find_phones(s))))
        to_run.append(("find_credit_cards", lambda s: len(tx.find_credit_cards(s))))

    for name, fn in to_run:
        # Multiple runs for stability; average throughput and keep last percentiles
        agg_time = 0.0
        agg_hits = 0
        last_res = None
        for _ in range(max(1, runs)):
            res = _measure_workload(name, corpus, fn)
            agg_time += res.wall_time_sec
            agg_hits += res.total_hits
            last_res = res
        assert last_res is not None
        total_bytes = sum(len(x) for x in corpus)
        mb = total_bytes / (1024 * 1024)
        thr = mb / (agg_time / max(1, runs))
        results[name] = BenchResult(
            name=name,
            docs=docs,
            total_bytes=total_bytes,
            total_hits=agg_hits // max(1, runs),
            runs=max(1, runs),
            wall_time_sec=round(agg_time / max(1, runs), 6),
            throughput_mb_s=round(thr, 2),
            doc_avg_us=last_res.doc_avg_us,
            p50_ms=last_res.p50_ms,
            p95_ms=last_res.p95_ms,
        )
    return results

# ---------------------------------- CLI -----------------------------------------

def _cli(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="Benchmark veilmind.utils.text_ops redaction and finders")
    ap.add_argument("--docs", type=int, default=5000, help="number of documents")
    ap.add_argument("--size-kb", type=int, default=16, help="approx size of each doc in KiB")
    ap.add_argument("--workload", choices=["redact-light", "redact-heavy", "finders", "all", "redact"], default="redact-heavy")
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    res = run_bench(args.workload, args.docs, args.size_kb, warmup=args.warmup, runs=args.runs, seed=args.seed)
    if args.json:
        out = {k: asdict(v) for k, v in res.items()}
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for name, r in res.items():
            print(f"[{name}] docs={r.docs} bytes={r.total_bytes} hits≈{r.total_hits} runs={r.runs}")
            print(f"  time={r.wall_time_sec:.6f}s  thr={r.throughput_mb_s:.2f} MB/s  avg={r.doc_avg_us:.2f} µs/doc  p50={r.p50_ms:.3f} ms  p95={r.p95_ms:.3f} ms")
    return 0

if __name__ == "__main__" and "PYTEST_CURRENT_TEST" not in os.environ:
    sys.exit(_cli(sys.argv[1:]))

# --------------------------- pytest-benchmark integration -----------------------

# These tests run only if pytest-benchmark is installed (provide 'benchmark' fixture).
try:
    import pytest  # type: ignore
    _HAS_PYTEST = True
except Exception:
    _HAS_PYTEST = False

if _HAS_PYTEST:

    @pytest.mark.benchmark(group="redact_secrets")
    @pytest.mark.skipif(pytest.importorskip("pytest_benchmark") is None, reason="pytest-benchmark not installed")
    def test_bench_redact_heavy_pytest(benchmark):
        docs = build_corpus(n_docs=2000, size_kb=8, seed=123, heavy=True)
        def op():
            c = 0
            for d in docs:
                _, n, _ = tx.redact_secrets(d)
                c += n
            return c
        total_hits = benchmark(op)
        assert total_hits >= 0  # sanity

    @pytest.mark.benchmark(group="finders")
    @pytest.mark.skipif(pytest.importorskip("pytest_benchmark") is None, reason="pytest-benchmark not installed")
    def test_bench_finders_sum_pytest(benchmark):
        docs = build_corpus(n_docs=1500, size_kb=8, seed=321, heavy=False)
        def op():
            c = 0
            for d in docs:
                c += len(tx.find_urls(d))
                c += len(tx.find_emails(d))
                c += len(tx.find_phones(d))
                c += len(tx.find_credit_cards(d))
            return c
        total_hits = benchmark(op)
        assert total_hits > 0
