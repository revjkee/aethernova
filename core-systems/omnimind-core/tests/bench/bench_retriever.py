# path: tests/bench/bench_retriever.py
from __future__ import annotations

import asyncio
import importlib
import json
import math
import os
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

import pytest

# Типы запроса/ответа для стаб-стора и проверки контрактов
from omnimind.memory.stores.chroma_store import (
    QueryRequest,
    QueryFilters,
    QueryResponse,
    SearchHit,
    Snippet,
)

# =========================
# Конфигурация бенчмарка
# =========================

@dataclass
class BenchConfig:
    # Нагрузочные параметры
    runs: int = int(os.getenv("BENCH_RUNS", "1000"))
    warmup: int = int(os.getenv("BENCH_WARMUP", "50"))
    concurrency: int = int(os.getenv("BENCH_CONCURRENCY", "1"))  # для async
    # Режимы
    mode: str = os.getenv("BENCH_MODE", "fake")  # fake | chroma
    async_hint: Optional[str] = os.getenv("BENCH_ASYNC_HINT")  # force_async | force_sync | None (auto)
    # Запрос
    query: str = os.getenv("BENCH_QUERY", "hello world")
    namespace: str = os.getenv("BENCH_NAMESPACE", "prod")
    kinds: List[str] = os.getenv("BENCH_KINDS", "conversation").split(",")
    top_k: int = int(os.getenv("BENCH_TOPK", "5"))
    # Векторный режим
    space: Optional[str] = os.getenv("BENCH_SPACE") or None
    vector_dim: int = int(os.getenv("BENCH_VECTOR_DIM", "1536"))
    # Стаб-латентность стора (мс) в fake-режиме
    store_latency_ms: int = int(os.getenv("BENCH_STORE_LATENCY_MS", "0"))
    # Репорт
    results_path: Optional[str] = os.getenv("BENCH_RESULTS_JSON") or None
    # Chroma
    chroma_path: Optional[str] = os.getenv("CHROMA_PATH") or None  # для реального стора


CFG = BenchConfig()

# =========================
# Утилиты
# =========================

def _perc(xs: Sequence[float], p: float) -> float:
    if not xs:
        return math.nan
    k = max(0, min(len(xs) - 1, int(round((p / 100.0) * (len(xs) - 1)))))
    return sorted(xs)[k]

def _rand_vec(dim: int, seed: int = 42) -> List[float]:
    # Быстрый детерминированный вектор без внешних зависимостей
    v = []
    r = seed
    for i in range(dim):
        r = (1103515245 * r + 12345) & 0x7FFFFFFF
        v.append((r % 1000) / 999.0)
    return v

def _build_request(cfg: BenchConfig) -> QueryRequest:
    return QueryRequest(
        text_query=cfg.query,
        embedding_space=cfg.space,
        embedding_vector=_rand_vec(cfg.vector_dim) if cfg.space else None,
        top_k=cfg.top_k,
        vector_weight=0.7 if cfg.space else 0.0,
        text_weight=0.3 if cfg.space else 1.0,
        filters=QueryFilters(namespace=cfg.namespace, kinds=cfg.kinds),
    )

def _hit(idx: int, score: float, ns: str, kind: str) -> SearchHit:
    cid = f"c{idx}"
    mid = f"m{idx}"
    return SearchHit(
        memory_id=mid,
        chunk_id=cid,
        score=score,
        vector_score=score,
        text_score=0.0,
        snippet=Snippet(chunk_id=cid, text=f"snippet {cid}"),
        metadata={"namespace": ns, "kind": kind},
    )

# =========================
# FakeStore / реальный store
# =========================

class FakeStore:
    def __init__(self, latency_ms: int = 0, ns: str = "prod", kind: str = "conversation"):
        self.latency_ms = max(0, int(latency_ms))
        self.ns = ns
        self.kind = kind
        self.calls = 0

    def query(self, req: QueryRequest) -> QueryResponse:
        self.calls += 1
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000.0)
        # Генерируем top_k хитов с линейно убывающим скором
        k = max(1, req.top_k)
        hits = [_hit(i, score=1.0 - i / (k + 1), ns=self.ns, kind=self.kind) for i in range(k)]
        return QueryResponse(hits=hits)

def _build_chroma_store(cfg: BenchConfig):
    try:
        import chromadb  # type: ignore
        from omnimind.memory.stores.chroma_store import ChromaStore
    except Exception as e:
        raise RuntimeError(f"Chroma mode requested but dependencies are missing: {e!r}")
    path = cfg.chroma_path or "./.chroma"
    client = chromadb.PersistentClient(path=path)
    return ChromaStore(client)

# =========================
# Загрузка ретривера
# =========================

def _load_retriever_cls():
    try:
        mod = importlib.import_module("omnimind.memory.retriever")
    except Exception as e:
        raise RuntimeError(f"Retriever module not available: {e!r}")
    for name in ("MemoryRetriever", "Retriever", "MemorySearch", "RetrieverService"):
        if hasattr(mod, name):
            return getattr(mod, name)
    raise RuntimeError("Retriever class not found in omnimind.memory.retriever")

def _instantiate_retriever(store: Any):
    cls = _load_retriever_cls()
    # Поддерживаем разные имена аргумента стора
    for kw in ("store", "memory_store", "backend"):
        try:
            return cls(**{kw: store})
        except TypeError:
            continue
    # Последняя попытка: без именованных (на случай позиционного конструктора)
    try:
        return cls(store)
    except TypeError as e:
        raise RuntimeError(f"Cannot instantiate retriever with provided store: {e}")

def _is_async_retrieve(ret) -> bool:
    if CFG.async_hint == "force_async":
        return True
    if CFG.async_hint == "force_sync":
        return False
    import inspect
    return inspect.iscoroutinefunction(getattr(ret, "retrieve", None))

# =========================
# Измерения
# =========================

def _aggregate(latencies: List[float], errors: int, runs: int, started_at: float, finished_at: float) -> dict:
    elapsed = finished_at - started_at
    ok = len(latencies)
    res = {
        "runs": runs,
        "ok": ok,
        "errors": errors,
        "elapsed_s": round(elapsed, 6),
        "rps": round(ok / elapsed if elapsed > 0 else 0.0, 2),
        "avg_ms": round(statistics.mean(latencies) * 1000, 3) if ok else math.nan,
        "median_ms": round(statistics.median(latencies) * 1000, 3) if ok else math.nan,
        "p90_ms": round(_perc(latencies, 90) * 1000, 3) if ok else math.nan,
        "p95_ms": round(_perc(latencies, 95) * 1000, 3) if ok else math.nan,
        "p99_ms": round(_perc(latencies, 99) * 1000, 3) if ok else math.nan,
    }
    return res

async def _bench_async(retriever, req: QueryRequest, runs: int, warmup: int, concurrency: int) -> dict:
    latencies: List[float] = []
    errors = 0

    async def one_run():
        t0 = time.perf_counter()
        try:
            await retriever.retrieve(
                query=req.text_query,
                namespace=req.filters.namespace,
                kinds=req.filters.kinds,
                top_k=req.top_k,
                space=req.embedding_space,
                vector=req.embedding_vector,
                vector_weight=req.vector_weight,
                text_weight=req.text_weight,
            )
            latencies.append(time.perf_counter() - t0)
        except Exception:
            nonlocal errors
            errors += 1

    # Warmup (не учитываем в статистике)
    for _ in range(warmup):
        try:
            await retriever.retrieve(
                query=req.text_query,
                namespace=req.filters.namespace,
                kinds=req.filters.kinds,
                top_k=req.top_k,
                space=req.embedding_space,
                vector=req.embedding_vector,
                vector_weight=req.vector_weight,
                text_weight=req.text_weight,
            )
        except Exception:
            pass

    started_at = time.perf_counter()

    # Лимитируем одновременные задачи семафором
    sem = asyncio.Semaphore(max(1, concurrency))

    async def guarded():
        async with sem:
            await one_run()

    tasks = [guarded() for _ in range(runs)]
    await asyncio.gather(*tasks)

    finished_at = time.perf_counter()
    return _aggregate(latencies, errors, runs, started_at, finished_at)

def _bench_sync(retriever, req: QueryRequest, runs: int, warmup: int) -> dict:
    latencies: List[float] = []
    errors = 0

    def call():
        return retriever.retrieve(
            query=req.text_query,
            namespace=req.filters.namespace,
            kinds=req.filters.kinds,
            top_k=req.top_k,
            space=req.embedding_space,
            vector=req.embedding_vector,
            vector_weight=req.vector_weight,
            text_weight=req.text_weight,
        )

    # Warmup
    for _ in range(warmup):
        try:
            call()
        except Exception:
            pass

    started_at = time.perf_counter()
    for _ in range(runs):
        t0 = time.perf_counter()
        try:
            call()
            latencies.append(time.perf_counter() - t0)
        except Exception:
            errors += 1
    finished_at = time.perf_counter()
    return _aggregate(latencies, errors, runs, started_at, finished_at)

def _prepare_retriever_and_request(cfg: BenchConfig):
    # Выбор стора
    if cfg.mode == "fake":
        store = FakeStore(latency_ms=cfg.store_latency_ms, ns=cfg.namespace, kind=cfg.kinds[0])
    elif cfg.mode == "chroma":
        store = _build_chroma_store(cfg)
    else:
        raise RuntimeError(f"Unknown BENCH_MODE={cfg.mode}")
    retriever = _instantiate_retriever(store)
    req = _build_request(cfg)
    return retriever, req

# =========================
# Pytest тест (скип по умолчанию)
# =========================

@pytest.mark.skipif(os.getenv("BENCH", "0") != "1", reason="Set BENCH=1 to run benchmarks")
def test_bench_retriever():
    retriever, req = _prepare_retriever_and_request(CFG)

    if _is_async_retrieve(retriever):
        results = asyncio.run(_bench_async(retriever, req, CFG.runs, CFG.warmup, CFG.concurrency))
    else:
        results = _bench_sync(retriever, req, CFG.runs, CFG.warmup)

    # Диагностический вывод
    payload = {
        "mode": CFG.mode,
        "async": _is_async_retrieve(retriever),
        "runs": CFG.runs,
        "warmup": CFG.warmup,
        "concurrency": CFG.concurrency,
        "top_k": CFG.top_k,
        "space": CFG.space,
        "namespace": CFG.namespace,
        "kinds": CFG.kinds,
        "store_latency_ms": CFG.store_latency_ms,
        "stats": results,
    }
    print(json.dumps(payload, ensure_ascii=False))

    # Минимальный инвариант: хотя бы один успешный вызов и rps > 0
    assert results["ok"] > 0
    assert results["rps"] >= 0.0

# =========================
# CLI режим
# =========================

def _main(argv: Optional[Sequence[str]] = None) -> int:
    retriever, req = _prepare_retriever_and_request(CFG)
    is_async = _is_async_retrieve(retriever)

    if is_async:
        results = asyncio.run(_bench_async(retriever, req, CFG.runs, CFG.warmup, CFG.concurrency))
    else:
        results = _bench_sync(retriever, req, CFG.runs, CFG.warmup)

    payload = {
        "mode": CFG.mode,
        "async": is_async,
        "runs": CFG.runs,
        "warmup": CFG.warmup,
        "concurrency": CFG.concurrency,
        "top_k": CFG.top_k,
        "space": CFG.space,
        "namespace": CFG.namespace,
        "kinds": CFG.kinds,
        "store_latency_ms": CFG.store_latency_ms,
        "stats": results,
    }
    out = json.dumps(payload, ensure_ascii=False, indent=2)
    sys.stdout.write(out + "\n")

    if CFG.results_path:
        try:
            with open(CFG.results_path, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            sys.stderr.write(f"Failed to write results to {CFG.results_path}: {e!r}\n")
            return 2

    # Возвращаем 0 всегда, чтобы использовать в профилировании без падений
    return 0

if __name__ == "__main__":
    sys.exit(_main())
