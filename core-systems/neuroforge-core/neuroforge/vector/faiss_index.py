# File: neuroforge-core/neuroforge/vector/faiss_index.py
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

import numpy as np

try:
    import faiss  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("FAISS is required: install faiss-cpu or faiss-gpu") from e

# Optional dependencies
try:
    from pydantic import BaseModel, Field, field_validator  # pydantic v2+
    _HAS_PYDANTIC = True
except Exception:  # pragma: no cover
    _HAS_PYDANTIC = False

try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False
    def Counter(*a, **k): return None  # type: ignore
    def Histogram(*a, **k): return None  # type: ignore
    def Gauge(*a, **k): return None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

log = logging.getLogger(__name__)

MetricT = Literal["l2", "ip", "cosine"]
IndexTypeT = Literal["flat", "ivf_flat", "ivf_pq"]
DeviceT = Literal["auto", "cpu", "gpu"]

# ---------- Metrics ----------
_IDX_SIZE = Gauge("nf_faiss_index_size", "Number of vectors in the index") if _HAS_PROM else None
_OP_LAT = Histogram("nf_faiss_op_seconds", "FAISS operation latency seconds", ["op"]) if _HAS_PROM else None
_OP_ERR = Counter("nf_faiss_op_errors_total", "FAISS operation errors", ["op", "type"]) if _HAS_PROM else None


def _otel_span(name: str):
    if not _HAS_OTEL:
        class _N:
            def __enter__(self): return None
            def __exit__(self, *a): return False
        return _N()
    tracer = trace.get_tracer(__name__)  # type: ignore
    return tracer.start_as_current_span(name)  # type: ignore


# ---------- Config ----------
if _HAS_PYDANTIC:
    class FaissIndexConfig(BaseModel):
        dim: int = Field(..., gt=0)
        metric: MetricT = Field("l2", description="l2|ip|cosine (cosine реализуется через нормализацию + IP)")
        index_type: IndexTypeT = Field("ivf_flat")

        # IVF params
        nlist: int = Field(1024, gt=0, description="число кластеров (IVF)")
        nprobe: int = Field(16, gt=1, description="число кластеров для поиска")

        # PQ params (для ivf_pq)
        pq_m: int = Field(16, gt=0, description="кол-во сабкодов")
        pq_bits: int = Field(8, gt=1, description="бит на сабкод")
        opq_m: Optional[int] = Field(None, description="если задано — добавляет OPQ(d, opq_m) как предтрансформ")

        # Preprocessing
        normalize: bool = Field(False, description="принудительная нормализация входов (авто для cosine)")
        pca_dim: Optional[int] = Field(None, description="если задано — применить PCA до индекса")

        # Device
        device: DeviceT = Field("auto")
        gpu_device_id: int = Field(0, ge=0)

        # Save path aux meta
        meta_ext: str = Field(".meta.json")

        @field_validator("nprobe")
        @classmethod
        def _nprobe_le_nlist(cls, v: int, info):
            nlist = info.data.get("nlist", 1024)
            if v > nlist:
                raise ValueError("nprobe must be <= nlist")
            return v

        @field_validator("pca_dim")
        @classmethod
        def _pca_le_dim(cls, v: Optional[int], info):
            if v is not None and v <= 0:
                raise ValueError("pca_dim must be > 0")
            if v is not None and v > info.data.get("dim", 0):
                raise ValueError("pca_dim must be <= dim")
            return v
else:
    @dataclass
    class FaissIndexConfig:  # type: ignore
        dim: int = 0
        metric: MetricT = "l2"
        index_type: IndexTypeT = "ivf_flat"
        nlist: int = 1024
        nprobe: int = 16
        pq_m: int = 16
        pq_bits: int = 8
        opq_m: Optional[int] = None
        normalize: bool = False
        pca_dim: Optional[int] = None
        device: DeviceT = "auto"
        gpu_device_id: int = 0
        meta_ext: str = ".meta.json"


def _faiss_metric(metric: MetricT) -> int:
    if metric in ("ip", "cosine"):
        return faiss.METRIC_INNER_PRODUCT
    return faiss.METRIC_L2


def _ensure_float32(a: np.ndarray) -> np.ndarray:
    if a.dtype != np.float32:
        return a.astype(np.float32, copy=False)
    return a


def _normalize_rows(x: np.ndarray) -> np.ndarray:
    # Avoid division by zero
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return x / norms


def _with_metric_timer(op: str):
    class _T:
        def __enter__(self):
            self.timer = None
            if _HAS_PROM and _OP_LAT:
                self.timer = _OP_LAT.labels(op=op).time()
            return self
        def __exit__(self, exc_type, exc, tb):
            if self.timer:
                self.timer.__exit__(exc_type, exc, tb)
            if exc and _HAS_PROM and _OP_ERR:
                _OP_ERR.labels(op=op, type=exc.__class__.__name__).inc()
            return False
    return _T()


# ---------- Index wrapper ----------
class FaissIndex:
    """
    Потокобезопасная обертка над FAISS с поддержкой:
     - типов индексов: flat | ivf_flat | ivf_pq
     - метрик: l2 | ip | cosine (через нормализацию и IP)
     - CPU/GPU (прозрачный fallback)
     - трансформов: PCA, OPQ
     - IDMap2 (add_with_ids/remove_ids), reconstruct
     - save/load (+конфиг метаданные *.meta.json)
    """

    def __init__(self, config: FaissIndexConfig):
        self.cfg = config
        if self.cfg.dim <= 0:
            raise ValueError("dim must be > 0")
        if self.cfg.metric == "cosine":
            self.cfg.normalize = True  # косинус требует нормализации
        self._index: Optional[faiss.Index] = None
        self._gpu_res = None  # GPU resources if used
        self._is_gpu = False
        self._lock = threading.RLock()
        self._trained = False

    # ---------- Build/Train ----------
    def build(self) -> None:
        with self._lock, _with_metric_timer("build"), _otel_span("nf.faiss.build"):
            idx = self._make_base_index()
            # ID map to support external ids, deletions
            idmap = faiss.IndexIDMap2(idx)
            # GPU?
            idmap = self._maybe_to_gpu(idmap)
            self._index = idmap
            self._trained = self._index.is_trained
            self._apply_search_params()

    def train(self, train_vectors: np.ndarray) -> None:
        with self._lock, _with_metric_timer("train"), _otel_span("nf.faiss.train"):
            self._ensure_built()
            x = self._prepare_vectors(train_vectors)
            if not self._index.is_trained:
                self._index.train(x)
            self._trained = True

    # ---------- CRUD ----------
    def add(self, vectors: np.ndarray, ids: np.ndarray) -> int:
        """
        Добавляет векторы с явными 64-битными id. Возвращает число добавленных.
        """
        with self._lock, _with_metric_timer("add"), _otel_span("nf.faiss.add"):
            self._ensure_ready_for_add(vectors, ids)
            x = self._prepare_vectors(vectors)
            ids64 = self._prepare_ids(ids)
            # Для IVF индекс должен быть обучен
            if not self._index.is_trained:
                raise RuntimeError("index is not trained; call train() first (IVF types)")
            self._index.add_with_ids(x, ids64)
            self._update_size_gauge()
            return x.shape[0]

    def upsert(self, vectors: np.ndarray, ids: np.ndarray) -> int:
        """
        Обновляет (заменяет) по id: remove_ids + add_with_ids. Возвращает число добавленных.
        """
        with self._lock, _with_metric_timer("upsert"), _otel_span("nf.faiss.upsert"):
            self._ensure_ready_for_add(vectors, ids)
            ids64 = self._prepare_ids(ids)
            self._remove_ids_internal(ids64)
            return self.add(vectors, ids)

    def remove(self, ids: np.ndarray) -> int:
        with self._lock, _with_metric_timer("remove"), _otel_span("nf.faiss.remove"):
            self._ensure_built()
            ids64 = self._prepare_ids(ids)
            n = self._remove_ids_internal(ids64)
            self._update_size_gauge()
            return n

    def _remove_ids_internal(self, ids64: np.ndarray) -> int:
        sel = faiss.IDSelectorBatch(ids64.size, faiss.swig_ptr(ids64))
        n = self._index.remove_ids(sel)
        return int(n)

    # ---------- Search ----------
    def search(self, queries: np.ndarray, k: int) -> Tuple[np.ndarray, np.ndarray]:
        """
        Возвращает (distances, ids) формы [nq, k]
        """
        with self._lock, _with_metric_timer("search"), _otel_span("nf.faiss.search"):
            self._ensure_built()
            if k <= 0:
                raise ValueError("k must be > 0")
            q = self._prepare_vectors(queries)
            self._apply_search_params()
            D, I = self._index.search(q, k)
            return D, I

    def reconstruct(self, ids: np.ndarray) -> np.ndarray:
        """
        Реконструирует векторы по id (если индекс поддерживает).
        """
        with self._lock, _with_metric_timer("reconstruct"), _otel_span("nf.faiss.reconstruct"):
            self._ensure_built()
            ids64 = self._prepare_ids(ids)
            out = np.zeros((ids64.shape[0], self.cfg.dim), dtype=np.float32)
            for i, _id in enumerate(ids64):
                out[i] = self._index.reconstruct(int(_id))
            # Если хранили cosine (=нормированные), отдаём нормализованные представления (ожидаемо).
            return out

    def ntotal(self) -> int:
        with self._lock:
            self._ensure_built()
            return int(self._index.ntotal)

    # ---------- Save/Load ----------
    def save(self, path: str) -> None:
        """
        Сохраняет индекс на диск. Для GPU — переводит на CPU перед записью.
        Рядом пишет конфиг в *.meta.json
        """
        with self._lock, _with_metric_timer("save"), _otel_span("nf.faiss.save"):
            self._ensure_built()
            idx = self._index
            if self._is_gpu:
                idx = faiss.index_gpu_to_cpu(idx)
            faiss.write_index(idx, path)
            meta = self._meta_dict()
            with open(path + self.cfg.meta_ext, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "FaissIndex":
        """
        Загружает индекс + метаданные. Если device в метаданных = auto/gpu и доступен GPU,
        переносит на GPU.
        """
        with _with_metric_timer("load"), _otel_span("nf.faiss.load"):
            # Читаем метаданные
            meta_path = cls._meta_path_for(path)
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                cfg = cls._config_from_meta(meta)
            else:
                raise RuntimeError("missing metadata file for index: " + meta_path)

            # Сам индекс
            idx = faiss.read_index(path)
            # Обернуть IDMap2, если нужно
            if not isinstance(idx, faiss.IndexIDMap2):
                idx = faiss.IndexIDMap2(idx)

            self = cls(cfg)
            self._index = self._maybe_to_gpu(idx)
            self._trained = self._index.is_trained
            self._apply_search_params()
            self._update_size_gauge()
            return self

    # ---------- Internal builders ----------
    def _make_base_index(self) -> faiss.Index:
        d = self.cfg.dim
        metric = _faiss_metric(self.cfg.metric)

        # Предтрансформы (PCA/OPQ)
        transforms: List[Any] = []
        if self.cfg.pca_dim:
            transforms.append(faiss.PCAMatrix(d, self.cfg.pca_dim))
            d = self.cfg.pca_dim
        if self.cfg.opq_m:
            transforms.append(faiss.OPQMatrix(d, self.cfg.opq_m))
        pre: Optional[Any] = None
        if transforms:
            pre = faiss.ChainTransform()
            for t in transforms:
                pre.append(t)

        # Базовый индекс
        if self.cfg.index_type == "flat":
            base = self._make_flat_index(d, metric)
        elif self.cfg.index_type == "ivf_flat":
            base = self._make_ivf_flat_index(d, metric)
        elif self.cfg.index_type == "ivf_pq":
            base = self._make_ivf_pq_index(d, metric)
        else:
            raise ValueError(f"unsupported index_type={self.cfg.index_type}")

        if pre is not None:
            base = faiss.IndexPreTransform(pre, base)
        return base

    def _make_flat_index(self, d: int, metric: int) -> faiss.Index:
        if metric == faiss.METRIC_L2:
            return faiss.IndexFlatL2(d)
        return faiss.IndexFlatIP(d)

    def _make_ivf_flat_index(self, d: int, metric: int) -> faiss.Index:
        quant = self._make_flat_index(d, metric)
        idx = faiss.IndexIVFFlat(quant, d, self.cfg.nlist, metric)
        return idx

    def _make_ivf_pq_index(self, d: int, metric: int) -> faiss.Index:
        quant = self._make_flat_index(d, metric)
        idx = faiss.IndexIVFPQ(quant, d, self.cfg.nlist, self.cfg.pq_m, self.cfg.pq_bits, metric)
        return idx

    def _maybe_to_gpu(self, idx: faiss.Index) -> faiss.Index:
        want_gpu = self.cfg.device == "gpu" or (self.cfg.device == "auto" and faiss.get_num_gpus() > 0)
        if not want_gpu:
            self._is_gpu = False
            self._gpu_res = None
            return idx
        try:
            res = faiss.StandardGpuResources()  # noqa
            gpu_id = min(self.cfg.gpu_device_id, faiss.get_num_gpus() - 1)
            idx_gpu = faiss.index_cpu_to_gpu(res, gpu_id, idx)
            self._gpu_res = res
            self._is_gpu = True
            return idx_gpu
        except Exception as e:
            log.warning("faiss: GPU unavailable or conversion failed (%s); using CPU", e)
            self._is_gpu = False
            self._gpu_res = None
            return idx

    # ---------- Helpers ----------
    def _prepare_vectors(self, v: np.ndarray) -> np.ndarray:
        if not isinstance(v, np.ndarray):
            v = np.asarray(v, dtype=np.float32)
        v = _ensure_float32(v)
        if v.ndim != 2 or v.shape[1] != self.cfg.dim:
            raise ValueError(f"vectors must have shape [N, {self.cfg.dim}]")
        if self.cfg.normalize:
            v = _normalize_rows(v)
        return v

    @staticmethod
    def _prepare_ids(ids: np.ndarray) -> np.ndarray:
        if not isinstance(ids, np.ndarray):
            ids = np.asarray(ids)
        if ids.ndim != 1:
            raise ValueError("ids must be 1-D array")
        # faiss expects int64 (np.int64)
        if ids.dtype != np.int64:
            ids = ids.astype(np.int64, copy=False)
        return ids

    def _ensure_built(self) -> None:
        if self._index is None:
            raise RuntimeError("index is not built; call build() first")

    def _ensure_ready_for_add(self, vectors: np.ndarray, ids: np.ndarray) -> None:
        self._ensure_built()
        if vectors.shape[0] != ids.shape[0]:
            raise ValueError("vectors and ids must have the same length")

    def _apply_search_params(self) -> None:
        # Установка nprobe для IVF
        base = self._unwrap_base_index(self._index)
        if isinstance(base, (faiss.IndexIVFFlat, faiss.IndexIVFPQ)):
            base.nprobe = int(self.cfg.nprobe)

    @staticmethod
    def _unwrap_base_index(idx: faiss.Index) -> faiss.Index:
        # IDMap2(IndexPreTransform(IndexIVF...))) -> добираемся до базового
        base = idx
        if isinstance(base, faiss.IndexIDMap2):
            base = base.index
        if isinstance(base, faiss.IndexPreTransform):
            base = base.index
        return base

    def _update_size_gauge(self) -> None:
        if _HAS_PROM and _IDX_SIZE and self._index is not None:
            try:
                _IDX_SIZE.set(self._index.ntotal)
            except Exception:
                pass

    def _meta_dict(self) -> Dict[str, Any]:
        return {
            "dim": self.cfg.dim,
            "metric": self.cfg.metric,
            "index_type": self.cfg.index_type,
            "nlist": self.cfg.nlist,
            "nprobe": self.cfg.nprobe,
            "pq_m": self.cfg.pq_m,
            "pq_bits": self.cfg.pq_bits,
            "opq_m": self.cfg.opq_m,
            "normalize": self.cfg.normalize,
            "pca_dim": self.cfg.pca_dim,
            "device": self.cfg.device,
            "gpu_device_id": self.cfg.gpu_device_id,
            "meta_ext": self.cfg.meta_ext,
            "ntotal": int(self._index.ntotal) if self._index is not None else 0,
        }

    @staticmethod
    def _meta_path_for(path: str) -> str:
        base, _ = os.path.splitext(path)
        # сохраняем ровно path + ".meta.json", как в save()
        return path + ".meta.json"

    @staticmethod
    def _config_from_meta(meta: Dict[str, Any]) -> FaissIndexConfig:
        if _HAS_PYDANTIC:
            # восстановить строго по схеме (с дефолтами)
            return FaissIndexConfig(**meta)
        # Dataclass fallback
        return FaissIndexConfig(
            dim=int(meta["dim"]),
            metric=meta.get("metric", "l2"),
            index_type=meta.get("index_type", "ivf_flat"),
            nlist=int(meta.get("nlist", 1024)),
            nprobe=int(meta.get("nprobe", 16)),
            pq_m=int(meta.get("pq_m", 16)),
            pq_bits=int(meta.get("pq_bits", 8)),
            opq_m=meta.get("opq_m"),
            normalize=bool(meta.get("normalize", False)),
            pca_dim=meta.get("pca_dim"),
            device=meta.get("device", "auto"),
            gpu_device_id=int(meta.get("gpu_device_id", 0)),
            meta_ext=meta.get("meta_ext", ".meta.json"),
        )


# ---------- Convenience factory ----------
def create_and_maybe_train(cfg: FaissIndexConfig, train_vectors: Optional[np.ndarray] = None) -> FaissIndex:
    """
    Удобная фабрика: build() и train(train_vectors) при необходимости.
    """
    idx = FaissIndex(cfg)
    idx.build()
    base = idx._unwrap_base_index(idx._index) if idx._index is not None else None
    needs_train = isinstance(base, (faiss.IndexIVFFlat, faiss.IndexIVFPQ)) and not idx._index.is_trained
    if needs_train:
        if train_vectors is None:
            raise RuntimeError("IVF index requires train_vectors")
        idx.train(train_vectors)
    return idx


# ---------- Minimal usage example (commented) ----------
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     dim = 128
#     cfg = FaissIndexConfig(dim=dim, metric="cosine", index_type="ivf_pq", nlist=256, nprobe=8, pq_m=16, pq_bits=8)
#     np.random.seed(0)
#     xb = np.random.randn(10_000, dim).astype(np.float32)
#     xq = np.random.randn(5, dim).astype(np.float32)
#     ids = np.arange(xb.shape[0], dtype=np.int64)
#     idx = create_and_maybe_train(cfg, xb)
#     idx.add(xb, ids)
#     D, I = idx.search(xq, k=10)
#     print(D.shape, I.shape)
