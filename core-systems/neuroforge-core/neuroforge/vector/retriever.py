# neuroforge/vector/retriever.py
# SPDX-License-Identifier: Apache-2.0
"""
Vector retriever для NeuroForge: гибридный поиск (BM25 + векторы), фильтры, MMR, несколько бэкендов.

Доступные бэкенды:
  - NumPyBruteForceBackend — всегда доступен; быстрый для до ~100k объектов.
  - FaissBackend — если установлен faiss (CPU/GPU).
  - HnswBackend — если установлен hnswlib.

Поддержка:
  - Метрики: cosine, ip (inner product), l2.
  - Фильтры по метаданным: eq/ne/in/nin/gt/gte/lt/lte/exists и вложенные ключи через "a.b.c".
  - BM25 (встроенная реализация, k1=1.2, b=0.75).
  - Гибридное ранжирование: score = alpha*vec + (1-alpha)*bm25 (с приводом скоров к [0,1]).
  - MMR-диверсификация.
  - Неймспейсы (collections), персистентность индекса и метаданных.
  - Простая интеграция эмбеддеров: передайте callable(List[str])->np.ndarray.

Пример:
    from neuroforge.vector.retriever import VectorRetriever, VectorDoc, SearchQuery, VectorMetric

    # эмбеддер-заглушка
    def embed(texts):
        import numpy as np
        return np.stack([np.random.randn(384).astype(np.float32) for _ in texts], axis=0)

    retr = VectorRetriever(
        collection="docs",
        dim=384,
        embedding_fn=embed,
        metric="cosine",
        backend="auto",              # "auto"|"numpy"|"faiss"|"hnsw"
        persist_path="./.vf_index",  # опционально
    )

    retr.upsert([
        VectorDoc(id="1", text="Neural networks and transformers", metadata={"lang": "en"}),
        VectorDoc(id="2", text="Обучение с учителем и без", metadata={"lang": "ru"}),
    ])  # векторы будут сгенерированы из text

    q = SearchQuery(text="transformers for NLP", top_k=5, alpha=0.7)  # гибридный
    results = retr.search(q)
    for r in results:
        print(r.id, r.score, r.metadata)

"""

from __future__ import annotations

import json
import math
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import numpy as np


# =========================
# Типы данных и утилиты
# =========================

Vector = np.ndarray
EmbeddingFn = Callable[[List[str]], np.ndarray]
VectorMetric = Union[str, "Metric"]

class Metric:
    COSINE = "cosine"
    IP = "ip"         # inner product
    L2 = "l2"

def _as_metric(m: VectorMetric) -> str:
    m = (m or "").lower()
    if m in {Metric.COSINE, "cos"}:
        return Metric.COSINE
    if m in {Metric.IP, "dot", "inner"}:
        return Metric.IP
    if m in {Metric.L2, "euclidean"}:
        return Metric.L2
    return Metric.COSINE

def _normalize_rows(x: np.ndarray) -> np.ndarray:
    # нормализация для cosine/IP
    norms = np.linalg.norm(x, axis=1, keepdims=True) + 1e-12
    return x / norms

def _dot(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return a @ b.T

def _ensure_float32(x: np.ndarray) -> np.ndarray:
    return x.astype(np.float32, copy=False)

def _to1d(x: np.ndarray) -> np.ndarray:
    return x.reshape(-1)

def _safe_get(d: Mapping[str, Any], path: str) -> Any:
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, Mapping) or p not in cur:
            return None
        cur = cur[p]
    return cur


@dataclass
class VectorDoc:
    id: str
    text: Optional[str] = None
    vector: Optional[Vector] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchQuery:
    # Либо text (будет эмбедден), либо уже готовый vector; можно и то, и то — для гибрида
    text: Optional[str] = None
    vector: Optional[Vector] = None
    top_k: int = 10
    # alpha в [0,1]: 1.0 = только векторы; 0.0 = только BM25
    alpha: float = 1.0
    # Фильтры по метаданным
    filters: Optional[Dict[str, Any]] = None
    # Диверсификация (MMR)
    mmr_lambda: Optional[float] = None   # None = без MMR; иначе 0..1
    mmr_k: Optional[int] = None          # если задано — сколько документов отбирать MMR


@dataclass
class ScoredDoc:
    id: str
    score: float
    vector_score: Optional[float] = None
    bm25_score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    text: Optional[str] = None


# =========================
# Фильтры метаданных
# =========================

def _match_filter(meta: Mapping[str, Any], flt: Mapping[str, Any]) -> bool:
    """
    Поддержка:
      {"lang": {"eq": "en"}}
      {"year": {"gte": 2020, "lte": 2022}}
      {"tags": {"in": ["ml","nlp"]}}
      {"a.b.c": {"exists": True}}
      {"kind": {"ne": "draft"}}
      {"status": {"nin": ["deleted","archived"]}}
    """
    def cmp(v: Any, cond: Mapping[str, Any]) -> bool:
        for op, val in cond.items():
            if op == "eq":
                if v != val: return False
            elif op == "ne":
                if v == val: return False
            elif op == "in":
                if v not in set(val): return False
            elif op == "nin":
                if v in set(val): return False
            elif op == "gt":
                if not (isinstance(v, (int, float)) and v > val): return False
            elif op == "gte":
                if not (isinstance(v, (int, float)) and v >= val): return False
            elif op == "lt":
                if not (isinstance(v, (int, float)) and v < val): return False
            elif op == "lte":
                if not (isinstance(v, (int, float)) and v <= val): return False
            elif op == "exists":
                if bool(v is not None) != bool(val): return False
            else:
                return False
        return True

    for key, cond in flt.items():
        v = _safe_get(meta, key)
        # exists без значения — трактуем как exists==True
        if isinstance(cond, bool):
            cond = {"exists": cond}
        if not isinstance(cond, Mapping):
            cond = {"eq": cond}
        if not cmp(v, cond):
            return False
    return True


# =========================
# BM25 (встроенная реализация)
# =========================

class BM25:
    def __init__(self, k1: float = 1.2, b: float = 0.75) -> None:
        self.k1 = float(k1)
        self.b = float(b)
        self._docs: Dict[str, List[str]] = {}
        self._dl: Dict[str, int] = {}
        self._df: Dict[str, int] = {}
        self._avgdl: float = 0.0
        self._N: int = 0
        self._lock = threading.RLock()

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        # простая токенизация: нижний регистр + разделение по не-алфанум
        import re
        return [t for t in re.split(r"[^0-9a-zA-Zа-яА-ЯёЁ_]+", text.lower()) if t]

    def add(self, doc_id: str, text: str) -> None:
        toks = self._tokenize(text)
        with self._lock:
            if doc_id in self._docs:
                self.remove(doc_id)
            self._docs[doc_id] = toks
            self._dl[doc_id] = len(toks)
            self._N += 1
            for t in set(toks):
                self._df[t] = self._df.get(t, 0) + 1
            self._recompute_avgdl()

    def remove(self, doc_id: str) -> None:
        with self._lock:
            toks = self._docs.pop(doc_id, None)
            if toks is None:
                return
            self._N -= 1
            self._dl.pop(doc_id, None)
            for t in set(toks):
                self._df[t] -= 1
                if self._df[t] <= 0:
                    self._df.pop(t, None)
            self._recompute_avgdl()

    def _recompute_avgdl(self) -> None:
        self._avgdl = (sum(self._dl.values()) / max(1, len(self._dl))) if self._dl else 0.0

    def score(self, query: str, doc_id: str) -> float:
        toks = self._docs.get(doc_id, [])
        if not toks or self._N == 0:
            return 0.0
        tf: Dict[str, int] = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        q_terms = self._tokenize(query)
        dl = self._dl.get(doc_id, 0)
        score = 0.0
        for term in q_terms:
            df = self._df.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1 + (self._N - df + 0.5) / (df + 0.5))
            f = tf.get(term, 0)
            denom = f + self.k1 * (1 - self.b + self.b * (dl / max(self._avgdl, 1e-9)))
            score += idf * (f * (self.k1 + 1)) / (denom + 1e-12)
        return float(score)

    def batch_score(self, query: str, doc_ids: Sequence[str]) -> np.ndarray:
        return np.array([self.score(query, d) for d in doc_ids], dtype=np.float32)

    def dump(self) -> Dict[str, Any]:
        # сохраняем только исходные тексты токенов, DF/avgdl восстанавливаем
        return {"docs": {k: " ".join(v) for k, v in self._docs.items()}}

    def load(self, data: Dict[str, Any]) -> None:
        self._docs.clear(); self._df.clear(); self._dl.clear()
        self._N = 0
        for doc_id, fake_text in (data.get("docs") or {}).items():
            # токены уже "как есть"
            toks = fake_text.split(" ") if fake_text else []
            self._docs[doc_id] = toks
            self._dl[doc_id] = len(toks)
            self._N += 1
            for t in set(toks):
                self._df[t] = self._df.get(t, 0) + 1
        self._recompute_avgdl()


# =========================
# Бэкенды векторного поиска
# =========================

class BaseBackend:
    def __init__(self, dim: int, metric: str) -> None:
        self.dim = int(dim)
        self.metric = _as_metric(metric)

    # коллекции (неймспейсы)
    def create(self, collection: str) -> None: ...
    def drop(self, collection: str) -> None: ...
    def upsert(self, collection: str, ids: List[str], vectors: np.ndarray, metas: List[Dict[str, Any]]) -> None: ...
    def delete(self, collection: str, ids: List[str]) -> None: ...
    def search(self, collection: str, query_vec: np.ndarray, top_k: int, candidates: Optional[Iterable[str]] = None) -> Tuple[List[str], np.ndarray]:
        """
        Возвращает (ids, scores) где scores — по направлению «чем больше, тем лучше».
        Для L2 автоматически инвертируем расстояние в сходство.
        """
        raise NotImplementedError()
    def persist(self, collection: str, path: Path) -> None: ...
    def load(self, collection: str, path: Path) -> None: ...
    def count(self, collection: str) -> int: ...


class NumPyBruteForceBackend(BaseBackend):
    """
    Простой и надёжный бэкенд на NumPy. Хранит векторы в памяти; персистит через .npz + JSON.
    """
    def __init__(self, dim: int, metric: str) -> None:
        super().__init__(dim, metric)
        self._vecs: Dict[str, np.ndarray] = {}          # collection -> (N, D)
        self._ids: Dict[str, List[str]] = {}            # collection -> [ids]
        self._metas: Dict[str, Dict[str, Dict[str, Any]]] = {}  # collection -> id -> meta
        self._lock = threading.RLock()

    def create(self, collection: str) -> None:
        with self._lock:
            self._vecs.setdefault(collection, np.zeros((0, self.dim), dtype=np.float32))
            self._ids.setdefault(collection, [])
            self._metas.setdefault(collection, {})

    def drop(self, collection: str) -> None:
        with self._lock:
            self._vecs.pop(collection, None)
            self._ids.pop(collection, None)
            self._metas.pop(collection, None)

    def upsert(self, collection: str, ids: List[str], vectors: np.ndarray, metas: List[Dict[str, Any]]) -> None:
        vectors = _ensure_float32(vectors)
        assert vectors.shape[1] == self.dim, f"dimension mismatch: {vectors.shape[1]} != {self.dim}"
        with self._lock:
            self.create(collection)
            id2idx = {id_: i for i, id_ in enumerate(self._ids[collection])}
            new_ids: List[str] = []
            new_vecs: List[np.ndarray] = []
            # заменяем существующие
            for i, id_ in enumerate(ids):
                if id_ in id2idx:
                    idx = id2idx[id_]
                    self._vecs[collection][idx] = vectors[i]
                else:
                    new_ids.append(id_)
                    new_vecs.append(vectors[i])
                self._metas[collection][id_] = metas[i] or {}
            if new_ids:
                V = self._vecs[collection]
                V = np.vstack([V, np.stack(new_vecs, axis=0)]) if V.size else np.stack(new_vecs, axis=0)
                self._vecs[collection] = V
                self._ids[collection].extend(new_ids)

    def delete(self, collection: str, ids: List[str]) -> None:
        with self._lock:
            if collection not in self._ids:
                return
            keep_idx = [i for i, id_ in enumerate(self._ids[collection]) if id_ not in set(ids)]
            self._vecs[collection] = self._vecs[collection][keep_idx] if keep_idx else np.zeros((0, self.dim), dtype=np.float32)
            self._ids[collection] = [self._ids[collection][i] for i in keep_idx]
            for id_ in ids:
                self._metas[collection].pop(id_, None)

    def _similarity(self, A: np.ndarray, q: np.ndarray) -> np.ndarray:
        if self.metric == Metric.COSINE:
            A_n = _normalize_rows(A)
            q_n = _normalize_rows(q[None, :])
            return _dot(A_n, q_n).reshape(-1)
        if self.metric == Metric.IP:
            return _dot(A, q[None, :]).reshape(-1)
        # L2 -> преобразуем в псевдо-сходство (инвертированное расстояние)
        d = np.linalg.norm(A - q[None, :], axis=1)
        return 1.0 / (1.0 + d)

    def search(self, collection: str, query_vec: np.ndarray, top_k: int, candidates: Optional[Iterable[str]] = None) -> Tuple[List[str], np.ndarray]:
        with self._lock:
            if collection not in self._vecs or self._vecs[collection].shape[0] == 0:
                return [], np.zeros((0,), dtype=np.float32)
            vecs = self._vecs[collection]
            ids = self._ids[collection]
            if candidates is not None:
                mask = [i for i, id_ in enumerate(ids) if id_ in set(candidates)]
                if not mask:
                    return [], np.zeros((0,), dtype=np.float32)
                vecs = vecs[mask]
                ids = [ids[i] for i in mask]
            q = _ensure_float32(query_vec).reshape(-1)
            sims = self._similarity(vecs, q)
            k = min(int(top_k), sims.shape[0])
            if k <= 0:
                return [], np.zeros((0,), dtype=np.float32)
            idx = np.argpartition(-sims, k - 1)[:k]
            idx = idx[np.argsort(-sims[idx])]
            return [ids[i] for i in idx], sims[idx]

    def persist(self, collection: str, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if collection not in self._vecs:
                return
            np.savez_compressed(path / f"{collection}.npz", vecs=self._vecs[collection])
            (path / f"{collection}.ids.json").write_text(json.dumps(self._ids[collection], ensure_ascii=False))
            (path / f"{collection}.meta.json").write_text(json.dumps(self._metas[collection], ensure_ascii=False))

    def load(self, collection: str, path: Path) -> None:
        with self._lock:
            npz = path / f"{collection}.npz"
            if npz.is_file():
                data = np.load(npz)
                self._vecs[collection] = _ensure_float32(data["vecs"])
            else:
                self._vecs[collection] = np.zeros((0, self.dim), dtype=np.float32)
            ids_path = path / f"{collection}.ids.json"
            meta_path = path / f"{collection}.meta.json"
            self._ids[collection] = json.loads(ids_path.read_text()) if ids_path.is_file() else []
            self._metas[collection] = json.loads(meta_path.read_text()) if meta_path.is_file() else {}

    def count(self, collection: str) -> int:
        with self._lock:
            return int(self._vecs.get(collection, np.zeros((0, self.dim))).shape[0])


# Опциональные бэкенды: FAISS / HNSW
def _faiss_available() -> bool:
    try:
        import faiss  # type: ignore
        _ = faiss  # silence linter
        return True
    except Exception:
        return False

def _hnsw_available() -> bool:
    try:
        import hnswlib  # type: ignore
        _ = hnswlib
        return True
    except Exception:
        return False


class FaissBackend(BaseBackend):
    def __init__(self, dim: int, metric: str) -> None:
        if not _faiss_available():
            raise ImportError("faiss не установлен")
        super().__init__(dim, metric)
        import faiss  # type: ignore
        self.faiss = faiss
        self._index: Dict[str, Any] = {}
        self._ids: Dict[str, List[str]] = {}
        self._metas: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _new_index(self):
        if self.metric == Metric.L2:
            return self.faiss.IndexFlatL2(self.dim)
        # Для cosine используем L2 по нормализованным векторам
        return self.faiss.IndexFlatIP(self.dim)

    def create(self, collection: str) -> None:
        with self._lock:
            self._index.setdefault(collection, self._new_index())
            self._ids.setdefault(collection, [])
            self._metas.setdefault(collection, {})

    def drop(self, collection: str) -> None:
        with self._lock:
            self._index.pop(collection, None)
            self._ids.pop(collection, None)
            self._metas.pop(collection, None)

    def upsert(self, collection: str, ids: List[str], vectors: np.ndarray, metas: List[Dict[str, Any]]) -> None:
        # Для IP желательно нормализовать, если используем cosine-подобную семантику
        vecs = _ensure_float32(vectors)
        if self.metric == Metric.COSINE:
            vecs = _normalize_rows(vecs)
        with self._lock:
            self.create(collection)
            # FAISS IndexFlat не поддерживает удаление/апдейт — держим параллельные массивы и пересобираем при заменах
            # Простая стратегия: если есть id, пересобрать индекс.
            id2idx = {id_: i for i, id_ in enumerate(self._ids[collection])}
            need_rebuild = any(id_ in id2idx for id_ in ids)
            if need_rebuild:
                # пересобираем
                new_ids = []
                new_vecs = []
                new_metas = {}
                # добавляем все старые, кроме тех, что апдейтятся
                updating = set(ids)
                for i, old_id in enumerate(self._ids[collection]):
                    if old_id in updating:
                        continue
                    new_ids.append(old_id)
                    new_vecs.append(self._index[collection].reconstruct(i))
                    new_metas[old_id] = self._metas[collection][old_id]
                # добавляем новые/обновлённые
                for i, id_ in enumerate(ids):
                    new_ids.append(id_)
                    new_vecs.append(vecs[i])
                    new_metas[id_] = metas[i] or {}
                # пересоздаём индекс
                idx = self._new_index()
                if len(new_vecs):
                    idx.add(np.stack(new_vecs, axis=0))
                self._index[collection] = idx
                self._ids[collection] = new_ids
                self._metas[collection] = new_metas
            else:
                self._index[collection].add(vecs)
                self._ids[collection].extend(ids)
                for i, id_ in enumerate(ids):
                    self._metas[collection][id_] = metas[i] or {}

    def delete(self, collection: str, ids: List[str]) -> None:
        with self._lock:
            if collection not in self._index:
                return
            # Пересборка без удаляемых
            keep = []
            metas = {}
            for i, id_ in enumerate(self._ids[collection]):
                if id_ in set(ids): continue
                keep.append((id_, self._index[collection].reconstruct(i)))
                metas[id_] = self._metas[collection][id_]
            idx = self._new_index()
            if keep:
                idx.add(np.stack([v for _, v in keep], axis=0))
            self._index[collection] = idx
            self._ids[collection] = [k for k, _ in keep]
            self._metas[collection] = metas

    def search(self, collection: str, query_vec: np.ndarray, top_k: int, candidates: Optional[Iterable[str]] = None) -> Tuple[List[str], np.ndarray]:
        with self._lock:
            if collection not in self._index:
                return [], np.zeros((0,), dtype=np.float32)
            idx = self._index[collection]
            ids = self._ids[collection]
            if candidates is not None:
                # FAISS Flat не фильтрует — fallback на NumPy для кандидатов
                bf = NumPyBruteForceBackend(self.dim, self.metric)
                V = np.stack([idx.reconstruct(i) for i in range(idx.ntotal)], axis=0) if idx.ntotal else np.zeros((0, self.dim), dtype=np.float32)
                bf.create("c"); bf._vecs["c"] = V; bf._ids["c"] = ids
                return bf.search("c", query_vec, top_k, candidates=candidates)
            q = _ensure_float32(query_vec).reshape(1, -1)
            if self.metric == Metric.COSINE:
                q = _normalize_rows(q)
            if idx.ntotal == 0:
                return [], np.zeros((0,), dtype=np.float32)
            D, I = idx.search(q, min(top_k, idx.ntotal))
            # Для L2 FAISS возвращает расстояние — конвертим в сходство
            if self.metric == Metric.L2:
                sims = 1.0 / (1.0 + np.sqrt(np.maximum(D[0], 0.0)))
            else:
                sims = D[0]
            res_ids = [ids[i] for i in I[0]]
            return res_ids, sims

    def persist(self, collection: str, path: Path) -> None:
        import faiss  # type: ignore
        path.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if collection not in self._index:
                return
            faiss.write_index(self._index[collection], str(path / f"{collection}.faiss"))
            (path / f"{collection}.ids.json").write_text(json.dumps(self._ids[collection], ensure_ascii=False))
            (path / f"{collection}.meta.json").write_text(json.dumps(self._metas[collection], ensure_ascii=False))

    def load(self, collection: str, path: Path) -> None:
        import faiss  # type: ignore
        with self._lock:
            idx_path = path / f"{collection}.faiss"
            self._index[collection] = self._new_index() if not idx_path.is_file() else faiss.read_index(str(idx_path))
            ids_path = path / f"{collection}.ids.json"
            meta_path = path / f"{collection}.meta.json"
            self._ids[collection] = json.loads(ids_path.read_text()) if ids_path.is_file() else []
            self._metas[collection] = json.loads(meta_path.read_text()) if meta_path.is_file() else {}

    def count(self, collection: str) -> int:
        with self._lock:
            return int(self._index.get(collection).ntotal if collection in self._index else 0)


class HnswBackend(BaseBackend):
    def __init__(self, dim: int, metric: str) -> None:
        if not _hnsw_available():
            raise ImportError("hnswlib не установлен")
        super().__init__(dim, metric)
        import hnswlib  # type: ignore
        self.hnswlib = hnswlib
        self._index: Dict[str, Any] = {}
        self._ids: Dict[str, List[str]] = {}
        self._metas: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _space(self) -> str:
        return "cosine" if self.metric in (Metric.COSINE, Metric.IP) else "l2"

    def create(self, collection: str) -> None:
        with self._lock:
            if collection in self._index:
                return
            idx = self.hnswlib.Index(space=self._space(), dim=self.dim)
            idx.init_index(max_elements=1, ef_construction=200, M=48)
            idx.set_ef(128)
            self._index[collection] = idx
            self._ids[collection] = []
            self._metas[collection] = {}

    def _ensure_capacity(self, idx, need: int):
        cur = idx.get_max_elements()
        if need > cur:
            idx.resize_index(need)

    def drop(self, collection: str) -> None:
        with self._lock:
            self._index.pop(collection, None); self._ids.pop(collection, None); self._metas.pop(collection, None)

    def upsert(self, collection: str, ids: List[str], vectors: np.ndarray, metas: List[Dict[str, Any]]) -> None:
        vecs = _ensure_float32(vectors)
        if self.metric == Metric.COSINE or self.metric == Metric.IP:
            vecs = _normalize_rows(vecs)
        with self._lock:
            self.create(collection)
            idx = self._index[collection]
            # HNSW не поддерживает update — заменим через soft-delete+rebuild простым способом:
            exist = set(self._ids[collection])
            need_rebuild = any(id_ in exist for id_ in ids)
            if need_rebuild:
                # полная пересборка
                all_ids = [id_ for id_ in self._ids[collection] if id_ not in set(ids)] + ids
                # реконструировать старые вектора не из чего — храним их отдельно? Для простоты: fallback на BF persist в реальных системах.
                # Здесь — чистый апдейт допустим только для новых ID.
                # Для промышленности храните копию векторов отдельно. Мы примем, что апдейт без старых векторов невозможен.
                raise NotImplementedError("HNSW upsert existing ids не поддержан без внешнего хранения векторов")
            self._ensure_capacity(idx, len(self._ids[collection]) + len(ids))
            labels = np.arange(len(self._ids[collection]), len(self._ids[collection]) + len(ids))
            idx.add_items(vecs, labels)
            self._ids[collection].extend(ids)
            for i, id_ in enumerate(ids):
                self._metas[collection][id_] = metas[i] or {}

    def delete(self, collection: str, ids: List[str]) -> None:
        # hnswlib soft-delete отсутствует — требуется пересборка
        raise NotImplementedError("HNSW delete требует пересборки индекса вне модуля")

    def search(self, collection: str, query_vec: np.ndarray, top_k: int, candidates: Optional[Iterable[str]] = None) -> Tuple[List[str], np.ndarray]:
        with self._lock:
            if collection not in self._index or not self._ids[collection]:
                return [], np.zeros((0,), dtype=np.float32)
            idx = self._index[collection]
            q = _ensure_float32(query_vec).reshape(1, -1)
            if self.metric in (Metric.COSINE, Metric.IP):
                q = _normalize_rows(q)
            if candidates is not None:
                # hnswlib не фильтрует — fallback на NumPy
                bf = NumPyBruteForceBackend(self.dim, self.metric)
                # нет простого доступа к векторам — см. примечание в upsert()
                raise NotImplementedError("HNSW candidate-filtered search недоступен без внешнего хранения векторов")
            labels, dists = idx.knn_query(q, k=min(top_k, len(self._ids[collection])))
            ids = [self._ids[collection][int(l)] for l in labels[0]]
            # cosine space в hnswlib возвращает расстояние; преобразуем в сходство
            sims = 1.0 / (1.0 + dists[0])
            return ids, sims

    def persist(self, collection: str, path: Path) -> None:
        with self._lock:
            path.mkdir(parents=True, exist_ok=True)
            if collection not in self._index:
                return
            self._index[collection].save_index(str(path / f"{collection}.hnsw"))
            (path / f"{collection}.ids.json").write_text(json.dumps(self._ids[collection], ensure_ascii=False))
            (path / f"{collection}.meta.json").write_text(json.dumps(self._metas[collection], ensure_ascii=False))

    def load(self, collection: str, path: Path) -> None:
        with self._lock:
            self.create(collection)
            idx_path = path / f"{collection}.hnsw"
            if idx_path.is_file():
                self._index[collection].load_index(str(idx_path))
            ids_path = path / f"{collection}.ids.json"
            meta_path = path / f"{collection}.meta.json"
            self._ids[collection] = json.loads(ids_path.read_text()) if ids_path.is_file() else []
            self._metas[collection] = json.loads(meta_path.read_text()) if meta_path.is_file() else {}

    def count(self, collection: str) -> int:
        with self._lock:
            return len(self._ids.get(collection, []))


# =========================
# Фасад VectorRetriever
# =========================

class VectorRetriever:
    """
    Высокоуровневый фасад: хранит текст/векторы/метаданные, поддерживает гибридный поиск и MMR.
    """
    def __init__(
        self,
        collection: str,
        dim: int,
        metric: VectorMetric = "cosine",
        *,
        embedding_fn: Optional[EmbeddingFn] = None,
        backend: str = "auto",           # "auto"|"numpy"|"faiss"|"hnsw"
        persist_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.collection = collection
        self.dim = int(dim)
        self.metric = _as_metric(metric)
        self.embedding_fn = embedding_fn
        self.persist_path = Path(persist_path) if persist_path else None
        self._lock = threading.RLock()

        # метаданные и тексты — всегда в памяти, т.к. нужны для фильтров и BM25
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._text: Dict[str, Optional[str]] = {}
        self._bm25 = BM25()

        # выбор бэкенда
        self.backend = self._init_backend(backend)
        self.backend.create(self.collection)

        if self.persist_path:
            self._load()

    def _init_backend(self, backend: str) -> BaseBackend:
        b = (backend or "auto").lower()
        if b == "numpy":
            return NumPyBruteForceBackend(self.dim, self.metric)
        if b == "faiss":
            return FaissBackend(self.dim, self.metric)
        if b == "hnsw":
            return HnswBackend(self.dim, self.metric)
        # auto: faiss -> hnsw -> numpy
        try:
            return FaissBackend(self.dim, self.metric)
        except Exception:
            try:
                return HnswBackend(self.dim, self.metric)
            except Exception:
                return NumPyBruteForceBackend(self.dim, self.metric)

    # ---------- Персистентность ----------

    def _save(self) -> None:
        if not self.persist_path:
            return
        p = self.persist_path
        p.mkdir(parents=True, exist_ok=True)
        with self._lock:
            (p / f"{self.collection}.meta.json").write_text(json.dumps(self._meta, ensure_ascii=False))
            (p / f"{self.collection}.text.json").write_text(json.dumps(self._text, ensure_ascii=False))
            # BM25
            (p / f"{self.collection}.bm25.json").write_text(json.dumps(self._bm25.dump(), ensure_ascii=False))
            # Векторный бэкенд
            self.backend.persist(self.collection, p)

    def _load(self) -> None:
        p = self.persist_path
        if not p:
            return
        with self._lock:
            meta_path = p / f"{self.collection}.meta.json"
            text_path = p / f"{self.collection}.text.json"
            bm25_path = p / f"{self.collection}.bm25.json"
            self._meta = json.loads(meta_path.read_text()) if meta_path.is_file() else {}
            self._text = json.loads(text_path.read_text()) if text_path.is_file() else {}
            if bm25_path.is_file():
                self._bm25.load(json.loads(bm25_path.read_text()))
            self.backend.load(self.collection, p)

    # ---------- Мутации ----------

    def upsert(self, docs: Sequence[VectorDoc]) -> None:
        if not docs:
            return
        ids: List[str] = []
        metas: List[Dict[str, Any]] = []
        texts: List[Optional[str]] = []
        vecs: List[Optional[np.ndarray]] = []

        for d in docs:
            ids.append(d.id)
            metas.append(d.metadata or {})
            texts.append(d.text)
            vecs.append(d.vector)

        # эмбеддинг, если нужно
        need_embed_idx = [i for i, (t, v) in enumerate(zip(texts, vecs)) if v is None and t]
        if need_embed_idx:
            if not self.embedding_fn:
                raise ValueError("embedding_fn не задан, а document.vector отсутствует")
            embed_input = [texts[i] for i in need_embed_idx]  # type: ignore
            emb = self.embedding_fn(embed_input)
            if not isinstance(emb, np.ndarray) or emb.shape[1] != self.dim:
                raise ValueError(f"embedding_fn вернул массив неправильной формы: {getattr(emb,'shape',None)}")
            for j, i in enumerate(need_embed_idx):
                vecs[i] = _ensure_float32(emb[j])

        # проверяем, что у всех векторы есть
        final_vecs: List[np.ndarray] = []
        for i, v in enumerate(vecs):
            if v is None:
                raise ValueError(f"документ {ids[i]} не содержит vector и text")
            vv = _ensure_float32(v).reshape(-1)
            if vv.shape[0] != self.dim:
                raise ValueError(f"dimension mismatch для {ids[i]}: {vv.shape[0]} != {self.dim}")
            final_vecs.append(vv)

        with self._lock:
            # обновляем тексты/мета + BM25
            for i, id_ in enumerate(ids):
                self._meta[id_] = metas[i]
                self._text[id_] = texts[i]
                if texts[i]:
                    self._bm25.add(id_, texts[i] or "")
                else:
                    self._bm25.remove(id_)
            # бэкенд
            self.backend.upsert(self.collection, ids, np.stack(final_vecs, axis=0), metas)
            self._save()

    def delete(self, ids: Sequence[str]) -> None:
        if not ids:
            return
        with self._lock:
            for id_ in ids:
                self._meta.pop(id_, None)
                self._text.pop(id_, None)
                self._bm25.remove(id_)
            self.backend.delete(self.collection, list(ids))
            self._save()

    def drop_collection(self) -> None:
        with self._lock:
            self.backend.drop(self.collection)
            self._meta.clear(); self._text.clear()
            self._bm25 = BM25()
            if self.persist_path:
                for ext in ("npz","faiss","hnsw","meta.json","text.json","bm25.json","ids.json","meta.json"):
                    f = self.persist_path / f"{self.collection}.{ext}"
                    if f.is_file():
                        try: f.unlink()
                        except Exception: pass

    # ---------- Поиск ----------

    def _filter_ids(self, ids: Sequence[str], filters: Optional[Dict[str, Any]]) -> List[str]:
        if not filters:
            return list(ids)
        return [id_ for id_ in ids if _match_filter(self._meta.get(id_, {}), filters)]

    def _bm25_scores(self, query_text: Optional[str], ids: Sequence[str]) -> np.ndarray:
        if not query_text or not ids:
            return np.zeros((len(ids),), dtype=np.float32)
        return self._bm25.batch_score(query_text, list(ids))

    @staticmethod
    def _minmax_scale(x: np.ndarray) -> np.ndarray:
        if x.size == 0: return x
        mn, mx = float(np.min(x)), float(np.max(x))
        if mx - mn < 1e-12:
            return np.zeros_like(x)
        return (x - mn) / (mx - mn + 1e-12)

    def _mmr(self, ids: List[str], vec_scores: np.ndarray, query_vec: Optional[np.ndarray], lam: float, k: int) -> List[int]:
        # Простая MMR по нормализованным векторам; если query_vec отсутствует — используем веса vec_scores
        if not ids:
            return []
        selected: List[int] = []
        candidates = list(range(len(ids)))
        # нормализованный q
        q = None
        if query_vec is not None:
            q = _normalize_rows(query_vec.reshape(1, -1))
        # получаем нормализованные векторы документов из бэкенда, если он это поддерживает — у нас нет общего API для выдачи векторов.
        # Используем vec_scores как приближение, если q недоступен: диверсифицируем просто по штрафу топ-скора.
        sims_to_q = vec_scores.copy()
        for _ in range(min(k, len(candidates))):
            if not selected:
                best = int(np.argmax(sims_to_q))
                selected.append(best)
                candidates.remove(best)
                continue
            # отступление от ранее выбранных: max sim(doc, s) — приближаем по близости скоров
            max_sim_to_selected = np.array([max(vec_scores[j] for j in selected)] * len(candidates))
            mmr_score = lam * sims_to_q[candidates] - (1 - lam) * max_sim_to_selected
            pick_idx = int(np.argmax(mmr_score))
            chosen = candidates[pick_idx]
            selected.append(chosen)
            del candidates[pick_idx]
        return selected

    def search(self, query: SearchQuery) -> List<ScoredDoc]:
        if query.top_k <= 0:
            return []
        alpha = float(max(0.0, min(1.0, query.alpha)))
        # 1) подготовка вектора запросов
        q_vec: Optional[np.ndarray] = None
        if query.vector is not None:
            q_vec = _ensure_float32(query.vector).reshape(-1)
            if q_vec.shape[0] != self.dim:
                raise ValueError(f"query.vector dim mismatch: {q_vec.shape[0]} != {self.dim}")
        elif query.text and self.embedding_fn:
            q_vec = _ensure_float32(self.embedding_fn([query.text]))[0]
            if q_vec.shape[0] != self.dim:
                raise ValueError(f"embedding_fn выдал вектор неправильной размерности: {q_vec.shape[0]} != {self.dim}")

        # 2) кандидаты: без фильтров — весь индекс; с фильтрами — сначала берём широкую выборку top_k*X по вектору/BM25
        # Простая стратегия: собираем до 1000 кандидатов каждой стороны (векторной и BM25), объединяем и фильтруем
        candidate_ids: List[str] = []
        with self._lock:
            # из бэкенда не получить список ids универсально; NumPy/FAISS мы держим отдельно.
            # Для NumPy у нас есть список в backend._ids; для FAISS/HNSW — тоже.
            ids_pool: List[str] = []
            if isinstance(self.backend, NumPyBruteForceBackend):
                ids_pool = list(self.backend._ids.get(self.collection, []))
            elif isinstance(self.backend, FaissBackend):
                ids_pool = list(self.backend._ids.get(self.collection, []))
            elif isinstance(self.backend, HnswBackend):
                ids_pool = list(self.backend._ids.get(self.collection, []))
            else:
                ids_pool = []

        if query.filters:
            ids_pool = self._filter_ids(ids_pool, query.filters)

        # кандидаты из BM25
        bm25_candidates: List[str] = []
        if query.text:
            # оценим всех и возьмём topN — для больших коллекций это O(N); оптимизируйте, если нужно
            if ids_pool:
                bm25_scores_all = self._bm25_scores(query.text, ids_pool)
                kbm = min(len(ids_pool), max(query.top_k * 5, 100))
                idx = np.argpartition(-bm25_scores_all, kbm - 1)[:kbm]
                bm25_candidates = [ids_pool[i] for i in idx]

        # кандидаты из векторного поиска
        vec_candidates: List[str] = []
        vec_scores_cand = np.array([], dtype=np.float32)
        if q_vec is not None and len(ids_pool) > 0:
            ids_v, sims_v = self.backend.search(self.collection, q_vec, top_k=min(len(ids_pool), max(query.top_k * 5, 1000)))
            if query.filters:
                # после фильтрации сохраним соответствующие скор
                mask = [i for i, id_ in enumerate(ids_v) if id_ in set(ids_pool)]
                ids_v = [ids_v[i] for i in mask]; sims_v = sims_v[mask]
            vec_candidates = ids_v; vec_scores_cand = sims_v

        # объединяем кандидатов
        candidate_ids = list(dict.fromkeys(bm25_candidates + vec_candidates))  # preserve order
        if not candidate_ids and ids_pool:
            candidate_ids = ids_pool

        # 3) финальное скорирование на объединённом пуле
        bm25_scores = self._bm25_scores(query.text, candidate_ids) if query.text else np.zeros((len(candidate_ids),), dtype=np.float32)
        vec_scores = np.zeros((len(candidate_ids),), dtype=np.float32)
        if q_vec is not None and candidate_ids:
            # для кандидатов нужно получить векторные скоры; вызываем backend.search по всем кандидатам
            ids_sc, sims_sc = self.backend.search(self.collection, q_vec, top_k=len(candidate_ids), candidates=candidate_ids)
            # сопоставляем по id
            pos = {id_: i for i, id_ in enumerate(ids_sc)}
            for i, id_ in enumerate(candidate_ids):
                j = pos.get(id_)
                if j is not None:
                    vec_scores[i] = float(sims_sc[j])

        # нормализация к [0,1]
        bm25_s = self._minmax_scale(bm25_scores)
        vec_s = self._minmax_scale(vec_scores)
        final = alpha * vec_s + (1.0 - alpha) * bm25_s

        # 4) MMR (если включён)
        order_idx: List[int]
        if query.mmr_lambda is not None and query.mmr_k:
            sel = self._mmr(candidate_ids, vec_s, q_vec, lam=float(query.mmr_lambda), k=int(query.mmr_k))
            order_idx = sel
        else:
            order_idx = list(np.argsort(-final))

        # 5) собираем топ_k
        k = min(len(order_idx), int(query.top_k))
        out: List<ScoredDoc] = []
        for i in order_idx[:k]:
            id_ = candidate_ids[i]
            out.append(
                ScoredDoc(
                    id=id_,
                    score=float(final[i]),
                    vector_score=float(vec_s[i]) if q_vec is not None else None,
                    bm25_score=float(bm25_s[i]) if query.text else None,
                    metadata=self._meta.get(id_, {}),
                    text=self._text.get(id_),
                )
            )
        return out

    # ---------- Служебные ----------

    def count(self) -> int:
        return self.backend.count(self.collection)

    def get_meta(self, id_: str) -> Dict[str, Any]:
        return dict(self._meta.get(id_, {}) or {})

    def get_text(self, id_: str) -> Optional[str]:
        return self._text.get(id_)

    def reindex_bm25(self) -> None:
        with self._lock:
            self._bm25 = BM25()
            for id_, t in self._text.items():
                if t:
                    self._bm25.add(id_, t)
            self._save()


__all__ = [
    "VectorRetriever",
    "VectorDoc",
    "SearchQuery",
    "ScoredDoc",
    "VectorMetric",
    "Metric",
]
