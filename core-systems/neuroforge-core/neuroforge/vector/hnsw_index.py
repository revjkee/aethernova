# neuroforge/vector/hnsw_index.py
from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import numpy as np

try:
    import hnswlib  # type: ignore
except Exception as exc:  # pragma: no cover
    raise RuntimeError("hnswlib is required: pip install hnswlib") from exc

log = logging.getLogger("neuroforge.vector.hnsw")

# Types
Metadata = Dict[str, Any]
MetricsHook = Callable[[str, Dict[str, str], float], None]  # (event, labels, latency_s)


# ========================= RW Lock (fair, simple) =============================

class RWLock:
    """
    Простая readers-writer блокировка: множественные читатели или один писатель.
    Без звёзд, но надёжно для Python GIL.
    """
    def __init__(self) -> None:
        self._read_ready = threading.Condition(threading.Lock())
        self._readers = 0

    @contextlib.contextmanager
    def read(self):
        with self._read_ready:
            self._readers += 1
        try:
            yield
        finally:
            with self._read_ready:
                self._readers -= 1
                if self._readers == 0:
                    self._read_ready.notify_all()

    @contextlib.contextmanager
    def write(self):
        with self._read_ready:
            while self._readers > 0:
                self._read_ready.wait()
            yield


# ================================ Config ======================================

@dataclass
class HNSWConfig:
    dim: int
    space: str = "cosine"          # 'l2' | 'ip' | 'cosine'
    max_elements: int = 100_000
    m: int = 32
    ef_construction: int = 200
    ef_search: int = 64
    allow_replace_deleted: bool = True
    num_threads: int = max(1, (os.cpu_count() or 1) // 2)
    normalize: bool = False        # нормализация L2 для косинуса/inner product по желанию
    storage_dir: Path = Path("./data/vector/hnsw")
    index_filename: str = "hnsw.index.bin"
    state_filename: str = "state.json"
    sqlite_filename: str = "meta.db"
    autosave_on_update: bool = True
    autosave_min_interval_s: float = 5.0
    metrics_hook: Optional[MetricsHook] = None

    def validate(self) -> None:
        if self.dim <= 0:
            raise ValueError("dim must be > 0")
        if self.space not in {"l2", "ip", "cosine"}:
            raise ValueError("space must be 'l2'|'ip'|'cosine'")
        if self.max_elements <= 0:
            raise ValueError("max_elements must be > 0")
        if self.m < 2:
            raise ValueError("m must be >= 2")
        if self.ef_construction < 8:
            raise ValueError("ef_construction must be >= 8")
        if self.ef_search < 8:
            raise ValueError("ef_search must be >= 8")


# ============================= Metadata Store =================================

class _MetaStore:
    """
    SQLite-хранилище для:
      - соответствия external_id <-> label (int),
      - метаданных JSON,
      - soft-delete статуса.
    """
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

    def start(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), timeout=30, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA temp_store=MEMORY;")
        self._conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            label       INTEGER PRIMARY KEY,
            external_id TEXT UNIQUE NOT NULL,
            meta_json   TEXT,
            deleted     INTEGER NOT NULL DEFAULT 0
        ) WITHOUT ROWID;
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_items_external ON items(external_id);")

    def stop(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def upsert_items(self, rows: Sequence[Tuple[int, str, Optional[Metadata]]]) -> None:
        if not rows:
            return
        with self._lock:
            cur = self._conn.cursor()  # type: ignore[union-attr]
            cur.executemany(
                "INSERT INTO items(label, external_id, meta_json, deleted) VALUES(?,?,?,0) "
                "ON CONFLICT(external_id) DO UPDATE SET label=excluded.label, meta_json=excluded.meta_json, deleted=0",
                [(lbl, eid, json.dumps(meta or {}, ensure_ascii=False)) for lbl, eid, meta in rows]
            )
            cur.close()

    def get_labels(self, external_ids: Sequence[str]) -> Dict[str, int]:
        if not external_ids:
            return {}
        with self._lock:
            placeholders = ",".join("?" for _ in external_ids)
            cur = self._conn.execute(f"SELECT external_id,label FROM items WHERE external_id IN ({placeholders})", list(external_ids))  # type: ignore[union-attr]
            return {eid: lbl for eid, lbl in cur.fetchall()}

    def get_meta_by_labels(self, labels: Sequence[int]) -> Dict[int, Metadata]:
        if not labels:
            return {}
        with self._lock:
            placeholders = ",".join("?" for _ in labels)
            cur = self._conn.execute(f"SELECT label, meta_json FROM items WHERE label IN ({placeholders})", list(labels))  # type: ignore[union-attr]
            out: Dict[int, Metadata] = {}
            for lbl, meta_json in cur.fetchall():
                try:
                    out[int(lbl)] = json.loads(meta_json) if meta_json else {}
                except Exception:
                    out[int(lbl)] = {}
            return out

    def label_for_insert(self, external_id: str) -> Optional[int]:
        with self._lock:
            cur = self._conn.execute("SELECT label FROM items WHERE external_id = ?", (external_id,))  # type: ignore[union-attr]
            row = cur.fetchone()
            return int(row[0]) if row else None

    def mark_deleted(self, labels: Sequence[int], deleted: bool = True) -> None:
        if not labels:
            return
        with self._lock:
            placeholders = ",".join("?" for _ in labels)
            self._conn.execute(f"UPDATE items SET deleted = ? WHERE label IN ({placeholders})", [1 if deleted else 0, *labels])  # type: ignore[union-attr]

    def deleted_flags(self, labels: Sequence[int]) -> Dict[int, bool]:
        if not labels:
            return {}
        with self._lock:
            placeholders = ",".join("?" for _ in labels)
            cur = self._conn.execute(f"SELECT label, deleted FROM items WHERE label IN ({placeholders})", list(labels))  # type: ignore[union-attr]
            return {int(lbl): bool(delv) for lbl, delv in cur.fetchall()}

    def stats(self) -> Dict[str, int]:
        with self._lock:
            cur = self._conn.execute("SELECT count(*), sum(deleted) FROM items")  # type: ignore[union-attr]
            total, deleted = cur.fetchone()
            return {"items": int(total or 0), "deleted": int(deleted or 0)}


# =============================== State model ==================================

@dataclass
class _State:
    dim: int
    space: str
    m: int
    ef_construction: int
    ef_search: int
    max_elements: int
    current_count: int

    @staticmethod
    def from_config(cfg: HNSWConfig) -> "_State":
        return _State(
            dim=cfg.dim,
            space=cfg.space,
            m=cfg.m,
            ef_construction=cfg.ef_construction,
            ef_search=cfg.ef_search,
            max_elements=cfg.max_elements,
            current_count=0,
        )


# ================================ HNSWIndex ===================================

class HNSWIndex:
    """
    Промышленный адаптер hnswlib с:
      - стабильной персистенцией,
      - авто-resize,
      - thread-safety,
      - хранением метаданных и внешних ID,
      - upsert/soft-delete/undelete,
      - фильтрацией по предикату метаданных,
      - warmup и метриками.
    """

    def __init__(self, cfg: HNSWConfig):
        cfg.validate()
        self.cfg = cfg
        self.dir = Path(cfg.storage_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / self.cfg.index_filename
        self.state_path = self.dir / self.cfg.state_filename
        self.sqlite_path = self.dir / self.cfg.sqlite_filename

        self._lock = RWLock()
        self._index: Optional[hnswlib.Index] = None
        self._state: _State = _State.from_config(cfg)
        self._meta = _MetaStore(self.sqlite_path)

        self._last_autosave = 0.0

    # ---------------- Lifecycle ----------------

    def start(self) -> None:
        t0 = time.perf_counter()
        self._meta.start()
        with self._lock.write():
            if self.index_path.exists() and self.state_path.exists():
                self._load_index()
                self._metric("hnsw.load.ok", {}, time.perf_counter() - t0)
                return
            self._create_index()
        self._metric("hnsw.create.ok", {}, time.perf_counter() - t0)

    def stop(self) -> None:
        with self._lock.write():
            if self._index is not None and self.cfg.autosave_on_update:
                self._save_index(force=True)
            self._index = None
        self._meta.stop()

    # ---------------- Public ops ----------------

    def upsert(
        self,
        vectors: np.ndarray,
        external_ids: Sequence[str],
        metadata: Optional[Sequence[Optional[Metadata]]] = None,
        replace_deleted: Optional[bool] = None,
    ) -> List[int]:
        """
        Вставка/обновление. Возвращает список внутренних labels.
        Поведение:
          - новый external_id -> выделяется новый label, добавляется в индекс,
          - существующий external_id -> upsert (replace_deleted=True позволит перезаписать).
        """
        t0 = time.perf_counter()
        if vectors.ndim != 2 or vectors.shape[1] != self.cfg.dim:
            raise ValueError(f"vectors must be (N,{self.cfg.dim})")
        n = vectors.shape[0]
        if n != len(external_ids):
            raise ValueError("vectors and external_ids length mismatch")
        if metadata and len(metadata) != n:
            raise ValueError("metadata length mismatch")

        vecs = self._normalize_if_needed(vectors)
        rep = self.cfg.allow_replace_deleted if replace_deleted is None else replace_deleted

        with self._lock.write():
            self._ensure_index()
            self._ensure_capacity(extra=n)
            labels = self._allocate_labels(external_ids)
            # upsert метаданных
            rows = [(lbl, eid, metadata[i] if metadata else None) for i, (eid, lbl) in enumerate(zip(external_ids, labels))]
            self._meta.upsert_items(rows)
            # добавление/замена в HNSW
            self._index.add_items(vecs, np.asarray(labels, dtype=np.int64), replace_deleted=bool(rep))  # type: ignore[union-attr]
            self._state.current_count = self._index.get_current_count()  # type: ignore[union-attr]
            self._maybe_autosave_locked()
            lbls_out = list(map(int, labels))
        self._metric("hnsw.upsert.ok", {"n": str(n)}, time.perf_counter() - t0)
        return lbls_out

    def delete(self, external_ids: Sequence[str]) -> List[int]:
        """
        Soft-delete: помечает элементы удалёнными на уровне индекса и метаданных.
        """
        t0 = time.perf_counter()
        if not external_ids:
            return []
        with self._lock.write():
            self._ensure_index()
            mapping = self._meta.get_labels(external_ids)
            labels = list(mapping.values())
            for lbl in labels:
                self._index.mark_deleted(int(lbl))  # type: ignore[union-attr]
            self._meta.mark_deleted(labels, True)
            self._maybe_autosave_locked()
        self._metric("hnsw.delete.ok", {"n": str(len(labels))}, time.perf_counter() - t0)
        return labels

    def undelete(self, external_ids: Sequence[str]) -> List[int]:
        """
        Снимает soft-delete: делает элементы снова видимыми.
        """
        t0 = time.perf_counter()
        if not external_ids:
            return []
        with self._lock.write():
            self._ensure_index()
            mapping = self._meta.get_labels(external_ids)
            labels = list(mapping.values())
            for lbl in labels:
                self._index.unmark_deleted(int(lbl))  # type: ignore[union-attr]
            self._meta.mark_deleted(labels, False)
            self._maybe_autosave_locked()
        self._metric("hnsw.undelete.ok", {"n": str(len(labels))}, time.perf_counter() - t0)
        return labels

    def query(
        self,
        query_vectors: np.ndarray,
        k: int,
        ef_search: Optional[int] = None,
        metadata_predicate: Optional[Callable[[Metadata], bool]] = None,
        oversample_factor: float = 2.0,
        return_metadata: bool = True,
    ) -> Tuple[np.ndarray, np.ndarray, Optional[List[List[Metadata]]]]:
        """
        Поиск ближайших соседей.
        Если задан metadata_predicate, применяется фильтрация на клиенте с oversample.
        Возвращает (labels, distances, metas?).
        """
        t0 = time.perf_counter()
        if query_vectors.ndim != 2 or query_vectors.shape[1] != self.cfg.dim:
            raise ValueError(f"query_vectors must be (Q,{self.cfg.dim})")
        if k <= 0:
            raise ValueError("k must be > 0")

        q = self._normalize_if_needed(query_vectors)
        with self._lock.read():
            self._ensure_index()
            prev_ef = self._index.get_ef()  # type: ignore[union-attr]
            try:
                if ef_search and ef_search > 0:
                    self._index.set_ef(int(ef_search))  # type: ignore[union-attr]
                need = int(math.ceil(k * (oversample_factor if metadata_predicate else 1.0)))
                need = max(need, k)
                labels, dists = self._index.knn_query(q, k=need, num_threads=self.cfg.num_threads)  # type: ignore[union-attr]
            finally:
                if ef_search and ef_search > 0:
                    self._index.set_ef(int(prev_ef))  # type: ignore[union-attr]

        # Фильтрация метаданными при необходимости
        metas_out: Optional[List[List[Metadata]]] = None
        if metadata_predicate:
            # Получим метаданные для всех кандидатов пачкой
            unique_labels = sorted(set(int(x) for x in labels.flatten().tolist()))
            meta_map = self._meta.get_meta_by_labels(unique_labels)
            # применим предикат
            filtered_labels: List[List[int]] = []
            filtered_dists: List[List[float]] = []
            filtered_metas: List[List[Metadata]] = []
            for row_lbls, row_d in zip(labels, dists):
                row: List[Tuple[int, float, Metadata]] = []
                for l, d in zip(row_lbls, row_d):
                    md = meta_map.get(int(l), {})
                    try:
                        keep = bool(metadata_predicate(md))
                    except Exception:
                        keep = False
                    if keep:
                        row.append((int(l), float(d), md))
                row.sort(key=lambda x: x[1])
                row = row[:k]
                filtered_labels.append([l for l, _, _ in row])
                filtered_dists.append([d for _, d, _ in row])
                filtered_metas.append([m for _, _, m in row])
            labels = np.asarray(filtered_labels, dtype=np.int64)
            dists = np.asarray(filtered_dists, dtype=np.float32)
            metas_out = filtered_metas if return_metadata else None
        elif return_metadata:
            unique_labels = sorted(set(int(x) for x in labels.flatten().tolist()))
            meta_map = self._meta.get_meta_by_labels(unique_labels)
            metas_out = [[meta_map.get(int(l), {}) for l in row] for row in labels]

        self._metric("hnsw.query.ok", {"q": str(query_vectors.shape[0]), "k": str(k)}, time.perf_counter() - t0)
        return labels, dists, metas_out

    def stats(self) -> Dict[str, Any]:
        with self._lock.read():
            self._ensure_index()
            s = self._meta.stats()
            return {
                "space": self.cfg.space,
                "dim": self.cfg.dim,
                "m": self.cfg.m,
                "ef_construction": self.cfg.ef_construction,
                "ef_search": self._index.get_ef(),  # type: ignore[union-attr]
                "max_elements": self._state.max_elements,
                "current_count": self._index.get_current_count(),  # type: ignore[union-attr]
                "meta_items": s["items"],
                "meta_deleted": s["deleted"],
                "index_path": str(self.index_path),
                "state_path": str(self.state_path),
                "sqlite_path": str(self.sqlite_path),
            }

    def set_ef_search(self, ef: int) -> None:
        if ef < 8:
            raise ValueError("ef must be >= 8")
        with self._lock.write():
            self._ensure_index()
            self._index.set_ef(int(ef))  # type: ignore[union-attr]
            self._state.ef_search = int(ef)
            self._maybe_autosave_locked()

    def set_num_threads(self, n: int) -> None:
        with self._lock.write():
            self.cfg.num_threads = max(1, int(n))
            if self._index is not None:
                self._index.set_num_threads(self.cfg.num_threads)  # type: ignore[union-attr]

    def rebuild(self, max_elements: Optional[int] = None, ef_construction: Optional[int] = None, m: Optional[int] = None) -> None:
        """
        Полная перестройка индекса с сохранением данных (дорого). Берёт все «живые» элементы из метастора.
        """
        t0 = time.perf_counter()
        with self._lock.write():
            # 1) считываем все живые элементы
            # Для простоты — извлечём метаданные и соответствия через прямой SQL
            conn = self._meta._conn  # type: ignore
            cur = conn.execute("SELECT label, external_id FROM items WHERE deleted = 0 ORDER BY label ASC")
            rows = cur.fetchall()
            if not rows:
                # просто пересоздадим пустой индекс
                self._create_index(
                    override_max=max_elements or self._state.max_elements,
                    override_m=m or self._state.m,
                    override_efc=ef_construction or self._state.ef_construction,
                )
                self._maybe_autosave_locked(force=True)
                self._metric("hnsw.rebuild.ok", {"count": "0"}, time.perf_counter() - t0)
                return

            labels = np.asarray([int(r[0]) for r in rows], dtype=np.int64)
            # 2) получим вектора обратно из индекса (hnswlib не хранит явного доступа к векторам),
            # поэтому rebuild корректно выполнить можно только если вы храните исходные эмбеддинги отдельно.
            # Здесь — безопасный путь: выгрузка из текущего индекса (если поддерживается) или ошибка.
            if not hasattr(self._index, "get_items"):  # type: ignore[union-attr]
                raise RuntimeError("Current hnswlib build does not support get_items; provide original vectors to rebuild.")
            vecs = self._index.get_items(labels)  # type: ignore[union-attr]

            # 3) пересоздание индекса
            new_max = int(max_elements or max(self._state.max_elements, int(len(labels) * 1.5)))
            self._create_index(override_max=new_max, override_m=m or self._state.m, override_efc=ef_construction or self._state.ef_construction)
            self._index.add_items(vecs, labels, replace_deleted=True)  # type: ignore[union-attr]
            self._state.current_count = self._index.get_current_count()  # type: ignore[union-attr]
            self._maybe_autosave_locked(force=True)
        self._metric("hnsw.rebuild.ok", {"count": str(len(labels))}, time.perf_counter() - t0)

    # ---------------- Internal helpers ----------------

    def _normalize_if_needed(self, x: np.ndarray) -> np.ndarray:
        if not self.cfg.normalize:
            return x
        # L2 нормализация по оси 1 (batch,row-wise)
        norms = np.linalg.norm(x, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return x / norms

    def _ensure_index(self) -> None:
        if self._index is None:
            raise RuntimeError("Index is not started; call start()")

    def _ensure_capacity(self, extra: int) -> None:
        need = (self._index.get_current_count() if self._index else 0) + max(0, int(extra))  # type: ignore[union-attr]
        if need <= self._state.max_elements:
            return
        # Увеличим до ближайшей степени двойки
        new_cap = 1 << (int(math.ceil(math.log2(need))) if need > 0 else 1)
        new_cap = max(new_cap, need)
        log.info("Resizing HNSW index: %s -> %s", self._state.max_elements, new_cap)
        self._index.resize_index(new_cap)  # type: ignore[union-attr]
        self._state.max_elements = int(new_cap)

    def _allocate_labels(self, external_ids: Sequence[str]) -> np.ndarray:
        """
        Для каждого external_id возвращает уникальный внутренний label (int64).
        Повторные ID получают свой уже существующий label.
        """
        mapping = self._meta.get_labels(external_ids)
        labels = np.empty(len(external_ids), dtype=np.int64)
        # текущий максимум
        cur_count = self._index.get_current_count()  # type: ignore[union-attr]
        # для уникальности смещаем свободные лейблы в верхнюю часть
        next_label = max(cur_count, max(mapping.values(), default=-1) + 1)
        for i, eid in enumerate(external_ids):
            lbl = mapping.get(eid)
            if lbl is None:
                lbl = next_label
                next_label += 1
            labels[i] = int(lbl)
        return labels

    def _create_index(self, override_max: Optional[int] = None, override_m: Optional[int] = None, override_efc: Optional[int] = None) -> None:
        self._index = hnswlib.Index(space=self.cfg.space, dim=self.cfg.dim)
        max_el = int(override_max or self.cfg.max_elements)
        self._index.init_index(max_elements=max_el, ef_construction=int(override_efc or self.cfg.ef_construction), M=int(override_m or self.cfg.m))  # type: ignore[union-attr]
        self._index.set_ef(self.cfg.ef_search)  # type: ignore[union-attr]
        self._index.set_num_threads(self.cfg.num_threads)  # type: ignore[union-attr]
        self._state = _State(
            dim=self.cfg.dim,
            space=self.cfg.space,
            m=int(override_m or self.cfg.m),
            ef_construction=int(override_efc or self.cfg.ef_construction),
            ef_search=self.cfg.ef_search,
            max_elements=max_el,
            current_count=0,
        )
        self._save_state_locked()

    def _load_index(self) -> None:
        st = self._load_state_locked()
        if st.dim != self.cfg.dim or st.space != self.cfg.space:
            raise RuntimeError(f"State/config mismatch: state(dim={st.dim},space={st.space}) vs cfg(dim={self.cfg.dim},space={self.cfg.space})")
        self._index = hnswlib.Index(space=st.space, dim=st.dim)
        # load_index позволяет загрузить, затем resize при необходимости
        self._index.load_index(str(self.index_path), max_elements=st.max_elements)  # type: ignore[union-attr]
        self._index.set_ef(st.ef_search)  # type: ignore[union-attr]
        self._index.set_num_threads(self.cfg.num_threads)  # type: ignore[union-attr]
        self._state = st

    # -------- Persistence (atomic) --------

    def _save_state_locked(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        data = json.dumps(asdict(self._state), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        tmp.write_bytes(data)
        os.replace(tmp, self.state_path)

    def _load_state_locked(self) -> _State:
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        st = _State(**data)
        return st

    def _save_index(self, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._last_autosave) < self.cfg.autosave_min_interval_s:
            return
        if self._index is None:
            return
        # атомарно пишем в .tmp + replace
        tmp = self.index_path.with_suffix(".bin.tmp")
        self._index.save_index(str(tmp))  # type: ignore[union-attr]
        os.replace(tmp, self.index_path)
        self._save_state_locked()
        self._last_autosave = now
        log.debug("HNSW index saved to %s", self.index_path)

    def _maybe_autosave_locked(self, force: bool = False) -> None:
        if self.cfg.autosave_on_update or force:
            self._save_index(force=force)

    # ---------------- Metrics ----------------

    def _metric(self, event: str, labels: Dict[str, str], latency_s: float) -> None:
        if self.cfg.metrics_hook:
            with contextlib.suppress(Exception):
                self.cfg.metrics_hook(event, labels, latency_s)


# ============================== Convenience API ===============================

def build_hnsw_from_env(dim: int) -> HNSWIndex:
    """
    Упрощённый конструктор из ENV.
    """
    cfg = HNSWConfig(
        dim=dim,
        space=os.getenv("HNSW_SPACE", "cosine"),
        max_elements=int(os.getenv("HNSW_MAX_ELEMENTS", "100000")),
        m=int(os.getenv("HNSW_M", "32")),
        ef_construction=int(os.getenv("HNSW_EF_CONSTRUCTION", "200")),
        ef_search=int(os.getenv("HNSW_EF_SEARCH", "64")),
        allow_replace_deleted=os.getenv("HNSW_REPLACE_DELETED", "true").lower() == "true",
        num_threads=int(os.getenv("HNSW_NUM_THREADS", str(max(1, (os.cpu_count() or 1) // 2)))),
        normalize=os.getenv("HNSW_NORMALIZE", "false").lower() == "true",
        storage_dir=Path(os.getenv("HNSW_STORAGE_DIR", "./data/vector/hnsw")),
        index_filename=os.getenv("HNSW_INDEX_FILE", "hnsw.index.bin"),
        state_filename=os.getenv("HNSW_STATE_FILE", "state.json"),
        sqlite_filename=os.getenv("HNSW_SQLITE_FILE", "meta.db"),
        autosave_on_update=os.getenv("HNSW_AUTOSAVE", "true").lower() == "true",
        autosave_min_interval_s=float(os.getenv("HNSW_AUTOSAVE_INTERVAL_S", "5.0")),
    )
    return HNSWIndex(cfg)
