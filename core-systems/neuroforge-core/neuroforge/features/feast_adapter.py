# neuroforge-core/neuroforge/features/feast_adapter.py
# Production-grade Feast adapter for Neuroforge.
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

try:
    from feast import FeatureStore  # type: ignore
except Exception:  # pragma: no cover
    FeatureStore = None  # type: ignore

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

LOG = logging.getLogger("neuroforge.feast")
if not LOG.handlers:
    logging.basicConfig(
        level=getattr(logging, os.getenv("NF_LOG_LEVEL", "INFO").upper(), logging.INFO),
        format='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s"}',
    )

# --------------------------
# Errors
# --------------------------

class FeastAdapterError(Exception):
    pass

class DependencyMissingError(FeastAdapterError):
    pass

# --------------------------
# Config
# --------------------------

@dataclass(frozen=True)
class FeastAdapterConfig:
    # Feast
    repo_path: str
    project: Optional[str] = None
    full_feature_names: bool = True

    # Resilience
    retries: int = 2
    backoff_base_ms: int = 50
    backoff_max_ms: int = 1500
    request_timeout_s: float = 5.0

    # Caching (online features only)
    cache_ttl_s: int = 2
    cache_max_items: int = 2048
    cache_enabled: bool = True

    # Circuit breaker
    cb_fail_threshold: int = 8
    cb_cooldown_s: int = 5

    # Telemetry
    log_inputs: bool = False  # не логируем значения по умолчанию (PII)

    @staticmethod
    def from_env() -> "FeastAdapterConfig":
        return FeastAdapterConfig(
            repo_path=os.getenv("NF_FEAST_REPO", "."),
            project=os.getenv("NF_FEAST_PROJECT") or None,
            full_feature_names=os.getenv("NF_FEAST_FULL_NAMES", "true").lower() == "true",
            retries=int(os.getenv("NF_FEAST_RETRIES", "2")),
            backoff_base_ms=int(os.getenv("NF_FEAST_BACKOFF_BASE_MS", "50")),
            backoff_max_ms=int(os.getenv("NF_FEAST_BACKOFF_MAX_MS", "1500")),
            request_timeout_s=float(os.getenv("NF_FEAST_TIMEOUT_S", "5.0")),
            cache_ttl_s=int(os.getenv("NF_FEAST_CACHE_TTL_S", "2")),
            cache_max_items=int(os.getenv("NF_FEAST_CACHE_MAX_ITEMS", "2048")),
            cache_enabled=os.getenv("NF_FEAST_CACHE", "true").lower() == "true",
            cb_fail_threshold=int(os.getenv("NF_FEAST_CB_THRESHOLD", "8")),
            cb_cooldown_s=int(os.getenv("NF_FEAST_CB_COOLDOWN_S", "5")),
            log_inputs=os.getenv("NF_FEAST_LOG_INPUTS", "false").lower() == "true",
        )

# --------------------------
# Small TTL-LRU cache
# --------------------------

class _TTLCache:
    def __init__(self, ttl_s: int, max_items: int):
        self.ttl = max(0, int(ttl_s))
        self.max = max(1, int(max_items))
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()

    def _evict(self):
        while len(self._order) > self.max:
            k = self._order.pop(0)
            self._store.pop(k, None)

    def get(self, key: str) -> Any:
        if self.ttl <= 0:
            return None
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            ts, val = item
            if (time.time() - ts) > self.ttl:
                self._store.pop(key, None)
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
                return None
            # bump LRU
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            return val

    def set(self, key: str, val: Any):
        if self.ttl <= 0:
            return
        with self._lock:
            self._store[key] = (time.time(), val)
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            self._evict()

# --------------------------
# Circuit breaker (very small)
# --------------------------

class _CircuitBreaker:
    def __init__(self, threshold: int, cooldown_s: int):
        self.threshold = max(1, int(threshold))
        self.cooldown = max(1, int(cooldown_s))
        self._fails = 0
        self._opened_at: Optional[float] = None
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if (time.time() - self._opened_at) >= self.cooldown:
                # half-open: allow one attempt
                return True
            return False

    def on_success(self):
        with self._lock:
            self._fails = 0
            self._opened_at = None

    def on_failure(self):
        with self._lock:
            self._fails += 1
            if self._fails >= self.threshold:
                self._opened_at = time.time()

# --------------------------
# Adapter
# --------------------------

class FeastAdapter:
    """
    Thin, resilient wrapper over Feast FeatureStore.
    """

    def __init__(self, config: FeastAdapterConfig):
        if FeatureStore is None:
            raise DependencyMissingError("Feast is not installed. `pip install feast`.")
        self.cfg = config
        self._store = FeatureStore(repo_path=self.cfg.repo_path, project=self.cfg.project)  # type: ignore
        self._cache = _TTLCache(self.cfg.cache_ttl_s, self.cfg.cache_max_items)
        self._cb = _CircuitBreaker(self.cfg.cb_fail_threshold, self.cfg.cb_cooldown_s)

    @classmethod
    def from_env(cls) -> "FeastAdapter":
        return cls(FeastAdapterConfig.from_env())

    # ---------- Online ----------

    def get_online_features(
        self,
        features: Sequence[str],
        entity_rows: Sequence[Mapping[str, Any]],
        full_feature_names: Optional[bool] = None,
        use_cache: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Returns per-row dicts with feature values.
        """
        if not features:
            return [{} for _ in entity_rows]

        key = None
        if use_cache and self.cfg.cache_enabled:
            key = self._cache_key(features, entity_rows, full_feature_names)
            hit = self._cache.get(key)
            if hit is not None:
                return hit

        out_rows: List[Dict[str, Any]] = self._do_with_retries(
            lambda: self._fetch_online(features, entity_rows, full_feature_names)
        )

        if key is not None:
            self._cache.set(key, out_rows)
        return out_rows

    def _fetch_online(
        self,
        features: Sequence[str],
        entity_rows: Sequence[Mapping[str, Any]],
        full_feature_names: Optional[bool],
    ) -> List[Dict[str, Any]]:
        if not self._cb.allow():
            raise FeastAdapterError("circuit_open: too many recent failures")

        started = time.time()
        try:
            # Feast call (sync)
            resp = self._store.get_online_features(  # type: ignore[attr-defined]
                features=list(features),
                entity_rows=list(entity_rows),
                full_feature_names=self.cfg.full_feature_names if full_feature_names is None else bool(full_feature_names),
            )
            data = resp.to_dict()  # {feature_name: [v1, v2, ...]}
            rows = _dict_to_rows(data)
            took = int((time.time() - started) * 1000)
            LOG.debug('feast_online ok features=%d rows=%d took_ms=%d', len(features), len(entity_rows), took)
            self._cb.on_success()
            return rows
        except Exception as e:
            self._cb.on_failure()
            LOG.warning("feast_online error: %s", str(e))
            raise FeastAdapterError(f"online_failed: {e}") from e

    # ---------- Historical ----------
    def get_historical_features(
        self,
        features: Sequence[str],
        entity_df: Union["pd.DataFrame", str],  # DataFrame or SQL
        full_feature_names: Optional[bool] = None,
    ) -> "pd.DataFrame":
        if pd is None:
            raise DependencyMissingError("pandas is required for historical retrieval (`pip install pandas`).")
        if not features:
            return pd.DataFrame()  # type: ignore

        def _call():
            resp = self._store.get_historical_features(  # type: ignore[attr-defined]
                entity_df=entity_df,
                features=list(features),
                full_feature_names=self.cfg.full_feature_names if full_feature_names is None else bool(full_feature_names),
            )
            return resp.to_df()  # type: ignore[attr-defined]

        try:
            df = self._do_with_retries(_call)
            LOG.debug("feast_historical ok features=%d rows=%d", len(features), len(df))  # type: ignore
            return df  # type: ignore
        except Exception as e:
            LOG.error("feast_historical error: %s", str(e))
            raise FeastAdapterError(f"historical_failed: {e}") from e

    # ---------- Materialization ----------
    def materialize(self, start_date: datetime, end_date: datetime, feature_views: Optional[Sequence[str]] = None) -> None:
        try:
            kwargs = {"start_date": start_date, "end_date": end_date}
            if feature_views:
                kwargs["feature_views"] = list(feature_views)  # type: ignore
            self._do_with_retries(lambda: self._store.materialize(**kwargs))  # type: ignore[attr-defined]
            LOG.info("feast_materialize ok start=%s end=%s views=%s", start_date.isoformat(), end_date.isoformat(), feature_views)
        except TypeError:
            # older Feast without feature_views arg
            self._do_with_retries(lambda: self._store.materialize(start_date, end_date))  # type: ignore
            LOG.info("feast_materialize ok(start,end) legacy")
        except Exception as e:
            LOG.error("feast_materialize error: %s", str(e))
            raise FeastAdapterError(f"materialize_failed: {e}") from e

    def materialize_incremental(self, end_date: datetime, feature_views: Optional[Sequence[str]] = None) -> None:
        try:
            kwargs = {"end_date": end_date}
            if feature_views:
                kwargs["feature_views"] = list(feature_views)  # type: ignore
            self._do_with_retries(lambda: self._store.materialize_incremental(**kwargs))  # type: ignore[attr-defined]
            LOG.info("feast_materialize_incremental ok end=%s views=%s", end_date.isoformat(), feature_views)
        except TypeError:
            self._do_with_retries(lambda: self._store.materialize_incremental(end_date))  # type: ignore
            LOG.info("feast_materialize_incremental ok(end) legacy")
        except Exception as e:
            LOG.error("feast_materialize_incremental error: %s", str(e))
            raise FeastAdapterError(f"materialize_incremental_failed: {e}") from e

    # ---------- Push sources ----------
    def push(self, source_name: str, df: "pd.DataFrame") -> None:
        if pd is None:
            raise DependencyMissingError("pandas is required for push (`pip install pandas`).")
        try:
            self._do_with_retries(lambda: self._store.push(source_name, df))  # type: ignore[attr-defined]
            LOG.info('feast_push ok source="%s" rows=%d', source_name, len(df))
        except Exception as e:
            LOG.error("feast_push error: %s", str(e))
            raise FeastAdapterError(f"push_failed: {e}") from e

    # ---------- Maintenance ----------
    def refresh_registry(self) -> None:
        try:
            self._store.refresh_registry()  # type: ignore[attr-defined]
            LOG.info("feast_refresh_registry ok")
        except Exception as e:
            LOG.warning("feast_refresh_registry error: %s", str(e))
            raise FeastAdapterError(f"refresh_registry_failed: {e}") from e

    def healthcheck(self) -> bool:
        """Lightweight check: list feature views; returns True/False."""
        try:
            _ = self._store.list_feature_views()  # type: ignore[attr-defined]
            return True
        except Exception:
            return False

    # ---------- Async facades ----------
    async def aget_online_features(
        self,
        features: Sequence[str],
        entity_rows: Sequence[Mapping[str, Any]],
        full_feature_names: Optional[bool] = None,
        use_cache: bool = True,
        loop=None,
    ) -> List[Dict[str, Any]]:
        import asyncio
        loop = loop or asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.get_online_features(features, entity_rows, full_feature_names, use_cache)
        )

    async def aget_historical_features(
        self,
        features: Sequence[str],
        entity_df: Union["pd.DataFrame", str],
        full_feature_names: Optional[bool] = None,
        loop=None,
    ) -> "pd.DataFrame":
        import asyncio
        loop = loop or asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.get_historical_features(features, entity_df, full_feature_names)
        )

    # ---------- Internal helpers ----------
    def _do_with_retries(self, fn):
        # naive retries with exponential backoff
        attempts = max(0, self.cfg.retries) + 1
        last_exc = None
        for i in range(attempts):
            try:
                return fn()
            except Exception as e:  # noqa
                last_exc = e
                if i == attempts - 1:
                    break
                delay = min(self.cfg.backoff_max_ms, self.cfg.backoff_base_ms * (2 ** i)) / 1000.0
                time.sleep(delay)
        # propagate
        raise last_exc  # type: ignore[misc]

    def _cache_key(
        self,
        features: Sequence[str],
        entity_rows: Sequence[Mapping[str, Any]],
        full_feature_names: Optional[bool],
    ) -> str:
        payload = {
            "f": list(features),
            "r": [ _stable_row(er) for er in entity_rows ],
            "n": self.cfg.full_feature_names if full_feature_names is None else bool(full_feature_names),
        }
        return _sha256_json(payload)

# --------------------------
# Utils
# --------------------------

def _sha256_json(obj: Any) -> str:
    import hashlib
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _stable_row(row: Mapping[str, Any]) -> Mapping[str, Any]:
    # convert non-json types
    out: Dict[str, Any] = {}
    for k, v in row.items():
        if isinstance(v, (datetime, )):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out

def _dict_to_rows(data: Mapping[str, List[Any]]) -> List[Dict[str, Any]]:
    """
    Feast to_dict() -> {feature_name: [v1, v2, ...]}.
    Return list of {feature_name: value} aligned by index.
    """
    # Determine number of rows by first value length
    n = 0
    for v in data.values():
        if isinstance(v, list):
            n = len(v)
            break
    rows: List[Dict[str, Any]] = [ {} for _ in range(n) ]
    for name, values in data.items():
        # Some Feast versions return lists; if scalar, broadcast
        if isinstance(values, list):
            for i, val in enumerate(values):
                rows[i][name] = val
        else:
            for i in range(n):
                rows[i][name] = values
    return rows

# --------------------------
# Example minimal usage (commented)
# --------------------------
# if __name__ == "__main__":
#     cfg = FeastAdapterConfig.from_env()
#     fa = FeastAdapter(cfg)
#     rows = fa.get_online_features(
#         features=["driver_stats:conv_rate", "driver_stats:acc_rate"],
#         entity_rows=[{"driver_id": 1001}, {"driver_id": 1002}],
#     )
#     print(rows)
