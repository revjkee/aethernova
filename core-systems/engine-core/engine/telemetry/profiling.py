# engine/telemetry/profiling.py
from __future__ import annotations

import atexit
import contextlib
import dataclasses
import functools
import io
import json
import logging
import os
import pstats
import signal
import threading
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

try:
    # Опционально: если psutil установлен, добавим метрики RSS/CPU%
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False

LOG = logging.getLogger(__name__)

# ---------- Конфигурация ----------

@dataclass(frozen=True)
class TelemetryConfig:
    enabled: bool = True
    profile_cpu: bool = True
    profile_memory: bool = True
    capture_tracemalloc_frames: int = 25
    top_n_functions: int = 50

    # Вывод
    output_dir: Union[str, Path] = "telemetry/profiles"
    file_prefix: str = "profile"
    dump_pstats: bool = True
    dump_json: bool = True
    dump_chrome_trace: bool = True

    # Сортировка pstats: 'cumulative', 'time', 'calls'
    pstats_sort: str = "cumulative"

    # Поведение
    env_prefix: str = "ENGINE"  # например ENGINE_PROFILING=1
    auto_dump_on_atexit: bool = False
    include_process_metrics: bool = True  # при наличии psutil

    # Ограничения/безопасность вывода
    dump_timeout_seconds: float = 5.0

    # Имя профиля по умолчанию
    default_span_name: str = "engine"

    def with_overrides(self, **kwargs: Any) -> "TelemetryConfig":
        data = dataclasses.asdict(self)
        data.update(kwargs)
        return TelemetryConfig(**data)  # type: ignore[arg-type]


def init_from_env(base: Optional[TelemetryConfig] = None) -> TelemetryConfig:
    base = base or TelemetryConfig()
    prefix = base.env_prefix.upper()
    def _envb(key: str, default: bool) -> bool:
        v = os.getenv(f"{prefix}_{key}", "")
        if v == "":
            return default
        return v.strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")

    def _envi(key: str, default: int) -> int:
        v = os.getenv(f"{prefix}_{key}", "")
        return int(v) if v.isdigit() else default

    def _envs(key: str, default: str) -> str:
        v = os.getenv(f"{prefix}_{key}", "")
        return v if v else default

    cfg = base.with_overrides(
        enabled=_envb("PROFILING", base.enabled),
        profile_cpu=_envb("PROFILING_CPU", base.profile_cpu),
        profile_memory=_envb("PROFILING_MEMORY", base.profile_memory),
        capture_tracemalloc_frames=_envi("TRACEMALLOC_FRAMES", base.capture_tracemalloc_frames),
        top_n_functions=_envi("TOP_N_FUNCTIONS", base.top_n_functions),
        output_dir=_envs("PROFILE_DIR", str(base.output_dir)),
        file_prefix=_envs("PROFILE_PREFIX", base.file_prefix),
        dump_pstats=_envb("DUMP_PSTATS", base.dump_pstats),
        dump_json=_envb("DUMP_JSON", base.dump_json),
        dump_chrome_trace=_envb("DUMP_CHROME", base.dump_chrome_trace),
        pstats_sort=_envs("PSTATS_SORT", base.pstats_sort),
        auto_dump_on_atexit=_envb("AUTO_DUMP_ATEXIT", base.auto_dump_on_atexit),
        include_process_metrics=_envb("INCLUDE_PROCESS_METRICS", base.include_process_metrics),
    )
    return cfg

# ---------- Вспомогательные структуры ----------

@dataclass
class SpanRecord:
    name: str
    t_start: float
    t_end: Optional[float] = None
    cpu_time_start: Optional[float] = None
    cpu_time_end: Optional[float] = None
    rss_start: Optional[int] = None
    rss_end: Optional[int] = None

    def close(self, proc: Optional["psutil.Process"] = None) -> None:
        self.t_end = time.perf_counter()
        try:
            self.cpu_time_end = time.process_time()
        except Exception:
            self.cpu_time_end = None
        if proc is not None:
            try:
                self.rss_end = proc.memory_info().rss
            except Exception:
                self.rss_end = None

    @property
    def wall_seconds(self) -> Optional[float]:
        if self.t_end is None:
            return None
        return self.t_end - self.t_start

    @property
    def cpu_seconds(self) -> Optional[float]:
        if self.cpu_time_end is None or self.cpu_time_start is None:
            return None
        return self.cpu_time_end - self.cpu_time_start

    @property
    def rss_delta(self) -> Optional[int]:
        if self.rss_end is None or self.rss_start is None:
            return None
        return self.rss_end - self.rss_start


# ---------- Основной профайлер ----------

class Profiler:
    """
    Промышленный профайлер:
      - cProfile (CPU), tracemalloc (memory)
      - Контекст-менеджер и декоратор (sync/async)
      - Дамп pstats / JSON / Chrome trace
      - Вложенные span'ы (на уровне этого файла — плоский список секций)
      - Потокобезопасность
      - No-op при disabled
    """

    def __init__(
        self,
        name: Optional[str] = None,
        config: Optional[TelemetryConfig] = None,
    ) -> None:
        self.config = config or TelemetryConfig()
        self.name = name or self.config.default_span_name
        self._lock = threading.RLock()
        self._started = False
        self._start_ts = 0.0
        self._end_ts: Optional[float] = None
        self._proc = psutil.Process(os.getpid()) if (_HAS_PSUTIL and self.config.include_process_metrics) else None

        # CPU
        self._prof = None
        if self.config.profile_cpu:
            import cProfile  # local import
            self._prof = cProfile.Profile()

        # Memory
        self._tracemalloc_started_here = False

        # Собираемые данные
        self._spans: List[SpanRecord] = []
        self._stats_str: Optional[str] = None
        self._json_summary: Optional[Dict[str, Any]] = None
        self._chrome_trace: Optional[Dict[str, Any]] = None

    # --- Контекстный API ---

    def __enter__(self) -> "Profiler":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
        # Ошибки не подавляем — пусть пробрасываются
        self.dump()

    async def __aenter__(self) -> "Profiler":
        self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.stop()
        self.dump()

    # --- Публичные методы ---

    def start(self) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            if self._started:
                return
            self._started = True
            self._start_ts = time.perf_counter()
            if self._prof is not None:
                self._prof.enable()
            if self.config.profile_memory:
                if not tracemalloc.is_tracing():
                    tracemalloc.start(self.config.capture_tracemalloc_frames)
                    self._tracemalloc_started_here = True
            # Корневой span
            self._open_span(self.name)

    def stop(self) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            if not self._started:
                return
            # Закрыть последний span
            self._close_current_span()
            if self._prof is not None:
                self._prof.disable()
            if self.config.profile_memory and self._tracemalloc_started_here:
                # Трек снимков сделаем при сборе
                pass
            self._end_ts = time.perf_counter()
            # Сбор результатов
            self._collect_results()
            # Останов tracemalloc если мы включали
            if self.config.profile_memory and self._tracemalloc_started_here:
                with contextlib.suppress(Exception):
                    tracemalloc.stop()
            self._started = False

    def span(self, name: str) -> contextlib.AbstractContextManager:
        """
        Вложенная секция измерений (wall/cpu/rss deltas).
        Использование:
            with profiler.span("db_query"):
                ...
        """
        if not self.config.enabled:
            return _NullContext()
        return _SpanContext(self, name)

    def dump(self) -> None:
        if not self.config.enabled:
            return
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        pid = os.getpid()
        base = f"{self.config.file_prefix}-{self.name}-{timestamp}-pid{pid}"

        # pstats
        if self.config.dump_pstats and self._stats_str:
            target = out_dir / f"{base}.pstats.txt"
            self._safe_write_text(target, self._stats_str)

        # json summary
        if self.config.dump_json and self._json_summary is not None:
            target = out_dir / f"{base}.summary.json"
            self._safe_write_json(target, self._json_summary)

        # chrome trace
        if self.config.dump_chrome_trace and self._chrome_trace is not None:
            target = out_dir / f"{base}.trace.json"
            self._safe_write_json(target, self._chrome_trace)

    # --- Внутреннее ---

    def _open_span(self, name: str) -> None:
        with self._lock:
            rec = SpanRecord(
                name=name,
                t_start=time.perf_counter(),
            )
            try:
                rec.cpu_time_start = time.process_time()
            except Exception:
                rec.cpu_time_start = None
            if self._proc is not None:
                try:
                    rec.rss_start = self._proc.memory_info().rss
                except Exception:
                    rec.rss_start = None
            self._spans.append(rec)

    def _close_current_span(self) -> None:
        with self._lock:
            if not self._spans:
                return
            rec = self._spans[-1]
            if rec.t_end is None:
                rec.close(self._proc)

    def _collect_results(self) -> None:
        # pstats текст
        stats_text = None
        if self._prof is not None:
            s = io.StringIO()
            ps = pstats.Stats(self._prof, stream=s)
            # Очистка путей для читабельности
            with contextlib.suppress(Exception):
                ps.strip_dirs()
            sort_key = self.config.pstats_sort
            with contextlib.suppress(Exception):
                ps.sort_stats(sort_key)
            ps.print_stats(self.config.top_n_functions)
            stats_text = s.getvalue()
            self._stats_str = stats_text

        # tracemalloc top
        memory_top = []
        total_alloc_current = 0
        peak_alloc = 0
        if self.config.profile_memory and tracemalloc.is_tracing():
            try:
                current, peak = tracemalloc.get_traced_memory()
                total_alloc_current = int(current)
                peak_alloc = int(peak)
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics("lineno")
                for st in top_stats[: self.config.top_n_functions]:
                    memory_top.append({
                        "trace": str(st.traceback[0]) if st.traceback else "",
                        "size_bytes": int(st.size),
                        "count": int(st.count),
                    })
            except Exception as e:
                LOG.warning("tracemalloc collection failed: %s", e)

        # spans
        spans_data = []
        for sp in self._spans:
            spans_data.append({
                "name": sp.name,
                "wall_seconds": sp.wall_seconds,
                "cpu_seconds": sp.cpu_seconds,
                "rss_delta": sp.rss_delta,
            })

        # process metrics
        proc_metrics: Dict[str, Any] = {}
        if self._proc is not None:
            with contextlib.suppress(Exception):
                pmem = self._proc.memory_info()
                proc_metrics["rss_bytes"] = int(pmem.rss)
                proc_metrics["vms_bytes"] = int(getattr(pmem, "vms", 0))
            with contextlib.suppress(Exception):
                cpu_times = self._proc.cpu_times()
                proc_metrics["cpu_user"] = float(cpu_times.user)
                proc_metrics["cpu_system"] = float(cpu_times.system)

        # json summary
        self._json_summary = {
            "name": self.name,
            "started_at_perf": self._start_ts,
            "ended_at_perf": self._end_ts,
            "wall_seconds_total": (self._end_ts - self._start_ts) if self._end_ts else None,
            "pstats_top": self._extract_pstats_table(self._prof, self.config.top_n_functions) if self._prof else [],
            "memory": {
                "current_traced_bytes": total_alloc_current,
                "peak_traced_bytes": peak_alloc,
                "top_allocations": memory_top,
            } if self.config.profile_memory else None,
            "spans": spans_data,
            "process": proc_metrics or None,
        }

        # chrome trace (минимальный)
        self._chrome_trace = self._build_chrome_trace()

    def _extract_pstats_table(self, prof_obj: Any, top_n: int) -> List[Dict[str, Any]]:
        # Парсим таблицу из pstats
        try:
            s = io.StringIO()
            ps = pstats.Stats(prof_obj, stream=s)
            with contextlib.suppress(Exception):
                ps.strip_dirs()
            with contextlib.suppress(Exception):
                ps.sort_stats(self.config.pstats_sort)
            ps.print_stats(top_n)
            text = s.getvalue()
            return _parse_pstats_table(text)
        except Exception as e:
            LOG.debug("Failed to parse pstats table: %s", e)
            return []

    def _build_chrome_trace(self) -> Dict[str, Any]:
        """
        Упрощённое событие длительности по span'ам.
        Chrome trace формат: https://chromedevtools.github.io/devtools-protocol/tot/Tracing/
        """
        events: List[Dict[str, Any]] = []
        if not self._spans:
            return {"traceEvents": events}
        t0 = self._spans[0].t_start
        pid = os.getpid()
        tid = threading.get_ident()
        for sp in self._spans:
            if sp.t_end is None:
                continue
            events.append({
                "name": sp.name,
                "ph": "X",
                "ts": int((sp.t_start - t0) * 1e6),  # микросекунды
                "dur": int((sp.t_end - sp.t_start) * 1e6),
                "pid": pid,
                "tid": tid,
                "args": {
                    "cpu_seconds": sp.cpu_seconds,
                    "rss_delta": sp.rss_delta,
                }
            })
        return {"traceEvents": events}

    def _safe_write_text(self, path: Path, text: str) -> None:
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)
        except Exception as e:
            LOG.error("Failed to write %s: %s", path, e)

    def _safe_write_json(self, path: Path, obj: Dict[str, Any]) -> None:
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            LOG.error("Failed to write %s: %s", path, e)


# ---------- Вспомогательные контексты и парсинг ----------

class _NullContext(contextlib.AbstractContextManager):
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False

class _SpanContext(contextlib.AbstractContextManager):
    def __init__(self, profiler: Profiler, name: str) -> None:
        self._p = profiler
        self._name = name
        self._opened = False

    def __enter__(self):
        if self._p.config.enabled:
            self._p._open_span(self._name)
            self._opened = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._p.config.enabled and self._opened:
            self._p._close_current_span()
        return False


def _parse_pstats_table(text: str) -> List[Dict[str, Any]]:
    """
    Грубый парсер вывода pstats.print_stats() для извлечения основных колонок.
    """
    lines = text.splitlines()
    table_started = False
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not table_started:
            # Строка заголовка начинается после 'function calls'... и 'ncalls  tottime  percall  cumtime  percall filename:lineno(function)'
            if "ncalls" in ln and "filename:lineno(function)" in ln:
                table_started = True
            continue
        ln = ln.strip()
        if not ln:
            continue
        # Пример строки:
        #  120/1    0.001    0.000    0.120    0.120 module/file.py:10(func)
        parts = ln.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            rows.append({
                "ncalls": parts[0],
                "tottime": float(parts[1]),
                "percall_tottime": float(parts[2]),
                "cumtime": float(parts[3]),
                "percall_cumtime": float(parts[4]),
                "location": parts[5],
            })
        except Exception:
            continue
    return rows


# ---------- Упрощённый внешний API ----------

def profile_block(name: Optional[str] = None, config: Optional[TelemetryConfig] = None):
    """
    Контекст для разовой секции профилирования.
    Пример:
        with profile_block("load_batch"):
            ...
    """
    cfg = config or init_from_env(TelemetryConfig())
    if not cfg.enabled:
        return _NullContext()
    return Profiler(name=name or cfg.default_span_name, config=cfg)

def profiled(
    name: Optional[str] = None,
    config: Optional[TelemetryConfig] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Декоратор для функций/корутин.
    """
    def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        is_coro = _is_coroutine_function(func)

        if is_coro:
            @functools.wraps(func)
            async def _aw(*args, **kwargs):
                cfg = config or init_from_env(TelemetryConfig())
                if not cfg.enabled:
                    return await func(*args, **kwargs)
                prof = Profiler(name or func.__qualname__, cfg)
                async with prof:
                    return await func(*args, **kwargs)
            return _aw
        else:
            @functools.wraps(func)
            def _w(*args, **kwargs):
                cfg = config or init_from_env(TelemetryConfig())
                if not cfg.enabled:
                    return func(*args, **kwargs)
                prof = Profiler(name or func.__qualname__, cfg)
                with prof:
                    return func(*args, **kwargs)
            return _w
    return _decorator

def _is_coroutine_function(fn: Callable[..., Any]) -> bool:
    try:
        import inspect
        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False


# ---------- Автодамп на выходе процесса (опционально) ----------

_GLOBAL_PROFILERS: List[Profiler] = []
_GLOBAL_CFG: Optional[TelemetryConfig] = None
_global_lock = threading.RLock()

def enable_global(config: Optional[TelemetryConfig] = None, name: Optional[str] = None) -> Profiler:
    """
    Включить глобальный профайлер процесса (ручное управление).
    """
    cfg = config or init_from_env(TelemetryConfig())
    prof = Profiler(name=name or cfg.default_span_name, config=cfg)
    prof.start()
    with _global_lock:
        _GLOBAL_PROFILERS.append(prof)
    return prof

def disable_global() -> None:
    with _global_lock:
        for p in _GLOBAL_PROFILERS:
            with contextlib.suppress(Exception):
                p.stop()
                p.dump()
        _GLOBAL_PROFILERS.clear()

def _atexit_dump() -> None:
    with _global_lock:
        for p in _GLOBAL_PROFILERS:
            with contextlib.suppress(Exception):
                if p._started:
                    p.stop()
                p.dump()

# Регистрация atexit — активируем только если явно включено в конфиге
def configure_atexit_from_env() -> None:
    cfg = init_from_env(TelemetryConfig())
    if cfg.auto_dump_on_atexit:
        atexit.register(_atexit_dump)


# Инициализация логгера по умолчанию (безопасно для продакшена)
if not LOG.handlers:
    handler = logging.StreamHandler()
    fmt = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
