# path: ops/omnimind/orchestrator/execution_graph.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import functools
import hashlib
import inspect
import json
import logging
import random
import signal
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterable,
    Awaitable,
    Callable,
    Coroutine,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Set,
    Tuple,
    Type,
    Union,
)

# =========================
# Public Types / Protocols
# =========================

JSONable = Union[str, int, float, bool, None, Mapping[str, Any], List[Any]]

class FingerprintFn(Protocol):
    def __call__(self, *, node_id: str, upstream_results: Mapping[str, Any], inputs: Mapping[str, Any]) -> str: ...


class MetricsSink(Protocol):
    """Интерфейс для интеграции с метриками (Prometheus/StatsD и т.п.). Все методы опциональны."""
    def on_node_start(self, node_id: str) -> None: ...
    def on_node_end(self, node_id: str, status: str, duration_seconds: float, attempts: int) -> None: ...
    def on_graph_end(self, status: str, duration_seconds: float) -> None: ...


class EventSubscriber(Protocol):
    """Синхронный или асинхронный подписчик на события."""
    def __call__(self, event: "Event") -> Union[None, Awaitable[None]]: ...


# =========================
# Retry / Timeout Policies
# =========================

@dataclass(frozen=True)
class RetryPolicy:
    """Политика повторов выполнения задачи."""
    max_attempts: int = 3
    initial_backoff: float = 0.2  # сек
    max_backoff: float = 10.0
    multiplier: float = 2.0
    jitter: float = 0.2  # 0..1 (доля от бэкоффа)
    retry_on: Tuple[Type[BaseException], ...] = (Exception,)
    retry_on_result: Optional[Callable[[Any], bool]] = None  # если True -> повторить

    def next_backoff(self, attempt: int) -> float:
        base = min(self.initial_backoff * (self.multiplier ** (attempt - 1)), self.max_backoff)
        if self.jitter > 0:
            delta = base * self.jitter
            return max(0.0, random.uniform(base - delta, base + delta))
        return base


@dataclass(frozen=True)
class TimeoutPolicy:
    seconds: Optional[float] = None  # None = без таймаута


@dataclass(frozen=True)
class ConcurrencyPolicy:
    """Ограничения конкуренции: глобально и по меткам узлов."""
    global_limit: int = 8
    per_tag_limits: Mapping[str, int] = dataclasses.field(default_factory=dict)


# =========================
# Caching
# =========================

class CacheBackend(Protocol):
    async def get(self, key: str) -> Tuple[bool, Any]: ...
    async def set(self, key: str, value: Any, ttl_seconds: Optional[int]) -> None: ...
    async def invalidate(self, key: str) -> None: ...


class InMemoryTTLCache(CacheBackend):
    """Простой потокобезопасный кэш с TTL для одного процесса."""
    def __init__(self, max_items: int = 1000) -> None:
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._max = max_items
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Tuple[bool, Any]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return False, None
            expires_at, value = item
            if expires_at and expires_at < time.monotonic():
                self._store.pop(key, None)
                return False, None
            return True, value

    async def set(self, key: str, value: Any, ttl_seconds: Optional[int]) -> None:
        async with self._lock:
            if len(self._store) >= self._max:
                # Простая эвикция: удаляем произвольный элемент
                self._store.pop(next(iter(self._store)), None)
            exp = (time.monotonic() + ttl_seconds) if ttl_seconds else float("inf")
            self._store[key] = (exp, value)

    async def invalidate(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)


# =========================
# Events
# =========================

@dataclass(frozen=True)
class Event:
    kind: str
    at: dt.datetime
    run_id: str
    node_id: Optional[str] = None
    payload: Mapping[str, Any] = dataclasses.field(default_factory=dict)


# =========================
# Execution Types
# =========================

TaskFunc = Union[
    Callable[..., Any],
    Callable[..., Awaitable[Any]],
]

@dataclass
class Node:
    id: str
    func: TaskFunc
    needs: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    timeout: TimeoutPolicy = field(default_factory=TimeoutPolicy)
    cache_ttl_seconds: Optional[int] = None
    cacheable: bool = False
    fingerprint: Optional[FingerprintFn] = None
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise ValueError("Node.id must be a non-empty string")
        if not callable(self.func):
            raise ValueError(f"Node.func must be callable: {self.id}")


@dataclass
class Graph:
    nodes: Dict[str, Node] = field(default_factory=dict)

    def add(self, node: Node) -> None:
        if node.id in self.nodes:
            raise ValueError(f"Duplicate node id: {node.id}")
        self.nodes[node.id] = node

    def validate(self) -> None:
        # Проверка зависимостей и циклов
        for nid, n in self.nodes.items():
            unknown = n.needs - self.nodes.keys()
            if unknown:
                raise ValueError(f"Node {nid} depends on unknown: {unknown}")
        # Поиск циклов: Kahn
        indeg = {nid: 0 for nid in self.nodes}
        for n in self.nodes.values():
            for dep in n.needs:
                indeg[n.id] += 1
        q = deque([nid for nid, d in indeg.items() if d == 0])
        seen = 0
        while q:
            u = q.popleft()
            seen += 1
            for v in (x for x in self.nodes.values() if u in x.needs):
                indeg[v.id] -= 1
                if indeg[v.id] == 0:
                    q.append(v.id)
        if seen != len(self.nodes):
            raise ValueError("Graph has cycles")

    def topo_layers(self) -> List[Set[str]]:
        """Возвращает слои топологии (пакеты независимых узлов)."""
        self.validate()
        needs = {nid: set(n.needs) for nid, n in self.nodes.items()}
        remaining = set(self.nodes.keys())
        layers: List[Set[str]] = []
        while remaining:
            layer = {nid for nid in remaining if not needs[nid]}
            if not layer:
                raise ValueError("Graph has cycles (during layering)")
            layers.append(layer)
            remaining -= layer
            for nd in remaining:
                needs[nd] -= layer
        return layers


@dataclass
class ExecutionContext:
    run_id: str
    started_at: dt.datetime
    logger: logging.Logger
    store: Dict[str, Any] = field(default_factory=dict)
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def request_cancel(self) -> None:
        self.cancel_event.set()


@dataclass
class TaskResult:
    node_id: str
    status: str  # succeeded | failed | skipped
    started_at: dt.datetime
    finished_at: dt.datetime
    attempts: int
    output: Any = None
    error: Optional[str] = None
    elapsed_seconds: float = 0.0
    from_cache: bool = False
    upstream_fingerprint: Optional[str] = None


@dataclass
class GraphResult:
    run_id: str
    started_at: dt.datetime
    finished_at: dt.datetime
    status: str  # succeeded | failed | cancelled
    results: Dict[str, TaskResult]


# =========================
# Orchestrator
# =========================

class Orchestrator:
    """Асинхронный оркестратор DAG с ретраями, таймаутами, конкуренцией и кэшированием."""

    def __init__(
        self,
        *,
        metrics: Optional[MetricsSink] = None,
        cache: Optional[CacheBackend] = None,
        concurrency: ConcurrencyPolicy = ConcurrencyPolicy(),
        fail_fast: bool = True,
    ) -> None:
        self._metrics = metrics
        self._cache = cache or InMemoryTTLCache()
        self._conc = concurrency
        self._fail_fast = fail_fast

        self._global_sem = asyncio.Semaphore(concurrency.global_limit)
        self._tag_sems: Dict[str, asyncio.Semaphore] = {
            tag: asyncio.Semaphore(limit) for tag, limit in (concurrency.per_tag_limits or {}).items()
        }
        self._subs: List[EventSubscriber] = []

    # -------- Events --------

    def subscribe(self, sub: EventSubscriber) -> None:
        self._subs.append(sub)

    async def _emit(self, event: Event) -> None:
        for sub in list(self._subs):
            try:
                ret = sub(event)
                if inspect.isawaitable(ret):
                    await ret  # type: ignore[func-returns-value]
            except Exception:  # безопасная изоляция подписчиков
                # Никаких raise — события не должны ломать выполнение
                pass

    # -------- Public API --------

    async def run(
        self,
        graph: Graph,
        *,
        inputs: Mapping[str, Any] | None = None,
        run_id: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        cancel_on_signals: Iterable[int] = (signal.SIGINT, signal.SIGTERM),
    ) -> GraphResult:
        """Запускает исполнение графа, возвращает детальный результат."""
        graph.validate()

        rid = run_id or dt.datetime.utcnow().strftime("run-%Y%m%d-%H%M%S-%f")
        log = logger or logging.getLogger(f"orchestrator.{rid}")
        ctx = ExecutionContext(run_id=rid, started_at=dt.datetime.utcnow(), logger=log)

        started = time.perf_counter()
        results: Dict[str, TaskResult] = {}
        status = "succeeded"

        # Установка хендлеров сигналов для graceful cancel
        loop = asyncio.get_running_loop()
        removers: List[Callable[[], None]] = []
        for sig in cancel_on_signals:
            try:
                loop.add_signal_handler(sig, ctx.request_cancel)
                removers.append(functools.partial(loop.remove_signal_handler, sig))
            except NotImplementedError:
                # Windows/embedded loop — пропускаем
                pass

        try:
            await self._execute(graph, ctx, inputs or {}, results)
        except asyncio.CancelledError:
            status = "cancelled"
            raise
        except Exception:
            status = "failed"
            raise
        finally:
            for rm in removers:
                with contextlib.suppress(Exception):
                    rm()
            finished = dt.datetime.utcnow()
            elapsed = time.perf_counter() - started
            if self._metrics:
                with contextlib.suppress(Exception):
                    self._metrics.on_graph_end(status, elapsed)
            await self._emit(Event(kind="graph.finished", at=finished, run_id=rid, payload={"status": status}))

        return GraphResult(
            run_id=rid,
            started_at=ctx.started_at,
            finished_at=finished,
            status=status if all(r.status == "succeeded" for r in results.values()) else "failed",
            results=results,
        )

    # -------- Core scheduling --------

    async def _execute(
        self,
        graph: Graph,
        ctx: ExecutionContext,
        inputs: Mapping[str, Any],
        results: Dict[str, TaskResult],
    ) -> None:
        pending_deps: Dict[str, Set[str]] = {nid: set(n.needs) for nid, n in graph.nodes.items()}
        ready: Set[str] = {nid for nid, deps in pending_deps.items() if not deps}
        running: Set[str] = set()
        failed: Set[str] = set()
        skipped: Set[str] = set()

        # Канал для нотификаций о завершении узлов
        done_q: asyncio.Queue[Tuple[str, TaskResult]] = asyncio.Queue()

        async def launch(nid: str) -> None:
            running.add(nid)
            node = graph.nodes[nid]
            await self._emit(Event(kind="node.start", at=dt.datetime.utcnow(), run_id=ctx.run_id, node_id=nid))
            if self._metrics:
                with contextlib.suppress(Exception):
                    self._metrics.on_node_start(nid)
            res = await self._run_node(node, graph, ctx, inputs, results)
            await done_q.put((nid, res))

        # Главный цикл
        tasks: Dict[str, asyncio.Task[None]] = {}
        try:
            while True:
                # Планируем готовые узлы при наличии слотов
                dispatch = []
                for nid in list(ready):
                    if ctx.cancelled():
                        break
                    if nid in running or nid in tasks or nid in failed or nid in skipped:
                        ready.discard(nid)
                        continue
                    # Соблюдаем лимиты конкуренции: глобально и по тегам
                    if self._global_sem.locked() and self._global_sem._value <= 0:  # noqa: SLF001
                        break
                    # Проверим теги
                    tag_sems = [self._tag_sems[t] for t in graph.nodes[nid].tags if t in self._tag_sems]
                    if any(s._value <= 0 for s in tag_sems):  # noqa: SLF001
                        continue
                    dispatch.append(nid)

                for nid in dispatch:
                    ready.discard(nid)
                    tasks[nid] = asyncio.create_task(self._with_semaphores(launch, graph.nodes[nid]))

                if not tasks and not ready:
                    # Завершение: либо все узлы обработаны, либо нечего планировать
                    break

                # Дожидаемся завершения любой задачи
                done_nid, res = await done_q.get()
                tasks.pop(done_nid, None)
                running.discard(done_nid)
                results[done_nid] = res

                # Обработка статуса
                if res.status == "failed":
                    failed.add(done_nid)
                    if self._fail_fast:
                        ctx.request_cancel()
                        # Пропускаем все downstream
                        for nid, deps in pending_deps.items():
                            if done_nid in deps:
                                skipped.add(nid)
                    await self._emit(Event(kind="node.failed", at=dt.datetime.utcnow(), run_id=ctx.run_id, node_id=done_nid, payload={"error": res.error}))
                elif res.status == "skipped":
                    skipped.add(done_nid)
                    await self._emit(Event(kind="node.skipped", at=dt.datetime.utcnow(), run_id=ctx.run_id, node_id=done_nid))
                else:
                    await self._emit(Event(kind="node.succeeded", at=dt.datetime.utcnow(), run_id=ctx.run_id, node_id=done_nid))

                # Обновляем зависимости и готовность downstream
                for nid, deps in pending_deps.items():
                    if done_nid in deps:
                        deps.remove(done_nid)
                        # Узел становится готовым, если все его зависимости выполнены успешно
                        if not deps:
                            # Проверяем, не зависит ли он от проваленных/пропущенных узлов
                            deps_ok = all(results[d].status == "succeeded" for d in graph.nodes[nid].needs)
                            if not deps_ok:
                                skipped.add(nid)
                                results[nid] = self._make_skipped(nid, "dependency_failed_or_skipped")
                                await self._emit(Event(kind="node.skipped", at=dt.datetime.utcnow(), run_id=ctx.run_id, node_id=nid))
                            else:
                                ready.add(nid)

                # Выход, если отмена и ничего не бежит
                if ctx.cancelled() and not tasks:
                    break
        finally:
            # Грациозная отмена оставшихся задач
            for t in tasks.values():
                t.cancel()
                with contextlib.suppress(Exception):
                    await t

    async def _with_semaphores(self, fn: Callable[[str], Awaitable[None]], node: Node) -> None:
        sems: List[asyncio.Semaphore] = [self._global_sem] + [self._tag_sems[t] for t in node.tags if t in self._tag_sems]
        # Взять все семафоры
        async with AsyncMultiSemaphore(sems):
            await fn(node.id)

    # -------- Node execution --------

    async def _run_node(
        self,
        node: Node,
        graph: Graph,
        ctx: ExecutionContext,
        inputs: Mapping[str, Any],
        results: Mapping[str, TaskResult],
    ) -> TaskResult:
        started = dt.datetime.utcnow()
        t0 = time.perf_counter()

        # Сформируем upstream результаты
        upstream: Dict[str, Any] = {}
        for dep in node.needs:
            dep_res = results.get(dep)
            if not dep_res:
                return self._make_failed(node.id, started, "missing_dependency_result")
            if dep_res.status != "succeeded":
                return self._make_skipped(node.id, "dependency_failed_or_skipped")
            upstream[dep] = dep_res.output

        # Кэширование
        upstream_fpr = None
        cache_hit = False
        if node.cacheable:
            upstream_fpr = self._fingerprint(node, upstream, inputs)
            cache_key = f"node:{node.id}:fp:{upstream_fpr}"
            cached, value = await self._cache.get(cache_key)
            if cached:
                finished = dt.datetime.utcnow()
                elapsed = time.perf_counter() - t0
                res = TaskResult(
                    node_id=node.id,
                    status="succeeded",
                    started_at=started,
                    finished_at=finished,
                    attempts=0,
                    output=value,
                    error=None,
                    elapsed_seconds=elapsed,
                    from_cache=True,
                    upstream_fingerprint=upstream_fpr,
                )
                if self._metrics:
                    with contextlib.suppress(Exception):
                        self._metrics.on_node_end(node.id, res.status, res.elapsed_seconds, res.attempts)
                return res

        # Вызов с ретраями и таймаутом
        attempts = 0
        last_exc: Optional[BaseException] = None
        while attempts < max(1, node.retry.max_attempts):
            attempts += 1
            try:
                result = await self._call_task(node.func, ctx=ctx, upstream=upstream, inputs=inputs, timeout=node.timeout.seconds)
                # Проверка retry_on_result
                if node.retry.retry_on_result and node.retry.retry_on_result(result):
                    raise RetryableResult("retry_on_result predicate matched")
                # Успех
                finished = dt.datetime.utcnow()
                elapsed = time.perf_counter() - t0
                res = TaskResult(
                    node_id=node.id,
                    status="succeeded",
                    started_at=started,
                    finished_at=finished,
                    attempts=attempts,
                    output=result,
                    error=None,
                    elapsed_seconds=elapsed,
                    from_cache=False,
                    upstream_fingerprint=upstream_fpr,
                )
                # Кладём в кэш
                if node.cacheable:
                    cache_key = f"node:{node.id}:fp:{upstream_fpr}"
                    await self._cache.set(cache_key, result, node.cache_ttl_seconds)
                if self._metrics:
                    with contextlib.suppress(Exception):
                        self._metrics.on_node_end(node.id, res.status, res.elapsed_seconds, attempts)
                return res
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                last_exc = exc
                # Проверяем, ретраится ли
                if not isinstance(exc, node.retry.retry_on):
                    break
                if attempts >= node.retry.max_attempts:
                    break
                backoff = node.retry.next_backoff(attempts)
                await asyncio.sleep(backoff)

        # Неудача
        finished = dt.datetime.utcnow()
        elapsed = time.perf_counter() - t0
        msg = repr(last_exc) if last_exc else "unknown_error"
        res = TaskResult(
            node_id=node.id,
            status="failed",
            started_at=started,
            finished_at=finished,
            attempts=attempts,
            output=None,
            error=msg,
            elapsed_seconds=elapsed,
            from_cache=cache_hit,
            upstream_fingerprint=upstream_fpr,
        )
        if self._metrics:
            with contextlib.suppress(Exception):
                self._metrics.on_node_end(node.id, res.status, res.elapsed_seconds, attempts)
        return res

    async def _call_task(
        self,
        func: TaskFunc,
        *,
        ctx: ExecutionContext,
        upstream: Mapping[str, Any],
        inputs: Mapping[str, Any],
        timeout: Optional[float],
    ) -> Any:
        """Вызывает задачу, подставляя только поддерживаемые параметры и учитывая таймаут."""
        kwargs: Dict[str, Any] = {}
        sig = None
        try:
            sig = inspect.signature(func)  # type: ignore[arg-type]
        except Exception:
            sig = None

        supported = {"ctx": ctx, "upstream": upstream, "inputs": inputs}
        if sig:
            for name in supported:
                if name in sig.parameters:
                    kwargs[name] = supported[name]

        async def invoke() -> Any:
            if inspect.iscoroutinefunction(func):  # type: ignore[arg-type]
                return await func(**kwargs)  # type: ignore[misc]
            # синхронная функция — выполняем в default executor
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, functools.partial(func, **kwargs))  # type: ignore[misc]

        if timeout and timeout > 0:
            return await asyncio.wait_for(invoke(), timeout=timeout)
        return await invoke()

    def _fingerprint(self, node: Node, upstream: Mapping[str, Any], inputs: Mapping[str, Any]) -> str:
        if node.fingerprint:
            return node.fingerprint(node_id=node.id, upstream_results=upstream, inputs=inputs)
        # Дет. сериализация JSON для отпечатка
        def _normalize(obj: Any) -> Any:
            if isinstance(obj, (str, int, float, bool)) or obj is None:
                return obj
            if isinstance(obj, Mapping):
                return {k: _normalize(obj[k]) for k in sorted(obj)}
            if isinstance(obj, (list, tuple)):
                return [_normalize(x) for x in obj]
            # Фоллбек на строковое представление
            return repr(obj)

        payload = {"node": node.id, "upstream": _normalize(upstream), "inputs": _normalize(inputs)}
        blob = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @staticmethod
    def _make_skipped(nid: str, reason: str) -> TaskResult:
        now = dt.datetime.utcnow()
        return TaskResult(
            node_id=nid,
            status="skipped",
            started_at=now,
            finished_at=now,
            attempts=0,
            output=None,
            error=reason,
            elapsed_seconds=0.0,
        )

    @staticmethod
    def _make_failed(nid: str, started_at: dt.datetime, reason: str) -> TaskResult:
        now = dt.datetime.utcnow()
        return TaskResult(
            node_id=nid,
            status="failed",
            started_at=started_at,
            finished_at=now,
            attempts=1,
            output=None,
            error=reason,
            elapsed_seconds=(now - started_at).total_seconds(),
        )


# =========================
# Utilities
# =========================

class RetryableResult(RuntimeError):
    """Исключение для повторов при неудовлетворительном результате."""


class AsyncMultiSemaphore:
    """Контекст для атомарного захвата/освобождения нескольких семафоров."""
    def __init__(self, semaphores: Iterable[asyncio.Semaphore]) -> None:
        self._sems = list(semaphores)

    async def __aenter__(self) -> "AsyncMultiSemaphore":
        # Стабильный порядок, чтобы уменьшить дедлоки
        for s in sorted(self._sems, key=lambda x: id(x)):
            await s.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        for s in self._sems:
            s.release()


# =========================
# Example (commented)
# =========================
# async def main():
#     async def prepare(ctx):
#         ctx.logger.info("prepare")
#         return {"ts": dt.datetime.utcnow().isoformat()}
#
#     async def task_a(ctx, upstream):
#         await asyncio.sleep(0.1)
#         return f"a:{upstream['prepare']['ts']}"
#
#     def task_b(upstream, inputs):
#         return f"b:{upstream['prepare']['ts']}:{inputs.get('x', 0)}"
#
#     g = Graph()
#     g.add(Node("prepare", prepare, cacheable=True, cache_ttl_seconds=60))
#     g.add(Node("a", task_a, needs={"prepare"}, timeout=TimeoutPolicy(2)))
#     g.add(Node("b", task_b, needs={"prepare"}, retry=RetryPolicy(max_attempts=2)))
#     orch = Orchestrator(concurrency=ConcurrencyPolicy(global_limit=2, per_tag_limits={"io": 1}))
#     res = await orch.run(g, inputs={"x": 42})
#     for nid, r in res.results.items():
#         print(nid, r.status, r.output)
#
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     asyncio.run(main())

__all__ = [
    "Node",
    "Graph",
    "ExecutionContext",
    "TaskResult",
    "GraphResult",
    "RetryPolicy",
    "TimeoutPolicy",
    "ConcurrencyPolicy",
    "CacheBackend",
    "InMemoryTTLCache",
    "Event",
    "MetricsSink",
    "EventSubscriber",
    "Orchestrator",
    "RetryableResult",
]
