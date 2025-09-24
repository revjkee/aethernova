# automation-core/src/automation_core/concurrency/thread_pool.py
"""
Industrial ThreadPool wrapper for Automation Core.

Key guarantees
--------------
- Backpressure: bounded in-flight submissions via threading.BoundedSemaphore.
- Context propagation: copy_context() per PEP 567; tasks run under caller's context.
- Cooperative cancellation: CancelToken for already-running tasks (Future.cancel()
  can't cancel running work; only pending tasks can be cancelled).  # Python docs
- Deterministic shutdown: mirrors Executor.shutdown(wait, cancel_futures)
  semantics; ensures semaphore is released when futures complete.
- Ergonomics: thread_name_prefix, optional initializer/initargs, typed API.

Authoritative references
------------------------
- concurrent.futures ThreadPoolExecutor (initializer, thread_name_prefix, shutdown with
  cancel_futures; Future.cancel()/result/TimeoutError).  # https://docs.python.org/3/library/concurrent.futures.html
- queue.Queue / thread-safety for inter-thread coordination.  # https://docs.python.org/3/library/queue.html
- PEP 567 / contextvars (copy_context, Context.run).  # https://peps.python.org/pep-0567/
- signal + threads (handlers только в главном потоке).  # https://docs.python.org/3/library/signal.html
- Logging cookbook (структурированное логирование).  # https://docs.python.org/3/howto/logging-cookbook.html
"""

from __future__ import annotations

import functools
import logging
import threading
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    TimeoutError as _FuturesTimeout,  # alias to avoid name clash
)
from contextvars import ContextVar, copy_context
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Sequence, Tuple, TypeVar

# Public contextvar for cooperative cancellation (available to task code)
CANCEL_TOKEN: ContextVar["CancelToken | None"] = ContextVar("automation_core_cancel_token", default=None)

T = TypeVar("T")
R = TypeVar("R")


class QueueFullError(RuntimeError):
    """Raised when submission is non-blocking and the pool's queue is full."""


@dataclass(frozen=True)
class SubmitOptions:
    """Optional controls for submit()."""
    block: bool = True
    timeout: Optional[float] = None
    cancellable: bool = False


class CancelToken:
    """
    Cooperative cancellation token for running tasks.

    Task code can poll token via contextvar `CANCEL_TOKEN.get()`, or receive the token
    explicitly if `inject_token=True` in submit(). The token is set once and never reset.
    """
    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._event.wait(timeout=timeout)


class ThreadPool:
    """
    Industrial wrapper around ThreadPoolExecutor.

    Notes:
    - Future.cancel() only cancels *pending* tasks; running tasks won't be interrupted
      and must cooperate via CancelToken.  # See Python docs
    - Signals are handled only in the main thread; use Events for inter-thread signalling.  # See Python docs
    """

    def __init__(
        self,
        *,
        max_workers: Optional[int] = None,
        queue_capacity: Optional[int] = None,
        thread_name_prefix: str = "automation-core",
        initializer: Optional[Callable[..., None]] = None,
        initargs: Sequence[Any] = (),
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Create a pool.

        Args:
            max_workers: at most this many threads (see Python docs default heuristic).
            queue_capacity: max number of *in-flight* tasks (pending + running) allowed
                beyond worker capacity; None -> unbounded submissions.
            thread_name_prefix: deterministic names aid debugging.
            initializer/initargs: run once per worker thread (Python >= 3.7).
        """
        self._log = logger or logging.getLogger(__name__)
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=thread_name_prefix,
            initializer=initializer,
            initargs=tuple(initargs),
        )  # docs: initializer, thread_name_prefix.  # noqa: E501
        self._closed = False
        # semaphore counts *submitted but not yet completed* tasks
        self._sem: Optional[threading.BoundedSemaphore]
        self._sem = threading.BoundedSemaphore(queue_capacity) if queue_capacity and queue_capacity > 0 else None
        self._lock = threading.RLock()

    # --------------------------- internal helpers ----------------------------

    def _acquire_slot(self, block: bool, timeout: Optional[float]) -> None:
        if self._sem is None:
            return
        ok = self._sem.acquire(blocking=block, timeout=timeout if block else 0)
        if not ok:
            raise QueueFullError("thread-pool queue is full")

    def _release_slot(self) -> None:
        if self._sem is None:
            return
        try:
            self._sem.release()
        except ValueError:
            # should never happen; guard against double-release
            self._log.warning("attempted to release more slots than acquired")

    @staticmethod
    def _wrap_callable(
        fn: Callable[..., R],
        args: Tuple[Any, ...],
        kwargs: dict,
        *,
        token: Optional[CancelToken],
    ) -> Callable[[], R]:
        """
        Produce a zero-arg callable that:
        - installs CancelToken into contextvar (if provided),
        - executes the user function.
        """
        def runner() -> R:
            tok_reset = None
            if token is not None:
                tok_reset = CANCEL_TOKEN.set(token)
            try:
                return fn(*args, **kwargs)
            finally:
                if tok_reset is not None:
                    CANCEL_TOKEN.reset(tok_reset)
        return runner

    # ------------------------------- API -------------------------------------

    def submit(
        self,
        fn: Callable[..., R],
        *args: Any,
        block: bool = True,
        timeout: Optional[float] = None,
        cancellable: bool = False,
        inject_token: bool = False,
        **kwargs: Any,
    ) -> Future[R]:
        """
        Submit task with optional backpressure and cooperative cancellation.

        Args:
            block: if False, raise QueueFullError immediately when queue is full.
            timeout: max seconds to wait for a submission slot when block=True.
            cancellable: create a CancelToken for cooperative cancellation.
            inject_token: if True and `cancellable`, pass token as kwarg `cancel_token`
                          to callable (in addition to contextvar).
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("ThreadPool is shut down")

        self._acquire_slot(block, timeout)

        # ensure we release slot if submission fails
        try:
            token = CancelToken() if cancellable else None
            if inject_token and token is not None:
                kwargs = dict(kwargs)
                # don't overwrite user-supplied cancel_token
                kwargs.setdefault("cancel_token", token)

            # capture caller context per PEP 567
            ctx = copy_context()

            work = self._wrap_callable(fn, args, kwargs, token=token)

            # run the callable under captured context
            def task() -> R:
                return ctx.run(work)

            fut: Future[R] = self._executor.submit(task)
        except Exception:
            self._release_slot()
            raise

        # Release slot when future finishes (done/cancelled/exception)
        def _on_done(_f: Future) -> None:
            self._release_slot()

        fut.add_done_callback(_on_done)

        # attach token for cooperative cancel
        if cancellable:
            setattr(fut, "_cancel_token", token)  # for cancel_running()

        return fut

    def cancel_running(self, fut: Future[Any]) -> bool:
        """
        Attempt to cooperatively cancel a *running* task by setting its CancelToken.
        Returns True if a token was present and set, otherwise False.

        Note: Future.cancel() cancels only *pending* tasks; this method exists to
        signal running tasks.  # See Python docs
        """
        tok = getattr(fut, "_cancel_token", None)
        if isinstance(tok, CancelToken):
            tok.cancel()
            return True
        return False

    def map(
        self,
        fn: Callable[[T], R],
        iterable: Iterable[T],
        *,
        block: bool = True,
        timeout: Optional[float] = None,
        cancellable: bool = False,
        inject_token: bool = False,
        return_futures: bool = False,
    ) -> Iterable[Future[R]] | Iterable[R]:
        """
        Submit a series with backpressure (one-by-one submission under semaphore).

        If return_futures=True, yields futures as they are submitted; otherwise,
        blocks and yields concrete results in order (propagates exceptions).
        """
        if return_futures:
            for item in iterable:
                yield self.submit(fn, item, block=block, timeout=timeout, cancellable=cancellable, inject_token=inject_token)
        else:
            futs = [self.submit(fn, item, block=block, timeout=timeout, cancellable=cancellable, inject_token=inject_token)
                    for item in iterable]
            # Wait for ordered results
            results: list[R] = []
            for f in futs:
                results.append(f.result())  # may raise, as per Python docs
            return results

    def shutdown(self, *, wait: bool = True, cancel_futures: bool = False) -> None:
        """
        Shut down the pool; mirrors Executor.shutdown semantics.

        - If cancel_futures=True, pending tasks are cancelled; running tasks complete.  # Python 3.9+
        - If wait=True, blocks until running tasks finish and resources are freed.      # Python docs
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)

    # Context manager convenience
    def __enter__(self) -> "ThreadPool":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # We wait; pending tasks will be cancelled only if caller passes cancel_futures explicitly elsewhere.
        self.shutdown(wait=True, cancel_futures=False)


# ------------------------------ Example usage ---------------------------------
# def work(n: int, *, cancel_token: CancelToken | None = None) -> int:
#     # cooperative cancel
#     for i in range(n):
#         if cancel_token and cancel_token.cancelled():
#             return -1
#         # do chunk...
#     return n
#
# with ThreadPool(max_workers=8, queue_capacity=64) as pool:
#     f = pool.submit(work, 10_000_000, cancellable=True, inject_token=True)
#     # later...
#     pool.cancel_running(f)  # cooperative signal
#     print(f.result())  # may return early per task logic
