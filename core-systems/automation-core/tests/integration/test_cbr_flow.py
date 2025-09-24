# automation-core/tests/integration/test_cbr_flow.py
# SPDX-License-Identifier: MIT
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple, Literal

import pytest
import httpx


# ============================ Инфраструктура CBR ============================

class CircuitOpenError(RuntimeError):
    """Запрос заблокирован: circuit breaker в состоянии OPEN."""


State = Literal["CLOSED", "OPEN", "HALF_OPEN"]


@dataclass
class CBRMetrics:
    state: State
    failure_count: int
    success_count: int
    opened_at: Optional[float]
    half_open_at: Optional[float]


class CircuitBreaker:
    """
    Минимальный промышленный Circuit Breaker:
    - CLOSED: пропускает трафик, считает отказы
    - OPEN: блокирует до истечения recovery_timeout
    - HALF_OPEN: пробный запрос; успех -> CLOSE, ошибка -> OPEN
    """
    __slots__ = (
        "_failure_threshold",
        "_recovery_timeout",
        "_expected",
        "_time",
        "_state",
        "_failure_count",
        "_success_count",
        "_opened_at",
        "_half_open_at",
    )

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        recovery_timeout: float = 10.0,
        expected_exceptions: Tuple[type[BaseException], ...] = (httpx.HTTPError,),
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be > 0")
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._expected = expected_exceptions
        self._time = time_fn

        self._state: State = "CLOSED"
        self._failure_count = 0
        self._success_count = 0
        self._opened_at: Optional[float] = None
        self._half_open_at: Optional[float] = None

    # ------------------------------- API ---------------------------------

    def metrics(self) -> CBRMetrics:
        return CBRMetrics(
            state=self._state,
            failure_count=self._failure_count,
            success_count=self._success_count,
            opened_at=self._opened_at,
            half_open_at=self._half_open_at,
        )

    def call(self, func: Callable[[], httpx.Response]) -> httpx.Response:
        now = self._time()

        # Быстрый выход в OPEN
        if self._state == "OPEN":
            assert self._opened_at is not None
            if now - self._opened_at < self._recovery_timeout:
                raise CircuitOpenError("circuit is OPEN; cooldown not elapsed")
            # Переход в HALF_OPEN
            self._state = "HALF_OPEN"
            self._half_open_at = now

        try:
            resp = func()
            # 5xx считаем как отказ удалённого сервиса
            if 500 <= resp.status_code <= 599:
                raise httpx.HTTPStatusError(
                    f"Server error: {resp.status_code}",
                    request=resp.request,
                    response=resp,
                )
            self._record_success()
            return resp
        except self._expected as ex:
            self._record_failure()
            raise ex

    # --------------------------- Служебные методы -------------------------

    def _record_success(self) -> None:
        self._success_count += 1
        if self._state in ("HALF_OPEN", "OPEN"):
            # восстановление
            self._transition_close()
        else:
            # CLOSED остаётся, сбрасывать счётчик отказов не обязательно,
            # но безопаснее обнулить для классического поведения
            self._failure_count = 0

    def _record_failure(self) -> None:
        if self._state == "HALF_OPEN":
            # Немедленный возврат в OPEN
            self._transition_open()
            return

        self._failure_count += 1
        if self._failure_count >= self._failure_threshold:
            self._transition_open()

    def _transition_open(self) -> None:
        self._state = "OPEN"
        self._opened_at = self._time()
        self._half_open_at = None

    def _transition_close(self) -> None:
        self._state = "CLOSED"
        self._failure_count = 0
        self._opened_at = None
        self._half_open_at = None


# ========================== Утилиты для тестов =============================

class FakeClock:
    """Детерминированные «часы» для управления тайм-аутами без реального ожидания."""
    __slots__ = ("_t",)

    def __init__(self, start: float = 0.0) -> None:
        self._t = float(start)

    def __call__(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += float(seconds)


def flaky_handler_factory(n_failures: int, *, raise_timeout: bool = False) -> Callable[[httpx.Request], httpx.Response]:
    """
    Возвращает обработчик для httpx.MockTransport:
    - Первые n_failures запросов: 500 / либо исключение таймаута
    - Далее: 200 OK
    """
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] <= n_failures:
            if raise_timeout:
                raise httpx.TimeoutException("Simulated timeout")
            return httpx.Response(500, request=request, text="fail")
        return httpx.Response(200, request=request, text="ok")

    return handler


def cbr_request(
    client: httpx.Client,
    request: httpx.Request,
    *,
    breaker: CircuitBreaker,
    max_retries: int = 2,
) -> httpx.Response:
    """
    Синхронная CBR-обёртка:
    - CircuitBreaker контролирует подачу запроса
    - До max_retries дополнительный повтор при 5xx/Timeout
    """
    attempt = 0
    last_exc: Optional[Exception] = None

    while attempt <= max_retries:
        attempt += 1
        try:
            def do_call() -> httpx.Response:
                return client.send(request)
            return breaker.call(do_call)
        except (httpx.HTTPError, CircuitOpenError) as e:
            last_exc = e
            # CircuitOpenError не ретраим — он сигнализирует блок
            if isinstance(e, CircuitOpenError):
                break
            if attempt > max_retries:
                break
            # простая линейная задержка могла бы быть тут; тестам это не нужно
            continue

    assert last_exc is not None
    raise last_exc


# ============================== ТЕСТ-КЕЙСЫ =================================

def test_cbr_flow_opens_and_recovers():
    """
    1) 3 последовательных 5xx -> OPEN
    2) Следующий вызов до истечения cooldown -> CircuitOpenError, апстрим не вызывается
    3) По истечении cooldown -> HALF_OPEN; успешный запрос -> CLOSED
    """
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0, time_fn=clock)

    transport = httpx.MockTransport(flaky_handler_factory(n_failures=3))
    client = httpx.Client(transport=transport, timeout=1.0)

    req = client.build_request("GET", "https://svc.test/health")

    # 3 сбоя подряд -> OPEN
    with pytest.raises(httpx.HTTPStatusError):
        cbr_request(client, req, breaker=breaker, max_retries=0)
    with pytest.raises(httpx.HTTPStatusError):
        cbr_request(client, req, breaker=breaker, max_retries=0)
    with pytest.raises(httpx.HTTPStatusError):
        cbr_request(client, req, breaker=breaker, max_retries=0)

    m = breaker.metrics()
    assert m.state == "OPEN"
    assert m.failure_count == 3
    assert m.opened_at is not None

    # До истечения cooldown блокируем сразу
    with pytest.raises(CircuitOpenError):
        cbr_request(client, req, breaker=breaker, max_retries=0)

    # По истечении cooldown -> HALF_OPEN -> успешный запрос -> CLOSED
    clock.advance(10.0)
    resp = cbr_request(client, req, breaker=breaker, max_retries=0)
    assert resp.status_code == 200

    m2 = breaker.metrics()
    assert m2.state == "CLOSED"
    assert m2.failure_count == 0
    assert m2.success_count >= 1


def test_cbr_flow_retries_then_success():
    """
    Ретраи: первая попытка 5xx, вторая 200 -> успех без открытия брейкера.
    """
    transport = httpx.MockTransport(flaky_handler_factory(n_failures=1))
    client = httpx.Client(transport=transport, timeout=1.0)
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)

    req = client.build_request("GET", "https://svc.test/ping")
    resp = cbr_request(client, req, breaker=breaker, max_retries=2)
    assert resp.status_code == 200

    m = breaker.metrics()
    assert m.state == "CLOSED"
    # один отказ + один успех
    assert m.success_count >= 1
    assert m.failure_count == 0  # сброшен после успеха


def test_cbr_flow_timeout_counts_as_failure():
    """
    Таймаут считается отказом; после трех подряд таймаутов -> OPEN.
    """
    transport = httpx.MockTransport(flaky_handler_factory(n_failures=3, raise_timeout=True))
    client = httpx.Client(transport=transport, timeout=0.01)
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)

    req = client.build_request("GET", "https://svc.test/slow")
    with pytest.raises(httpx.TimeoutException):
        cbr_request(client, req, breaker=breaker, max_retries=0)
    with pytest.raises(httpx.TimeoutException):
        cbr_request(client, req, breaker=breaker, max_retries=0)
    with pytest.raises(httpx.TimeoutException):
        cbr_request(client, req, breaker=breaker, max_retries=0)

    m = breaker.metrics()
    assert m.state == "OPEN"
    assert m.failure_count == 3


def test_cbr_flow_metrics_snapshot_and_half_open_failure():
    """
    HALF_OPEN при неудаче возвращается в OPEN.
    """
    clock = FakeClock()
    # сначала 2 сбоя для быстрого открытия после третьего в HALF_OPEN
    transport = httpx.MockTransport(flaky_handler_factory(n_failures=10))  # всегда 500 первые 10
    client = httpx.Client(transport=transport, timeout=1.0)
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=5.0, time_fn=clock)

    req = client.build_request("GET", "https://svc.test/check")

    # два сбоя -> OPEN
    with pytest.raises(httpx.HTTPStatusError):
        cbr_request(client, req, breaker=breaker, max_retries=0)
    with pytest.raises(httpx.HTTPStatusError):
        cbr_request(client, req, breaker=breaker, max_retries=0)
    assert breaker.metrics().state == "OPEN"

    # Ждём восстановления -> HALF_OPEN, но апстрим всё ещё возвращает 500 -> снова OPEN
    clock.advance(5.0)
    with pytest.raises(httpx.HTTPStatusError):
        cbr_request(client, req, breaker=breaker, max_retries=0)

    m = breaker.metrics()
    assert m.state == "OPEN"
    assert m.opened_at is not None
    assert m.half_open_at is None  # после ошибки в HALF_OPEN вернулись в OPEN, half_open_at сброшен
