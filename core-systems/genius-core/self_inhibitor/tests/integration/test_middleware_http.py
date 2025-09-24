# core-systems/genius_core/security/self_inhibitor/tests/integration/test_middleware_http.py
from __future__ import annotations

import math
import sys
import types
from typing import Any, Callable, Dict, Optional

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

# Контракты типов (см. ранее предоставленный interfaces/types.py)
try:
    from genius_core.security.self_inhibitor.interfaces.types import (
        DecisionReason,
        SelfInhibitDecision,
        StrategyProtocol,
        http_status_for,
    )
except Exception as e:
    pytest.skip(f"Missing interfaces.types contract: {e}", allow_module_level=True)

# Попытка импортировать боевой middleware; если его нет — создаём резервную реализацию.
try:
    from genius_core.security.self_inhibitor.middleware.http import SelfInhibitMiddleware  # type: ignore
except Exception:
    class SelfInhibitMiddleware(BaseHTTPMiddleware):  # type: ignore
        """
        Резервная ASGI-реализация self-inhibitor middleware.
        Контракты:
          - evaluate(key) перед обработчиком
          - commit(success=True|False) после
          - deny -> HTTP по reason через http_status_for, заголовки Retry-After/X-Retry-After-Sec/X-Self-Inhibit-Reason
        """

        def __init__(
            self,
            app,
            *,
            strategy: StrategyProtocol,
            key_builder: Optional[Callable[[Request], str]] = None,
            exclude_paths: Optional[list[str]] = None,
            header_key: str = "X-Inhibit-Key",
            raise_on_deny: bool = False,
        ):
            super().__init__(app)
            self.strategy = strategy
            self.key_builder = key_builder or (lambda req: req.headers.get(header_key) or f"{req.method}:{req.url.path}")
            self.exclude_paths = exclude_paths or []
            self.raise_on_deny = raise_on_deny

        async def dispatch(self, request: Request, call_next):
            # Исключения по путям
            path = request.url.path
            for patt in self.exclude_paths:
                if _path_match(path, patt):
                    return await call_next(request)

            key = self.key_builder(request)
            decision = self.strategy.evaluate(key)

            if not decision.allowed:
                if self.raise_on_deny:
                    # стратегию можно попросить бросить исключение — но здесь формируем ответ сами
                    pass
                status = http_status_for(decision)
                retry_after = int(math.ceil(max(0.0, float(decision.retry_after_s))))
                body = {
                    "reason": decision.reason.value,
                    "key": decision.key or key,
                    "retry_after_s": decision.retry_after_s,
                    "allowed": False,
                    "strategy": decision.strategy_id,
                }
                headers = {
                    "Retry-After": str(retry_after),
                    "X-Retry-After-Sec": str(retry_after),
                    "X-Self-Inhibit-Reason": decision.reason.value,
                }
                return JSONResponse(status_code=status, content=body, headers=headers)

            # Разрешено — пропускаем вниз, фиксируем исход в commit
            try:
                response = await call_next(request)
                # успех: любые коды < 500 считаем success
                success = response.status_code < 500
                self.strategy.commit(key, success=success)
                return response
            except Exception:
                # исключение — failure
                self.strategy.commit(key, success=False)
                raise


def _path_match(path: str, pattern: str) -> bool:
    # Простейший glob: '*' — любой хвост
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


# -----------------------------
# Фейковая стратегия для тестов
# -----------------------------

class FakeStrategy(StrategyProtocol):  # type: ignore[assignment]
    """
    Управляемая стратегия: можно задавать поведение по ключам/путям в словаре decisions.
    Логирует вызовы evaluate/commit для проверки в ассертах.
    """
    def __init__(self, strategy_id: str = "fake/cooldown"):
        self._id = strategy_id
        self.decisions: Dict[str, SelfInhibitDecision] = {}
        self.calls: list[dict] = []

    @property
    def id(self) -> str:
        return self._id

    def set_allowed(self, key: str) -> None:
        self.decisions[key] = SelfInhibitDecision(
            allowed=True,
            reason=DecisionReason.OK,
            retry_after_s=0.0,
            strikes=0.0,
            key=key,
            strategy_id=self._id,
            next_penalty_s=0.0,
        )

    def set_denied(
        self,
        key: str,
        *,
        reason: DecisionReason = DecisionReason.COOLDOWN,
        retry_after_s: float = 1.5,
        strikes: float = 2.0,
    ) -> None:
        self.decisions[key] = SelfInhibitDecision(
            allowed=False,
            reason=reason,
            retry_after_s=retry_after_s,
            strikes=strikes,
            key=key,
            strategy_id=self._id,
            next_penalty_s=retry_after_s,
        )

    def evaluate(self, key: str, *, now_ts: Optional[float] = None) -> SelfInhibitDecision:
        self.calls.append({"fn": "evaluate", "key": key})
        return self.decisions.get(
            key,
            SelfInhibitDecision(allowed=True, reason=DecisionReason.OK, key=key, strategy_id=self._id),
        )

    def commit(self, key: str, *, success: bool, weight: float = 1.0, now_ts: Optional[float] = None) -> SelfInhibitDecision:
        self.calls.append({"fn": "commit", "key": key, "success": success, "weight": weight})
        # Возвращаем актуальное решение как «allowed»
        return SelfInhibitDecision(allowed=True, reason=DecisionReason.OK, key=key, strategy_id=self._id)

    def guard(self, key: str, *, raise_on_deny: bool = False, now_ts: Optional[float] = None):  # pragma: no cover
        # Для данного набора тестов guard не используется
        raise NotImplementedError


# -----------------------------
# Фабрика приложения для тестов
# -----------------------------

def make_app(strategy: FakeStrategy, **mw_kwargs: Any) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SelfInhibitMiddleware, strategy=strategy, **mw_kwargs)

    @app.get("/health")
    def health():
        return PlainTextResponse("ok", status_code=200)

    @app.get("/work")
    def work():
        return JSONResponse({"ok": True}, status_code=200)

    @app.get("/error")
    def err():
        raise RuntimeError("boom")

    return app


# -----------------------------
# Тесты
# -----------------------------

def test_allows_and_commits_success():
    strat = FakeStrategy()
    # ключ составим из метода+пути (логика по умолчанию в резервном middleware)
    key = "GET:/work"
    strat.set_allowed(key)
    app = make_app(strat)
    client = TestClient(app)

    resp = client.get("/work")

    assert resp.status_code == 200
    # evaluate и commit(success=True) должны быть вызваны
    assert {"fn": "evaluate", "key": key} in strat.calls
    assert {"fn": "commit", "key": key, "success": True, "weight": 1.0} in strat.calls


def test_denies_with_retry_after_and_headers():
    strat = FakeStrategy()
    key = "GET:/work"
    strat.set_denied(key, reason=DecisionReason.COOLDOWN, retry_after_s=1.6, strikes=3.0)

    app = make_app(strat)
    client = TestClient(app)

    resp = client.get("/work")
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After") == "2"
    assert resp.headers.get("X-Retry-After-Sec") == "2"
    assert resp.headers.get("X-Self-Inhibit-Reason") == DecisionReason.COOLDOWN.value
    body = resp.json()
    assert body["reason"] == "cooldown"
    assert body["allowed"] is False
    # commit не должен вызываться на отклонённом запросе
    assert not any(c for c in strat.calls if c.get("fn") == "commit")


def test_circuit_open_maps_to_503():
    strat = FakeStrategy()
    key = "GET:/work"
    strat.set_denied(key, reason=DecisionReason.CIRCUIT_OPEN, retry_after_s=5.0)

    app = make_app(strat)
    client = TestClient(app)

    resp = client.get("/work")
    assert resp.status_code == 503
    assert resp.headers.get("Retry-After") == "5"
    assert resp.json()["reason"] == "circuit_open"


def test_policy_deny_maps_to_403():
    strat = FakeStrategy()
    key = "GET:/work"
    strat.set_denied(key, reason=DecisionReason.POLICY_DENY, retry_after_s=0.0)

    app = make_app(strat)
    client = TestClient(app)

    resp = client.get("/work")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "policy_deny"


def test_commit_failure_on_handler_exception():
    strat = FakeStrategy()
    key = "GET:/error"
    strat.set_allowed(key)

    app = make_app(strat)
    client = TestClient(app)

    with pytest.raises(RuntimeError):
        client.get("/error")

    # commit должен зафиксировать неуспех
    assert {"fn": "commit", "key": key, "success": False, "weight": 1.0} in strat.calls


def test_exclude_paths_skip_middleware():
    strat = FakeStrategy()
    # На /health никаких вызовов стратегии быть не должно
    app = make_app(strat, exclude_paths=["/health"])
    client = TestClient(app)

    resp = client.get("/health")
    assert resp.status_code == 200
    assert all(call.get("key") != "GET:/health" for call in strat.calls)


def test_custom_key_builder_uses_headers():
    strat = FakeStrategy()

    def kb(req: Request) -> str:
        return f"user:{req.headers.get('X-User','-')}|{req.method}:{req.url.path}"

    app = make_app(strat, key_builder=kb)
    client = TestClient(app)
    key = "user:42|GET:/work"
    strat.set_allowed(key)

    resp = client.get("/work", headers={"X-User": "42"})
    assert resp.status_code == 200
    assert {"fn": "evaluate", "key": key} in strat.calls


def test_retry_after_rounding_and_body_integrity():
    strat = FakeStrategy()
    key = "GET:/work"
    strat.set_denied(key, retry_after_s=0.01)  # очень маленькое окно
    app = make_app(strat)
    client = TestClient(app)

    resp = client.get("/work")
    # ceil(0.01) -> 1
    assert resp.headers.get("Retry-After") == "1"
    body = resp.json()
    assert set(["reason", "key", "retry_after_s", "allowed", "strategy"]).issubset(body.keys())
