# -*- coding: utf-8 -*-
"""
Unit-tests for OmniMind Planner Bridge.

Требования:
  - pytest
  - pytest-asyncio

Запуск:
  pytest -q tests/unit/test_planner.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from typing import Any, AsyncIterator, Mapping, Optional

import pytest

# ---------------------------
# Импорт тестируемого модуля
# ---------------------------

# Добавим корень репозитория в sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

BRIDGE = None
try:
    # Основной путь (как мы клали ранее)
    from ops.omnimind.orchestrator.planner_bridge import (
        PlannerBridge,
        PlanDTO,
        PlanValidationError,
        SecurityContext,
    )
    BRIDGE = "ops.omnimind.orchestrator.planner_bridge"
except Exception:
    # Альтернативный импорт, если структура иная
    from omnimind.orchestrator.planner_bridge import (
        PlannerBridge,
        PlanDTO,
        PlanValidationError,
        SecurityContext,
    )
    BRIDGE = "omnimind.orchestrator.planner_bridge"


# ---------------------------
# Дублеры клиентов Planner/Executor
# ---------------------------

class DummyPlannerClient:
    """
    Фейковый Planner: считает вызовы, умеет "падать" заданное число раз, возвращает name.
    Если в payload присутствует idempotency_key — используем его в name для стабильности.
    """
    def __init__(self, should_fail_times: int = 0):
        self.should_fail_times = int(should_fail_times)
        self._fail_count = 0
        self.calls = []  # сохраняем payload'ы

    async def create_plan(self, plan_payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append(plan_payload)
        if self._fail_count < self.should_fail_times:
            self._fail_count += 1
            raise RuntimeError("transient create_plan error")
        idem = plan_payload.get("idempotency_key") or "generated"
        return {"name": f"plans/{idem}"}


class DummyExecutorClient:
    """
    Фейковый Executor: открывает поток событий, при необходимости "падает" при старте указанное число раз.
    """
    def __init__(self, events: list[Mapping[str, Any]], fail_times: int = 0):
        self.events = list(events)
        self.fail_times = int(fail_times)
        self._attempts = 0

    async def execute_plan(
        self,
        name: str,
        *,
        override_params: Optional[Mapping[str, Any]] = None,
        override_execution: Optional[Mapping[str, Any]] = None,
        override_budget: Optional[Mapping[str, Any]] = None,
        trace: Optional[Mapping[str, Any]] = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        if self._attempts < self.fail_times:
            self._attempts += 1
            raise RuntimeError("stream open failed")

        async def _gen():
            for e in self.events:
                await asyncio.sleep(0)  # уступим планировщику
                yield e
        return _gen()


# ---------------------------
# Вспомогательные заготовки
# ---------------------------

def sample_raw_plan(n_steps: int = 2) -> dict:
    """
    Собирает минимальный валидный план: линейный пайплайн step_i -> step_{i+1}
    """
    steps = []
    edges = []
    for i in range(1, n_steps + 1):
        steps.append({
            "id": f"step_{i}",
            "type": "TOOL",
            "tool": "echo",
            "invocation": {
                "name": "echo",
                "inputs": {"text": f"hello_{i}"},
                "parameters": [{"key": "p", "value": i}],
            },
            "depends_on": [f"step_{i-1}"] if i > 1 else [],
            "labels": {"k": "v"},
        })
        if i > 1:
            edges.append({"from": f"step_{i-1}", "to": f"step_{i}"})
    return {
        "steps": steps,
        "edges": edges,
        "params": {"foo": "bar"},
        "labels": {"plan": "demo"},
        "budget": {"max_steps": n_steps},
        "execution_policy": {"max_parallel": 2, "fail_fast": False},
    }


@pytest.fixture
def fast_sleep(monkeypatch):
    async def _fast_sleep(sec):
        return None
    monkeypatch.setattr(asyncio, "sleep", _fast_sleep)


# ---------------------------
# Тесты нормализации и валидации
# ---------------------------

@pytest.mark.asyncio
async def test_normalize_and_validate_ok():
    planner = DummyPlannerClient()
    executor = DummyExecutorClient(events=[])
    bridge = PlannerBridge(planner_client=planner, executor_client=executor)

    raw = sample_raw_plan(3)
    plan: PlanDTO = bridge.normalize_plan(raw, tenant_id="tenant-A", display_name="Demo", idempotency_key="idem-1")
    assert plan.tenant_id == "tenant-A"
    assert len(plan.steps) == 3
    assert len(plan.edges) == 2
    # валидация не должна бросать
    await bridge.validate_plan(plan)


@pytest.mark.asyncio
async def test_validate_cycle_detection():
    planner = DummyPlannerClient()
    executor = DummyExecutorClient(events=[])
    bridge = PlannerBridge(planner_client=planner, executor_client=executor)

    raw = sample_raw_plan(3)
    # Создадим цикл: step_3 -> step_1
    raw["edges"].append({"from": "step_3", "to": "step_1"})
    plan = bridge.normalize_plan(raw, tenant_id="t")
    with pytest.raises(PlanValidationError) as ei:
        await bridge.validate_plan(plan)
    assert "cycle detected" in str(ei.value)


@pytest.mark.asyncio
async def test_validate_missing_refs_and_limits():
    bridge = PlannerBridge(planner_client=DummyPlannerClient(), executor_client=DummyExecutorClient([]))
    raw = sample_raw_plan(2)
    # Неверная ссылка ребра
    raw["edges"].append({"from": "missing", "to": "step_2"})
    # Превысим бюджет по шагам
    raw["budget"]["max_steps"] = 1
    plan = bridge.normalize_plan(raw, tenant_id="t")
    with pytest.raises(PlanValidationError) as ei:
        await bridge.validate_plan(plan)
    msg = "; ".join(ei.value.reasons)
    assert "edge.from not found" in msg
    assert "budget.max_steps" in msg


@pytest.mark.asyncio
async def test_validate_label_length_and_type():
    bridge = PlannerBridge(planner_client=DummyPlannerClient(), executor_client=DummyExecutorClient([]))
    raw = sample_raw_plan(1)
    # Длинный ключ лейбла
    raw["steps"][0]["labels"] = {"k" * 80: "v"}
    plan = bridge.normalize_plan(raw, tenant_id="t")
    with pytest.raises(PlanValidationError) as ei:
        await bridge.validate_plan(plan)
    assert "label too long" in str(ei.value)

    # Неподдерживаемый тип шага
    raw2 = sample_raw_plan(1)
    raw2["steps"][0]["type"] = "SHELL"
    plan2 = bridge.normalize_plan(raw2, tenant_id="t")
    with pytest.raises(PlanValidationError) as ei2:
        await bridge.validate_plan(plan2)
    assert "unsupported step type" in str(ei2.value)


# ---------------------------
# Тесты создания плана и идемпотентности
# ---------------------------

@pytest.mark.asyncio
async def test_create_plan_idempotency_cache(fast_sleep):
    planner = DummyPlannerClient()
    executor = DummyExecutorClient(events=[])
    bridge = PlannerBridge(planner_client=planner, executor_client=executor)

    raw = sample_raw_plan(2)
    plan = bridge.normalize_plan(raw, tenant_id="t", idempotency_key="idem-42")
    await bridge.validate_plan(plan)

    created1 = await bridge.create_plan(plan)
    created2 = await bridge.create_plan(plan)  # должен отдать из кэша, не дергая клиент
    assert created1["name"].startswith("plans/")
    assert created2["name"] == created1["name"]
    # Клиент должен быть вызван ровно 1 раз
    assert len(planner.calls) == 1


@pytest.mark.asyncio
async def test_create_plan_with_retries_on_transient_errors(fast_sleep):
    # Первый и второй вызовы падают, третий успешен
    planner = DummyPlannerClient(should_fail_times=2)
    executor = DummyExecutorClient(events=[])
    bridge = PlannerBridge(planner_client=planner, executor_client=executor, create_retries=3, backoff_initial_ms=10)

    raw = sample_raw_plan(1)
    plan = bridge.normalize_plan(raw, tenant_id="t", idempotency_key="idem-R")
    await bridge.validate_plan(plan)

    created = await bridge.create_plan(plan)
    assert created["name"] == "plans/idem-R"
    assert len(planner.calls) == 3  # 2 ошибки + 1 успех


@pytest.mark.asyncio
async def test_signature_change_triggers_new_plan_creation(fast_sleep):
    planner = DummyPlannerClient()
    executor = DummyExecutorClient(events=[])
    bridge = PlannerBridge(planner_client=planner, executor_client=executor)

    raw = sample_raw_plan(1)
    plan1 = bridge.normalize_plan(raw, tenant_id="t", idempotency_key="idem-A")
    await bridge.validate_plan(plan1)
    c1 = await bridge.create_plan(plan1)

    # Изменим params — подпись плана изменится, должен создаться новый на стороне сервера
    raw2 = sample_raw_plan(1)
    raw2["params"]["foo"] = "baz"
    plan2 = bridge.normalize_plan(raw2, tenant_id="t", idempotency_key="idem-B")
    await bridge.validate_plan(plan2)
    c2 = await bridge.create_plan(plan2)

    assert c1["name"] != c2["name"]
    assert len(planner.calls) == 2


# ---------------------------
# Тесты исполнения и редактирования PII
# ---------------------------

@pytest.mark.asyncio
async def test_execute_plan_stream_and_redaction(fast_sleep):
    events = [
        {"delta": {"text": "User email is user@example.com and token sk-SECRETSECRETSECRET"}},
        {"delta": {"text": "All good"}},
    ]
    planner = DummyPlannerClient()
    executor = DummyExecutorClient(events=events)
    bridge = PlannerBridge(planner_client=planner, executor_client=executor)  # redact_logs=True по умолчанию

    # корректное имя плана
    name = "plans/test-1"
    got = []
    async for ev in bridge.execute_plan(name):
        got.append(ev)

    assert len(got) == 2
    first = got[0]["delta"]["text"]
    assert "example.com" not in first
    assert "sk-" in first and "SECRET" not in first  # токен отредактирован


@pytest.mark.asyncio
async def test_execute_plan_stream_no_redaction_when_disabled(fast_sleep):
    events = [{"delta": {"text": "Contact me at test@example.com"}}]
    bridge = PlannerBridge(
        planner_client=DummyPlannerClient(),
        executor_client=DummyExecutorClient(events=events),
        redact_logs=False,
    )
    got = []
    async for ev in bridge.execute_plan("plans/demo"):
        got.append(ev)
    assert "example.com" in got[0]["delta"]["text"]  # без редактирования


@pytest.mark.asyncio
async def test_execute_plan_retries_then_succeeds(fast_sleep):
    # Первый запуск stream падает, затем успешный
    executor = DummyExecutorClient(
        events=[{"delta": {"text": "ok"}}],
        fail_times=1,
    )
    bridge = PlannerBridge(
        planner_client=DummyPlannerClient(),
        executor_client=executor,
        execute_retries=2,
        backoff_initial_ms=10,
    )
    got = []
    async for ev in bridge.execute_plan("plans/retry-demo"):
        got.append(ev)
    assert len(got) == 1
    assert got[0]["delta"]["text"] == "ok"


@pytest.mark.asyncio
async def test_execute_invalid_plan_name_raises():
    bridge = PlannerBridge(planner_client=DummyPlannerClient(), executor_client=DummyExecutorClient([]))
    with pytest.raises(ValueError):
        async for _ in bridge.execute_plan("invalid/name"):
            pass


# ---------------------------
# Дополнительные негативные кейсы
# ---------------------------

@pytest.mark.asyncio
async def test_validation_too_many_steps():
    # max_steps по умолчанию 1000; сузим, чтобы спровоцировать ошибку
    bridge = PlannerBridge(planner_client=DummyPlannerClient(), executor_client=DummyExecutorClient([]), max_steps=2)
    raw = sample_raw_plan(3)
    plan = bridge.normalize_plan(raw, tenant_id="t")
    with pytest.raises(PlanValidationError) as ei:
        await bridge.validate_plan(plan)
    assert "too many steps" in str(ei.value)


@pytest.mark.asyncio
async def test_depends_on_missing_step():
    bridge = PlannerBridge(planner_client=DummyPlannerClient(), executor_client=DummyExecutorClient([]))
    raw = sample_raw_plan(2)
    raw["steps"][1]["depends_on"] = ["no_such_step"]
    plan = bridge.normalize_plan(raw, tenant_id="t")
    with pytest.raises(PlanValidationError) as ei:
        await bridge.validate_plan(plan)
    assert "references missing step" in str(ei.value)
