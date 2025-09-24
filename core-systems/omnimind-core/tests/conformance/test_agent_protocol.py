import asyncio
import json
import types
from dataclasses import dataclass
from typing import Any, List, Optional

import pytest

# Тестируем публичный протокол и примерную реализацию
# Если модуль отсутствует — это нарушение конформанса примера.
from examples import agent_demo as M


# --------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФЕЙКИ
# --------------------------

@dataclass
class _FakeDoc:
    doc_id: str
    text: str
    source: Optional[str] = None
    namespace: str = "default"

@dataclass
class _FakeScored:
    doc: _FakeDoc
    score: float


class _FakeRetriever:
    """Минимальный ретривер, совместимый по интерфейсу с MemorySearchTool/Model."""
    def __init__(self, items: Optional[List[_FakeScored]] = None):
        self._items = items or [
            _FakeScored(_FakeDoc("d1", "OmniMind Core использует pgvector."), 0.91),
            _FakeScored(_FakeDoc("d2", "Retriever поддерживает MMR переранжирование."), 0.88),
        ]

    async def query(self, params: Any) -> List[_FakeScored]:  # params — совместимая структура (QueryParams)
        # Возвращаем заранее подготовленный список; фильтрация здесь не принципиальна для конформанса
        top_k = getattr(params, "top_k", 5)
        return self._items[:top_k]


# --------------------------
# ФИКСТУРЫ
# --------------------------

@pytest.fixture(scope="module")
def fake_retriever() -> _FakeRetriever:
    return _FakeRetriever()

@pytest.fixture(scope="module")
def tools(fake_retriever):
    return M.build_tools(fake_retriever)

@pytest.fixture(scope="module")
def tool_schema(tools):
    return M.tool_schemas(tools)

@pytest.fixture(scope="module")
def model(fake_retriever):
    return M.SimpleTemplateModel(retriever=fake_retriever)

@pytest.fixture(scope="module")
def agent(fake_retriever, tools):
    # Агент использует демонстрационную модель
    mdl = M.SimpleTemplateModel(retriever=fake_retriever)
    return M.Agent(model=mdl, tools=tools, retriever=fake_retriever, timeout_s=5.0, max_tool_hops=2)


# --------------------------
# ТЕСТЫ СХЕМ И ИНТЕРФЕЙСОВ
# --------------------------

def test_tool_schemas_shape(tool_schema):
    # Каждая схема — это {"type":"function","function":{"name":..., "parameters":{...}}}
    assert isinstance(tool_schema, list) and len(tool_schema) >= 3
    names = set()
    for entry in tool_schema:
        assert entry.get("type") == "function"
        fn = entry.get("function") or {}
        assert "name" in fn and isinstance(fn["name"], str) and fn["name"]
        assert "parameters" in fn and isinstance(fn["parameters"], dict)
        names.add(fn["name"])
    # Набор инструментов должен включать базовые
    assert {"calculator", "time_now", "memory_search"}.issubset(names)

@pytest.mark.asyncio
async def test_model_plans_calculator_tool(model, tools):
    schemas = M.tool_schemas(tools)
    msg = [{"role": "user", "content": "посчитай (2+2)*5"}]
    resp = await model.acomplete(msg, tools_schema=schemas)
    assert "tool_calls" in resp and isinstance(resp["tool_calls"], list) and resp["tool_calls"]
    tc = resp["tool_calls"][0]
    assert tc["type"] == "function"
    assert tc["function"]["name"] == "calculator"
    assert "expression" in tc["function"]["arguments"]

@pytest.mark.asyncio
async def test_calculator_tool_exec(tools):
    calc = next(t for t in tools if t.name == "calculator")
    out = await calc.run(expression="(2+2)*5")
    assert out["ok"] is True and out["result"] == 20

def test_calculator_is_safe():
    # Доступ к атрибутам/вызовам должен быть запрещен
    with pytest.raises(ValueError):
        M._safe_eval("__import__('os').system('echo PWN')")  # nosec
    with pytest.raises(ValueError):
        M._safe_eval("(1).__class__")
    with pytest.raises(ValueError):
        M._safe_eval("pow(2,10)")  # вызовы функций запрещены, даже если безопасны по смыслу
    # Слишком большие степени тоже запрещены
    with pytest.raises(ValueError):
        M._safe_eval("2**1000")

@pytest.mark.asyncio
async def test_memory_search_tool_with_fake_retriever(fake_retriever):
    tool = M.MemorySearchTool(retriever=fake_retriever)
    out = await tool.run(query="pgvector", top_k=1, namespace="docs")
    assert out["ok"] is True
    assert "items" in out and isinstance(out["items"], list) and len(out["items"]) == 1
    item = out["items"][0]
    assert {"doc_id", "text", "score", "namespace"}.issubset(item.keys())
    assert item["namespace"] == "default" or item["namespace"] == "docs"

@pytest.mark.asyncio
async def test_model_plans_memory_search(model, tools):
    schemas = M.tool_schemas(tools)
    msg = [{"role": "user", "content": "найди pgvector в памяти"}]
    resp = await model.acomplete(msg, tools_schema=schemas)
    names = [tc["function"]["name"] for tc in resp.get("tool_calls", [])]
    assert "memory_search" in names

@pytest.mark.asyncio
async def test_http_get_tool_without_httpx(monkeypatch):
    # Форсируем режим без httpx для детерминизма
    monkeypatch.setattr(M, "_HAVE_HTTPX", False, raising=False)
    tool = M.HttpGetTool()
    out = await tool.run(url="https://example.org", timeout_s=1)
    assert out["ok"] is False
    assert "httpx not installed" in out.get("error", "")

@pytest.mark.asyncio
async def test_agent_produces_final_answer(agent):
    # Агент должен возвращать финальную строку ответа, даже без tool_calls
    text = await agent.run("Расскажи в одном предложении, что такое Retriever.")
    assert isinstance(text, str) and len(text) > 0

@pytest.mark.asyncio
async def test_agent_tool_cycle(agent):
    # Агент должен уметь пройти цикл: спланировать калькулятор -> выполнить -> выдать финальный ответ
    text = await agent.run("сколько будет (10-3)*6?")
    assert isinstance(text, str) and len(text) > 0

def test_execute_tool_dispatch(tools):
    # Диспетчеризация по имени инструмента
    res_ok = asyncio.get_event_loop().run_until_complete(M.execute_tool(tools, "calculator", {"expression": "3*7"}))
    assert res_ok["ok"] and res_ok["result"] == 21
    res_fail = asyncio.get_event_loop().run_until_complete(M.execute_tool(tools, "no_such_tool", {}))
    assert res_fail["ok"] is False

def test_module_exports_and_contracts():
    # Базовые символы модуля должны существовать
    assert hasattr(M, "Agent")
    assert hasattr(M, "SimpleTemplateModel")
    assert hasattr(M, "build_tools")
    assert hasattr(M, "tool_schemas")
    assert hasattr(M, "execute_tool")
    # Проверка сигнатур через наличие атрибутов (минимальный контракт)
    assert callable(M.build_tools)
    assert callable(M.tool_schemas)
    assert callable(M.execute_tool)
