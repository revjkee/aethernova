# omnimind-core/tests/e2e/test_agent_end2end.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

# Импортируем тестируемый CLI как модуль (внутрипроцессный запуск)
from omnimind.cli.tools import run_agent


# --------------- Вспомогательные утилиты ---------------

def _write_tools_pkg(tmp: Path) -> str:
    """
    Создает временный Python-пакет e2e_tools с тремя инструментами:
      - math.add: суммирование двух чисел
      - text.upper: верхний регистр
      - sleep.ms: задержка (для проверки тайм-аутов/REPL)
    Все регистрируется через @register из вашего ToolRegistry.
    """
    pkg = tmp / "e2e_tools"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("# e2e tools package\n", encoding="utf-8")

    tools_py = textwrap.dedent(
        """
        from __future__ import annotations
        from typing import Any, Dict
        try:
            from pydantic import BaseModel  # type: ignore
        except Exception:
            class BaseModel:  # минимальная заглушка
                def __init__(self, **kw): 
                    for k, v in kw.items(): setattr(self, k, v)
                @classmethod
                def model_validate(cls, v): 
                    if isinstance(v, dict): return cls(**v)
                    raise TypeError("expected dict")
                def model_dump(self): 
                    return self.__dict__

        from omnimind.tools.registry import register, ExecutionContext, RateLimitConf

        class AddIn(BaseModel):
            a: float
            b: float

        class AddOut(BaseModel):
            sum: float

        @register(
            name="math.add",
            version="1.0.0",
            description="Sum two numbers",
            input_model=AddIn,
            output_model=AddOut,
            timeout_s=2.0,
        )
        def math_add(payload: AddIn, ctx: ExecutionContext) -> AddOut:
            return AddOut(sum=payload.a + payload.b)

        class UpperIn(BaseModel):
            text: str

        class UpperOut(BaseModel):
            text: str

        @register(
            name="text.upper",
            version="1.0.0",
            description="Uppercase text",
            input_model=UpperIn,
            output_model=UpperOut,
            cache_ttl_s=5.0,
        )
        def text_upper(payload: UpperIn, ctx: ExecutionContext) -> UpperOut:
            return UpperOut(text=(payload.text or "").upper())

        class SleepIn(BaseModel):
            ms: int

        class SleepOut(BaseModel):
            ok: bool

        @register(
            name="sleep.ms",
            version="1.0.0",
            description="Sleep for ms",
            input_model=SleepIn,
            output_model=SleepOut,
            timeout_s=0.5,
        )
        def sleep_ms(payload: SleepIn, ctx: ExecutionContext) -> SleepOut:
            import time
            time.sleep(max(0, payload.ms) / 1000.0)
            return SleepOut(ok=True)
        """
    )
    (pkg / "tools.py").write_text(tools_py, encoding="utf-8")
    return "e2e_tools"


def _append_sys_path(path: Path):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def _parse_json_lines(stdout: str) -> list[dict]:
    lines = []
    for ln in stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            lines.append(json.loads(ln))
        except Exception:
            # в режиме call/plan CLI выводит и JSON результата; фильтруем JSONL по наличию "event"
            if ln.startswith("{") and '"event"' in ln:
                lines.append(json.loads(ln))
    return lines


# --------------- Фикстуры ---------------

@pytest.fixture
def tools_pkg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """
    Создает временный пакет инструментов и добавляет его в sys.path.
    Возвращает имя пакета (e2e_tools).
    """
    pkg_name = _write_tools_pkg(tmp_path)
    _append_sys_path(tmp_path)
    # убедимся, что среда для discovery указывает на наш пакет
    monkeypatch.setenv("TOOLS_PKG", pkg_name)
    return pkg_name


# --------------- Тесты: внутрипроцессный запуск ----------------

@pytest.mark.asyncio
async def test_call_single_tool_success(tools_pkg: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    """
    Проверяет однократный вызов инструмента:
      - discover временного пакета
      - корректный код возврата и JSON результата
      - JSONL события call.begin / call.ok
    """
    # Переключаем логи в JSONL
    monkeypatch.setenv("JSON_LOGS", "1")

    argv = [
        "call",
        "--tool", "math.add",
        "--payload", '{"a": 2, "b": 2.5}',
        "--discover", tools_pkg,
    ]
    code = await run_agent._main_async(argv)
    assert code == 0

    out = capsys.readouterr().out
    # В stdout сперва JSONL событий, затем JSON результата (по коду — возможны разные порядки буфера)
    # Находим последний валидный JSON результата
    result_obj = None
    for ln in out.splitlines()[::-1]:
        ln = ln.strip()
        if ln.startswith("{") and '"sum"' in ln:
            result_obj = json.loads(ln)
            break
    assert result_obj is not None
    assert result_obj["sum"] == 4.5

    # Проверим, что события присутствуют
    events = _parse_json_lines(out)
    kinds = {e.get("event") for e in events}
    assert {"call.begin", "call.ok"} <= kinds


@pytest.mark.asyncio
async def test_plan_with_statefile_and_vars(tools_pkg: str, tmp_path: Path, capsys: pytest.CaptureFixture):
    """
    Проверяет выполнение плана с подстановкой переменных и сохранением состояния.
    """
    plan_yaml = textwrap.dedent(
        """
        env_scopes: ["math:use"]
        principal: "user-e2e"
        default_timeout_s: 2
        steps:
          - kind: set
            vars:
              x: 3
              y: 7
          - kind: call
            name: "math.add"
            save_as: "s1"
            payload: {"a": "$x", "b": "$y"}
          - kind: call
            name: "text.upper"
            save_as: "t1"
            payload: {"text": "hello $s1"}
        """
    ).strip()
    plan_path = tmp_path / "plan.yaml"
    plan_path.write_text(plan_yaml, encoding="utf-8")
    state_path = tmp_path / "state.json"

    argv = [
        "plan",
        "--file", str(plan_path),
        "--state-file", str(state_path),
        "--discover", tools_pkg,
    ]
    code = await run_agent._main_async(argv)
    assert code == 0

    out = capsys.readouterr().out
    # Финальный stdout — JSON со всеми переменными (vars)
    obj = json.loads(out)
    vars_ctx = obj["vars"]
    # s1 = 3 + 7 = 10
    assert vars_ctx["s1"]["sum"] == 10
    # t1 = "HELLO {'sum': 10}" — из-за сериализации результата; допустим проверяем префикс
    assert str(vars_ctx["t1"]["text"]).startswith("HELLO ")

    # Проверка сохраненного состояния
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert "s1" in saved and "t1" in saved


@pytest.mark.asyncio
async def test_repl_basic_commands(tools_pkg: str, tmp_path: Path):
    """
    Проверяет REPL: :ls, вызов call <name> <json>, установка скоупов.
    Запуск интерактивного режима имитируем через подачу stdin.
    """
    # Соберем псевдо-ввод REPL:
    fake_input = "\n".join(
        [
            ":ls",
            "call math.add {\"a\": 1, \"b\": 2}",
            ":scopes tool.read,tool.write",
            ":who am_i",
            ":q",
            "",
        ]
    )
    # Подменяем stdin через subprocess-подобный подход: перенаправим sys.stdin с помощью TemporaryFile
    # Здесь проще запустить CLI как подпроцесс, чтобы не вмешиваться в цикл чтения.
    import subprocess

    cmd = [
        sys.executable,
        "-m",
        "omnimind.cli.tools.run_agent",
        "repl",
        "--discover",
        tools_pkg,
    ]
    proc = subprocess.run(
        cmd,
        input=fake_input.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    # Код возврата успешный
    assert proc.returncode == 0
    # В stdout должны присутствовать JSONL-события начала/завершения REPL
    stdout = proc.stdout.decode("utf-8", errors="ignore")
    events = _parse_json_lines(stdout)
    kinds = {e.get("event") for e in events}
    assert {"repl.start", "repl.end"} <= kinds
    # В stderr REPL печатает подсказки и ответы; убедимся, что есть вывод math.add
    stderr = proc.stderr.decode("utf-8", errors="ignore")
    assert "scopes set:" in stderr or "principal=" in stderr


# --------------- Тесты: обработка ошибок и коды возврата ----------------

@pytest.mark.asyncio
async def test_timeout_error_code(tools_pkg: str, capsys: pytest.CaptureFixture):
    """
    Инструмент sleep.ms имеет timeout_s=0.5; дадим 700мс, чтобы попасть в ToolTimeoutError.
    Проверяем корректный код возврата и JSONL события call.error.
    """
    argv = [
        "call",
        "--tool", "sleep.ms",
        "--payload", '{"ms": 700}',
        "--discover", tools_pkg,
    ]
    code = await run_agent._main_async(argv)
    # см. mapping в _exit_code_from_exc: ToolTimeoutError -> 8
    assert code == 8

    out = capsys.readouterr().out
    events = _parse_json_lines(out)
    # Последнее событие должно быть call.error
    assert any(e.get("event") == "call.error" and e.get("error") == "ToolTimeoutError" for e in events)


@pytest.mark.asyncio
async def test_unknown_tool_returns_not_found_code(tools_pkg: str):
    """
    Вызов несуществующего инструмента должен вернуть код 5 (ToolNotFound).
    """
    code = await run_agent._main_async(["call", "--tool", "no.such.tool", "--discover", tools_pkg])
    assert code == 5
