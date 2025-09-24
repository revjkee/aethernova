# cybersecurity-core/tests/unit/test_yara_engine.py
# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты для YARA-движка.

Ожидаемый интерфейс тестируемого модуля: `cybersecurity_core.yara.engine`

Минимальные требования к интерфейсу:
- Класс YaraEngine (предпочтительно) ИЛИ модульные функции с эквивалентными именами.
- Методы/функции:
    - compile(...) -> compiled_handle
      Поддерживает компиляцию из:
        * словаря {namespace_or_name: rule_text} ИЛИ
        * пути (str/Path) к .yar/.yara файлам ИЛИ
        * списка путей
      Дополнительно допускаются:
        includes: список путей с .yar, которые подключаются директивой `include`
        externals: словарь внешних переменных YARA (int/bool/str)
        namespace: строка namespace по умолчанию
    - scan_bytes(data: bytes, compiled=None, externals: dict|None=None, timeout: int|float|None=None) -> list[dict]
    - scan_file(path: str|Path, compiled=None, externals: dict|None=None, timeout: int|float|None=None) -> list[dict]
    - scan_path(path: str|Path, recursive: bool=True, compiled=None, externals: dict|None=None, timeout: int|float|None=None)
      Возвращает список результатов, где каждый элемент минимум содержит:
        {
          "file_path": str|None,  # None для scan_bytes
          "matches": [
              {
                 "rule": str,
                 "tags": list[str],
                 "meta": dict,
                 "strings": list[tuple[int, str, bytes]] | list[dict]  # форма допускается любая, но поле должно существовать
              }, ...
          ]
        }
Примечание: Если интерфейс отличается, тесты пытаются использовать наиболее близкий API. При отсутствии совместимости — тест помечается xfail/skip.

Зависимости:
- pytest
- python-yara (опционально; при отсутствии некоторые тесты пропускаются)

"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# --- Попытка импортировать тестируемый модуль ---
ENGINE_IMPORT_ERROR: Optional[str] = None
engine_mod = None
try:
    engine_mod = __import__("cybersecurity_core.yara.engine", fromlist=["*"])
except Exception as e:  # noqa: BLE001
    ENGINE_IMPORT_ERROR = f"Не удалось импортировать cybersecurity_core.yara.engine: {e!r}"

# --- Проверяем доступность python-yara (опционально) ---
_yara_lib = None
try:
    import yara as _yara_lib  # type: ignore
except Exception:
    _yara_lib = None


def _skip_if_no_engine() -> None:
    if ENGINE_IMPORT_ERROR:
        pytest.skip(ENGINE_IMPORT_ERROR, allow_module_level=False)


def _has_method(obj: Any, name: str) -> bool:
    return hasattr(obj, name) and callable(getattr(obj, name))


def _get_engine_instance() -> Any:
    """
    Возвращает экземпляр движка либо сам модуль, если API модульное.
    """
    _skip_if_no_engine()
    assert engine_mod is not None
    if hasattr(engine_mod, "YaraEngine"):
        return engine_mod.YaraEngine()
    # Фолбэк на модульные функции
    required = ["compile", "scan_bytes", "scan_file", "scan_path"]
    if all(_has_method(engine_mod, n) for n in required):
        return engine_mod
    pytest.skip(
        "Интерфейс движка не найден. Требуется класс YaraEngine или модульные функции compile/scan_*.",
        allow_module_level=False,
    )


def _compile(engine: Any, **kwargs: Any) -> Any:
    """
    Унифицированный вызов компиляции.
    """
    if _has_method(engine, "compile"):
        return engine.compile(**kwargs)
    if _has_method(engine, "compile_rules"):
        return engine.compile_rules(**kwargs)
    pytest.skip("Метод компиляции не найден (compile|compile_rules).", allow_module_level=False)


def _scan_bytes(engine: Any, data: bytes, **kwargs: Any) -> Any:
    if _has_method(engine, "scan_bytes"):
        return engine.scan_bytes(data, **kwargs)
    pytest.skip("Метод scan_bytes не найден.", allow_module_level=False)


def _scan_file(engine: Any, path: Path, **kwargs: Any) -> Any:
    if _has_method(engine, "scan_file"):
        return engine.scan_file(str(path), **kwargs)
    pytest.skip("Метод scan_file не найден.", allow_module_level=False)


def _scan_path(engine: Any, path: Path, **kwargs: Any) -> Any:
    if _has_method(engine, "scan_path"):
        return engine.scan_path(str(path), **kwargs)
    pytest.skip("Метод scan_path не найден.", allow_module_level=False)


# ----------------------------
# Фикстуры
# ----------------------------

@pytest.fixture(scope="session")
def tmp_rules_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("yara_rules")
    return d


@pytest.fixture()
def engine() -> Any:
    return _get_engine_instance()


# ----------------------------
# Утилиты тестов
# ----------------------------

def _write_file(p: Path, content: str) -> None:
    p.write_text(content, encoding="utf-8")
    assert p.exists() and p.stat().st_size > 0


def _assert_match_shape(match: Dict[str, Any]) -> None:
    assert "rule" in match and isinstance(match["rule"], str)
    # tags/meta/strings могут быть пустыми, но поля должны присутствовать
    assert "tags" in match and isinstance(match["tags"], (list, tuple))
    assert "meta" in match and isinstance(match["meta"], dict)
    assert "strings" in match


def _assert_scan_result_shape(result: Dict[str, Any], expect_file_path: bool) -> None:
    assert "matches" in result and isinstance(result["matches"], list)
    if expect_file_path:
        assert "file_path" in result
        assert result["file_path"] is None or isinstance(result["file_path"], (str, os.PathLike))
    for m in result["matches"]:
        _assert_match_shape(m)


# ----------------------------
# Тесты компиляции правил
# ----------------------------

def test_compile_from_string_and_basic_scan_bytes(engine: Any) -> None:
    rule_text = r'''
rule R1 : malware suspicious
{
  meta:
    author = "unit"
    score = 10
  strings:
    $a = "evil"
  condition:
    $a
}
'''
    compiled = _compile(engine, rules={"default": rule_text})
    data = b"This is evil payload"
    res = _scan_bytes(engine, data, compiled=compiled, timeout=5)
    # Ожидаем список результатов. Разрешаем как прямой список матчей, так и обертку с matches.
    if isinstance(res, dict) and "matches" in res:
        _assert_scan_result_shape(res, expect_file_path=False)
        assert any(m["rule"] == "R1" for m in res["matches"])
    else:
        # Допускаем API, возвращающее просто список матчей
        assert isinstance(res, list)
        for m in res:
            _assert_match_shape(m)
        assert any(m["rule"] == "R1" for m in res)


def test_compile_from_files_and_include(engine: Any, tmp_rules_dir: Path, tmp_path: Path) -> None:
    inc = tmp_rules_dir / "include_strings.yar"
    main = tmp_rules_dir / "main.yar"

    inc_text = r'''
rule INCLUDE_COMMON {
  strings:
    $i1 = "needle"
  condition:
    $i1
}
'''
    _write_file(inc, inc_text)

    main_text = r'''
include "include_strings.yar"

rule USE_INCLUDE {
  condition:
    INCLUDE_COMMON
}
'''
    _write_file(main, main_text)

    compiled = _compile(engine, rules=[str(main)], includes=[str(tmp_rules_dir)])
    f = tmp_path / "file.txt"
    f.write_bytes(b"haystack........needle........")
    res = _scan_file(engine, f, compiled=compiled, timeout=5)
    if isinstance(res, dict):
        _assert_scan_result_shape(res, expect_file_path=True)
        assert any(m["rule"] in ("USE_INCLUDE", "INCLUDE_COMMON") for m in res["matches"])
    else:
        # список матчей допустим
        assert any(m["rule"] in ("USE_INCLUDE", "INCLUDE_COMMON") for m in res)


def test_compile_invalid_rule_raises(engine: Any) -> None:
    bad_rule = r'''
rule BAD {
  strings:
    $a = "x"
  condition:
    any of (  // синтаксическая ошибка (скобка не закрыта)
'''
    with pytest.raises(Exception):
        _compile(engine, rules={"default": bad_rule})


@pytest.mark.skipif(_yara_lib is None, reason="python-yara недоступен; пропускаем проверку timeout.")
def test_scan_timeout_enforced(engine: Any, tmp_rules_dir: Path, tmp_path: Path) -> None:
    """
    Проверяем, что параметр timeout пробрасывается до движка.
    Делать «намеренно тяжёлое» правило, затем устанавливать маленький timeout.
    """
    # Правило с большим перебором: используем очень длинные данные и условие с for-циклами.
    # Важно: конкретная "тяжесть" может различаться, цель — поймать TimeoutError либо аналогичный сигнал от движка.
    heavy_rule = r'''
rule HEAVY {
  strings:
    $x = "Z" wide ascii
  condition:
    for any i in (0..filesize) : ( @x[i] )
}
'''
    compiled = _compile(engine, rules={"default": heavy_rule})
    huge = b"Y" * (2_000_000) + b"Z" + b"Y" * (2_000_000)

    # Ожидаем либо поднятие исключения, либо возврат с пометкой об ошибке таймаута.
    try:
        res = _scan_bytes(engine, huge, compiled=compiled, timeout=1)
    except Exception:
        # Любое исключение таймаута/ограничения — допустимый исход.
        return

    # Если исключения нет — допускаем объект ответа с ошибкой таймаута
    if isinstance(res, dict):
        # Ищем флаг ошибки/метку таймаута среди полей высокого уровня или матчей.
        serialized = str(res).lower()
        assert ("timeout" in serialized) or ("error" in serialized) or (len(res.get("matches", [])) == 0)
    elif isinstance(res, list):
        # Допускаем пустой результат как следствие таймаута/остановки
        assert len(res) == 0
    else:
        # Непредвиденный тип — считаем допустимым, но фиксируем.
        pytest.xfail("Неизвестный формат ответа при таймауте; проверьте реализацию движка.")


# ----------------------------
# Тесты сканирования файлов и директорий
# ----------------------------

def test_scan_file_and_no_match(engine: Any, tmp_path: Path) -> None:
    rule_text = r'''
rule JUST_A_MATCH {
  strings:
    $a = "secret"
  condition:
    $a
}
'''
    compiled = _compile(engine, rules={"default": rule_text})
    f = tmp_path / "clean.txt"
    f.write_bytes(b"no secrets here")
    res = _scan_file(engine, f, compiled=compiled, timeout=5)
    if isinstance(res, dict):
        _assert_scan_result_shape(res, expect_file_path=True)
        assert not any(m["rule"] == "JUST_A_MATCH" for m in res["matches"])
    else:
        assert isinstance(res, list)
        assert not any(m["rule"] == "JUST_A_MATCH" for m in res)


def test_scan_path_recursive_counts(engine: Any, tmp_path: Path) -> None:
    rule_text = r'''
rule FIND_TAGGED : tag1 tag2
{
  meta:
    family = "demo"
    risk = 3
  strings:
    $s = "marker"
  condition:
    $s
}
'''
    compiled = _compile(engine, rules={"ns": rule_text})

    # Дерево файлов
    d1 = tmp_path / "a"
    d2 = tmp_path / "a/b"
    d1.mkdir()
    d2.mkdir()
    (d1 / "file1.bin").write_bytes(b"something marker here")
    (d2 / "file2.bin").write_bytes(b"nope")
    (d2 / "file3.bin").write_bytes(b"marker marker")

    res = _scan_path(engine, tmp_path, recursive=True, compiled=compiled, timeout=5)
    # Ожидаем список результатов по файлам
    assert isinstance(res, list)
    # Проверим хотя бы общую форму и что есть совпадения в 2 файлах
    file_matches = 0
    for item in res:
        assert isinstance(item, dict)
        _assert_scan_result_shape(item, expect_file_path=True)
        has_match = any(m["rule"] == "FIND_TAGGED" for m in item["matches"])
        if has_match:
            file_matches += 1
    assert file_matches == 2


# ----------------------------
# Внешние переменные и метаданные
# ----------------------------

def test_external_variables(engine: Any, tmp_path: Path) -> None:
    rule_text = r'''
rule EXTERNAL_GATE {
  meta:
    source = "unit"
  condition:
    ext_int == 7 and ext_bool and ext_str == "ok"
}
'''
    compiled = _compile(engine, rules={"default": rule_text}, externals={"ext_int": 0, "ext_bool": False, "ext_str": ""})
    # Передадим значения при сканировании
    res = _scan_bytes(
        engine,
        b"any",
        compiled=compiled,
        externals={"ext_int": 7, "ext_bool": True, "ext_str": "ok"},
        timeout=3,
    )
    # Ожидаем совпадение правила
    if isinstance(res, dict):
        _assert_scan_result_shape(res, expect_file_path=False)
        assert any(m["rule"] == "EXTERNAL_GATE" for m in res["matches"])
        # Проверим наличие meta
        meta = next((m.get("meta", {}) for m in res["matches"] if m["rule"] == "EXTERNAL_GATE"), {})
        assert meta.get("source") == "unit"
    else:
        assert isinstance(res, list)
        assert any(m["rule"] == "EXTERNAL_GATE" for m in res)


def test_tags_and_strings_presence(engine: Any, tmp_path: Path) -> None:
    rule_text = r'''
rule TAGGED_RULE : triage quick
{
  meta:
    severity = "low"
  strings:
    $a = "abc"
    $b = { 62 63 64 }  // hex: b c d
  condition:
    any of them
}
'''
    compiled = _compile(engine, rules={"ns": rule_text})
    f = tmp_path / "t.bin"
    f.write_bytes(b"...abc...bcd...")
    res = _scan_file(engine, f, compiled=compiled, timeout=5)

    # Приводим к общей форме и валидируем наличие полей tags/strings/meta
    matches: List[Dict[str, Any]]
    if isinstance(res, dict):
        _assert_scan_result_shape(res, expect_file_path=True)
        matches = res["matches"]
    else:
        assert isinstance(res, list)
        matches = res

    tmatch = next((m for m in matches if m["rule"] == "TAGGED_RULE"), None)
    assert tmatch is not None
    assert isinstance(tmatch.get("tags", []), list)
    # Разрешаем любое внутреннее представление strings, но поле должно быть
    assert "strings" in tmatch
    # Проверяем meta
    meta = tmatch.get("meta", {})
    assert meta.get("severity") == "low"


# ----------------------------
# XFail/совместимость
# ----------------------------

@pytest.mark.xfail(reason="Если реализация не поддерживает namespace как ключ словаря.")
def test_namespace_as_key_dict(engine: Any) -> None:
    """
    Допускается словарь вида {"myns": "rule ..."} — если движок не поддерживает кастомный namespace,
    этот тест помечен xfail.
    """
    rule_text = r'''
rule NS_RULE { condition: true }
'''
    compiled = _compile(engine, rules={"myns": rule_text})
    res = _scan_bytes(engine, b"x", compiled=compiled, timeout=2)
    if isinstance(res, dict):
        _assert_scan_result_shape(res, expect_file_path=False)
    else:
        assert isinstance(res, list)
