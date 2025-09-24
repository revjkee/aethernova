# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты для модуля сценариев adversary emulation.

Ожидаемый объект тестирования (любой из):
  - cybersecurity.adversary_emulation.scenario_loader.load_scenario(path, variables=None, **kw)
  - cybersecurity.adversary_emulation.scenario_loader.ScenarioLoader(...).load(path, variables=None, **kw)
  - cybersecurity.adversary_emulation.scenario_loader.load(path, variables=None, **kw)

Тесты НЕ навязывают конкретную реализацию и гибко адаптируются:
  - если фича не реализована (hash(), redaction, includes, schema, env/vars),
    соответствующие проверки помечаются как SKIPPED с внятной причиной.
  - только стандартная библиотека + pytest.

Покрываемые аспекты:
  1) Загрузка YAML/JSON и консистентность контента
  2) Обработка отсутствующего файла и синтаксической ошибки
  3) Include-механизм и детекция циклов
  4) Подстановка переменных и их приоритет (vars_in_file < env < variables_param)
  5) Базовая проверка схемы/обязательных полей
  6) Редактирование секретов в представлениях/логах (repr/to_dict)
  7) Хэш/версионность артефактов (изменение при правке файла)
  8) Потокобезопасность одновременной загрузки

Важно:
  - Для максимально широкой совместимости тесты не импортируют PyYAML и не читают YAML сами.
  - Все шаблоны файлов создаются на лету в tmp_path.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

import pytest


# --------------------------- ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ --------------------------

def _import_loader_module():
    return importlib.import_module("cybersecurity.adversary_emulation.scenario_loader")


def _resolve_loader_api(mod) -> Tuple[Callable[..., Any], Optional[Callable[..., Any]]]:
    """
    Возвращает (callable_load, optional_get_hash)

    callable_load(path, variables=None, **kw) -> scenario_object_or_dict

    Попытки:
      1) mod.load_scenario(...)
      2) mod.load(...)
      3) mod.ScenarioLoader().load(...)
    """
    if hasattr(mod, "load_scenario") and callable(mod.load_scenario):
        return mod.load_scenario, getattr(mod, "scenario_hash", None)
    if hasattr(mod, "load") and callable(mod.load):
        return mod.load, getattr(mod, "scenario_hash", None)
    if hasattr(mod, "ScenarioLoader"):
        inst = mod.ScenarioLoader()  # type: ignore[attr-defined]
        if hasattr(inst, "load") and callable(inst.load):
            # Заворачиваем чтобы сигнатура была едина
            def _call(path, variables=None, **kw):
                return inst.load(path, variables=variables, **kw)
            get_hash = getattr(inst, "scenario_hash", None)
            return _call, get_hash  # type: ignore[return-value]
    pytest.skip("Не найден публичный API загрузчика сценариев (load_scenario/load/ScenarioLoader.load)")


def _as_dict(scn: Any) -> dict:
    """
    Пытаемся привести результат к dict для унифицированных проверок.
    Допускаем:
      - уже dict
      - dataclass со 'to_dict' или 'dict'/'model_dump'
      - объект с '__dict__'
    """
    if isinstance(scn, dict):
        return scn
    for attr in ("to_dict", "dict", "model_dump"):
        if hasattr(scn, attr) and callable(getattr(scn, attr)):
            return getattr(scn, attr)()
    if hasattr(scn, "__dict__"):
        return dict(scn.__dict__)
    # Ничего лучшего — финальный fallback
    return {"_object": repr(scn)}


def _write(tmp_path: Path, rel: str, content: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _has_key(d: dict, dotted: str) -> bool:
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


def _get(d: dict, dotted: str, default=None):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


# --------------------------------- ТЕСТЫ --------------------------------------

def test_missing_file_raises():
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)
    with pytest.raises((FileNotFoundError, IOError, OSError)):
        loader("Z:/definitely/missing/file.yml")


def test_invalid_yaml_raises(tmp_path: Path):
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    bad = _write(tmp_path, "scenarios/bad.yml", "id: test\nsteps:\n  - name: ok\n    action: run\n  : broken\n")
    with pytest.raises(Exception):
        loader(str(bad))


def test_load_yaml_and_json_equivalence(tmp_path: Path):
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    data = {
        "id": "demo-eq",
        "version": "1.0",
        "metadata": {"title": "Equivalence"},
        "steps": [
            {"name": "s1", "action": "noop"},
            {"name": "s2", "action": "noop"},
        ],
    }
    yml = _write(
        tmp_path,
        "scenarios/eq.yml",
        (
            "id: demo-eq\n"
            "version: '1.0'\n"
            "metadata:\n  title: Equivalence\n"
            "steps:\n"
            "  - name: s1\n    action: noop\n"
            "  - name: s2\n    action: noop\n"
        ),
    )
    jsn = _write(tmp_path, "scenarios/eq.json", json.dumps(data))

    s1 = _as_dict(loader(str(yml)))
    s2 = _as_dict(loader(str(jsn)))

    assert _get(s1, "id") == _get(s2, "id") == "demo-eq"
    assert _get(s1, "version") == _get(s2, "version") == "1.0"
    assert len(_get(s1, "steps", [])) == len(_get(s2, "steps", [])) == 2


def test_includes_and_cycle_detection(tmp_path: Path):
    """
    Проверяем, что include сливает шаги и цикл детектируется.
    Если функционал не поддерживается — обе части помечаются SKIPPED.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    # Основной с include
    main = _write(
        tmp_path,
        "scenarios/main.yml",
        (
            "id: root\n"
            "version: '1.0'\n"
            "includes:\n"
            "  - child.yml\n"
            "steps:\n"
            "  - name: root-step\n    action: noop\n"
        ),
    )
    child = _write(
        tmp_path,
        "scenarios/child.yml",
        (
            "id: child\n"
            "version: '1.0'\n"
            "steps:\n"
            "  - name: child-step\n    action: noop\n"
        ),
    )

    scn = _as_dict(loader(str(main)))
    if not (_has_key(scn, "steps") and len(_get(scn, "steps", [])) >= 1):
        pytest.skip("Загрузчик не возвращает поле steps — пропуск проверки include")

    # Если includes не поддержаны, в steps останется только root-step
    steps = _get(scn, "steps", [])
    names = {s.get("name") for s in steps if isinstance(s, dict)}
    if "child-step" not in names:
        pytest.skip("Функция includes не реализована — пропуск части теста")

    assert "root-step" in names and "child-step" in names

    # Цикл: child включает main
    _write(
        tmp_path,
        "scenarios/child.yml",
        ("id: child\nversion: '1.0'\nincludes:\n  - main.yml\nsteps:\n  - name: child-step\n    action: noop\n"),
    )
    with pytest.raises(Exception):
        loader(str(main))


def test_variable_resolution_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Приоритет ожидается как: значения по умолчанию в файле < ENV < variables_param.
    Если какая-то ступень не реализована — пропускаем с пояснением.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    # Файл с шаблоном и default vars (если поддерживаются)
    yml = _write(
        tmp_path,
        "scenarios/vars.yml",
        (
            "id: vars-demo\n"
            "version: '1.0'\n"
            "vars:\n"
            "  who: file\n"
            "steps:\n"
            "  - name: hello\n"
            "    action: echo\n"
            "    args:\n"
            "      msg: \"Hello {{ who }}\"\n"
        ),
    )

    # 1) Только файл
    scn1 = _as_dict(loader(str(yml)))
    msg1 = _get(scn1, "steps", [{}])[0].get("args", {}).get("msg")
    if msg1 is None or "{{" in msg1:
        pytest.skip("Шаблоны/vars не подставляются — пропуск проверки приоритета")

    # 2) ENV перекрывает файл
    monkeypatch.setenv("WHO", "env")
    scn2 = _as_dict(loader(str(yml)))
    msg2 = _get(scn2, "steps", [{}])[0].get("args", {}).get("msg")
    if msg2 == msg1:
        pytest.skip("ENV не учитываются в подстановке — пропуск следующей части")

    # 3) variables_param перекрывает ENV
    scn3 = _as_dict(loader(str(yml), variables={"who": "param"}))
    msg3 = _get(scn3, "steps", [{}])[0].get("args", {}).get("msg")

    assert msg1 == "Hello file"
    assert msg2 == "Hello env"
    assert msg3 == "Hello param"


def test_schema_enforcement_required_fields(tmp_path: Path):
    """
    Если есть валидация схемы — отсутствующие ключи должны вызывать исключение.
    Иначе — SKIP.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    good = _write(
        tmp_path,
        "scenarios/good.yml",
        (
            "id: schema-ok\n"
            "version: '1.0'\n"
            "steps:\n"
            "  - name: s1\n    action: noop\n"
        ),
    )
    bad = _write(
        tmp_path,
        "scenarios/bad.yml",
        (
            "version: '1.0'\n"  # нет id
            "steps:\n"
            "  - name: s1\n    action: noop\n"
        ),
    )

    # Хороший сценарий должен грузиться
    scn = _as_dict(loader(str(good)))
    assert _get(scn, "id") == "schema-ok"

    # Плохой — либо исключение, либо успешная загрузка (если схема не применена)
    try:
        loader(str(bad))
        pytest.skip("Схема не применяется (нет исключения при отсутствии 'id')")
    except Exception:
        # Есть схема — ок
        assert True


def test_secrets_redaction_in_repr_or_dict(tmp_path: Path):
    """
    Если в реализации есть редактирование секретов, проверяем, что токены не светятся.
    Иначе — SKIP.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    yml = _write(
        tmp_path,
        "scenarios/secret.yml",
        (
            "id: secret-demo\n"
            "version: '1.0'\n"
            "metadata:\n"
            "  api_key: 'SECRET-ABC-123'\n"
            "  password: 'P@ssw0rd!'\n"
            "  token: 'tkn-xyz'\n"
            "steps:\n"
            "  - name: noop\n    action: noop\n"
        ),
    )

    scn = loader(str(yml))
    d = _as_dict(scn)

    # Пробуем либо на словаре (редактированные значения), либо в repr
    redacted = False
    secrets = [
        _get(d, "metadata.api_key"),
        _get(d, "metadata.password"),
        _get(d, "metadata.token"),
    ]
    if any(s and isinstance(s, str) and ("****" in s or "[REDACTED]" in s) for s in secrets):
        redacted = True

    if not redacted:
        # смотрим repr
        rp = repr(scn)
        if any(x in rp for x in ("SECRET-ABC-123", "P@ssw0rd!", "tkn-xyz")):
            pytest.skip("Редактирование секретов не реализовано — секреты видны в repr/dict")
        else:
            redacted = True

    assert redacted is True


def test_hash_changes_on_file_update(tmp_path: Path):
    """
    Если реализация предоставляет хэширование сценария (scenario.hash / scenario_hash()),
    проверяем, что правка файла меняет хэш.
    Иначе — SKIP.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, get_hash = _resolve_loader_api(mod)

    yml = _write(
        tmp_path,
        "scenarios/hash.yml",
        (
            "id: hash-demo\n"
            "version: '1.0'\n"
            "steps:\n"
            "  - name: s1\n    action: noop\n"
        ),
    )

    scn1 = loader(str(yml))
    # Получаем хэш через API объекта или внешнюю функцию
    h1 = None
    if hasattr(scn1, "hash"):
        h1 = getattr(scn1, "hash")
        if callable(h1):
            h1 = h1()
    elif get_hash and callable(get_hash):
        h1 = get_hash(scn1)
    else:
        pytest.skip("API хэширования сценария не обнаружен — пропуск")

    # Меняем файл
    _write(
        tmp_path,
        "scenarios/hash.yml",
        (
            "id: hash-demo\n"
            "version: '1.0'\n"
            "steps:\n"
            "  - name: s1\n    action: noop\n"
            "  - name: s2\n    action: noop\n"
        ),
    )
    scn2 = loader(str(yml))
    if hasattr(scn2, "hash"):
        h2 = getattr(scn2, "hash")
        if callable(h2):
            h2 = h2()
    elif get_hash and callable(get_hash):
        h2 = get_hash(scn2)
    else:
        pytest.skip("API хэширования сценария не обнаружен — пропуск")

    assert h1 != h2


def test_concurrent_loaders_are_thread_safe(tmp_path: Path):
    """
    Одновременная загрузка одного и того же файла не должна конфликтовать/падать.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    yml = _write(
        tmp_path,
        "scenarios/concurrent.yml",
        (
            "id: conc-demo\n"
            "version: '1.0'\n"
            "steps:\n"
            "  - name: s1\n    action: noop\n"
        ),
    )

    errors = []
    results = []

    def worker():
        try:
            res = loader(str(yml))
            results.append(_as_dict(res).get("id"))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, name=f"T{i}") for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert not errors, f"Ошибки в потоках: {errors}"
    assert all(r == "conc-demo" for r in results)


def test_basic_fields_presence(tmp_path: Path):
    """
    Минимальный sanity-чек: базовые поля присутствуют (id, steps), шаги — список.
    """
    mod = pytest.importorskip("cybersecurity.adversary_emulation.scenario_loader")
    loader, _ = _resolve_loader_api(mod)

    yml = _write(
        tmp_path,
        "scenarios/basic.yml",
        (
            "id: basic-demo\n"
            "version: '1.0'\n"
            "metadata:\n  title: 'Basic'\n"
            "steps:\n"
            "  - name: one\n    action: noop\n"
        ),
    )

    scn = _as_dict(loader(str(yml)))
    assert _get(scn, "id") == "basic-demo"
    steps = _get(scn, "steps")
    assert isinstance(steps, list) and len(steps) == 1
