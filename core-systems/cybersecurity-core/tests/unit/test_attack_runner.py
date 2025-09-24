# cybersecurity-core/tests/unit/test_attack_runner.py
# -*- coding: utf-8 -*-
"""
Промышленный набор unit-тестов для раннера эмуляции противника.

Ключевые свойства:
- Безопасные (benign) тесты: не требуют сети, прав администратора и не создают долговременных артефактов.
- Мягкая привязка к API: через pytest.importorskip и интроспекцию сигнатур.
- Устойчивость к эволюции: тесты подстраиваются под названия аргументов run(profile|profile_id|profile_path|plan).
- Валидируют: загрузку профиля, dry-run guardrails, порядок процедур, интерполяцию переменных, ролбэк на сбое.
"""

from __future__ import annotations

import inspect
import io
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest
import yaml

# ---------------------------------------------------------------------------
# Мягкая загрузка модуля раннера (если нет — пропускаем весь файл тестов).
# ---------------------------------------------------------------------------

runner_mod = pytest.importorskip(
    "cybersecurity.adversary_emulation.attack_simulator.runner",
    reason="Модуль раннера не найден; пропуск набора тестов."
)

# Попытка вытащить ожидаемые сущности; если нет — тесты адаптируются.
AttackRunner = getattr(runner_mod, "AttackRunner", None)
RunnerConfig = getattr(runner_mod, "RunnerConfig", None)
AttackRunnerError = getattr(runner_mod, "AttackRunnerError", Exception)

if AttackRunner is None:
    pytest.skip("AttackRunner отсутствует в модуле раннера.", allow_module_level=True)

# ---------------------------------------------------------------------------
# Вспомогательные функции для адаптации к API
# ---------------------------------------------------------------------------

def _supports_kw(obj: Any, name: str) -> bool:
    """Проверяет, поддерживает ли вызываемый объект именованный аргумент."""
    try:
        sig = inspect.signature(obj)
    except (TypeError, ValueError):
        return False
    return any(p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD) and p.name == name
               for p in sig.parameters.values())

def _filter_kwargs(callable_obj, **kwargs) -> Dict[str, Any]:
    """Оставляет только те kwargs, которые реально поддерживаются сигнатурой."""
    try:
        sig = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return {}
    allowed = {}
    for name, val in kwargs.items():
        if name in sig.parameters:
            allowed[name] = val
    return allowed

def _call_run(runner_inst, profile_path: Path, variables: Optional[Dict[str, Any]] = None):
    """
    Унифицированный вызов run(...) с поддержкой разных сигнатур:
    - run(profile=...), run(profile_path=...), run(profile_id=...), run(plan=...)
    - variables / context / params
    Возвращает кортеж (result, invoked_arg_name).
    """
    candidates = ("profile", "profile_path", "path", "profile_id", "plan")
    kwargs = {}
    for name in candidates:
        if _supports_kw(runner_inst.run, name):
            kwargs[name] = str(profile_path)
            invoked = name
            break
    else:
        # Падает обратно на позиционный вызов, если есть.
        try:
            return runner_inst.run(str(profile_path)), "<positional>"
        except TypeError as e:
            raise AssertionError("Не удалось подобрать способ вызвать run(...)") from e

    # Переменные:
    var_names = ("variables", "context", "params")
    for vn in var_names:
        if _supports_kw(runner_inst.run, vn) and variables is not None:
            kwargs[vn] = variables
            break

    kwargs = _filter_kwargs(runner_inst.run, **kwargs)
    return runner_inst.run(**kwargs), invoked

def _extract_dictish(obj: Any) -> Dict[str, Any]:
    """
    Превращает результат в словарь, по возможности.
    Поддерживает dict, dataclass-like (через __dict__), pydantic-like (dict()).
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "dict") and callable(obj.dict):
        try:
            return obj.dict()  # type: ignore[call-arg]
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    # Последняя попытка: JSON через __str__
    try:
        return json.loads(str(obj))
    except Exception:
        return {}

# ---------------------------------------------------------------------------
# Базовый безопасный профиль YAML для тестов
# ---------------------------------------------------------------------------

BENIGN_PROFILE_YAML = """\
schema_version: "1.0"
profile:
  id: "windows_enterprise"
  name: "Windows Enterprise - Benign"
  version: "1.0.0"
  safety_mode: "benign"
  description: "Безопасная эмуляция: echo и чтение реестра (dry-run обязателен)."
requirements:
  os:
    platforms: ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"]
  privileges:
    run_as: "standard_user"
variables:
  benign_marker: "AETHERNOVA_TEST"
procedures:
  - id: "exec_cmd_benign"
    name: "T1059 - Command Interpreter (echo benign)"
    tactic: ["execution"]
    technique: { id: "T1059", name: "Command and Scripting Interpreter" }
    steps:
      - executor: "cmd"
        run: "cmd.exe /c echo %benign_marker%"
    expected_events:
      - channel: "Security"
        event_id: 4688
    cleanup: []
rollbacks:
  on_failure: []
reporting:
  artifacts_to_collect: []
"""

# Профиль, заставляющий один шаг упасть (для проверки ролбэков).
FAILING_PROFILE_YAML = """\
schema_version: "1.0"
profile:
  id: "windows_enterprise_fail"
  name: "Windows Enterprise - Negative Case"
  version: "1.0.0"
  safety_mode: "benign"
variables:
  benign_marker: "AETHERNOVA_TEST"
procedures:
  - id: "will_fail_step"
    name: "Intended to fail"
    tactic: ["execution"]
    technique: { id: "T1059", name: "Command and Scripting Interpreter" }
    steps:
      - executor: "cmd"
        run: "this_command_definitely_does_not_exist_zzz"
    expected_events: []
    cleanup:
      - executor: "cmd"
        run: "echo cleanup"
rollbacks:
  on_failure:
    - executor: "cmd"
      run: "echo rollback_called"
reporting:
  artifacts_to_collect: []
"""

# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def tmp_profiles_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("profiles")
    return d

@pytest.fixture
def benign_profile_path(tmp_profiles_dir: Path) -> Path:
    p = tmp_profiles_dir / "windows_enterprise.yaml"
    p.write_text(BENIGN_PROFILE_YAML, encoding="utf-8")
    return p

@pytest.fixture
def failing_profile_path(tmp_profiles_dir: Path) -> Path:
    p = tmp_profiles_dir / "windows_enterprise_fail.yaml"
    p.write_text(FAILING_PROFILE_YAML, encoding="utf-8")
    return p

@pytest.fixture
def runner(benign_profile_path: Path) -> Any:
    """
    Конструирует AttackRunner. Предпочтительно включает dry_run и safety_mode=benign,
    если эти аргументы поддерживаются.
    """
    # Предпочитаемые аргументы-значения:
    preferred_kwargs = dict(
        dry_run=True,
        safety_mode="benign",
        profile_search_paths=[str(benign_profile_path.parent)],
        profile_paths=[str(benign_profile_path.parent)],
        logger=None,
        max_concurrency=1,
    )

    # Вариант 1: через RunnerConfig, если он есть.
    if RunnerConfig is not None:
        cfg_kwargs = _filter_kwargs(RunnerConfig, **preferred_kwargs)
        try:
            cfg = RunnerConfig(**cfg_kwargs)
            # Вариант 1а: AttackRunner(config=...)
            if _supports_kw(AttackRunner, "config"):
                return AttackRunner(config=cfg)
            # Вариант 1б: AttackRunner(**cfg.__dict__)
            return AttackRunner(**_filter_kwargs(AttackRunner, **cfg.__dict__))
        except Exception:
            # Переходим к прямой инициализации без RunnerConfig
            pass

    # Вариант 2: прямая инициализация AttackRunner(**kwargs)
    kwargs = _filter_kwargs(AttackRunner, **preferred_kwargs)
    return AttackRunner(**kwargs)

# ---------------------------------------------------------------------------
# Тесты
# ---------------------------------------------------------------------------

def test_smoke_run_benign_profile(runner, benign_profile_path: Path):
    """
    Smoke: раннер должен уметь прогонять benign-профиль без исключений.
    Если раннер поддерживает dry_run — он должен быть включён.
    """
    # Проверка dry_run guardrail, если атрибут доступен.
    if hasattr(runner, "dry_run"):
        assert getattr(runner, "dry_run") is True, "Ожидалось dry_run=True для безопасных тестов"

    result, invoked = _call_run(runner, benign_profile_path, variables={"extra": "ok"})
    data = _extract_dictish(result)

    # Мягкие инварианты результата:
    # 1) Профиль отработал успешно (если поле есть).
    if "success" in data:
        assert data["success"] in (True, 1, "ok")
    # 2) В результате должен быть указан хотя бы идентификатор профиля/имя (если поле есть).
    possible_id_keys = ("profile_id", "profile", "id", "name")
    assert any(k in data for k in possible_id_keys), \
        f"Ожидался идентификатор профиля в результате (использован аргумент: {invoked})"

def test_profile_yaml_is_valid_yaml(benign_profile_path: Path):
    """
    Минимальная валидация: профиль парсится YAML-библиотекой и содержит ключевые разделы.
    """
    with benign_profile_path.open("r", encoding="utf-8") as f:
        y = yaml.safe_load(f)
    assert isinstance(y, dict)
    for key in ("schema_version", "profile", "procedures"):
        assert key in y, f"Отсутствует обязательный ключ: {key}"
    assert isinstance(y["procedures"], list) and len(y["procedures"]) >= 1

def test_order_of_procedures_preserved(runner, benign_profile_path: Path):
    """
    Если раннер возвращает результаты по процедурам, порядок должен совпадать с YAML.
    """
    with benign_profile_path.open("r", encoding="utf-8") as f:
        y = yaml.safe_load(f)
    expected_order = [p["id"] for p in y.get("procedures", [])]

    result, _ = _call_run(runner, benign_profile_path, variables={})
    data = _extract_dictish(result)

    # Ищем список результатов шагов/процедур в распространённых местах.
    candidates = (
        "procedures", "procedure_results", "steps", "executed_procedures", "results"
    )
    proc_list: Optional[List[Dict[str, Any]]] = None
    for c in candidates:
        v = data.get(c)
        if isinstance(v, list) and v and isinstance(v[0], (dict, object)):
            proc_list = v
            break

    if proc_list is None:
        pytest.skip("Раннер не возвращает детализированный список процедур — пропуск проверки порядка.")

    # Нормализуем идентификаторы процедур (id/name)
    def pid(item: Any) -> Optional[str]:
        if isinstance(item, dict):
            return item.get("id") or item.get("procedure_id") or item.get("name")
        if hasattr(item, "__dict__"):
            d = item.__dict__
            return d.get("id") or d.get("procedure_id") or d.get("name")
        return None

    got_order = [pid(p) for p in proc_list if pid(p)]
    # Проверяем, что последовательность сохраняет относительный порядок из YAML:
    # ожидаем, что got_order является надпоследовательностью expected_order.
    idx = 0
    for g in got_order:
        if idx < len(expected_order) and g == expected_order[idx]:
            idx += 1
    assert idx == len(expected_order), "Порядок процедур нарушен относительно YAML."

def test_variable_interpolation_present(runner, benign_profile_path: Path):
    """
    Переменные из секции variables должны быть доступны при исполнении.
    Мы не проверяем фактический запуск, только что раннер принял и отразил контекст.
    """
    variables = {"benign_marker": "AETHERNOVA_TEST", "extra": "value"}
    result, _ = _call_run(runner, benign_profile_path, variables=variables)
    data = _extract_dictish(result)

    # Часто раннер возвращает окончательный контекст/vars — проверим наличие хотя бы одного маркера.
    possible_ctx_keys = ("variables", "context", "params", "resolved_variables", "env")
    ctx = None
    for k in possible_ctx_keys:
        if k in data and isinstance(data[k], dict):
            ctx = data[k]
            break
    if ctx is None:
        pytest.skip("Раннер не экспонирует контекст переменных — пропуск проверки интерполяции.")
    assert ctx.get("benign_marker") == "AETHERNOVA_TEST"

@pytest.mark.timeout(10)
def test_failure_triggers_rollback_if_defined(runner, failing_profile_path: Path):
    """
    При преднамеренном сбое раннер должен попытаться выполнить cleanup/rollback.
    Тест устойчив: если раннер работает только в dry-run и не исполняет команд,
    он может вернуть статус сбоя без фактического запуска — валидируем наличие признаков ролбэка в структуре.
    """
    result, _ = _call_run(runner, failing_profile_path, variables=None)
    data = _extract_dictish(result)

    # Если есть общий success — он должен сигнализировать о сбое.
    if "success" in data:
        assert data["success"] in (False, 0, "fail"), "Ожидался общий сбой для сценария FAIL."

    # Ищем, выполнялся ли cleanup/rollback (по структуре/флагам/логам), без привязки к строкам.
    indicators = ("rollback", "rolled_back", "cleanup_executed", "on_failure_executed")
    if not any(k in data for k in indicators):
        pytest.skip("Раннер не отражает состояние ролбэка в результате.")
    # Если отражает — хотя бы один индикатор должен быть истинным/непустым.
    for k in indicators:
        v = data.get(k, None)
        if isinstance(v, (bool, int)) and v:
            break
        if isinstance(v, (list, dict)) and len(v) > 0:
            break
    else:
        pytest.fail("Структура результата не содержит подтверждения выполнения ролбэка/cleanup.")

def test_guardrails_benign_mode_enforced(runner):
    """
    Если раннер имеет safety_mode/guardrails, он должен быть в режиме 'benign' для тестов.
    """
    # safety_mode может быть полем инстанса или конфигурации.
    if hasattr(runner, "safety_mode"):
        assert str(getattr(runner, "safety_mode")).lower() == "benign"
    elif hasattr(runner, "config") and hasattr(getattr(runner, "config"), "safety_mode"):
        assert str(getattr(runner.config, "safety_mode")).lower() == "benign"
    else:
        pytest.skip("Раннер не экспонирует safety_mode — пропуск проверки guardrails.")

