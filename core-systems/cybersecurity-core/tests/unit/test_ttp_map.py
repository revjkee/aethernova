# -*- coding: utf-8 -*-
"""
Промышленная валидация карты TTP и модульных аннотаций __TTP__.

Назначение:
  1) Проверить целостность JSON-карты TTP (по умолчанию: cybersecurity/attack_library/ttp_map.json
     или путь из переменной окружения TTP_MAP_PATH).
  2) Проверить формат technique_id (T####(.###)?), корректность tactic по списку ATT&CK enterprise.
  3) Проверить дубликаты (technique_id + module), и общую консистентность полей.
  4) Проверить импортируемость модулей, объявленных в карте, и соответствие их аннотаций __TTP__.
  5) При отсутствии артефактов — информативно пропускать (pytest.skip), не валя весь пайплайн.

Зависимости: pytest (стандарт для unit-тестирования в Python).
Внешние источники не требуются; тест валидирует формат/контракт проекта.
"""

from __future__ import annotations

import json
import os
import re
import types
import importlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import pytest


# ----------------------------- Константы схемы ------------------------------

# Разрешённые тактики (Enterprise ATT&CK). При необходимости расширьте.
# Источник таксонов контролируется внутри проекта; внешние зависимости не требуются.
ENTERPRISE_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

# Разрешённые статусы реализации в проекте (примерный корпоративный стандарт).
ALLOWED_STATUS = {
    "planned",      # запланировано
    "simulated",    # эмуляция (безопасная)
    "implemented",  # реализовано (боевой модуль)
    "deprecated",   # снято с поддержки
}


# ------------------------------- Утилиты -------------------------------------

def _env_ttp_map_path() -> Path:
    """Определяет путь к JSON карте TTP. Предпочтительно из переменной окружения."""
    raw = os.environ.get("TTP_MAP_PATH")
    if raw:
        return Path(raw).expanduser().resolve()
    # Значение по умолчанию — внутри репозитория
    return Path("cybersecurity") / "attack_library" / "ttp_map.json"


def _load_json_if_exists(path: Path) -> Optional[List[Dict[str, Any]]]:
    """Грузит JSON (ожидается список объектов). Возвращает None, если файла нет."""
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise AssertionError("TTP map JSON must be a list of objects")
    return data


def _is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _uniq_key(entry: Dict[str, Any]) -> Tuple[str, str]:
    # Ключ уникальности — technique_id + module (пустой модуль маппим как "*")
    tid = str(entry.get("technique_id") or "").upper()
    mods = entry.get("modules") or []
    if not mods:
        return (tid, "*")
    # Для проверки дубликатов на уровне пары используем первый модуль,
    # Далее в отдельной проверке пройдёмся по всем модулям.
    return (tid, str(mods[0]))


def _iter_module_paths(entries: Iterable[Dict[str, Any]]) -> Iterable[str]:
    for e in entries:
        mods = e.get("modules") or []
        for m in mods:
            yield str(m)


def _import_module_safe(dotted: str) -> Optional[types.ModuleType]:
    try:
        return importlib.import_module(dotted)
    except Exception:
        return None


def _assert_ttp_annotation(mod: types.ModuleType, expected_tid: Optional[str] = None) -> None:
    """
    Проверяет наличие словаря __TTP__ в модуле.
    При наличии expected_tid сверяет technique_id.
    """
    assert hasattr(mod, "__TTP__"), f"Module {mod.__name__} must expose __TTP__"
    ttp = getattr(mod, "__TTP__")
    assert isinstance(ttp, dict), f"Module {mod.__name__}.__TTP__ must be dict"
    # Обязательные ключи
    for k in ("technique_id", "tactic", "name"):
        assert k in ttp and isinstance(ttp[k], str) and ttp[k].strip(), (
            f"Module {mod.__name__}.__TTP__ missing/invalid key: {k}"
        )
    # Формат technique_id
    tid = str(ttp["technique_id"]).upper()
    assert TECHNIQUE_ID_RE.match(tid), f"Module {mod.__name__}.__TTP__.technique_id invalid: {tid}"
    # Тактика
    tac = str(ttp["tactic"]).strip()
    assert tac in ENTERPRISE_TACTICS, f"Module {mod.__name__}.__TTP__.tactic not in ENTERPRISE_TACTICS: {tac}"
    # Сверка с ожидаемым из карты (если задана)
    if expected_tid:
        assert tid == expected_tid.upper(), (
            f"Module {mod.__name__}.__TTP__.technique_id '{tid}' "
            f"!= expected '{expected_tid.upper()}' from TTP map"
        )


# ------------------------------- Фикстуры ------------------------------------

@pytest.fixture(scope="session")
def ttp_map_path() -> Path:
    return _env_ttp_map_path()


@pytest.fixture(scope="session")
def ttp_entries(ttp_map_path: Path) -> List[Dict[str, Any]]:
    data = _load_json_if_exists(ttp_map_path)
    if data is None:
        pytest.skip(f"TTP map not found at {ttp_map_path}. Set TTP_MAP_PATH or add default file.")
    return data


# ------------------------------- Тесты карты ---------------------------------

def test_map_schema_and_values(ttp_entries: List[Dict[str, Any]]) -> None:
    """
    Базовая валидация схемы и значений.
    Поля entry:
      technique_id: str (T####(.###)?)
      tactic: str in ENTERPRISE_TACTICS
      name: str
      status: str in ALLOWED_STATUS
      references: list[str] (валидные URL, не пустой)
      modules: list[str] (dotted paths), допускается пустой список
      detection: list[str] (опционально)
      notes: str (опционально)
    """
    seen_pairs: set[Tuple[str, str]] = set()
    for idx, e in enumerate(ttp_entries):
        assert isinstance(e, dict), f"Entry #{idx} must be dict"

        # technique_id
        tid = str(e.get("technique_id") or "").upper()
        assert tid, f"Entry #{idx}: technique_id required"
        assert TECHNIQUE_ID_RE.match(tid), f"Entry #{idx}: invalid technique_id format: {tid}"

        # tactic
        tac = str(e.get("tactic") or "").strip()
        assert tac in ENTERPRISE_TACTICS, f"Entry #{idx}: tactic not allowed: {tac}"

        # name
        name = str(e.get("name") or "").strip()
        assert name, f"Entry #{idx}: name required"

        # status
        status = str(e.get("status") or "").strip() or "planned"
        assert status in ALLOWED_STATUS, f"Entry #{idx}: status not allowed: {status}"

        # references
        refs = e.get("references")
        assert isinstance(refs, list) and refs, f"Entry #{idx}: references must be non-empty list"
        for u in refs:
            assert isinstance(u, str) and _is_valid_url(u), f"Entry #{idx}: bad reference URL: {u}"

        # modules
        mods = e.get("modules", [])
        assert isinstance(mods, list), f"Entry #{idx}: modules must be list"
        for m in mods:
            assert isinstance(m, str) and m.strip(), f"Entry #{idx}: bad module dotted path: {m}"

        # detection (optional)
        det = e.get("detection", [])
        if det:
            assert isinstance(det, list), f"Entry #{idx}: detection must be list if present"
            for d in det:
                assert isinstance(d, str) and d.strip(), f"Entry #{idx}: empty detection entry"

        # notes (optional)
        notes = e.get("notes")
        if notes is not None:
            assert isinstance(notes, str), f"Entry #{idx}: notes must be string if present"

        # duplicates check by (technique_id + module)
        key = _uniq_key(e)
        assert key not in seen_pairs, f"Duplicate entry for key {key}"
        seen_pairs.add(key)


def test_declared_modules_are_importable(ttp_entries: List[Dict[str, Any]]) -> None:
    """
    Все модули, перечисленные в карте, должны импортироваться.
    Если модулей нет (пусто), тест пропускается для такой записи.
    """
    missing: List[str] = []
    for m in _iter_module_paths(ttp_entries):
        mod = _import_module_safe(m)
        if mod is None:
            missing.append(m)
    if missing:
        pytest.fail("Unimportable modules: " + ", ".join(sorted(set(missing))))


def test_module_ttp_annotations_match_map(ttp_entries: List[Dict[str, Any]]) -> None:
    """
    Каждая запись с указанными modules должна соответствовать __TTP__ внутри импортированного модуля.
    """
    problems: List[str] = []
    for e in ttp_entries:
        tid = str(e.get("technique_id") or "").upper()
        mods = e.get("modules") or []
        for dotted in mods:
            mod = _import_module_safe(dotted)
            if mod is None:
                problems.append(f"{dotted}: import failed")
                continue
            try:
                _assert_ttp_annotation(mod, expected_tid=tid)
            except AssertionError as ex:
                problems.append(f"{dotted}: {ex}")
    if problems:
        pytest.fail("TTP annotation mismatches:\n- " + "\n- ".join(problems))


def test_reference_urls_are_unique_per_entry(ttp_entries: List[Dict[str, Any]]) -> None:
    """
    Внутри одной записи ссылки не должны дублироваться (согласованность документации).
    """
    for idx, e in enumerate(ttp_entries):
        refs = e.get("references") or []
        if len(refs) != len(set(refs)):
            pytest.fail(f"Entry #{idx} has duplicate references")


def test_no_duplicate_module_associations(ttp_entries: List[Dict[str, Any]]) -> None:
    """
    Глобальная проверка: один и тот же модуль не должен быть привязан к конфликтующим technique_id.
    """
    per_mod: dict[str, set[str]] = {}
    for e in ttp_entries:
        tid = str(e.get("technique_id") or "").upper()
        for m in e.get("modules") or []:
            per_mod.setdefault(m, set()).add(tid)

    conflicts = {m: tids for m, tids in per_mod.items() if len(tids) > 1}
    if conflicts:
        lines = [f"{m}: {', '.join(sorted(tids))}" for m, tids in sorted(conflicts.items())]
        pytest.fail("Conflicting technique_id per module:\n- " + "\n- ".join(lines))


def test_map_file_reasonable_size(ttp_map_path: Path) -> None:
    """
    Страховка против случайной «раздутости» файла.
    Порог 5 МБ для JSON-карты (регулируется при необходимости).
    """
    if not ttp_map_path.exists():
        pytest.skip(f"TTP map not found at {ttp_map_path}")
    size = ttp_map_path.stat().st_size
    assert size < 5 * 1024 * 1024, f"TTP map is too large: {size} bytes"


def test_all_technique_ids_unique_globally(ttp_entries: List[Dict[str, Any]]) -> None:
    """
    Доп. ограничение: technique_id не должен объявляться с разными именами (name) в разных записях.
    Это предотвращает расхождения терминологии.
    """
    tid2name: dict[str, str] = {}
    problems: List[str] = []
    for e in ttp_entries:
        tid = str(e.get("technique_id") or "").upper()
        name = str(e.get("name") or "")
        prev = tid2name.get(tid)
        if prev is None:
            tid2name[tid] = name
        elif prev != name:
            problems.append(f"{tid}: '{prev}' vs '{name}'")
    if problems:
        pytest.fail("Technique name conflicts for same technique_id:\n- " + "\n- ".join(problems))
