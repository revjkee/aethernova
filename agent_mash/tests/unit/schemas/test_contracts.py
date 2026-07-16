# agent_mash/tests/unit/schemas/test_contracts.py
from __future__ import annotations

import importlib
import inspect
import json
import os
import pkgutil
import re
import typing as t
from dataclasses import dataclass
from pathlib import Path

import pytest

Json = t.Dict[str, t.Any]


@dataclass(frozen=True, slots=True)
class ModelRef:
    module: str
    name: str


def _project_root() -> Path:
    """
    Находит корень репозитория относительно текущего файла теста.
    tests/unit/schemas/test_contracts.py -> project root (4 уровня вверх)
    """
    return Path(__file__).resolve().parents[4]


def _snapshots_dir() -> Path:
    return Path(__file__).resolve().parent / "snapshots"


def _read_env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = raw.strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


def _safe_filename(s: str) -> str:
    s = s.strip().replace("\\", ".").replace("/", ".")
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("._-")


def _try_import(module: str) -> t.Any:
    try:
        return importlib.import_module(module)
    except Exception:
        return None


def _discover_schema_packages() -> list[str]:
    """
    Пытается обнаружить пакет со схемами в типичных местах.
    Возвращает список пакетов-кандидатов.
    """
    candidates = [
        "agent_mash.schema",
        "agent_mash.schemas",
        "agent_mash.domain.schema",
        "agent_mash.domain.schemas",
    ]
    out: list[str] = []
    for m in candidates:
        mod = _try_import(m)
        if mod is not None and getattr(mod, "__path__", None) is not None:
            out.append(m)
    return out


def _iter_modules(package_name: str) -> t.Iterable[str]:
    pkg = importlib.import_module(package_name)
    pkg_path = getattr(pkg, "__path__", None)
    if pkg_path is None:
        return []
    for m in pkgutil.walk_packages(pkg_path, prefix=package_name + "."):
        yield m.name


def _is_pydantic_model(obj: t.Any) -> bool:
    """
    Определяет Pydantic-модель (v1/v2) без жёсткой зависимости.
    """
    if obj is None or not inspect.isclass(obj):
        return False
    # Pydantic v2: BaseModel имеет model_json_schema, model_validate, model_dump
    if hasattr(obj, "model_json_schema") and hasattr(obj, "model_validate") and hasattr(obj, "model_dump"):
        return True
    # Pydantic v1: BaseModel имеет schema, parse_obj, dict
    if hasattr(obj, "schema") and hasattr(obj, "parse_obj") and hasattr(obj, "dict"):
        return True
    return False


def _discover_models() -> list[ModelRef]:
    packages = _discover_schema_packages()
    if not packages:
        return []

    found: set[tuple[str, str]] = set()

    for pkg in packages:
        # включаем и сам пакет, и подмодули
        modules = [pkg, *list(_iter_modules(pkg))]
        for mod_name in modules:
            mod = _try_import(mod_name)
            if mod is None:
                continue
            for name, obj in vars(mod).items():
                if name.startswith("_"):
                    continue
                if _is_pydantic_model(obj):
                    found.add((mod_name, name))

    # сортировка для детерминизма
    return [ModelRef(module=m, name=n) for (m, n) in sorted(found, key=lambda x: (x[0], x[1]))]


def _get_model(ref: ModelRef) -> type:
    mod = importlib.import_module(ref.module)
    obj = getattr(mod, ref.name)
    if not _is_pydantic_model(obj):
        raise TypeError(f"{ref.module}.{ref.name} is not a Pydantic model")
    return t.cast(type, obj)


def _model_schema(model: type) -> Json:
    """
    Достаёт JSON Schema у Pydantic v2/v1.
    """
    if hasattr(model, "model_json_schema"):
        # Pydantic v2
        schema = model.model_json_schema()  # type: ignore[attr-defined]
        if not isinstance(schema, dict):
            raise TypeError("model_json_schema() must return dict")
        return t.cast(Json, schema)

    if hasattr(model, "schema"):
        # Pydantic v1
        schema = model.schema()  # type: ignore[attr-defined]
        if not isinstance(schema, dict):
            raise TypeError("schema() must return dict")
        return t.cast(Json, schema)

    raise RuntimeError("Unsupported Pydantic model interface")


def _deep_sort(obj: t.Any) -> t.Any:
    """
    Детерминированная сортировка словарей и списков, чтобы schema сравнивалась стабильно.
    """
    if isinstance(obj, dict):
        return {k: _deep_sort(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_deep_sort(x) for x in obj]
    return obj


def _normalize_schema(schema: Json) -> Json:
    """
    Нормализует schema для стабильных snapshot сравнения.
    Убирает очевидно несущественные/нестабильные поля (если встречаются).
    """
    schema = json.loads(json.dumps(schema, ensure_ascii=False))  # полная копия
    schema = t.cast(Json, _deep_sort(schema))

    # Часто нестабильны/не критичны:
    # - "title" в некоторых генерациях может меняться (зависит от алиасов/названий)
    # - "description" в некоторых проектах автогенерируется
    # Удаляем только если явно отмечено окружением.
    if _read_env_bool("SCHEMA_STRIP_TITLES", default=True):
        _strip_key_recursively(schema, "title")
    if _read_env_bool("SCHEMA_STRIP_DESCRIPTIONS", default=False):
        _strip_key_recursively(schema, "description")

    return schema


def _strip_key_recursively(obj: t.Any, key: str) -> None:
    if isinstance(obj, dict):
        if key in obj:
            obj.pop(key, None)
        for v in list(obj.values()):
            _strip_key_recursively(v, key)
    elif isinstance(obj, list):
        for x in obj:
            _strip_key_recursively(x, key)


def _snapshot_path(ref: ModelRef) -> Path:
    filename = _safe_filename(f"{ref.module}.{ref.name}.schema.json")
    return _snapshots_dir() / filename


def _write_json(path: Path, data: Json) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    path.write_text(raw + "\n", encoding="utf-8")


def _read_json(path: Path) -> Json:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise TypeError(f"Snapshot must be a JSON object: {path}")
    return t.cast(Json, data)


def _extract_examples(schema: Json) -> list[t.Any]:
    """
    Пытается достать примеры из JSON Schema.
    Поддерживает варианты:
      - schema["examples"]
      - schema["json_schema_extra"]["examples"] (в некоторых стилях)
      - schema["$defs"][...]["examples"] не разворачиваем, берём только верхний уровень
    """
    examples: list[t.Any] = []

    if isinstance(schema.get("examples"), list):
        examples.extend(schema["examples"])

    jse = schema.get("json_schema_extra")
    if isinstance(jse, dict) and isinstance(jse.get("examples"), list):
        examples.extend(jse["examples"])

    # Удаляем дубликаты по JSON-представлению
    seen: set[str] = set()
    uniq: list[t.Any] = []
    for ex in examples:
        try:
            key = json.dumps(ex, ensure_ascii=False, sort_keys=True)
        except Exception:
            key = repr(ex)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(ex)
    return uniq


def _validate_and_roundtrip(model: type, payload: t.Any) -> None:
    """
    Валидирует payload и проверяет сериализацию/десериализацию (Pydantic v1/v2).
    """
    if hasattr(model, "model_validate") and hasattr(model, "model_dump"):
        # Pydantic v2
        inst = model.model_validate(payload)  # type: ignore[attr-defined]
        dumped = inst.model_dump(mode="json")  # type: ignore[attr-defined]
        inst2 = model.model_validate(dumped)  # type: ignore[attr-defined]
        dumped2 = inst2.model_dump(mode="json")  # type: ignore[attr-defined]
        assert dumped2 == dumped
        return

    if hasattr(model, "parse_obj") and hasattr(model, "dict"):
        # Pydantic v1
        inst = model.parse_obj(payload)  # type: ignore[attr-defined]
        dumped = inst.dict()  # type: ignore[attr-defined]
        inst2 = model.parse_obj(dumped)  # type: ignore[attr-defined]
        dumped2 = inst2.dict()  # type: ignore[attr-defined]
        assert dumped2 == dumped
        return

    raise RuntimeError("Unsupported Pydantic model interface")


MODELS: list[ModelRef] = _discover_models()


@pytest.mark.skipif(not MODELS, reason="No schema packages/models discovered")
@pytest.mark.parametrize("ref", MODELS, ids=lambda r: f"{r.module}.{r.name}")
def test_schema_contract_snapshot(ref: ModelRef) -> None:
    """
    Контракт: JSON Schema модели должен совпадать с snapshot.
    Обновление snapshot допускается только при UPDATE_SNAPSHOTS=1.
    """
    model = _get_model(ref)
    schema = _normalize_schema(_model_schema(model))

    snap_path = _snapshot_path(ref)
    update = _read_env_bool("UPDATE_SNAPSHOTS", default=False)

    if update or not snap_path.exists():
        _write_json(snap_path, schema)

    expected = _read_json(snap_path)
    assert schema == expected


@pytest.mark.skipif(not MODELS, reason="No schema packages/models discovered")
@pytest.mark.parametrize("ref", MODELS, ids=lambda r: f"{r.module}.{r.name}")
def test_schema_examples_roundtrip(ref: ModelRef) -> None:
    """
    Контракт: если у схемы есть примеры, они должны валидироваться и проходить round-trip.
    """
    model = _get_model(ref)
    schema = _normalize_schema(_model_schema(model))
    examples = _extract_examples(schema)

    if not examples:
        pytest.skip("No examples in schema")

    for ex in examples:
        _validate_and_roundtrip(model, ex)


@pytest.mark.skipif(not MODELS, reason="No schema packages/models discovered")
def test_snapshots_directory_is_consistent() -> None:
    """
    Контракт: snapshots директория не содержит мусорных файлов и пустых json.
    """
    d = _snapshots_dir()
    if not d.exists():
        pytest.skip("No snapshots directory")

    for p in d.glob("*.json"):
        raw = p.read_text(encoding="utf-8").strip()
        assert raw, f"Empty snapshot file: {p}"
        data = json.loads(raw)
        assert isinstance(data, dict), f"Snapshot must be JSON object: {p}"


@pytest.mark.skipif(not MODELS, reason="No schema packages/models discovered")
def test_models_list_is_deterministic() -> None:
    """
    Контракт: список моделей в тестах детерминирован и отсортирован.
    """
    tuples = [(m.module, m.name) for m in MODELS]
    assert tuples == sorted(tuples, key=lambda x: (x[0], x[1]))
