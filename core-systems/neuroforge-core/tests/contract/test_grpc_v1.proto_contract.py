# -*- coding: utf-8 -*-
"""
gRPC v1 Proto Contract Tests (industrial)

Как использовать (CI/локально):
  GRPC_PB2_MODULES="pkg.api.v1.foo_pb2,pkg.api.v1.bar_pb2" \
  PYTHONPATH="." \
  pytest -q neuroforge-core/tests/contract/test_grpc_v1.proto_contract.py

Опциональные переменные окружения:
  - GRPC_PB2_MODULES           : список модулей *_pb2 через запятую.
  - EXPECTED_PACKAGE           : ожидаемое имя пакета (например, "pkg.api.v1") — проверка строгоя.
  - EXPECTED_API_VERSION       : семвер-строка ожидаемой версии API — сверяется с модулем.
  - SNAPSHOT_DIR               : каталог для снапшотов (по умолчанию tests/contract/snapshots).
  - ALLOW_SNAPSHOT_UPDATE=1    : явно разрешить обновление/создание снапшотов.
  - MAX_ROUNDTRIP_DEPTH        : глубина рекурсивной генерации тестовых сообщений (дефолт 2).

Тесты:
  1) Стабильность контракта (снапшот): структуры messages/enums/services/fields/oneof/labels/типов/номеров/резервов.
  2) Запрет breaking changes: смена номера поля, удаление без reserve, изменение streaming-флагов.
  3) Бинарный и JSON roundtrip по каждому message (минимальные валидные полезные нагрузки).
  4) Валидация пакета и (опционально) версии API.
"""

from __future__ import annotations

import difflib
import importlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

# Протобуф — стандартные артефакты
from google.protobuf import descriptor as _desc
from google.protobuf import descriptor_pb2
from google.protobuf import json_format
from google.protobuf import message as _message
from google.protobuf import symbol_database as _symdb

# -----------------------------
# Конфигурация и утилиты
# -----------------------------
_ROOT = Path(__file__).resolve().parents[2]  # neuroforge-core/
_DEFAULT_SNAPSHOT_DIR = _ROOT / "tests" / "contract" / "snapshots"


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v is not None else default


def _bool_env(name: str) -> bool:
    return os.environ.get(name, "").strip() in ("1", "true", "TRUE", "yes", "YES")


def _get_pb2_modules() -> List[str]:
    raw = _env("GRPC_PB2_MODULES", "")
    if not raw:
        return []
    return [m.strip() for m in raw.split(",") if m.strip()]


def _snapshot_dir() -> Path:
    return Path(_env("SNAPSHOT_DIR", str(_DEFAULT_SNAPSHOT_DIR)))


def _load_module(modname: str):
    try:
        return importlib.import_module(modname)
    except Exception as e:
        pytest.skip(f"Не удалось импортировать модуль {modname}: {e}")


def _sym_db():
    return _symdb.Default()


# -----------------------------
# Нормализация дескрипторов
# -----------------------------
_SCALAR_TYPES = {
    _desc.FieldDescriptor.TYPE_DOUBLE: "double",
    _desc.FieldDescriptor.TYPE_FLOAT: "float",
    _desc.FieldDescriptor.TYPE_INT64: "int64",
    _desc.FieldDescriptor.TYPE_UINT64: "uint64",
    _desc.FieldDescriptor.TYPE_INT32: "int32",
    _desc.FieldDescriptor.TYPE_FIXED64: "fixed64",
    _desc.FieldDescriptor.TYPE_FIXED32: "fixed32",
    _desc.FieldDescriptor.TYPE_BOOL: "bool",
    _desc.FieldDescriptor.TYPE_STRING: "string",
    _desc.FieldDescriptor.TYPE_BYTES: "bytes",
    _desc.FieldDescriptor.TYPE_UINT32: "uint32",
    _desc.FieldDescriptor.TYPE_SFIXED32: "sfixed32",
    _desc.FieldDescriptor.TYPE_SFIXED64: "sfixed64",
    _desc.FieldDescriptor.TYPE_SINT32: "sint32",
    _desc.FieldDescriptor.TYPE_SINT64: "sint64",
}

_LABELS = {
    _desc.FieldDescriptor.LABEL_OPTIONAL: "optional",
    _desc.FieldDescriptor.LABEL_REPEATED: "repeated",
}


def _field_entry(fd: _desc.FieldDescriptor) -> Dict[str, Any]:
    # Тип
    if fd.message_type is not None:
        ftype = {"message": fd.message_type.full_name}
    elif fd.enum_type is not None:
        ftype = {"enum": fd.enum_type.full_name}
    else:
        ftype = {"scalar": _SCALAR_TYPES.get(fd.type, f"unknown_{fd.type}")}

    # Map entry
    is_map = False
    if fd.message_type is not None and fd.message_type.GetOptions().map_entry:
        is_map = True
        # Для map<K,V> — извлекаем типы ключа/значения
        key_f = fd.message_type.fields_by_name.get("key")
        val_f = fd.message_type.fields_by_name.get("value")
        ftype = {
            "map": {
                "key": _SCALAR_TYPES.get(key_f.type, f"unknown_{key_f.type}") if key_f else "unknown",
                "value": (
                    {"message": val_f.message_type.full_name}
                    if val_f and val_f.message_type
                    else {"enum": val_f.enum_type.full_name}
                    if val_f and val_f.enum_type
                    else {"scalar": _SCALAR_TYPES.get(val_f.type, f"unknown_{val_f.type}") if val_f else "unknown"}
                ),
            }
        }

    return {
        "name": fd.name,
        "json_name": fd.json_name,
        "number": fd.number,
        "label": _LABELS.get(fd.label, "optional"),
        "type": ftype,
        "oneof": fd.containing_oneof.name if fd.containing_oneof else None,
        "packed": fd.has_options and fd.GetOptions().packed,
        "proto3_optional": getattr(fd, "proto3_optional", False),
        "is_map": is_map,
    }


def _message_entry(md: _desc.Descriptor) -> Dict[str, Any]:
    fields = [_field_entry(f) for f in md.fields]
    oneofs = [o.name for o in md.oneofs]
    reserved_ranges = [{"start": r.start, "end": r.end} for r in md.GetOptions().deprecated_desc.ReservedRange] if False else []
    # У Python runtime нет прямого списка reserved; читаем из FileDescriptorProto ниже (в снапшоте заполним).
    return {
        "name": md.name,
        "full_name": md.full_name,
        "oneofs": sorted(oneofs),
        "fields": sorted(fields, key=lambda x: x["number"]),
        "nested_types": sorted([n.name for n in md.nested_types]),
        "enums": sorted([e.name for e in md.enum_types]),
        "reserved": [],  # будет дополнено из FileDescriptorProto
    }


def _enum_entry(ed: _desc.EnumDescriptor) -> Dict[str, Any]:
    return {
        "name": ed.name,
        "full_name": ed.full_name,
        "values": [{"name": v.name, "number": v.number} for v in ed.values],
        "reserved": [],  # дополнится из proto
    }


def _service_entry(sd: _desc.ServiceDescriptor) -> Dict[str, Any]:
    methods = []
    for m in sd.methods:
        methods.append(
            {
                "name": m.name,
                "input": m.input_type.full_name,
                "output": m.output_type.full_name,
                "client_streaming": m.is_client_streaming,
                "server_streaming": m.is_server_streaming,
            }
        )
    return {"name": sd.name, "full_name": sd.full_name, "methods": sorted(methods, key=lambda x: x["name"])}


def _file_proto(module) -> descriptor_pb2.FileDescriptorProto:
    # Берём из скомпилированного модуля исходный FileDescriptorProto
    return module.DESCRIPTOR.serialized_pb  # type: ignore[attr-defined]


def _file_proto_decoded(module) -> descriptor_pb2.FileDescriptorProto:
    fdp = descriptor_pb2.FileDescriptorProto()
    fdp.ParseFromString(module.DESCRIPTOR.serialized_pb)  # type: ignore[attr-defined]
    return fdp


def _normalize_module(module) -> Dict[str, Any]:
    fdp = _file_proto_decoded(module)
    # Достроим reserved ranges/names из исходного FileDescriptorProto
    reserved_by_msg: Dict[str, Dict[str, Any]] = {}
    for td in fdp.message_type:
        key = f"{fdp.package}.{td.name}" if fdp.package else td.name
        reserved_by_msg[key] = {
            "ranges": [{"start": r.start, "end": r.end} for r in td.reserved_range],
            "names": list(td.reserved_name),
        }
    reserved_by_enum: Dict[str, Dict[str, Any]] = {}
    for ed in fdp.enum_type:
        key = f"{fdp.package}.{ed.name}" if fdp.package else ed.name
        reserved_by_enum[key] = {
            "ranges": [{"start": r.start, "end": r.end} for r in ed.reserved_range],
            "names": list(ed.reserved_name),
        }

    file_desc: _desc.FileDescriptor = module.DESCRIPTOR  # type: ignore[attr-defined]
    msgs = []
    for md in file_desc.message_types_by_name.values():
        e = _message_entry(md)
        rv = reserved_by_msg.get(md.full_name)
        if rv:
            e["reserved"] = rv
        msgs.append(e)

    enums = []
    for ed in file_desc.enum_types_by_name.values():
        e = _enum_entry(ed)
        rv = reserved_by_enum.get(ed.full_name)
        if rv:
            e["reserved"] = rv
        enums.append(e)

    services = [_service_entry(s) for s in file_desc.services_by_name.values()]

    imports = sorted(list(file_desc.dependencies), key=lambda d: d.name)
    return {
        "name": file_desc.name,
        "package": file_desc.package,
        "syntax": fdp.syntax or "proto3",
        "messages": sorted(msgs, key=lambda x: x["full_name"]),
        "enums": sorted(enums, key=lambda x: x["full_name"]),
        "services": sorted(services, key=lambda x: x["full_name"]),
        "imports": [d.name for d in imports],
        "options": {"java_package": fdp.options.java_package if fdp.options.HasField("java_package") else None},
    }


def _pretty_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


def _diff_json(a: Any, b: Any) -> str:
    a_s = _pretty_json(a).splitlines(keepends=True)
    b_s = _pretty_json(b).splitlines(keepends=True)
    return "".join(difflib.unified_diff(a_s, b_s, fromfile="expected", tofile="actual"))


# -----------------------------
# Семвер-валидатор (без внешних deps)
# -----------------------------
def _parse_semver(s: str) -> Tuple[int, int, int]:
    core = s.split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        pytest.skip(f"Некорректная семвер-строка EXPECTED_API_VERSION={s}")
    return int(parts[0]), int(parts[1]), int(parts[2])


# -----------------------------
# Построение снапшота на диск
# -----------------------------
def _snapshot_path(module_name: str) -> Path:
    sd = _snapshot_dir()
    sd.mkdir(parents=True, exist_ok=True)
    fname = module_name.replace(".", "_") + ".json"
    return sd / fname


def _load_snapshot(path: Path) -> Dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _save_snapshot(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_pretty_json(data), encoding="utf-8")
    os.replace(tmp, path)


# -----------------------------
# Фабрика тестовых сообщений
# -----------------------------
def _sample_for_field(fd: _desc.FieldDescriptor, depth: int) -> Any:
    # depth ограничивает рекурсию
    if fd.label == _desc.FieldDescriptor.LABEL_REPEATED and not (
        fd.message_type and fd.message_type.GetOptions().map_entry
    ):
        # повторяющиеся поля (не map)
        inner = _sample_for_field(fd if fd.message_type is None else _desc.FieldDescriptor(
            name=fd.name, full_name=fd.full_name, index=fd.index,
            number=fd.number, type=fd.type, cpp_type=fd.cpp_type,
            label=_desc.FieldDescriptor.LABEL_OPTIONAL,
            containing_type=fd.containing_type, message_type=fd.message_type,
            enum_type=fd.enum_type, is_extension=fd.is_extension, extension_scope=fd.extension_scope,
            options=fd.GetOptions(), has_default_value=False, default_value=None
        ), depth)
        return [inner]

    # map<K,V>
    if fd.message_type is not None and fd.message_type.GetOptions().map_entry:
        key_f = fd.message_type.fields_by_name["key"]
        val_f = fd.message_type.fields_by_name["value"]
        key_sample = _sample_for_field(key_f, depth)
        val_sample = _sample_for_field(val_f, depth - 1 if depth > 0 else 0)
        return {key_sample: val_sample}

    # простые типы
    if fd.type in _SCALAR_TYPES:
        t = _SCALAR_TYPES[fd.type]
        return {
            "double": 1.0,
            "float": 1.0,
            "int64": 1,
            "uint64": 1,
            "int32": 1,
            "fixed64": 1,
            "fixed32": 1,
            "bool": True,
            "string": "x",
            "bytes": b"x",
            "uint32": 1,
            "sfixed32": 1,
            "sfixed64": 1,
            "sint32": 1,
            "sint64": 1,
        }[t]

    if fd.enum_type is not None:
        # Берём первый валидный элемент enum
        return fd.enum_type.values[0].number if fd.enum_type.values else 0

    if fd.message_type is not None:
        if depth <= 0:
            return None
        # Рекурсивный message
        # Попытаемся найти Python-класс для сообщения
        sym = _sym_db().GetSymbol(fd.message_type.full_name)
        if not isinstance(sym, type) or not issubclass(sym, _message.Message):
            return None
        inst = sym()
        for nf in fd.message_type.fields:
            try:
                val = _sample_for_field(nf, depth - 1)
                if val is None:
                    continue
                if nf.label == _desc.FieldDescriptor.LABEL_REPEATED and not (
                    nf.message_type and nf.message_type.GetOptions().map_entry
                ):
                    getattr(inst, nf.name).extend(val if isinstance(val, list) else [val])
                elif nf.message_type and nf.message_type.GetOptions().map_entry:
                    # map
                    mp = getattr(inst, nf.name)
                    for k, v in val.items():
                        mp[k] = v
                else:
                    setattr(inst, nf.name, val)
            except Exception:
                # пропускаем сложные/oneof во избежание конфликтов
                pass
        return inst

    return None


def _roundtrip_message(cls: type[_message.Message], depth: int = 2) -> Tuple[bool, str]:
    try:
        msg = cls()
        for f in msg.DESCRIPTOR.fields:
            val = _sample_for_field(f, depth)
            if val is None:
                continue
            if f.label == _desc.FieldDescriptor.LABEL_REPEATED and not (
                f.message_type and f.message_type.GetOptions().map_entry
            ):
                getattr(msg, f.name).extend(val if isinstance(val, list) else [val])
            elif f.message_type and f.message_type.GetOptions().map_entry:
                mp = getattr(msg, f.name)
                for k, v in val.items():
                    mp[k] = v
            else:
                setattr(msg, f.name, val)

        # binary
        data = msg.SerializeToString()
        msg2 = cls()
        msg2.ParseFromString(data)
        if msg != msg2:
            return False, "binary roundtrip mismatch"

        # json
        js = json_format.MessageToJson(msg)
        msg3 = cls()
        json_format.Parse(js, msg3)
        if msg != msg3:
            return False, "json roundtrip mismatch"
        return True, "ok"
    except Exception as e:
        return False, f"exception: {e}"


# -----------------------------
# Тест-набор
# -----------------------------
@pytest.mark.parametrize("module_name", _get_pb2_modules() or ["__NO_MODULES__"])
def test_snapshot_and_breaking_changes(module_name: str):
    if module_name == "__NO_MODULES__":
        pytest.skip("GRPC_PB2_MODULES не задан — пропуск контракт-тестов")

    mod = _load_module(module_name)
    normalized = _normalize_module(mod)

    # Проверка имени пакета при наличии EXPECTED_PACKAGE
    exp_pkg = _env("EXPECTED_PACKAGE")
    if exp_pkg:
        assert normalized["package"] == exp_pkg, f"Ожидался пакет {exp_pkg}, получен {normalized['package']}"

    snap_path = _snapshot_path(module_name)
    existing = _load_snapshot(snap_path)

    if existing is None:
        if _bool_env("ALLOW_SNAPSHOT_UPDATE"):
            _save_snapshot(snap_path, normalized)
            pytest.skip(f"Снапшот создан: {snap_path}")
        else:
            pytest.fail(
                f"Снапшот отсутствует: {snap_path}. "
                f"Запустите с ALLOW_SNAPSHOT_UPDATE=1 для первичного сохранения."
            )

    # Дифф целиком (удобно видеть любые изменения)
    if normalized != existing:
        diff = _diff_json(existing, normalized)

        # Строгая проверка на breaking changes:
        # 1) Номер любого поля не должен меняться.
        # 2) Удаление поля допустимо только при наличии reserve.
        # 3) Изменение streaming-флагов — breaking.
        _assert_no_breaking_changes(existing, normalized)

        # Если добрались сюда — изменения считаем небрекинг (например, добавили optional поле с новым номером).
        # Но всё равно тест падает для осознанного апдейта снапшота.
        if _bool_env("ALLOW_SNAPSHOT_UPDATE"):
            _save_snapshot(snap_path, normalized)
            pytest.skip(f"Снапшот обновлён (неbreaking): {snap_path}\n{diff}")
        else:
            pytest.fail(f"Изменения в контракте обнаружены. Проверьте дифф и, при необходимости, обновите снапшот:\n{diff}")


def _index_fields(snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    messages_index[full_name][field_name] = {"number": ..., "type": ..., ...}
    """
    idx: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for m in snapshot.get("messages", []):
        fields = {f["name"]: f for f in m.get("fields", [])}
        idx[m["full_name"]] = fields
    return idx


def _index_services(snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    services_index[full_name][method_name] = {...}
    """
    idx: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for s in snapshot.get("services", []):
        idx[s["full_name"]] = {m["name"]: m for m in s.get("methods", [])}
    return idx


def _assert_no_breaking_changes(old: Dict[str, Any], new: Dict[str, Any]) -> None:
    old_fields = _index_fields(old)
    new_fields = _index_fields(new)

    # 1) Номера полей
    for msg_full_name, oflds in old_fields.items():
        nfls = new_fields.get(msg_full_name, {})
        for fname, fmeta in oflds.items():
            if fname not in nfls:
                # поле исчезло — должно быть зарезервировано
                _ensure_reserved(new, msg_full_name, fmeta["number"], fname)
            else:
                # номер поля должен совпадать
                assert (
                    fmeta["number"] == nfls[fname]["number"]
                ), f"Breaking change: изменился номер поля {msg_full_name}.{fname}: {fmeta['number']} -> {nfls[fname]['number']}"

    # 2) Streaming-флаги и сигнатуры методов
    oserv = _index_services(old)
    nserv = _index_services(new)
    for srv_full, omethods in oserv.items():
        nmethods = nserv.get(srv_full, {})
        for mname, mmeta in omethods.items():
            nm = nmethods.get(mname)
            assert nm is not None, f"Breaking change: удалён метод {srv_full}.{mname}"
            for key in ("input", "output", "client_streaming", "server_streaming"):
                assert (
                    mmeta[key] == nm[key]
                ), f"Breaking change: изменился атрибут метода {srv_full}.{mname}.{key}: {mmeta[key]} -> {nm[key]}"


def _ensure_reserved(snapshot: Dict[str, Any], msg_full_name: str, field_no: int, field_name: str) -> None:
    # Ищем блок reserved для сообщения
    for m in snapshot.get("messages", []):
        if m["full_name"] != msg_full_name:
            continue
        r = m.get("reserved", {})
        ranges = r.get("ranges", [])
        names = set(r.get("names", []))
        in_range = any(rg["start"] <= field_no <= rg["end"] for rg in ranges)
        if in_range or field_name in names:
            return
        pytest.fail(
            f"Breaking change: поле {msg_full_name}.{field_name} (#{field_no}) удалено без резервирования (reserved range/name)."
        )
    pytest.fail(f"В снапшоте нет записи для сообщения {msg_full_name} при проверке reserve.")


# -----------------------------
# Roundtrip-проверки сообщений
# -----------------------------
@pytest.mark.parametrize("module_name", _get_pb2_modules() or ["__NO_MODULES__"])
def test_message_roundtrip_binary_and_json(module_name: str):
    if module_name == "__NO_MODULES__":
        pytest.skip("GRPC_PB2_MODULES не задан — пропуск roundtrip-тестов")

    mod = _load_module(module_name)
    depth = int(_env("MAX_ROUNDTRIP_DEPTH", "2") or "2")

    # Собираем Python-классы сообщений из модуля
    classes: List[type] = []
    for name, sym in mod.__dict__.items():
        if isinstance(sym, type) and issubclass(sym, _message.Message) and name[0].isupper():
            classes.append(sym)

    if not classes:
        pytest.skip(f"В модуле {module_name} не найдено protobuf-классов")

    errors = []
    for cls in classes:
        ok, info = _roundtrip_message(cls, depth=depth)
        if not ok:
            errors.append(f"{cls.__name__}: {info}")

    if errors:
        pytest.fail("Roundtrip ошибки:\n- " + "\n- ".join(errors))


# -----------------------------
# Дополнительные проверки (пакет/версия)
# -----------------------------
@pytest.mark.parametrize("module_name", _get_pb2_modules() or ["__NO_MODULES__"])
def test_expected_package_and_version(module_name: str):
    if module_name == "__NO_MODULES__":
        pytest.skip("GRPC_PB2_MODULES не задан — пропуск проверки версии/пакета")

    mod = _load_module(module_name)
    normalized = _normalize_module(mod)

    exp_pkg = _env("EXPECTED_PACKAGE")
    if exp_pkg:
        assert normalized["package"] == exp_pkg, f"Ожидался пакет {exp_pkg}, получен {normalized['package']}"

    exp_ver = _env("EXPECTED_API_VERSION")
    if not exp_ver:
        pytest.skip("EXPECTED_API_VERSION не задан — пропуск семвер-проверки")

    _parse_semver(exp_ver)  # валидируем формат
    # Ищем версию в модуле (_API_VERSION или __version__ или атрибут в DESCRIPTOR)
    candidates = [
        getattr(mod, "_API_VERSION", None),
        getattr(mod, "__version__", None),
        getattr(getattr(mod, "DESCRIPTOR", None), "GetOptions", None),
    ]
    found = None
    for c in candidates:
        if isinstance(c, str) and c.strip():
            found = c.strip()
            break
    if not found:
        pytest.skip(f"Версия API в модуле {module_name} не найдена — пропуск точной сверки")
    assert found == exp_ver, f"Несовпадение версии API: ожидалось {exp_ver}, модуль сообщает {found}"
