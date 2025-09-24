# path: zero-trust-core/tests/contract/test_grpc_v1.proto_contract.py
# -*- coding: utf-8 -*-
"""
Промышленный контракт‑тест для gRPC v1 (Protobuf).

Поддерживаемые режимы:
1) FileDescriptorSet:
   - ZT_FDS_CURRENT=/path/to/current.fds  (обязателен)
   - ZT_FDS_GOLDEN=/path/to/golden.fds   (опционален; если не задан и ZT_SNAPSHOT_WRITE=1 — создаст снапшот)
2) Python‑модули с сгенерированными protobuf:
   - ZT_PROTO_MODULES="zero_trust.proto.v1.policy_pb2,zero_trust.proto.v1.policy_pb2_grpc"
     (в этом случае текущий FDS соберётся из DESCRIPTOR модулей; для "golden" используйте режим 1)

Дополнительные параметры:
- ZT_PROTO_PACKAGE="zero_trust.v1"  — фильтр по пакету (по умолчанию — без фильтра)
- ZT_ALLOW_ADDITIVE=1               — разрешить аддитивные изменения (не падать на них)
- ZT_SNAPSHOT_WRITE=1               — при отсутствии golden сохранить текущий как golden
- ZT_GOLDEN_DEFAULT_PATH="tests/contract/golden_v1.fds" — путь по умолчанию для снапшота

Тесты:
- test_contract_backward_compatible — сравнение current vs golden с детальным diff.
- test_current_invariants          — валидация инвариантов текущей схемы.
"""

from __future__ import annotations

import os
import io
import json
import pathlib
from typing import Dict, Any, List, Tuple, Optional, Iterable, Set

import pytest

try:
    from google.protobuf import descriptor_pb2, json_format
except Exception as e:  # pragma: no cover
    pytest.skip(f"google.protobuf не установлен: {e}", allow_module_level=True)


# ------------------------------- Загрузка FDS --------------------------------

def _load_fds_from_file(path: str) -> descriptor_pb2.FileDescriptorSet:
    data = pathlib.Path(path).read_bytes()
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(data)
    return fds


def _load_fds_from_modules(mod_names: Iterable[str]) -> descriptor_pb2.FileDescriptorSet:
    """
    Собираем FileDescriptorSet из DESCRIPTOR каждого модуля.
    """
    import importlib
    pool = set()
    out = descriptor_pb2.FileDescriptorSet()
    for name in mod_names:
        name = name.strip()
        if not name:
            continue
        mod = importlib.import_module(name)
        fd_serialized = getattr(mod, "DESCRIPTOR", None).serialized_pb  # type: ignore[attr-defined]
        if fd_serialized in pool:
            continue
        pool.add(fd_serialized)
        fdp = descriptor_pb2.FileDescriptorProto()
        fdp.ParseFromString(fd_serialized)
        out.file.append(fdp)
    return out


def _get_current_fds() -> descriptor_pb2.FileDescriptorSet:
    env_path = os.environ.get("ZT_FDS_CURRENT")
    if env_path:
        return _load_fds_from_file(env_path)
    modules = os.environ.get("ZT_PROTO_MODULES")
    if modules:
        return _load_fds_from_modules(modules.split(","))
    pytest.skip("Не задан ни ZT_FDS_CURRENT, ни ZT_PROTO_MODULES — нечего проверять.")


def _get_golden_fds() -> Optional[descriptor_pb2.FileDescriptorSet]:
    env_path = os.environ.get("ZT_FDS_GOLDEN")
    if env_path and pathlib.Path(env_path).exists():
        return _load_fds_from_file(env_path)
    default_path = os.environ.get("ZT_GOLDEN_DEFAULT_PATH", "tests/contract/golden_v1.fds")
    p = pathlib.Path(default_path)
    if p.exists():
        return _load_fds_from_file(str(p))
    return None


def _write_golden(fds: descriptor_pb2.FileDescriptorSet) -> str:
    default_path = os.environ.get("ZT_GOLDEN_DEFAULT_PATH", "tests/contract/golden_v1.fds")
    p = pathlib.Path(default_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(fds.SerializeToString())
    return str(p)


# --------------------------- Нормализация и индекс ---------------------------

_TYPE_MAP = {  # для читаемых diff‑отчётов
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
    11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
    16: "sfixed64", 17: "sint32", 18: "sint64",
}
_LABEL_MAP = {1: "optional", 2: "required", 3: "repeated"}


def _full_name(pkg: str, *parts: str) -> str:
    base = ".".join(p for p in parts if p)
    return f"{pkg}.{base}" if pkg else base


def _collect_index(
    fds: descriptor_pb2.FileDescriptorSet,
    package_filter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Строим индекс:
      messages: {full_name: {...}}
      enums:    {full_name: {values: {NAME: num}}}
      services: {full_name: {methods: {...}}}
    """
    idx: Dict[str, Any] = {"messages": {}, "enums": {}, "services": {}}

    def walk_msg(pkg: str, prefix: str, m: descriptor_pb2.DescriptorProto):
        fq_name = _full_name(pkg, prefix, m.name)
        fields = []
        field_numbers: Set[int] = set()
        for f in m.field:
            fields.append({
                "name": f.name,
                "number": f.number,
                "label": _LABEL_MAP.get(f.label, str(f.label)),
                "type": _TYPE_MAP.get(f.type, str(f.type)),
                "type_name": f.type_name,  # .package.Message
                "json_name": f.json_name or f.name,
                "deprecated": bool(getattr(f.options, "deprecated", False)),
            })
            field_numbers.add(f.number)
        reserved_nums = []
        for rr in m.reserved_range:
            reserved_nums.extend(list(range(rr.start, rr.end)))
        reserved_names = list(m.reserved_name)

        idx["messages"][fq_name] = {
            "name": fq_name,
            "fields": sorted(fields, key=lambda x: x["number"]),
            "field_numbers": sorted(field_numbers),
            "reserved_numbers": sorted(set(reserved_nums)),
            "reserved_names": sorted(set(reserved_names)),
            "map_entry": bool(getattr(m.options, "map_entry", False)),
        }
        # вложенные
        for mm in m.nested_type:
            walk_msg(pkg, f"{prefix}{m.name}.", mm)
        for ee in m.enum_type:
            fq_e = _full_name(pkg, prefix, m.name, ee.name)
            vals = {v.name: v.number for v in ee.value}
            idx["enums"][fq_e] = {"name": fq_e, "values": vals}

    for f in fds.file:
        pkg = f.package
        if package_filter and not pkg.startswith(package_filter):
            continue
        # сообщения
        for m in f.message_type:
            walk_msg(pkg, "", m)
        # enum на верхнем уровне
        for ee in f.enum_type:
            fq_e = _full_name(pkg, ee.name)
            vals = {v.name: v.number for v in ee.value}
            idx["enums"][fq_e] = {"name": fq_e, "values": vals}
        # сервисы
        for s in f.service:
            fq_svc = _full_name(pkg, s.name)
            methods = {}
            for m in s.method:
                methods[m.name] = {
                    "name": m.name,
                    "input_type": m.input_type,     # .package.Message
                    "output_type": m.output_type,   # .package.Message
                    "client_streaming": bool(m.client_streaming),
                    "server_streaming": bool(m.server_streaming),
                }
            idx["services"][fq_svc] = {"name": fq_svc, "methods": methods}

    return idx


# ------------------------------ Сравнение схемы ------------------------------

class Change:
    def __init__(self, kind: str, path: str, detail: str, breaking: bool):
        self.kind = kind
        self.path = path
        self.detail = detail
        self.breaking = breaking

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "detail": self.detail,
            "breaking": self.breaking,
        }

    def __str__(self) -> str:
        sev = "BREAK" if self.breaking else "ADD/INFO"
        return f"[{sev}] {self.kind} at {self.path}: {self.detail}"


def _diff_indices(old: Dict[str, Any], new: Dict[str, Any]) -> List[Change]:
    changes: List[Change] = []
    # Messages
    old_msgs = old["messages"]
    new_msgs = new["messages"]
    for name in sorted(old_msgs.keys() - new_msgs.keys()):
        changes.append(Change("message.removed", name, "удалено сообщение", True))
    for name in sorted(new_msgs.keys() - old_msgs.keys()):
        changes.append(Change("message.added", name, "добавлено сообщение", False))
    for name in sorted(old_msgs.keys() & new_msgs.keys()):
        changes.extend(_diff_message(name, old_msgs[name], new_msgs[name]))

    # Enums (простая проверка)
    old_enums = old["enums"]
    new_enums = new["enums"]
    for name in sorted(old_enums.keys() - new_enums.keys()):
        changes.append(Change("enum.removed", name, "удален enum", True))
    for name in sorted(new_enums.keys() - old_enums.keys()):
        changes.append(Change("enum.added", name, "добавлен enum", False))
    for name in sorted(old_enums.keys() & new_enums.keys()):
        o_vals = old_enums[name]["values"]
        n_vals = new_enums[name]["values"]
        # Изменение номера существующего имени — breaking
        for k in sorted(o_vals.keys() & n_vals.keys()):
            if o_vals[k] != n_vals[k]:
                changes.append(Change("enum.value.renumber", f"{name}.{k}", f"{o_vals[k]} -> {n_vals[k]}", True))
        # Удаления
        for k in sorted(o_vals.keys() - n_vals.keys()):
            changes.append(Change("enum.value.removed", f"{name}.{k}", f"удалено значение {o_vals[k]}", True))
        # Добавления — допустимы
        for k in sorted(n_vals.keys() - o_vals.keys()):
            changes.append(Change("enum.value.added", f"{name}.{k}", f"добавлено значение {n_vals[k]}", False))

    # Services
    old_svcs = old["services"]
    new_svcs = new["services"]
    for name in sorted(old_svcs.keys() - new_svcs.keys()):
        changes.append(Change("service.removed", name, "удалён сервис", True))
    for name in sorted(new_svcs.keys() - old_svcs.keys()):
        changes.append(Change("service.added", name, "добавлен сервис", False))
    for name in sorted(old_svcs.keys() & new_svcs.keys()):
        changes.extend(_diff_service(name, old_svcs[name], new_svcs[name]))

    return changes


def _diff_message(name: str, old: Dict[str, Any], new: Dict[str, Any]) -> List[Change]:
    c: List[Change] = []
    o_fields = {f["number"]: f for f in old["fields"]}
    n_fields = {f["number"]: f for f in new["fields"]}
    o_by_name = {f["name"]: f for f in old["fields"]}
    n_by_name = {f["name"]: f for f in new["fields"]}

    # Удалённые поля (по номеру) — breaking если номер не зарезервирован
    for num in sorted(o_fields.keys() - n_fields.keys()):
        fld = o_fields[num]
        reserved = num in set(new.get("reserved_numbers", []))
        c.append(Change(
            "field.removed",
            f"{name}.{fld['name']}#{num}",
            "удалено поле (номер остался зарезервирован)" if reserved else "удалено поле (номер НЕ зарезервирован)",
            not reserved
        ))

    # Добавленные поля — допустимо (если номер не в reserved)
    for num in sorted(n_fields.keys() - o_fields.keys()):
        fld = n_fields[num]
        in_reserved = num in set(old.get("reserved_numbers", []))
        c.append(Change(
            "field.added",
            f"{name}.{fld['name']}#{num}",
            "добавлено поле" + (" (НОМЕР был в reserved старой схемы)" if in_reserved else ""),
            in_reserved  # это может быть breaking, если нарушает reserved
        ))

    # Совпавшие номера — сверяем атрибуты
    for num in sorted(o_fields.keys() & n_fields.keys()):
        oldf, newf = o_fields[num], n_fields[num]
        path = f"{name}.{oldf['name']}#{num}"
        if oldf["name"] != newf["name"]:
            c.append(Change("field.rename", path, f"{oldf['name']} -> {newf['name']}", True))
        if oldf["type"] != newf["type"]:
            c.append(Change("field.type.change", path, f"{oldf['type']} -> {newf['type']}", True))
        if oldf["type_name"] != newf["type_name"]:
            c.append(Change("field.type_name.change", path, f"{oldf['type_name']} -> {newf['type_name']}", True))
        if oldf["label"] != newf["label"]:
            c.append(Change("field.label.change", path, f"{oldf['label']} -> {newf['label']}", True))
        if oldf["json_name"] != newf["json_name"]:
            c.append(Change("field.json_name.change", path, f"{oldf['json_name']} -> {newf['json_name']}", True))
        # deprecated переключение — не ломающее (информируем)
        if oldf["deprecated"] != newf["deprecated"]:
            c.append(Change("field.deprecated.toggle", path, f"{oldf['deprecated']} -> {newf['deprecated']}", False))

    # Перенумерация по имени (номер изменился) — считаем breaking
    for name_only in sorted(o_by_name.keys() & n_by_name.keys()):
        if o_by_name[name_only]["number"] != n_by_name[name_only]["number"]:
            c.append(Change(
                "field.number.change",
                f"{name}.{name_only}",
                f"{o_by_name[name_only]['number']} -> {n_by_name[name_only]['number']}",
                True
            ))

    return c


def _diff_service(name: str, old: Dict[str, Any], new: Dict[str, Any]) -> List[Change]:
    c: List[Change] = []
    o_m = old["methods"]
    n_m = new["methods"]
    for m in sorted(o_m.keys() - n_m.keys()):
        c.append(Change("rpc.removed", f"{name}.{m}", "удалён метод", True))
    for m in sorted(n_m.keys() - o_m.keys()):
        c.append(Change("rpc.added", f"{name}.{m}", "добавлен метод", False))
    for m in sorted(o_m.keys() & n_m.keys()):
        o, n = o_m[m], n_m[m]
        path = f"{name}.{m}"
        if o["input_type"] != n["input_type"]:
            c.append(Change("rpc.input.change", path, f"{o['input_type']} -> {n['input_type']}", True))
        if o["output_type"] != n["output_type"]:
            c.append(Change("rpc.output.change", path, f"{o['output_type']} -> {n['output_type']}", True))
        if o["client_streaming"] != n["client_streaming"]:
            c.append(Change("rpc.client_streaming.toggle", path, f"{o['client_streaming']} -> {n['client_streaming']}", True))
        if o["server_streaming"] != n["server_streaming"]:
            c.append(Change("rpc.server_streaming.toggle", path, f"{o['server_streaming']} -> {n['server_streaming']}", True))
    return c


# ------------------------------ Инварианты схемы -----------------------------

def _assert_invariants_current(idx: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    # Уникальные номера полей
    for msg_name, m in idx["messages"].items():
        nums = m["field_numbers"]
        if len(nums) != len(set(nums)):
            problems.append(f"{msg_name}: дублирующиеся номера полей")
        # В proto3 нет required; считаем required ломающим инвариантом
        for f in m["fields"]:
            if f["label"] == "required":
                problems.append(f"{msg_name}.{f['name']}#{f['number']}: label 'required' недопустим в proto3")
        # Номера полей в допустимых диапазонах и не пересекаются с reserved
        reserved = set(m.get("reserved_numbers", []))
        for f in m["fields"]:
            if f["number"] in reserved:
                problems.append(f"{msg_name}.{f['name']}#{f['number']}: номер в reserved")
            if not (1 <= f["number"] < (1 << 29)):
                problems.append(f"{msg_name}.{f['name']}#{f['number']}: недопустимый номер")
    # Уникальные значения enum
    for enum_name, e in idx["enums"].items():
        vals = list(e["values"].values())
        if len(vals) != len(set(vals)):
            problems.append(f"{enum_name}: дублирующиеся номера enum значений")
    return problems


# -------------------------------- Pytest тесты -------------------------------

@pytest.mark.order(1)
def test_contract_backward_compatible():
    """
    Сравнение текущего дескриптора и golden‑снимка.
    Ломающие изменения -> FAIL. Аддитивные допускаются, если ZT_ALLOW_ADDITIVE=1 иначе -> FAIL.
    """
    package_filter = os.environ.get("ZT_PROTO_PACKAGE") or None

    current = _get_current_fds()
    golden = _get_golden_fds()

    if golden is None:
        if os.environ.get("ZT_SNAPSHOT_WRITE") == "1":
            path = _write_golden(current)
            pytest.skip(f"Golden не найден. Создан снапшот: {path}")
        else:
            pytest.skip("Golden не найден (ZT_FDS_GOLDEN или tests/contract/golden_v1.fds). "
                        "Установите ZT_SNAPSHOT_WRITE=1 для автосоздания.")

    idx_cur = _collect_index(current, package_filter)
    idx_old = _collect_index(golden, package_filter)

    changes = _diff_indices(idx_old, idx_cur)
    breaking = [c for c in changes if c.breaking]
    additive = [c for c in changes if not c.breaking]

    # Формируем удобочитаемый отчёт
    def fmt(chs: List[Change]) -> str:
        return "\n".join(str(c) for c in chs) or "—"

    allow_additive = os.environ.get("ZT_ALLOW_ADDITIVE") == "1"

    report = io.StringIO()
    report.write("=== gRPC/Proto v1 Contract Diff ===\n")
    report.write(f"breaking: {len(breaking)}, additive: {len(additive)}\n\n")
    if breaking:
        report.write("— BREAKING CHANGES —\n")
        report.write(fmt(breaking) + "\n\n")
    if additive:
        report.write("— ADDITIVE / INFO —\n")
        report.write(fmt(additive) + "\n")

    if breaking:
        pytest.fail(report.getvalue())
    if additive and not allow_additive:
        pytest.fail(report.getvalue())


@pytest.mark.order(2)
def test_current_invariants():
    """
    Проверка внутренних инвариантов текущей схемы.
    """
    package_filter = os.environ.get("ZT_PROTO_PACKAGE") or None
    current = _get_current_fds()
    idx_cur = _collect_index(current, package_filter)
    problems = _assert_invariants_current(idx_cur)
    if problems:
        msg = "Нарушены инварианты схемы:\n" + "\n".join(f"- {p}" for p in problems)
        pytest.fail(msg)


# ------------------------------ Отладочная печать ----------------------------

def _debug_dump_idx(idx: Dict[str, Any]) -> str:
    """Опциональная отладка: канонический JSON индекса."""
    canon = {
        "messages": {k: {kk: vv for kk, vv in v.items() if kk in ("fields", "reserved_numbers", "reserved_names")}
                     for k, v in idx["messages"].items()},
        "enums": idx["enums"],
        "services": {k: {"methods": v["methods"]} for k, v in idx["services"].items()},
    }
    return json.dumps(canon, ensure_ascii=False, sort_keys=True, indent=2)


@pytest.mark.optionalhook
def pytest_addoption(parser):
    parser.addoption("--dump-proto-index", action="store_true", default=False,
                     help="Вывести канонический индекс текущей схемы (для диагностики).")


@pytest.fixture(autouse=True, scope="session")
def _maybe_dump(request):
    if request.config.getoption("--dump-proto-index"):
        cur = _get_current_fds()
        idx = _collect_index(cur, os.environ.get("ZT_PROTO_PACKAGE") or None)
        print("\n=== PROTO INDEX (current) ===\n" + _debug_dump_idx(idx))
