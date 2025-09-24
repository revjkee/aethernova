# oblivionvault-core/tests/contract/test_grpc_v1.proto_contract.py
# -*- coding: utf-8 -*-
"""
Contract tests for OblivionVault gRPC v1 protobufs.

Проверяются:
  - syntax = "proto3"
  - package = oblivionvault.grpc.v1
  - service RetentionService со строго заданным набором RPC
  - ключевые сообщения и их поля (имена/номера/типы)
  - enum RetentionMode с фиксированными значениями
  - уникальность номеров полей, отсутствие пересечений с reserved

Поиск файла:
  - OV_PROTO_ROOT (env), например: path/to/repo/proto
  - по умолчанию: ./proto/oblivionvault/grpc/v1/retention.proto от корня репозитория

Зависимости: pytest, стандартная библиотека.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest


# ---------------------------
# Простенький парсер .proto
# ---------------------------

@dataclass
class Field:
    label: str  # '', 'repeated' (proto3 не использует required/optional)
    type: str
    name: str
    number: int

@dataclass
class Message:
    name: str
    fields: Dict[int, Field]  # по номеру поля
    reserved_nums: List[int]
    reserved_ranges: List[Tuple[int, int]]

@dataclass
class EnumVal:
    name: str
    number: int

@dataclass
class Enum:
    name: str
    values: Dict[str, int]

@dataclass
class Method:
    name: str
    input_type: str
    output_type: str

@dataclass
class Service:
    name: str
    methods: Dict[str, Method]

@dataclass
class ProtoModel:
    syntax: str
    package: str
    imports: List[str]
    messages: Dict[str, Message]
    enums: Dict[str, Enum]
    services: Dict[str, Service]


def _strip_comments(src: str) -> str:
    # удалим /* ... */ и // ...
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//.*?$", "", src, flags=re.MULTILINE)
    return src


_FIELD_RE = re.compile(
    r"(?P<label>repeated\s+)?(?P<type>[A-Za-z0-9_.]+)\s+(?P<name>[A-Za-z0-9_]+)\s*=\s*(?P<num>\d+)\s*(?:\[[^\]]*\])?\s*;",
)

_RESERVED_RE = re.compile(
    r"reserved\s+(?P<body>[^;]+);"
)

_RANGE_RE = re.compile(
    r"(?P<start>\d+)\s+to\s+(?P<end>\d+)"
)

_IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)";', re.MULTILINE)

def parse_proto(text: str) -> ProtoModel:
    src = _strip_comments(text)

    # syntax
    m = re.search(r'syntax\s*=\s*"([^"]+)"\s*;', src)
    if not m:
        raise AssertionError("Не найдено 'syntax = \"...\";'")
    syntax = m.group(1).strip()

    # package
    p = re.search(r'package\s+([A-Za-z0-9_.]+)\s*;', src)
    if not p:
        raise AssertionError("Не найдено объявление 'package ...;'")
    package = p.group(1).strip()

    # imports
    imports = _IMPORT_RE.findall(src)

    # messages
    messages: Dict[str, Message] = {}
    for mm in re.finditer(r"\bmessage\s+([A-Za-z0-9_]+)\s*{", src):
        name = mm.group(1)
        start = mm.end()
        depth, i = 1, start
        while i < len(src) and depth > 0:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = src[start:i-1]
        fields: Dict[int, Field] = {}
        for fm in _FIELD_RE.finditer(body):
            label = (fm.group("label") or "").strip()
            ftype = fm.group("type")
            fname = fm.group("name")
            num = int(fm.group("num"))
            if num in fields:
                raise AssertionError(f"Дублирующий номер поля {num} в message {name}")
            fields[num] = Field(label=label, type=ftype, name=fname, number=num)
        # reserved
        reserved_nums: List[int] = []
        reserved_ranges: List[Tuple[int, int]] = []
        for rm in _RESERVED_RE.finditer(body):
            bodytxt = rm.group("body")
            # отдельные номера через запятую
            for token in [t.strip() for t in bodytxt.split(",")]:
                if not token:
                    continue
                mrange = __RANGE_RE.search(token)
                if mrange:
                    reserved_ranges.append((int(mrange.group("start")), int(mrange.group("end"))))
                else:
                    # может быть '1' или '"foo","bar"' — игнорируем имена
                    if token.isdigit():
                        reserved_nums.append(int(token))
        messages[name] = Message(name=name, fields=fields, reserved_nums=reserved_nums, reserved_ranges=reserved_ranges)

    # enums
    enums: Dict[str, Enum] = {}
    for em in re.finditer(r"\benum\s+([A-Za-z0-9_]+)\s*{", src):
        ename = em.group(1)
        start = em.end()
        depth, i = 1, start
        while i < len(src) and depth > 0:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = src[start:i-1]
        values: Dict[str, int] = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("option"):
                continue
            mval = re.match(r"([A-Za-z0-9_]+)\s*=\s*(\d+)\s*;", line)
            if mval:
                values[mval.group(1)] = int(mval.group(2))
        enums[ename] = Enum(name=ename, values=values)

    # services
    services: Dict[str, Service] = {}
    for sm in re.finditer(r"\bservice\s+([A-Za-z0-9_]+)\s*{", src):
        sname = sm.group(1)
        start = sm.end()
        depth, i = 1, start
        while i < len(src) and depth > 0:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = src[start:i-1]
        methods: Dict[str, Method] = {}
        for rm in re.finditer(
            r"rpc\s+([A-Za-z0-9_]+)\s*\(\s*([A-Za-z0-9_.]+)\s*\)\s*returns\s*\(\s*([A-Za-z0-9_.]+)\s*\)\s*;",
            body,
        ):
            mname, in_t, out_t = rm.group(1), rm.group(2), rm.group(3)
            methods[mname] = Method(name=mname, input_type=in_t, output_type=out_t)
        services[sname] = Service(name=sname, methods=methods)

    return ProtoModel(
        syntax=syntax,
        package=package,
        imports=imports,
        messages=messages,
        enums=enums,
        services=services,
    )


# ---------------------------
# Ожидаемый контракт v1
# ---------------------------

EXPECTED_PACKAGE = "oblivionvault.grpc.v1"
EXPECTED_FILE = "retention.proto"  # имя файла, для сообщения об ошибке

# Сервис и RPC
EXPECTED_SERVICE = "RetentionService"
EXPECTED_METHODS = {
    "ApplyPolicy": ("ApplyPolicyRequest", "ApplyPolicyResponse"),
    "PlaceLegalHold": ("PlaceLegalHoldRequest", "PlaceLegalHoldResponse"),
    "RemoveLegalHold": ("RemoveLegalHoldRequest", "RemoveLegalHoldResponse"),
    "GetStatus": ("GetStatusRequest", "GetStatusResponse"),
    "ShortenGovernanceRetention": ("ShortenGovernanceRetentionRequest", "ShortenGovernanceRetentionResponse"),
    "VerifyAuditChain": ("VerifyAuditChainRequest", "VerifyAuditChainResponse"),
    "ExportAudit": ("ExportAuditRequest", "ExportAuditResponse"),
}

# Ключевые сообщения и ожидаемые поля (type, number)
EXPECTED_MESSAGES: Dict[str, Dict[str, Tuple[str, int]]] = {
    "RetentionPolicy": {
        "mode": ("RetentionMode", 1),
        "duration_seconds": ("int64", 2),
        "retention_until": ("google.protobuf.Timestamp", 3),
        "allow_extension_only": ("bool", 4),
    },
    "RetentionState": {
        "object_id": ("string", 1),
        "retention_until": ("google.protobuf.Timestamp", 2),
        "mode": ("RetentionMode", 3),
        "legal_hold": ("bool", 4),
        "version": ("int32", 5),
        "last_updated": ("google.protobuf.Timestamp", 6),
    },
    "ApplyPolicyRequest": {
        "object_id": ("string", 1),
        "policy": ("RetentionPolicy", 2),
        "actor": ("string", 3),
        "created_at": ("google.protobuf.Timestamp", 4),
        "capability_token": ("string", 5),
        "approvals": ("string", 6),  # repeated string (проверка лейбла ниже)
    },
    "ApplyPolicyResponse": {
        "state": ("RetentionState", 1),
    },
    "PlaceLegalHoldRequest": {
        "object_id": ("string", 1),
        "actor": ("string", 2),
        "reason": ("string", 3),
        "capability_token": ("string", 4),
    },
    "PlaceLegalHoldResponse": {
        "state": ("RetentionState", 1),
    },
    "RemoveLegalHoldRequest": {
        "object_id": ("string", 1),
        "actor": ("string", 2),
        "reason": ("string", 3),
        "capability_token": ("string", 4),
        "approvals": ("string", 5),
    },
    "RemoveLegalHoldResponse": {
        "state": ("RetentionState", 1),
    },
    "GetStatusRequest": {
        "object_id": ("string", 1),
    },
    "GetStatusResponse": {
        "state": ("RetentionState", 1),
    },
    "ShortenGovernanceRetentionRequest": {
        "object_id": ("string", 1),
        "actor": ("string", 2),
        "new_retention_until": ("google.protobuf.Timestamp", 3),
        "capability_token": ("string", 4),
        "approvals": ("string", 5),
    },
    "ShortenGovernanceRetentionResponse": {
        "state": ("RetentionState", 1),
    },
    "VerifyAuditChainRequest": {
        "object_id": ("string", 1),
    },
    "VerifyAuditChainResponse": {
        "ok": ("bool", 1),
    },
    "ExportAuditRequest": {
        "object_id": ("string", 1),
    },
    "ExportAuditResponse": {
        "events_jsonl": ("bytes", 1),
    },
}

# Enum RetentionMode
EXPECTED_ENUMS = {
    "RetentionMode": {
        "RETENTION_MODE_UNSPECIFIED": 0,
        "GOVERNANCE": 1,
        "COMPLIANCE": 2,
    }
}

# Проверим, что Timestamp импортирован
REQUIRED_IMPORTS = {"google/protobuf/timestamp.proto"}


# ---------------------------
# Локатор файла .proto
# ---------------------------

def _locate_proto() -> Path:
    root_env = os.getenv("OV_PROTO_ROOT")
    if root_env:
        p = Path(root_env) / "oblivionvault" / "grpc" / "v1" / EXPECTED_FILE
        if p.exists():
            return p
    # По умолчанию — repo_root/proto/oblivionvault/grpc/v1/retention.proto
    cwd = Path.cwd()
    candidates = [
        cwd / "proto" / "oblivionvault" / "grpc" / "v1" / EXPECTED_FILE,
        cwd / "oblivionvault-core" / "proto" / "oblivionvault" / "grpc" / "v1" / EXPECTED_FILE,
    ]
    for c in candidates:
        if c.exists():
            return c
    # Если не найден — падаем с внятным сообщением
    raise AssertionError(
        f"Не найден {EXPECTED_FILE}. Укажите OV_PROTO_ROOT или разместите файл по пути ./proto/oblivionvault/grpc/v1/{EXPECTED_FILE}"
    )


# ---------------------------
# Тесты контракта
# ---------------------------

@pytest.fixture(scope="module")
def model() -> ProtoModel:
    path = _locate_proto()
    text = path.read_text(encoding="utf-8")
    return parse_proto(text)


def test_syntax_and_package(model: ProtoModel) -> None:
    assert model.syntax == "proto3", f"Ожидался proto3, найдено: {model.syntax}"
    assert model.package == EXPECTED_PACKAGE, f"Ожидался пакет {EXPECTED_PACKAGE}, найден: {model.package}"


def test_required_imports_present(model: ProtoModel) -> None:
    missing = REQUIRED_IMPORTS.difference(set(model.imports))
    assert not missing, f"Отсутствуют обязательные импорты: {sorted(missing)}"


def test_service_and_methods(model: ProtoModel) -> None:
    assert EXPECTED_SERVICE in model.services, f"Не найден сервис {EXPECTED_SERVICE}"
    svc = model.services[EXPECTED_SERVICE]
    # Полный набор методов
    expected = set(EXPECTED_METHODS.keys())
    actual = set(svc.methods.keys())
    missing = expected - actual
    extra = actual - expected
    assert not missing, f"В сервисе {EXPECTED_SERVICE} отсутствуют методы: {sorted(missing)}"
    assert not extra, f"В сервисе {EXPECTED_SERVICE} неожиданно обнаружены лишние методы: {sorted(extra)}"
    # Сигнатуры
    for mname, (in_t, out_t) in EXPECTED_METHODS.items():
        m = svc.methods[mname]
        assert m.input_type.endswith(in_t), f"{mname}: ожидался вход {in_t}, найден {m.input_type}"
        assert m.output_type.endswith(out_t), f"{mname}: ожидался выход {out_t}, найден {m.output_type}"


def test_messages_and_fields(model: ProtoModel) -> None:
    for msg_name, exp_fields in EXPECTED_MESSAGES.items():
        assert msg_name in model.messages, f"Не найдено message {msg_name}"
        msg = model.messages[msg_name]
        # обратная карта: имя->(type,num)
        actual_by_name = {f.name: (f.type, f.number, f.label) for f in msg.fields.values()}
        # проверяем наличие каждого поля, тип и номер
        for fname, (ftype, fnum) in exp_fields.items():
            assert fname in actual_by_name, f"{msg_name}: нет поля {fname}"
            actual_type, actual_num, label = actual_by_name[fname]
            assert actual_type.endswith(ftype), f"{msg_name}.{fname}: тип {actual_type}, ожидался {ftype}"
            assert actual_num == fnum, f"{msg_name}.{fname}: номер {actual_num}, ожидался {fnum}"
            if fname in ("approvals",) and msg_name.endswith("Request"):
                # approvals должны быть repeated string
                assert label.startswith("repeated"), f"{msg_name}.{fname} должен быть repeated, найден label='{label or ''}'"

        # уникальность номеров
        nums = [f.number for f in msg.fields.values()]
        assert len(nums) == len(set(nums)), f"{msg_name}: номера полей не уникальны: {nums}"

        # отсутствие пересечений с reserved
        reserved = set(msg.reserved_nums)
        for r0, r1 in msg.reserved_ranges:
            reserved.update(range(r0, r1 + 1))
        overlaps = [n for n in nums if n in reserved]
        assert not overlaps, f"{msg_name}: номера {overlaps} конфликтуют с reserved {sorted(reserved)}"


def test_enum_retention_mode(model: ProtoModel) -> None:
    assert "RetentionMode" in model.enums, "Отсутствует enum RetentionMode"
    e = model.enums["RetentionMode"].values
    # Полный набор значений
    for name, num in EXPECTED_ENUMS["RetentionMode"].items():
        assert name in e, f"RetentionMode: отсутствует {name}"
        assert e[name] == num, f"RetentionMode.{name}: {e[name]} != {num}"
    # Запрещаем появление неожиданных отрицательных значений
    negs = [k for k, v in e.items() if v < 0]
    assert not negs, f"RetentionMode: недопустимые отрицательные значения: {negs}"


def test_message_field_numbers_are_dense_enough(model: ProtoModel) -> None:
    """
    Нефункциональная проверка: номера полей не должны начинаться с больших значений
    (чтобы сохранить место для еволюции). Не обязательная строгость —  в рамках < 128.
    """
    for name, msg in model.messages.items():
        if name not in EXPECTED_MESSAGES:
            continue  # для ключевых сообщений — проверяем
        max_num = max(msg.fields.keys())
        assert max_num < 128, f"{name}: максимальный номер поля {max_num} слишком велик для v1"


def test_service_namespaces_are_unqualified(model: ProtoModel) -> None:
    """
    Убеждаемся, что сообщения в RPC сигнатурах без избыточной квалификации пакетом (или оканчиваются на ожидаемое имя).
    Это упрощает переиспользование.
    """
    svc = model.services[EXPECTED_SERVICE]
    for m in svc.methods.values():
        assert "." not in m.name, f"Имя метода содержит точки: {m.name}"
        # input/output могут быть с пакетной квалификацией — валидация сделана в test_service_and_methods.


# ---------------------------
# Помощь при падении
# ---------------------------

def _summarize(model: ProtoModel) -> str:
    lines = [
        f"syntax: {model.syntax}",
        f"package: {model.package}",
        f"imports: {', '.join(model.imports)}",
        f"enums: {', '.join(model.enums.keys())}",
        f"messages: {', '.join(model.messages.keys())}",
        f"services: {', '.join(model.services.keys())}",
    ]
    return "\n".join(lines)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # При ошибке приложим краткую сводку по модели (если доступна)
    outcome = yield
    rep = outcome.get_result()
    if rep.failed and "model" in item.fixturenames:
        try:
            m = item.funcargs["model"]
            rep.longrepr.addsection("PROTO SUMMARY", _summarize(m))  # type: ignore[attr-defined]
        except Exception:
            pass
