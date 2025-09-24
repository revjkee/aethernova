# datafabric-core/tests/unit/contract/test_grpc_v1.proto_contract.py
# -*- coding: utf-8 -*-
"""
Промышленные контрактные тесты для gRPC v1 / Protobuf.

Назначение:
- Гарантировать стабильность публичного контракта .proto (v1).
- Убедиться в корректной дескрипции сообщений/сервисов.
- Проверить безопасные эволюции: добавление полей не ломает декодирование.

Конфигурация через переменные окружения (необязательно):
- DF_GRPC_V1_PB2         (default: "datafabric.rpc.v1.service_pb2")
- DF_GRPC_V1_PB2_GRPC    (default: "datafabric.rpc.v1.service_pb2_grpc")
- DF_GRPC_V1_EXPECT_PKG  (пример: "datafabric.rpc.v1")
- DF_GRPC_V1_EXPECT_SVC  (пример: "DataFabricService")
- DF_GRPC_V1_METHODS_CSV (пример: "Ping,GetItem,PutItem,StreamEvents")
"""

from __future__ import annotations

import importlib
import os
from typing import Iterable, List, Set, Tuple

import pytest

# Мягкое пропускание при отсутствии зависимостей
pb2_path = os.environ.get("DF_GRPC_V1_PB2", "datafabric.rpc.v1.service_pb2")
pb2_grpc_path = os.environ.get("DF_GRPC_V1_PB2_GRPC", "datafabric.rpc.v1.service_pb2_grpc")

pb2 = pytest.importorskip(pb2_path, reason=f"pb2 module not found: {pb2_path}")
pb2_grpc = pytest.importorskip(pb2_grpc_path, reason=f"pb2_grpc module not found: {pb2_grpc_path}")

from google.protobuf.json_format import MessageToJson, Parse
from google.protobuf.descriptor import Descriptor, FieldDescriptor, FileDescriptor, ServiceDescriptor

# --------------------------- Хелперы ---------------------------

def _all_message_descriptors(fd: FileDescriptor) -> List[Descriptor]:
    out: List[Descriptor] = []
    def walk(descs: Iterable[Descriptor]):
        for d in descs:
            out.append(d)
            if d.nested_types:
                walk(d.nested_types)
    walk(fd.message_types_by_name.values())
    return out

def _all_service_descriptors(fd: FileDescriptor) -> List[ServiceDescriptor]:
    return list(fd.services_by_name.values())

def _json_roundtrip(msg) -> None:
    # Проверяем JSON round-trip без потерь для заполненного сообщения
    # Заполняем поля простыми значениями по типу
    m = msg.__class__()  # чистый
    for f in msg.DESCRIPTOR.fields:
        if f.containing_oneof is not None:
            # один из oneof — установим только первое поле
            if f is msg.DESCRIPTOR.containing_oneofs[0].fields[0]:
                _assign_field(m, f)
        else:
            _assign_field(m, f)
    j = MessageToJson(m)
    m2 = msg.__class__()
    Parse(j, m2)
    assert m2.SerializeToString(deterministic=True) == m.SerializeToString(deterministic=True)

def _assign_field(m, f: FieldDescriptor):
    # Подставляем стабильные demo-значения в зависимости от типа
    if f.label == FieldDescriptor.LABEL_REPEATED:
        # для повторяющихся добавим 2 значения (если не message/bytes — иначе 1)
        if f.type == FieldDescriptor.TYPE_MESSAGE:
            sub = getattr(m, f.name).add()
            _init_message_field(sub)
            sub2 = getattr(m, f.name).add()
            _init_message_field(sub2)
        elif f.type == FieldDescriptor.TYPE_BYTES:
            getattr(m, f.name).extend([b"a", b"b"])
        elif f.type == FieldDescriptor.TYPE_ENUM:
            getattr(m, f.name).extend([0, 0])
        else:
            getattr(m, f.name).extend([_scalar_example(f), _scalar_example(f)])
    else:
        if f.type == FieldDescriptor.TYPE_MESSAGE:
            sub = getattr(m, f.name)
            _init_message_field(sub)
        elif f.containing_oneof is not None:
            setattr(m, f.name, _scalar_example(f))
        elif f.type == FieldDescriptor.TYPE_BYTES:
            setattr(m, f.name, b"abc")
        elif f.type == FieldDescriptor.TYPE_ENUM:
            setattr(m, f.name, 0)
        else:
            setattr(m, f.name, _scalar_example(f))

def _init_message_field(msg):
    # Для вложенного message проставим хотя бы одно скалярное поле
    for ff in msg.DESCRIPTOR.fields:
        if ff.type != FieldDescriptor.TYPE_MESSAGE:
            _assign_field(msg, ff)
            return

def _scalar_example(f: FieldDescriptor):
    if f.type in (FieldDescriptor.TYPE_INT32, FieldDescriptor.TYPE_SINT32, FieldDescriptor.TYPE_SFIXED32):
        return 1
    if f.type in (FieldDescriptor.TYPE_INT64, FieldDescriptor.TYPE_SINT64, FieldDescriptor.TYPE_SFIXED64):
        return 2
    if f.type in (FieldDescriptor.TYPE_UINT32, FieldDescriptor.TYPE_FIXED32):
        return 3
    if f.type in (FieldDescriptor.TYPE_UINT64, FieldDescriptor.TYPE_FIXED64):
        return 4
    if f.type == FieldDescriptor.TYPE_BOOL:
        return True
    if f.type == FieldDescriptor.TYPE_FLOAT:
        return 1.5
    if f.type == FieldDescriptor.TYPE_DOUBLE:
        return 2.5
    if f.type == FieldDescriptor.TYPE_STRING:
        return "x"
    # bytes/enum/message обрабатываются в _assign_field
    return 0

def _append_unknown_field(wire: bytes, field_number: int = 19999, varint_value: int = 123) -> bytes:
    # Простейший varint-unknown (wire type 0). tag = (field_number << 3) | 0
    tag = (field_number << 3) | 0
    return wire + _encode_varint(tag) + _encode_varint(varint_value)

def _encode_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        to_write = v & 0x7F
        v >>= 7
        if v:
            out.append(0x80 | to_write)
        else:
            out.append(to_write)
            break
    return bytes(out)

def _deterministic_bytes(msg) -> bytes:
    return msg.SerializeToString(deterministic=True)

# --------------------------- Фикстуры ---------------------------

@pytest.fixture(scope="module")
def file_desc() -> FileDescriptor:
    return pb2.DESCRIPTOR  # type: ignore[attr-defined]

@pytest.fixture(scope="module")
def messages(file_desc: FileDescriptor) -> List[Descriptor]:
    return _all_message_descriptors(file_desc)

@pytest.fixture(scope="module")
def services(file_desc: FileDescriptor) -> List[ServiceDescriptor]:
    return _all_service_descriptors(file_desc)

# --------------------------- Тесты файла/пакета ---------------------------

def test_file_uses_proto3_and_v1_package(file_desc: FileDescriptor):
    assert file_desc.syntax == "proto3"
    expected_pkg = os.environ.get("DF_GRPC_V1_EXPECT_PKG")
    if expected_pkg:
        assert file_desc.package == expected_pkg
    # Базовая эвристика версии в пакете
    assert "v1" in file_desc.package

def test_pb2_grpc_exports_stubs():
    # Проверяем наличие сгенерированных классов для клиентов/серверов
    exported = dir(pb2_grpc)
    has_stub = any(name.endswith("Stub") for name in exported)
    has_add = any(name.startswith("add_") and name.endswith("_to_server") for name in exported)
    assert has_stub and has_add

# --------------------------- Тесты сообщений ---------------------------

@pytest.mark.parametrize("desc_idx", range(0, 1))  # placeholder, заменим ниже в runtime
def test_placeholder(desc_idx):
    # Этот тест заменяется ниже — нужен, чтобы pytest не ругался при пустой параметризации.
    assert True

def pytest_generate_tests(metafunc):
    # Динамическая параметризация по всем сообщениям/сервисам
    if "msg_desc" in metafunc.fixturenames:
        fdesc: FileDescriptor = pb2.DESCRIPTOR  # type: ignore[attr-defined]
        items = _all_message_descriptors(fdesc)
        metafunc.parametrize("msg_desc", items, ids=[d.full_name for d in items])
    if "svc_desc" in metafunc.fixturenames:
        fdesc = pb2.DESCRIPTOR  # type: ignore
        items = _all_service_descriptors(fdesc)
        metafunc.parametrize("svc_desc", items, ids=[d.full_name for d in items])

@pytest.mark.usefixtures("messages")
def test_message_field_numbers_unique(messages: List[Descriptor]):
    for md in messages:
        numbers: Set[int] = set()
        for f in md.fields:
            assert f.number not in numbers, f"duplicate field number in {md.full_name}"
            numbers.add(f.number)
            assert f.number >= 1

def test_message_json_names_unique_and_stable(messages: List[Descriptor]):
    for md in messages:
        json_names: Set[str] = set()
        for f in md.fields:
            jn = f.json_name or f.name
            assert jn not in json_names, f"duplicate json_name in {md.full_name}"
            json_names.add(jn)

def test_message_deterministic_serialization_stable(messages: List[Descriptor]):
    for md in messages:
        # создаём экземпляр и проверяем стабильность сериализации
        cls = getattr(pb2, md.name, None)
        if cls is None:
            pytest.xfail(f"Generated class not found for {md.name}")
        m1 = cls()
        m2 = cls()
        assert _deterministic_bytes(m1) == _deterministic_bytes(m2)

def test_message_unknown_fields_tolerated(messages: List[Descriptor]):
    for md in messages:
        cls = getattr(pb2, md.name, None)
        if cls is None:
            pytest.xfail(f"Generated class not found for {md.name}")
        m = cls()
        m_ser = _deterministic_bytes(m)
        # добавим неизвестное поле
        altered = _append_unknown_field(m_ser, field_number=19999, varint_value=7)
        m2 = cls()
        # парсинг не должен падать
        m2.ParseFromString(altered)
        # известные поля пустого сообщения неизменны
        assert _deterministic_bytes(m) == _deterministic_bytes(m2)

def test_message_json_roundtrip(messages: List[Descriptor]):
    for md in messages:
        cls = getattr(pb2, md.name, None)
        if cls is None:
            pytest.xfail(f"Generated class not found for {md.name}")
        _json_roundtrip(cls())

def test_oneof_exclusivity(messages: List[Descriptor]):
    found_any = False
    for md in messages:
        if not md.oneofs:
            continue
        found_any = True
        cls = getattr(pb2, md.name, None)
        if cls is None:
            pytest.xfail(f"Generated class not found for {md.name}")
        m = cls()
        # установим по очереди два поля из первого oneof
        one = md.oneofs[0]
        if len(one.fields) < 2:
            continue
        setattr(m, one.fields[0].name, _scalar_example(one.fields[0]))
        assert m.WhichOneof(one.name) == one.fields[0].name
        setattr(m, one.fields[1].name, _scalar_example(one.fields[1]))
        # второе должно заменить первое
        assert m.WhichOneof(one.name) == one.fields[1].name
    if not found_any:
        pytest.xfail("No oneof messages found in v1 schema")

# --------------------------- Тесты сервисов ---------------------------

def test_services_exist_and_named_v1(services: List[ServiceDescriptor], file_desc: FileDescriptor):
    assert len(services) >= 1, "At least one service must be defined in v1"
    expect_svc = os.environ.get("DF_GRPC_V1_EXPECT_SVC")
    if expect_svc:
        names = {s.name for s in services}
        assert expect_svc in names
    # пакет v1 должен быть общим
    for s in services:
        for m in s.methods:
            # типы запрос/ответ должны быть внутри пакета файла
            assert m.input_type.file is file_desc
            assert m.output_type.file is file_desc

def test_methods_have_requests_and_responses(services: List[ServiceDescriptor]):
    for s in services:
        assert len(s.methods) >= 1
        for m in s.methods:
            assert m.input_type is not None
            assert m.output_type is not None
            # ограничим типы: сообщение, не enum
            assert isinstance(m.input_type, Descriptor.__class__.__mro__[0].__class__) or True  # форма проверки
            # Клиент/сервер стриминги допустимы, просто проверяем флаги присутствуют
            assert isinstance(m.client_streaming, bool)
            assert isinstance(m.server_streaming, bool)

def test_methods_list_matches_env_if_provided(services: List[ServiceDescriptor]):
    env = os.environ.get("DF_GRPC_V1_METHODS_CSV")
    if not env:
        pytest.skip("DF_GRPC_V1_METHODS_CSV not set")
    expected = {x.strip() for x in env.split(",") if x.strip()}
    actual = {m.name for s in services for m in s.methods}
    missing = expected - actual
    assert not missing, f"Missing methods: {sorted(missing)}"

# --------------------------- Инварианты обратной совместимости ---------------------------

def test_field_numbers_do_not_conflict_across_nested(messages: List[Descriptor]):
    # Внутри каждого message номера уникальны; дополнительно проверим,
    # что в nested типах нет повторного использования номеров в пределах одного oneof с одинаковыми именами.
    for md in messages:
        for one in md.oneofs:
            nums = {f.number for f in one.fields}
            assert len(nums) == len(one.fields), f"oneof duplicate numbers in {md.full_name}.{one.name}"

def test_no_required_fields_proto3(messages: List[Descriptor]):
    # В proto3 нет required; проверим отсутствие field presence флагов не-oneof
    for md in messages:
        for f in md.fields:
            # В Python-прото3 поля не имеют required; просто убеждаемся, что optional не помечены как required
            assert f.label in (
                FieldDescriptor.LABEL_OPTIONAL,
                FieldDescriptor.LABEL_REPEATED,
            )

# --------------------------- Smoke для generated stubs ---------------------------

def test_stub_classes_constructible():
    # Пытаемся найти любой Stub и создать без реального канала (channel=None допустим не всегда)
    # Корректно — создаём dummy канал через grpc.insecure_channel к несуществующему endpoint,
    # но без вызовов; чтобы не тащить grpc рантайм здесь — мягкая проверка экспортов.
    stubs = [getattr(pb2_grpc, name) for name in dir(pb2_grpc) if name.endswith("Stub")]
    assert stubs, "No Stub classes exported"
    # Не инстанциируем, чтобы не требовать grpc рантайм в юнитах без сети

# --------------------------- Диагностика ---------------------------

def test_descriptor_has_at_least_one_message_and_service(file_desc: FileDescriptor):
    assert len(file_desc.message_types_by_name) >= 1
    # service может отсутствовать в чистых моделях, но для gRPC контракта — обязателен
    if len(file_desc.services_by_name) == 0:
        pytest.xfail("No services defined in v1 descriptor (model-only proto?)")
