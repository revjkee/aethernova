# veilmind-core/tests/contract/test_grpc_v1.proto_contract.py
# -*- coding: utf-8 -*-
"""
Контрактный тест gRPC/protobuf v1 для VeilMind.

Проверяет:
- Синтаксис proto3 и корректность пакета (veilmind.* v1).
- Наличие сообщений DetectRequest/DetectResponse и стабильность критичных полей.
- Наличие сервиса с методом Evaluate(DetectRequest) -> DetectResponse.
- Фиксацию номеров полей DetectRequest: event (#1) и explain (#2).
- Базовый набор обязательных полей в DetectResponse.
"""

from __future__ import annotations

import importlib
from typing import Iterable, Optional

import pytest

try:
    from google.protobuf.descriptor import (
        FileDescriptor,
        Descriptor,
        FieldDescriptor,
        ServiceDescriptor,
    )
except Exception as e:  # pragma: no cover
    pytest.skip(f"google.protobuf (protobuf runtime) недоступен: {e!r}")

PB2_CANDIDATES = [
    "veilmind.schemas.proto.v1.veilmind.detect_pb2",
    "veilmind.schemas.proto.v1.detect_pb2",
    "schemas.proto.v1.veilmind.detect_pb2",
    "schemas.proto.v1.detect_pb2",
    "veilmind_core.schemas.proto.v1.veilmind.detect_pb2",
    "veilmind_core.schemas.proto.v1.detect_pb2",
]
GRPC_CANDIDATES = [m.replace("_pb2", "_pb2_grpc") for m in PB2_CANDIDATES]


def _import_pb2():
    last = None
    for n in PB2_CANDIDATES:
        try:
            return importlib.import_module(n)
        except Exception as e:
            last = e
            continue
    pytest.skip(f"Не удалось импортировать detect_pb2. Пробовали: {PB2_CANDIDATES}. Последняя ошибка: {last!r}")


def _import_grpc_optional():
    for n in GRPC_CANDIDATES:
        try:
            return importlib.import_module(n)
        except Exception:
            continue
    return None


PB2 = _import_pb2()
PB2_GRPC = _import_grpc_optional()


def _get_file_descriptor(mod) -> FileDescriptor:
    fd = getattr(mod, "DESCRIPTOR", None)
    if not isinstance(fd, FileDescriptor):
        pytest.skip("В модуле *_pb2 отсутствует корректный FileDescriptor DESCRIPTOR")
    return fd


def _find_message(fd: FileDescriptor, *names: str) -> Optional[Descriptor]:
    pool = fd.pool
    pkg = fd.package or ""
    candidates = []
    for n in names:
        if not n:
            continue
        n = n.strip(".")
        candidates.extend([n, f"{pkg}.{n}" if pkg else n])
        if not n.endswith("Request"):
            candidates.append(n + "Request")
        if not n.endswith("Response"):
            candidates.append(n + "Response")
    for name in candidates:
        try:
            d = pool.FindMessageTypeByName(name)
            if isinstance(d, Descriptor):
                return d
        except Exception:
            continue
    for md in fd.message_types_by_name.values():
        if any(md.name.lower() == n.lower() for n in names if n):
            return md
    return None


def _find_service(fd: FileDescriptor, *name_hints: str) -> Optional[ServiceDescriptor]:
    for s in fd.services_by_name.values():
        if any(h and h.lower() in s.name.lower() for h in name_hints):
            return s
    for s in fd.services_by_name.values():
        if any(m.name.lower() == "evaluate" for m in s.methods):
            return s
    return next(iter(fd.services_by_name.values()), None)


def _field_map(desc: Descriptor) -> dict[str, FieldDescriptor]:
    return {f.name: f for f in desc.fields}


def test_proto_package_and_syntax():
    fd = _get_file_descriptor(PB2)
    assert fd.syntax == "proto3", "Ожидается proto3 синтаксис"
    pkg = fd.package or ""
    assert "veilmind" in pkg, f"Ожидался пакет содержащий 'veilmind', получен: {pkg!r}"
    assert "v1" in pkg, f"Ожидалась версия 'v1' в имени пакета, получен: {pkg!r}"


def test_messages_presence_and_fields():
    fd = _get_file_descriptor(PB2)
    req = _find_message(fd, "DetectRequest", "Request", "Detect")
    assert isinstance(req, Descriptor), "Сообщение DetectRequest не найдено"
    req_fields = _field_map(req)
    assert "event" in req_fields, "В DetectRequest отсутствует поле 'event'"
    assert req_fields["event"].number == 1, "Поле 'event' должно иметь номер 1"
    assert "explain" in req_fields, "В DetectRequest отсутствует поле 'explain'"
    assert req_fields["explain"].number == 2, "Поле 'explain' должно иметь номер 2"
    assert req_fields["explain"].type == FieldDescriptor.TYPE_BOOL, "Поле 'explain' должно быть bool"

    resp = _find_message(fd, "DetectResponse", "Response", "Detect")
    assert isinstance(resp, Descriptor), "Сообщение DetectResponse не найдено"
    resp_fields = set(_field_map(resp).keys())
    required_resp = {
        "correlation_id",
        "score_raw",
        "score",
        "decision",
        "hard_rule_triggered",
        "thresholds",
        "factors",
        "ts",
    }
    missing = required_resp - resp_fields
    assert not missing, f"В DetectResponse отсутствуют поля: {sorted(missing)}"


def test_service_and_method_signature():
    fd = _get_file_descriptor(PB2)
    svc = _find_service(fd, "Detect", "Detection", "Risk", "Evaluate")
    assert isinstance(svc, ServiceDescriptor), "gRPC сервис обнаружения не найден"
    method = next((m for m in svc.methods if m.name.lower() == "evaluate"), None)
    assert method is not None, f"В сервисе {svc.name} отсутствует метод Evaluate"
    in_type, out_type = method.input_type, method.output_type
    assert in_type and out_type, "У метода Evaluate отсутствуют типы входа/выхода"
    assert "request" in in_type.name.lower(), f"Тип запроса должен быть DetectRequest, получен: {in_type.full_name}"
    assert "response" in out_type.name.lower(), f"Тип ответа должен быть DetectResponse, получен: {out_type.full_name}"


def test_no_field_number_regressions_for_request():
    fd = _get_file_descriptor(PB2)
    req = _find_message(fd, "DetectRequest", "Request", "Detect")
    assert isinstance(req, Descriptor), "DetectRequest не найден"
    numbers = {f.name: f.number for f in req.fields}
    expected = {"event": 1, "explain": 2}
    for name, num in expected.items():
        assert numbers.get(name) == num, f"Нарушена стабильность номера поля '{name}': ожидался {num}, получен {numbers.get(name)}"


@pytest.mark.skipif(PB2_GRPC is None, reason="gRPC python stабы недоступны")
def test_grpc_stub_exports():
    svc_attrs = [a for a in dir(PB2_GRPC) if a.endswith("Stub")]
    assert svc_attrs, "В *_pb2_grpc не обнаружены классы Stub"
    servicers = [a for a in dir(PB2_GRPC) if a.endswith("Servicer")]
    assert servicers, "В *_pb2_grpc не обнаружены классы Servicer"
