# -*- coding: utf-8 -*-
"""
Промышленная контрактная проверка для gRPC v1.

Что делает:
1) Динамически собирает дескрипторы всех загруженных Protobuf-модулей,
   отфильтровывает по пакету/имени, содержащему версию "v1".
2) Валидирует:
   - стиль имён сообщений/сервисов/методов/полей (PascalCase, lowerCamelCase, snake_case);
   - уникальность и положительность номеров полей, отсутствие дубликатов;
   - корректность enum и уникальность значений;
   - что у каждого RPC есть Request/Response типы;
3) Сравнивает текущий FileDescriptorSet с «золотым» снимком, если он существует
   (по умолчанию: tests/contract/testdata/test_grpc_v1.desc), чтобы отследить
   обратную совместимость (номера полей, наличие RPC и т.п.).
4) Предоставляет CLI: python -m engine.contract.test_grpc_v1.proto_contract --write-golden <path>

Зависимости: pytest, protobuf (google.protobuf)
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pytest
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pb2
from google.protobuf import json_format
from google.protobuf import symbol_database as _symbol_database


# -----------------------------
# ПАРАМЕТРЫ/КОНФИГ
# -----------------------------
# Пакеты/файлы, которые считаем v1-контрактом (регэксп применяется к package, full_name и имени файла)
V1_FILTER_REGEX = os.getenv("GRPC_V1_FILTER_REGEX", r"(?:^|\.)(v1)(?:\.|$)")
# Путь «золотого» снимка дескрипторов (FileDescriptorSet)
DEFAULT_GOLDEN_PATH = Path(
    os.getenv(
        "GRPC_V1_GOLDEN_DESCRIPTOR",
        "engine/tests/contract/testdata/test_grpc_v1.desc",
    )
)

# Для строгой стилистики имён
RE_PASCAL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
RE_LOWER_CAMEL = re.compile(r"^[a-z][A-Za-z0-9]*$")
RE_SNAKE = re.compile(r"^[a-z][a-z0-9_]*$")


# -----------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# -----------------------------
def _iter_loaded_message_types() -> Iterable[Tuple[str, type]]:
    """
    Возвращает пары (full_name, message_class) для всех загруженных типов сообщений.
    Использует реестр символов Protobuf.
    """
    sym_db = _symbol_database.Default()

    # NB: _classes — внутренний атрибут, но это де-факто стандартный способ для инспекции
    # загруженных типов сообщений в рантайме Python Protobuf.
    classes = getattr(sym_db, "_classes", {})  # type: ignore[attr-defined]
    for full_name, cls in classes.items():
        yield full_name, cls


def _collect_file_descriptors_for_v1() -> List[_descriptor.FileDescriptor]:
    """
    Собирает уникальные FileDescriptor для всех типов сообщений, удовлетворяющих фильтру V1.
    """
    file_by_name: Dict[str, _descriptor.FileDescriptor] = {}
    v1_re = re.compile(V1_FILTER_REGEX)

    for full_name, cls in _iter_loaded_message_types():
        msg_desc: _descriptor.Descriptor = cls.DESCRIPTOR
        file_desc: _descriptor.FileDescriptor = msg_desc.file

        # Кандидаты: если пакет/полное имя/имя файла соответствует v1
        package = file_desc.package or ""
        file_name = file_desc.name or ""
        if any(
            v1_re.search(s or "")
            for s in (package, full_name, file_name)
        ):
            file_by_name[file_desc.name] = file_desc

    return list(file_by_name.values())


def _fd_to_proto(fd: _descriptor.FileDescriptor) -> descriptor_pb2.FileDescriptorProto:
    proto = descriptor_pb2.FileDescriptorProto()
    proto.ParseFromString(fd.serialized_pb)
    return proto


def _build_fdset(files: Iterable[_descriptor.FileDescriptor]) -> descriptor_pb2.FileDescriptorSet:
    fdset = descriptor_pb2.FileDescriptorSet()
    seen: Set[str] = set()
    for fd in files:
        if fd.name in seen:
            continue
        seen.add(fd.name)
        proto = _fd_to_proto(fd)
        fdset.file.append(proto)
    # Стабилизируем порядок для детерминированных сравнений
    fdset.file.sort(key=lambda f: (f.package, f.name))
    return fdset


def _read_fdset(path: Path) -> Optional[descriptor_pb2.FileDescriptorSet]:
    if not path.exists():
        return None
    data = path.read_bytes()
    fdset = descriptor_pb2.FileDescriptorSet()
    fdset.ParseFromString(data)
    return fdset


def _fdset_to_json(fdset: descriptor_pb2.FileDescriptorSet) -> str:
    # Преобразуем в JSON для наглядных diff-ов при падениях тестов
    return json_format.MessageToJson(fdset, including_default_value_fields=False, sort_keys=True)


def _normalize_for_contract(fdset: descriptor_pb2.FileDescriptorSet) -> descriptor_pb2.FileDescriptorSet:
    """
    Нормализация для сравнения контрактов:
    - сортируем файлы, сообщения, поля, сервисы
    - удаляем нестабильные/не влияющие на контракт поля (source_code_info и прочие комментарии)
    """
    norm = descriptor_pb2.FileDescriptorSet()
    for f in fdset.file:
        f2 = descriptor_pb2.FileDescriptorProto()
        f2.CopyFrom(f)
        # Удаляем комментарии и нестабильные поля
        if f2.HasField("source_code_info"):
            f2.ClearField("source_code_info")
        # Стабилизация порядка сообщений
        f2.message_type.sort(key=lambda m: m.name)
        for m in f2.message_type:
            m.field.sort(key=lambda fld: fld.number)
            m.nested_type.sort(key=lambda x: x.name)
            m.enum_type.sort(key=lambda e: e.name)
        # Стабилизация сервисов/методов
        f2.service.sort(key=lambda s: s.name)
        for s in f2.service:
            s.method.sort(key=lambda mm: mm.name)
        # Стабилизация enum
        f2.enum_type.sort(key=lambda e: e.name)
        for e in f2.enum_type:
            e.value.sort(key=lambda vv: vv.number)
        norm.file.append(f2)
    norm.file.sort(key=lambda ff: (ff.package, ff.name))
    return norm


def _assert_style(name: str, regex: re.Pattern, kind: str) -> None:
    if not regex.match(name):
        pytest.fail(f"Style violation for {kind} '{name}'")


# -----------------------------
# ТЕСТЫ СТАТИЧЕСКОЙ ВАЛИДАЦИИ
# -----------------------------
@pytest.mark.parametrize("fd", _collect_file_descriptors_for_v1(), ids=lambda f: f.name)
def test_file_package_contains_v1(fd: _descriptor.FileDescriptor) -> None:
    v1_re = re.compile(V1_FILTER_REGEX)
    pkg = fd.package or ""
    file_name = fd.name or ""
    if not (v1_re.search(pkg) or v1_re.search(file_name)):
        pytest.skip(f"File {fd.name} does not look like v1; filter={V1_FILTER_REGEX}")


@pytest.mark.parametrize("fd", _collect_file_descriptors_for_v1(), ids=lambda f: f.name)
def test_message_and_field_styles_and_numbers(fd: _descriptor.FileDescriptor) -> None:
    # Имена сообщений/полей и номера полей
    for msg in fd.message_types_by_name.values():
        _assert_style(msg.name, RE_PASCAL, "message")
        seen_numbers: Set[int] = set()
        for fld in msg.fields:
            # snake_case поля
            _assert_style(fld.name, RE_SNAKE, f"field of {msg.full_name}")
            assert fld.number > 0, f"Field number must be positive: {msg.full_name}.{fld.name}"
            assert fld.number not in seen_numbers, (
                f"Duplicate field number {fld.number} in {msg.full_name}"
            )
            seen_numbers.add(fld.number)

        # Вложенные типы
        for nmsg in msg.nested_types:
            _assert_style(nmsg.name, RE_PASCAL, f"nested message in {msg.full_name}")
        for en in msg.enum_types:
            _assert_style(en.name, RE_PASCAL, f"enum in {msg.full_name}")
            seen_enum_values: Set[int] = set()
            for ev in en.values:
                # Enum константы обычно SCREAMING_SNAKE_CASE, но в дескрипторах это имя значения
                # Здесь проверим как минимум отсутствие дубликатов номеров
                assert ev.number not in seen_enum_values, (
                    f"Duplicate enum number {ev.number} in {en.full_name}"
                )
                seen_enum_values.add(ev.number)


@pytest.mark.parametrize("fd", _collect_file_descriptors_for_v1(), ids=lambda f: f.name)
def test_service_and_method_shapes(fd: _descriptor.FileDescriptor) -> None:
    # Имена сервисов и методов; проверка наличия Request/Response
    for svc in fd.services_by_name.values():
        _assert_style(svc.name, RE_PASCAL, "service")
        for m in svc.methods:
            _assert_style(m.name, RE_LOWER_CAMEL, f"method in service {svc.full_name}")
            assert m.input_type is not None, f"Method {svc.full_name}.{m.name} must have input_type"
            assert m.output_type is not None, f"Method {svc.full_name}.{m.name} must have output_type"
            # Проверим, что Request/Response находятся в том же пакете (часто рекомендуется)
            in_pkg = m.input_type.file.package or ""
            out_pkg = m.output_type.file.package or ""
            svc_pkg = fd.package or ""
            assert in_pkg == svc_pkg, (
                f"Input type package mismatch for {svc.full_name}.{m.name}: {in_pkg} != {svc_pkg}"
            )
            assert out_pkg == svc_pkg, (
                f"Output type package mismatch for {svc.full_name}.{m.name}: {out_pkg} != {svc_pkg}"
            )


# -----------------------------
# ТЕСТ ОБРАТНОЙ СОВМЕСТИМОСТИ (FDSET)
# -----------------------------
def _current_v1_fdset() -> descriptor_pb2.FileDescriptorSet:
    files = _collect_file_descriptors_for_v1()
    assert files, (
        "Не найдено ни одного v1 FileDescriptor. "
        "Убедитесь, что protobuf-модули v1 импортированы до запуска тестов "
        "(например, import engine.contract.v1.*_pb2 и *_pb2_grpc)."
    )
    return _build_fdset(files)


@pytest.mark.contract
def test_descriptor_set_matches_golden_snapshot() -> None:
    """
    Если «золотой» снимок существует — сравниваем нормализованные дескрипторы.
    Это защищает от несовместимых изменений:
      - переиспользование или смена номеров полей,
      - переименование RPC/сообщений,
      - удаление методов/полей без резервирования и миграций.
    """
    golden = _read_fdset(DEFAULT_GOLDEN_PATH)
    if golden is None:
        pytest.skip(f"Golden descriptor snapshot not found: {DEFAULT_GOLDEN_PATH}")

    current = _current_v1_fdset()
    golden_n = _normalize_for_contract(golden)
    current_n = _normalize_for_contract(current)

    golden_json = _fdset_to_json(golden_n)
    current_json = _fdset_to_json(current_n)

    if golden_json != current_json:
        # Печатаем дифф‑подсказку в лог (урезанно), чтобы понимать причину
        # Полный diff оставляем внешним инструментам CI (например, pytest --maxfail=1 -q с артефактами)
        msg = [
            "Contract drift detected between current descriptors and golden snapshot.",
            f"Golden path: {DEFAULT_GOLDEN_PATH}",
            "ACTION: если изменения ожидаемы и совместимы, обновите снимок через:",
            "  python -m engine.contract.test_grpc_v1.proto_contract --write-golden engine/tests/contract/testdata/test_grpc_v1.desc",
        ]
        # Для удобства — вывести первые 2К символов для каждой версии
        snippet_sz = 2000
        msg.append("\n--- GOLDEN (head) ---\n" + golden_json[:snippet_sz])
        msg.append("\n--- CURRENT (head) ---\n" + current_json[:snippet_sz])
        pytest.fail("\n".join(msg))


# -----------------------------
# CLI ДЛЯ ГЕНЕРАЦИИ GOLDEN SNAPSHOT
# -----------------------------
def _write_golden(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fdset = _current_v1_fdset()
    norm = _normalize_for_contract(fdset)
    path.write_bytes(norm.SerializeToString())
    print(f"[OK] Golden descriptor snapshot written: {path}")


def _main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="gRPC v1 contract verifier / golden snapshot manager"
    )
    parser.add_argument(
        "--write-golden",
        type=str,
        help="Write normalized descriptor set to the given path (creates dirs).",
    )
    parser.add_argument(
        "--dump-json",
        action="store_true",
        help="Dump current normalized descriptor set as JSON to stdout.",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Override V1 filter regex (applies to package/full_name/file).",
    )
    args = parser.parse_args(argv)

    if args.filter:
        os.environ["GRPC_V1_FILTER_REGEX"] = args.filter

    if args.write_golden:
        _write_golden(Path(args.write_golden))
        return 0

    if args.dump_json:
        fdset = _normalize_for_contract(_current_v1_fdset())
        sys.stdout.write(_fdset_to_json(fdset) + "\n")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
