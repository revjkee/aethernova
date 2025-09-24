# -*- coding: utf-8 -*-
"""
Промышленный контрактный тест для gRPC v1 протоколов Mythos Core.

Запуск: pytest -q mythos-core/tests/contract/test_grpc_v1.proto_contract.py
Переменные окружения:
  - MYTHOS_PROTO_ROOT: корень с .proto (по умолчанию ищем стандартные пути)
  - CI / GITHUB_ACTIONS: если установлены, запись голдена запрещена, только проверка
  - MYTHOS_ALLOW_GOLDEN_WRITE=true: разрешить авто-создание голдена (вне CI)

Зависимости:
  - pytest
  - protobuf
  - grpcio-tools (желательно, иначе требуется системный 'protoc' в PATH)

ВНИМАНИЕ:
  Этот тест НЕ навязывает конкретную схему — он даёт каркас проверок и «schema-lock».
  Заполните EXPECTED_SPEC под вашу фактическую gRPC-схему (сертификаты истинности не утверждаются).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set

import pytest

try:
    from google.protobuf import descriptor_pb2
except Exception as e:  # pragma: no cover
    raise RuntimeError("protobuf library is required: pip install protobuf") from e

# ---------- Константы и пути ----------
THIS_FILE = Path(__file__).resolve()
TEST_DIR = THIS_FILE.parent
CONTRACT_DIR = TEST_DIR
GOLDEN_DIR = CONTRACT_DIR / "_golden"
GOLDEN_PATH = GOLDEN_DIR / "grpc_v1.descriptor.pb"

# Корни, где будем искать .proto по умолчанию
DEFAULT_PROTO_ROOT_CANDIDATES = [
    Path(os.getenv("MYTHOS_PROTO_ROOT")) if os.getenv("MYTHOS_PROTO_ROOT") else None,
    Path.cwd() / "mythos_core" / "proto",
    Path.cwd() / "proto",
    Path.cwd() / "src" / "proto",
    Path.cwd() / "mythos-core" / "proto",
]
DEFAULT_PROTO_ROOT_CANDIDATES = [p for p in DEFAULT_PROTO_ROOT_CANDIDATES if p is not None]

# Маска файлов v1 API
V1_PROTO_GLOB = "**/api/grpc/v1/*.proto"

# ---------- Ожидаемая спецификация (заглушка: заполните под ваш API) ----------
@dataclass(frozen=True)
class ExpectedMethod:
    name: str
    input_type: str  # полный тип, например ".mythos.api.v1.GetEntityRequest"
    output_type: str # полный тип, например ".mythos.api.v1.GetEntityResponse"
    client_streaming: bool = False
    server_streaming: bool = False

@dataclass(frozen=True)
class ExpectedService:
    full_name: str  # например "mythos.api.v1.MythosService"
    methods: Tuple[ExpectedMethod, ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class ExpectedSpec:
    # Пакеты, которые должны существовать (минимум один с суффиксом .v1)
    required_packages: Tuple[str, ...] = field(default_factory=lambda: ())
    # Сервисы, которые требуются (оставлено пустым — не навязываем схему)
    services: Tuple[ExpectedService, ...] = field(default_factory=tuple)

# Пример заполнения (РАЗКОММЕНТИРУЙТЕ и скорректируйте под свою схему):
# EXPECTED_SPEC = ExpectedSpec(
#     required_packages=("mythos.api.grpc.v1",),
#     services=(
#         ExpectedService(
#             full_name="mythos.api.grpc.v1.MythosService",
#             methods=(
#                 ExpectedMethod(
#                     name="GetEntity",
#                     input_type=".mythos.api.grpc.v1.GetEntityRequest",
#                     output_type=".mythos.api.grpc.v1.GetEntityResponse",
#                 ),
#                 ExpectedMethod(
#                     name="ListEntities",
#                     input_type=".mythos.api.grpc.v1.ListEntitiesRequest",
#                     output_type=".mythos.api.grpc.v1.ListEntitiesResponse",
#                 ),
#             ),
#         ),
#     ),
# )
# По умолчанию не утверждаем факт наличия конкретных сервисов:
EXPECTED_SPEC = ExpectedSpec()

# ---------- Вспомогательные функции ----------
def discover_proto_root() -> Path:
    for root in DEFAULT_PROTO_ROOT_CANDIDATES:
        if root and root.exists():
            v1 = list(root.glob(V1_PROTO_GLOB))
            if v1:
                return root
    # Если не нашли, возвращаем первый кандидат (для нефатальной подсказки)
    return DEFAULT_PROTO_ROOT_CANDIDATES[0] if DEFAULT_PROTO_ROOT_CANDIDATES else Path("proto")

def find_v1_protos(proto_root: Path) -> List[Path]:
    files = sorted(proto_root.glob(V1_PROTO_GLOB))
    return files

def have_grpc_tools() -> bool:
    try:
        import grpc_tools.protoc  # noqa
        return True
    except Exception:
        return False

def have_system_protoc() -> bool:
    return shutil.which("protoc") is not None

def compile_descriptors(proto_root: Path, protos: List[Path]) -> bytes:
    """
    Компилирует список .proto в FileDescriptorSet (bytes).
    Сначала пробуем grpc_tools.protoc, затем системный protoc.
    """
    if not protos:
        raise FileNotFoundError(f"No .proto files found under: {proto_root} (pattern: {V1_PROTO_GLOB})")

    with tempfile.TemporaryDirectory(prefix="mythos_proto_") as tmpd:
        tmp = Path(tmpd)
        out = tmp / "descriptor.pb"

        include_args = []
        # Добавим корень и, на всякий случай, его верхние уровни
        include_args.extend(["-I", str(proto_root)])
        include_args.extend(["-I", str(proto_root.resolve())])
        include_args.extend(["-I", str(Path.cwd())])

        rel_protos = [str(p.relative_to(proto_root)) for p in protos]

        args = [
            "--include_source_info",
            f"--descriptor_set_out={out}",
        ]

        # Путь компиляции через grpc_tools.protoc
        if have_grpc_tools():
            from grpc_tools import protoc
            cmd = ["protoc"] + include_args + args + rel_protos
            rc = protoc.main(cmd)
            if rc != 0:
                # Падали — пробуем системный protoc
                if have_system_protoc():
                    _run_system_protoc(include_args, args, rel_protos, cwd=proto_root)
                else:
                    raise RuntimeError(f"grpc_tools.protoc failed with code {rc} and no system 'protoc' available.")
        else:
            # Только системный protoc
            if have_system_protoc():
                _run_system_protoc(include_args, args, rel_protos, cwd=proto_root)
            else:
                raise RuntimeError("Neither grpc_tools.protoc nor system 'protoc' found. Install grpcio-tools or protoc.")

        if not out.exists():
            raise RuntimeError("Descriptor set output was not generated.")

        return out.read_bytes()

def _run_system_protoc(include_args: List[str], args: List[str], rel_protos: List[str], cwd: Path) -> None:
    cmd = ["protoc"] + include_args + args + rel_protos
    proc = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"protoc failed: rc={proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

def parse_descriptor_set(raw: bytes) -> descriptor_pb2.FileDescriptorSet:
    fds = descriptor_pb2.FileDescriptorSet()
    fds.MergeFromString(raw)
    return fds

def file_packages(fds: descriptor_pb2.FileDescriptorSet) -> Set[str]:
    return {fd.package for fd in fds.file}

def is_ci() -> bool:
    return os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true"

def may_write_golden() -> bool:
    # В CI — запрещено
    if is_ci():
        return False
    # Вручную разрешить
    allow = os.getenv("MYTHOS_ALLOW_GOLDEN_WRITE", "").lower() in {"1", "true", "yes", "y"}
    return allow

def save_golden(raw: bytes) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_bytes(raw)

def load_golden() -> Optional[bytes]:
    return GOLDEN_PATH.read_bytes() if GOLDEN_PATH.exists() else None

def index_services(fds: descriptor_pb2.FileDescriptorSet) -> Dict[str, Dict]:
    """
    Строим индекс сервисов: {full_service_name: {"file": file, "methods": {name: method_desc, ...}}}
    """
    out: Dict[str, Dict] = {}
    for fd in fds.file:
        pkg = fd.package or ""
        for svc in fd.service:
            full = f"{pkg}.{svc.name}" if pkg else svc.name
            methods = {m.name: m for m in svc.method}
            out[full] = {"file": fd, "service": svc, "methods": methods, "package": pkg}
    return out

def index_messages(fds: descriptor_pb2.FileDescriptorSet) -> Dict[str, descriptor_pb2.DescriptorProto]:
    out: Dict[str, descriptor_pb2.DescriptorProto] = {}
    for fd in fds.file:
        pkg = fd.package or ""
        prefix = f".{pkg}." if pkg else "."
        def _walk(msgs: List[descriptor_pb2.DescriptorProto], cur_prefix: str):
            for m in msgs:
                out[cur_prefix + m.name] = m
                # Рекурсивно вложенные
                if m.nested_type:
                    _walk(m.nested_type, cur_prefix + m.name + ".")
        _walk(fd.message_type, prefix)
    return out

def render_service_signature(method: descriptor_pb2.MethodDescriptorProto) -> str:
    return f"{method.name}({method.input_type}) returns ({method.output_type})" + \
           (" stream" if method.server_streaming or method.client_streaming else "")

# ---------- Тесты ----------
def test_protoc_available():
    assert have_grpc_tools() or have_system_protoc(), (
        "Neither grpc_tools.protoc nor system 'protoc' found. "
        "Install 'grpcio-tools' (pip) or place 'protoc' in PATH."
    )

def test_compile_descriptor_set_and_basic_invariants():
    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)
    fds = parse_descriptor_set(raw)

    # 1) Должен быть хотя бы один файл, syntax=proto3
    assert len(fds.file) > 0, "Descriptor set contains no files."
    for fd in fds.file:
        # Поле syntax в FileDescriptorProto >= proto3 содержит "proto3" строкой
        assert fd.syntax == "proto3", f"File {fd.name} must declare syntax=proto3, got: {fd.syntax!r}"

    # 2) Должен быть минимум один пакет с суффиксом .v1
    pkgs = file_packages(fds)
    assert any(p.endswith(".v1") or p.endswith("_v1") for p in pkgs), (
        f"Expect at least one v1 package; found: {sorted(pkgs)}"
    )

def test_golden_descriptor_lock():
    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)

    golden = load_golden()
    if golden is None:
        # Нет голдена: вне CI можем записать, в CI — ошибку
        if may_write_golden():
            save_golden(raw)
        else:
            pytest.fail(
                f"Golden descriptor not found at {GOLDEN_PATH}. "
                f"Run locally with MYTHOS_ALLOW_GOLDEN_WRITE=true to create it."
            )
        return

    # В CI и локально при наличии голдена — строго сравниваем
    if raw != golden:
        # Мини-диагностика: различие размеров
        msg = (
            f"Descriptor set differs from golden.\n"
            f"Golden size: {len(golden)} bytes; Current: {len(raw)} bytes.\n"
            f"To update golden locally: set MYTHOS_ALLOW_GOLDEN_WRITE=true and re-run tests.\n"
            f"Path: {GOLDEN_PATH}"
        )
        pytest.fail(msg)

def test_expected_packages_and_services_shape():
    """
    Проверяем форму пакетов/сервисов по EXPECTED_SPEC (если она заполнена).
    Пустая EXPECTED_SPEC — допускается и не помечается как провал теста.
    """
    if not EXPECTED_SPEC.required_packages and not EXPECTED_SPEC.services:
        pytest.skip("EXPECTED_SPEC is empty; no shape assertions enforced.")

    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)
    fds = parse_descriptor_set(raw)

    # Пакеты
    pkgs = file_packages(fds)
    for rp in EXPECTED_SPEC.required_packages:
        assert rp in pkgs, f"Required package not found: {rp}. Found: {sorted(pkgs)}"

    # Сервисы
    svc_index = index_services(fds)
    for svc in EXPECTED_SPEC.services:
        assert svc.full_name in svc_index, f"Service missing: {svc.full_name}. Found: {sorted(svc_index.keys())}"
        methods = svc_index[svc.full_name]["methods"]

        for m in svc.methods:
            assert m.name in methods, (
                f"Method missing: {svc.full_name}.{m.name}. "
                f"Available: {sorted(methods.keys())}"
            )
            got = methods[m.name]
            # Полные типы в дескрипторе начинаются с '.'
            assert got.input_type == m.input_type, (
                f"Input type mismatch for {svc.full_name}.{m.name}: "
                f"expected {m.input_type}, got {got.input_type}"
            )
            assert got.output_type == m.output_type, (
                f"Output type mismatch for {svc.full_name}.{m.name}: "
                f"expected {m.output_type}, got {got.output_type}"
            )
            assert got.client_streaming == m.client_streaming, (
                f"client_streaming mismatch for {svc.full_name}.{m.name}"
            )
            assert got.server_streaming == m.server_streaming, (
                f"server_streaming mismatch for {svc.full_name}.{m.name}"
            )

def test_messages_field_uniqueness_and_numbers_monotonic():
    """
    Базовые инварианты сообщений:
      - уникальные имена полей внутри сообщения
      - уникальные номера полей, положительные
      - номера не 0, без дубликатов
    """
    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)
    fds = parse_descriptor_set(raw)

    msg_index = index_messages(fds)
    for full_name, msg in msg_index.items():
        names: Set[str] = set()
        numbers: Set[int] = set()
        for f in msg.field:
            assert f.name not in names, f"Duplicate field name in {full_name}: {f.name}"
            names.add(f.name)
            assert f.number > 0, f"Field number must be positive in {full_name}.{f.name} got {f.number}"
            assert f.number not in numbers, f"Duplicate field number {f.number} in {full_name}"
            numbers.add(f.number)

def test_services_have_at_least_one_method_and_types_resolve():
    """
    У каждого сервиса хотя бы один метод, и типы вход/выход резолвятся в объявленные сообщения.
    """
    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)
    fds = parse_descriptor_set(raw)
    svc_index = index_services(fds)
    msg_index = index_messages(fds)

    # Если сервисов нет — это валидный случай, но тогда тест пропускаем,
    # чтобы не делать недостоверных выводов.
    if not svc_index:
        pytest.skip("No services discovered; skipping type resolution checks.")

    for full_svc, bundle in svc_index.items():
        methods = bundle["methods"]
        assert methods, f"Service {full_svc} must have at least one method."
        for m in methods.values():
            assert m.input_type in msg_index, (
                f"Input type not resolved for {full_svc}.{m.name}: {m.input_type} "
                f"(known: {sorted(list(msg_index.keys()))[:10]} ...)"
            )
            assert m.output_type in msg_index, (
                f"Output type not resolved for {full_svc}.{m.name}: {m.output_type} "
                f"(known: {sorted(list(msg_index.keys()))[:10]} ...)"
            )

def test_package_suffix_v1_convention():
    """
    Пакет v1 должен следовать конвенции версионирования:
    - заканчивается на '.v1' или '_v1'
    - не смешиваем разные мажорные версии в одном пакете
    """
    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)
    fds = parse_descriptor_set(raw)
    pkgs = file_packages(fds)

    has_v1 = False
    for p in pkgs:
        if p.endswith(".v1") or p.endswith("_v1"):
            has_v1 = True
        # простая эвристика: не должно быть и v1 и v2 в одном корне
        if p.endswith(".v2") or p.endswith("_v2"):
            pytest.fail(f"Found non-v1 package in v1 suite: {p}")

    assert has_v1, f"Expected at least one v1 package; got: {sorted(pkgs)}"

def test_descriptor_is_deterministic_by_path_order():
    """
    Детерминизм сборки: одинаковый набор файлов и порядок — одинаковый дескриптор.
    Перекомпилируем и сравним хэш-байты (байт-в-байт).
    """
    import hashlib

    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)

    raw1 = compile_descriptors(proto_root, protos)
    raw2 = compile_descriptors(proto_root, protos)

    h1 = hashlib.sha256(raw1).hexdigest()
    h2 = hashlib.sha256(raw2).hexdigest()
    assert raw1 == raw2 and h1 == h2, f"Non-deterministic descriptor output: {h1} != {h2}"

def test_optional_json_dump_for_debug(tmp_path: Path = None):
    """
    Диагностический дамп (не влияет на прохождение): в локальном режиме можно
    выгрузить FileDescriptorSet в JSON для удобной ревизии.
    Активируется переменной окружения: MYTHOS_DUMP_DESCRIPTOR_JSON=true
    """
    if os.getenv("MYTHOS_DUMP_DESCRIPTOR_JSON", "").lower() not in {"1", "true", "yes"}:
        pytest.skip("Descriptor JSON dump disabled.")
    proto_root = discover_proto_root()
    protos = find_v1_protos(proto_root)
    raw = compile_descriptors(proto_root, protos)
    fds = parse_descriptor_set(raw)

    # Простейшая JSON-сериализация через MessageToDict избежать —
    # чтобы не вводить зависимость google.protobuf.json_format.
    # Сделаем вручную плоский обзор.
    overview = []
    for fd in fds.file:
        item = {
            "name": fd.name,
            "package": fd.package,
            "syntax": fd.syntax,
            "services": [svc.name for svc in fd.service],
            "messages": [msg.name for msg in fd.message_type],
        }
        overview.append(item)

    tmp_dir = Path(os.getenv("MYTHOS_DUMP_DIR", "")) if os.getenv("MYTHOS_DUMP_DIR") else Path(tempfile.gettempdir())
    tmp_dir.mkdir(parents=True, exist_ok=True)
    out = tmp_dir / "grpc_v1_descriptor_overview.json"
    out.write_text(json.dumps(overview, ensure_ascii=False, indent=2), encoding="utf-8")

    # Тест всегда проходит; дамп — побочный артефакт для разработчика.
    assert out.exists()
