# -*- coding: utf-8 -*-
"""
Промышленный контрактный тест для gRPC v1.

Назначение:
- Фиксирует бинарный контракт (protobuf/gRPC) как FileDescriptorSet (golden снапшот).
- Проверяет обратную совместимость между текущими дескрипторами и golden:
  * Запрет изменения типа поля, его номера, oneof-индекса и label.
  * Запрет удаления поля без резервирования номера/имени.
  * Запрет изменения числовых значений enum и удаления без резервирования.
  * Запрет удаления gRPC-методов и изменения их сигнатур (типов/стриминга).
  * Запрет удаления сервисов.
- Гарантирует неизменность (SHA-256) бинарного снимка при отсутствии контрактных изменений.

Источник дескрипторов (выбирается автоматически):
1) PB2 модули (перечислить через ENV CONTRACT_PB2_MODULES="pkg.a_pb2,pkg.b_pb2").
2) Файл дескрипторов (ENV CONTRACT_DESCRIPTOR_SET="path/to/grpc_v1.desc").

Golden хранится по пути:
  tests/contract/golden/grpc_v1.descriptor.pb      — бинарный FileDescriptorSet
  tests/contract/golden/grpc_v1.sha256             — хеш снимка (для быстрых проверок)

Обновление golden:
  CONTRACT_UPDATE_GOLDEN=1 pytest -k proto_contract

Необходимые зависимости:
- pytest
- google.protobuf>=4.21
(Генерация pb2 лежит вне этого теста; ожидается, что проект уже сгенерировал *_pb2.py)
"""

from __future__ import annotations

import importlib
import io
import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Set

import pytest
from google.protobuf import descriptor_pb2

# --------- Константы и окружение ---------

REPO_ROOT = Path(__file__).resolve().parents[3]  # .../physical-integration-core/
TESTS_DIR = Path(__file__).resolve().parents[1]
GOLDEN_DIR = TESTS_DIR / "golden"
GOLDEN_DESC = GOLDEN_DIR / "grpc_v1.descriptor.pb"
GOLDEN_SHA = GOLDEN_DIR / "grpc_v1.sha256"

ENV_PB2_MODULES = os.getenv("CONTRACT_PB2_MODULES", "")
ENV_DESC_SET = os.getenv("CONTRACT_DESCRIPTOR_SET", "")
ENV_UPDATE = os.getenv("CONTRACT_UPDATE_GOLDEN", "0") == "1"

# Необязательная спецификация (для доп. ассертов по пакету/сервисам), если хотите
SPEC_FILE = TESTS_DIR / "spec" / "grpc_v1_spec.json"  # опционально; тесты сами skip'нутся, если нет


# --------- Утилиты загрузки дескрипторов ---------

def _ensure_repo_on_syspath() -> None:
    # Добавим корень репо в sys.path для импорта pb2-модулей
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

def load_current_descriptor_set() -> descriptor_pb2.FileDescriptorSet:
    """
    Загружает текущий FileDescriptorSet:
      - либо из pb2-модулей (перечисленных в CONTRACT_PB2_MODULES),
      - либо из бинарного файла CONTRACT_DESCRIPTOR_SET (protoc --descriptor_set_out).
    """
    if ENV_PB2_MODULES.strip():
        _ensure_repo_on_syspath()
        modules = [m.strip() for m in ENV_PB2_MODULES.split(",") if m.strip()]
        return _load_from_pb2_modules(modules)
    if ENV_DESC_SET.strip():
        return _load_from_descriptor_file(Path(ENV_DESC_SET))
    # Попытка дефолтного поиска pb2-модулей (нестрого): ищем в src/ и пакете проекта
    # Чтобы избежать ложноположительных, требуем явного ENV — иначе skip
    pytest.skip("Set CONTRACT_PB2_MODULES or CONTRACT_DESCRIPTOR_SET to run contract tests.")

def _load_from_pb2_modules(module_names: List[str]) -> descriptor_pb2.FileDescriptorSet:
    """
    Импортирует pb2-модули и собирает их FileDescriptorProto.
    """
    files: Dict[str, descriptor_pb2.FileDescriptorProto] = {}
    for mod_name in module_names:
        mod = importlib.import_module(mod_name)
        fd_bytes = getattr(mod, "DESCRIPTOR").serialized_pb  # bytes of FileDescriptorProto
        proto = descriptor_pb2.FileDescriptorProto()
        proto.ParseFromString(fd_bytes)
        files[proto.name] = proto
    # Стабильный порядок по имени
    fds = descriptor_pb2.FileDescriptorSet()
    for name in sorted(files):
        fds.file.add().CopyFrom(files[name])
    return fds

def _load_from_descriptor_file(path: Path) -> descriptor_pb2.FileDescriptorSet:
    if not path.exists():
        raise FileNotFoundError(f"Descriptor set file not found: {path}")
    data = path.read_bytes()
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(data)
    # Нормализуем порядок файлов
    _sort_fds_files_inplace(fds)
    return fds


# --------- Нормализация и хеш ---------

def _sort_fds_files_inplace(fds: descriptor_pb2.FileDescriptorSet) -> None:
    files = sorted(fds.file, key=lambda f: f.name or "")
    del fds.file[:]
    fds.file.extend(files)

def fds_sha256(fds: descriptor_pb2.FileDescriptorSet) -> str:
    """
    Детеминированный SHA-256 для FileDescriptorSet.
    Мы сортируем список файлов по имени; сериализация protobuf детерминирована.
    """
    buf = fds.SerializeToString()
    return hashlib.sha256(buf).hexdigest()


# --------- Golden helpers ---------

def read_golden_fds() -> descriptor_pb2.FileDescriptorSet:
    if not GOLDEN_DESC.exists():
        pytest.skip(f"Golden descriptor not found: {GOLDEN_DESC}. Run with CONTRACT_UPDATE_GOLDEN=1 to create.")
    data = GOLDEN_DESC.read_bytes()
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(data)
    _sort_fds_files_inplace(fds)
    return fds

def write_golden(fds: descriptor_pb2.FileDescriptorSet) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    GOLDEN_DESC.write_bytes(fds.SerializeToString())
    GOLDEN_SHA.write_text(fds_sha256(fds), encoding="utf-8")


# --------- Парсеры и карты ---------

def files_by_name(fds: descriptor_pb2.FileDescriptorSet) -> Dict[str, descriptor_pb2.FileDescriptorProto]:
    return {f.name: f for f in fds.file}

def full_message_name(fd: descriptor_pb2.FileDescriptorProto, msg: descriptor_pb2.DescriptorProto) -> str:
    pkg = fd.package or ""
    return f"{pkg}.{msg.name}" if pkg else msg.name

def full_enum_name(fd: descriptor_pb2.FileDescriptorProto, en: descriptor_pb2.EnumDescriptorProto) -> str:
    pkg = fd.package or ""
    return f"{pkg}.{en.name}" if pkg else en.name

def full_service_name(fd: descriptor_pb2.FileDescriptorProto, svc: descriptor_pb2.ServiceDescriptorProto) -> str:
    pkg = fd.package or ""
    return f"{pkg}.{svc.name}" if pkg else svc.name

def index_messages(fd: descriptor_pb2.FileDescriptorProto) -> Dict[str, descriptor_pb2.DescriptorProto]:
    return {full_message_name(fd, m): m for m in fd.message_type}

def index_enums(fd: descriptor_pb2.FileDescriptorProto) -> Dict[str, descriptor_pb2.EnumDescriptorProto]:
    return {full_enum_name(fd, e): e for e in fd.enum_type}

def index_services(fd: descriptor_pb2.FileDescriptorProto) -> Dict[str, descriptor_pb2.ServiceDescriptorProto]:
    return {full_service_name(fd, s): s for s in fd.service}


# --------- Проверки совместимости ---------

class ContractViolation(Exception):
    pass

def compare_fds_backward_compatible(old: descriptor_pb2.FileDescriptorSet,
                                   new: descriptor_pb2.FileDescriptorSet) -> None:
    """
    Генерирует ContractViolation при ломающих изменениях.
    """
    old_files = files_by_name(old)
    new_files = files_by_name(new)

    # 1) Файлы, пакеты, опции — допустимы новые файлы; удаление файлов потенциально breaking,
    #    но разрешим, если они не содержали сервисов/сообщений (упростим до запрета удаления).
    for fname in old_files:
        if fname not in new_files:
            raise ContractViolation(f"Removed proto file: {fname}")

    # По каждому файлу сравниваем сущности
    for fname, ofd in old_files.items():
        nfd = new_files.get(fname)
        if nfd is None:
            continue

        # Сервисы/методы
        _compare_services(ofd, nfd)

        # Сообщения/поля
        _compare_messages(ofd, nfd)

        # Энимы/значения
        _compare_enums(ofd, nfd)


def _compare_services(ofd: descriptor_pb2.FileDescriptorProto, nfd: descriptor_pb2.FileDescriptorProto) -> None:
    o_svcs = index_services(ofd)
    n_svcs = index_services(nfd)

    for sname, svc in o_svcs.items():
        nsvc = n_svcs.get(sname)
        if not nsvc:
            raise ContractViolation(f"Removed service: {sname}")
        # Методы
        o_methods = {m.name: m for m in svc.method}
        n_methods = {m.name: m for m in nsvc.method}
        for mname, om in o_methods.items():
            nm = n_methods.get(mname)
            if not nm:
                raise ContractViolation(f"Removed RPC method: {sname}.{mname}")
            if om.input_type != nm.input_type:
                raise ContractViolation(f"Changed input_type for {sname}.{mname}: {om.input_type} -> {nm.input_type}")
            if om.output_type != nm.output_type:
                raise ContractViolation(f"Changed output_type for {sname}.{mname}: {om.output_type} -> {nm.output_type}")
            if om.client_streaming != nm.client_streaming:
                raise ContractViolation(f"Changed client_streaming for {sname}.{mname}")
            if om.server_streaming != nm.server_streaming:
                raise ContractViolation(f"Changed server_streaming for {sname}.{mname}")


def _compare_messages(ofd: descriptor_pb2.FileDescriptorProto, nfd: descriptor_pb2.FileDescriptorProto) -> None:
    o_msgs = index_messages(ofd)
    n_msgs = index_messages(nfd)

    for mname, om in o_msgs.items():
        nm = n_msgs.get(mname)
        if not nm:
            raise ContractViolation(f"Removed message: {mname}")

        # Индекс полей по номеру (wire-совместимость)
        o_fields = {f.number: f for f in om.field}
        n_fields = {f.number: f for f in nm.field}

        # Резервы
        o_res_numbers: Set[int] = _collect_reserved_numbers(om)
        n_res_numbers: Set[int] = _collect_reserved_numbers(nm)
        o_res_names: Set[str] = set(om.reserved_name)
        n_res_names: Set[str] = set(nm.reserved_name)

        # Проверяем, что удалённые поля зарезервированы и не переиспользованы
        for num, of in o_fields.items():
            nf = n_fields.get(num)
            if nf is None:
                # Удалено поле — должно быть зарезервировано по номеру ИЛИ имени
                if (num not in n_res_numbers) and (of.name not in n_res_names):
                    raise ContractViolation(f"Removed field without reservation: {mname}.{of.name}#{num}")
                continue

            # Существующее поле: проверяем совместимость
            if of.type != nf.type:
                raise ContractViolation(f"Changed type for {mname}.{of.name}#{of.number}: {of.type} -> {nf.type}")
            if of.type_name != nf.type_name:
                # Для message/enum полей имя типа должно совпадать
                raise ContractViolation(f"Changed type_name for {mname}.{of.name}#{of.number}: {of.type_name} -> {nf.type_name}")
            if of.label != nf.label:
                # label (optional/repeated) менять нельзя
                raise ContractViolation(f"Changed label for {mname}.{of.name}#{of.number}")
            if of.oneof_index != nf.oneof_index:
                # oneof принадлежность — часть бинарного контракта
                raise ContractViolation(f"Changed oneof_index for {mname}.{of.name}#{of.number}")
            # Имя поля теоретически можно менять без wire-ломки, но запрещаем для дисциплины
            if of.name != nf.name:
                raise ContractViolation(f"Renamed field {mname}.{of.name} -> {nf.name} (forbidden)")

        # Запрет на переиспользование номеров: любой новый field не должен занимать ранее резервированный номер
        for num, nf in n_fields.items():
            if num in o_res_numbers:
                raise ContractViolation(f"Reused previously reserved number in {mname}: #{num}")

def _collect_reserved_numbers(desc: descriptor_pb2.DescriptorProto) -> Set[int]:
    nums: Set[int] = set()
    for rr in desc.reserved_range:
        start = rr.start
        end = rr.end  # end exclusive
        for x in range(start, end):
            nums.add(x)
    return nums

def _compare_enums(ofd: descriptor_pb2.FileDescriptorProto, nfd: descriptor_pb2.FileDescriptorProto) -> None:
    o_enums = index_enums(ofd)
    n_enums = index_enums(nfd)

    for ename, oe in o_enums.items():
        ne = n_enums.get(ename)
        if not ne:
            raise ContractViolation(f"Removed enum: {ename}")

        o_vals = {v.number: v for v in oe.value}
        n_vals = {v.number: v for v in ne.value}

        # Проверяем, что значение с номером осталось и имя не менялось
        for num, ov in o_vals.items():
            nv = n_vals.get(num)
            if nv is None:
                # Удаление значения enum — запрещено (допускается только перевод в reserved_name, но protobuf для enum
                # не хранит reserved ranges/имена на уровне EnumDescriptorProto; потому просто запрещаем)
                raise ContractViolation(f"Removed enum value {ename}.{ov.name}#{num}")
            if ov.name != nv.name:
                raise ContractViolation(f"Renamed enum value {ename}.{ov.name} -> {nv.name} (forbidden)")


# --------- Тесты ---------

def test_contract_snapshot_hash_and_update():
    """
    Проверяет детерминированный SHA-256 снимка и, при CONTRACT_UPDATE_GOLDEN=1, обновляет golden.
    """
    current = load_current_descriptor_set()
    _sort_fds_files_inplace(current)
    current_hash = fds_sha256(current)

    if ENV_UPDATE or (not GOLDEN_DESC.exists()):
        # Обновляем golden-снимок
        write_golden(current)
        # Для явности перечитываем
        golden = read_golden_fds()
        golden_hash = fds_sha256(golden)
        assert current_hash == golden_hash, "Golden hash must match after write"
        # Завершаем успешно: режим обновления не должен падать
        return

    golden = read_golden_fds()
    golden_hash = fds_sha256(golden)
    assert current_hash == golden_hash, (
        f"gRPC v1 contract hash changed.\n"
        f"Golden: {golden_hash}\nCurrent: {current_hash}\n"
        f"If this change is intentional and backward compatible, update golden via CONTRACT_UPDATE_GOLDEN=1."
    )

def test_backward_compatibility_against_golden():
    """
    Глубокая проверка обратной совместимости относительно golden.
    """
    if not GOLDEN_DESC.exists():
        pytest.skip("Golden descriptor not found; run update flow first.")
    old = read_golden_fds()
    new = load_current_descriptor_set()
    with _no_contract_violation():
        compare_fds_backward_compatible(old, new)

@pytest.mark.skipif(not SPEC_FILE.exists(), reason="Optional spec file not present")
def test_optional_spec_expectations():
    """
    Необязательные проверки соответствия спецификации (package, сервисы и методы).
    Файл spec/grpc_v1_spec.json может содержать:
    {
      "packages": ["aethernova.grpc.v1"],
      "services": {
        "aethernova.grpc.v1.ControlService": {
          "methods": {
            "Ping": {"input": ".aethernova.grpc.v1.PingReq", "output": ".aethernova.grpc.v1.PingRes", "cs": false, "ss": false}
          }
        }
      }
    }
    """
    spec = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    current = load_current_descriptor_set()
    files = list(current.file)

    # Проверка пакетов
    exp_packages = set(spec.get("packages", []))
    if exp_packages:
        got_packages = {f.package for f in files if f.package}
        missing = exp_packages - got_packages
        assert not missing, f"Missing packages: {sorted(missing)}"

    # Проверка сервисов/методов
    exp_services: Dict[str, Dict] = spec.get("services", {})
    if exp_services:
        svc_map: Dict[str, descriptor_pb2.ServiceDescriptorProto] = {}
        for f in files:
            svc_map.update(index_services(f))
        for svc_full_name, svc_spec in exp_services.items():
            svc = svc_map.get(svc_full_name)
            assert svc is not None, f"Missing service: {svc_full_name}"
            exp_methods: Dict[str, Dict] = svc_spec.get("methods", {})
            got_methods = {m.name: m for m in svc.method}
            for mname, md in exp_methods.items():
                m = got_methods.get(mname)
                assert m is not None, f"Missing method {svc_full_name}.{mname}"
                assert m.input_type == md["input"], f"{svc_full_name}.{mname} input mismatch"
                assert m.output_type == md["output"], f"{svc_full_name}.{mname} output mismatch"
                assert bool(m.client_streaming) == bool(md.get("cs", False)), f"{svc_full_name}.{mname} client_streaming mismatch"
                assert bool(m.server_streaming) == bool(md.get("ss", False)), f"{svc_full_name}.{mname} server_streaming mismatch"


# --------- Вспомогательное ---------

from contextlib import contextmanager

@contextmanager
def _no_contract_violation():
    try:
        yield
    except ContractViolation as e:
        pytest.fail(f"Backward-compatibility violation: {e}")

