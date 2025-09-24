# ledger-core/tests/contract/test_grpc_v1.proto_contract.py
# -*- coding: utf-8 -*-
"""
Промышленная проверка gRPC v1 контракта:
- Компилирует все .proto из api/grpc/v1 в FileDescriptorSet
- Сравнивает с "золотым" слепком (fixtures/grpc_v1_descriptor_set.pb)
- Проверяет обратно совместимые изменения:
    * Нельзя удалять сообщения/поля/сервисы/методы
    * Нельзя менять номер поля, тип, label, json_name
    * Разрешены только добавления с новыми tag-номерами
- Умеет регенерировать golden при ALLOW_DESCRIPTOR_GOLDEN_UPDATE=1
- Подробные дифф-отчёты для CI

Зависимости: pytest, google.protobuf, (grpc_tools.protoc ИЛИ protoc в PATH)
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Iterable, Set

import pytest
from google.protobuf import descriptor_pb2

# --------------------------------------------------------------------------------------
# Конфигурация путей (автонастройка относительно расположения теста)
# --------------------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
# Ожидаемая структура репо:
# ledger-core/
#   api/grpc/v1/**/*.proto
#   tests/contract/fixtures/grpc_v1_descriptor_set.pb
REPO_ROOT = THIS_FILE.parents[3] if len(THIS_FILE.parents) >= 3 else THIS_FILE.parents[-1]
API_V1_DIR = (REPO_ROOT / "api" / "grpc" / "v1").resolve()
FIXTURES_DIR = (THIS_FILE.parent / "fixtures").resolve()
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
GOLDEN_DESCRIPTOR = FIXTURES_DIR / "grpc_v1_descriptor_set.pb"

# Можно перечислить дополнительные include-пути при сложных импортах .proto
EXTRA_INCLUDE_DIRS: List[Path] = [
    API_V1_DIR,
    REPO_ROOT / "api",   # на случай import "grpc/v1/foo.proto";
    REPO_ROOT,           # запасной корень
]

# Имя файла временного дескриптора (перезаписывается каждый прогон)
BUILD_DIR = (THIS_FILE.parent / ".build").resolve()
BUILD_DIR.mkdir(parents=True, exist_ok=True)
CURRENT_DESCRIPTOR = BUILD_DIR / "grpc_v1_descriptor_set.current.pb"

# Переключатели поведения в CI
ALLOW_UPDATE = os.getenv("ALLOW_DESCRIPTOR_GOLDEN_UPDATE", "0") == "1"
STRICT_MODE = os.getenv("PROTO_CONTRACT_STRICT", "1") == "1"  # жесткий режим проверок


# --------------------------------------------------------------------------------------
# Утилиты: поиск файлов, компиляция в FileDescriptorSet
# --------------------------------------------------------------------------------------

def _find_proto_files(root: Path) -> List[Path]:
    if not root.exists():
        pytest.skip(f"Каталог с .proto не найден: {root}")
    return sorted(p for p in root.rglob("*.proto") if p.is_file())


def _try_import_grpc_tools() -> Optional[str]:
    try:
        import grpc_tools.protoc  # noqa: F401
        return "grpc_tools"
    except Exception:
        return None


def _protoc_version() -> str:
    try:
        out = subprocess.check_output(["protoc", "--version"], text=True).strip()
        return out
    except Exception:
        return "unknown"


def _compile_with_grpc_tools(out_path: Path, proto_files: List[Path], include_paths: List[Path]) -> None:
    # python -m grpc_tools.protoc --descriptor_set_out=... --include_imports -I <inc> ... <files>
    cmd = [
        sys.executable, "-m", "grpc_tools.protoc",
        f"--descriptor_set_out={str(out_path)}",
        "--include_imports",
    ]
    for inc in include_paths:
        cmd.extend(["-I", str(inc)])
    cmd.extend([str(p) for p in proto_files])

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        raise AssertionError(f"grpc_tools.protoc завершился с кодом {e.returncode}\nКоманда: {' '.join(cmd)}") from e


def _compile_with_protoc_cli(out_path: Path, proto_files: List[Path], include_paths: List[Path]) -> None:
    # protoc --descriptor_set_out=... --include_imports -I <inc> ... <files>
    if shutil.which("protoc") is None:
        raise AssertionError("protoc не найден в PATH и grpc_tools.protoc недоступен")

    cmd = [
        "protoc",
        f"--descriptor_set_out={str(out_path)}",
        "--include_imports",
    ]
    for inc in include_paths:
        cmd.extend(["-I", str(inc)])
    cmd.extend([str(p) for p in proto_files])

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        raise AssertionError(f"protoc завершился с кодом {e.returncode}\nКоманда: {' '.join(cmd)}") from e


def compile_descriptor_set(out_path: Path, proto_root: Path, extra_includes: List[Path]) -> None:
    files = _find_proto_files(proto_root)
    assert files, f"В {proto_root} не найдено ни одного .proto"
    includes = list(dict.fromkeys([proto_root, *extra_includes]))  # unique, order-preserving

    # Пытаемся через grpc_tools, иначе — через protoc
    tool = _try_import_grpc_tools()
    if tool == "grpc_tools":
        _compile_with_grpc_tools(out_path, files, includes)
        return

    _compile_with_protoc_cli(out_path, files, includes)


# --------------------------------------------------------------------------------------
# Разбор FileDescriptorSet и вспомогательные структуры для диффа
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldKey:
    number: int
    name: str
    type: int
    label: int
    json_name: str


@dataclass(frozen=True)
class MessageKey:
    full_name: str


@dataclass(frozen=True)
class MethodKey:
    name: str
    input_type: str
    output_type: str
    client_streaming: bool
    server_streaming: bool


@dataclass(frozen=True)
class ServiceKey:
    full_name: str


@dataclass
class SchemaIndex:
    messages: Dict[str, Dict[int, FieldKey]]          # message_fullname -> field_number -> FieldKey
    services: Dict[str, Dict[str, MethodKey]]         # service_fullname -> method_name -> MethodKey
    files: Set[str]                                   # file names for reference
    package_by_file: Dict[str, str]                   # file -> package


def load_fds(path: Path) -> descriptor_pb2.FileDescriptorSet:
    data = path.read_bytes()
    fds = descriptor_pb2.FileDescriptorSet()
    fds.MergeFromString(data)
    return fds


def index_schema(fds: descriptor_pb2.FileDescriptorSet) -> SchemaIndex:
    messages: Dict[str, Dict[int, FieldKey]] = {}
    services: Dict[str, Dict[str, MethodKey]] = {}
    files: Set[str] = set()
    package_by_file: Dict[str, str] = {}

    def qualify(pkg: str, name: str) -> str:
        return f".{pkg}.{name}" if pkg else f".{name}"

    for fd in fds.file:
        files.add(fd.name)
        package_by_file[fd.name] = fd.package

        # Сообщения (включая вложенные)
        def walk_messages(prefix: str, desc_list: Iterable[descriptor_pb2.DescriptorProto]):
            for desc in desc_list:
                full = qualify(prefix, desc.name) if prefix else qualify(fd.package, desc.name)
                fields_by_num: Dict[int, FieldKey] = {}
                for f in desc.field:
                    fields_by_num[f.number] = FieldKey(
                        number=f.number,
                        name=f.name,
                        type=f.type,
                        label=f.label,
                        json_name=f.json_name or f.name,
                    )
                messages[full] = fields_by_num
                # Рекурсивно обойти вложенные
                if desc.nested_type:
                    walk_messages(full, desc.nested_type)

        walk_messages("", fd.message_type)

        # Сервисы
        for svc in fd.service:
            svc_full = qualify(fd.package, svc.name)
            methods: Dict[str, MethodKey] = {}
            for m in svc.method:
                mk = MethodKey(
                    name=m.name,
                    input_type=m.input_type,     # уже полностью квалифицированные имена (e.g., .pkg.Msg)
                    output_type=m.output_type,
                    client_streaming=m.client_streaming,
                    server_streaming=m.server_streaming,
                )
                methods[m.name] = mk
            services[svc_full] = methods

    return SchemaIndex(messages=messages, services=services, files=files, package_by_file=package_by_file)


# --------------------------------------------------------------------------------------
# Дифф и валидация совместимости
# --------------------------------------------------------------------------------------

@dataclass
class BreakingChange:
    kind: str
    where: str
    detail: str


def _format_breakings(items: List[BreakingChange]) -> str:
    if not items:
        return ""
    lines = ["Найдены несовместимые изменения в gRPC контракте:"]
    for it in items:
        lines.append(f"- [{it.kind}] {it.where}: {it.detail}")
    return "\n".join(lines)


def compare_indices(old: SchemaIndex, new: SchemaIndex) -> Tuple[List[BreakingChange], List[str]]:
    breakings: List[BreakingChange] = []
    infos: List[str] = []

    # Проверка сообщений и их полей
    old_msgs = set(old.messages.keys())
    new_msgs = set(new.messages.keys())

    removed_msgs = sorted(old_msgs - new_msgs)
    for full in removed_msgs:
        breakings.append(BreakingChange("message_removed", full, "Сообщение удалено"))

    # Существующие сообщения: сверяем поля
    intersect_msgs = sorted(old_msgs & new_msgs)
    for msg in intersect_msgs:
        old_fields = old.messages[msg]
        new_fields = new.messages[msg]

        # Удаленные поля
        removed_field_nums = sorted(set(old_fields.keys()) - set(new_fields.keys()))
        for num in removed_field_nums:
            f = old_fields[num]
            breakings.append(BreakingChange("field_removed", f"{msg}#{num}",
                                            f"Поле удалено: {f.name} (tag={num})"))

        # Существующие поля: нельзя менять type/label/json_name; имя поля менять нельзя
        common_nums = sorted(set(old_fields.keys()) & set(new_fields.keys()))
        for num in common_nums:
            of = old_fields[num]
            nf = new_fields[num]
            if of.name != nf.name:
                breakings.append(BreakingChange("field_renamed", f"{msg}#{num}",
                                                f"Имя поля изменено: {of.name} -> {nf.name}"))
            if of.type != nf.type:
                breakings.append(BreakingChange("field_type_changed", f"{msg}#{num}",
                                                f"Тип поля изменен: {of.type} -> {nf.type}"))
            if of.label != nf.label:
                breakings.append(BreakingChange("field_label_changed", f"{msg}#{num}",
                                                f"Label поля изменен: {of.label} -> {nf.label}"))
            if (of.json_name or of.name) != (nf.json_name or nf.name):
                breakings.append(BreakingChange("field_json_name_changed", f"{msg}#{num}",
                                                f"json_name изменен: {of.json_name} -> {nf.json_name}"))

        # Новые поля — ок (при условии уникальности номеров; protoc сам это обеспечивает)
        added_field_nums = sorted(set(new_fields.keys()) - set(old_fields.keys()))
        for num in added_field_nums:
            nf = new_fields[num]
            infos.append(f"[added_field] {msg}#{num}: {nf.name} (type={nf.type}, label={nf.label})")

    # Проверка сервисов/методов
    old_svcs = set(old.services.keys())
    new_svcs = set(new.services.keys())

    removed_svcs = sorted(old_svcs - new_svcs)
    for s in removed_svcs:
        breakings.append(BreakingChange("service_removed", s, "Сервис удален"))

    intersect_svcs = sorted(old_svcs & new_svcs)
    for svc in intersect_svcs:
        old_methods = old.services[svc]
        new_methods = new.services[svc]

        removed_methods = sorted(set(old_methods.keys()) - set(new_methods.keys()))
        for m in removed_methods:
            breakings.append(BreakingChange("method_removed", f"{svc}.{m}", "Метод удален"))

        common_methods = sorted(set(old_methods.keys()) & set(new_methods.keys()))
        for m in common_methods:
            om = old_methods[m]
            nm = new_methods[m]
            if om.input_type != nm.input_type:
                breakings.append(BreakingChange("method_input_changed", f"{svc}.{m}",
                                                f"Входной тип: {om.input_type} -> {nm.input_type}"))
            if om.output_type != nm.output_type:
                breakings.append(BreakingChange("method_output_changed", f"{svc}.{m}",
                                                f"Выходной тип: {om.output_type} -> {nm.output_type}"))
            if om.client_streaming != nm.client_streaming:
                breakings.append(BreakingChange("method_client_streaming_changed", f"{svc}.{m}",
                                                f"client_streaming: {om.client_streaming} -> {nm.client_streaming}"))
            if om.server_streaming != nm.server_streaming:
                breakings.append(BreakingChange("method_server_streaming_changed", f"{svc}.{m}",
                                                f"server_streaming: {om.server_streamming} -> {nm.server_streaming}"))

        added_methods = sorted(set(new_methods.keys()) - set(old_methods.keys()))
        for m in added_methods:
            nm = new_methods[m]
            infos.append(f"[added_method] {svc}.{m}({nm.input_type}) returns ({nm.output_type})")

    return breakings, infos


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------------------
# Тесты
# --------------------------------------------------------------------------------------

@pytest.mark.order(1)
def test_compile_current_descriptor_set():
    """Компилируем текущие .proto в FileDescriptorSet"""
    compile_descriptor_set(CURRENT_DESCRIPTOR, API_V1_DIR, EXTRA_INCLUDE_DIRS)
    assert CURRENT_DESCRIPTOR.exists(), "Не удалось сгенерировать текущий дескрипторный слепок"
    size = CURRENT_DESCRIPTOR.stat().st_size
    assert size > 0, "Пустой дескрипторный файл"
    print(f"[INFO] Сгенерирован текущий descriptor_set: {CURRENT_DESCRIPTOR} ({size} байт)")


@pytest.mark.order(2)
def test_golden_descriptor_exists_or_update():
    """
    Если GOLDEN отсутствует:
      - при ALLOW_DESCRIPTOR_GOLDEN_UPDATE=1 — создаем/обновляем его
      - иначе — падаем с четкой инструкцией
    """
    if GOLDEN_DESCRIPTOR.exists():
        return

    if not ALLOW_UPDATE:
        pytest.fail(
            "Отсутствует золотой дескриптор контрактов: "
            f"{GOLDEN_DESCRIPTOR}\n"
            "Создайте его локально, запустив тест с ALLOW_DESCRIPTOR_GOLDEN_UPDATE=1 "
            "или добавьте файл в VCS."
        )

    # Разрешено обновление — копируем текущий
    shutil.copy2(CURRENT_DESCRIPTOR, GOLDEN_DESCRIPTOR)
    assert GOLDEN_DESCRIPTOR.exists(), "Не удалось записать золотой дескриптор"
    print(f"[INFO] Golden создан: {GOLDEN_DESCRIPTOR}")


@pytest.mark.order(3)
def test_descriptor_hash_is_stable():
    """
    Хэш дескриптора — удобный быстрый сигнал в CI.
    Не является заменой детального диффа, но помогает быстро увидеть изменение.
    """
    cur_hash = sha256_file(CURRENT_DESCRIPTOR)
    gold_hash = sha256_file(GOLDEN_DESCRIPTOR)
    print(f"[INFO] current SHA256: {cur_hash}")
    print(f"[INFO] golden  SHA256: {gold_hash}")

    if cur_hash != gold_hash:
        print("[WARN] Хэши различаются — проверим дифф на совместимость.")
    # Не падаем здесь — детальная проверка дальше


@pytest.mark.order(4)
def test_backward_compatibility():
    """
    Основной тест: сравнение текущего и golden по правилам обратной совместимости.
    """
    current_fds = load_fds(CURRENT_DESCRIPTOR)
    golden_fds = load_fds(GOLDEN_DESCRIPTOR)

    cur_idx = index_schema(current_fds)
    gold_idx = index_schema(golden_fds)

    breakings, infos = compare_indices(gold_idx, cur_idx)

    # Печатаем полезные сведения для ревью (не критично)
    if infos:
        print("[INFO] Допустимые добавления/изменения:")
        for line in infos:
            print("  ", line)

    if breakings:
        report = _format_breakings(breakings)
        if ALLOW_UPDATE and not STRICT_MODE:
            # Мягкий режим: если явно разрешили обновление и STRICT отключен — не падаем,
            # но выводим отчет (полезно для подготовки новой мажорной версии).
            pytest.xfail("Найдены несовместимые изменения (см. лог), но разрешено обновление без строгого режима.\n" + report)
        else:
            pytest.fail(report)


@pytest.mark.order(5)
def test_packages_are_v1_namespaced():
    """
    Дополнительная стилевальная проверка: все файлы должны иметь пакет вида *.v1.*
    Это не факт контракта, но хорошая практика версионирования API.
    При необходимости ослабьте правило под ваш стиль.
    """
    fds = load_fds(CURRENT_DESCRIPTOR)
    bad: List[Tuple[str, str]] = []
    for fd in fds.file:
        pkg = fd.package or ""
        if ".v1" not in pkg and not pkg.endswith(".v1"):
            bad.append((fd.name, pkg))

    if bad:
        details = "\n".join(f"- {fname}: package='{pkg}'" for fname, pkg in bad)
        pytest.fail(
            "Обнаружены .proto без v1-неймспейса в package (требование версии API):\n" + details
        )


@pytest.mark.order(6)
def test_no_field_number_reuse_within_message():
    """
    Страховочная проверка: в одном сообщении не должно быть дубликатов номеров полей.
    protoc обычно это ловит, но тест дает явный репорт.
    """
    fds = load_fds(CURRENT_DESCRIPTOR)
    idx = index_schema(fds)
    violations: List[str] = []

    for msg, by_num in idx.messages.items():
        seen: Set[int] = set()
        for num in by_num.keys():
            if num in seen:
                violations.append(f"{msg} повторное использование tag={num}")
            seen.add(num)

    if violations:
        pytest.fail("Повторное использование tag номеров:\n" + "\n".join(f"- {v}" for v in violations))


@pytest.mark.order(7)
def test_protoc_available_or_tools():
    """
    Диагностический тест, чтобы в CI было ясно, каким способом компилируется.
    """
    tool = _try_import_grpc_tools()
    proto_cli = shutil.which("protoc")
    if tool:
        print("[INFO] Используется grpc_tools.protoc")
    elif proto_cli:
        print(f"[INFO] Используется protoc CLI: {_protoc_version()}")
    else:
        pytest.fail("Недоступны ни grpc_tools.protoc, ни protoc в PATH")
