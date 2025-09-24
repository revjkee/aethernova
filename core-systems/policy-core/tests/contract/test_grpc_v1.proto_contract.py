# policy-core/tests/contract/test_grpc_v1.proto_contract.py
# -*- coding: utf-8 -*-
"""
Промышленный контракт-тест для gRPC/Protobuf (v1).

Возможности:
- Поиск *.proto в стандартных местах (**/proto/**/v1/*.proto, **/grpc/**/v1/*.proto), с исключениями служебных директорий.
- Парсинг .proto БЕЗ protoc: package, syntax, imports, services/rpc (включая stream-флаги), messages/fields, enums/values.
- Строгие проверки качества:
  * syntax == "proto3"
  * package оканчивается на ".v1"
  * имена файлов snake_case
  * ServiceName оканчивается на "Service"
  * RPC методы в PascalCase
  * поля сообщений в snake_case, номера уникальны, нет запрещённых конструкций
- Стабилизация API: канонический JSON контракта + SHA256-хеш, снапшот-файл рядом с тестом.
  * Установка переменной окружения UPDATE_GRPC_CONTRACT=1 перезапишет снапшот.

Зависимости: pytest (стандарт для тестов). Остальное — стандартная библиотека.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable

import pytest

# -------------------------------
# Константы и настройки поиска
# -------------------------------

DEFAULT_SEARCH_GLOBS: Tuple[str, ...] = (
    "**/proto/**/v1/*.proto",
    "**/grpc/**/v1/*.proto",
)

EXCLUDED_DIR_NAMES: Tuple[str, ...] = (
    ".git",
    ".idea",
    ".vscode",
    "venv",
    ".venv",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
)

# Имя снапшота контракта (рядом с этим тестом)
SNAPSHOT_FILE_NAME = "grpc_v1_contract.snapshot.json"


# -------------------------------
# Вспомогательные структуры
# -------------------------------

@dataclass
class RpcMethod:
    name: str
    input_type: str
    output_type: str
    client_streaming: bool
    server_streaming: bool

@dataclass
class Service:
    name: str
    rpcs: List[RpcMethod] = field(default_factory=list)

@dataclass
class MessageField:
    label: Optional[str]  # None | "optional" | "repeated"
    type: str
    name: str
    number: int

@dataclass
class Message:
    name: str
    fields: List[MessageField] = field(default_factory=list)
    reserved_numbers: List[int] = field(default_factory=list)

@dataclass
class EnumValue:
    name: str
    number: int

@dataclass
class Enum:
    name: str
    values: List[EnumValue] = field(default_factory=list)

@dataclass
class ProtoFileModel:
    path: str                  # относительный путь
    syntax: str                # "proto3"
    package: str               # должен заканчиваться на ".v1"
    imports: List[str]
    services: List[Service]
    messages: List[Message]
    enums: List[Enum]


# -------------------------------
# Утилиты
# -------------------------------

_SNAKE_RE = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
_PASCAL_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
_PROTO_PACKAGE_V1_RE = re.compile(r"\.v1$")

def _repo_root_from(file: Path) -> Path:
    # Идём от файла вверх до корня репозитория (эвристика: папка с .git или до FS root)
    cur = file.resolve()
    for parent in [cur, *cur.parents]:
        if (parent / ".git").exists():
            return parent
    # если не нашли .git — берём верхний уровень проекта (родитель tests/contract/…)
    return file.parent.parent.parent.parent.resolve()

def _iter_proto_files(root: Path, env_search_globs: Optional[str] = None) -> List[Path]:
    globs: Iterable[str]
    if env_search_globs:
        # Позволяет задать свои шаблоны через переменную окружения
        globs = tuple(s.strip() for s in env_search_globs.split(",") if s.strip())
    else:
        globs = DEFAULT_SEARCH_GLOBS

    files: List[Path] = []
    for pattern in globs:
        for p in root.glob(pattern):
            if not p.is_file():
                continue
            # отфильтруем нежелательные директории
            if any(seg in EXCLUDED_DIR_NAMES for seg in p.parts):
                continue
            files.append(p.resolve())
    # Дедупликация и сортировка для детерминизма
    uniq = sorted(set(files))
    return uniq

def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _strip_comments(proto: str) -> str:
    # Удаляем /* ... */ (многострочные) и // ... (однострочные)
    no_block = re.sub(r"/\*.*?\*/", "", proto, flags=re.S)
    no_line = re.sub(r"//[^\n]*", "", no_block)
    return no_line


def _find_all_blocks(src: str, kind: str) -> List[Tuple[str, str]]:
    """
    Нахождение блоков вида:
      kind <Name> { ...balanced... }
    Возвращает список (Name, body).
    """
    results: List[Tuple[str, str]] = []
    pattern = re.compile(rf"\b{kind}\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{{", flags=re.M)
    for m in pattern.finditer(src):
        name = m.group(1)
        body, end = _extract_brace_block(src, m.end() - 1)  # позиция на '{'
        results.append((name, body))
    return results

def _extract_brace_block(src: str, open_brace_pos: int) -> Tuple[str, int]:
    """
    Получает тело блока с балансировкой фигурных скобок.
    open_brace_pos — позиция '{' в исходной строке.
    Возвращает: (body, end_index)
    """
    assert src[open_brace_pos] == "{"
    depth = 0
    i = open_brace_pos
    start = open_brace_pos + 1
    while i < len(src):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                # тело между start и i
                return src[start:i], i + 1
        i += 1
    raise ValueError("Unbalanced braces while parsing proto block")


def _parse_header(src: str) -> Tuple[str, str, List[str]]:
    """
    Возвращает (syntax, package, imports)
    """
    syntax_m = re.search(r'\bsyntax\s*=\s*"([^"]+)"\s*;', src)
    syntax = syntax_m.group(1).strip() if syntax_m else ""

    package_m = re.search(r'\bpackage\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;', src)
    package = package_m.group(1).strip() if package_m else ""

    imports = [m.group(1).strip() for m in re.finditer(r'\bimport\s+"([^"]+)"\s*;', src)]
    return syntax, package, imports


def _parse_rpc_methods(service_body: str) -> List[RpcMethod]:
    """
    Ищет объявления RPC:
      rpc Method (stream? Input) returns (stream? Output);
      rpc Method (Input) returns (Output) { ... }
    """
    results: List[RpcMethod] = []
    # Сначала найдём все сигнатуры RPC (без тела)
    rpc_sig_re = re.compile(
        r"""
        \brpc\s+([A-Za-z_][A-Za-z0-9_]*)      # 1: Method
        \s*\(\s*(stream\s+)?([.A-Za-z0-9_]+)\s*\)   # 2: opt 'stream', 3: Input
        \s*returns\s*\(\s*(stream\s+)?([.A-Za-z0-9_]+)\s*\)  # 4: opt 'stream', 5: Output
        """,
        re.X | re.M,
    )
    for m in rpc_sig_re.finditer(service_body):
        method = RpcMethod(
            name=m.group(1),
            input_type=m.group(3),
            output_type=m.group(5),
            client_streaming=bool(m.group(2)),
            server_streaming=bool(m.group(4)),
        )
        results.append(method)
    return results


def _parse_reserved_numbers(block_body: str) -> List[int]:
    """
    reserved 4, 15, 100 to 110;
    reserved "foo", "bar";  # Строковые метки игнорируем
    """
    numbers: List[int] = []
    for m in re.finditer(r"\breserved\s+([^;]+);", block_body):
        payload = m.group(1)
        # Извлекаем только числовые и диапазоны
        for piece in payload.split(","):
            piece = piece.strip()
            if not piece or piece.startswith('"'):
                continue
            if "to" in piece:
                a, b = (s.strip() for s in piece.split("to", 1))
                if a.isdigit() and b.isdigit():
                    numbers.extend(range(int(a), int(b) + 1))
            else:
                if piece.isdigit():
                    numbers.append(int(piece))
    return sorted(set(numbers))


def _parse_message_fields(block_body: str) -> List[MessageField]:
    """
    Поддержка базовой формы поля:
      <type> <name> = <number> [...];
      optional <type> <name> = <number> [...];
      repeated <type> <name> = <number> [...];

    Примеры типов: string, int64, bytes, .google.protobuf.Timestamp, SomeMessage, map<...> и т.д.
    """
    fields: List[MessageField] = []

    # Упростим тело: удалим oneof-блоки (номер поля внутри oneof тоже валидируем отдельно сложно —
    # здесь цель — контракт API по названиям/номерам/типам; для простоты вытащим строки с '=' вне service/enum)
    # Линии полей обычно заканчиваются ';' и содержат '='.
    # Отбросим зарезервированные и опции.
    candidate_lines = []
    for raw_line in block_body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("reserved ") or line.startswith("option "):
            continue
        if "=" in line and line.endswith(";"):
            candidate_lines.append(line)

    field_re = re.compile(
        r"""
        ^(?:(optional|repeated)\s+)?                # 1: label
        ([A-Za-z0-9_.<>,\s]+)\s+                    # 2: type (в т.ч. map<...>, .pkg.Type)
        ([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*            # 3: name
        (\d+)\s*                                    # 4: number
        (?:\[.*?\])?;                               # opt options [...]
        $
        """,
        re.X,
    )

    for line in candidate_lines:
        m = field_re.match(line)
        if not m:
            # Не распознали — пропускаем строку (могут быть сложные конструкции); тесты ниже проверят базовую корректность.
            continue
        label = m.group(1)
        typ = " ".join(m.group(2).split())  # схлопнем лишние пробелы
        name = m.group(3)
        number = int(m.group(4))
        fields.append(MessageField(label=label, type=typ, name=name, number=number))

    return fields


def _parse_file(path: Path, root: Path) -> ProtoFileModel:
    text = _read_text(path)
    # Базовые гигиенические проверки
    assert "\t" not in text, f"Файл содержит табы: {path}"
    # trailing spaces на строках — не критично, но лучше запретить в контракте
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.rstrip() != ln:
            raise AssertionError(f"Трейлинг-пробел в {path}:{i}")

    src = _strip_comments(text)
    syntax, package, imports = _parse_header(src)

    # Services
    services: List[Service] = []
    for svc_name, svc_body in _find_all_blocks(src, "service"):
        rpcs = _parse_rpc_methods(svc_body)
        services.append(Service(name=svc_name, rpcs=rpcs))

    # Messages
    messages: List[Message] = []
    for msg_name, msg_body in _find_all_blocks(src, "message"):
        reserved = _parse_reserved_numbers(msg_body)
        fields = _parse_message_fields(msg_body)
        messages.append(Message(name=msg_name, fields=fields, reserved_numbers=reserved))

    # Enums
    enums: List[Enum] = []
    enum_value_line = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*=\s*(-?\d+)\s*;")
    for enum_name, enum_body in _find_all_blocks(src, "enum"):
        values: List[EnumValue] = []
        for line in enum_body.splitlines():
            m = enum_value_line.match(line)
            if m:
                values.append(EnumValue(name=m.group(1), number=int(m.group(2))))
        enums.append(Enum(name=enum_name, values=values))

    rel = str(path.relative_to(root))
    return ProtoFileModel(
        path=rel,
        syntax=syntax,
        package=package,
        imports=imports,
        services=services,
        messages=messages,
        enums=enums,
    )


def _canonical_contract_json(model: List[ProtoFileModel]) -> str:
    """
    Получить детерминированный JSON представления контракта.
    Сортируем всё, где возможно, чтобы хеш был устойчив.
    """
    def sort_fields(fields: List[MessageField]) -> List[Dict]:
        return sorted(
            ({"label": f.label, "type": f.type, "name": f.name, "number": f.number} for f in fields),
            key=lambda x: x["number"],
        )

    def sort_rpcs(rpcs: List[RpcMethod]) -> List[Dict]:
        return sorted(
            (
                {
                    "name": r.name,
                    "input_type": r.input_type,
                    "output_type": r.output_type,
                    "client_streaming": r.client_streaming,
                    "server_streaming": r.server_streaming,
                }
                for r in rpcs
            ),
            key=lambda x: x["name"],
        )

    def sort_enums(values: List[EnumValue]) -> List[Dict]:
        return sorted(
            ({"name": v.name, "number": v.number} for v in values),
            key=lambda x: x["number"],
        )

    payload = []
    for pf in sorted(model, key=lambda x: x.path):
        payload.append(
            {
                "path": pf.path,
                "syntax": pf.syntax,
                "package": pf.package,
                "imports": sorted(pf.imports),
                "services": [
                    {
                        "name": svc.name,
                        "rpcs": sort_rpcs(svc.rpcs),
                    }
                    for svc in sorted(pf.services, key=lambda s: s.name)
                ],
                "messages": [
                    {
                        "name": msg.name,
                        "reserved_numbers": sorted(msg.reserved_numbers),
                        "fields": sort_fields(msg.fields),
                    }
                    for msg in sorted(pf.messages, key=lambda m: m.name)
                ],
                "enums": [
                    {
                        "name": en.name,
                        "values": sort_enums(en.values),
                    }
                    for en in sorted(pf.enums, key=lambda e: e.name)
                ],
            }
        )
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _snapshot_path(test_file: Path) -> Path:
    return test_file.parent / SNAPSHOT_FILE_NAME


# -------------------------------
# Проверки/тесты
# -------------------------------

def test_grpc_v1_proto_contract():
    """
    Главный интеграционный тест:
    - обнаружение .proto (v1),
    - разбор,
    - строгие проверки,
    - сверка со снапшотом.
    """
    test_file = Path(__file__).resolve()
    repo_root = _repo_root_from(test_file)

    env_globs = os.getenv("GRPC_CONTRACT_SEARCH_GLOBS")
    proto_files = _iter_proto_files(repo_root, env_search_globs=env_globs)

    assert proto_files, "Не найдено ни одного .proto в v1. Ожидаются файлы по шаблонам **/proto/**/v1/*.proto или **/grpc/**/v1/*.proto"

    models: List[ProtoFileModel] = []
    for p in proto_files:
        # Имя файла — строго snake_case
        assert _SNAKE_RE.match(p.name[:-6]), f"Имя файла должно быть snake_case: {p}"
        model = _parse_file(p, repo_root)

        # 1) syntax
        assert model.syntax == "proto3", f"{model.path}: syntax должен быть proto3"

        # 2) package с окончанием .v1
        assert model.package, f"{model.path}: отсутствует package;"
        assert _PROTO_PACKAGE_V1_RE.search(model.package), f"{model.path}: package должен заканчиваться на .v1 (получено: {model.package})"

        # 3) Services
        for svc in model.services:
            assert svc.name.endswith("Service"), f"{model.path}: имя сервиса '{svc.name}' должно оканчиваться на 'Service'"
            assert _PASCAL_RE.match(svc.name), f"{model.path}: имя сервиса '{svc.name}' должно быть в PascalCase"
            # Методы
            seen_rpc_names = set()
            for rpc in svc.rpcs:
                assert _PASCAL_RE.match(rpc.name), f"{model.path}: метод '{rpc.name}' должен быть в PascalCase"
                assert rpc.name not in seen_rpc_names, f"{model.path}: дублирующееся имя RPC '{rpc.name}' в сервисе {svc.name}"
                seen_rpc_names.add(rpc.name)

                # Типы входа/выхода указаны
                assert rpc.input_type, f"{model.path}: RPC '{svc.name}.{rpc.name}' без input_type"
                assert rpc.output_type, f"{model.path}: RPC '{svc.name}.{rpc.name}' без output_type"

        # 4) Messages: номера полей уникальны, имена snake_case
        for msg in model.messages:
            field_numbers = set()
            for fld in msg.fields:
                # Имена полей — snake_case
                assert _SNAKE_RE.match(fld.name), f"{model.path}: поле '{msg.name}.{fld.name}' должно быть snake_case"
                # Номер поля в допустимом диапазоне
                assert 1 <= fld.number <= 536870911, f"{model.path}: недопустимый номер поля '{msg.name}.{fld.name}' = {fld.number}"
                # Уникальность номера
                assert fld.number not in field_numbers, f"{model.path}: повторяющийся номер поля {fld.number} в сообщении '{msg.name}'"
                field_numbers.add(fld.number)
                # Запрет 'required' (в proto3 не должно быть)
                assert (fld.label is None) or (fld.label in ("optional", "repeated")), f"{model.path}: недопустимая метка поля '{msg.name}.{fld.name}': {fld.label}"
            # Номера не должны пересекаться с reserved
            if msg.reserved_numbers:
                inter = field_numbers.intersection(set(msg.reserved_numbers))
                assert not inter, f"{model.path}: у сообщения '{msg.name}' номера полей пересекаются с reserved: {sorted(inter)}"

        models.append(model)

    # Строим канонический контракт и сверяем со снапшотом
    canonical = _canonical_contract_json(models)
    digest = _sha256(canonical)

    snapshot_path = _snapshot_path(test_file)
    update = os.getenv("UPDATE_GRPC_CONTRACT") == "1"

    if update or not snapshot_path.exists():
        # Перезапись снапшота (осознанная операция)
        snapshot = {
            "sha256": digest,
            "contract": json.loads(canonical),
        }
        snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        # Фиксируем проверкой, что файл записан корректно
        written = json.loads(snapshot_path.read_text(encoding="utf-8"))
        assert written.get("sha256") == digest, "Снапшот записан, но хеш не совпал — проверьте права/ФС"
    else:
        # Сравнение с существующим снапшотом
        saved = json.loads(snapshot_path.read_text(encoding="utf-8"))
        saved_sha = saved.get("sha256")
        saved_contract = saved.get("contract")
        assert isinstance(saved_contract, list) and isinstance(saved_sha, str), "Повреждён снапшот контракта"

        # 1) Сверка хеша
        assert saved_sha == digest, (
            "Контракт gRPC v1 изменился. Это может быть легитимно.\n"
            "Если изменение ожидаемое, обновите снапшот: UPDATE_GRPC_CONTRACT=1 pytest -k proto_contract\n"
            f"old_sha={saved_sha}\nnew_sha={digest}"
        )

        # 2) На всякий случай — сверка содержимого (защитный дубль)
        assert saved_contract == json.loads(canonical), "Канонический контракт не совпал со снапшотом (различие в данных)"


# ----------------------------------------------------
# Локальные быстрые проверки naming/стиля по файлам
# ----------------------------------------------------

def test_proto_filenames_are_snake_case_and_proto3():
    """
    Локальная проверка имён и синтаксиса (быстрая диагностика).
    """
    test_file = Path(__file__).resolve()
    repo_root = _repo_root_from(test_file)
    proto_files = _iter_proto_files(repo_root, env_search_globs=os.getenv("GRPC_CONTRACT_SEARCH_GLOBS"))
    assert proto_files, "Не найдено .proto файлов в v1"

    for p in proto_files:
        assert p.suffix == ".proto"
        assert _SNAKE_RE.match(p.stem), f"Имя файла должно быть snake_case: {p.name}"
        src = _strip_comments(_read_text(p))
        syntax, package, _ = _parse_header(src)
        assert syntax == "proto3", f"{p}: syntax должен быть proto3"
        assert package, f"{p}: отсутствует package;"
        assert _PROTO_PACKAGE_V1_RE.search(package), f"{p}: package должен заканчиваться на .v1"


# ----------------------------------------------------
# Отладочные принты (помогают при падениях в CI)
# ----------------------------------------------------

def test_print_discovered_proto_files_for_debug():
    """
    Не функциональный тест, а отладочный: печатает найденные файлы.
    Его падение будет говорить о полном отсутствии файлов.
    """
    test_file = Path(__file__).resolve()
    repo_root = _repo_root_from(test_file)
    proto_files = _iter_proto_files(repo_root, env_search_globs=os.getenv("GRPC_CONTRACT_SEARCH_GLOBS"))
    assert proto_files, "gRPC v1 .proto не обнаружены"
    # Лаконичный вывод для логов CI
    rels = [str(p.relative_to(repo_root)) for p in proto_files]
    print("Discovered proto files (v1):")
    for r in rels:
        print(f"  - {r}")
