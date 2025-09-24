#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aethernova Engine | Codegen v1
proto_lint.py — линтер ProtoBuf-схем (proto3) с fail-on-error и JSON-отчетом.

Проверяет:
  A) Инструменты/компиляция:
     - buf lint (если установлен и есть buf.yaml/buf.gen.yaml)
     - sanity-компиляция grpc_tools.protoc (--descriptor_set_out, без вывода артефактов)

  B) Статические правила (быстро, без полноценного парсера):
     - syntax = "proto3";
     - package/option java_package/go_package/… согласованность с путём файла (эвристика);
     - имена Message/Enum — PascalCase, поля — snake_case, enum-значения — UPPER_SNAKE;
     - дубли и невалидные номера полей, пересечение reserved полей/диапазонов;
     - длина строки, табы, trailing spaces, финальная новая строка, EOL = LF;
     - отсутствие BOM, ширина файла (< 1MB), отсутствие CRLF;
     - запрет wildcard import, проверка существования import;
     - опционально enforce префиксов для package (e.g., engine.v1.*, common.v1.*).

Выход:
  - JSON-отчет на stdout со сводкой и списком findings.
Коды возврата:
  0 — OK, 1 — есть ошибки, 2 — ошибка исполнения/окружения.

Зависимости:
  - Python 3.8+
  - Опционально: buf, grpcio-tools, protobuf
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Set

# -------------------- Модели отчета --------------------

@dataclass
class Finding:
    file: str
    line: int
    col: int
    rule: str
    severity: str  # error|warn|info
    message: str

@dataclass
class Section:
    ok: bool
    summary: str
    details: Dict[str, object]

@dataclass
class Report:
    ok: bool
    root: str
    profile: str
    files_checked: int
    findings: List[Finding]
    sections: Dict[str, Section]

    def to_json(self) -> str:
        def default(o):
            if isinstance(o, (Report, Section, Finding)):
                return asdict(o)
            if isinstance(o, Path):
                return str(o)
            raise TypeError(type(o))
        return json.dumps(asdict(self), indent=2, ensure_ascii=False, default=default)


# -------------------- Утилиты --------------------

REPO_MARKERS = (".git", "pyproject.toml", "engine-core")

def detect_repo_root(start: Optional[Path] = None) -> Path:
    p = Path(start or __file__).resolve()
    for base in [p] + list(p.parents):
        for m in REPO_MARKERS:
            if (base / m).exists():
                return base
    return p.parents[4]

def run(cmd: List[str], cwd: Optional[Path] = None, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, timeout=timeout or 300)

def which(cmd: str) -> Optional[str]:
    from shutil import which as sh_which
    return sh_which(cmd)

def list_proto_files(root: Path, includes: List[str], excludes: List[str]) -> List[Path]:
    # includes/excludes — glob от корня репо
    out: Set[Path] = set()
    for pat in includes:
        out.update(root.glob(pat))
        out.update(root.rglob(pat) if "**" not in pat else [])
    # normalize: только файлы
    out = {p.resolve() for p in out if p.is_file()}
    # фильтры
    ex: Set[Path] = set()
    for pat in excludes:
        ex.update(root.glob(pat))
        ex.update(root.rglob(pat) if "**" not in pat else [])
    return sorted(p for p in out if p.suffix == ".proto" and p not in ex)

def rel_to_root(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except Exception:
        return str(p)


# -------------------- Правила линтинга --------------------

RE_SYNTAX = re.compile(r'^\s*syntax\s*=\s*"proto3"\s*;\s*$')
RE_PACKAGE = re.compile(r'^\s*package\s+([A-Za-z_][\w.]*)\s*;\s*$')
RE_IMPORT = re.compile(r'^\s*import\s+"([^"]+)"\s*;\s*$')
RE_MESSAGE = re.compile(r'^\s*message\s+([A-Za-z_]\w*)\s*{')
RE_ENUM = re.compile(r'^\s*enum\s+([A-Za-z_]\w*)\s*{')
RE_FIELD = re.compile(r'^\s*(repeated\s+)?(optional\s+)?(map<[^>]+>\s+|[A-Za-z_]\w*\s+)([a-z_][a-z0-9_]*)\s*=\s*([0-9]+)\s*(?:\[([^\]]*)\])?\s*;')
RE_ENUM_VALUE = re.compile(r'^\s*([A-Z][A-Z0-9_]*?)\s*=\s*([0-9]+)\s*;')
RE_RESERVED = re.compile(r'^\s*reserved\s+(.+?)\s*;\s*$')  # names "foo","bar" or ranges 1, 4 to 6

PASCAL = re.compile(r'^[A-Z][A-Za-z0-9]*$')
SNAKE = re.compile(r'^[a-z][a-z0-9_]*$')
UPPER_SNAKE = re.compile(r'^[A-Z][A-Z0-9_]*$')

def parse_reserved(expr: str) -> Tuple[Set[int], List[Tuple[int,int]], Set[str]]:
    nums: Set[int] = set()
    ranges: List[Tuple[int,int]] = []
    names: Set[str] = set()
    # Split by comma, tolerate "to"
    parts = [p.strip() for p in expr.split(",")]
    for p in parts:
        if not p:
            continue
        if p.startswith('"') and p.endswith('"') and len(p) >= 2:
            names.add(p.strip('"'))
            continue
        if "to" in p:
            a,b = [q.strip() for q in p.split("to",1)]
            if a.isdigit() and (b.isdigit() or b == "max"):
                ai = int(a)
                bi = 536870911 if b == "max" else int(b)
                if ai <= bi:
                    ranges.append((ai,bi))
            continue
        if p.isdigit():
            nums.add(int(p))
    return nums, ranges, names

def overlaps(a: Tuple[int,int], b: Tuple[int,int]) -> bool:
    return not (a[1] < b[0] or b[1] < a[0])

def check_file(path: Path, root: Path, cfg) -> Tuple[List[Finding], Dict[str, object]]:
    findings: List[Finding] = []
    rel = rel_to_root(path, root)
    try:
        data = path.read_bytes()
    except Exception as e:
        return [Finding(rel, 1, 1, "io.read", "error", f"Не удалось прочитать файл: {e}")], {}

    # Size rule
    if len(data) > cfg.max_file_size:
        findings.append(Finding(rel, 1, 1, "size.max", "error", f"Размер файла {len(data)}B > лимита {cfg.max_file_size}B"))

    # BOM/EOL rules
    if data.startswith(b"\xef\xbb\xbf"):
        findings.append(Finding(rel, 1, 1, "encoding.bom", "error", "UTF-8 BOM запрещен"))
        data = data[3:]
    text = None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        findings.append(Finding(rel, 1, 1, "encoding.utf8", "error", f"Не UTF-8: {e}"))
        return findings, {}

    if "\r\n" in text:
        findings.append(Finding(rel, 1, 1, "eol.crlf", "error", "CRLF обнаружены — используйте LF"))

    if not text.endswith("\n"):
        findings.append(Finding(rel, max(1, text.count("\n")), 1, "eol.eof", "error", "Файл должен оканчиваться переводом строки"))

    lines = text.splitlines(True)
    has_syntax = False
    package_name: Optional[str] = None
    imports: List[str] = []
    messages: List[Tuple[str,int]] = []
    enums: List[Tuple[str,int]] = []
    fields: List[Tuple[str,int,int]] = []  # (name, number, line)
    enum_values: List[Tuple[str,int,int]] = []
    reserved_nums: List[Tuple[int,int]] = []  # ranges and singles as (x,x)
    reserved_names: Set[str] = set()

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")

        # Trailing spaces
        if line.rstrip(" ") != line:
            findings.append(Finding(rel, idx, len(line), "style.trailing-space", "warn", "Лишние пробелы в конце строки"))
        # Tabs
        if "\t" in line:
            findings.append(Finding(rel, idx, 1, "style.tab", "warn", "Табуляции запрещены (используйте пробелы)"))
        # Length
        if len(line) > cfg.max_line_length:
            findings.append(Finding(rel, idx, cfg.max_line_length+1, "style.line-length", "warn", f"Длина строки {len(line)} > {cfg.max_line_length}"))

        if RE_SYNTAX.match(line):
            has_syntax = True
        m = RE_PACKAGE.match(line)
        if m:
            package_name = m.group(1)
        m = RE_IMPORT.match(line)
        if m:
            imports.append(m.group(1))
        m = RE_MESSAGE.match(line)
        if m:
            name = m.group(1)
            messages.append((name, idx))
            if not PASCAL.match(name):
                findings.append(Finding(rel, idx, 1, "naming.message", "error", f"Имя message должно быть PascalCase: {name}"))
        m = RE_ENUM.match(line)
        if m:
            name = m.group(1)
            enums.append((name, idx))
            if not PASCAL.match(name):
                findings.append(Finding(rel, idx, 1, "naming.enum", "error", f"Имя enum должно быть PascalCase: {name}"))
        m = RE_FIELD.match(line)
        if m:
            fname = m.group(4)
            fnum = int(m.group(5))
            fields.append((fname, fnum, idx))
            if not SNAKE.match(fname):
                findings.append(Finding(rel, idx, 1, "naming.field", "error", f"Имя поля должно быть snake_case: {fname}"))
            if fnum == 0 or fnum > 536870911:
                findings.append(Finding(rel, idx, 1, "field.number.range", "error", f"Номер поля вне диапазона: {fnum}"))
        m = RE_ENUM_VALUE.match(line)
        if m:
            ename = m.group(1)
            evaln = int(m.group(2))
            enum_values.append((ename, evaln, idx))
            if not UPPER_SNAKE.match(ename):
                findings.append(Finding(rel, idx, 1, "naming.enum.value", "error", f"Enum-значение должно быть UPPER_SNAKE: {ename}"))
        m = RE_RESERVED.match(line)
        if m:
            nums, ranges, names = parse_reserved(m.group(1))
            for n in nums:
                reserved_nums.append((n, n))
            reserved_nums.extend(ranges)
            reserved_names.update(names)

    # syntax rule
    if cfg.enforce_proto3 and not has_syntax:
        findings.append(Finding(rel, 1, 1, "syntax.proto3", "error", 'Отсутствует строка: syntax = "proto3";'))

    # package prefix rule
    if cfg.package_prefixes and package_name:
        if not any(package_name.startswith(pref) for pref in cfg.package_prefixes):
            findings.append(Finding(rel, 1, 1, "package.prefix", "warn", f"Пакет {package_name} не соответствует разрешенным префиксам {cfg.package_prefixes}"))

    # file path vs package heuristic
    if cfg.check_package_path and package_name:
        expected_parts = package_name.split(".")
        # эвристика: путь вида .../v1/... должен содержать v1 и сегменты пакета
        parts = rel.split("/")
        if "v1" in parts and not all(seg in parts for seg in expected_parts[-2:]):  # слабая проверка последних двух
            findings.append(Finding(rel, 1, 1, "package.path", "warn", f"Эвристика: путь {rel} может не соответствовать package {package_name}"))

    # duplicate field numbers
    seen_nums: Dict[int, int] = {}
    for fname, num, ln in fields:
        if num in seen_nums:
            findings.append(Finding(rel, ln, 1, "field.number.duplicate", "error", f"Дублирование номера поля {num} (предыдущее объявление на строке {seen_nums[num]})"))
        else:
            seen_nums[num] = ln

    # reserved overlap
    for fname, num, ln in fields:
        for r in reserved_nums:
            if r[0] <= num <= r[1]:
                findings.append(Finding(rel, ln, 1, "reserved.overlap", "error", f"Поле {fname} с номером {num} попадает в reserved {r[0]}..{r[1]}"))
                break

    # enum first value should be zero (style)
    for ename, epos in enums:
        # find first value after enum line
        vals = [v for v in enum_values if v[2] > epos]
        if vals:
            first = vals[0]
            if first[1] != 0:
                findings.append(Finding(rel, first[2], 1, "enum.zero-first", "warn", f"Первое значение enum обычно 0, найдено {first[1]}"))

    # imports existence
    for imp in imports:
        # запрет wildcard
        if "*" in imp:
            findings.append(Finding(rel, 1, 1, "import.wildcard", "error", f"Wildcard import запрещен: {imp}"))
        # проверка существования файла (относительно корней include)
        found = False
        for inc in cfg.includes:
            if (inc / imp).exists():
                found = True
                break
        if not found:
            findings.append(Finding(rel, 1, 1, "import.missing", "error", f"Файл импорта не найден в include-путях: {imp}"))

    # summary
    details = {
        "package": package_name,
        "messages": [n for n,_ in messages],
        "enums": [n for n,_ in enums],
        "imports": imports,
        "reserved_ranges": reserved_nums,
        "reserved_names": sorted(reserved_names),
    }
    return findings, details


# -------------------- Интеграции (buf, protoc) --------------------

def run_buf_lint(root: Path, targets: List[Path]) -> Section:
    cfg_present = (root / "buf.yaml").exists() or (root / "buf.gen.yaml").exists()
    if which("buf") is None or not cfg_present:
        return Section(ok=True, summary="buf lint: пропущен (нет buf или конфигурации)", details={"skipped": True})
    # buf lint по каталогу схем
    # Находим общие директории
    dirs = sorted({(root / "engine-core/schemas/proto").resolve()})
    outputs: List[str] = []
    ok = True
    for d in dirs:
        cp = run(["buf", "lint"], cwd=d)
        outputs.append(f"{d}:\n{cp.stdout}\n{cp.stderr}")
        if cp.returncode != 0:
            ok = False
    return Section(ok=ok, summary="buf lint выполнен", details={"outputs": outputs})

def run_protoc_sanity(root: Path, targets: List[Path], includes: List[Path]) -> Section:
    # Используем python -m grpc_tools.protoc, если установлен
    try:
        import grpc_tools.protoc  # noqa
    except Exception as e:
        return Section(ok=True, summary="protoc sanity: пропущен (нет grpc_tools)", details={"skipped": True, "reason": str(e)})
    # Сгенерируем временный descriptor_set в /dev/null аналогично
    inc_args: List[str] = []
    for inc in includes:
        inc_args.extend(["-I", str(inc)])
    findings: List[str] = []
    ok = True
    # Разбиваем по батчам, чтобы не превысить cmdline
    batch: List[Path] = []
    MAX_BATCH = 200
    for p in targets:
        batch.append(p)
        if len(batch) >= MAX_BATCH:
            ok &= _run_protoc_batch(root, inc_args, batch, findings)
            batch.clear()
    if batch:
        ok &= _run_protoc_batch(root, inc_args, batch, findings)
    return Section(ok=ok, summary="protoc sanity компиляция", details={"results": findings})

def _run_protoc_batch(root: Path, inc_args: List[str], batch: List[Path], findings: List[str]) -> bool:
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(suffix=".pb", delete=True) as tf:
        cmd = [sys.executable, "-m", "grpc_tools.protoc", *inc_args, f"--descriptor_set_out={tf.name}"]
        cmd.extend([str(p) for p in batch])
        cp = run(cmd, cwd=root)
        findings.append(f"cmd={' '.join(cmd)} rc={cp.returncode}\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}")
        return cp.returncode == 0


# -------------------- CLI/Config --------------------

@dataclass
class Config:
    profile: str
    enforce_proto3: bool
    package_prefixes: List[str]
    check_package_path: bool
    max_line_length: int
    max_file_size: int
    includes: List[Path]

def parse_args() -> Tuple[argparse.Namespace, Config, Path]:
    ap = argparse.ArgumentParser(description="Lint .proto files with style, naming and sanity compilation")
    ap.add_argument("--profile", choices=["dev","ci","release"], default="dev", help="Профиль проверки")
    ap.add_argument("--include", action="append", default=[], help="Include-пути для импорта (можно повторять)")
    ap.add_argument("--paths", nargs="*", default=["engine-core/schemas/proto/v1/**/*.proto"], help="Глоб-пути к *.proto")
    ap.add_argument("--exclude", action="append", default=["**/*_internal.proto"], help="Шаблоны исключений")
    ap.add_argument("--max-line-length", type=int, default=140)
    ap.add_argument("--max-file-size", type=int, default=1_000_000)
    ap.add_argument("--enforce-proto3", action="store_true", default=True)
    ap.add_argument("--no-enforce-proto3", dest="enforce_proto3", action="store_false")
    ap.add_argument("--package-prefix", action="append", default=["engine.v1","common.v1","economy.v1"], help="Разрешенные префиксы package")
    ap.add_argument("--no-check-package-path", dest="check_package_path", action="store_false", default=True)
    ap.add_argument("--json-only", action="store_true", help="Печатать только JSON-отчет")
    args = ap.parse_args()

    root = detect_repo_root()
    includes = [Path(p).resolve() if os.path.isabs(p) else (root / p).resolve() for p in (args.include or [])]
    if not includes:
        includes = [(root / "engine-core/schemas/proto").resolve(), root.resolve()]

    cfg = Config(
        profile=args.profile,
        enforce_proto3=args.enforce_proto3,
        package_prefixes=args.package_prefix,
        check_package_path=args.check_package_path,
        max_line_length=args.max_line_length,
        max_file_size=args.max_file_size,
        includes=includes,
    )
    return args, cfg, root


# -------------------- main --------------------

def main() -> int:
    args, cfg, root = parse_args()

    # Сканируем файлы
    files = list_proto_files(root, args.paths, args.exclude)
    sections: Dict[str, Section] = {}
    findings: List[Finding] = []

    # Статический анализ
    for fp in files:
        fnds, _details = check_file(fp, root, cfg)
        findings.extend(fnds)

    # buf lint
    sections["buf"] = run_buf_lint(root, files)

    # sanity компиляция
    sections["protoc"] = run_protoc_sanity(root, files, cfg.includes)

    # Итоговый статус
    # Ошибки — severity == error либо секции ok=False
    has_errors = any(f.severity == "error" for f in findings) or not all(sec.ok for sec in sections.values())
    rep = Report(
        ok=not has_errors,
        root=str(root),
        profile=cfg.profile,
        files_checked=len(files),
        findings=findings,
        sections=sections,
    )

    if not args.json_only:
        print(f"LINT RESULT: {'OK' if rep.ok else 'FAIL'}  files={len(files)}  errors={sum(1 for f in findings if f.severity=='error')} warnings={sum(1 for f in findings if f.severity=='warn')}")
    print(rep.to_json())

    return 0 if rep.ok else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Непредвиденная ошибка — код 2 и JSON с сообщением
        err_rep = {
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
            "hint": "Проверьте наличие Python, grpcio-tools/protobuf, а также корректность путей."
        }
        print(json.dumps(err_rep, ensure_ascii=False, indent=2))
        sys.exit(2)
