# path: mythos-core/cli/tools/validate_canon.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mythos Canon Validator (industrial edition)

Назначение:
- Асинхронная валидация YAML/JSON документов лора ("канона") Aethernova/NeuroCity.
- Проверка схемы, кросс-ссылок, уникальностей, циклов, семантики полей, целостности.
- Форматы отчетов: text, json, junit, sarif. Интеграция в CI с кодами выхода.
- Поддержка подавления правил x-ignore-rules и конфиг-файла.

Зависимости (опционально, при наличии повышают точность и UX):
- PyYAML (yaml), pydantic>=2, jsonschema, rich

При отсутствии внешних пакетов скрипт выполняет деградирующую валидацию
с базовыми проверками и plain-text выводом.

Примеры:
  python -m mythos_core.cli.tools.validate_canon ./canon/
  python -m mythos_core.cli.tools.validate_canon ./canon/angel.yml --format json --strict
  python -m mythos_core.cli.tools.validate_canon ./canon --config mythos-core/cli/config/validate_canon.yaml

Exit codes:
  0  OK (нет ошибок; предупреждения допустимы в нестрогом режиме)
  1  Ошибки валидации
  2  Только предупреждения, но --strict

Автор: Aethernova / NeuroCity
Лицензия: MIT
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import functools
import hashlib
import io
import json
import os
import re
import sys
import textwrap
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

# Опциональные зависимости
with contextlib.suppress(ImportError):
    import yaml  # type: ignore
with contextlib.suppress(ImportError):
    import aiofiles  # type: ignore
with contextlib.suppress(ImportError):
    from pydantic import BaseModel, Field, ValidationError as PydValidationError  # type: ignore
with contextlib.suppress(ImportError):
    import jsonschema  # type: ignore

# Опциональное цветное форматирование
RICH_AVAILABLE = False
Console = None
Style = None
with contextlib.suppress(Exception):
    from rich.console import Console as _Console  # type: ignore
    from rich.style import Style as _Style  # type: ignore

    Console = _Console
    Style = _Style
    RICH_AVAILABLE = True


# --------- Константы и базовые структуры ---------

DEFAULT_INCLUDE_EXTS = {".yml", ".yaml", ".json"}
IGNORED_HASH_FIELDS = {"integrity_hash", "signature", "_meta", "x-ignore-rules"}
DEFAULT_ALLOWED_TYPES = {"Law", "Angel", "God", "Artifact", "Chronicle", "Entity", "Concept"}
DEFAULT_ALLOWED_STATUS = {"draft", "review", "approved", "deprecated"}

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+].*)?$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")

# --------- Уровни и типы проблем ---------

class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


@dataclasses.dataclass
class Issue:
    rule_id: str
    severity: Severity
    file: Path
    pointer: str  # JSON Pointer style path like "/refs/0"
    message: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file": str(self.file),
            "pointer": self.pointer,
            "message": self.message,
        }


@dataclasses.dataclass
class Document:
    file: Path
    data: Dict[str, Any]
    id: Optional[str]
    slug: Optional[str]
    type: Optional[str]
    refs: List[str]
    ignore_rules_obj: Set[str]
    ignore_rules_file: Set[str]


# --------- Утилиты ввода-вывода ---------

async def read_text_async(path: Path) -> str:
    if "aiofiles" in sys.modules:
        async with aiofiles.open(path, "r", encoding="utf-8") as f:  # type: ignore
            return await f.read()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, path.read_text, "utf-8")


def load_config(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    if not path.exists():
        return {}
    text = path.read_text("utf-8")
    if "yaml" in sys.modules:
        return yaml.safe_load(text) or {}  # type: ignore
    # Минимальная поддержка JSON-конфига при отсутствии PyYAML
    with contextlib.suppress(Exception):
        return json.loads(text)
    return {}


def discover_files(inputs: List[Path], exts: Set[str]) -> List[Path]:
    results: List[Path] = []
    for p in inputs:
        if p.is_file() and p.suffix.lower() in exts:
            results.append(p)
        elif p.is_dir():
            for ext in exts:
                results.extend(p.rglob(f"*{ext}"))
    # Уникальность и стабильный порядок
    return sorted(set(results))


def parse_any(text: str, file: Path) -> Dict[str, Any]:
    # YAML предпочтительнее, т.к. часто используется в лоре
    if file.suffix.lower() in {".yml", ".yaml"} and "yaml" in sys.modules:
        return yaml.safe_load(text) or {}  # type: ignore
    with contextlib.suppress(Exception):
        return json.loads(text)
    # Попытка YAML как fallback
    if "yaml" in sys.modules:
        return yaml.safe_load(text) or {}  # type: ignore
    raise ValueError(f"Unable to parse file (no parsers available): {file}")


def to_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


# --------- Канонизация и хеш ---------

def _sorted_items(d: Dict[str, Any]) -> List[Tuple[str, Any]]:
    return sorted(d.items(), key=lambda kv: kv[0])


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        # Исключаем поля, которые не участвуют в хеше
        items = [(k, v) for k, v in _sorted_items(obj) if k not in IGNORED_HASH_FIELDS]
        return {k: _canonicalize(v) for k, v in items}
    if isinstance(obj, list):
        return [_canonicalize(v) for v in obj]
    return obj


def compute_integrity_hash(data: Dict[str, Any]) -> str:
    canon = _canonicalize(data)
    payload = to_json(canon).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# --------- Базовая модель (опционально через pydantic) ---------

class _NoPydBase:
    """Fallback базовая "модель", если pydantic недоступен."""

    def __init__(self, **kwargs: Any) -> None:
        self.raw = kwargs

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
        # Минимальные проверки, возвращаем id (если есть) и список ошибок
        errors: List[str] = []
        id_ = data.get("id")
        slug = data.get("slug")
        title = data.get("title")
        type_ = data.get("type")
        version = data.get("version")
        status = data.get("status")

        if id_ is not None and not isinstance(id_, str):
            errors.append("field 'id' must be string if present")
        if slug is not None and (not isinstance(slug, str) or not SLUG_RE.match(slug)):
            errors.append("field 'slug' must match slug pattern")
        if title is None or not isinstance(title, str) or not title.strip():
            errors.append("field 'title' is required non-empty string")
        if type_ is not None and type_ not in DEFAULT_ALLOWED_TYPES:
            errors.append(f"field 'type' must be one of {sorted(DEFAULT_ALLOWED_TYPES)}")
        if version is not None and (not isinstance(version, str) or not SEMVER_RE.match(version)):
            errors.append("field 'version' must be semver string")
        if status is not None and status not in DEFAULT_ALLOWED_STATUS:
            errors.append(f"field 'status' must be one of {sorted(DEFAULT_ALLOWED_STATUS)}")

        return (id_ if isinstance(id_, str) else None), errors


if "BaseModel" in globals():

    class CanonModel(BaseModel):  # type: ignore
        id: Optional[str] = None
        slug: Optional[str] = None
        type: Optional[str] = None
        title: str
        summary: Optional[str] = None
        version: Optional[str] = None
        status: Optional[str] = None
        refs: List[str] = []
        tags: List[str] = []
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        integrity_hash: Optional[str] = None
        signature: Optional[str] = None
        _meta: Dict[str, Any] = {}
        # произвольные расширения допускаем
        # model_config = ConfigDict(extra="allow")  # pydantic v2
        class Config:
            extra = "allow"

    def pydantic_validate(data: Dict[str, Any]) -> Tuple[Optional[CanonModel], List[str]]:
        try:
            model = CanonModel(**data)
        except PydValidationError as e:  # type: ignore
            return None, [str(e)]
        # семантические проверки базового уровня
        errs: List[str] = []
        if model.slug and not SLUG_RE.match(model.slug):
            errs.append("slug does not match pattern")
        if model.type and model.type not in DEFAULT_ALLOWED_TYPES:
            errs.append(f"type must be one of {sorted(DEFAULT_ALLOWED_TYPES)}")
        if model.version and not SEMVER_RE.match(model.version):
            errs.append("version must be valid semver")
        if model.status and model.status not in DEFAULT_ALLOWED_STATUS:
            errs.append(f"status must be one of {sorted(DEFAULT_ALLOWED_STATUS)}")
        # даты
        for fld in ("created_at", "updated_at"):
            v = getattr(model, fld)
            if v:
                try:
                    dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
                except Exception:
                    errs.append(f"{fld} must be ISO8601")
        if errs:
            return None, errs
        return model, []

else:
    CanonModel = _NoPydBase  # type: ignore

# --------- Правила валидации ---------

@dataclasses.dataclass
class RuleContext:
    documents: List[Document]
    by_id: Dict[str, Document]
    by_slug: Dict[str, Document]
    graph: Dict[str, Set[str]]  # id_or_slug -> set of id_or_slug referenced


def is_ignored(doc: Document, rule_id: str, pointer: str) -> bool:
    if rule_id in doc.ignore_rules_file:
        return True
    if rule_id in doc.ignore_rules_obj:
        return True
    # Поддержка локального подавления на pointer в будущем
    return False


def rule_unique_ids(ctx: RuleContext) -> List[Issue]:
    seen: Dict[str, Path] = {}
    issues: List[Issue] = []
    for d in ctx.documents:
        if d.id:
            if d.id in seen and seen[d.id] != d.file:
                issues.append(Issue("CANON-001", Severity.ERROR, d.file, "/id",
                                    f"Duplicate id '{d.id}' also in {seen[d.id]}"))
            else:
                seen[d.id] = d.file
    return issues


def rule_unique_slugs(ctx: RuleContext) -> List[Issue]:
    seen: Dict[str, Path] = {}
    issues: List[Issue] = []
    for d in ctx.documents:
        if d.slug:
            if d.slug in seen and seen[d.slug] != d.file:
                issues.append(Issue("CANON-002", Severity.ERROR, d.file, "/slug",
                                    f"Duplicate slug '{d.slug}' also in {seen[d.slug]}"))
            else:
                seen[d.slug] = d.file
    return issues


def rule_refs_exist(ctx: RuleContext) -> List[Issue]:
    issues: List[Issue] = []
    known = set(ctx.by_id.keys()) | set(ctx.by_slug.keys())
    for d in ctx.documents:
        for i, ref in enumerate(d.refs):
            if ref not in known:
                issues.append(Issue("CANON-003", Severity.ERROR, d.file, f"/refs/{i}",
                                    f"Broken reference '{ref}'"))
    return issues


def rule_cycles(ctx: RuleContext, max_cycle_report: int = 10) -> List[Issue]:
    issues: List[Issue] = []
    color = Severity.ERROR

    visited: Set[str] = set()
    stack: Set[str] = set()

    def visit(node: str, path: List[str]) -> None:
        nonlocal issues
        if node in stack:
            # цикл обнаружен
            cycle_start = path.index(node) if node in path else 0
            cycle = path[cycle_start:] + [node]
            msg = " -> ".join(cycle[:max_cycle_report])
            # Не все циклы критичны; для лора допустим WARN, но оставим ERROR для CI-жесткости
            issues.append(Issue("CANON-004", color, ctx.by_id.get(node, ctx.by_slug.get(node, ctx.documents[0])).file, "/refs",
                                f"Reference cycle detected: {msg}"))
            return
        if node in visited:
            return
        visited.add(node)
        stack.add(node)
        for neigh in ctx.graph.get(node, set()):
            visit(neigh, path + [node])
        stack.remove(node)

    for k in set(ctx.graph.keys()):
        visit(k, [])
    return issues


def rule_filename_matches_slug(ctx: RuleContext) -> List[Issue]:
    issues: List[Issue] = []
    for d in ctx.documents:
        if d.slug:
            expected = f"{d.slug}{d.file.suffix.lower()}"
            if d.file.name.lower() != expected:
                issues.append(Issue("CANON-005", Severity.WARN, d.file, "/slug",
                                    f"Filename should match slug: '{expected}'"))
    return issues


def rule_no_todo(docs: List[Document]) -> List[Issue]:
    issues: List[Issue] = []
    todo_re = re.compile(r"\bTODO\b|\bFIXME\b", re.IGNORECASE)
    for d in docs:
        blob = to_json(d.data)
        if todo_re.search(blob):
            issues.append(Issue("CANON-006", Severity.WARN, d.file, "/",
                                "Found TODO/FIXME markers"))
    return issues


def rule_title_length(docs: List[Document], max_len: int = 140) -> List[Issue]:
    issues: List[Issue] = []
    for d in docs:
        title = str(d.data.get("title", "")).strip()
        if not title:
            issues.append(Issue("CANON-007", Severity.ERROR, d.file, "/title", "Title is required"))
        elif len(title) > max_len:
            issues.append(Issue("CANON-007", Severity.WARN, d.file, "/title",
                                f"Title is too long: {len(title)} > {max_len}"))
    return issues


def rule_dates_iso(docs: List[Document]) -> List[Issue]:
    issues: List[Issue] = []
    for d in docs:
        for fld in ("created_at", "updated_at"):
            v = d.data.get(fld)
            if v:
                try:
                    dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                except Exception:
                    issues.append(Issue("CANON-008", Severity.ERROR, d.file, f"/{fld}",
                                        f"{fld} must be ISO8601"))
    return issues


def rule_semver_and_status(docs: List[Document]) -> List[Issue]:
    issues: List[Issue] = []
    for d in docs:
        v = d.data.get("version")
        s = d.data.get("status")
        if v and (not isinstance(v, str) or not SEMVER_RE.match(v)):
            issues.append(Issue("CANON-009", Severity.ERROR, d.file, "/version", "Invalid semver"))
        if s and s not in DEFAULT_ALLOWED_STATUS:
            issues.append(Issue("CANON-009", Severity.ERROR, d.file, "/status",
                                f"Invalid status, allowed: {sorted(DEFAULT_ALLOWED_STATUS)}"))
    return issues


def rule_integrity_hash(docs: List[Document]) -> List[Issue]:
    issues: List[Issue] = []
    for d in docs:
        declared = d.data.get("integrity_hash")
        if not declared:
            # Не ошибка, а предупреждение: хеш не обязателен
            issues.append(Issue("CANON-010", Severity.WARN, d.file, "/integrity_hash",
                                "Missing integrity_hash"))
            continue
        actual = compute_integrity_hash(d.data)
        if declared != actual:
            issues.append(Issue("CANON-010", Severity.ERROR, d.file, "/integrity_hash",
                                "integrity_hash mismatch"))
    return issues


def rule_slug_pattern(docs: List[Document]) -> List[Issue]:
    issues: List[Issue] = []
    for d in docs:
        if d.slug and not SLUG_RE.match(d.slug):
            issues.append(Issue("CANON-011", Severity.ERROR, d.file, "/slug",
                                "Slug must match ^[a-z0-9]+([-_][a-z0-9]+)*$"))
    return issues


def rule_type_allowed(docs: List[Document]) -> List[Issue]:
    issues: List[Issue] = []
    for d in docs:
        if d.type and d.type not in DEFAULT_ALLOWED_TYPES:
            issues.append(Issue("CANON-012", Severity.ERROR, d.file, "/type",
                                f"type must be one of {sorted(DEFAULT_ALLOWED_TYPES)}"))
    return issues


# --------- Загрузка и подготовка документов ---------

def extract_ignores(data: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    obj_ign: Set[str] = set()
    file_ign: Set[str] = set()
    x = data.get("x-ignore-rules")
    if isinstance(x, list):
        obj_ign = {str(v) for v in x}
    meta = data.get("_meta", {})
    if isinstance(meta, dict):
        ig = meta.get("ignore_rules")
        if isinstance(ig, list):
            file_ign = {str(v) for v in ig}
    return obj_ign, file_ign


async def load_document(file: Path) -> Document:
    text = await read_text_async(file)
    data = parse_any(text, file)
    obj_ign, file_ign = extract_ignores(data)

    # Pydantic если есть
    model_obj = None
    errors: List[str] = []
    if "CanonModel" in globals() and CanonModel is not _NoPydBase:  # type: ignore
        model_obj, errors = pydantic_validate(data)  # type: ignore
        if errors:
            # Мы не прерываемся — продолжаем, отметим как ERR позже в общем пайплайне
            pass
    else:
        _, errors = _NoPydBase.validate(data)

    doc = Document(
        file=file,
        data=data,
        id=str(data.get("id")) if data.get("id") is not None else None,
        slug=str(data.get("slug")) if data.get("slug") is not None else None,
        type=str(data.get("type")) if data.get("type") is not None else None,
        refs=[str(r) for r in (data.get("refs") or []) if isinstance(r, (str, int))],
        ignore_rules_obj=obj_ign,
        ignore_rules_file=file_ign,
    )

    # Преобразуем первичные pydantic-ошибки в issues уровня ERROR
    if errors:
        for idx, err in enumerate(errors):
            yield Issue("CANON-000", Severity.ERROR, file, "/", f"Schema validation: {err}")  # type: ignore

    # Возвращаем документ последним "элементом" генератора
    yield doc  # type: ignore


async def gather_documents(files: List[Path]) -> Tuple[List[Document], List[Issue]]:
    docs: List[Document] = []
    prelim_issues: List[Issue] = []

    async def load_one(f: Path):
        async for item in load_document(f):
            if isinstance(item, Document):
                docs.append(item)
            else:
                prelim_issues.append(item)  # type: ignore

    await asyncio.gather(*(load_one(f) for f in files))
    return docs, prelim_issues


def build_indexes(docs: List[Document]) -> Tuple[Dict[str, Document], Dict[str, Document], Dict[str, Set[str]]]:
    by_id: Dict[str, Document] = {}
    by_slug: Dict[str, Document] = {}
    graph: Dict[str, Set[str]] = {}

    for d in docs:
        if d.id:
            by_id[d.id] = d
        if d.slug:
            by_slug[d.slug] = d
    known = set(by_id.keys()) | set(by_slug.keys())
    for d in docs:
        key = d.id or d.slug or str(d.file)
        edges: Set[str] = set()
        for r in d.refs:
            if r in known:
                edges.add(r)
        graph[key] = edges
    return by_id, by_slug, graph


# --------- Отчеты ---------

def render_text(issues: List[Issue], strict: bool, console: Optional[Any]) -> str:
    buf = io.StringIO()
    total = len(issues)
    errors = sum(1 for i in issues if i.severity == Severity.ERROR)
    warns = sum(1 for i in issues if i.severity == Severity.WARN)
    infos = sum(1 for i in issues if i.severity == Severity.INFO)

    line = f"Issues: total={total}, errors={errors}, warns={warns}, infos={infos}, strict={strict}"
    print(line, file=buf)

    for it in issues:
        prefix = f"[{it.severity.value}] {it.rule_id}"
        print(f"{prefix} {it.file}:{it.pointer} - {it.message}", file=buf)

    return buf.getvalue()


def render_json(issues: List[Issue], strict: bool) -> str:
    payload = {
        "strict": strict,
        "summary": {
            "total": len(issues),
            "errors": sum(1 for i in issues if i.severity == Severity.ERROR),
            "warnings": sum(1 for i in issues if i.severity == Severity.WARN),
            "infos": sum(1 for i in issues if i.severity == Severity.INFO),
        },
        "issues": [i.as_dict() for i in issues],
    }
    return to_json(payload)


def render_junit(issues: List[Issue]) -> str:
    # Простой JUnit XML
    import xml.etree.ElementTree as ET

    testsuite = ET.Element("testsuite", name="mythos-canon", tests=str(len(issues)))
    for it in issues:
        case = ET.SubElement(testsuite, "testcase", classname=it.rule_id, name=f"{it.file}:{it.pointer}")
        if it.severity in (Severity.ERROR, Severity.WARN):
            tag = "failure" if it.severity == Severity.ERROR else "skipped"
            elem = ET.SubElement(case, tag, message=it.message)
            elem.text = it.message
    return ET.tostring(testsuite, encoding="unicode")


def render_sarif(issues: List[Issue]) -> str:
    # Минимальный SARIF 2.1.0
    rules_meta = {}
    for it in issues:
        rules_meta.setdefault(it.rule_id, {"id": it.rule_id, "shortDescription": {"text": it.rule_id}})

    runs = [{
        "tool": {
            "driver": {
                "name": "mythos-canon-validator",
                "informationUri": "https://aethernova.local/tools/mythos",  # placeholder
                "rules": list(rules_meta.values()),
            }
        },
        "results": [{
            "ruleId": it.rule_id,
            "level": "error" if it.severity == Severity.ERROR else "warning" if it.severity == Severity.WARN else "note",
            "message": {"text": it.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(it.file)},
                    "region": {"startLine": 1}
                }
            }]
        } for it in issues]
    }]
    sarif = {"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
             "version": "2.1.0", "runs": runs}
    return to_json(sarif)


# --------- Основной пайплайн ---------

async def validate(inputs: List[Path],
                   config_path: Optional[Path],
                   fmt: str,
                   strict: bool,
                   include_exts: Set[str]) -> Tuple[str, int]:
    console = Console() if RICH_AVAILABLE else None

    config = load_config(config_path)
    include_exts = set(config.get("include_exts", include_exts))
    max_cycle_report = int(config.get("max_cycle_report", 10))

    files = discover_files(inputs, include_exts)
    if not files:
        return "No input files found", 1

    docs, prelim_issues = await gather_documents(files)

    # Индексы
    by_id, by_slug, graph = build_indexes(docs)
    ctx = RuleContext(documents=docs, by_id=by_id, by_slug=by_slug, graph=graph)

    # Запуск правил
    all_issues: List[Issue] = list(prelim_issues)

    def filter_ignored(candidates: List[Issue]) -> List[Issue]:
        filtered: List[Issue] = []
        for it in candidates:
            # Поиск соответствующего документа
            doc = next((d for d in docs if d.file == it.file), None)
            if doc and is_ignored(doc, it.rule_id, it.pointer):
                continue
            filtered.append(it)
        return filtered

    all_issues += filter_ignored(rule_unique_ids(ctx))
    all_issues += filter_ignored(rule_unique_slugs(ctx))
    all_issues += filter_ignored(rule_refs_exist(ctx))
    all_issues += filter_ignored(rule_cycles(ctx, max_cycle_report))
    all_issues += filter_ignored(rule_filename_matches_slug(ctx))
    all_issues += filter_ignored(rule_no_todo(docs))
    all_issues += filter_ignored(rule_title_length(docs))
    all_issues += filter_ignored(rule_dates_iso(docs))
    all_issues += filter_ignored(rule_semver_and_status(docs))
    all_issues += filter_ignored(rule_integrity_hash(docs))
    all_issues += filter_ignored(rule_slug_pattern(docs))
    all_issues += filter_ignored(rule_type_allowed(docs))

    # Строгий режим: WARN -> ERROR
    if strict:
        all_issues = [
            Issue(it.rule_id, Severity.ERROR if it.severity == Severity.WARN else it.severity,
                  it.file, it.pointer, it.message)
            for it in all_issues
        ]

    # Рендер
    if fmt == "json":
        out = render_json(all_issues, strict)
    elif fmt == "junit":
        out = render_junit(all_issues)
    elif fmt == "sarif":
        out = render_sarif(all_issues)
    else:
        out = render_text(all_issues, strict, console)

    # Коды выхода
    had_error = any(i.severity == Severity.ERROR for i in all_issues)
    had_warn = any(i.severity == Severity.WARN for i in all_issues)
    if had_error:
        code = 1
    elif had_warn and strict:
        code = 2
    else:
        code = 0
    return out, code


# --------- CLI ---------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="validate_canon",
        description="Validate Mythos Canon YAML/JSON documents"
    )
    p.add_argument("inputs", nargs="+", help="Files or directories")
    p.add_argument("--config", type=str, help="Path to validator config (yaml/json)")
    p.add_argument("--format", choices=["text", "json", "junit", "sarif"], default="text", help="Output format")
    p.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    p.add_argument("--ext", action="append", help="Include file extensions (e.g., --ext .yaml --ext .json)")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    ns = parse_args(argv)
    inputs = [Path(x).resolve() for x in ns.inputs]
    cfg = Path(ns.config).resolve() if ns.config else None
    exts = set(ns.ext) if ns.ext else DEFAULT_INCLUDE_EXTS

    try:
        out, code = asyncio.run(validate(inputs, cfg, ns.format, ns.strict, exts))
        sys.stdout.write(out + ("\n" if not out.endswith("\n") else ""))
        return code
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted\n")
        return 1
    except Exception as e:
        # Непредвиденная ошибка — всегда ошибка валидации
        sys.stderr.write(f"Unhandled error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
