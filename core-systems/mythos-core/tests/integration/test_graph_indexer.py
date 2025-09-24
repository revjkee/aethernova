# path: mythos-core/tests/integration/test_graph_indexer.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты графового индексатора и CLI-валидатора канона.

Цели:
- Проверить построение индексов by_id/by_slug и графа ссылок.
- Проверить правила: циклы (CANON-004), разорванные ссылки (CANON-003),
  соответствие имени файла slug (CANON-005), уникальность (CANON-001/002).
- Проверить работу CLI с форматами вывода и строгим режимом.

Тесты не требуют внешних зависимостей (используют JSON вместо YAML).
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest


# ---------- Утилиты импорта тестируемого модуля ----------

def _load_validate_module() -> Any:
    """
    Импортирует модуль валидатора по одному из путей:
    1) mythos_core.cli.tools.validate_canon (предпочтительно, если проект упакован как пакет)
    2) относительный путь к файлу mythos-core/cli/tools/validate_canon.py (запуск из репозитория)
    """
    # Вариант 1: как установленный пакет
    try:
        return importlib.import_module("mythos_core.cli.tools.validate_canon")
    except Exception:
        pass

    # Вариант 2: локальный исходник по относительному пути от этого файла
    here = Path(__file__).resolve()
    candidate = here.parents[2] / "cli" / "tools" / "validate_canon.py"
    if not candidate.exists():
        # Вариант 3: альтернативное расположение (если структура отличается)
        alt = here.parents[3] / "mythos-core" / "cli" / "tools" / "validate_canon.py"
        candidate = alt if alt.exists() else candidate

    if not candidate.exists():
        raise RuntimeError(
            f"Не найден файл validate_canon.py. Ожидался путь: {candidate}"
        )

    spec = importlib.util.spec_from_file_location("validate_canon_local", candidate)
    assert spec and spec.loader, "Не удалось создать spec для validate_canon.py"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


# ---------- Утилиты подготовки тестовых документов ----------

def write_doc(base: Path, filename: str, payload: Dict[str, Any]) -> Path:
    """
    Записывает JSON-документ канона. Возвращает путь к файлу.
    """
    path = base / filename
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return path


async def _load_docs(mod: Any, files: List[Path]) -> Tuple[List[Any], List[Any]]:
    """
    Асинхронно загружает документы через gather_documents тестируемого модуля.
    """
    return await mod.gather_documents(files)


# ---------- Тесты построения индексов и графа ----------

def test_build_indexes_basic(tmp_path: Path):
    mod = _load_validate_module()

    a = {
        "id": "LAW-TRANSPARENCY",
        "slug": "law-transparency",
        "type": "Law",
        "title": "Law of Transparency",
        "version": "1.0.0",
        "status": "approved",
        "refs": ["ANGEL-MYTHOS"]
    }
    b = {
        "id": "ANGEL-MYTHOS",
        "slug": "angel-mythos",
        "type": "Angel",
        "title": "Angel of Mythos",
        "version": "0.1.0",
        "status": "review",
        "refs": []
    }

    f1 = write_doc(tmp_path, "law-transparency.json", a)
    f2 = write_doc(tmp_path, "angel-mythos.json", b)

    docs, prelim = asyncio.run(_load_docs(mod, [f1, f2]))
    assert len(prelim) == 0, f"Неожиданные предварительные ошибки: {prelim}"

    by_id, by_slug, graph = mod.build_indexes(docs)

    # Проверка индексов
    assert "LAW-TRANSPARENCY" in by_id
    assert "ANGEL-MYTHOS" in by_id
    assert "law-transparency" in by_slug
    assert "angel-mythos" in by_slug

    # Граф: закон -> ангел, ангел -> пусто
    k1 = docs[0].id or docs[0].slug
    k2 = docs[1].id or docs[1].slug
    assert k1 in graph and k2 in graph
    assert "ANGEL-MYTHOS" in graph[k1]
    assert len(graph[k2]) == 0


def test_rule_refs_exist_and_cycles(tmp_path: Path):
    mod = _load_validate_module()

    # Документы: A -> B, B -> A (цикл), C -> MISSING (разорванная ссылка)
    a = {"id": "A", "slug": "a", "type": "Concept", "title": "A", "version": "1.0.0", "status": "approved", "refs": ["B"]}
    b = {"id": "B", "slug": "b", "type": "Concept", "title": "B", "version": "1.0.0", "status": "approved", "refs": ["A"]}
    c = {"id": "C", "slug": "c", "type": "Concept", "title": "C", "version": "1.0.0", "status": "approved", "refs": ["MISSING"]}

    f1 = write_doc(tmp_path, "a.json", a)
    f2 = write_doc(tmp_path, "b.json", b)
    f3 = write_doc(tmp_path, "c.json", c)

    docs, prelim = asyncio.run(_load_docs(mod, [f1, f2, f3]))
    assert len(prelim) == 0

    by_id, by_slug, graph = mod.build_indexes(docs)
    ctx = mod.RuleContext(documents=docs, by_id=by_id, by_slug=by_slug, graph=graph)

    # Разорванные ссылки
    broken = mod.rule_refs_exist(ctx)
    assert any(i.rule_id == "CANON-003" and "MISSING" in i.message for i in broken)

    # Цикл
    cycles = mod.rule_cycles(ctx, max_cycle_report=10)
    assert any(i.rule_id == "CANON-004" for i in cycles)


def test_rule_filename_matches_slug_warn(tmp_path: Path):
    mod = _load_validate_module()

    d = {
        "id": "X",
        "slug": "alpha",
        "type": "Concept",
        "title": "Alpha Concept",
        "version": "1.2.3",
        "status": "review",
        "refs": []
    }
    # Нарочно неверное имя файла
    f = write_doc(tmp_path, "wrong.json", d)

    docs, _ = asyncio.run(_load_docs(mod, [f]))
    by_id, by_slug, graph = mod.build_indexes(docs)
    ctx = mod.RuleContext(documents=docs, by_id=by_id, by_slug=by_slug, graph=graph)

    issues = mod.rule_filename_matches_slug(ctx)
    assert any(i.rule_id == "CANON-005" and i.file.name == "wrong.json" for i in issues)


def test_unique_id_and_slug_rules(tmp_path: Path):
    mod = _load_validate_module()

    d1 = {"id": "DUP", "slug": "s1", "type": "Concept", "title": "One", "version": "0.1.0", "status": "draft", "refs": []}
    d2 = {"id": "DUP", "slug": "s2", "type": "Concept", "title": "Two", "version": "0.1.0", "status": "draft", "refs": []}
    d3 = {"id": "OK",  "slug": "s2", "type": "Concept", "title": "Three", "version": "0.1.0", "status": "draft", "refs": []}

    f1 = write_doc(tmp_path, "s1.json", d1)
    f2 = write_doc(tmp_path, "s2.json", d2)
    f3 = write_doc(tmp_path, "s2-dup.json", d3)

    docs, _ = asyncio.run(_load_docs(mod, [f1, f2, f3]))
    by_id, by_slug, graph = mod.build_indexes(docs)
    ctx = mod.RuleContext(documents=docs, by_id=by_id, by_slug=by_slug, graph=graph)

    dup_ids = mod.rule_unique_ids(ctx)
    dup_slugs = mod.rule_unique_slugs(ctx)

    assert any(i.rule_id == "CANON-001" and "Duplicate id 'DUP'" in i.message for i in dup_ids)
    assert any(i.rule_id == "CANON-002" and "Duplicate slug 's2'" in i.message for i in dup_slugs)


# ---------- Тесты CLI и форматов вывода ----------

def test_cli_json_output_and_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    mod = _load_validate_module()

    # Два валидных файла без integrity_hash -> будут WARN, но это не ошибка в нестрогом режиме
    a = {"id": "LAW-TRANSPARENCY", "slug": "law-transparency", "type": "Law", "title": "Law of Transparency", "version": "1.0.0", "status": "approved", "refs": []}
    b = {"id": "ANGEL-MYTHOS", "slug": "angel-mythos", "type": "Angel", "title": "Angel of Mythos", "version": "0.1.0", "status": "review", "refs": []}

    write_doc(tmp_path, "law-transparency.json", a)
    write_doc(tmp_path, "angel-mythos.json", b)

    # Нестрогий режим: ожидаем код 0
    code = mod.main([str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert code == 0, f"Ожидался код 0, получено {code}. stdout:\n{out}"

    payload = json.loads(out)
    assert "summary" in payload and "issues" in payload
    # В нестрогом режиме предупреждения остаются WARN
    warns = payload["summary"]["warnings"]
    errs = payload["summary"]["errors"]
    assert warns >= 1 and errs == 0

    # Строгий режим: WARN должны стать ERROR, код 2
    code_strict = mod.main([str(tmp_path), "--format", "json", "--strict"])
    out2 = capsys.readouterr().out
    assert code_strict == 2, f"Ожидался код 2 для --strict, получено {code_strict}. stdout:\n{out2}"

    payload2 = json.loads(out2)
    assert payload2["summary"]["errors"] >= 1
    assert payload2["summary"]["warnings"] == 0


def test_cli_text_output_contains_counts(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    mod = _load_validate_module()

    # Один документ со злонамеренно длинным title, чтобы спровоцировать WARN CANON-007
    long_title = "X" * 160
    d = {"id": "T", "slug": "t", "type": "Concept", "title": long_title, "version": "0.0.1", "status": "draft", "refs": []}
    write_doc(tmp_path, "t.json", d)

    code = mod.main([str(tmp_path), "--format", "text"])
    out = capsys.readouterr().out
    assert code in (0, 1, 2)  # код зависит от наличия WARN/ERROR
    assert "Issues: total=" in out
    # Убедимся, что конкретное правило присутствует
    assert "CANON-007" in out
