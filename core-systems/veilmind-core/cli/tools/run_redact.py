#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Veilmind Redaction CLI
======================

Назначение:
  Массовое безопасное редактирование (redaction) входных текстов и файлов с использованием
  veilmind.prompt_guard.sanitizer.PromptSanitizer. Выводит отредактированный контент и/или
  структурированный отчёт о находках.

Возможности:
  - Источники: stdin, список файлов, рекурсивные каталоги с include/exclude шаблонами.
  - Авто‑детект текста (быстрый) и безопасное декодирование (UTF‑8 с fallback).
  - JSON/JSONL обработка (по указанному полю; по умолчанию — целая строка).
  - Параллельная обработка (thread pool), упорядоченный вывод отчётов.
  - Режимы записи: stdout | in‑place | --out-dir | суффикс ".redacted".
  - JSON‑отчёт: на stdout или --report <path>.
  - Коды возврата: управляются --fail-on {never,review,deny}.
  - Настройки через YAML/JSON конфиг PromptSanitizer (см. configs/prompt_guard.yaml).
  - Логи: лаконичные INFO/ERROR, опция --verbose.

Зависимости: стандартная библиотека Python. Опционально PyYAML для YAML‑конфига.

Примеры:
  echo "user: alice, email alice@example.com" | run_redact.py --stdin
  run_redact.py data/*.txt --write stdout --config configs/prompt_guard.yaml
  run_redact.py ./docs --recursive --include '*.md' --exclude 'build/*' --out-dir ./redacted
  run_redact.py logs.jsonl --jsonl --json-field message --report report.json --threads 8
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import io
import json
import os
import sys
import fnmatch
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Опциональная зависимость для YAML
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# Внутренние зависимости veilmind
try:
    from veilmind.prompt_guard.sanitizer import PromptSanitizer, SanitizationResult
except Exception as e:
    print("FATAL: cannot import veilmind.prompt_guard.sanitizer. Ensure PYTHONPATH is set.", file=sys.stderr)
    raise

# --------------------------- Логирование ---------------------------

log = logging.getLogger("veilmind.cli.run_redact")

def setup_logging(verbose: bool) -> None:
    h = logging.StreamHandler(sys.stderr)
    fmt = "%(levelname)s %(message)s" if not verbose else "%(levelname)s [%(name)s] %(message)s"
    h.setFormatter(logging.Formatter(fmt))
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    logging.getLogger().handlers[:] = [h]
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)

# --------------------------- Утилиты ввода/вывода ---------------------------

TEXT_MAX_SNIFF = 4096
BINARY_BLACKLIST_BYTES = {0x00}

def is_probably_text(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(TEXT_MAX_SNIFF)
        if not chunk:
            return True
        if any(b in BINARY_BLACKLIST_BYTES for b in chunk):
            return False
        # Быстрая попытка UTF‑8
        try:
            chunk.decode("utf-8")
            return True
        except UnicodeDecodeError:
            # Допускаем, что это текст в legacy‑кодировке — разрешим, декодируем с заменами
            return True
    except Exception:
        return False

def read_text_safely(path: Path) -> str:
    with path.open("rb") as f:
        data = f.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Замена нерешаемых символов безопасным маркером U+FFFD
        return data.decode("utf-8", errors="replace")

def write_text_safely(path: Path, text: str) -> None:
    # Записываем в UTF‑8 (BOM не используем), атомарно по возможности
    tmp = path.with_suffix(path.suffix + ".tmp_redact")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        f.write(text)
    tmp.replace(path)

# --------------------------- Загрузка конфига ---------------------------

def load_sanitizer(config_path: Optional[Path]) -> PromptSanitizer:
    if not config_path:
        # Конструктор с дефолтами
        return PromptSanitizer.from_dict({})
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    suffix = config_path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not _HAS_YAML:
            raise RuntimeError("PyYAML not installed; install or use JSON config")
        return PromptSanitizer.from_yaml(str(config_path))
    # Поддержка JSON
    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return PromptSanitizer.from_dict(data)

# --------------------------- Обработка единицы работы ---------------------------

@dataclass
class WorkItem:
    source: str          # "stdin" | "file"
    path: Optional[Path] # для файла
    text: str            # исходный текст (для stdin/JSONL итераций)
    jsonl_index: Optional[int] = None
    jsonl_field: Optional[str] = None

@dataclass
class WorkResult:
    ok: bool
    decision: str
    risk: float
    redacted_text: str
    findings: List[Dict[str, Any]]
    metrics: List[Dict[str, Any]]
    reason_codes: List[str]
    source: str
    path: Optional[str]
    jsonl_index: Optional[int]
    error: Optional[str] = None

def sanitize_text(sanitizer: PromptSanitizer, text: str) -> SanitizationResult:
    # Обрабатываем как input (вход пользователя). Для фильтрации ответов используйте sanitize_output.
    return sanitizer.sanitize_input(text)

def process_item(sanitizer: PromptSanitizer, item: WorkItem) -> WorkResult:
    try:
        res = sanitize_text(sanitizer, item.text)
        return WorkResult(
            ok=True,
            decision=res.decision,
            risk=float(res.risk),
            redacted_text=res.sanitized_text,
            findings=[asdict(f) for f in res.findings],
            metrics=[asdict(m) for m in res.metrics],
            reason_codes=list(res.reason_codes),
            source=item.source,
            path=str(item.path) if item.path else None,
            jsonl_index=item.jsonl_index,
        )
    except Exception as e:
        return WorkResult(
            ok=False,
            decision="error",
            risk=1.0,
            redacted_text="",
            findings=[],
            metrics=[],
            reason_codes=["error"],
            source=item.source,
            path=str(item.path) if item.path else None,
            jsonl_index=item.jsonl_index,
            error=str(e),
        )

# --------------------------- Сбор входа ---------------------------

def iter_files(
    roots: List[Path],
    recursive: bool,
    include: List[str],
    exclude: List[str],
) -> Iterable[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        if not root.exists():
            log.warning("skip missing path: %s", root)
            continue
        if not recursive:
            for p in root.iterdir():
                if p.is_file() and _match(p, include, exclude):
                    yield p
        else:
            for p in root.rglob("*"):
                if p.is_file() and _match(p, include, exclude):
                    yield p

def _match(path: Path, include: List[str], exclude: List[str]) -> bool:
    s = str(path)
    if exclude and any(fnmatch.fnmatch(s, pat) for pat in exclude):
        return False
    if include:
        return any(fnmatch.fnmatch(s, pat) for pat in include)
    return True

# --------------------------- JSON/JSONL ---------------------------

def process_json_text(text: str, field: Optional[str]) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    """
    Если field указан — возвращаем значение этого поля (str) и исходный объект/ключ.
    Если field не указан — целиком сериализуем обратно (не изменяя структуру).
    """
    obj = json.loads(text)
    if field:
        val = obj.get(field)
        if not isinstance(val, str):
            raise ValueError(f"json field '{field}' is not a string or missing")
        return val, obj, field
    # Если поле не указано, рассматриваем весь json как текст (как есть)
    return json.dumps(obj, ensure_ascii=False), obj, None

def apply_json_result(obj: Dict[str, Any], field: Optional[str], new_text: str) -> str:
    if field:
        obj[field] = new_text
        return json.dumps(obj, ensure_ascii=False)
    # Если нет поля — возвращаем отредактированную строку как единственное поле "text"
    return new_text

# --------------------------- Основная функция ---------------------------

EXIT_OK = 0
EXIT_REVIEW = 10
EXIT_DENY = 20
EXIT_ERROR = 2

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="run_redact.py", description="Veilmind redaction tool")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--stdin", action="store_true", help="читать текст из stdin")
    ap.add_argument("paths", nargs="*", help="файлы/каталоги для обработки")
    ap.add_argument("--recursive", action="store_true", help="рекурсивный обход каталогов")
    ap.add_argument("--include", action="append", default=[], help="глоб‑шаблоны включения (можно несколько)")
    ap.add_argument("--exclude", action="append", default=[], help="глоб‑шаблоны исключения (можно несколько)")

    # JSON/JSONL
    ap.add_argument("--json", action="store_true", help="вход — JSON; редактировать указанное поле или весь объект")
    ap.add_argument("--jsonl", action="store_true", help="вход — JSON Lines; редактировать указанное поле или строку")
    ap.add_argument("--json-field", default=None, help="имя поля со строкой (для --json/--jsonl)")

    # Конфиг и режимы
    ap.add_argument("--config", type=Path, default=None, help="путь к конфигу sanitizer (YAML/JSON)")
    ap.add_argument("--threads", type=int, default=os.cpu_count() or 4, help="число потоков обработки")

    # Запись результата
    ap.add_argument("--write", choices=["stdout", "inplace", "suffix"], default="suffix",
                    help="куда писать отредактированный текст для файлов")
    ap.add_argument("--out-dir", type=Path, default=None, help="каталог для вывода (игнорируется, если --write=stdout|inplace)")
    ap.add_argument("--suffix", default=".redacted", help="суффикс для --write=suffix (по умолчанию .redacted)")
    ap.add_argument("--report", type=Path, default=None, help="путь для JSON‑отчёта (по умолчанию stdout)")

    # Политика выхода
    ap.add_argument("--fail-on", choices=["never", "review", "deny"], default="deny",
                    help="повышать код возврата при наличии review/deny")
    ap.add_argument("--verbose", action="store_true", help="подробные логи")

    args = ap.parse_args(argv)
    setup_logging(args.verbose)

    # Инициализируем sanitizer
    try:
        sanitizer = load_sanitizer(args.config)
    except Exception as e:
        log.error("cannot load config: %s", e)
        return EXIT_ERROR

    # Сбор входа
    work_items: List[WorkItem] = []
    is_stdin = args.stdin or (not args.paths)
    if is_stdin:
        # stdin (один блок текста или JSON/JSONL поток)
        data = sys.stdin.read()
        if args.jsonl:
            lines = data.splitlines()
            for idx, line in enumerate(lines):
                if not line.strip():
                    continue
                try:
                    if args.json:
                        text, obj, fld = process_json_text(line, args.json_field)
                    else:
                        # если указан --jsonl без --json, обрабатываем строку как текст
                        text, obj, fld = line, None, None
                except Exception as e:
                    log.error("jsonl parse error at line %d: %s", idx + 1, e)
                    return EXIT_ERROR
                work_items.append(WorkItem(source="stdin", path=None, text=text, jsonl_index=idx, jsonl_field=fld))
        elif args.json:
            try:
                text, obj, fld = process_json_text(data, args.json_field)
            except Exception as e:
                log.error("json parse error: %s", e)
                return EXIT_ERROR
            work_items.append(WorkItem(source="stdin", path=None, text=text, jsonl_index=None, jsonl_field=fld))
        else:
            work_items.append(WorkItem(source="stdin", path=None, text=data))
    else:
        # файлы/каталоги
        roots = [Path(p) for p in args.paths]
        files = [p for p in iter_files(roots, args.recursive, args.include, args.exclude)]
        if not files:
            log.warning("no files matched")
        for p in files:
            if not is_probably_text(p):
                log.info("skip non-text file: %s", p)
                continue
            try:
                if args.json or args.jsonl:
                    # При обработке файлов JSON/JSONL читаем построчно для JSONL, иначе целиком
                    if args.jsonl:
                        with p.open("r", encoding="utf-8", errors="replace", newline="") as f:
                            for idx, line in enumerate(f):
                                line = line.rstrip("\n")
                                if not line:
                                    continue
                                if args.json:
                                    text, obj, fld = process_json_text(line, args.json_field)
                                else:
                                    text, obj, fld = line, None, None
                                work_items.append(WorkItem(source="file", path=p, text=text, jsonl_index=idx, jsonl_field=fld))
                    else:
                        data = read_text_safely(p)
                        text, obj, fld = process_json_text(data, args.json_field)
                        work_items.append(WorkItem(source="file", path=p, text=text, jsonl_index=None, jsonl_field=fld))
                else:
                    data = read_text_safely(p)
                    work_items.append(WorkItem(source="file", path=p, text=data))
            except Exception as e:
                log.error("skip %s: %s", p, e)

    # Параллельная обработка
    results: List[WorkResult] = []
    with cf.ThreadPoolExecutor(max_workers=max(1, int(args.threads))) as pool:
        futs = [pool.submit(process_item, sanitizer, item) for item in work_items]
        for fut in cf.as_completed(futs):
            results.append(fut.result())

    # Стабильный порядок результатов (по источнику/пути/индексу)
    def sort_key(r: WorkResult) -> Tuple[int, str, int]:
        src_order = 0 if r.source == "stdin" else 1
        path = r.path or ""
        idx = r.jsonl_index or -1
        return (src_order, path, idx)
    results.sort(key=sort_key)

    # Запись результатов
    exit_code = EXIT_OK
    aggregated_report: List[Dict[str, Any]] = []

    for r in results:
        # Отредактированный текст
        if r.source == "stdin":
            # stdout всегда; не смешиваем с отчётом — отчёт ниже в JSON
            if args.write in ("stdout", "suffix") and not args.report:
                # Если --report направлен в файл, можно печатать отредактированный текст в stdout.
                sys.stdout.write(r.redacted_text)
                if args.jsonl and r.jsonl_index is not None:
                    sys.stdout.write("\n")
        else:
            # файл
            path = Path(r.path) if r.path else None
            if path:
                if args.write == "stdout":
                    sys.stdout.write(f"----- {path} -----\n")
                    sys.stdout.write(r.redacted_text)
                    sys.stdout.write("\n")
                elif args.write == "inplace":
                    write_text_safely(path, r.redacted_text)
                else:  # suffix
                    if args.out_dir:
                        out_path = args.out_dir.joinpath(Path(*path.parts)).with_suffix(path.suffix + args.suffix)
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                    else:
                        out_path = path.with_suffix(path.suffix + args.suffix)
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    write_text_safely(out_path, r.redacted_text)

        # Агрегируем отчёт
        aggregated_report.append({
            "source": r.source,
            "path": r.path,
            "jsonl_index": r.jsonl_index,
            "decision": r.decision,
            "risk": r.risk,
            "reason_codes": r.reason_codes,
            "findings": r.findings,
            "metrics": r.metrics,
            "error": r.error,
        })

        # Коды возврата
        if r.decision == "deny":
            if args.fail_on in ("deny",):
                exit_code = max(exit_code, EXIT_DENY)
        elif r.decision == "review":
            if args.fail_on in ("review",):
                exit_code = max(exit_code, EXIT_REVIEW)
        elif r.decision == "error":
            exit_code = max(exit_code, EXIT_ERROR)

    # Вывод отчёта
    report_json = json.dumps({"items": aggregated_report}, ensure_ascii=False, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("w", encoding="utf-8") as f:
            f.write(report_json)
        log.info("report written to %s", args.report)
    else:
        # Если stdin и писали редактированный текст в stdout, не мешаем отчёт.
        # В таком случае логичнее направить отчёт в stderr.
        if is_stdin and args.write in ("stdout", "suffix"):
            print(report_json, file=sys.stderr)
        else:
            print(report_json)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
