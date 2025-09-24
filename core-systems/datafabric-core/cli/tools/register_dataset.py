# datafabric-core/cli/tools/register_dataset.py
# -*- coding: utf-8 -*-
"""
DataFabric CLI — register-dataset

Назначение:
  Регистрация датасета в реестре DataFabric с вычислением контрольных
  хешей, подсчётом статистики и созданием версионированного манифеста.

Возможности:
- Источник: локальный каталог/файл или S3-префикс (через datafabric.io.file_io).
- Реестр: локальный путь или S3-префикс. Хранение:
    {registry}/datasets/{dataset_id}/{version}/manifest.json
    {registry}/index.json (глобальный индекс)
- Контроль целостности: дерево SHA-256 по файлам (stable order).
- Статистика: количество файлов, общий размер, список образцов.
- Автоопределение формата: csv/tsv/json/ndjson/parquet/* по расширению.
- Семантика версий: semver (major.minor.patch) с проверкой.
- Теги, провенанс (owner, source_url, commit, notes).
- Dry-run: вывод плана без записи.
- Лок: для локального реестра — файловая блокировка на время обновления индекса.
- Логирование и стабильные коды выхода.

Зависимости: стандартная библиотека + модуль проекта datafabric.io.file_io.
Опционально: PyYAML для YAML-вывода (--out-format yaml).

Коды выхода:
  0 — успех
  2 — неверные аргументы/валидация
  3 — датасет уже существует и --overwrite не задан
  4 — ошибки ввода-вывода/бэкенда
  5 — ошибки целостности/хешей
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import io
import json
import logging
import os
import pathlib
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Опциональный YAML
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# Внутренний модуль проекта
try:
    from datafabric.io.file_io import (
        FileIO,
        make_backend,
        LocalBackend,
        S3Backend,
        AlreadyExistsError,
        FileIOError,
        IntegrityError,
        BackendUnavailableError,
        detect_compression,
    )
except Exception as e:
    print("FATAL: cannot import datafabric.io.file_io: %s" % e, file=sys.stderr)
    sys.exit(4)

LOG = logging.getLogger("datafabric.cli.register_dataset")


# ---------------------------- Утилиты ----------------------------

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[+-].*)?$")


def now_utc_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def infer_format(name: str) -> str:
    n = name.lower()
    if n.endswith(".parquet"):
        return "parquet"
    if n.endswith(".csv.gz") or n.endswith(".csv"):
        return "csv"
    if n.endswith(".tsv") or n.endswith(".tsv.gz"):
        return "tsv"
    if n.endswith(".ndjson") or n.endswith(".jsonl"):
        return "ndjson"
    if n.endswith(".json"):
        return "json"
    if n.endswith(".txt") or n.endswith(".log"):
        return "text"
    return "binary"


def stable_walk(fileio: FileIO, src_path: str) -> List[str]:
    """
    Возвращает стабильно отсортированный список файлов для регистрации.
    Для S3 — listdir по префиксу; для локального — рекурсивный обход.
    """
    be = fileio.backend
    out: List[str] = []
    if isinstance(be, LocalBackend):
        base = be._resolve(src_path)  # type: ignore
        if base.is_dir():
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    # вернуть путь относительно корня источника
                    rel = str(p.relative_to(base)).replace("\\", "/")
                    out.append(rel)
        elif base.is_file():
            out.append(base.name)
        else:
            raise FileIOError(f"Источник не найден: {base}")
    else:
        # Обход S3 префикса плоско, затем фильтр "файлов"
        items = be.listdir(src_path)  # type: ignore
        # элементы вида "/prefix/dir/" и "/prefix/file.ext"
        for key in items:
            if key.endswith("/"):
                continue
            # нормализуем к относительному
            # src_path может быть "prefix" или "a/b", убираем префикс
            rel = key.lstrip("/")
            if src_path.strip("/"):
                pref = src_path.strip("/") + "/"
                if rel.startswith(pref):
                    rel = rel[len(pref):]
            out.append(rel)
        out.sort()
    return out


def read_file_bytes(fileio: FileIO, base: str, rel: str, chunk: int = 8 * 1024 * 1024) -> Iterable[bytes]:
    # Открываем по комбинации base + rel
    path = f"{base.rstrip('/')}/{rel}"
    with fileio.open(path, "rb") as fp:
        while True:
            buf = fp.read(chunk)
            if not buf:
                break
            yield buf


def tree_sha256(fileio: FileIO, base: str, rel_files: List[str]) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    """
    Вычисляет общий хеш по дереву файлов:
      H = sha256( concat( sha256(file_i) + b' ' + size_i + b' ' + relpath_i + b'\n' ) )
    Возвращает hex и карту метаданных по файлам.
    """
    meta: Dict[str, Dict[str, Any]] = {}
    hasher = hashlib.sha256()
    for rel in rel_files:
        fh = hashlib.sha256()
        total = 0
        for chunk in read_file_bytes(fileio, base, rel):
            fh.update(chunk)
            total += len(chunk)
        fhex = fh.hexdigest()
        line = f"{fhex} {total} {rel}\n".encode("utf-8")
        hasher.update(line)
        meta[rel] = {
            "sha256": fhex,
            "size": total,
            "format": infer_format(rel),
            "compression": detect_compression(rel),
        }
    return hasher.hexdigest(), meta


def is_local_backend(fileio: FileIO) -> bool:
    return isinstance(fileio.backend, LocalBackend)


# ---------------------------- Лок файл ----------------------------

class FileLock:
    """
    Простая файловая блокировка для локального FS (директория-замок).
    Для S3 блокировка не поддерживается (best-effort без lock).
    """
    def __init__(self, lock_dir: pathlib.Path, poll_interval: float = 0.2, timeout: float = 60.0):
        self.lock_dir = lock_dir
        self.poll_interval = poll_interval
        self.timeout = timeout

    def acquire(self) -> None:
        start = time.time()
        while True:
            try:
                os.mkdir(self.lock_dir)
                return
            except FileExistsError:
                if time.time() - start > self.timeout:
                    raise FileIOError(f"Lock timeout: {self.lock_dir}")
                time.sleep(self.poll_interval)

    def release(self) -> None:
        try:
            os.rmdir(self.lock_dir)
        except FileNotFoundError:
            pass


# ---------------------------- Модель манифеста ----------------------------

@dataclasses.dataclass
class DatasetManifest:
    dataset_id: str
    version: str
    created_at: str
    source_url: str
    registry_url: str
    owner: Optional[str]
    tags: List[str]
    notes: Optional[str]
    commit: Optional[str]
    files: Dict[str, Dict[str, Any]]
    total_files: int
    total_size: int
    tree_sha256: str
    sample: List[str]
    format_summary: Dict[str, int]
    extras: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------- Основная логика ----------------------------

def register_dataset(
    source_url: str,
    registry_url: str,
    dataset_id: str,
    version: str,
    *,
    owner: Optional[str],
    tags: List[str],
    notes: Optional[str],
    commit: Optional[str],
    sample_size: int,
    dry_run: bool,
    overwrite: bool,
    out_format: str,
) -> Dict[str, Any]:
    # Валидируем семантику версии
    if not SEMVER_RE.match(version):
        raise SystemExit(2)

    # Подготавливаем IO
    src_io = FileIO(backend=make_backend(source_url))
    reg_io = FileIO(backend=make_backend(registry_url))

    # Сканирование списка файлов
    rel_files = stable_walk(src_io, source_url)
    if not rel_files:
        LOG.error("Источник пуст: %s", source_url)
        raise SystemExit(2)

    # Хеш-дерево и карта файлов
    tree_hash, meta = tree_sha256(src_io, source_url, rel_files)
    total_size = sum(m["size"] for m in meta.values())

    # Сэмплы
    sample = rel_files[: max(0, sample_size)]
    fmt_summary: Dict[str, int] = {}
    for m in meta.values():
        fmt_summary[m["format"]] = fmt_summary.get(m["format"], 0) + 1

    manifest = DatasetManifest(
        dataset_id=dataset_id,
        version=version,
        created_at=now_utc_iso(),
        source_url=source_url,
        registry_url=registry_url,
        owner=owner,
        tags=sorted(set(tags)),
        notes=notes,
        commit=commit,
        files=meta,
        total_files=len(rel_files),
        total_size=total_size,
        tree_sha256=tree_hash,
        sample=sample,
        format_summary=dict(sorted(fmt_summary.items(), key=lambda x: (-x[1], x[0]))),
        extras={},
    )

    # Пути в реестре
    dataset_root = f"{registry_url.rstrip('/')}/datasets/{dataset_id}/{version}"
    manifest_path = f"{dataset_root}/manifest.json"
    index_path = f"{registry_url.rstrip('/')}/index.json"

    LOG.info("Готов к регистрации: dataset_id=%s version=%s files=%d size=%d",
             dataset_id, version, manifest.total_files, manifest.total_size)

    if dry_run:
        return _output_manifest(manifest, out_format, dry_run=True)

    # Проверка существования
    exists_manifest = reg_io.exists(manifest_path)
    if exists_manifest and not overwrite:
        LOG.error("Манифест уже существует: %s (используйте --overwrite)", manifest_path)
        raise SystemExit(3)

    # Запись манифеста (атомарно на локальном FS)
    try:
        payload = json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
        reg_io.write_bytes(manifest_path, payload, overwrite=True)
    except (AlreadyExistsError, FileIOError) as e:
        LOG.error("Ошибка записи манифеста: %s", e)
        raise SystemExit(4)

    # Обновление индекса
    try:
        _update_index(reg_io, index_path, manifest, lock_enabled=is_local_backend(reg_io))
    except FileIOError as e:
        LOG.error("Ошибка обновления индекса: %s", e)
        raise SystemExit(4)
    except IntegrityError as e:
        LOG.error("Ошибка целостности индекса: %s", e)
        raise SystemExit(5)

    return _output_manifest(manifest, out_format, dry_run=False)


def _update_index(reg_io: FileIO, index_path: str, mf: DatasetManifest, lock_enabled: bool) -> None:
    """
    Индекс — JSON объект:
      {
        "datasets": {
           "{dataset_id}": {
               "latest": "x.y.z",
               "versions": {
                   "x.y.z": {
                      "created_at": "...",
                      "manifest_path": "...",
                      "tree_sha256": "...",
                      "total_files": N,
                      "total_size": B,
                      "tags": [...],
                      "owner": "...",
                   }, ...
               }
           }, ...
        }
      }
    """
    existing: Dict[str, Any] = {"datasets": {}}
    if reg_io.exists(index_path):
        try:
            existing = json.loads(reg_io.read_text(index_path))
            if not isinstance(existing, dict) or "datasets" not in existing:
                raise IntegrityError("Формат index.json повреждён")
        except Exception as e:
            raise FileIOError(f"Невозможно прочитать индекс: {e}") from e

    # Модифицируем
    ds = existing.setdefault("datasets", {}).setdefault(mf.dataset_id, {"latest": mf.version, "versions": {}})
    ds["versions"][mf.version] = {
        "created_at": mf.created_at,
        "manifest_path": f"{mf.registry_url.rstrip('/')}/datasets/{mf.dataset_id}/{mf.version}/manifest.json",
        "tree_sha256": mf.tree_sha256,
        "total_files": mf.total_files,
        "total_size": mf.total_size,
        "tags": mf.tags,
        "owner": mf.owner,
    }
    # latest — по максимальной semver (простая лексикографическая с доп. разбором)
    ds["latest"] = _max_semver(list(ds["versions"].keys()))

    payload = json.dumps(existing, ensure_ascii=False, indent=2)

    # Лок только для локального FS
    if lock_enabled:
        assert isinstance(reg_io.backend, LocalBackend)
        idx_path = reg_io.backend._resolve(index_path)  # type: ignore
        lock_dir = idx_path.parent / ".lock-index"
        lock = FileLock(lock_dir)
        lock.acquire()
        try:
            reg_io.write_text(index_path, payload, overwrite=True)
        finally:
            lock.release()
    else:
        # Для S3 — без лока, просто перезапись
        reg_io.write_text(index_path, payload, overwrite=True)


def _max_semver(versions: List[str]) -> str:
    def parse(v: str) -> Tuple[int, int, int, str]:
        m = SEMVER_RE.match(v)
        if not m:
            return (0, 0, 0, v)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), v)
    return sorted(versions, key=parse)[-1]


def _output_manifest(mf: DatasetManifest, out_format: str, dry_run: bool) -> Dict[str, Any]:
    data = mf.to_dict()
    data["_dry_run"] = dry_run
    if out_format == "json":
        txt = json.dumps(data, ensure_ascii=False, indent=2)
        print(txt)
    elif out_format == "yaml":
        if not _HAS_YAML:
            raise SystemExit(2)
        print(yaml.safe_dump(data, sort_keys=False))  # type: ignore
    else:
        raise SystemExit(2)
    return data


# ---------------------------- CLI ----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="register-dataset",
        description="Регистрация датасета в реестре DataFabric",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--source-url", required=True, help="Источник датасета: file:///path/to/dir или s3://bucket/prefix")
    p.add_argument("--registry-url", required=True, help="Реестр: file:///path/to/registry или s3://bucket/registry")
    p.add_argument("--dataset-id", required=True, help="Уникальный идентификатор датасета (kebab_case)")
    p.add_argument("--version", required=True, help="Semver версия датасета, напр. 1.0.0")
    p.add_argument("--owner", default=None, help="Владелец/команда")
    p.add_argument("--tags", default="", help="Список тегов через запятую")
    p.add_argument("--notes", default=None, help="Заметки/описание")
    p.add_argument("--commit", default=None, help="Commit/ревизия исходного репо")
    p.add_argument("--sample-size", type=int, default=10, help="Количество файлов в выборке манифеста")
    p.add_argument("--out-format", choices=["json", "yaml"], default="json", help="Формат вывода результата")
    p.add_argument("--overwrite", action="store_true", help="Перезаписывать существующий манифест версии")
    p.add_argument("--dry-run", action="store_true", help="Только рассчитать и вывести манифест, без записи")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Уровень логирования")
    return p


def configure_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        h = logging.StreamHandler(stream=sys.stderr)
        fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        h.setFormatter(fmt)
        root.addHandler(h)
    root.setLevel(lvl)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)

    tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    try:
        register_dataset(
            source_url=args.source_url,
            registry_url=args.registry_url,
            dataset_id=args.dataset_id,
            version=args.version,
            owner=args.owner,
            tags=tags,
            notes=args.notes,
            commit=args.commit,
            sample_size=args.sample_size,
            dry_run=args.dry_run,
            overwrite=args.overwrite,
            out_format=args.out_format,
        )
        return 0
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 2
    except BackendUnavailableError as e:
        LOG.error("Недоступен бэкенд: %s", e)
        return 4
    except FileIOError as e:
        LOG.error("Ошибка ввода-вывода: %s", e)
        return 4
    except Exception as e:
        LOG.exception("Необработанная ошибка: %s", e)
        return 4


if __name__ == "__main__":
    sys.exit(main())
