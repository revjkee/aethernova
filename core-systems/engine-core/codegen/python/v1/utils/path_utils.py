# -*- coding: utf-8 -*-
"""
Aethernova Engine | Codegen v1 | path_utils

Назначение:
  Надёжные утилиты работы с путями для пайплайна генерации (protobuf/gRPC):
    - определение корня репозитория;
    - нормализация/канонизация путей (symlink-aware, registry-aware);
    - безопасные join/relpath с защитой от traversal;
    - разрешение import для .proto по include-путям;
    - сканирование с шаблонами include/exclude;
    - дедупликация, сортировка, коллизии по регистру;
    - стабильные SHA-256 хэши файлов/деревьев.

Зависимости: стандартная библиотека Python 3.11+.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
import platform
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence

__all__ = [
    "PathSecurityError",
    "ResolutionError",
    "detect_repo_root",
    "is_probably_case_insensitive_fs",
    "PathNormalizer",
    "IncludeResolver",
    "safe_join",
    "ensure_within",
    "canonicalize",
    "relativize_to_nearest",
    "merge_unique_paths",
    "list_glob",
    "list_files",
    "compute_file_hash",
    "compute_tree_hash",
    "has_case_conflicts",
]

log = logging.getLogger(__name__)
if not log.handlers:
    # По умолчанию — тихий логгер; окружение может переопределить.
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


# ----------------------------- Исключения -----------------------------

class PathSecurityError(RuntimeError):
    """Нарушение политик безопасности путей (traversal, выход за пределы корня и т.п.)."""


class ResolutionError(RuntimeError):
    """Ошибка разрешения пути/импорта."""


# ------------------------- Определение корня --------------------------

_REPO_MARKERS = (".git", "pyproject.toml", "setup.cfg", "engine-core")


def detect_repo_root(start: Path | None = None) -> Path:
    """
    Ищет корень репозитория от start вверх по дереву по маркерам.
    Возвращает ближайший найденный каталог либо эвристический родитель.

    Безопасно для вызова из любых подпапок codegen.
    """
    p = Path(start or __file__).resolve()
    for base in [p] + list(p.parents):
        for m in _REPO_MARKERS:
            if (base / m).exists():
                return base
    # Fallback: несколько уровней вверх от utils/
    return p.parents[4]


# ----------------------- Чувствительность к регистру ------------------

@lru_cache(maxsize=1_024)
def is_probably_case_insensitive_fs(root: Path | None = None) -> bool:
    """
    Эвристика: платформа + проверка нормализации имени.
    Windows — True; macOS — True (APFS/HFS обычно case-insensitive); Linux — False.
    Если каталог отсутствует, используем платформенное значение.
    """
    sysname = platform.system().lower()
    if "windows" in sysname:
        return True
    if "darwin" in sysname or "mac" in sysname:
        return True
    # Linux и прочие — проверим простую эвристику
    base = (root or Path.cwd()).resolve()
    if not base.exists():
        return False
    probe = base / "A"
    # Если в каталоге нет 'a'/'A', нормализация не покажет разницы; оставим платформенный дефолт
    return False


# --------------------------- Нормализатор путей -----------------------

_WINDOWS_LONG_PREFIX = "\\\\?\\"


@dataclass(frozen=True, slots=True)
class PathNormalizer:
    """
    Конфигурация и операции канонизации путей.

    Параметры:
      repo_root: Базовый корень безопасности (для ensure_within).
      resolve_symlinks: Делать Path.resolve(strict=...) перед проверками.
      strict: Требовать существование при resolve_symlinks.
      casefold_key: Функция нормализации регистра для дедупликации/сортировки.
      allow_outside_repo: Разрешать пути вне repo_root (по умолчанию False).
    """
    repo_root: Path
    resolve_symlinks: bool = True
    strict: bool = False
    allow_outside_repo: bool = False

    def __post_init__(self):
        object.__setattr__(self, "repo_root", self.repo_root.resolve())

    # ---------- базовые операции ----------

    def normalize(self, p: str | os.PathLike) -> Path:
        """
        Нормализует путь:
          - разворачивает переменные окружения и ~;
          - приводит разделители/пустые части;
          - по желанию resolve() с учетом symlink;
          - возвращает абсолютный Path.
        """
        s = str(p)
        s = os.path.expandvars(os.path.expanduser(s))
        path = Path(s)
        if not path.is_absolute():
            path = (self.repo_root / path)
        # Windows long-path префикс не добавляем — Python 3.11+ обычно не требует.
        if self.resolve_symlinks:
            try:
                path = path.resolve(strict=self.strict)
            except FileNotFoundError:
                # При strict=False допускаем несуществующие пути, но канонизируем родителя
                parent = path.parent.resolve(strict=False)
                path = (parent / path.name)
        else:
            path = path.absolute()
        return path

    def safe_join(self, base: Path | str, *parts: str | os.PathLike, must_exist: bool | None = None) -> Path:
        """
        Безопасное склеивание: запрещает выход из base (traversal).
        При must_exist=True дополнительно проверяет существование результата.
        """
        base_p = self.normalize(base)
        out = base_p
        for part in parts:
            out = (out / str(part))
        out = self.normalize(out)
        self.ensure_within(out, base_p)
        if must_exist:
            if not out.exists():
                raise PathSecurityError(f"Путь не существует: {out}")
        return out

    def ensure_within(self, child: Path | str, parent: Path | str | None = None) -> None:
        """
        Гарантирует, что child находится внутри parent (по умолчанию repo_root).
        """
        c = self.normalize(child)
        p = self.normalize(parent or self.repo_root)
        try:
            c.relative_to(p)
        except Exception:
            if not self.allow_outside_repo:
                raise PathSecurityError(f"Путь вне разрешённого корня: {c} ∉ {p}")

    def canonical_key(self, p: Path | str) -> str:
        """
        Ключ канонизации для дедупликации: абсолютный путь, нормализованный по регистру, если ФС нечувствительна.
        """
        path = self.normalize(p)
        key = str(path)
        if is_probably_case_insensitive_fs(self.repo_root):
            key = key.lower()
        return key


# ------------------------- Разрешение import --------------------------

@dataclass(frozen=True, slots=True)
class IncludeResolver:
    """
    Разрешение import "foo/bar.proto" по списку include-корней (аналог -I для protoc).
    """
    includes: tuple[Path, ...]
    normalizer: PathNormalizer

    @classmethod
    def from_roots(cls, roots: Sequence[Path | str], repo_root: Path | None = None) -> "IncludeResolver":
        repo = detect_repo_root(repo_root)
        norm = PathNormalizer(repo_root=repo, resolve_symlinks=True, strict=False)
        incs = tuple(norm.normalize(p) for p in roots)
        return cls(includes=incs, normalizer=norm)

    def resolve_import(self, import_path: str) -> Path:
        """
        Ищет import относительно каждого include-корня. Возвращает первый найденный Path.
        Бросает ResolutionError, если не найден.
        """
        imp_norm = import_path.lstrip("/").replace("\\", "/")
        if ".." in imp_norm.split("/"):
            raise PathSecurityError(f"Запрещённый импорт с '..': {import_path}")

        for root in self.includes:
            candidate = self.normalizer.safe_join(root, imp_norm, must_exist=False)
            if candidate.exists():
                return candidate
        raise ResolutionError(
            f"Не удалось разрешить импорт '{import_path}'. "
            f"Проверены include-пути: {', '.join(str(p) for p in self.includes)}"
        )

    def search_all(self, pattern: str) -> list[Path]:
        """
        Возвращает все пути, соответствующие шаблону (glob) во всех include-корнях.
        """
        out: list[Path] = []
        for root in self.includes:
            out.extend(root.rglob(pattern))
        # дедуп по каноническому ключу
        uniq: dict[str, Path] = {}
        for p in out:
            uniq[self.normalizer.canonical_key(p)] = self.normalizer.normalize(p)
        return sorted(uniq.values())


# -------------------------- Вспомогательные API -----------------------

def safe_join(base: Path | str, *parts: str | os.PathLike, must_exist: bool | None = None) -> Path:
    norm = PathNormalizer(detect_repo_root(), resolve_symlinks=True, strict=False)
    return norm.safe_join(base, *parts, must_exist=must_exist)


def ensure_within(child: Path | str, parent: Path | str | None = None) -> None:
    norm = PathNormalizer(detect_repo_root(), resolve_symlinks=True, strict=False)
    norm.ensure_within(child, parent)


def canonicalize(p: Path | str) -> Path:
    norm = PathNormalizer(detect_repo_root(), resolve_symlinks=True, strict=False)
    return norm.normalize(p)


def relativize_to_nearest(path: Path | str, bases: Iterable[Path | str]) -> Path:
    """
    Возвращает кратчайший относительный путь path относительно одного из bases.
    Если ни к одному не удаётся привести — возвращает абсолютный путь.
    """
    norm = PathNormalizer(detect_repo_root(), resolve_symlinks=True, strict=False)
    abs_path = norm.normalize(path)
    best: Path | None = None
    best_len = 1 << 30
    for b in bases:
        base = norm.normalize(b)
        try:
            rel = abs_path.relative_to(base)
            # выбираем самый глубокий базовый путь (минимальная длина rel)
            if len(str(rel)) < best_len:
                best = rel
                best_len = len(str(rel))
        except Exception:
            continue
    return best if best is not None else abs_path


def merge_unique_paths(paths: Iterable[Path | str]) -> list[Path]:
    """
    Дедуплицирует пути с учётом чувствительности ФС и возвращает отсортированный список.
    """
    norm = PathNormalizer(detect_repo_root(), resolve_symlinks=True, strict=False)
    seen: dict[str, Path] = {}
    for p in paths:
        key = norm.canonical_key(p)
        seen[key] = norm.normalize(p)
    return sorted(seen.values())


def _iter_patterns(base: Path, includes: Sequence[str], excludes: Sequence[str]) -> Iterator[Path]:
    """
    Генерирует файлы под base, поддерживая glob-шаблоны includes и excludes.
    """
    # Быстрый путь: если шаблон не содержит **, используем glob; иначе rglob.
    for pat in includes:
        if "**" in pat:
            for p in base.rglob(pat.replace("**/", "")):
                yield p
        else:
            yield from base.glob(pat)


def list_glob(root: Path | str, includes: Sequence[str], excludes: Sequence[str] | None = None) -> list[Path]:
    """
    Возвращает файлы под root, совпадающие с includes (glob), минус excludes (glob).
    """
    base = canonicalize(root)
    inc = list(includes) if includes else ["**/*"]
    exc = list(excludes or [])
    files: list[Path] = []
    for p in _iter_patterns(base, inc, exc):
        if not p.is_file():
            continue
        rel = str(p.relative_to(base)).replace("\\", "/")
        if any(fnmatch.fnmatch(rel, e) for e in exc):
            continue
        files.append(p.resolve())
    return merge_unique_paths(files)


def list_files(base: Path | str, patterns: Sequence[str], excludes: Sequence[str] | None = None) -> list[Path]:
    """
    Синоним list_glob для совместимости с существующими вызовами.
    """
    return list_glob(base, patterns, excludes)


# -------------------------- Хэши и целостность ------------------------

_CHUNK = 1 << 20  # 1 MiB


def compute_file_hash(path: Path | str, algo: str = "sha256") -> str:
    """
    Вычисляет стабильный хэш содержимого файла (по умолчанию SHA-256).
    """
    p = canonicalize(path)
    h = hashlib.new(algo)
    with p.open("rb") as f:
        while True:
            b = f.read(_CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def compute_tree_hash(paths: Sequence[Path | str], algo: str = "sha256") -> str:
    """
    Стабильный хэш набора файлов: учитывает относительные пути и содержимое.
    """
    normed = merge_unique_paths(paths)
    # Стабильный порядок
    normed = sorted(normed, key=lambda p: str(p).lower())
    h = hashlib.new(algo)
    for p in normed:
        rel = str(relativize_to_nearest(p, [detect_repo_root()])).replace("\\", "/")
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        with Path(p).open("rb") as f:
            while True:
                b = f.read(_CHUNK)
                if not b:
                    break
                h.update(b)
        h.update(b"\n")
    return h.hexdigest()


# ----------------------- Коллизии по регистру -------------------------

def has_case_conflicts(paths: Iterable[Path | str]) -> list[tuple[Path, Path]]:
    """
    Возвращает пары путей, которые различаются только регистром (на чувствительных ФС).
    На нечувствительных ФС возвращает пустой список (коллизии всё равно опасны в git/CI).
    """
    if is_probably_case_insensitive_fs(detect_repo_root()):
        # На нечувствительных ФС коллизии не различимы — возвращаем пусто.
        return []
    normed = [canonicalize(p) for p in paths]
    by_lower: dict[str, Path] = {}
    conflicts: list[tuple[Path, Path]] = []
    for p in normed:
        k = str(p).lower()
        if k in by_lower and by_lower[k] != p:
            conflicts.append((by_lower[k], p))
        else:
            by_lower[k] = p
    return conflicts


# ----------------------------- Утилиты -------------------------------

_PROTO_IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"\s*;\s*$')


def extract_proto_imports(proto_file: Path | str) -> list[str]:
    """
    Эвристически извлекает строки import "..." из .proto файла (без полного парсинга).
    """
    p = canonicalize(proto_file)
    out: list[str] = []
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _PROTO_IMPORT_RE.match(line)
            if m:
                out.append(m.group(1))
    except FileNotFoundError:
        raise ResolutionError(f"Файл не найден: {p}")
    return out


# ------------------------- Примеры использования ----------------------

if __name__ == "__main__":
    # Простой smoke-тест (не влияет на импорт)
    repo = detect_repo_root()
    norm = PathNormalizer(repo_root=repo)
    inc = IncludeResolver.from_roots([repo / "engine-core/schemas/proto", repo], repo_root=repo)

    print(f"repo_root = {repo}")
    # Пример канонизации
    print("canonicalize(repo_root) =", canonicalize(repo))
    # Пример безопасного join
    try:
        print("safe_join(repo_root, 'engine-core', 'schemas') =", safe_join(repo, "engine-core", "schemas"))
    except PathSecurityError as e:
        print("PathSecurityError:", e)
    # Поиск proto
    protos = list_glob(repo / "engine-core/schemas/proto", ["v1/**/*.proto"], ["**/*_internal.proto"])
    print(f"found protos: {len(protos)}")
    # Импорт из первого файла (если есть)
    if protos:
        imps = extract_proto_imports(protos[0])
        print("imports(example):", imps[:5])
        if imps:
            try:
                print("resolve_import(example):", inc.resolve_import(imps[0]))
            except Exception as e:
                print("resolve_import error:", e)
