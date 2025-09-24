# SPDX-License-Identifier: MIT
"""
Промышленный набор утилит для безопасной работы с файловой системой.

Ключевые возможности:
- Атомарная запись текстовых и бинарных файлов (tempfile в той же директории + os.replace).
- Явная принудительная запись на диск (fsync файла и каталога — где поддерживается).
- Чтение/запись JSON с атомарностью и предсказуемой кодировкой.
- Кроссплатформенный файловый лок (Unix fcntl / Windows msvcrt) с таймаутом и контекстным менеджером.
- Вычисление хэшей (SHA-256 по умолчанию) и коротких отпечатков.
- Рекурсивный поиск файлов по маскам (glob), игнорирование скрытых по желанию.
- Безопасные операции: проверка вхождения пути в базовый каталог (защита от traversal),
  «мягкое» удаление дерева с обработкой ошибок, уникальные имена.
- Копирование с опцией сохранения метаданных, управляемым overwrite.

Зависимости: только стандартная библиотека Python 3.11+.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Literal, Sequence

# Опциональные импорты для локов (платформенно-зависимые)
try:  # Unix-подобные
    import fcntl  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

try:  # Windows
    import msvcrt  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]

__all__ = [
    "FileError",
    "FileLockError",
    "ensure_dir",
    "assert_within_base",
    "read_text",
    "write_text_atomic",
    "read_bytes",
    "write_bytes_atomic",
    "read_json",
    "write_json_atomic",
    "hash_file",
    "short_hash",
    "copy_file",
    "list_files",
    "remove_tree_safe",
    "unique_name",
    "cwd",
    "FileLock",
]


# =========================
# Исключения
# =========================
class FileError(Exception):
    """Базовая ошибка файловых операций."""


class FileLockError(FileError):
    """Ошибка файлового лока (невозможно захватить/освободить)."""


# =========================
# Вспомогательные функции
# =========================
def _to_path(p: os.PathLike[str] | str) -> Path:
    return p if isinstance(p, Path) else Path(p)


def ensure_dir(p: os.PathLike[str] | str, mode: int = 0o755) -> Path:
    """Создать каталог (включая родителей), если отсутствует. Вернуть Path."""
    path = _to_path(p)
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    return path


def assert_within_base(base: os.PathLike[str] | str, target: os.PathLike[str] | str) -> None:
    """
    Гарантирует, что target лежит внутри base (предотвращение path traversal).
    Бросает FileError при нарушении.
    """
    b = _to_path(base).resolve()
    t = _to_path(target).resolve()
    if b == t:
        return
    try:
        t.relative_to(b)
    except Exception as exc:
        raise FileError(f"Path {t} is outside base {b}") from exc


# =========================
# Чтение/запись файлов
# =========================
def read_text(path: os.PathLike[str] | str, encoding: str = "utf-8") -> str:
    """Прочитать файл как строку (utf-8 по умолчанию)."""
    p = _to_path(path)
    return p.read_text(encoding=encoding)


def read_bytes(path: os.PathLike[str] | str) -> bytes:
    """Прочитать файл как bytes."""
    return _to_path(path).read_bytes()


def _fsync_dir(dir_path: Path) -> None:
    """Принудительно записать метаданные каталога на диск, если поддерживается."""
    with contextlib.suppress(Exception):
        if hasattr(os, "O_RDONLY"):
            fd = os.open(dir_path, os.O_RDONLY)
            try:
                os.fsync(fd)  # type: ignore[arg-type]
            finally:
                os.close(fd)


def _atomic_write_core(
    path: Path,
    data: bytes,
    *,
    perms: int | None,
) -> None:
    """
    Записать байты атомарно:
      1) временный файл в той же директории;
      2) flush + fsync файла;
      3) os.replace(tmp, path);
      4) fsync каталога (где возможно).
    """
    parent = path.parent
    ensure_dir(parent)

    # Создаем временный файл рядом с целевым
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        if perms is not None:
            with contextlib.suppress(Exception):
                os.chmod(tmp_path, perms)

        # Атомарная замена
        os.replace(tmp_path, path)

        # Синхронизируем каталог
        _fsync_dir(parent)
    except Exception:
        # Гарантированно пытаемся удалить временный файл
        with contextlib.suppress(Exception):
            tmp_path.unlink(missing_ok=True)
        raise


def write_text_atomic(
    path: os.PathLike[str] | str,
    text: str,
    *,
    encoding: str = "utf-8",
    newline: str | None = "\n",
    perms: int | None = 0o644,
) -> None:
    """
    Атомарно записать текстовый файл.
    newline=None — использовать системное значение; по умолчанию '\\n' для детерминизма.
    """
    p = _to_path(path)
    # Кодируем в память, чтобы избежать частичной записи в temp
    with io.StringIO() as buf:
        print(text, end="", file=buf)  # не добавляем перевод строки автоматически
        data = buf.getvalue().replace("\r\n", "\n") if newline == "\n" else buf.getvalue()
    if newline is None:
        data_bytes = data.encode(encoding)
    else:
        # Явно нормализуем переводы строк
        normalized = data.replace("\r\n", "\n").replace("\r", "\n")
        normalized = normalized.replace("\n", newline)
        data_bytes = normalized.encode(encoding)
    _atomic_write_core(p, data_bytes, perms=perms)


def write_bytes_atomic(path: os.PathLike[str] | str, data: bytes, *, perms: int | None = 0o644) -> None:
    """Атомарно записать бинарный файл."""
    _atomic_write_core(_to_path(path), data, perms=perms)


def read_json(path: os.PathLike[str] | str, *, encoding: str = "utf-8") -> Any:
    """Прочитать JSON (utf-8)."""
    raw = read_text(path, encoding=encoding)
    return json.loads(raw)


def write_json_atomic(
    path: os.PathLike[str] | str,
    payload: Any,
    *,
    encoding: str = "utf-8",
    indent: int = 2,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
    perms: int | None = 0o644,
) -> None:
    """Атомарно записать JSON с читаемым форматированием."""
    text = json.dumps(payload, ensure_ascii=ensure_ascii, indent=indent, sort_keys=sort_keys)
    write_text_atomic(path, text, encoding=encoding, newline="\n", perms=perms)


# =========================
# Хэши и отпечатки
# =========================
def hash_file(path: os.PathLike[str] | str, algo: Literal["sha256", "sha1", "md5"] = "sha256") -> str:
    """
    Вычислить хэш файла выбранным алгоритмом.
    По умолчанию безопасный SHA-256.
    """
    p = _to_path(path)
    h = hashlib.new(algo)
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def short_hash(data: bytes | str, *, algo: Literal["sha256", "sha1", "md5"] = "sha256", length: int = 12) -> str:
    """Короткий отпечаток (по умолчанию 12 символов от SHA-256)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.new(algo, data).hexdigest()[:length]


# =========================
# Копирование и удаление
# =========================
def copy_file(
    src: os.PathLike[str] | str,
    dst: os.PathLike[str] | str,
    *,
    overwrite: bool = False,
    preserve_metadata: bool = True,
) -> Path:
    """
    Скопировать файл. При overwrite=False — ошибка, если dst существует.
    preserve_metadata=True — использовать copy2 (с метаданными), иначе copyfile.
    """
    s = _to_path(src)
    d = _to_path(dst)
    ensure_dir(d.parent)
    if d.exists() and not overwrite:
        raise FileError(f"Destination exists: {d}")
    if preserve_metadata:
        return Path(shutil.copy2(s, d))
    return Path(shutil.copyfile(s, d))


def remove_tree_safe(root: os.PathLike[str] | str) -> None:
    """Удалить дерево каталогов; ошибки прав/непустых каталогов логически игнорируются (onerror)."""
    r = _to_path(root)

    def _onerror(func, path, exc_info):  # noqa: ANN001
        # Ничего не делаем, «мягкое» удаление
        return

    shutil.rmtree(r, ignore_errors=False, onerror=_onerror)


# =========================
# Поиск и имена
# =========================
def list_files(
    roots: Sequence[os.PathLike[str] | str],
    patterns: Sequence[str] = ("**/*",),
    *,
    include_hidden: bool = False,
    files_only: bool = True,
) -> list[Path]:
    """
    Рекурсивный поиск по наборам корней и масок glob.
    include_hidden=False — скрытые элементы (начинающиеся с '.') исключаются.
    files_only=True — возвращать только файлы.
    """
    out: list[Path] = []
    for root in roots:
        base = _to_path(root)
        if not base.exists():
            continue
        for pat in patterns:
            for p in base.glob(pat):
                if not include_hidden and any(part.startswith(".") for part in p.parts):
                    continue
                if files_only and not p.is_file():
                    continue
                out.append(p)
    # Уникальность + стабильная сортировка
    return sorted(set(out), key=lambda x: (str(x.parent), x.name))


def unique_name(base_path: os.PathLike[str] | str, suffix: str = "", *, max_tries: int = 100) -> Path:
    """
    Сгенерировать уникальное имя на основе base_path, добавляя суффикс и счётчик.
    Пример: /data/report.txt -> /data/report (1).txt
    """
    base = _to_path(base_path)
    parent, stem, ext = base.parent, base.stem, base.suffix
    candidate = base if not base.exists() else None
    if candidate is None:
        for i in range(1, max_tries + 1):
            c = parent / f"{stem} ({i}){suffix or ''}{ext}"
            if not c.exists():
                candidate = c
                break
    if candidate is None:
        raise FileError("Unable to generate unique name after max_tries")
    return candidate


# =========================
# Рабочая директория (контекст)
# =========================
@contextlib.contextmanager
def cwd(path: os.PathLike[str] | str) -> Iterator[None]:
    """Временная смена рабочей директории."""
    prev = Path.cwd()
    os.chdir(_to_path(path))
    try:
        yield
    finally:
        os.chdir(prev)


# =========================
# Файловые локи
# =========================
@dataclass
class FileLock:
    """
    Кроссплатформенный файловый лок.

    Принцип:
      - Используется отдельный lock-файл (path + '.lock').
      - На Unix применяется fcntl.flock (если доступен).
      - На Windows — msvcrt.locking (эксклюзивно).
      - Таймаут реализован активным ожиданием с малым сном.

    Эксклюзивный режим предназначен для синхронизации процессов/потоков,
    не защищает от «жёсткого» удаления lock-файла.
    """

    path: Path
    timeout: float = 10.0
    poll_interval: float = 0.05
    exclusive: bool = True  # shared режим поддерживается только на Unix; на Windows принудительно exclusive

    def __post_init__(self) -> None:
        self.path = _to_path(self.path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._fh: io.BufferedRandom | None = None

    def acquire(self) -> None:
        start = time.monotonic()
        ensure_dir(self.lock_path.parent)
        # Открываем/создаем файл для лока
        fh = open(self.lock_path, "a+b", buffering=0)
        self._fh = fh

        while True:
            try:
                if fcntl is not None:
                    # Unix: поддержка shared/exclusive
                    flag = os.O_RDONLY  # не влияет на flock
                    _ = flag
                    mode = (  # type: ignore[assignment]
                        fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH  # type: ignore[attr-defined]
                    )
                    fcntl.flock(fh.fileno(), mode | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                    return
                elif msvcrt is not None:
                    # Windows: только эксклюзивный неблокирующий лок на 1 байт
                    if not self.exclusive:
                        # Принудительно эксклюзивно
                        pass
                    try:
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
                        return
                    except OSError:
                        # занят
                        pass
                else:
                    # Платформа без поддержки — деградируем до создания lock-файла без гарантий
                    if self.lock_path.exists():
                        raise FileLockError("Lock emulation: busy")
                    # Попытка создать эксклюзивно
                    fd, tmp = tempfile.mkstemp(prefix=self.lock_path.name + ".", dir=self.lock_path.parent)
                    os.close(fd)
                    os.replace(tmp, self.lock_path)
                    return
            except BlockingIOError:
                # занят на Unix
                pass

            if (time.monotonic() - start) >= self.timeout:
                fh.close()
                self._fh = None
                raise FileLockError(f"Timeout acquiring lock: {self.lock_path}")

            time.sleep(self.poll_interval)

    def release(self) -> None:
        fh = self._fh
        if fh is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
            elif msvcrt is not None:
                with contextlib.suppress(Exception):
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        finally:
            try:
                fh.close()
            finally:
                self._fh = None
                # Сам lock-файл оставляем — это безвредно и избавляет от гонок удаления.
                # Если необходимо, можно раскомментировать удаление:
                # with contextlib.suppress(Exception):
                #     self.lock_path.unlink(missing_ok=True)

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.release()
