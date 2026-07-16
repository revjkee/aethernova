# agent_mash/legacy/scripts_archive/utilities/compatibility_helpers.py
"""
compatibility_helpers.py

Промышленный набор утилит для кросс-платформенной совместимости (Windows/macOS/Linux),
устойчивого выполнения подпроцессов, безопасной работы с путями/кодировками и
аккуратного подключения опциональных модулей.

Требования:
- Только стандартная библиотека Python.
- Предсказуемое поведение, строгие типы, аккуратные исключения.
- Никакой "магии": функции должны быть очевидны и проверяемы.

Замечание по проверяемости:
- Этот файл не содержит фактических утверждений, требующих источников; это реализация кода.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import (
    Any,
    Callable,
    Iterator,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    overload,
)

__all__ = [
    "CompatError",
    "OptionalImportError",
    "SubprocessError",
    "Version",
    "atomic_write_text",
    "atomic_write_bytes",
    "ensure_utf8_stdio",
    "get_interpreter_tag",
    "get_os_tag",
    "get_platform_fingerprint",
    "import_optional",
    "is_ci",
    "is_linux",
    "is_macos",
    "is_windows",
    "normalize_newlines",
    "parse_version",
    "python_implementation",
    "python_version_tuple",
    "run_subprocess",
    "safe_decode",
    "supports_color",
    "which",
    "with_env",
]

_T = TypeVar("_T")


class CompatError(RuntimeError):
    """Базовая ошибка модуля совместимости."""


class OptionalImportError(CompatError, ImportError):
    """Ошибка опционального импорта с дружелюбным сообщением."""


class SubprocessError(CompatError):
    """Ошибка выполнения подпроцесса."""

    def __init__(
        self,
        message: str,
        *,
        returncode: Optional[int] = None,
        cmd: Optional[Sequence[str]] = None,
        stdout: Optional[bytes] = None,
        stderr: Optional[bytes] = None,
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.cmd = tuple(cmd) if cmd is not None else None
        self.stdout = stdout
        self.stderr = stderr


@dataclasses.dataclass(frozen=True, slots=True, order=True)
class Version:
    """
    Минимальная, но строгая модель версии.

    Поддерживает сравнение и сортировку.
    Пример: Version(3, 11, 6) < Version(3, 12, 0) == True
    """

    major: int
    minor: int = 0
    patch: int = 0
    pre: Tuple[Union[str, int], ...] = dataclasses.field(default_factory=tuple)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if not self.pre:
            return base
        pre = ".".join(str(x) for x in self.pre)
        return f"{base}-{pre}"


_VERSION_RE = re.compile(
    r"^\s*(?P<maj>0|[1-9]\d*)"
    r"(?:\.(?P<min>0|[1-9]\d*))?"
    r"(?:\.(?P<pat>0|[1-9]\d*))?"
    r"(?:[-_\.]?(?P<pre>[A-Za-z0-9][A-Za-z0-9\.\-_]*))?\s*$"
)


def parse_version(value: str) -> Version:
    """
    Парсит строку версии в Version.

    Поддерживаемые варианты:
    - "1"
    - "1.2"
    - "1.2.3"
    - "1.2.3-rc1" / "1.2.3_rc1" / "1.2.3rc1"

    Исключения:
    - ValueError при некорректном формате.
    """
    m = _VERSION_RE.match(value)
    if not m:
        raise ValueError(f"Invalid version string: {value!r}")

    maj = int(m.group("maj"))
    min_ = int(m.group("min") or 0)
    pat = int(m.group("pat") or 0)

    pre_raw = m.group("pre")
    if not pre_raw:
        return Version(maj, min_, pat)

    parts: list[Union[str, int]] = []
    for token in re.split(r"[.\-_]+", pre_raw.strip()):
        if not token:
            continue
        if token.isdigit():
            parts.append(int(token))
        else:
            parts.append(token.lower())
    return Version(maj, min_, pat, tuple(parts))


def python_version_tuple() -> Tuple[int, int, int]:
    """Возвращает версию Python (major, minor, micro)."""
    v = sys.version_info
    return (int(v.major), int(v.minor), int(v.micro))


def python_implementation() -> str:
    """Возвращает реализацию Python (CPython, PyPy и т.д.)."""
    return platform.python_implementation()


def is_windows() -> bool:
    """True если ОС Windows."""
    return os.name == "nt"


def is_macos() -> bool:
    """True если ОС macOS."""
    return sys.platform == "darwin"


def is_linux() -> bool:
    """True если ОС Linux."""
    return sys.platform.startswith("linux")


def is_ci(env: Optional[Mapping[str, str]] = None) -> bool:
    """
    Детект CI по распространённым переменным окружения.
    Возвращает True/False без исключений.
    """
    e = env if env is not None else os.environ
    keys = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TF_BUILD")
    return any(str(e.get(k, "")).strip().lower() in ("1", "true", "yes", "on") for k in keys)


def get_os_tag() -> str:
    """
    Возвращает краткий тег ОС: windows | macos | linux | other
    """
    if is_windows():
        return "windows"
    if is_macos():
        return "macos"
    if is_linux():
        return "linux"
    return "other"


def get_interpreter_tag() -> str:
    """
    Возвращает краткий тег интерпретатора: cpython | pypy | other
    """
    impl = python_implementation().strip().lower()
    if impl == "cpython":
        return "cpython"
    if impl == "pypy":
        return "pypy"
    return "other"


def get_platform_fingerprint() -> str:
    """
    Возвращает стабильный отпечаток платформы для логов/диагностики.
    Формат: os=<...>;py=<...>;impl=<...>;arch=<...>
    """
    os_tag = get_os_tag()
    py = ".".join(map(str, python_version_tuple()))
    impl = get_interpreter_tag()
    arch = platform.machine() or "unknown"
    return f"os={os_tag};py={py};impl={impl};arch={arch}"


def supports_color() -> bool:
    """
    Определяет поддержку ANSI-цветов для stdout.

    Решение консервативное:
    - Если stdout не TTY -> False
    - Windows: учитывает популярные терминалы (WT_SESSION, ANSICON, ConEmu)
    - Если NO_COLOR задан -> False
    """
    if os.environ.get("NO_COLOR"):
        return False

    try:
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
    except Exception:
        return False

    if is_windows():
        if os.environ.get("WT_SESSION"):
            return True
        if os.environ.get("ANSICON"):
            return True
        if os.environ.get("ConEmuANSI", "").strip().lower() == "on":
            return True
        if os.environ.get("TERM", "").lower() in ("xterm", "xterm-256color", "vt100"):
            return True
        return False

    return True


def ensure_utf8_stdio() -> None:
    """
    Пытается обеспечить UTF-8 для stdin/stdout/stderr в рамках возможностей Python.

    Безопасное поведение:
    - Не бросает исключения наружу.
    - Не ломает поток, если переподключение невозможно.
    """
    # Python 3.7+ поддерживает reconfigure у текстовых потоков.
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace", newline="")
            except Exception:
                continue


def normalize_newlines(text: str) -> str:
    """Приводит переводы строк к LF."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def which(cmd: str, *, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """
    Возвращает абсолютный путь к исполняемому файлу, если найден.
    """
    path = None
    if env is not None:
        # shutil.which умеет принимать env только через PATH, поэтому подставляем PATH.
        path = env.get("PATH")
    return shutil.which(cmd, path=path)


@overload
def safe_decode(data: bytes, *, encoding: str = "utf-8", errors: str = "replace") -> str: ...
@overload
def safe_decode(data: Optional[bytes], *, encoding: str = "utf-8", errors: str = "replace") -> str: ...


def safe_decode(data: Optional[bytes], *, encoding: str = "utf-8", errors: str = "replace") -> str:
    """
    Безопасно декодирует bytes -> str.
    Если data is None -> пустая строка.
    """
    if not data:
        return ""
    try:
        return data.decode(encoding, errors=errors)
    except Exception:
        # Фоллбек: latin-1 никогда не падает
        try:
            return data.decode("latin-1", errors="replace")
        except Exception:
            return ""


@dataclasses.dataclass(frozen=True, slots=True)
class SubprocessResult:
    cmd: Tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def stdout_text(self) -> str:
        return safe_decode(self.stdout)

    @property
    def stderr_text(self) -> str:
        return safe_decode(self.stderr)


def run_subprocess(
    cmd: Sequence[str],
    *,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout_s: Optional[float] = None,
    check: bool = True,
    capture: bool = True,
    text_mode: bool = False,
    stdin: Optional[Union[bytes, str]] = None,
) -> Union[SubprocessResult, Tuple[int, str, str]]:
    """
    Запускает подпроцесс безопасно и предсказуемо.

    Параметры:
    - cmd: команда списком аргументов (без shell=True)
    - cwd: рабочая директория
    - env: переменные окружения (полная мапа или None)
    - timeout_s: таймаут выполнения
    - check: если True и returncode != 0 -> SubprocessError
    - capture: если True -> захватывает stdout/stderr
    - text_mode: если True -> возвращает (returncode, stdout_str, stderr_str)
    - stdin: bytes или str для stdin (если передан)

    Возврат:
    - SubprocessResult (bytes) или (rc, out, err) для text_mode=True
    """
    if not cmd or not all(isinstance(x, str) and x for x in cmd):
        raise ValueError("cmd must be a non-empty sequence of non-empty strings")

    final_env: Optional[MutableMapping[str, str]] = None
    if env is not None:
        final_env = dict(env)

    stdin_bytes: Optional[bytes] = None
    if stdin is not None:
        if isinstance(stdin, str):
            stdin_bytes = stdin.encode("utf-8", errors="replace")
        elif isinstance(stdin, (bytes, bytearray)):
            stdin_bytes = bytes(stdin)
        else:
            raise TypeError("stdin must be bytes, bytearray, str, or None")

    try:
        p = subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd is not None else None,
            env=final_env,
            input=stdin_bytes,
            timeout=timeout_s,
            check=False,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except subprocess.TimeoutExpired as e:
        raise SubprocessError(
            f"Subprocess timeout after {timeout_s!r} seconds",
            returncode=None,
            cmd=cmd,
            stdout=getattr(e, "stdout", None),
            stderr=getattr(e, "stderr", None),
        ) from e
    except FileNotFoundError as e:
        raise SubprocessError(
            "Subprocess executable not found",
            returncode=None,
            cmd=cmd,
            stdout=None,
            stderr=None,
        ) from e
    except OSError as e:
        raise SubprocessError(
            f"Subprocess OS error: {e}",
            returncode=None,
            cmd=cmd,
            stdout=None,
            stderr=None,
        ) from e

    out = p.stdout if p.stdout is not None else b""
    err = p.stderr if p.stderr is not None else b""

    if check and p.returncode != 0:
        raise SubprocessError(
            "Subprocess failed",
            returncode=int(p.returncode),
            cmd=cmd,
            stdout=out,
            stderr=err,
        )

    if text_mode:
        return (int(p.returncode), safe_decode(out), safe_decode(err))

    return SubprocessResult(tuple(cmd), int(p.returncode), out, err)


def import_optional(module_name: str, *, purpose: str = "", install_hint: str = "") -> Any:
    """
    Импортирует опциональный модуль.

    Поведение:
    - При успехе возвращает модуль.
    - При неудаче бросает OptionalImportError с ясным сообщением.

    purpose: для чего нужен модуль (контекст)
    install_hint: подсказка установки (например: "pip install X")
    """
    if not module_name or not isinstance(module_name, str):
        raise ValueError("module_name must be a non-empty string")

    try:
        __import__(module_name)
        return sys.modules[module_name]
    except Exception as e:
        parts = [f"Optional dependency '{module_name}' is not available."]
        if purpose:
            parts.append(f"Purpose: {purpose}")
        if install_hint:
            parts.append(f"Install: {install_hint}")
        msg = " ".join(parts)
        raise OptionalImportError(msg) from e


@contextlib.contextmanager
def with_env(overrides: Mapping[str, Optional[str]]) -> Iterator[None]:
    """
    Временная подмена переменных окружения.

    overrides:
    - key -> value: установить значение
    - key -> None: удалить переменную

    Восстановление гарантируется.
    """
    if overrides is None:
        raise ValueError("overrides must not be None")

    old: dict[str, Optional[str]] = {}
    for k, v in overrides.items():
        if not isinstance(k, str) or not k:
            raise ValueError("environment variable names must be non-empty strings")
        old[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

    try:
        yield
    finally:
        for k, prev in old.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


def _fsync_dir_for(path: Path) -> None:
    """
    Попытка fsync директории на POSIX для максимальной надёжности atomic-write.
    На Windows безопасно no-op.
    """
    if is_windows():
        return
    try:
        dir_fd = os.open(str(path), os.O_DIRECTORY)
    except Exception:
        return
    try:
        os.fsync(dir_fd)
    except Exception:
        return
    finally:
        try:
            os.close(dir_fd)
        except Exception:
            pass


def atomic_write_bytes(
    target: Union[str, Path],
    data: bytes,
    *,
    mode: int = 0o644,
    make_parents: bool = True,
) -> None:
    """
    Атомарная запись bytes в файл.

    Гарантии:
    - Запись идёт во временный файл рядом с target.
    - Затем os.replace (атомарно на поддерживаемых ФС).
    - На POSIX пытается fsync файла и директории (best-effort).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")

    target_path = Path(target).expanduser().resolve()
    if make_parents:
        target_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_fd: Optional[int] = None
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            dir=str(target_path.parent),
        )
        tmp_fd = fd
        tmp_path = Path(tmp_name)

        os.write(tmp_fd, bytes(data))
        try:
            os.fsync(tmp_fd)
        except Exception:
            pass

        try:
            os.fchmod(tmp_fd, mode)
        except Exception:
            pass

        os.close(tmp_fd)
        tmp_fd = None

        os.replace(str(tmp_path), str(target_path))

        _fsync_dir_for(target_path.parent)

    finally:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except Exception:
                pass
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)  # type: ignore[attr-defined]
            except Exception:
                pass


def atomic_write_text(
    target: Union[str, Path],
    text: str,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    newline: str = "\n",
    mode: int = 0o644,
    make_parents: bool = True,
) -> None:
    """
    Атомарная запись текста в файл с контролем кодировки.

    newline:
    - "\n" (по умолчанию) принудительно нормализует переводы строк.
    - "" оставляет как есть.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")

    payload = text
    if newline == "\n":
        payload = normalize_newlines(payload)

    data = payload.encode(encoding, errors=errors)
    atomic_write_bytes(target, data, mode=mode, make_parents=make_parents)


def _sleep_backoff(attempt: int, base_s: float, cap_s: float) -> None:
    if attempt <= 0:
        return
    delay = min(cap_s, base_s * (2 ** (attempt - 1)))
    time.sleep(delay)


def _retry_on_windows_sharing_violation(err: OSError) -> bool:
    # Windows sharing violation / access denied during replace/unlink sometimes transient.
    if not is_windows():
        return False
    if isinstance(err, PermissionError):
        return True
    return getattr(err, "errno", None) in (errno.EACCES, errno.EPERM)


def get_platform_fingerprint_safe() -> str:
    """
    Совместимость: исторически могли звать функцию так.
    Оставляем алиас без удаления публичного API.
    """
    return get_platform_fingerprint()
