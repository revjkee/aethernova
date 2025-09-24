# -*- coding: utf-8 -*-
"""
AUTO-FACADE for Aethernova Engine common/error.proto (Python)
Фасад над автогенерируемым модулем Protocol Buffers.

Назначение:
- Идемпотентно проверить и при необходимости сгенерировать Python-код из
  engine-core/schemas/proto/v1/common/error/error.proto.
- Потокобезопасность через межпроцессную файловую блокировку.
- Атомарная выдача артефактов в каталоге generated/_autogen/common/error/.
- Прозрачный ре-экспорт всех публичных символов из autogen-модуля.

Зависимости:
    pip install grpcio grpcio-tools protobuf
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

# --- Параметры фасада ---
CODEGEN_API_VERSION = "1.0.0"
# Относительный путь к proto-файлу от корня репозитория
PROTO_REL_PATH = Path("engine-core/schemas/proto/v1/common/error/error.proto")
# Маркеры корня репозитория
PACKAGE_ROOT_MARKERS = {".git", "pyproject.toml", "setup.cfg", "engine-core"}
# Имя подкаталога для автогенерируемых модулей
AUTOGEN_DIR_NAME = "_autogen"
# Служебные файлы в каталоге _autogen
STAMP_FILE = "__genstamp__.json"
LOCK_FILE = "__genlock__.lck"
# Таймаут генерации
GEN_TIMEOUT_SEC = 300

# --- Типы/исключения ---

@dataclass(frozen=True)
class ToolVersions:
    protoc: str
    grpc_tools: str
    protobuf: str

class CodegenError(RuntimeError):
    """Ошибка при подготовке/генерации автогенерируемых модулей."""


# --- Вспомогательные функции ---

def _detect_repo_root(start: Optional[Path] = None) -> Path:
    """Эвристический поиск корня репозитория по маркерам."""
    p = Path(start or __file__).resolve()
    for base in [p] + list(p.parents):
        for marker in PACKAGE_ROOT_MARKERS:
            if (base / marker).exists():
                return base
    # Fallback: три уровня вверх от текущего файла
    return Path(__file__).resolve().parents[5]

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def _tool_versions() -> ToolVersions:
    # Версия grpc_tools
    try:
        import grpc_tools.protoc as grpc_protoc  # type: ignore
        grpc_tools_ver = getattr(grpc_protoc, "__version__", "unknown")
    except Exception:
        grpc_tools_ver = "missing"
    # Версия protobuf
    try:
        import google.protobuf as gp  # type: ignore
        protobuf_ver = getattr(gp, "__version__", "unknown")
    except Exception:
        protobuf_ver = "missing"
    # Версия protoc
    protoc_ver = "unknown"
    for exe in ("protoc", "protoc.exe"):
        try:
            out = subprocess.run([exe, "--version"], check=False, capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout:
                protoc_ver = out.stdout.strip()
                break
        except Exception:
            pass
    return ToolVersions(protoc=protoc_ver, grpc_tools=grpc_tools_ver, protobuf=protobuf_ver)

@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """Кроссплатформенная межпроцессная блокировка на файле."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import msvcrt  # type: ignore
        with open(lock_path, "a+b") as f:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                yield
            finally:
                with contextlib.suppress(Exception):
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl  # type: ignore
        with open(lock_path, "a+b") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                with contextlib.suppress(Exception):
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def _ensure_autogen_paths() -> Tuple[Path, Path]:
    """
    Подготавливает каталоги:
      generated/_autogen/common/error/
    и создает __init__.py для пакетов.
    Возвращает (autogen_dir, out_pkg_dir).
    """
    this_file = Path(__file__).resolve()
    generated_dir = this_file.parents[2]                 # .../generated
    autogen_dir = generated_dir / AUTOGEN_DIR_NAME       # .../generated/_autogen
    pkg_dir = autogen_dir / "common" / "error"           # .../generated/_autogen/common/error
    pkg_dir.mkdir(parents=True, exist_ok=True)
    # Инициализация пакетов
    for d in (autogen_dir, autogen_dir / "common", pkg_dir):
        init_fp = d / "__init__.py"
        if not init_fp.exists():
            init_fp.write_text("# auto-generated package init\n", encoding="utf-8")
    return autogen_dir, pkg_dir

def _load_stamp(stamp_path: Path) -> Dict[str, str]:
    if not stamp_path.exists():
        return {}
    try:
        return json.loads(stamp_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _save_stamp(stamp_path: Path, data: Dict[str, str]) -> None:
    tmp = stamp_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(stamp_path)

def _needs_regen(stamp: Dict[str, str], source_hash: str, tools: ToolVersions) -> bool:
    if not stamp:
        return True
    if stamp.get("codegen_api") != CODEGEN_API_VERSION:
        return True
    if stamp.get("source_hash") != source_hash:
        return True
    if stamp.get("grpc_tools") != tools.grpc_tools:
        return True
    if stamp.get("protobuf") != tools.protobuf:
        return True
    if tools.protoc != "unknown" and stamp.get("protoc") != tools.protoc:
        return True
    return False

def _run_protoc(repo_root: Path, out_pkg_dir: Path) -> None:
    proto_path = repo_root / PROTO_REL_PATH
    if not proto_path.exists():
        raise CodegenError(f"Не найден proto-файл: {proto_path}")

    with tempfile.TemporaryDirectory(prefix="codegen_pb2_common_error_") as td:
        tmp_out = Path(td)
        (tmp_out / "common" / "error").mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable, "-m", "grpc_tools.protoc",
            # include-пути
            "-I", str(repo_root / "engine-core" / "schemas" / "proto"),
            "-I", str(repo_root),
            # выходы
            "--python_out", str(tmp_out),
            "--grpc_python_out", str(tmp_out),
            # источник
            str(proto_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GEN_TIMEOUT_SEC)
        if proc.returncode != 0:
            raise CodegenError(
                "Ошибка grpc_tools.protoc\n"
                f"cmd: {' '.join(cmd)}\n"
                f"stdout:\n{proc.stdout}\n"
                f"stderr:\n{proc.stderr}"
            )

        # Переносим результирующие файлы атомарно
        for rel in ("common/error/error_pb2.py", "common/error/error_pb2_grpc.py"):
            src = tmp_out / rel
            if src.exists():
                dst = out_pkg_dir / Path(rel).name
                tmp_dst = dst.with_suffix(".tmp")
                shutil.copy2(src, tmp_dst)
                tmp_dst.replace(dst)

def _ensure_generated_impl() -> Path:
    repo_root = _detect_repo_root()
    autogen_dir, out_pkg_dir = _ensure_autogen_paths()

    proto_abs = (repo_root / PROTO_REL_PATH).resolve()
    if not proto_abs.exists():
        raise CodegenError(f"Proto-файл не найден: {proto_abs}")

    tools = _tool_versions()
    source_hash = _sha256_file(proto_abs)

    stamp_path = autogen_dir / STAMP_FILE
    lock_path = autogen_dir / LOCK_FILE

    with _file_lock(lock_path):
        stamp = _load_stamp(stamp_path)
        if _needs_regen(stamp, source_hash, tools):
            _run_protoc(repo_root, out_pkg_dir)
            _save_stamp(
                stamp_path,
                {
                    "codegen_api": CODEGEN_API_VERSION,
                    "source": str(PROTO_REL_PATH),
                    "source_hash": source_hash,
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "protoc": tools.protoc,
                    "grpc_tools": tools.grpc_tools,
                    "protobuf": tools.protobuf,
                    "python": sys.version.split()[0],
                },
            )

    return out_pkg_dir / "error_pb2.py"

def _import_autogen_module():
    """
    Гарантирует наличие автогенерируемого модуля и импортирует его
    из каталога generated/_autogen/common/error/.
    """
    out_file = _ensure_generated_impl()

    # Добавляем generated/_autogen в sys.path, если его там нет
    autogen_dir = out_file.parent.parent.parent  # .../_autogen
    if str(autogen_dir) not in sys.path:
        sys.path.insert(0, str(autogen_dir))

    # Импортируем как common.error.error_pb2
    mod = importlib.import_module("common.error.error_pb2")
    return mod

# --- Импорт и ре-экспорт ---

try:
    _mod = _import_autogen_module()
except Exception as e:
    raise CodegenError(
        f"Не удалось подготовить/импортировать автогенерированный модуль error_pb2: {e}"
    ) from e

# Публичный ре-экспорт
if hasattr(_mod, "__all__"):
    __all__ = list(_mod.__all__)  # type: ignore[attr-defined]
    for name in __all__:
        globals()[name] = getattr(_mod, name)
else:
    exported = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("_")}
    globals().update(exported)
    __all__ = list(exported.keys())

# Метаданные
__codegen_api_version__ = CODEGEN_API_VERSION
__autogen_file__ = getattr(_mod, "__file__", None)
