# -*- coding: utf-8 -*-
"""
AUTO-FACADE for Aethernova Engine network.proto (Python)
Этот модуль выступает фасадом над автогенерируемым модулем из Protocol Buffers.

Функции:
- Идемпотентно проверяет, что исходная схема *.proto сгенерирована.
- Генерирует код в подкаталог `_autogen/engine/` при отсутствии/устаревании.
- Потокобезопасная файловая блокировка (межпроцессная).
- Строгая диагностика ошибок генерации.
- Прозрачный ре‑экспорт всех публичных символов сгенерированного модуля.

Зависимости для генерации:
    pip install grpcio grpcio-tools protobuf

Структура вывода:
    engine-core/codegen/python/v1/generated/_autogen/engine/network_pb2.py
    engine-core/codegen/python/v1/generated/_autogen/engine/network_pb2_grpc.py (если потребуется)

ВАЖНО:
- Этот файл можно коммитить. Он самодостаточный фасад.
- Реальный сгенерированный код хранится в `_autogen/engine/`.
- При обновлении .proto/инструментов фасад сам перегенерирует код.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
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
PROTO_REL_PATH = Path("engine-core/schemas/proto/v1/engine/network.proto")
PACKAGE_ROOT_MARKERS = {".git", "pyproject.toml", "setup.cfg", "engine-core"}
AUTOGEN_DIR_NAME = "_autogen"  # внутри generated/
STAMP_FILE = "__genstamp__.json"
LOCK_FILE = "__genlock__.lck"
GEN_TIMEOUT_SEC = 300

# --- Вспомогательные утилиты ---

@dataclass(frozen=True)
class ToolVersions:
    protoc: str
    grpc_tools: str
    protobuf: str

class CodegenError(RuntimeError):
    pass

def _detect_repo_root(start: Optional[Path] = None) -> Path:
    p = Path(start or __file__).resolve()
    for base in [p] + list(p.parents):
        for marker in PACKAGE_ROOT_MARKERS:
            if (base / marker).exists():
                return base
    # fallback: два уровня вверх от generated/engine/
    return Path(__file__).resolve().parents[3]

def _read_text(path: Path) -> str:
    with path.open("rb") as f:
        return f.read().decode("utf-8")

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_file(path: Path) -> str:
    with path.open("rb") as f:
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
        return h.hexdigest()

def _tool_versions() -> ToolVersions:
    # Версии инструментов
    try:
        import grpc_tools.protoc as grpc_protoc  # type: ignore
        grpc_tools_ver = getattr(grpc_protoc, "__version__", "unknown")
    except Exception:
        grpc_tools_ver = "missing"
    try:
        import google.protobuf as gp  # type: ignore
        protobuf_ver = getattr(gp, "__version__", "unknown")
    except Exception:
        protobuf_ver = "missing"
    # Версия protoc через subprocess, если доступен
    protoc_ver = "unknown"
    candidates = ("protoc", "protoc.exe")
    for c in candidates:
        try:
            out = subprocess.run([c, "--version"], check=False, capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout:
                protoc_ver = out.stdout.strip()
                break
        except Exception:
            pass
    return ToolVersions(protoc=protoc_ver, grpc_tools=grpc_tools_ver, protobuf=protobuf_ver)

@contextlib.contextmanager
def _file_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # Кроссплатформенная блокировка
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
    # Текущая директория этого файла: .../generated/engine/network_pb2.py
    this_file = Path(__file__).resolve()
    generated_dir = this_file.parents[1]            # .../generated
    autogen_dir = generated_dir / AUTOGEN_DIR_NAME  # .../generated/_autogen
    pkg_dir = autogen_dir / "engine"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    # Положим __init__.py, если его нет
    for d in (autogen_dir, pkg_dir):
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
    # protoc не всегда критичен, но учитываем при наличии
    if tools.protoc != "unknown" and stamp.get("protoc") != tools.protoc:
        return True
    return False

def _run_protoc(repo_root: Path, out_pkg_dir: Path) -> None:
    proto_path = repo_root / PROTO_REL_PATH
    if not proto_path.exists():
        raise CodegenError(f"Не найден proto-файл: {proto_path}")

    # Временный каталог для сборки с последующим атомарным переносом
    with tempfile.TemporaryDirectory(prefix="codegen_pb2_") as td:
        tmp_out = Path(td)
        (tmp_out / "engine").mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable, "-m", "grpc_tools.protoc",
            "-I", str(repo_root / "engine-core" / "schemas" / "proto"),
            "-I", str(repo_root),
            "--python_out", str(tmp_out),
            "--grpc_python_out", str(tmp_out),
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

        # Переносим результаты в пакет вывода
        for rel in ("engine/network_pb2.py", "engine/network_pb2_grpc.py"):
            src = tmp_out / rel
            if src.exists():
                dst = out_pkg_dir / Path(rel).name
                # атомарная замена
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

    return out_pkg_dir / "network_pb2.py"

def _import_autogen_module():
    """
    Гарантирует, что автогенерированный модуль присутствует, и импортирует его
    как Python‑модуль, после чего ре‑экспортирует его публичные символы.
    """
    out_file = _ensure_generated_impl()

    # Добавим каталог `_autogen` в sys.path, если его там нет
    autogen_dir = out_file.parent.parent  # .../generated/_autogen
    if str(autogen_dir) not in sys.path:
        sys.path.insert(0, str(autogen_dir))

    # Импортируем модуль как engine.network_pb2 из `_autogen`
    mod = importlib.import_module("engine.network_pb2")
    return mod

# --- Импорт и ре‑экспорт символов сгенерированного модуля ---

try:
    _mod = _import_autogen_module()
except Exception as e:
    raise CodegenError(
        f"Не удалось подготовить/импортировать автогенерированный модуль network_pb2: {e}"
    ) from e

# Прозрачный ре‑экспорт
globals().update({k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("_")})

# Явный экспортируемый список
if hasattr(_mod, "__all__"):
    __all__ = list(_mod.__all__)  # type: ignore
else:
    __all__ = [k for k in globals().keys() if not k.startswith("_")]

# Метаданные для отладки
__codegen_api_version__ = CODEGEN_API_VERSION
__autogen_file__ = getattr(_mod, "__file__", None)
