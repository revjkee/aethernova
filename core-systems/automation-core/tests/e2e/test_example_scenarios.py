# automation-core/tests/e2e/test_example_scenarios.py
# -*- coding: utf-8 -*-
"""
E2E-сценарии для скрипта генерации protobuf-кода:
  - Smoke: protoc + Python (grpc_tools.protoc)
  - Optional: buf + Python (remote plugins) — пропуск без сети/без buf
  - Negative: отсутствие .proto -> корректная ошибка
  - Idempotency: повторный запуск не ломает артефакты

Тесты изолированы (tmp_path), используют subprocess.run с timeout
и мягко пропускаются при отсутствии требуемых инструментов.
"""

from __future__ import annotations

import os
import sys
import json
import shutil
import textwrap
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

# -------------------------- constants --------------------------

REL_SCRIPT = Path(__file__).resolve().parents[3] / "automation-core" / "scripts" / "gen_proto.sh"

# Разрешать сетевые тесты (buf remote plugins) только при явном флаге
ALLOW_NETWORK = os.environ.get("E2E_ALLOW_NETWORK", "0") == "1"

# -------------------------- helpers ---------------------------

def _have(cmd: str) -> bool:
    """Проверяет наличие команды в PATH (shutil.which)."""
    import shutil as _sh
    return _sh.which(cmd) is not None  # docs: Python shutil.which. :contentReference[oaicite:0]{index=0}

def _require_module(mod: str) -> bool:
    """Проверяет импортируемость модуля без падения."""
    try:
        __import__(mod)
        return True
    except Exception:
        return False

def _run(cmd: List[str], *, env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None, timeout: int = 120):
    """Безопасный запуск subprocess.run с таймаутом и захватом вывода."""
    # docs: subprocess.run recommended API & timeout. :contentReference[oaicite:1]{index=1}
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed

def _write_proto(tree_root: Path, pkg: str = "example.v1", fname: str = "echo.proto") -> Path:
    """Создаёт минимальный proto-файл с сервисом Greeter."""
    pkg_path = tree_root / "example" / "v1"
    pkg_path.mkdir(parents=True, exist_ok=True)
    proto = textwrap.dedent(
        f'''
        syntax = "proto3";
        package {pkg};

        message HelloReq {{ string name = 1; }}
        message HelloResp {{ string message = 1; }}

        service Greeter {{
          rpc SayHello(HelloReq) returns (HelloResp);
        }}
        '''
    ).strip() + "\n"
    p = pkg_path / fname
    p.write_text(proto, encoding="utf-8")
    return p

def _repo_root_fallback() -> Path:
    """Определение корня репозитория: git rev-parse или относительный путь."""
    try:
        r = _run(["git", "rev-parse", "--show-toplevel"], timeout=10)
        if r.returncode == 0:
            return Path(r.stdout.strip())
    except Exception:
        pass
    # fallback: три уровня вверх от tests/e2e
    return Path(__file__).resolve().parents[3]

# -------------------------- markers/skip -----------------------

pytestmark = pytest.mark.e2e

def _skip_if_no_bash():
    if not _have("bash"):
        pytest.skip("bash недоступен в PATH — пропуск E2E для shell-скрипта.")

def _skip_if_no_protoc():
    if not _have("protoc"):
        pytest.skip("protoc недоступен в PATH — пропуск protoc-сценариев.")

def _skip_if_no_grpc_tools():
    # grpcio-tools предоставляет python -m grpc_tools.protoc. :contentReference[oaicite:2]{index=2}
    if not _require_module("grpc_tools"):
        pytest.skip("grpcio-tools не установлен — пропуск Python-генерации.")

def _skip_if_no_buf_or_network():
    if not _have("buf"):
        pytest.skip("buf недоступен — пропуск buf-сценариев.")
    if not ALLOW_NETWORK:
        pytest.skip("Сетевые тесты отключены (E2E_ALLOW_NETWORK!=1).")

# -------------------------- tests ------------------------------

@pytest.mark.timeout(180)  # plugin timeout; see docs. :contentReference[oaicite:3]{index=3}
def test_protoc_python_generation_smoke(tmp_path: Path):
    """
    Smoke: генерация Python-стабов через protoc + grpc_tools.protoc.
    Проверяется наличие ожидаемых файлов *_pb2.py и *_pb2_grpc.py.
    """
    _skip_if_no_bash()
    _skip_if_no_protoc()
    _skip_if_no_grpc_tools()

    repo_root = _repo_root_fallback()
    assert REL_SCRIPT.exists(), f"Скрипт не найден: {REL_SCRIPT}"

    # Подготовка структуры входа/выхода
    proto_root = tmp_path / "proto"
    out_base = tmp_path / "generated"
    proto_root.mkdir(parents=True, exist_ok=True)
    _write_proto(proto_root)

    env = {
        "MODE": "protoc",
        "LANGS": "python",
        "IN_DIRS": str(proto_root),
        "OUT_BASE": str(out_base),
        "CLEAN": "1",
        "VERBOSE": "1",
    }

    # Запуск скрипта через bash
    res = _run(["bash", str(REL_SCRIPT)], env=env, cwd=repo_root)
    assert res.returncode == 0, f"gen_proto.sh завершился с ошибкой:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"

    # Проверка артефактов
    py_out = out_base / "python" / "example" / "v1"
    files = {p.name for p in py_out.glob("*.py")}
    # grpc_tools.protoc генерирует echo_pb2.py и echo_pb2_grpc.py
    assert "echo_pb2.py" in files and "echo_pb2_grpc.py" in files, f"Не найдены ожидаемые файлы в {py_out}"

@pytest.mark.timeout(240)  # чуть больше — buf может скачать плагины
def test_buf_python_generation_optional(tmp_path: Path):
    """
    Optional: генерация через buf (remote plugins для Python).
    Пропускается, если нет buf или сетевые тесты отключены.
    """
    _skip_if_no_bash()
    _skip_if_no_buf_or_network()

    repo_root = _repo_root_fallback()
    assert REL_SCRIPT.exists(), f"Скрипт не найден: {REL_SCRIPT}"

    proto_root = tmp_path / "protos"
    out_base = tmp_path / "out"
    proto_root.mkdir(parents=True, exist_ok=True)
    _write_proto(proto_root)

    env = {
        "MODE": "buf",
        "LANGS": "python",
        "IN_DIRS": str(proto_root),
        "OUT_BASE": str(out_base),
        "CLEAN": "1",
        "VERBOSE": "1",
    }

    res = _run(["bash", str(REL_SCRIPT)], env=env, cwd=repo_root, timeout=240)
    assert res.returncode == 0, f"buf-генерация упала:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"

    py_out = out_base / "python" / "example" / "v1"
    files = {p.name for p in py_out.glob("*.py")}
    assert "echo_pb2.py" in files and "echo_pb2_grpc.py" in files

@pytest.mark.timeout(60)
def test_failure_without_proto_inputs(tmp_path: Path):
    """
    Negative: при отсутствии .proto входов скрипт должен завершаться с ненулевым кодом.
    """
    _skip_if_no_bash()

    repo_root = _repo_root_fallback()
    empty_root = tmp_path / "empty"
    out_base = tmp_path / "generated"
    empty_root.mkdir(parents=True, exist_ok=True)

    env = {
        "MODE": "protoc",      # режим не важен — входы пустые
        "LANGS": "python",
        "IN_DIRS": str(empty_root),
        "OUT_BASE": str(out_base),
        "CLEAN": "1",
    }

    res = _run(["bash", str(REL_SCRIPT)], env=env, cwd=repo_root, timeout=60)
    assert res.returncode != 0, "Ожидался ненулевой код возврата при пустом каталоге .proto"
    # Допускаем, что сообщение об ошибке выводится в stderr
    assert "No .proto files found" in (res.stderr + res.stdout), "Ожидалось диагностическое сообщение о пустом входе"

@pytest.mark.timeout(180)
def test_idempotent_double_run_protoc_python(tmp_path: Path):
    """
    Idempotency: два последовательных запуска с одинаковыми параметрами не ломают артефакты.
    """
    _skip_if_no_bash()
    _skip_if_no_protoc()
    _skip_if_no_grpc_tools()

    repo_root = _repo_root_fallback()

    proto_root = tmp_path / "proto"
    out_base = tmp_path / "generated"
    proto_root.mkdir(parents=True, exist_ok=True)
    _write_proto(proto_root)

    env = {
        "MODE": "protoc",
        "LANGS": "python",
        "IN_DIRS": str(proto_root),
        "OUT_BASE": str(out_base),
        "CLEAN": "1",
        "VERBOSE": "1",
    }

    # Первый запуск
    res1 = _run(["bash", str(REL_SCRIPT)], env=env, cwd=repo_root)
    assert res1.returncode == 0, f"Первый прогон завершился с ошибкой:\n{res1.stderr}"

    # Второй запуск (без CLEAN=1, чтобы протестировать отсутствие конфликтов sequence tokens и т.п.)
    env2 = dict(env)
    env2["CLEAN"] = "0"
    res2 = _run(["bash", str(REL_SCRIPT)], env=env2, cwd=repo_root)
    assert res2.returncode == 0, f"Повторный прогон завершился с ошибкой:\n{res2.stderr}"

    py_out = out_base / "python" / "example" / "v1"
    files = sorted(p.name for p in py_out.glob("*.py"))
    assert files and "echo_pb2.py" in files and "echo_pb2_grpc.py" in files
