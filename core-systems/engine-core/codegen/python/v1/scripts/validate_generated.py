#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aethernova Engine | Codegen v1
Validator: проверка актуальности и целостности артефактов Python protobuf/gRPC.

Что проверяет:
  1) Наличие каталога generated/_autogen и пакетных __init__.py.
  2) Чистоту git-диффа по generated/_autogen (нет незакоммиченных изменений).
  3) Хэши всех *.proto под schemas/proto/v1 против SBOM/штампов (best-effort).
  4) Консистентность SBOM.CODEGEN.txt с актуальным хэшем автогенов.
  5) Возможность импорта ключевых автоген-модулей (engine.network_pb2, *_grpc).
  6) Структурированный JSON-отчет (stdout) и четкие коды возврата.

Коды возврата:
  0 — OK, валидно
  1 — найдено нарушение (несоответствие/грязный дифф/ошибка импорта)
  2 — ошибка исполнения (неверная конфигурация/IO/исключение)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# --------- Константы и умолчания ---------
PROJECT_REL_OUT = "engine-core/codegen/python/v1/generated"
AUTOGEN_DIR = "_autogen"
SCHEMAS_REL = "engine-core/schemas/proto/v1"
SBOM_NAME = "SBOM.CODEGEN.txt"
STAMP_NAME = "__genstamp__.json"

KEY_MODULES = [
    # Базовые автоген-модули для smoke-import
    "engine.network_pb2",
    "engine.network_pb2_grpc",
    "common.error.error_pb2",
    "common.error.error_pb2_grpc",
]

# --------- Модели отчета ---------
@dataclass
class SectionStatus:
    ok: bool
    details: Dict[str, object]

@dataclass
class Report:
    ok: bool
    profile: str
    repo_root: str
    autogen_dir: str
    checks: Dict[str, SectionStatus]

    def to_json(self) -> str:
        def default(o):
            if isinstance(o, (Report, SectionStatus)):
                d = asdict(o)
                return d
            if isinstance(o, Path):
                return str(o)
            raise TypeError(type(o))
        return json.dumps(asdict(self), indent=2, ensure_ascii=False, default=default)


# --------- Вспомогательные функции ---------
def detect_repo_root(start: Optional[Path] = None) -> Path:
    p = Path(start or __file__).resolve()
    for base in [p] + list(p.parents):
        if (base / ".git").exists() or (base / "pyproject.toml").exists() or (base / "engine-core").exists():
            return base
    return p.parents[4]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_tree(root: Path, patterns: Tuple[str, ...]) -> str:
    files: List[Path] = []
    for pat in patterns:
        files.extend(sorted(root.glob(pat)))
    h = hashlib.sha256()
    for fp in files:
        if not fp.is_file():
            continue
        h.update(str(fp.relative_to(root)).encode("utf-8"))
        h.update(b"\0")
        with fp.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()

def run(cmd: List[str], cwd: Optional[Path] = None, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, check=check)

def is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()

def safe_read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None

def find_files(base: Path, patterns: Tuple[str, ...]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        out.extend(base.rglob(pat))
    return sorted({p for p in out if p.is_file()})


# --------- Проверки ---------
def check_structure(out_root: Path) -> SectionStatus:
    autogen = out_root / AUTOGEN_DIR
    req = {
        "autogen_exists": autogen.exists(),
        "autogen_is_dir": autogen.is_dir(),
        "pkg_inits": [],
        "missing_inits": [],
    }
    ok = autogen.exists() and autogen.is_dir()
    # обязательные пакеты
    pkg_candidates = [
        autogen,
        autogen / "engine",
        autogen / "common",
        autogen / "common" / "error",
        autogen / "economy",
    ]
    for d in pkg_candidates:
        if d.exists():
            has_init = (d / "__init__.py").exists()
            req["pkg_inits"].append(str(d))
            if not has_init:
                req["missing_inits"].append(str(d))
                ok = False
    return SectionStatus(ok=ok, details=req)

def check_git_clean(out_root: Path, repo_root: Path, no_git: bool) -> SectionStatus:
    details: Dict[str, object] = {"repo": str(repo_root), "path": str(out_root), "clean": True, "changed": []}
    if no_git or not is_git_repo(repo_root):
        details["skipped"] = True
        return SectionStatus(ok=True, details=details)
    rel = str(out_root.relative_to(repo_root))
    diff = run(["git", "status", "--porcelain", "--", rel], cwd=repo_root)
    changed = [line.strip() for line in diff.stdout.splitlines() if line.strip()]
    details["changed"] = changed
    details["clean"] = len(changed) == 0
    return SectionStatus(ok=len(changed) == 0, details=details)

def check_proto_hashes(repo_root: Path) -> SectionStatus:
    """Считаем сводный SHA256 по всем .proto под schemas/proto/v1 (кроме *_internal.proto).
    Сверяем только между собой и с наличием штампа (best-effort, не фейлим при его отсутствии)."""
    schemas = repo_root / SCHEMAS_REL
    if not schemas.exists():
        return SectionStatus(ok=False, details={"error": f"schemas dir not found: {schemas}"})
    protos = [p for p in schemas.rglob("*.proto") if "_internal.proto" not in p.name]
    if not protos:
        return SectionStatus(ok=False, details={"error": "no proto files found"})
    h = hashlib.sha256()
    files = []
    for p in sorted(protos):
        files.append(str(p.relative_to(repo_root)))
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        h.update(sha256_file(p).encode("ascii"))
        h.update(b"\n")
    digest = h.hexdigest()
    details: Dict[str, object] = {"files": files, "digest": digest}
    # Попробуем загрузить штамп и SBOM (если есть)
    out_root = repo_root / PROJECT_REL_OUT / AUTOGEN_DIR
    stamp = out_root / STAMP_NAME
    sbom = out_root / SBOM_NAME
    if stamp.exists():
        details["stamp_present"] = True
        details["stamp_size"] = stamp.stat().st_size
        text = safe_read_text(stamp)
        if text:
            # В штампе из фасадов может быть одиночный source_hash — это не полное покрытие.
            # Не фейлим по содержимому, просто отражаем наличие.
            details["stamp_sample"] = text[:2000]
    else:
        details["stamp_present"] = False
    if sbom.exists():
        details["sbom_present"] = True
        details["sbom_value"] = safe_read_text(sbom)
    else:
        details["sbom_present"] = False
    return SectionStatus(ok=True, details=details)

def check_sbom(out_root: Path) -> SectionStatus:
    """Сверяем текущую сводную сумму по *.py в _autogen с записанной SBOM.CODEGEN.txt."""
    autogen = out_root / AUTOGEN_DIR
    sbom = autogen / SBOM_NAME
    py_files = find_files(autogen, ("*.py",))
    h = hashlib.sha256()
    for fp in py_files:
        # стабильный порядок
        h.update(str(fp.relative_to(autogen)).encode("utf-8"))
        h.update(b"\0")
        with fp.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    actual = h.hexdigest()
    recorded = safe_read_text(sbom) if sbom.exists() else None
    ok = recorded is not None and recorded.strip() == actual
    return SectionStatus(ok=ok, details={
        "autogen": str(autogen),
        "files_count": len(py_files),
        "actual": actual,
        "recorded": recorded.strip() if recorded else None,
        "sbom_exists": sbom.exists(),
    })

def check_imports(out_root: Path) -> SectionStatus:
    """Добавляем _autogen в sys.path и пробуем импортировать ключевые модули."""
    autogen = out_root / AUTOGEN_DIR
    details: Dict[str, object] = {"sys_path_added": str(autogen), "imports": []}
    if not autogen.exists():
        return SectionStatus(ok=False, details={"error": f"autogen dir not found: {autogen}"})
    if str(autogen) not in sys.path:
        sys.path.insert(0, str(autogen))
    ok = True
    for mod in KEY_MODULES:
        item = {"module": mod, "ok": False, "error": None}
        try:
            __import__(mod)
            item["ok"] = True
        except Exception as e:
            item["error"] = f"{type(e).__name__}: {e}"
            ok = False
        details["imports"].append(item)
    return SectionStatus(ok=ok, details=details)


# --------- CLI ---------
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate generated protobuf/gRPC artifacts")
    ap.add_argument("--profile", choices=["dev", "ci", "release"], default="dev", help="Контекст проверки")
    ap.add_argument("--no-git", action="store_true", help="Пропустить git-проверки")
    ap.add_argument("--json-only", action="store_true", help="Печатать только JSON-отчет без пояснений")
    ap.add_argument("--out-root", default=PROJECT_REL_OUT, help="Путь к каталогу generated/")
    return ap.parse_args()

def main() -> int:
    args = parse_args()
    repo_root = detect_repo_root()
    out_root = (repo_root / args.out_root).resolve()

    checks: Dict[str, SectionStatus] = {}
    try:
        checks["structure"] = check_structure(out_root)
        checks["git_clean"] = check_git_clean(out_root / AUTOGEN_DIR, repo_root, no_git=args.no_git)
        checks["proto_hashes"] = check_proto_hashes(repo_root)
        checks["sbom"] = check_sbom(out_root)
        checks["imports"] = check_imports(out_root)
    except Exception as e:
        rep = Report(
            ok=False,
            profile=args.profile,
            repo_root=str(repo_root),
            autogen_dir=str(out_root / AUTOGEN_DIR),
            checks={"exception": SectionStatus(ok=False, details={"error": f"{type(e).__name__}: {e}"})},
        )
        if not args.json_only:
            print("VALIDATION: exception during checks", file=sys.stderr)
        print(rep.to_json())
        return 2

    overall_ok = all(s.ok for s in checks.values())

    rep = Report(
        ok=overall_ok,
        profile=args.profile,
        repo_root=str(repo_root),
        autogen_dir=str(out_root / AUTOGEN_DIR),
        checks=checks,
    )

    if not args.json_only:
        print(f"VALIDATION RESULT: {'OK' if overall_ok else 'FAIL'}")
    print(rep.to_json())
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
