#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuroForge Model Packager (package_model.py)
Промышленный CLI для упаковки ML-моделей и артефактов в воспроизводимые пакеты.

Возможности:
- Детерминированная упаковка (zip или tar.gz) с фиксированными метаданными
- manifest.json: полные хеши (SHA256/SHA3), размеры, список файлов, платформа, git-коммит, семантическая версия
- Автодетект фреймворка/формата (PyTorch/TensorFlow/ONNX/sklearn/XGBoost/Custom)
- Опциональная подпись манифеста через gpg (detached .sig) при наличии gpg в системе
- Верификация пакета (хеши, подпись, целостность)
- Опциональная генерация SBOM (CycloneDX-like JSON) на основе pip freeze или requirements.txt
- JSON-логирование, коды выхода, строгие ошибки, без обязательных внешних зависимостей (yaml — опционально)

Примеры:
  # Сборка tar.gz с автоимёнованием
  python package_model.py build -i ./model_dir --arch tar.gz

  # Явное имя пакета и версия
  python package_model.py build -i ./model_dir -o dist/my-model-1.2.3.neuroforge.tgz --name my-model --version 1.2.3

  # С включениями/исключениями и детерминированной сборкой
  python package_model.py build -i ./model_dir --include "**/*.pt" --include "config/**" \
      --exclude "**/__pycache__/**" --deterministic

  # Подпись манифеста (если установлен gpg и доступен secret key)
  python package_model.py build -i ./model_dir --sign-pgp "KEYID_OR_EMAIL"

  # Верификация созданного пакета
  python package_model.py verify -p dist/my-model-1.2.3.neuroforge.zip

Коды выхода:
  0 - успех; 1 - ошибка валидации/аргументов; 2 - ошибка сборки/IO; 3 - ошибка верификации.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import dataclasses
import fnmatch
import hashlib
import json
import logging
import mimetypes
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------
# Опциональные зависимости
# --------------------
try:
    import yaml  # type: ignore
    _YAML = True
except Exception:
    _YAML = False

# --------------------
# Константы
# --------------------
DEFAULT_INCLUDES = [
    "**/*.pt", "**/*.pth", "**/*.bin", "**/*.safetensors",
    "**/*.onnx", "**/*.pb", "**/*.h5", "**/*.tflite",
    "**/*.pkl", "**/*.joblib", "**/tokenizer.json",
    "**/config.json", "**/*.json", "**/*.yml", "**/*.yaml",
    "**/*.txt", "**/*.md", "**/*.py", "assets/**", "config/**"
]
DEFAULT_EXCLUDES = [
    "**/.git/**", "**/.gitignore", "**/.gitattributes", "**/.DS_Store",
    "**/__pycache__/**", "**/.ipynb_checkpoints/**", "**/*.tmp", "**/*.log"
]
SUPPORTED_ARCH = {"zip", "tar.gz"}
FIXED_EPOCH = 315532800  # 1980-01-01 UTC для zip (минимальная поддерживаемая epoc у zip)

SCHEMA_VERSION = "1.0.0"

# --------------------
# Логирование (JSON)
# --------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "name": record.name,
            "file": record.filename,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def configure_logging(verbosity: int) -> None:
    log = logging.getLogger()
    log.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    log.addHandler(h)
    log.setLevel(logging.INFO if verbosity == 0 else logging.DEBUG)

log = logging.getLogger("nf.package")

# --------------------
# Датаклассы манифеста
# --------------------
@dataclass
class FileEntry:
    path: str
    size: int
    mode: int
    sha256: str
    sha3_256: str
    mime: Optional[str] = None
    executable: bool = False

@dataclass
class Manifest:
    schema_version: str
    name: str
    version: str
    created_at: str
    platform: Dict[str, str]
    build: Dict[str, Any]
    framework: str
    model_format: str
    archive: Dict[str, Any]
    files: List[FileEntry]
    dependencies: Dict[str, Any]
    notes: Optional[str] = None

# --------------------
# Утилиты
# --------------------
def read_text_file_safe(p: Path) -> Optional[str]:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return None

def run_cmd_silent(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def get_git_commit(base: Path) -> Optional[str]:
    if not (base / ".git").exists():
        return None
    code, out, _ = run_cmd_silent(["git", "-C", str(base), "rev-parse", "HEAD"])
    return out if code == 0 else None

def normalize_posix(p: Path, base: Path) -> str:
    return p.relative_to(base).as_posix()

def match_any(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)

def discover_framework_and_format(all_files: List[Path]) -> Tuple[str, str]:
    names = {p.name.lower() for p in all_files}
    exts  = {p.suffix.lower() for p in all_files}

    # Форматы
    if ".onnx" in exts:
        model_format = "ONNX"
    elif ".pt" in exts or ".pth" in exts or ".safetensors" in exts:
        model_format = "TorchWeights"
    elif ".pb" in exts or ".h5" in exts or ".tflite" in exts:
        model_format = "TensorFlow"
    elif ".pkl" in exts or ".joblib" in exts:
        model_format = "PickleBundle"
    else:
        model_format = "Custom"

    # Фреймворки (грубая эвристика)
    if "pytorch_model.bin" in names or ".pt" in exts or ".pth" in exts or "torch_model.bin" in names:
        framework = "PyTorch"
    elif "saved_model.pb" in names or ".h5" in exts or ".tflite" in exts:
        framework = "TensorFlow/Keras"
    elif ".onnx" in exts:
        framework = "ONNX"
    elif ".pkl" in exts or ".joblib" in exts:
        framework = "Scikit-Learn/XGBoost"
    else:
        framework = "Custom"

    return framework, model_format

def iter_files(base: Path) -> List[Path]:
    return [p for p in base.rglob("*") if p.is_file()]

def filter_files(base: Path, includes: List[str], excludes: List[str]) -> List[Path]:
    all_files = iter_files(base)
    result: List[Path] = []
    for p in all_files:
        rel = normalize_posix(p, base)
        if includes:
            if not match_any(rel, includes):
                continue
        if excludes and match_any(rel, excludes):
            continue
        result.append(p)
    # если includes пуст — используем разумный дефолт
    if not includes:
        result = []
        for p in all_files:
            rel = normalize_posix(p, base)
            if match_any(rel, DEFAULT_EXCLUDES):
                continue
            result.append(p)
    return sorted(result, key=lambda x: normalize_posix(x, base))

def file_hashes(path: Path, chunk: int = 2**20) -> Tuple[str, str]:
    h1 = hashlib.sha256()
    h2 = hashlib.sha3_256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h1.update(b); h2.update(b)
    return h1.hexdigest(), h2.hexdigest()

def compute_file_entries(base: Path, files: List[Path], threads: int = 4) -> List[FileEntry]:
    entries: List[FileEntry] = []

    def work(p: Path) -> FileEntry:
        s = p.stat()
        sha256, sha3 = file_hashes(p)
        mime, _ = mimetypes.guess_type(str(p))
        exec_bit = bool(s.st_mode & stat.S_IXUSR)
        return FileEntry(
            path=normalize_posix(p, base),
            size=int(s.st_size),
            mode=stat.S_IMODE(s.st_mode),
            sha256=sha256,
            sha3_256=sha3,
            mime=mime,
            executable=exec_bit,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for entry in ex.map(work, files):
            entries.append(entry)

    return entries

def parse_meta(meta_path: Optional[Path]) -> Dict[str, Any]:
    if not meta_path:
        return {}
    if not meta_path.exists():
        raise FileNotFoundError(f"Meta file not found: {meta_path}")
    text = read_text_file_safe(meta_path) or ""
    if meta_path.suffix.lower() in (".yml", ".yaml") and _YAML:
        return yaml.safe_load(text) or {}
    try:
        return json.loads(text)
    except Exception:
        # Если yaml недоступен, а это yaml — упадём с понятной ошибкой
        if meta_path.suffix.lower() in (".yml", ".yaml"):
            raise RuntimeError("YAML metadata provided but PyYAML is not installed.")
        raise

def build_dependencies(base: Path, requirements: Optional[Path]) -> Dict[str, Any]:
    deps: Dict[str, Any] = {"source": None, "packages": []}
    text = None
    if requirements and requirements.exists():
        deps["source"] = "requirements.txt"
        text = read_text_file_safe(requirements)
        pkgs = []
        if text:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkgs.append(line)
        deps["packages"] = pkgs
        return deps
    # fallback: pip freeze
    code, out, _ = run_cmd_silent([sys.executable, "-m", "pip", "freeze"])
    if code == 0 and out:
        deps["source"] = "pip_freeze"
        deps["packages"] = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return deps

def generate_sbom(deps: Dict[str, Any]) -> Dict[str, Any]:
    # Упрощённый CycloneDX-like
    components = []
    for spec in deps.get("packages", []):
        name = spec
        version = None
        m = re.match(r"^([A-Za-z0-9_.\-]+)==(.+)$", spec)
        if m:
            name, version = m.group(1), m.group(2)
        components.append({
            "type": "library",
            "name": name,
            "version": version or "unknown",
            "purl": f"pkg:pypi/{name}@{version}" if version else None,
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{_uuid4()}",
        "version": 1,
        "components": components
    }

def _uuid4() -> str:
    import uuid
    return str(uuid.uuid4())

def sign_with_gpg(data: bytes, key: Optional[str]) -> Optional[bytes]:
    # Detached signature (binary). Требуется установленный gpg.
    code, _, _ = run_cmd_silent(["gpg", "--version"])
    if code != 0:
        log.info("gpg not found; skipping signature")
        return None
    cmd = ["gpg", "--detach-sign", "--armor", "--batch", "--yes", "-o", "-", "-"]
    if key:
        cmd = ["gpg", "--local-user", key, "--detach-sign", "--armor", "--batch", "--yes", "-o", "-", "-"]
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
        out, err = p.communicate(input=data)
        if p.returncode != 0:
            log.warning(f"gpg signature failed: {err.decode('utf-8', 'ignore')}")
            return None
        return out
    except Exception as e:
        log.warning(f"gpg invocation failed: {e}")
        return None

def deterministic_zip_write(zf: zipfile.ZipFile, src: Path, arcname: str) -> None:
    zi = zipfile.ZipInfo(filename=arcname)
    zi.date_time = time.gmtime(FIXED_EPOCH)[:6]
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = 0o644 << 16
    with src.open("rb") as f:
        zf.writestr(zi, f.read(), compress_type=zipfile.ZIP_DEFLATED)

def deterministic_tarinfo(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = 0; ti.gid = 0; ti.uname = ""; ti.gname = ""
    ti.mtime = FIXED_EPOCH
    if ti.isfile():
        ti.mode = 0o644
    elif ti.isdir():
        ti.mode = 0o755
    else:
        ti.mode = 0o644
    return ti

def build_manifest(
    name: str, version: str, base: Path, files: List[Path], entries: List[FileEntry],
    framework: str, model_format: str, arch_kind: str, archive_name: str, notes: Optional[str],
    deps: Dict[str, Any]
) -> Manifest:
    plat = {
        "os": platform.system(),
        "arch": platform.machine(),
        "python": platform.python_version(),
    }
    build = {
        "git_commit": get_git_commit(base),
        "builder": os.getenv("CI_RUNNER", "local"),
        "ci_job": os.getenv("CI_JOB_ID"),
    }
    return Manifest(
        schema_version=SCHEMA_VERSION,
        name=name,
        version=version,
        created_at=datetime.now(timezone.utc).isoformat(),
        platform=plat,
        build=build,
        framework=framework,
        model_format=model_format,
        archive={"kind": arch_kind, "file": archive_name},
        files=entries,
        dependencies=deps,
        notes=notes,
    )

def write_archive_zip(out_path: Path, base: Path, files: List[Path], deterministic: bool) -> None:
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for p in files:
            arc = normalize_posix(p, base)
            if deterministic:
                deterministic_zip_write(zf, p, arc)
            else:
                zf.write(p, arc)

def write_archive_targz(out_path: Path, base: Path, files: List[Path], deterministic: bool) -> None:
    with tarfile.open(out_path, "w:gz", format=tarfile.GNU_FORMAT, compresslevel=9) as tf:
        for p in files:
            arc = normalize_posix(p, base)
            ti = tf.gettarinfo(str(p), arcname=arc)
            if deterministic:
                ti = deterministic_tarinfo(ti)
            with p.open("rb") as f:
                tf.addfile(ti, f)

def load_name_version(meta: Dict[str, Any], fallback_dir: Path) -> Tuple[str, str]:
    name = str(meta.get("name") or fallback_dir.name)
    version = str(meta.get("version") or "0.1.0")
    return name, version

def ensure_out_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def save_text(path: Path, text: str) -> None:
    ensure_out_dir(path)
    path.write_text(text, encoding="utf-8")

def build_package(args: argparse.Namespace) -> int:
    base = Path(args.input).resolve()
    if not base.exists() or not base.is_dir():
        log.error(f"Input directory not found: {base}")
        return 1

    includes = args.include or []
    excludes = args.exclude or DEFAULT_EXCLUDES
    deterministic = bool(args.deterministic)
    arch = args.arch.lower()
    if arch not in SUPPORTED_ARCH:
        log.error(f"Unsupported archive kind: {arch}")
        return 1

    # Метаданные пользователя
    user_meta = parse_meta(Path(args.meta)) if args.meta else {}
    name = args.name or user_meta.get("name")
    version = args.version or user_meta.get("version")
    if not name or not version:
        auto_name, auto_version = load_name_version(user_meta, base)
        name = name or auto_name
        version = version or auto_version

    # Файлы
    files = filter_files(base, includes, excludes)
    if not files:
        log.error("No files selected for packaging")
        return 1

    # Входной список файлов для хеширования и манифеста
    entries = compute_file_entries(base, files, threads=max(1, args.threads))

    framework, model_fmt = discover_framework_and_format(files)
    deps = build_dependencies(base, Path(args.requirements) if args.requirements else None)

    # SBOM опционально
    sbom_obj = generate_sbom(deps) if args.sbom else None
    if sbom_obj:
        sbom_txt = json.dumps(sbom_obj, ensure_ascii=False, indent=2)
        # временный файл для включения в пакет
        tmp_sbom = base / ".nf_tmp_sbom.json"
        tmp_sbom.write_text(sbom_txt, encoding="utf-8")
        files.append(tmp_sbom)
        entries.append(FileEntry(
            path=normalize_posix(tmp_sbom, base),
            size=tmp_sbom.stat().st_size,
            mode=0o644,
            sha256=hashlib.sha256(sbom_txt.encode("utf-8")).hexdigest(),
            sha3_256=hashlib.sha3_256(sbom_txt.encode("utf-8")).hexdigest(),
            mime="application/json",
            executable=False,
        ))

    # Манифест
    # MANIFEST кладём в корень архива, поэтому добавляем в список
    manifest_path = base / ".nf_manifest.json"
    manifest = build_manifest(
        name=name, version=version, base=base, files=files, entries=entries,
        framework=framework, model_format=model_fmt, arch_kind=arch,
        archive_name="", notes=args.notes, deps=deps
    )
    manifest_json = json.dumps(asdict(manifest), ensure_ascii=False, indent=2)
    manifest_path.write_text(manifest_json, encoding="utf-8")
    files.append(manifest_path)

    # Подпись манифеста (если есть gpg)
    sig_bytes = sign_with_gpg(manifest_json.encode("utf-8"), args.sign_pgp)
    sig_path = None
    if sig_bytes:
        sig_path = base / ".nf_manifest.sig.asc"
        sig_path.write_bytes(sig_bytes)
        files.append(sig_path)

    # Имя архива
    out_path = Path(args.output) if args.output else None
    if out_path is None:
        suffix = "zip" if arch == "zip" else "tgz"
        out_dir = Path(args.dist or "dist").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{name}-{version}.neuroforge.{suffix}"

    # Запись архива
    ensure_out_dir(out_path)
    try:
        if arch == "zip":
            write_archive_zip(out_path, base, files, deterministic)
        else:
            write_archive_targz(out_path, base, files, deterministic)
    except Exception as e:
        log.error(f"Archive write failed: {e}", exc_info=True)
        return 2

    # Обновим имя архива в манифесте и перезапишем (копию положим рядом)
    final_manifest = dataclasses.replace(manifest, archive={"kind": arch, "file": out_path.name})
    manifest_export = out_path.with_suffix(out_path.suffix + ".manifest.json")
    save_text(manifest_export, json.dumps(asdict(final_manifest), ensure_ascii=False, indent=2))
    log.info(f"Package built: {out_path}")
    log.info(f"Manifest export: {manifest_export}")

    # Очистим временные файлы
    try:
        if sbom_obj and (base / ".nf_tmp_sbom.json").exists():
            (base / ".nf_tmp_sbom.json").unlink(missing_ok=True)  # type: ignore[arg-type]
        manifest_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        if sig_path:
            sig_path.unlink(missing_ok=True)  # type: ignore[arg-type]
    except Exception:
        pass

    return 0

def verify_package(args: argparse.Namespace) -> int:
    pkg = Path(args.package).resolve()
    if not pkg.exists():
        log.error(f"Package not found: {pkg}")
        return 1

    # Извлечём манифест из внешнего файла, если приложен
    ext_manifest = pkg.with_suffix(pkg.suffix + ".manifest.json")
    manifest_obj: Optional[Dict[str, Any]] = None
    if ext_manifest.exists():
        try:
            manifest_obj = json.loads(ext_manifest.read_text(encoding="utf-8"))
        except Exception:
            pass

    def read_member(path: str, reader: Any) -> Optional[bytes]:
        try:
            return reader(path)
        except KeyError:
            return None

    files_map: Dict[str, bytes] = {}

    try:
        if pkg.suffix.endswith("zip"):
            with zipfile.ZipFile(pkg, "r") as zf:
                # Попытаемся найти встроенный MANIFEST
                if manifest_obj is None:
                    for n in zf.namelist():
                        if n.endswith(".nf_manifest.json"):
                            manifest_obj = json.loads(zf.read(n).decode("utf-8"))
                            break
                # Считаем все файлы, чтобы проверить хеши
                for n in zf.namelist():
                    files_map[n] = zf.read(n)
        else:
            with tarfile.open(pkg, "r:gz") as tf:
                # Попытка найти MANIFEST
                if manifest_obj is None:
                    for m in tf.getmembers():
                        if m.name.endswith(".nf_manifest.json"):
                            f = tf.extractfile(m)
                            if f:
                                manifest_obj = json.loads(f.read().decode("utf-8"))
                            break
                for m in tf.getmembers():
                    if m.isfile():
                        f = tf.extractfile(m)
                        if f:
                            files_map[m.name] = f.read()
    except Exception as e:
        log.error(f"Failed to open package: {e}", exc_info=True)
        return 2

    if manifest_obj is None:
        log.error("Manifest not found (internal or external)")
        return 3

    # Проверка хешей
    files_section = manifest_obj.get("files", [])
    failed: List[str] = []
    for item in files_section:
        rel = item.get("path")
        if not rel:
            continue
        blob = files_map.get(rel)
        if blob is None:
            failed.append(f"missing:{rel}")
            continue
        h1 = hashlib.sha256(blob).hexdigest()
        h2 = hashlib.sha3_256(blob).hexdigest()
        if h1 != item.get("sha256"):
            failed.append(f"sha256:{rel}")
        if h2 != item.get("sha3_256"):
            failed.append(f"sha3_256:{rel}")

    if failed:
        log.error(f"Hash verification failed for: {', '.join(failed)}")
        return 3

    # Проверка подписи, если есть
    # Ищем .nf_manifest.sig.asc
    sig_path = None
    for fname in files_map.keys():
        if fname.endswith(".nf_manifest.sig.asc"):
            sig_path = fname
            break

    if sig_path:
        code, _, _ = run_cmd_silent(["gpg", "--version"])
        if code != 0:
            log.warning("gpg not available — skipping signature verification")
        else:
            # Нужен исходный контент manifest.json из пакета
            manifest_internal = None
            for k in files_map.keys():
                if k.endswith(".nf_manifest.json"):
                    manifest_internal = files_map[k]
                    break
            if manifest_internal is None:
                log.warning("Manifest content not found for signature verification")
            else:
                # gpg --verify expects files, создадим временные
                tmp_manifest = pkg.parent / (pkg.name + ".tmp.manifest")
                tmp_sig = pkg.parent / (pkg.name + ".tmp.sig")
                try:
                    tmp_manifest.write_bytes(manifest_internal)
                    tmp_sig.write_bytes(files_map[sig_path])
                    code, out, err = run_cmd_silent(["gpg", "--verify", str(tmp_sig), str(tmp_manifest)])
                    if code != 0:
                        log.error(f"Signature verification failed: {err or out}")
                        return 3
                    log.info("Signature verified successfully")
                finally:
                    tmp_manifest.unlink(missing_ok=True)  # type: ignore[arg-type]
                    tmp_sig.unlink(missing_ok=True)       # type: ignore[arg-type]

    log.info("Package verification OK")
    return 0

def export_manifest(args: argparse.Namespace) -> int:
    base = Path(args.input).resolve()
    if not base.exists() or not base.is_dir():
        log.error(f"Input directory not found: {base}")
        return 1

    includes = args.include or []
    excludes = args.exclude or DEFAULT_EXCLUDES

    files = filter_files(base, includes, excludes)
    if not files:
        log.error("No files selected")
        return 1

    entries = compute_file_entries(base, files, threads=max(1, args.threads))
    framework, model_fmt = discover_framework_and_format(files)

    user_meta = parse_meta(Path(args.meta)) if args.meta else {}
    name = args.name or user_meta.get("name") or base.name
    version = args.version or user_meta.get("version") or "0.1.0"
    deps = build_dependencies(base, Path(args.requirements) if args.requirements else None)

    manifest = build_manifest(
        name=name, version=version, base=base, files=files, entries=entries,
        framework=framework, model_format=model_fmt, arch_kind=args.arch.lower(),
        archive_name="", notes=args.notes, deps=deps
    )
    out = Path(args.output) if args.output else Path("manifest.json").resolve()
    save_text(out, json.dumps(asdict(manifest), ensure_ascii=False, indent=2))
    log.info(f"Manifest written: {out}")
    return 0

# --------------------
# CLI
# --------------------
def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="package_model", description="NeuroForge model packager")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (repeat for more)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-i", "--input", required=True, help="Input model directory")
    common.add_argument("--include", action="append", help="Glob to include (repeatable)")
    common.add_argument("--exclude", action="append", help="Glob to exclude (repeatable)")
    common.add_argument("--name", help="Model name (override)")
    common.add_argument("--version", help="Model version (override)")
    common.add_argument("--meta", help="Path to JSON/YAML meta to merge")
    common.add_argument("--requirements", help="Path to requirements.txt")
    common.add_argument("--notes", help="Notes field for manifest")
    common.add_argument("--threads", type=int, default=4, help="Hashing threads")
    common.add_argument("--arch", choices=list(SUPPORTED_ARCH), default="tar.gz", help="Archive type")

    b = sub.add_parser("build", parents=[common], help="Build package")
    b.add_argument("-o", "--output", help="Output file (default: dist/<name>-<version>.neuroforge.{zip|tgz})")
    b.add_argument("--dist", help="Output directory (default: dist/)")
    b.add_argument("--deterministic", action="store_true", help="Deterministic archive metadata")
    b.add_argument("--sbom", action="store_true", help="Include SBOM (CycloneDX-like)")
    b.add_argument("--sign-pgp", nargs="?", const="", help="Sign manifest with gpg (optional key id/email)")

    v = sub.add_parser("verify", help="Verify package integrity and signature")
    v.add_argument("-p", "--package", required=True, help="Path to package (.zip or .tgz)")

    m = sub.add_parser("manifest", parents=[common], help="Generate manifest only (no archive)")
    m.add_argument("-o", "--output", help="Output manifest path (default: ./manifest.json)")

    return p

def main(argv: Optional[List[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        if args.cmd == "build":
            return build_package(args)
        elif args.cmd == "verify":
            return verify_package(args)
        elif args.cmd == "manifest":
            return export_manifest(args)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        log.error("Interrupted by user")
        return 1
    except Exception as e:
        log.error(f"Unhandled error: {e}", exc_info=True)
        return 2

if __name__ == "__main__":
    sys.exit(main())
