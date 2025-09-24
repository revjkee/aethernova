# neuroforge/registry/packager.py
from __future__ import annotations

import concurrent.futures as cf
import contextlib
import dataclasses
import fnmatch
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# Optional compressors / storages
try:
    import zstandard as zstd  # type: ignore
except Exception:  # pragma: no cover
    zstd = None  # type: ignore

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

try:
    from google.cloud import storage as gcs  # type: ignore
except Exception:  # pragma: no cover
    gcs = None  # type: ignore


# ============================== Data classes ==================================

@dataclass(frozen=True)
class FileSpec:
    """Источник для упаковки: файл или директория."""
    path: Path
    arcbase: Optional[str] = None  # переопределить базовый путь в архиве (поддиректория)

@dataclass(frozen=True)
class PackageSpec:
    """
    Описание пакета NeuroForge.
    - name/version — обязательны (semver или pep440; валидация мягкая).
    - sources — список исходников (файлы/директории).
    - excludes_glob — паттерны исключений (сравниваются по относительному пути).
    - excludes_regex — регулярные исключения.
    - follow_symlinks — сохранять реальный файл вместо симлинка.
    - deterministic_ts — mtime для воспроизводимости (если None — SOURCE_DATE_EPOCH|0).
    """
    name: str
    version: str
    sources: Sequence[FileSpec]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    excludes_glob: Sequence[str] = field(default_factory=lambda: ["**/.git/**", "**/__pycache__/**", "**/*.tmp"])
    excludes_regex: Sequence[str] = field(default_factory=tuple)
    follow_symlinks: bool = False
    deterministic_ts: Optional[int] = None  # POSIX seconds

@dataclass(frozen=True)
class PackagerConfig:
    """
    Настройки упаковки:
    - compression: 'gz'|'zstd'|'none'
    - level: уровень компрессии
    - root_dir: корневая директория внутри архива; по умолчанию "<name>-<version>"
    - parallel_hash_workers: число потоков хеширования
    - hmac_key_env: имя переменной окружения для HMAC подписи манифеста
    """
    compression: str = "gz"
    level: int = 6
    root_dir: Optional[str] = None
    parallel_hash_workers: int = max(1, os.cpu_count() or 1)
    hmac_key_env: str = "PACKAGER_SIGN_KEY"

@dataclass(frozen=True)
class FileRecord:
    path: str          # относительный путь внутри архива (root_dir/..)
    size: int
    mode: int
    mtime: int
    sha256: str
    link: Optional[str] = None  # если симлинк

@dataclass(frozen=True)
class Manifest:
    api_version: str
    name: str
    version: str
    created_at: str
    files: Sequence[FileRecord]
    total_size: int
    metadata: Mapping[str, Any]
    root_dir: str
    compression: str

@dataclass(frozen=True)
class PackageResult:
    artifact_path: Path
    artifact_sha256: str
    bytes_written: int
    manifest: Manifest
    signature_hex: Optional[str] = None


# ================================ Utilities ===================================

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _deterministic_mtime(spec: PackageSpec) -> int:
    if spec.deterministic_ts is not None:
        return int(spec.deterministic_ts)
    sde = os.getenv("SOURCE_DATE_EPOCH")
    return int(sde) if sde and sde.isdigit() else 0  # 1970-01-01

def _norm_arcname(s: str) -> str:
    s = s.replace("\\", "/")
    s = s.lstrip("/")
    s = re.sub(r"/+", "/", s)
    if s == "":
        s = "."
    return s

def _is_excluded(rel: str, excludes_glob: Sequence[str], excludes_regex: Sequence[str]) -> bool:
    for pat in excludes_glob:
        if fnmatch.fnmatch(rel, pat):
            return True
    for rx in excludes_regex:
        if re.search(rx, rel):
            return True
    return False

def _safe_walk(base: Path) -> Iterable[Path]:
    """Безопасный обход: игнорируем спецфайлы/устройства/сокеты."""
    base = base.resolve()
    for p in sorted(base.rglob("*")):
        try:
            st = p.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or stat.S_ISDIR(st.st_mode):
            yield p
        # игнорируем остальное

def _sha256_file(path: Path) -> Tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            h.update(chunk)
    return size, h.hexdigest()

def _hmac_sha256(data: bytes, key: bytes) -> str:
    import hmac
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def _ensure_parent(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def _select_root_dir(spec: PackageSpec, cfg: PackagerConfig) -> str:
    return cfg.root_dir or f"{spec.name}-{spec.version}"

def _validate_name_ver(name: str, version: str) -> None:
    if not re.match(r"^[A-Za-z0-9._\-]+$", name or ""):
        raise ValueError("Invalid package name")
    # мягкая проверка semver/pep440
    if not re.match(r"^[0-9A-Za-z.\-+!]+$", version or ""):
        raise ValueError("Invalid version string")

# ================================ Storages ====================================

class StorageAdapter:
    """Интерфейс для выгрузки артефакта по URI."""
    def upload_file(self, src: Path, uri: str) -> None:  # pragma: no cover
        raise NotImplementedError

class FilesystemStorage(StorageAdapter):
    def upload_file(self, src: Path, uri: str) -> None:
        # uri вида: file:///abs/path/to/dir/ или просто /abs/path/to/dir/
        target = uri
        if uri.startswith("file://"):
            target = uri[7:]
        d = Path(target)
        d.mkdir(parents=True, exist_ok=True)
        dst = d / src.name
        data = src.read_bytes()
        (d / src.name).write_bytes(data)

class S3Storage(StorageAdapter):
    def __init__(self) -> None:
        if boto3 is None:
            raise RuntimeError("boto3 is required for s3:// uploads")
        self._s3 = boto3.client("s3")

    def upload_file(self, src: Path, uri: str) -> None:
        # s3://bucket/prefix/
        m = re.match(r"^s3://([^/]+)/?(.*)$", uri)
        if not m:
            raise ValueError("Invalid s3 URI")
        bucket, prefix = m.group(1), m.group(2) or ""
        key = f"{prefix.rstrip('/')}/{src.name}" if prefix else src.name
        self._s3.upload_file(str(src), bucket, key)

class GCSStorage(StorageAdapter):
    def __init__(self) -> None:
        if gcs is None:
            raise RuntimeError("google-cloud-storage is required for gs:// uploads")
        self._client = gcs.Client()

    def upload_file(self, src: Path, uri: str) -> None:
        # gs://bucket/prefix/
        m = re.match(r"^gs://([^/]+)/?(.*)$", uri)
        if not m:
            raise ValueError("Invalid gs URI")
        bucket_name, prefix = m.group(1), m.group(2) or ""
        bucket = self._client.bucket(bucket_name)
        blob = bucket.blob(f"{prefix.rstrip('/')}/{src.name}" if prefix else src.name)
        blob.upload_from_filename(str(src))

def get_storage_for_uri(uri: Optional[str]) -> Optional[StorageAdapter]:
    if not uri:
        return None
    if uri.startswith("s3://"):
        return S3Storage()
    if uri.startswith("gs://"):
        return GCSStorage()
    if uri.startswith("file://") or uri.startswith("/") or re.match(r"^[A-Za-z]:\\", uri):
        return FilesystemStorage()
    raise ValueError(f"Unsupported storage URI: {uri}")


# ================================ Packager ====================================

class Packager:
    """
    Упаковщик NeuroForge:
      1) Собирает список файлов (с фильтрами).
      2) Считает SHA-256 параллельно.
      3) Генерирует manifest.json и sbom.spdx.json.
      4) Формирует tar (+gzip|zstd) со строгими атрибутами и добавляет служебные файлы.
      5) Опционально подписывает манифест HMAC и выгружает артефакт.
    """

    API_VERSION = "nf.pkg/v1"

    def __init__(self, cfg: Optional[PackagerConfig] = None):
        self.cfg = cfg or PackagerConfig()

    def build(self, spec: PackageSpec, dest_dir: Path, upload_uri: Optional[str] = None) -> PackageResult:
        _validate_name_ver(spec.name, spec.version)
        mtime = _deterministic_mtime(spec)
        root_dir = _select_root_dir(spec, self.cfg)

        # 1) Собираем канонический список файлов
        files_abs: List[Tuple[Path, str]] = []  # (abs_path, arc_path relative to root_dir)
        for src in spec.sources:
            base = src.path
            arcbase = _norm_arcname(src.arcbase or base.name)
            if not base.exists():
                raise FileNotFoundError(str(base))
            base = base.resolve()
            if base.is_file():
                rel = base.name
                rel_arc = _norm_arcname(f"{arcbase}/{rel}")
                if _is_excluded(rel, spec.excludes_glob, spec.excludes_regex):
                    continue
                files_abs.append((base, rel_arc))
            else:
                for p in _safe_walk(base):
                    rel = str(p.relative_to(base))
                    rel_arc = _norm_arcname(f"{arcbase}/{rel}")
                    if _is_excluded(rel_arc, spec.excludes_glob, spec.excludes_regex):
                        continue
                    # Директории в манифест не добавляем как файлы; но создадим их в tar при необходимости
                    if p.is_dir():
                        continue
                    files_abs.append((p, rel_arc))

        # 2) Параллельное хеширование
        records: List[FileRecord] = []
        total_size = 0

        def _hash_one(item: Tuple[Path, str]) -> Tuple[FileRecord, int]:
            p, arc = item
            st = p.lstat()
            mode = 0o644
            link = None
            size = 0
            digest = "0" * 64
            if stat.S_ISLNK(st.st_mode):
                link = os.readlink(p)
                # для симлинков хешируем строку цели
                digest = hashlib.sha256(link.encode("utf-8")).hexdigest()
            elif stat.S_ISREG(st.st_mode):
                size, digest = _sha256_file(p)
            else:
                # игнор
                return None, 0  # type: ignore
            rec = FileRecord(
                path=f"{root_dir}/{arc}",
                size=size,
                mode=mode,
                mtime=mtime,
                sha256=digest,
                link=link,
            )
            return rec, size

        with cf.ThreadPoolExecutor(max_workers=self.cfg.parallel_hash_workers) as ex:
            futures = [ex.submit(_hash_one, item) for item in files_abs]
            for fut in cf.as_completed(futures):
                rec, sz = fut.result()
                if rec is not None:
                    records.append(rec)
                    total_size += sz

        records.sort(key=lambda r: r.path)

        # 3) Генерация манифеста и SBOM
        manifest = Manifest(
            api_version=self.API_VERSION,
            name=spec.name,
            version=spec.version,
            created_at=_utcnow_iso(),
            files=tuple(records),
            total_size=total_size,
            metadata=dict(spec.metadata),
            root_dir=root_dir,
            compression=self.cfg.compression,
        )
        manifest_bytes = json.dumps(dataclasses.asdict(manifest), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sbom_bytes = _make_min_spdx_sbom(spec, manifest).encode("utf-8")

        # 4) HMAC подпись манифеста (опционально)
        signature_hex: Optional[str] = None
        hkey_env = os.getenv(self.cfg.hmac_key_env)
        if hkey_env:
            key = hkey_env.encode("utf-8")
            signature_hex = _hmac_sha256(manifest_bytes, key)

        # 5) Формирование архива
        artifact_name = f"{spec.name}-{spec.version}.tar"
        if self.cfg.compression == "gz":
            artifact_name += ".gz"
        elif self.cfg.compression == "zstd":
            artifact_name += ".zst"

        dest_dir = Path(dest_dir).resolve()
        _ensure_parent(dest_dir / "dummy")
        out_path = dest_dir / artifact_name

        bytes_written = self._write_archive(
            out_path=out_path,
            files=files_abs,
            manifest_bytes=manifest_bytes,
            sbom_bytes=sbom_bytes,
            signature_hex=signature_hex,
            root_dir=root_dir,
            mtime=mtime,
        )

        # 6) Хеш всего архива
        artifact_sha256 = _sha256_file(out_path)[1]

        # 7) Загрузка (если указано)
        if upload_uri:
            storage = get_storage_for_uri(upload_uri)
            if storage:
                storage.upload_file(out_path, upload_uri)

        return PackageResult(
            artifact_path=out_path,
            artifact_sha256=artifact_sha256,
            bytes_written=bytes_written,
            manifest=manifest,
            signature_hex=signature_hex,
        )

    def verify(self, artifact_path: Path) -> Tuple[bool, str]:
        """
        Проверяет целостность архива: сверяет хеши файлов с манифестом.
        Возвращает (ok, message).
        """
        artifact_path = Path(artifact_path)
        if not artifact_path.exists():
            return False, "Artifact not found"
        # раскрываем tar (gzip/zstd/none распознаём по расширению)
        try:
            fileobj, tf = _open_tar_for_read(artifact_path)
        except Exception as exc:
            return False, f"Open error: {exc}"

        with contextlib.ExitStack() as es:
            if fileobj:
                es.enter_context(fileobj)
            es.enter_context(tf)
            # читаем manifest.json
            try:
                m = tf.extractfile("manifest.json")
                if m is None:
                    return False, "manifest.json missing"
                manifest = json.loads(m.read().decode("utf-8"))
                files = manifest.get("files", [])
            except Exception as exc:
                return False, f"Manifest read error: {exc}"

            # сверяем каждый файл
            for rec in files:
                p = rec["path"]
                if p.endswith("/"):  # директория
                    continue
                ti = tf.getmember(p) if p in tf.getnames() else None
                if not ti:
                    return False, f"Missing member: {p}"
                if ti.issym():
                    # для симлинков сверяем цель
                    target = ti.linkname
                    if hashlib.sha256(target.encode("utf-8")).hexdigest() != rec["sha256"]:
                        return False, f"Symlink hash mismatch: {p}"
                elif ti.isfile():
                    f = tf.extractfile(ti)
                    if f is None:
                        return False, f"Cannot read: {p}"
                    h = hashlib.sha256()
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                    if h.hexdigest() != rec["sha256"]:
                        return False, f"Hash mismatch: {p}"
                # остальное игнор
            return True, "ok"

    # ---------------------------- internals -----------------------------------

    def _write_archive(
        self,
        out_path: Path,
        files: List[Tuple[Path, str]],
        manifest_bytes: bytes,
        sbom_bytes: bytes,
        signature_hex: Optional[str],
        root_dir: str,
        mtime: int,
    ) -> int:
        mode = self.cfg.compression
        bytes_written = 0

        if mode == "gz":
            with open(out_path, "wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=int(self.cfg.level), mtime=mtime) as gz:
                    with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                        bytes_written = self._fill_tar(tf, files, manifest_bytes, sbom_bytes, signature_hex, root_dir, mtime)
        elif mode == "zstd":
            if zstd is None:
                raise RuntimeError("zstandard not available; install `zstandard` or use compression='gz'|'none'")
            cctx = zstd.ZstdCompressor(level=int(self.cfg.level))
            with open(out_path, "wb") as raw:
                with cctx.stream_writer(raw) as zw:
                    with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                        bytes_written = self._fill_tar(tf, files, manifest_bytes, sbom_bytes, signature_hex, root_dir, mtime)
        else:
            with tarfile.open(out_path, mode="w", format=tarfile.PAX_FORMAT) as tf:
                bytes_written = self._fill_tar(tf, files, manifest_bytes, sbom_bytes, signature_hex, root_dir, mtime)

        return bytes_written

    def _fill_tar(
        self,
        tf: tarfile.TarFile,
        files: List[Tuple[Path, str]],
        manifest_bytes: bytes,
        sbom_bytes: bytes,
        signature_hex: Optional[str],
        root_dir: str,
        mtime: int,
    ) -> int:
        written = 0

        # 0) Добавим корневую директорию (deterministic)
        root_ti = tarfile.TarInfo(name=_norm_arcname(root_dir))
        root_ti.type = tarfile.DIRTYPE
        root_ti.mode = 0o755
        root_ti.uid = 0
        root_ti.gid = 0
        root_ti.uname = "root"
        root_ti.gname = "root"
        root_ti.mtime = mtime
        tf.addfile(root_ti)

        # 1) Файлы
        for abs_path, arc_rel in files:
            arc_path = _norm_arcname(f"{root_dir}/{arc_rel}")
            st = abs_path.lstat()
            if stat.S_ISLNK(st.st_mode):
                # симлинк (сохраняем линк как есть, без follow)
                target = os.readlink(abs_path)
                ti = tarfile.TarInfo(name=arc_path)
                ti.type = tarfile.SYMTYPE
                ti.linkname = target
                ti.mode = 0o777
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mtime = mtime
                tf.addfile(ti)
            elif stat.S_ISREG(st.st_mode):
                ti = tarfile.TarInfo(name=arc_path)
                ti.size = st.st_size
                ti.mode = 0o644
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mtime = mtime
                with abs_path.open("rb") as f:
                    tf.addfile(ti, fileobj=f)
                written += st.st_size
            elif stat.S_ISDIR(st.st_mode):
                # для полноты — если директория встретилась
                di = tarfile.TarInfo(name=arc_path)
                di.type = tarfile.DIRTYPE
                di.mode = 0o755
                di.uid = 0
                di.gid = 0
                di.uname = "root"
                di.gname = "root"
                di.mtime = mtime
                tf.addfile(di)
            # остальное — пропускаем

        # 2) Служебные файлы в корень архива
        def _add_bytes(name: str, data: bytes, mode: int = 0o644) -> None:
            ti = tarfile.TarInfo(name=_norm_arcname(name))
            ti.size = len(data)
            ti.mode = mode
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            ti.mtime = mtime
            tf.addfile(ti, io.BytesIO(data))

        _add_bytes("manifest.json", manifest_bytes)
        _add_bytes("sbom.spdx.json", sbom_bytes)
        if signature_hex:
            _add_bytes("SIGNATURE.hmac", signature_hex.encode("ascii"), mode=0o600)

        return written


# ================================ SBOM ========================================

def _make_min_spdx_sbom(spec: PackageSpec, manifest: Manifest) -> str:
    """
    Минимальный SPDX-совместимый JSON SBOM (не полный SPDX, но совместим для парсеров).
    """
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{spec.name}-{spec.version}",
        "documentNamespace": f"https://sbom.neuroforge.local/{spec.name}/{spec.version}/{int(time.time())}",
        "creationInfo": {
            "created": _utcnow_iso(),
            "creators": ["Tool: neuroforge-packager"],
        },
        "packages": [
            {
                "name": spec.name,
                "SPDXID": "SPDXRef-Package",
                "versionInfo": spec.version,
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "originator": "Organization: NeuroForge",
                "supplier": "Organization: NeuroForge",
                "externalRefs": [],
                "hasFiles": [
                    {
                        "fileName": rec.path,
                        "SPDXID": f"SPDXRef-File-{i}",
                        "checksums": [{"algorithm": "SHA256", "checksumValue": rec.sha256}],
                    }
                    for i, rec in enumerate(manifest.files)
                ],
            }
        ],
    }
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


# ================================ Tar reading =================================

def _open_tar_for_read(path: Path) -> Tuple[Optional[Any], tarfile.TarFile]:
    """
    Возвращает (fileobj, TarFile) для чтения tar[.gz|.zst]
    """
    suffix = "".join(path.suffixes[-2:]) if len(path.suffixes) >= 2 else (path.suffixes[-1] if path.suffixes else "")
    if suffix.endswith(".tar.gz") or path.suffix == ".gz":
        f = open(path, "rb")
        gz = gzip.GzipFile(fileobj=f, mode="rb")
        tf = tarfile.open(fileobj=gz, mode="r|")
        return contextlib.ExitStack().enter_context(contextlib.ExitStack()), tf  # dummy; handled by caller
    if suffix.endswith(".tar.zst") or path.suffix == ".zst":
        if zstd is None:
            raise RuntimeError("zstandard not available")
        f = open(path, "rb")
        dctx = zstd.ZstdDecompressor()
        r = dctx.stream_reader(f)
        tf = tarfile.open(fileobj=r, mode="r|")
        # caller must close both r and f; we return only tf and manage in verify()
        return None, tf
    return None, tarfile.open(path, mode="r")


# ================================ Example usage ===============================

# Пример:
# spec = PackageSpec(
#     name="neuroforge-core",
#     version="1.2.3",
#     sources=[FileSpec(Path("models"), "models"), FileSpec(Path("scripts"), "scripts")],
#     metadata={"owner": "ml-team", "model": "bert"},
# )
# res = Packager().build(spec, Path("./dist"), upload_uri="s3://my-bucket/artifacts/")
# ok, msg = Packager().verify(res.artifact_path)
# assert ok, msg
