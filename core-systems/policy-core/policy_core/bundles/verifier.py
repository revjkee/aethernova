# policy_core/bundles/verifier.py
from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import io
import json
import logging
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Зависимости: pydantic v2 (модели/валидация), cryptography (подпись) — опционально
from pydantic import BaseModel, Field, RootModel, ValidationError, field_validator, computed_field

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding, ec
    from cryptography.exceptions import InvalidSignature
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False
    InvalidSignature = Exception  # fallback type


# ==========================
#         Models
# ==========================

class Severity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"


class Issue(BaseModel):
    severity: Severity
    code: str
    message: str
    path: Optional[str] = None


class SignatureAlgo(str, Enum):
    ed25519 = "ed25519"
    rs256 = "rs256"     # RSA PKCS1v1.5 SHA-256
    rsapss256 = "rsapss256"  # RSA-PSS SHA-256
    es256 = "es256"     # ECDSA P-256 SHA-256


class FileEntry(BaseModel):
    path: str
    sha256: str
    size: int
    mode: Optional[str] = None

    @field_validator("path")
    @classmethod
    def _no_abs_or_parent(cls, v: str) -> str:
        if v.startswith(("/", "\\")) or (".." + os.sep) in v or v.startswith("../"):
            raise ValueError("Manifest contains unsafe path")
        return v.replace("\\", "/")

    @field_validator("sha256")
    @classmethod
    def _sha256_len(cls, v: str) -> str:
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError("sha256 must be 64 hex chars")
        return v

    @field_validator("size")
    @classmethod
    def _size_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError("size must be >= 0")
        return v


class BundleInfo(BaseModel):
    name: str
    version: str
    created_at: str  # ISO8601; строгую проверку оставляем внешнему коду при необходимости


class EngineConstraints(BaseModel):
    min_version: Optional[str] = None
    max_version: Optional[str] = None

    def is_compatible(self, engine_version: Optional[str]) -> Tuple[bool, str]:
        if engine_version is None:
            return True, "engine_version not provided — skipping compatibility check"
        # Простейшее сравнение версий: разбиваем на числовые компоненты.
        def _parse(v: str) -> Tuple[int, ...]:
            parts: List[int] = []
            for p in v.split("."):
                try:
                    parts.append(int(p))
                except ValueError:
                    # обрезаем суффиксы (e.g., -rc1)
                    num = "".join(ch for ch in p if ch.isdigit())
                    parts.append(int(num) if num else 0)
            return tuple(parts)

        ev = _parse(engine_version)
        if self.min_version:
            if ev < _parse(self.min_version):
                return False, f"engine_version {engine_version} < min_version {self.min_version}"
        if self.max_version:
            if ev > _parse(self.max_version):
                return False, f"engine_version {engine_version} > max_version {self.max_version}"
        return True, "compatible"


class SignatureMeta(BaseModel):
    algo: SignatureAlgo = Field(default=SignatureAlgo.ed25519)
    key_id: Optional[str] = None
    sig_format: str = Field(default="raw")  # raw|base64|jws (поддерживаем raw/base64)


class BundleManifest(BaseModel):
    bundle: BundleInfo
    engine: Optional[EngineConstraints] = None
    files: List[FileEntry]
    signature: Optional[SignatureMeta] = None

    @computed_field
    @property
    def file_map(self) -> Dict[str, FileEntry]:
        return {f.path.replace("\\", "/"): f for f in self.files}


class VerificationReport(BaseModel):
    ok: bool
    integrity_ok: bool
    signature_ok: bool
    compatibility_ok: bool
    bundle_digest: Optional[str] = None       # sha256 общего архива или директории (по manifest)
    manifest_digest: Optional[str] = None     # sha256 канонического манифеста (без подписи)
    key_id_used: Optional[str] = None
    algo_used: Optional[SignatureAlgo] = None
    issues: List[Issue] = Field(default_factory=list)

    def add(self, severity: Severity, code: str, message: str, path: Optional[str] = None) -> None:
        self.issues.append(Issue(severity=severity, code=code, message=message, path=path))

    @property
    def errors(self) -> List[Issue]:
        return [i for i in self.issues if i.severity == Severity.error]


# ==========================
#     Signature backends
# ==========================

class SignatureBackend:
    """
    Плагинный слой для проверки подписи.
    """
    def __init__(self, trusted_keys: Dict[str, Union[str, bytes]]):
        self._keys: Dict[str, Any] = {}
        self._load_keys(trusted_keys)

    def _load_keys(self, keys: Dict[str, Union[str, bytes]]) -> None:
        for key_id, material in keys.items():
            pem: bytes = material.encode("utf-8") if isinstance(material, str) else material
            if not _HAS_CRYPTO:
                raise RuntimeError("cryptography is required for signature verification")
            pub = serialization.load_pem_public_key(pem)
            self._keys[key_id] = pub

    def verify(
        self,
        data: bytes,
        signature: bytes,
        algo: SignatureAlgo,
        key_id: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Возвращает (ok, used_key_id). Если key_id не задан, пробует все ключи.
        """
        candidates: Iterable[Tuple[str, Any]]
        if key_id:
            if key_id not in self._keys:
                return False, None
            candidates = [(key_id, self._keys[key_id])]
        else:
            candidates = list(self._keys.items())

        for kid, pub in candidates:
            try:
                if algo == SignatureAlgo.ed25519:
                    if not isinstance(pub, ed25519.Ed25519PublicKey):
                        # допускаем загрузку как generic key: попытаемся сериализовать и пересоздать
                        pub = _cast_to_ed25519(pub)
                    pub.verify(signature, data)
                    return True, kid
                elif algo == SignatureAlgo.rs256:
                    if not isinstance(pub, rsa.RSAPublicKey):
                        pub = _cast_to_rsa(pub)
                    pub.verify(
                        signature,
                        data,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    return True, kid
                elif algo == SignatureAlgo.rsapss256:
                    if not isinstance(pub, rsa.RSAPublicKey):
                        pub = _cast_to_rsa(pub)
                    pub.verify(
                        signature,
                        data,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    return True, kid
                elif algo == SignatureAlgo.es256:
                    if not isinstance(pub, ec.EllipticCurvePublicKey):
                        pub = _cast_to_ec(pub)
                    pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                    return True, kid
            except InvalidSignature:
                continue
            except Exception as e:  # pragma: no cover
                # не прерываем — пробуем другие ключи
                continue
        return False, None


def _cast_to_ed25519(pub: Any) -> ed25519.Ed25519PublicKey:
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return pub
    try:
        pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return serialization.load_pem_public_key(pem)
    except Exception as e:
        raise TypeError("Provided key is not Ed25519") from e


def _cast_to_rsa(pub: Any) -> rsa.RSAPublicKey:
    if isinstance(pub, rsa.RSAPublicKey):
        return pub
    try:
        pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return serialization.load_pem_public_key(pem)
    except Exception as e:
        raise TypeError("Provided key is not RSA") from e


def _cast_to_ec(pub: Any) -> ec.EllipticCurvePublicKey:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub
    try:
        pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return serialization.load_pem_public_key(pem)
    except Exception as e:
        raise TypeError("Provided key is not EC") from e


# ==========================
#     Bundle Verifier
# ==========================

@dataclass
class BundlePaths:
    root: Path                  # корень распака/директории
    manifest: Path              # manifest.json
    signature_file: Optional[Path]  # manifest.sig | manifest.sig.b64 (если есть)


class BundleVerifier:
    """
    Проверка «бандла» политик:
      1) Безопасная распаковка (zip/tar.gz/tgz/tar) в temp, или использование директории.
      2) Загрузка и валидация manifest.json (Pydantic).
      3) Проверка целостности всех файлов согласно манифесту (sha256, размер).
      4) Канонизация манифеста и проверка подписи (detached).
      5) Проверка совместимости с движком (min/max версии).
      6) Подробный отчет без утечки чувствительных данных.
    """
    def __init__(
        self,
        trusted_keys: Optional[Dict[str, Union[str, bytes]]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.logger = logger or logging.getLogger(__name__)
        self.backend = SignatureBackend(trusted_keys or {}) if (trusted_keys is not None) else None

    # ---------- Public API ----------

    def verify(
        self,
        bundle: Union[str, Path],
        engine_version: Optional[str] = None,
    ) -> VerificationReport:
        report = VerificationReport(ok=False, integrity_ok=False, signature_ok=False, compatibility_ok=True, issues=[])
        bundle = Path(bundle)

        try:
            with self._prepare_root(bundle) as paths:
                manifest = self._load_manifest(paths.manifest, report)
                if not manifest:
                    return self._finalize(report)

                integrity_ok, bundle_sha = self._verify_integrity(paths.root, manifest, report)
                report.integrity_ok = integrity_ok
                report.bundle_digest = bundle_sha

                # Подпись
                if self.backend is None:
                    report.add(Severity.warning, "SIGNATURE_SKIPPED", "trusted_keys not provided — signature check skipped")
                    signature_ok = False
                else:
                    signature_ok, manifest_sha, kid, algo = self._verify_signature(paths, manifest, report)
                    report.manifest_digest = manifest_sha
                    report.key_id_used = kid
                    report.algo_used = algo or (manifest.signature.algo if manifest.signature else None)
                report.signature_ok = signature_ok if self.backend is not None else False

                # Совместимость
                compat_ok = self._verify_compatibility(manifest, engine_version, report)
                report.compatibility_ok = compat_ok

                report.ok = (integrity_ok and (signature_ok if self.backend is not None else True) and compat_ok)
                return self._finalize(report)

        except Exception as e:
            self.logger.exception("Bundle verification failed")
            report.add(Severity.error, "UNEXPECTED_ERROR", str(e))
            return self._finalize(report)

    # ---------- Steps ----------

    def _load_manifest(self, manifest_path: Path, report: VerificationReport) -> Optional[BundleManifest]:
        if not manifest_path.exists():
            report.add(Severity.error, "MANIFEST_MISSING", "manifest.json not found", str(manifest_path))
            return None
        try:
            raw = manifest_path.read_text(encoding="utf-8")
        except Exception as e:
            report.add(Severity.error, "MANIFEST_IO_ERROR", f"cannot read manifest.json: {e}", str(manifest_path))
            return None

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            report.add(Severity.error, "MANIFEST_JSON_ERROR", f"invalid JSON: {e}", str(manifest_path))
            return None

        try:
            manifest = BundleManifest.model_validate(data)
            return manifest
        except ValidationError as e:
            report.add(Severity.error, "MANIFEST_SCHEMA_ERROR", f"invalid manifest schema: {e}", str(manifest_path))
            return None

    def _verify_integrity(self, root: Path, manifest: BundleManifest, report: VerificationReport) -> Tuple[bool, Optional[str]]:
        ok = True
        # Проверяем каждый файл из манифеста
        for rel, entry in manifest.file_map.items():
            fp = _safe_join(root, rel)
            if not fp.exists():
                ok = False
                report.add(Severity.error, "FILE_MISSING", f"file listed in manifest not found: {rel}", rel)
                continue
            if not fp.is_file():
                ok = False
                report.add(Severity.error, "NOT_A_FILE", f"expected file but got directory/symlink: {rel}", rel)
                continue
            # Размер
            try:
                size = fp.stat().st_size
            except Exception as e:
                ok = False
                report.add(Severity.error, "FILE_STAT_ERROR", f"cannot stat file: {e}", rel)
                continue
            if size != entry.size:
                ok = False
                report.add(Severity.error, "SIZE_MISMATCH", f"size mismatch for {rel}: {size} != {entry.size}", rel)
            # Хеш
            digest = _sha256_file(fp)
            if digest != entry.sha256:
                ok = False
                report.add(Severity.error, "HASH_MISMATCH", f"sha256 mismatch for {rel}", rel)

        # Необъявленные файлы (опционально: предупреждение)
        declared = set(manifest.file_map.keys())
        actual = set(_iter_files(root))
        extra = [f for f in actual if f not in declared and f not in {"manifest.json", "manifest.sig", "manifest.sig.b64"}]
        for rel in sorted(extra):
            report.add(Severity.warning, "UNDECLARED_FILE", f"file exists but not listed in manifest: {rel}", rel)

        # Общий дайджест как sha256 канонизированного списка файлов + их хешей
        bundle_digest = _digest_of_manifest_files(manifest)
        return ok, bundle_digest

    def _verify_signature(
        self,
        paths: BundlePaths,
        manifest: BundleManifest,
        report: VerificationReport
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[SignatureAlgo]]:
        if manifest.signature is None:
            report.add(Severity.error, "SIGNATURE_META_MISSING", "manifest.signature meta not provided")
            return False, None, None, None
        if self.backend is None:
            report.add(Severity.warning, "SIGNATURE_SKIPPED", "no backend configured")
            return False, None, None, manifest.signature.algo

        sig_file = paths.signature_file
        if sig_file is None or not sig_file.exists():
            report.add(Severity.error, "SIGNATURE_FILE_MISSING", "signature file (manifest.sig|manifest.sig.b64) not found")
            return False, None, None, manifest.signature.algo

        try:
            raw_sig = sig_file.read_bytes()
        except Exception as e:
            report.add(Severity.error, "SIGNATURE_IO_ERROR", f"cannot read signature: {e}", str(sig_file))
            return False, None, None, manifest.signature.algo

        if sig_file.suffix == ".b64":
            try:
                signature = base64.b64decode(raw_sig, validate=True)
            except Exception as e:
                report.add(Severity.error, "SIGNATURE_B64_ERROR", f"invalid base64 signature: {e}", str(sig_file))
                return False, None, None, manifest.signature.algo
        else:
            signature = raw_sig

        canonical = _canonicalize_manifest(paths.manifest)
        manifest_sha = hashlib.sha256(canonical).hexdigest()

        ok, kid = self.backend.verify(
            data=canonical,
            signature=signature,
            algo=manifest.signature.algo,
            key_id=manifest.signature.key_id,
        )
        if not ok:
            report.add(Severity.error, "SIGNATURE_INVALID", "signature verification failed")
        return ok, manifest_sha, kid, manifest.signature.algo

    def _verify_compatibility(self, manifest: BundleManifest, engine_version: Optional[str], report: VerificationReport) -> bool:
        if not manifest.engine:
            report.add(Severity.info, "ENGINE_CONSTRAINTS_ABSENT", "engine constraints not provided — skipping")
            return True
        ok, why = manifest.engine.is_compatible(engine_version)
        if not ok:
            report.add(Severity.error, "ENGINE_INCOMPATIBLE", why)
        return ok

    # ---------- Extraction / Root resolution ----------

    class _TempRoot:
        def __init__(self, path: Path, cleanup: Optional[tempfile.TemporaryDirectory] = None):
            self.path = path
            self.cleanup_ctx = cleanup

        def __enter__(self) -> BundlePaths:
            return BundlePaths(
                root=self.path,
                manifest=self.path / "manifest.json",
                signature_file=_resolve_signature_file(self.path),
            )

        def __exit__(self, exc_type, exc, tb):
            if self.cleanup_ctx:
                self.cleanup_ctx.cleanup()

    def _prepare_root(self, bundle: Path) -> "BundleVerifier._TempRoot":
        if bundle.is_dir():
            return self._TempRoot(bundle.resolve())
        if not bundle.exists():
            raise FileNotFoundError(f"bundle not found: {bundle}")

        suffix = "".join(bundle.suffixes).lower()
        tmp = tempfile.TemporaryDirectory(prefix="policy-bundle-")
        root = Path(tmp.name)

        if suffix.endswith(".zip"):
            self._safe_unzip(bundle, root)
        elif suffix.endswith(".tar.gz") or suffix.endswith(".tgz") or suffix.endswith(".tar"):
            self._safe_untar(bundle, root)
        else:
            raise ValueError(f"unsupported bundle format: {bundle.name}")

        return self._TempRoot(root.resolve(), cleanup=tmp)

    # ---------- Safe extractors ----------

    def _safe_unzip(self, archive: Path, dest: Path) -> None:
        with zipfile.ZipFile(archive, "r") as zf:
            for info in zf.infolist():
                _guard_zipinfo(info)
                target = _safe_join(dest, info.filename)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, open(target, "wb") as out:
                    _copy_stream(src, out)

    def _safe_untar(self, archive: Path, dest: Path) -> None:
        mode = "r:*"  # auto-detect
        with tarfile.open(archive, mode) as tf:
            for member in tf.getmembers():
                _guard_tarinfo(member)
                target = _safe_join(dest, member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isreg():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tf.extractfile(member) as src, open(target, "wb") as out:
                        if src is None:
                            raise IOError(f"cannot extract member: {member.name}")
                        _copy_stream(src, out)
                else:
                    # ссылки, сокеты и пр. запрещены
                    raise ValueError(f"unsupported tar member type: {member.name}")

# ==========================
#       Utilities
# ==========================

def _resolve_signature_file(root: Path) -> Optional[Path]:
    for name in ("manifest.sig", "manifest.sig.b64"):
        p = root / name
        if p.exists():
            return p
    return None


def _iter_files(root: Path) -> Iterable[str]:
    for p in root.rglob("*"):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            yield rel


def _sha256_file(fp: Path) -> str:
    h = hashlib.sha256()
    with open(fp, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _digest_of_manifest_files(manifest: BundleManifest) -> str:
    """
    Детерминированный общий дайджест: конкатенация "path\\0sha256\\0size\\n" по сортированным путям.
    """
    h = hashlib.sha256()
    for path in sorted(manifest.file_map.keys()):
        entry = manifest.file_map[path]
        line = f"{path}\x00{entry.sha256}\x00{entry.size}\n".encode("utf-8")
        h.update(line)
    return h.hexdigest()


def _canonicalize_manifest(manifest_path: Path) -> bytes:
    """
    Канонизируем manifest.json: удаляем раздел signature и сериализуем с сортировкой ключей.
    """
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data.pop("signature", None)
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _copy_stream(src, dst, chunk: int = 1024 * 1024) -> None:
    while True:
        buf = src.read(chunk)
        if not buf:
            break
        dst.write(buf)


def _safe_join(root: Path, unsafe_rel: str) -> Path:
    # нормализуем и предотвращаем выход за пределы корня
    rel = Path(unsafe_rel.replace("\\", "/"))
    joined = (root / rel).resolve()
    root_resolved = root.resolve()
    if not str(joined).startswith(str(root_resolved)):
        raise ValueError(f"unsafe path traversal: {unsafe_rel}")
    return joined


def _guard_zipinfo(info: zipfile.ZipInfo) -> None:
    name = info.filename
    if name.startswith("/") or name.startswith("\\") or ".." in name:
        raise ValueError(f"unsafe entry in zip: {name}")


def _guard_tarinfo(member: tarfile.TarInfo) -> None:
    name = member.name
    if name.startswith("/") or name.startswith("\\") or ".." in name:
        raise ValueError(f"unsafe entry in tar: {name}")
    if member.issym() or member.islnk():
        raise ValueError(f"links are not allowed in bundle: {name}")


# ==========================
#           CLI
# ==========================

def _load_trusted_keys_dir(keys_dir: Path) -> Dict[str, bytes]:
    """
    Загружаем все *.pem из каталога доверенных ключей. key_id = имя файла без расширения.
    """
    result: Dict[str, bytes] = {}
    if not keys_dir.exists():
        raise FileNotFoundError(f"trusted keys directory not found: {keys_dir}")
    for p in keys_dir.glob("*.pem"):
        result[p.stem] = p.read_bytes()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Policy bundle verifier")
    parser.add_argument("bundle", type=str, help="path to bundle (dir|.zip|.tar.gz|.tgz|.tar)")
    parser.add_argument("--engine-version", type=str, default=None, help="engine version for compatibility check")
    parser.add_argument("--keys-dir", type=str, default=None, help="directory with trusted *.pem public keys")
    parser.add_argument("--key", action="append", nargs=2, metavar=("KEY_ID", "PEM_FILE"),
                        help="trusted key id and PEM path; can be repeated")
    args = parser.parse_args()

    trusted: Dict[str, bytes] = {}
    if args.keys_dir:
        trusted.update(_load_trusted_keys_dir(Path(args.keys_dir)))
    if args.key:
        for kid, pem in args.key:
            trusted[kid] = Path(pem).read_bytes()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    verifier = BundleVerifier(trusted_keys=trusted)
    rep = verifier.verify(args.bundle, engine_version=args.engine_version)

    print(json.dumps(rep.model_dump(), indent=2))
    return 0 if rep.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
