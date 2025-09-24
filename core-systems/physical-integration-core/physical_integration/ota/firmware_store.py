# -*- coding: utf-8 -*-
"""
physical_integration/ota/firmware_store.py

Промышленное хранилище прошивок/артефактов OTA для edge/устройств:
- Бекенды: локальная ФС, опционально S3 (boto3).
- Целостность: SHA-256, размер, идемпотентность (artifact_id, sha256).
- Подпись: RSA/ECDSA (PEM public key), алгоритмы RS256/RS384/RS512/ES256/ES384/ES512.
- Индекс: SQLite (артефакты, метаданные, каналы релизов, таргеты устройств).
- Загрузка: staging (чанки) → commit (атомарный move/s3 put), докачка по offset.
- Доставка: выбор лучшего кандидата по семантическим версиям и каналам.
- Эксплуатация: деприкация, ретенция, сборка мусора (GC), простые файловые блокировки.

Зависимости: только стандартная библиотека. Для S3 требуется boto3 (опционально).
Для верификации подписи рекомендуется 'cryptography' (опционально).
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import functools
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import typing as t
from dataclasses import dataclass, field
from pathlib import Path

# -----------------------------------------------------------------------------
# Опциональные зависимости (S3 и криптография)
# -----------------------------------------------------------------------------
try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

try:
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import padding, ec  # type: ignore
    from cryptography.exceptions import InvalidSignature  # type: ignore
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
SEMVER_RE = re.compile(r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:[-+].*)?$")

def parse_semver(v: str) -> tuple[int, int, int, str]:
    """
    Простая семантическая версия: major.minor.patch, суффиксы игнорируются
    при сравнении, но сохраняются для выводов.
    """
    m = SEMVER_RE.match(v.strip())
    if not m:
        # fallback: попытка "1.2" -> (1,2,0)
        parts = [p for p in re.split(r"[^\d]+", v) if p]
        nums = [int(x) for x in parts[:3]] + [0] * (3 - len(parts[:3]))
        return nums[0], nums[1], nums[2], v
    return int(m.group("major")), int(m.group("minor")), int(m.group("patch")), v

def compare_versions(a: str, b: str) -> int:
    aa = parse_semver(a)
    bb = parse_semver(b)
    return (aa[:3] > bb[:3]) - (aa[:3] < bb[:3])

def sha256_file(path: Path, bufsize: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(bufsize), b""):
            h.update(chunk)
    return h.hexdigest()

# -----------------------------------------------------------------------------
# Исключения
# -----------------------------------------------------------------------------
class FirmwareStoreError(Exception): ...
class NotFound(FirmwareStoreError): ...
class IntegrityError(FirmwareStoreError): ...
class SignatureError(FirmwareStoreError): ...
class BackendError(FirmwareStoreError): ...
class Conflict(FirmwareStoreError): ...

# -----------------------------------------------------------------------------
# Модель данных
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class ArtifactKey:
    vendor: str
    product: str
    model: str
    hw_rev: str
    platform: str
    arch: str

@dataclass
class ArtifactMeta:
    key: ArtifactKey
    version: str
    build: str | None = None
    channel: str = "stable"  # stable/beta/canary или произвольный
    min_version: str | None = None
    size_bytes: int = 0
    sha256: str = ""
    created_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    deprecated: bool = False
    deprecated_at: dt.datetime | None = None
    signer_alg: str | None = None   # RS256/ES256/...
    signature_b64: str | None = None
    extra: dict[str, t.Any] = field(default_factory=dict)

    @property
    def artifact_id(self) -> str:
        """Детерминированный ID артефакта (ключ + версия + sha256/8)."""
        p = self.key
        short = (self.sha256 or "")[:8]
        return f"{p.vendor}:{p.product}:{p.model}:{p.hw_rev}:{p.platform}:{p.arch}:{self.version}:{short}"

# -----------------------------------------------------------------------------
# Бекенды хранения
# -----------------------------------------------------------------------------
class StorageBackend:
    def put(self, relpath: str, src: Path) -> None: raise NotImplementedError
    def stream(self, relpath: str, start: int = 0, end: int | None = None) -> t.Iterator[bytes]: raise NotImplementedError
    def delete(self, relpath: str) -> None: raise NotImplementedError
    def exists(self, relpath: str) -> bool: raise NotImplementedError
    def size(self, relpath: str) -> int: raise NotImplementedError
    def url(self, relpath: str, expires_s: int = 900) -> str | None: return None  # опционально

class LocalFSBackend(StorageBackend):
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _abs(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if not str(p).startswith(str(self.root.resolve())):
            raise BackendError("Path escape")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def put(self, relpath: str, src: Path) -> None:
        dst = self._abs(relpath)
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)

    def stream(self, relpath: str, start: int = 0, end: int | None = None) -> t.Iterator[bytes]:
        p = self._abs(relpath)
        size = p.stat().st_size
        s = max(0, start)
        e = min(size, end) if end is not None else size
        with p.open("rb") as f:
            f.seek(s)
            remaining = e - s
            while remaining > 0:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    def delete(self, relpath: str) -> None:
        p = self._abs(relpath)
        with contextlib.suppress(FileNotFoundError):
            p.unlink()

    def exists(self, relpath: str) -> bool:
        return self._abs(relpath).exists()

    def size(self, relpath: str) -> int:
        return self._abs(relpath).stat().st_size

class S3Backend(StorageBackend):
    def __init__(self, bucket: str, prefix: str = "", sse: str | None = "AES256") -> None:
        if boto3 is None:
            raise BackendError("boto3 not installed")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.sse = sse
        self._s3 = boto3.client("s3")

    def _key(self, rel: str) -> str:
        return f"{self.prefix}/{rel}".lstrip("/") if self.prefix else rel

    def put(self, relpath: str, src: Path) -> None:
        extra = {}
        if self.sse:
            extra["ServerSideEncryption"] = self.sse
        self._s3.upload_file(str(src), self.bucket, self._key(relpath), ExtraArgs=extra)

    def stream(self, relpath: str, start: int = 0, end: int | None = None) -> t.Iterator[bytes]:
        rng = f"bytes={start}-" if end is None else f"bytes={start}-{end-1}"
        resp = self._s3.get_object(Bucket=self.bucket, Key=self._key(relpath), Range=rng)
        body = resp["Body"]
        for chunk in iter(lambda: body.read(1024 * 1024), b""):
            if not chunk:
                break
            yield chunk

    def delete(self, relpath: str) -> None:
        self._s3.delete_object(Bucket=self.bucket, Key=self._key(relpath))

    def exists(self, relpath: str) -> bool:
        try:
            self._s3.head_object(Bucket=self.bucket, Key=self._key(relpath))
            return True
        except Exception:
            return False

    def size(self, relpath: str) -> int:
        head = self._s3.head_object(Bucket=self.bucket, Key=self._key(relpath))
        return int(head["ContentLength"])

    def url(self, relpath: str, expires_s: int = 900) -> str:
        return self._s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": self._key(relpath)},
            ExpiresIn=expires_s,
        )

# -----------------------------------------------------------------------------
# Подписи
# -----------------------------------------------------------------------------
class SignatureVerifier:
    """
    Верификация подписи. Поддержка RSA (RS256/384/512) и ECDSA (ES256/384/512).
    """
    def __init__(self, public_keys_pem: list[bytes], algs: set[str] | None = None) -> None:
        if not _CRYPTO:
            raise SignatureError("cryptography is not installed")
        self.keys = [serialization.load_pem_public_key(pem) for pem in public_keys_pem]
        self.algs = algs or {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

    def verify(self, digest: bytes, signature: bytes, alg: str) -> bool:
        if alg not in self.algs:
            return False
        for key in self.keys:
            try:
                if alg.startswith("RS"):
                    hash_alg = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}[alg]()
                    key.verify(signature, digest, padding.PKCS1v15(), hash_alg)
                    return True
                elif alg.startswith("ES"):
                    hash_alg = {"ES256": hashes.SHA256, "ES384": hashes.SHA384, "ES512": hashes.SHA512}[alg]()
                    key.verify(signature, digest, ec.ECDSA(hash_alg))
                    return True
            except InvalidSignature:
                continue
        return False

# -----------------------------------------------------------------------------
# Настройки и блокировки
# -----------------------------------------------------------------------------
@dataclass
class StoreSettings:
    root_dir: Path
    backend: StorageBackend | None = None
    db_path: Path | None = None
    namespace: str = "default"
    artifacts_rel: str = "artifacts"   # каталог хранения бинарей
    staging_rel: str = "staging"
    meta_rel: str = "meta"             # побочные json/вспом. данные
    max_stage_size_mb: int = 512
    signer_required: bool = False
    # Ретенция
    retention_keep_last: int = 5
    retention_days: int | None = None

class FileLock:
    """
    Простейшая межпроцессная блокировка на основе lock-файла.
    """
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 10.0) -> None:
        end = time.time() + timeout
        while True:
            with self._lock:
                try:
                    self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                    os.write(self._fd, str(os.getpid()).encode())
                    return
                except FileExistsError:
                    pass
            if time.time() > end:
                raise TimeoutError(f"lock timeout: {self.path}")
            time.sleep(0.05)

    def release(self) -> None:
        with self._lock:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                finally:
                    with contextlib.suppress(FileNotFoundError):
                        self.path.unlink()
                self._fd = None

    def __enter__(self): self.acquire(); return self
    def __exit__(self, exc_type, exc, tb): self.release()

# -----------------------------------------------------------------------------
# Основной класс хранилища
# -----------------------------------------------------------------------------
class FirmwareStore:
    def __init__(self, settings: StoreSettings, verifier: SignatureVerifier | None = None) -> None:
        self.s = settings
        self.root = settings.root_dir
        self.root.mkdir(parents=True, exist_ok=True)
        self.verifier = verifier
        self.backend = settings.backend or LocalFSBackend(self.root / self.s.artifacts_rel)
        self.db_path = settings.db_path or (self.root / "index.db")
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._init_schema()

        # внутренние каталоги (для FS-бекенда)
        (self.root / self.s.staging_rel).mkdir(parents=True, exist_ok=True)
        (self.root / self.s.meta_rel).mkdir(parents=True, exist_ok=True)
        self._locks_dir = self.root / ".locks"
        self._locks_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------- Схема и индекс -------------------------------
    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS artifacts (
            namespace TEXT NOT NULL,
            artifact_id TEXT PRIMARY KEY,
            vendor TEXT, product TEXT, model TEXT, hw_rev TEXT, platform TEXT, arch TEXT,
            version TEXT, build TEXT, channel TEXT,
            min_version TEXT,
            size_bytes INTEGER, sha256 TEXT NOT NULL,
            deprecated INTEGER DEFAULT 0,
            created_at TEXT, deprecated_at TEXT,
            signer_alg TEXT, signature_b64 TEXT,
            extra_json TEXT
        )""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_lookup ON artifacts(namespace, vendor, product, model, hw_rev, platform, arch, channel)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_version ON artifacts(namespace, vendor, product, model, hw_rev, platform, arch, version)")
        self._conn.commit()

    # ------------------------- Утилиты путей/локи ---------------------------
    def _lock(self, name: str) -> FileLock:
        return FileLock(self._locks_dir / f"{name}.lock")

    def _blob_relpath(self, sha256: str, filename: str) -> str:
        # Дерево: ab/cd/ef.../filename
        return f"{sha256[0:2]}/{sha256[2:4]}/{sha256}/{filename}"

    def _stage_dir(self, token: str) -> Path:
        return (self.root / self.s.staging_rel / token)

    # ------------------------- Публичные операции ---------------------------
    def put_artifact(self, src_path: Path, meta: ArtifactMeta, filename: str | None = None) -> ArtifactMeta:
        """
        Атомарное помещение бинаря в хранилище + запись индекса.
        """
        if not src_path.exists() or not src_path.is_file():
            raise FileNotFoundError(src_path)

        sha = sha256_file(src_path)
        size = src_path.stat().st_size
        if meta.sha256 and meta.sha256.lower() != sha.lower():
            raise IntegrityError("sha256 mismatch vs metadata")

        meta.sha256 = sha
        meta.size_bytes = size
        if self.s.signer_required and not (meta.signer_alg and meta.signature_b64):
            raise SignatureError("signature required by settings")

        # Проверка подписи (если передана)
        if meta.signature_b64 and meta.signer_alg:
            self._verify_signature_file(src_path, meta.signer_alg, meta.signature_b64)

        # Запись бинаря в бекенд
        filename = filename or f"{meta.key.model}-{meta.version}.bin"
        rel = self._blob_relpath(sha, filename)
        with self._lock(sha):
            if not self.backend.exists(rel):
                self.backend.put(rel, src_path)

        # Запись индекса
        self._upsert_meta(meta)
        return meta

    # --------- Staging upload: start/append/finalize/abort ------------------
    def stage_upload_start(self, expected_sha256: str | None = None, expected_size: int | None = None) -> str:
        """
        Возвращает токен staging-директории. Можно докладывать чанками и потом finalize.
        """
        token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        d = self._stage_dir(token)
        d.mkdir(parents=True, exist_ok=True)
        (d / "offset").write_text("0")
        control = {"expected_sha256": (expected_sha256 or "").lower(), "expected_size": int(expected_size or 0)}
        (d / "control.json").write_text(json.dumps(control))
        return token

    def stage_upload_append(self, token: str, data: bytes, expected_offset: int | None = None) -> int:
        """
        Пишет чанк в staging. Возвращает новый offset. Поддерживает докачку.
        """
        d = self._stage_dir(token)
        if not d.exists():
            raise NotFound("staging token not found")
        off_path = d / "offset"
        bin_path = d / "blob"
        lock = self._lock(f"stage-{token}")
        with lock:
            current = int(off_path.read_text())
            if expected_offset is not None and expected_offset != current:
                # клиент отстал — сообщим фактический offset
                return current
            with bin_path.open("ab") as f:
                f.write(data)
                current += len(data)
            off_path.write_text(str(current))
            max_bytes = self.s.max_stage_size_mb * 1024 * 1024
            if current > max_bytes:
                raise IntegrityError("staging size exceeds limit")
            return current

    def stage_upload_finalize(self, token: str, meta: ArtifactMeta, filename: str | None = None) -> ArtifactMeta:
        d = self._stage_dir(token)
        if not d.exists():
            raise NotFound("staging token not found")
        ctrl = json.loads((d / "control.json").read_text())
        blob = d / "blob"
        if not blob.exists():
            raise IntegrityError("no data")

        size = blob.stat().st_size
        if ctrl.get("expected_size") and ctrl["expected_size"] != size:
            raise IntegrityError("size mismatch (expected_size)")

        sha = sha256_file(blob)
        if ctrl.get("expected_sha256") and ctrl["expected_sha256"] and ctrl["expected_sha256"] != sha.lower():
            raise IntegrityError("sha256 mismatch (expected_sha256)")
        meta.sha256, meta.size_bytes = sha, size

        # Проверка подписи, если задана
        if self.s.signer_required and not (meta.signer_alg and meta.signature_b64):
            raise SignatureError("signature required by settings")
        if meta.signature_b64 and meta.signer_alg:
            self._verify_signature_file(blob, meta.signer_alg, meta.signature_b64)

        # Помещаем в бекенд и индекс
        filename = filename or f"{meta.key.model}-{meta.version}.bin"
        rel = self._blob_relpath(sha, filename)
        with self._lock(sha):
            if not self.backend.exists(rel):
                self.backend.put(rel, blob)
        self._upsert_meta(meta)

        # Удаляем staging
        shutil.rmtree(d, ignore_errors=True)
        return meta

    def stage_upload_abort(self, token: str) -> None:
        d = self._stage_dir(token)
        shutil.rmtree(d, ignore_errors=True)

    # -------------------------- Чтение/выбор кандидатa ----------------------
    def open_stream(self, meta: ArtifactMeta, start: int = 0, end: int | None = None) -> t.Iterator[bytes]:
        rel = self._find_existing_rel(meta.sha256)
        if not rel:
            raise NotFound("artifact blob missing")
        return self.backend.stream(rel, start=start, end=end)

    def presigned_url(self, meta: ArtifactMeta, expires_s: int = 900) -> str | None:
        rel = self._find_existing_rel(meta.sha256)
        if not rel:
            return None
        return self.backend.url(rel, expires_s=expires_s)

    def list_artifacts(self, key: ArtifactKey | None = None, channel: str | None = None, include_deprecated: bool = False) -> list[ArtifactMeta]:
        cur = self._conn.cursor()
        params: list[t.Any] = [self.s.namespace]
        q = "SELECT * FROM artifacts WHERE namespace = ?"
        if key:
            for field in ("vendor","product","model","hw_rev","platform","arch"):
                q += f" AND {field} = ?"
                params.append(getattr(key, field))
        if channel:
            q += " AND channel = ?"
            params.append(channel)
        if not include_deprecated:
            q += " AND COALESCE(deprecated,0) = 0"
        q += " ORDER BY created_at DESC"
        rows = cur.execute(q, params).fetchall()
        return [self._row_to_meta(r) for r in rows]

    def resolve_candidate(
        self,
        key: ArtifactKey,
        current_version: str | None = None,
        channel_preference: list[str] | None = None,
        allow_downgrade: bool = False,
        min_version: str | None = None,
    ) -> ArtifactMeta | None:
        """
        Выбор лучшего артефакта для устройства.
        """
        channel_preference = channel_preference or ["stable", "beta", "canary"]
        metas = self.list_artifacts(key=key, include_deprecated=False)
        if min_version:
            metas = [m for m in metas if not m.min_version or compare_versions(m.min_version, min_version) <= 0]
        selected: ArtifactMeta | None = None
        for ch in channel_preference:
            candidates = [m for m in metas if m.channel == ch]
            if not candidates:
                continue
            # Сортируем по версии убыв.
            candidates.sort(key=lambda m: parse_semver(m.version)[:3], reverse=True)
            if current_version and not allow_downgrade:
                candidates = [m for m in candidates if compare_versions(m.version, current_version) > 0]
            if candidates:
                selected = candidates[0]
                break
        return selected

    # -------------------------- Управление жизненным циклом -----------------
    def deprecate(self, artifact_id: str, when: dt.datetime | None = None) -> None:
        cur = self._conn.cursor()
        cur.execute(
            "UPDATE artifacts SET deprecated=1, deprecated_at=? WHERE namespace=? AND artifact_id=?",
            ((when or dt.datetime.now(dt.timezone.utc)).isoformat(), self.s.namespace, artifact_id),
        )
        if cur.rowcount == 0:
            raise NotFound("artifact not found")
        self._conn.commit()

    def apply_retention(self, key: ArtifactKey, keep_last: int | None = None) -> list[str]:
        """
        Удаляет из индекса устаревшие записи и возвращает список artifact_id,
        которые теперь не референсятся (для GC).
        """
        keep = keep_last or self.s.retention_keep_last
        metas = [m for m in self.list_artifacts(key=key, include_deprecated=True)]
        # Сортировка по версии
        metas.sort(key=lambda m: parse_semver(m.version)[:3], reverse=True)
        to_keep = metas[:keep]
        to_drop = metas[keep:]
        orphan_ids: list[str] = []
        cur = self._conn.cursor()
        for m in to_drop:
            cur.execute("DELETE FROM artifacts WHERE namespace=? AND artifact_id=?", (self.s.namespace, m.artifact_id))
            orphan_ids.append(m.artifact_id)
        self._conn.commit()
        return orphan_ids

    def gc_orphans(self) -> list[str]:
        """
        Находит блобы в бекенде без ссылок в индексе и удаляет их.
        Работает только для LocalFSBackend (сканирует каталог). Для S3 — noop.
        """
        deleted: list[str] = []
        if not isinstance(self.backend, LocalFSBackend):
            return deleted
        # Собираем все sha256 из индекса
        cur = self._conn.cursor()
        rows = cur.execute("SELECT sha256 FROM artifacts WHERE namespace=?", (self.s.namespace,)).fetchall()
        used = {r[0] for r in rows}
        # Сканируем каталоги /artifacts/aa/bb/sha/file
        base = self.backend.root  # type: ignore[attr-defined]
        for path in base.rglob("*"):
            if path.is_file() and len(path.parents) >= 3:
                sha = path.parents[1].name  # .../sha256/filename -> parents[1] = sha256
                if re.fullmatch(r"[0-9a-f]{64}", sha) and sha not in used:
                    with contextlib.suppress(Exception):
                        path.unlink()
                        deleted.append(str(path))
        return deleted

    # -------------------------- Низкоуровневые детали ----------------------
    def _verify_signature_file(self, path: Path, alg: str, signature_b64: str) -> None:
        if not self.verifier:
            raise SignatureError("signature verifier not configured")
        digest = hashlib.sha256(path.read_bytes()).digest()
        sig = base64.b64decode(signature_b64)
        ok = self.verifier.verify(digest, sig, alg)
        if not ok:
            raise SignatureError("signature verification failed")

    def _upsert_meta(self, meta: ArtifactMeta) -> None:
        row = self._meta_to_row(meta)
        cur = self._conn.cursor()
        # Идемпотентная вставка/обновление
        cur.execute("""
        INSERT INTO artifacts
        (namespace, artifact_id, vendor, product, model, hw_rev, platform, arch, version, build, channel,
         min_version, size_bytes, sha256, deprecated, created_at, deprecated_at, signer_alg, signature_b64, extra_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(artifact_id) DO UPDATE SET
          channel=excluded.channel,
          min_version=excluded.min_version,
          size_bytes=excluded.size_bytes,
          sha256=excluded.sha256,
          deprecated=excluded.deprecated,
          created_at=excluded.created_at,
          deprecated_at=excluded.deprecated_at,
          signer_alg=excluded.signer_alg,
          signature_b64=excluded.signature_b64,
          extra_json=excluded.extra_json
        """, row)
        self._conn.commit()

    def _meta_to_row(self, m: ArtifactMeta) -> tuple:
        k = m.key
        return (
            self.s.namespace, m.artifact_id, k.vendor, k.product, k.model, k.hw_rev, k.platform, k.arch,
            m.version, m.build, m.channel, m.min_version, m.size_bytes, m.sha256,
            1 if m.deprecated else 0,
            (m.created_at or dt.datetime.now(dt.timezone.utc)).isoformat(),
            m.deprecated_at.isoformat() if m.deprecated_at else None,
            m.signer_alg, m.signature_b64, json.dumps(m.extra or {}, ensure_ascii=False, separators=(",", ":")),
        )

    def _row_to_meta(self, r: sqlite3.Row | tuple) -> ArtifactMeta:
        # Порядок столбцов соотв. _init_schema
        (namespace, artifact_id, vendor, product, model, hw_rev, platform, arch,
         version, build, channel, min_version, size_bytes, sha256, deprecated,
         created_at, deprecated_at, signer_alg, signature_b64, extra_json) = r
        key = ArtifactKey(vendor, product, model, hw_rev, platform, arch)
        meta = ArtifactMeta(
            key=key, version=version, build=build, channel=channel, min_version=min_version,
            size_bytes=int(size_bytes or 0), sha256=sha256 or "",
            created_at=dt.datetime.fromisoformat(created_at) if created_at else dt.datetime.now(dt.timezone.utc),
            deprecated=bool(deprecated), deprecated_at=(dt.datetime.fromisoformat(deprecated_at) if deprecated_at else None),
            signer_alg=signer_alg, signature_b64=signature_b64,
            extra=json.loads(extra_json or "{}"),
        )
        return meta

    def _find_existing_rel(self, sha256: str) -> str | None:
        # Пытаемся определить существующий файл по известному имени (берём любой)
        # Для FS просканируем директорию sha, для S3 используем соглашение имени.
        if isinstance(self.backend, LocalFSBackend):
            base = self.backend.root / sha256[0:2] / sha256[2:4] / sha256  # type: ignore[attr-defined]
            if base.exists():
                for child in base.iterdir():
                    if child.is_file():
                        # возвращаем относительный путь от корня бекенда
                        rel = str((sha256[0:2] + "/" + sha256[2:4] + "/" + sha256 + "/" + child.name))
                        return rel
            return None
        else:
            # Для S3 используем соглашение с filename неизвестным — предположим canonical "<sha>.bin"
            # Можно хранить имя в extra, но если неизвестно — используем sha.bin.
            return f"{sha256[0:2]}/{sha256[2:4]}/{sha256}/{sha256}.bin"

# -----------------------------------------------------------------------------
# Пример использования (справочно; не исполняется при импорте)
# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    root = Path(os.getenv("FW_ROOT", "./_firmware_store"))
    settings = StoreSettings(root_dir=root, signer_required=False)
    store = FirmwareStore(settings)

    key = ArtifactKey(
        vendor="Acme", product="SensorX", model="SX-100", hw_rev="A1", platform="rtos", arch="armv7"
    )
    meta = ArtifactMeta(key=key, version="1.2.3", channel="stable")

    # Создадим тестовый бинарь
    tmp = Path(tempfile.mktemp(suffix=".bin"))
    tmp.write_bytes(os.urandom(512 * 1024))
    try:
        stored = store.put_artifact(tmp, meta, filename="sensorx-1.2.3.bin")
        print("Stored:", stored.artifact_id, stored.sha256, stored.size_bytes)

        # Поиск лучшего кандидата
        cand = store.resolve_candidate(key, current_version="1.0.0", channel_preference=["stable"])
        print("Candidate:", cand.version if cand else None)

        # Поток чтения первых 64К
        it = store.open_stream(cand, start=0, end=65536)  # type: ignore[arg-type]
        got = 0
        for chunk in it:
            got += len(chunk)
        print("Read:", got, "bytes")

        # Ретенция (оставить 1)
        orphan_ids = store.apply_retention(key, keep_last=1)
        print("Orphans after retention:", orphan_ids)

        # GC (FS)
        deleted = store.gc_orphans()
        print("GC deleted files:", len(deleted))
    finally:
        with contextlib.suppress(Exception):
            tmp.unlink()
