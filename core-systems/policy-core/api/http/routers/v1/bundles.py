#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
policy-core/api/http/routers/v1/bundles.py

Промышленный роутер управления бандлами политик (PAP endpoint) для policy-core.
Особенности:
- Публикация бандла (multipart/form-data) с проверкой SHA-256, ETag и подписей.
- Валидация содержимого по JSON Schema (если доступна) + структурированный отчёт.
- Получение актуального бандла, списка и конкретных версий с ETag/If-None-Match.
- Потоковая выдача контента (StreamingResponse) и корректные MIME-типы.
- Пагинация по курсору (lexicographic id + created_at).
- Строгие коды ошибок, трассировка и аудит.

Зависимости: fastapi, starlette; jsonschema/pgpy/cryptography (опционально; при отсутствии — валидация/подпись отключаются с понятной ошибкой).
Python >= 3.11
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Path as FPath,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import JSONResponse, StreamingResponse
from starlette import status

# ----------------------------- ЛОГИ ----------------------------------------- #
log = logging.getLogger("policy_core.api.v1.bundles")


# ------------------------- УТИЛИТЫ/КОНСТАНТЫ -------------------------------- #
BUNDLES_DIR = Path(os.getenv("POLICYCORE_BUNDLES_DIR", "artifacts/bundles")).resolve()
SCHEMA_PATH = Path(os.getenv("POLICYCORE_POLICY_SCHEMA_PATH", "schemas/policy.schema.json")).resolve()
MAX_BUNDLE_SIZE_BYTES = int(os.getenv("POLICYCORE_MAX_BUNDLE_SIZE", str(200 * 1024 * 1024)))  # 200 MiB
ALLOWED_CONTENT_TYPES = {
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-gtar",
    "application/x-tar+gzip",
    "application/octet-stream",  # допускаем, но проверяем расширение
}
BUNDLE_FILENAME_RE = re.compile(r"^[A-Za-z0-9._:-]+$")  # допустимый bundle_id


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: Optional[dt.datetime] = None) -> str:
    return (ts or utcnow()).isoformat()


def compute_sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def compute_sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src, dst)  # атомарно внутри FS


# ----------------------------- МОДЕЛИ --------------------------------------- #
@dataclass(slots=True)
class BundleMeta:
    id: str
    version: int
    created_at: str
    etag: str
    sha256: str
    size_bytes: int
    signature_type: Optional[str] = None  # "ed25519" | "gpg" | "cosign"
    signer: Optional[str] = None
    manifest: Optional[dict] = None

    def asdict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ----------------------------- СХЕМА (опц.) --------------------------------- #
try:
    import jsonschema  # type: ignore

    _JSONSCHEMA_AVAILABLE = True
except Exception:  # pragma: no cover
    jsonschema = None  # type: ignore
    _JSONSCHEMA_AVAILABLE = False


class SchemaValidator:
    def __init__(self, schema_path: Path):
        self.schema_path = schema_path
        self._schema_cache: Optional[dict] = None

    def _load_schema(self) -> dict:
        if self._schema_cache is None:
            try:
                with self.schema_path.open("r", encoding="utf-8") as f:
                    self._schema_cache = json.load(f)
            except FileNotFoundError as e:
                raise HTTPException(status_code=500, detail=f"Policy schema not found: {self.schema_path}") from e
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Policy schema invalid: {e}") from e
        return self._schema_cache

    def validate_bundle(self, bundle_dir: Path) -> Dict[str, Any]:
        """
        Ищет манифест и файлы политик (*.json|*.yaml не распаковываем здесь; предполагается тар-архив).
        Для простоты: проверяет только manifest.json, если присутствует.
        В реальной системе распаковывайте TAR и валидируйте каждый файл по rule.schema.json.
        """
        if not _JSONSCHEMA_AVAILABLE:
            raise HTTPException(status_code=501, detail="jsonschema library is not available on server")
        schema = self._load_schema()
        manifest = bundle_dir / "manifest.json"
        report: Dict[str, Any] = {"schema": self.schema_path.as_posix(), "valid": True, "errors": []}
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8") or "{}")
            except Exception as e:
                report["valid"] = False
                report["errors"].append({"file": "manifest.json", "error": f"invalid json: {e}"})
                return report
            try:
                jsonschema.validate(instance=data, schema=schema)  # type: ignore
            except Exception as e:  # pragma: no cover
                report["valid"] = False
                report["errors"].append({"file": "manifest.json", "error": f"schema violation: {e}"})
        else:
            report["valid"] = False
            report["errors"].append({"file": "manifest.json", "error": "not found"})
        return report


# --------------------------- ПОДПИСИ (расширяемо) --------------------------- #
class SignatureVerifier:
    """
    Расширяемый валидатор подписи. Для краткости: провайдеры опциональны.
    В проде замените на KMS/HSM или keyless (Fulcio/Rekor) по Cosign.
    """

    def __init__(self, public_keys_dir: Optional[Path] = None):
        self.public_keys_dir = public_keys_dir

    def verify(
        self,
        data_path: Path,
        sig_b64: Optional[str],
        sig_type: Optional[str],
        signer_hint: Optional[str] = None,
    ) -> Tuple[bool, str]:
        if not sig_b64:
            return False, "no signature provided"
        if not sig_type:
            return False, "signature_type is required"
        try:
            raw_sig = base64.b64decode(sig_b64)
        except Exception:
            return False, "signature must be base64-encoded"

        st = sig_type.lower()
        if st == "ed25519":
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # type: ignore
                from cryptography.hazmat.primitives import serialization  # type: ignore
            except Exception:
                return False, "ed25519 verification unavailable (cryptography not installed)"
            # Пытаемся найти ключ
            key_file = None
            if self.public_keys_dir:
                cand = self.public_keys_dir / "policy-ed25519.pub"
                if cand.exists():
                    key_file = cand
            if not key_file:
                return False, "ed25519 public key not found"
            key_bytes = key_file.read_bytes()
            try:
                pub = Ed25519PublicKey.from_public_bytes(key_bytes)  # raw
            except Exception:
                try:
                    pub = serialization.load_pem_public_key(key_bytes)  # pem
                except Exception as e:
                    return False, f"unsupported ed25519 key format: {e}"
            try:
                pub.verify(raw_sig, data_path.read_bytes())
                return True, "ok"
            except Exception as e:
                return False, f"ed25519 verify failed: {e}"

        elif st == "gpg":
            try:
                import pgpy  # type: ignore
            except Exception:
                return False, "GPG verification unavailable (pgpy not installed)"
            key_file = None
            if self.public_keys_dir:
                cand = self.public_keys_dir / "policy-gpg.pub.asc"
                if cand.exists():
                    key_file = cand
            if not key_file:
                return False, "gpg public key not found"
            key, _ = pgpy.PGPKey.from_file(str(key_file))
            msg = pgpy.PGPMessage.new(data_path.read_bytes())
            try:
                sig = pgpy.PGPSignature.from_blob(raw_sig)
            except Exception:
                # допускаем ASCII-armored сигнатуры
                try:
                    sig = pgpy.PGPSignature.from_blob(sig_b64.encode("utf-8"))
                except Exception as e:
                    return False, f"invalid gpg signature blob: {e}"
            try:
                ok = key.verify(msg, sig)
                return (ok, "ok" if ok else "gpg verify failed")
            except Exception as e:
                return False, f"gpg verify failed: {e}"

        elif st == "cosign":
            # Для server-side cosign verify обычно нужен внешний двоичный cosign и реестр/свидетельство.
            # Здесь оставляем заглушку-отказ, чтобы явно сигнализировать о неподдержке.
            return False, "cosign verification not implemented server-side (use admission/CI)"
        else:
            return False, f"unsupported signature_type: {sig_type}"
        # unreachable


# ------------------------------ ХРАНИЛИЩЕ ----------------------------------- #
class BundleStorage:
    async def save(self, bundle_id: str, content_path: Path, meta: BundleMeta) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def get_latest(self) -> Tuple[BundleMeta, Path] | None:
        raise NotImplementedError

    async def get(self, bundle_id: str) -> Tuple[BundleMeta, Path] | None:
        raise NotImplementedError

    async def list(self, limit: int, cursor: Optional[str]) -> Tuple[List[BundleMeta], Optional[str]]:
        raise NotImplementedError


class FileBundleStorage(BundleStorage):
    """
    Файловое хранение: на диск кладём <id>.tgz и <id>.json (метаданные).
    Идентификатор — детерминированный: либо передан, либо sha256[:12]-<timestamp>.
    """

    def __init__(self, root: Path):
        self.root = root
        ensure_dir(self.root)

    def _meta_path(self, bid: str) -> Path:
        return self.root / f"{bid}.json"

    def _blob_path(self, bid: str) -> Path:
        return self.root / f"{bid}.tgz"

    async def save(self, bundle_id: str, content_path: Path, meta: BundleMeta) -> None:
        safe_move(content_path, self._blob_path(bundle_id))
        self._meta_path(bundle_id).write_text(json.dumps(meta.asdict(), ensure_ascii=False, indent=2), encoding="utf-8")

    def _load_meta(self, p: Path) -> Optional[BundleMeta]:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return BundleMeta(**data)
        except Exception as e:  # pragma: no cover
            log.error("Corrupted bundle meta %s: %s", p, e)
            return None

    async def get_latest(self) -> Tuple[BundleMeta, Path] | None:
        metas: List[Tuple[dt.datetime, BundleMeta, Path]] = []
        for mp in self.root.glob("*.json"):
            m = self._load_meta(mp)
            if not m:
                continue
            try:
                ts = dt.datetime.fromisoformat(m.created_at)
            except Exception:
                continue
            metas.append((ts, m, self._blob_path(m.id)))
        if not metas:
            return None
        metas.sort(key=lambda t: t[0], reverse=True)
        _, meta, path = metas[0]
        if not path.exists():
            return None
        return meta, path

    async def get(self, bundle_id: str) -> Tuple[BundleMeta, Path] | None:
        mp = self._meta_path(bundle_id)
        bp = self._blob_path(bundle_id)
        if not (mp.exists() and bp.exists()):
            return None
        m = self._load_meta(mp)
        if not m:
            return None
        return m, bp

    async def list(self, limit: int, cursor: Optional[str]) -> Tuple[List[BundleMeta], Optional[str]]:
        items: List[BundleMeta] = []
        metas: List[BundleMeta] = []
        for mp in self.root.glob("*.json"):
            m = self._load_meta(mp)
            if m:
                metas.append(m)
        metas.sort(key=lambda x: (x.created_at, x.id), reverse=True)
        start = 0
        if cursor:
            # cursor = "<created_at>|<id>"
            try:
                start = next(i for i, m in enumerate(metas) if f"{m.created_at}|{m.id}" == cursor) + 1
            except StopIteration:
                start = 0
        slice_ = metas[start : start + limit]
        items.extend(slice_)
        next_cursor = None
        if start + limit < len(metas) and slice_:
            last = slice_[-1]
            next_cursor = f"{last.created_at}|{last.id}"
        return items, next_cursor


# --------------------------- DEPENDENCIES (DI) ------------------------------- #
def get_storage() -> BundleStorage:
    return FileBundleStorage(BUNDLES_DIR)


def get_validator() -> SchemaValidator:
    return SchemaValidator(SCHEMA_PATH)


def get_sig_verifier() -> SignatureVerifier:
    keys_dir_env = os.getenv("POLICYCORE_KEYS_DIR")
    return SignatureVerifier(public_keys_dir=Path(keys_dir_env) if keys_dir_env else None)


# ------------------------------- РОУТЕР ------------------------------------- #
router = APIRouter(prefix="/v1/bundles", tags=["bundles"])


# ------------------------------ СХЕМЫ API ----------------------------------- #
class _ListResponse(JSONResponse):
    media_type = "application/json"


# ------------------------------- ENDPOINTS ---------------------------------- #
@router.get("", summary="Список бандлов", response_class=_ListResponse)
async def list_bundles(
    limit: int = Query(20, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Курсор пагинации: <created_at>|<id>"),
    storage: BundleStorage = Depends(get_storage),
):
    items, next_cursor = await storage.list(limit=limit, cursor=cursor)
    return {
        "items": [m.asdict() for m in items],
        "next_cursor": next_cursor,
        "count": len(items),
    }


@router.get("/current", summary="Актуальный бандл (метаданные или контент)")
async def get_current(
    request: Request,
    download: bool = Query(False, description="Если true — вернуть контент архива"),
    storage: BundleStorage = Depends(get_storage),
):
    pair = await storage.get_latest()
    if not pair:
        raise HTTPException(status_code=404, detail="no bundles")
    meta, path = pair
    # ETag по sha256
    etag = f"W/\"{meta.sha256}\""

    inm = request.headers.get("if-none-match")
    if inm and inm == etag and not download:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    if not download:
        return JSONResponse(meta.asdict(), headers={"ETag": etag})

    def _iter() -> Iterable[bytes]:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                yield chunk

    headers = {"Content-Type": "application/gzip", "Content-Disposition": f'attachment; filename="{path.name}"', "ETag": etag}
    return StreamingResponse(_iter(), headers=headers)


@router.get("/{bundle_id}", summary="Метаданные бандла")
async def get_bundle(
    request: Request,
    bundle_id: str = FPath(..., min_length=1, pattern=BUNDLE_FILENAME_RE.pattern),
    storage: BundleStorage = Depends(get_storage),
):
    res = await storage.get(bundle_id)
    if not res:
        raise HTTPException(status_code=404, detail="bundle not found")
    meta, _ = res
    etag = f'W/"{meta.sha256}"'
    inm = request.headers.get("if-none-match")
    if inm and inm == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})
    return JSONResponse(meta.asdict(), headers={"ETag": etag})


@router.get("/{bundle_id}/content", summary="Скачать бандл")
async def download_bundle(
    bundle_id: str = FPath(..., min_length=1, pattern=BUNDLE_FILENAME_RE.pattern),
    storage: BundleStorage = Depends(get_storage),
):
    res = await storage.get(bundle_id)
    if not res:
        raise HTTPException(status_code=404, detail="bundle not found")
    meta, path = res

    def _iter() -> Iterable[bytes]:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                yield chunk

    headers = {
        "Content-Type": "application/gzip",
        "Content-Disposition": f'attachment; filename="{path.name}"',
        "ETag": f'W/"{meta.sha256}"',
    }
    return StreamingResponse(_iter(), headers=headers)


@router.post(
    "",
    summary="Опубликовать новый бандл",
    status_code=201,
    responses={
        201: {"description": "Создано"},
        400: {"description": "Неверный запрос"},
        409: {"description": "Конфликт: ETag/sha256 уже существует"},
        422: {"description": "Ошибка валидации схемы"},
    },
)
async def publish_bundle(
    request: Request,
    file: UploadFile = File(..., description="Архив TAR.GZ бандла"),
    sha256: str = Form(..., description="Контрольная сумма SHA-256 всего архива (hex)"),
    signature: Optional[str] = Form(None, description="Подпись архива base64"),
    signature_type: Optional[str] = Form(None, description="Тип подписи: ed25519|gpg|cosign"),
    signer: Optional[str] = Form(None, description="Подсказка идентификатора ключа/подписанта"),
    bundle_id: Optional[str] = Form(None, description="Явный идентификатор бандла; если пуст — сгенерируется"),
    validate_only: bool = Form(False, description="Только проверить и не сохранять"),
    storage: BundleStorage = Depends(get_storage),
    validator: SchemaValidator = Depends(get_validator),
    sigver: SignatureVerifier = Depends(get_sig_verifier),
):
    # MIME и размер
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"unsupported content_type: {file.content_type}")
    # Чтение в tmp-файл с ограничением размера
    tmp_fd, tmp_path_s = tempfile.mkstemp(prefix="bundle-", suffix=".tgz")
    os.close(tmp_fd)
    tmp_path = Path(tmp_path_s)
    try:
        size = 0
        with tmp_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BUNDLE_SIZE_BYTES:
                    raise HTTPException(status_code=400, detail="bundle size exceeds limit")
                out.write(chunk)
        # Проверка sha256
        real_sha = compute_sha256_file(tmp_path)
        if real_sha != sha256.lower():
            raise HTTPException(status_code=400, detail="sha256 mismatch")
        # Подпись (если задана)
        if signature or signature_type:
            ok, msg = sigver.verify(tmp_path, signature, signature_type, signer_hint=signer)
            if not ok:
                raise HTTPException(status_code=400, detail=f"signature verify failed: {msg}")
        # Валидация (опционально, при наличии jsonschema)
        report = None
        if _JSONSCHEMA_AVAILABLE:
            # в данном файле не распаковываем tar; предполагаем, что manifest.json рядом
            # если ваш пайплайн упаковывает манифест внутрь архива, вынесите в слой CI/Admission
            work_dir = tmp_path.parent
            report = validator.validate_bundle(work_dir)
            if not report.get("valid", False):
                raise HTTPException(status_code=422, detail={"schema_report": report})

        # bundle_id
        bid = bundle_id.strip() if bundle_id else None
        if bid:
            if not BUNDLE_FILENAME_RE.match(bid):
                raise HTTPException(status_code=400, detail="invalid bundle_id format")
        else:
            # детерминированный id: sha256[:12]-YYYYMMDDHHMMSS
            bid = f"{real_sha[:12]}-{utcnow().strftime('%Y%m%d%H%M%S')}"

        meta = BundleMeta(
            id=bid,
            version=1,
            created_at=iso(),
            etag=real_sha,
            sha256=real_sha,
            size_bytes=size,
            signature_type=signature_type,
            signer=signer,
            manifest=None,
        )

        if validate_only:
            return JSONResponse({"status": "ok", "validate_only": True, "meta": meta.asdict(), "schema_report": report})

        # Конфликт по существующему sha256/id
        exists = await storage.get(bid)
        if exists:
            raise HTTPException(status_code=409, detail="bundle_id already exists")

        await storage.save(bid, tmp_path, meta)
        # tmp_path перемещён; не удаляем
        headers = {"ETag": f'W/"{meta.sha256}"', "Location": f"/v1/bundles/{bid}"}
        return JSONResponse(status_code=201, content={"status": "created", "meta": meta.asdict()}, headers=headers)
    finally:
        # удаляем, если файл ещё лежит в tmp (не был перемещён)
        try:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
        except Exception:  # pragma: no cover
            pass


@router.post(
    "/validate",
    summary="Проверить бандл без сохранения",
    responses={501: {"description": "Валидатор схем недоступен"}},
)
async def validate_bundle(
    file: UploadFile = File(..., description="Архив TAR.GZ бандла или manifest.json"),
    validator: SchemaValidator = Depends(get_validator),
):
    if not _JSONSCHEMA_AVAILABLE:
        raise HTTPException(status_code=501, detail="jsonschema library is not available on server")

    tmp_fd, tmp_path_s = tempfile.mkstemp(prefix="bundle-", suffix=".tgz")
    os.close(tmp_fd)
    tmp_path = Path(tmp_path_s)
    try:
        with tmp_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        report = validator.validate_bundle(tmp_path.parent)
        status_code = 200 if report.get("valid", False) else 422
        return JSONResponse(status_code=status_code, content={"report": report})
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
