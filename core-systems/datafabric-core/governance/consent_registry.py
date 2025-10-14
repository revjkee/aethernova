# -*- coding: utf-8 -*-
"""
DataFabric | governance | consent_registry.py

Асинхронный реестр согласий (GDPR/CCPA совместимый) с:
- Append-only журналом событий (NDJSON) и хэш-цепочками целостности
- Поддержкой оснований обработки (lawful basis) по GDPR
- Версионированием политики/текста, отзывом, сроками действия
- Детерминированными "consent receipt" и верификацией целостности
- Файловой блокировкой (Unix/Windows), безопасной ротацией и fsync
- Опциональной HMAC-подписью событий для аттестации источника
- Без внешних зависимостей; интеграция с datafabric.processing.transforms.hashing

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import enum
import io
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# Крипто-утилиты (из промышленного hashing.py)
try:
    from datafabric.processing.transforms.hashing import (
        hash_json_canonical,
        HashConfig,
        verify_digest,
    )
except Exception as e:
    raise RuntimeError("consent_registry.py requires hashing.py to be present") from e

# ---------------------------
# Константы и типы
# ---------------------------

ISO8601 = "%Y-%m-%dT%H:%M:%S.%fZ"

def utc_now() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).strftime(ISO8601)

def to_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO8601)

def from_utc(s: str) -> datetime:
    # допускаем микросекунды
    return datetime.strptime(s, ISO8601).replace(tzinfo=timezone.utc)


class LawfulBasis(str, enum.Enum):
    CONSENT = "consent"                   # ст. 6(1)(a)
    CONTRACT = "contract"                 # ст. 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation" # ст. 6(1)(c)
    VITAL_INTERESTS = "vital_interests"   # ст. 6(1)(d)
    PUBLIC_TASK = "public_task"           # ст. 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # ст. 6(1)(f)


class ConsentStatus(str, enum.Enum):
    GRANTED = "granted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class EventType(str, enum.Enum):
    GRANT = "grant"
    REVOKE = "revoke"
    UPDATE = "update"
    ACCESS = "access"


# ---------------------------
# Модели
# ---------------------------

@dataclass(frozen=True)
class ConsentKey:
    subject_id: str
    controller_id: str
    purpose_id: str

    def as_tuple(self) -> Tuple[str, str, str]:
        return (self.subject_id, self.controller_id, self.purpose_id)

    def as_str(self) -> str:
        return f"{self.subject_id}:{self.controller_id}:{self.purpose_id}"


@dataclass(frozen=True)
class ConsentRecord:
    consent_id: str
    key: ConsentKey
    basis: LawfulBasis
    policy_version: str
    policy_uri: Optional[str]
    text_hash_hex: Optional[str]  # хэш текста/формы согласия (например, PDF/HTML)
    granted_at: str               # UTC ISO8601
    expires_at: Optional[str]     # UTC ISO8601
    status: ConsentStatus
    version: int                  # версия записи (счётчик изменений)
    last_event_hash: Optional[str] = None  # крипто-якорь последнего события


@dataclass(frozen=True)
class ConsentEvent:
    """
    Событие журнала (append-only).
    Хэш события вычисляется детерминированно по (payload + prev_hash).
    """
    event_id: str
    event_type: EventType
    occurred_at: str
    actor: str                   # кто инициировал (сервис/оператор/пользователь)
    consent_id: str
    payload: Dict[str, Any]      # дифф или поля состояния
    prev_event_hash: Optional[str]
    event_hash: str              # хэш (json_canonical(payload+prev)) -> hex
    hmac_alg: Optional[str] = None
    hmac_sig_hex: Optional[str] = None     # опциональная HMAC-подпись события


@dataclass(frozen=True)
class ConsentReceipt:
    """
    Детерминированный receipt (квитанция) для пользователя/аудита.
    """
    consent: ConsentRecord
    event_hash: str
    chain_tip: str
    receipt_hash_hex: str
    issued_at: str


# ---------------------------
# Исключения
# ---------------------------

class ConsentError(Exception):
    pass

class IntegrityError(ConsentError):
    pass

class NotFoundError(ConsentError):
    pass

class ValidationError(ConsentError):
    pass


# ---------------------------
# Файловая блокировка (кросс-платформенная)
# ---------------------------

@contextlib.contextmanager
def file_lock(path: Union[str, Path], timeout: float = 10.0):
    """
    Примитив межпроцессной блокировки для журнала.
    """
    lock_path = str(path) + ".lock"
    start = time.time()

    if os.name == "nt":
        import msvcrt  # type: ignore
        with open(lock_path, "a+b") as f:
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    try:
                        yield
                    finally:
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    break
                except OSError:
                    if time.time() - start > timeout:
                        raise TimeoutError(f"Failed to acquire lock: {lock_path}")
                    time.sleep(0.05)
    else:
        import fcntl  # type: ignore
        with open(lock_path, "a+") as f:
            while True:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    try:
                        yield
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    break
                except BlockingIOError:
                    if time.time() - start > timeout:
                        raise TimeoutError(f"Failed to acquire lock: {lock_path}")
                    time.sleep(0.05)


# ---------------------------
# Бэкенд: файловый журнал NDJSON с хэш-цепочкой
# ---------------------------

class FileJournalBackend:
    """
    Append-only NDJSON журнал: по строке на событие.
    Каждая строка — JSON с полями ConsentEvent.
    Стабильность: fsync на запись; атомарная ротация; цепочка hash(prev->curr).
    """

    def __init__(self, root_dir: Union[str, Path], file_name: str = "consent_journal.ndjson"):
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / file_name

    def _fsync(self, f) -> None:
        f.flush()
        os.fsync(f.fileno())

    def _encode_event(self, ev: ConsentEvent) -> str:
        return json.dumps(dataclasses.asdict(ev), ensure_ascii=False, separators=(",", ":"))

    def _decode_event(self, line: str) -> ConsentEvent:
        obj = json.loads(line)
        return ConsentEvent(
            event_id=obj["event_id"],
            event_type=EventType(obj["event_type"]),
            occurred_at=obj["occurred_at"],
            actor=obj["actor"],
            consent_id=obj["consent_id"],
            payload=obj["payload"],
            prev_event_hash=obj.get("prev_event_hash"),
            event_hash=obj["event_hash"],
            hmac_alg=obj.get("hmac_alg"),
            hmac_sig_hex=obj.get("hmac_sig_hex"),
        )

    def rotate(self, suffix: Optional[str] = None) -> Path:
        """
        Безопасная ротация журнала: атомарный rename под локом.
        """
        with file_lock(self.path):
            if not self.path.exists():
                return self.path
            stamp = suffix or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            to_path = self.root / f"{self.path.stem}.{stamp}{self.path.suffix}"
            self.path.replace(to_path)
            return to_path

    def append(self, ev: ConsentEvent) -> None:
        """
        Запись события с fsync под локом.
        """
        line = self._encode_event(ev)
        with file_lock(self.path):
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                self._fsync(f)

    def read_all(self) -> Iterable[ConsentEvent]:
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield self._decode_event(line)

    def read_tail(self, n: int = 1000) -> List[ConsentEvent]:
        """
        Простой tail без внешних зависимостей (для отладки).
        """
        if not self.path.exists():
            return []
        # Читаем целиком — нормально, т.к. журнал обычно легковесен (метаданные).
        return list(self.read_all())[-n:]


# ---------------------------
# Помощники: генерация и валидация событий
# ---------------------------

def _make_event(
    event_type: EventType,
    actor: str,
    consent_id: str,
    payload: Dict[str, Any],
    prev_event_hash: Optional[str],
    hmac_secret_b64: Optional[str] = None,
    hmac_alg: Optional[str] = "sha256",
) -> ConsentEvent:
    """
    Формирование события и вычисление event_hash: H(payload + prev_hash).
    Опционально добавляется HMAC-подпись (shared secret, base64).
    """
    canonical = {"payload": payload, "prev": prev_event_hash}
    hres = hash_json_canonical(canonical, HashConfig(algo="b2b-256"))
    event_hash = hres.hex

    ev = ConsentEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        occurred_at=utc_now(),
        actor=actor,
        consent_id=consent_id,
        payload=payload,
        prev_event_hash=prev_event_hash,
        event_hash=event_hash,
    )

    if hmac_secret_b64:
        try:
            secret = base64.b64decode(hmac_secret_b64)
        except Exception as e:
            raise ValidationError("Invalid HMAC secret (base64 expected)") from e
        # Подписываем именно event_hash, чтобы подпись была короткой и стабильной
        from datafabric.processing.transforms.hashing import hmac_bytes
        sig_hex, _ = hmac_bytes(secret, event_hash.encode("utf-8"), algo=hmac_alg or "sha256")
        ev = dataclasses.replace(ev, hmac_alg=hmac_alg, hmac_sig_hex=sig_hex)

    return ev


def _validate_basis(basis: LawfulBasis, explicit: bool) -> None:
    """
    Валидация соответствия основания и типа согласия:
    - Если basis == CONSENT, должно быть explicit=True (получено явное согласие).
    """
    if basis == LawfulBasis.CONSENT and not explicit:
        raise ValidationError("Explicit user consent required for LawfulBasis.CONSENT")


# ---------------------------
# Основной реестр (асинхронный)
# ---------------------------

class AsyncConsentRegistry:
    """
    Высокоуровневый асинхронный API реестра.
    Бэкенд — файловый журнал с хэш-цепочкой. Легко заменить на БД.
    """

    def __init__(
        self,
        backend: FileJournalBackend,
        *,
        hmac_secret_b64: Optional[str] = None,  # для подписи событий
        actor_default: str = "datafabric.governance",
        expiry_grace: timedelta = timedelta(seconds=0),
    ):
        self.backend = backend
        self.hmac_secret_b64 = hmac_secret_b64
        self.actor_default = actor_default
        self.expiry_grace = expiry_grace

    # --------- Публичные методы ---------

    async def grant_consent(
        self,
        subject_id: str,
        controller_id: str,
        purpose_id: str,
        *,
        basis: LawfulBasis = LawfulBasis.CONSENT,
        explicit: bool = True,
        policy_version: str,
        policy_uri: Optional[str] = None,
        text_hash_hex: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        actor: Optional[str] = None,
    ) -> ConsentReceipt:
        """
        Выдача/обновление согласия. Если запись существует — инкремент версии и UPDATE,
        иначе создаётся новая запись с GRANT.
        """
        _validate_basis(basis, explicit)
        key = ConsentKey(subject_id=subject_id, controller_id=controller_id, purpose_id=purpose_id)
        state, tip = await self._rebuild_state()

        existing: Optional[ConsentRecord] = None
        for rec in state.values():
            if rec.key == key:
                existing = rec
                break

        now_iso = utc_now()
        exp_iso = to_utc(expires_at) if isinstance(expires_at, datetime) else None

        if existing is None:
            consent_id = str(uuid.uuid4())
            payload = {
                "consent_id": consent_id,
                "key": dataclasses.asdict(key),
                "basis": basis.value,
                "policy_version": policy_version,
                "policy_uri": policy_uri,
                "text_hash_hex": text_hash_hex,
                "granted_at": now_iso,
                "expires_at": exp_iso,
                "status": ConsentStatus.GRANTED.value,
                "version": 1,
            }
            ev = await self._append_event(EventType.GRANT, actor or self.actor_default, consent_id, payload, tip)
            record = ConsentRecord(
                consent_id=consent_id,
                key=key,
                basis=basis,
                policy_version=policy_version,
                policy_uri=policy_uri,
                text_hash_hex=text_hash_hex,
                granted_at=now_iso,
                expires_at=exp_iso,
                status=ConsentStatus.GRANTED,
                version=1,
                last_event_hash=ev.event_hash,
            )
        else:
            # Обновление существующего согласия (например, новая версия политики/сроков)
            consent_id = existing.consent_id
            new_version = existing.version + 1
            payload = {
                "consent_id": consent_id,
                "key": dataclasses.asdict(key),
                "basis": basis.value,
                "policy_version": policy_version,
                "policy_uri": policy_uri,
                "text_hash_hex": text_hash_hex,
                "granted_at": existing.granted_at,  # исходная дата выдачи сохраняется
                "expires_at": exp_iso or existing.expires_at,
                "status": ConsentStatus.GRANTED.value,
                "version": new_version,
            }
            ev = await self._append_event(EventType.UPDATE, actor or self.actor_default, consent_id, payload, tip)
            record = ConsentRecord(
                consent_id=consent_id,
                key=key,
                basis=basis,
                policy_version=policy_version,
                policy_uri=policy_uri,
                text_hash_hex=text_hash_hex,
                granted_at=existing.granted_at,
                expires_at=exp_iso or existing.expires_at,
                status=ConsentStatus.GRANTED,
                version=new_version,
                last_event_hash=ev.event_hash,
            )

        return self._make_receipt(record, ev.event_hash, tip_hash=ev.event_hash)

    async def revoke_consent(
        self,
        subject_id: str,
        controller_id: str,
        purpose_id: str,
        *,
        reason: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> ConsentReceipt:
        """
        Отзыв согласия. Меняет статус на REVOKED, инкрементирует версию.
        """
        key = ConsentKey(subject_id=subject_id, controller_id=controller_id, purpose_id=purpose_id)
        state, tip = await self._rebuild_state()

        rec = self._find_by_key(state, key)
        if rec is None:
            raise NotFoundError("Consent not found to revoke")

        payload = {
            "consent_id": rec.consent_id,
            "key": dataclasses.asdict(key),
            "status": ConsentStatus.REVOKED.value,
            "version": rec.version + 1,
            "reason": reason,
            "occurred_at": utc_now(),
        }
        ev = await self._append_event(EventType.REVOKE, actor or self.actor_default, rec.consent_id, payload, tip)

        updated = dataclasses.replace(
            rec,
            status=ConsentStatus.REVOKED,
            version=rec.version + 1,
            last_event_hash=ev.event_hash,
        )
        return self._make_receipt(updated, ev.event_hash, tip_hash=ev.event_hash)

    async def check_permission(
        self,
        subject_id: str,
        controller_id: str,
        purpose_id: str,
        *,
        at_time: Optional[datetime] = None,
    ) -> bool:
        """
        Проверка права обработки для пары (subject, controller, purpose).
        True, если согласие активно и не отозвано/не истекло на момент at_time.
        """
        key = ConsentKey(subject_id=subject_id, controller_id=controller_id, purpose_id=purpose_id)
        state, _ = await self._rebuild_state()
        rec = self._find_by_key(state, key)
        if rec is None:
            return False

        if rec.status != ConsentStatus.GRANTED:
            return False

        check_time = (at_time or datetime.utcnow().replace(tzinfo=timezone.utc))
        if rec.expires_at:
            exp = from_utc(rec.expires_at)
            if check_time > (exp + self.expiry_grace):
                return False
        return True

    async def get_consent(
        self,
        consent_id: str,
    ) -> ConsentRecord:
        """
        Получение актуального состояния согласия по ID.
        """
        state, _ = await self._rebuild_state()
        rec = state.get(consent_id)
        if rec is None:
            raise NotFoundError("Consent not found")
        return rec

    async def list_subject_consents(self, subject_id: str) -> List[ConsentRecord]:
        """
        Список согласий субъекта.
        """
        state, _ = await self._rebuild_state()
        return [rec for rec in state.values() if rec.key.subject_id == subject_id]

    async def record_access(
        self,
        consent_id: str,
        *,
        data_categories: Optional[List[str]] = None,
        actor: Optional[str] = None,
        purpose_id: Optional[str] = None,
    ) -> str:
        """
        Аудит-факт доступа к данным в рамках согласия (не меняет состояние).
        Возвращает хэш события (якорь).
        """
        state, tip = await self._rebuild_state()
        if consent_id not in state:
            raise NotFoundError("Consent not found")
        payload = {
            "consent_id": consent_id,
            "purpose_id": purpose_id,
            "data_categories": data_categories or [],
        }
        ev = await self._append_event(EventType.ACCESS, actor or self.actor_default, consent_id, payload, tip)
        return ev.event_hash

    async def export_receipt(self, consent_id: str) -> ConsentReceipt:
        """
        Генерация квитанции на основе текущего состояния и последнего события.
        """
        state, tip = await self._rebuild_state()
        rec = state.get(consent_id)
        if rec is None:
            raise NotFoundError("Consent not found")
        tip_hash = rec.last_event_hash or ""
        receipt = self._make_receipt(rec, rec.last_event_hash or "", tip_hash=tip_hash)
        return receipt

    async def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Полная проверка целостности журнала: event_hash i == H(payload_i, prev=hash_{i-1})
        и связность цепочки. Возвращает (ok, error_message|None).
        """
        # чтение тяжёлое — выносим в пул
        events: List[ConsentEvent] = await asyncio.to_thread(lambda: list(self.backend.read_all()))
        prev = None
        for i, ev in enumerate(events):
            canonical = {"payload": ev.payload, "prev": prev}
            hres = hash_json_canonical(canonical)
            if hres.hex != ev.event_hash:
                return False, f"Integrity mismatch at index={i}, event_id={ev.event_id}"
            prev = ev.event_hash
        return True, None

    # --------- Внутренние утилиты ---------

    async def _append_event(
        self,
        et: EventType,
        actor: str,
        consent_id: str,
        payload: Dict[str, Any],
        prev_hash: Optional[str],
    ) -> ConsentEvent:
        ev = _make_event(
            event_type=et,
            actor=actor,
            consent_id=consent_id,
            payload=payload,
            prev_event_hash=prev_hash,
            hmac_secret_b64=self.hmac_secret_b64,
        )
        # Запись в журнал переносим в thread executor (IO-bound)
        await asyncio.to_thread(self.backend.append, ev)
        return ev

    async def _rebuild_state(self) -> Tuple[Dict[str, ConsentRecord], Optional[str]]:
        """
        Редукция журнала в актуальное состояние. Возвращает (state, tip_hash).
        """
        events: List[ConsentEvent] = await asyncio.to_thread(lambda: list(self.backend.read_all()))
        state: Dict[str, ConsentRecord] = {}
        tip: Optional[str] = None

        for ev in events:
            tip = ev.event_hash
            et = ev.event_type

            if et == EventType.GRANT or et == EventType.UPDATE:
                # из payload восстанавливаем состояние
                k = ev.payload["key"]
                rec = ConsentRecord(
                    consent_id=ev.payload["consent_id"],
                    key=ConsentKey(k["subject_id"], k["controller_id"], k["purpose_id"]),
                    basis=LawfulBasis(ev.payload["basis"]) if "basis" in ev.payload else state.get(ev.payload["consent_id"], ConsentRecord(
                        consent_id=ev.payload["consent_id"],
                        key=ConsentKey(k["subject_id"], k["controller_id"], k["purpose_id"]),
                        basis=LawfulBasis.CONSENT,
                        policy_version=ev.payload.get("policy_version", "unknown"),
                        policy_uri=ev.payload.get("policy_uri"),
                        text_hash_hex=ev.payload.get("text_hash_hex"),
                        granted_at=ev.payload.get("granted_at", ev.occurred_at),
                        expires_at=ev.payload.get("expires_at"),
                        status=ConsentStatus.GRANTED,
                        version=1,
                        last_event_hash=ev.event_hash,
                    )).basis,
                    policy_version=ev.payload.get("policy_version", "unknown"),
                    policy_uri=ev.payload.get("policy_uri"),
                    text_hash_hex=ev.payload.get("text_hash_hex"),
                    granted_at=ev.payload.get("granted_at", ev.occurred_at),
                    expires_at=ev.payload.get("expires_at"),
                    status=ConsentStatus(ev.payload.get("status", ConsentStatus.GRANTED.value)),
                    version=int(ev.payload.get("version", 1)),
                    last_event_hash=ev.event_hash,
                )
                state[rec.consent_id] = rec

            elif et == EventType.REVOKE:
                cid = ev.payload["consent_id"]
                if cid not in state:
                    # защита от рассинхронизации: игнорируем оборванные revoke
                    continue
                prev = state[cid]
                rec = dataclasses.replace(
                    prev,
                    status=ConsentStatus.REVOKED,
                    version=int(ev.payload.get("version", prev.version + 1)),
                    last_event_hash=ev.event_hash,
                )
                state[cid] = rec

            elif et == EventType.ACCESS:
                # событие доступа состояние не меняет
                continue

        # Автоматическое истечение
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        for cid, rec in list(state.items()):
            if rec.expires_at:
                exp = from_utc(rec.expires_at)
                if now > (exp + self.expiry_grace) and rec.status == ConsentStatus.GRANTED:
                    state[cid] = dataclasses.replace(rec, status=ConsentStatus.EXPIRED)

        return state, tip

    def _find_by_key(self, state: Mapping[str, ConsentRecord], key: ConsentKey) -> Optional[ConsentRecord]:
        for rec in state.values():
            if rec.key == key:
                return rec
        return None

    def _make_receipt(self, rec: ConsentRecord, event_hash: str, *, tip_hash: str) -> ConsentReceipt:
        """
        Детерминированный receipt: хэшируем (record + anchors).
        """
        payload = {
            "consent": {
                "consent_id": rec.consent_id,
                "key": {
                    "subject_id": rec.key.subject_id,
                    "controller_id": rec.key.controller_id,
                    "purpose_id": rec.key.purpose_id,
                },
                "basis": rec.basis.value,
                "policy_version": rec.policy_version,
                "policy_uri": rec.policy_uri,
                "text_hash_hex": rec.text_hash_hex,
                "granted_at": rec.granted_at,
                "expires_at": rec.expires_at,
                "status": rec.status.value,
                "version": rec.version,
                "last_event_hash": rec.last_event_hash,
            },
            "anchors": {
                "event_hash": event_hash,
                "chain_tip": tip_hash,
            },
            "issued_at": utc_now(),
        }
        h = hash_json_canonical(payload)
        return ConsentReceipt(
            consent=rec,
            event_hash=event_hash,
            chain_tip=tip_hash,
            receipt_hash_hex=h.hex,
            issued_at=payload["issued_at"],
        )


# ---------------------------
# Пример и быстрые тесты (manually runnable)
# ---------------------------

if __name__ == "__main__":
    async def main():
        root = Path(os.environ.get("DF_CONSENT_DIR", "/tmp/datafabric-consent"))
        backend = FileJournalBackend(root)

        # Секрет для HMAC можно передать через env: base64(key)
        secret_b64 = os.environ.get("DF_CONSENT_HMAC_B64")
        reg = AsyncConsentRegistry(backend, hmac_secret_b64=secret_b64)

        # Grant
        receipt1 = await reg.grant_consent(
            subject_id="user-123",
            controller_id="acme-corp",
            purpose_id="analytics",
            basis=LawfulBasis.CONSENT,
            explicit=True,
            policy_version="v1.2",
            policy_uri="https://acme.example/policy/v1.2",
            text_hash_hex=None,
            expires_at=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(days=365),
        )
        print("GRANT receipt:", dataclasses.asdict(receipt1))

        # Check
        ok = await reg.check_permission("user-123", "acme-corp", "analytics")
        print("check_permission:", ok)

        # Access log
        evh = await reg.record_access(receipt1.consent.consent_id, data_categories=["email", "ip"])
        print("access event hash:", evh)

        # Update (policy bump)
        receipt2 = await reg.grant_consent(
            subject_id="user-123",
            controller_id="acme-corp",
            purpose_id="analytics",
            basis=LawfulBasis.CONSENT,
            explicit=True,
            policy_version="v1.3",
            policy_uri="https://acme.example/policy/v1.3",
        )
        print("UPDATE receipt:", dataclasses.asdict(receipt2))

        # Revoke
        receipt3 = await reg.revoke_consent("user-123", "acme-corp", "analytics", reason="user request")
        print("REVOKE receipt:", dataclasses.asdict(receipt3))

        # Integrity
        ok, err = await reg.verify_integrity()
        print("verify_integrity:", ok, err)

        # Export receipt
        out = await reg.export_receipt(receipt3.consent.consent_id)
        print("export_receipt:", dataclasses.asdict(out))

    asyncio.run(main())
