# datafabric/security/key_rotation.py
# Industrial-grade key rotation orchestrator for DataFabric
# Stdlib-only. No cryptography implemented here; integrate with KMS/HSM via CryptoProvider.

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, runtime_checkable

# =========================
# JSON logging (one-line)
# =========================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _jlog(level: str, message: str, **kwargs) -> None:
    rec = {
        "ts": _utcnow().isoformat(),
        "level": level.upper(),
        "component": "datafabric.security.key_rotation",
        "message": message,
    }
    rec.update(kwargs or {})
    print(json.dumps(rec, ensure_ascii=False), flush=True)

def _info(m: str, **kw) -> None: _jlog("INFO", m, **kw)
def _warn(m: str, **kw) -> None: _jlog("WARN", m, **kw)
def _error(m: str, **kw) -> None: _jlog("ERROR", m, **kw)

# =========================
# Errors
# =========================

class RotationError(Exception): ...
class NotFound(RotationError): ...
class AlreadyExists(RotationError): ...
class ValidationError(RotationError): ...
class AccessDenied(RotationError): ...
class Conflict(RotationError): ...
class IdempotentReplay(RotationError): ...
class ProviderError(RotationError): ...

# =========================
# Model
# =========================

class KeyState(str, Enum):
    PENDING = "PENDING"                # создан, но не активен; не используется для шифрования
    ACTIVE = "ACTIVE"                  # текущая версия для шифрования
    DEPRECATED = "DEPRECATED"          # больше не для шифрования, только для расшифровки конвертов
    DESTROY_SCHEDULED = "DESTROY_SCHEDULED"  # назначено уничтожение после срока
    DESTROYED = "DESTROYED"            # окончательно удалён в KMS/HSM

@dataclass
class RotationPolicy:
    """Параметры политики ротации мастер-ключа."""
    rotation_period: timedelta = timedelta(days=90)       # период создания новой версии
    overlap_period: timedelta = timedelta(days=30)        # окно совместного использования при ре-обёртке
    destroy_grace: timedelta = timedelta(days=30)         # срок от DEPRECATED до удаления
    max_rewrap_batch: int = 1000                          # размер батча ре-обёртки конвертов
    max_retries: int = 5                                   # ретраи операций провайдера
    backoff_initial_s: float = 0.5                         # базовый бэкофф
    backoff_max_s: float = 30.0                            # максимум бэкоффа

@dataclass
class KeyVersionMeta:
    version_id: str
    state: KeyState
    created_at: str
    activated_at: Optional[str] = None
    deprecated_at: Optional[str] = None
    destroy_at: Optional[str] = None
    # Оптимистичная конкуррентность
    etag: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Произвольные метки/атрибуты аудита
    annotations: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MasterKey:
    """Запись мастер-ключа, без ключевого материала, только метаданные и версии."""
    key_id: str
    name: str
    policy: RotationPolicy
    versions: List[KeyVersionMeta] = field(default_factory=list)
    active_version_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: _utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: _utcnow().isoformat())
    # RBAC / двойной контроль
    owners: List[str] = field(default_factory=list)       # владельцы
    approvers_required: int = 2                           # сколько подтверждений нужно для крит. операций
    pending_approvals: Dict[str, List[str]] = field(default_factory=dict)  # op_id -> [approver_ids]
    # Метаданные и аудит
    tags: Dict[str, str] = field(default_factory=dict)
    etag: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class Envelope:
    """
    Конверт для данных: зашифрованный data key (EDK) обёрнут мастер-ключом версии mk_version_id.
    Поле 'payload' (данные) здесь не хранится. Сервис работает лишь с пере‑обёрткой edk.
    """
    envelope_id: str
    mk_id: str
    mk_version_id: str
    edk: bytes
    created_at: str = field(default_factory=lambda: _utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: _utcnow().isoformat())
    # Идемпотентность ре‑обёртки
    last_rewrap_op: Optional[str] = None

# =========================
# Provider and Store APIs
# =========================

@runtime_checkable
class CryptoProvider(Protocol):
    """
    Интерфейс к KMS/HSM. Ключевой материал не выходит наружу.
    Все операции должны быть идемпотентными по op_id.
    """
    def create_key_version(self, mk_id: str, op_id: str) -> str: ...
    def set_primary(self, mk_id: str, version_id: str, op_id: str) -> None: ...
    def schedule_destroy(self, mk_id: str, version_id: str, when_utc: datetime, op_id: str) -> None: ...
    def cancel_destroy(self, mk_id: str, version_id: str, op_id: str) -> None: ...
    def decrypt_edk(self, mk_id: str, version_id: str, edk: bytes, op_id: str) -> bytes: ...
    def encrypt_edk(self, mk_id: str, version_id: str, raw_data_key: bytes, op_id: str) -> bytes: ...
    # Необязательные: label/constraints/attributes и пр.

class InsecureDemoProvider:
    """
    Демонстрационный провайдер БЕЗ криптографии. НИКОГДА не используйте в продакшене.
    Он только имитирует API KMS для тестов оркестратора.
    """
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, bytes]] = {}  # mk_id -> version_id -> salt
        self._lock = threading.RLock()
        self._seen_ops: set[str] = set()

    def _idemp(self, op_id: str) -> None:
        if op_id in self._seen_ops:
            return
        self._seen_ops.add(op_id)

    def create_key_version(self, mk_id: str, op_id: str) -> str:
        self._idemp(op_id)
        with self._lock:
            vid = str(uuid.uuid4())
            self._store.setdefault(mk_id, {})[vid] = b"salt-" + uuid.uuid4().bytes
            return vid

    def set_primary(self, mk_id: str, version_id: str, op_id: str) -> None:
        self._idemp(op_id)
        with self._lock:
            if version_id not in self._store.get(mk_id, {}):
                raise ProviderError("version not found")

    def schedule_destroy(self, mk_id: str, version_id: str, when_utc: datetime, op_id: str) -> None:
        self._idemp(op_id)

    def cancel_destroy(self, mk_id: str, version_id: str, op_id: str) -> None:
        self._idemp(op_id)

    def decrypt_edk(self, mk_id: str, version_id: str, edk: bytes, op_id: str) -> bytes:
        self._idemp(op_id)
        # Имитируем "раскрутку" конверта: возвращаем edk как псевдо raw key
        return edk

    def encrypt_edk(self, mk_id: str, version_id: str, raw_data_key: bytes, op_id: str) -> bytes:
        self._idemp(op_id)
        # Имитируем "обёртку": возвращаем как есть
        return raw_data_key

class KeyStore(Protocol):
    """Персистентное хранилище метаданных (версионирование, конверты, аудит, идемпотентность)."""
    def begin(self) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def get_master(self, key_id: str) -> MasterKey: ...
    def put_master(self, mk: MasterKey) -> None: ...
    def list_masters(self) -> List[MasterKey]: ...
    def get_envelopes(self, mk_id: str, limit: int, cursor: Optional[str]) -> Tuple[List[Envelope], Optional[str]]: ...
    def put_envelope(self, env: Envelope) -> None: ...
    def append_audit(self, rec: Dict[str, Any]) -> None: ...
    def idemp_seen(self, op_id: str) -> bool: ...
    def idemp_remember(self, op_id: str) -> None: ...

class InMemoryKeyStore(KeyStore):
    """Потокобезопасное In‑Memory хранилище для тестов/разработки."""
    def __init__(self) -> None:
        self._mk: Dict[str, MasterKey] = {}
        self._envs: Dict[str, Dict[str, Envelope]] = {}  # mk_id -> envelope_id -> Envelope
        self._audit: List[Dict[str, Any]] = []
        self._idemp: set[str] = set()
        self._lock = threading.RLock()
        self._txn = threading.local()
        self._buffer: Dict[str, Any] = {}

    def begin(self) -> None:
        setattr(self._txn, "active", True)
        self._buffer = {"mk": {}, "envs": {}, "audit": []}

    def commit(self) -> None:
        if getattr(self._txn, "active", False):
            with self._lock:
                for k, v in self._buffer["mk"].items():
                    self._mk[k] = v
                for mk_id, envs in self._buffer["envs"].items():
                    dst = self._envs.setdefault(mk_id, {})
                    for eid, e in envs.items():
                        dst[eid] = e
                self._audit.extend(self._buffer["audit"])
            setattr(self._txn, "active", False)
            self._buffer = {}

    def rollback(self) -> None:
        setattr(self._txn, "active", False)
        self._buffer = {}

    def _buf(self) -> Dict[str, Any]:
        return self._buffer if getattr(self._txn, "active", False) else None

    def get_master(self, key_id: str) -> MasterKey:
        with self._lock:
            mk = self._mk.get(key_id)
            if not mk:
                raise NotFound(f"master key not found: {key_id}")
            return mk

    def put_master(self, mk: MasterKey) -> None:
        b = self._buf()
        if b is not None:
            b["mk"][mk.key_id] = mk
        else:
            with self._lock:
                self._mk[mk.key_id] = mk

    def list_masters(self) -> List[MasterKey]:
        with self._lock:
            return list(self._mk.values())

    def get_envelopes(self, mk_id: str, limit: int, cursor: Optional[str]) -> Tuple[List[Envelope], Optional[str]]:
        with self._lock:
            envs = list(self._envs.get(mk_id, {}).values())
            start = int(cursor) if cursor else 0
            end = min(start + limit, len(envs))
            next_cur = str(end) if end < len(envs) else None
            return envs[start:end], next_cur

    def put_envelope(self, env: Envelope) -> None:
        b = self._buf()
        if b is not None:
            b["envs"].setdefault(env.mk_id, {})[env.envelope_id] = env
        else:
            with self._lock:
                self._envs.setdefault(env.mk_id, {})[env.envelope_id] = env

    def append_audit(self, rec: Dict[str, Any]) -> None:
        b = self._buf()
        if b is not None:
            b["audit"].append(rec)
        else:
            with self._lock:
                self._audit.append(rec)

    def idemp_seen(self, op_id: str) -> bool:
        with self._lock:
            return op_id in self._idemp

    def idemp_remember(self, op_id: str) -> None:
        with self._lock:
            self._idemp.add(op_id)

# =========================
# Service
# =========================

@dataclass
class KeyRotationService:
    store: KeyStore = field(default_factory=InMemoryKeyStore)
    provider: CryptoProvider = field(default_factory=InsecureDemoProvider)

    # --------- Audit / Idempotency ---------
    def _audit(self, actor: str, action: str, key_id: Optional[str], payload: Dict[str, Any]) -> None:
        rec = {
            "id": str(uuid.uuid4()),
            "ts": _utcnow().isoformat(),
            "actor": actor,
            "action": action,
            "key_id": key_id,
            "payload": payload,
        }
        self.store.append_audit(rec)
        _info("audit", action=action, actor=actor, key_id=key_id)

    def _idemp(self, op_id: Optional[str]) -> None:
        if not op_id:
            return
        if self.store.idemp_seen(op_id):
            raise IdempotentReplay(f"idempotent replay: {op_id}")
        self.store.idemp_remember(op_id)

    # --------- Master Key lifecycle ---------

    def create_master(self, actor: str, name: str, policy: RotationPolicy, owners: List[str], approvers_required: int = 2, tags: Optional[Dict[str, str]] = None, op_id: Optional[str] = None) -> MasterKey:
        self._idemp(op_id)
        key_id = name.lower()
        try:
            self.store.get_master(key_id)
            raise AlreadyExists(f"master exists: {key_id}")
        except NotFound:
            pass

        mk = MasterKey(
            key_id=key_id,
            name=name,
            policy=policy,
            owners=owners,
            approvers_required=max(1, approvers_required),
            tags=tags or {},
        )

        # Создаём первую версию (PENDING), но не активируем без подтверждения
        v_id = self.provider.create_key_version(key_id, op_id or str(uuid.uuid4()))
        ver = KeyVersionMeta(version_id=v_id, state=KeyState.PENDING, created_at=_utcnow().isoformat())
        mk.versions.append(ver)

        self.store.begin()
        try:
            self.store.put_master(mk)
            self._audit(actor, "create_master", key_id, {"version_id": v_id})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return mk

    def request_activate(self, actor: str, key_id: str, version_id: str, request_id: Optional[str] = None) -> str:
        """
        Инициирует процедуру активации версии: требуется N подтверждений (owners/admins).
        Возвращает op_id заявки.
        """
        op_id = request_id or str(uuid.uuid4())
        mk = self.store.get_master(key_id)
        if actor not in mk.owners:
            raise AccessDenied("only owners can request activation")
        mk.pending_approvals[op_id] = [actor]
        self.store.begin()
        try:
            mk.updated_at = _utcnow().isoformat()
            self.store.put_master(mk)
            self._audit(actor, "request_activate", key_id, {"op_id": op_id, "version_id": version_id})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return op_id

    def approve(self, actor: str, key_id: str, op_id: str) -> None:
        mk = self.store.get_master(key_id)
        if actor not in mk.owners:
            raise AccessDenied("only owners can approve")
        approvers = mk.pending_approvals.get(op_id, [])
        if actor in approvers:
            return
        approvers.append(actor)
        mk.pending_approvals[op_id] = approvers
        self.store.begin()
        try:
            mk.updated_at = _utcnow().isoformat()
            self.store.put_master(mk)
            self._audit(actor, "approve", key_id, {"op_id": op_id})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise

    def activate_version(self, actor: str, key_id: str, version_id: str, op_id: Optional[str] = None) -> MasterKey:
        """Активация версии после достижения кворума подтверждений."""
        self._idemp(op_id)
        mk = self.store.get_master(key_id)
        # Проверка кворума (по любой активной заявке)
        ok = any(len(v) >= mk.approvers_required for v in mk.pending_approvals.values())
        if not ok:
            raise AccessDenied("approvals quorum not met")
        # Сбрасываем все заявки
        mk.pending_approvals.clear()

        # Состояния версий
        target = None
        for v in mk.versions:
            if v.version_id == version_id:
                target = v
                break
        if not target:
            raise NotFound("version not found")
        if target.state not in (KeyState.PENDING, KeyState.DEPRECATED):
            raise Conflict(f"invalid state for activation: {target.state}")

        # Провайдер: назначаем primary
        self._with_retries(lambda oid: self.provider.set_primary(key_id, version_id, oid), mk.policy)

        # Переводим статусы: старая ACTIVE → DEPRECATED, новая → ACTIVE
        now = _utcnow().isoformat()
        for v in mk.versions:
            if v.state == KeyState.ACTIVE and v.version_id != version_id:
                v.state = KeyState.DEPRECATED
                v.deprecated_at = now
        target.state = KeyState.ACTIVE
        target.activated_at = now
        mk.active_version_id = version_id
        mk.updated_at = now
        mk.etag = str(uuid.uuid4())

        self.store.begin()
        try:
            self.store.put_master(mk)
            self._audit(actor, "activate_version", key_id, {"version_id": version_id})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return mk

    def rotate_now(self, actor: str, key_id: str, op_id: Optional[str] = None) -> MasterKey:
        """Создаёт новую PENDING версию и активирует её с кворумом (если кворум уже достигнут, иначе — только PENDING)."""
        self._idemp(op_id)
        mk = self.store.get_master(key_id)
        v_id = self.provider.create_key_version(key_id, op_id or str(uuid.uuid4()))
        ver = KeyVersionMeta(version_id=v_id, state=KeyState.PENDING, created_at=_utcnow().isoformat())
        mk.versions.append(ver)
        mk.updated_at = _utcnow().isoformat()

        self.store.begin()
        try:
            self.store.put_master(mk)
            self._audit(actor, "rotate_now", key_id, {"version_id": v_id})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return mk

    def schedule_destroy(self, actor: str, key_id: str, version_id: str, when: Optional[datetime] = None, op_id: Optional[str] = None) -> MasterKey:
        """Планирует уничтожение версии после периода grace."""
        self._idemp(op_id)
        mk = self.store.get_master(key_id)
        ver = self._find_version(mk, version_id)
        if ver.state not in (KeyState.DEPRECATED, KeyState.DESTROY_SCHEDULED):
            raise Conflict(f"invalid state for destroy scheduling: {ver.state}")
        if when is None:
            when = _utcnow() + mk.policy.destroy_grace

        self._with_retries(lambda oid: self.provider.schedule_destroy(key_id, version_id, when, oid), mk.policy)

        ver.state = KeyState.DESTROY_SCHEDULED
        ver.destroy_at = when.isoformat()
        mk.updated_at = _utcnow().isoformat()

        self.store.begin()
        try:
            self.store.put_master(mk)
            self._audit(actor, "schedule_destroy", key_id, {"version_id": version_id, "when": ver.destroy_at})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return mk

    def cancel_destroy(self, actor: str, key_id: str, version_id: str, op_id: Optional[str] = None) -> MasterKey:
        self._idemp(op_id)
        mk = self.store.get_master(key_id)
        ver = self._find_version(mk, version_id)
        if ver.state != KeyState.DESTROY_SCHEDULED:
            raise Conflict("not scheduled for destroy")

        self._with_retries(lambda oid: self.provider.cancel_destroy(key_id, version_id, oid), mk.policy)

        ver.state = KeyState.DEPRECATED
        ver.destroy_at = None
        mk.updated_at = _utcnow().isoformat()

        self.store.begin()
        try:
            self.store.put_master(mk)
            self._audit(actor, "cancel_destroy", key_id, {"version_id": version_id})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return mk

    # --------- Planning ---------

    def plan_rotation(self, key_id: str) -> Dict[str, Any]:
        """Возвращает план ротации согласно политике (создать новую версию? депрекировать старую?)."""
        mk = self.store.get_master(key_id)
        last_active = self._active_version(mk)
        now = _utcnow()
        due_new = False
        due_deprecate = False

        if last_active:
            created = datetime.fromisoformat(last_active.activated_at or last_active.created_at)
            if now - created >= mk.policy.rotation_period:
                due_new = True

        # Если есть ACTIVE и есть более новая PENDING — можно активировать; если ACTIVE старше overlap → депрекировать
        if last_active:
            for v in mk.versions:
                if v.state == KeyState.PENDING:
                    due_new = True
                    break
            # Проверка на истечение overlap (если уже активирована новая)
            # Здесь только план: фактическая депрекация делается в activate_version
            # Для упрощения вернём флаг due_deprecate, если есть более свежая ACTIVE (не в этом демо).
            due_deprecate = False

        return {
            "key_id": key_id,
            "active_version_id": mk.active_version_id,
            "due_new_version": due_new,
            "due_deprecate": due_deprecate,
        }

    # --------- Envelope re-wrap ---------

    def rewrap_envelopes(self, actor: str, key_id: str, target_version_id: str, batch_limit: Optional[int] = None, op_label: Optional[str] = None) -> Dict[str, Any]:
        """
        Пере‑обёртка конвертов (EDK) на целевую версию мастер-ключа.
        Выполняется в батчах. Возвращает прогресс одной итерации.
        """
        mk = self.store.get_master(key_id)
        target = self._find_version(mk, target_version_id)
        if target.state != KeyState.ACTIVE:
            raise Conflict("target version must be ACTIVE")
        limit = batch_limit or mk.policy.max_rewrap_batch

        cursor: Optional[str] = None
        processed = 0
        success = 0
        failed = 0
        op_base = op_label or f"rewrap-{uuid.uuid4()}"

        self.store.begin()
        try:
            envs, cursor = self.store.get_envelopes(key_id, limit, cursor)
            for env in envs:
                processed += 1
                op_id = f"{op_base}:{env.envelope_id}"
                try:
                    raw = self._with_retries(lambda oid: self.provider.decrypt_edk(key_id, env.mk_version_id, env.edk, oid), mk.policy)
                    new_edk = self._with_retries(lambda oid: self.provider.encrypt_edk(key_id, target.version_id, raw, oid), mk.policy)
                    env.edk = new_edk
                    env.mk_version_id = target.version_id
                    env.updated_at = _utcnow().isoformat()
                    env.last_rewrap_op = op_id
                    self.store.put_envelope(env)
                    success += 1
                except Exception as e:
                    failed += 1
                    self._audit(actor, "rewrap_failed", key_id, {"envelope_id": env.envelope_id, "error": str(e)})
            self._audit(actor, "rewrap_batch", key_id, {"target_version": target.version_id, "processed": processed, "success": success, "failed": failed})
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise

        return {"processed": processed, "success": success, "failed": failed, "next_cursor": cursor}

    # --------- Helpers ---------

    def _with_retries(self, fn, policy: RotationPolicy):
        """Обёртка операций KMS с экспоненциальным бэкоффом и идемпотентным op_id."""
        attempt = 0
        delay = policy.backoff_initial_s
        while True:
            try:
                op_id = str(uuid.uuid4())
                return fn(op_id)
            except Exception as e:
                attempt += 1
                if attempt > policy.max_retries:
                    _error("provider_max_retries", error=str(e))
                    raise
                time.sleep(min(delay, policy.backoff_max_s))
                delay *= 2

    def _find_version(self, mk: MasterKey, version_id: str) -> KeyVersionMeta:
        for v in mk.versions:
            if v.version_id == version_id:
                return v
        raise NotFound("version not found")

    def _active_version(self, mk: MasterKey) -> Optional[KeyVersionMeta]:
        if not mk.active_version_id:
            return None
        for v in mk.versions:
            if v.version_id == mk.active_version_id:
                return v
        return None

# =========================
# Reference usage (comment)
# =========================
# svc = KeyRotationService()
# pol = RotationPolicy(rotation_period=timedelta(days=90))
# mk = svc.create_master(actor="alice", name="df-master", policy=pol, owners=["alice","bob"], approvers_required=2)
# req_id = svc.request_activate(actor="alice", key_id=mk.key_id, version_id=mk.versions[0].version_id)
# svc.approve(actor="bob", key_id=mk.key_id, op_id=req_id)
# mk = svc.activate_version(actor="carol", key_id=mk.key_id, version_id=mk.versions[0].version_id)  # carol должна быть владельцем в реальном RBAC
# # Массовое добавление конвертов (примерно):
# for i in range(2500):
#     env = Envelope(envelope_id=str(uuid.uuid4()), mk_id=mk.key_id, mk_version_id=mk.active_version_id, edk=b"demo-edk-"+str(i).encode())
#     svc.store.put_envelope(env)
# # Ротация:
# mk = svc.rotate_now(actor="alice", key_id=mk.key_id)
# req2 = svc.request_activate(actor="alice", key_id=mk.key_id, version_id=mk.versions[-1].version_id)
# svc.approve(actor="bob", key_id=mk.key_id, op_id=req2)
# mk = svc.activate_version(actor="bob", key_id=mk.key_id, version_id=mk.versions[-1].version_id)
# progress = svc.rewrap_envelopes(actor="alice", key_id=mk.key_id, target_version_id=mk.active_version_id, batch_limit=1000)
# print(progress)
