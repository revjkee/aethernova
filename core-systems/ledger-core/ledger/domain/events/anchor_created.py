from __future__ import annotations

import json
import re
import uuid
import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple


SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_uuid(v: Any, *, field_name: str) -> uuid.UUID:
    if isinstance(v, uuid.UUID):
        return v
    try:
        return uuid.UUID(str(v))
    except Exception:
        raise ValueError(f"{field_name} must be a UUID")  # noqa: TRY003


def _ensure_utc(dt: datetime, *, field_name: str) -> datetime:
    if dt.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware (UTC)")
    return dt.astimezone(timezone.utc)


class AnchorStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DELETED = "deleted"


@dataclass(frozen=True, slots=True)
class AnchorCreated:
    """
    Доменное событие: якорь создан.

    Контракт стабилен: события только добавляют новые опциональные поля в минорных версиях.
    Нумерация полей отражена в JSON-ключах; переиспользование ключей запрещено.
    """

    # ---- Обязательные системные поля ----
    event_name: str = field(default="ledger.anchor.created", init=False)
    schema_version: str = field(default="1.0.0", init=False)  # semver
    event_id: uuid.UUID = field(default_factory=uuid.uuid4)   # уникальный id события
    occurred_at: datetime = field(default_factory=_utcnow)    # момент возникновения (UTC)
    producer: str = "ledger-core"                             # идентификатор продьюсера (сервис/модуль)

    # ---- Трассировка и идемпотентность ----
    correlation_id: Optional[str] = None                      # связывает цепочку запросов
    causation_id: Optional[str] = None                        # исходное событие/команда
    idempotency_key: Optional[str] = None                     # предотвращение повторов публикации

    # ---- Ключевые доменные данные ----
    tenant_id: uuid.UUID = field(default_factory=uuid.uuid4)
    anchor_id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = field(default="")
    description: Optional[str] = None
    status: AnchorStatus = AnchorStatus.ACTIVE
    metadata: Dict[str, str] = field(default_factory=dict)

    # ---- Аудит/версионирование сущности ----
    anchor_version: int = 1                   # версия агрегата (optimistic locking)
    created_at: datetime = field(default_factory=_utcnow)  # время создания записи (UTC)

    # ---- Расширения (оставлять None; заполняются в консьюмерах) ----
    extensions: Dict[str, Any] = field(default_factory=dict)

    # ------------------------- ВАЛИДАЦИЯ -------------------------

    def __post_init__(self):
        # schema_version — строгий semver
        if not SEMVER_RE.match(self.schema_version):
            raise ValueError("schema_version must be semver")

        # UUID поля
        _ensure_uuid(self.event_id, field_name="event_id")
        _ensure_uuid(self.tenant_id, field_name="tenant_id")
        _ensure_uuid(self.anchor_id, field_name="anchor_id")

        # Времена строго UTC
        _ensure_utc(self.occurred_at, field_name="occurred_at")
        _ensure_utc(self.created_at, field_name="created_at")

        # Имя: 3..200, без управляющих символов
        if not isinstance(self.name, str) or not (3 <= len(self.name) <= 200) or any(ord(c) < 32 for c in self.name):
            raise ValueError("name must be 3..200 visible characters")

        # Description: <=1000
        if self.description is not None and (not isinstance(self.description, str) or len(self.description) > 1000):
            raise ValueError("description must be <=1000 chars")

        # metadata: ключ<=64, значение<=256, строки
        for k, v in (self.metadata or {}).items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("metadata must be a dict[str,str]")
            if len(k) > 64 or len(v) > 256:
                raise ValueError("metadata key<=64 and value<=256")

        # anchor_version
        if not isinstance(self.anchor_version, int) or self.anchor_version < 1:
            raise ValueError("anchor_version must be integer >=1")

    # ------------------------- СЕРИАЛИЗАЦИЯ -------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Портативное представление для JSON/Avro/Proto энкодеров."""
        return {
            "event_name": self.event_name,
            "schema_version": self.schema_version,
            "event_id": str(self.event_id),
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat(),
            "producer": self.producer,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "idempotency_key": self.idempotency_key,
            "tenant_id": str(self.tenant_id),
            "anchor_id": str(self.anchor_id),
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "metadata": dict(self.metadata or {}),
            "anchor_version": self.anchor_version,
            "created_at": self.created_at.astimezone(timezone.utc).isoformat(),
            "extensions": self.extensions or {},
        }

    def to_json(self) -> str:
        """JSON со стабильной сортировкой ключей (удобно для тестов и сигнатур)."""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AnchorCreated":
        """Безопасная десериализация с приведением типов."""
        try:
            # Обязательные доменные поля
            tenant_id = _ensure_uuid(data["tenant_id"], field_name="tenant_id")
            anchor_id = _ensure_uuid(data["anchor_id"], field_name="anchor_id")
            status = AnchorStatus(str(data.get("status", "active")))
            name = str(data["name"])
        except KeyError as e:
            raise ValueError(f"missing required field: {e.args[0]}")  # noqa: TRY003

        # Системные/трассировочные
        event_id = _ensure_uuid(data.get("event_id", uuid.uuid4()), field_name="event_id")
        occurred_at = _ensure_utc(
            _parse_dt(data.get("occurred_at")) or _utcnow(), field_name="occurred_at"
        )
        created_at = _ensure_utc(
            _parse_dt(data.get("created_at")) or _utcnow(), field_name="created_at"
        )

        obj = cls(
            event_id=event_id,
            occurred_at=occurred_at,
            producer=str(data.get("producer") or "ledger-core"),
            correlation_id=_opt_str(data.get("correlation_id")),
            causation_id=_opt_str(data.get("causation_id")),
            idempotency_key=_opt_str(data.get("idempotency_key")),
            tenant_id=tenant_id,
            anchor_id=anchor_id,
            name=name,
            description=_opt_str(data.get("description")),
            status=status,
            metadata=dict(data.get("metadata") or {}),
            anchor_version=int(data.get("anchor_version") or 1),
            created_at=created_at,
            extensions=dict(data.get("extensions") or {}),
        )

        # Если пришла schema_version — убедимся в валидности, но сохраняем нашу константу,
        # чтобы продьюсер управлял совместимостью.
        sv = data.get("schema_version")
        if sv is not None and not SEMVER_RE.match(str(sv)):
            raise ValueError("schema_version in payload is not semver")

        return obj

    # ------------------------- ИНТЕГРАЦИЯ С ШИНОЙ -------------------------

    @property
    def topic(self) -> str:
        """Рекомендуемая тема/subject для шины."""
        return "ledger.anchor"  # стабильная тема; тип события в заголовке

    def partition_key(self) -> str:
        """
        Ключ партиционирования для упорядочивания по агрегату:
        используем tenant_id:anchor_id.
        """
        return f"{self.tenant_id}:{self.anchor_id}"

    def message_headers(self) -> Dict[str, str]:
        """
        Стабильные заголовки для Kafka/NATS/Rabbit:
        - event-type/ -version — для маршрутизации
        - content-type — фиксируем JSON UTF-8
        - idempotency/correlation/causation для трассировки
        """
        return {
            "content-type": "application/json; charset=utf-8",
            "event-type": self.event_name,
            "event-version": self.schema_version,
            "event-id": str(self.event_id),
            "correlation-id": self.correlation_id or "",
            "causation-id": self.causation_id or "",
            "idempotency-key": self.idempotency_key or "",
            "producer": self.producer,
        }

    def message_key_bytes(self) -> bytes:
        """Байт‑ключ сообщения для брокера (Kafka): хеш партиционирующего ключа."""
        return hashlib.sha256(self.partition_key().encode("utf-8")).digest()

    # ------------------------- ДОП. УТИЛИТЫ -------------------------

    def with_correlation(self, *, correlation_id: str, causation_id: Optional[str] = None) -> "AnchorCreated":
        return replace(self, correlation_id=correlation_id, causation_id=causation_id or self.causation_id)

    def with_idempotency(self, *, idempotency_key: str) -> "AnchorCreated":
        return replace(self, idempotency_key=idempotency_key)

    def etag(self) -> str:
        """Детерминированный ETag по anchor_id+anchor_version."""
        raw = f"{self.anchor_id}:{self.anchor_version}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


# ------------------------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ -------------------------

def _opt_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v)
    return s if s else None


def _parse_dt(v: Any) -> Optional[datetime]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        # Поддержка ISO8601 с 'Z'
        if isinstance(v, str):
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
            return datetime.fromisoformat(v)
    except Exception:
        return None
    return None


# ------------------------- ПРИМЕР ИСПОЛЬЗОВАНИЯ (для тестов) -------------------------
if __name__ == "__main__":
    evt = AnchorCreated(
        tenant_id=uuid.uuid4(),
        anchor_id=uuid.uuid4(),
        name="Primary settlement anchor",
        description="Created by provisioning job",
        status=AnchorStatus.ACTIVE,
        metadata={"region": "eu-central-1"},
        anchor_version=1,
    ).with_correlation(correlation_id=str(uuid.uuid4())).with_idempotency(idempotency_key=str(uuid.uuid4()))

    print("topic:", evt.topic)
    print("key:", evt.partition_key())
    print("headers:", evt.message_headers())
    print("etag:", evt.etag())
    print("json:", evt.to_json())
