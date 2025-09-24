# -*- coding: utf-8 -*-
"""
datafabric.metadata.dataset_registry
------------------------------------

Промышленный асинхронный реестр датасетов:

Возможности:
- Регистрация датасетов с версионированием (semver-like и автоинкрементные build'ы)
- Хранение схемы, описаний, owner'а, бизнес/тех тегов, SLA/SLO атрибутов
- Оптимистическая блокировка через ETag (version_hash) и ревизии
- Линейдж (родители/дети) на уровне датасетов и версий
- Мягкое удаление (soft delete) и восстановление
- Поиск и фильтрация: по тегам, владельцу, статусам, частичному имени, времени
- Аудит‑хуки (подключение логгера/синки в DWH)
- Абстрактное хранилище + InMemory реализация с индексацией и потокобезопасностью
- Валидации схемы (минимальные), безопасная нормализация и утилиты сравнения

Зависимости: только стандартная библиотека.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, MutableMapping, Optional, Sequence, Set, Tuple

# ------------------------------- Логирование ---------------------------------

logger = logging.getLogger("datafabric.metadata.dataset_registry")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# ------------------------------- Исключения ----------------------------------

class RegistryError(Exception):
    """Базовая ошибка реестра."""


class ValidationError(RegistryError):
    """Ошибка валидации входных данных."""


class NotFoundError(RegistryError):
    """Датасет/версия не найдены."""


class ConflictError(RegistryError):
    """Конфликт изменения/дубликаты/ETag."""


# --------------------------------- Модели ------------------------------------

class DatasetStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"  # используется для мягкого удаления


@dataclass(frozen=True)
class SchemaField:
    name: str
    type: str                 # логический тип: string, int, float, bool, date, timestamp, decimal(p,s), struct, array<T>...
    nullable: bool = True
    description: str = ""

    def __post_init__(self):
        if not self.name or not isinstance(self.name, str):
            raise ValidationError("SchemaField.name must be a non-empty string.")
        if not self.type or not isinstance(self.type, str):
            raise ValidationError("SchemaField.type must be a non-empty string.")


@dataclass(frozen=True)
class DatasetSchema:
    fields: Tuple[SchemaField, ...]
    schema_version: str = "1.0"

    def __post_init__(self):
        names = [f.name for f in self.fields]
        if len(set(names)) != len(names):
            raise ValidationError("Schema has duplicate field names.")
        if not self.fields:
            raise ValidationError("Schema must contain at least one field.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "fields": [asdict(f) for f in self.fields],
        }


@dataclass(frozen=True)
class SLA:
    freshness_seconds: int = 0         # допустимая задержка обновления
    availability_target: float = 0.0   # 0..1
    quality_score_target: float = 0.0  # 0..1


@dataclass(frozen=True)
class LineageEdge:
    parent_dataset: str     # dataset_id родителя (имя/URN)
    parent_version: Optional[str] = None  # может быть None (ссылка на датасет в целом)
    note: str = ""


@dataclass
class DatasetVersion:
    dataset_id: str
    version: str                 # семантическая или произвольная строка
    schema: DatasetSchema
    created_at: float = field(default_factory=lambda: time.time())
    created_by: str = "system"
    description: str = ""
    tags: Set[str] = field(default_factory=set)
    custom: Dict[str, Any] = field(default_factory=dict)
    lineage_in: Tuple[LineageEdge, ...] = field(default_factory=tuple)
    lineage_out: Tuple[LineageEdge, ...] = field(default_factory=tuple)
    revision: int = 0                         # оптимистическая блокировка на уровне версии
    etag: str = ""                            # hash(snapshot)
    status: DatasetStatus = DatasetStatus.ACTIVE

    def compute_etag(self) -> str:
        payload = {
            "dataset_id": self.dataset_id,
            "version": self.version,
            "schema": self.schema.to_dict(),
            "description": self.description,
            "tags": sorted(self.tags),
            "custom": self.custom,
            "lineage_in": [asdict(e) for e in self.lineage_in],
            "lineage_out": [asdict(e) for e in self.lineage_out],
            "status": self.status.value,
            "revision": self.revision,
        }
        b = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        return hashlib.sha256(b).hexdigest()

    def refresh_etag(self) -> None:
        self.etag = self.compute_etag()


@dataclass
class DatasetDescriptor:
    dataset_id: str                 # глобальное имя/URN (например, "df.s3.sales.orders_v1")
    display_name: str               # человекочитаемое имя
    owner: str                      # владелец/группа
    domain: str                     # бизнес-домен (sales/fin/ops/…)
    description: str = ""
    created_at: float = field(default_factory=lambda: time.time())
    created_by: str = "system"
    status: DatasetStatus = DatasetStatus.ACTIVE
    tags: Set[str] = field(default_factory=set)          # бизнес/тех‑теги
    tech: Dict[str, Any] = field(default_factory=dict)   # произвольные тех. атрибуты: storage, format, partitioning
    sla: SLA = field(default_factory=SLA)
    latest_version: Optional[str] = None
    revision: int = 0               # оптимистическая блокировка на уровне дескриптора
    etag: str = ""

    def compute_etag(self) -> str:
        payload = {
            "dataset_id": self.dataset_id,
            "display_name": self.display_name,
            "owner": self.owner,
            "domain": self.domain,
            "description": self.description,
            "status": self.status.value,
            "tags": sorted(self.tags),
            "tech": self.tech,
            "sla": asdict(self.sla),
            "latest_version": self.latest_version,
            "revision": self.revision,
        }
        b = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        return hashlib.sha256(b).hexdigest()

    def refresh_etag(self) -> None:
        self.etag = self.compute_etag()


# ----------------------------- Аудит/интерфейсы ------------------------------

@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    ts: float
    actor: str
    action: str
    object_type: str
    object_id: str
    details: Dict[str, Any]


class Auditor(ABC):
    @abstractmethod
    async def emit(self, event: AuditEvent) -> None:
        ...


class LoggingAuditor(Auditor):
    def __init__(self, level: int = logging.INFO) -> None:
        self._level = level

    async def emit(self, event: AuditEvent) -> None:
        logger.log(
            self._level,
            "AUDIT id=%s ts=%.3f actor=%s action=%s object=%s:%s details=%s",
            event.event_id, event.ts, event.actor, event.action, event.object_type, event.object_id, json.dumps(event.details, ensure_ascii=False, default=str),
        )


# ----------------------------- Абстракция стора ------------------------------

class RegistryStore(ABC):
    """Абстрактное асинхронное хранилище."""

    # Дескриптор датасета
    @abstractmethod
    async def put_dataset(self, descriptor: DatasetDescriptor, *, upsert: bool = False) -> None: ...

    @abstractmethod
    async def get_dataset(self, dataset_id: str) -> DatasetDescriptor: ...

    @abstractmethod
    async def delete_dataset(self, dataset_id: str) -> None: ...

    @abstractmethod
    async def list_datasets(self) -> List[str]: ...

    # Версии
    @abstractmethod
    async def put_version(self, version: DatasetVersion, *, upsert: bool = False) -> None: ...

    @abstractmethod
    async def get_version(self, dataset_id: str, version: str) -> DatasetVersion: ...

    @abstractmethod
    async def list_versions(self, dataset_id: str) -> List[str]: ...

    @abstractmethod
    async def delete_version(self, dataset_id: str, version: str) -> None: ...

    # Поиск/индексы
    @abstractmethod
    async def search(self, *, name_like: Optional[str], tags_all: Set[str], owner: Optional[str], status_in: Set[DatasetStatus], domain: Optional[str]) -> List[str]: ...


class InMemoryRegistryStore(RegistryStore):
    """
    Потокобезопасное in-memory хранилище с индексами:
    - по owner, domain, статусу, тегам, имени (подстрока)
    """
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._datasets: Dict[str, DatasetDescriptor] = {}
        self._versions: Dict[Tuple[str, str], DatasetVersion] = {}

        # Индексы
        self._by_owner: Dict[str, Set[str]] = {}
        self._by_domain: Dict[str, Set[str]] = {}
        self._by_status: Dict[DatasetStatus, Set[str]] = {}
        self._by_tag: Dict[str, Set[str]] = {}

    async def put_dataset(self, descriptor: DatasetDescriptor, *, upsert: bool = False) -> None:
        async with self._lock:
            exists = descriptor.dataset_id in self._datasets
            if exists and not upsert:
                raise ConflictError(f"Dataset {descriptor.dataset_id} already exists.")
            if exists:
                # снятие старых индексов
                old = self._datasets[descriptor.dataset_id]
                self._by_owner.get(old.owner, set()).discard(old.dataset_id)
                self._by_domain.get(old.domain, set()).discard(old.dataset_id)
                self._by_status.get(old.status, set()).discard(old.dataset_id)
                for t in old.tags:
                    self._by_tag.get(t, set()).discard(old.dataset_id)
            # запись
            self._datasets[descriptor.dataset_id] = descriptor
            # обновление индексов
            self._by_owner.setdefault(descriptor.owner, set()).add(descriptor.dataset_id)
            self._by_domain.setdefault(descriptor.domain, set()).add(descriptor.dataset_id)
            self._by_status.setdefault(descriptor.status, set()).add(descriptor.dataset_id)
            for t in descriptor.tags:
                self._by_tag.setdefault(t, set()).add(descriptor.dataset_id)

    async def get_dataset(self, dataset_id: str) -> DatasetDescriptor:
        async with self._lock:
            d = self._datasets.get(dataset_id)
            if not d:
                raise NotFoundError(f"Dataset {dataset_id} not found.")
            # возврат копии (защита от внешней мутации)
            return _copy_descriptor(d)

    async def delete_dataset(self, dataset_id: str) -> None:
        async with self._lock:
            d = self._datasets.pop(dataset_id, None)
            if not d:
                raise NotFoundError(f"Dataset {dataset_id} not found.")
            self._by_owner.get(d.owner, set()).discard(dataset_id)
            self._by_domain.get(d.domain, set()).discard(dataset_id)
            self._by_status.get(d.status, set()).discard(dataset_id)
            for t in d.tags:
                self._by_tag.get(t, set()).discard(dataset_id)
            # удалить версии
            to_del = [k for k in self._versions.keys() if k[0] == dataset_id]
            for k in to_del:
                self._versions.pop(k, None)

    async def list_datasets(self) -> List[str]:
        async with self._lock:
            return list(self._datasets.keys())

    async def put_version(self, version: DatasetVersion, *, upsert: bool = False) -> None:
        async with self._lock:
            key = (version.dataset_id, version.version)
            exists = key in self._versions
            if exists and not upsert:
                raise ConflictError(f"Version {version.dataset_id}:{version.version} already exists.")
            self._versions[key] = version

    async def get_version(self, dataset_id: str, version: str) -> DatasetVersion:
        async with self._lock:
            v = self._versions.get((dataset_id, version))
            if not v:
                raise NotFoundError(f"Version {dataset_id}:{version} not found.")
            return _copy_version(v)

    async def list_versions(self, dataset_id: str) -> List[str]:
        async with self._lock:
            return [ver for (ds, ver) in self._versions.keys() if ds == dataset_id]

    async def delete_version(self, dataset_id: str, version: str) -> None:
        async with self._lock:
            k = (dataset_id, version)
            if k not in self._versions:
                raise NotFoundError(f"Version {dataset_id}:{version} not found.")
            self._versions.pop(k, None)

    async def search(self, *, name_like: Optional[str], tags_all: Set[str], owner: Optional[str], status_in: Set[DatasetStatus], domain: Optional[str]) -> List[str]:
        async with self._lock:
            # стартовый набор
            if owner and owner in self._by_owner:
                result = set(self._by_owner[owner])
            elif domain and domain in self._by_domain:
                result = set(self._by_domain[domain])
            else:
                result = set(self._datasets.keys())

            if status_in:
                result = {d for d in result if self._datasets[d].status in status_in}
            if tags_all:
                for t in tags_all:
                    ids = self._by_tag.get(t, set())
                    result &= ids
            if domain:
                result = {d for d in result if self._datasets[d].domain == domain}
            if name_like:
                nl = name_like.lower()
                result = {
                    d for d in result
                    if nl in d.lower() or nl in self._datasets[d].display_name.lower()
                }
            return sorted(result)


def _copy_descriptor(d: DatasetDescriptor) -> DatasetDescriptor:
    # Глубокая копия без внешних зависимостей
    return DatasetDescriptor(
        dataset_id=d.dataset_id,
        display_name=d.display_name,
        owner=d.owner,
        domain=d.domain,
        description=d.description,
        created_at=d.created_at,
        created_by=d.created_by,
        status=d.status,
        tags=set(d.tags),
        tech=dict(d.tech),
        sla=SLA(**asdict(d.sla)),
        latest_version=d.latest_version,
        revision=d.revision,
        etag=d.etag,
    )


def _copy_version(v: DatasetVersion) -> DatasetVersion:
    return DatasetVersion(
        dataset_id=v.dataset_id,
        version=v.version,
        schema=DatasetSchema(tuple(SchemaField(**asdict(f)) for f in v.schema.fields), schema_version=v.schema.schema_version),
        created_at=v.created_at,
        created_by=v.created_by,
        description=v.description,
        tags=set(v.tags),
        custom=dict(v.custom),
        lineage_in=tuple(LineageEdge(**asdict(e)) for e in v.lineage_in),
        lineage_out=tuple(LineageEdge(**asdict(e)) for e in v.lineage_out),
        revision=v.revision,
        etag=v.etag,
        status=v.status,
    )


# ---------------------------- Сервис реестра ---------------------------------

class DatasetRegistry:
    """
    Высокоуровневый сервис поверх абстрактного стора.
    Реализует:
      - CRUD для датасетов и версий
      - Автовыставление latest_version
      - Оптимистическая блокировка (revision + etag)
      - Линейдж API
      - Поиск с индексами
      - Мягкое удаление/восстановление
      - Аудит событий
    """

    def __init__(self, store: RegistryStore, auditor: Optional[Auditor] = None) -> None:
        self._store = store
        self._auditor = auditor or LoggingAuditor()
        self._rw_lock = asyncio.Lock()  # последовательность критичных операций

    # ------------------------ Утилиты/валидации ----------------------------

    @staticmethod
    def _validate_dataset_id(dataset_id: str) -> None:
        if not dataset_id or not isinstance(dataset_id, str):
            raise ValidationError("dataset_id must be a non-empty string.")
        if len(dataset_id) > 256:
            raise ValidationError("dataset_id too long.")
        if any(ch.isspace() for ch in dataset_id):
            raise ValidationError("dataset_id must not contain whitespace.")

    @staticmethod
    def _validate_version(version: str) -> None:
        if not version or not isinstance(version, str):
            raise ValidationError("version must be a non-empty string.")
        if len(version) > 128:
            raise ValidationError("version too long.")

    async def _audit(self, actor: str, action: str, obj_type: str, obj_id: str, details: Dict[str, Any]) -> None:
        try:
            await self._auditor.emit(AuditEvent(
                event_id=str(uuid.uuid4()),
                ts=time.time(),
                actor=actor,
                action=action,
                object_type=obj_type,
                object_id=obj_id,
                details=details,
            ))
        except Exception as e:
            logger.error("Audit hook failed: %r", e)

    # -------------------------- Dataset CRUD -------------------------------

    async def create_dataset(
        self,
        *,
        dataset_id: str,
        display_name: str,
        owner: str,
        domain: str,
        description: str = "",
        tags: Optional[Iterable[str]] = None,
        tech: Optional[Dict[str, Any]] = None,
        sla: Optional[SLA] = None,
        actor: str = "system",
    ) -> DatasetDescriptor:
        self._validate_dataset_id(dataset_id)
        if not display_name or not owner or not domain:
            raise ValidationError("display_name, owner and domain are required.")
        desc = DatasetDescriptor(
            dataset_id=dataset_id,
            display_name=display_name,
            owner=owner,
            domain=domain,
            description=description,
            tags=set(tags or ()),
            tech=dict(tech or {}),
            sla=sla or SLA(),
        )
        desc.refresh_etag()
        async with self._rw_lock:
            await self._store.put_dataset(desc, upsert=False)
        await self._audit(actor, "create_dataset", "dataset", dataset_id, {"display_name": display_name, "owner": owner, "domain": domain})
        return desc

    async def get_dataset(self, dataset_id: str) -> DatasetDescriptor:
        return await self._store.get_dataset(dataset_id)

    async def update_dataset(
        self,
        dataset_id: str,
        *,
        expected_etag: Optional[str],
        mutate: Dict[str, Any],
        actor: str = "system",
    ) -> DatasetDescriptor:
        """
        Обновление с оптимистической блокировкой.
        mutate: произвольные поля (display_name/description/owner/domain/tags/tech/sla/status).
        """
        async with self._rw_lock:
            current = await self._store.get_dataset(dataset_id)
            if expected_etag and expected_etag != current.etag:
                raise ConflictError("ETag mismatch for dataset update.")
            # применяем изменения
            if "display_name" in mutate:
                dn = mutate["display_name"]
                if not dn:
                    raise ValidationError("display_name cannot be empty.")
                current.display_name = dn  # type: ignore
            if "description" in mutate:
                current.description = str(mutate["description"])  # type: ignore
            if "owner" in mutate:
                current.owner = str(mutate["owner"])  # type: ignore
            if "domain" in mutate:
                current.domain = str(mutate["domain"])  # type: ignore
            if "tags" in mutate:
                current.tags = set(mutate["tags"])  # type: ignore
            if "tech" in mutate:
                if not isinstance(mutate["tech"], dict):
                    raise ValidationError("tech must be a dictionary.")
                current.tech = dict(mutate["tech"])  # type: ignore
            if "sla" in mutate:
                if not isinstance(mutate["sla"], SLA):
                    raise ValidationError("sla must be SLA instance.")
                current.sla = mutate["sla"]  # type: ignore
            if "status" in mutate:
                st = DatasetStatus(str(mutate["status"]))
                current.status = st  # type: ignore

            current.revision += 1
            current.refresh_etag()
            await self._store.put_dataset(current, upsert=True)

        await self._audit(actor, "update_dataset", "dataset", dataset_id, {"mutate": list(mutate.keys())})
        return current

    async def soft_delete_dataset(self, dataset_id: str, *, actor: str = "system") -> DatasetDescriptor:
        async with self._rw_lock:
            d = await self._store.get_dataset(dataset_id)
            if d.status == DatasetStatus.DELETED:
                return d
            d.status = DatasetStatus.DELETED
            d.revision += 1
            d.refresh_etag()
            await self._store.put_dataset(d, upsert=True)
        await self._audit(actor, "soft_delete_dataset", "dataset", dataset_id, {})
        return d

    async def restore_dataset(self, dataset_id: str, *, actor: str = "system") -> DatasetDescriptor:
        async with self._rw_lock:
            d = await self._store.get_dataset(dataset_id)
            if d.status != DatasetStatus.DELETED:
                return d
            d.status = DatasetStatus.ACTIVE
            d.revision += 1
            d.refresh_etag()
            await self._store.put_dataset(d, upsert=True)
        await self._audit(actor, "restore_dataset", "dataset", dataset_id, {})
        return d

    # ------------------------- Versions CRUD --------------------------------

    async def create_version(
        self,
        *,
        dataset_id: str,
        version: str,
        schema: DatasetSchema,
        description: str = "",
        tags: Optional[Iterable[str]] = None,
        lineage_in: Optional[Iterable[LineageEdge]] = None,
        lineage_out: Optional[Iterable[LineageEdge]] = None,
        custom: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        set_as_latest: bool = True,
    ) -> DatasetVersion:
        self._validate_dataset_id(dataset_id)
        self._validate_version(version)
        # базовые проверки схемы (минимальные)
        if not isinstance(schema, DatasetSchema):
            raise ValidationError("schema must be a DatasetSchema.")
        v = DatasetVersion(
            dataset_id=dataset_id,
            version=version,
            schema=schema,
            description=description,
            tags=set(tags or ()),
            lineage_in=tuple(lineage_in or ()),
            lineage_out=tuple(lineage_out or ()),
            custom=dict(custom or {}),
        )
        v.refresh_etag()
        async with self._rw_lock:
            # убеждаемся, что датасет существует
            d = await self._store.get_dataset(dataset_id)
            await self._store.put_version(v, upsert=False)
            if set_as_latest:
                d.latest_version = version
                d.revision += 1
                d.refresh_etag()
                await self._store.put_dataset(d, upsert=True)
        await self._audit(actor, "create_version", "version", f"{dataset_id}:{version}", {"set_as_latest": set_as_latest})
        return v

    async def get_version(self, dataset_id: str, version: str) -> DatasetVersion:
        return await self._store.get_version(dataset_id, version)

    async def update_version(
        self,
        dataset_id: str,
        version: str,
        *,
        expected_etag: Optional[str],
        mutate: Dict[str, Any],
        actor: str = "system",
    ) -> DatasetVersion:
        async with self._rw_lock:
            v = await self._store.get_version(dataset_id, version)
            if expected_etag and expected_etag != v.etag:
                raise ConflictError("ETag mismatch for version update.")

            if "description" in mutate:
                v.description = str(mutate["description"])  # type: ignore
            if "tags" in mutate:
                v.tags = set(mutate["tags"])  # type: ignore
            if "custom" in mutate:
                if not isinstance(mutate["custom"], dict):
                    raise ValidationError("custom must be a dictionary.")
                v.custom = dict(mutate["custom"])  # type: ignore
            if "status" in mutate:
                v.status = DatasetStatus(str(mutate["status"]))  # type: ignore
            if "schema" in mutate:
                sc = mutate["schema"]
                if not isinstance(sc, DatasetSchema):
                    raise ValidationError("schema must be DatasetSchema.")
                v.schema = sc  # type: ignore
            if "lineage_in" in mutate:
                v.lineage_in = tuple(mutate["lineage_in"])  # type: ignore
            if "lineage_out" in mutate:
                v.lineage_out = tuple(mutate["lineage_out"])  # type: ignore

            v.revision += 1
            v.refresh_etag()
            await self._store.put_version(v, upsert=True)

        await self._audit(actor, "update_version", "version", f"{dataset_id}:{version}", {"mutate": list(mutate.keys())})
        return v

    async def delete_version(self, dataset_id: str, version: str, *, actor: str = "system") -> None:
        async with self._rw_lock:
            await self._store.delete_version(dataset_id, version)
            # если удалили latest_version, обнуляем ссылку
            d = await self._store.get_dataset(dataset_id)
            if d.latest_version == version:
                d.latest_version = None
                d.revision += 1
                d.refresh_etag()
                await self._store.put_dataset(d, upsert=True)
        await self._audit(actor, "delete_version", "version", f"{dataset_id}:{version}", {})

    async def set_latest(self, dataset_id: str, version: str, *, actor: str = "system") -> DatasetDescriptor:
        async with self._rw_lock:
            # проверим наличие версии
            await self._store.get_version(dataset_id, version)
            d = await self._store.get_dataset(dataset_id)
            d.latest_version = version
            d.revision += 1
            d.refresh_etag()
            await self._store.put_dataset(d, upsert=True)
        await self._audit(actor, "set_latest", "dataset", dataset_id, {"version": version})
        return d

    # ----------------------------- Линейдж API --------------------------------

    async def add_lineage_in(self, dataset_id: str, version: str, edges: Iterable[LineageEdge], *, actor: str = "system") -> DatasetVersion:
        async with self._rw_lock:
            v = await self._store.get_version(dataset_id, version)
            v.lineage_in = tuple(list(v.lineage_in) + list(edges))
            v.revision += 1
            v.refresh_etag()
            await self._store.put_version(v, upsert=True)
        await self._audit(actor, "add_lineage_in", "version", f"{dataset_id}:{version}", {"count": len(list(edges))})
        return v

    async def add_lineage_out(self, dataset_id: str, version: str, edges: Iterable[LineageEdge], *, actor: str = "system") -> DatasetVersion:
        async with self._rw_lock:
            v = await self._store.get_version(dataset_id, version)
            v.lineage_out = tuple(list(v.lineage_out) + list(edges))
            v.revision += 1
            v.refresh_etag()
            await self._store.put_version(v, upsert=True)
        await self._audit(actor, "add_lineage_out", "version", f"{dataset_id}:{version}", {"count": len(list(edges))})
        return v

    # ------------------------------- Поиск ------------------------------------

    async def search(
        self,
        *,
        name_like: Optional[str] = None,
        tags_all: Optional[Iterable[str]] = None,
        owner: Optional[str] = None,
        status_in: Optional[Iterable[DatasetStatus]] = None,
        domain: Optional[str] = None,
    ) -> List[DatasetDescriptor]:
        ids = await self._store.search(
            name_like=name_like,
            tags_all=set(tags_all or ()),
            owner=owner,
            status_in=set(status_in or ()),
            domain=domain,
        )
        # батч-загрузка
        result: List[DatasetDescriptor] = []
        for dsid in ids:
            try:
                result.append(await self._store.get_dataset(dsid))
            except NotFoundError:
                # конкурентное удаление — пропускаем
                continue
        return result


# ------------------------------- Утилиты --------------------------------------

def infer_schema_from_records(records: Sequence[Dict[str, Any]], *, sample: int = 1000) -> DatasetSchema:
    """
    Грубая эвристика определения схемы по записям (для initial bootstrap).
    """
    if not records:
        raise ValidationError("records cannot be empty for schema inference.")
    names: Dict[str, str] = {}
    n = 0
    for r in records[:sample]:
        for k, v in r.items():
            t = _infer_type(v)
            names[k] = _merge_type(names.get(k), t)
        n += 1
    fields = tuple(SchemaField(name=k, type=tp, nullable=True) for k, tp in sorted(names.items()))
    return DatasetSchema(fields=fields, schema_version="inferred-1")

def _infer_type(v: Any) -> str:
    if v is None:
        return "string"  # по умолчанию
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int) and not isinstance(v, bool):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, (list, tuple)):
        inner = _infer_type(v[0]) if v else "string"
        return f"array<{inner}>"
    if isinstance(v, dict):
        return "struct"
    return "string"

def _merge_type(old: Optional[str], new: str) -> str:
    if old is None:
        return new
    if old == new:
        return old
    # упрощённые правила приведения
    if {old, new} == {"int", "float"}:
        return "float"
    return "string"


def validate_record_against_schema(record: Dict[str, Any], schema: DatasetSchema) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    sfields = {f.name: f for f in schema.fields}
    for name, field in sfields.items():
        if name not in record:
            if not field.nullable:
                errors.append(f"missing required field: {name}")
            continue
        val = record[name]
        if val is None and not field.nullable:
            errors.append(f"field {name} cannot be null")
            continue
        # типовая проверка (очень базовая)
        if val is not None and not _value_conforms_type(val, field.type):
            errors.append(f"field {name} type mismatch: expected {field.type}, got {type(val).__name__}")
    return (len(errors) == 0), errors

def _value_conforms_type(val: Any, t: str) -> bool:
    try:
        if t == "string":
            return isinstance(val, str)
        if t == "int":
            return isinstance(val, int) and not isinstance(val, bool)
        if t == "float":
            return isinstance(val, (int, float)) and not isinstance(val, bool)
        if t == "bool":
            return isinstance(val, bool)
        if t.startswith("array<") and t.endswith(">"):
            inner = t[len("array<"):-1]
            if not isinstance(val, (list, tuple)):
                return False
            return all(_value_conforms_type(x, inner) for x in val)
        if t == "struct":
            return isinstance(val, dict)
        # прочие типы принимаем как true (делегируем движку ниже по конвейеру)
        return True
    except Exception:
        return False


# ------------------------------- Self-test -----------------------------------

async def _selftest() -> None:
    store = InMemoryRegistryStore()
    reg = DatasetRegistry(store)

    # 1) Создание датасета
    ds = await reg.create_dataset(
        dataset_id="df.s3.sales.orders",
        display_name="Sales Orders",
        owner="team_sales",
        domain="sales",
        tags={"pii", "gold"},
        actor="tester",
    )

    # 2) Создание версии
    schema = DatasetSchema(fields=(
        SchemaField("order_id", "string", False, "Order identifier"),
        SchemaField("amount", "float", False),
        SchemaField("created_at", "string", False),
    ))
    v1 = await reg.create_version(
        dataset_id=ds.dataset_id,
        version="1.0.0",
        schema=schema,
        description="Initial version",
        tags={"gold"},
        actor="tester",
    )

    # 3) Обновление датасета (оптимистическая блокировка)
    ds2 = await reg.update_dataset(ds.dataset_id, expected_etag=ds.etag, mutate={"description": "Updated desc"}, actor="tester")

    # 4) Поиск
    found = await reg.search(name_like="orders", tags_all={"gold"}, owner="team_sales", status_in={DatasetStatus.ACTIVE}, domain="sales")
    assert any(x.dataset_id == "df.s3.sales.orders" for x in found)

    # 5) Валидация записи по схеме
    ok, errs = validate_record_against_schema({"order_id": "A1", "amount": 12.3, "created_at": "2024-01-01"}, schema)
    assert ok and not errs

    # 6) Мягкое удаление/восстановление
    await reg.soft_delete_dataset(ds.dataset_id, actor="tester")
    await reg.restore_dataset(ds.dataset_id, actor="tester")

    # 7) Обновление версии
    v1b = await reg.update_version(ds.dataset_id, "1.0.0", expected_etag=v1.etag, mutate={"description": "patch"}, actor="tester")
    assert v1b.description == "patch"

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_selftest())
        print("DatasetRegistry selftest passed.")
    except Exception as e:
        print(f"DatasetRegistry selftest failed: {e}")
