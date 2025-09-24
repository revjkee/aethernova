# oblivionvault-core/oblivionvault/policy/loader.py
# -*- coding: utf-8 -*-
"""
OblivionVault — Industrial Policy Loader

Назначение:
- Безопасная загрузка и валидация документов политики Retention
- Источники: файловая система (JSON/TOML), переменные окружения (JSON/Base64), in-memory
- Криптографическая целостность: HMAC-SHA256 подпись тела документа ("sig")
- Индексация селекторов (patterns/tags), семвер/priority, временные окна not_before/not_after
- Стратегии резолва: "priority" (по приоритету/версии) или "most_restrictive" (наиболее строгая)
- LRU-кэш результатов, асинхронный watcher (polling) и очередь событий reload

Совместимость:
- Возвращает объекты RetentionPolicy/RetentionMode из oblivionvault.archive.retention_lock

Автор: OblivionVault Team
Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

try:  # Python 3.11+
    import tomllib  # type: ignore
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore

# Внутренние типы хранения
Number = Union[int, float]

# Импорт моделей политики хранения
from ..archive.retention_lock import (
    RetentionPolicy,
    RetentionMode,
)

# =========================
# Исключения
# =========================

class PolicyError(Exception):
    """Базовая ошибка подсистемы политик."""


class PolicySourceError(PolicyError):
    """Ошибка при чтении источника политик."""


class PolicyValidationError(PolicyError):
    """Схема/значения документа политики некорректны."""


class PolicySignatureError(PolicyError):
    """Подпись политики отсутствует/некорректна/неверная."""


class PolicyResolutionError(PolicyError):
    """Ошибка при вычислении применимой политики."""


# =========================
# Вспомогательные утилиты
# =========================

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _canon_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)

def _parse_rfc3339(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    if not _RFC3339.match(ts):
        raise PolicyValidationError(f"Invalid RFC3339 timestamp: {ts}")
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()

# --- Семантическая версия без внешних зависимостей
@dataclass(frozen=True, order=True)
class SemVer:
    major: int
    minor: int
    patch: int
    pre: Tuple[Union[int, str], ...] = dataclasses.field(default_factory=tuple, compare=True)

    _PRE_SPLIT = re.compile(r"[-+]")

    @staticmethod
    def parse(s: str) -> "SemVer":
        # допускаем "1.2.3", "1.2.3-rc.1", "1.2.3+build"
        main, *rest = SemVer._PRE_SPLIT.split(s, maxsplit=1)
        parts = main.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise PolicyValidationError(f"Invalid semver: {s}")
        major, minor, patch = (int(p) for p in parts)
        pre: Tuple[Union[int, str], ...] = tuple()
        if rest:
            pre_raw = rest[0]
            if pre_raw.startswith("rc") or pre_raw.startswith("alpha") or pre_raw.startswith("beta"):
                pre = tuple(int(x) if x.isdigit() else x for x in re.split(r"[.\-]", pre_raw))
        return SemVer(major, minor, patch, pre)

# =========================
# Модель документа политики
# =========================

@dataclass(frozen=True)
class PolicySelector:
    patterns: Tuple[str, ...] = ()
    tags_any: Tuple[str, ...] = ()
    tags_all: Tuple[str, ...] = ()

@dataclass(frozen=True)
class PolicyConstraints:
    not_before: Optional[float] = None
    not_after: Optional[float] = None

class ResolutionStrategy(str, Enum):
    PRIORITY = "priority"           # выбираем документ с max (priority, semver, id)
    MOST_RESTRICTIVE = "most_restrictive"  # объединяем: compliance побеждает, больший срок побеждает

@dataclass(frozen=True)
class PolicyDoc:
    kind: str
    doc_id: str
    version: SemVer
    priority: int
    mode: RetentionMode
    duration_seconds: Optional[int]
    retention_until: Optional[float]
    allow_extension_only: bool
    selector: PolicySelector
    constraints: PolicyConstraints
    sig: Optional[str]
    source_id: str
    raw: Mapping[str, Any]

    def to_retention(self, created_at: float) -> RetentionPolicy:
        if self.retention_until is not None:
            return RetentionPolicy(
                mode=self.mode,
                retention_until=self.retention_until,
                allow_extension_only=self.allow_extension_only,
            )
        if self.duration_seconds is None:
            raise PolicyValidationError(f"Policy {self.doc_id} has neither duration_seconds nor retention_until")
        return RetentionPolicy(
            mode=self.mode,
            duration_seconds=self.duration_seconds,
            allow_extension_only=self.allow_extension_only,
        )

# =========================
# Источники политик
# =========================

class PolicySource(Protocol):
    """Абстракция источника политик."""
    def source_id(self) -> str: ...
    async def list_documents(self) -> List[Mapping[str, Any]]: ...
    async def fingerprint(self) -> str: ...

class FSDirectorySource:
    """
    Файловый источник: рекурсивно читает *.json и *.toml из каталога.
    TOML поддерживается, если доступен tomllib (Py3.11+).
    """
    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)

    def source_id(self) -> str:
        return f"fs:{self.root.resolve()}"

    async def list_documents(self) -> List[Mapping[str, Any]]:
        exts = {".json", ".toml"} if tomllib else {".json"}
        docs: List[Mapping[str, Any]] = []

        def _read_one(p: Path) -> Optional[Mapping[str, Any]]:
            try:
                if p.suffix == ".json":
                    return json.loads(p.read_text(encoding="utf-8"))
                if p.suffix == ".toml" and tomllib:
                    return tomllib.loads(p.read_text(encoding="utf-8"))  # type: ignore
            except Exception as e:
                raise PolicySourceError(f"Failed to read {p}: {e}") from e
            return None

        for path in self.root.rglob("*"):
            if path.is_file() and path.suffix in exts:
                doc = await asyncio.to_thread(_read_one, path)
                if doc is None:
                    continue
                # добавим метаданные пути
                if isinstance(doc, dict):
                    doc.setdefault("_meta", {})  # non-signed service field
                    doc["_meta"]["path"] = str(path)
                docs.append(doc)
        return docs

    async def fingerprint(self) -> str:
        # Хэш по списку файлов + mtime
        parts: List[str] = []
        for p in sorted(self.root.rglob("*")):
            if p.is_file():
                try:
                    stat = p.stat()
                    parts.append(f"{p}:{int(stat.st_mtime)}:{stat.st_size}")
                except FileNotFoundError:
                    continue
        digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
        return digest

class EnvVarJSONSource:
    """
    Источник из переменной окружения: JSON документ или массив документов.
    Поддерживает base64url через префикс "b64:".
    """
    def __init__(self, env_name: str = "OBLIVIONVAULT_POLICY_JSON") -> None:
        self.env = env_name

    def source_id(self) -> str:
        return f"env:{self.env}"

    async def list_documents(self) -> List[Mapping[str, Any]]:
        val = os.getenv(self.env)
        if not val:
            return []
        if val.startswith("b64:"):
            val = _b64u_decode(val[4:]).decode("utf-8")
        try:
            data = json.loads(val)
        except Exception as e:
            raise PolicySourceError(f"Invalid JSON in {self.env}: {e}") from e
        docs: List[Mapping[str, Any]] = []
        if isinstance(data, list):
            docs.extend(data)
        elif isinstance(data, dict):
            docs.append(data)
        else:
            raise PolicySourceError(f"{self.env} must contain JSON object or array")
        for d in docs:
            if isinstance(d, dict):
                d.setdefault("_meta", {})
                d["_meta"]["env"] = self.env
        return docs

    async def fingerprint(self) -> str:
        raw = os.getenv(self.env, "")
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class InMemorySource:
    """Простой источник для тестов/внедрений."""
    def __init__(self, docs: Sequence[Mapping[str, Any]], sid: str = "mem") -> None:
        self._docs = list(docs)
        self._sid = sid
        self._fp = hashlib.sha256(_canon_json(self._docs)).hexdigest()

    def source_id(self) -> str:
        return f"mem:{self._sid}"

    async def list_documents(self) -> List[Mapping[str, Any]]:
        return list(self._docs)

    async def fingerprint(self) -> str:
        return self._fp

# =========================
# Валидация и подпись
# =========================

def _validate_and_build(
    raw: Mapping[str, Any],
    *,
    hmac_key: Optional[bytes],
    require_signature: bool,
    source_id: str,
) -> PolicyDoc:
    if not isinstance(raw, Mapping):
        raise PolicyValidationError("Policy document must be a JSON object")

    # Снимем служебные метаданные при каноникализации
    body = dict(raw)
    meta = body.pop("_meta", None)
    sig = body.get("sig")

    # Подпись (если требуется)
    if require_signature and not sig:
        raise PolicySignatureError("Signature 'sig' required but missing")
    if sig and hmac_key:
        body_no_sig = dict(body)
        body_no_sig.pop("sig", None)
        expected = hmac.new(hmac_key, _canon_json(body_no_sig), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(sig)):
            raise PolicySignatureError("Invalid policy signature")

    # Обязательные поля
    kind = str(body.get("kind", ""))
    if kind != "RetentionPolicy":
        raise PolicyValidationError(f"Unsupported kind: {kind}")

    doc_id = str(body.get("id", "")).strip()
    if not doc_id:
        raise PolicyValidationError("Field 'id' is required and non-empty")

    version = SemVer.parse(str(body.get("version", "0.0.0")))
    priority = int(body.get("priority", 0))

    mode_raw = str(body.get("mode", "")).lower()
    try:
        mode = RetentionMode(mode_raw)
    except Exception:
        raise PolicyValidationError(f"Invalid retention mode: {mode_raw}")

    duration_seconds = body.get("duration_seconds")
    retention_until_raw = body.get("retention_until")
    allow_extension_only = bool(body.get("allow_extension_only", True))

    if duration_seconds is not None:
        if not isinstance(duration_seconds, int) or duration_seconds <= 0:
            raise PolicyValidationError("duration_seconds must be positive integer")
    retention_until: Optional[float] = None
    if retention_until_raw is not None:
        retention_until = _parse_rfc3339(str(retention_until_raw))

    if duration_seconds is None and retention_until is None:
        raise PolicyValidationError("Either duration_seconds or retention_until must be provided")

    # Селекторы
    sel = body.get("selectors", {})
    if not isinstance(sel, Mapping):
        raise PolicyValidationError("selectors must be an object")
    patterns = tuple(str(x) for x in sel.get("patterns", []) if isinstance(x, (str,)))
    tags_any = tuple(str(x) for x in sel.get("tags_any", []) if isinstance(x, (str,)))
    tags_all = tuple(str(x) for x in sel.get("tags_all", []) if isinstance(x, (str,)))

    selector = PolicySelector(patterns=patterns, tags_any=tags_any, tags_all=tags_all)

    # Ограничения по времени жизни документа
    c = body.get("constraints", {})
    if c and not isinstance(c, Mapping):
        raise PolicyValidationError("constraints must be an object")
    not_before = _parse_rfc3339(str(c.get("not_before"))) if c else None
    not_after = _parse_rfc3339(str(c.get("not_after"))) if c else None
    constraints = PolicyConstraints(not_before=not_before, not_after=not_after)

    # Compliance не должен допускать «смягчения» (рекомендация)
    if mode is RetentionMode.compliance and allow_extension_only is False:
        raise PolicyValidationError("compliance policy must have allow_extension_only=true")

    return PolicyDoc(
        kind=kind,
        doc_id=doc_id,
        version=version,
        priority=priority,
        mode=mode,
        duration_seconds=duration_seconds,
        retention_until=retention_until,
        allow_extension_only=allow_extension_only,
        selector=selector,
        constraints=constraints,
        sig=str(sig) if sig else None,
        source_id=source_id,
        raw=raw,
    )

# =========================
# Индексация и резолв
# =========================

def _selector_matches(sel: PolicySelector, object_id: str, tags: Iterable[str]) -> bool:
    tset = set(tags or [])
    if sel.tags_all and not set(sel.tags_all).issubset(tset):
        return False
    if sel.tags_any and tset.isdisjoint(sel.tags_any):
        return False
    if sel.patterns:
        for p in sel.patterns:
            if fnmatch.fnmatchcase(object_id, p):
                return True
        return False
    # если паттернов нет — селектор по тегам уже проверен
    return True

def _doc_active_now(doc: PolicyDoc, now: float) -> bool:
    if doc.constraints.not_before and now < doc.constraints.not_before:
        return False
    if doc.constraints.not_after and now > doc.constraints.not_after:
        return False
    return True

def _prefer(a: PolicyDoc, b: PolicyDoc) -> PolicyDoc:
    """Сравнение по (priority, version, id)."""
    if a.priority != b.priority:
        return a if a.priority > b.priority else b
    if a.version != b.version:
        return a if a.version > b.version else b
    return a if a.doc_id > b.doc_id else b

def _most_restrictive(docs: Sequence[PolicyDoc], created_at: float) -> PolicyDoc:
    """
    Выбор наиболее строгой политики:
    - compliance > governance
    - больший срок хранения строже
    - allow_extension_only: если хотя бы у одного True — итог True
    Преимущества по priority/version используются как tie-break.
    """
    def effective_until(doc: PolicyDoc) -> float:
        if doc.retention_until is not None:
            return doc.retention_until
        assert doc.duration_seconds is not None
        return created_at + float(doc.duration_seconds)

    chosen = docs[0]
    cu = effective_until(chosen)
    for d in docs[1:]:
        du = effective_until(d)
        better = False
        if d.mode is RetentionMode.compliance and chosen.mode is not RetentionMode.compliance:
            better = True
        elif (d.mode is chosen.mode) and du > cu:
            better = True
        if better:
            chosen, cu = d, du
        elif not better:
            # tie-break
            chosen = _prefer(chosen, d)
            cu = effective_until(chosen)
    # enforce allow_extension_only if any requires it
    if any(x.allow_extension_only for x in docs):
        chosen = dataclasses.replace(chosen, allow_extension_only=True)
    return chosen

# =========================
# LRU кэш
# =========================

class _LRU:
    def __init__(self, size: int = 4096) -> None:
        self.size = int(size)
        self._od: OrderedDict[Tuple[str, Tuple[str, ...]], RetentionPolicy] = OrderedDict()

    def get(self, key: Tuple[str, Tuple[str, ...]]) -> Optional[RetentionPolicy]:
        v = self._od.get(key)
        if v is not None:
            self._od.move_to_end(key, last=True)
        return v

    def put(self, key: Tuple[str, Tuple[str, ...]], value: RetentionPolicy) -> None:
        if key in self._od:
            self._od.move_to_end(key, last=True)
        self._od[key] = value
        if len(self._od) > self.size:
            self._od.popitem(last=False)

    def clear(self) -> None:
        self._od.clear()

# =========================
# Основной загрузчик политик
# =========================

@dataclass
class LoaderConfig:
    require_signature: bool = False
    resolution_strategy: ResolutionStrategy = ResolutionStrategy.PRIORITY
    cache_size: int = 4096
    watch_poll_interval: float = 2.0

class PolicyLoader:
    """
    PolicyLoader — безопасная загрузка и резолв политик Retention.

    Публичный API:
      - await load()
      - resolve(object_id: str, tags: Iterable[str], created_at: Optional[datetime]=None) -> Optional[RetentionPolicy]
      - start_watcher() / stop_watcher()
      - get_active_documents() -> List[PolicyDoc]
      - events: asyncio.Queue[str]  # "reloaded:<generation>"
    """
    def __init__(
        self,
        sources: Sequence[PolicySource],
        *,
        hmac_key: Optional[bytes] = None,
        logger: Optional[logging.Logger] = None,
        config: Optional[LoaderConfig] = None,
    ) -> None:
        self.sources = list(sources)
        self.hmac_key = hmac_key
        self.log = logger or logging.getLogger(__name__)
        self.cfg = config or LoaderConfig()
        self._docs: List[PolicyDoc] = []
        self._gen: int = 0
        self._cache = _LRU(self.cfg.cache_size)
        self._lock = asyncio.Lock()
        self._watch_task: Optional[asyncio.Task] = None
        self._last_fp: Dict[str, str] = {}
        self.events: "asyncio.Queue[str]" = asyncio.Queue()

    @property
    def generation(self) -> int:
        return self._gen

    async def load(self) -> int:
        """
        Загружает и валидирует документы из всех источников, перестраивает индекс и очищает кэш.
        Возвращает новый generation.
        """
        async with self._lock:
            docs: List[PolicyDoc] = []
            for src in self.sources:
                sid = src.source_id()
                try:
                    raw_docs = await src.list_documents()
                except Exception as e:
                    raise PolicySourceError(f"{sid}: {e}") from e
                for raw in raw_docs:
                    try:
                        doc = _validate_and_build(
                            raw,
                            hmac_key=self.hmac_key,
                            require_signature=self.cfg.require_signature,
                            source_id=sid,
                        )
                        docs.append(doc)
                    except Exception as e:
                        # жёсткий отказ по одной политике не блокирует остальные, но логируем
                        self.log.error("Policy rejected from %s: %s", sid, e)
                        continue

            # Обновление fingerprint'ов для watcher
            for src in self.sources:
                try:
                    self._last_fp[src.source_id()] = await src.fingerprint()
                except Exception:
                    # не критично
                    pass

            # Сортируем стабильным порядком (priority desc, version desc, id desc)
            docs_sorted = sorted(
                docs,
                key=lambda d: (d.priority, d.version, d.doc_id),
                reverse=True,
            )
            self._docs = docs_sorted
            self._cache.clear()
            self._gen += 1
            await self.events.put(f"reloaded:{self._gen}")
            self.log.info("PolicyLoader: loaded %d documents, generation=%d", len(self._docs), self._gen)
            return self._gen

    def get_active_documents(self) -> List[PolicyDoc]:
        """Текущий снимок списка документов (без копий raw)."""
        return list(self._docs)

    def _resolve_docs(self, object_id: str, tags: Iterable[str], *, created_at: float) -> Optional[PolicyDoc]:
        now = _utc_now().timestamp()
        candidates = [d for d in self._docs if _doc_active_now(d, now) and _selector_matches(d.selector, object_id, tags)]
        if not candidates:
            return None
        if self.cfg.resolution_strategy is ResolutionStrategy.PRIORITY:
            # уже отсортированы по предпочтениям
            return candidates[0]
        # most_restrictive
        return _most_restrictive(candidates, created_at=created_at)

    def resolve(
        self,
        object_id: str,
        tags: Iterable[str] = (),
        *,
        created_at: Optional[dt.datetime] = None,
    ) -> Optional[RetentionPolicy]:
        """
        Синхронный резолв (потокобезопасен при внешнем мьютексе load()).
        Кэширует результат по ключу (object_id, sorted(tags)).
        """
        tkey = tuple(sorted(set(tags)))
        key = (object_id, tkey)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        created_ts = (created_at or _utc_now()).replace(tzinfo=dt.timezone.utc).timestamp()
        doc = self._resolve_docs(object_id, tags, created_at=created_ts)
        if not doc:
            return None
        pol = doc.to_retention(created_at=created_ts)
        self._cache.put(key, pol)
        return pol

    async def resolve_async(
        self,
        object_id: str,
        tags: Iterable[str] = (),
        *,
        created_at: Optional[dt.datetime] = None,
    ) -> Optional[RetentionPolicy]:
        """Асинхронная обёртка (на случай конкуренции с watcher/load)."""
        async with self._lock:
            return self.resolve(object_id, tags, created_at=created_at)

    async def start_watcher(self) -> None:
        """
        Запускает фонового наблюдателя (polling fingerprint'ов источников).
        Перезагружает политики при изменениях.
        """
        if self._watch_task and not self._watch_task.done():
            return

        async def _watch() -> None:
            self.log.info("PolicyLoader watcher started (interval=%.2fs)", self.cfg.watch_poll_interval)
            try:
                while True:
                    await asyncio.sleep(self.cfg.watch_poll_interval)
                    changed = False
                    for src in self.sources:
                        sid = src.source_id()
                        try:
                            fp = await src.fingerprint()
                        except Exception:
                            continue
                        if self._last_fp.get(sid) != fp:
                            changed = True
                            self._last_fp[sid] = fp
                    if changed:
                        await self.load()
            except asyncio.CancelledError:
                self.log.info("PolicyLoader watcher cancelled")
                raise

        self._watch_task = asyncio.create_task(_watch(), name="oblivionvault-policy-watcher")

    async def stop_watcher(self) -> None:
        """Останавливает наблюдателя, если он запущен."""
        if self._watch_task and not self._watch_task.done():
            self._watch_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):  # type: ignore
                await self._watch_task
        self._watch_task = None


# =========================
# Пример безопасной выдачи подписи (опционально)
# =========================

def issue_policy_signature(body: Mapping[str, Any], key: bytes) -> str:
    """
    Формирует HMAC-SHA256 подпись для документа политики.
    Внимание: в body не должно быть поля 'sig'. Служебные поля '_meta' не подписываются.
    """
    b = dict(body)
    b.pop("sig", None)
    b.pop("_meta", None)
    return hmac.new(key, _canon_json(b), hashlib.sha256).hexdigest()


__all__ = [
    "PolicyLoader",
    "LoaderConfig",
    "ResolutionStrategy",
    "PolicyDoc",
    "PolicySelector",
    "PolicyConstraints",
    "PolicyError",
    "PolicySourceError",
    "PolicyValidationError",
    "PolicySignatureError",
    "PolicyResolutionError",
    "PolicySource",
    "FSDirectorySource",
    "EnvVarJSONSource",
    "InMemorySource",
    "issue_policy_signature",
]
