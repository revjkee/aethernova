# cybersecurity-core/cybersecurity/adversary_emulation/registry.py
# -*- coding: utf-8 -*-
"""
Промышленный реестр для эмуляции противника (Adversary Emulation).

Возможности:
- Регистрация действий эмуляции (EmulationAction) и профилей (AdversaryProfile)
- Потокобезопасность (RLock), иммутабельные dataclass'ы (frozen) и copy-on-write
- Загрузка определений из файлов/директорий/глобов (.yml/.yaml/.json)
- Безопасный YAML loader с детекцией дубликатов ключей
- Минимальная структурная валидация и опциональная JSON Schema валидация (если установлен jsonschema)
- Нормализация полей (строки/списки, сортировка тегов, платформ)
- Детерминированная идентификация (hash-подход), контроль дубликатов
- Поиск/фильтрация по tactic/technique_id/platform/tags
- Экспорт в JSONL (атомарная запись) и импорт плагинов через entry points

Зависимости:
- stdlib
- PyYAML (рекомендуется) — для YAML
- jsonschema (опционально) — для валидации по схеме
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import fnmatch
import gzip
import hashlib
import importlib
import importlib.metadata as imeta
import io
import json
import logging
import os
import re
import threading
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Set

# --- Логирование ----------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# --- Опциональные зависимости ---------------------------------------------------

try:  # YAML (рекомендуется)
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:  # JSON Schema (опционально)
    import jsonschema  # type: ignore
except Exception:  # pragma: no cover
    jsonschema = None  # type: ignore

# --- Безопасный YAML Loader с детекцией дубликатов ключей -----------------------

if yaml is not None:
    class DuplicateKeySafeLoader(yaml.SafeLoader):
        pass

    def _construct_mapping(loader: DuplicateKeySafeLoader, node: yaml.nodes.MappingNode, deep: bool = False) -> Any:
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key: {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    DuplicateKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_mapping,
    )

# --- Утилиты --------------------------------------------------------------------

def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def _sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="strict")
    return hashlib.sha256(data).hexdigest()

def _file_sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _as_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return tuple()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(x) for x in value)
    return (str(value),)

def _norm_nonempty_str(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = str(s).strip()
    return s or None

# --- Исключения -----------------------------------------------------------------

class RegistryError(Exception):
    pass

class ValidationError(RegistryError):
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or []

class DuplicateIdError(RegistryError):
    pass

# --- Схемы (минимальные) --------------------------------------------------------

ACTION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["name", "technique_id", "tactic", "executor", "command"],
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "tactic": {"type": "string"},
        "technique_id": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},  # T1059 или T1059.001
        "subtechnique_id": {"type": "string"},
        "platforms": {
            "anyOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}}
            ]
        },
        "executor": {"type": "string"},  # powershell, cmd, bash, python, etc.
        "command": {"type": "string"},
        "arguments": {"type": "array", "items": {"type": "string"}},
        "prerequisites": {"type": "array", "items": {"type": "string"}},
        "permissions_required": {"type": "array", "items": {"type": "string"}},
        "cleanup": {"type": "string"},
        "references": {"type": "array", "items": {"type": "string"}},
        "tags": {"type": "array", "items": {"type": "string"}},
        "author": {"type": "string"},
        "created": {"type": "string"},
        "modified": {"type": "string"},
        "version": {"type": "string"}
    },
    "additionalProperties": True,
}

PROFILE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["name"],
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "techniques": {"type": "array", "items": {"type": "string"}},
        "groups": {"type": "array", "items": {"type": "string"}},
        "references": {"type": "array", "items": {"type": "string"}},
        "tags": {"type": "array", "items": {"type": "string"}},
        "actions": {"type": "array", "items": {"type": "string"}},
        "author": {"type": "string"},
        "created": {"type": "string"},
        "modified": {"type": "string"},
        "version": {"type": "string"}
    },
    "additionalProperties": True,
}

# --- Модели ---------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class EmulationAction:
    action_id: str
    name: str
    tactic: str
    technique_id: str
    executor: str
    command: str

    # Опциональные
    description: Optional[str] = None
    subtechnique_id: Optional[str] = None
    platforms: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    arguments: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    prerequisites: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    permissions_required: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    cleanup: Optional[str] = None
    references: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    tags: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    author: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    version: str = "1"

    # Происхождение
    source_path: Optional[str] = None
    checksum: Optional[str] = None
    import_ts: Optional[str] = None

    # Исходник
    raw: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "name": self.name,
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "subtechnique_id": self.subtechnique_id,
            "executor": self.executor,
            "command": self.command,
            "description": self.description,
            "platforms": list(self.platforms),
            "arguments": list(self.arguments),
            "prerequisites": list(self.prerequisites),
            "permissions_required": list(self.permissions_required),
            "cleanup": self.cleanup,
            "references": list(self.references),
            "tags": list(self.tags),
            "author": self.author,
            "created": self.created,
            "modified": self.modified,
            "version": self.version,
            "source_path": self.source_path,
            "checksum": self.checksum,
            "import_ts": self.import_ts,
            "raw": self.raw,
        }

@dataclasses.dataclass(frozen=True)
class AdversaryProfile:
    adversary_id: str
    name: str
    description: Optional[str] = None
    techniques: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    groups: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    references: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    tags: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    actions: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    author: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    version: str = "1"

    source_path: Optional[str] = None
    checksum: Optional[str] = None
    import_ts: Optional[str] = None

    raw: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adversary_id": self.adversary_id,
            "name": self.name,
            "description": self.description,
            "techniques": list(self.techniques),
            "groups": list(self.groups),
            "references": list(self.references),
            "tags": list(self.tags),
            "actions": list(self.actions),
            "author": self.author,
            "created": self.created,
            "modified": self.modified,
            "version": self.version,
            "source_path": self.source_path,
            "checksum": self.checksum,
            "import_ts": self.import_ts,
            "raw": self.raw,
        }

# --- Нормализация и валидация ---------------------------------------------------

def _validate_schema(obj: Dict[str, Any], schema: Dict[str, Any], strict: bool) -> List[str]:
    """
    Возвращает список ошибок. Если jsonschema недоступен — выполняется только минимальная проверка required.
    """
    errors: List[str] = []

    # Минимальная проверка required
    req = schema.get("required", [])
    for k in req:
        if k not in obj or (obj[k] is None) or (isinstance(obj[k], str) and not obj[k].strip()):
            errors.append(f"Missing required field: {k}")

    # Опциональная jsonschema-валидация
    if jsonschema is not None:
        try:
            jsonschema.validate(obj, schema)  # type: ignore[attr-defined]
        except Exception as exc:
            errors.append(str(exc))
    elif strict:
        errors.append("jsonschema is not installed but strict validation requested")

    return errors

def _norm_action_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(d)
    out["name"] = (out.get("name") or "").strip()
    out["tactic"] = (out.get("tactic") or "").strip()
    out["technique_id"] = (out.get("technique_id") or "").strip()
    out["executor"] = (out.get("executor") or "").strip()
    out["command"] = out.get("command") or ""
    out["subtechnique_id"] = _norm_nonempty_str(out.get("subtechnique_id"))
    out["description"] = _norm_nonempty_str(out.get("description"))
    out["cleanup"] = _norm_nonempty_str(out.get("cleanup"))
    out["author"] = _norm_nonempty_str(out.get("author"))
    out["created"] = _norm_nonempty_str(out.get("created") or out.get("date"))
    out["modified"] = _norm_nonempty_str(out.get("modified"))
    out["version"] = _norm_nonempty_str(out.get("version")) or "1"

    out["platforms"] = sorted(_as_tuple(out.get("platforms")))
    out["arguments"] = tuple(_as_tuple(out.get("arguments")))
    out["prerequisites"] = tuple(_as_tuple(out.get("prerequisites")))
    out["permissions_required"] = tuple(_as_tuple(out.get("permissions_required")))
    out["references"] = tuple(_as_tuple(out.get("references")))
    out["tags"] = tuple(sorted(set(map(str, _as_tuple(out.get("tags"))))))
    return out

def _norm_profile_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(d)
    out["name"] = (out.get("name") or "").strip()
    out["description"] = _norm_nonempty_str(out.get("description"))
    out["author"] = _norm_nonempty_str(out.get("author"))
    out["created"] = _norm_nonempty_str(out.get("created") or out.get("date"))
    out["modified"] = _norm_nonempty_str(out.get("modified"))
    out["version"] = _norm_nonempty_str(out.get("version")) or "1"

    out["techniques"] = tuple(sorted(set(map(str, _as_tuple(out.get("techniques"))))))
    out["groups"] = tuple(sorted(set(map(str, _as_tuple(out.get("groups"))))))
    out["references"] = tuple(_as_tuple(out.get("references")))
    out["tags"] = tuple(sorted(set(map(str, _as_tuple(out.get("tags"))))))
    out["actions"] = tuple(sorted(set(map(str, _as_tuple(out.get("actions"))))))
    return out

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

def _deterministic_action_id(payload: Dict[str, Any]) -> str:
    # Значимые поля: name, tactic, technique_id, executor, command, tags
    significant = {
        "name": payload.get("name"),
        "tactic": payload.get("tactic"),
        "technique_id": payload.get("technique_id"),
        "executor": payload.get("executor"),
        "command": payload.get("command"),
        "tags": sorted(payload.get("tags") or []),
    }
    blob = json.dumps(significant, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(blob)

def _deterministic_profile_id(payload: Dict[str, Any]) -> str:
    significant = {
        "name": payload.get("name"),
        "techniques": sorted(payload.get("techniques") or []),
        "actions": sorted(payload.get("actions") or []),
        "tags": sorted(payload.get("tags") or []),
    }
    blob = json.dumps(significant, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(blob)

# --- Загрузка файлов ------------------------------------------------------------

DEFAULT_PATTERNS = ("*.yml", "*.yaml", "*.json")

def _iter_files(inputs: Sequence[str], recursive: bool, patterns: Sequence[str] = DEFAULT_PATTERNS) -> Iterator[Path]:
    seen: Set[Path] = set()
    for item in inputs:
        p = Path(item)
        if p.is_file():
            if any(fnmatch.fnmatch(p.name, pat) for pat in patterns):
                if p not in seen:
                    seen.add(p); yield p
        elif p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            for f in it:
                if f.is_file() and any(fnmatch.fnmatch(f.name, pat) for pat in patterns):
                    if f not in seen:
                        seen.add(f); yield f
        else:
            # glob
            for f in Path().glob(item):
                if f.is_file() and any(fnmatch.fnmatch(f.name, pat) for pat in patterns):
                    if f not in seen:
                        seen.add(f); yield f

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def _parse_yaml_or_json(text: str, path: Optional[Path]) -> Dict[str, Any]:
    if path and path.suffix.lower() == ".json":
        return json.loads(text)
    if yaml is None:
        # JSON-парсер попробует разобрать YAML-супермножество, но это риск; явно сообщим
        raise ValidationError("PyYAML is not installed; cannot parse YAML", [])
    return yaml.load(text, Loader=DuplicateKeySafeLoader) or {}

# --- Экспорт --------------------------------------------------------------------

def _write_jsonl_atomic(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    gz = str(path).endswith(".gz")
    if gz:
        with tempfile.NamedTemporaryFile(delete=False, dir=str(path.parent)) as tmp:
            tmppath = Path(tmp.name)
        with gzip.open(tmppath, "wt", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        tmppath.replace(path)
    else:
        with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as tmp:
            for row in rows:
                tmp.write(json.dumps(row, ensure_ascii=False) + "\n")
            tmppath = Path(tmp.name)
        tmppath.replace(path)

# --- Реестр ---------------------------------------------------------------------

class AdversaryRegistry:
    """
    Потокобезопасный реестр действий и профилей.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._actions: Dict[str, EmulationAction] = {}
        self._profiles: Dict[str, AdversaryProfile] = {}

    # -- Регистрация / удаление --

    def register_action(self, action: EmulationAction, *, overwrite: bool = False) -> None:
        with self._lock:
            if not overwrite and action.action_id in self._actions:
                raise DuplicateIdError(f"Action id already exists: {action.action_id}")
            self._actions[action.action_id] = action

    def unregister_action(self, action_id: str) -> None:
        with self._lock:
            self._actions.pop(action_id, None)

    def register_profile(self, profile: AdversaryProfile, *, overwrite: bool = False) -> None:
        with self._lock:
            if not overwrite and profile.adversary_id in self._profiles:
                raise DuplicateIdError(f"Adversary id already exists: {profile.adversary_id}")
            self._profiles[profile.adversary_id] = profile

    def unregister_profile(self, adversary_id: str) -> None:
        with self._lock:
            self._profiles.pop(adversary_id, None)

    # -- Получение / список --

    def get_action(self, action_id: str) -> Optional[EmulationAction]:
        with self._lock:
            return self._actions.get(action_id)

    def get_profile(self, adversary_id: str) -> Optional[AdversaryProfile]:
        with self._lock:
            return self._profiles.get(adversary_id)

    def list_actions(
        self,
        *,
        tactic: Optional[str] = None,
        technique_id: Optional[str] = None,
        platform: Optional[str] = None,
        tags_any: Optional[Iterable[str]] = None,
    ) -> List[EmulationAction]:
        with self._lock:
            items = list(self._actions.values())
        if tactic:
            items = [a for a in items if a.tactic == tactic]
        if technique_id:
            items = [a for a in items if a.technique_id == technique_id]
        if platform:
            items = [a for a in items if platform in a.platforms]
        if tags_any:
            s = set(tags_any)
            items = [a for a in items if s.intersection(a.tags)]
        return sorted(items, key=lambda x: (x.technique_id, x.name))

    def list_profiles(self, *, tag: Optional[str] = None) -> List[AdversaryProfile]:
        with self._lock:
            items = list(self._profiles.values())
        if tag:
            items = [p for p in items if tag in p.tags]
        return sorted(items, key=lambda x: x.name)

    # -- Загрузка из файлов --

    def load_actions_from_paths(
        self,
        inputs: Sequence[str],
        *,
        recursive: bool = True,
        strict: bool = False,
        schema: Optional[Dict[str, Any]] = ACTION_SCHEMA,
        overwrite: bool = False,
        id_strategy: str = "hash",  # "hash" | "native"
    ) -> int:
        """
        Возвращает число успешно загруженных действий.
        """
        count = 0
        for path in _iter_files(inputs, recursive=recursive):
            try:
                text = _read_text(path)
                obj = _parse_yaml_or_json(text, path)
                if isinstance(obj, list):
                    for idx, d in enumerate(obj):
                        count += self._ingest_action_dict(d, path, strict=strict, schema=schema,
                                                          overwrite=overwrite, id_strategy=id_strategy, seq_index=idx)
                else:
                    count += self._ingest_action_dict(obj, path, strict=strict, schema=schema,
                                                      overwrite=overwrite, id_strategy=id_strategy, seq_index=None)
            except Exception as exc:
                if strict:
                    raise
                logger.warning("Failed to load action file %s: %s", path, exc)
        return count

    def load_profiles_from_paths(
        self,
        inputs: Sequence[str],
        *,
        recursive: bool = True,
        strict: bool = False,
        schema: Optional[Dict[str, Any]] = PROFILE_SCHEMA,
        overwrite: bool = False,
        id_strategy: str = "hash",  # "hash" | "native"
    ) -> int:
        count = 0
        for path in _iter_files(inputs, recursive=recursive):
            try:
                text = _read_text(path)
                obj = _parse_yaml_or_json(text, path)
                if isinstance(obj, list):
                    for idx, d in enumerate(obj):
                        count += self._ingest_profile_dict(d, path, strict=strict, schema=schema,
                                                           overwrite=overwrite, id_strategy=id_strategy, seq_index=idx)
                else:
                    count += self._ingest_profile_dict(obj, path, strict=strict, schema=schema,
                                                       overwrite=overwrite, id_strategy=id_strategy, seq_index=None)
            except Exception as exc:
                if strict:
                    raise
                logger.warning("Failed to load profile file %s: %s", path, exc)
        return count

    # -- Плагины (entry points) --

    def discover_plugins(self, group: str = "cybersecurity.adversary_actions") -> int:
        """
        Ожидается, что entry point возвращает Iterable[Dict[str, Any]] или Iterable[EmulationAction].
        """
        added = 0
        for ep in imeta.entry_points().select(group=group):
            try:
                factory = ep.load()
                payloads = list(factory())  # type: ignore[call-arg]
                for item in payloads:
                    if isinstance(item, EmulationAction):
                        self.register_action(item, overwrite=False)
                        added += 1
                    else:
                        added += self._ingest_action_dict(item, path=None, strict=False, schema=ACTION_SCHEMA,
                                                          overwrite=False, id_strategy="hash", seq_index=None)
            except Exception as exc:  # pragma: no cover (зависит от внешних env)
                logger.warning("Plugin %s failed: %s", ep.name, exc)
        return added

    # -- Экспорт --

    def export_actions_jsonl(self, path: str | Path) -> int:
        """
        Экспорт действий в JSONL (поддержка .gz).
        """
        with self._lock:
            rows = [a.to_dict() for a in self._actions.values()]
        _write_jsonl_atomic(Path(path), rows)
        return len(rows)

    def export_profiles_jsonl(self, path: str | Path) -> int:
        with self._lock:
            rows = [p.to_dict() for p in self._profiles.values()]
        _write_jsonl_atomic(Path(path), rows)
        return len(rows)

    # -- Внутреннее поглощение словарей --

    def _ingest_action_dict(
        self,
        d: Dict[str, Any],
        path: Optional[Path],
        *,
        strict: bool,
        schema: Optional[Dict[str, Any]],
        overwrite: bool,
        id_strategy: str,
        seq_index: Optional[int],
    ) -> int:
        if not isinstance(d, dict):
            if strict:
                raise ValidationError("Action payload must be a mapping", [])
            logger.warning("Skip non-mapping action in %s", path)
            return 0

        d = _norm_action_dict(d)
        errors = _validate_schema(d, ACTION_SCHEMA if schema is None else schema, strict)
        if d.get("technique_id") and not _TECHNIQUE_ID_RE.match(d["technique_id"]):
            errors.append(f"Invalid technique_id format: {d['technique_id']}")

        if errors:
            if strict:
                raise ValidationError("Action validation failed", errors)
            logger.warning("Action validation errors in %s: %s", path, errors)
            return 0

        native_id = _norm_nonempty_str(d.get("id"))
        if id_strategy == "native" and native_id:
            action_id = native_id
        else:
            action_id = _deterministic_action_id(d)

        checksum = _file_sha256_hex(path) if path else None
        import_ts = _utc_now_iso()
        src_path = str(path) if path else None

        action = EmulationAction(
            action_id=action_id,
            name=d["name"],
            tactic=d["tactic"],
            technique_id=d["technique_id"],
            subtechnique_id=_norm_nonempty_str(d.get("subtechnique_id")),
            executor=d["executor"],
            command=d["command"],
            description=_norm_nonempty_str(d.get("description")),
            platforms=tuple(d.get("platforms") or ()),
            arguments=tuple(d.get("arguments") or ()),
            prerequisites=tuple(d.get("prerequisites") or ()),
            permissions_required=tuple(d.get("permissions_required") or ()),
            cleanup=_norm_nonempty_str(d.get("cleanup")),
            references=tuple(d.get("references") or ()),
            tags=tuple(d.get("tags") or ()),
            author=_norm_nonempty_str(d.get("author")),
            created=_norm_nonempty_str(d.get("created")),
            modified=_norm_nonempty_str(d.get("modified")),
            version=str(d.get("version") or "1"),
            source_path=src_path,
            checksum=checksum,
            import_ts=import_ts,
            raw=d,
        )
        self.register_action(action, overwrite=overwrite)
        return 1

    def _ingest_profile_dict(
        self,
        d: Dict[str, Any],
        path: Optional[Path],
        *,
        strict: bool,
        schema: Optional[Dict[str, Any]],
        overwrite: bool,
        id_strategy: str,
        seq_index: Optional[int],
    ) -> int:
        if not isinstance(d, dict):
            if strict:
                raise ValidationError("Profile payload must be a mapping", [])
            logger.warning("Skip non-mapping profile in %s", path)
            return 0

        d = _norm_profile_dict(d)
        errors = _validate_schema(d, PROFILE_SCHEMA if schema is None else schema, strict)

        if errors:
            if strict:
                raise ValidationError("Profile validation failed", errors)
            logger.warning("Profile validation errors in %s: %s", path, errors)
            return 0

        native_id = _norm_nonempty_str(d.get("id"))
        adversary_id = native_id if (id_strategy == "native" and native_id) else _deterministic_profile_id(d)

        checksum = _file_sha256_hex(path) if path else None
        import_ts = _utc_now_iso()
        src_path = str(path) if path else None

        profile = AdversaryProfile(
            adversary_id=adversary_id,
            name=d["name"],
            description=_norm_nonempty_str(d.get("description")),
            techniques=tuple(d.get("techniques") or ()),
            groups=tuple(d.get("groups") or ()),
            references=tuple(d.get("references") or ()),
            tags=tuple(d.get("tags") or ()),
            actions=tuple(d.get("actions") or ()),
            author=_norm_nonempty_str(d.get("author")),
            created=_norm_nonempty_str(d.get("created")),
            modified=_norm_nonempty_str(d.get("modified")),
            version=str(d.get("version") or "1"),
            source_path=src_path,
            checksum=checksum,
            import_ts=import_ts,
            raw=d,
        )
        self.register_profile(profile, overwrite=overwrite)
        return 1
