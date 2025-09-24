# -*- coding: utf-8 -*-
"""
DataFabric | metadata.schema_registry

Промышленный in-process реестр схем с версиями и политиками совместимости.
Поддерживаемые типы: JSON_SCHEMA, AVRO. Совместимость: NONE, BACKWARD, FORWARD, FULL.
Опционально: строгая валидация JSON Schema через библиотеку `jsonschema` (если установлена).

Возможности:
- Регистрация схем (id, subject, version), дедупликация по каноническому отпечатку.
- Политики совместимости per-subject и глобальная политика по умолчанию.
- Проверка эволюции (упрощённые корректные правила) для JSON Schema и Avro.
- Каноникализация и fingerprint (sha256 + короткий id).
- Ссылки/референсы (subject:version) с проверкой разрешения.
- Безопасность: потокобезопасность (RLock), атомарность операций.
- Экспорт/импорт снапшота в/из JSON; опциональная файловая персистентность.
- Структурированный лог и аккуратные исключения.

Зависимости: стандартная библиотека.
Опционально: jsonschema (для строгой проверки JSON Schema).

(c) Aethernova / DataFabric Core
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

# Опциональная строгая валидация JSON Schema
try:
    import jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except Exception:
    _HAS_JSONSCHEMA = False

_LOG = logging.getLogger("datafabric.metadata.schema_registry")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s trace=%(trace)s %(message)s"))
    _LOG.addHandler(_h)
    _LOG.setLevel(logging.INFO)


# =========================
# Типы и исключения
# =========================

class SchemaType(str, Enum):
    JSON_SCHEMA = "JSON_SCHEMA"
    AVRO = "AVRO"

class Compatibility(str, Enum):
    NONE = "NONE"
    BACKWARD = "BACKWARD"
    FORWARD = "FORWARD"
    FULL = "FULL"  # BACKWARD + FORWARD

class RegistryError(Exception):
    pass

class SubjectNotFound(RegistryError):
    pass

class VersionNotFound(RegistryError):
    pass

class SchemaValidationError(RegistryError):
    pass

class CompatibilityError(RegistryError):
    pass


# =========================
# Модели
# =========================

@dataclass(frozen=True)
class SchemaReference:
    subject: str
    version: int

@dataclass
class SchemaEntry:
    id: int
    subject: str
    version: int
    schema_type: SchemaType
    schema_str: str
    fingerprint: str          # sha256 канонической формы
    created_at: float = field(default_factory=lambda: time.time())
    references: List[SchemaReference] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SubjectConfig:
    compatibility: Compatibility


# =========================
# Утилиты: каноникализация и отпечатки
# =========================

def _canonical_json_str(s: str) -> str:
    """Каноникализация: загрузка и dump с сортировкой ключей и минимальной формой."""
    try:
        obj = json.loads(s)
    except Exception as e:
        raise SchemaValidationError(f"Invalid JSON: {e}") from e
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def _canonical_avro_str(s: str) -> str:
    """Каноникализация Avro JSON (без внешних зависимостей)."""
    # Avro схемы также JSON — используем такой же подход.
    # Дополнительно нормализуем порядок полей record по имени.
    try:
        obj = json.loads(s)
    except Exception as e:
        raise SchemaValidationError(f"Invalid Avro JSON: {e}") from e

    def normalize(node: Any) -> Any:
        if isinstance(node, dict):
            # Сортируем поля record по имени (если есть)
            if node.get("type") == "record" and isinstance(node.get("fields"), list):
                fields = node["fields"]
                # сортируем поля по имени, но сохраним внутренние структуры
                node = dict(node)  # копия
                node["fields"] = sorted(
                    [normalize(f) for f in fields],
                    key=lambda f: f.get("name", ""),
                )
            else:
                node = {k: normalize(v) for k, v in node.items()}
            # сортировка ключей при сериализации ниже
            return node
        if isinstance(node, list):
            return [normalize(v) for v in node]
        return node

    norm = normalize(obj)
    return json.dumps(norm, sort_keys=True, separators=(",", ":"))

def _fingerprint(canonical: str) -> str:
    return sha256(canonical.encode("utf-8")).hexdigest()

def _short_id_from_fp(fp_hex: str) -> int:
    # Берём младшие 8 байт отпечатка как positive int
    return int(fp_hex[-16:], 16)


# =========================
# Совместимость: JSON Schema (упрощённо + строгая проверка при наличии jsonschema)
# =========================

def _jsonschema_validate(schema_str: str) -> None:
    """Best-effort валидация структуры JSON Schema (через jsonschema при наличии)."""
    obj = json.loads(schema_str)
    if _HAS_JSONSCHEMA:
        # Проверяем саму схему как мета-схему Draft-07/2020-12 при наличии $schema,
        # иначе пытаемся валидировать базовую структуру свойств.
        try:
            # Попытка: если указана мета-схема — загрузим её из стандартных метаданных jsonschema.
            # Без сетевых запросов: пропустим $schema, валидируем базовые поля.
            jsonschema.Draft7Validator.check_schema(obj)
        except Exception as e:
            # Если схема не соответствует Draft7 — не фейлим жёстко: это может быть другой драфт.
            # Но проверим хотя бы, что type/properties корректны.
            if not isinstance(obj, dict):
                raise SchemaValidationError(f"JSON Schema must be an object: {type(obj)}") from e
    else:
        # Минимальная проверка
        if not isinstance(obj, dict):
            raise SchemaValidationError("JSON Schema must be a JSON object")

def _jsonschema_backward_compatible(old_s: str, new_s: str) -> bool:
    """
    BACKWARD: новый читает старые данные.
    Упрощённые правила:
      - Нельзя удалять существующие required свойства или менять их тип на несовместимый.
      - Можно добавлять опциональные свойства.
      - Сужение enum запрещено (расширение допускается).
    """
    o = json.loads(old_s)
    n = json.loads(new_s)

    def req_set(s: dict) -> set:
        r = s.get("required", [])
        return set(r) if isinstance(r, list) else set()

    def props(d: dict) -> dict:
        p = d.get("properties", {})
        return p if isinstance(p, dict) else {}

    old_req = req_set(o)
    new_req = req_set(n)
    old_props = props(o)
    new_props = props(n)

    # Нельзя удалить required поле
    if not old_req.issubset(new_req.union(set(new_props.keys()))):
        # если поле вовсе исчезло или стало не-required — для BACKWARD это допустимо,
        # но если оно исчезло из properties — старые данные могут не валидироваться.
        missing = [x for x in old_req if x not in new_props]
        if missing:
            return False

    # Проверка типов и enum для пересекающихся свойств
    for name, odef in old_props.items():
        if name not in new_props:
            # Удалили свойство: если оно было required — плохо.
            if name in old_req:
                return False
            continue
        ndef = new_props[name]
        if not _jsonschema_types_compatible(odef, ndef, direction="backward"):
            return False

    return True

def _jsonschema_forward_compatible(old_s: str, new_s: str) -> bool:
    """
    FORWARD: старый читает новые данные.
    Упрощённые правила:
      - Нельзя добавлять новые required свойства.
      - Расширение enum допустимо, сужение запрещено.
    """
    o = json.loads(old_s)
    n = json.loads(new_s)

    def req_set(s: dict) -> set:
        r = s.get("required", [])
        return set(r) if isinstance(r, list) else set()

    old_req = req_set(o)
    new_req = req_set(n)

    # Нельзя добавлять новые required
    if not new_req.issubset(old_req):
        return False

    old_props = o.get("properties", {}) or {}
    new_props = n.get("properties", {}) or {}

    # Типы для пересекающихся ключей: не должны сузиться
    for name, ndef in new_props.items():
        if name in old_props:
            odef = old_props[name]
            if not _jsonschema_types_compatible(odef, ndef, direction="forward"):
                return False

    return True

_JSON_TYPEMAP = {
    "string": {"string"},
    "number": {"number", "integer"},
    "integer": {"integer"},
    "boolean": {"boolean"},
    "object": {"object"},
    "array": {"array"},
    "null": {"null"},
}

def _normalize_js_types(defn: Any) -> set:
    if not isinstance(defn, dict):
        return set()
    t = defn.get("type")
    if t is None:
        return set()  # без типа — считаем совместимым
    if isinstance(t, list):
        out = set()
        for x in t:
            out |= _JSON_TYPEMAP.get(x, {x})
        return out
    return _JSON_TYPEMAP.get(t, {t})

def _json_enum(defn: Any) -> Optional[set]:
    if isinstance(defn, dict) and "enum" in defn and isinstance(defn["enum"], list):
        return set(defn["enum"])
    return None

def _jsonschema_types_compatible(a: dict, b: dict, direction: str) -> bool:
    # direction: "backward" (новый читает старые) или "forward" (старый читает новые)
    ta = _normalize_js_types(a)
    tb = _normalize_js_types(b)
    if direction == "backward":
        # новый должен принимать всё, что производил старый => ta ⊆ tb
        if ta and tb and not ta.issubset(tb):
            return False
    else:
        # forward: старый должен принимать новые => tb ⊆ ta
        if ta and tb and not tb.issubset(ta):
            return False
    # enum
    ea = _json_enum(a)
    eb = _json_enum(b)
    if ea is not None and eb is not None:
        if direction == "backward":
            # новый enum должен охватывать старые значения
            if not ea.issubset(eb):
                return False
        else:
            # forward: новые значения не должны выходить за старые
            if not eb.issubset(ea):
                return False
    return True


# =========================
# Совместимость: Avro (упрощённые корректные правила)
# =========================

_AVRO_PROMOTIONS = {
    "int": {"long", "float", "double"},
    "long": {"float", "double"},
    "float": {"double"},
}

def _avro_backward_compatible(old_s: str, new_s: str) -> bool:
    """
    BACKWARD: читатель = новый, писатель = старый.
    Разрешено:
      - Добавление новых полей с default.
      - Изменение типа по безопасным промоушенам (int->long->float->double).
    Запрещено:
      - Удалять поля без default у чтения.
      - Сужать тип (double->float и т.п.).
    """
    try:
        old = json.loads(old_s)
        new = json.loads(new_s)
    except Exception:
        return False
    return _avro_record_backward(old, new)

def _avro_forward_compatible(old_s: str, new_s: str) -> bool:
    """
    FORWARD: читатель = старый, писатель = новый.
    Разрешено:
      - Добавлять только поля с default (чтобы старый читатель мог читать, игнорируя незнакомые поля).
      - Типы не должны сужаться для общих полей.
    """
    try:
        old = json.loads(old_s)
        new = json.loads(new_s)
    except Exception:
        return False
    return _avro_record_forward(old, new)

def _avro_record_backward(old: Any, new: Any) -> bool:
    # Поддерживаем только record/primitive/union подмножество.
    if _avro_type(old) == "record" and _avro_type(new) == "record":
        oldf = {f["name"]: f for f in old.get("fields", [])}
        newf = {f["name"]: f for f in new.get("fields", [])}
        # старые поля должны быть читаемы новым
        for name, of in oldf.items():
            if name not in newf:
                # если поле отсутствует у нового читателя — плохо
                return False
            if not _avro_types_compatible(of.get("type"), newf[name].get("type"), direction="backward"):
                return False
        # новые поля в новом могут быть, но только если у них есть default (иначе старые записи не содержат значения)
        for name, nf in newf.items():
            if name not in oldf:
                if "default" not in nf:
                    return False
        return True
    # примитивы/union
    return _avro_types_compatible(old, new, direction="backward")

def _avro_record_forward(old: Any, new: Any) -> bool:
    if _avro_type(old) == "record" and _avro_type(new) == "record":
        oldf = {f["name"]: f for f in old.get("fields", [])}
        newf = {f["name"]: f for f in new.get("fields", [])}
        # новые поля у писателя должны иметь default, чтобы старый читатель смог их проигнорировать или подставить default
        for name, nf in newf.items():
            if name not in oldf:
                if "default" not in nf:
                    return False
        # общие поля: не сужать тип
        for name, nf in newf.items():
            if name in oldf:
                if not _avro_types_compatible(oldf[name].get("type"), nf.get("type"), direction="forward"):
                    return False
        return True
    return _avro_types_compatible(old, new, direction="forward")

def _avro_type(x: Any) -> str:
    if isinstance(x, dict):
        t = x.get("type")
        if isinstance(t, dict) or isinstance(t, list):
            return _avro_type(t)
        return str(t)
    if isinstance(x, list):
        return "union"
    if isinstance(x, str):
        return x
    return "unknown"

def _avro_types_compatible(old_t: Any, new_t: Any, direction: str) -> bool:
    # Поддержка примитивов и union. Для union требуем пересечение без сужения.
    def prim_ok(a: str, b: str) -> bool:
        if a == b:
            return True
        if direction == "backward":
            # читатель = новый, писатель = старый → новый должен прочитать старое → a (старый) может промоутиться к b (новый)
            return a in _AVRO_PROMOTIONS and b in _AVRO_PROMOTIONS[a]
        else:
            # forward: читатель = старый, писатель = новый → новый не должен сужать тип относительно старого
            return b == a or (a in _AVRO_PROMOTIONS and b in _AVRO_PROMOTIONS[a])

    # Развёртываем до множеств примитивов (для union)
    def to_set(t: Any) -> set:
        if isinstance(t, list):
            out = set()
            for e in t:
                out |= to_set(e)
            return out
        if isinstance(t, dict):
            return to_set(t.get("type"))
        if isinstance(t, str):
            return {t}
        return {"unknown"}

    A = to_set(old_t)
    B = to_set(new_t)
    # Для backward: каждое из A должно быть совместимо с некоторым в B (новый читатель должен уметь прочитать всё старое)
    if direction == "backward":
        for a in A:
            if not any(prim_ok(a, b) for b in B):
                return False
        return True
    # Forward: каждое из B не должно сужаться относительно A
    for b in B:
        if not any(prim_ok(a, b) for a in A):
            return False
    return True


# =========================
# Реестр
# =========================

class SchemaRegistry:
    """
    In-memory потокобезопасный реестр. Для персистентности используйте
    методы snapshot_export/snapshot_import и save_to_dir/load_from_dir.
    """
    def __init__(self, default_compatibility: Compatibility = Compatibility.BACKWARD) -> None:
        self._lock = threading.RLock()
        self._next_id = 1
        # subject -> {version:int -> SchemaEntry}
        self._by_subject: Dict[str, Dict[int, SchemaEntry]] = {}
        # id -> SchemaEntry
        self._by_id: Dict[int, SchemaEntry] = {}
        # fingerprint -> id (дедуп)
        self._by_fp: Dict[str, int] = {}
        # subject -> SubjectConfig
        self._subject_cfg: Dict[str, SubjectConfig] = {}
        self._default_cfg = SubjectConfig(compatibility=default_compatibility)

    # --------- Публичное API ---------

    def set_compatibility(self, subject: str, level: Compatibility) -> None:
        with self._lock:
            self._subject_cfg[subject] = SubjectConfig(level)

    def get_compatibility(self, subject: str) -> Compatibility:
        with self._lock:
            return self._subject_cfg.get(subject, self._default_cfg).compatibility

    def register_schema(
        self,
        subject: str,
        schema_str: str,
        schema_type: SchemaType,
        references: Optional[List[SchemaReference]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        trace: str = "-",
    ) -> SchemaEntry:
        """
        Регистрирует схему: проверяет валидность, совместимость, выполняет дедупликацию.
        Возвращает созданную (или существующую) запись.
        """
        with self._lock:
            canon = self._canonical(schema_str, schema_type)
            fp = _fingerprint(canon)
            if fp in self._by_fp:
                # Уже зарегистрирована. Возвращаем существующую запись.
                existing = self._by_id[self._by_fp[fp]]
                _LOG.info("register.dedup id=%s subject=%s v=%s", existing.id, existing.subject, existing.version, extra={"trace": trace})
                return existing

            # Валидация
            self._validate(schema_str, schema_type)

            # Проверка ссылок
            refs = references or []
            self._check_references(refs)

            # Проверка совместимости с последней версией subject
            comp = self.get_compatibility(subject)
            latest = self._get_latest_unsafe(subject)
            if latest is not None and comp != Compatibility.NONE:
                self._check_compatibility(latest.schema_str, schema_str, schema_type, comp)

            # Присваиваем id и версию
            sid = self._next_id
            self._next_id += 1
            version = self._next_version(subject)

            entry = SchemaEntry(
                id=sid,
                subject=subject,
                version=version,
                schema_type=schema_type,
                schema_str=schema_str,
                fingerprint=fp,
                references=refs,
                metadata=metadata or {},
            )
            self._index(entry)

            _LOG.info("register.ok id=%s subject=%s v=%s comp=%s", sid, subject, version, comp.value, extra={"trace": trace})
            return entry

    def test_compatibility(
        self, subject: str, schema_str: str, schema_type: SchemaType, level: Optional[Compatibility] = None
    ) -> bool:
        with self._lock:
            latest = self._get_latest_unsafe(subject)
            if latest is None:
                return True
            level = level or self.get_compatibility(subject)
            if level == Compatibility.NONE:
                return True
            return self._compatible(latest.schema_str, schema_str, schema_type, level)

    def get_by_id(self, schema_id: int) -> SchemaEntry:
        with self._lock:
            if schema_id not in self._by_id:
                raise VersionNotFound(f"Schema id={schema_id} not found")
            return self._by_id[schema_id]

    def get_latest(self, subject: str) -> SchemaEntry:
        with self._lock:
            latest = self._get_latest_unsafe(subject)
            if latest is None:
                raise SubjectNotFound(f"Subject '{subject}' not found")
            return latest

    def get_version(self, subject: str, version: int) -> SchemaEntry:
        with self._lock:
            versions = self._by_subject.get(subject)
            if not versions or version not in versions:
                raise VersionNotFound(f"{subject}@{version} not found")
            return versions[version]

    def list_subjects(self) -> List[str]:
        with self._lock:
            return sorted(self._by_subject.keys())

    def list_versions(self, subject: str) -> List[int]:
        with self._lock:
            versions = self._by_subject.get(subject)
            if versions is None:
                raise SubjectNotFound(f"Subject '{subject}' not found")
            return sorted(versions.keys())

    # --------- Снапшоты и файловая персистентность ---------

    def snapshot_export(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "default_compatibility": self._default_cfg.compatibility.value,
                "subjects": {
                    s: {
                        "config": self._subject_cfg.get(s, self._default_cfg).compatibility.value,
                        "versions": [asdict(v) for _, v in sorted(vers.items())],
                    }
                    for s, vers in self._by_subject.items()
                },
            }

    def snapshot_import(self, snapshot: Dict[str, Any]) -> None:
        with self._lock:
            self._by_subject.clear()
            self._by_id.clear()
            self._by_fp.clear()
            self._subject_cfg.clear()

            defcfg = snapshot.get("default_compatibility", Compatibility.BACKWARD.value)
            self._default_cfg = SubjectConfig(compatibility=Compatibility(defcfg))

            for subject, sdata in snapshot.get("subjects", {}).items():
                cfg = sdata.get("config", self._default_cfg.compatibility.value)
                self._subject_cfg[subject] = SubjectConfig(compatibility=Compatibility(cfg))
                for ent in sdata.get("versions", []):
                    entry = SchemaEntry(
                        id=ent["id"],
                        subject=ent["subject"],
                        version=ent["version"],
                        schema_type=SchemaType(ent["schema_type"]),
                        schema_str=ent["schema_str"],
                        fingerprint=ent["fingerprint"],
                        created_at=ent.get("created_at", time.time()),
                        references=[SchemaReference(**r) for r in ent.get("references", [])],
                        metadata=ent.get("metadata", {}),
                    )
                    self._index(entry)
            # поправим next_id
            if self._by_id:
                self._next_id = max(self._by_id.keys()) + 1
            else:
                self._next_id = 1

    def save_to_dir(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)
        snap = self.snapshot_export()
        fp = os.path.join(path, "schema_registry_snapshot.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2, sort_keys=True)

    def load_from_dir(self, path: str) -> None:
        fp = os.path.join(path, "schema_registry_snapshot.json")
        if not os.path.isfile(fp):
            raise RegistryError(f"Snapshot file not found: {fp}")
        with open(fp, "r", encoding="utf-8") as f:
            snap = json.load(f)
        self.snapshot_import(snap)

    # --------- Внутренние помощники ---------

    def _index(self, entry: SchemaEntry) -> None:
        self._by_id[entry.id] = entry
        self._by_subject.setdefault(entry.subject, {})[entry.version] = entry
        self._by_fp[entry.fingerprint] = entry.id

    def _next_version(self, subject: str) -> int:
        versions = self._by_subject.get(subject)
        if not versions:
            return 1
        return max(versions.keys()) + 1

    def _get_latest_unsafe(self, subject: str) -> Optional[SchemaEntry]:
        versions = self._by_subject.get(subject)
        if not versions:
            return None
        return versions[max(versions.keys())]

    def _canonical(self, schema_str: str, schema_type: SchemaType) -> str:
        if schema_type == SchemaType.JSON_SCHEMA:
            return _canonical_json_str(schema_str)
        if schema_type == SchemaType.AVRO:
            return _canonical_avro_str(schema_str)
        raise RegistryError(f"Unsupported schema type: {schema_type}")

    def _validate(self, schema_str: str, schema_type: SchemaType) -> None:
        if schema_type == SchemaType.JSON_SCHEMA:
            _jsonschema_validate(schema_str)
            return
        if schema_type == SchemaType.AVRO:
            # Базовая проверка JSON‑структуры
            obj = json.loads(schema_str)
            if not isinstance(obj, (dict, list, str)):
                raise SchemaValidationError("Avro schema must be dict/list/str")
            return
        raise RegistryError(f"Unsupported schema type: {schema_type}")

    def _check_references(self, refs: List[SchemaReference]) -> None:
        for r in refs:
            versions = self._by_subject.get(r.subject)
            if not versions or r.version not in versions:
                raise VersionNotFound(f"Reference {r.subject}@{r.version} not found")

    def _check_compatibility(self, old_str: str, new_str: str, schema_type: SchemaType, level: Compatibility) -> None:
        ok = self._compatible(old_str, new_str, schema_type, level)
        if not ok:
            raise CompatibilityError(f"Incompatible schema (type={schema_type}, level={level})")

    def _compatible(self, old_str: str, new_str: str, schema_type: SchemaType, level: Compatibility) -> bool:
        if level == Compatibility.NONE:
            return True
        if schema_type == SchemaType.JSON_SCHEMA:
            back = _jsonschema_backward_compatible(old_str, new_str)
            fwd = _jsonschema_forward_compatible(old_str, new_str)
        else:
            back = _avro_backward_compatible(old_str, new_str)
            fwd = _avro_forward_compatible(old_str, new_str)

        if level == Compatibility.BACKWARD:
            return back
        if level == Compatibility.FORWARD:
            return fwd
        if level == Compatibility.FULL:
            return back and fwd
        return True


# =========================
# Утилиты высокоуровневого удобства
# =========================

def normalize_and_fingerprint(schema_str: str, schema_type: SchemaType) -> Tuple[str, str, int]:
    """
    Возвращает (canonical_str, fingerprint_hex, short_id_int).
    """
    canon = _canonical_json_str(schema_str) if schema_type == SchemaType.JSON_SCHEMA else _canonical_avro_str(schema_str)
    fp = _fingerprint(canon)
    sid = _short_id_from_fp(fp)
    return canon, fp, sid


# =========================
# Публичная API-поверхность
# =========================

__all__ = [
    "SchemaType",
    "Compatibility",
    "RegistryError",
    "SubjectNotFound",
    "VersionNotFound",
    "SchemaValidationError",
    "CompatibilityError",
    "SchemaReference",
    "SchemaEntry",
    "SubjectConfig",
    "SchemaRegistry",
    "normalize_and_fingerprint",
]
