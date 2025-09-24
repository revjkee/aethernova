# mythos-core/mythos/assets/tagging.py
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Set, Tuple

logger = logging.getLogger("mythos.assets.tagging")

# =============================================================================
# МОДЕЛИ
# =============================================================================

class TagConfidence(int, Enum):
    LOW = 25
    MEDIUM = 60
    HIGH = 90
    ABSOLUTE = 100  # неизменяемые/системные


@dataclass(frozen=True, order=True)
class Tag:
    """
    Канонический тег: namespace:value
    """
    namespace: str
    value: str
    confidence: TagConfidence = TagConfidence.MEDIUM
    source: str = "manual"  # "manual" | "rule:<id>" | "system" | "import:<x>"

    def key(self) -> str:
        return f"{self.namespace}:{self.value}"

    def with_conf(self, conf: TagConfidence) -> "Tag":
        return Tag(self.namespace, self.value, conf, self.source)

    def with_source(self, src: str) -> "Tag":
        return Tag(self.namespace, self.value, self.confidence, src)


@dataclass(frozen=True)
class AssetInfo:
    """
    Унифицированная мета ассета для правил.
    """
    asset_id: str
    path: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    mime: Optional[str] = None
    size_bytes: Optional[int] = None
    width: Optional[int] = None
    height: Optional[int] = None
    duration_sec: Optional[float] = None
    checksum_sha256: Optional[str] = None
    exif: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)  # произвольные поля


@dataclass(frozen=True)
class TaggingResult:
    tags: Tuple[Tag, ...]
    added: Tuple[str, ...]
    removed: Tuple[str, ...]
    conflicts: Tuple[str, ...]
    reasons: Tuple[str, ...]
    hash_sha256: str


# =============================================================================
# ТАКСОНОМИЯ
# =============================================================================

@dataclass
class Taxonomy:
    """
    Управляет нормализацией, валидацией, синонимами, импликациями и мьютексами.
    """
    allowed_namespaces: Set[str]
    default_namespace: str = "tag"
    # Простые валидаторы по неймспейсу: regex и/или белые списки значений
    validators: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    # Синонимы: alias_key -> canonical_key  (оба в формате ns:value)
    synonyms: Mapping[str, str] = field(default_factory=dict)
    # Импликации: key -> set(keys)
    implies: Mapping[str, Set[str]] = field(default_factory=dict)
    # Взаимоисключения: list of sets(keys), из которых допустим не более одного
    mutex_groups: Sequence[Set[str]] = field(default_factory=list)
    # Ограничения по неймспейсу: максимум тегов
    max_per_namespace: Mapping[str, int] = field(default_factory=dict)
    # Зарезервированные (запрет к удалению/изменению)
    reserved: Set[str] = field(default_factory=set)

    _slug_re = re.compile(r"[^a-z0-9\-_\.]+")
    _space_re = re.compile(r"\s+")

    def canonicalize(self, raw: str) -> str:
        """
        Преобразует произвольное представление в canonical key.
        Допускает:
          - "namespace:value"
          - "value" (подставит default_namespace)
        """
        raw = (raw or "").strip()
        if not raw:
            raise ValueError("Empty tag")
        ns = self.default_namespace
        val = raw
        if ":" in raw:
            p = raw.split(":", 1)
            ns, val = p[0].strip(), p[1].strip()
        ns = self._slug(ns.lower())
        if ns not in self.allowed_namespaces:
            raise ValueError(f"Unknown namespace '{ns}'")
        val = self._slug(val.lower())
        if not val:
            raise ValueError("Empty value")
        return f"{ns}:{val}"

    def _slug(self, s: str) -> str:
        s = self._space_re.sub("-", s.strip().lower())
        return self._slug_re.sub("", s)

    def to_tag(self, raw: str, confidence: TagConfidence = TagConfidence.MEDIUM, source: str = "manual") -> Tag:
        key = self.canonicalize(raw)
        ns, val = key.split(":", 1)
        self._validate(ns, val)
        return Tag(ns, val, confidence, source)

    def _validate(self, ns: str, val: str) -> None:
        spec = self.validators.get(ns) or {}
        rx = spec.get("regex")
        if rx and not re.fullmatch(rx, val):
            raise ValueError(f"Value '{val}' does not match regex for {ns}")
        allow = spec.get("allow")
        if allow and val not in allow:
            raise ValueError(f"Value '{val}' not allowed in {ns}")

    def normalize_set(self, tags: Iterable[str | Tag]) -> List[Tag]:
        result: List[Tag] = []
        for t in tags:
            if isinstance(t, Tag):
                key = self.canonicalize(t.key())
                ns, val = key.split(":", 1)
                self._validate(ns, val)
                result.append(Tag(ns, val, t.confidence, t.source))
            else:
                result.append(self.to_tag(t))
        return result

    def apply_synonyms(self, keys: Iterable[str]) -> List[str]:
        out = []
        for k in keys:
            out.append(self.synonyms.get(k, k))
        return sorted(set(out))

    def apply_implications(self, keys: Iterable[str]) -> List[str]:
        out: Set[str] = set(keys)
        # Замыкание по импликациям
        stack = list(keys)
        while stack:
            k = stack.pop()
            implied = self.implies.get(k) or set()
            for i in implied:
                if i not in out:
                    out.add(i)
                    stack.append(i)
        return sorted(out)

    def detect_conflicts(self, keys: Iterable[str]) -> List[Tuple[str, Set[str]]]:
        ks = set(keys)
        conflicts: List[Tuple[str, Set[str]]] = []
        for group in self.mutex_groups:
            inter = ks.intersection(group)
            if len(inter) > 1:
                conflicts.append(("mutex", inter))
        return conflicts

    def enforce_limits(self, tags: List[Tag]) -> List[Tag]:
        """
        Усечение по max_per_namespace: сохраняем самые уверенные, затем лексикографически стабильны.
        """
        buckets: Dict[str, List[Tag]] = {}
        for t in tags:
            buckets.setdefault(t.namespace, []).append(t)
        out: List[Tag] = []
        for ns, arr in buckets.items():
            limit = self.max_per_namespace.get(ns, 1_000_000)
            arr.sort(key=lambda x: (-int(x.confidence), x.value, x.source))
            out.extend(arr[:limit])
        return out


# =============================================================================
# ПРАВИЛА
# =============================================================================

@dataclass(frozen=True)
class Rule:
    """
    Простейший DSL правил авто-тегирования.
    Поля-триггеры опциональны; если не задан ни один — правило не сработает.
    """
    rule_id: str
    # Триггеры
    title_regex: Optional[str] = None
    desc_regex: Optional[str] = None
    path_regex: Optional[str] = None
    mime_prefix: Optional[str] = None
    width_range: Optional[Tuple[int, int]] = None
    height_range: Optional[Tuple[int, int]] = None
    duration_range: Optional[Tuple[float, float]] = None
    metadata_equals: Mapping[str, Any] = field(default_factory=dict)
    metadata_contains: Mapping[str, Any] = field(default_factory=dict)
    # Действия
    add_tags: Sequence[str] = field(default_factory=list)           # литеральные теги
    add_tags_from_groups: Mapping[str, str] = field(default_factory=dict)  # regex group -> "ns:{}"
    confidence: TagConfidence = TagConfidence.MEDIUM
    priority: int = 0  # при конфликте выигрывает правило с большим приоритетом

    def match(self, asset: AssetInfo) -> Optional[Dict[str, str]]:
        """
        Возвращает группы regex (объединённые) либо None.
        """
        groups: Dict[str, str] = {}
        matched_any = False

        def _match_text(rx: Optional[str], text: Optional[str], prefix: str) -> None:
            nonlocal matched_any
            if rx and text:
                m = re.search(rx, text, flags=re.IGNORECASE | re.MULTILINE)
                if m:
                    matched_any = True
                    groups.update({f"{prefix}{k}": v for k, v in m.groupdict().items() if v is not None})
                    # также доступ по числовым индексам
                    for i, val in enumerate(m.groups(), start=1):
                        if val is not None:
                            groups[f"{prefix}{i}"] = val

        _match_text(self.title_regex, asset.title, "t:")
        _match_text(self.desc_regex, asset.description, "d:")
        _match_text(self.path_regex, asset.path, "p:")

        if self.mime_prefix:
            if asset.mime and asset.mime.lower().startswith(self.mime_prefix.lower()):
                matched_any = True
            else:
                return None

        def in_range(val, rng) -> bool:
            if val is None or rng is None:
                return True
            lo, hi = rng
            return (lo is None or val >= lo) and (hi is None or val <= hi)

        if not in_range(asset.width, self.width_range):
            return None
        if not in_range(asset.height, self.height_range):
            return None
        if not in_range(asset.duration_sec, self.duration_range):
            return None

        # metadata_equals
        for k, v in (self.metadata_equals or {}).items():
            if (asset.metadata or {}).get(k) != v:
                return None
            matched_any = True
        # metadata_contains
        for k, v in (self.metadata_contains or {}).items():
            src = (asset.metadata or {}).get(k)
            if src is None:
                return None
            if isinstance(v, str):
                if isinstance(src, str) and v.lower() in src.lower():
                    matched_any = True
                else:
                    return None
            elif isinstance(v, (list, tuple, set)):
                ok = False
                for needle in v:
                    if isinstance(src, (list, tuple, set)):
                        if needle in src:
                            ok = True
                            break
                    elif isinstance(src, str) and isinstance(needle, str) and needle.lower() in src.lower():
                        ok = True
                        break
                if not ok:
                    return None
                matched_any = True

        return groups if matched_any else None


class RuleEngine:
    def __init__(self, taxonomy: Taxonomy, rules: Sequence[Rule]):
        self.taxonomy = taxonomy
        # Правила сортируются по приоритету убыв.
        self.rules = sorted(rules, key=lambda r: (-int(r.priority), r.rule_id))

    def infer(self, asset: AssetInfo) -> List[Tag]:
        out: List[Tag] = []
        for r in self.rules:
            groups = r.match(asset)
            if groups is None:
                continue
            # Литеральные теги
            for lit in r.add_tags:
                try:
                    out.append(self.taxonomy.to_tag(lit, confidence=r.confidence, source=f"rule:{r.rule_id}"))
                except Exception as e:
                    logger.debug("Rule %s literal tag invalid: %s", r.rule_id, e)
            # Из групп
            for gname, template in (r.add_tags_from_groups or {}).items():
                if gname in groups:
                    try:
                        raw = template.format(groups[gname])
                        out.append(self.taxonomy.to_tag(raw, confidence=r.confidence, source=f"rule:{r.rule_id}"))
                    except Exception as e:
                        logger.debug("Rule %s group tag invalid: %s", r.rule_id, e)
        return out


# =============================================================================
# ХРАНИЛИЩЕ (контракт и dev-реализация)
# =============================================================================

class TagStorage(Protocol):
    async def get_synonyms(self) -> Mapping[str, str]: ...
    async def get_implies(self) -> Mapping[str, Set[str]]: ...
    async def get_mutex_groups(self) -> Sequence[Set[str]]: ...
    async def save_asset_tags(self, asset_id: str, tags: Sequence[Tag], idempotency_key: str) -> None: ...
    async def get_asset_tags(self, asset_id: str) -> Sequence[Tag]: ...


class InMemoryTagStorage(TagStorage):
    def __init__(self) -> None:
        self._tags: Dict[str, List[Tag]] = {}
        self._syn: Dict[str, str] = {}
        self._imp: Dict[str, Set[str]] = {}
        self._mutex: List[Set[str]] = []
        self._lock = threading.Lock()

    async def get_synonyms(self) -> Mapping[str, str]:
        return self._syn

    async def get_implies(self) -> Mapping[str, Set[str]]:
        return self._imp

    async def get_mutex_groups(self) -> Sequence[Set[str]]:
        return self._mutex

    async def save_asset_tags(self, asset_id: str, tags: Sequence[Tag], idempotency_key: str) -> None:
        with self._lock:
            # Простая идемпотентность: если хэш уже совпал, ничего не делаем
            prev = self._tags.get(asset_id) or []
            prev_hash = Tagger.hash_tags(prev)
            if prev_hash == idempotency_key:
                return
            self._tags[asset_id] = list(tags)

    async def get_asset_tags(self, asset_id: str) -> Sequence[Tag]:
        return list(self._tags.get(asset_id) or [])


# =============================================================================
# ЗАПРОСЫ (DSL AND/OR/NOT)
# =============================================================================

class QueryNode:
    def eval(self, keys: Set[str]) -> bool:
        return True


@dataclass
class QTag(QueryNode):
    key: str
    def eval(self, keys: Set[str]) -> bool:
        return self.key in keys


@dataclass
class QNot(QueryNode):
    node: QueryNode
    def eval(self, keys: Set[str]) -> bool:
        return not self.node.eval(keys)


@dataclass
class QAnd(QueryNode):
    left: QueryNode
    right: QueryNode
    def eval(self, keys: Set[str]) -> bool:
        return self.left.eval(keys) and self.right.eval(keys)


@dataclass
class QOr(QueryNode):
    left: QueryNode
    right: QueryNode
    def eval(self, keys: Set[str]) -> bool:
        return self.left.eval(keys) or self.right.eval(keys)


class QueryParser:
    _tok_re = re.compile(r"\s*(\(|\)|AND|OR|NOT|[-!]?[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.]+)\s*", re.IGNORECASE)

    def __init__(self, taxonomy: Taxonomy):
        self.taxonomy = taxonomy

    def parse(self, s: str) -> QueryNode:
        tokens = [t for t in self._tok_re.findall(s or "") if t.strip()]
        if not tokens:
            return QTag("__always__:true")  # всегда false (если такой тег отсутствует)
        output: List[Any] = []
        ops: List[str] = []

        def precedence(op: str) -> int:
            return {"NOT": 3, "AND": 2, "OR": 1}.get(op.upper(), 0)

        def apply(op: str) -> None:
            if op.upper() == "NOT":
                a = output.pop()
                output.append(QNot(a))
            else:
                b = output.pop()
                a = output.pop()
                output.append(QAnd(a, b) if op.upper() == "AND" else QOr(a, b))

        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t == "(":
                ops.append(t)
            elif t == ")":
                while ops and ops[-1] != "(":
                    apply(ops.pop())
                if not ops:
                    raise ValueError("Mismatched parentheses")
                ops.pop()
            elif t.upper() in ("AND", "OR", "NOT"):
                while ops and precedence(ops[-1]) >= precedence(t):
                    apply(ops.pop())
                ops.append(t.upper())
            else:
                neg = False
                if t.startswith("-") or t.startswith("!"):
                    neg = True
                    t = t[1:]
                key = self.taxonomy.canonicalize(t)
                node = QTag(key)
                output.append(QNot(node) if neg else node)
            i += 1
        while ops:
            apply(ops.pop())
        return output[0] if output else QTag("__always__:true")


def compile_query(taxonomy: Taxonomy, query: str) -> Callable[[Iterable[str]], bool]:
    """
    Возвращает предикат, принимающий множество ключей.
    """
    parser = QueryParser(taxonomy)
    ast = parser.parse(query)

    def predicate(keys: Iterable[str]) -> bool:
        return ast.eval(set(keys))

    return predicate


# =============================================================================
# КОНФИГ-ЛОАДЕР
# =============================================================================

class ConfigLoader:
    """
    Загружает конфиг (dict или YAML), нормализуя части таксономии и правил.
    """
    def __init__(self, data: Optional[Mapping[str, Any]] = None, yaml_path: Optional[str] = None):
        self._data = data
        self._path = yaml_path
        self._cached: Optional[Mapping[str, Any]] = None
        self._mtime: Optional[float] = None
        self._lock = threading.Lock()

    def get(self) -> Mapping[str, Any]:
        if self._data is not None:
            return self._data
        with self._lock:
            mtime = None
            if self._path and os.path.exists(self._path):
                mtime = os.path.getmtime(self._path)
            if self._cached is not None and mtime == self._mtime:
                return self._cached
            if not self._path:
                return self._cached or {}
            try:
                import yaml  # type: ignore
            except Exception:
                logger.warning("PyYAML is not installed; cannot load %s", self._path)
                return self._cached or {}
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    obj = yaml.safe_load(f) or {}
                self._cached = obj
                self._mtime = mtime
                return obj
            except Exception as e:
                logger.error("Failed to load yaml %s: %s", self._path, e)
                return self._cached or {}


# =============================================================================
# TAGGER
# =============================================================================

class Tagger:
    """
    Центральный агрегатор: объединяет ручные и авто-теги, применяет таксономию,
    разрешает конфликты и сохраняет результат через хранилище.
    """
    def __init__(self, taxonomy: Taxonomy, storage: TagStorage, rules: Optional[RuleEngine] = None):
        self.taxonomy = taxonomy
        self.storage = storage
        self.rules = rules

    async def tag_asset(
        self,
        asset: AssetInfo,
        manual_tags: Sequence[str | Tag] = (),
        *,
        save: bool = True,
    ) -> TaggingResult:
        # 1) Базовые, ручные и системные теги
        base: List[Tag] = self.taxonomy.normalize_set(manual_tags)

        # 2) Правила
        auto: List[Tag] = []
        if self.rules:
            auto = self.rules.infer(asset)

        # 3) Синонимы/импликации из хранилища (для горячих изменений)
        syn = await self.storage.get_synonyms()
        imp = await self.storage.get_implies()
        mutex = await self.storage.get_mutex_groups()

        # Временная таксономия с runtime-обновлениями
        runtime_tax = dataclasses.replace(self.taxonomy)
        runtime_tax.synonyms = {**self.taxonomy.synonyms, **syn}
        # Объединить implications
        merged_imp: Dict[str, Set[str]] = {}
        for src in (self.taxonomy.implies, imp):
            for k, vals in src.items():
                merged_imp.setdefault(k, set()).update(vals)
        runtime_tax.implies = merged_imp
        runtime_tax.mutex_groups = list(self.taxonomy.mutex_groups) + list(mutex)

        # 4) Объединение и каноникализация
        merged: List[Tag] = []
        merged.extend(base)
        merged.extend(auto)

        # Сгруппировать по ключу с выбором наибольшей уверенности/приоритета источника
        by_key: Dict[str, Tag] = {}
        for t in merged:
            key = t.key()
            best = by_key.get(key)
            if best is None:
                by_key[key] = t
            else:
                if int(t.confidence) > int(best.confidence):
                    by_key[key] = t
                elif int(t.confidence) == int(best.confidence):
                    # стабильное предпочтение: system > rule > manual
                    pri = _source_priority(t.source) >= _source_priority(best.source)
                    if pri:
                        by_key[key] = t

        keys = sorted(by_key.keys())

        # 5) Синонимы → канонические ключи
        keys = runtime_tax.apply_synonyms(keys)

        # 6) Импликации
        keys = runtime_tax.apply_implications(keys)

        # 7) Взаимоисключения: оставляем тег с максимальной уверенностью
        conflicts = runtime_tax.detect_conflicts(keys)
        removed: Set[str] = set()
        reasons: List[str] = []
        if conflicts:
            for _, group in conflicts:
                # Выбрать лучший по уверенности/источнику
                candidates = [(by_key.get(k) or Tag(*k.split(":", 1)), k) for k in group]
                candidates.sort(key=lambda pair: (-int(pair[0].confidence), -_source_priority(pair[0].source), pair[1]))
                keep_key = candidates[0][1]
                for _, k in candidates[1:]:
                    removed.add(k)
                reasons.append(f"mutex:{','.join(sorted(group))}->keep:{keep_key}")

        # Применить исключения
        final_keys = [k for k in keys if k not in removed]

        # 8) Пересобрать Tag-объекты из by_key либо создать базовые
        final_tags: List[Tag] = []
        for k in final_keys:
            if k in by_key:
                final_tags.append(by_key[k])
            else:
                ns, val = k.split(":", 1)
                final_tags.append(Tag(ns, val, TagConfidence.MEDIUM, "system"))

        # 9) Лимиты по namespace
        final_tags = runtime_tax.enforce_limits(final_tags)

        # 10) Отсечь попытки удаления резерва
        for t in list(final_tags):
            if t.key() in runtime_tax.reserved:
                # поведение по умолчанию: зарезервированные присутствуют всегда; ничего не делаем
                pass

        # 11) Идемпотентный хэш
        h = self.hash_tags(final_tags)

        # 12) Сохранение
        if save:
            await self.storage.save_asset_tags(asset.asset_id, final_tags, h)

        # Разница со старыми (если есть)
        before = {t.key() for t in await self.storage.get_asset_tags(asset.asset_id)}
        after = {t.key() for t in final_tags}
        added = tuple(sorted(after - before))
        removed_final = tuple(sorted(before - after))

        return TaggingResult(
            tags=tuple(sorted(final_tags, key=lambda t: (t.namespace, t.value))),
            added=added,
            removed=removed_final,
            conflicts=tuple(sorted({k for _, g in conflicts for k in g})),
            reasons=tuple(reasons),
            hash_sha256=h,
        )

    @staticmethod
    def hash_tags(tags: Sequence[Tag]) -> str:
        """
        Детерминированный хэш для набора тегов (ключи + confidence + source).
        """
        payload = [
            {"k": t.key(), "c": int(t.confidence), "s": t.source}
            for t in sorted(tags, key=lambda x: x.key())
        ]
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


def _source_priority(source: str) -> int:
    if source.startswith("system"):
        return 3
    if source.startswith("rule"):
        return 2
    if source.startswith("import"):
        return 1
    return 0


# =============================================================================
# УТИЛИТЫ ДЛЯ БЫСТРОГО СОЗДАНИЯ ТАКСОНОМИИ/ПРАВИЛ
# =============================================================================

def build_default_taxonomy() -> Taxonomy:
    """
    Боевая разумная база для Mythos:
      - namespace'ы: tag, character, location, faction, item, rarity, media, rating, spoiler, locale, license
      - синонимы и импликации для некоторых часто встречающихся тегов
    """
    allowed = {
        "tag", "character", "location", "faction", "item", "rarity",
        "media", "rating", "spoiler", "locale", "license"
    }
    validators = {
        "rarity": {"allow": {"common", "uncommon", "rare", "epic", "legendary"}},
        "rating": {"allow": {"g", "pg", "pg13", "r", "nc17"}},
        "spoiler": {"allow": {"none", "low", "medium", "high"}},
        "locale": {"regex": r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$"},
        "media": {"allow": {"image", "video", "audio", "text"}},
        "license": {"allow": {"all-rights", "cc-by", "cc-by-sa", "cc-by-nc", "cc0"}},
    }
    synonyms = {
        "media:img": "media:image",
        "media:pic": "media:image",
        "rating:pg-13": "rating:pg13",
    }
    implies = {
        "media:image": {"tag:visual"},
        "media:video": {"tag:visual"},
        "media:audio": {"tag:audio"},
        "rarity:legendary": {"tag:valuable"},
        "spoiler:high": {"tag:restricted"},
    }
    mutex = [
        {"spoiler:none", "spoiler:low", "spoiler:medium", "spoiler:high"},
        {"media:image", "media:video", "media:audio", "media:text"},
        {"rating:g", "rating:pg", "rating:pg13", "rating:r", "rating:nc17"},
    ]
    max_per_ns = {
        "rating": 1,
        "spoiler": 1,
        "media": 1,
        "rarity": 1,
    }
    reserved = {"license:all-rights"}  # пример: лицензионный тег должен всегда присутствовать
    return Taxonomy(
        allowed_namespaces=set(allowed),
        validators=validators,
        synonyms=synonyms,
        implies={k: set(v) for k, v in implies.items()},
        mutex_groups=[set(m) for m in mutex],
        max_per_namespace=max_per_ns,
        reserved=set(reserved),
    )


def build_rules_from_config(taxonomy: Taxonomy, cfg: Mapping[str, Any]) -> RuleEngine:
    """
    Ожидаемый формат:
      rules:
        - id: image-basic
          mime_prefix: image/
          add_tags: [ "media:image" ]
          confidence: HIGH
          priority: 10
        - id: location-forest
          desc_regex: "(?P<loc>forest|лес)"
          add_tags_from_groups: { "d:loc": "location:{}" }
          confidence: MEDIUM
    """
    rules_raw = (cfg or {}).get("rules") or []
    rules: List[Rule] = []
    for r in rules_raw:
        try:
            conf = getattr(TagConfidence, str(r.get("confidence", "MEDIUM")).upper(), TagConfidence.MEDIUM)
            rules.append(
                Rule(
                    rule_id=str(r["id"]),
                    title_regex=r.get("title_regex"),
                    desc_regex=r.get("desc_regex"),
                    path_regex=r.get("path_regex"),
                    mime_prefix=r.get("mime_prefix"),
                    width_range=tuple(r["width_range"]) if r.get("width_range") else None,
                    height_range=tuple(r["height_range"]) if r.get("height_range") else None,
                    duration_range=tuple(r["duration_range"]) if r.get("duration_range") else None,
                    metadata_equals=r.get("metadata_equals") or {},
                    metadata_contains=r.get("metadata_contains") or {},
                    add_tags=list(r.get("add_tags") or []),
                    add_tags_from_groups=r.get("add_tags_from_groups") or {},
                    confidence=conf,
                    priority=int(r.get("priority", 0)),
                )
            )
        except Exception as e:
            logger.warning("Invalid rule %s: %s", r, e)
    return RuleEngine(taxonomy, rules)


# =============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ (dev)
# =============================================================================

if __name__ == "__main__":  # pragma: no cover
    import asyncio

    async def main():
        taxonomy = build_default_taxonomy()
        storage = InMemoryTagStorage()

        # Пример конфигурации правил
        cfg = {
            "rules": [
                {"id": "media-image", "mime_prefix": "image/", "add_tags": ["media:image"], "confidence": "HIGH", "priority": 10},
                {"id": "legendary-in-title", "title_regex": r"\blegendary\b", "add_tags": ["rarity:legendary"], "confidence": "MEDIUM", "priority": 5},
                {"id": "location-forest", "desc_regex": r"(?P<loc>forest|лес)", "add_tags_from_groups": {"d:loc": "location:{}"}, "confidence": "MEDIUM"},
                {"id": "spoiler-if-keyword", "desc_regex": r"(ending|финал)", "add_tags": ["spoiler:high"], "confidence": "HIGH"},
            ]
        }
        rules = build_rules_from_config(taxonomy, cfg)
        tagger = Tagger(taxonomy, storage, rules)

        asset = AssetInfo(
            asset_id="asset-001",
            title="Legendary Sword Artwork",
            description="Concept art. Deep forest vibes. Possible ending spoiler.",
            mime="image/png",
            width=2048,
            height=1024,
            metadata={"author": "mythos", "collection": "weapons"},
        )
        res = await tagger.tag_asset(asset, manual_tags=["license:all-rights", "rating:pg"])

        print("TAGS:", [t.key() for t in res.tags])
        print("ADDED:", res.added)
        print("REMOVED:", res.removed)
        print("CONFLICTS:", res.conflicts)
        print("HASH:", res.hash_sha256)

        # Пример запроса
        predicate = compile_query(taxonomy, "media:image AND rarity:legendary AND NOT spoiler:high")
        print("MATCH FILTER:", predicate([t.key() for t in res.tags]))

    asyncio.run(main())
