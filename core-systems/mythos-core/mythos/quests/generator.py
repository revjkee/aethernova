# mythos-core/mythos/quests/generator.py
from __future__ import annotations

import dataclasses
import datetime as dt
import functools
import hashlib
import hmac
import json
import logging
import os
import random
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple

logger = logging.getLogger("mythos.quests.generator")

UTC = dt.timezone.utc


# ===========================
# Модели домена генерации
# ===========================

@dataclass(frozen=True)
class UserProfile:
    user_id: str
    region: Optional[str] = None     # "EU", "US", ...
    platform: Optional[str] = None   # "pc", "console", "mobile"
    app_version: Optional[str] = None
    attributes: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class QuestCandidate:
    quest_id: str              # stable key, e.g. "daily_login_streak"
    revision: int
    priority: int
    weight: float
    flags: Mapping[str, Any]
    availability: Mapping[str, Any]
    segmentation: Mapping[str, Any]
    rollout: Mapping[str, Any]
    ab_config: Mapping[str, Any]
    mutex_groups: Sequence[str]  # from flags.mutuallyExclusiveGroups
    i18n: Mapping[str, Any]      # optional, used for diagnostics


@dataclass(frozen=True)
class ABAssignment:
    bucket_key: str
    variant_key: str


@dataclass(frozen=True)
class QuestAssignment:
    user_id: str
    quest_id: str
    quest_version_id: str               # UUID/ID вашей версии (может быть синтезирован или извлечён из БД)
    revision: int
    assigned_at: dt.datetime
    expires_at: Optional[dt.datetime]
    cooldown_until: Optional[dt.datetime]
    ab: Tuple[ABAssignment, ...]        # финальные варианты по бакетам
    idempotency_key: str                # для леджера и user_quests
    source: str = "generator/daily"
    meta: Mapping[str, Any] = dataclasses.field(default_factory=dict)


# ===========================
# Контракты для интеграции
# ===========================

class QuestStorage(Protocol):
    """
    Абстракция поверх вашей БД/кэша.

    Рекомендуемая прод-реализация опирается на таблицы из schemas/sql/migrations/0002_quests.sql:
      - mythos.quests / mythos.quest_versions
      - mythos.user_quests / mythos.user_objective_progress / mythos.reward_ledger
    """

    async def fetch_current_candidates(self, *, now: dt.datetime) -> Sequence[QuestCandidate]:
        """Вернуть список опубликованных (is_current=true, status=published) кандидатов."""

    async def map_version_ids(self, *, quest_revisions: Sequence[Tuple[str, int]]) -> Mapping[Tuple[str, int], str]:
        """
        Вернуть карту (quest_id, revision) -> quest_version_id (uuid/строка), чтобы сохранить назначение.
        """

    async def get_user_active_quests(self, user_id: str) -> Sequence[QuestAssignment]:
        """Действующие назначения пользователя (state in active/cooldown и т.п.)."""

    async def get_user_counters(self, user_id: str, quest_id: str, *, window: str) -> int:
        """
        Вернуть число завершений в зависимости от окна: "daily" | "weekly" | "lifetime".
        Используется для ограничений maxCompletions и капов.
        """

    async def put_assignments(self, assignments: Sequence[QuestAssignment]) -> None:
        """
        Идемпотентно записать назначения (используя idempotency_key как уникальный ключ).
        """


# ===========================
# Вспомогательные функции
# ===========================

def _iso_now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def _to_utc(d: Optional[str]) -> Optional[dt.datetime]:
    if not d:
        return None
    # Поддерживаем RFC3339 и ISO8601 без tz (считаем UTC)
    try:
        v = dt.datetime.fromisoformat(d.replace("Z", "+00:00"))
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    except Exception:
        return None


def _parse_duration(s: Optional[str]) -> dt.timedelta:
    if not s:
        return dt.timedelta(0)
    # Простой парсер "60s", "24h", "7d"
    suffix = s[-1].lower()
    try:
        val = int(s[:-1])
    except Exception:
        return dt.timedelta(0)
    if suffix == "s":
        return dt.timedelta(seconds=val)
    if suffix == "m":
        return dt.timedelta(minutes=val)
    if suffix == "h":
        return dt.timedelta(hours=val)
    if suffix == "d":
        return dt.timedelta(days=val)
    return dt.timedelta(0)


def _semver_tuple(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in re_split_cached(r"[^\d]+", v) if x.isdigit())
    except Exception:
        return (0,)


@functools.lru_cache(maxsize=512)
def re_split_cached(pattern: str, text: Optional[str] = None) -> List[str]:
    import re
    if text is None:
        return []
    return re.split(pattern, text)


def _user_seed(user_id: str, date_key: str, salt: str = "mythos-quests") -> int:
    h = hashlib.sha256(f"{salt}|{user_id}|{date_key}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big", signed=False)


def _stable_hbucket(user_id: str, bucket_key: str, salt: str = "ab") -> float:
    h = hashlib.blake2b(f"{salt}|{user_id}|{bucket_key}".encode("utf-8"), digest_size=8).digest()
    # 0..1
    return int.from_bytes(h, "big") / 2**64


def _weighted_sample_without_replacement(
    rng: random.Random,
    items: Sequence[QuestCandidate],
    weights: Sequence[float],
    k: int,
) -> List[int]:
    """
    Возвращает индексы выбранных элементов.
    Алгоритм Efraimidis–Spirakis: ключ = U^{1/weight}, выбираем top-k по ключу.
    """
    import math
    assert len(items) == len(weights)
    if k <= 0 or not items:
        return []
    k = min(k, len(items))
    keys: List[Tuple[float, int]] = []
    for i, w in enumerate(weights):
        w = max(0.000001, float(w))
        u = rng.random()
        keys.append((u ** (1.0 / w), i))
    keys.sort(reverse=True)
    return [idx for _, idx in keys[:k]]


def _in_rollout(now: dt.datetime, rollout: Mapping[str, Any]) -> bool:
    """
    rollout: { stages: [ {percent:int, since: ISO}... ] }
    Допускаем: если нет stages — считаем 100%.
    """
    try:
        stages = rollout.get("stages") or []
    except Exception:
        stages = []
    if not stages:
        return True
    active_pct = 0
    for st in stages:
        since = _to_utc(st.get("since"))
        pct = int(st.get("percent", 0))
        if since and now >= since:
            active_pct = max(active_pct, min(100, max(0, pct)))
    if active_pct >= 100:
        return True
    # Используем хеш по квесту для распределения пользователей глобально в процентах
    # Решение о включении принимается позже по пользователю (ниже), здесь только наличие активной стадии.
    return active_pct > 0


def _rollout_allows_user(user_id: str, quest_id: str, now: dt.datetime, rollout: Mapping[str, Any]) -> bool:
    stages = rollout.get("stages") or []
    if not stages:
        return True
    active_pct = 0
    for st in stages:
        since = _to_utc(st.get("since"))
        pct = int(st.get("percent", 0))
        if since and now >= since:
            active_pct = max(active_pct, min(100, max(0, pct)))
    if active_pct >= 100:
        return True
    # Статическое распределение по пользователю (чтобы один и тот же пользователь всегда попадал/не попадал)
    hb = _stable_hbucket(user_id, f"rollout:{quest_id}", salt="rollout")
    return hb < (active_pct / 100.0)


def _segmentation_allows(user: UserProfile, seg: Mapping[str, Any]) -> bool:
    # rolloutPercent
    rp = int(seg.get("rolloutPercent", seg.get("rollout_percent", 100)))
    if rp < 100:
        hb = _stable_hbucket(user.user_id, "segmentation")
        if hb >= (max(0, rp) / 100.0):
            return False

    regions = [str(x).upper() for x in (seg.get("regions") or [])]
    if regions and (not user.region or user.region.upper() not in regions):
        return False

    platforms = [str(x).lower() for x in (seg.get("platforms") or [])]
    if platforms and (not user.platform or user.platform.lower() not in platforms):
        return False

    min_ver = seg.get("minAppVersion")
    if min_ver and user.app_version:
        if _semver_tuple(user.app_version) < _semver_tuple(str(min_ver)):
            return False

    attrs = seg.get("attributes") or {}
    # простое сравнение AND по равенству (списки — как включение)
    for k, v in attrs.items():
        uv = user.attributes.get(k)
        if isinstance(v, list):
            if uv not in v:
                return False
        else:
            if uv != v:
                return False
    return True


def _availability_allows(now: dt.datetime, avail: Mapping[str, Any]) -> Tuple[bool, Optional[dt.datetime], Optional[dt.datetime]]:
    """
    Проверяет окно доступности.
    Возвращает (ok, expires_at, cooldown_until_base)
    """
    starts = _to_utc(str(avail.get("startsAt"))) if avail.get("startsAt") else None
    ends = _to_utc(str(avail.get("endsAt"))) if avail.get("endsAt") else None
    if starts and now < starts:
        return False, None, None
    if ends and now > ends:
        return False, None, None

    # cooldown (базовый) — пригодится для вычисления cooldown_until
    cd = _parse_duration(str(avail.get("cooldown") or "0s"))
    return True, ends, (now + cd) if cd.total_seconds() > 0 else None


def _compute_ab_assignments(user_id: str, ab_config: Mapping[str, Any]) -> Tuple[ABAssignment, ...]:
    """
    ab_config:
      bucket: "name"
      variants: [{key:"A", traffic:50}, {key:"B", traffic:50}, ...]
    или множественные бакеты.
    """
    buckets = []
    if "bucket" in ab_config and "variants" in ab_config:
        buckets = [ab_config]
    elif isinstance(ab_config, dict):
        # возможно, несколько полей-ведер
        for _, b in ab_config.items():
            if isinstance(b, dict) and b.get("variants"):
                buckets.append(b)

    res: List[ABAssignment] = []
    for b in buckets:
        bkey = str(b.get("bucket") or b.get("key") or "default")
        variants = b.get("variants") or []
        # Нормализуем трафик
        total = sum(int(v.get("traffic", 0)) for v in variants)
        if total <= 0:
            continue
        # Стабильный выбор по долям
        hb = _stable_hbucket(user_id, f"ab:{bkey}")
        cum = 0.0
        chosen = variants[-1].get("key")  # fallback
        for v in variants:
            share = max(0, int(v.get("traffic", 0))) / total
            cum += share
            if hb <= cum:
                chosen = v.get("key")
                break
        res.append(ABAssignment(bucket_key=bkey, variant_key=str(chosen)))
    return tuple(res)


def _idempotency_for_assignment(user_id: str, quest_id: str, revision: int, period_key: str) -> str:
    raw = f"{user_id}:{quest_id}:{revision}:{period_key}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ===========================
# Конфиг-лоадер (YAML опционально)
# ===========================

class ConfigLoader:
    """
    Кэширует конфиг в памяти; источник — dict или YAML-файл.
    """

    def __init__(self, data: Optional[Mapping[str, Any]] = None, yaml_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._data = data
        self._yaml_path = yaml_path
        self._cache_key = None
        self._cached: Optional[Mapping[str, Any]] = None

    def get(self) -> Mapping[str, Any]:
        with self._lock:
            if self._data is not None:
                return self._data
            if self._yaml_path:
                mtime = None
                try:
                    mtime = os.path.getmtime(self._yaml_path)
                except Exception:
                    pass
                key = (self._yaml_path, mtime)
                if self._cache_key == key and self._cached is not None:
                    return self._cached
                try:
                    import yaml  # type: ignore
                    with open(self._yaml_path, "r", encoding="utf-8") as f:
                        obj = yaml.safe_load(f) or {}
                    self._cached = obj
                    self._cache_key = key
                    return obj
                except Exception as e:
                    logger.error("Failed to load quests config: %s", e)
                    return self._cached or {}
            return self._cached or {}


# ===========================
# Генератор квестов
# ===========================

class QuestGenerator:
    def __init__(self, storage: QuestStorage, config: ConfigLoader):
        self._storage = storage
        self._config = config

    async def generate_daily(
        self,
        user: UserProfile,
        *,
        now: Optional[dt.datetime] = None,
        limit: int = 3,
        namespace: str = "daily",
    ) -> Sequence[QuestAssignment]:
        """
        Генерирует ежедневный набор квестов (детерминированно для user+date).
        """
        now = now or _iso_now()
        period_key = now.astimezone(UTC).date().isoformat()
        seed = _user_seed(user.user_id, f"{namespace}:{period_key}")
        rng = random.Random(seed)
        return await self.generate(user, now=now, rng=rng, limit=limit, period_key=period_key, source=f"generator/{namespace}")

    async def generate(
        self,
        user: UserProfile,
        *,
        now: Optional[dt.datetime] = None,
        rng: Optional[random.Random] = None,
        limit: int = 3,
        period_key: Optional[str] = None,
        source: str = "generator/custom",
    ) -> Sequence[QuestAssignment]:
        """
        Универсальная генерация с предоставленным PRNG и ключом периода (для идемпотентности).
        """
        now = now or _iso_now()
        rng = rng or random.Random(_user_seed(user.user_id, now.astimezone(UTC).isoformat()))
        period_key = period_key or now.astimezone(UTC).isoformat()

        # 1) Получаем доступные текущие кандидаты из хранилища
        candidates = list(await self._storage.fetch_current_candidates(now=now))
        if not candidates:
            return []

        # 2) Фильтрация по доступности, раскатке, сегментации
        filtered: List[QuestCandidate] = []
        expiration_map: Dict[str, dt.datetime] = {}
        cooldown_base_map: Dict[str, Optional[dt.datetime]] = {}

        for c in candidates:
            ok, exp_at, cd_base = _availability_allows(now, c.availability)
            if not ok:
                continue
            if not _in_rollout(now, c.rollout):
                continue
            if not _rollout_allows_user(user.user_id, c.quest_id, now, c.rollout):
                continue
            if not _segmentation_allows(user, c.segmentation or {}):
                continue
            filtered.append(c)
            if exp_at:
                expiration_map[c.quest_id] = exp_at
            cooldown_base_map[c.quest_id] = cd_base

        if not filtered:
            return []

        # 3) Учитываем активные назначения (мьютексы и кулдауны)
        active = await self._storage.get_user_active_quests(user.user_id)
        active_mutex: set[str] = set()
        active_quests: set[str] = set()
        for a in active:
            active_quests.add(a.quest_id)
            for mg in getattr(a, "meta", {}).get("mutex_groups", []) or []:
                active_mutex.add(mg)

        # 4) Применяем ограничения maxCompletions / perDay / perWeek / lifetime (по counters) и мьютексы
        eligible: List[QuestCandidate] = []
        weights: List[float] = []

        for c in filtered:
            flags = c.flags or {}
            if not bool(flags.get("enabled", True)):
                continue

            # мьютексы
            if any(mg in active_mutex for mg in (c.mutex_groups or [])):
                continue

            # daily/weekly/lifetime лимиты из availability.maxCompletions
            avail = c.availability or {}
            maxc = (avail.get("maxCompletions") or {}) if isinstance(avail.get("maxCompletions"), dict) else {}
            per_user_total = int(maxc.get("perUser", 0))
            per_user_per_day = int(maxc.get("perUserPerDay", 0))

            # lifetime
            if per_user_total > 0:
                life = await self._storage.get_user_counters(user.user_id, c.quest_id, window="lifetime")
                if life >= per_user_total:
                    continue
            # per day
            if per_user_per_day > 0:
                dcnt = await self._storage.get_user_counters(user.user_id, c.quest_id, window="daily")
                if dcnt >= per_user_per_day:
                    continue

            # кулдаун: если квест уже в активных и не истёк кулдаун, не предлагаем
            if c.quest_id in active_quests:
                continue

            eligible.append(c)
            # приоритет — целое выше=важнее. Вес — положительный.
            base_weight = max(0.000001, float(c.flags.get("weight", c.weight or 1.0)))
            # буст за priority для ранжирования: weight'ом управляет выбор, а priority — tie-breaker позже
            weights.append(base_weight)

        if not eligible:
            return []

        # 5) Выбор по весам без замены
        chosen_idx = _weighted_sample_without_replacement(rng, eligible, weights, limit)
        chosen = [eligible[i] for i in chosen_idx]

        # 6) Учитываем priority как tie-breaker для стабильного порядка
        chosen.sort(key=lambda q: (-int(q.priority), q.quest_id))

        # 7) Сопоставляем версии и рассчитываем A/B
        ver_map = await self._storage.map_version_ids(quest_revisions=[(q.quest_id, q.revision) for q in chosen])

        # 8) Формируем назначения
        out: List[QuestAssignment] = []
        for c in chosen:
            qvid = ver_map.get((c.quest_id, c.revision))
            if not qvid:
                # если версии нет — пропускаем безопасно
                logger.warning("No quest_version_id for %s rev %s", c.quest_id, c.revision)
                continue

            ab = _compute_ab_assignments(user.user_id, c.ab_config or {})
            idk = _idempotency_for_assignment(user.user_id, c.quest_id, c.revision, period_key)

            expires_at = expiration_map.get(c.quest_id)
            cooldown_until = cooldown_base_map.get(c.quest_id)

            out.append(
                QuestAssignment(
                    user_id=user.user_id,
                    quest_id=c.quest_id,
                    quest_version_id=qvid,
                    revision=c.revision,
                    assigned_at=now,
                    expires_at=expires_at,
                    cooldown_until=cooldown_until,
                    ab=ab,
                    idempotency_key=idk,
                    source=source,
                    meta={
                        "mutex_groups": list(c.mutex_groups or []),
                        "priority": c.priority,
                        "seed_period": period_key,
                    },
                )
            )

        if not out:
            return []

        # 9) Идемпотентная запись в стор
        await self._storage.put_assignments(out)
        return out


# ===========================
# In-memory dev storage (пример)
# ===========================

@dataclass
class _MemQVersion:
    quest_id: str
    revision: int
    version_id: str


class InMemoryQuestStorage(QuestStorage):
    """
    Безопасная dev-реализация без внешних зависимостей.
    В проде замените на реализацию поверх БД.
    """

    def __init__(self, config: ConfigLoader):
        self._config = config
        self._assignments: Dict[str, QuestAssignment] = {}
        self._user_events: Dict[Tuple[str, str], Dict[str, int]] = {}  # (user_id, quest_id) -> {"daily":int,"lifetime":int}
        self._versions: Dict[Tuple[str, int], str] = {}
        self._lock = threading.Lock()

    def _ensure_versions(self) -> None:
        with self._lock:
            cfg = self._config.get() or {}
            quests = cfg.get("quests") or []
            for q in quests:
                qid = str(q.get("id"))
                rev = int(q.get("revision", 1))
                key = (qid, rev)
                if key not in self._versions:
                    # synthesize a deterministic UUID-like string
                    raw = hashlib.sha256(f"{qid}:{rev}".encode("utf-8")).hexdigest()
                    self._versions[key] = f"qv-{raw[:24]}"

    async def fetch_current_candidates(self, *, now: dt.datetime) -> Sequence[QuestCandidate]:
        self._ensure_versions()
        cfg = self._config.get() or {}
        quests = cfg.get("quests") or []

        res: List[QuestCandidate] = []
        for q in quests:
            qid = str(q.get("id"))
            rev = int(q.get("revision", 1))
            flags = q.get("flags") or {}
            ui = q.get("ui") or {}
            avail = q.get("availability") or {}
            seg = q.get("segmentation") or {}
            rollout = q.get("rollout") or {}
            # приоритет/вес по умолчанию
            priority = int(ui.get("priority", 0))
            weight = float(flags.get("weight", 1.0))
            mutex = list((q.get("locks") or {}).get("exclusiveWith", [])) + list(flags.get("mutuallyExclusiveGroups", []))
            ab = q.get("abTest") or {}

            res.append(
                QuestCandidate(
                    quest_id=qid,
                    revision=rev,
                    priority=priority,
                    weight=weight,
                    flags=flags,
                    availability=avail,
                    segmentation=seg,
                    rollout=rollout,
                    ab_config=ab,
                    mutex_groups=tuple(mutex),
                    i18n=q.get("i18n") or {},
                )
            )
        return res

    async def map_version_ids(self, *, quest_revisions: Sequence[Tuple[str, int]]) -> Mapping[Tuple[str, int], str]:
        self._ensure_versions()
        return {key: self._versions[key] for key in quest_revisions if key in self._versions}

    async def get_user_active_quests(self, user_id: str) -> Sequence[QuestAssignment]:
        # В dev считаем активными все ранее назначенные не истёкшие назначения
        now = _iso_now()
        return [a for a in self._assignments.values() if a.user_id == user_id and (a.expires_at is None or a.expires_at > now)]

    async def get_user_counters(self, user_id: str, quest_id: str, *, window: str) -> int:
        return self._user_events.get((user_id, quest_id), {}).get("daily" if window == "daily" else ("weekly" if window == "weekly" else "lifetime"), 0)

    async def put_assignments(self, assignments: Sequence[QuestAssignment]) -> None:
        with self._lock:
            for a in assignments:
                if a.idempotency_key in self._assignments:
                    continue
                self._assignments[a.idempotency_key] = a


# ===========================
# Пример использования (dev)
# ===========================

if __name__ == "__main__":  # pragma: no cover
    # Пример конфигурации (упрощённый, совместим с configs/quests.yaml)
    sample_cfg = {
        "quests": [
            {
                "id": "daily_login_streak",
                "revision": 3,
                "flags": {"enabled": True, "weight": 1.0, "mutuallyExclusiveGroups": []},
                "ui": {"priority": 90},
                "availability": {"cooldown": "24h", "maxCompletions": {"perUser": 0, "perUserPerDay": 1}},
                "segmentation": {"rolloutPercent": 100, "regions": [], "platforms": []},
                "rollout": {"stages": [{"percent": 100, "since": "2025-01-01T00:00:00Z"}]},
                "abTest": {"bucket": "daily_login_copy", "variants": [{"key": "A", "traffic": 50}, {"key": "B", "traffic": 50}]},
            },
            {
                "id": "hunt_goblins",
                "revision": 7,
                "flags": {"enabled": True, "weight": 1.0, "mutuallyExclusiveGroups": ["weekly-featured"]},
                "ui": {"priority": 70},
                "availability": {"cooldown": "7d", "maxCompletions": {"perUser": 1, "perUserPerDay": 0}},
                "segmentation": {"rolloutPercent": 100, "regions": ["EU", "US"], "platforms": ["pc", "console"]},
                "rollout": {"stages": [{"percent": 100, "since": "2025-01-01T00:00:00Z"}]},
            },
        ]
    }

    async def _demo():
        cfg = ConfigLoader(data=sample_cfg)
        storage = InMemoryQuestStorage(cfg)
        gen = QuestGenerator(storage=storage, config=cfg)

        user = UserProfile(user_id="u123", region="EU", platform="pc", app_version="1.2.3")
        out = await gen.generate_daily(user, limit=2)
        for a in out:
            print(f"Assigned {a.quest_id}@rev{a.revision} -> {a.quest_version_id}, ab={[(x.bucket_key,x.variant_key) for x in a.ab]} idemp={a.idempotency_key}")

    import asyncio
    asyncio.run(_demo())
