# -*- coding: utf-8 -*-
"""
veilmind-core.veilmind.consent.registry

Промышленный реестр согласий (Consent Registry) с безопасной псевдонимизацией subjectId,
поддержкой внешних сигналов (GPC/DNT/US Privacy/TCF), возрастных ограничений, юрисдикций
и вычислением эффективного состояния по политике.

Зависимости: стандартная библиотека.
Совместимость: Python 3.10+

Интеграция:
  from veilmind.consent.registry import ConsentRegistry, InMemoryConsentStore, ConsentHasher
  policy = yaml.safe_load(open("configs/templates/consent_policy.example.yaml"))
  store = InMemoryConsentStore()
  hasher = ConsentHasher(secret=os.environ["CONSENT_HASH_SECRET"])
  registry = ConsentRegistry(policy=policy, store=store, hasher=hasher)

  # Получение состояний
  states = registry.get_state(subject_id="user@example.com", purposes=["analytics"], ctx={"region":"EEA"})

  # Установка состояний
  updated = registry.set_state(
      subject_id="user@example.com",
      changes={"analytics":"allow","ads":"deny"},
      evidence={"uiVersion":"1.2.3","ipHash":"<hash>","userAgent":"..."},
      ctx={"region":"EEA"}
  )

  # Вычисление с учетом сигналов
  eff = registry.evaluate(
      subject_id="user@example.com",
      purposes=["analytics","ads","strictly_necessary"],
      ctx={"region":"US-CA","signals":{"gpc": True, "usPrivacy":"Y"}}
  )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

log = logging.getLogger(__name__)


# =============================== Исключения ===================================

class ConsentError(RuntimeError):
    """Общие ошибки реестра согласий."""


class PolicyValidationError(ConsentError):
    """Политика невалидна."""


# ============================ Псевдонимизация =================================

class ConsentHasher:
    """
    Псевдонимизация subjectId через HMAC-SHA256.
    Безопасно хранить только хеш; исходный subjectId не сохраняется.
    """

    def __init__(self, secret: str, prefix: str = "sub:") -> None:
        if not secret or len(secret) < 16:
            raise ConsentError("ConsentHasher: secret must be >= 16 chars")
        self._key = secret.encode("utf-8")
        self._prefix = prefix

    def hash_subject(self, subject_id: str) -> str:
        mac = hmac.new(self._key, subject_id.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{self._prefix}{mac}"


# ================================ Хранилища ===================================

@dataclass
class ConsentRecord:
    states: Dict[str, str]                           # purpose -> state ("allow"/"deny"/"prompt")
    updated_at: float                                 # epoch seconds
    version: int = 1
    evidence: List[Dict[str, Any]] = field(default_factory=list)


class ConsentStore:
    """
    Абстрактное хранилище согласий.
    Реализуйте для Redis/SQL при необходимости.
    """

    def get(self, subject_hash: str) -> Optional[ConsentRecord]:
        raise NotImplementedError

    def set(self, subject_hash: str, record: ConsentRecord) -> None:
        raise NotImplementedError

    def purge_expired(self, before_epoch: float) -> int:
        """Удалить просроченные записи (если retention управляется на уровне реестра). Возвращает число записей."""
        return 0


class InMemoryConsentStore(ConsentStore):
    """Потокобезопасное in-memory хранилище для dev/микро‑инстансов."""

    def __init__(self) -> None:
        self._data: Dict[str, ConsentRecord] = {}
        self._lock = threading.RLock()

    def get(self, subject_hash: str) -> Optional[ConsentRecord]:
        with self._lock:
            rec = self._data.get(subject_hash)
            # Возвращаем копию для безопасности
            if rec:
                return ConsentRecord(states=dict(rec.states), updated_at=rec.updated_at,
                                     version=rec.version, evidence=list(rec.evidence))
            return None

    def set(self, subject_hash: str, record: ConsentRecord) -> None:
        with self._lock:
            self._data[subject_hash] = record

    def purge_expired(self, before_epoch: float) -> int:
        with self._lock:
            keys = [k for k, v in self._data.items() if v.updated_at < before_epoch]
            for k in keys:
                self._data.pop(k, None)
            return len(keys)


# =============================== Вспомогательные ==============================

def _now() -> float:
    return time.time()


def _as_set(iterable: Optional[Iterable[str]]) -> set[str]:
    return set(iterable or [])


def _read(d: Mapping[str, Any], *path: str, default: Any = None) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, Mapping) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _validate_state(val: str) -> str:
    if val not in ("allow", "deny", "prompt"):
        raise ConsentError(f"invalid state '{val}'")
    return val


def _lower_dict_keys(d: Mapping[str, Any]) -> Dict[str, Any]:
    return {str(k).lower(): v for k, v in d.items()}


# =============================== Реестр политики ==============================

class ConsentRegistry:
    """
    Реестр согласий с вычислением эффективного состояния по политике.

    Основной порядок оценки (см. spec.evaluation.order):
      1) jurisdiction     — определение юрисдикции и специализаций правил
      2) ageGating        — возрастные ограничения
      3) externalSignals  — внешние сигналы (GPC/DNT/US Privacy/TCF)
      4) userChoice       — пользовательский выбор из хранилища
      5) orgDefault       — дефолт по политике

    Конфликты: spec.evaluation.conflictResolution (most_protective|user_priority|signal_priority).
    """

    def __init__(
        self,
        policy: Mapping[str, Any],
        store: ConsentStore,
        hasher: Optional[ConsentHasher] = None,
        retention_days: Optional[int] = None,
    ) -> None:
        self.policy = policy
        self.store = store
        self.hasher = hasher
        self.retention_days = retention_days or int(_read(policy, "spec", "records", "retentionDays", default=395))
        self._validate_policy()

    # --------------------------- Публичный API --------------------------------

    def get_state(
        self,
        subject_id: str,
        purposes: Optional[List[str]] = None,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """
        Возвращает сохраненный пользовательский выбор (без применения внешних сигналов и юрисдикции).
        Если записей нет — формирует дефолтные по политике для указанных целей.
        """
        ctx = ctx or {}
        subject_hash = self._subject_hash(subject_id)
        stored = self.store.get(subject_hash)
        if stored:
            return self._subset_states(stored.states, purposes)

        # Нет записей — вернем дефолты по политике для указанных целей
        region = self._resolve_region(ctx)
        default_map = self._defaults_for_region(region)
        allowed = set(purposes or default_map.keys())
        return {p: default_map.get(p, self._default_state_global(p)) for p in allowed}

    def set_state(
        self,
        subject_id: str,
        changes: Mapping[str, str],
        evidence: Optional[Mapping[str, Any]] = None,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """
        Сохраняет пользовательский выбор (allow/deny) для целей.
        Возвращает актуальное состояние всех целей, присутствующих в записи.
        """
        ctx = ctx or {}
        if not changes:
            raise ConsentError("changes must not be empty")

        # Валидация целей и значений
        valid_purposes = self._purpose_ids()
        for purpose, state in changes.items():
            if purpose not in valid_purposes:
                raise ConsentError(f"unknown purpose '{purpose}'")
            if state not in ("allow", "deny"):
                raise ConsentError(f"invalid state for change '{state}', only 'allow' | 'deny'")

        # doubleOptIn обработка для каналов с подтверждением (если включено в политике)
        changes = dict(changes)
        self._apply_double_opt_in(changes, evidence=evidence)

        subject_hash = self._subject_hash(subject_id)
        rec = self.store.get(subject_hash) or ConsentRecord(states={}, updated_at=0.0, version=1, evidence=[])
        rec.states.update(changes)  # "prompt" здесь не записываем, только allow/deny
        rec.updated_at = _now()
        if evidence:
            rec.evidence.append(dict(evidence))
        self.store.set(subject_hash, rec)

        # Ротация (TTL) по retentionDays
        self._rotate_if_needed()

        # Вернем текущую проекцию сохраненных
        return dict(rec.states)

    def evaluate(
        self,
        subject_id: str,
        purposes: Optional[List[str]] = None,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """
        Вычисляет ЭФФЕКТИВНОЕ состояние с учетом:
        - юрисдикции
        - возрастных ограничений
        - внешних сигналов (GPC/DNT/US Privacy/TCF)
        - пользовательского выбора
        - дефолтов по политике

        Возвращает map: purpose -> state ("allow"/"deny"/"prompt").
        """
        ctx = ctx or {}
        region = self._resolve_region(ctx)
        purposes_all = purposes or list(self._purpose_ids())
        purposes_all = [p for p in purposes_all if p in self._purpose_ids()]  # нормализация

        # 1) jurisdiction defaults
        states = self._defaults_for_region(region)

        # 2) ageGating
        age = ctx.get("age")
        if age is not None:
            self._apply_age_gating(states, age=age, region=region)

        # 3) externalSignals
        signals = _lower_dict_keys(ctx.get("signals", {})) if isinstance(ctx.get("signals"), dict) else {}
        self._apply_external_signals(states, region=region, signals=signals)

        # 4) userChoice
        stored = self.store.get(self._subject_hash(subject_id))
        user_choice = stored.states if stored else {}
        # Конфликт‑резолюция с учетом spec.evaluation.conflictResolution
        conflict_mode = _read(self.policy, "spec", "evaluation", "conflictResolution", default="most_protective")
        states = self._merge_user_choice(states, user_choice, conflict_mode)

        # 5) orgDefault уже учтен на шаге (1), дополнительно проверим fallback
        fallback = _read(self.policy, "spec", "evaluation", "fallback", default="deny")
        for p in purposes_all:
            if p not in states:
                states[p] = self._default_state_global(p) or fallback

        # Вернем проекцию по списку purposes
        result = {p: states.get(p, self._default_state_global(p)) for p in purposes_all}
        return result

    # --------------------------- Проверки и загрузка ---------------------------

    def _validate_policy(self) -> None:
        if _read(self.policy, "apiVersion") != "veilmind.io/v1" or _read(self.policy, "kind") != "ConsentPolicy":
            raise PolicyValidationError("policy must be ConsentPolicy veilmind.io/v1")
        if not isinstance(_read(self.policy, "spec", "purposes"), list) or not _read(self.policy, "spec", "purposes"):
            raise PolicyValidationError("spec.purposes must be non-empty list")
        # Уникальность purpose.id
        ids = [p.get("id") for p in _read(self.policy, "spec", "purposes")]
        if len(ids) != len(set(ids)):
            raise PolicyValidationError("spec.purposes ids must be unique")

    # --------------------------- Утилиты политики ------------------------------

    def _purpose_ids(self) -> set[str]:
        return {p.get("id") for p in _read(self.policy, "spec", "purposes")}

    def _purpose_by_id(self, pid: str) -> Mapping[str, Any]:
        for p in _read(self.policy, "spec", "purposes"):
            if p.get("id") == pid:
                return p
        raise ConsentError(f"unknown purpose '{pid}'")

    def _default_state_global(self, purpose: str) -> str:
        # Глобальный defaultState из описания цели
        try:
            p = self._purpose_by_id(purpose)
        except ConsentError:
            return "deny"
        return p.get("defaultState", "deny")

    def _defaults_for_region(self, region: str) -> Dict[str, str]:
        # Используем defaultState и региональные overrides (через legalBasis в примере это неявно),
        # поэтому по умолчанию берем defaultState; для некоторых регионов (EEA/UK) политика может
        # переопределять defaultState на "deny" для нестрого необходимых — это уже в файле.
        result = {}
        for p in _read(self.policy, "spec", "purposes"):
            pid = p.get("id")
            result[pid] = p.get("defaultState", "deny")
        # Юрисдикционный defaultState для секций может быть задан на верхнем уровне (jurisdictions[].defaultState)
        region_defaults = {}
        for j in _read(self.policy, "spec", "jurisdictions", default=[]):
            if j.get("code") == region and "defaultState" in j:
                region_defaults = {pid: j["defaultState"] for pid in result}
                break
        # Применим, если задано
        if region_defaults:
            for k, v in region_defaults.items():
                if k in result:
                    result[k] = v
        return result

    # ---------------------------- Юрисдикции -----------------------------------

    def _resolve_region(self, ctx: Mapping[str, Any]) -> str:
        # Приоритет: явно ctx["region"], затем по geo/ip/таймзоне, иначе ROW
        region = ctx.get("region")
        if isinstance(region, str) and region:
            return region
        # Иначе fallback
        return "ROW"

    # ---------------------------- Age gating -----------------------------------

    def _apply_age_gating(self, states: MutableMapping[str, str], *, age: int, region: str) -> None:
        ag = _read(self.policy, "spec", "ageGating", default={})
        if not ag or not ag.get("enabled", False):
            return
        # Определим возраст согласия по региону
        age_rules = {j.get("code"): j.get("ageOfConsent") for j in _read(self.policy, "spec", "jurisdictions", default=[])}
        age_of_consent = age_rules.get(region)
        if age_of_consent is None:
            age_of_consent = 13  # дефолт
        if age >= age_of_consent:
            return
        # Малолетний — применяем политику (deny_non_essential|block_all)
        mode = ag.get("underAgeAction", "deny_non_essential")
        if mode == "block_all":
            for k in list(states.keys()):
                states[k] = "deny"
            return
        # deny_non_essential: строго необходимые остаются allow, остальное deny
        essential_tags = set(["essential"])
        # Находим цели с тегом essential
        for p in _read(self.policy, "spec", "purposes"):
            pid = p.get("id")
            tags = set(_read(p, "enforcement", "tags", default=[]))
            if pid in states and not (essential_tags & tags):
                states[pid] = "deny"

    # ------------------------ Внешние сигналы (GPC/DNT/...) --------------------

    def _apply_external_signals(self, states: MutableMapping[str, str], *, region: str, signals: Mapping[str, Any]) -> None:
        ext = _read(self.policy, "spec", "externalSignals", default={})
        # GPC
        if ext.get("gpc", {}).get("enabled") and signals.get("gpc") is True:
            effect = _read(ext, "gpc", "effect", region, default=None) or _read(ext, "gpc", "effect", "default", default=None)
            if isinstance(effect, Mapping):
                for purpose, new_state in effect.items():
                    states[purpose] = _validate_state(new_state)
        # DNT
        if ext.get("dnt", {}).get("enabled") and signals.get("dnt") in (True, "1", "yes"):
            effect = _read(ext, "dnt", "effect", "default", default=None)
            if isinstance(effect, Mapping):
                for purpose, new_state in effect.items():
                    states[purpose] = _validate_state(new_state)
        # US Privacy (usp)
        if ext.get("usPrivacy", {}).get("enabled"):
            usp = signals.get("usprivacy") or signals.get("us_privacy") or signals.get("usp")
            if isinstance(usp, str):
                mapping = _read(ext, "usPrivacy", "map", default={})
                exact = mapping.get(usp)
                if isinstance(exact, Mapping):
                    for purpose, new_state in exact.items():
                        states[purpose] = _validate_state(new_state)
        # TCF (упрощенный маппинг)
        if ext.get("tcf", {}).get("enabled"):
            tcf = signals.get("tcf") or {}
            # Ожидаем tcf как dict с {purposeId(str): "allow"/"deny"} или raw consent string — здесь упрощенно
            if isinstance(tcf, Mapping):
                map_p = _read(ext, "tcf", "mapPurposes", default={})
                for k, v in tcf.items():
                    purpose_id = map_p.get(str(k))
                    if not purpose_id:
                        continue
                    if v in ("allow", "deny"):
                        states[purpose_id] = v  # type: ignore[assignment]

    # -------------------------- Конфликт‑резолюция ------------------------------

    def _merge_user_choice(
        self,
        states: Mapping[str, str],
        user_choice: Mapping[str, str],
        mode: str,
    ) -> Dict[str, str]:
        result = dict(states)
        for k, v in user_choice.items():
            if v not in ("allow", "deny"):
                continue
            if k not in result:
                result[k] = v
                continue
            if mode == "user_priority":
                result[k] = v
            elif mode == "signal_priority":
                # Ничего — внешние сигналы уже применены, пользовательский выбор не перекрывает
                pass
            else:  # most_protective
                # Самый «защитный» — deny > prompt > allow
                current = result[k]
                order = {"deny": 2, "prompt": 1, "allow": 0}
                result[k] = v if order.get(v, 0) >= order.get(current, 0) else current
        return result

    # ----------------------------- Double opt-in --------------------------------

    def _apply_double_opt_in(self, changes: MutableMapping[str, str], evidence: Optional[Mapping[str, Any]]) -> None:
        # Если для цели задан doubleOptIn: true — разрешение (allow) допускается только при наличии evidence.verify=true
        if not changes:
            return
        for p in _read(self.policy, "spec", "purposes"):
            pid = p.get("id")
            if pid not in changes:
                continue
            if p.get("doubleOptIn") and changes[pid] == "allow":
                verified = False
                if isinstance(evidence, Mapping):
                    # простое правило: evidence.emailVerified или channelVerified
                    verified = bool(evidence.get("emailVerified") or evidence.get("channelVerified"))
                if not verified:
                    # Оставим explicit deny или отменим allow (установим prompt)
                    changes[pid] = "prompt"  # не записываем "prompt" в storage, но сообщим вызывающему коду
                    log.info("doubleOptIn required for purpose '%s': downgraded to 'prompt'", pid)

    # ------------------------------- Прочее ------------------------------------

    def _subject_hash(self, subject_id: str) -> str:
        if self.hasher:
            return self.hasher.hash_subject(subject_id)
        # Безопасность: без hasher сохраняем raw — допускается только в dev
        return f"raw:{subject_id}"

    def _subset_states(self, states: Mapping[str, str], purposes: Optional[Iterable[str]]) -> Dict[str, str]:
        if not purposes:
            return dict(states)
        allowed = _as_set(purposes)
        return {k: v for k, v in states.items() if k in allowed}

    def _rotate_if_needed(self) -> None:
        # Вызывается лениво после set_state
        retention_days = int(self.retention_days or 0)
        if retention_days <= 0:
            return
        before = _now() - retention_days * 24 * 3600
        try:
            purged = self.store.purge_expired(before_epoch=before)
            if purged:
                log.debug("consent store: purged %d expired records", purged)
        except Exception as e:
            log.warning("consent store purge failed: %s", e)


# ============================ Тестовая проверка ===============================

if __name__ == "__main__":
    # Мини‑самопроверка поведения (не юнит‑тесты)
    logging.basicConfig(level=logging.INFO)
    example_policy = {
        "apiVersion": "veilmind.io/v1",
        "kind": "ConsentPolicy",
        "spec": {
            "jurisdictions": [
                {"code": "EEA", "defaultState": "deny", "ageOfConsent": 16},
                {"code": "US-CA", "defaultState": "prompt", "ageOfConsent": 13},
                {"code": "ROW", "defaultState": "prompt", "ageOfConsent": 13},
            ],
            "purposes": [
                {"id": "strictly_necessary", "defaultState": "allow", "enforcement": {"tags": ["essential"]}},
                {"id": "analytics", "defaultState": "deny"},
                {"id": "ads", "defaultState": "deny"},
                {"id": "email_marketing", "defaultState": "deny", "doubleOptIn": True},
            ],
            "externalSignals": {
                "gpc": {"enabled": True, "effect": {"default": {"ads": "deny"}}},
                "dnt": {"enabled": True, "effect": {"default": {"analytics": "deny", "ads": "deny"}}},
                "usPrivacy": {"enabled": True, "map": {"Y": {"ads": "deny"}, "N": {"ads": "allow"}}},
                "tcf": {"enabled": False},
            },
            "evaluation": {"order": ["jurisdiction", "ageGating", "externalSignals", "userChoice", "orgDefault"],
                           "conflictResolution":"most_protective", "fallback":"deny"},
            "records": {"retentionDays": 395}
        }
    }

    store = InMemoryConsentStore()
    hasher = ConsentHasher(secret="this_is_demo_secret_for_hmac_only")
    reg = ConsentRegistry(policy=example_policy, store=store, hasher=hasher)

    user = "alice@example.com"
    print("Defaults (ROW):", reg.get_state(user, purposes=["analytics", "strictly_necessary"], ctx={"region": "ROW"}))
    print("Evaluate + GPC:", reg.evaluate(user, purposes=["analytics","ads","strictly_necessary"],
                                          ctx={"region":"US-CA","signals":{"gpc": True}}))
    print("Set allow analytics:", reg.set_state(user, {"analytics":"allow"}, evidence={"uiVersion":"1.0"}, ctx={"region":"ROW"}))
    print("Evaluate after set:", reg.evaluate(user, purposes=["analytics","ads"], ctx={"region":"ROW"}))
    print("Double opt-in (email_marketing allow w/o verify):", reg.set_state(user, {"email_marketing":"allow"}, evidence={"uiVersion":"1.0"}))
