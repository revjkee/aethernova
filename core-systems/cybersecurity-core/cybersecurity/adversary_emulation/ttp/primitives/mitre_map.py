# cybersecurity-core/cybersecurity/adversary_emulation/ttp/mitre_map.py
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK TTP Map (STIX 2.1) — промышленный модуль индексации и экспорта.

Назначение:
- Загрузка локального STIX 2.1 JSON с данными ATT&CK (enterprise/mobile/ics).
- Индексация тактик (tactics) и техник/подтехник (techniques/sub-techniques).
- Фильтрация revoked/deprecated, запросы по платформам/тактикам/идентификаторам.
- Экспорт слоя ATT&CK Navigator (JSON), пригодного для импорта в веб-интерфейс.

Справочные источники:
- ATT&CK в STIX 2.1 (официальный набор данных): https://attack.mitre.org/resources/attack-data-and-tools/
- Репозиторий STIX 2.1 коллекций ATT&CK (enterprise-attack.json и др.):
  https://github.com/mitre-attack/attack-stix-data
- ATT&CK Navigator (веб-инструмент слоёв/матриц): https://mitre-attack.github.io/attack-navigator/
- Примеры/описание работы со слоями Navigator (слой — JSON): https://github.com/mitre-attack/attack-navigator
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

__all__ = [
    "MITREMapError",
    "Tactic",
    "Technique",
    "MITREMap",
    "NavigatorLayerConfig",
]

# ----------------------------- МОДЕЛИ ---------------------------------------


@dataclass(frozen=True)
class Tactic:
    id: str                  # TAxxxx (external_id)
    name: str                # e.g., Execution
    shortname: str           # e.g., execution
    stix_id: str             # STIX SDO id (x-mitre-tactic--uuid)


@dataclass(frozen=True)
class Technique:
    id: str                  # Txxxx или Txxxx.yyy (external_id)
    name: str
    description: Optional[str]
    is_subtechnique: bool
    parent_id: Optional[str]           # "Txxxx" для подтехники
    tactics: Set[str] = field(default_factory=set)   # shortnames (e.g., {"execution"})
    tactic_ids: Set[str] = field(default_factory=set)  # TAxxxx
    platforms: Set[str] = field(default_factory=set)   # x_mitre_platforms
    data_sources: Set[str] = field(default_factory=set)
    detection: Optional[str] = None
    revoked: bool = False
    deprecated: bool = False
    stix_id: Optional[str] = None      # attack-pattern--uuid
    version: Optional[str] = None      # x_mitre_version


@dataclass(frozen=True)
class NavigatorLayerConfig:
    """
    Конфигурация экспорта слоя Navigator.
    Важно: спецификация слоя может меняться, поэтому значения версий рекомендуется
    при необходимости переопределять на стороне вызывающей системы.
    """
    name: str = "Aethernova Layer"
    description: str = "Generated layer"
    domain: str = "enterprise-attack"  # или mobile-attack / ics-attack
    # Поле versions является рекомендуемым и может быть уточнено пользователем.
    versions: Dict[str, str] = field(
        default_factory=lambda: {
            # Пользователь вправе заменить на актуальные под конкретный выпуск Navigator/ATT&CK.
            "layer": "4.6",
            "attack": "14",
            "navigator": "4.8.1",
        }
    )
    gradient_colors: Tuple[str, str] = ("#ffe766", "#ff6666")  # start, end
    min_value: int = 0
    max_value: int = 100
    default_score: int = 100
    show_technique_name: bool = True


# ---------------------------- ИСКЛЮЧЕНИЕ ------------------------------------


class MITREMapError(RuntimeError):
    pass


# --------------------------- ВСПОМОГАТЕЛЬНОЕ --------------------------------


def _ext_id(obj: Dict[str, Any]) -> Optional[str]:
    """
    Извлекает внешний идентификатор ATT&CK (Txxxx/TAxxxx) из external_references
    с source_name вида mitre-attack / mitre-mobile-attack / mitre-ics-attack.
    """
    refs = obj.get("external_references") or []
    for r in refs:
        src = (r.get("source_name") or "").lower()
        if src in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}:
            eid = r.get("external_id")
            if isinstance(eid, str):
                return eid
    return None


def _as_set(value: Optional[Iterable[str]]) -> Set[str]:
    if not value:
        return set()
    return {str(x) for x in value if x}


# ------------------------------ ЯДРО -----------------------------------------


class MITREMap:
    """
    Индексатор STIX 2.1 данных ATT&CK.

    Использование:
        mmap = MITREMap.from_file("enterprise-attack.json", include_revoked=False)
        mmap.count() -> (tactics, techniques)
        mmap.get_technique("T1059")
        mmap.find_techniques(tactic="execution", platform="Windows")
        layer = mmap.to_navigator_layer(["T1059", "T1059.001"], NavigatorLayerConfig(name="Plan"))

    Формат данных ATT&CK и Navigator подтверждён официальной документацией MITRE. :contentReference[oaicite:1]{index=1}
    """

    def __init__(self, domain: str = "enterprise-attack", include_revoked: bool = False):
        self.domain: str = domain
        self.include_revoked: bool = include_revoked

        self._tactics_by_shortname: Dict[str, Tactic] = {}
        self._tactics_by_id: Dict[str, Tactic] = {}
        self._techniques_by_id: Dict[str, Technique] = {}
        self._loaded: bool = False

        # Метаданные набора (best-effort)
        self.dataset_attack_spec: Optional[str] = None  # x_mitre_attack_spec_version (если присутствует)
        self.dataset_created: Optional[str] = None

    # -------- ЗАГРУЗКА --------

    @classmethod
    def from_file(cls, path: str | Path, domain: str = "enterprise-attack", include_revoked: bool = False) -> "MITREMap":
        p = Path(path)
        if not p.exists():
            raise MITREMapError(f"Файл не найден: {p}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            raise MITREMapError(f"Ошибка чтения STIX JSON: {e}") from e

        inst = cls(domain=domain, include_revoked=include_revoked)
        inst._load(data)
        return inst

    def _load(self, stix: Dict[str, Any]) -> None:
        if "objects" not in stix or not isinstance(stix["objects"], list):
            raise MITREMapError("Некорректный STIX JSON: отсутствует список 'objects'.")

        objects = stix["objects"]

        # Индексация тактик (x-mitre-tactic)
        for obj in objects:
            if obj.get("type") != "x-mitre-tactic":
                continue
            if (obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True) and not self.include_revoked:
                continue

            shortname = obj.get("x_mitre_shortname")
            name = obj.get("name")
            stix_id = obj.get("id")
            eid = _ext_id(obj)
            if not (shortname and name and stix_id and eid and eid.startswith("TA")):
                continue

            tactic = Tactic(id=eid, name=name, shortname=shortname, stix_id=stix_id)
            self._tactics_by_shortname[shortname] = tactic
            self._tactics_by_id[eid] = tactic

        # Индексация техник (attack-pattern)
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            revoked = bool(obj.get("revoked"))
            deprecated = bool(obj.get("x_mitre_deprecated"))

            if (revoked or deprecated) and not self.include_revoked:
                continue

            eid = _ext_id(obj)  # Txxxx или Txxxx.yyy
            if not eid or not eid.startswith("T"):
                continue

            name = obj.get("name")
            stix_id = obj.get("id")
            is_sub = bool(obj.get("x_mitre_is_subtechnique"))
            parent_id = None
            if is_sub and "." in eid:
                parent_id = eid.split(".", 1)[0]

            # Тактики по kill_chain_phases -> phase_name == shortname тактики
            tactics_short: Set[str] = set()
            for kcp in obj.get("kill_chain_phases") or []:
                if kcp.get("kill_chain_name") == "mitre-attack":
                    ph = kcp.get("phase_name")
                    if isinstance(ph, str):
                        tactics_short.add(ph)

            tactic_ids: Set[str] = set()
            for short in list(tactics_short):
                t = self._tactics_by_shortname.get(short)
                if t:
                    tactic_ids.add(t.id)

            platforms = _as_set(obj.get("x_mitre_platforms"))
            data_sources = _as_set(obj.get("x_mitre_data_sources"))
            detection = obj.get("x_mitre_detection")
            version = obj.get("x_mitre_version")

            tech = Technique(
                id=eid,
                name=name or eid,
                description=obj.get("description"),
                is_subtechnique=is_sub,
                parent_id=parent_id,
                tactics=tactics_short,
                tactic_ids=tactic_ids,
                platforms=platforms,
                data_sources=data_sources,
                detection=detection,
                revoked=revoked,
                deprecated=deprecated,
                stix_id=stix_id,
                version=version,
            )
            self._techniques_by_id[eid] = tech

        self.dataset_attack_spec = stix.get("x_mitre_attack_spec_version") or None
        self.dataset_created = stix.get("created") or None
        self._loaded = True

    # -------- ИНФО / СТАТИКА --------

    def loaded(self) -> bool:
        return self._loaded

    def count(self) -> Tuple[int, int]:
        return len(self._tactics_by_id), len(self._techniques_by_id)

    # -------- ДОСТУП К ТАКТИКАМ/ТЕХНИКАМ --------

    def get_tactic(self, ref: str) -> Optional[Tactic]:
        """
        Поиск тактики по shortname (execution) или TA-id (TA0002).
        """
        if ref.lower() in self._tactics_by_shortname:
            return self._tactics_by_shortname[ref.lower()]
        return self._tactics_by_id.get(ref)

    def get_technique(self, tid_or_name: str) -> Optional[Technique]:
        """
        Поиск техники по идентификатору (T1059 или T1059.001) либо по точному имени.
        """
        if tid_or_name in self._techniques_by_id:
            return self._techniques_by_id[tid_or_name]
        # exact name match
        for t in self._techniques_by_id.values():
            if t.name == tid_or_name:
                return t
        return None

    def find_techniques(
        self,
        tactic: Optional[str] = None,          # shortname ("execution") или TA-id
        platform: Optional[str] = None,        # "Windows", "Linux", "macOS", "IaaS", ...
        name_regex: Optional[str] = None,      # регэксп по имени
        include_subtechniques: bool = True,
    ) -> List[Technique]:
        """
        Гибкий поиск по сокращению тактики/TA, платформам и имени (regex).
        """
        if tactic:
            tac = self.get_tactic(tactic)
            if not tac:
                return []
            tactic_short = tac.shortname
        else:
            tactic_short = None

        rx = re.compile(name_regex, re.I) if name_regex else None
        res: List[Technique] = []
        for tech in self._techniques_by_id.values():
            if not include_subtechniques and tech.is_subtechnique:
                continue
            if tactic_short and tactic_short not in tech.tactics:
                continue
            if platform and platform not in tech.platforms:
                continue
            if rx and not rx.search(tech.name):
                continue
            res.append(tech)
        # стабильный порядок: по id
        res.sort(key=lambda t: t.id)
        return res

    # -------- ЭКСПОРТ NAVIGATOR LAYER ---------------------------------------

    def to_navigator_layer(
        self,
        techniques: Iterable[str | Technique],
        cfg: Optional[NavigatorLayerConfig] = None,
    ) -> Dict[str, Any]:
        """
        Генерирует JSON-слой Navigator (для импорта в веб-интерфейс).
        Слой — это JSON объект, который может быть импортирован в Navigator. :contentReference[oaicite:2]{index=2}
        """
        if cfg is None:
            cfg = NavigatorLayerConfig()

        # Сбор техник (включая актуальные тактики для каждой техники)
        items: List[Dict[str, Any]] = []
        for item in techniques:
            tech = item if isinstance(item, Technique) else self._techniques_by_id.get(str(item))
            if not tech:
                # игнорируем неизвестные идентификаторы
                continue
            for tactic_short in sorted(tech.tactics) or [None]:
                entry = {
                    "techniqueID": tech.id,
                    # В Navigator техника может повторяться с разными тактиками
                    # (technique+tactic пара). Если тактики отсутствуют, поле можно опустить.
                    **({"tactic": tactic_short} if tactic_short else {}),
                    "score": cfg.default_score,
                    "comment": tech.name,
                    "enabled": True,
                    "metadata": [],
                    "color": None,
                    "links": [],
                    "showSubtechniques": True,
                }
                items.append(entry)

        layer: Dict[str, Any] = {
            "name": cfg.name,
            "description": cfg.description,
            "domain": cfg.domain,
            "versions": cfg.versions,  # рекомендуемо, но остаётся на усмотрение пользователя
            "sorting": 0,
            "layout": {
                "layout": "flat",
                "aggregateFunction": "average",
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": items,
            "gradient": {
                "colors": list(cfg.gradient_colors),
                "minValue": cfg.min_value,
                "maxValue": cfg.max_value,
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": True,
            "expandedSubtechniques": [],
            "zoom": 1,
        }
        return layer

    # -------- СЛУЖЕБНОЕ -----------------------------------------------------

    def all_tactics(self) -> List[Tactic]:
        return sorted(self._tactics_by_id.values(), key=lambda t: t.id)

    def all_techniques(self) -> List[Technique]:
        return sorted(self._techniques_by_id.values(), key=lambda t: t.id)

    def dataset_meta(self) -> Dict[str, Optional[str]]:
        return {
            "attack_spec_version": self.dataset_attack_spec,
            "created": self.dataset_created,
            "domain": self.domain,
        }
