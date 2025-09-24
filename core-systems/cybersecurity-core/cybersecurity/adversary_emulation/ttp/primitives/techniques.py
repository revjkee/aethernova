# cybersecurity-core/cybersecurity/adversary_emulation/ttp/techniques.py
# -*- coding: utf-8 -*-
"""
Safe Adversary Emulation TTP Schema & Registry (industrial-grade, dry-only)

Данный модуль предоставляет безопасную (неисполняющую) модель описания техник
противника (TTP) для нужд эмуляции/тестирования. Он строго моделирует данные,
валидирует их, строит «планы эмуляции» и рендерит командные шаблоны, но НЕ
выполняет никакие команды. Любая попытка выполнения намеренно приводит к
исключению.

Особенности:
- Жесткие типы и валидация (ID техник вида T####(.###)? и т. п.).
- Реестр техник: добавление, поиск, загрузка из JSON/JSONL каталогов.
- Конструктор планов и экспорт в JSON/Markdown.
- Логирование жизненного цикла, стабильные исключения.
- Нулевая опасность исполнения: только рендер строк, без системных вызовов.

Зависимости: стандартная библиотека Python 3.10+.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from string import Template
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Логирование
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(
        level=os.environ.get("TTP_LOGLEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

# ---------------------------------------------------------------------------
# Константы и паттерны
# ---------------------------------------------------------------------------

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")  # T#### или T####.###
TACTIC_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z \-/&]+$")  # Мягкая валидация имени тактики

DEFAULT_SCHEMA_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------

class TechniqueValidationError(ValueError):
    """Ошибка валидации техники/шагов."""


class RegistryError(RuntimeError):
    """Ошибка операций реестра техник."""


class ExecutionDisabledError(RuntimeError):
    """Любая попытка фактического исполнения запрещена."""


# ---------------------------------------------------------------------------
# Перечисления
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    NETWORK = "network"
    CLOUD = "cloud"
    CONTAINER = "container"


class Executor(str, Enum):
    POWERSHELL = "powershell"
    CMD = "cmd"
    BASH = "bash"
    PYTHON = "python"
    SH = "sh"


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Artifact:
    """Ожидаемые артефакты (логи, файлы, реестр и т. п.)."""
    type: str
    location: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class Detection:
    """Подсказки детектирования: источники, правила, эвристики."""
    sources: Tuple[str, ...] = field(default_factory=tuple)
    hints: Tuple[str, ...] = field(default_factory=tuple)
    artifacts: Tuple[Artifact, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sources": list(self.sources),
            "hints": list(self.hints),
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


@dataclass(frozen=True)
class ProcedureStep:
    """
    Шаг процедуры с безопасным шаблоном команды.
    ВАЖНО: Здесь только шаблон (Template) для дальнейшего рендера,
    без какого-либо исполнения.
    """
    id: str
    description: str
    executor: Executor
    command_template: str
    requires_admin: bool = False
    opsec_safe: bool = True
    timeout_sec: Optional[int] = None

    def render(self, variables: Optional[Dict[str, Any]] = None) -> str:
        """Рендер безопасного шаблона (без исполнения)."""
        variables = variables or {}
        try:
            return Template(self.command_template).safe_substitute(**variables)
        except Exception as e:  # noqa: BLE001
            raise TechniqueValidationError(f"Template render error in step {self.id}: {e}") from e

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "executor": self.executor.value,
            "command_template": self.command_template,
            "requires_admin": self.requires_admin,
            "opsec_safe": self.opsec_safe,
            "timeout_sec": self.timeout_sec,
        }


@dataclass(frozen=True)
class Reference:
    """Ссылки на источники/документацию (строки URL или идентификаторы)."""
    title: str
    url: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Technique:
    """
    Безопасная модель техники (TTP). НЕ исполняет команды.
    """
    id: str
    name: str
    tactics: Tuple[str, ...]
    platforms: Tuple[Platform, ...]
    severity: Severity = Severity.MEDIUM
    description: Optional[str] = None
    steps: List[ProcedureStep] = field(default_factory=list)
    prerequisites: Tuple[str, ...] = field(default_factory=tuple)
    cleanup: Tuple[str, ...] = field(default_factory=tuple)
    detection: Optional[Detection] = None
    references: Tuple[Reference, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = DEFAULT_SCHEMA_VERSION
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ---------------- Validation ----------------

    def validate(self) -> None:
        """Полная валидация техники и шагов."""
        if not TECHNIQUE_ID_RE.match(self.id):
            raise TechniqueValidationError(f"Invalid technique id: {self.id!r} (expected T#### or T####.###)")
        if not self.name or not self.name.strip():
            raise TechniqueValidationError("Technique name must be non-empty.")
        if not self.tactics:
            raise TechniqueValidationError("Technique must have at least one tactic name.")
        for t in self.tactics:
            if not TACTIC_NAME_RE.match(t):
                raise TechniqueValidationError(f"Invalid tactic name: {t!r}")
        if not self.platforms:
            raise TechniqueValidationError("Technique must declare at least one platform.")
        # уникальность id шагов
        seen_ids = set()
        for step in self.steps:
            if step.id in seen_ids:
                raise TechniqueValidationError(f"Duplicate step id: {step.id!r}")
            seen_ids.add(step.id)
            if not step.description.strip():
                raise TechniqueValidationError(f"Empty description in step {step.id}")
            if not isinstance(step.executor, Executor):
                raise TechniqueValidationError(f"Invalid executor in step {step.id}: {step.executor!r}")
            # Проверяем, что шаблон можно безопасно отрендерить хотя бы пустыми переменными
            _ = step.render({})

        # ссылки
        for ref in self.references:
            if not ref.title.strip() or not ref.url.strip():
                raise TechniqueValidationError("Reference must have non-empty title and url.")

        # даты ISO-8601
        for dt in (self.created_at, self.updated_at):
            if "T" not in dt:
                raise TechniqueValidationError("Timestamps must be ISO-8601 (contain 'T').")

    # ---------------- Transform & Export ----------------

    def to_dict(self, include_steps: bool = True) -> Dict[str, Any]:
        base = {
            "id": self.id,
            "name": self.name,
            "tactics": list(self.tactics),
            "platforms": [p.value for p in self.platforms],
            "severity": self.severity.value,
            "description": self.description,
            "prerequisites": list(self.prerequisites),
            "cleanup": list(self.cleanup),
            "detection": self.detection.to_dict() if self.detection else None,
            "references": [r.to_dict() for r in self.references],
            "tags": list(self.tags),
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if include_steps:
            base["steps"] = [s.to_dict() for s in self.steps]
        return base

    def render_commands(self, variables: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        """
        Возвращает СТРОКИ команд для каждого шага (без выполнения).
        Формат: [{"step_id": "...", "executor": "...", "command": "..."}, ...]
        """
        variables = variables or {}
        out: List[Dict[str, str]] = []
        for s in self.steps:
            out.append(
                {
                    "step_id": s.id,
                    "executor": s.executor.value,
                    "command": s.render(variables),
                }
            )
        return out

    # ---------------- Safe Execution Guard ----------------

    def execute(self, *_: Any, **__: Any) -> None:  # pragma: no cover
        """
        Любая попытка «исполнить» технику запрещена.
        """
        raise ExecutionDisabledError(
            "Execution is disabled by design. Use render_commands() to obtain dry command strings."
        )


# ---------------------------------------------------------------------------
# Реестр техник
# ---------------------------------------------------------------------------

class TechniqueRegistry:
    """
    Потокобезопасный, простой реестр техник (в рамках одного процесса).
    Хранит техники по ID, поддерживает поиск и загрузку из файлов.
    """

    def __init__(self) -> None:
        self._by_id: Dict[str, Technique] = {}

    # ------------ базовые операции ------------

    def add(self, tech: Technique, *, overwrite: bool = False) -> None:
        tech.validate()
        if not overwrite and tech.id in self._by_id:
            raise RegistryError(f"Technique already exists: {tech.id}")
        self._by_id[tech.id] = tech
        logger.debug("Technique registered: %s", tech.id)

    def get(self, tech_id: str) -> Technique:
        try:
            return self._by_id[tech_id]
        except KeyError as e:
            raise RegistryError(f"Technique not found: {tech_id}") from e

    def remove(self, tech_id: str) -> None:
        if tech_id in self._by_id:
            del self._by_id[tech_id]
            logger.debug("Technique removed: %s", tech_id)
        else:
            raise RegistryError(f"Technique not found: {tech_id}")

    def list_ids(self) -> List[str]:
        return sorted(self._by_id.keys())

    # ------------ поиск/фильтрация ------------

    def search(
        self,
        *,
        platforms: Optional[Sequence[Platform]] = None,
        severity_at_least: Optional[Severity] = None,
        tactic_contains: Optional[str] = None,
        tag_contains: Optional[str] = None,
    ) -> List[Technique]:
        res = list(self._by_id.values())
        if platforms:
            pset = set(platforms)
            res = [t for t in res if any(p in pset for p in t.platforms)]
        if severity_at_least:
            order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            idx = order.index(severity_at_least)
            allowed = set(order[idx:])
            res = [t for t in res if t.severity in allowed]
        if tactic_contains:
            tc = tactic_contains.lower()
            res = [t for t in res if any(tc in x.lower() for x in t.tactics)]
        if tag_contains:
            tg = tag_contains.lower()
            res = [t for t in res if any(tg in x.lower() for x in t.tags)]
        return sorted(res, key=lambda t: (t.severity.value, t.id))

    # ------------ загрузка из файлов ------------

    def load_from_path(self, path: str | Path, *, overwrite: bool = False) -> int:
        """
        Загружает техники из JSON/JSONL файлов. Возвращает количество загруженных техник.
        Ожидаемый формат JSON: объект техники как в Technique.to_dict(include_steps=True).
        JSONL: по одной технике на строку.
        """
        p = Path(path)
        if p.is_dir():
            count = 0
            for f in sorted(p.glob("**/*.json*")):
                count += self._load_file(f, overwrite=overwrite)
            return count
        else:
            return self._load_file(p, overwrite=overwrite)

    def _load_file(self, file_path: Path, *, overwrite: bool) -> int:
        if not file_path.exists():
            raise RegistryError(f"File not found: {file_path}")
        suffix = file_path.suffix.lower()
        loaded = 0
        if suffix == ".jsonl":
            for line in file_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                self._add_from_obj(obj, overwrite=overwrite)
                loaded += 1
        elif suffix == ".json":
            obj_text = file_path.read_text(encoding="utf-8")
            obj = json.loads(obj_text)
            # допускаем список техник в одном файле
            if isinstance(obj, list):
                for item in obj:
                    self._add_from_obj(item, overwrite=overwrite)
                    loaded += 1
            else:
                self._add_from_obj(obj, overwrite=overwrite)
                loaded += 1
        else:
            # «.json.gz» и подобные — поддерживаются выше через glob("**/*.json*"), тут
            # можно добавить простую попытку json.loads на прочитанный текст
            text = file_path.read_text(encoding="utf-8")
            obj = json.loads(text)
            if isinstance(obj, list):
                for item in obj:
                    self._add_from_obj(item, overwrite=overwrite)
                    loaded += 1
            else:
                self._add_from_obj(obj, overwrite=overwrite)
                loaded += 1
        logger.info("Loaded %d technique(s) from %s", loaded, file_path)
        return loaded

    def _add_from_obj(self, obj: Dict[str, Any], *, overwrite: bool) -> None:
        tech = self._technique_from_dict(obj)
        self.add(tech, overwrite=overwrite)

    # ------------ десериализация ------------

    def _technique_from_dict(self, d: Dict[str, Any]) -> Technique:
        try:
            platforms = tuple(Platform(p) for p in d["platforms"])
            severity = Severity(d.get("severity", Severity.MEDIUM.value))
            steps_raw = d.get("steps", []) or []
            steps = [
                ProcedureStep(
                    id=s["id"],
                    description=s["description"],
                    executor=Executor(s["executor"]),
                    command_template=s["command_template"],
                    requires_admin=bool(s.get("requires_admin", False)),
                    opsec_safe=bool(s.get("opsec_safe", True)),
                    timeout_sec=s.get("timeout_sec"),
                )
                for s in steps_raw
            ]
            detection_raw = d.get("detection") or None
            detection = (
                Detection(
                    sources=tuple(detection_raw.get("sources", []) or []),
                    hints=tuple(detection_raw.get("hints", []) or []),
                    artifacts=tuple(
                        Artifact(**a) for a in (detection_raw.get("artifacts", []) or [])
                    ),
                )
                if detection_raw
                else None
            )
            refs = tuple(Reference(**r) for r in (d.get("references", []) or []))
            tech = Technique(
                id=d["id"],
                name=d["name"],
                tactics=tuple(d["tactics"]),
                platforms=platforms,
                severity=severity,
                description=d.get("description"),
                steps=steps,
                prerequisites=tuple(d.get("prerequisites", []) or []),
                cleanup=tuple(d.get("cleanup", []) or []),
                detection=detection,
                references=refs,
                tags=tuple(d.get("tags", []) or []),
                schema_version=d.get("schema_version", DEFAULT_SCHEMA_VERSION),
                created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
                updated_at=d.get("updated_at", datetime.now(timezone.utc).isoformat()),
            )
            tech.validate()
            return tech
        except Exception as e:  # noqa: BLE001
            raise RegistryError(f"Invalid technique object: {e}") from e


# ---------------------------------------------------------------------------
# План эмуляции
# ---------------------------------------------------------------------------

@dataclass
class EmulationPlan:
    """
    План эмуляции — упорядоченный набор техник и шагов (без исполнения).
    """
    techniques: List[Technique] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    title: str = "Adversary Emulation Plan"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add(self, tech: Technique) -> None:
        tech.validate()
        self.techniques.append(tech)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "created_at": self.created_at,
            "variables": self.variables,
            "techniques": [t.to_dict(include_steps=True) for t in self.techniques],
        }

    def render_commands(self) -> List[Dict[str, Any]]:
        """
        Возвращает плоский список шагов с отрендеренными командами (без исполнения).
        Формат:
          [
            {
              "technique_id": "T####(.###)?",
              "technique_name": "...",
              "step_id": "...",
              "executor": "...",
              "command": "..."
            }, ...
          ]
        """
        rows: List[Dict[str, Any]] = []
        for t in self.techniques:
            for row in t.render_commands(self.variables):
                rows.append(
                    {
                        "technique_id": t.id,
                        "technique_name": t.name,
                        "step_id": row["step_id"],
                        "executor": row["executor"],
                        "command": row["command"],
                    }
                )
        return rows

    def to_markdown(self) -> str:
        """Экспорт плана в Markdown-таблицу (для отчётов)."""
        header = "# " + self.title + "\n\n"
        meta = f"- Created: {self.created_at}\n\n"
        table_head = "| Technique | Name | Step | Executor | Command |\n|---|---|---|---|---|\n"
        lines = [header, meta, table_head]
        for row in self.render_commands():
            lines.append(
                f"| {row['technique_id']} | {row['technique_name']} | {row['step_id']} | {row['executor']} | {row['command'].replace('|', '\\|')} |\n"
            )
        return "".join(lines)


# ---------------------------------------------------------------------------
# Утилиты быстрого построения из реестра
# ---------------------------------------------------------------------------

def build_plan_from_registry(
    reg: TechniqueRegistry,
    *,
    technique_ids: Optional[Sequence[str]] = None,
    platforms: Optional[Sequence[Platform]] = None,
    min_severity: Optional[Severity] = None,
    variables: Optional[Dict[str, Any]] = None,
    title: str = "Adversary Emulation Plan",
) -> EmulationPlan:
    """
    Создаёт план эмуляции по набору фильтров или явному списку ID.
    """
    variables = variables or {}
    plan = EmulationPlan(variables=variables, title=title)
    items: List[Technique]
    if technique_ids:
        items = [reg.get(tid) for tid in technique_ids]
    else:
        items = reg.search(platforms=platforms, severity_at_least=min_severity)
    for t in items:
        plan.add(t)
    logger.info("Plan built with %d technique(s).", len(items))
    return plan


# ---------------------------------------------------------------------------
# Пример безопасной (пустой) техники для шаблонизации проектов
# ---------------------------------------------------------------------------

def example_technique() -> Technique:
    """
    Возвращает безопасный пример техники без вредных действий.
    Команды — нейтральные (echo), исключительно для демонстрации шаблонов.
    """
    t = Technique(
        id="T0000.001",
        name="Demo Technique (Safe Echo)",
        tactics=("Execution",),
        platforms=(Platform.LINUX, Platform.WINDOWS, Platform.MACOS),
        severity=Severity.LOW,
        description="Safe demonstration technique that uses only echo commands.",
        steps=[
            ProcedureStep(
                id="s1",
                description="Print context variables safely.",
                executor=Executor.BASH,
                command_template='echo "User=${user} Host=${host} Env=${env}"',
                requires_admin=False,
                opsec_safe=True,
            ),
            ProcedureStep(
                id="s2",
                description="No-op on Windows CMD (echo).",
                executor=Executor.CMD,
                command_template='echo %USERNAME% %COMPUTERNAME%',
                requires_admin=False,
                opsec_safe=True,
            ),
        ],
        detection=Detection(
            sources=("process_creation",),
            hints=("This is a harmless echo demonstration.",),
            artifacts=(Artifact(type="log", location="N/A", description="No real artifact."),),
        ),
        references=(Reference(title="Project README", url="https://example.invalid/readme"),),
        tags=("demo", "safe"),
    )
    t.validate()
    return t


# ---------------------------------------------------------------------------
# Простейший CLI-хук (не исполняет команды, только демонстрация)
# ---------------------------------------------------------------------------

def _demo_cli(argv: Sequence[str]) -> int:  # pragma: no cover
    """
    Пример: python techniques.py --demo
    Выводит безопасный план с отрендеренными «echo»-командами.
    """
    if "--demo" not in argv:
        print("Usage: python techniques.py --demo", file=sys.stderr)
        return 2
    reg = TechniqueRegistry()
    reg.add(example_technique(), overwrite=True)
    plan = build_plan_from_registry(
        reg,
        variables={"user": "alice", "host": "workstation", "env": "lab"},
        title="Demo Plan (Dry Only)",
    )
    print(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2))
    print()
    print(plan.to_markdown())
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        sys.exit(_demo_cli(sys.argv[1:]))
    except ExecutionDisabledError as e:
        logger.error("Execution attempt blocked: %s", e)
        sys.exit(1)
