# cybersecurity-core/cybersecurity/adversary_emulation/scenarios/library/scenario_base.py
# -*- coding: utf-8 -*-
"""
Базовый промышленный каркас сценария имитации противника (Adversary Emulation).

Методологические опоры (проверяемые источники):
- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
  https://csrc.nist.gov/publications/detail/sp/800-115/final
- MITRE ATT&CK (тактики/техники):
  https://attack.mitre.org/
- MITRE Engenuity CTID — Adversary Emulation Library (структуры и примеры сценариев):
  https://github.com/center-for-threat-informed-defense/adversary_emulation_library

Ключевые свойства:
- Явная модель шага (ATT&CK mapping), флаги деструктивности, уровень привилегий.
- Dry-run по умолчанию, запрет на prod (если не разрешено), «guardrails» для опасных действий.
- DAG-планировщик с проверкой циклов, асинхронное выполнение, ограничение параллелизма.
- Тайм-ауты, ретраи с экспоненциальной задержкой, ограничение частоты.
- Структурированное JSON-логирование и JSONL-аудит.
- Подпись сценария SHA-256 для контроля целостности.
- Расширяемый RBAC-хук и pre/post hooks.

Автор: Aethernova / cybersecurity-core
Лицензия: Apache-2.0 (при необходимости заменить под политику репозитория)
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import functools
import hashlib
import json
import logging
import os
import platform
import secrets
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

try:
    # Опциональная телеметрия. Если нет — gracefully degrade.
    from opentelemetry import trace  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore

__all__ = [
    "ScenarioError",
    "ScenarioSafetyError",
    "ScenarioValidationError",
    "ScenarioRBACError",
    "PrivilegeLevel",
    "StepStatus",
    "ScenarioStep",
    "ScenarioMetadata",
    "ScenarioConfig",
    "StepResult",
    "ScenarioResult",
    "RateLimiter",
    "ScenarioBase",
]

__version__ = "1.0.0"


# ----------------------------- Исключения ------------------------------------
class ScenarioError(Exception):
    """Базовая ошибка сценария."""


class ScenarioSafetyError(ScenarioError):
    """Нарушение ограничений безопасности (prod, destructive и т.д.)."""


class ScenarioValidationError(ScenarioError):
    """Неверная конфигурация/валидация сценария или шагов."""


class ScenarioRBACError(ScenarioError):
    """Недостаточно прав для исполнения сценария/шага."""


# ------------------------------ Перечисления ---------------------------------
class PrivilegeLevel(enum.IntEnum):
    """Уровень привилегий, требуемый шагом."""
    USER = 1
    ELEVATED = 2
    ADMIN = 3
    SYSTEM = 4


class StepStatus(enum.Enum):
    PENDING = "PENDING"
    SKIPPED = "SKIPPED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


# ------------------------------ Модели данных --------------------------------
@dataclass(frozen=True)
class ScenarioMetadata:
    """
    Метаданные сценария (для репортинга, сопоставления с ATT&CK и источниками).
    Включайте ссылки на ATT&CK и NIST SP 800-115 внутри `references`.
    """
    id: str
    name: str
    description: str
    version: str = "1.0"
    attacker_profile: Optional[str] = None
    target_profile: Optional[str] = None
    # Например: ["TA0001", "TA0002"] — ATT&CK Tactics
    tactics: Tuple[str, ...] = ()
    # Ссылки на методологию/плейбуки (ATT&CK / NIST / CTID AE Library)
    references: Tuple[str, ...] = ()


@dataclass
class ScenarioConfig:
    """
    Конфигурация исполнения сценария. Безопасные значения по умолчанию.
    """
    name: str
    scenario_id: str = field(default_factory=lambda: f"scn-{uuid.uuid4()}")
    dry_run: bool = True
    allow_prod: bool = False
    allow_destructive: bool = False
    environment: Optional[str] = None  # auto-detect если None
    max_concurrency: int = 2
    default_timeout_s: float = 600.0
    retry_attempts: int = 1
    retry_backoff_base_s: float = 1.5
    rate_limit_per_min: Optional[int] = None  # None = без ограничения
    audit_dir: Path = field(default_factory=lambda: Path("./audit"))
    audit_file_prefix: str = "adversary_emulation"
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def resolved_environment(self) -> str:
        if self.environment:
            return self.environment
        # Автовывод из переменных окружения/файла настроек
        return os.getenv("AE_ENV") or os.getenv("APP_ENV") or "lab"

    @property
    def is_prod(self) -> bool:
        env = self.resolved_environment().lower()
        return env in {"prod", "production", "live"}


@dataclass(frozen=True)
class ScenarioStep:
    """
    Описание шага TTP:
    - technique: ATT&CK Technique ID (например, "T1059")
      Источник: https://attack.mitre.org/techniques/
    - tactic: ATT&CK Tactic ID (например, "TA0002")
      Источник: https://attack.mitre.org/tactics/
    """
    id: str
    name: str
    description: str
    tactic: Optional[str] = None
    technique: Optional[str] = None
    privilege: PrivilegeLevel = PrivilegeLevel.USER
    timeout_s: Optional[float] = None
    depends_on: Tuple[str, ...] = ()
    # Параметры конкретного исполнителя (например, командная строка/аргументы).
    params: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    destructive: bool = False
    idempotent: bool = True
    enabled: bool = True


@dataclass
class StepResult:
    step_id: str
    status: StepStatus
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    duration_s: Optional[float] = None
    attempt: int = 0
    output: Optional[str] = None
    error: Optional[str] = None
    traceback: Optional[str] = None
    telemetry: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScenarioResult:
    scenario_id: str
    scenario_name: str
    started_at: str
    ended_at: Optional[str] = None
    duration_s: Optional[float] = None
    status: StepStatus = StepStatus.PENDING
    signature_sha256: str = ""
    environment: str = "lab"
    dry_run: bool = True
    steps: List[StepResult] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


# ------------------------------ Подсистемы -----------------------------------
class JsonFormatter(logging.Formatter):
    """Минималистичный JSON-форматтер для структурированных логов (ECS-совместимый стиль)."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "@timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "log.level": record.levelname,
            "message": record.getMessage(),
            "logger.name": record.name,
            "process.pid": record.process,
            "thread.name": record.threadName,
            "event.dataset": "adversary_emulation",
        }
        if record.exc_info:
            payload["error.type"] = str(record.exc_info[0].__name__)
            payload["error.message"] = str(record.exc_info[1])
            payload["error.stack_trace"] = self.formatException(record.exc_info)
        # Включаем дополнительные поля через record.__dict__
        for k, v in getattr(record, "__dict__", {}).items():
            if k.startswith("_"):
                continue
            if k in payload:
                continue
            # фильтруем служебное
            if k in ("msg", "args", "name", "levelname", "levelno", "pathname", "filename",
                     "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                     "created", "msecs", "relativeCreated", "thread", "process", "asctime"):
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except Exception:
                payload[k] = repr(v)
        return json.dumps(payload, ensure_ascii=False)


def build_logger(name: str = __name__) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = build_logger(__name__)


class RateLimiter:
    """Простой лимитер в стиле "X событий в минуту"."""

    def __init__(self, rate_per_minute: Optional[int]):
        self._rate = rate_per_minute
        self._tokens = float(rate_per_minute or 0)
        self._last = time.monotonic()

    async def acquire(self) -> None:
        if not self._rate:
            return
        now = time.monotonic()
        # пополнение токенов
        self._tokens += (now - self._last) * (self._rate / 60.0)
        self._last = now
        if self._tokens > self._rate:
            self._tokens = float(self._rate)
        if self._tokens < 1.0:
            # ожидание до накопления одного токена
            needed = 1.0 - self._tokens
            delay = needed * (60.0 / self._rate)
            await asyncio.sleep(delay)
            self._tokens = 0.0
        else:
            self._tokens -= 1.0


# --------------------------- Утилиты и проверка DAG ---------------------------
def _toposort(steps: Sequence[ScenarioStep]) -> List[ScenarioStep]:
    """Проверка DAG и топологическая сортировка."""
    by_id: Dict[str, ScenarioStep] = {s.id: s for s in steps if s.enabled}
    indeg: Dict[str, int] = {sid: 0 for sid in by_id}
    adj: Dict[str, Set[str]] = {sid: set() for sid in by_id}

    for s in by_id.values():
        for dep in s.depends_on:
            if dep not in by_id:
                raise ScenarioValidationError(f"Шаг '{s.id}' зависит от отсутствующего шага '{dep}'")
            adj[dep].add(s.id)
            indeg[s.id] += 1

    queue: List[str] = [sid for sid, d in indeg.items() if d == 0]
    order: List[ScenarioStep] = []

    while queue:
        sid = queue.pop(0)
        order.append(by_id[sid])
        for succ in adj[sid]:
            indeg[succ] -= 1
            if indeg[succ] == 0:
                queue.append(succ)

    if len(order) != len(by_id):
        # цикл обнаружен
        raise ScenarioValidationError("Обнаружен цикл зависимостей шагов сценария")
    return order


def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scenario_signature(meta: ScenarioMetadata, steps: Sequence[ScenarioStep]) -> str:
    # Подпись на структуру сценария: метаданные + шаги (детерминизм)
    obj = {
        "meta": dataclasses.asdict(meta),
        "steps": [dataclasses.asdict(s) for s in steps],
        "version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
    }
    b = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return _sha256_of_bytes(b)


# ------------------------------- Базовый класс --------------------------------
class ScenarioBase:
    """
    Базовый класс сценария имитации противника.

    Наследник обязан:
    - реализовать `metadata` (ScenarioMetadata);
    - реализовать `build_steps()` -> Sequence[ScenarioStep];
    - реализовать `execute_step_async(step, context)` — «что делать» на каждом шаге
      (эмуляция TTP, вызов runner'ов, клиентов SSH/WinRM/API и т.п.).

    Безопасность по умолчанию:
    - dry_run=True (нет исполнения опасных действий);
    - запрет в prod, если `allow_prod=False`;
    - деструктивные шаги блокируются, если `allow_destructive=False`.

    Источники методологии:
    - NIST SP 800-115 (процедуры тестирования/оценки безопасности).
    - MITRE ATT&CK (классификация действий противника).
    - CTID Adversary Emulation Library (структура/идеи сценариев).
    """

    def __init__(self, config: ScenarioConfig):
        self.config = config
        self._rate_limiter = RateLimiter(config.rate_limit_per_min)
        self._tracer = trace.get_tracer(__name__) if trace else None  # type: ignore

    # --------- Требующие переопределения свойства/методы ----------
    @property
    def metadata(self) -> ScenarioMetadata:
        """Метаданные конкретного сценария (обязателен override)."""
        raise NotImplementedError

    def build_steps(self) -> Sequence[ScenarioStep]:
        """Сконструировать шаги сценария (обязателен override)."""
        raise NotImplementedError

    async def execute_step_async(self, step: ScenarioStep, context: MutableMapping[str, Any]) -> str:
        """
        Исполнить шаг и вернуть «выходные данные» (stdout/описание результата).
        ДОЛЖЕН быть переопределён в наследнике.
        """
        raise NotImplementedError

    # ---------------------- Расширяемые хуки -----------------------
    async def pre_checks_async(self, context: MutableMapping[str, Any]) -> None:
        """Проверки перед запуском (сеть, доступы, RBAC и т.п.)."""
        self._enforce_environment_safety()
        await self._rbac_guard_async(context)

    async def post_cleanup_async(self, context: MutableMapping[str, Any]) -> None:
        """Финальная уборка (закрыть соединения, удалить временные файлы и т.п.)."""
        return

    async def on_event_async(self, event: Dict[str, Any]) -> None:
        """Хук для телеметрии/событий (можно переопределить)."""
        return

    async def _rbac_guard_async(self, context: MutableMapping[str, Any]) -> None:
        """
        Расширяемый RBAC-хук. По умолчанию — пропускает.
        Наследник может реализовать проверку токена/ролей и бросить ScenarioRBACError.
        """
        return

    # ---------------------- Публичные методы запуска ----------------
    def run(self, context: Optional[MutableMapping[str, Any]] = None) -> ScenarioResult:
        """Синхронная обёртка над асинхронным исполнением."""
        return asyncio.run(self.run_async(context=context))

    async def run_async(self, context: Optional[MutableMapping[str, Any]] = None) -> ScenarioResult:
        """
        Асинхронный запуск сценария с планированием шагов, безопасностью и аудитом.
        """
        ctx: MutableMapping[str, Any] = context or {}
        steps = [s for s in self.build_steps() if s.enabled]
        ordered = _toposort(steps)

        sig = _scenario_signature(self.metadata, ordered)
        started = datetime.now(timezone.utc).isoformat()

        result = ScenarioResult(
            scenario_id=self.config.scenario_id,
            scenario_name=self.config.name,
            started_at=started,
            signature_sha256=sig,
            environment=self.config.resolved_environment(),
            dry_run=self.config.dry_run,
            meta={"metadata": dataclasses.asdict(self.metadata), "tags": sorted(self.config.tags)},
        )

        self._prepare_audit_dir()
        await self.pre_checks_async(ctx)

        try:
            await self._execute_all_async(ordered, result, ctx)
            result.status = StepStatus.SUCCESS if all(s.status == StepStatus.SUCCESS or s.status == StepStatus.SKIPPED
                                                      for s in result.steps) else StepStatus.FAILED
        except asyncio.CancelledError:
            result.status = StepStatus.CANCELLED
            raise
        except Exception as ex:
            result.status = StepStatus.FAILED
            LOGGER.error("scenario_failed", exc_info=True, scenario_id=self.config.scenario_id, error=str(ex))
        finally:
            await self.post_cleanup_async(ctx)
            result.ended_at = datetime.now(timezone.utc).isoformat()
            result.duration_s = _duration_s(result.started_at, result.ended_at)
            self._write_audit_record({"type": "scenario_summary", "result": dataclasses.asdict(result)})

        return result

    # ------------------------ Внутренняя логика ---------------------
    async def _execute_all_async(
        self,
        steps: Sequence[ScenarioStep],
        result: ScenarioResult,
        context: MutableMapping[str, Any],
    ) -> None:
        deps = {s.id: set(s.depends_on) for s in steps}
        dependents: Dict[str, Set[str]] = {s.id: set() for s in steps}
        for s in steps:
            for d in s.depends_on:
                dependents.setdefault(d, set()).add(s.id)

        ready: Set[str] = {s.id for s in steps if not deps[s.id]}
        by_id: Dict[str, ScenarioStep] = {s.id: s for s in steps}
        in_progress: Set[str] = set()
        done: Set[str] = set()
        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # Карта результатов по шагам
        results_map: Dict[str, StepResult] = {}

        async def run_one(step_id: str) -> None:
            step = by_id[step_id]
            async with semaphore:
                in_progress.add(step_id)
                try:
                    sr = await self._execute_step_with_retries_async(step, context)
                    results_map[step_id] = sr
                finally:
                    in_progress.remove(step_id)
                    done.add(step_id)
                    # освобождаем зависящие шаги
                    for child in dependents.get(step_id, ()):
                        deps[child].discard(step_id)
                        if not deps[child] and child not in done and child not in in_progress:
                            ready.add(child)

        tasks: Dict[str, asyncio.Task[None]] = {}
        while len(done) < len(steps):
            # Запускаем доступные шаги
            while ready and len(in_progress) < self.config.max_concurrency:
                sid = ready.pop()
                tasks[sid] = asyncio.create_task(run_one(sid))

            if not tasks:
                # Должно быть невозможно (так как DAG уже проверен).
                raise ScenarioValidationError("Планировщик оказался без доступных задач — проверьте DAG.")

            # Ждём завершения любой задачи
            _done, _pending = await asyncio.wait(tasks.values(), return_when=asyncio.FIRST_COMPLETED)
            # Удаляем завершённые
            for t in list(tasks.keys()):
                if tasks[t].done():
                    del tasks[t]

        # Собираем результаты в порядке исходного списка
        result.steps = [results_map[s.id] for s in steps]

    async def _execute_step_with_retries_async(
        self,
        step: ScenarioStep,
        context: MutableMapping[str, Any],
    ) -> StepResult:
        await self._rate_limiter.acquire()

        sr = StepResult(step_id=step.id, status=StepStatus.PENDING)
        attempts = max(1, self.config.retry_attempts)
        timeout = step.timeout_s or self.config.default_timeout_s

        if self.config.dry_run:
            # В dry-run не исполняем, но помечаем как SKIPPED и логируем.
            sr.status = StepStatus.SKIPPED
            sr.output = "dry_run=True: шаг не исполнялся"
            self._log_event("step_skipped_dry_run", step, sr)
            self._write_audit_record({"type": "step", "event": "skipped_dry_run", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})
            return sr

        # Guardrails: prod / destructive
        self._enforce_step_safety(step)

        backoff = self.config.retry_backoff_base_s
        for attempt in range(1, attempts + 1):
            sr.attempt = attempt
            sr.started_at = datetime.now(timezone.utc).isoformat()
            sr.status = StepStatus.RUNNING
            self._log_event("step_started", step, sr)
            self._write_audit_record({"type": "step", "event": "started", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})

            try:
                if self._tracer:
                    with self._tracer.start_as_current_span(f"step:{step.id}"):  # type: ignore
                        out = await asyncio.wait_for(self.execute_step_async(step, context), timeout=timeout)
                else:
                    out = await asyncio.wait_for(self.execute_step_async(step, context), timeout=timeout)

                sr.output = _truncate_str(out, 32_768)
                sr.status = StepStatus.SUCCESS
                sr.ended_at = datetime.now(timezone.utc).isoformat()
                sr.duration_s = _duration_s(sr.started_at, sr.ended_at)
                self._log_event("step_succeeded", step, sr)
                self._write_audit_record({"type": "step", "event": "succeeded", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})
                return sr

            except asyncio.TimeoutError:
                sr.status = StepStatus.TIMEOUT
                sr.error = f"Шаг превысил тайм-аут {timeout}s"
                sr.traceback = None
                sr.ended_at = datetime.now(timezone.utc).isoformat()
                sr.duration_s = _duration_s(sr.started_at, sr.ended_at)
                self._log_event("step_timeout", step, sr)
                self._write_audit_record({"type": "step", "event": "timeout", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})
            except ScenarioSafetyError:
                # Без повторов: это нарушение политики, а не сбой среды
                sr.status = StepStatus.FAILED
                sr.error = "Нарушение ограничений безопасности (prod/destructive)"
                sr.traceback = traceback.format_exc()
                sr.ended_at = datetime.now(timezone.utc).isoformat()
                sr.duration_s = _duration_s(sr.started_at, sr.ended_at)
                self._log_event("step_safety_violation", step, sr)
                self._write_audit_record({"type": "step", "event": "safety_violation", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})
                return sr
            except ScenarioRBACError:
                sr.status = StepStatus.FAILED
                sr.error = "RBAC: недостаточно прав"
                sr.traceback = traceback.format_exc()
                sr.ended_at = datetime.now(timezone.utc).isoformat()
                sr.duration_s = _duration_s(sr.started_at, sr.ended_at)
                self._log_event("step_rbac_denied", step, sr)
                self._write_audit_record({"type": "step", "event": "rbac_denied", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})
                return sr
            except Exception:
                sr.status = StepStatus.FAILED
                sr.error = str(sys.exc_info()[1])
                sr.traceback = traceback.format_exc()
                sr.ended_at = datetime.now(timezone.utc).isoformat()
                sr.duration_s = _duration_s(sr.started_at, sr.ended_at)
                self._log_event("step_failed", step, sr)
                self._write_audit_record({"type": "step", "event": "failed", "step": dataclasses.asdict(step), "result": dataclasses.asdict(sr)})

            # retry logic (если ещё остались попытки)
            if attempt < attempts:
                await asyncio.sleep(backoff)
                backoff *= self.config.retry_backoff_base_s

        # Все попытки исчерпаны
        return sr

    # -------------------------- Безопасность/аудит ----------------------------
    def _enforce_environment_safety(self) -> None:
        """Глобальные ограничения окружения (prod и т.д.)."""
        if self.config.is_prod and not self.config.allow_prod:
            raise ScenarioSafetyError("Запуск сценария в prod запрещен (allow_prod=False). См. NIST SP 800-115.")

    def _enforce_step_safety(self, step: ScenarioStep) -> None:
        """Проверка деструктивности и прочих ограничений на шаг."""
        if step.destructive and not self.config.allow_destructive:
            raise ScenarioSafetyError(f"Шаг '{step.id}' помечен как деструктивный, но allow_destructive=False.")

    def _prepare_audit_dir(self) -> None:
        self.config.audit_dir.mkdir(parents=True, exist_ok=True)

    def _audit_file_path(self) -> Path:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        fname = f"{self.config.audit_file_prefix}_{self.config.scenario_id}_{date_str}.jsonl"
        return self.config.audit_dir / fname

    def _write_audit_record(self, record: Mapping[str, Any]) -> None:
        rec = dict(record)
        rec["ts"] = datetime.now(timezone.utc).isoformat()
        rec["scenario_id"] = self.config.scenario_id
        with self._audit_file_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _log_event(self, event: str, step: Optional[ScenarioStep], sr: Optional[StepResult]) -> None:
        extra = {
            "event.action": event,
            "scenario.id": self.config.scenario_id,
            "scenario.name": self.config.name,
        }
        if step:
            extra.update({
                "step.id": step.id,
                "step.name": step.name,
                "step.tactic": step.tactic,
                "step.technique": step.technique,
                "step.destructive": step.destructive,
                "step.privilege": int(step.privilege),
            })
        if sr:
            extra.update({
                "step.status": sr.status.value,
                "step.attempt": sr.attempt,
                "step.duration_s": sr.duration_s,
                "step.error": sr.error,
            })
        LOGGER.info("adversary_event", extra=extra)


# ------------------------------ Вспомогательные -------------------------------
def _truncate_str(s: Optional[str], limit: int) -> Optional[str]:
    if s is None:
        return None
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


def _duration_s(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[float]:
    if not start_iso or not end_iso:
        return None
    try:
        start = datetime.fromisoformat(start_iso)
        end = datetime.fromisoformat(end_iso)
        return max(0.0, (end - start).total_seconds())
    except Exception:
        return None
