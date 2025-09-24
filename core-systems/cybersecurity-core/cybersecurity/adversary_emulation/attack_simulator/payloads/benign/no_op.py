# SPDX-License-Identifier: MIT
"""
cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/payloads/benign/no_op.py

Benign payload: "no-op" — преднамеренно ничего не делает, кроме:
- валидации параметров
- опциональной паузы в допустимых пределах (для прогонов/замеров)
- аккуратного логирования/метрик в JSON
- корректной обработки сигналов SIGINT/SIGTERM
- детерминированного результата с измерением времени и хэшем файла

Назначение:
  Используется как безопасная заглушка в пайплайнах эмуляции противника,
  тестах, dry-run и профилировании без каких-либо действий над системой.

Зависимости: только стандартная библиотека.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

__all__ = ["NoOpConfig", "ExecResult", "execute_no_op", "main"]

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

ISO = "%Y-%m-%dT%H:%M:%S.%f%z"

# Безопасный верхний предел задержки (мс). Может быть ужесточён через ENV.
DEFAULT_MAX_SLEEP_MS = 60_000  # 60s
ENV_MAX_SLEEP_MS = "NOOP_MAX_SLEEP_MS"  # переопределение лимита через окружение
ENV_LOG_JSON = "NOOP_LOG_JSON"          # если "1" — включить JSON-логгер для CLI

# Минимальный heartbeat при ожидании (мс), чтобы оставаться «живым» в длинных прогонах.
HEARTBEAT_MS = 1_000


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(ts: dt.datetime) -> str:
    return ts.strftime(ISO)


def _read_max_sleep_ms() -> int:
    # ENV выигрывает, но только если это целое и >=0
    raw = os.getenv(ENV_MAX_SLEEP_MS)
    if not raw:
        return DEFAULT_MAX_SLEEP_MS
    try:
        val = int(raw)
    except ValueError:
        return DEFAULT_MAX_SLEEP_MS
    return max(0, val)


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class NoOpConfig:
    """
    Конфигурация «no-op» пэйлоада.

    duration_ms: желаемая задержка перед завершением (мс).
    label: произвольная метка запуска (для корреляции).
    trace_id: внешний/внутренний идентификатор трассы; если не задан — сгенерируется UUID4.
    """
    duration_ms: int = 0
    label: str = "no-op"
    trace_id: Optional[str] = None

    @staticmethod
    def validate_duration(value: int) -> int:
        max_ms = _read_max_sleep_ms()
        if value < 0:
            raise ValueError("duration_ms must be >= 0")
        if value > max_ms:
            raise ValueError(f"duration_ms exceeds limit ({value} > {max_ms}); "
                             f"override via {ENV_MAX_SLEEP_MS} if intended and safe.")
        return value

    def normalized(self) -> "NoOpConfig":
        duration = self.validate_duration(int(self.duration_ms))
        trace = self.trace_id or str(uuid.uuid4())
        return NoOpConfig(duration_ms=duration, label=self.label, trace_id=trace)


@dataclass(frozen=True)
class ExecResult:
    """
    Итог выполнения benign no-op.
    """
    success: bool
    started_at: str
    finished_at: str
    duration_ms: int
    message: str = "no-op completed"
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    label: str = "no-op"
    warnings: list[str] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False, separators=(",", ":"))


class _CancelFlag:
    __slots__ = ("_cancelled",)

    def __init__(self) -> None:
        self._cancelled = False

    def set(self) -> None:
        self._cancelled = True

    def is_set(self) -> bool:
        return self._cancelled


def execute_no_op(config: NoOpConfig) -> ExecResult:
    """
    Выполняет benign no-op согласно конфигурации.
    Возвращает структурированный ExecResult и логирует JSON-события.

    Безопасность:
      - Никаких операций с сетью/ФС/процессами.
      - Только ожидание с heartbeat и измерением времени.

    Исключения не «глотаются»: наружу возвращается ExecResult с error.
    """
    cfg = config.normalized()
    started = _now_utc()
    started_ns = time.perf_counter_ns()
    cancel = _CancelFlag()

    # Установка обработчиков сигналов только для текущего контекста CLI.
    def _handler(signum, _frame):
        LOGGER.info(
            _j({"event": "signal_received", "signal": signum, "trace_id": cfg.trace_id, "label": cfg.label})
        )
        cancel.set()

    prev_int = signal.getsignal(signal.SIGINT)
    prev_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    warnings: list[str] = []
    error: Optional[str] = None

    LOGGER.info(_j({
        "event": "start",
        "trace_id": cfg.trace_id,
        "label": cfg.label,
        "requested_duration_ms": cfg.duration_ms,
        "max_sleep_ms": _read_max_sleep_ms(),
        "script_sha256": _safe_self_hash()
    }))

    try:
        # Безопасное «ожидание» кусками, чтобы реагировать на сигналы.
        remaining = cfg.duration_ms
        last_hb = 0
        while remaining > 0 and not cancel.is_set():
            step = min(remaining, HEARTBEAT_MS)
            time.sleep(step / 1000.0)
            remaining -= step
            last_hb += step
            if last_hb >= HEARTBEAT_MS:
                last_hb = 0
                LOGGER.info(_j({
                    "event": "heartbeat",
                    "trace_id": cfg.trace_id,
                    "label": cfg.label,
                    "remaining_ms": remaining
                }))

        if cancel.is_set():
            warnings.append("Execution interrupted by signal.")
    except Exception as ex:  # noqa: BLE001
        error = f"{type(ex).__name__}: {ex}"
        LOGGER.error(_j({
            "event": "exception",
            "trace_id": cfg.trace_id,
            "label": cfg.label,
            "error": error
        }))
    finally:
        # Восстановить предыдущие обработчики сигналов
        try:
            signal.signal(signal.SIGINT, prev_int)
            signal.signal(signal.SIGTERM, prev_term)
        except Exception:
            # Ничего критичного: только попытка «почиститься».
            pass

    finished = _now_utc()
    elapsed_ms = max(0, int((time.perf_counter_ns() - started_ns) / 1_000_000))

    success = error is None
    result = ExecResult(
        success=success,
        started_at=_iso(started),
        finished_at=_iso(finished),
        duration_ms=elapsed_ms,
        message="no-op interrupted" if cancel.is_set() else "no-op completed",
        trace_id=cfg.trace_id or "",
        label=cfg.label,
        warnings=warnings,
        error=error,
        metadata={
            "requested_duration_ms": cfg.duration_ms,
            "script_sha256": _safe_self_hash(),
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
        },
    )

    LOGGER.info(_j({
        "event": "finish",
        "trace_id": cfg.trace_id,
        "label": cfg.label,
        "success": result.success,
        "elapsed_ms": result.duration_ms
    }))
    return result


def _safe_self_hash() -> str:
    """
    Пытается получить sha256 текущего файла, если доступен.
    При невозможности (напр., упаковано в zipapp) — возвращает "n/a".
    """
    try:
        return _file_sha256(__file__)
    except Exception:
        return "n/a"


def _setup_cli_logging(json_logs: bool) -> None:
    # Не переопределяем формат, если logging уже настроен извне
    if LOGGER.handlers and not isinstance(LOGGER.handlers[0], logging.NullHandler):
        return

    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        formatter = logging.Formatter("%(message)s")
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s :: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S%z",
        )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Удалим NullHandler из локального логгера
    for h in list(LOGGER.handlers):
        if isinstance(h, logging.NullHandler):
            LOGGER.removeHandler(h)
    root.addHandler(handler)


def _j(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benign no-op payload for adversary emulation dry-runs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=True,
    )
    parser.add_argument("--duration-ms", type=int, default=0,
                        help="Задержка перед завершением, миллисекунды (неотрицательно).")
    parser.add_argument("--label", type=str, default="no-op",
                        help="Произвольная метка запуска для корреляции логов.")
    parser.add_argument("--trace-id", type=str, default=None,
                        help="Идентификатор трассы; если не задан — будет сгенерирован UUID4.")
    parser.add_argument("--json-logs", action="store_true",
                        help=f"Логировать события в чистом JSON. Также можно через ENV {ENV_LOG_JSON}=1.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    ns = _parse_args(argv or sys.argv[1:])
    json_logs = ns.json_logs or os.getenv(ENV_LOG_JSON) == "1"
    _setup_cli_logging(json_logs=json_logs)

    try:
        cfg = NoOpConfig(
            duration_ms=ns.duration_ms,
            label=ns.label,
            trace_id=ns.trace_id,
        )
        result = execute_no_op(cfg)
        # Итог всегда печатаем в stdout как JSON (для пайплайнов/парсеров)
        print(result.to_json())
        return 0 if result.success else 1
    except Exception as ex:  # noqa: BLE001
        # Фатальная ошибка конфигурации/выполнения: сообщаем и возвращаем 2
        err = _j({"event": "fatal", "error": f"{type(ex).__name__}: {ex}"})
        # Пишем в stderr, чтобы не смешивать с чистым JSON результатом
        sys.stderr.write(err + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
