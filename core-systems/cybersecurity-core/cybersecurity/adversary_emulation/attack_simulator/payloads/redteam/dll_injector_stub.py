# -*- coding: utf-8 -*-
"""
Safe DLL Injection Emulation Stub (NON-FUNCTIONAL)
Path:
  cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/payloads/redteam/dll_injector_stub.pyy

Описание:
  Промышленный безопасный заглушечный модуль для эмуляции «жизненного цикла»
  техники внедрения в процесс (ATT&CK T1055) БЕЗ фактической инжекции DLL
  и БЕЗ системных вызовов. Модуль:
    - Требует явный допуск лаборатории через переменную окружения
      ADVERSARY_EMULATION_ALLOWED=1
    - Требует наличия файла правил проведения теста (Rules of Engagement, ROE)
    - Валидирует наличие «артефакта DLL» как файла (для трассировки и аудита)
    - Пишет неизменяемый NDJSON-аудит и структурированные JSON-логи
    - Только симулирует этапы, НИКАКИХ операций с памятью/процессами не выполняет

Правовой и методический контекст:
  - MITRE ATT&CK T1055 описывает процессное внедрение как вектор противника.
  - NIST SP 800-115 и определение ROE требуют утвержденного объема работ
    и явных разрешений перед любыми испытаниями.

ВНИМАНИЕ:
  Это не эксплойт и не средство инжекции. Любые попытки превратить данный
  модуль в рабочий инжектор противоречат назначению и политике безопасности.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


# ----------------------------- JSON logging --------------------------------- #

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts_ms": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Поддержка дополнительных полей через LoggerAdapter
        for extra_key in ("run_id", "event", "context"):
            val = getattr(record, extra_key, None)
            if val is not None:
                payload[extra_key] = val
        return json.dumps(payload, ensure_ascii=False)


def _build_logger(name: str, run_id: str) -> logging.LoggerAdapter:
    base = logging.getLogger(name)
    base.setLevel(logging.INFO)
    if not base.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        base.addHandler(handler)
    return logging.LoggerAdapter(base, {"run_id": run_id})


# ------------------------------ Data model ---------------------------------- #

@dataclass(slots=True)
class InjectorConfig:
    """
    Конфигурация «payload» для симуляции DLL-инжектора.

    ВНИМАНИЕ: Поле dll_path используется ТОЛЬКО для учета артефакта и хеширования.
    Никакие загрузки/исполнения не производятся.
    """
    target_pid: Optional[int] = None
    target_name: Optional[str] = None
    dll_path: Path = Path("-")
    audit_dir: Path = Path("./audit")
    safety_roe_path: Optional[Path] = None
    simulate_latency_ms: int = 350
    strict: bool = True

    def validate(self) -> None:
        if self.target_pid is None and not self.target_name:
            raise ValueError("Either --target-pid or --target-name must be provided")
        if self.dll_path in (None, Path("-")):
            raise ValueError("--dll must be provided")
        if not self.dll_path.exists() or not self.dll_path.is_file():
            raise FileNotFoundError(f"DLL artifact not found: {self.dll_path}")
        if self.safety_roe_path is not None and not self.safety_roe_path.exists():
            raise FileNotFoundError(f"ROE file not found: {self.safety_roe_path}")
        self.audit_dir.mkdir(parents=True, exist_ok=True)


@dataclass(slots=True)
class SafetyPolicy:
    """
    Политики безопасности выполнения в лабораторной среде.
    """
    env_flag: str = "ADVERSARY_EMULATION_ALLOWED"
    require_roe: bool = True

    def enforce(self, cfg: InjectorConfig) -> None:
        if os.environ.get(self.env_flag) != "1":
            raise PermissionError(
                f"Safety gate: set {self.env_flag}=1 to confirm isolated lab execution"
            )
        if self.require_roe and (not cfg.safety_roe_path or not cfg.safety_roe_path.exists()):
            raise PermissionError(
                "Safety gate: Rules-of-Engagement artifact is required (use --roe PATH)"
            )


@dataclass(slots=True)
class AuditTrail:
    """
    Неизменяемый NDJSON-аудит.
    """
    run_id: str
    path: Path

    def write(self, event: str, **context: Any) -> None:
        rec = {
            "run_id": self.run_id,
            "ts": time.time(),
            "event": event,
            "context": context or {},
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    @staticmethod
    def make_path(directory: Path, run_id: str) -> Path:
        return directory / f"dll_injector_stub_{run_id}.ndjson"


# --------------------------- Utility functions ------------------------------ #

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(131072), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------ Stub logic ---------------------------------- #

class DllInjectorStub:
    """
    Эмулятор жизненного цикла «DLL-инжекции» БЕЗ выполнения инжекции.
    Все шаги — логические, исключительно для тренажера/аудита.
    """

    def __init__(self, cfg: InjectorConfig, safety: SafetyPolicy) -> None:
        self.cfg = cfg
        self.safety = safety
        self.run_id = uuid.uuid4().hex
        self.logger = _build_logger("dll_injector_stub", self.run_id)
        self.audit = AuditTrail(self.run_id, AuditTrail.make_path(cfg.audit_dir, self.run_id))

    def _log_step(self, step: str, **context: Any) -> None:
        self.logger.info(step, extra={"event": step, "context": context})
        self.audit.write(step, **context)

    def execute(self) -> None:
        # Валидация и допуски
        self.cfg.validate()
        self.safety.enforce(self.cfg)

        dll_hash = _sha256_file(self.cfg.dll_path)

        # Симулированные этапы (никаких системных вызовов)
        self._log_step(
            "start",
            target_pid=self.cfg.target_pid,
            target_name=self.cfg.target_name,
            dll=str(self.cfg.dll_path),
            dll_sha256=dll_hash,
        )

        time.sleep(self.cfg.simulate_latency_ms / 1000.0)
        self._log_step("resolve_target_identity", mode="simulate_only")

        time.sleep(0.05)
        self._log_step("verify_artifact", dll_exists=self.cfg.dll_path.exists(), dll_sha256=dll_hash)

        time.sleep(0.05)
        self._log_step("stage_artifact", rationale="simulation_no_io_side_effects")

        time.sleep(0.05)
        self._log_step("simulate_memory_mapping", details="no_syscalls_no_handles")

        time.sleep(0.05)
        self._log_step("simulate_transfer", transport="logical_model_only")

        time.sleep(0.05)
        self._log_step("simulate_exec_context", thread="virtualized_context", mode="dry_run")

        time.sleep(0.05)
        self._log_step("complete")

        self._log_step("end")

    # Любые реальные операции запрещены намеренно
    def _forbidden(self, *_: Any, **__: Any) -> None:
        raise RuntimeError("Real-mode operations are disabled in this stub")


# --------------------------------- CLI -------------------------------------- #

def _parse_args(argv: list[str]) -> InjectorConfig:
    p = argparse.ArgumentParser(
        prog="dll_injector_stub",
        description="Safe, NON-FUNCTIONAL DLL injection emulation (simulation only).",
    )
    p.add_argument("--target-pid", type=int, help="Target PID (simulation metadata)")
    p.add_argument("--target-name", type=str, help="Target process name (simulation metadata)")
    p.add_argument("--dll", type=Path, required=True, help="Path to DLL artifact (for hashing/audit only)")
    p.add_argument("--roe", type=Path, required=True, help="Path to Rules-of-Engagement artifact")
    p.add_argument("--audit-dir", type=Path, default=Path("./audit"))
    p.add_argument("--latency-ms", type=int, default=350, help="Base artificial latency in milliseconds")
    args = p.parse_args(argv)
    return InjectorConfig(
        target_pid=args.target_pid,
        target_name=args.target_name,
        dll_path=args.dll,
        audit_dir=args.audit_dir,
        safety_roe_path=args.roe,
        simulate_latency_ms=args.latency_ms,
    )


def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cfg = _parse_args(argv)
    stub = DllInjectorStub(cfg, SafetyPolicy())
    try:
        stub.execute()
        return 0
    except Exception as e:
        logger = _build_logger("dll_injector_stub", getattr(stub, "run_id", "unknown"))
        logger.error("error", extra={"event": "error", "context": {"type": type(e).__name__, "msg": str(e)}})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
