# cybersecurity_core/cybersecurity/adversary_emulation/scenarios/library/scenario_ransomware.py
# -*- coding: utf-8 -*-
"""
Безопасный промышленный сценарий эмуляции «ransomware» без разрушений.

Назначение:
- Смоделировать телеметрию и артефакты для MITRE ATT&CK:
  - T1486 "Data Encrypted for Impact" (эмуляция через псевдошифрование в изолированной папке)
  - T1490 "Inhibit System Recovery" (эмуляция маркерными файлами и событиями)
- Создавать NDJSON-логи, канареечные файлы и по флагу — ZIP-пакет «evidence».
- Исключительно безопасно: без удаления/изменения системных настроек и пользовательских данных.

Справочные материалы (для операторов сценария):
- MITRE ATT&CK T1486 — Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1490 — Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- Общее описание ATT&CK: https://attack.mitre.org/
- NIST SP 800-115 (методология безопасных оценок): https://csrc.nist.gov/pubs/sp/800/115/final
- NIST SP 800-53 CA-8 (pen-testing как контроль): https://csf.tools/reference/nist-sp-800-53/r5/ca/ca-8/

ВНИМАНИЕ:
- Сценарий выполняет ТОЛЬКО безвредные операции в своей рабочей директории.
- Любые «опасные» действия здесь заменены на безопасные аналоги (создание файлов-маркеров и логов).
- Используйте в тестовой среде.

Автор: Aethernova / Cybersecurity Core
Лицензия: Apache-2.0
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import platform
import random
import shutil
import socket
import string
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

# --------- Константы техники MITRE ATT&CK (только справочные строки) ----------
T1486 = {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
T1490 = {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"}

# --------- ИСКЛЮЧИТЕЛЬНО БЕЗОПАСНЫЙ СЦЕНАРИЙ ---------------------------------
# Никаких системных действий, никаких внешних сетевых вызовов.
# Все операции ограничены рабочей директорией.

def _now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def _rand_name(prefix: str, length: int = 6, ext: Optional[str] = None) -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    if ext:
        return f"{prefix}_{token}.{ext.lstrip('.')}"
    return f"{prefix}_{token}"

def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def _host_facts() -> Dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "python": sys.version.split()[0],
        "pid": os.getpid(),
    }

class ScenarioError(Exception):
    pass

@dataclass
class ScenarioConfig:
    safe_mode: bool = True
    file_count: int = 12
    file_size_kb: int = 16
    step_timeout_sec: int = 15
    seed: Optional[int] = None
    create_zip: bool = True

    # директории
    base_dir: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "advemu_ransomware")
    work_dir: Optional[Path] = None
    artifacts_dir: Optional[Path] = None
    telemetry_path: Optional[Path] = None

    def finalize(self) -> None:
        if self.seed is not None:
            random.seed(self.seed)
        base = _ensure_dir(self.base_dir)
        self.work_dir = _ensure_dir((self.work_dir or (base / _rand_name("scenario", 8))))
        self.artifacts_dir = _ensure_dir((self.artifacts_dir or (self.work_dir / "artifacts")))
        self.telemetry_path = self.telemetry_path or (self.artifacts_dir / "telemetry.ndjson")

@dataclass
class StepResult:
    step_id: str
    status: str
    message: str
    technique: Dict[str, str]
    artifacts: List[Path] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = field(default_factory=_now_iso)

class TelemetryWriter:
    def __init__(self, path: Path, scenario_id: str) -> None:
        self.path = path
        self.scenario_id = scenario_id
        _ensure_dir(path.parent)

    def write(self, result: StepResult, extra: Optional[Dict[str, Any]] = None) -> None:
        entry: Dict[str, Any] = {
            "ts": _now_iso(),
            "scenario_id": self.scenario_id,
            "step_id": result.step_id,
            "technique": result.technique,
            "status": result.status,
            "message": result.message,
            "artifacts": [
                {
                    "path": str(a),
                    "sha256": _sha256(a) if a.exists() and a.is_file() else None,
                    "size": a.stat().st_size if a.exists() and a.is_file() else None,
                }
                for a in result.artifacts
            ],
            "metrics": result.metrics,
            "host": _host_facts(),
            "started_at": result.started_at,
            "finished_at": result.finished_at,
        }
        if extra:
            entry.update(extra)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

@dataclass
class ScenarioContext:
    cfg: ScenarioConfig
    scenario_id: str
    telemetry: TelemetryWriter
    work_dir: Path
    artifacts_dir: Path

# ------------------------- Реализация шагов -----------------------------------

async def step_generate_canaries(ctx: ScenarioContext) -> StepResult:
    """
    Эмуляция подготовки целей: создание канареечных файлов в рабочей директории.
    Безопасный аналог подготовительного этапа до T1486.
    """
    start = _now_iso()
    created: List[Path] = []
    for i in range(ctx.cfg.file_count):
        name = _rand_name("canary", 6, ext=random.choice(["txt", "log", "cfg", "dat"]))
        p = ctx.work_dir / name
        with p.open("wb") as f:
            f.write(b"# CANARY FILE - SAFE EMULATION\n")
            f.write(os.urandom(ctx.cfg.file_size_kb * 1024))
        created.append(p)
    # запишем список в артефакты
    manifest = ctx.artifacts_dir / "canaries_manifest.txt"
    with manifest.open("w", encoding="utf-8") as mf:
        for p in created:
            mf.write(f"{p.name}\n")
    end = _now_iso()
    return StepResult(
        step_id="generate_canaries",
        status="success",
        message=f"Создано {len(created)} канареечных файлов",
        technique=T1486,  # связываем подготовительный шаг с будущей техникой воздействия
        artifacts=created + [manifest],
        metrics={"count": len(created), "avg_size_kb": ctx.cfg.file_size_kb},
        started_at=start,
        finished_at=end,
    )

async def step_simulate_encryption(ctx: ScenarioContext) -> StepResult:
    """
    Эмуляция T1486: НЕ реальное шифрование, а безопасное «псевдошифрование».
    - Создаём копии канареек с расширением .locked, добавляя заголовок-маркёр.
    - Исходные файлы НЕ трогаем.
    """
    start = _now_iso()
    created_locked: List[Path] = []
    for p in ctx.work_dir.iterdir():
        if p.is_file() and p.name.startswith("canary_"):
            locked = p.with_suffix(p.suffix + ".locked")
            with p.open("rb") as src, locked.open("wb") as dst:
                dst.write(b"SAFE_EMULATION_ONLY\n")  # маркёр симуляции
                shutil.copyfileobj(src, dst)
            created_locked.append(locked)
    note = ctx.work_dir / "README_EMULATION_ONLY.txt"
    with note.open("w", encoding="utf-8") as f:
        f.write(
            "Это безопасная эмуляция техники MITRE ATT&CK T1486 (Data Encrypted for Impact).\n"
            "Файлы *.locked — копии канареечных данных. Никакие реальные данные не затронуты.\n"
        )
    end = _now_iso()
    return StepResult(
        step_id="simulate_encryption",
        status="success",
        message=f"Создано {len(created_locked)} псевдозашифрованных копий (*.locked)",
        technique=T1486,
        artifacts=created_locked + [note],
        metrics={"locked_count": len(created_locked)},
        started_at=start,
        finished_at=end,
    )

async def step_simulate_inhibit_recovery(ctx: ScenarioContext) -> StepResult:
    """
    Эмуляция T1490: вместо вмешательства в системы восстановления
    создаём безопасные маркеры и телеметрию.
    """
    start = _now_iso()
    marker = ctx.work_dir / "SIMULATED_RECOVERY_INHIBIT.marker"
    with marker.open("w", encoding="utf-8") as f:
        f.write(
            "SAFE EMULATION of MITRE ATT&CK T1490 (Inhibit System Recovery). "
            "Никаких системных изменений не производится.\n"
        )
    guide = ctx.artifacts_dir / "t1490_reference.txt"
    with guide.open("w", encoding="utf-8") as f:
        f.write("Справка по технике T1490: Inhibit System Recovery (см. mitre.org)\n")
    end = _now_iso()
    return StepResult(
        step_id="simulate_inhibit_recovery",
        status="success",
        message="Созданы маркеры безопасной эмуляции T1490",
        technique=T1490,
        artifacts=[marker, guide],
        metrics={},
        started_at=start,
        finished_at=end,
    )

async def step_collect_evidence_zip(ctx: ScenarioContext) -> StepResult:
    """
    Сбор «доказательств» (артефактов и логов) в ZIP.
    """
    start = _now_iso()
    zip_path = ctx.artifacts_dir / "evidence_package.zip"
    # собираем только содержимое work_dir + artifacts_dir + telemetry
    to_pack: List[Path] = []
    for root in [ctx.work_dir, ctx.artifacts_dir]:
        for p in root.rglob("*"):
            if p.is_file():
                to_pack.append(p)
    with shutil.make_archive(zip_path.with_suffix("").as_posix(), "zip", ctx.work_dir) as _:
        pass  # pathlib не даёт контекстник; make_archive уже создал архив
    # Добавим артефакты из artifacts_dir:
    with shutil.make_archive((ctx.artifacts_dir / "artifacts_bundle").as_posix(), "zip", ctx.artifacts_dir) as _:
        pass
    end = _now_iso()
    # аккуратно: у make_archive возвращается путь, но мы уже знаем имена
    return StepResult(
        step_id="collect_evidence_zip",
        status="success",
        message="Собран ZIP-пакет доказательств (work_dir.zip и artifacts_bundle.zip)",
        technique={"id": "AUX", "name": "Evidence Packaging", "tactic": "Testing"},
        artifacts=[zip_path, ctx.artifacts_dir / "artifacts_bundle.zip"],
        metrics={"files_packed": len(to_pack)},
        started_at=start,
        finished_at=end,
    )

# -------------------------- Исполнитель сценария ------------------------------

AttackFn = Callable[[ScenarioContext], Awaitable[StepResult]]

@dataclass
class AttackStep:
    step_id: str
    runner: AttackFn
    timeout_sec: int
    enabled: bool = True

class RansomwareScenario:
    """
    Асинхронный исполнитель безопасной эмуляции «ransomware» с телеметрией и артефактами.
    """

    def __init__(self, cfg: ScenarioConfig) -> None:
        self.cfg = cfg
        self.cfg.finalize()
        scenario_id = _rand_name("ransomware_scn", 8)
        self.ctx = ScenarioContext(
            cfg=self.cfg,
            scenario_id=scenario_id,
            telemetry=TelemetryWriter(self.cfg.telemetry_path, scenario_id),
            work_dir=self.cfg.work_dir,  # type: ignore[arg-type]
            artifacts_dir=self.cfg.artifacts_dir,  # type: ignore[arg-type]
        )
        self.steps: List[AttackStep] = [
            AttackStep("generate_canaries", step_generate_canaries, self.cfg.step_timeout_sec),
            AttackStep("simulate_encryption", step_simulate_encryption, self.cfg.step_timeout_sec),
            AttackStep("simulate_inhibit_recovery", step_simulate_inhibit_recovery, self.cfg.step_timeout_sec),
        ]
        if self.cfg.create_zip:
            self.steps.append(AttackStep("collect_evidence_zip", step_collect_evidence_zip, self.cfg.step_timeout_sec))

        # Дополнительные проверки безопасности
        self._validate_environment()

    def _validate_environment(self) -> None:
        # Разрешаем работу только в подкаталогах системной temp-директории.
        tmp_root = Path(tempfile.gettempdir()).resolve()
        if not str(self.ctx.work_dir.resolve()).startswith(str(tmp_root)):
            raise ScenarioError(
                f"Рабочая директория {self.ctx.work_dir} должна быть внутри системной временной папки {tmp_root}."
            )

    async def run(self) -> List[StepResult]:
        results: List[StepResult] = []
        self.ctx.telemetry.write(
            StepResult(
                step_id="scenario_start",
                status="info",
                message="Старт сценария безопасной эмуляции ransomware",
                technique={"id": "INIT", "name": "Scenario Start", "tactic": "Testing"},
            ),
            extra={"config": self.cfg.__dict__},
        )
        for s in self.steps:
            if not s.enabled:
                continue
            try:
                res: StepResult = await asyncio.wait_for(s.runner(self.ctx), timeout=s.timeout_sec)
                results.append(res)
                self.ctx.telemetry.write(res)
            except asyncio.TimeoutError:
                res = StepResult(
                    step_id=s.step_id,
                    status="timeout",
                    message=f"Шаг превысил таймаут {s.timeout_sec}s",
                    technique={"id": "ERR", "name": "Timeout", "tactic": "Testing"},
                )
                results.append(res)
                self.ctx.telemetry.write(res)
            except Exception as e:
                res = StepResult(
                    step_id=s.step_id,
                    status="error",
                    message=f"Исключение: {e}",
                    technique={"id": "ERR", "name": "Exception", "tactic": "Testing"},
                )
                results.append(res)
                self.ctx.telemetry.write(res)
        self.ctx.telemetry.write(
            StepResult(
                step_id="scenario_end",
                status="info",
                message="Завершение сценария",
                technique={"id": "DONE", "name": "Scenario End", "tactic": "Testing"},
            )
        )
        return results

# ------------------------------- CLI -----------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> ScenarioConfig:
    p = argparse.ArgumentParser(
        prog="scenario_ransomware",
        description="Безопасная эмуляция сценария ransomware (MITRE ATT&CK T1486/T1490) с телеметрией и артефактами.",
    )
    p.add_argument("--file-count", type=int, default=12, help="Количество канареечных файлов (по умолчанию: 12)")
    p.add_argument("--file-size-kb", type=int, default=16, help="Размер каждого файла в КБ (по умолчанию: 16)")
    p.add_argument("--timeout", type=int, default=15, help="Таймаут шага в секундах (по умолчанию: 15)")
    p.add_argument("--seed", type=int, default=None, help="Seed генератора случайных чисел")
    p.add_argument("--no-zip", action="store_true", help="Не собирать ZIP-пакеты с артефактами")
    p.add_argument("--base-dir", type=Path, default=None, help="Базовая директория (по умолчанию: системная TEMP)")
    p.add_argument("--work-dir", type=Path, default=None, help="Рабочая директория сценария (по умолчанию: base/scenario_*)")
    p.add_argument("--artifacts-dir", type=Path, default=None, help="Каталог артефактов (по умолчанию: work_dir/artifacts)")
    p.add_argument("--telemetry", type=Path, default=None, help="Путь к NDJSON телеметрии (по умолчанию: artifacts/telemetry.ndjson)")

    args = p.parse_args(argv)
    cfg = ScenarioConfig(
        safe_mode=True,
        file_count=max(1, args.file_count),
        file_size_kb=max(1, args.file_size_kb),
        step_timeout_sec=max(3, args.timeout),
        seed=args.seed,
        create_zip=(not args.no_zip),
        base_dir=(args.base_dir if args.base_dir else Path(tempfile.gettempdir()) / "advemu_ransomware"),
        work_dir=args.work_dir,
        artifacts_dir=args.artifacts_dir,
        telemetry_path=args.telemetry,
    )
    return cfg

def main(argv: Optional[List[str]] = None) -> int:
    try:
        cfg = parse_args(argv)
        scenario = RansomwareScenario(cfg)
        asyncio.run(scenario.run())
        print(f"[OK] Эмуляция завершена. Рабочая директория: {scenario.ctx.work_dir}")
        print(f"     Телеметрия: {scenario.cfg.telemetry_path}")
        print(f"     Артефакты: {scenario.ctx.artifacts_dir}")
        return 0
    except ScenarioError as e:
        print(f"[SCENARIO ERROR] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[INTERRUPTED] Остановка пользователем.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
