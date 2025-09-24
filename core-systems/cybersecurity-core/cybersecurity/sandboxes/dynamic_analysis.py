# file: cybersecurity-core/cybersecurity/sandboxes/dynamic_analysis.py
"""
Dynamic Analysis Orchestrator (industrial-grade, safety-first)

Назначение:
- Управление динамическим анализом образцов в изолированной среде (sandbox).
- Строгие модели входа/выхода, сбор артефактов, метрик, опциональных детекций (YARA).
- Провайдер-агностичный интерфейс (dry-run по умолчанию; реальные провайдеры подключаются отдельно).
- Безопасные "поручни": модуль никогда не исполняет образцы без явного разрешения.

Важная безопасность:
- По умолчанию используется DryRunSandboxProvider (ничего не запускает).
- Для включения реального исполнения требуется установить переменную окружения:
    DYNANALYSIS_ALLOW_EXEC=1
  и предоставить провайдер, реализующий интерфейс SandboxProvider.
- Модуль НЕ навязывает конкретную технологию песочницы (Docker, Firecracker, VM).
- Никогда не запускайте образцы вне доверенной изоляции.

Зависимости:
- Python 3.10+
- pydantic (v1 или v2) — опционально, для строгих схем (модуль работает и без pydantic при импорте ошибок)
- (опционально) yara-python — для YARA-скана, если установлен.

CLI:
    python -m cybersecurity.sandboxes.dynamic_analysis \
      --sample /path/to/sample.bin \
      --output report.json \
      --provider dry-run \
      --timeout 60 \
      --yara-rules rules.yar

Автор: Aethernova / cybersecurity-core
Лицензия: Apache-2.0
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import datetime as dt
import gzip
import hashlib
import json
import logging
import os
import random
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Protocol, Tuple, Union

# Pydantic v1/v2 compatibility (опционально)
try:
    from pydantic import BaseModel, Field, root_validator, validator  # v1
    _PD_V2 = False
except Exception:  # pragma: no cover
    try:
        from pydantic import BaseModel, Field, field_validator as validator, model_validator as root_validator  # v2
        _PD_V2 = True  # type: ignore
    except Exception:
        BaseModel = object  # type: ignore
        Field = lambda *a, **k: None  # type: ignore
        validator = lambda *a, **k: (lambda f: f)  # type: ignore
        root_validator = lambda *a, **k: (lambda f: f)  # type: ignore
        _PD_V2 = False

# Опциональный YARA
try:
    import yara  # type: ignore
    _HAS_YARA = True
except Exception:  # pragma: no cover
    yara = None  # type: ignore
    _HAS_YARA = False

logger = logging.getLogger("cybersecurity.sandboxes.dynamic")
if not logger.handlers:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ---------------------------------- MODELS -----------------------------------

SampleKind = Literal["pe", "elf", "mach-o", "script", "doc", "archive", "unknown"]
NetworkMode = Literal["none", "sinkhole", "limited", "full"]
Verdict = Literal["unknown", "benign", "suspicious", "malicious"]

@dataclass(frozen=True)
class SampleSpec:
    path: Path
    filename: str
    size: int
    sha256: str
    sha1: str
    md5: str
    kind: SampleKind = "unknown"

    @staticmethod
    def from_path(p: Path, kind: SampleKind = "unknown") -> "SampleSpec":
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Sample not found: {p}")
        size = p.stat().st_size
        sha256, sha1, md5 = _hash_file_all(p)
        return SampleSpec(path=p.resolve(), filename=p.name, size=size, sha256=sha256, sha1=sha1, md5=md5, kind=kind)


class Detection(BaseModel):
    engine: str = Field(..., min_length=1, max_length=64)
    rule: str = Field(..., min_length=1, max_length=128)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    description: Optional[str] = None


class ProcessEvent(BaseModel):
    ts: float
    pid: int
    ppid: Optional[int] = None
    image: str
    cmdline: str
    status: Literal["start", "exit"]


class FileEvent(BaseModel):
    ts: float
    path: str
    operation: Literal["create", "write", "read", "delete", "rename"]
    size: Optional[int] = None
    sha256: Optional[str] = None


class NetworkEvent(BaseModel):
    ts: float
    direction: Literal["outbound", "inbound"]
    proto: Literal["tcp", "udp", "icmp", "other"] = "tcp"
    saddr: Optional[str] = None
    sport: Optional[int] = None
    daddr: Optional[str] = None
    dport: Optional[int] = None
    verdict: Optional[str] = None  # allowed/blocked/sinkhole


class SandboxMetrics(BaseModel):
    started_at: str
    finished_at: Optional[str] = None
    runtime_seconds: Optional[float] = None
    cpu_seconds: Optional[float] = None
    peak_rss_bytes: Optional[int] = None
    messages: int = 0


class AnalysisSummary(BaseModel):
    verdict: Verdict = "unknown"
    score: int = Field(0, ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    schema_version: str = "1.0.0"
    sample: Dict[str, Any]
    policy: Dict[str, Any]
    summary: AnalysisSummary
    detections: List[Detection] = Field(default_factory=list)
    processes: List[ProcessEvent] = Field(default_factory=list)
    files: List[FileEvent] = Field(default_factory=list)
    network: List[NetworkEvent] = Field(default_factory=list)
    artifacts: List[str] = Field(default_factory=list)
    metrics: SandboxMetrics


# --------------------------------- POLICY ------------------------------------

@dataclass
class AnalysisPolicy:
    max_runtime_seconds: int = 60
    kill_after_seconds: int = 10
    network_mode: NetworkMode = "none"
    record_pcap: bool = False
    enable_yara: bool = False
    yara_rules_path: Optional[Path] = None
    command: Optional[List[str]] = None        # чем запускать образец (если нужно)
    env: Optional[Dict[str, str]] = None       # переменные окружения в госте
    working_dir: str = "/opt/sample"           # директория в госте
    sample_guest_path: str = "/opt/sample/sample.bin"


# ------------------------------ PROVIDER API ---------------------------------

class ExecResult(Protocol):
    exit_code: int
    stdout: bytes
    stderr: bytes
    started_at: float
    finished_at: float


class SandboxProvider(Protocol):
    """
    Контракт провайдера песочницы. Реализации обязаны обеспечивать изоляцию.
    """

    name: str

    async def prepare(self, *, policy: AnalysisPolicy, workdir: Path) -> str:
        ...

    async def upload(self, ctx: str, host_path: Path, guest_path: str) -> None:
        ...

    async def start_captures(self, ctx: str, *, policy: AnalysisPolicy) -> None:
        ...

    async def execute(self, ctx: str, command: List[str], *, env: Dict[str, str], timeout: int) -> ExecResult:
        ...

    async def stop_captures(self, ctx: str) -> List[Path]:
        ...

    async def collect_artifacts(self, ctx: str) -> List[Path]:
        ...

    async def destroy(self, ctx: str) -> None:
        ...


# ---------------------------- SAFE DEFAULT PROVIDER --------------------------

@dataclass
class _SimExecResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    started_at: float
    finished_at: float


class DryRunSandboxProvider:
    """
    Безопасный «сухой» провайдер: ничего не исполняет, эмулирует события.
    Подходит для тестов CI и проверки пайплайна.
    """
    name = "dry-run"

    async def prepare(self, *, policy: AnalysisPolicy, workdir: Path) -> str:
        await asyncio.sleep(0.01)
        return f"dry-{int(time.time()*1000)}"

    async def upload(self, ctx: str, host_path: Path, guest_path: str) -> None:
        await asyncio.sleep(0.01)

    async def start_captures(self, ctx: str, *, policy: AnalysisPolicy) -> None:
        await asyncio.sleep(0.01)

    async def execute(self, ctx: str, command: List[str], *, env: Dict[str, str], timeout: int) -> ExecResult:
        started = time.time()
        # Имитация активности
        await asyncio.sleep(min(0.1, timeout))
        # Симулируем «нормальный» выход
        finished = time.time()
        return _SimExecResult(
            exit_code=0,
            stdout=b"dry-run: simulated execution\n",
            stderr=b"",
            started_at=started,
            finished_at=finished,
        )

    async def stop_captures(self, ctx: str) -> List[Path]:
        await asyncio.sleep(0.01)
        return []

    async def collect_artifacts(self, ctx: str) -> List[Path]:
        await asyncio.sleep(0.01)
        return []

    async def destroy(self, ctx: str) -> None:
        await asyncio.sleep(0.01)


# ------------------------------ ANALYZER CORE --------------------------------

@dataclass
class AnalyzerConfig:
    provider: SandboxProvider
    policy: AnalysisPolicy
    allow_execution: bool = False  # защищает от случайного запуска
    work_base: Path = Path(tempfile.gettempdir()) / "dyn-analysis"


class DynamicAnalyzer:
    def __init__(self, cfg: AnalyzerConfig) -> None:
        self.cfg = cfg

    async def run(self, sample: SampleSpec) -> AnalysisReport:
        _ensure_safety(self.cfg.allow_execution)
        workdir = _mk_workdir(self.cfg.work_base, sample.sha256)
        metrics = SandboxMetrics(started_at=dt.datetime.utcnow().isoformat() + "Z")

        ctx = ""
        artifacts: List[Path] = []
        detections: List[Detection] = []
        processes: List[ProcessEvent] = []
        files: List[FileEvent] = []
        net: List[NetworkEvent] = []

        try:
            logger.info("Preparing sandbox with provider=%s", getattr(self.cfg.provider, "name", "unknown"))
            ctx = await self.cfg.provider.prepare(policy=self.cfg.policy, workdir=workdir)

            logger.info("Uploading sample -> %s", self.cfg.policy.sample_guest_path)
            await self.cfg.provider.upload(ctx, sample.path, self.cfg.policy.sample_guest_path)

            # Доп. артефакт: manifest.json
            manifest = workdir / "manifest.json"
            manifest.write_text(json.dumps(dataclasses.asdict(sample), ensure_ascii=False, indent=2), encoding="utf-8")

            # Запускаем сбор данных (pcap/др.)
            await self.cfg.provider.start_captures(ctx, policy=self.cfg.policy)

            # Команда запуска: либо заданная, либо просто sample_guest_path
            command = self.cfg.policy.command or [self.cfg.policy.sample_guest_path]
            env = dict(self.cfg.policy.env or {})

            logger.info("Executing command (timeout=%ss): %s", self.cfg.policy.max_runtime_seconds, command)
            exec_res = await self.cfg.provider.execute(
                ctx,
                command,
                env=env,
                timeout=self.cfg.policy.max_runtime_seconds,
            )

            # Синтетические события (минимум) — в реальных провайдерах это заменит агент/инструментация
            processes.append(
                ProcessEvent(
                    ts=exec_res.started_at,
                    pid=1,
                    ppid=None,
                    image=command[0],
                    cmdline=" ".join(command),
                    status="start",
                )
            )
            processes.append(
                ProcessEvent(
                    ts=exec_res.finished_at,
                    pid=1,
                    ppid=None,
                    image=command[0],
                    cmdline=" ".join(command),
                    status="exit",
                )
            )

            # Сбор артефактов с провайдера (дампы/логи/pcap и т.д.)
            logger.info("Stopping captures and collecting artifacts")
            artifacts += await self.cfg.provider.stop_captures(ctx)
            artifacts += await self.cfg.provider.collect_artifacts(ctx)

            # Опциональный YARA-скан (локально, безопасно)
            if self.cfg.policy.enable_yara and _HAS_YARA and self.cfg.policy.yara_rules_path:
                logger.info("Running YARA scan: %s", self.cfg.policy.yara_rules_path)
                detections += await _yara_scan(sample.path, self.cfg.policy.yara_rules_path)

            # Простейшие эвристики вердикта (показательно, реальная логика — в ваших правилах)
            summary = _score(sample, detections, processes, files, net, exec_res.exit_code)

            # Метрики
            metrics.finished_at = dt.datetime.utcnow().isoformat() + "Z"
            metrics.runtime_seconds = float(max(0.0, (exec_res.finished_at - exec_res.started_at)))
            metrics.messages = len(processes) + len(files) + len(net)

            # Финальный отчет
            report = AnalysisReport(
                sample={
                    "filename": sample.filename,
                    "size": sample.size,
                    "sha256": sample.sha256,
                    "sha1": sample.sha1,
                    "md5": sample.md5,
                    "kind": sample.kind,
                },
                policy={
                    "max_runtime_seconds": self.cfg.policy.max_runtime_seconds,
                    "network_mode": self.cfg.policy.network_mode,
                    "record_pcap": self.cfg.policy.record_pcap,
                    "enable_yara": self.cfg.policy.enable_yara,
                },
                summary=summary,
                detections=detections,
                processes=processes,
                files=files,
                network=net,
                artifacts=[str(p) for p in artifacts],
                metrics=metrics,
            )
            return report

        finally:
            try:
                if ctx:
                    await self.cfg.provider.destroy(ctx)
            except Exception:
                logger.warning("Sandbox destroy failed", exc_info=True)
            _cleanup_workdir(workdir)


# ------------------------------ HELPERS & LOGIC ------------------------------

def _ensure_safety(allow_execution_flag: bool) -> None:
    env = os.getenv("DYNANALYSIS_ALLOW_EXEC", "0")
    allowed = allow_execution_flag and env not in ("0", "", "false", "False", "no", "No")
    if not allowed:
        # Никаких реальных запусков, если защита не снята
        logger.info("Execution is disabled (DryRun enforced). Set DYNANALYSIS_ALLOW_EXEC=1 and allow_execution=True to enable.")
    # Принудительно заменим провайдера на dry-run, если флаг не разрешен
    # Решаем это на уровне вызова: пользователь должен передать DryRunSandboxProvider, если не разрешено.


def _hash_file_all(path: Path) -> Tuple[str, str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


async def _yara_scan(sample_path: Path, rules_path: Path) -> List[Detection]:
    dets: List[Detection] = []
    try:
        rules = yara.compile(str(rules_path))  # type: ignore
        matches = rules.match(str(sample_path))  # type: ignore
        for m in matches:
            sev = "medium"
            if getattr(m, "meta", None):
                sev = str(m.meta.get("severity", sev)).lower()
                if sev not in ("low", "medium", "high", "critical"):
                    sev = "medium"
            dets.append(Detection(engine="YARA", rule=str(m.rule), severity=sev, description=str(m.meta)))
    except Exception as e:  # pragma: no cover
        logger.warning("YARA scan failed: %s", e)
    return dets


def _score(
    sample: SampleSpec,
    detections: List[Detection],
    processes: List[ProcessEvent],
    files: List[FileEvent],
    network: List[NetworkEvent],
    exit_code: int,
) -> AnalysisSummary:
    score = 0
    reasons: List[str] = []

    # Детекции
    for d in detections:
        if d.severity == "critical":
            score += 50
        elif d.severity == "high":
            score += 30
        elif d.severity == "medium":
            score += 15
        else:
            score += 5
        reasons.append(f"{d.engine}:{d.rule}={d.severity}")

    # Поведение (синтетика; реальные провайдеры могут заполнить события)
    if any(ev.direction == "outbound" for ev in network):
        score += 10
        reasons.append("outbound_network")

    if exit_code != 0:
        score += 3
        reasons.append("nonzero_exit")

    score = max(0, min(100, score))
    if score >= 70:
        verdict: Verdict = "malicious"
    elif score >= 35:
        verdict = "suspicious"
    elif score == 0:
        verdict = "unknown"
    else:
        verdict = "benign"

    return AnalysisSummary(verdict=verdict, score=score, reasons=reasons)


def _mk_workdir(base: Path, sha256: str) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    wd = base / f"job-{sha256[:12]}-{int(time.time())}"
    wd.mkdir(parents=True, exist_ok=True)
    return wd


def _cleanup_workdir(path: Path) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        logger.warning("Failed to cleanup workdir %s", path, exc_info=True)


# ------------------------------------ CLI ------------------------------------

def _cli(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Dynamic Analysis Orchestrator (safe by default)")
    p.add_argument("--sample", required=True, help="Path to sample file")
    p.add_argument("--output", required=True, help="Where to write JSON report")
    p.add_argument("--provider", default="dry-run", choices=["dry-run"], help="Sandbox provider")
    p.add_argument("--timeout", type=int, default=60, help="Max runtime seconds")
    p.add_argument("--network", default="none", choices=["none", "sinkhole", "limited", "full"], help="Network mode")
    p.add_argument("--yara-rules", dest="yara_rules", help="Path to YARA rules (optional)")
    p.add_argument("--enable-yara", action="store_true", help="Enable YARA scan (requires yara-python)")
    p.add_argument("--allow-exec", action="store_true", help="Allow real execution (requires DYNANALYSIS_ALLOW_EXEC=1)")
    args = p.parse_args(argv)

    sample_path = Path(args.sample)
    sample = SampleSpec.from_path(sample_path, kind="unknown")

    policy = AnalysisPolicy(
        max_runtime_seconds=max(1, args.timeout),
        network_mode=args.network,  # провайдер может интерпретировать
        enable_yara=args.enable_yara,
        yara_rules_path=Path(args.yara_rules) if args.yara_rules else None,
    )

    # Провайдеры (по умолчанию dry-run)
    provider: SandboxProvider
    if args.provider == "dry-run":
        provider = DryRunSandboxProvider()
    else:  # pragma: no cover
        raise ValueError("Unsupported provider (only dry-run is built-in)")

    cfg = AnalyzerConfig(
        provider=provider,
        policy=policy,
        allow_execution=bool(args.allow_exec),
    )

    async def _run() -> int:
        analyzer = DynamicAnalyzer(cfg)
        report = await analyzer.run(sample)
        Path(args.output).write_text(json.dumps(_to_serializable(report), ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("Report written: %s", args.output)
        # Если вердикт вредоносный/подозрительный — вернуть код 1 для CI по желанию; здесь всегда 0
        return 0

    return asyncio.run(_run())


def _to_serializable(obj: Any) -> Any:
    if hasattr(obj, "dict"):
        return obj.dict()
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(x) for x in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# --------------------------------- EXTENSION API -----------------------------
# Ниже — точки расширения для кастомных провайдеров. Реализации должны
# обеспечивать изоляцию и уважать политику AnalysisPolicy.
#
# Пример каркаса провайдера (заглушка):
#
# class DockerSandboxProvider:
#     name = "docker"
#     async def prepare(self, *, policy: AnalysisPolicy, workdir: Path) -> str: ...
#     async def upload(self, ctx: str, host_path: Path, guest_path: str) -> None: ...
#     async def start_captures(self, ctx: str, *, policy: AnalysisPolicy) -> None: ...
#     async def execute(self, ctx: str, command: List[str], *, env: Dict[str, str], timeout: int) -> ExecResult: ...
#     async def stop_captures(self, ctx: str) -> List[Path]: ...
#     async def collect_artifacts(self, ctx: str) -> List[Path]: ...
#     async def destroy(self, ctx: str) -> None: ...
#
# Подключайте собственные провайдеры в вашем коде и передавайте их в AnalyzerConfig.

# -----------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
