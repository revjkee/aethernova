# cybersecurity-core/cybersecurity/adversary_emulation/tooling/atomic_runner.py
# -*- coding: utf-8 -*-
"""
Atomic Runner (Safe-by-Default) for Adversary Emulation

Назначение
----------
Промышленный безопасный раннер для запуска "атомарных" сценариев эмуляции техник MITRE ATT&CK.
По умолчанию НЕ выполняет команды (dry-run), поддерживает allowlist сценариев, denylist опасных токенов,
таймауты, песочницу рабочих директорий, подробный аудит и ротацию логов.

Основы и источники (проверяемые ссылки)
---------------------------------------
- MITRE ATT&CK (тактика/техники): https://attack.mitre.org
- Atomic Red Team (концепция атомарных тестов): https://github.com/redcanaryco/atomic-red-team
- NIST SP 800-53 Rev. 5 (AU, CM, SI — аудит, конфигурация, инциденты):
  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- Microsoft Sysmon schema (для последующего сопоставления телеметрии, если используется вне этого файла):
  https://learn.microsoft.com/windows/security/threat-protection/windows-defender-advanced-threat-protection/attack-surface-reduction

Принципы безопасности
---------------------
1) По умолчанию dry-run: команды не исполняются, только моделируются.
2) Явное включение исполнения (--enable-exec) + обязательная allowlist тестов/техник.
3) Denylist опасных токенов (напр. "format", "cipher /w", "del /f /s /q", "reg add", "sc create", "powershell -enc").
4) Запрет сетевых загрузок/обращений (например, "curl", "wget", "Invoke-WebRequest") если не включён режим --allow-network.
5) Песочница рабочих директорий и ограниченное окружение процесса.
6) Таймауты/лимиты параллелизма, JSON-аудит, ротация логов.

Внимание
--------
Этот раннер не содержит и не распространяет эксплойтов, не предлагает эксплуатационные инструкции.
Используйте только с полученным разрешением владельца инфраструктуры и в контролируемой среде.

Лицензия
--------
Apache-2.0
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import logging
import os
import platform
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0"
__vendor__ = "Aethernova Cybersecurity Core"
__runner_id__ = "ATOMIC-RUNNER-SAFE"


# ==============================
# Data classes
# ==============================

@dataclasses.dataclass
class AtomicStep:
    name: str
    command: str
    shell: str = "cmd"  # cmd|powershell|sh
    timeout_sec: int = 20
    working_dir: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    simulate_only: Optional[bool] = None  # если None — наследует от глобального dry-run

@dataclasses.dataclass
class AtomicTest:
    id: str                  # уникальный ID теста (например, "win.T1112.sample-1")
    title: str               # человекочитаемое имя
    technique: str           # ATT&CK technique id, напр. "T1112"
    platform: List[str]      # ["windows"]|["linux"]|["macos"] ...
    tags: List[str]
    checksum_sha256: Optional[str]  # контроль целостности файла-описания
    steps: List[AtomicStep]

@dataclasses.dataclass
class StepResult:
    test_id: str
    step_name: str
    shell: str
    command: str
    started_utc: str
    finished_utc: str
    duration_ms: int
    exit_code: Optional[int]
    stdout: str
    stderr: str
    simulated: bool
    blocked_reason: Optional[str]
    ok: bool

@dataclasses.dataclass
class RunReport:
    runner_id: str
    version: str
    vendor: str
    timestamp_utc: str
    host: str
    os: str
    username: str
    dry_run: bool
    allow_network: bool
    max_workers: int
    total_tests: int
    executed_steps: int
    blocked_steps: int
    results: List[StepResult]


# ==============================
# Logging
# ==============================

def build_logger(level: str = "INFO") -> logging.Logger:
    logs_dir = Path(os.environ.get("PROGRAMDATA", Path.cwd())) / "CyberAudit" / "atomic_runner" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "atomic_runner.log"
    logger = logging.getLogger("atomic_runner")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    rfh = RotatingFileHandler(str(log_path), maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    rfh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(rfh)
    logger.addHandler(sh)
    return logger


# ==============================
# Loaders (JSON/YAML)
# ==============================

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def load_atomic_tests(path: Path, logger: logging.Logger) -> List[AtomicTest]:
    """
    Загружает описание тестов из JSON или YAML (если установлен PyYAML).
    Формат ожидается как список тестов с полями AtomicTest/AtomicStep (см. dataclass-ы выше).
    """
    if not path.exists():
        raise FileNotFoundError(f"Test definition not found: {path}")

    content = path.read_text(encoding="utf-8")
    ext = path.suffix.lower()
    try:
        if ext in (".json",):
            data = json.loads(content)
        elif ext in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
            except Exception as e:
                raise RuntimeError("PyYAML is required to load YAML. Install 'pyyaml' or provide JSON.") from e
            data = yaml.safe_load(content)
        else:
            raise ValueError(f"Unsupported file extension: {ext}")
    except Exception as e:
        raise RuntimeError(f"Failed to parse test definition: {e}") from e

    if not isinstance(data, list):
        raise ValueError("Test definition root must be a list")

    checksum = _sha256_file(path)

    tests: List[AtomicTest] = []
    for i, item in enumerate(data):
        try:
            steps_raw = item.get("steps", [])
            steps = [
                AtomicStep(
                    name=s.get("name", f"step-{idx+1}"),
                    command=s["command"],
                    shell=s.get("shell", "cmd"),
                    timeout_sec=int(s.get("timeout_sec", 20)),
                    working_dir=s.get("working_dir"),
                    env=s.get("env"),
                    simulate_only=s.get("simulate_only"),
                ) for idx, s in enumerate(steps_raw)
            ]
            tests.append(AtomicTest(
                id=item["id"],
                title=item.get("title", item["id"]),
                technique=item["technique"],
                platform=item.get("platform", ["windows"]),
                tags=item.get("tags", []),
                checksum_sha256=item.get("checksum_sha256", checksum),
                steps=steps
            ))
        except Exception as e:
            raise ValueError(f"Invalid test at index {i}: {e}") from e

    logger.info("Loaded %d atomic test(s) from %s (sha256=%s)", len(tests), path, checksum)
    return tests


# ==============================
# Safety policy
# ==============================

# Потенциально разрушительные токены (denylist)
DANGEROUS_TOKENS = [
    # generic destructive
    r"\brm\b", r"\brmdir\b", r"\bdel\b", r"\bformat\b", r"\bmkfs\b", r"\bdiskpart\b", r"\bfsutil\b",
    r"\bcipher\s+/w\b",
    # registry/services persistence
    r"\breg\s+add\b", r"\breg\s+delete\b", r"\bsc\s+create\b", r"\bsc\s+delete\b", r"\bNew-Service\b",
    # encoded/obfuscated PowerShell
    r"\bpowershell\b.*-enc(odedcommand)?\b",
    # drivers and bcd (boot)
    r"\bbcdedit\b", r"\bpnputil\b",
    # shadow copies/system restore
    r"\bvssadmin\b\s+(delete|resize|revert)\b",
    # encryption/bitlocker
    r"\bmanage-bde\b",
]

# Сетевые индикаторы (запрещаются без --allow-network)
NETWORK_TOKENS = [
    r"\bcurl\b", r"\bwget\b", r"\bInvoke-WebRequest\b", r"\bStart-BitsTransfer\b",
    r"\npowershell\b.*New-Object\s+Net\.WebClient",
    r"\bpowershell\b.*System\.Net\.Http",
]

# Мини-allowlist шеллов
ALLOWED_SHELLS = {"cmd", "powershell", "sh"}

def token_block_reason(cmd: str, allow_network: bool) -> Optional[str]:
    for pat in DANGEROUS_TOKENS:
        if re.search(pat, cmd, flags=re.IGNORECASE):
            return f"blocked_by_denylist:{pat}"
    if not allow_network:
        for pat in NETWORK_TOKENS:
            if re.search(pat, cmd, flags=re.IGNORECASE):
                return f"blocked_network_token:{pat}"
    return None


# ==============================
# Executor
# ==============================

class TimeoutExpired(Exception):
    pass

class CommandExecutor:
    def __init__(self, timeout_sec: int = 20):
        self.timeout_sec = timeout_sec

    @staticmethod
    def _creation_flags() -> int:
        # Windows: CREATE_NO_WINDOW = 0x08000000
        return 0x08000000 if platform.system().lower() == "windows" else 0

    @staticmethod
    def _safe_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = {
            "LANG": "C",
            "LC_ALL": "C",
        }
        env.update({k: v for k, v in os.environ.items() if k in ("SystemRoot", "WINDIR", "PATH")})
        if extra:
            env.update({k: str(v) for k, v in extra.items()})
        # Очистим переменные, могущие повлиять на загрузку модулей
        for k in ("PYTHONPATH", "VIRTUAL_ENV"):
            env.pop(k, None)
        return env

    def run(self, shell: str, command: str, timeout_sec: int, cwd: Optional[Path], env: Optional[Dict[str, str]]) -> Tuple[int, str, str, int]:
        if shell not in ALLOWED_SHELLS:
            return 127, "", f"Shell '{shell}' is not allowed", 0

        if shell == "cmd":
            cmdline = ["cmd.exe", "/c", command]
        elif shell == "powershell":
            cmdline = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]
        else:  # sh
            cmdline = ["sh", "-c", command]

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmdline,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                text=True,
                shell=False,
                env=self._safe_env(env),
                creationflags=self._creation_flags(),
            )
        except FileNotFoundError as e:
            dur = int((time.monotonic() - start) * 1000)
            return 127, "", str(e), dur

        timer = threading.Timer(timeout_sec, lambda: _terminate(proc))
        timer.start()
        try:
            out, err = proc.communicate()
        finally:
            timer.cancel()
        dur = int((time.monotonic() - start) * 1000)
        return proc.returncode, out or "", err or "", dur


def _terminate(proc: subprocess.Popen) -> None:
    try:
        if platform.system().lower() == "windows":
            proc.kill()
        else:
            os.kill(proc.pid, signal.SIGKILL)
    except Exception:
        pass


# ==============================
# Runner
# ==============================

class AtomicRunner:
    def __init__(self, logger: logging.Logger, dry_run: bool, allow_network: bool, max_workers: int, sandbox_root: Optional[Path] = None):
        self.logger = logger
        self.dry_run = dry_run
        self.allow_network = allow_network
        self.max_workers = max_workers
        self.sandbox_root = sandbox_root or Path(tempfile.gettempdir()) / "atomic_runner_sandbox"
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self.executor = CommandExecutor()

    def _sandbox_dir(self, test: AtomicTest, step: AtomicStep) -> Path:
        safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", test.id)
        safe_step = re.sub(r"[^A-Za-z0-9_.-]+", "_", step.name)
        d = self.sandbox_root / safe_id / safe_step
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _should_block(self, cmd: str) -> Optional[str]:
        return token_block_reason(cmd, self.allow_network)

    def run_tests(self, tests: List[AtomicTest], only_ids: Optional[List[str]], only_techniques: Optional[List[str]]) -> RunReport:
        uname = platform.uname()
        username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
        filtered = []
        for t in tests:
            if only_ids and t.id not in only_ids:
                continue
            if only_techniques and t.technique not in only_techniques:
                continue
            filtered.append(t)

        results: List[StepResult] = []
        blocked_steps = 0
        executed_steps = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = []
            for test in filtered:
                for step in test.steps:
                    futures.append(pool.submit(self._run_step, test, step))

            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                results.append(res)
                if res.blocked_reason or res.simulated:
                    blocked_steps += 1 if res.blocked_reason else 0
                if res.exit_code is not None:
                    executed_steps += 1

        report = RunReport(
            runner_id=__runner_id__,
            version=__version__,
            vendor=__vendor__,
            timestamp_utc=datetime.utcnow().isoformat(timespec="seconds") + "Z",
            host=uname.node,
            os=f"{uname.system} {uname.release} ({uname.version})",
            username=username,
            dry_run=self.dry_run,
            allow_network=self.allow_network,
            max_workers=self.max_workers,
            total_tests=len(filtered),
            executed_steps=executed_steps,
            blocked_steps=blocked_steps,
            results=sorted(results, key=lambda r: (r.test_id, r.step_name)),
        )
        return report

    def _run_step(self, test: AtomicTest, step: AtomicStep) -> StepResult:
        started = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        # Валидации
        if platform.system().lower() not in [p.lower() for p in test.platform]:
            return self._mk_result(test, step, started, "Platform not supported for this test", simulated=True, ok=True)

        if step.shell not in ALLOWED_SHELLS:
            return self._mk_result(test, step, started, f"Shell not allowed: {step.shell}", simulated=True, ok=True)

        # Политики безопасности
        deny = self._should_block(step.command)
        if deny:
            self._log_block(test, step, deny)
            return self._mk_result(test, step, started, f"Blocked by policy: {deny}", simulated=True, ok=True, blocked_reason=deny)

        # Dry-run и simulate_only
        simulate = self.dry_run if step.simulate_only is None else bool(step.simulate_only)
        if simulate:
            self._log_simulate(test, step)
            return self._mk_result(test, step, started, None, simulated=True, ok=True)

        # Песочница
        cwd = self._sandbox_dir(test, step) if not step.working_dir else Path(step.working_dir)
        timeout = max(1, int(step.timeout_sec))

        # Исполнение
        exit_code, out, err, dur = self.executor.run(step.shell, step.command, timeout, cwd, step.env)

        ok = (exit_code == 0)
        finished = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        return StepResult(
            test_id=test.id,
            step_name=step.name,
            shell=step.shell,
            command=step.command,
            started_utc=started,
            finished_utc=finished,
            duration_ms=dur,
            exit_code=exit_code,
            stdout=out,
            stderr=err,
            simulated=False,
            blocked_reason=None,
            ok=ok
        )

    def _mk_result(self, test: AtomicTest, step: AtomicStep, started: str, reason: Optional[str], simulated: bool, ok: bool, blocked_reason: Optional[str] = None) -> StepResult:
        finished = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        return StepResult(
            test_id=test.id,
            step_name=step.name,
            shell=step.shell,
            command=step.command,
            started_utc=started,
            finished_utc=finished,
            duration_ms=0,
            exit_code=None,
            stdout="",
            stderr=reason or "",
            simulated=simulated,
            blocked_reason=blocked_reason,
            ok=ok,
        )

    def _log_block(self, test: AtomicTest, step: AtomicStep, reason: str) -> None:
        self.logger.warning("[BLOCK] test=%s step=%s reason=%s", test.id, step.name, reason)

    def _log_simulate(self, test: AtomicTest, step: AtomicStep) -> None:
        self.logger.info("[SIMULATE] test=%s step=%s shell=%s cmd=%s", test.id, step.name, step.shell, _safe_preview(step.command))


def _safe_preview(cmd: str, length: int = 240) -> str:
    s = re.sub(r"\s+", " ", cmd).strip()
    return s if len(s) <= length else s[: length - 3] + "..."


# ==============================
# Reporting
# ==============================

def report_to_json(rep: RunReport) -> str:
    return json.dumps(dataclasses.asdict(rep), ensure_ascii=False, indent=2)

def report_to_text(rep: RunReport) -> str:
    lines = []
    lines.append(f"Runner: {rep.runner_id} v{rep.version} by {rep.vendor}")
    lines.append(f"Timestamp (UTC): {rep.timestamp_utc}")
    lines.append(f"Host: {rep.host} | OS: {rep.os} | User: {rep.username}")
    lines.append(f"Mode: dry_run={rep.dry_run} allow_network={rep.allow_network} workers={rep.max_workers}")
    lines.append(f"Summary: tests={rep.total_tests} executed_steps={rep.executed_steps} blocked_steps={rep.blocked_steps}")
    lines.append("-" * 80)
    for r in rep.results:
        lines.append(f"[{r.test_id}] {r.step_name} :: shell={r.shell} simulated={r.simulated} ok={r.ok}")
        if r.blocked_reason:
            lines.append(f"  BLOCKED: {r.blocked_reason}")
        if not r.simulated and r.exit_code is not None:
            lines.append(f"  Exit={r.exit_code} Duration={r.duration_ms}ms")
            if r.stdout.strip():
                lines.append("  STDOUT:")
                for line in r.stdout.splitlines():
                    lines.append(f"    {line}")
            if r.stderr.strip():
                lines.append("  STDERR:")
                for line in r.stderr.splitlines():
                    lines.append(f"    {line}")
        lines.append("")
    return "\n".join(lines)


# ==============================
# CLI
# ==============================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="atomic_runner",
        description="Безопасный раннер атомарных тестов ATT&CK (dry-run по умолчанию)."
    )
    p.add_argument("--tests-file", required=True, help="Путь к JSON/YAML с описаниями тестов")
    p.add_argument("--only-id", action="append", default=[], help="Запустить только указанный test.id (можно повторять)")
    p.add_argument("--only-technique", action="append", default=[], help="Фильтр по ATT&CK технике (напр. T1112)")
    p.add_argument("--enable-exec", action="store_true", help="Разрешить реальное исполнение (по умолчанию dry-run)")
    p.add_argument("--allow-network", action="store_true", help="Разрешить сетевые команды (curl/wget/Invoke-WebRequest)")
    p.add_argument("--sandbox-dir", default="", help="Каталог песочницы (по умолчанию %TEMP%/atomic_runner_sandbox)")
    p.add_argument("--workers", type=int, default=4, help="Количество параллельных воркеров")
    p.add_argument("--log-level", default="INFO", help="Уровень логирования")
    p.add_argument("--json", action="store_true", help="Вывести отчёт в JSON")
    p.add_argument("--output", default="", help="Файл для сохранения отчёта (JSON)")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logger = build_logger(args.log_level)

    try:
        tests_path = Path(args.tests_file).expanduser().resolve()

        tests = load_atomic_tests(tests_path, logger)

        # Контроль целостности: сверяем, если в тестах указан checksum_sha256, иначе — сравнение пропускается
        file_digest = _sha256_file(tests_path)
        for t in tests:
            if t.checksum_sha256 and t.checksum_sha256 != file_digest:
                logger.warning("Checksum mismatch for test-file vs test '%s' (declared=%s actual=%s)",
                               t.id, t.checksum_sha256, file_digest)

        runner = AtomicRunner(
            logger=logger,
            dry_run=not args.enable_exec,
            allow_network=bool(args.allow_network),
            max_workers=max(1, int(args.workers)),
            sandbox_root=Path(args.sandbox_dir).expanduser().resolve() if args.sandbox_dir else None
        )

        # Фильтрация по id/technique (если заданы)
        only_ids = args.only_id or None
        only_techniques = args.only_technique or None

        # Для исполнения требуется явный allowlist (через --only-id/--only-technique) — иначе работаем только в dry-run
        if args.enable_exec and not (only_ids or only_techniques):
            logger.error("Execution enabled but no allowlist provided (--only-id/--only-technique). Aborting for safety.")
            return 2

        report = runner.run_tests(tests, only_ids, only_techniques)

        data = report_to_json(report) if args.json or args.output else report_to_text(report)
        if args.output:
            out = Path(args.output).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(data, encoding="utf-8")
            print(str(out))
        else:
            print(data)

        return 0
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
