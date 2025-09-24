# cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/sandbox.py
# -*- coding: utf-8 -*-
"""
Attack Sandbox: промышленный исполняющий модуль для безопасного запуска шагов эмуляции противника (TTP)
с ограничением ресурсов, контролем вывода и аудита артефактов.

Особенности:
- POSIX rlimit: CPU, память (адресное пространство), открытые файлы, размер создаваемых файлов, число процессов, запрет core-dump.
- Изоляция каталога выполнения (tempdir), минимальная среда окружения (white-list).
- Создание новой сессии/группы процессов для корректного убийства всего дерева при таймауте.
- Неблокирующее чтение stdout/stderr через selectors, запись полных логов на диск + возврат «хвостов».
- Таймаут по «стене времени» и гарантированная элиминация группы процессов.
- JSON-логи и SHA-256 артефактов для трассируемости (в т.ч. привязка к MITRE ATT&CK Technique ID).
- Без внешних зависимостей (stdlib only). На Windows rlimit недоступен — ограничения пропускаются честно.

ВНИМАНИЕ:
Это best-effort песочница уровня ОС. Полной изоляции ядра/сети/системных вызовов она не предоставляет.
Для строгой изоляции используйте контейнеры/VM/секкомп в оркестраторе поверх этого слоя.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

import subprocess
import selectors

# Опциональный импорт POSIX-модуля resource
try:
    import resource  # type: ignore
except Exception:  # pragma: no cover
    resource = None  # На Windows модуль отсутствует


# -----------------------------
# Конфигурация и результат
# -----------------------------

@dataclass(slots=True)
class SandboxLimits:
    """Жесткие ограничения для дочернего процесса."""
    cpu_time_seconds: Optional[int] = 5            # RLIMIT_CPU
    memory_bytes: Optional[int] = 256 * 1024 * 1024  # RLIMIT_AS
    open_files: Optional[int] = 64                 # RLIMIT_NOFILE
    file_size_bytes: Optional[int] = 32 * 1024 * 1024  # RLIMIT_FSIZE
    max_processes: Optional[int] = 16              # RLIMIT_NPROC
    allow_core_dump: bool = False                  # RLIMIT_CORE=0 по умолчанию


@dataclass(slots=True)
class SandboxConfig:
    """Параметры песочницы."""
    wall_clock_timeout_seconds: int = 30
    limits: SandboxLimits = field(default_factory=SandboxLimits)

    # Окружение
    inherit_env: bool = False
    allowed_env_keys: Tuple[str, ...] = (
        "LANG",
        "LC_ALL",
        "TZ",
        "PATH",
    )
    base_path: str = "/usr/bin:/bin"

    # Сбор артефактов
    collect_artifacts: bool = True
    artifacts_max_files: int = 200
    artifacts_max_total_bytes: int = 64 * 1024 * 1024

    # Возвращаемые «хвосты» stdout/stderr (байты)
    stdout_tail_bytes: int = 64 * 1024
    stderr_tail_bytes: int = 64 * 1024

    # Логирование
    log_level: int = logging.INFO


@dataclass(slots=True)
class ArtifactInfo:
    path: str
    size: int
    sha256: str


@dataclass(slots=True)
class SandboxResult:
    success: bool
    exit_code: Optional[int]
    timed_out: bool
    duration_seconds: float
    stdout_tail: bytes
    stderr_tail: bytes
    stdout_path: str
    stderr_path: str
    workdir: str
    technique_id: Optional[str] = None
    technique_desc: Optional[str] = None
    rusage: Optional[Dict[str, int]] = None
    artifacts: List[ArtifactInfo] = field(default_factory=list)


# -----------------------------
# JSON-логирование
# -----------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(record.created * 1000),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _build_logger(level: int) -> logging.Logger:
    logger = logging.getLogger("attack_sandbox")
    logger.setLevel(level)
    # Избегаем дублирования хендлеров при повторном создании
    if not logger.handlers:
        h = logging.StreamHandler(stream=sys.stderr)
        h.setFormatter(_JsonFormatter())
        logger.addHandler(h)
        logger.propagate = False
    return logger


# -----------------------------
# Утилиты окружения и ограничений
# -----------------------------

def _build_env(config: SandboxConfig) -> Dict[str, str]:
    if config.inherit_env:
        env = {k: v for k, v in os.environ.items() if k in config.allowed_env_keys}
    else:
        env = {}
    # Гарантируем минимальный PATH
    env["PATH"] = config.base_path
    # Нейтрализуем переменные, потенциально влияющие на сеть/прокси
    for k in list(env.keys()):
        if k.upper().endswith("_PROXY"):
            env.pop(k, None)
    return env


def _posix_apply_rlimits(limits: SandboxLimits) -> None:
    """Вызывается в дочернем процессе до exec(). POSIX only."""
    if resource is None:
        return

    # Формируем «мягкий=жесткий» лимит, чтобы дочерний не мог его поднять
    def _set(kind: int, value: Optional[int]) -> None:
        if value is None:
            return
        soft = hard = int(value)
        resource.setrlimit(kind, (soft, hard))

    # Ограничения
    if limits.cpu_time_seconds is not None:
        _set(resource.RLIMIT_CPU, limits.cpu_time_seconds)

    if limits.memory_bytes is not None:
        _set(resource.RLIMIT_AS, limits.memory_bytes)

    if limits.open_files is not None:
        _set(resource.RLIMIT_NOFILE, limits.open_files)

    if limits.file_size_bytes is not None:
        _set(resource.RLIMIT_FSIZE, limits.file_size_bytes)

    if limits.max_processes is not None and hasattr(resource, "RLIMIT_NPROC"):
        _set(resource.RLIMIT_NPROC, limits.max_processes)

    # core dump
    if not limits.allow_core_dump:
        _set(resource.RLIMIT_CORE, 0)

    # Жесткий umask для создаваемых файлов
    os.umask(0o077)


def _platform_supports_posix_limits() -> bool:
    return (os.name == "posix") and (resource is not None)


def _kill_process_group(proc: subprocess.Popen, logger: logging.Logger) -> None:
    """Безопасно завершить группу процессов на всех поддерживаемых платформах."""
    try:
        if os.name == "posix":
            # Убиваем всю группу процессов
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        else:
            # Windows: отправим CTRL_BREAK_EVENT, затем Terminate
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            except Exception:
                pass
            proc.kill()
    except Exception as e:
        logger.warning("failed_to_kill_process_group: %s", e)


def _read_streams_to_files(
    proc: subprocess.Popen,
    sel: selectors.BaseSelector,
    out_file,
    err_file,
    logger: logging.Logger,
) -> Tuple[bytes, bytes]:
    """Читает stdout/stderr неблокирующе и пишет в файлы. Возвращает финальные хвосты."""
    tail_out = bytearray()
    tail_err = bytearray()

    # Регистрация каналов
    if proc.stdout:
        sel.register(proc.stdout, selectors.EVENT_READ, data=("out", out_file, tail_out))
    if proc.stderr:
        sel.register(proc.stderr, selectors.EVENT_READ, data=("err", err_file, tail_err))

    # Читаем, пока есть открытые каналы или процесс не завершился
    while True:
        events = sel.select(timeout=0.2)
        for key, _ in events:
            kind, fobj, tail_buf = key.data
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)  # type: ignore[arg-type]
            except Exception:
                chunk = b""
            if not chunk:
                try:
                    sel.unregister(key.fileobj)
                except Exception:
                    pass
                continue
            fobj.write(chunk)
            # ограничиваем хвост ~256KB для экономии памяти (на всякий случай)
            if len(tail_buf) <= 256 * 1024:
                tail_buf += chunk

        if proc.poll() is not None:
            # дренируем остаток
            events = sel.select(timeout=0)
            for key, _ in events:
                kind, fobj, tail_buf = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)  # type: ignore[arg-type]
                except Exception:
                    chunk = b""
                if chunk:
                    fobj.write(chunk)
                    if len(tail_buf) <= 256 * 1024:
                        tail_buf += chunk
                try:
                    sel.unregister(key.fileobj)
                except Exception:
                    pass
            break

    return bytes(tail_out), bytes(tail_err)


def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _scan_artifacts(
    workdir: Path,
    stdout_path: Path,
    stderr_path: Path,
    max_files: int,
    max_total_bytes: int,
    logger: logging.Logger,
) -> List[ArtifactInfo]:
    """Собирает информацию об артефактах, кроме stdout/stderr, с лимитами."""
    artifacts: List[ArtifactInfo] = []
    total = 0
    count = 0

    for p in sorted(workdir.rglob("*")):
        if not p.is_file():
            continue
        # Пропускаем собственные логи
        if p.samefile(stdout_path) or p.samefile(stderr_path):
            continue
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            continue

        if count + 1 > max_files or total + size > max_total_bytes:
            logger.warning("artifacts_limit_reached: count=%s total=%s", count, total)
            break

        try:
            digest = _sha256_file(p)
        except Exception as e:
            logger.warning("artifact_hash_failed: path=%s err=%s", str(p), e)
            continue

        artifacts.append(ArtifactInfo(path=str(p), size=size, sha256=digest))
        total += size
        count += 1

    return artifacts


# -----------------------------
# Основной класс песочницы
# -----------------------------

class AttackSandbox:
    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()
        self.logger = _build_logger(self.config.log_level)

    def run_command(
        self,
        argv: Sequence[str],
        *,
        technique_id: Optional[str] = None,
        technique_desc: Optional[str] = None,
        input_bytes: Optional[bytes] = None,
    ) -> SandboxResult:
        """
        Запускает внешнюю команду в изолированном временном каталоге с ограничениями и таймаутом.

        :param argv: Команда и аргументы.
        :param technique_id: Идентификатор техники MITRE ATT&CK (например, "T1059.003").
        :param technique_desc: Человекочитаемое описание шага.
        :param input_bytes: Необязательный stdin.
        :return: SandboxResult со всеми метаданными и артефактами.
        """
        cfg = self.config
        env = _build_env(cfg)

        start = time.monotonic()
        timed_out = False
        stdout_tail = b""
        stderr_tail = b""

        with tempfile.TemporaryDirectory(prefix="attack_sbx_") as tmpdir:
            workdir = Path(tmpdir)
            stdout_path = workdir / "stdout.log"
            stderr_path = workdir / "stderr.log"

            self.logger.info(
                "sandbox_start argv=%s workdir=%s technique_id=%s",
                argv, str(workdir), technique_id
            )

            # Открываем файлы логов заранее
            with stdout_path.open("wb") as f_out, stderr_path.open("wb") as f_err:
                sel = selectors.DefaultSelector()

                popen_kwargs = dict(
                    args=argv,
                    cwd=str(workdir),
                    env=env,
                    stdin=subprocess.PIPE if input_bytes is not None else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=False,
                    bufsize=0,
                )

                if os.name == "posix":
                    # Новая сессия и группа процессов
                    popen_kwargs.update(
                        start_new_session=True,  # эквивалент os.setsid() в дочернем
                    )
                else:
                    # Windows: новая группа процесса
                    popen_kwargs.update(
                        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    )

                # POSIX ограничения через preexec_fn (альтернативы в stdlib нет)
                if _platform_supports_posix_limits():
                    popen_kwargs.update(preexec_fn=lambda: _posix_apply_rlimits(cfg.limits))  # type: ignore[call-arg]

                proc = subprocess.Popen(**popen_kwargs)  # type: ignore[arg-type]

                # Подаем stdin, если был
                if input_bytes is not None and proc.stdin:
                    try:
                        proc.stdin.write(input_bytes)
                    finally:
                        try:
                            proc.stdin.close()
                        except Exception:
                            pass

                # Читаем вывод неблокирующе
                try:
                    # Контроль таймаута с периодической проверкой
                    deadline = start + cfg.wall_clock_timeout_seconds
                    while True:
                        # Дренируем вывод частями
                        chunk_out, chunk_err = _read_streams_to_files(proc, sel, f_out, f_err, self.logger)
                        stdout_tail += chunk_out
                        stderr_tail += chunk_err

                        if proc.poll() is not None:
                            break

                        now = time.monotonic()
                        if now >= deadline:
                            timed_out = True
                            self.logger.warning("sandbox_timeout_kill argv=%s", argv)
                            _kill_process_group(proc, self.logger)
                            proc.wait(timeout=5)
                            break
                        # Маленькая пауза, чтобы не жечь CPU
                        time.sleep(0.05)
                finally:
                    try:
                        sel.close()
                    except Exception:
                        pass

            end = time.monotonic()
            duration = end - start

            exit_code = proc.returncode

            # Обрезаем «хвосты» до лимита возврата
            if len(stdout_tail) > cfg.stdout_tail_bytes:
                stdout_tail = stdout_tail[-cfg.stdout_tail_bytes :]
            if len(stderr_tail) > cfg.stderr_tail_bytes:
                stderr_tail = stderr_tail[-cfg.stderr_tail_bytes :]

            # Сбор артефактов
            artifacts: List[ArtifactInfo] = []
            if cfg.collect_artifacts:
                artifacts = _scan_artifacts(
                    workdir=workdir,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    max_files=cfg.artifacts_max_files,
                    max_total_bytes=cfg.artifacts_max_total_bytes,
                    logger=self.logger,
                )

            # rusage (только POSIX)
            rusage: Optional[Dict[str, int]] = None
            if _platform_supports_posix_limits():
                try:
                    ru = resource.getrusage(resource.RUSAGE_CHILDREN)  # type: ignore[attr-defined]
                    rusage = {
                        "utime_ms": int(ru.ru_utime * 1000),
                        "stime_ms": int(ru.ru_stime * 1000),
                        "maxrss_kb": getattr(ru, "ru_maxrss", 0),
                        "inblock": getattr(ru, "ru_inblock", 0),
                        "oublock": getattr(ru, "ru_oublock", 0),
                    }
                except Exception:
                    rusage = None

            success = (not timed_out) and (exit_code == 0)

            # Переносим временный каталог и логи наружу для дальнейшего анализа
            # (если нужно хранить после завершения контекста tempdir)
            # По умолчанию — оставляем внутри tempdir, но возвращаем полный путь.
            result = SandboxResult(
                success=success,
                exit_code=exit_code,
                timed_out=timed_out,
                duration_seconds=duration,
                stdout_tail=stdout_tail,
                stderr_tail=stderr_tail,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                workdir=str(workdir),
                technique_id=technique_id,
                technique_desc=technique_desc,
                rusage=rusage,
                artifacts=artifacts,
            )

            self.logger.info(
                "sandbox_end success=%s exit=%s timeout=%s dur=%.3fs workdir=%s artifacts=%s",
                result.success, result.exit_code, result.timed_out, result.duration_seconds,
                result.workdir, len(result.artifacts),
            )

            # ВАЖНО: к моменту выхода из with TemporaryDirectory каталог будет удален.
            # Если нужно сохранить, скопируйте result.workdir заранее через copytree.
            # Здесь демонстрируем честное поведение: возвращаем путь, но он станет невалидным.
            # В промышленной интеграции перенесите каталог в постоянное хранилище до return.
            return result


# -----------------------------
# Пример использования (не выполняется при импорте)
# -----------------------------

if __name__ == "__main__":  # pragma: no cover
    cfg = SandboxConfig(
        wall_clock_timeout_seconds=10,
        limits=SandboxLimits(
            cpu_time_seconds=3,
            memory_bytes=128 * 1024 * 1024,
            open_files=64,
            file_size_bytes=8 * 1024 * 1024,
            max_processes=8,
            allow_core_dump=False,
        ),
        inherit_env=False,
        allowed_env_keys=("LANG", "LC_ALL", "TZ", "PATH"),
        base_path="/usr/bin:/bin",
        collect_artifacts=True,
        artifacts_max_files=100,
        artifacts_max_total_bytes=16 * 1024 * 1024,
        stdout_tail_bytes=32 * 1024,
        stderr_tail_bytes=32 * 1024,
        log_level=logging.INFO,
    )

    sbx = AttackSandbox(cfg)
    cmd = ("/usr/bin/echo", "hello-from-sandbox")
    res = sbx.run_command(cmd, technique_id="T1059.003", technique_desc="Execute echo as benign stand-in for shell TTP")
    print(json.dumps({
        "success": res.success,
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "duration_seconds": res.duration_seconds,
        "stdout_tail": res.stdout_tail.decode(errors="replace"),
        "stderr_tail": res.stderr_tail.decode(errors="replace"),
        "artifacts": [dataclasses.asdict(a) for a in res.artifacts],
        "workdir": res.workdir,
        "rusage": res.rusage,
    }, ensure_ascii=False, indent=2))
