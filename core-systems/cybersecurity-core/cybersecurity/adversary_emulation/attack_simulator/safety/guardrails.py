# cybersecurity_core/cybersecurity/adversary_emulation/attack_simulator/safety/guardrails.py
# -*- coding: utf-8 -*-
"""
Промышленный модуль guardrails для безопасной эмуляции атак (adversary emulation).

Назначение:
- Конфайнмент операций внутри разрешённой рабочей директории.
- Полная блокировка исходящих/входящих сетевых подключений для шагов симуляции.
- Белые списки команд/инструментов и запрет опасных параметров.
- Очистка и нормализация переменных окружения.
- Лимиты ресурсов (CPU time, RSS, файловые дескрипторы, размер файла) и жёсткие таймауты.
- NDJSON-аудит действий с редакцией секретов.
- Декоратор @safety_guard для функций-«шагов» сценария.

Зависимости: только стандартная библиотека Python.

Примечание:
- На Unix-подобных ОС используются «resource» лимиты. На Windows часть лимитов недоступна — модуль
  включает мягкие проверки и таймауты, оставаясь кросс-платформенным.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import io
import json
import os
import re
import resource  # type: ignore[attr-defined]  # на Windows может отсутствовать
import signal
import socket
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

# ========================= Исключения и типы ==================================

class SafetyViolation(RuntimeError):
    """Нарушение правил безопасности (жёсткая остановка шага)."""

class SafetySoftViolation(RuntimeError):
    """Мягкое нарушение (может быть преобразовано в предупреждение/лог)."""

# ============================ Конфигурация ====================================

@dataclass(frozen=True)
class SafetyConfig:
    # Конфайнмент
    base_dir: Path
    allow_subdirs: Tuple[str, ...] = (".", "artifacts", "tmp", "work")
    follow_symlinks: bool = False

    # Команды/параметры
    allowed_binaries: Tuple[str, ...] = ()
    denied_binaries: Tuple[str, ...] = (
        "rm", "dd", "mkfs", "mount", "umount", "shutdown", "reboot", "iptables",
        "tc", "sysctl", "reg", "sc", "vssadmin", "bcdedit", "cipher", "wmic",
    )
    denied_args_patterns: Tuple[re.Pattern, ...] = (
        re.compile(r"--?no[-_]?preserve[-_]?root", re.I),
        re.compile(r"--?force", re.I),
        re.compile(r"--?recursive", re.I),
        re.compile(r"--?delete", re.I),
        re.compile(r"--?format", re.I),
    )

    # Окружение
    env_allowlist: Tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TZ")
    env_overrides: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({"LANG": "C", "LC_ALL": "C"}))  # type: ignore
    wipe_others: bool = True

    # Лимиты
    cpu_seconds: int = 5
    wall_timeout_seconds: int = 20
    rss_megabytes: int = 512
    nofile: int = 256
    fsize_megabytes: int = 128

    # Сеть
    disable_network: bool = True

    # Аудит
    audit_enabled: bool = True
    audit_path: Optional[Path] = None
    redact_patterns: Tuple[re.Pattern, ...] = (
        re.compile(r"(api_?key|token|secret|password)\s*=\s*([^\s,;]+)", re.I),
        re.compile(r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*"),
        re.compile(r"0x[a-fA-F0-9]{32,}"),
    )

    # Поведение
    strict: bool = True  # True -> SafetyViolation; False -> мягкое предупреждение


# ============================== Аудит =========================================

@dataclass
class AuditEvent:
    ts: float
    level: str
    action: str
    details: Dict[str, Any]

class SafetyAudit:
    def __init__(self, cfg: SafetyConfig) -> None:
        self.cfg = cfg
        self._fp: Optional[io.TextIOBase] = None
        if self.cfg.audit_enabled:
            path = self.cfg.audit_path or (Path(tempfile.gettempdir()) / "advemu_audit.ndjson")
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fp = open(path, "a", encoding="utf-8", buffering=1)

    def _redact(self, text: str) -> str:
        redacted = text
        for pat in self.cfg.redact_patterns:
            redacted = pat.sub(lambda m: m.group(0).split("=")[0] + "=<REDACTED>", redacted)
        return redacted

    def log(self, level: str, action: str, **details: Any) -> None:
        if not self._fp:
            return
        safe_details: Dict[str, Any] = {}
        for k, v in details.items():
            if isinstance(v, str):
                safe_details[k] = self._redact(v)
            else:
                safe_details[k] = v
        evt = AuditEvent(ts=time.time(), level=level.upper(), action=action, details=safe_details)
        self._fp.write(json.dumps(dataclasses.asdict(evt), ensure_ascii=False) + "\n")

    def close(self) -> None:
        if self._fp:
            try:
                self._fp.flush()
                self._fp.close()
            finally:
                self._fp = None

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()


# ============================ Утилиты =========================================

def _realpath(p: Union[str, Path]) -> Path:
    path = Path(p).resolve()
    return path

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _platform_is_windows() -> bool:
    return os.name == "nt"


# ======================== Конфайнмент путей ===================================

class PathConfiner:
    def __init__(self, cfg: SafetyConfig, audit: SafetyAudit) -> None:
        self.cfg = cfg
        self.audit = audit
        self.base = _realpath(self.cfg.base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def ensure_inside(self, p: Union[str, Path]) -> Path:
        rp = _realpath(p)
        if not str(rp).startswith(str(self.base)):
            self.audit.log("ERROR", "path_outside_base", path=str(rp), base=str(self.base))
            if self.cfg.strict:
                raise SafetyViolation(f"Запрещён доступ вне base_dir: {rp}")
            raise SafetySoftViolation(f"Вне base_dir: {rp}")
        if not self.cfg.follow_symlinks and rp.is_symlink():
            self.audit.log("ERROR", "symlink_blocked", path=str(rp))
            if self.cfg.strict:
                raise SafetyViolation(f"Симлинки запрещены: {rp}")
            raise SafetySoftViolation(f"Симлинк запрещён: {rp}")
        return rp

    def safe_open(self, p: Union[str, Path], mode: str = "r", **kw: Any):
        rp = self.ensure_inside(p)
        # запрет опасных режимов вне разрешённых поддиректорий
        if any(x in mode for x in ("w", "a", "+")):
            rel = rp.relative_to(self.base)
            top = rel.parts[0] if rel.parts else "."
            if top not in self.cfg.allow_subdirs:
                self.audit.log("ERROR", "write_blocked_outside_allowed", path=str(rp), mode=mode, allowed=self.cfg.allow_subdirs)
                raise SafetyViolation(f"Запись разрешена только в {self.cfg.allow_subdirs}, путь: {rp}")
        self.audit.log("INFO", "file_open", path=str(rp), mode=mode)
        return open(rp, mode, **kw)

    def safe_mkdir(self, p: Union[str, Path], parents: bool = True, exist_ok: bool = True) -> Path:
        rp = self.ensure_inside(p)
        rel = rp.relative_to(self.base)
        top = rel.parts[0] if rel.parts else "."
        if top not in self.cfg.allow_subdirs:
            self.audit.log("ERROR", "mkdir_blocked", path=str(rp), allowed=self.cfg.allow_subdirs)
            raise SafetyViolation(f"Создание директорий разрешено только в {self.cfg.allow_subdirs}")
        rp.mkdir(parents=parents, exist_ok=exist_ok)
        self.audit.log("INFO", "mkdir", path=str(rp))
        return rp


# ====================== Очистка переменных окружения ==========================

class EnvSanitizer:
    def __init__(self, cfg: SafetyConfig, audit: SafetyAudit) -> None:
        self.cfg = cfg
        self.audit = audit

    def build_env(self, extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        env: Dict[str, str] = {}
        for k in self.cfg.env_allowlist:
            if k in os.environ:
                env[k] = str(os.environ[k])
        # overrides
        for k, v in self.cfg.env_overrides.items():
            env[k] = str(v)
        # extras
        if extra:
            for k, v in extra.items():
                if k in self.cfg.env_allowlist:
                    env[k] = str(v)
        self.audit.log("INFO", "env_sanitized", keys=list(env.keys()))
        return env


# ============================ Сетевая изоляция ================================

class _NetworkBlocker:
    """
    Блокирует все сетевые подключения в рамках активного контекста.
    Переопределяет socket.socket на заглушку.
    """
    def __init__(self, audit: SafetyAudit) -> None:
        self._orig_socket = socket.socket
        self._audit = audit

    def __enter__(self):
        audit = self._audit

        class _DenySocket(socket.socket):  # type: ignore[misc]
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                audit.log("ERROR", "network_denied_construct", family=self.family, type=self.type)

            def connect(self, *a, **kw):  # type: ignore[override]
                audit.log("ERROR", "network_connect_blocked", args=str(a), kwargs=str(kw))
                raise SafetyViolation("Сетевые подключения заблокированы")

            def connect_ex(self, *a, **kw):  # type: ignore[override]
                audit.log("ERROR", "network_connect_ex_blocked", args=str(a), kwargs=str(kw))
                return 111  # ECONNREFUSED

            def send(self, *a, **kw):  # type: ignore[override]
                audit.log("ERROR", "network_send_blocked")
                raise SafetyViolation("Сеть запрещена")

            def recv(self, *a, **kw):  # type: ignore[override]
                audit.log("ERROR", "network_recv_blocked")
                raise SafetyViolation("Сеть запрещена")

        socket.socket = _DenySocket  # type: ignore[assignment]
        self._audit.log("INFO", "network_blocked_on")
        return self

    def __exit__(self, exc_type, exc, tb):
        socket.socket = self._orig_socket  # type: ignore[assignment]
        self._audit.log("INFO", "network_blocked_off")


# ============================== Лимиты ресурсов ===============================

class ResourceLimiter:
    def __init__(self, cfg: SafetyConfig, audit: SafetyAudit) -> None:
        self.cfg = cfg
        self.audit = audit

    @contextlib.contextmanager
    def limits(self):
        """
        Применяет лимиты ресурсов для текущего процесса (Unix) и создаёт
        контроль wall-clock таймаута для любых платформ.
        """
        timer = None
        # Unix resource limits
        unix_ok = hasattr(resource, "setrlimit")
        if unix_ok:
            # CPU time
            resource.setrlimit(resource.RLIMIT_CPU, (self.cfg.cpu_seconds, self.cfg.cpu_seconds))
            # Max resident set size (RSS) — не все ОС поддерживают строго
            if hasattr(resource, "RLIMIT_AS"):
                bytes_limit = int(self.cfg.rss_megabytes * 1024 * 1024)
                resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
            # Open files
            if hasattr(resource, "RLIMIT_NOFILE"):
                resource.setrlimit(resource.RLIMIT_NOFILE, (self.cfg.nofile, self.cfg.nofile))
            # File size
            if hasattr(resource, "RLIMIT_FSIZE"):
                fs_bytes = int(self.cfg.fsize_megabytes * 1024 * 1024)
                resource.setrlimit(resource.RLIMIT_FSIZE, (fs_bytes, fs_bytes))
            self.audit.log("INFO", "unix_limits_applied", cpu=self.cfg.cpu_seconds, rss_mb=self.cfg.rss_megabytes,
                           nofile=self.cfg.nofile, fsize_mb=self.cfg.fsize_megabytes)
        else:
            self.audit.log("WARN", "unix_limits_unavailable")

        # Wall-clock timeout
        stop_flag = threading.Event()

        def killer():
            if not stop_flag.wait(self.cfg.wall_timeout_seconds):
                self.audit.log("ERROR", "wall_timeout_exceeded", seconds=self.cfg.wall_timeout_seconds)
                # жёсткая остановка процесса
                if hasattr(signal, "SIGKILL"):
                    os.kill(os.getpid(), signal.SIGKILL)  # type: ignore[attr-defined]
                else:
                    os._exit(137)  # Last resort

        timer = threading.Thread(target=killer, daemon=True)
        timer.start()
        try:
            yield
        finally:
            stop_flag.set()
            if timer:
                timer.join(timeout=1.0)
            self.audit.log("INFO", "limits_released")


# ======================= Проверка команд и аргументов =========================

class ExecPolicy:
    def __init__(self, cfg: SafetyConfig, audit: SafetyAudit) -> None:
        self.cfg = cfg
        self.audit = audit

    def validate_command(self, argv: Sequence[str]) -> None:
        if not argv:
            raise SafetyViolation("Пустая команда запрещена")
        bin_name = Path(argv[0]).name.lower()

        if self.cfg.allowed_binaries and bin_name not in {b.lower() for b in self.cfg.allowed_binaries}:
            self.audit.log("ERROR", "binary_not_in_allowlist", binary=bin_name, allow=self.cfg.allowed_binaries)
            raise SafetyViolation(f"Бинарь запрещён: {bin_name} (не в allowlist)")

        if bin_name in {b.lower() for b in self.cfg.denied_binaries}:
            self.audit.log("ERROR", "binary_in_denylist", binary=bin_name)
            raise SafetyViolation(f"Бинарь запрещён: {bin_name}")

        # args scanning
        for a in argv[1:]:
            s = " ".join(argv)
            for pat in self.cfg.denied_args_patterns:
                if pat.search(a):
                    self.audit.log("ERROR", "arg_pattern_denied", arg=a, pattern=str(pat.pattern), cmd=s)
                    raise SafetyViolation(f"Запрещённый аргумент: {a}")

        self.audit.log("INFO", "command_allowed", argv=list(argv))


# =========================== Песочница и декоратор ============================

class Sandbox:
    """
    Комбинирует:
    - Конфайнмент файловых операций
    - Сетевую блокировку
    - Лимиты ресурсов
    - Аудит
    """
    def __init__(self, cfg: SafetyConfig) -> None:
        self.cfg = cfg
        self.audit = SafetyAudit(cfg)
        self.paths = PathConfiner(cfg, self.audit)
        self.env = EnvSanitizer(cfg, self.audit)
        self.exec_policy = ExecPolicy(cfg, self.audit)
        self._net_ctx: Optional[_NetworkBlocker] = None
        self._res_ctx = ResourceLimiter(cfg, self.audit)

    @contextlib.contextmanager
    def activate(self):
        with self._res_ctx.limits():
            if self.cfg.disable_network:
                self._net_ctx = _NetworkBlocker(self.audit)
                self._net_ctx.__enter__()
            try:
                yield self
            finally:
                if self._net_ctx:
                    self._net_ctx.__exit__(None, None, None)

    def close(self) -> None:
        self.audit.close()


def safety_guard(cfg: SafetyConfig) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Декоратор для безопасного выполнения шага:
    - Включает песочницу, аудит и лимиты.
    - Перехватывает исключения и нормализует их в SafetyViolation при strict=True.
    """
    def outer(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sandbox = Sandbox(cfg)
            with sandbox.activate():
                sandbox.audit.log("INFO", "step_start", func=func.__name__)
                try:
                    result = func(sandbox, *args, **kwargs)
                    sandbox.audit.log("INFO", "step_success", func=func.__name__)
                    return result
                except SafetySoftViolation as e:
                    sandbox.audit.log("WARN", "step_soft_violation", func=func.__name__, error=str(e))
                    if cfg.strict:
                        raise SafetyViolation(str(e))
                    return None
                except SafetyViolation as e:
                    sandbox.audit.log("ERROR", "step_violation", func=func.__name__, error=str(e))
                    raise
                except Exception as e:
                    sandbox.audit.log("ERROR", "step_exception", func=func.__name__, error=str(e), type=type(e).__name__)
                    if cfg.strict:
                        raise SafetyViolation(f"Исключение шага: {e}")
                    return None
                finally:
                    sandbox.audit.log("INFO", "step_end", func=func.__name__)
                    sandbox.close()
        return wrapper
    return outer


# =============================== Публичные API =================================

__all__ = [
    "SafetyViolation",
    "SafetySoftViolation",
    "SafetyConfig",
    "SafetyAudit",
    "PathConfiner",
    "EnvSanitizer",
    "ExecPolicy",
    "ResourceLimiter",
    "Sandbox",
    "safety_guard",
]

# ============================== Примеры интеграции =============================
# Ниже — иллюстративные фрагменты (не исполняются автоматически).
# Оставлены для разработчиков, чтобы понимать ожидаемый контракт.
#
# from pathlib import Path
#
# cfg = SafetyConfig(
#     base_dir=Path(tempfile.gettempdir()) / "advemu_safe",
#     allowed_binaries=("echo", "cat"),
# )
#
# @safety_guard(cfg)
# def step_list_artifacts(sb: Sandbox, subdir: str = "artifacts") -> List[str]:
#     p = sb.paths.safe_mkdir(sb.paths.base / subdir)
#     return [str(x) for x in p.glob("*")]
#
# @safety_guard(cfg)
# def step_write_file(sb: Sandbox, relpath: str, data: bytes) -> str:
#     # запись только в разрешённые поддиректории
#     fp = sb.paths.base / "artifacts" / relpath
#     with sb.paths.safe_open(fp, "wb") as f:
#         f.write(data)
#     return str(fp)
