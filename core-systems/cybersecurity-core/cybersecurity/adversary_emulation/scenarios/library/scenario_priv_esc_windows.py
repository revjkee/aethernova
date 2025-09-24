# cybersecurity-core/cybersecurity/adversary_emulation/scenarios/library/scenario_priv_esc_windows.py
# -*- coding: utf-8 -*-
"""
Windows Privilege Escalation Defensive Audit Scenario (Safe / Non-Exploit)

Назначение:
    Промышленный, безопасный для запуска сценарий аудита конфигураций Windows,
    связанных с рисками эскалации привилегий. Сценарий ИСКЛЮЧИТ эксплойт-действия.
    Только сбор артефактов, проверка настроек и отчёт о рисках.

Ключевые свойства:
    - Только чтение конфигурации (read-only), без модификаций.
    - Вычислимые метрики риска (Low/Medium/High/Critical).
    - Отчёт в JSON + человекочитаемый вывод.
    - Таймауты, параллельное выполнение, изоляция команд.
    - Логи с ротацией (по умолчанию %PROGRAMDATA%/CyberAudit/logs/).
    - Явные проверки платформы (запуск только на Windows).
    - Без внешних зависимостей (стандартная библиотека Python).
    - Удобная CLI-обёртка для интеграции в пайплайны CI/CD/IR/BlueTeam.

Важное замечание безопасности:
    Сценарий не выполняет эксплойтов и не даёт инструкций по эксплуатации уязвимостей.
    Использовать только на системах, где у вас есть законное разрешение владельца.

Справочные материалы (для каждой проверки приведены официальные источники — см. ниже в описаниях):
    [MS-UAC]  Microsoft Docs: UAC policy keys (EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop)
    [CIS-WIN] CIS Microsoft Windows Benchmark (разделы по UAC, правам, службам, политикам)
    [MITRE-PE] MITRE ATT&CK Privilege Escalation matrix (Tactics/Techniques overview)
    [MITRE-T1548] Abuse Elevation Control Mechanism
    [MITRE-T1574.009] Hijack Execution Flow: Path Interception by Unquoted Path
    [MITRE-T1068] Exploitation for Privilege Escalation (общее описание, без эксплуатационных деталей)
    [MS-Installer] AlwaysInstallElevated policy keys
    [MS-SDDL] Service Control Manager security descriptors (SDDL)

Ссылки:
    MS-UAC:
        https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/how-it-works
        https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/user-account-control-group-policy-and-registry-key-settings
    CIS-WIN:
        https://www.cisecurity.org/benchmark/microsoft_windows
    MITRE-PE:
        https://attack.mitre.org/tactics/TA0004/
    MITRE-T1548:
        https://attack.mitre.org/techniques/T1548/
    MITRE-T1574.009:
        https://attack.mitre.org/techniques/T1574/009/
    MITRE-T1068:
        https://attack.mitre.org/techniques/T1068/
    MS-Installer (AlwaysInstallElevated):
        https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/always-install-elevated
    MS-SDDL:
        https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format

Все утверждения в отчёте основаны на проверяемых данных, извлечённых локально, и интерпретируются в соответствии с указанными источниками. Эксплуатационных рекомендаций не приводится.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


__version__ = "1.2.0"
__scenario_id__ = "WIN-PRIVESC-AUDIT-SAFE"
__scenario_name__ = "Windows Privilege Escalation Defensive Audit (Safe)"
__vendor__ = "Aethernova Cybersecurity Core"
__license__ = "Apache-2.0"


# ------------------------------ Utilities & Types ------------------------------


@dataclasses.dataclass
class CheckResult:
    key: str
    title: str
    description: str
    risk: str
    rationale: str
    evidence: Dict[str, Any]
    references: List[str]
    ok: bool
    duration_ms: int


@dataclasses.dataclass
class ScenarioReport:
    scenario_id: str
    scenario_name: str
    version: str
    vendor: str
    timestamp_utc: str
    host: str
    os: str
    username: str
    checks: List[CheckResult]
    summary: Dict[str, Any]


class TimeoutExpired(Exception):
    pass


class CommandRunner:
    """
    Безопасный исполнитель команд ОС с таймаутом, ограничением окружения и сбором stdout/stderr.
    Не выполняет разрушительных действий — ответственность за передаваемые команды на вызывающем коде.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def run(self, cmd: List[str]) -> Tuple[int, str, str, int]:
        """
        Возвращает: (exit_code, stdout, stderr, duration_ms)
        """
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                shell=False,
                env=self._safe_env(),
                creationflags=self._creation_flags(),
            )

            timer = threading.Timer(self.timeout, self._kill_process, [proc])
            timer.start()
            stdout, stderr = proc.communicate()
            timer.cancel()
            duration = int((time.monotonic() - start) * 1000)
            return proc.returncode, stdout or "", stderr or "", duration
        except FileNotFoundError as e:
            duration = int((time.monotonic() - start) * 1000)
            return 127, "", str(e), duration
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            return 1, "", f"Command error: {e}", duration

    @staticmethod
    def _kill_process(proc: subprocess.Popen) -> None:
        with contextlib_suppressed(Exception):
            if platform.system().lower() == "windows":
                proc.kill()
            else:
                os.kill(proc.pid, signal.SIGKILL)

    @staticmethod
    def _safe_env() -> Dict[str, str]:
        env = os.environ.copy()
        # Минимизируем влияние внешних переменных на поведение системных утилит
        env.pop("PYTHONPATH", None)
        env.pop("VIRTUAL_ENV", None)
        env["LANG"] = "C"
        env["LC_ALL"] = "C"
        return env

    @staticmethod
    def _creation_flags() -> int:
        if platform.system().lower() == "windows":
            # CREATE_NO_WINDOW = 0x08000000
            return 0x08000000
        return 0


class contextlib_suppressed:
    """Упрощённый suppress без импорта contextlib, чтобы держать stdlib-минимум."""
    def __init__(self, *exceptions):
        self.exceptions = exceptions or (Exception,)

    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, self.exceptions)


# ------------------------------ Logging ------------------------------


def build_logger(level: str = "INFO") -> logging.Logger:
    log_dir = Path(os.environ.get("PROGRAMDATA", Path.cwd())) / "CyberAudit" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "win_privesc_audit.log"

    logger = logging.getLogger("win_privesc_audit")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    rfh = RotatingFileHandler(str(log_file), maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
    rfh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(rfh)

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(sh)

    return logger


# ------------------------------ Risk helpers ------------------------------


def risk_max(*levels: str) -> str:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    inv = {v: k for k, v in order.items()}
    return inv[max(order.get(l, 0) for l in levels)]


def normalize_bool_str(val: Optional[str]) -> Optional[bool]:
    if val is None:
        return None
    v = val.strip().lower()
    if v in ("1", "true", "yes", "on", "enabled", "enable", "enablelua"):
        return True
    if v in ("0", "false", "no", "off", "disabled", "disable"):
        return False
    return None


# ------------------------------ Core Checks (Windows only) ------------------------------


class WindowsPrivEscAudit:
    """
    Реализует набор безопасных проверок, отражённых в официальных источниках:

    - UAC ключи реестра и политика (MS-UAC, CIS-WIN) — см. ссылки в модуле.
    - AlwaysInstallElevated (MS-Installer) — известный риск, если HKLM/HKCU = 1.
    - Некавыченные пути служб (MITRE-T1574.009) — индикатор риска при пробелах.
    - Потенциально небезопасные ACL для системных путей (CIS-WIN).
    - Переменная PATH содержит каталоги с правами на запись для обычных пользователей (CIS-WIN).
    - Базовая инвентаризация прав пользователя (информативно; MS Docs).

    Данный класс НЕ выполняет эксплуатационных действий.
    """

    def __init__(self, runner: CommandRunner, logger: logging.Logger):
        self.runner = runner
        self.logger = logger

    # ---- System / Identity ----

    def check_system_identity(self) -> CheckResult:
        start = time.monotonic()
        os_info = {}
        uname = platform.uname()
        os_info["system"] = uname.system
        os_info["release"] = uname.release
        os_info["version"] = uname.version
        os_info["node"] = uname.node

        # systeminfo даёт дополнительные сведения (локализовано)
        code, out, err, dur = self.runner.run(["cmd.exe", "/c", "systeminfo"])
        if code == 0:
            # Сбор основных полей без привязки к локали
            os_info["systeminfo_present"] = True
            os_info["systeminfo_len"] = len(out)
        else:
            os_info["systeminfo_present"] = False
            os_info["systeminfo_error"] = err.strip()

        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="system.identity",
            title="Системная идентификация",
            description="Сбор общих сведений о системе (безопасная инвентаризация).",
            risk="INFO",
            rationale="Инвентаризация без влияния на конфигурацию. Используется как контекст для остальных проверок.",
            evidence=os_info,
            references=[
                "https://learn.microsoft.com/windows/client-management/system-information",
            ],
            ok=True,
            duration_ms=duration_ms,
        )

    # ---- UAC ----

    def check_uac_policy(self) -> CheckResult:
        """
        Проверка ключей реестра UAC:
            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
                EnableLUA (1 = UAC включён)
                ConsentPromptBehaviorAdmin (0..5; 2/5 более строгие)
                PromptOnSecureDesktop (1 = запросы на защищённом рабочем столе)

        Интерпретация согласно MS-UAC и CIS-WIN. Безопасные настройки: EnableLUA=1; PromptOnSecureDesktop=1.
        """
        start = time.monotonic()
        evidence = {}

        def reg_query(name: str) -> Tuple[Optional[str], Optional[str]]:
            cmd = ["reg.exe", "query",
                   r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", name]
            code, out, err, _ = self.runner.run(cmd)
            if code == 0:
                m = re.search(rf"{re.escape(name)}\s+REG_\w+\s+(.+)$", out, re.IGNORECASE | re.MULTILINE)
                if m:
                    return m.group(1).strip(), None
                return None, "ValueNotFound"
            return None, err.strip() or "RegQueryFailed"

        enable_lua, err1 = reg_query("EnableLUA")
        consent_admin, err2 = reg_query("ConsentPromptBehaviorAdmin")
        secure_desktop, err3 = reg_query("PromptOnSecureDesktop")

        evidence["EnableLUA"] = enable_lua if err1 is None else f"ERROR:{err1}"
        evidence["ConsentPromptBehaviorAdmin"] = consent_admin if err2 is None else f"ERROR:{err2}"
        evidence["PromptOnSecureDesktop"] = secure_desktop if err3 is None else f"ERROR:{err3}"

        # Оценка риска
        risk = "LOW"
        ok = True
        rationale = []
        el = normalize_bool_str(enable_lua)
        if el is False:
            risk, ok = "HIGH", False
            rationale.append("EnableLUA=0 (UAC отключён) — MS-UAC, CIS-WIN.")
        if normalize_bool_str(secure_desktop) is False:
            risk = risk_max(risk, "MEDIUM")
            ok = False
            rationale.append("PromptOnSecureDesktop=0 — менее безопасно (MS-UAC, CIS-WIN).")

        if not rationale:
            rationale.append("Ключевые UAC-настройки не указывают на явные риски.")

        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="uac.policy",
            title="Политика UAC (ключи реестра)",
            description="Анализ базовых ключей UAC: EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop.",
            risk=risk,
            rationale="; ".join(rationale),
            evidence=evidence,
            references=[
                "https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/user-account-control-group-policy-and-registry-key-settings",
                "https://www.cisecurity.org/benchmark/microsoft_windows",
            ],
            ok=ok,
            duration_ms=duration_ms,
        )

    # ---- AlwaysInstallElevated ----

    def check_always_install_elevated(self) -> CheckResult:
        """
        Проверка AlwaysInstallElevated:
            HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
            HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
        Наличие значения 1 в обоих местах — повышенный риск согласно MS-Installer и CIS.
        """
        start = time.monotonic()
        evidence = {}

        def reg_get(hive: str) -> Optional[str]:
            code, out, err, _ = self.runner.run([
                "reg.exe", "query",
                rf"{hive}\Software\Policies\Microsoft\Windows\Installer",
                "/v", "AlwaysInstallElevated"
            ])
            if code != 0:
                return None
            m = re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
            return str(int(m.group(1), 16)) if m else None

        hklm = reg_get("HKLM")
        hkcu = reg_get("HKCU")

        evidence["HKLM"] = hklm if hklm is not None else "NotSet"
        evidence["HKCU"] = hkcu if hkcu is not None else "NotSet"

        risk, ok = "LOW", True
        rationale = []
        if hklm == "1" and hkcu == "1":
            risk, ok = "HIGH", False
            rationale.append("AlwaysInstallElevated=1 в HKLM и HKCU — повышенный риск (MS-Installer, CIS).")
        elif hklm == "1" or hkcu == "1":
            risk, ok = "MEDIUM", False
            rationale.append("AlwaysInstallElevated=1 установлен только в одном из ульев — умеренный риск.")

        if not rationale:
            rationale.append("AlwaysInstallElevated не установлен или выключен.")

        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="installer.always_install_elevated",
            title="Политика AlwaysInstallElevated",
            description="Проверка значений AlwaysInstallElevated (HKLM/HKCU) согласно MS-Installer.",
            risk=risk,
            rationale="; ".join(rationale),
            evidence=evidence,
            references=[
                "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/always-install-elevated",
                "https://www.cisecurity.org/benchmark/microsoft_windows",
            ],
            ok=ok,
            duration_ms=duration_ms,
        )

    # ---- Services: Unquoted Paths ----

    def check_services_unquoted_paths(self) -> CheckResult:
        """
        Некавыченные пути служб с пробелами — индикатор риска (MITRE-T1574.009).
        Проверяем вывеску путей через WMIC (совместимо) или sc qc.
        """
        start = time.monotonic()
        evidence: Dict[str, Any] = {"suspicious": []}
        suspicious = []

        # WMIC может быть отсутствовать в новых версиях; fallback на sc qc per-service.
        code, out, err, _ = self.runner.run(["wmic.exe", "service", "get", "Name,PathName,StartMode"])
        if code == 0 and out.strip():
            lines = out.splitlines()
            # Формат: Name  PathName  StartMode
            for line in lines[1:]:
                parts = [p.strip() for p in re.split(r"\s{2,}", line.strip()) if p.strip()]
                if len(parts) < 2:
                    continue
                # Пытаемся найти PathName по эвристике: содержит \ или :
                path_candidate = None
                for p in parts:
                    if "\\" in p or ":" in p:
                        path_candidate = p
                        break
                if not path_candidate:
                    continue
                if self._looks_unquoted_with_spaces(path_candidate):
                    suspicious.append({"path": path_candidate, "source": "wmic"})
        else:
            # Fallback: просканировать список служб и вызвать sc qc по каждой
            code2, out2, err2, _ = self.runner.run(["sc.exe", "query", "type=", "service", "state=", "all"])
            if code2 == 0:
                names = re.findall(r"SERVICE_NAME:\s+([^\r\n]+)", out2)
                for name in names[:512]:  # ограничим до 512 служб для производительности
                    c, o, e, _ = self.runner.run(["sc.exe", "qc", name])
                    if c == 0:
                        m = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", o)
                        if m:
                            path = m.group(1).strip()
                            if self._looks_unquoted_with_spaces(path):
                                suspicious.append({"service": name, "path": path, "source": "sc qc"})

        evidence["suspicious"] = suspicious
        count = len(suspicious)
        risk = "LOW" if count == 0 else ("MEDIUM" if count <= 3 else "HIGH")
        ok = count == 0
        rationale = (
            "Обнаружены некавыченные пути служб с пробелами — индикатор риска (MITRE-T1574.009)."
            if not ok else
            "Некавыченные пути служб с пробелами не обнаружены."
        )

        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="services.unquoted_paths",
            title="Службы: некавыченные пути с пробелами",
            description="Поиск путей служб без кавычек (при наличии пробелов) — индикатор риска перехвата пути.",
            risk=risk,
            rationale=rationale,
            evidence=evidence,
            references=[
                "https://attack.mitre.org/techniques/T1574/009/",
                "https://www.cisecurity.org/benchmark/microsoft_windows",
            ],
            ok=ok,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _looks_unquoted_with_spaces(path: str) -> bool:
        p = path.strip()
        if not p:
            return False
        # Игнорируем уже заключённые в кавычки значения
        if p.startswith('"') and p.endswith('"'):
            return False
        # Проверяем наличие пробелов в потенциальной части пути к exe
        has_space = " " in p
        # Наличие .exe или .bat / .cmd — эвристика
        has_exe = re.search(r"\.(exe|bat|cmd)\b", p, flags=re.IGNORECASE) is not None
        return has_space and has_exe

    # ---- ACL sanity for common dirs ----

    def check_common_paths_acl(self) -> CheckResult:
        """
        Базовая проверка прав доступа (icacls) для чувствительных каталогов.
        Ищем потенциально небезопасные ACL (Everyone:(F) или BUILTIN\Users:(F)/(M) и т.п.).
        Список директорий эвристический и консервативный.
        """
        start = time.monotonic()
        targets = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\Users\Public",
            r"C:\Temp",
        ]
        patterns = [
            r"Everyone:\(F\)", r"Everyone:\(M\)",
            r"BUILTIN\\Users:\(F\)", r"BUILTIN\\Users:\(M\)",
        ]
        evidence = {"flags": []}
        risk = "LOW"
        ok = True

        for t in targets:
            if not os.path.exists(t):
                continue
            code, out, err, _ = self.runner.run(["icacls.exe", t])
            if code != 0:
                evidence["flags"].append({"path": t, "error": err.strip() or "icacls failed"})
                # не повышаем риск из-за недоступности
                continue
            text = out.replace("\r", "")
            for pat in patterns:
                if re.search(pat, text, flags=re.IGNORECASE):
                    evidence["flags"].append({"path": t, "pattern": pat})
                    risk = risk_max(risk, "MEDIUM")
                    ok = False

        if ok:
            rationale = "Не обнаружены очевидные небезопасные ACL по заданным эвристикам."
        else:
            rationale = "Обнаружены потенциально небезопасные ACL (Everyone/Users с F/M) — свериться с CIS-WIN."

        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="filesystem.common_acl",
            title="ACL системных директорий (базовая эвристика)",
            description="Проверка базовых ACL для общих директорий через icacls (индикаторы небезопасности).",
            risk=risk,
            rationale=rationale,
            evidence=evidence,
            references=[
                "https://www.cisecurity.org/benchmark/microsoft_windows",
                "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/",
            ],
            ok=ok,
            duration_ms=duration_ms,
        )

    # ---- PATH writable dirs ----

    def check_path_writable_dirs(self) -> CheckResult:
        """
        Проверка элементов PATH на запись текущим пользователем.
        Наличие директории PATH с правами записи для непривилегированного пользователя — индикатор риска.
        Основано на общем принципе поиска небезопасных путей загрузки (CIS-WIN).
        """
        start = time.monotonic()
        path_env = os.environ.get("PATH", "")
        entries = [e.strip('"') for e in path_env.split(os.pathsep) if e.strip()]
        writable = []
        for e in entries:
            try:
                if os.path.isdir(e) and os.access(e, os.W_OK):
                    writable.append(e)
            except Exception:
                continue

        risk = "LOW" if not writable else ("MEDIUM" if len(writable) <= 2 else "HIGH")
        ok = len(writable) == 0
        evidence = {"writable_path_entries": writable, "total_entries": len(entries)}
        rationale = (
            "В PATH обнаружены директории, доступные на запись текущему пользователю — индикатор риска."
            if not ok else
            "Директории PATH не доступны на запись текущему пользователю."
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="environment.path_writable",
            title="PATH: директории с правами на запись",
            description="Анализ окружения PATH на предмет директорий, доступных на запись пользователю.",
            risk=risk,
            rationale=rationale,
            evidence=evidence,
            references=[
                "https://www.cisecurity.org/benchmark/microsoft_windows",
            ],
            ok=ok,
            duration_ms=duration_ms,
        )

    # ---- User token info (informational) ----

    def check_user_groups_privs(self) -> CheckResult:
        """
        Информативная проверка: whoami /groups (безопасно) даёт представление о группах/привилегиях токена.
        Не даёт эксплуатационных указаний, служит контекстом.
        """
        start = time.monotonic()
        code, out, err, _ = self.runner.run(["whoami.exe", "/groups"])
        evidence: Dict[str, Any] = {}
        ok = code == 0
        if ok:
            evidence["groups_len"] = len(out.splitlines())
            # Укажем ключевые привилегии, если встречаются в выводе (информативно)
            flags = []
            for key in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege",
                        "SeRestorePrivilege", "SeTakeOwnershipPrivilege"):
                if key.lower() in out.lower():
                    flags.append(key)
            evidence["notable_privileges"] = flags
        else:
            evidence["error"] = err.strip() or "whoami failed"

        # Это информативная проверка, не оценочная
        duration_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(
            key="identity.user_groups",
            title="Группы и привилегии пользователя (информативно)",
            description="whoami /groups — инвентаризация групп/привилегий токена.",
            risk="INFO",
            rationale="Справочная информация; см. MS Docs по привилегиям и маркерам доступа.",
            evidence=evidence,
            references=[
                "https://learn.microsoft.com/windows/security/identity-protection/access-control/access-tokens",
                "https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-token-rights",
            ],
            ok=ok,
            duration_ms=duration_ms,
        )


# ------------------------------ Orchestrator ------------------------------


def run_audit(max_workers: int, timeout: int, log_level: str) -> ScenarioReport:
    assert platform.system().lower() == "windows", "Сценарий поддерживается только на Windows."
    logger = build_logger(log_level)
    runner = CommandRunner(timeout=timeout)
    audit = WindowsPrivEscAudit(runner, logger)

    username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

    checks = [
        ("system.identity", audit.check_system_identity),
        ("uac.policy", audit.check_uac_policy),
        ("installer.always_install_elevated", audit.check_always_install_elevated),
        ("services.unquoted_paths", audit.check_services_unquoted_paths),
        ("filesystem.common_acl", audit.check_common_paths_acl),
        ("environment.path_writable", audit.check_path_writable_dirs),
        ("identity.user_groups", audit.check_user_groups_privs),
    ]

    results: List[CheckResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {ex.submit(fn): key for key, fn in checks}
        for fut in concurrent.futures.as_completed(fut_map):
            key = fut_map[fut]
            try:
                res: CheckResult = fut.result()
                results.append(res)
            except Exception as e:
                results.append(
                    CheckResult(
                        key=key,
                        title=f"{key} (ошибка)",
                        description="Исключение при выполнении проверки.",
                        risk="INFO",
                        rationale=str(e),
                        evidence={},
                        references=[],
                        ok=False,
                        duration_ms=0,
                    )
                )

    # Итоги
    risk_overall = "INFO"
    failed = 0
    for r in results:
        risk_overall = risk_max(risk_overall, r.risk)
        if not r.ok:
            failed += 1

    uname = platform.uname()
    report = ScenarioReport(
        scenario_id=__scenario_id__,
        scenario_name=__scenario_name__,
        version=__version__,
        vendor=__vendor__,
        timestamp_utc=datetime.utcnow().isoformat(timespec="seconds") + "Z",
        host=uname.node,
        os=f"{uname.system} {uname.release} ({uname.version})",
        username=username,
        checks=sorted(results, key=lambda x: x.key),
        summary={
            "overall_risk": risk_overall,
            "total_checks": len(results),
            "failed_checks": failed,
        },
    )
    return report


def printable_report(rep: ScenarioReport) -> str:
    lines = []
    lines.append(f"Scenario: {rep.scenario_name} [{rep.scenario_id}] v{rep.version} by {rep.vendor}")
    lines.append(f"Timestamp (UTC): {rep.timestamp_utc}")
    lines.append(f"Host: {rep.host} | OS: {rep.os} | User: {rep.username}")
    lines.append(f"Summary: risk={rep.summary['overall_risk']}, checks={rep.summary['total_checks']}, failed={rep.summary['failed_checks']}")
    lines.append("-" * 80)
    for c in rep.checks:
        lines.append(f"[{c.key}] {c.title}")
        lines.append(f"  Risk: {c.risk} | OK: {c.ok} | Duration: {c.duration_ms}ms")
        lines.append(f"  Description: {c.description}")
        lines.append(f"  Rationale: {c.rationale}")
        if c.evidence:
            ev_json = json.dumps(c.evidence, ensure_ascii=False, indent=2)
            for line in ev_json.splitlines():
                lines.append(f"  {line}")
        if c.references:
            lines.append("  References:")
            for ref in c.references:
                lines.append(f"    - {ref}")
        lines.append("")
    return "\n".join(lines)


def to_json(rep: ScenarioReport) -> str:
    return json.dumps(dataclasses.asdict(rep), ensure_ascii=False, indent=2)


# ------------------------------ CLI ------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="scenario_priv_esc_windows",
        description="Безопасный аудит рисков эскалации привилегий в Windows (read-only).",
    )
    p.add_argument("--json", action="store_true", help="Вывести отчёт в формате JSON.")
    p.add_argument("--output", type=str, default="", help="Путь для сохранения отчёта (JSON).")
    p.add_argument("--timeout", type=int, default=15, help="Таймаут на одну команду (сек).")
    p.add_argument("--workers", type=int, default=6, help="Количество параллельных воркеров.")
    p.add_argument("--log-level", type=str, default="INFO", help="Уровень логирования (INFO/DEBUG/WARN/ERROR).")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        if platform.system().lower() != "windows":
            print("Этот сценарий поддерживается только на Windows.", file=sys.stderr)
            return 3
        args = parse_args(argv)
        report = run_audit(max_workers=max(1, args.workers), timeout=max(1, args.timeout), log_level=args.log_level)

        if args.json or args.output:
            data = to_json(report)
            if args.output:
                out_path = Path(args.output).expanduser().resolve()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(data, encoding="utf-8")
                print(str(out_path))
            else:
                print(data)
        else:
            print(printable_report(report))

        return 0
    except AssertionError as ae:
        print(f"Ошибка: {ae}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
