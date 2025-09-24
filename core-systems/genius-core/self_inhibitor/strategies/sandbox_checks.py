# -*- coding: utf-8 -*-
"""
Sandbox Checks Strategy — промышленный набор проверок изоляции/ресурсных ограничений.

OS: Linux (best-effort на других платформах с graceful degradation)
Deps: stdlib only

Что проверяет:
- Пользователь не root (UID != 0) [config.allow_root]
- seccomp включен (Seccomp: 2 в /proc/self/status) [config.require_seccomp]
- no_new_privs активен (NoNewPrivs: 1 в /proc/self/status) [config.require_no_new_privs]
- rlimits заданы (CPU/AS/NOFILE/NPROC/STACK не RLIM_INFINITY) и соответствуют минимальным порогам
- cgroup v2 лимиты: memory.max, pids.max, cpu.max (quota/period) с валидацией порогов
- capabilities сброшены (CapEff пустой или не содержит привилегированные cap) [config.fail_on_caps]
- безопасные флаги монтирования для /proc и /sys (nodev,nosuid,noexec)
- /tmp имеет режим 1777 (world-writable со sticky bit)
- отсутствие «секретных» переменных окружения (AWS/GCP/Token/SSH и т.д.)
- опционально: отключение исходящих соединений (попытка connect к 1.1.1.1:80) [config.require_network_off]

Вывод:
- SandboxReport: список CheckResult {name, status: PASS|WARN|FAIL, severity, message, details}
- .ok / .warnings / .failures / .score (0..1) агрегированные метрики
- .to_json() для логирования/телеметрии

Интеграция:
- Стратегия может вызываться из self_inhibitor.evaluator перед разрешением выполнения.
- При строгом режиме (config.enforce=True) любой FAIL -> блокировка.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import os
import platform
import resource
import socket
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# --------------------------------------------------------------------------------------
# Модель результатов
# --------------------------------------------------------------------------------------

class Status(str, enum.Enum):
    PASS_ = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NA = "NA"  # не применимо/не удалось определить


@dataclass(slots=True, frozen=True)
class CheckResult:
    name: str
    status: Status
    severity: int  # 0..100 (влияет на итоговый score)
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SandboxReport:
    results: List[CheckResult]
    duration_ms: int

    @property
    def ok(self) -> bool:
        return all(r.status in (Status.PASS_, Status.NA) for r in self.results)

    @property
    def warnings(self) -> List[CheckResult]:
        return [r for r in self.results if r.status == Status.WARN]

    @property
    def failures(self) -> List[CheckResult]:
        return [r for r in self.results if r.status == Status.FAIL]

    @property
    def score(self) -> float:
        """
        Итоговый балл 0..1: PASS=1.0, WARN снижает, FAIL сильно снижает.
        """
        if not self.results:
            return 0.0
        score = 1.0
        for r in self.results:
            if r.status == Status.WARN:
                score -= min(0.2, r.severity / 500.0)  # до -0.2 за предупреждения
            elif r.status == Status.FAIL:
                score -= min(0.7, r.severity / 120.0)   # до -0.7 за крит
        return max(0.0, min(1.0, score))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "score": round(self.score, 4),
            "duration_ms": self.duration_ms,
            "results": [dataclasses.asdict(r) for r in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


# --------------------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------------------

@dataclass(slots=True)
class SandboxChecksConfig:
    enforce: bool = True  # при FAIL можно останавливать выполнение на уровне self_inhibitor
    # Требования
    allow_root: bool = False
    require_seccomp: bool = True
    require_no_new_privs: bool = True
    require_network_off: bool = False  # если True, успешное внешнее соединение => FAIL
    fail_on_caps: bool = True

    # Пороговые значения rlimit (минимальные/максимальные)
    min_cpu_time_s: int = 1            # RLIMIT_CPU >= 1
    max_as_bytes: int = 2 * 1024**3    # RLIMIT_AS <= 2 GiB (иначе WARN/FAIL)
    max_nproc: int = 512               # RLIMIT_NPROC <= 512
    max_nofile: int = 4096             # RLIMIT_NOFILE <= 4096
    max_stack_bytes: int = 64 * 1024**2

    # Пороговые значения для cgroups (если доступны)
    max_cgroup_mem_bytes: int = 2 * 1024**3  # memory.max <= 2 GiB
    max_cgroup_pids: int = 512               # pids.max <= 512
    min_cpu_quota_millicores: int = 100      # cpu.max quota >= 0.1 CPU

    # Список запрещенных env переменных
    forbidden_env_keys: Tuple[str, ...] = (
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT",
        "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID",
        "GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK", "SSH_PRIVATE_KEY",
        "OPENAI_API_KEY", "HUGGINGFACEHUB_API_TOKEN", "HF_TOKEN",
    )

# --------------------------------------------------------------------------------------
# Вспомогательные чтения /proc и cgroups
# --------------------------------------------------------------------------------------

def _read_proc_status() -> Dict[str, str]:
    path = Path("/proc/self/status")
    data: Dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()
    except Exception:
        pass
    return data

def _capset_from_hex(hexval: str) -> List[str]:
    """
    Преобразует 64-битную маску CapEff в список имён capabilities.
    Список основных cap (Linux, может различаться по ядру — best-effort).
    """
    try:
        mask = int(hexval, 16)
    except Exception:
        return []
    cap_names = [
        "CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER","CAP_FSETID",
        "CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST","CAP_NET_ADMIN","CAP_NET_RAW",
        "CAP_IPC_LOCK","CAP_IPC_OWNER","CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE","CAP_SYS_PACCT","CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE",
        "CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD","CAP_LEASE",
        "CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP","CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM","CAP_BLOCK_SUSPEND","CAP_AUDIT_READ",
        "CAP_BPF","CAP_CHECKPOINT_RESTORE","CAP_PERFMON","CAP_SYS_BOOT"  # последняя может дублироваться — ok
    ]
    out = []
    for i, name in enumerate(cap_names):
        if mask & (1 << i):
            out.append(name)
    return out

def _read_mount_flags(path: str) -> List[str]:
    """
    Возвращает список флагов монтирования для первого подходящего монтпоинта.
    """
    flags: List[str] = []
    try:
        with open("/proc/self/mountinfo", "r") as f:
            for line in f:
                # mountinfo формата: ... - fstype source options
                # Интересуют options (после " - ")
                if f" {path} " in line or line.strip().endswith(f" {path}"):
                    parts = line.split(" - ", 1)
                    if len(parts) == 2:
                        tail = parts[1]
                        # tail: "fstype source opts\n"
                        opts = tail.split()
                        if len(opts) >= 3:
                            flags = opts[2].split(",")
                            break
    except Exception:
        pass
    return flags

def _cgv2_path() -> Optional[Path]:
    p = Path("/sys/fs/cgroup")
    if p.exists():
        return p
    return None

def _read_cgroup_value(relpath: str) -> Optional[str]:
    base = _cgv2_path()
    if not base:
        return None
    fp = base / relpath
    try:
        return fp.read_text().strip()
    except Exception:
        return None

def _parse_cpu_max(val: str) -> Tuple[Optional[int], Optional[int]]:
    """
    cpu.max: "max" или "<quota> <period>", где quota в мкс.
    Возвращаем (millicores, period).
    """
    if not val:
        return None, None
    if val == "max":
        return None, None
    try:
        quota_us, period_us = [int(x) for x in val.split()]
        if period_us <= 0:
            return None, period_us
        # millicores = quota/period * 1000
        mc = int(quota_us * 1000 / period_us)
        return mc, period_us
    except Exception:
        return None, None

# --------------------------------------------------------------------------------------
# Собственно проверки
# --------------------------------------------------------------------------------------

def check_uid(cfg: SandboxChecksConfig) -> CheckResult:
    uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if uid == 0 and not cfg.allow_root:
        return CheckResult("uid_not_root", Status.FAIL, 90, "Процесс выполняется от root, что запрещено.", {"uid": uid})
    return CheckResult("uid_not_root", Status.PASS_, 5, "UID не root.", {"uid": uid})

def check_seccomp(cfg: SandboxChecksConfig) -> CheckResult:
    st = _read_proc_status()
    val = st.get("Seccomp")
    if val is None:
        return CheckResult("seccomp", Status.WARN if cfg.require_seccomp else Status.NA, 40, "Не удалось определить Seccomp.", {})
    enabled = (val.strip() == "2")
    if cfg.require_seccomp and not enabled:
        return CheckResult("seccomp", Status.FAIL, 85, "Seccomp фильтрация не активна.", {"Seccomp": val})
    return CheckResult("seccomp", Status.PASS_, 10, "Seccomp активен." if enabled else "Seccomp не обязателен и не активен.", {"Seccomp": val})

def check_no_new_privs(cfg: SandboxChecksConfig) -> CheckResult:
    st = _read_proc_status()
    val = st.get("NoNewPrivs")
    if val is None:
        return CheckResult("no_new_privs", Status.WARN if cfg.require_no_new_privs else Status.NA, 35, "Не удалось определить NoNewPrivs.", {})
    on = (val.strip() == "1")
    if cfg.require_no_new_privs and not on:
        return CheckResult("no_new_privs", Status.FAIL, 80, "no_new_privs выключен.", {"NoNewPrivs": val})
    return CheckResult("no_new_privs", Status.PASS_, 10, "no_new_privs включен." if on else "no_new_privs не обязателен.", {"NoNewPrivs": val})

def _rlim(name: str, res: int) -> Tuple[int, int]:
    soft, hard = resource.getrlimit(res)
    return int(soft), int(hard)

def check_rlimits(cfg: SandboxChecksConfig) -> List[CheckResult]:
    out: List[CheckResult] = []
    # CPU
    soft, hard = _rlim("CPU", resource.RLIMIT_CPU)
    if soft == resource.RLIM_INFINITY or soft < cfg.min_cpu_time_s:
        out.append(CheckResult("rlimit_cpu", Status.FAIL, 80, "RLIMIT_CPU не задан или слишком мал.", {"soft": soft, "min": cfg.min_cpu_time_s}))
    else:
        out.append(CheckResult("rlimit_cpu", Status.PASS_, 10, "RLIMIT_CPU установлен.", {"soft": soft}))

    # AS (address space)
    soft, hard = _rlim("AS", resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY or soft > cfg.max_as_bytes:
        out.append(CheckResult("rlimit_as", Status.WARN, 50, "RLIMIT_AS отсутствует или слишком велик.", {"soft": soft, "max": cfg.max_as_bytes}))
    else:
        out.append(CheckResult("rlimit_as", Status.PASS_, 10, "RLIMIT_AS ограничен.", {"soft": soft}))

    # NPROC
    soft, hard = _rlim("NPROC", resource.RLIMIT_NPROC)
    if soft == resource.RLIM_INFINITY or soft > cfg.max_nproc:
        out.append(CheckResult("rlimit_nproc", Status.WARN, 50, "RLIMIT_NPROC отсутствует или слишком велик.", {"soft": soft, "max": cfg.max_nproc}))
    else:
        out.append(CheckResult("rlimit_nproc", Status.PASS_, 10, "RLIMIT_NPROC ограничен.", {"soft": soft}))

    # NOFILE
    soft, hard = _rlim("NOFILE", resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY or soft > cfg.max_nofile:
        out.append(CheckResult("rlimit_nofile", Status.WARN, 35, "RLIMIT_NOFILE слишком велик или не установлен.", {"soft": soft, "max": cfg.max_nofile}))
    else:
        out.append(CheckResult("rlimit_nofile", Status.PASS_, 5, "RLIMIT_NOFILE ограничен.", {"soft": soft}))

    # STACK
    soft, hard = _rlim("STACK", resource.RLIMIT_STACK)
    if soft == resource.RLIM_INFINITY or soft > cfg.max_stack_bytes:
        out.append(CheckResult("rlimit_stack", Status.WARN, 30, "RLIMIT_STACK слишком велик.", {"soft": soft, "max": cfg.max_stack_bytes}))
    else:
        out.append(CheckResult("rlimit_stack", Status.PASS_, 5, "RLIMIT_STACK ограничен.", {"soft": soft}))
    return out

def check_cgroups(cfg: SandboxChecksConfig) -> List[CheckResult]:
    out: List[CheckResult] = []
    # Memory
    mem_raw = _read_cgroup_value("memory.max")
    if mem_raw is None:
        out.append(CheckResult("cgroup_memory", Status.NA, 5, "cgroup memory.max недоступен.", {}))
    elif mem_raw == "max" or (mem_raw.isdigit() and int(mem_raw) > cfg.max_cgroup_mem_bytes):
        out.append(CheckResult("cgroup_memory", Status.WARN, 50, "cgroup memory.max отсутствует или превышает порог.", {"memory.max": mem_raw, "max": cfg.max_cgroup_mem_bytes}))
    else:
        out.append(CheckResult("cgroup_memory", Status.PASS_, 10, "cgroup memory.max ограничен.", {"memory.max": mem_raw}))

    # PIDs
    pids_raw = _read_cgroup_value("pids.max")
    if pids_raw is None:
        out.append(CheckResult("cgroup_pids", Status.NA, 5, "cgroup pids.max недоступен.", {}))
    elif pids_raw == "max" or (pids_raw.isdigit() and int(pids_raw) > cfg.max_cgroup_pids):
        out.append(CheckResult("cgroup_pids", Status.WARN, 45, "cgroup pids.max отсутствует или превышает порог.", {"pids.max": pids_raw, "max": cfg.max_cgroup_pids}))
    else:
        out.append(CheckResult("cgroup_pids", Status.PASS_, 10, "cgroup pids.max ограничен.", {"pids.max": pids_raw}))

    # CPU
    cpu_raw = _read_cgroup_value("cpu.max")
    if cpu_raw is None:
        out.append(CheckResult("cgroup_cpu", Status.NA, 5, "cgroup cpu.max недоступен.", {}))
    else:
        mc, period = _parse_cpu_max(cpu_raw)
        if mc is None:
            out.append(CheckResult("cgroup_cpu", Status.WARN, 35, "cpu.max не ограничен (max).", {"cpu.max": cpu_raw}))
        elif mc < cfg.min_cpu_quota_millicores:
            out.append(CheckResult("cgroup_cpu", Status.WARN, 25, "cpu.max слишком мал — возможны таймауты.", {"millicores": mc, "min": cfg.min_cpu_quota_millicores}))
        else:
            out.append(CheckResult("cgroup_cpu", Status.PASS_, 5, "cpu.max ограничен.", {"millicores": mc, "period_us": period}))
    return out

def check_caps(cfg: SandboxChecksConfig) -> CheckResult:
    st = _read_proc_status()
    val = st.get("CapEff")
    if val is None:
        return CheckResult("capabilities", Status.NA, 10, "Не удалось определить CapEff.", {})
    caps = _capset_from_hex(val)
    if cfg.fail_on_caps and caps:
        return CheckResult("capabilities", Status.FAIL, 85, "Процесс имеет эффективные capabilities.", {"CapEff": val, "caps": caps})
    return CheckResult("capabilities", Status.PASS_, 10, "Capabilities сброшены.", {"CapEff": val, "caps": caps})

def check_mounts() -> List[CheckResult]:
    out: List[CheckResult] = []
    for mp in ("/proc", "/sys"):
        flags = _read_mount_flags(mp)
        needed = {"nodev", "nosuid", "noexec"}
        if not flags:
            out.append(CheckResult(f"mount_flags_{mp}", Status.NA, 10, f"Не удалось прочитать флаги для {mp}.", {}))
            continue
        missing = sorted(list(needed - set(flags)))
        if missing:
            out.append(CheckResult(f"mount_flags_{mp}", Status.WARN, 35, f"{mp} без рекомендуемых флагов: {','.join(missing)}", {"flags": flags}))
        else:
            out.append(CheckResult(f"mount_flags_{mp}", Status.PASS_, 5, f"{mp} смонтирован с безопасными флагами.", {"flags": flags}))
    return out

def check_tmp_mode() -> CheckResult:
    try:
        st = os.stat("/tmp")
        ok = stat.S_ISDIR(st.st_mode) and (st.st_mode & 0o7777) == 0o1777
        if ok:
            return CheckResult("tmp_mode_1777", Status.PASS_, 5, "/tmp имеет режим 1777 (sticky).", {"mode_octal": oct(st.st_mode & 0o7777)})
        return CheckResult("tmp_mode_1777", Status.WARN, 25, "/tmp не имеет режима 1777 — риск удаления чужих файлов.", {"mode_octal": oct(st.st_mode & 0o7777)})
    except Exception as e:
        return CheckResult("tmp_mode_1777", Status.NA, 10, f"Не удалось проверить /tmp: {e}", {})

def check_env(cfg: SandboxChecksConfig) -> List[CheckResult]:
    out: List[CheckResult] = []
    env = os.environ
    found = {k: bool(env.get(k)) for k in cfg.forbidden_env_keys if env.get(k)}
    if found:
        out.append(CheckResult("env_secrets", Status.FAIL, 90, "Обнаружены чувствительные переменные окружения.", {"keys": sorted(found.keys())}))
    else:
        out.append(CheckResult("env_secrets", Status.PASS_, 5, "Секретные переменные отсутствуют.", {}))
    return out

def check_network(cfg: SandboxChecksConfig) -> CheckResult:
    """
    Best-effort «активная» проверка: пытаемся соединиться с 1.1.1.1:80 с таймаутом 200 мс.
    Если соединение успешно, сеть считается доступной.
    """
    addr = ("1.1.1.1", 80)
    reachable = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            s.connect(addr)
            reachable = True
    except Exception:
        reachable = False
    if cfg.require_network_off:
        if reachable:
            return CheckResult("network_off", Status.FAIL, 80, "Сеть доступна, но должна быть отключена.", {"target": f"{addr[0]}:{addr[1]}", "reachable": True})
        return CheckResult("network_off", Status.PASS_, 10, "Сеть отключена (внешние соединения недоступны).", {"reachable": False})
    # Если сеть не обязана быть выключенной — даем WARN только при недоступности (возможна ошибка конфигурации)
    if not reachable:
        return CheckResult("network_reachability", Status.WARN, 10, "Сеть недоступна (возможно, ожидаемо в песочнице).", {"reachable": False})
    return CheckResult("network_reachability", Status.PASS_, 1, "Сеть доступна.", {"reachable": True})

# --------------------------------------------------------------------------------------
# Запуск стратегии
# --------------------------------------------------------------------------------------

def run_checks(cfg: Optional[SandboxChecksConfig] = None) -> SandboxReport:
    cfg = cfg or SandboxChecksConfig()
    start = time.perf_counter()

    results: List[CheckResult] = []
    # Платформа
    sysinfo = f"{platform.system()} {platform.release()}"
    results.append(CheckResult("platform", Status.PASS_, 0, "Сбор информации о системе.", {"platform": sysinfo}))

    # Базовые проверки
    results.append(check_uid(cfg))
    results.append(check_seccomp(cfg))
    results.append(check_no_new_privs(cfg))
    results += check_rlimits(cfg)
    results += check_cgroups(cfg)
    results.append(check_caps(cfg))
    results += check_mounts()
    results.append(check_tmp_mode())
    results += check_env(cfg)
    results.append(check_network(cfg))

    duration_ms = int((time.perf_counter() - start) * 1000)
    return SandboxReport(results=results, duration_ms=duration_ms)

# --------------------------------------------------------------------------------------
# Интеграционная обертка для Self Inhibitor (опционально)
# --------------------------------------------------------------------------------------

@dataclass(slots=True)
class Decision:
    allow: bool
    label: str
    reasons: Tuple[str, ...] = ()
    report: Optional[SandboxReport] = None

def evaluate_sandbox(cfg: Optional[SandboxChecksConfig] = None) -> Decision:
    """
    Высокоуровневый интерфейс: запускает проверки и возвращает решение для self_inhibitor.
    """
    cfg = cfg or SandboxChecksConfig()
    report = run_checks(cfg)
    if cfg.enforce and not report.ok:
        # блокируем при любой критической ошибке
        reasons = tuple(f"{r.name}:{r.message}" for r in report.failures)
        return Decision(allow=False, label="sandbox_violation", reasons=reasons, report=report)
    # допускаем, но можем проставить сниженный trust по score
    return Decision(allow=True, label="sandbox_ok" if report.ok else "sandbox_warn", reasons=tuple(r.message for r in report.warnings), report=report)

# --------------------------------------------------------------------------------------
# Пример запуска
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    rep = run_checks()
    print(rep.to_json())
    # При необходимости — принять решение
    dec = evaluate_sandbox()
    print(json.dumps({
        "allow": dec.allow,
        "label": dec.label,
        "reasons": list(dec.reasons),
        "score": rep.score,
    }, ensure_ascii=False))
