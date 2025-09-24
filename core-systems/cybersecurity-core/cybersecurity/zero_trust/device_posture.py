# cybersecurity-core/cybersecurity/zero_trust/device_posture.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

try:
    import psutil  # type: ignore
except Exception:  # psutil опционален; деградируем при отсутствии
    psutil = None  # type: ignore

# ----------------------------- Константы и утилиты ----------------------------

JSON_SEPARATORS = (",", ":")
ISO = lambda dt: dt.astimezone(timezone.utc).isoformat()

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def host_fingerprint() -> str:
    try:
        mid_paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        for p in mid_paths:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as fh:
                    return fh.read().strip()
    except Exception:
        pass
    raw = f"{socket.gethostname()}|{platform.system()}|{platform.version()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

def redact(text: str) -> str:
    # минимальная редакция токенов
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]+", r"\1***REDACTED***", text)
    text = re.sub(r"(?i)(password|secret|token)\s*[:=]\s*[^\s]+", r"\1=***REDACTED***", text)
    return text

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

# ----------------------------- Безопасный запуск ------------------------------

async def run_cmd(
    *args: str,
    timeout: float = 8.0,
    max_bytes: int = 512_000,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str]:
    """
    Безопасно запускает процесс без shell, возвращает (rc, stdout_stderr_truncated).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, **(env or {})},
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return 124, f"timeout after {timeout}s"
        out = (out or b"")[:max_bytes]
        txt = out.decode("utf-8", errors="replace")
        return proc.returncode or 0, redact(txt)
    except FileNotFoundError:
        return 127, "not found"
    except Exception as e:
        return 1, f"error: {e}"

# ----------------------------- Модель результатов -----------------------------

CheckName = Literal[
    "os_version",
    "disk_encryption",
    "firewall",
    "secure_boot",
    "edr_agent",
    "patch_recency",
]

TrustLevel = Literal["trusted", "degraded", "untrusted"]

@dataclass(slots=True)
class CheckResult:
    name: CheckName
    ok: bool
    value: Union[str, int, bool, None]
    details: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class DeviceMeta:
    hostname: str
    os_type: str
    os_version: str
    kernel: str
    arch: str
    sensor_id: str

@dataclass(slots=True)
class PosturePolicy:
    # Веса (в сумме целесообразно ~100)
    weight_os_version: int = 10
    weight_disk_encryption: int = 25
    weight_firewall: int = 15
    weight_secure_boot: int = 20
    weight_edr_agent: int = 20
    weight_patch_recency: int = 10

    # Пороговые значения
    min_os_major: Optional[int] = None  # пример: 12 для macOS 12+, 10 для Win10+, 20 для Ubuntu 20.04+
    max_patch_age_days: int = 30
    trust_threshold: int = 85
    degraded_threshold: int = 60

@dataclass(slots=True)
class Evaluation:
    score: int
    level: TrustLevel
    violations: List[Dict[str, Any]] = field(default_factory=list)

@dataclass(slots=True)
class DevicePosture:
    collected_at: str
    meta: DeviceMeta
    checks: List[CheckResult]
    evaluation: Evaluation
    signature_hmac_sha256: Optional[str] = None

# ----------------------------- Кэш TTL ---------------------------------------

class TTLCache:
    __slots__ = ("_val", "_exp")

    def __init__(self) -> None:
        self._val: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        v = self._val.get(key)
        if not v:
            return None
        exp, data = v
        if time.monotonic() > exp:
            self._val.pop(key, None)
            return None
        return data

    def put(self, key: str, ttl_sec: float, data: Any) -> None:
        self._val[key] = (time.monotonic() + ttl_sec, data)

CACHE = TTLCache()

# ----------------------------- Сенсоры ОС ------------------------------------

class BaseOS:
    def __init__(self) -> None:
        self.system = platform.system().lower()

    async def os_version(self) -> Tuple[str, bool, Dict[str, Any]]:
        # Возвращает (версия-читаемо, ок по политике?, evidence)
        ver = platform.platform()
        return ver, True, {"platform": ver}

    async def disk_encryption(self) -> Tuple[bool, Dict[str, Any]]:
        return False, {"reason": "unknown"}

    async def firewall(self) -> Tuple[bool, Dict[str, Any]]:
        return False, {"reason": "unknown"}

    async def secure_boot(self) -> Tuple[bool, Dict[str, Any]]:
        return False, {"reason": "unknown"}

    async def edr_agent(self) -> Tuple[bool, Dict[str, Any]]:
        # Эвристика по известным процессам/сервисам
        names = {
            "crowdstrike": ("falcon-sensor", "falcond", "csagent", "crowdstrike"),
            "sentinelone": ("sentinelone", "sentinel-agent", "SentinelAgent"),
            "carbonblack": ("cbagent", "carbonblack", "repux", "cbdefense"),
            "microsoft_defender": ("MsMpEng", "wdavdaemon", "mdatp", "wdendpoint"),
            "sophos": ("savservice", "Sophos", "sophosd"),
            "bitdefender": ("bdservicehost", "bdagent"),
        }
        running: List[str] = []
        try:
            if psutil:
                for p in psutil.process_iter(attrs=["name"]):
                    n = (p.info.get("name") or "").lower()
                    if not n:
                        continue
                    for fam, pats in names.items():
                        if any(x.lower() in n for x in pats):
                            running.append(fam)
            else:
                # грубая деградация через ps
                rc, out = await run_cmd("ps", "-A")
                for fam, pats in names.items():
                    for pat in pats:
                        if re.search(pat, out, re.I):
                            running.append(fam)
        except Exception:
            pass
        uniq = sorted(set(running))
        return (len(uniq) > 0), {"detected": uniq}

    async def patch_recency(self) -> Tuple[Optional[int], Dict[str, Any]]:
        # Возвращает возраст последнего апдейта в днях, если удалось определить
        return None, {"reason": "unknown"}

class LinuxOS(BaseOS):
    async def os_version(self) -> Tuple[str, bool, Dict[str, Any]]:
        ver = platform.platform()
        ok = True
        evidence = {"platform": ver}
        # Попытка вытащить VERSION_ID (например 22.04)
        try:
            content = Path("/etc/os-release").read_text(encoding="utf-8")
            evidence["/etc/os-release"] = content
            m = re.search(r'^VERSION_ID="?([0-9.]+)"?', content, re.M)
            if m:
                evidence["version_id"] = m.group(1)
        except Exception:
            pass
        return ver, ok, evidence

    async def disk_encryption(self) -> Tuple[bool, Dict[str, Any]]:
        # Проверяем dm-crypt/LUKS монтирование root
        rc, out = await run_cmd("lsblk", "-o", "NAME,TYPE,MOUNTPOINT,FSTYPE")
        encrypted = bool(re.search(r"\bdm-crypt\b", out)) or bool(re.search(r"\bfstype\s+crypt\b", out))
        # Альтернатива: наличие записей в /etc/crypttab
        crypttab = Path("/etc/crypttab")
        if crypttab.exists():
            try:
                if crypttab.read_text(encoding="utf-8").strip():
                    encrypted = True or encrypted
            except Exception:
                pass
        return encrypted, {"lsblk": out[:2000]}

    async def firewall(self) -> Tuple[bool, Dict[str, Any]]:
        # UFW
        rc1, out1 = await run_cmd("ufw", "status")
        if rc1 == 0 and re.search(r"Status:\s+active", out1, re.I):
            return True, {"ufw": out1}
        # firewalld
        rc2, out2 = await run_cmd("firewall-cmd", "--state")
        if rc2 == 0 and "running" in out2.lower():
            return True, {"firewalld": out2}
        # nftables/iptables: минимальная эвристика
        rc3, out3 = await run_cmd("iptables", "-S")
        if rc3 == 0 and "-P" in out3:
            return True, {"iptables": out3[:1000]}
        return False, {"ufw": out1, "firewalld": out2, "iptables": out3}

    async def secure_boot(self) -> Tuple[bool, Dict[str, Any]]:
        # mokutil --sb-state
        rc, out = await run_cmd("mokutil", "--sb-state")
        if rc == 0:
            enabled = "enabled" in out.lower()
            return enabled, {"mokutil": out}
        # попытка через efivars
        p = Path("/sys/firmware/efi/efivars")
        if p.exists():
            sb = list(p.glob("SecureBoot-*"))
            if sb:
                try:
                    raw = sb[0].read_bytes()
                    return (raw[-1] == 1), {"efivars": "present", "value_last_byte": int(raw[-1])}
                except Exception:
                    pass
        return False, {"reason": "unknown"}

    async def patch_recency(self) -> Tuple[Optional[int], Dict[str, Any]]:
        # Debian/Ubuntu: /var/lib/apt/periodic/update-success-stamp
        stamp = Path("/var/lib/apt/periodic/update-success-stamp")
        if stamp.exists():
            try:
                mtime = datetime.fromtimestamp(stamp.stat().st_mtime, tz=timezone.utc)
                age = (utcnow() - mtime).days
                return age, {"source": str(stamp), "mtime": ISO(mtime)}
            except Exception:
                pass
        # RedHat family fallback: dnf history last
        rc, out = await run_cmd("dnf", "history", "info", "last")
        if rc == 0:
            m = re.search(r"Begin time\s*:\s*(.*)", out)
            if m:
                try:
                    # грубый парсинг даты
                    age = None
                    for fmt in ("%Y-%m-%d %H:%M", "%a %d %b %Y %H:%M:%S"):
                        try:
                            dt = datetime.strptime(m.group(1).strip(), fmt).replace(tzinfo=timezone.utc)
                            age = (utcnow() - dt).days
                            break
                        except Exception:
                            continue
                    if age is not None:
                        return age, {"dnf": m.group(1)}
                except Exception:
                    pass
        return None, {"reason": "unknown"}

class MacOS(BaseOS):
    async def os_version(self) -> Tuple[str, bool, Dict[str, Any]]:
        rc, out = await run_cmd("sw_vers")
        evidence = {"sw_vers": out}
        ver = platform.platform()
        return ver, True, evidence

    async def disk_encryption(self) -> Tuple[bool, Dict[str, Any]]:
        rc, out = await run_cmd("fdesetup", "status")
        if rc == 0 and re.search(r"FileVault is On", out, re.I):
            return True, {"fdesetup": out}
        return False, {"fdesetup": out}

    async def firewall(self) -> Tuple[bool, Dict[str, Any]]:
        # Application Firewall
        rc, out = await run_cmd("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
        if rc == 0:
            try:
                val = int(out.strip().splitlines()[-1])
                # 1 и 2 означают enabled (различные режимы)
                return (val >= 1), {"alf.globalstate": val}
            except Exception:
                pass
        return False, {"alf": out}

    async def secure_boot(self) -> Tuple[bool, Dict[str, Any]]:
        # На macOS проверим SIP (csrutil). Это не Secure Boot, но базовая защита системы.
        rc, out = await run_cmd("csrutil", "status")
        if rc == 0 and "enabled" in out.lower():
            return True, {"csrutil": out}
        return False, {"csrutil": out}

    async def patch_recency(self) -> Tuple[Optional[int], Dict[str, Any]]:
        # softwareupdate --history (может быть дорогой)
        rc, out = await run_cmd("softwareupdate", "--history", "--all")
        if rc == 0:
            # эвристика: искать последнюю строку с Installed
            lines = [l for l in out.splitlines() if "Installed" in l]
            if lines:
                # Дата обычно в конце строки, но формат локалезависимый — оставляем evidence
                return None, {"history": lines[-1]}
        return None, {"reason": "unknown"}

class WindowsOS(BaseOS):
    async def os_version(self) -> Tuple[str, bool, Dict[str, Any]]:
        rc, out = await run_cmd("cmd.exe", "/c", "ver")
        return platform.platform(), True, {"ver": out}

    async def disk_encryption(self) -> Tuple[bool, Dict[str, Any]]:
        # manage-bde -status c:
        rc, out = await run_cmd("manage-bde", "-status", "C:")
        if rc == 0 and re.search(r"Protection Status:\s*Protection On", out, re.I):
            return True, {"manage-bde": out}
        return False, {"manage-bde": out}

    async def firewall(self) -> Tuple[bool, Dict[str, Any]]:
        # netsh advfirewall show allprofiles
        rc, out = await run_cmd("netsh", "advfirewall", "show", "allprofiles")
        if rc == 0 and re.search(r"State\s+ON", out, re.I):
            return True, {"netsh": out}
        # PowerShell альтернативный путь
        rc2, out2 = await run_cmd("powershell", "-NoProfile", "-Command", "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled")
        if rc2 == 0 and re.search(r"True", out2):
            return True, {"powershell": out2}
        return False, {"netsh": out, "powershell": out2}

    async def secure_boot(self) -> Tuple[bool, Dict[str, Any]]:
        # PowerShell Confirm-SecureBootUEFI
        rc, out = await run_cmd("powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI")
        if rc == 0 and "True" in out:
            return True, {"Confirm-SecureBootUEFI": out}
        return False, {"Confirm-SecureBootUEFI": out}

    async def patch_recency(self) -> Tuple[Optional[int], Dict[str, Any]]:
        # PowerShell: (Get-HotFix | sort InstalledOn)[-1]
        rc, out = await run_cmd(
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 1).InstalledOn"
        )
        if rc == 0 and out.strip():
            return None, {"last_hotfix": out.strip()}
        return None, {"reason": "unknown"}

# ----------------------------- Фабрика ОС ------------------------------------

def get_os() -> BaseOS:
    sysname = platform.system().lower()
    if sysname == "linux":
        return LinuxOS()
    if sysname == "darwin":
        return MacOS()
    if sysname == "windows":
        return WindowsOS()
    return BaseOS()

# ----------------------------- Оценщик позы ----------------------------------

@dataclass(slots=True)
class DevicePostureEvaluator:
    policy: PosturePolicy = field(default_factory=PosturePolicy)
    hmac_key_env: str = "DEVICE_POSTURE_HMAC_KEY"

    async def collect(self) -> DevicePosture:
        sensor_id = host_fingerprint()
        meta = DeviceMeta(
            hostname=socket.gethostname(),
            os_type=platform.system().lower(),
            os_version=platform.platform(),
            kernel=platform.release(),
            arch=platform.machine(),
            sensor_id=sensor_id,
        )
        osif = get_os()
        checks: List[CheckResult] = []

        # Запускаем сенсоры параллельно
        os_version_task = asyncio.create_task(osif.os_version())
        disk_task = asyncio.create_task(osif.disk_encryption())
        fw_task = asyncio.create_task(osif.firewall())
        sb_task = asyncio.create_task(osif.secure_boot())
        edr_task = asyncio.create_task(osif.edr_agent())
        patch_task = asyncio.create_task(osif.patch_recency())

        ver_str, ver_ok, ver_ev = await os_version_task
        checks.append(CheckResult(name="os_version", ok=ver_ok, value=ver_str, details="", evidence=ver_ev))

        disk_ok, disk_ev = await disk_task
        checks.append(CheckResult(name="disk_encryption", ok=disk_ok, value=disk_ok, details="", evidence=disk_ev))

        fw_ok, fw_ev = await fw_task
        checks.append(CheckResult(name="firewall", ok=fw_ok, value=fw_ok, details="", evidence=fw_ev))

        sb_ok, sb_ev = await sb_task
        checks.append(CheckResult(name="secure_boot", ok=sb_ok, value=sb_ok, details="", evidence=sb_ev))

        edr_ok, edr_ev = await edr_task
        checks.append(CheckResult(name="edr_agent", ok=edr_ok, value=edr_ok, details="", evidence=edr_ev))

        patch_age, patch_ev = await patch_task
        # Если известен возраст, то ok = patch_age <= max_patch_age_days
        patch_ok = patch_age is not None and patch_age <= self.policy.max_patch_age_days
        checks.append(CheckResult(
            name="patch_recency",
            ok=patch_ok if patch_age is not None else False,
            value=patch_age if patch_age is not None else "unknown",
            details="" if patch_age is not None else "age unknown",
            evidence=patch_ev,
        ))

        evaluation = self._evaluate(checks)
        signature = self._sign(meta, checks, evaluation)

        return DevicePosture(
            collected_at=ISO(utcnow()),
            meta=meta,
            checks=checks,
            evaluation=evaluation,
            signature_hmac_sha256=signature,
        )

    def _evaluate(self, checks: List[CheckResult]) -> Evaluation:
        # Маппинг веса
        w = self.policy
        weight_map = {
            "os_version": w.weight_os_version,
            "disk_encryption": w.weight_disk_encryption,
            "firewall": w.weight_firewall,
            "secure_boot": w.weight_secure_boot,
            "edr_agent": w.weight_edr_agent,
            "patch_recency": w.weight_patch_recency,
        }
        total_weight = sum(weight_map.values())
        score = 0
        violations: List[Dict[str, Any]] = []

        for c in checks:
            wt = weight_map.get(c.name, 0)
            if c.name == "patch_recency":
                if isinstance(c.value, int):
                    ok = c.ok
                else:
                    ok = False  # неизвестно => считаем отрицательно
            else:
                ok = c.ok

            if ok:
                score += wt
            else:
                violations.append({
                    "check": c.name,
                    "value": c.value,
                    "evidence_hint": list(c.evidence.keys()),
                })

        # Нормируем на 100, если веса не 100
        score = int(round((score / total_weight) * 100)) if total_weight else 0
        level: TrustLevel
        if score >= self.policy.trust_threshold:
            level = "trusted"
        elif score >= self.policy.degraded_threshold:
            level = "degraded"
        else:
            level = "untrusted"

        return Evaluation(score=score, level=level, violations=violations)

    def _sign(self, meta: DeviceMeta, checks: List[CheckResult], evaluation: Evaluation) -> Optional[str]:
        key = os.getenv(self.hmac_key_env)
        if not key:
            return None
        payload = json.dumps({
            "meta": asdict(meta),
            "checks": [asdict(c) for c in checks],
            "evaluation": asdict(evaluation),
            "ts": ISO(utcnow()),
        }, ensure_ascii=False, separators=JSON_SEPARATORS).encode("utf-8")
        return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

# ----------------------------- API: высокоуровневая функция -------------------

async def collect_device_posture() -> Dict[str, Any]:
    evaluator = DevicePostureEvaluator()
    posture = await evaluator.collect()
    return {
        "device_posture": {
            "collected_at": posture.collected_at,
            "meta": asdict(posture.meta),
            "checks": [asdict(c) for c in posture.checks],
            "evaluation": asdict(posture.evaluation),
            "signature_hmac_sha256": posture.signature_hmac_sha256,
        }
    }

# ----------------------------- CLI -------------------------------------------

def _sync_run(coro):
    return asyncio.run(coro)

def main(argv: Optional[List[str]] = None) -> int:
    argv = argv or sys.argv[1:]
    # Простейшие опции: --json, --pretty
    pretty = "--pretty" in argv
    try:
        data = _sync_run(collect_device_posture())
        if pretty:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(data, ensure_ascii=False, separators=JSON_SEPARATORS))
        level = data["device_posture"]["evaluation"]["level"]
        return 0 if level == "trusted" else 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
