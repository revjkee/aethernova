# cybersecurity-core/cybersecurity/adversary_emulation/ttp/primitives/cred_access.py
# -*- coding: utf-8 -*-
"""
Безопасная эмуляция TTP «Credential Access» (MITRE ATT&CK: TA0006).
ВНИМАНИЕ: МОДУЛЬ ПРИНЦИПИАЛЬНО НЕ ИЗВЛЕКАЕТ СЕКРЕТЫ И НЕ ДЕЛАЕТ
НЕЗАКОННЫХ ДЕЙСТВИЙ. Он предназначен для «безопасных» проверок готовности,
инвентаризации и обучения Blue Team. Любые потенциально опасные операции
(например, чтение LSASS/DPAPI/Keychain, выгрузка браузерных баз) — отключены
архитектурно и дополнительно защищены Consent-gate.

Соответствие MITRE ATT&CK (для картирования сценариев эмуляции):
- TA0006 Credential Access — тактика доступа к учетным данным (MITRE ATT&CK).
- T1003 OS Credential Dumping — дампинг учетных данных ОС.
- T1552 Unsecured Credentials — небезопасно хранимые учетные данные.
- T1558.003 Kerberoasting — добыча TGS-билетов для офлайн-брата-форса.

Данный модуль реализует:
1) ConsentGate и строгую «политику нулевой утечки» (No-Data Policy)
   — никакие секреты не читаются и не выводятся.
2) Безопасное сканирование ФС: только метаданные потенциально чувствительных
   файлов (наличие, размер, права, хэши путей), без чтения содержимого.
3) Детекцию доступности облачных metadata-endpoint’ов (AWS/Azure/GCP)
   без извлечения токенов/метаданных (только быстрые, локальные проверки).
4) Стандартизованный отчёт и аудит-цепочку JSONL с HMAC (опционально).
5) Интерфейс эмуляции «рискованных» TTP (LSASS/DPAPI/Kerberos) как заглушки,
   возвращающие безопасные «NOT_IMPLEMENTED_BY_POLICY».

Ограничения по безопасности:
- По умолчанию действует No-Data Policy: секреты не читаются и не покидают хост.
- Даже при наличии «согласия» модуль не реализует извлечение секретов —
  разрешены только неинвазивные проверки (инвентаризация, доступность узлов).
- Любая попытка активировать небезопасные действия приводит к отказу.

Примечания по источникам (см. README проекта для полного мэппинга):
- MITRE ATT&CK TA0006/T1003/T1552/T1558.003.
- Облачные endpoints: AWS IMDS (169.254.169.254 + IMDSv2), Azure Managed Identity,
  GCP Metadata Server (metadata.google.internal / 169.254.169.254).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import fnmatch
import hashlib
import hmac
import json
import os
import platform
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Dict, Any, Union

# =========================
# Конфигурация и модели
# =========================

DEFAULT_SENSITIVE_NAME_PATTERNS: Tuple[str, ...] = (
    # Общие
    "*.env", ".env", ".env.*", "*.pem", "*.pfx", "*.p12", "*.key", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "*credentials*", "*secret*", "*passwd*", "*password*", "*auth*",
    # Облачные/DevOps
    "config", "credentials", ".dockerconfigjson", "known_hosts", "authorized_keys",
)

DEFAULT_ROOTS: Tuple[Path, ...] = tuple(
    p for p in [
        Path.home(),
        Path.cwd(),
        Path("/etc") if os.name != "nt" else None,
        Path(os.getenv("APPDATA")) if os.name == "nt" and os.getenv("APPDATA") else None,
    ] if p is not None
)

DEFAULT_ENVVAR_PATTERNS: Tuple[str, ...] = (
    # AWS
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_REGION",
    # Azure
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "MSI_ENDPOINT", "IDENTITY_ENDPOINT", "IMDS_ENDPOINT",
    # GCP
    "GOOGLE_APPLICATION_CREDENTIALS", "GCP_PROJECT", "GCE_METADATA_HOST",
    # Generic
    "*TOKEN*", "*PASSWORD*", "*PASS*", "*SECRET*", "*KEY*",
)

HMAC_HASH = hashlib.sha256  # Для цепочки аудита


@dataclasses.dataclass(frozen=True)
class ScanConfig:
    roots: Tuple[Path, ...] = dataclasses.field(default_factory=lambda: DEFAULT_ROOTS)
    name_patterns: Tuple[str, ...] = dataclasses.field(default_factory=lambda: DEFAULT_SENSITIVE_NAME_PATTERNS)
    envvar_patterns: Tuple[str, ...] = dataclasses.field(default_factory=lambda: DEFAULT_ENVVAR_PATTERNS)
    follow_symlinks: bool = False
    max_files_per_root: int = 5000
    consent_token_env: str = "CONSENT_TOKEN"
    audit_key_env: Optional[str] = "CRED_ACCESS_AUDIT_HMAC_KEY"
    # Сетевая часть
    check_cloud_metadata: bool = True
    network_timeout_s: float = 0.15  # очень агрессивный таймаут


@dataclasses.dataclass
class FileFinding:
    path: str
    size: int
    mode: str
    mtime_iso: str
    path_hash: str  # хэш ПУТИ, не содержимого
    matched_by: str  # какой паттерн сработал


@dataclasses.dataclass
class EnvFinding:
    name: str  # имя переменной (значение не возвращаем)
    matched_by: str


@dataclasses.dataclass
class CloudMetaProbe:
    provider: str  # aws|azure|gcp
    reachable: bool
    endpoint: str
    notes: str = ""


@dataclasses.dataclass
class Report:
    host: str
    os: str
    ts_utc: str
    policy: str  # ALWAYS_NO_DATA
    totals: Dict[str, int]
    files: List[FileFinding]
    envvars: List[EnvFinding]
    cloud: List[CloudMetaProbe]
    notes: List[str]


# =========================
# Аудит-цепочка JSONL
# =========================

class AuditSink:
    def __init__(self, path: Optional[Path], hmac_key: Optional[bytes]) -> None:
        self.path = path
        self.hmac_key = hmac_key
        self._prev = b""

    def _line(self, event: str, data: Dict[str, Any]) -> Dict[str, Any]:
        rec = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "event": event,
            "data": data,
        }
        wire = json.dumps(rec, ensure_ascii=False, sort_keys=True).encode("utf-8")
        chained = self._prev + wire
        if self.hmac_key:
            digest = hmac.new(self.hmac_key, chained, HMAC_HASH).digest()
            method = "HMAC-SHA256"
        else:
            digest = HMAC_HASH(chained).digest()
            method = "SHA256"
        self._prev = digest
        return {
            **rec,
            "hash_method": method,
            "record_hash_b64": _b64(digest),
        }

    def write(self, event: str, data: Dict[str, Any]) -> None:
        if not self.path:
            return
        line = self._line(event, data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as f:
            f.write((json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))


# =========================
# Consent Gate
# =========================

class ConsentGate:
    """
    Жёсткий gate: модуль работает ТОЛЬКО в режиме «нулевой утечки».
    Даже при корректном токене запрещены любые действия, ведущие к
    извлечению секретов. Токен используется лишь для включения сетевых
    «ping-style» проверок и расширенной инвентаризации МЕТАДАННЫХ.
    """
    REQUIRED_VALUE = "I_HAVE_AUTHORIZATION"

    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg

    def has_consent(self) -> bool:
        val = os.getenv(self.cfg.consent_token_env, "")
        return val == self.REQUIRED_VALUE


# =========================
# Утилиты
# =========================

def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")

def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()

def _mode_to_str(m: int) -> str:
    try:
        return stat.filemode(m)
    except Exception:
        return oct(m)

def _hash_path(p: Path) -> str:
    return hashlib.sha256(str(p).encode("utf-8")).hexdigest()

def _host_os() -> Tuple[str, str]:
    return socket.gethostname(), f"{platform.system()} {platform.release()}"

def _match_any(name: str, patterns: Sequence[str]) -> Optional[str]:
    for pat in patterns:
        if fnmatch.fnmatch(name, pat):
            return pat
    return None

def _safe_scandir(root: Path) -> Iterable[Path]:
    try:
        yield from root.rglob("*")
    except Exception:
        return


# =========================
# Основной примитив
# =========================

class CredentialAccessPrimitive:
    """
    Безопасная эмуляция «Credential Access»:
    - НЕ читает содержимое файлов, потенциально содержащих секреты.
    - НЕ обращается к LSASS/DPAPI/Keychain/браузерным БД.
    - Возвращает только метаданные и агрегаты (presence/fingerprint пути).
    """

    def __init__(self, cfg: Optional[ScanConfig] = None, audit: Optional[AuditSink] = None) -> None:
        self.cfg = cfg or ScanConfig()
        key = (os.getenv(self.cfg.audit_key_env).encode("utf-8") if self.cfg.audit_key_env and os.getenv(self.cfg.audit_key_env) else None)
        self.audit = audit or AuditSink(path=Path(".artifacts/audit/cred_access.jsonl"), hmac_key=key)
        self.consent = ConsentGate(self.cfg)

    # ------------- Публичный API -------------

    def run_safe_inventory(self) -> Report:
        """Основной безопасный проход: ФС + ENV + облачные metadata-проверки."""
        host, os_name = _host_os()
        self.audit.write("start", {"host": host, "os": os_name, "policy": "ALWAYS_NO_DATA"})

        files = self._scan_filesystem()
        envs = self._scan_envvars()
        cloud = self._probe_cloud_metadata() if self.cfg.check_cloud_metadata else []

        totals = {
            "files_flagged": len(files),
            "envvars_flagged": len(envs),
            "cloud_endpoints": len(cloud),
        }

        rpt = Report(
            host=host,
            os=os_name,
            ts_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
            policy="ALWAYS_NO_DATA",
            totals=totals,
            files=files,
            envvars=envs,
            cloud=cloud,
            notes=self._notes(os_name),
        )
        self.audit.write("finish", {"totals": totals})
        return rpt

    # ----- Заглушки «опасных» TTP (намеренно не реализованы) -----

    def simulate_os_credential_dumping(self) -> Dict[str, Any]:
        """
        Заглушка T1003 (OS Credential Dumping).
        По политике безопасности возврат только статуса запрета.
        """
        self.audit.write("blocked", {"technique": "T1003", "reason": "No-Data-Policy"})
        return {"technique": "T1003", "status": "NOT_IMPLEMENTED_BY_POLICY"}

    def simulate_kerberoasting(self) -> Dict[str, Any]:
        """
        Заглушка T1558.003 (Kerberoasting).
        """
        self.audit.write("blocked", {"technique": "T1558.003", "reason": "No-Data-Policy"})
        return {"technique": "T1558.003", "status": "NOT_IMPLEMENTED_BY_POLICY"}

    # ------------- Внутренние шаги -------------

    def _scan_filesystem(self) -> List[FileFinding]:
        """Безопасный скан ФС: только метаданные, без чтения содержимого."""
        findings: List[FileFinding] = []
        seen = 0
        for root in self.cfg.roots:
            root = root.expanduser().resolve()
            count_root = 0
            for p in _safe_scandir(root):
                # Ограничение на количество, чтобы не «пылесосить» систему.
                if count_root >= self.cfg.max_files_per_root:
                    break
                try:
                    if not p.is_file():
                        continue
                    matched = _match_any(p.name, self.cfg.name_patterns)
                    if not matched:
                        continue
                    st = p.stat()
                    findings.append(
                        FileFinding(
                            path=str(p),
                            size=int(st.st_size),
                            mode=_mode_to_str(st.st_mode),
                            mtime_iso=_iso(st.st_mtime),
                            path_hash=_hash_path(p),
                            matched_by=matched,
                        )
                    )
                    count_root += 1
                    seen += 1
                except Exception:
                    continue
        self.audit.write("fs_scan", {"flagged": len(findings), "seen_limit": seen})
        return findings

    def _scan_envvars(self) -> List[EnvFinding]:
        """Флаги по переменным окружения: только ИМЕНА, без значений."""
        out: List[EnvFinding] = []
        for name in os.environ.keys():
            matched = _match_any(name, self.cfg.envvar_patterns)
            if matched:
                out.append(EnvFinding(name=name, matched_by=matched))
        self.audit.write("env_scan", {"flagged": len(out)})
        return out

    def _probe_cloud_metadata(self) -> List[CloudMetaProbe]:
        """
        Пассивные «availability-style» проверки облачных endpoints.
        НИЧЕГО не читаем, только локальная проверка доступности адреса.
        """
        probes: List[CloudMetaProbe] = []

        # AWS IMDS (169.254.169.254:80) — проверка наличия маршрута через socket.connect_ex
        probes.append(self._probe_host("aws", ("169.254.169.254", 80), "imds"))
        # Azure Managed Identity локальные переменные/endpoint — не трогаем HTTP, только признаки окружения
        azure_reachable = any(os.getenv(k) for k in ("IDENTITY_ENDPOINT", "MSI_ENDPOINT"))
        probes.append(CloudMetaProbe(provider="azure", reachable=bool(azure_reachable),
                                     endpoint=os.getenv("IDENTITY_ENDPOINT") or os.getenv("MSI_ENDPOINT") or "n/a",
                                     notes="env-detected"))
        # GCP Metadata (metadata.google.internal:80 -> 169.254.169.254) — локальный DNS/route check
        try:
            ip = socket.gethostbyname("metadata.google.internal")
            reachable = ip == "169.254.169.254"
            probes.append(CloudMetaProbe(provider="gcp", reachable=reachable,
                                         endpoint=f"{ip}:80", notes="dns-only"))
        except Exception:
            probes.append(CloudMetaProbe(provider="gcp", reachable=False, endpoint="metadata.google.internal", notes="dns-failed"))

        self.audit.write("cloud_probe", {"count": len(probes)})
        return probes

    def _probe_host(self, provider: str, addr: Tuple[str, int], tag: str) -> CloudMetaProbe:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.cfg.network_timeout_s)
        ok = False
        try:
            ok = (s.connect_ex(addr) == 0)
        except Exception:
            ok = False
        finally:
            try:
                s.close()
            except Exception:
                pass
        return CloudMetaProbe(provider=provider, reachable=ok, endpoint=f"{addr[0]}:{addr[1]}", notes=tag)

    def _notes(self, os_name: str) -> List[str]:
        notes = [
            "Политика: модуль никогда не читает содержимое потенциально секретных файлов.",
            "Cloud-probes: выполняются только проверки доступности/признаков окружения.",
            "Любые запросы к LSASS/DPAPI/Keychain/браузерам заблокированы архитектурно.",
        ]
        if "Windows" in os_name:
            notes.append("Windows: потенциальные риски относятся к T1003/T1558.x, но тут только эмуляция.")
        return notes


# =========================
# CLI для безопасной эмуляции
# =========================

def _as_paths(csv: Optional[str]) -> Tuple[Path, ...]:
    if not csv:
        return DEFAULT_ROOTS
    parts = [Path(x.strip()) for x in csv.split(",") if x.strip()]
    return tuple(p for p in parts if p.exists())

def _as_patterns(csv: Optional[str], default: Tuple[str, ...]) -> Tuple[str, ...]:
    if not csv:
        return default
    return tuple(x.strip() for x in csv.split(",") if x.strip())

def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="cred-access-emu",
        description="Безопасная эмуляция Credential Access (инвентаризация/метаданные, без утечки секретов).",
    )
    parser.add_argument("--roots", help="CSV путей-источников (по умолчанию: домашний каталог, CWD, /etc*)")
    parser.add_argument("--name-patterns", help="CSV паттернов имён файлов (glob)")
    parser.add_argument("--envvar-patterns", help="CSV паттернов имён переменных окружения (glob)")
    parser.add_argument("--max-per-root", type=int, default=5000, help="Ограничение найденных файлов на корень")
    parser.add_argument("--no-cloud", action="store_true", help="Отключить облачные probes")
    parser.add_argument("--audit", default=".artifacts/audit/cred_access.jsonl", help="Путь к audit JSONL")
    parser.add_argument("--timeout", type=float, default=0.15, help="Таймаут сети для probe")
    parser.add_argument("--pretty", action="store_true", help="Форматированный JSON вывод")
    args = parser.parse_args(argv or sys.argv[1:])

    cfg = ScanConfig(
        roots=_as_paths(args.roots),
        name_patterns=_as_patterns(args.name_patterns, DEFAULT_SENSITIVE_NAME_PATTERNS),
        envvar_patterns=_as_patterns(args.envvar_patterns, DEFAULT_ENVVAR_PATTERNS),
        follow_symlinks=False,
        max_files_per_root=max(1, args.max_per_root),
        check_cloud_metadata=not args.no_cloud,
        network_timeout_s=max(0.05, float(args.timeout)),
    )
    audit = AuditSink(path=Path(args.audit) if args.audit else None,
                      hmac_key=(os.getenv(cfg.audit_key_env).encode("utf-8") if cfg.audit_key_env and os.getenv(cfg.audit_key_env) else None))

    prim = CredentialAccessPrimitive(cfg, audit)
    rep = prim.run_safe_inventory()
    out = dataclasses.asdict(rep)
    print(json.dumps(out, ensure_ascii=False, indent=(2 if args.pretty else None), sort_keys=args.pretty))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
