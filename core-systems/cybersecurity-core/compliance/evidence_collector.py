# cybersecurity-core/cybersecurity/compliance/evidence_collector.py
from __future__ import annotations

import asyncio
import dataclasses
import fnmatch
import gzip
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------------------------
# ЛОГИРОВАНИЕ
# ---------------------------------------------------------------------------
LOG = logging.getLogger("cybersecurity.compliance.evidence")
if not LOG.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# ---------------------------------------------------------------------------
# КОНСТАНТЫ И УТИЛИТЫ
# ---------------------------------------------------------------------------
ISO = lambda dt: dt.astimezone(timezone.utc).isoformat()

EVIDENCE_HMAC_KEY = os.getenv("EVIDENCE_HMAC_KEY", "").encode("utf-8") if os.getenv("EVIDENCE_HMAC_KEY") else None
DEFAULT_RETENTION_DAYS = int(os.getenv("EVIDENCE_RETENTION_DAYS", "365"))
MAX_INLINE_BYTES = int(os.getenv("EVIDENCE_MAX_INLINE", "8_000_000"))  # 8 MB до gzip
SHELL_TIMEOUT_SEC = float(os.getenv("EVIDENCE_CMD_TIMEOUT_SEC", "15.0"))
SHELL_MAX_BYTES = int(os.getenv("EVIDENCE_CMD_MAX_BYTES", "4_000_000"))  # 4 MB stdout cap
PARALLELISM = int(os.getenv("EVIDENCE_PARALLELISM", "6"))

SAFE_COMMAND_ALLOWLIST: Tuple[str, ...] = tuple(
    filter(None, os.getenv("EVIDENCE_CMD_ALLOW", "uname,uptime,whoami,systemctl,docker,kubectl,git,openssl,python,pip").split(","))
)

SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)\b(api_?key|access_?key|secret|password|passwd|pwd|token|bearer)\s*[:=]\s*[\"']?([^\s\"']+)", re.M),
    re.compile(r"(?i)authorization:\s*bearer\s+([A-Za-z0-9\-._~+/=]+)"),
    re.compile(r"(?i)(?:aws|gcp|azure)[_-]?(secret|key)\s*[:=]\s*[\"']?([^\s\"']+)"),
]

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def redact_secrets(text: str) -> str:
    redacted = text
    for pat in SECRET_PATTERNS:
        redacted = pat.sub(lambda m: m.group(0).replace(m.groups()[-1], "***REDACTED***"), redacted)
    return redacted

def stable_uuid() -> str:
    return str(uuid.uuid4())

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def is_tool_available(name: str) -> bool:
    return shutil.which(name) is not None

# ---------------------------------------------------------------------------
# МОДЕЛИ ДАННЫХ
# ---------------------------------------------------------------------------
EvidenceCategory = Literal["policy", "procedure", "config", "log", "screenshot", "report", "attestation", "inventory"]
ContentType = Literal["text/plain", "application/json", "application/octet-stream", "application/gzip"]

@dataclass(slots=True)
class ControlRef:
    framework: str  # ISO27001, SOC2, NIST800-53, PCI-DSS, CIS
    id: str         # A.12.4.1, CC6.1, AC-2, 10.2, 1.1.1
    description: str = ""

@dataclass(slots=True)
class EvidenceMeta:
    id: str
    created_at: str
    category: EvidenceCategory
    description: str
    controls: List[ControlRef]
    labels: List[str] = field(default_factory=list)
    pii: bool = False
    retention_days: int = DEFAULT_RETENTION_DAYS
    content_type: ContentType = "text/plain"
    source: str = ""  # probe name
    hostname: str = platform.node()
    environment: str = os.getenv("ENVIRONMENT", "prod")
    tenant_id: Optional[str] = os.getenv("TENANT_ID")

@dataclass(slots=True)
class EvidenceItem:
    meta: EvidenceMeta
    relpath: str             # относительный путь внутри evidence store
    sha256: str
    size: int

# ---------------------------------------------------------------------------
# ХРАНИЛИЩЕ ДОКАЗАТЕЛЬСТВ
# ---------------------------------------------------------------------------
class EvidenceStore:
    """
    Локальное хранилище: <base>/YYYY/MM/DD/<uuid>.<ext>
    Также формирует bundles/<ts>_<id>.tar.gz с манифестом (и HMAC-подписью опционально).
    """

    def __init__(self, base_dir: Union[str, Path]) -> None:
        self.base = Path(base_dir).resolve()
        ensure_dir(self.base)
        ensure_dir(self.base / "bundles")

    def _ext_from_ct(self, ct: ContentType) -> str:
        return {
            "text/plain": "txt",
            "application/json": "json",
            "application/octet-stream": "bin",
            "application/gzip": "gz",
        }.get(ct, "bin")

    def put(self, meta: EvidenceMeta, data: bytes) -> EvidenceItem:
        day = utcnow()
        rel = Path(str(day.year)) / f"{day.month:02d}" / f"{day.day:02d}"
        ensure_dir(self.base / rel)
        ext = self._ext_from_ct(meta.content_type)
        fname = f"{meta.id}.{ext}"
        path = self.base / rel / fname

        # Запись и защита целостности
        path.write_bytes(data)
        digest = sha256_bytes(data)
        size = path.stat().st_size

        # Метаданные рядом: <file>.meta.json
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        meta_json = json.dumps(asdict(meta), ensure_ascii=False, indent=2)
        meta_path.write_text(meta_json, encoding="utf-8")

        relpath = str(rel / fname)
        LOG.info("Evidence stored: %s sha256=%s size=%d", relpath, digest, size)
        return EvidenceItem(meta=meta, relpath=relpath, sha256=digest, size=size)

    def bundle(self, items: List[EvidenceItem], bundle_id: Optional[str] = None) -> Path:
        if not items:
            raise ValueError("No items to bundle")
        ts = utcnow().strftime("%Y%m%dT%H%M%SZ")
        bundle_id = bundle_id or stable_uuid()
        tar_path = self.base / "bundles" / f"{ts}_{bundle_id}.tar.gz"
        manifest: Dict[str, Any] = {
            "bundle_id": bundle_id,
            "created_at": ISO(utcnow()),
            "items": [],
            "hmac_sha256": None,
        }

        with tempfile.TemporaryDirectory() as tmpd:
            tmpdir = Path(tmpd)
            # Скопировать файлы и собрать манифест
            for it in items:
                src = self.base / it.relpath
                dst = tmpdir / it.relpath
                ensure_dir(dst.parent)
                dst.write_bytes(src.read_bytes())
                manifest["items"].append({
                    "relpath": it.relpath,
                    "sha256": it.sha256,
                    "size": it.size,
                    "meta": asdict(it.meta),
                })

            manifest_path = tmpdir / "manifest.json"
            manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")

            # Опциональная HMAC подпись манифеста (включая items)
            if EVIDENCE_HMAC_KEY:
                sig = hmac.new(EVIDENCE_HMAC_KEY, manifest_json, hashlib.sha256).hexdigest()
                manifest["hmac_sha256"] = sig
                manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            manifest_path.write_bytes(manifest_json)

            # Сформировать tar.gz
            ensure_dir(tar_path.parent)
            with tarfile.open(tar_path, "w:gz") as tar:
                # Добавить файлы доказательств
                for it in items:
                    tar.add(tmpdir / it.relpath, arcname=it.relpath)
                # Добавить манифест
                tar.add(manifest_path, arcname="manifest.json")

        LOG.info("Evidence bundle created: %s (%d items)", tar_path, len(items))
        return tar_path

# ---------------------------------------------------------------------------
# БАЗОВЫЙ ИНТЕРФЕЙС ПРОБ
# ---------------------------------------------------------------------------
class ProbeError(RuntimeError):
    pass

@dataclass(slots=True)
class ProbeContext:
    store: EvidenceStore
    now: datetime
    tenant_id: Optional[str] = os.getenv("TENANT_ID")
    labels: List[str] = field(default_factory=list)

class Probe:
    name: str = "probe"

    async def run(self, ctx: ProbeContext) -> List[EvidenceItem]:  # pragma: no cover
        raise NotImplementedError

# ---------------------------------------------------------------------------
# ПРОБЫ
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class CommandProbe(Probe):
    """
    Безопасный запуск системной команды с редакцией секретов.
    """
    name: str
    command: Sequence[str]              # ["uname","-a"]
    description: str
    controls: List[ControlRef]
    category: EvidenceCategory = "config"
    timeout_sec: float = SHELL_TIMEOUT_SEC
    max_bytes: int = SHELL_MAX_BYTES
    env: Dict[str, str] = field(default_factory=dict)
    redact: bool = True
    required: bool = False             # если команда отсутствует — падать или пропускать
    pii: bool = False

    def _validate(self) -> None:
        if not self.command:
            raise ProbeError("Empty command")
        cmd0 = self.command[0]
        if SAFE_COMMAND_ALLOWLIST and cmd0 not in SAFE_COMMAND_ALLOWLIST:
            raise ProbeError(f"Command '{cmd0}' not in allow-list")
        if not is_tool_available(cmd0):
            if self.required:
                raise ProbeError(f"Command not found: {cmd0}")
            else:
                raise FileNotFoundError(f"Command not found: {cmd0}")

    async def run(self, ctx: ProbeContext) -> List[EvidenceItem]:
        self._validate()
        meta = EvidenceMeta(
            id=stable_uuid(),
            created_at=ISO(ctx.now),
            category=self.category,
            description=self.description,
            controls=self.controls,
            labels=ctx.labels + [self.name, "command"],
            pii=self.pii,
            content_type="text/plain",
            source=self.name,
        )

        # subprocess без shell, ограничение по времени и размеру
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, **self.env},
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_sec)
            except asyncio.TimeoutError:
                proc.kill()
                out = f"Timed out after {self.timeout_sec}s".encode("utf-8")
            out = out[: self.max_bytes]
        except FileNotFoundError as e:
            # команда недоступна — собираем артефакт с сообщением (не критично)
            out = str(e).encode("utf-8")

        text = out.decode("utf-8", errors="replace")
        if self.redact:
            text = redact_secrets(text)

        return [ctx.store.put(meta, text.encode("utf-8"))]

@dataclass(slots=True)
class FileProbe(Probe):
    """
    Захват файлов по шаблонам (glob). Крупные файлы автоматически gzip'ятся.
    """
    name: str
    patterns: List[str]                 # например ["/etc/ssh/sshd_config","/etc/*release"]
    description: str
    controls: List[ControlRef]
    category: EvidenceCategory = "config"
    max_inline_bytes: int = MAX_INLINE_BYTES
    pii: bool = False

    async def run(self, ctx: ProbeContext) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        paths: List[Path] = []
        for pat in self.patterns:
            if any(ch in pat for ch in ["*", "?", "[", "]"]):
                paths.extend(Path("/").glob(pat.lstrip("/")))
            else:
                paths.append(Path(pat))
        seen: set[Path] = set()
        for p in paths:
            if p in seen:
                continue
            seen.add(p)
            if not p.exists() or not p.is_file():
                continue
            b = p.read_bytes()
            ct: ContentType = "application/octet-stream"
            # Простая эвристика: текст?
            try:
                _ = b.decode("utf-8")
                ct = "text/plain"
            except Exception:
                pass

            meta = EvidenceMeta(
                id=stable_uuid(),
                created_at=ISO(ctx.now),
                category=self.category,
                description=f"{self.description}: {str(p)}",
                controls=self.controls,
                labels=ctx.labels + [self.name, "file"],
                pii=self.pii,
                content_type=ct,
                source=self.name,
            )

            data = b
            if len(b) > self.max_inline_bytes:
                meta.content_type = "application/gzip"
                with tempfile.TemporaryFile() as tf:
                    with gzip.GzipFile(fileobj=tf, mode="wb") as gz:
                        gz.write(b)
                    tf.seek(0)
                    data = tf.read()
            items.append(ctx.store.put(meta, data))
        return items

@dataclass(slots=True)
class DirSnapshotProbe(Probe):
    """
    Снимок каталога: дерево путей + стат.метаданные (без содержимого).
    """
    name: str
    root: Path
    globs: List[str]                    # включающие/исключающие маски: "include:*.conf", "exclude:*.log"
    description: str
    controls: List[ControlRef]
    category: EvidenceCategory = "inventory"
    max_entries: int = 50_000

    def _match(self, path: Path, kind: str) -> bool:
        decision: Optional[bool] = None
        for rule in self.globs:
            try:
                mode, pattern = rule.split(":", 1)
            except ValueError:
                continue
            if fnmatch.fnmatch(path.name, pattern):
                if mode == "include":
                    decision = True
                elif mode == "exclude":
                    decision = False
        return bool(True if decision is None else decision)

    async def run(self, ctx: ProbeContext) -> List[EvidenceItem]:
        lst: List[Dict[str, Any]] = []
        count = 0
        base = self.root.resolve()
        for p in base.rglob("*"):
            if count >= self.max_entries:
                break
            rel = p.relative_to(base)
            if not self._match(p, "file" if p.is_file() else "dir"):
                continue
            try:
                st = p.stat()
            except Exception:
                continue
            lst.append({
                "path": str(rel),
                "type": "file" if p.is_file() else "dir",
                "mode": oct(st.st_mode),
                "size": st.st_size,
                "mtime": ISO(datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)),
            })
            count += 1

        meta = EvidenceMeta(
            id=stable_uuid(),
            created_at=ISO(ctx.now),
            category=self.category,
            description=self.description,
            controls=self.controls,
            labels=ctx.labels + [self.name, "dirsnapshot"],
            content_type="application/json",
            source=self.name,
        )
        data = json.dumps({"root": str(base), "entries": lst, "count": count}, ensure_ascii=False, indent=2).encode("utf-8")
        return [ctx.store.put(meta, data)]

@dataclass(slots=True)
class SystemInfoProbe(Probe):
    """
    Базовый системный отчёт (OS, ядро, CPU, Python, PATH, диски).
    """
    name: str
    description: str
    controls: List[ControlRef]
    category: EvidenceCategory = "report"

    async def run(self, ctx: ProbeContext) -> List[EvidenceItem]:
        info = {
            "timestamp": ISO(ctx.now),
            "hostname": platform.node(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "path": os.getenv("PATH", ""),
        }
        try:
            info["cpu_count"] = os.cpu_count()
            info["disk_usage_root"] = {k: getattr(shutil.disk_usage("/"), k) for k in ("total", "used", "free")}
        except Exception:
            pass

        meta = EvidenceMeta(
            id=stable_uuid(),
            created_at=ISO(ctx.now),
            category=self.category,
            description=self.description,
            controls=self.controls,
            labels=ctx.labels + [self.name, "systeminfo"],
            content_type="application/json",
            source=self.name,
        )
        data = json.dumps(info, ensure_ascii=False, indent=2).encode("utf-8")
        return [ctx.store.put(meta, data)]

# ---------------------------------------------------------------------------
# КОЛЛЕКТОР
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class CollectorPlan:
    probes: List[Probe]
    labels: List[str] = field(default_factory=list)
    bundle: bool = True
    bundle_id: Optional[str] = None

class EvidenceCollector:
    """
    Оркестратор: выполняет пробы параллельно, собирает артефакты, формирует bundle.
    """

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    async def collect(self, plan: CollectorPlan) -> Dict[str, Any]:
        ctx = ProbeContext(store=self.store, now=utcnow(), labels=plan.labels)
        sem = asyncio.Semaphore(clamp(PARALLELISM, 1, 64))
        items: List[EvidenceItem] = []
        errors: List[str] = []

        async def _run_probe(p: Probe) -> None:
            try:
                async with sem:
                    out = await p.run(ctx)
                    items.extend(out)
            except FileNotFoundError as e:
                msg = f"{p.__class__.__name__} '{getattr(p, 'name', '')}': skipped - {e}"
                LOG.warning(msg)
                errors.append(msg)
            except ProbeError as e:
                msg = f"{p.__class__.__name__} '{getattr(p, 'name', '')}': probe error - {e}"
                LOG.error(msg)
                errors.append(msg)
            except Exception as e:
                msg = f"{p.__class__.__name__} '{getattr(p, 'name', '')}': unexpected - {e}"
                LOG.exception(msg)
                errors.append(msg)

        await asyncio.gather(*[_run_probe(p) for p in plan.probes])

        bundle_path: Optional[Path] = None
        if plan.bundle:
            bundle_path = self.store.bundle(items, bundle_id=plan.bundle_id)

        return {
            "items": [dataclasses.asdict(it) for it in items],
            "bundle": str(bundle_path) if bundle_path else None,
            "errors": errors,
        }

# ---------------------------------------------------------------------------
# ГОТОВЫЕ ПАКЕТЫ ПРОБ (пример для SOC 2/ISO 27001)
# ---------------------------------------------------------------------------
def baseline_plan(store: EvidenceStore) -> CollectorPlan:
    controls = [
        ControlRef("ISO27001", "A.12.1.2", "Change management"),
        ControlRef("SOC2", "CC6.1", "Logical access"),
        ControlRef("CIS", "1.1.1", "System inventory"),
    ]
    probes: List[Probe] = [
        SystemInfoProbe(
            name="system_info",
            description="System baseline information",
            controls=controls,
        ),
        CommandProbe(
            name="uname",
            command=["uname", "-a"],
            description="Kernel and OS version",
            controls=[ControlRef("ISO27001", "A.12.6.1", "Technical vulnerability management")],
        ),
        CommandProbe(
            name="uptime",
            command=["uptime"],
            description="System uptime",
            controls=[ControlRef("SOC2", "CC7.4", "Security monitoring")],
        ),
        CommandProbe(
            name="whoami",
            command=["whoami"],
            description="Current user context",
            controls=[ControlRef("SOC2", "CC6.1", "Access controls")],
        ),
        # Не все системы имеют systemctl/docker/kubectl — эти команды помечены как optional
        CommandProbe(
            name="systemctl_list",
            command=["systemctl", "list-unit-files", "--type=service", "--no-pager"],
            description="Systemd services list",
            controls=[ControlRef("CIS", "2.1", "Service configuration")],
            required=False,
        ),
        CommandProbe(
            name="docker_version",
            command=["docker", "version", "--format", "{{json .}}"],
            description="Docker version",
            controls=[ControlRef("CIS", "5.1", "Docker baseline")],
            required=False,
        ),
        CommandProbe(
            name="kubectl_cluster_info",
            command=["kubectl", "cluster-info"],
            description="Kubernetes cluster info",
            controls=[ControlRef("CIS", "1.1.1", "Cluster inventory")],
            required=False,
        ),
        FileProbe(
            name="os_release",
            patterns=["/etc/*release"],
            description="OS release files",
            controls=[ControlRef("CIS", "1.1.1", "Asset inventory")],
        ),
        DirSnapshotProbe(
            name="etc_snapshot",
            root=Path("/etc"),
            globs=["include:*.conf", "include:ssh*", "exclude:*.log", "exclude:*.tmp"],
            description="/etc configuration snapshot (names + stats)",
            controls=[ControlRef("ISO27001", "A.8.1.1", "Inventory of assets")],
        ),
    ]
    return CollectorPlan(probes=probes, labels=["baseline", "soc2-iso27001"], bundle=True)

# ---------------------------------------------------------------------------
# CLI / ПРИМЕР ЗАПУСКА
# ---------------------------------------------------------------------------
async def _amain() -> None:  # pragma: no cover
    store_dir = os.getenv("EVIDENCE_STORE", "./evidence")
    store = EvidenceStore(store_dir)
    plan = baseline_plan(store)
    res = await EvidenceCollector(store).collect(plan)
    LOG.info("Collected %d items, bundle=%s, errors=%d", len(res["items"]), res["bundle"], len(res["errors"]))
    if res["errors"]:
        LOG.info("Errors: %s", json.dumps(res["errors"], ensure_ascii=False, indent=2))

def main() -> None:  # pragma: no cover
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":  # pragma: no cover
    main()
