#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
controls_validation/edr_check.py

Industrial-grade, cross-platform EDR presence checker for control validation in adversary emulation contexts.
- Safe: read-only, no privilege escalation, no modification of system state.
- Portable: standard library only; psutil is optional if available.
- Concurrent: asyncio-based collectors to minimize runtime footprint.
- Deterministic output: JSON (default), YAML (best-effort), or table.

Author: Aethernova / NeuroCity Blue Team
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


__version__ = "1.0.0"
__schema_version__ = "2025-09-01"


# -----------------------------
# Utilities
# -----------------------------

def _now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()


def _safe_lower(x: str) -> str:
    return x.lower() if isinstance(x, str) else x


def _run(cmd: Sequence[str], timeout: float = 3.0) -> Tuple[int, str, str]:
    """
    Run a subprocess safely and return (rc, stdout, stderr). Never raises.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _glob_exists(paths: Iterable[str]) -> List[str]:
    hits: List[str] = []
    for p in paths:
        for m in Path("/").glob(p.lstrip("/")) if os.name != "nt" else Path("C:\\").glob(p):
            try:
                if m.exists():
                    hits.append(str(m))
            except Exception:
                continue
    return hits


def _simple_yaml_dump(data: object, indent: int = 0) -> str:
    """
    Extremely small YAML emitter supporting dicts/lists/str/int/bool/None.
    For portability we avoid external dependencies. Not for complex types.
    """
    def dump(obj, level) -> List[str]:
        pad = "  " * level
        lines: List[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k)
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{key}:")
                    lines.extend(dump(v, level + 1))
                else:
                    lines.append(f"{pad}{key}: {json.dumps(v) if isinstance(v, str) else v}")
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, (dict, list)):
                    lines.append(f"{pad}-")
                    lines.extend(dump(it, level + 1))
                else:
                    val = json.dumps(it) if isinstance(it, str) else it
                    lines.append(f"{pad}- {val}")
        else:
            # scalars at root
            val = json.dumps(obj) if isinstance(obj, str) else obj
            lines.append(f"{pad}{val}")
        return lines
    return "\n".join(dump(data, indent)) + "\n"


# -----------------------------
# Data Models
# -----------------------------

@dataclass(frozen=True)
class Signature:
    vendor: str
    product: str
    processes: Tuple[str, ...] = ()
    services: Tuple[str, ...] = ()
    drivers: Tuple[str, ...] = ()  # windows drivers or kext names
    modules: Tuple[str, ...] = ()  # linux kernel modules/system extensions
    paths: Tuple[str, ...] = ()
    registry: Tuple[str, ...] = ()  # windows registry keys substrings
    packages: Tuple[str, ...] = ()
    apps: Tuple[str, ...] = ()  # macOS application bundle names
    notes: str = ""


@dataclass
class Evidence:
    kind: str  # process/service/driver/module/path/registry/package/app
    value: str
    source: str  # which collector or path provided this
    weight: int


@dataclass
class Detection:
    vendor: str
    product: str
    score: int
    confidence: str
    evidences: List[Evidence] = field(default_factory=list)


# -----------------------------
# Signature Catalog (embedded)
# -----------------------------

def _edr_catalog() -> List[Signature]:
    # Patterns are case-insensitive substrings or regexes (compiled as casefold substrings).
    # Keep minimal yet representative; this is not an exhaustive list.
    return [
        Signature(
            vendor="CrowdStrike",
            product="Falcon",
            processes=("csfalconservice", "falcon", "falcond", "falcon-sensor"),
            services=("csfalconservice", "crowdstrike falcon sensor"),
            drivers=("crowdstrike", "csagent"),
            paths=(
                r"C:\Windows\System32\drivers\CrowdStrike\*",
                r"C:\Program Files\CrowdStrike\*",
                "/Library/CS/falconctl",
                "/opt/CrowdStrike/*",
            ),
            registry=("CrowdStrike", "CSFalconService"),
            packages=("crowdstrike", "falcon-sensor"),
            apps=("Falcon.app",),
            notes="Widely deployed EDR sensor."
        ),
        Signature(
            vendor="SentinelOne",
            product="Singularity",
            processes=("sentinelagent", "sentinelsvc", "s1agent", "sentinelone"),
            services=("sentinel agent", "sentinelsvc", "sentineloneservice"),
            drivers=("sentinel", "s1", "sentinelmonitor"),
            paths=(
                r"C:\Program Files\SentinelOne\*",
                "/Library/Sentinel/sentinelctl",
                "/opt/sentinelone/*",
            ),
            registry=("Sentinel", "SentinelOne"),
            packages=("sentinelone", "s1-agent"),
            apps=("SentinelOne.app",),
            notes="Kernel drivers and userland sensor."
        ),
        Signature(
            vendor="Microsoft",
            product="Defender for Endpoint",
            processes=("msmpeng.exe", "senseir", "mde", "mdatp"),
            services=("windefend", "sense"),
            drivers=("wdfilter", "wdfilter", "wdniss", "wdboot"),
            paths=(
                r"C:\Program Files\Windows Defender\*",
                "/opt/microsoft/mdatp/*",
                "/Library/Application Support/Microsoft/Defender/*",
            ),
            registry=("Windows Defender", "SecurityHealth", "Sense"),
            packages=("mdatp", "defender"),
            apps=("Microsoft Defender.app",),
            notes="Windows built-in AV/EDR; Linux/macOS mdatp agent."
        ),
        Signature(
            vendor="VMware",
            product="Carbon Black",
            processes=("cb", "cbdefense", "confer", "repux", "sensorservice"),
            services=("carbon black", "confer", "cbdefense"),
            drivers=("carbonblack", "parity"),
            paths=(
                r"C:\Program Files\CarbonBlack\*",
                r"C:\Program Files\Confer\*",
                "/opt/carbonblack/*",
            ),
            registry=("Carbon", "Confer", "CBDefense"),
            packages=("carbon-black", "confer-sensor"),
            apps=("CbDefense.app",),
            notes="Formerly Bit9/Confer; now VMware Carbon Black."
        ),
        Signature(
            vendor="Palo Alto Networks",
            product="Cortex XDR (Traps)",
            processes=("cyserver", "cyvera", "traps", "cortex xdr", "xdr"),
            services=("cyveraservice", "traps", "cortex xdr"),
            drivers=("cyverakm", "cyveradrv"),
            paths=(
                r"C:\Program Files\Palo Alto Networks\Traps\*",
                r"C:\Program Files\Palo Alto Networks\Cortex XDR\*",
                "/opt/traps/*",
                "/opt/paloaltonetworks/cortex-xdr/*",
            ),
            registry=("Cyvera", "Traps", "Cortex XDR"),
            packages=("cortex-xdr", "traps"),
            apps=("Cortex XDR.app",),
            notes="Traps renamed to Cortex XDR."
        ),
        Signature(
            vendor="Cisco",
            product="Secure Endpoint (AMP)",
            processes=("ciscoamp", "amp", "sfc.exe", "cisco secure endpoint"),
            services=("ciscoamp", "cisco secure endpoint"),
            drivers=("ciscoamp", "ampk"),
            paths=(
                r"C:\Program Files\Cisco\AMP\*",
                "/opt/cisco/amp/*",
            ),
            registry=("Cisco AMP", "Secure Endpoint"),
            packages=("cisco-amp", "secure-endpoint"),
            apps=("Cisco Secure Endpoint.app",),
            notes="Formerly AMP for Endpoints."
        ),
        Signature(
            vendor="Elastic",
            product="Elastic Defend (Endpoint Security)",
            processes=("elastic-endpoint", "endpoint-security"),
            services=("elastic-endpoint", "endpoint-security"),
            modules=("elastic_endpoint",),
            paths=("/opt/Elastic/Endpoint/*", "/Library/Elastic/Endpoint/*"),
            packages=("elastic-agent", "elastic-endpoint"),
            apps=(),
            notes="Elastic Agent with Endpoint Integration."
        ),
        Signature(
            vendor="Sophos",
            product="Intercept X / EDR",
            processes=("sophos", "sophosav", "sophosedr", "sophosml"),
            services=("sophos", "sophosedr", "savservice"),
            drivers=("sophos", "sldriver"),
            paths=(r"C:\Program Files\Sophos\*",
                   "/opt/sophos/*",
                   "/Library/Sophos Anti-Virus/*"),
            registry=("Sophos", "SAVService"),
            packages=("sophos",),
            apps=("Sophos Endpoint.app",),
            notes="Sophos AV/EDR family."
        ),
        Signature(
            vendor="Trellix",
            product="Endpoint Security (McAfee)",
            processes=("mfemms", "mcshield", "trellix", "mfefire"),
            services=("mfemms", "mcshield", "trellix"),
            drivers=("mfe", "mfencfilter"),
            paths=(r"C:\Program Files\Trellix\*",
                   r"C:\Program Files\McAfee\*",
                   "/opt/trellix/*",
                   "/opt/McAfee/*"),
            registry=("McAfee", "Trellix"),
            packages=("trellix", "mcafee"),
            apps=("Trellix Endpoint.app", "McAfee Endpoint Security for Mac.app"),
            notes="McAfee rebranded to Trellix."
        ),
        Signature(
            vendor="Broadcom (Symantec)",
            product="Endpoint Protection",
            processes=("ccSvcHst.exe".lower(), "smc.exe", "sep", "symantec"),
            services=("sep", "symantec", "smc"),
            drivers=("symds", "symevent"),
            paths=(r"C:\Program Files\Symantec\*",
                   "/Library/Application Support/Symantec/*"),
            registry=("Symantec", "SEP"),
            packages=("symantec",),
            apps=("Symantec Endpoint Protection.app",),
            notes="Symantec/Broadcom SEP."
        ),
        Signature(
            vendor="Trend Micro",
            product="Apex One / OfficeScan",
            processes=("tmbmsrv", "ntrtscan", "tmd", "trend micro"),
            services=("trend micro", "tmbmsrv", "ntrtscan"),
            drivers=("tmcomm", "tmfilter"),
            paths=(r"C:\Program Files\Trend Micro\*",
                   "/opt/trendmicro/*"),
            registry=("Trend Micro", "Apex One", "OfficeScan"),
            packages=("trendmicro", "apex-one"),
            apps=("Trend Micro Security.app",),
            notes="Trend Micro enterprise endpoint."
        ),
        Signature(
            vendor="Palo Alto Networks",
            product="XSIAM Agent (Endpoint)",
            processes=("xsiam", "panw", "cortex", "xdr agent"),
            services=("xdr agent", "xsiam"),
            paths=("/opt/panw/*",),
            notes="Some orgs deploy XSIAM agent branding."
        ),
        Signature(
            vendor="ESET",
            product="Endpoint Security",
            processes=("ekrn", "eset", "egui"),
            services=("ekrn", "eset"),
            drivers=("ehdrv", "epfwwfp"),
            paths=(r"C:\Program Files\ESET\*",
                   "/Library/Application Support/ESET/*"),
            registry=("ESET",),
            packages=("eset",),
            apps=("ESET Endpoint Security.app",),
            notes="ESET enterprise endpoint."
        ),
        Signature(
            vendor="Malwarebytes",
            product="EDR / Endpoint",
            processes=("mbam", "malwarebytes", "mbcloud", "mbedr"),
            services=("mbamservice", "mbedrservice"),
            drivers=("mwac", "mbamchameleon"),
            paths=(r"C:\Program Files\Malwarebytes\*",
                   "/Library/Application Support/Malwarebytes/*"),
            registry=("Malwarebytes",),
            packages=("malwarebytes",),
            apps=("Malwarebytes.app",),
            notes="Malwarebytes business endpoint."
        ),
        Signature(
            vendor="Check Point",
            product="Harmony Endpoint",
            processes=("tracer", "epmd", "cpda", "checkpoint"),
            services=("tracer", "epmd", "checkpoint"),
            drivers=("epflt", "cphulk"),
            paths=(r"C:\Program Files\CheckPoint\*",
                   "/opt/Checkpoint/*"),
            registry=("CheckPoint", "Harmony"),
            packages=("checkpoint", "harmony-endpoint"),
            apps=("Check Point Endpoint Security.app",),
            notes="Check Point Harmony Endpoint."
        ),
        Signature(
            vendor="Bitdefender",
            product="GravityZone",
            processes=("bdservicehost", "epsecurityservice", "bitdefender"),
            services=("bdservicehost", "epsecurityservice"),
            drivers=("bdfndisf", "trufos"),
            paths=(r"C:\Program Files\Bitdefender\*",
                   "/Library/Bitdefender/*",
                   "/opt/bitdefender/*"),
            registry=("Bitdefender",),
            packages=("bitdefender",),
            apps=("EndpointSecurityforMac.app",),
            notes="Bitdefender enterprise endpoint."
        ),
        Signature(
            vendor="F-Secure (WithSecure)",
            product="Elements Endpoint Protection",
            processes=("f-secure", "withsecure", "fsaua", "fsorsp"),
            services=("f-secure", "withsecure"),
            drivers=("fsbts", "fsatp"),
            paths=(r"C:\Program Files\F-Secure\*",
                   "/Library/F-Secure/*"),
            registry=("F-Secure", "WithSecure"),
            packages=("f-secure", "withsecure"),
            apps=("F-Secure.app", "WithSecure.app"),
            notes="WithSecure (formerly F-Secure) enterprise endpoint."
        ),
        Signature(
            vendor="Kaspersky",
            product="Endpoint Security for Business",
            processes=("avp.exe".lower(), "kaspersky", "kes"),
            services=("kavfs", "klnagent", "kes"),
            drivers=("klflt", "klif"),
            paths=(r"C:\Program Files\Kaspersky Lab\*",
                   "/Library/Application Support/Kaspersky Lab/*"),
            registry=("Kaspersky", "KES"),
            packages=("kaspersky", "kes"),
            apps=("Kaspersky Endpoint Security for Mac.app",),
            notes="Kaspersky KES."
        ),
        Signature(
            vendor="Palo Alto Networks",
            product="XDR Agent for macOS",
            processes=("xdragent",),
            services=("xdragent",),
            apps=("Cortex XDR.app",),
            notes="Additional macOS naming."
        ),
    ]


# -----------------------------
# Collectors (async)
# -----------------------------

async def collect_process_names() -> Set[str]:
    names: Set[str] = set()
    # Try psutil first if available
    try:
        import psutil  # type: ignore
        for p in psutil.process_iter(attrs=["name"]):
            n = p.info.get("name") or ""
            if n:
                names.add(n.lower())
        return names
    except Exception:
        pass
    # Fallbacks
    if os.name == "nt":
        rc, out, _ = await asyncio.to_thread(_run, ["cmd", "/c", "chcp 65001>nul & tasklist /FO CSV"], 5.0)
        if rc == 0 and out:
            for line in out.splitlines()[1:]:
                try:
                    cols = [c.strip('"') for c in line.split(",")]
                    if cols:
                        names.add(cols[0].lower())
                except Exception:
                    continue
    else:
        rc, out, _ = await asyncio.to_thread(_run, ["ps", "-axo", "comm"], 3.0)
        if rc == 0 and out:
            for line in out.splitlines()[1:]:
                line = line.strip()
                if line:
                    names.add(os.path.basename(line).lower())
    return names


async def collect_services() -> Set[str]:
    names: Set[str] = set()
    if os.name == "nt":
        try:
            import psutil  # type: ignore
            for s in psutil.win_service_iter():
                try:
                    names.add(s.name().lower())
                    display = s.display_name()
                    if display:
                        names.add(display.lower())
                except Exception:
                    continue
            return names
        except Exception:
            pass
        rc, out, _ = await asyncio.to_thread(_run, ["sc", "query", "type=", "service", "state=", "all"], 5.0)
        if rc == 0 and out:
            for line in out.splitlines():
                if "SERVICE_NAME" in line or "DISPLAY_NAME" in line:
                    _, val = line.split(":", 1)
                    names.add(val.strip().lower())
    else:
        if _which("systemctl"):
            rc, out, _ = await asyncio.to_thread(_run, ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"], 5.0)
            if rc == 0:
                for line in out.splitlines():
                    parts = line.split()
                    if parts:
                        svc = parts[0]
                        names.add(svc.lower())
        elif _which("service"):
            rc, out, _ = await asyncio.to_thread(_run, ["service", "--status-all"], 5.0)
            if rc == 0:
                for line in out.splitlines():
                    svc = line.strip().lstrip("[]+- ")
                    if svc:
                        names.add(svc.lower())
        if sys.platform == "darwin" and _which("launchctl"):
            rc, out, _ = await asyncio.to_thread(_run, ["launchctl", "list"], 5.0)
            if rc == 0:
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        names.add(parts[-1].lower())
    return names


async def collect_kernel_modules() -> Set[str]:
    names: Set[str] = set()
    if sys.platform.startswith("linux"):
        if _which("lsmod"):
            rc, out, _ = await asyncio.to_thread(_run, ["lsmod"], 3.0)
            if rc == 0:
                for line in out.splitlines()[1:]:
                    mod = line.split()[0]
                    names.add(mod.lower())
    elif sys.platform == "darwin":
        # macOS system extensions / kexts are limited on modern versions
        if _which("kextstat"):
            rc, out, _ = await asyncio.to_thread(_run, ["kextstat"], 5.0)
            if rc == 0:
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        names.add(parts[5].lower())
        if _which("systemextensionsctl"):
            rc, out, _ = await asyncio.to_thread(_run, ["systemextensionsctl", "list"], 5.0)
            if rc == 0:
                for line in out.splitlines():
                    s = line.strip().lower()
                    if s:
                        names.add(s)
    else:
        # Windows kernel drivers will be collected via services & drivers path scanning
        pass
    return names


async def collect_registry_entries() -> Set[str]:
    entries: Set[str] = set()
    if os.name != "nt":
        return entries
    try:
        import winreg  # type: ignore
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ]
        for root, path in roots:
            try:
                hkey = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
            except Exception:
                continue
            try:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(hkey, i)
                        entries.add(sub.lower())
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
    except Exception:
        pass
    return entries


async def collect_packages() -> Set[str]:
    names: Set[str] = set()
    if sys.platform.startswith("linux"):
        if _which("dpkg"):
            rc, out, _ = await asyncio.to_thread(_run, ["dpkg", "-l"], 6.0)
            if rc == 0:
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and (parts[0].startswith("ii") or parts[0] == "rc"):
                        names.add(parts[1].lower())
        if _which("rpm"):
            rc, out, _ = await asyncio.to_thread(_run, ["rpm", "-qa"], 6.0)
            if rc == 0:
                for line in out.splitlines():
                    if line.strip():
                        names.add(line.strip().lower())
    elif sys.platform == "darwin":
        if _which("pkgutil"):
            rc, out, _ = await asyncio.to_thread(_run, ["pkgutil", "--pkgs"], 6.0)
            if rc == 0:
                for line in out.splitlines():
                    if line.strip():
                        names.add(line.strip().lower())
    else:
        # Windows packages via registry handled in collect_registry_entries()
        pass
    return names


async def collect_paths() -> Set[str]:
    hits: Set[str] = set()
    candidates: List[str] = []
    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\*",
            r"C:\Program Files (x86)\*",
            r"C:\Windows\System32\drivers\*",
        ])
    else:
        candidates.extend([
            "/Applications/*",
            "/Library/*",
            "/opt/*",
            "/usr/local/*",
        ])
    # To be efficient, just record directory names
    for pat in candidates:
        base = Path(pat).drive + "\\" if os.name == "nt" else "/"
        try:
            # Use glob carefully to avoid deep recursion
            for p in Path(base).glob(p.lstrip("/")):
                try:
                    name = str(p).lower()
                    hits.add(name)
                except Exception:
                    continue
        except Exception:
            continue
    return hits


async def collect_apps() -> Set[str]:
    names: Set[str] = set()
    if sys.platform == "darwin":
        apps_dir = Path("/Applications")
        if apps_dir.exists():
            for p in apps_dir.glob("*.app"):
                names.add(p.name.lower())
    return names


# -----------------------------
# Matching Engine
# -----------------------------

@dataclass
class Collected:
    processes: Set[str]
    services: Set[str]
    modules: Set[str]
    registry: Set[str]
    packages: Set[str]
    paths: Set[str]
    apps: Set[str]


async def collect_all() -> Collected:
    results = await asyncio.gather(
        collect_process_names(),
        collect_services(),
        collect_kernel_modules(),
        collect_registry_entries(),
        collect_packages(),
        collect_paths(),
        collect_apps(),
        return_exceptions=True,
    )
    def safe_set(idx: int) -> Set[str]:
        v = results[idx]
        return v if isinstance(v, set) else set()
    return Collected(
        processes=safe_set(0),
        services=safe_set(1),
        modules=safe_set(2),
        registry=safe_set(3),
        packages=safe_set(4),
        paths=safe_set(5),
        apps=safe_set(6),
    )


def _match_patterns(values: Set[str], patterns: Sequence[str]) -> List[str]:
    """
    Best-effort safe matcher:
    - Case-insensitive.
    - For short patterns (<=3 chars), require whole word match to avoid false positives.
    - For longer patterns, use word-boundary regex if the pattern is alnum; otherwise fallback to substring.
    """
    hits: List[str] = []
    if not patterns:
        return hits
    for pat in patterns:
        p = pat.lower()
        if not p:
            continue
        # Build a regex with word boundaries if pattern is alnum-ish
        use_regex = bool(re.fullmatch(r"[a-z0-9_\-\. ]+", p))
        if len(p) <= 3:
            # short patterns: require exact token match
            token_re = re.compile(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])")
        elif use_regex:
            token_re = re.compile(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])")
        else:
            token_re = None
        for val in values:
            v = val.lower()
            if token_re:
                if token_re.search(v):
                    hits.append(val)
                    break
            else:
                if p in v:
                    hits.append(val)
                    break
    return hits


def evaluate_signatures(col: Collected, catalog: Sequence[Signature]) -> List[Detection]:
    detections: List[Detection] = []
    weights = {
        "process": 3,
        "service": 4,
        "driver": 4,   # mapped via paths or modules names
        "module": 3,
        "path": 2,
        "registry": 4,
        "package": 2,
        "app": 2,
    }

    for sig in catalog:
        evidences: List[Evidence] = []
        # processes
        for hit in _match_patterns(col.processes, sig.processes):
            evidences.append(Evidence("process", hit, "process_list", weights["process"]))
        # services
        for hit in _match_patterns(col.services, sig.services):
            evidences.append(Evidence("service", hit, "service_list", weights["service"]))
        # modules (linux/mac)
        for hit in _match_patterns(col.modules, sig.modules):
            evidences.append(Evidence("module", hit, "kernel_modules", weights["module"]))
        # registry (windows)
        for hit in _match_patterns(col.registry, sig.registry):
            evidences.append(Evidence("registry", hit, "registry", weights["registry"]))
        # packages
        for hit in _match_patterns(col.packages, sig.packages):
            evidences.append(Evidence("package", hit, "packages", weights["package"]))
        # apps
        for hit in _match_patterns(col.apps, sig.apps):
            evidences.append(Evidence("app", hit, "apps", weights["app"]))
        # drivers/paths (approximate by path existence)
        path_hits = []
        for pat in sig.paths:
            p = pat.lower().rstrip("*")
            for have in col.paths:
                if p and p in have:
                    path_hits.append(have)
                    break
        for hit in path_hits:
            evidences.append(Evidence("path", hit, "filesystem", weights["path"]))

        score = sum(ev.weight for ev in evidences)
        if score <= 0:
            continue
        # Confidence heuristics
        if score >= 8 and any(ev.kind in {"service", "registry", "module"} for ev in evidences):
            conf = "high"
        elif score >= 5:
            conf = "medium"
        else:
            conf = "low"

        detections.append(Detection(
            vendor=sig.vendor,
            product=sig.product,
            score=score,
            confidence=conf,
            evidences=evidences,
        ))

    # sort by score desc
    detections.sort(key=lambda d: d.score, reverse=True)
    return detections


# -----------------------------
# Output Rendering
# -----------------------------

def render_table(dets: List[Detection]) -> str:
    if not dets:
        return "No EDR indicators found.\n"
    # simple fixed-width table
    headers = ["Vendor", "Product", "Score", "Confidence", "Evidence (kind:value)"]
    rows: List[List[str]] = []
    for d in dets:
        evs = ", ".join(f"{e.kind}:{e.value}" for e in d.evidences[:6])
        if len(d.evidences) > 6:
            evs += f", +{len(d.evidences)-6} more"
        rows.append([d.vendor, d.product, str(d.score), d.confidence, evs])
    colw = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    lines = [" | ".join(h.ljust(colw[i]) for i, h in enumerate(headers))]
    lines.append("-+-".join("-" * w for w in colw))
    for r in rows:
        lines.append(" | ".join(r[i].ljust(colw[i]) for i in range(len(headers))))
    return "\n".join(lines) + "\n"


def to_dict(dets: List[Detection]) -> Dict[str, object]:
    return {
        "schema_version": __schema_version__,
        "tool": "edr_check",
        "version": __version__,
        "timestamp_utc": _now_iso(),
        "host": {
            "hostname": platform.node(),
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "platform": platform.platform(),
                "python": sys.version.split()[0],
            },
        },
        "summary": {
            "edr_detected": bool(dets),
            "count": len(dets),
            "vendors": sorted({(d.vendor) for d in dets}),
        },
        "detections": [
            {
                "vendor": d.vendor,
                "product": d.product,
                "score": d.score,
                "confidence": d.confidence,
                "evidences": [
                    dataclasses.asdict(e) for e in d.evidences
                ],
            }
            for d in dets
        ],
        "disclaimer": (
            "Best-effort heuristic detection. Absence of evidence is not evidence of absence. "
            "Results depend on platform visibility and permissions."
        ),
    }


# -----------------------------
# CLI
# -----------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="edr_check",
        description="Cross-platform EDR presence checker for control validation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python edr_check.py
              python edr_check.py --format table
              python edr_check.py --format yaml --output edr_report.yaml
        """),
    )
    p.add_argument("--format", choices=["json", "yaml", "table"], default="json",
                   help="Output format.")
    p.add_argument("--output", "-o", metavar="PATH", help="Write report to PATH instead of stdout.")
    p.add_argument("--max-runtime", type=float, default=10.0,
                   help="Soft cap for runtime in seconds (best-effort).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


async def run_check(max_runtime: float) -> List[Detection]:
    try:
        col = await asyncio.wait_for(collect_all(), timeout=max_runtime)
    except asyncio.TimeoutError:
        # partial: attempt to continue with what we have by running collectors individually with small timeouts
        col = Collected(set(), set(), set(), set(), set(), set(), set())
    catalog = _edr_catalog()
    return evaluate_signatures(col, catalog)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    dets: List[Detection] = asyncio.run(run_check(args.max_runtime))
    report = to_dict(dets)

    if args.format == "json":
        out = json.dumps(report, ensure_ascii=False, indent=2)
    elif args.format == "yaml":
        out = _simple_yaml_dump(report)
    else:
        out = render_table(dets)

    if args.output:
        try:
            Path(args.output).write_text(out, encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Error writing output: {e}\n")
            return 2
        return 0
    else:
        sys.stdout.write(out + ("" if out.endswith("\n") else "\n"))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
