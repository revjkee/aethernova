# zero-trust-core/zero_trust/posture/collectors.py
# Industrial posture signal collectors for Zero Trust device evaluation.
# Stdlib-only. Async-first. Includes: base collector, plugin registry, runner with concurrency,
# retries, timeouts, simple circuit breaker, caching, privacy redaction, normalization.
from __future__ import annotations

import abc
import asyncio
import base64
import dataclasses
import hashlib
import json
import logging
import os
import platform
import re
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Type, Union
from urllib import request as _urlreq
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# ---------------------------
# Common types and utilities
# ---------------------------

EpochS = float

def _now() -> EpochS:
    return time.time()

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

@dataclass(frozen=True)
class Signal:
    key: str                      # e.g. "os.version"
    value: Any
    source: str                   # enum-like: "local", "pki", "mdm:intune", "edr:crowdstrike", "attestation:windows"
    ts: EpochS                    # collection timestamp (epoch seconds)
    stale_ttl: float              # seconds before considered stale
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass
class CollectorResult:
    signals: List[Signal] = field(default_factory=list)
    duration_s: float = 0.0
    error: Optional[str] = None
    skipped: bool = False         # e.g., circuit open or unsupported platform

# ---------------------------
# Privacy redaction
# ---------------------------

@dataclass
class RedactionConfig:
    # redact keys by exact name and by regex applied to attribute keys/values
    redact_keys: Tuple[str, ...] = ("serialNumber", "username", "wifi.ssid", "token", "secret")
    redact_regex: Optional[re.Pattern] = re.compile(r"(?i)(token|secret|cookie|authorization)")
    replacement: str = "[REDACTED]"

def redact_value(key: str, value: Any, cfg: RedactionConfig) -> Any:
    try:
        if key in cfg.redact_keys:
            return cfg.replacement
        if isinstance(value, str):
            if cfg.redact_regex and cfg.redact_regex.search(value):
                return cfg.replacement
            return value
        if isinstance(value, Mapping):
            return {k: redact_value(k, v, cfg) for k, v in value.items()}
        if isinstance(value, list):
            return [redact_value(key, v, cfg) for v in value]
        return value
    except Exception:
        return cfg.replacement

# ---------------------------
# Collector base and registry
# ---------------------------

CollectorContext = Dict[str, Any]  # free-form context: tenant, device_id, headers, mTLS, tokens, etc.

@dataclass
class CollectorConfig:
    name: str
    timeout_s: float = 3.0
    retries: int = 1
    backoff_s: float = 0.2
    breaker_fail_threshold: int = 5     # open after N consecutive failures
    breaker_reset_after_s: float = 60.0 # half-open after cooldown
    stale_ttl_s: float = 600.0          # default staleness for produced signals
    enabled: bool = True

class BaseCollector(abc.ABC):
    kind: str = "base"
    def __init__(self, cfg: CollectorConfig):
        self.cfg = cfg
        self._fails = 0
        self._opened_at: Optional[EpochS] = None

    def _breaker_open(self) -> bool:
        if self._opened_at is None:
            return False
        return (_now() - self._opened_at) < self.cfg.breaker_reset_after_s

    def _on_success(self):
        self._fails = 0
        self._opened_at = None

    def _on_failure(self):
        self._fails += 1
        if self._fails >= self.cfg.breaker_fail_threshold:
            self._opened_at = _now()

    async def run(self, ctx: CollectorContext) -> CollectorResult:
        if not self.cfg.enabled:
            return CollectorResult(skipped=True)
        if self._breaker_open():
            return CollectorResult(skipped=True, error="circuit_open")
        start = _now()
        attempt = 0
        last_err: Optional[str] = None
        try:
            while True:
                attempt += 1
                try:
                    sigs = await asyncio.wait_for(self._collect(ctx), timeout=self.cfg.timeout_s)
                    self._on_success()
                    dur = max(0.0, _now() - start)
                    return CollectorResult(signals=sigs, duration_s=dur)
                except asyncio.TimeoutError:
                    last_err = "timeout"
                    self._on_failure()
                except Exception as e:
                    last_err = f"{type(e).__name__}: {e}"
                    self._on_failure()
                if attempt > self.cfg.retries:
                    break
                await asyncio.sleep(self.cfg.backoff_s * attempt)
            dur = max(0.0, _now() - start)
            return CollectorResult(duration_s=dur, error=last_err)
        finally:
            if last_err:
                logger.debug("collector %s failed attempt=%s err=%s", self.cfg.name, attempt, last_err)

    @abc.abstractmethod
    async def _collect(self, ctx: CollectorContext) -> List[Signal]:
        ...

# Registry
_REGISTRY: Dict[str, Type[BaseCollector]] = {}

def register_collector(kind: str):
    def deco(cls: Type[BaseCollector]):
        cls.kind = kind
        _REGISTRY[kind] = cls
        return cls
    return deco

def make_collector(kind: str, cfg: CollectorConfig) -> BaseCollector:
    cls = _REGISTRY.get(kind)
    if not cls:
        raise KeyError(f"unknown collector kind: {kind}")
    return cls(cfg)

# ---------------------------
# Local Agent Collector
# ---------------------------

@register_collector("local_agent")
class LocalAgentCollector(BaseCollector):
    """
    Collects OS/platform posture using stdlib and best-effort CLI probes.
    Signals (examples):
      - os.platform        -> windows|macos|linux
      - os.version         -> string
      - security.firewall.enabled -> bool|unknown
      - security.diskEncryption   -> filevault|bitlocker|luks|none|unknown
      - security.screenLock.enabled -> bool|unknown
    """
    async def _collect(self, ctx: CollectorContext) -> List[Signal]:
        now = _now()
        stale = self.cfg.stale_ttl_s
        plat = platform.system().lower()
        sigs: List[Signal] = [
            Signal("os.platform", plat, "local", now, stale),
            Signal("os.version", platform.version(), "local", now, stale),
            Signal("os.release", platform.release(), "local", now, stale),
        ]
        # Firewall
        fw = await self._probe_firewall(plat)
        sigs.append(Signal("security.firewall.enabled", fw, "local", now, stale))
        # Disk encryption
        enc = await self._probe_disk_encryption(plat)
        sigs.append(Signal("security.diskEncryption", enc, "local", now, stale))
        # Screen lock
        lock = await self._probe_screen_lock(plat)
        sigs.append(Signal("security.screenLock.enabled", lock, "local", now, stale))
        # Jailbreak/root (best-effort)
        jail_root = await self._probe_root_jailbreak(plat)
        sigs.append(Signal("device.jailbreak", jail_root.get("jailbreak", False), "local", now, stale))
        sigs.append(Signal("device.root", jail_root.get("root", False), "local", now, stale))
        return sigs

    async def _probe_firewall(self, plat: str) -> Union[bool, str]:
        try:
            if plat == "windows":
                # netsh advfirewall show allprofiles
                if not shutil_which("netsh"):
                    return "unknown"
                out = await run_cmd(["netsh", "advfirewall", "show", "allprofiles"])
                return "state on" in out.lower()
            if plat == "darwin":
                # defaults read /Library/Preferences/com.apple.alf globalstate -> 0/1/2
                if not shutil_which("defaults"):
                    return "unknown"
                out = await run_cmd(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"])
                try:
                    return int(out.strip()) in (1, 2)
                except Exception:
                    return "unknown"
            if plat == "linux":
                # ufw status | firewalld detection (best-effort)
                if shutil_which("ufw"):
                    out = await run_cmd(["ufw", "status"])
                    return "status: active" in out.lower()
                if shutil_which("firewall-cmd"):
                    out = await run_cmd(["firewall-cmd", "--state"])
                    return "running" in out.lower()
                # nftables check
                if shutil_which("nft"):
                    out = await run_cmd(["nft", "list", "ruleset"])
                    return len(out.strip()) > 0
                return "unknown"
            return "unknown"
        except Exception:
            return "unknown"

    async def _probe_disk_encryption(self, plat: str) -> str:
        try:
            if plat == "windows":
                if shutil_which("manage-bde"):
                    out = await run_cmd(["manage-bde", "-status"])
                    if "percentage encrypted: 100%" in out.lower() or "conversion status: fully encrypted" in out.lower():
                        return "bitlocker"
                    return "none"
                return "unknown"
            if plat == "darwin":
                if shutil_which("fdesetup"):
                    out = await run_cmd(["fdesetup", "status"])
                    if "filevault is on" in out.lower():
                        return "filevault"
                    return "none"
                return "unknown"
            if plat == "linux":
                # check mounts with 'dm-crypt' or 'crypt'
                try:
                    with open("/proc/mounts", "r", encoding="utf-8") as f:
                        m = f.read().lower()
                        if "dm-crypt" in m or " /dev/mapper/" in m:
                            return "luks"
                        return "none"
                except Exception:
                    return "unknown"
            return "unknown"
        except Exception:
            return "unknown"

    async def _probe_screen_lock(self, plat: str) -> Union[bool, str]:
        try:
            if plat == "windows":
                # policy check via registry would need winreg; keep best-effort
                return "unknown"
            if plat == "darwin":
                # com.apple.screensaver askForPassword = 1
                if shutil_which("defaults"):
                    out = await run_cmd(["/usr/bin/defaults", "read", "com.apple.screensaver", "askForPassword"])
                    return out.strip() == "1"
                return "unknown"
            if plat == "linux":
                # environment-dependent; assume unknown
                return "unknown"
            return "unknown"
        except Exception:
            return "unknown"

    async def _probe_root_jailbreak(self, plat: str) -> Dict[str, bool]:
        try:
            if plat == "linux":
                return {"root": os.geteuid() == 0, "jailbreak": False}
            if plat == "darwin":
                # jailbreak unlikely on macOS desktop; root if uid==0
                return {"root": os.geteuid() == 0, "jailbreak": False}
            if plat == "windows":
                # cannot reliably determine admin; return unknown flags as False
                return {"root": False, "jailbreak": False}
            return {"root": False, "jailbreak": False}
        except Exception:
            return {"root": False, "jailbreak": False}

# ---------------------------
# PKI / mTLS Collector
# ---------------------------

@register_collector("pki_mtls")
class PkiMtlsCollector(BaseCollector):
    """
    Consumes client cert details from ctx and produces:
      - mTLS.present
      - mTLS.eku.clientAuth (bool if provided)
      - mTLS.subject / issuer
      - mTLS.thumbprint (x5t#S256)
      - mTLS.ocspStatus (good|revoked|unknown) if present
    Context keys:
      ctx["mtls"] = {"der": bytes|None, "subject": str|None, "issuer": str|None,
                     "eku_client_auth": Optional[bool], "ocsp_status": Optional[str]}
    """
    async def _collect(self, ctx: CollectorContext) -> List[Signal]:
        now = _now(); stale = self.cfg.stale_ttl_s
        mtls = ctx.get("mtls") or {}
        der: Optional[bytes] = mtls.get("der")
        present = der is not None
        sigs: List[Signal] = [
            Signal("mTLS.present", present, "pki", now, stale),
        ]
        if present:
            thumb = _b64url(hashlib.sha256(der).digest())
            sigs.append(Signal("mTLS.thumbprint", thumb, "pki", now, stale))
        if "eku_client_auth" in mtls:
            sigs.append(Signal("mTLS.eku.clientAuth", bool(mtls.get("eku_client_auth")), "pki", now, stale))
        if "subject" in mtls and mtls["subject"]:
            sigs.append(Signal("mTLS.subject", str(mtls["subject"]), "pki", now, stale))
        if "issuer" in mtls and mtls["issuer"]:
            sigs.append(Signal("mTLS.issuer", str(mtls["issuer"]), "pki", now, stale))
        if "ocsp_status" in mtls and mtls["ocsp_status"]:
            status = str(mtls["ocsp_status"]).lower()
            if status not in ("good", "revoked", "unknown"):
                status = "unknown"
            sigs.append(Signal("mTLS.ocspStatus", status, "pki", now, stale))
        return sigs

# ---------------------------
# Generic HTTP Collector (MDM/EDR)
# ---------------------------

@dataclass
class HttpClientConfig:
    base_url: str
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_s: float = 3.0
    verify_ssl: bool = True

async def _http_get(cfg: HttpClientConfig, path: str) -> Tuple[int, str, Dict[str, str]]:
    url = urljoin(cfg.base_url.rstrip("/") + "/", path.lstrip("/"))
    req = _urlreq.Request(url, headers=cfg.headers, method="GET")
    loop = asyncio.get_running_loop()
    def _do():
        context = None
        if not cfg.verify_ssl and url.lower().startswith("https"):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with _urlreq.urlopen(req, timeout=cfg.timeout_s, context=context) as resp:
                code = resp.getcode()
                body = resp.read().decode("utf-8", "replace")
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                return code, body, hdrs
        except HTTPError as e:
            body = e.read().decode("utf-8", "replace") if hasattr(e, "read") else ""
            return e.code, body, {}
        except URLError as e:
            raise e
    return await loop.run_in_executor(None, _do)

@register_collector("http_json")
class HttpJsonCollector(BaseCollector):
    """
    Generic HTTP JSON collector for MDM/EDR endpoints.
    cfg.name should be like "mdm:intune" or "edr:crowdstrike" for source tagging.
    Context may hold templates for device_id/user_id interpolation into path.
    config overrides:
      ctx["http"]["path"], ctx["http"]["headers"], ctx["http"]["timeout_s"], ctx["http"]["verify_ssl"]
    The response JSON is mapped via ctx["http"]["mapping"]: dict "json_path" -> "signal.key".
    Supported json path: dot.key1.key2 (no arrays). Values copied as-is.
    """
    def __init__(self, cfg: CollectorConfig, http_cfg: Optional[HttpClientConfig] = None, default_path: str = "/"):
        super().__init__(cfg)
        self.http_cfg = http_cfg or HttpClientConfig(base_url="http://localhost/")
        self.default_path = default_path

    async def _collect(self, ctx: CollectorContext) -> List[Signal]:
        now = _now(); stale = self.cfg.stale_ttl_s
        http_ctx: Dict[str, Any] = ctx.get("http", {})
        path = str(http_ctx.get("path") or self.default_path)
        # interpolate using context
        path = path.format_map(DefaultingDict(ctx))
        # merge headers
        headers = dict(self.http_cfg.headers)
        headers.update(http_ctx.get("headers", {}))
        http_cfg = HttpClientConfig(
            base_url=self.http_cfg.base_url,
            headers=headers,
            timeout_s=float(http_ctx.get("timeout_s", self.http_cfg.timeout_s)),
            verify_ssl=bool(http_ctx.get("verify_ssl", self.http_cfg.verify_ssl)),
        )
        code, body, hdrs = await _http_get(http_cfg, path)
        if code >= 400:
            raise RuntimeError(f"http {code}")
        try:
            data = json.loads(body)
        except Exception as e:
            raise RuntimeError(f"bad json: {e}") from e
        mapping: Dict[str, str] = http_ctx.get("mapping") or {}
        src = self.cfg.name  # e.g. "mdm:intune"
        sigs: List[Signal] = []
        for json_path, signal_key in mapping.items():
            val = _json_extract_simple(data, json_path)
            sigs.append(Signal(signal_key, val, src, now, stale))
        # allow raw payload passthrough (redacted) for diagnostics
        if http_ctx.get("include_raw"):
            sigs.append(Signal(f"{src}.raw", {"size": len(body)}, src, now, stale, attributes={"digest": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()}))
        return sigs

def _json_extract_simple(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return None
        cur = cur[part]
    return cur

class DefaultingDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"

# ---------------------------
# Attestation Collector (framework)
# ---------------------------

VerifyFunc = Callable[[str, Dict[str, Any]], Awaitable[Dict[str, Any]]]
# VerifyFunc receives token str and expected claims, returns {"valid": bool, "claims": {...}, "reason": str|None}

@register_collector("attestation")
class AttestationCollector(BaseCollector):
    """
    Attestation tokens may come from Windows DHA, Android Play Integrity, Apple DeviceCheck/MDM.
    Context:
      ctx["attestation"] = {
        "windows_dha": {"token": "...", "expected": {"iss": "...", "aud": "..."}},
        "android_play": {"token": "...", "expected": {...}},
        "apple": {"token": "...", "expected": {...}}
      }
      ctx["attestation_verify"] = async callable(token, expected) -> {"valid":bool,"claims":dict,"reason":str|None}
    Produces:
      - attestation.summary
      - attestation.windows.secureBoot / tpm.present / tpm.version (if claims present)
      - attestation.android.deviceIntegrity / strongIntegrity / basicIntegrity
      - attestation.apple.platformAttestation
    Signature verification must be implemented by injected verify function (cryptography/JWKS out of scope here).
    """
    async def _collect(self, ctx: CollectorContext) -> List[Signal]:
        now = _now(); stale = self.cfg.stale_ttl_s
        src = "attestation"
        att: Dict[str, Any] = ctx.get("attestation") or {}
        verify: VerifyFunc = ctx.get("attestation_verify")  # must be provided by integrator
        if not verify:
            return [Signal("attestation.summary", {"valid": False, "reason": "no_verifier"}, src, now, stale)]
        sigs: List[Signal] = []
        summary: Dict[str, Any] = {}
        # Windows DHA
        if "windows_dha" in att:
            res = await verify(att["windows_dha"]["token"], att["windows_dha"].get("expected", {}))
            summary["windows"] = {"valid": bool(res.get("valid")), "reason": res.get("reason")}
            claims = res.get("claims") or {}
            sigs.extend([
                Signal("attestation.windows.secureBoot", bool(_getp(claims, "secure_boot")), src, now, stale),
                Signal("attestation.windows.virtualizationBasedSecurity", bool(_getp(claims, "vbs")), src, now, stale),
                Signal("attestation.windows.tpm.present", bool(_getp(claims, "tpm.present")), src, now, stale),
                Signal("attestation.windows.tpm.version", str(_getp(claims, "tpm.version") or ""), src, now, stale),
            ])
        # Android Play Integrity
        if "android_play" in att:
            res = await verify(att["android_play"]["token"], att["android_play"].get("expected", {}))
            summary["android"] = {"valid": bool(res.get("valid")), "reason": res.get("reason")}
            c = res.get("claims") or {}
            sigs.extend([
                Signal("attestation.android.deviceIntegrity", bool(_getp(c, "deviceIntegrity")), src, now, stale),
                Signal("attestation.android.strongIntegrity", bool(_getp(c, "strongIntegrity")), src, now, stale),
                Signal("attestation.android.basicIntegrity", bool(_getp(c, "basicIntegrity")), src, now, stale),
                Signal("attestation.android.bootloaderLocked", bool(_getp(c, "bootloaderLocked")), src, now, stale),
            ])
        # Apple
        if "apple" in att:
            res = await verify(att["apple"]["token"], att["apple"].get("expected", {}))
            summary["apple"] = {"valid": bool(res.get("valid")), "reason": res.get("reason")}
            c = res.get("claims") or {}
            sigs.append(Signal("attestation.apple.platformAttestation", bool(_getp(c, "platformAttestation")), src, now, stale))
            sigs.append(Signal("attestation.apple.secureBoot", bool(_getp(c, "secureBoot")), src, now, stale))
            sigs.append(Signal("attestation.apple.filevault", bool(_getp(c, "fileVault")), src, now, stale))
        sigs.append(Signal("attestation.summary", summary, src, now, stale))
        return sigs

def _getp(obj: Mapping[str, Any], path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return None
        cur = cur[part]
    return cur

# ---------------------------
# Runner / Aggregation
# ---------------------------

@dataclass
class RunnerConfig:
    parallelism: int = 8
    redact: RedactionConfig = RedactionConfig()
    drop_stale: bool = False

class PostureCollectorRunner:
    """
    Orchestrates collectors concurrently, merges signals, applies redaction, returns normalized dict.
    """
    def __init__(self, runner_cfg: RunnerConfig, collectors: Sequence[BaseCollector]):
        self.cfg = runner_cfg
        self.collectors = list(collectors)

    async def collect_all(self, ctx: CollectorContext) -> Dict[str, Any]:
        sem = asyncio.Semaphore(self.cfg.parallelism)
        async def _run(c: BaseCollector) -> CollectorResult:
            async with sem:
                return await c.run(ctx)

        tasks = [asyncio.create_task(_run(c)) for c in self.collectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge signals
        merged: Dict[str, Dict[str, Any]] = {}   # key -> {value, source, ts, stale_ttl, attributes}
        diagnostics: List[Dict[str, Any]] = []
        now = _now()

        for c, res in zip(self.collectors, results):
            if isinstance(res, Exception):
                diagnostics.append({"collector": c.cfg.name, "error": f"{type(res).__name__}: {res}"})
                continue
            diag = {"collector": c.cfg.name, "skipped": res.skipped, "error": res.error, "duration_s": round(res.duration_s, 4)}
            diagnostics.append(diag)
            for sig in res.signals:
                if self.cfg.drop_stale and (now - sig.ts) > sig.stale_ttl:
                    continue
                prev = merged.get(sig.key)
                # keep newest; if equal ts prefer non-"unknown"
                if (not prev) or (sig.ts >= prev["ts"] and prev.get("value") in (None, "unknown")):
                    val = redact_value(sig.key, sig.value, self.cfg.redact)
                    merged[sig.key] = {
                        "value": val,
                        "source": sig.source,
                        "ts": sig.ts,
                        "stale_ttl": sig.stale_ttl,
                        "attributes": {k: redact_value(k, v, self.cfg.redact) for k, v in sig.attributes.items()},
                    }

        # Normalize output
        out = {
            "collected_at": now,
            "signals": {k: v["value"] for k, v in merged.items()},
            "meta": {
                "sources": {k: v["source"] for k, v in merged.items()},
                "timestamps": {k: v["ts"] for k, v in merged.items()},
                "stale_ttls": {k: v["stale_ttl"] for k, v in merged.items()},
                "attributes": {k: v["attributes"] for k, v in merged.items()},
                "diagnostics": diagnostics,
            },
        }
        return out

# ---------------------------
# Utilities
# ---------------------------

def shutil_which(cmd: str) -> Optional[str]:
    # small re-implementation to avoid importing shutil for one function
    paths = os.environ.get("PATH", "").split(os.pathsep)
    exts = [""] + (os.environ.get("PATHEXT", "").split(os.pathsep) if os.name == "nt" else [])
    for p in paths:
        full = os.path.join(p, cmd)
        for ext in exts:
            cand = full + ext
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None

async def run_cmd(cmd: List[str]) -> str:
    """
    Runs a command with a short timeout inherited from event loop default.
    Captures stdout, returns text (utf-8 with replacement).
    """
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=2.5)
    except asyncio.TimeoutError:
        with suppress_exc(lambda: proc.kill()):
            pass
        raise
    text = (out_b or b"").decode("utf-8", "replace")
    return text

def suppress_exc(func: Callable[[], Any]) -> None:
    try:
        func()
    except Exception:
        pass

# ---------------------------
# Example factory (not executed)
# ---------------------------

def default_collectors() -> List[BaseCollector]:
    return [
        LocalAgentCollector(CollectorConfig(name="local", timeout_s=2.0, retries=0, stale_ttl_s=600)),
        PkiMtlsCollector(CollectorConfig(name="pki", timeout_s=1.0, retries=0, stale_ttl_s=300)),
    ]

# End of module
