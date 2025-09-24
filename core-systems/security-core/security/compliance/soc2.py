# security-core/security/compliance/soc2.py
# Industrial SOC 2 engine: controls catalog, evidence collectors, rule evaluation,
# attestation pack, caching, metrics. Minimal deps: pydantic; httpx/yaml optional.

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union, Iterable, Callable

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

try:
    import httpx  # type: ignore
except Exception:
    httpx = None

from pydantic import BaseModel, Field, PositiveInt, validator

# =========================
# Enums and constants
# =========================

ControlType = Literal["preventive", "detective", "corrective"]
ControlCategory = Literal["security", "availability", "confidentiality", "processing_integrity", "privacy"]
Severity = Literal["low", "medium", "high", "critical"]
Frequency = Literal["continuous", "daily", "weekly", "monthly", "quarterly", "on_event"]
Decision = Literal["PASS", "WARN", "FAIL", "UNVERIFIED"]

# =========================
# Models
# =========================

class EvidenceRequirement(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    source: Literal["fs", "http", "inline"] = "inline"
    # For fs: path supports glob; For http: GET url; For inline: payload is used directly
    path: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    timeout_ms: PositiveInt = 2500
    # Minimal schema: required keys we expect to exist in payload
    required_keys: List[str] = Field(default_factory=list)
    ttl_seconds: PositiveInt = 600

class RuleSpec(BaseModel):
    # Simple DSL of checks evaluated over merged evidence payloads
    # type: require_keys | exists | threshold | value_in | count_ge
    type: Literal["require_keys", "exists", "threshold", "value_in", "count_ge"]
    path: Optional[str] = None            # dot.path for lookup (supports dots and [*] for any array entry)
    keys: List[str] = Field(default_factory=list)  # for require_keys
    op: Optional[Literal[">=", ">", "<=", "<", "==", "!="]] = None
    value: Optional[Any] = None
    in_set: Optional[List[Any]] = None
    min_count: Optional[int] = None
    warn_only: bool = False               # downgrade FAIL to WARN if True

class Control(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    title: str
    description: str
    category: ControlCategory = "security"
    tsc_ref: Optional[str] = None              # optional Trust Services Criteria reference
    type: ControlType = "preventive"
    severity: Severity = "medium"
    frequency: Frequency = "continuous"
    owner: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    requirements: List[EvidenceRequirement] = Field(default_factory=list)
    rules: List[RuleSpec] = Field(default_factory=list)
    # If true, absence of evidence yields UNVERIFIED (not FAIL)
    soft_on_missing_evidence: bool = True

class Evidence(BaseModel):
    requirement_id: str
    collected_at: int
    collector: str
    ok: bool
    payload: Any = None
    sha256_hex: Optional[str] = None
    error: Optional[str] = None
    cached: bool = False
    uri: Optional[str] = None

class Finding(BaseModel):
    rule: RuleSpec
    decision: Decision
    message: str
    path: Optional[str] = None

class ControlResult(BaseModel):
    control_id: str
    decision: Decision
    findings: List[Finding] = Field(default_factory=list)
    evidence: Dict[str, Evidence] = Field(default_factory=dict)
    started_at: int
    finished_at: int
    severity: Severity
    category: ControlCategory
    tsc_ref: Optional[str] = None

class RunReport(BaseModel):
    run_id: str
    started_at: int
    finished_at: int
    env: str
    results: List[ControlResult]
    metrics: Dict[str, Any]
    summary: Dict[str, Any]
    manifest_sha256: str

# =========================
# Utility helpers
# =========================

def _now_s() -> int:
    return int(time.time())

def _sha256_hex(data: bytes) -> str:
    h = hashlib.sha256(); h.update(data); return h.hexdigest()

def _json_bytes(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _lookup(data: Any, path: Optional[str]) -> List[Any]:
    """
    Very small JSON path utility:
    - dot.separated paths: a.b.c
    - [*] traverses arrays
    Returns all matching values.
    """
    if path is None or path == "" or data is None:
        return []
    parts: List[str] = []
    buf = ""
    for ch in path:
        if ch == ".":
            if buf:
                parts.append(buf); buf = ""
        else:
            buf += ch
    if buf:
        parts.append(buf)

    def step(values: List[Any], token: str) -> List[Any]:
        out: List[Any] = []
        any_arr = token.endswith("[*]")
        key = token[:-3] if any_arr else token
        for v in values:
            if isinstance(v, dict) and key in v:
                val = v[key]
                if any_arr and isinstance(val, list):
                    out.extend(val)
                else:
                    out.append(val)
            elif isinstance(v, list):
                try:
                    idx = int(key)
                    if 0 <= idx < len(v):
                        out.append(v[idx])
                except Exception:
                    # key over list not supported unless numeric
                    pass
        return out

    vals: List[Any] = [data]
    for tok in parts:
        vals = step(vals, tok)
        if not vals:
            break
    return vals

def _require_keys(payload: Any, keys: List[str]) -> Tuple[bool, List[str]]:
    missing: List[str] = []
    if not isinstance(payload, dict):
        return False, keys
    for k in keys:
        if k not in payload:
            missing.append(k)
    return (len(missing) == 0), missing

# =========================
# Evidence collectors (pluggable)
# =========================

class Collector:
    name = "base"
    async def collect(self, req: EvidenceRequirement) -> Evidence:
        raise NotImplementedError

class InlineCollector(Collector):
    name = "inline"
    def __init__(self, inline_store: Dict[str, Any]):
        self._inline = inline_store

    async def collect(self, req: EvidenceRequirement) -> Evidence:
        started = _now_s()
        payload = self._inline.get(req.id)
        ok = payload is not None
        sha = _sha256_hex(_json_bytes(payload)) if ok else None
        return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=ok, payload=payload, sha256_hex=sha)

class FSCollector(Collector):
    name = "fs"

    async def collect(self, req: EvidenceRequirement) -> Evidence:
        started = _now_s()
        try:
            if not req.path:
                raise ValueError("fs collector requires 'path'")
            matches = list(Path().glob(req.path))
            if not matches:
                raise FileNotFoundError(req.path)
            # read first match
            p = matches[0]
            raw = p.read_bytes()
            text = raw.decode("utf-8", errors="ignore")
            data: Any = None
            if p.suffix.lower() in {".yaml", ".yml"} and yaml is not None:
                data = yaml.safe_load(text)
            else:
                try:
                    data = json.loads(text)
                except Exception:
                    data = {"raw": text}
            ok = True
            sha = _sha256_hex(_json_bytes(data))
            return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=ok, payload=data, sha256_hex=sha, uri=str(p))
        except Exception as e:
            return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=False, error=str(e))

class HTTPCollector(Collector):
    name = "http"

    async def collect(self, req: EvidenceRequirement) -> Evidence:
        started = _now_s()
        if httpx is None:
            return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=False, error="httpx not installed")
        if not req.path:
            return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=False, error="http collector requires 'path' (URL)")
        try:
            timeout = httpx.Timeout(req.timeout_ms / 1000.0)
            async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
                r = await client.get(req.path, headers=req.headers or {})
                r.raise_for_status()
                ctype = r.headers.get("content-type", "")
                data: Any
                if "json" in ctype:
                    data = r.json()
                elif "yaml" in ctype and yaml is not None:
                    data = yaml.safe_load(r.text)
                else:
                    try:
                        data = r.json()
                    except Exception:
                        data = {"raw": r.text}
                sha = _sha256_hex(_json_bytes(data))
                return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=True, payload=data, sha256_hex=sha, uri=req.path)
        except Exception as e:
            return Evidence(requirement_id=req.id, collected_at=started, collector=self.name, ok=False, error=str(e))

# Collector registry
_COLLECTORS: Dict[str, Collector] = {}

def register_collector(name: str, collector: Collector) -> None:
    _COLLECTORS[name] = collector

def get_collector(source: str) -> Optional[Collector]:
    return _COLLECTORS.get(source)

# =========================
# Evidence cache
# =========================

@dataclass
class _CacheItem:
    evidence: Evidence
    expires_at: int

class EvidenceCache:
    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str], _CacheItem] = {}

    def get(self, control_id: str, req: EvidenceRequirement) -> Optional[Evidence]:
        key = (control_id, req.id)
        item = self._store.get(key)
        if not item:
            return None
        if _now_s() > item.expires_at:
            self._store.pop(key, None)
            return None
        ev = item.evidence.copy()
        ev.cached = True
        return ev

    def put(self, control_id: str, req: EvidenceRequirement, ev: Evidence) -> None:
        ttl = int(req.ttl_seconds)
        self._store[(control_id, req.id)] = _CacheItem(evidence=ev, expires_at=_now_s() + ttl)

# =========================
# Rule evaluation
# =========================

class RuleEvaluator:
    def evaluate(self, rule: RuleSpec, evidence_payloads: Dict[str, Any]) -> Finding:
        # Merge payloads into a single dict under keys by requirement_id
        merged = evidence_payloads
        decision: Decision = "UNVERIFIED"
        msg = ""

        # Helper to target either merged or a path
        def get_values(p: Optional[str]) -> List[Any]:
            if not p:
                return [merged]
            return _lookup(merged, p)

        if rule.type == "require_keys":
            vals = get_values(rule.path)
            if not vals:
                decision = "UNVERIFIED"
                msg = f"path not found: {rule.path}"
            else:
                ok_all = True
                missing_total: List[str] = []
                for v in vals:
                    ok, missing = _require_keys(v, rule.keys)
                    if not ok:
                        ok_all = False
                        missing_total.extend(missing)
                if ok_all:
                    decision = "PASS"
                    msg = "all required keys present"
                else:
                    decision = "WARN" if rule.warn_only else "FAIL"
                    msg = f"missing keys: {sorted(set(missing_total))}"

        elif rule.type == "exists":
            vals = get_values(rule.path)
            if vals:
                decision = "PASS"
                msg = "value exists"
            else:
                decision = "WARN" if rule.warn_only else "FAIL"
                msg = "path not found"

        elif rule.type == "threshold":
            vals = get_values(rule.path)
            if not vals:
                decision = "UNVERIFIED"
                msg = "no values to compare"
            else:
                # Take any numeric values and apply op to each; all must satisfy
                numeric = []
                for v in vals:
                    try:
                        numeric.append(float(v))
                    except Exception:
                        pass
                if not numeric:
                    decision = "UNVERIFIED"
                    msg = "no numeric values at path"
                else:
                    op = rule.op or ">="
                    ref = float(rule.value if rule.value is not None else 0.0)
                    ok = all(_compare(x, op, ref) for x in numeric)
                    decision = "PASS" if ok else ("WARN" if rule.warn_only else "FAIL")
                    msg = f"threshold {op} {ref}, values={numeric}"

        elif rule.type == "value_in":
            vals = get_values(rule.path)
            if not vals:
                decision = "UNVERIFIED"
                msg = "no value for value_in"
            else:
                allowed = set(rule.in_set or [])
                ok = all(v in allowed for v in vals)
                decision = "PASS" if ok else ("WARN" if rule.warn_only else "FAIL")
                msg = f"allowed={sorted(list(allowed))}, values={vals}"

        elif rule.type == "count_ge":
            vals = get_values(rule.path)
            count = 0
            for v in vals:
                if isinstance(v, list):
                    count += len(v)
                else:
                    count += 1
            minc = int(rule.min_count or 1)
            ok = count >= minc
            decision = "PASS" if ok else ("WARN" if rule.warn_only else "FAIL")
            msg = f"count={count}, required>={minc}"

        else:
            decision = "UNVERIFIED"
            msg = f"unsupported rule type: {rule.type}"

        return Finding(rule=rule, decision=decision, message=msg, path=rule.path)

def _compare(x: float, op: str, y: float) -> bool:
    if op == ">=": return x >= y
    if op == "<=": return x <= y
    if op == ">":  return x > y
    if op == "<":  return x < y
    if op == "==": return x == y
    if op == "!=": return x != y
    return False

# =========================
# Engine
# =========================

class SOCEngine:
    def __init__(self, env: str = "prod") -> None:
        self.env = env
        self._controls: List[Control] = []
        self._cache = EvidenceCache()
        self._evaluator = RuleEvaluator()
        self._metrics: Dict[str, Any] = {
            "runs": 0, "controls": 0, "evidence_collected": 0, "evidence_cached": 0,
            "pass": 0, "warn": 0, "fail": 0, "unverified": 0, "errors": 0
        }

    # -------- controls loading --------

    def load_from_yaml(self, path: Union[str, Path]) -> None:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load controls from YAML")
        p = Path(path)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        controls = []
        for item in data.get("controls", []):
            controls.append(Control(**item))
        self._controls = controls
        self._metrics["controls"] = len(self._controls)

    def set_controls(self, controls: List[Control]) -> None:
        self._controls = list(controls)
        self._metrics["controls"] = len(self._controls)

    def controls(self) -> List[Control]:
        return list(self._controls)

    # -------- run --------

    async def run_once(self, inline_evidence: Optional[Dict[str, Any]] = None) -> RunReport:
        run_id = _sha256_hex(os.urandom(16))
        started = _now_s()
        # default collectors
        register_collector("inline", InlineCollector(inline_evidence or {}))
        register_collector("fs", FSCollector())
        register_collector("http", HTTPCollector())

        results: List[ControlResult] = []
        tasks: List[asyncio.Task] = []
        # naive sequential; could be parallelized per control
        for c in self._controls:
            res = await self._evaluate_control(c)
            results.append(res)
            # metrics
            self._metrics[res.decision.lower()] += 1

        finished = _now_s()
        summary = self._build_summary(results)
        manifest = {
            "run_id": run_id,
            "env": self.env,
            "started_at": started,
            "finished_at": finished,
            "results": [self._result_manifest(r) for r in results],
            "summary": summary,
            "metrics": self._metrics,
        }
        manifest_sha = _sha256_hex(_json_bytes(manifest))
        report = RunReport(
            run_id=run_id,
            started_at=started,
            finished_at=finished,
            env=self.env,
            results=results,
            metrics=dict(self._metrics),
            summary=summary,
            manifest_sha256=manifest_sha,
        )
        self._metrics["runs"] += 1
        return report

    async def _evaluate_control(self, control: Control) -> ControlResult:
        st = _now_s()
        collected: Dict[str, Evidence] = {}
        merged_payloads: Dict[str, Any] = {}
        # Collect evidence with caching
        for req in control.requirements:
            ev = self._cache.get(control.id, req)
            if ev is None:
                ev = await self._collect(req)
                if ev.ok:
                    self._cache.put(control.id, req, ev)
            else:
                self._metrics["evidence_cached"] += 1
            collected[req.id] = ev
            if ev.ok:
                merged_payloads[req.id] = ev.payload
            else:
                self._metrics["errors"] += 1

        # Evaluate rules
        findings: List[Finding] = []
        decisions: List[Decision] = []

        # If any required evidence missing and not soft, mark FAIL
        missing = [rid for rid, ev in collected.items() if (not ev.ok)]
        if missing and not control.soft_on_missing_evidence:
            findings.append(Finding(rule=RuleSpec(type="exists", path=None), decision="FAIL", message=f"evidence missing: {missing}"))
            decisions.append("FAIL")
        else:
            for rule in control.rules:
                f = self._evaluator.evaluate(rule, merged_payloads)
                findings.append(f)
                decisions.append(f.decision)

        # Aggregate decision by severity: FAIL > WARN > UNVERIFIED > PASS
        decision = _aggregate_decision(decisions)

        fin = _now_s()
        return ControlResult(
            control_id=control.id,
            decision=decision,
            findings=findings,
            evidence=collected,
            started_at=st,
            finished_at=fin,
            severity=control.severity,
            category=control.category,
            tsc_ref=control.tsc_ref,
        )

    async def _collect(self, req: EvidenceRequirement) -> Evidence:
        col = get_collector(req.source)
        if not col:
            return Evidence(requirement_id=req.id, collected_at=_now_s(), collector="none", ok=False, error=f"unknown collector: {req.source}")
        ev = await col.collect(req)
        if ev.ok and req.required_keys:
            ok, missing = _require_keys(ev.payload, req.required_keys)
            if not ok:
                ev.ok = False
                ev.error = f"missing required keys: {missing}"
        if ev.ok:
            self._metrics["evidence_collected"] += 1
        else:
            self._metrics["errors"] += 1
        return ev

    # -------- attestation --------

    def build_attestation_pack(self, report: RunReport, sign_private_b64: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns attestation dictionary: manifest, report (sanitized), signatures (optional).
        If sign_private_b64 provided (Ed25519 raw private key base64), produce detached signature.
        """
        manifest = {
            "run_id": report.run_id,
            "env": report.env,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "manifest_sha256": report.manifest_sha256,
            "summary": report.summary,
        }
        pack: Dict[str, Any] = {"manifest": manifest, "report": json.loads(report.json())}

        if sign_private_b64:
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519  # type: ignore
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(sign_private_b64))
                sig = priv.sign(_json_bytes(pack["manifest"]))
                pack["signature"] = {"alg": "Ed25519", "sig_b64": base64.b64encode(sig).decode("ascii")}
            except Exception as e:
                pack["signature_error"] = str(e)
        pack["pack_sha256"] = _sha256_hex(_json_bytes(pack))
        return pack

    # -------- helpers --------

    def _build_summary(self, results: List[ControlResult]) -> Dict[str, Any]:
        total = len(results)
        counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "UNVERIFIED": 0}
        sev_counts: Dict[str, int] = {}
        for r in results:
            counts[r.decision] += 1
            sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        return {"total": total, "by_decision": counts, "by_severity": sev_counts}

    def _result_manifest(self, r: ControlResult) -> Dict[str, Any]:
        ev_index = {
            k: {"sha256_hex": v.sha256_hex, "collector": v.collector, "uri": v.uri, "ok": v.ok, "collected_at": v.collected_at}
            for k, v in r.evidence.items()
        }
        return {"control_id": r.control_id, "decision": r.decision, "evidence_index": ev_index, "started_at": r.started_at, "finished_at": r.finished_at}

def _aggregate_decision(decisions: Iterable[Decision]) -> Decision:
    order = {"FAIL": 3, "WARN": 2, "UNVERIFIED": 1, "PASS": 0}
    top = "PASS"
    maxv = -1
    for d in decisions:
        v = order.get(d, 0)
        if v > maxv:
            maxv = v
            top = d
    return top  # type: ignore

# =========================
# Example YAML (reference)
# =========================
"""
controls:
  - id: "CC-Change-Management"
    title: "Changes are authorized and tracked"
    description: "All production changes are reviewed and approved"
    category: "security"
    tsc_ref: "CC8.1"
    type: "preventive"
    severity: "high"
    frequency: "continuous"
    requirements:
      - id: "cm.pull_requests"
        source: "http"
        path: "https://vcs.example/api/prs?state=merged&label=approved"
        required_keys: ["items"]
        ttl_seconds: 300
    rules:
      - type: "count_ge"
        path: "cm.pull_requests.items[*]"
        min_count: 1
        warn_only: false

  - id: "CC-Identity-MFA"
    title: "MFA enforced for admins"
    description: "Admin accounts must have MFA enabled"
    category: "security"
    tsc_ref: "CC6.1"
    type: "preventive"
    severity: "critical"
    frequency: "continuous"
    requirements:
      - id: "iam.accounts"
        source: "fs"
        path: "artifacts/iam_accounts.json"
        required_keys: ["accounts"]
        ttl_seconds: 600
    rules:
      - type: "threshold"
        path: "iam.accounts.accounts[*].mfa_enabled_ratio"
        op: ">="
        value: 1.0
"""

# =========================
# Minimal CLI for debugging (optional)
# =========================

if __name__ == "__main__":  # pragma: no cover
    import argparse, sys
    ap = argparse.ArgumentParser(description="Run SOC 2 controls once")
    ap.add_argument("--env", default=os.getenv("RUNTIME_ENV", "prod"))
    ap.add_argument("--yaml", required=False, help="Path to controls YAML")
    args = ap.parse_args()

    async def _main():
        eng = SOCEngine(env=args.env)
        if args.yaml:
            if yaml is None:
                print("PyYAML is required for --yaml", file=sys.stderr); sys.exit(2)
            eng.load_from_yaml(args.yaml)
        else:
            # fallback demo control if YAML not provided
            eng.set_controls([
                Control(
                    id="DEMO-Logging-Enabled",
                    title="Central logging enabled",
                    description="Ensure logging stream exists and has events",
                    category="security",
                    severity="medium",
                    requirements=[
                        EvidenceRequirement(id="log.stream", source="inline", ttl_seconds=60),
                    ],
                    rules=[
                        RuleSpec(type="exists", path="log.stream.name"),
                        RuleSpec(type="count_ge", path="log.stream.events[*]", min_count=1),
                    ],
                )
            ])
        rep = await eng.run_once(inline_evidence={"log.stream": {"name": "audit-stream", "events": [1,2,3]}})
        pack = eng.build_attestation_pack(rep)
        print(json.dumps(pack["manifest"], indent=2, ensure_ascii=False))

    asyncio.run(_main())
