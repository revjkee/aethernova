# datafabric-core/datafabric/governance/dlp_scanner.py
# Industrial-grade DLP scanner for DataFabric
# - Declarative policy (rules: PII, secrets, financial IDs, custom regex)
# - Multi-level severity, thresholds, suppression (allowlists, negative patterns)
# - Risk scoring and enforcement with block/quarantine/notify
# - Actions: redact/hash/tokenize via pluggable callback, quarantine sink callback
# - Auditing to JSONL with safe snippets (no full exposure)
# - Pandas & Spark integration (foreachBatch for streaming)
# - Environment-driven defaults and deterministic behavior
# - No hard deps except optional: pandas, pyspark

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ---------------------------
# Utilities
# ---------------------------

_NOW = lambda: dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)

def _safe_snippet(val: Any, max_len: int = 64) -> str:
    if val is None:
        return ""
    s = str(val)
    if len(s) <= max_len:
        return s
    # show head/tail only
    head = s[: max_len // 2]
    tail = s[-max_len // 2 :]
    return f"{head}…{tail}"

def _hash_sample(s: str, algo: str = "sha256") -> str:
    return getattr(hashlib, algo)(s.encode("utf-8")).hexdigest()[:16]

def _env_flag(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

# ---------------------------
# Built-in detectors (regex)
# ---------------------------

REGEX_LIBRARY: Dict[str, str] = {
    # PII
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "phone": r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "ipv6": r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b",
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    "ssn_us": r"\b\d{3}-\d{2}-\d{4}\b",
    "passport_generic": r"\b([A-Z0-9]{6,9})\b",
    # Payment / finance
    "credit_card": r"\b(?:\d[ -]*?){13,19}\b",
    "swift_bic": r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b",
    # Secrets / credentials
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "aws_secret_key": r"(?i)aws(.{0,20})?(secret|access|key)\s*[:=]\s*[A-Za-z0-9/+=]{40}",
    "gcp_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "bearer_jwt": r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
    "basic_auth": r"\bBasic\s+[A-Za-z0-9+/=]{10,}\b",
    "private_key_block": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    # Crypto
    "eth_address": r"\b0x[a-fA-F0-9]{40}\b",
    "btc_address": r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
}

def compile_patterns(patterns: Mapping[str, str]) -> Dict[str, re.Pattern]:
    return {k: re.compile(v, re.I | re.M) for k, v in patterns.items()}

COMPILED_LIBRARY = compile_patterns(REGEX_LIBRARY)

# ---------------------------
# Policy model
# ---------------------------

@dataclass
class Suppression:
    allow_domains: List[str] = field(default_factory=list)    # for emails
    allow_regex: List[str] = field(default_factory=list)      # negative patterns
    min_length: int = 0                                       # ignore very short matches

    def to_runtime(self) -> Dict[str, re.Pattern]:
        return {f"rx_{i}": re.compile(pat, re.I | re.M) for i, pat in enumerate(self.allow_regex)}

@dataclass
class ActionSpec:
    type: str                      # 'redact' | 'hash' | 'tokenize' | 'block' | 'notify' | 'quarantine'
    params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Rule:
    id: str
    name: str
    pattern_ref: str               # key from REGEX_LIBRARY or custom name present in policy.custom_patterns
    severity: str = "high"         # low|medium|high|critical
    min_count: int = 1             # min matches to consider violated at cell level
    scope: str = "cell"            # cell|row|column|table
    actions: List[ActionSpec] = field(default_factory=lambda: [ActionSpec(type="redact")])
    suppression: Suppression = field(default_factory=Suppression)
    context_window: int = 32       # snippet chars around match
    max_findings: int = 5          # per cell
    threshold: int = 1             # per row aggregation

@dataclass
class DLPPolicy:
    version: str = "1.0"
    namespace: str = "datafabric.dlp"
    rules: List[Rule] = field(default_factory=list)
    custom_patterns: Dict[str, str] = field(default_factory=dict)
    risk_weights: Dict[str, int] = field(default_factory=lambda: {
        "low": 1, "medium": 3, "high": 7, "critical": 10
    })
    enforce_severity_at_least: str = "high"  # minimal severity to enforce block
    audit_path: Optional[str] = None         # JSONL sink path

    @staticmethod
    def from_env(env: str = "DF_DLP_POLICY_JSON") -> "DLPPolicy":
        raw = os.getenv(env)
        if not raw:
            # Sensible default policy
            rules = [
                Rule(id="R_EMAIL", name="Email address", pattern_ref="email", severity="medium",
                     actions=[ActionSpec("redact")],
                     suppression=Suppression(allow_domains=os.getenv("DF_DLP_ALLOW_EMAIL_DOMAINS", "").split(",") if os.getenv("DF_DLP_ALLOW_EMAIL_DOMAINS") else [])),
                Rule(id="R_CC", name="Payment card", pattern_ref="credit_card", severity="critical",
                     actions=[ActionSpec("block"), ActionSpec("quarantine"), ActionSpec("notify")]),
                Rule(id="R_PK", name="Private key", pattern_ref="private_key_block", severity="critical",
                     actions=[ActionSpec("block"), ActionSpec("quarantine"), ActionSpec("notify")]),
                Rule(id="R_AWS", name="AWS access key", pattern_ref="aws_access_key", severity="high",
                     actions=[ActionSpec("hash"), ActionSpec("quarantine"), ActionSpec("notify")]),
                Rule(id="R_JWT", name="JWT token", pattern_ref="bearer_jwt", severity="high",
                     actions=[ActionSpec("redact")]),
            ]
            return DLPPolicy(
                rules=rules,
                audit_path=os.getenv("DF_DLP_AUDIT_PATH"),
            )
        try:
            d = json.loads(raw)
        except Exception as e:
            raise ValueError(f"Invalid {env}: {e}")
        # Construct
        custom = d.get("custom_patterns", {})
        rules = []
        for rd in d.get("rules", []):
            sup = rd.get("suppression", {})
            rule = Rule(
                id=rd["id"],
                name=rd.get("name", rd["id"]),
                pattern_ref=rd["pattern_ref"],
                severity=rd.get("severity", "high"),
                min_count=int(rd.get("min_count", 1)),
                scope=rd.get("scope", "cell"),
                actions=[ActionSpec(**a) for a in rd.get("actions", [{"type": "redact"}])],
                suppression=Suppression(
                    allow_domains=sup.get("allow_domains", []),
                    allow_regex=sup.get("allow_regex", []),
                    min_length=int(sup.get("min_length", 0)),
                ),
                context_window=int(rd.get("context_window", 32)),
                max_findings=int(rd.get("max_findings", 5)),
                threshold=int(rd.get("threshold", 1)),
            )
            rules.append(rule)
        return DLPPolicy(
            version=str(d.get("version", "1.0")),
            namespace=str(d.get("namespace", "datafabric.dlp")),
            rules=rules,
            custom_patterns=custom,
            risk_weights=d.get("risk_weights", {"low":1,"medium":3,"high":7,"critical":10}),
            enforce_severity_at_least=d.get("enforce_severity_at_least", "high"),
            audit_path=d.get("audit_path"),
        )

# ---------------------------
# Findings & Result
# ---------------------------

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    column: Optional[str]
    row_index: Optional[int]
    snippet: str
    count: int
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    ok: bool
    total_findings: int
    risk_score: int
    findings: List[Finding]
    enforced: bool
    blocked: bool
    reason: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

# ---------------------------
# DLP Scanner
# ---------------------------

class DLPScanner:
    def __init__(
        self,
        policy: Optional[DLPPolicy] = None,
        tokenizer: Optional[Callable[[str, Dict[str, Any]], str]] = None,   # for 'tokenize' action
        masker: Optional[Callable[[str, Any, Dict[str, Any]], Any]] = None, # for redact/hash via external masker
        quarantine_sink: Optional[Callable[[Mapping[str, Any]], None]] = None,
        notifier: Optional[Callable[[ScanResult], None]] = None,
        compiled_cache: Optional[Dict[str, re.Pattern]] = None,
    ):
        self.policy = policy or DLPPolicy.from_env()
        self.tokenizer = tokenizer
        self.masker = masker
        self.quarantine_sink = quarantine_sink
        self.notifier = notifier
        self.compiled = dict(COMPILED_LIBRARY)
        # add custom patterns
        for k, v in (self.policy.custom_patterns or {}).items():
            self.compiled[k] = re.compile(v, re.I | re.M)
        if compiled_cache:
            self.compiled.update(compiled_cache)
        self._sev_order = ["low", "medium", "high", "critical"]

    # --------- Core matching ---------

    def _passes_suppression(self, rule: Rule, text: str, match: re.Match) -> bool:
        if rule.suppression.min_length > 0 and len(match.group(0)) < rule.suppression.min_length:
            return False
        # email domain allowlist
        if rule.pattern_ref == "email" and rule.suppression.allow_domains:
            try:
                domain = match.group(0).split("@", 1)[1].lower()
                if domain in [d.strip().lower() for d in rule.suppression.allow_domains if d.strip()]:
                    return False
            except Exception:
                pass
        # negative patterns
        for _, rx in rule.suppression.to_runtime().items():
            if rx.search(text):
                return False
        return True

    def _scan_text(self, text: str, rule: Rule) -> Tuple[int, List[str]]:
        if not text:
            return 0, []
        rx = self.compiled.get(rule.pattern_ref)
        if not rx:
            return 0, []
        findings: List[str] = []
        cnt = 0
        for m in rx.finditer(text):
            if not self._passes_suppression(rule, text, m):
                continue
            cnt += 1
            if len(findings) < rule.max_findings:
                start = max(0, m.start() - rule.context_window)
                end = min(len(text), m.end() + rule.context_window)
                findings.append(_safe_snippet(text[start:end]))
        return cnt, findings

    # --------- Actions ---------

    def _apply_actions_on_cell(self, value: Any, rule: Rule, column: Optional[str]) -> Any:
        v = value
        for act in rule.actions:
            t = act.type
            p = dict(act.params or {})
            if t == "redact":
                v = "***REDACTED***"
            elif t == "hash":
                v = f"HASH:{_hash_sample(str(v))}"
            elif t == "tokenize":
                if not self.tokenizer:
                    v = f"TOKEN:{_hash_sample(str(v))}"
                else:
                    v = self.tokenizer(str(v), {"rule": rule.id, "column": column})
            elif t == "quarantine":
                if self.quarantine_sink:
                    try:
                        self.quarantine_sink({"column": column, "rule": rule.id, "value_hash": _hash_sample(str(value))})
                    except Exception:
                        pass
            elif t == "notify":
                # real notification happens after aggregate; here we noop
                pass
            elif t == "block":
                # handled at aggregate result
                pass
        return v

    # --------- Record scanning ---------

    def scan_record(self, record: Mapping[str, Any]) -> ScanResult:
        findings: List[Finding] = []
        risk = 0
        blocked = False
        enforce_min = self.policy.enforce_severity_at_least

        for col, val in record.items():
            text = str(val) if isinstance(val, (str, int, float)) or val is None else json.dumps(val, ensure_ascii=False)
            for rule in self.policy.rules:
                cnt, snippets = self._scan_text(text, rule)
                if cnt >= rule.min_count:
                    findings.append(Finding(
                        rule_id=rule.id, rule_name=rule.name, severity=rule.severity,
                        column=col, row_index=None,
                        snippet=" | ".join(snippets),
                        count=cnt,
                        context={"column": col}
                    ))
                    risk += self.policy.risk_weights.get(rule.severity, 1) * cnt
                    if self._sev_order.index(rule.severity) >= self._sev_order.index(enforce_min):
                        # mark potential block; final decision after all rules
                        blocked = blocked or any(a.type == "block" for a in rule.actions)

        res = ScanResult(ok=(len(findings) == 0), total_findings=len(findings),
                         risk_score=risk, findings=findings,
                         enforced=blocked, blocked=blocked,
                         reason="blocked_by_policy" if blocked else None,
                         meta={"ts": _NOW().isoformat(), "namespace": self.policy.namespace})

        # Notify (single shot)
        if self.notifier and any(a.type == "notify" for r in self.policy.rules for a in r.actions) and len(findings) > 0:
            try:
                self.notifier(res)
            except Exception:
                pass

        return res

    # --------- DataFrame (Pandas) ---------

    def scan_pandas(self, df, sample_fraction: float = 1.0, random_state: Optional[int] = 42,
                    mutate: bool = False) -> Tuple[ScanResult, "pandas.DataFrame"]:
        import pandas as pd  # lazy import

        if sample_fraction < 1.0:
            df_sc = df.sample(frac=sample_fraction, random_state=random_state)
        else:
            df_sc = df

        agg_findings: List[Finding] = []
        risk = 0
        blocked = False

        # Prepare actions map for faster lookup
        actions_by_rule = {r.id: r.actions for r in self.policy.rules}

        def process_cell(val: Any, col: str) -> Any:
            nonlocal agg_findings, risk, blocked
            text = str(val) if isinstance(val, (str, int, float)) or val is None else json.dumps(val, ensure_ascii=False)
            for rule in self.policy.rules:
                cnt, snippets = self._scan_text(text, rule)
                if cnt >= rule.min_count:
                    agg_findings.append(Finding(
                        rule_id=rule.id, rule_name=rule.name, severity=rule.severity,
                        column=col, row_index=None, snippet=" | ".join(snippets), count=cnt,
                        context={"column": col}))
                    risk += self.policy.risk_weights.get(rule.severity, 1) * cnt
                    if self._sev_order.index(rule.severity) >= self._sev_order.index(self.policy.enforce_severity_at_least):
                        blocked = blocked or any(a.type == "block" for a in actions_by_rule[rule.id])
                    if mutate:
                        return self._apply_actions_on_cell(val, rule, col)
            return val

        if mutate:
            df_out = df.copy()
            for c in df_out.columns:
                df_out[c] = df_out[c].apply(lambda v, col=c: process_cell(v, col))
        else:
            df_out = df
            # still iterate for findings without mutation
            for c in df_sc.columns:
                _ = df_sc[c].apply(lambda v, col=c: process_cell(v, col))

        res = ScanResult(ok=(len(agg_findings) == 0), total_findings=len(agg_findings),
                         risk_score=risk, findings=agg_findings,
                         enforced=blocked, blocked=blocked,
                         reason="blocked_by_policy" if blocked else None,
                         meta={"ts": _NOW().isoformat(), "rows_scanned": int(df_sc.shape[0]),
                               "cols": list(df_sc.columns), "namespace": self.policy.namespace})

        if self.notifier and any(a.type == "notify" for r in self.policy.rules for a in r.actions) and len(agg_findings) > 0:
            try:
                self.notifier(res)
            except Exception:
                pass

        return res, df_out

    # --------- Spark integration ---------

    def scan_spark_batch(self, sdf, mutate: bool = False):
        """
        Non-streaming Spark batch scan. Returns (ScanResult, SparkDataFrame).
        """
        from pyspark.sql import functions as F  # type: ignore
        from pyspark.sql import types as T      # type: ignore

        rules_bc = [(r.id, r.name, r.severity, r.pattern_ref, r.min_count, r.context_window, r.max_findings) for r in self.policy.rules]
        compiled = {name: self.compiled[name].pattern for _, _, _, name, _, _, _ in rules_bc}

        # Broadcast policy to executors via literals (avoid pickling regex objects)
        @F.udf(returnType=T.ArrayType(T.StructType([
            T.StructField("rule_id", T.StringType()),
            T.StructField("rule_name", T.StringType()),
            T.StructField("severity", T.StringType()),
            T.StructField("count", T.IntegerType()),
            T.StructField("snippet", T.StringType()),
        ])))
        def dlp_cell(text: T.StringType) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            if text is None:
                return out
            s = str(text)
            for rid, rname, sev, pref, minc, ctxw, maxf in rules_bc:
                try:
                    rx = re.compile(compiled[pref], re.I | re.M)
                except Exception:
                    continue
                cnt = 0
                snippets: List[str] = []
                for m in rx.finditer(s):
                    cnt += 1
                    if len(snippets) < int(maxf):
                        st = max(0, m.start() - int(ctxw))
                        en = min(len(s), m.end() + int(ctxw))
                        snippets.append(_safe_snippet(s[st:en]))
                if cnt >= int(minc):
                    out.append({"rule_id": rid, "rule_name": rname, "severity": sev, "count": int(cnt), "snippet": " | ".join(snippets)})
            return out

        # Explode findings per cell, aggregate risk
        cols = sdf.columns
        findings_cols = [F.explode_outer(dlp_cell(F.col(c))).alias("f") for c in cols]
        # To avoid cross-join, union findings per column and aggregate
        fdfs = []
        for c in cols:
            fdfs.append(sdf.select(F.lit(c).alias("column"), dlp_cell(F.col(c)).alias("arr")).selectExpr("column", "inline(arr) as f"))
        union = None
        for i, fd in enumerate(fdfs):
            union = fd if i == 0 else union.unionByName(fd, allowMissingColumns=True)

        if union is None:
            # empty frame
            return ScanResult(ok=True, total_findings=0, risk_score=0, findings=[], enforced=False, blocked=False), sdf

        risk_weights = self.policy.risk_weights
        risk_udf = F.udf(lambda sev: int(risk_weights.get(sev, 1)))

        agg = (union
               .withColumn("sev_w", risk_udf(F.col("f.severity")))
               .withColumn("risk", F.col("sev_w") * F.col("f.count"))
               .groupBy()
               .agg(F.count(F.lit(1)).alias("findings"),
                    F.sum("risk").alias("risk_score"))).collect()[0]

        total_findings = int(agg["findings"]) if agg["findings"] is not None else 0
        risk_score = int(agg["risk_score"]) if agg["risk_score"] is not None else 0

        blocked = False
        if total_findings > 0:
            # conservative: if any rule with action block exists in union
            # collect distinct rule_ids with severity >= threshold
            severities = {r.id: r.severity for r in self.policy.rules}
            enforce_min = self.policy.enforce_severity_at_least
            # We can't easily check per-rule actions post-agg without more joins; decide via policy presence
            blocked = any(
                (severities.get(r.id, "low") and
                 self._sev_order.index(severities.get(r.id, "low")) >= self._sev_order.index(enforce_min) and
                 any(a.type == "block" for a in r.actions))
                for r in self.policy.rules
            )

        res = ScanResult(
            ok=(total_findings == 0),
            total_findings=total_findings,
            risk_score=risk_score,
            findings=[],  # omit per-row expansion for batch summary (can be added via persist_findings())
            enforced=blocked,
            blocked=blocked,
            reason="blocked_by_policy" if blocked else None,
            meta={"ts": _NOW().isoformat(), "namespace": self.policy.namespace, "columns": cols},
        )

        if mutate and total_findings > 0:
            # Apply cell-level actions for high-level strategies (redact/hash/tokenize)
            # Note: heavy; for large frames use column subset.
            from pyspark.sql import functions as F
            def make_replacer(rule: Rule):
                rx = re.compile(self.compiled[rule.pattern_ref].pattern, re.I | re.M)
                def repl(text: Optional[str]) -> Optional[str]:
                    if text is None:
                        return None
                    s = str(text)
                    if any(a.type in ("redact", "hash", "tokenize") for a in rule.actions):
                        # for redact -> replace with ***
                        if any(a.type == "redact" for a in rule.actions):
                            return rx.sub("***REDACTED***", s)
                        if any(a.type == "hash" for a in rule.actions):
                            return rx.sub(lambda m: f"HASH:{_hash_sample(m.group(0))}", s)
                        if any(a.type == "tokenize" for a in rule.actions):
                            return rx.sub(lambda m: f"TOKEN:{_hash_sample(m.group(0))}", s)
                    return s
                return repl
            out = sdf
            for rule in self.policy.rules:
                if not any(a.type in ("redact","hash","tokenize") for a in rule.actions):
                    continue
                rx_replacer = make_replacer(rule)
                u = F.udf(rx_replacer)
                for c in sdf.columns:
                    out = out.withColumn(c, u(F.col(c)))
            sdf = out

        return res, sdf

    def foreach_batch_enforcer(self, mutate: bool = False) -> Callable[[Any, int], None]:
        """
        Use with Spark Structured Streaming:
            query = sdf.writeStream.foreachBatch(scanner.foreach_batch_enforcer(mutate=True))...
        This will block microbatches by raising Exception when policy requires it.
        """
        def _fn(batch_df, batch_id: int):
            res, out = self.scan_spark_batch(batch_df, mutate=mutate)
            self._audit_result(res, context={"batch_id": batch_id, "rows": out.count()})
            if res.blocked:
                raise RuntimeError(f"DLP block at batch {batch_id}: severity>={self.policy.enforce_severity_at_least}, risk={res.risk_score}")
        return _fn

    # --------- Auditing ---------

    def _audit_result(self, res: ScanResult, context: Optional[Dict[str, Any]] = None) -> None:
        if not self.policy.audit_path and not _env_flag("DF_DLP_STDERR_AUDIT", True):
            return
        rec = {
            "ts": _NOW().isoformat(),
            "namespace": self.policy.namespace,
            "ok": res.ok,
            "blocked": res.blocked,
            "enforced": res.enforced,
            "risk_score": res.risk_score,
            "total_findings": res.total_findings,
            "reason": res.reason,
            "meta": res.meta | (context or {})
        }
        line = json.dumps(rec, ensure_ascii=False)
        # Write to file (append JSONL) or stderr
        try:
            if self.policy.audit_path:
                with open(self.policy.audit_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            if _env_flag("DF_DLP_STDERR_AUDIT", True):
                print(f"[DLP-AUDIT] {line}", file=sys.stderr, flush=True)
        except Exception:
            # best-effort
            pass

# ---------------------------
# Convenience factory
# ---------------------------

def build_default_scanner() -> DLPScanner:
    # Optional external tokenizer/masker/quarantine/notifier can be injected here
    return DLPScanner(policy=DLPPolicy.from_env())

# ---------------------------
# Self-test / Example (non-invasive)
# ---------------------------

if __name__ == "__main__":
    policy = DLPPolicy.from_env()
    scanner = DLPScanner(policy=policy)

    record = {
        "email": "user@example.com",
        "note": "Key: AKIAABCDEFGHIJKLMNOP and jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb",
        "cc": "4111 1111 1111 1111",
        "text": "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----",
        "ok": "no issues here",
    }

    res = scanner.scan_record(record)
    scanner._audit_result(res, context={"example": True})
    print(json.dumps(dataclasses.asdict(res), ensure_ascii=False, indent=2))
