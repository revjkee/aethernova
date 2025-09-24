# cybersecurity-core/cybersecurity/compliance/mapper_iso27001.py
# Industrial ISO/IEC 27001:2022 Annex A mapper
#
# Features:
# - Loads external crosswalks (YAML/JSON): other frameworks -> ISO/IEC 27001:2022 controls
# - Rule engine: keyword/type/tag driven mapping to ISO controls with weights
# - Direct evidence-to-control linking
# - Coverage and gap analysis with weighted scoring
# - Deterministic exports (CSV/JSONL) and trace for explainability
# - Thread-safe read paths; minimal deps (yaml is optional)
#
# IMPORTANT:
# This module intentionally ships with a *minimal* built-in ISO control catalog
# (IDs and brief generic tags only). For full control set use external mapping files.
# We do NOT reproduce ISO copyrighted text here.

from __future__ import annotations

import csv
import json
import logging
import re
import threading
from dataclasses import dataclass, field, asdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Union

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # optional: JSON remains supported

# ---------------------------
# Data models
# ---------------------------

ISO_VERSION = "ISO/IEC 27001:2022"

@dataclass(frozen=True)
class ControlRef:
    id: str                   # e.g., "A.5.1"
    domain: str               # e.g., "A.5" (Organizational), "A.6" (People), "A.7" (Physical), "A.8" (Technological)
    title_hint: str = ""      # short non-copyrighted hint; not authoritative
    tags: Set[str] = field(default_factory=set)

    def key(self) -> str:
        return f"{self.id}"

@dataclass
class MappingEntry:
    source_framework: str           # e.g., "CISv8", "NIST800-53r5", "SOC2-CC"
    source_id: str                  # e.g., "1.1", "AC-2", "CC6.1"
    iso_controls: Set[str]          # set of ISO control IDs (e.g., {"A.8.21"})
    weight: float = 1.0
    notes: str = ""

@dataclass
class EvidenceRecord:
    evidence_id: str
    title: str
    source: str                     # e.g., "Trivy", "SIEM", "PolicyRepo"
    kind: str                       # e.g., "policy", "procedure", "runbook", "config", "scan", "ticket", "log"
    tags: Set[str] = field(default_factory=set)
    refs: Dict[str, List[str]] = field(default_factory=dict)  # framework->list of control ids (e.g., {"CISv8": ["4.1"]})
    attributes: Dict[str, Any] = field(default_factory=dict)  # arbitrary fields
    text_snippet: str = ""          # optional text to parse (keywords)
    iso_links: Set[str] = field(default_factory=set)  # direct pre-linked ISO controls, if known

@dataclass
class CoverageItem:
    control_id: str
    weight_accum: float = 0.0
    evidence_ids: Set[str] = field(default_factory=set)
    rule_hits: List[str] = field(default_factory=list)  # explainability: which rules matched

@dataclass
class AssessmentSummary:
    version: str
    total_controls: int
    covered: int
    partial: int
    none: int
    coverage_percent: float

# ---------------------------
# Built-in minimal catalog (IDs only; short neutral hints)
# Note: for full catalog load external file via Mapper.load_catalog()
# ---------------------------

_MINIMAL_ISO_CATALOG: Dict[str, ControlRef] = {
    # Organizational (A.5) — examples
    "A.5.1": ControlRef("A.5.1", "A.5", "Policies for ISMS", {"policy", "isms"}),
    "A.5.2": ControlRef("A.5.2", "A.5", "Information security roles and responsibilities", {"roles", "responsibility"}),
    "A.5.9": ControlRef("A.5.9", "A.5", "Inventory of information and other assets", {"asset", "inventory"}),
    "A.5.10": ControlRef("A.5.10", "A.5", "Acceptable use of information and assets", {"acceptable-use"}),
    # People (A.6) — examples
    "A.6.1": ControlRef("A.6.1", "A.6", "Screening", {"hr", "screening"}),
    "A.6.3": ControlRef("A.6.3", "A.6", "Awareness, education and training", {"training", "awareness"}),
    # Physical (A.7) — examples
    "A.7.1": ControlRef("A.7.1", "A.7", "Physical security perimeter", {"physical", "perimeter"}),
    "A.7.2": ControlRef("A.7.2", "A.7", "Physical entry controls", {"badge", "visitor"}),
    # Technological (A.8) — examples
    "A.8.8": ControlRef("A.8.8", "A.8", "Malware protection", {"malware", "av"}),
    "A.8.9": ControlRef("A.8.9", "A.8", "Data backup", {"backup"}),
    "A.8.10": ControlRef("A.8.10", "A.8", "Logging", {"logging", "audit"}),
    "A.8.11": ControlRef("A.8.11", "A.8", "Monitoring", {"monitoring"}),
    "A.8.12": ControlRef("A.8.12", "A.8", "Clock synchronization", {"ntp", "time"}),
    "A.8.13": ControlRef("A.8.13", "A.8", "Network security", {"network", "segmentation", "fw"}),
    "A.8.14": ControlRef("A.8.14", "A.8", "Use of cryptography", {"crypto", "encryption"}),
    "A.8.16": ControlRef("A.8.16", "A.8", "Application security", {"appsec", "sdlc"}),
    "A.8.21": ControlRef("A.8.21", "A.8", "Security testing in development and acceptance", {"testing", "sast", "dast"}),
}

# ---------------------------
# Rule schema (keyword/type/tag → control IDs)
# ---------------------------

_DEFAULT_RULES: List[Tuple[str, Set[str], float]] = [
    # (regex pattern (case-insensitive), mapped controls, weight)
    (r"\blog(s|ging)?\b|audit trail|auditlog", {"A.8.10"}, 1.0),
    (r"\bmonitor(ing)?\b|telemetry|observability", {"A.8.11"}, 0.8),
    (r"\bbackup(s)?\b|restore|snapshot", {"A.8.9"}, 1.0),
    (r"\bencrypt(ion|ed|ing)?\b|cryptograph(y|ic)", {"A.8.14"}, 1.0),
    (r"\bmalware|antivirus|edr|av\b", {"A.8.8"}, 1.0),
    (r"\bntp|time sync|clock sync", {"A.8.12"}, 0.6),
    (r"\b(segmentation|firewall|vpc|subnet|sg|nacl)\b", {"A.8.13"}, 0.8),
    (r"\b(appsec|sdlc|secure coding|threat modeling)\b", {"A.8.16"}, 0.8),
    (r"\b(sast|dast|iasta|pentest|fuzz)\b", {"A.8.21"}, 0.8),
    (r"\basset(s)? inventory\b|\bcmdb\b", {"A.5.9"}, 0.8),
]

# Kind/tag → control hints
_KIND_HINTS: Dict[str, Set[str]] = {
    "policy": {"A.5.1", "A.5.10"},
    "procedure": {"A.5.2"},
    "training": {"A.6.3"},
    "scan": {"A.8.21", "A.8.11"},
    "config": {"A.8.13", "A.8.14"},
    "runbook": {"A.8.9", "A.8.10"},
    "ticket": {"A.8.11"},
}

# ---------------------------
# Mapper implementation
# ---------------------------

class ISO27001Mapper:
    """
    ISO/IEC 27001:2022 Annex A mapper with rule-based engine and crosswalk imports.

    External mapping file structure (YAML or JSON):

    catalog:
      iso27001_2022:
        controls:
          - id: "A.8.21"
            domain: "A.8"
            title_hint: "Security testing in development"
            tags: ["testing","sast","dast"]

    rules:
      # regex (case-insensitive) → ISO controls and weight
      - pattern: "\\bbackup(s)?\\b"
        controls: ["A.8.9"]
        weight: 1.0

    crosswalks:
      # framework -> mapping
      CISv8:
        "4.1": ["A.8.10", "A.8.11"]
      NIST800-53r5:
        "AU-6": ["A.8.10"]

    direct_links:
      # evidence_id -> ISO controls
      "EV-1234": ["A.8.11"]
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.log = logger or logging.getLogger("iso27001.mapper")
        self._catalog: Dict[str, ControlRef] = dict(_MINIMAL_ISO_CATALOG)
        self._rules: List[Tuple[re.Pattern[str], Set[str], float]] = [
            (re.compile(pat, flags=re.IGNORECASE), ctrls, w) for pat, ctrls, w in _DEFAULT_RULES
        ]
        self._kind_hints: Dict[str, Set[str]] = _KIND_HINTS.copy()
        self._crosswalks: Dict[str, Dict[str, Set[str]]] = {}  # framework -> source_id -> iso_controls
        self._direct_links: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()

    # -------- Catalog & rules management --------

    def load_catalog(self, mapping_path: Union[str, Path]) -> None:
        """
        Load catalog + rules + crosswalks + direct links from YAML/JSON file.
        """
        with self._lock:
            data = self._load_any(mapping_path)
            self._ingest_data(data)

    def load_catalog_from_dict(self, data: Mapping[str, Any]) -> None:
        with self._lock:
            self._ingest_data(dict(data))

    def _ingest_data(self, data: Mapping[str, Any]) -> None:
        # catalog
        catalog = (((data or {}).get("catalog") or {}).get("iso27001_2022") or {}).get("controls", [])
        for c in catalog:
            cid = str(c.get("id") or "").strip()
            if not cid:
                continue
            self._catalog[cid] = ControlRef(
                id=cid,
                domain=str(c.get("domain") or "").strip() or cid.split(".")[0],
                title_hint=str(c.get("title_hint") or "").strip(),
                tags=set(str(t) for t in (c.get("tags") or [])),
            )

        # rules
        rules = (data.get("rules") or [])
        compiled: List[Tuple[re.Pattern[str], Set[str], float]] = []
        for r in rules:
            pat = r.get("pattern")
            ctrls = set(str(x) for x in (r.get("controls") or []))
            weight = float(r.get("weight", 1.0))
            if pat and ctrls:
                compiled.append((re.compile(pat, flags=re.IGNORECASE), ctrls, weight))
        if compiled:
            self._rules = compiled

        # crosswalks
        cross = data.get("crosswalks") or {}
        cross_new: Dict[str, Dict[str, Set[str]]] = {}
        for fw, mp in cross.items():
            tmp: Dict[str, Set[str]] = {}
            for sid, arr in (mp or {}).items():
                tmp[str(sid)] = set(str(x) for x in (arr or []))
            cross_new[str(fw)] = tmp
        if cross_new:
            self._crosswalks = cross_new

        # direct links
        dl = data.get("direct_links") or {}
        new_dl: Dict[str, Set[str]] = {str(eid): set(str(x) for x in ctrls) for eid, ctrls in dl.items()}
        if new_dl:
            self._direct_links = new_dl

        # kind hints (optional override/extend)
        kh = data.get("kind_hints") or {}
        if kh:
            updated = {}
            for k, v in kh.items():
                updated[str(k)] = set(str(x) for x in (v or []))
            self._kind_hints = updated

        self._invalidate_caches()
        self.log.debug("Catalog ingested", extra={
            "controls": len(self._catalog),
            "rules": len(self._rules),
            "crosswalk_frameworks": len(self._crosswalks),
            "direct_links": len(self._direct_links),
        })

    def _load_any(self, path: Union[str, Path]) -> Dict[str, Any]:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Mapping file not found: {p}")
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() in (".yaml", ".yml"):
            if not yaml:
                raise RuntimeError("PyYAML is required to load YAML files")
            return yaml.safe_load(text) or {}
        # default JSON
        return json.loads(text or "{}")

    def _invalidate_caches(self) -> None:
        self.lookup_from_crosswalk.cache_clear()  # type: ignore
        self.lookup_from_rules.cache_clear()      # type: ignore

    # -------- Lookup primitives --------

    @lru_cache(maxsize=8192)
    def lookup_from_crosswalk(self, framework: str, source_id: str) -> Set[str]:
        return set(self._crosswalks.get(framework, {}).get(source_id, set()))

    @lru_cache(maxsize=8192)
    def lookup_from_rules(self, text: str) -> List[Tuple[str, float, str]]:
        """
        Returns list of (control_id, weight, rule_pattern) from keyword rules.
        """
        matches: List[Tuple[str, float, str]] = []
        for rex, ctrls, w in self._rules:
            if rex.search(text):
                for c in ctrls:
                    matches.append((c, w, rex.pattern))
        return matches

    # -------- Mapping core --------

    def map_evidence(self, ev: EvidenceRecord) -> Dict[str, CoverageItem]:
        """
        Map a single EvidenceRecord to ISO controls; returns map control_id -> CoverageItem.
        """
        with self._lock:
            acc: Dict[str, CoverageItem] = {}

            def bump(cid: str, w: float, rule: Optional[str]) -> None:
                if cid not in self._catalog:
                    # unknown control id in mapping: skip silently (or log debug)
                    return
                ci = acc.get(cid)
                if not ci:
                    ci = CoverageItem(control_id=cid)
                    acc[cid] = ci
                ci.weight_accum += w
                ci.evidence_ids.add(ev.evidence_id)
                if rule:
                    ci.rule_hits.append(rule)

            # 1) direct links
            for cid in (ev.iso_links or self._direct_links.get(ev.evidence_id, set())):
                bump(cid, 1.0, "direct")

            # 2) crosswalks from referenced frameworks
            for fw, ids in (ev.refs or {}).items():
                for sid in ids or []:
                    for cid in self.lookup_from_crosswalk(str(fw), str(sid)):
                        bump(cid, 1.0, f"crosswalk:{fw}:{sid}")

            # 3) kind-based hints
            for cid in self._kind_hints.get(ev.kind, set()):
                bump(cid, 0.5, f"kind:{ev.kind}")

            # 4) tag-based hints
            for t in (ev.tags or set()):
                # Try exact match with control tag set
                for cid, cref in self._catalog.items():
                    if t in cref.tags:
                        bump(cid, 0.4, f"tag:{t}")

            # 5) keyword rules (title + snippet + selected attributes)
            blob_parts: List[str] = [ev.title or "", ev.text_snippet or ""]
            for k in ("path", "resource", "service", "control", "category"):
                v = ev.attributes.get(k)
                if isinstance(v, str):
                    blob_parts.append(v)
            blob = " ".join(x for x in blob_parts if x).lower()
            for cid, w, pat in self.lookup_from_rules(blob):
                bump(cid, w, f"rule:{pat}")

            return acc

    def aggregate(self, evidences: Iterable[EvidenceRecord]) -> Dict[str, CoverageItem]:
        """
        Aggregate mapping across many evidences.
        """
        total: Dict[str, CoverageItem] = {}
        for ev in evidences:
            items = self.map_evidence(ev)
            for cid, it in items.items():
                tgt = total.get(cid)
                if not tgt:
                    tgt = CoverageItem(control_id=cid)
                    total[cid] = tgt
                tgt.weight_accum += it.weight_accum
                tgt.evidence_ids |= it.evidence_ids
                tgt.rule_hits.extend(it.rule_hits)
        return total

    # -------- Coverage & reporting --------

    def coverage(self, evidences: Iterable[EvidenceRecord],
                 threshold_full: float = 1.0,
                 threshold_partial: float = 0.4) -> Tuple[AssessmentSummary, Dict[str, Dict[str, Any]]]:
        """
        Computes coverage per ISO control with qualitative status:
        - covered: weight >= threshold_full
        - partial: threshold_partial <= weight < threshold_full
        - none: weight < threshold_partial (including 0)
        Returns (summary, details_by_control).
        """
        agg = self.aggregate(evidences)
        details: Dict[str, Dict[str, Any]] = {}
        covered = partial = none = 0
        for cid in self._catalog.keys():
            it = agg.get(cid)
            w = it.weight_accum if it else 0.0
            if w >= threshold_full:
                status = "covered"
                covered += 1
            elif w >= threshold_partial:
                status = "partial"
                partial += 1
            else:
                status = "none"
                none += 1
            details[cid] = {
                "control_id": cid,
                "domain": self._catalog[cid].domain,
                "title_hint": self._catalog[cid].title_hint,
                "weight": round(w, 3),
                "status": status,
                "evidence_count": len(it.evidence_ids) if it else 0,
                "evidence_ids": sorted(it.evidence_ids) if it else [],
                "explain": it.rule_hits if it else [],
            }
        total_controls = len(self._catalog)
        coverage_percent = (covered / total_controls * 100.0) if total_controls else 0.0
        summary = AssessmentSummary(
            version=ISO_VERSION,
            total_controls=total_controls,
            covered=covered,
            partial=partial,
            none=none,
            coverage_percent=round(coverage_percent, 2),
        )
        return summary, details

    def gap_report(self, evidences: Iterable[EvidenceRecord],
                   only_gaps: bool = True) -> List[Dict[str, Any]]:
        """
        Produce gap list sorted by weakest coverage first.
        """
        _, details = self.coverage(evidences)
        rows = list(details.values())
        rows.sort(key=lambda r: (0 if r["status"] == "none" else 1 if r["status"] == "partial" else 2,
                                 r["weight"]))
        if only_gaps:
            rows = [r for r in rows if r["status"] != "covered"]
        return rows

    # -------- Export utilities --------

    def export_csv(self, rows: Sequence[Mapping[str, Any]], path: Union[str, Path]) -> None:
        if not rows:
            Path(path).write_text("", encoding="utf-8")
            return
        headers = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
            for r in rows:
                w.writerow({k: self._stringify(v) for k, v in r.items()})

    def export_jsonl(self, rows: Sequence[Mapping[str, Any]], path: Union[str, Path]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")

    # -------- Helpers --------

    def controls(self) -> List[ControlRef]:
        return [self._catalog[cid] for cid in sorted(self._catalog.keys(), key=self._ctrl_sort_key)]

    def _ctrl_sort_key(self, cid: str) -> Tuple[str, Tuple[int, ...]]:
        # sort by domain, then numeric parts
        domain = self._catalog[cid].domain
        nums = tuple(int(x) for x in re.findall(r"\d+", cid))
        return (domain, nums)

    @staticmethod
    def _stringify(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, (list, set, tuple)):
            return ", ".join(str(x) for x in v)
        if isinstance(v, dict):
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return str(v)

# ---------------------------
# Convenience factories
# ---------------------------

def make_evidence(evidence_id: str,
                  title: str,
                  source: str,
                  kind: str,
                  *,
                  tags: Optional[Iterable[str]] = None,
                  refs: Optional[Mapping[str, Sequence[str]]] = None,
                  attributes: Optional[Mapping[str, Any]] = None,
                  text_snippet: str = "",
                  iso_links: Optional[Iterable[str]] = None) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        title=title,
        source=source,
        kind=kind,
        tags=set(tags or []),
        refs={k: list(v) for k, v in (refs or {}).items()},
        attributes=dict(attributes or {}),
        text_snippet=text_snippet,
        iso_links=set(iso_links or []),
    )

# ---------------------------
# Example of in-memory feed (disabled in module import)
# ---------------------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("demo")
    mapper = ISO27001Mapper(log)

    # Optionally load external YAML/JSON with full catalog
    # mapper.load_catalog("iso_catalog.yaml")

    evs = [
        make_evidence(
            evidence_id="EV-1",
            title="Daily backups of production PostgreSQL",
            source="BackupSystem",
            kind="runbook",
            tags={"backup", "database"},
            text_snippet="pg_dump snapshot restore",
        ),
        make_evidence(
            evidence_id="EV-2",
            title="Centralized logging enabled for API gateway",
            source="Gateway",
            kind="config",
            tags={"logging", "gateway"},
            text_snippet="access log; auditlog; shipper",
            refs={"CISv8": ["8.2"]},
        ),
        make_evidence(
            evidence_id="EV-3",
            title="SAST pipeline for main service",
            source="CI",
            kind="scan",
            tags={"sast", "ci"},
            text_snippet="codeql sast",
        ),
        make_evidence(
            evidence_id="EV-4",
            title="Crypto at rest configured (AES-256)",
            source="CloudKMS",
            kind="config",
            tags={"encryption", "kms"},
            text_snippet="encryption at rest",
        ),
    ]

    # External crosswalk example (programmatic)
    mapper.load_catalog_from_dict({
        "crosswalks": {
            "CISv8": {"8.2": ["A.8.10", "A.8.11"]},
        }
    })

    summary, details = mapper.coverage(evs)
    log.info("Summary: %s", asdict(summary))
    for cid, d in details.items():
        log.info("%s -> %s", cid, d["status"])

    gaps = mapper.gap_report(evs)
    log.info("Gaps: %d", len(gaps))
