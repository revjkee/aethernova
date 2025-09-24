# cybersecurity-core/cybersecurity/compliance/mapper_nist80053.py
# SPDX-License-Identifier: MIT
# Public domain content references: NIST SP 800-53 Rev.5 catalog structure compatible.
# Industrial-grade mapper for NIST 800-53 Rev.5 with crosswalks and evidence coverage.

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

__all__ = [
    "NistFamily",
    "Baseline",
    "Control",
    "ControlLink",
    "Crosswalk",
    "Evidence",
    "EvidenceStatus",
    "Catalog",
    "NistMapper",
    "InvalidControlError",
    "CatalogNotLoadedError",
]

__version__ = "1.0.0"
__schema_version__ = "2025-09-03"
__dataset_hint__ = "NIST-800-53r5-minimal-seed"


# ---------------------------
# Logging (JSON-capable)
# ---------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _get_logger() -> logging.Logger:
    logger = logging.getLogger("cybersecurity.compliance.mapper_nist80053")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = _get_logger()


# ---------------------------
# Domain model
# ---------------------------
class InvalidControlError(ValueError):
    pass


class CatalogNotLoadedError(RuntimeError):
    pass


CONTROL_ID_RE = re.compile(r"^[A-Z]{2,3}-\d{1,3}(?:\(\d+\))?$")
FAMILY_RE = re.compile(r"^[A-Z]{2,3}$")


class NistFamily:
    # Canonical NIST 800-53 control families (subset enumeration for safety)
    ACCESS_CONTROL = "AC"
    AUDIT_AND_ACCOUNTABILITY = "AU"
    AWARENESS_AND_TRAINING = "AT"
    CONFIGURATION_MANAGEMENT = "CM"
    CONTINGENCY_PLANNING = "CP"
    IDENTIFICATION_AND_AUTHENTICATION = "IA"
    INCIDENT_RESPONSE = "IR"
    MAINTENANCE = "MA"
    MEDIA_PROTECTION = "MP"
    PERSONNEL_SECURITY = "PS"
    PHYSICAL_AND_ENVIRONMENTAL_PROTECTION = "PE"
    PLANNING = "PL"
    PROGRAM_MANAGEMENT = "PM"
    RISK_ASSESSMENT = "RA"
    SYSTEM_AND_COMMUNICATIONS_PROTECTION = "SC"
    SYSTEM_AND_INFORMATION_INTEGRITY = "SI"
    SYSTEM_AND_SERVICES_ACQUISITION = "SA"

    @classmethod
    def all(cls) -> Tuple[str, ...]:
        return tuple(
            getattr(cls, name)
            for name in dir(cls)
            if name.isupper() and not name.startswith("_") and isinstance(getattr(cls, name), str)
        )


class Baseline:
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    PRIVACY = "PRIVACY"  # Optional privacy overlay

    @classmethod
    def all(cls) -> Tuple[str, ...]:
        return (cls.LOW, cls.MODERATE, cls.HIGH, cls.PRIVACY)


@dataclass(frozen=True)
class Control:
    id: str
    family: str
    title: str
    rev: str = "r5"
    priority: Optional[str] = None
    baseline: Tuple[str, ...] = field(default_factory=tuple)
    enhancements: Tuple[str, ...] = field(default_factory=tuple)  # e.g., ("AC-2(1)", "AC-2(2)")
    statement: Optional[str] = None

    def canonical_id(self) -> str:
        return canonical_control_id(self.id)


@dataclass(frozen=True)
class ControlLink:
    # Cross-framework linkage
    framework: str  # e.g., "ISO27001:2022", "SOC2-CC", "CISv8"
    control_id: str
    weight: float = 1.0  # 0..1 subjective alignment
    note: Optional[str] = None


@dataclass
class Crosswalk:
    # control_id -> list[ControlLink]
    links: Dict[str, List[ControlLink]] = field(default_factory=dict)

    def for_control(self, control_id: str) -> List[ControlLink]:
        return list(self.links.get(canonical_control_id(control_id), []))

    def add(self, control_id: str, link: ControlLink) -> None:
        cid = canonical_control_id(control_id)
        self.links.setdefault(cid, []).append(link)

    def hash(self) -> str:
        payload = {k: [dataclasses.asdict(l) for l in v] for k, v in sorted(self.links.items())}
        return sha256_of_json(payload)


@dataclass
class Evidence:
    control_id: str
    artifact_id: str
    type: str  # e.g., "policy", "screenshot", "config", "scan", "ticket", "log"
    updated_at: dt.datetime
    owner: Optional[str] = None
    status: str = "present"  # see EvidenceStatus

    def is_fresh(self, max_age_days: int = 365) -> bool:
        return (dt.datetime.utcnow() - self.updated_at).days <= max_age_days


class EvidenceStatus:
    PRESENT = "present"
    MISSING = "missing"
    STALE = "stale"
    REJECTED = "rejected"


@dataclass
class Catalog:
    controls: Dict[str, Control]  # canonical id -> Control
    crosswalk: Crosswalk = field(default_factory=Crosswalk)

    def hash(self) -> str:
        payload = {
            "controls": {k: dataclasses.asdict(v) for k, v in sorted(self.controls.items())},
            "crosswalk": json.loads(json.dumps({k: [dataclasses.asdict(l) for l in v]
                                                for k, v in self.crosswalk.links.items()}, ensure_ascii=False)),
        }
        return sha256_of_json(payload)

    def get(self, control_id: str) -> Control:
        cid = canonical_control_id(control_id)
        try:
            return self.controls[cid]
        except KeyError:
            raise InvalidControlError(f"Unknown control id: {control_id}")


# ---------------------------
# Helpers
# ---------------------------
def sha256_of_json(obj: object) -> str:
    data = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_control_id(control_id: str) -> str:
    if not isinstance(control_id, str):
        raise InvalidControlError("Control id must be a string")
    control_id = control_id.strip().upper()
    if not CONTROL_ID_RE.match(control_id):
        raise InvalidControlError(f"Invalid control id syntax: {control_id}")
    return control_id


def extract_family(control_id: str) -> str:
    fam = canonical_control_id(control_id).split("-", 1)[0]
    if not FAMILY_RE.match(fam):
        raise InvalidControlError(f"Invalid control family: {fam}")
    return fam


def _normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _tokenize(s: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


# ---------------------------
# Default minimal seed (safe)
# ---------------------------
# Minimal internal seed to keep the module self-contained.
# For production, load full catalog via load_catalog(...).
_DEFAULT_CONTROLS: Dict[str, Control] = {
    "AC-2": Control(
        id="AC-2",
        family=NistFamily.ACCESS_CONTROL,
        title="Account Management",
        baseline=(Baseline.LOW, Baseline.MODERATE, Baseline.HIGH),
        enhancements=("AC-2(1)", "AC-2(3)", "AC-2(7)"),
        statement="Manage information system accounts, including creation, modification, disabling, and removal.",
    ),
    "AC-2(1)": Control(
        id="AC-2(1)",
        family=NistFamily.ACCESS_CONTROL,
        title="Automated System Account Management",
        baseline=(Baseline.MODERATE, Baseline.HIGH),
        statement="Employ automated mechanisms to support the management of information system accounts.",
    ),
    "RA-5": Control(
        id="RA-5",
        family=NistFamily.RISK_ASSESSMENT,
        title="Vulnerability Monitoring and Scanning",
        baseline=(Baseline.LOW, Baseline.MODERATE, Baseline.HIGH),
        enhancements=("RA-5(1)", "RA-5(2)"),
        statement="Scan for vulnerabilities and remediate in accordance with risk assessments.",
    ),
    "SC-7": Control(
        id="SC-7",
        family=NistFamily.SYSTEM_AND_COMMUNICATIONS_PROTECTION,
        title="Boundary Protection",
        baseline=(Baseline.LOW, Baseline.MODERATE, Baseline.HIGH),
        statement="Monitor and control communications at external boundaries and key internal boundaries.",
    ),
}

_DEFAULT_CROSSWALK = Crosswalk(
    links={
        "AC-2": [
            ControlLink(framework="ISO27001:2022", control_id="A.5.16", weight=0.9,
                        note="Identity management lifecycle"),
            ControlLink(framework="SOC2-CC", control_id="CC6.2", weight=0.8,
                        note="Logical and physical access controls"),
        ],
        "RA-5": [
            ControlLink(framework="ISO27001:2022", control_id="A.8.8", weight=0.85,
                        note="Vulnerability management"),
            ControlLink(framework="CISv8", control_id="07", weight=0.7, note="Continuous vulnerability management"),
        ],
        "SC-7": [
            ControlLink(framework="ISO27001:2022", control_id="A.8.20", weight=0.8, note="Network security"),
        ],
    }
)


# ---------------------------
# Mapper
# ---------------------------
class NistMapper:
    """
    Industrial NIST 800-53 Rev.5 mapper.
    - Load/merge catalog from JSON/YAML files.
    - Validate control ids including enhancements.
    - Search controls by text/family/baseline.
    - Crosswalk to ISO/SOC2/CIS etc.
    - Compute evidence coverage posture.
    - CLI for validate/search/map/coverage.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._catalog = Catalog(controls=dict(_DEFAULT_CONTROLS), crosswalk=_DEFAULT_CROSSWALK)

    # ------------- Catalog IO -------------
    def load_catalog(self, *paths: os.PathLike | str) -> None:
        """
        Load and merge external catalogs (JSON/YAML). Later files override earlier by id.
        Expected schema:
        {
          "controls": [
            {
              "id": "AC-2",
              "family": "AC",
              "title": "...",
              "rev": "r5",
              "priority": "P1",
              "baseline": ["LOW","MODERATE","HIGH"],
              "enhancements": ["AC-2(1)"],
              "statement": "..."
            },
            ...
          ],
          "crosswalk": {
            "AC-2": [
              {"framework":"ISO27001:2022","control_id":"A.5.16","weight":0.9,"note":"..."}
            ]
          }
        }
        """
        with self._lock:
            controls = dict(self._catalog.controls)
            xwalk = Crosswalk(links=dict(self._catalog.crosswalk.links))

            for p in paths:
                pth = Path(p)
                if not pth.exists():
                    raise FileNotFoundError(f"Catalog file not found: {pth}")
                data = self._read_any(pth)
                # controls
                for raw in data.get("controls", []):
                    ctrl = self._control_from_raw(raw)
                    controls[ctrl.canonical_id()] = ctrl
                # crosswalk
                for cid, arr in data.get("crosswalk", {}).items():
                    canon = canonical_control_id(cid)
                    for it in arr or []:
                        link = ControlLink(
                            framework=str(it["framework"]),
                            control_id=str(it["control_id"]),
                            weight=float(it.get("weight", 1.0)),
                            note=it.get("note"),
                        )
                        xwalk.add(canon, link)

            self._catalog = Catalog(controls=controls, crosswalk=xwalk)
            log.info(f"catalog_loaded hash={self._catalog.hash()} version={__version__}")

    def _read_any(self, path: Path) -> dict:
        suffix = path.suffix.lower()
        text = path.read_text(encoding="utf-8")
        if suffix in (".yaml", ".yml"):
            if not _HAS_YAML:
                raise RuntimeError("PyYAML is required to read YAML files. Install pyyaml.")
            return yaml.safe_load(text) or {}
        if suffix == ".json":
            return json.loads(text)
        raise ValueError(f"Unsupported file type: {suffix}")

    def _control_from_raw(self, raw: Mapping[str, object]) -> Control:
        try:
            cid = canonical_control_id(str(raw["id"]))
            fam = str(raw.get("family") or extract_family(cid))
            if fam not in NistFamily.all():
                # Accept unknown family if syntactically valid; use from id
                fam = extract_family(cid)
            title = str(raw.get("title") or "")
            rev = str(raw.get("rev") or "r5")
            priority = raw.get("priority")
            baseline = tuple(str(x).upper() for x in raw.get("baseline", ()))
            enhancements = tuple(str(x).upper() for x in raw.get("enhancements", ()))
            statement = raw.get("statement")
        except Exception as e:
            raise InvalidControlError(f"Invalid control record: {raw}") from e
        return Control(
            id=cid,
            family=fam,
            title=title,
            rev=rev,
            priority=str(priority) if priority else None,
            baseline=baseline,
            enhancements=enhancements,
            statement=str(statement) if statement is not None else None,
        )

    # ------------- Queries -------------
    def get(self, control_id: str) -> Control:
        self._ensure_loaded()
        return self._catalog.get(control_id)

    def crosswalk(self, control_id: str) -> List[ControlLink]:
        self._ensure_loaded()
        return self._catalog.crosswalk.for_control(control_id)

    def list_controls(
        self,
        family: Optional[str] = None,
        baseline: Optional[str] = None,
        include_enhancements: bool = True,
    ) -> List[Control]:
        self._ensure_loaded()
        fam = family.upper() if family else None
        if fam and not FAMILY_RE.match(fam):
            raise InvalidControlError(f"Invalid family: {fam}")
        bl = baseline.upper() if baseline else None
        out: List[Control] = []
        for ctrl in self._catalog.controls.values():
            if fam and ctrl.family != fam:
                continue
            if bl and bl not in ctrl.baseline:
                continue
            if not include_enhancements and "(" in ctrl.id:
                continue
            out.append(ctrl)
        return sorted(out, key=lambda c: c.id)

    def search(
        self,
        text: str,
        family: Optional[str] = None,
        baseline: Optional[str] = None,
        limit: int = 20,
    ) -> List[Control]:
        self._ensure_loaded()
        q_tokens = set(_tokenize(text))
        fam = family.upper() if family else None
        bl = baseline.upper() if baseline else None

        scored: List[Tuple[float, Control]] = []
        for c in self._catalog.controls.values():
            if fam and c.family != fam:
                continue
            if bl and bl not in c.baseline:
                continue
            hay = " ".join(filter(None, [c.id, c.title, c.statement or ""]))
            tokens = set(_tokenize(hay))
            if not q_tokens:
                score = 0.0
            else:
                inter = q_tokens & tokens
                score = len(inter) / max(1, len(q_tokens))
            if score > 0 or not q_tokens:
                scored.append((score, c))

        scored.sort(key=lambda t: (-t[0], t[1].id))
        return [c for _, c in scored[:limit]]

    # ------------- Evidence coverage -------------
    def coverage(
        self,
        evidences: Iterable[Evidence],
        freshness_days: int = 365,
    ) -> Dict[str, Dict[str, object]]:
        """
        Compute per-control coverage:
        - status: covered | missing | stale
        - artifacts: list of artifact ids
        - freshness: max age days
        """
        self._ensure_loaded()
        by_ctrl: Dict[str, List[Evidence]] = {}
        for ev in evidences:
            cid = canonical_control_id(ev.control_id)
            by_ctrl.setdefault(cid, []).append(ev)

        report: Dict[str, Dict[str, object]] = {}
        for cid in self._catalog.controls.keys():
            arr = by_ctrl.get(cid, [])
            if not arr:
                report[cid] = {"status": "missing", "artifacts": [], "freshness_days": None}
                continue
            ages = [(dt.datetime.utcnow() - ev.updated_at).days for ev in arr]
            min_age = min(ages) if ages else None
            if min_age is None:
                report[cid] = {"status": "missing", "artifacts": [], "freshness_days": None}
                continue
            status = "covered" if min_age <= freshness_days else "stale"
            report[cid] = {
                "status": status,
                "artifacts": [ev.artifact_id for ev in arr],
                "freshness_days": min_age,
            }
        return report

    # ------------- Export -------------
    def export(self) -> Dict[str, object]:
        self._ensure_loaded()
        return {
            "meta": {
                "mapper_version": __version__,
                "schema_version": __schema_version__,
                "dataset_hint": __dataset_hint__,
                "hash": self._catalog.hash(),
            },
            "controls": [dataclasses.asdict(c) for c in sorted(self._catalog.controls.values(), key=lambda x: x.id)],
            "crosswalk": {
                cid: [dataclasses.asdict(l) for l in links]
                for cid, links in sorted(self._catalog.crosswalk.links.items())
            },
        }

    # ------------- Internal -------------
    def _ensure_loaded(self) -> None:
        if not self._catalog or not self._catalog.controls:
            raise CatalogNotLoadedError("Catalog is not loaded")

    # ------------- CLI -------------
    @classmethod
    def main(cls, argv: Optional[Sequence[str]] = None) -> int:
        parser = argparse.ArgumentParser(
            prog="mapper_nist80053",
            description="NIST SP 800-53 Rev.5 mapper with crosswalks and evidence coverage",
        )
        sub = parser.add_subparsers(dest="cmd", required=True)

        p_validate = sub.add_parser("validate", help="Validate NIST control ids")
        p_validate.add_argument("ids", nargs="+", help="Control ids (e.g., AC-2 AC-2(1) RA-5)")

        p_search = sub.add_parser("search", help="Search controls by text")
        p_search.add_argument("text", help="Search text")
        p_search.add_argument("--family", help="Family code (e.g., AC, RA)")
        p_search.add_argument("--baseline", help="Baseline (LOW/MODERATE/HIGH)")
        p_search.add_argument("--limit", type=int, default=20)

        p_map = sub.add_parser("map", help="Show crosswalk for a control id")
        p_map.add_argument("id", help="Control id (e.g., AC-2)")

        p_cov = sub.add_parser("coverage", help="Compute coverage from evidences JSON")
        p_cov.add_argument("file", help="JSON file with evidences array")
        p_cov.add_argument("--freshness-days", type=int, default=365)

        p_load = sub.add_parser("load", help="Load and merge catalogs, then export merged JSON to stdout")
        p_load.add_argument("files", nargs="+", help="Catalog files (JSON/YAML)")

        args = parser.parse_args(argv)
        mapper = cls()

        if args.cmd == "validate":
            for cid in args.ids:
                try:
                    print(canonical_control_id(cid))
                except InvalidControlError as e:
                    print(f"INVALID: {cid} :: {e}", file=sys.stderr)
                    return 2
            return 0

        if args.cmd == "search":
            res = mapper.search(text=args.text, family=args.family, baseline=args.baseline, limit=args.limit)
            out = [
                {
                    "id": c.id,
                    "family": c.family,
                    "title": c.title,
                    "baseline": list(c.baseline),
                    "enhancements": list(c.enhancements),
                }
                for c in res
            ]
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0

        if args.cmd == "map":
            try:
                links = mapper.crosswalk(args.id)
            except InvalidControlError as e:
                print(str(e), file=sys.stderr)
                return 2
            out = [dataclasses.asdict(l) for l in links]
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0

        if args.cmd == "coverage":
            data = json.loads(Path(args.file).read_text(encoding="utf-8"))
            evidences = []
            for it in data:
                evidences.append(
                    Evidence(
                        control_id=str(it["control_id"]),
                        artifact_id=str(it["artifact_id"]),
                        type=str(it.get("type", "artifact")),
                        updated_at=_parse_dt(it.get("updated_at")),
                        owner=it.get("owner"),
                        status=str(it.get("status", EvidenceStatus.PRESENT)),
                    )
                )
            report = mapper.coverage(evidences, freshness_days=args.freshness_days)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0

        if args.cmd == "load":
            mapper.load_catalog(*args.files)
            print(json.dumps(mapper.export(), ensure_ascii=False, indent=2))
            return 0

        parser.print_help()
        return 1


# ---------------------------
# Utilities
# ---------------------------
def _parse_dt(val: object) -> dt.datetime:
    if isinstance(val, dt.datetime):
        return val
    if isinstance(val, (int, float)):
        return dt.datetime.utcfromtimestamp(float(val))
    if isinstance(val, str):
        try:
            # Try ISO 8601
            return dt.datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass
        # Fallback: RFC3339-like
        m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", val)
        if m:
            return dt.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
    # Default to now if not parseable; safer to avoid crashing CLI
    return dt.datetime.utcnow()


# ---------------------------
# Caching adapters
# ---------------------------
@lru_cache(maxsize=1024)
def parse_control_id_cached(control_id: str) -> Tuple[str, Optional[int]]:
    """
    Parse control id into (base_id, enhancement_number)
    e.g., AC-2 -> ("AC-2", None), AC-2(1) -> ("AC-2", 1)
    """
    cid = canonical_control_id(control_id)
    m = re.match(r"^([A-Z]{2,3}-\d{1,3})(?:\((\d+)\))?$", cid)
    if not m:
        raise InvalidControlError(f"Invalid control id: {control_id}")
    base = m.group(1)
    enh = int(m.group(2)) if m.group(2) else None
    return base, enh


# ---------------------------
# Entrypoint
# ---------------------------
if __name__ == "__main__":
    sys.exit(NistMapper.main())
