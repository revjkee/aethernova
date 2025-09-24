# file: cybersecurity-core/cybersecurity/compliance/mapper_soc2.py
"""
SOC2 Compliance Mapper (industrial-grade)

Назначение:
- Управление каталогом критериев SOC 2 (TSC) и внутренних контролей.
- Маппинг контролей на критерии SOC 2 с оценкой покрытия (full/partial).
- Валидация схемы данных, строгая проверка ссылочной целостности.
- Отчётность: JSON/CSV, агрегаты по категориям и критериям, разрывы (gaps).
- CLI для интеграции в CI/CD.

Зависимости:
- pydantic (v1 или v2) — валидаторы моделей.
- (опционально) PyYAML для YAML-входа; без него работает с JSON.

SOC2 примечание:
- Модуль НЕ вшивает "официальный" список критериев SOC 2, чтобы избежать
  недостоверных названий. Каталог критериев передаётся пользователем (ID + title).
- Формат ID валидируется (CCx.y, A1.x, C1.x, PI1.x, P1.x). Названия и состав
  критериев — из внешнего файла организации.

Входные структуры (единый dataset):
{
  "criteria": [
    {"id": "CC1.1", "title": "...", "category": "SECURITY"},
    ...
  ],
  "controls": [
    {"id": "SEC-001", "title": "Zero Trust", "owner": "SecOps", "status": "enabled"},
    ...
  ],
  "mappings": [
    {
      "control_id": "SEC-001",
      "criterion_id": "CC1.1",
      "coverage": "full",
      "rationale": "Control fully addresses CC1.1 via ...",
      "frequency": "quarterly",
      "last_tested": "2025-08-20",
      "evidence": [
        {"type": "policy", "uri": "https://.../policy.pdf", "sha256": "..."},
        {"type": "ticket", "uri": "JIRA-123"}
      ]
    }
  ]
}

CLI:
  python -m cybersecurity.compliance.mapper_soc2 \
    --in dataset.yaml \
    --report-json report.json \
    --report-csv coverage.csv \
    --fail-on-gap
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple

# Pydantic v1/v2 compatibility
try:
    from pydantic import BaseModel, Field, root_validator, validator  # v1
    _PD_V2 = False
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field, field_validator as validator, model_validator as root_validator  # v2
    _PD_V2 = True  # type: ignore

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    yaml = None  # type: ignore
    _HAS_YAML = False

logger = logging.getLogger("cybersecurity.compliance.mapper_soc2")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ----------------------------- CONSTANTS & UTILS -----------------------------

SOC2_ID_RE = re.compile(r"^(CC\d+(?:\.\d+)?|A\d+(?:\.\d+)?|C\d+(?:\.\d+)?|PI\d+(?:\.\d+)?|P\d+(?:\.\d+)?)$")

CATEGORY = Literal["SECURITY", "AVAILABILITY", "CONFIDENTIALITY", "PROCESSING_INTEGRITY", "PRIVACY"]
CONTROL_STATUS = Literal["enabled", "disabled", "monitor"]
COVERAGE = Literal["full", "partial"]

EVIDENCE_TYPE = Literal[
    "policy", "procedure", "log", "screenshot", "ticket", "attestation", "config", "report", "other"
]

FREQ = Literal["continuous", "daily", "weekly", "monthly", "quarterly", "semiannual", "annual", "ad-hoc"]


def infer_category(criterion_id: str) -> CATEGORY:
    """
    По ID критерия определяет категорию SOC2 TSC.
    """
    if criterion_id.startswith("CC"):
        return "SECURITY"
    if criterion_id.startswith("A"):
        return "AVAILABILITY"
    if criterion_id.startswith("C"):
        return "CONFIDENTIALITY"
    if criterion_id.startswith("PI"):
        return "PROCESSING_INTEGRITY"
    if criterion_id.startswith("P"):
        return "PRIVACY"
    # fallback — валидация выше не должна сюда пускать
    return "SECURITY"  # pragma: no cover


def sha256_hex_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# --------------------------------- MODELS ------------------------------------

class Criterion(BaseModel):
    id: str = Field(..., description="SOC 2 criterion ID, e.g., CC1.1")
    title: Optional[str] = Field(None, max_length=500)
    category: Optional[CATEGORY] = None

    @validator("id")
    def _id_format(cls, v: str) -> str:
        if not SOC2_ID_RE.match(v):
            raise ValueError(f"Invalid SOC2 criterion id format: {v}")
        return v

    @root_validator  # v1, v2-compatible alias defined above
    def _cat_infer(cls, values: Dict[str, Any]):
        if not values.get("category"):
            values["category"] = infer_category(values["id"])
        return values


class Control(BaseModel):
    id: str = Field(..., min_length=3, max_length=64)
    title: str = Field(..., min_length=3, max_length=200)
    owner: Optional[str] = Field(None, max_length=200)
    status: CONTROL_STATUS = "enabled"
    tags: List[str] = Field(default_factory=list)

    @validator("id")
    def _control_id(cls, v: str) -> str:
        if not re.match(r"^[A-Z]{2,8}-\d{3,5}$", v):
            # допускаем и другие корпоративные форматы, но предупреждаем
            logger.debug("Non-standard control id format: %s", v)
        return v

    @validator("tags", each_item=True)
    def _tag_format(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9][a-z0-9_.-]{0,62}$", v):
            raise ValueError(f"Invalid tag: {v}")
        return v


class Evidence(BaseModel):
    type: EVIDENCE_TYPE
    uri: str = Field(..., min_length=1, max_length=1000)
    sha256: Optional[str] = Field(
        None, regex=r"^[A-Fa-f0-9]{64}$", description="SHA-256 (hex) для локальных артефактов"
    )

    @validator("uri")
    def _uri_ok(cls, v: str) -> str:
        # Разрешаем https://, s3://, file://, jira:KEY, vault:PATH
        if not re.match(r"^(https://|s3://|file://|jira:|vault:|gs://|azureblob://|artifactory://|git:)", v):
            logger.debug("Non-standard evidence URI scheme: %s", v)
        return v


class Mapping(BaseModel):
    control_id: str
    criterion_id: str
    coverage: COVERAGE
    rationale: str = Field(..., min_length=5, max_length=2000)
    frequency: Optional[FREQ] = None
    last_tested: Optional[dt.date] = None
    evidence: List[Evidence] = Field(default_factory=list)

    @validator("criterion_id")
    def _crit_id_format(cls, v: str) -> str:
        if not SOC2_ID_RE.match(v):
            raise ValueError(f"Invalid SOC2 criterion id format: {v}")
        return v

    @validator("last_tested", pre=True)
    def _parse_date(cls, v):
        if v in (None, ""):
            return None
        if isinstance(v, dt.date):
            return v
        try:
            return dt.date.fromisoformat(v)
        except Exception as e:
            raise ValueError(f"last_tested must be ISO date (YYYY-MM-DD): {e}")


class Dataset(BaseModel):
    criteria: List[Criterion]
    controls: List[Control]
    mappings: List[Mapping]

    @root_validator
    def _validate_refs(cls, values: Dict[str, Any]):
        crit_ids: Set[str] = {c.id for c in values.get("criteria", [])}
        ctrl_ids: Set[str] = {c.id for c in values.get("controls", [])}

        # уникальность
        if len(crit_ids) != len(values.get("criteria", [])):
            raise ValueError("Duplicate criterion IDs in criteria list")
        if len(ctrl_ids) != len(values.get("controls", [])):
            raise ValueError("Duplicate control IDs in controls list")

        # ссылки
        unknown_crit = [m.criterion_id for m in values.get("mappings", []) if m.criterion_id not in crit_ids]
        unknown_ctrl = [m.control_id for m in values.get("mappings", []) if m.control_id not in ctrl_ids]
        if unknown_crit:
            raise ValueError(f"Mappings reference unknown criterion IDs: {sorted(set(unknown_crit))}")
        if unknown_ctrl:
            raise ValueError(f"Mappings reference unknown control IDs: {sorted(set(unknown_ctrl))}")

        return values


# ------------------------------ COVERAGE ENGINE ------------------------------

@dataclass(frozen=True)
class CoverageCell:
    criterion_id: str
    category: CATEGORY
    controls: List[str]
    coverage: Literal["full", "partial", "none"]


@dataclass(frozen=True)
class CoverageReport:
    total_criteria: int
    covered_full: int
    covered_partial: int
    covered_none: int
    by_category: Dict[CATEGORY, Dict[str, int]]
    cells: List[CoverageCell]
    gaps: List[str]  # criterion_id без покрытия


def compute_coverage(ds: Dataset, *, include_disabled_controls: bool = False) -> CoverageReport:
    """
    Считает покрытие по каждому критерию на основе маппинга.
    full — если есть хотя бы один mapping с coverage=full и контролем в статусе enabled/monitor.
    partial — если нет full, но есть хотя бы один partial.
    none — если нет ни одного mapping.
    """
    ctrl_status = {c.id: c.status for c in ds.controls}
    crit_meta = {c.id: c for c in ds.criteria}

    # группировка маппингов по критерию
    by_crit: Dict[str, List[Mapping]] = {}
    for m in ds.mappings:
        if not include_disabled_controls and ctrl_status.get(m.control_id) == "disabled":
            continue
        by_crit.setdefault(m.criterion_id, []).append(m)

    cells: List[CoverageCell] = []
    covered_full = covered_partial = covered_none = 0
    by_category: Dict[CATEGORY, Dict[str, int]] = {
        "SECURITY": {"full": 0, "partial": 0, "none": 0},
        "AVAILABILITY": {"full": 0, "partial": 0, "none": 0},
        "CONFIDENTIALITY": {"full": 0, "partial": 0, "none": 0},
        "PROCESSING_INTEGRITY": {"full": 0, "partial": 0, "none": 0},
        "PRIVACY": {"full": 0, "partial": 0, "none": 0},
    }

    for crit in ds.criteria:
        maps = by_crit.get(crit.id, [])
        ctrl_ids = [m.control_id for m in maps]
        if any(m.coverage == "full" for m in maps):
            cov = "full"
            covered_full += 1
        elif any(m.coverage == "partial" for m in maps):
            cov = "partial"
            covered_partial += 1
        else:
            cov = "none"
            covered_none += 1

        by_category[crit.category][cov] += 1
        cells.append(CoverageCell(criterion_id=crit.id, category=crit.category, controls=ctrl_ids, coverage=cov))

    gaps = [c.criterion_id for c in cells if c.coverage == "none"]
    return CoverageReport(
        total_criteria=len(ds.criteria),
        covered_full=covered_full,
        covered_partial=covered_partial,
        covered_none=covered_none,
        by_category=by_category,
        cells=cells,
        gaps=gaps,
    )


# ------------------------------ IO & REPORTS --------------------------------

def load_dataset(path: Path) -> Dataset:
    """
    Загружает Dataset из YAML или JSON.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        if not _HAS_YAML:
            raise RuntimeError("PyYAML is required to load YAML files")
        data = yaml.safe_load(text)  # type: ignore
    else:
        data = json.loads(text)
    return Dataset(**data)


def save_json(obj: Any, path: Path) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def export_coverage_csv(report: CoverageReport, path: Path) -> None:
    """
    Экспорт покритериального покрытия в CSV.
    """
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["criterion_id", "category", "coverage", "controls"])
        for c in report.cells:
            w.writerow([c.criterion_id, c.category, c.coverage, ";".join(c.controls)])


def generate_report(ds: Dataset) -> Dict[str, Any]:
    """
    Полный отчёт по dataset: метрики покрытия + качество данных.
    """
    cov = compute_coverage(ds)
    by_cat = {
        cat: {
            "full": cov.by_category[cat]["full"],
            "partial": cov.by_category[cat]["partial"],
            "none": cov.by_category[cat]["none"],
            "total": sum(cov.by_category[cat].values()),
        }
        for cat in cov.by_category
    }

    # Проверки качества: устаревшие тестирования (> 1 года), отсутствие evidence при full
    stale_controls: List[Tuple[str, str]] = []  # (criterion_id, control_id)
    missing_evidence: List[Tuple[str, str]] = []
    today = dt.date.today()

    maps_by_crit: Dict[str, List[Mapping]] = {}
    for m in ds.mappings:
        maps_by_crit.setdefault(m.criterion_id, []).append(m)

    for cell in cov.cells:
        if cell.coverage == "none":
            continue
        for m in maps_by_crit.get(cell.criterion_id, []):
            if m.coverage == "full":
                if not m.evidence:
                    missing_evidence.append((cell.criterion_id, m.control_id))
            if m.last_tested and (today - m.last_tested).days > 365:
                stale_controls.append((cell.criterion_id, m.control_id))

    return {
        "summary": {
            "total_criteria": cov.total_criteria,
            "covered_full": cov.covered_full,
            "covered_partial": cov.covered_partial,
            "covered_none": cov.covered_none,
            "coverage_pct_full_or_partial": round(
                100.0 * (cov.covered_full + cov.covered_partial) / max(1, cov.total_criteria), 2
            ),
        },
        "by_category": by_cat,
        "gaps": cov.gaps,
        "data_quality": {
            "stale_controls": stale_controls,
            "missing_evidence": missing_evidence,
        },
    }


# ------------------------------ CLI INTERFACE --------------------------------

def _cli(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="SOC2 Compliance Mapper")
    p.add_argument("--in", dest="inp", required=True, help="Path to dataset (YAML/JSON)")
    p.add_argument("--report-json", dest="report_json", help="Write JSON report to path")
    p.add_argument("--report-csv", dest="report_csv", help="Write coverage CSV to path")
    p.add_argument("--fail-on-gap", action="store_true", help="Exit non-zero if there are uncovered criteria")
    p.add_argument("--include-disabled", action="store_true", help="Include disabled controls in coverage")
    args = p.parse_args(argv)

    ds = load_dataset(Path(args.inp))
    if args.include_disabled:
        cov = compute_coverage(ds, include_disabled_controls=True)
    else:
        cov = compute_coverage(ds)

    report = generate_report(ds)

    if args.report_json:
        save_json(report, Path(args.report_json))
        logger.info("Report JSON written: %s", args.report_json)
    if args.report_csv:
        export_coverage_csv(cov, Path(args.report_csv))
        logger.info("Report CSV written: %s", args.report_csv)

    if args.fail_on_gap and cov.covered_none > 0:
        logger.error("Coverage gaps detected: %d criteria without coverage", cov.covered_none)
        return 2

    logger.info(
        "Coverage: total=%d full=%d partial=%d none=%d",
        cov.total_criteria, cov.covered_full, cov.covered_partial, cov.covered_none
    )
    return 0


# ----------------------------- PUBLIC API ------------------------------------

__all__ = [
    "Criterion",
    "Control",
    "Evidence",
    "Mapping",
    "Dataset",
    "CoverageCell",
    "CoverageReport",
    "compute_coverage",
    "load_dataset",
    "export_coverage_csv",
    "generate_report",
]

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
