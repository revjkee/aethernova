# File: oblivionvault/cli/tools/release_legal_hold.py
# Purpose: Safely release Legal Hold flags under strict controls with full audit/evidence
# Python: 3.10+

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    _TRACER = None  # type: ignore

# Internal modules (robust optional imports with graceful degradation)
_AUDIT_READY = True
try:
    from oblivionvault.audit.trail import (
        AuditTrail, AuditConfig, AuditEvent, StdoutJsonSink, BigQueryAuditSink
    )
except Exception:  # pragma: no cover
    _AUDIT_READY = False

_BQ_READY = True
try:
    from oblivionvault.adapters.storage_bigquery import BigQueryStorageAdapter, BigQueryConfig
except Exception:  # pragma: no cover
    _BQ_READY = False

_EVIDENCE_READY = True
try:
    from oblivionvault.workers.evidence_builder import (
        EvidenceBuilder, EvidenceConfig, ArtifactInput
    )
except Exception:  # pragma: no cover
    _EVIDENCE_READY = False


# ------------------------------- Helpers ------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _maybe_span(name: str):
    class _Null:
        def __enter__(self): return None
        def __exit__(self, *a): return False
    if _TRACER:
        return _TRACER.start_as_current_span(name)
    return _Null()

def _require(expr: bool, msg: str):
    if not expr:
        raise SystemExit(f"ERROR: {msg}")

def _as_bool(s: Optional[str]) -> Optional[bool]:
    if s is None:
        return None
    return s.lower() in ("1", "true", "t", "yes", "y", "on")


# ------------------------------ Config --------------------------------------

@dataclass(slots=True)
class ToolConfig:
    # BigQuery
    project_id: str = field(default_factory=lambda: os.getenv("BQ_PROJECT_ID", ""))
    dataset: str = field(default_factory=lambda: os.getenv("BQ_DATASET", "oblivionvault"))
    location: str = field(default_factory=lambda: os.getenv("BQ_LOCATION", "EU"))
    table: str = field(default_factory=lambda: os.getenv("BQ_VAULT_TABLE", "vault_records"))

    # Safety limits
    default_limit: int = 1000  # maximum rows to affect unless --force-large
    require_two_person_rule: bool = field(default_factory=lambda: _as_bool(os.getenv("LH_REQUIRE_TWO_PERSON", "true")) or True)

    # Audit
    enable_bq_audit_sink: bool = field(default_factory=lambda: _as_bool(os.getenv("AUDIT_TO_BQ", "false")) or False)
    audit_state_path: Optional[str] = field(default_factory=lambda: os.getenv("AUDIT_STATE_PATH", None))
    hmac_key_id: Optional[str] = field(default_factory=lambda: os.getenv("AUDIT_HMAC_KEY_ID", None))
    hmac_key_b64: Optional[str] = field(default_factory=lambda: os.getenv("AUDIT_HMAC_KEY_B64", None))  # base64 key

    # Evidence
    enable_evidence: bool = field(default_factory=lambda: _as_bool(os.getenv("LH_EVIDENCE_ENABLE", "true")) or True)
    evidence_base_dir: str = field(default_factory=lambda: os.getenv("EVIDENCE_BASE_DIR", "/var/lib/oblivionvault/evidence"))

    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    def validate(self):
        _require(bool(self.project_id), "BQ_PROJECT_ID must be set (env or args)")
        _require(bool(self.dataset), "BQ_DATASET must be set (env or args)")
        _require(bool(self.table), "BQ_VAULT_TABLE must be set (env or args)")


# -------------------------- BigQuery Driver ---------------------------------

class VaultBigQuery:
    """Thin facade over BigQueryStorageAdapter for vault_records DML/SELECT."""

    def __init__(self, cfg: ToolConfig, logger: logging.Logger):
        if not _BQ_READY:
            raise SystemExit("ERROR: BigQuery adapter is not available")
        self.log = logger
        self.cfg = cfg
        self._bq = BigQueryStorageAdapter(
            config=BigQueryConfig(
                project_id=cfg.project_id,
                dataset=cfg.dataset,
                location=cfg.location
            ),
            logger=logger
        )

    def preview_scope(self,
                      tenant_id: Optional[str],
                      case_id: Optional[str],
                      id_list: Optional[List[str]],
                      older_than: Optional[str]) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Returns (count, sample_rows up to 100)
        """
        with _maybe_span("lh.preview"):
            table_id = f"`{self.cfg.project_id}.{self.cfg.dataset}.{self.cfg.table}`"
            where = ["legal_hold = TRUE"]
            params: Dict[str, Any] = {}

            if tenant_id:
                where.append("tenant_id = @tenant_id")
                params["tenant_id"] = tenant_id
            if case_id:
                where.append("case_id = @case_id")
                params["case_id"] = case_id
            if id_list:
                # Use SPLIT over comma-joined list to avoid ARRAY param complexity
                where.append("id IN UNNEST(SPLIT(@id_list))")
                params["id_list"] = ",".join(sorted(set(id_list)))
            if older_than:
                where.append("legal_hold_set_at < @older_than")
                params["older_than"] = older_than

            where_sql = " AND ".join(where)
            count_sql = f"SELECT COUNT(1) AS cnt FROM {table_id} WHERE {where_sql}"
            rows = self._bq.query(count_sql, params=params)
            cnt = int(rows[0]["cnt"]) if rows else 0

            sample_sql = f"""
                SELECT id, tenant_id, case_id, legal_hold, legal_hold_set_at
                FROM {table_id}
                WHERE {where_sql}
                ORDER BY legal_hold_set_at ASC
                LIMIT 100
            """
            sample = self._bq.query(sample_sql, params=params)
            return cnt, sample

    def release_hold(self,
                     tenant_id: Optional[str],
                     case_id: Optional[str],
                     id_list: Optional[List[str]],
                     older_than: Optional[str],
                     ticket: str,
                     reason: str,
                     approver1: str,
                     approver2: str,
                     operator: str) -> int:
        """
        Performs parameterized UPDATE; returns affected row count (BigQuery DML returns job stats).
        """
        with _maybe_span("lh.release"):
            table_id = f"`{self.cfg.project_id}.{self.cfg.dataset}.{self.cfg.table}`"
            set_sql = """
                legal_hold = FALSE,
                legal_hold_released_at = CURRENT_TIMESTAMP(),
                legal_hold_release_ticket = @ticket,
                legal_hold_release_reason = @reason,
                legal_hold_release_approver1 = @approver1,
                legal_hold_release_approver2 = @approver2,
                legal_hold_release_operator = @operator,
                updated_at = CURRENT_TIMESTAMP()
            """
            where = ["legal_hold = TRUE"]
            params: Dict[str, Any] = {
                "ticket": ticket,
                "reason": reason,
                "approver1": approver1,
                "approver2": approver2,
                "operator": operator,
            }

            if tenant_id:
                where.append("tenant_id = @tenant_id")
                params["tenant_id"] = tenant_id
            if case_id:
                where.append("case_id = @case_id")
                params["case_id"] = case_id
            if id_list:
                where.append("id IN UNNEST(SPLIT(@id_list))")
                params["id_list"] = ",".join(sorted(set(id_list)))
            if older_than:
                where.append("legal_hold_set_at < @older_than")
                params["older_than"] = older_than

            where_sql = " AND ".join(where)
            sql = f"UPDATE {table_id} SET {set_sql} WHERE {where_sql}"
            job_rows = self._bq.query(sql, params=params)
            # For UPDATE, google client returns empty result set; we can re-count post
            rows_after, _ = self.preview_scope(tenant_id, case_id, id_list, older_than)
            # rows_after are remaining holds; we need affected count:
            # compute before - after externally; callsites pass "before_count"
            return -1  # sentinel; caller computes by diff

    def close(self):
        self._bq.close()


# ------------------------------ Reporting -----------------------------------

def write_report_json(path: Path, payload: Dict[str, Any], log: logging.Logger) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp.json")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    log.info("Report written", extra={"path": str(path)})

def write_report_csv(path: Path, rows: Sequence[Dict[str, Any]], log: logging.Logger) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        log.info("CSV report (empty) written", extra={"path": str(path)})
        return
    fieldnames = list(rows[0].keys())
    tmp = path.with_suffix(".tmp.csv")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    os.replace(tmp, path)
    log.info("CSV report written", extra={"path": str(path)})


# ------------------------------- Evidence -----------------------------------

def maybe_build_evidence(enable: bool,
                         case_id: str,
                         scope: Dict[str, Any],
                         affected_ids: List[str],
                         evidence_dir: str,
                         log: logging.Logger) -> Optional[Dict[str, Any]]:
    if not enable or not _EVIDENCE_READY:
        return None

    builder = EvidenceBuilder(
        config=EvidenceConfig(
            base_dir=evidence_dir,
            make_parents=True,
            active_key_id=None,  # sidecar HMAC optional here
            hmac_keys={}
        ),
        sinks=[],  # local only; metadata sinks можно добавить при необходимости
        logger=log
    )

    manifest = {
        "action": "legal_hold.release",
        "scope": scope,
        "affected_count": len(affected_ids),
        "affected_ids": affected_ids[:1000],  # чтобы манифест не раздувался; полный список — в JSON отчёте
        "ts": _utcnow_iso(),
    }

    res = builder.build(
        case_id=case_id or "global",
        artifacts=[
            ArtifactInput(inline_json=manifest, alias="release_summary.json"),
        ],
        labels={"module": "legal_hold"},
        related_events=[]
    )
    builder.close()
    return {
        "bundle_path": str(res.bundle_path),
        "signature_path": str(res.signature_path),
        "bundle_digest_hex": res.bundle_digest_hex,
        "merkle_root_hex": res.merkle_root_hex,
    }


# -------------------------------- Audit -------------------------------------

def _maybe_init_audit(cfg: ToolConfig, log: logging.Logger) -> Optional[AuditTrail]:
    if not _AUDIT_READY:
        log.warning("AuditTrail not available; falling back to logger only")
        return None

    hmac_keys = {}
    if cfg.hmac_key_id and cfg.hmac_key_b64:
        import base64
        try:
            hmac_keys[cfg.hmac_key_id] = base64.b64decode(cfg.hmac_key_b64)
        except Exception:
            log.warning("Invalid AUDIT_HMAC_KEY_B64; proceeding without HMAC")

    acfg = AuditConfig(
        app_name="oblivionvault",
        node_id=os.getenv("NODE_ID", "cli"),
        tenant_id=None,
        hmac_keys=hmac_keys,
        active_key_id=cfg.hmac_key_id if hmac_keys else None,
        state_path=cfg.audit_state_path
    )

    sink = StdoutJsonSink()
    if cfg.enable_bq_audit_sink:
        try:
            sink = BigQueryAuditSink(dataset=os.getenv("BQ_DATASET", cfg.dataset),
                                     table="audit_events")
        except Exception as e:
            log.warning("BigQueryAuditSink init failed: %s; using Stdout sink", e)

    trail = AuditTrail(acfg, sink, logger=log)
    return trail


# ------------------------------- CLI Logic ----------------------------------

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="release-legal-hold",
        description="Safely release Legal Hold flags with audit and evidence"
    )
    # Scope
    p.add_argument("--tenant-id", help="Tenant scope", default=None)
    p.add_argument("--case-id", help="Case scope", default=None)
    p.add_argument("--ids", help="Comma-separated list of record IDs", default=None)
    p.add_argument("--ids-file", help="Path to file with IDs (one per line)", default=None)
    p.add_argument("--older-than", help="ISO-8601 timestamp; only holds set before this moment", default=None)

    # Safety / confirmation
    p.add_argument("--dry-run", action="store_true", help="Preview only; no changes")
    p.add_argument("--confirm", choices=["yes", "no"], default="no", help="Must be 'yes' to execute")
    p.add_argument("--limit", type=int, default=None, help="Max rows to affect; defaults to env/default")
    p.add_argument("--force-large", action="store_true", help="Allow affecting more than default limit")

    # Approvals
    p.add_argument("--ticket", required=False, help="Change/incident ticket reference")
    p.add_argument("--reason", required=False, help="Human-readable justification")
    p.add_argument("--approver1", required=False, help="First approver identity (email or id)")
    p.add_argument("--approver2", required=False, help="Second approver identity (must differ)")

    # BigQuery config overrides
    p.add_argument("--bq-project", default=None, help="Override BQ project")
    p.add_argument("--bq-dataset", default=None, help="Override BQ dataset")
    p.add_argument("--bq-table", default=None, help="Override BQ table (default vault_records)")
    p.add_argument("--bq-location", default=None, help="Override BQ location")

    # Reporting
    p.add_argument("--report-json", default=None, help="Write JSON report to path")
    p.add_argument("--report-csv", default=None, help="Write CSV sample to path")

    # Evidence
    p.add_argument("--evidence", action="store_true", help="Force evidence bundle build")
    p.add_argument("--no-evidence", action="store_true", help="Disable evidence bundle build")
    p.add_argument("--evidence-dir", default=None, help="Base dir for evidence bundles")

    # Logging
    p.add_argument("--log-level", default=None, help="Logging level")

    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    # Logger
    log_level = (args.log_level or os.getenv("LOG_LEVEL", "INFO")).upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    log = logging.getLogger("oblivionvault.cli.release_legal_hold")

    # Tool config
    cfg = ToolConfig()
    if args.bq_project: cfg.project_id = args.bq_project
    if args.bq_dataset: cfg.dataset = args.bq_dataset
    if args.bq_table:   cfg.table = args.bq_table
    if args.bq_location: cfg.location = args.bq_location
    if args.limit is not None: cfg.default_limit = args.limit
    if args.evidence: cfg.enable_evidence = True
    if args.no_evidence: cfg.enable_evidence = False
    if args.evidence_dir: cfg.evidence_base_dir = args.evidence_dir
    if args.log_level: cfg.log_level = args.log_level
    cfg.validate()

    # Scope validation
    ids: List[str] = []
    if args.ids:
        ids.extend([x.strip() for x in args.ids.split(",") if x.strip()])
    if args.ids_file:
        p = Path(args.ids_file)
        _require(p.exists(), f"IDs file not found: {p}")
        ids.extend([line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()])

    # Must have at least one scope limiter
    _require(any([args.tenant-id if False else args.tenant_id, args.case_id, ids, args.older_than]),
             "At least one scope filter is required: --tenant-id, --case-id, --ids/--ids-file, or --older-than")

    # two-person rule check (if required and not dry-run)
    if cfg.require_two_person_rule and not args.dry_run and args.confirm == "yes":
        _require(bool(args.ticket), "--ticket is required")
        _require(bool(args.reason), "--reason is required")
        _require(bool(args.approver1) and bool(args.approver2), "--approver1 and --approver2 are required")
        _require(args.approver1 != args.approver2, "--approver1 and --approver2 must differ")

    operator = os.getenv("OPERATOR_ID", os.getenv("USER", "unknown"))

    # BigQuery facade
    vault = VaultBigQuery(cfg, log)

    # Preview scope
    before_count, sample_rows = vault.preview_scope(
        tenant_id=args.tenant_id, case_id=args.case_id, id_list=ids or None, older_than=args.older_than
    )
    log.info("Scope preview", extra={"count": before_count})

    if args.report_csv:
        write_report_csv(Path(args.report_csv), sample_rows, log)

    # Safety limit check
    if not args.force_large and before_count > cfg.default_limit:
        log.error("Scope exceeds safety limit", extra={"count": before_count, "limit": cfg.default_limit})
        log.error("Use --force-large or lower the scope")
        return 2

    if args.dry_run or args.confirm != "yes":
        # Dry-run summary and JSON report
        payload = {
            "mode": "dry-run" if args.dry_run or args.confirm != "yes" else "execute",
            "ts": _utcnow_iso(),
            "project": cfg.project_id,
            "dataset": cfg.dataset,
            "table": cfg.table,
            "scope": {
                "tenant_id": args.tenant_id,
                "case_id": args.case_id,
                "ids_count": len(ids),
                "older_than": args.older_than,
            },
            "preview_count": before_count,
            "limit": cfg.default_limit,
        }
        if args.report_json:
            write_report_json(Path(args.report_json), payload, log)
        log.info("Dry-run: no changes applied. Re-run with --confirm yes to execute.")
        vault.close()
        return 0

    # Execute release
    # We recompute affected IDs for evidence/report by sampling IDs only (if too large, we keep up to 100k in memory)
    affected_ids: List[str] = []
    try:
        # Efficient collection: we can re-query ids; here reusing sample approach with higher LIMIT
        table_id = f"`{cfg.project_id}.{cfg.dataset}.{cfg.table}`"
        where = ["legal_hold = TRUE"]
        params: Dict[str, Any] = {}
        if args.tenant_id:
            where.append("tenant_id = @tenant_id"); params["tenant_id"] = args.tenant_id
        if args.case_id:
            where.append("case_id = @case_id"); params["case_id"] = args.case_id
        if ids:
            where.append("id IN UNNEST(SPLIT(@id_list))"); params["id_list"] = ",".join(sorted(set(ids)))
        if args.older_than:
            where.append("legal_hold_set_at < @older_than"); params["older_than"] = args.older_than
        where_sql = " AND ".join(where)

        # Fetch up to 100k IDs for evidence/report; avoid huge memory for very large scopes
        fetch_sql = f"SELECT id FROM {table_id} WHERE {where_sql} LIMIT 100000"
        with _maybe_span("lh.fetch_ids"):
            affected_rows = vault._bq.query(fetch_sql, params=params)  # using adapter directly
        affected_ids = [r["id"] for r in affected_rows]
    except Exception as e:
        log.warning("Failed to prefetch affected IDs (continuing): %s", e)

    # Perform update
    _ = vault.release_hold(
        tenant_id=args.tenant_id,
        case_id=args.case_id,
        id_list=ids or None,
        older_than=args.older_than,
        ticket=args.ticket or "",
        reason=args.reason or "",
        approver1=args.approver1 or "",
        approver2=args.approver2 or "",
        operator=operator,
    )

    # Post-state check
    after_count, _ = vault.preview_scope(
        tenant_id=args.tenant_id, case_id=args.case_id, id_list=ids or None, older_than=args.older_than
    )
    updated = before_count - after_count
    log.info("Legal Hold released", extra={"updated": updated, "remaining_holds": after_count})

    # Report JSON
    exec_payload = {
        "mode": "execute",
        "ts": _utcnow_iso(),
        "project": cfg.project_id,
        "dataset": cfg.dataset,
        "table": cfg.table,
        "scope": {
            "tenant_id": args.tenant_id,
            "case_id": args.case_id,
            "ids_count": len(ids),
            "older_than": args.older_than,
        },
        "updated": updated,
        "remaining_holds": after_count,
        "ticket": args.ticket,
        "reason": args.reason,
        "approver1": args.approver1,
        "approver2": args.approver2,
        "operator": operator,
        "affected_ids_sample": affected_ids[:1000],
    }
    if args.report_json:
        write_report_json(Path(args.report_json), exec_payload, log)

    # Audit trail
    trail = _maybe_init_audit(cfg, log)
    try:
        if trail:
            event = AuditEvent(
                action="legal_hold.release",
                subject={"type": "dataset", "id": f"{cfg.project_id}.{cfg.dataset}.{cfg.table}"},
                actor={"type": "cli", "id": operator, "roles": ["operator"]},
                resource={"type": "legal_hold_scope", "id": args.case_id or args.tenant_id or "ad-hoc"},
                outcome="SUCCESS",
                severity="INFO",
                labels={"module": "legal_hold", "ticket": args.ticket or ""},
                data={
                    "scope": exec_payload["scope"],
                    "updated": updated,
                    "remaining_holds": after_count,
                    "approver1": args.approver1,
                    "approver2": args.approver2,
                }
            )
            trail.log_event(event)
            trail.flush()
    finally:
        if trail:
            trail.close()

    # Evidence bundle (optional)
    if cfg.enable_evidence and not args.no_evidence:
        evidence_info = maybe_build_evidence(
            enable=True,
            case_id=args.case_id or "global",
            scope=exec_payload["scope"],
            affected_ids=affected_ids,
            evidence_dir=cfg.evidence_base_dir,
            log=log
        )
        if evidence_info:
            log.info("Evidence bundle created", extra=evidence_info)

    vault.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit as e:
        raise
    except Exception as e:
        logging.basicConfig(level=logging.ERROR, format="%(asctime)s %(levelname)s %(message)s")
        logging.exception("Unhandled error: %s", e)
        sys.exit(1)
