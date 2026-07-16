# human-sovereignty-core/audit/tamper_alarm.py
#
# Industrial-grade tamper alarm for audit hash chains.
#
# Purpose:
# - Verify integrity of an append-only audit log hash chain
# - Detect tampering: hash mismatches, broken prev links, reordering, duplicates, malformed records
# - Emit alarm events to configured sinks (no network calls)
#
# Non-goals:
# - No persistence policy decisions
# - No external dependencies
# - No claims about cryptographic “impossibility”; only deterministic checks
#
# This module asserts no external facts; it implements integrity verification logic only.

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple


class AuditTamperError(RuntimeError):
    pass


class AuditRecordError(ValueError):
    pass


@dataclass(frozen=True)
class AuditRecord:
    """
    Canonical audit record for hash-chain verification.

    Required fields:
      - id: unique record id (string)
      - ts: unix timestamp seconds (int)
      - type: event type (string)
      - payload: dict payload (object)
      - prev_hash: hex string or "" for genesis
      - hash: hex string, computed over canonical fields (see compute_record_hash)

    Optional fields:
      - seq: monotonic sequence (int) if present is validated (non-decreasing)
      - meta: dict (object)
      - sig: optional HMAC signature hex over canonical hash input (see compute_record_sig)
    """

    id: str
    ts: int
    type: str
    payload: Dict[str, Any]
    prev_hash: str
    hash: str

    seq: Optional[int] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    sig: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "ts": self.ts,
            "type": self.type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }
        if self.seq is not None:
            d["seq"] = self.seq
        if self.meta:
            d["meta"] = self.meta
        if self.sig is not None:
            d["sig"] = self.sig
        return d


@dataclass(frozen=True)
class TamperFinding:
    severity: str  # INFO | WARN | FAIL
    code: str
    message: str
    record_id: Optional[str] = None
    index: Optional[int] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "record_id": self.record_id,
            "index": self.index,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class TamperReport:
    ok: bool
    checked_at_utc: int
    chain_id: str
    total_records: int
    findings: Tuple[TamperFinding, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "checked_at_utc": self.checked_at_utc,
            "chain_id": self.chain_id,
            "total_records": self.total_records,
            "findings": [f.as_dict() for f in self.findings],
        }


class AlarmSink(Protocol):
    def emit(self, report: TamperReport) -> None:
        ...


class StdoutAlarmSink:
    """
    Minimal local sink (no special chars).
    """

    def emit(self, report: TamperReport) -> None:
        print(json.dumps(report.as_dict(), ensure_ascii=False, sort_keys=True))


class FileAlarmSink:
    """
    Appends alarm reports to a local file path.
    """

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path.strip():
            raise ValueError("path must be non-empty string")
        self._path = path

    def emit(self, report: TamperReport) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        line = json.dumps(report.as_dict(), ensure_ascii=False, sort_keys=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


@dataclass(frozen=True)
class TamperPolicy:
    """
    Verification policy. All checks are deterministic.

    - require_monotonic_ts: timestamps must be non-decreasing
    - max_future_skew_seconds: flag timestamps too far in the future (local check)
    - require_unique_ids: record ids must be unique
    - require_prev_link: prev_hash must match previous record hash (except genesis)
    - require_hash_match: record.hash must match recomputed hash
    - require_sig_match: if provided secret_key and record.sig present, verify it
    - fail_on_warn: treat WARN as failure gate
    - allow_genesis_prev_hash_empty: allow first prev_hash to be empty string
    """

    require_monotonic_ts: bool = True
    max_future_skew_seconds: int = 300
    require_unique_ids: bool = True

    require_prev_link: bool = True
    require_hash_match: bool = True

    secret_key: Optional[bytes] = None
    require_sig_match: bool = False

    require_monotonic_seq_if_present: bool = True
    fail_on_warn: bool = False
    allow_genesis_prev_hash_empty: bool = True


def _now_utc() -> int:
    return int(time.time())


def _is_hex(s: str, min_len: int = 0, max_len: int = 128) -> bool:
    if not isinstance(s, str):
        return False
    ss = s.strip().lower()
    if len(ss) < min_len or len(ss) > max_len:
        return False
    if ss == "":
        return min_len == 0
    for ch in ss:
        if ch not in "0123456789abcdef":
            return False
    return True


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_record_hash(
    *,
    record_id: str,
    ts: int,
    event_type: str,
    payload: Mapping[str, Any],
    prev_hash: str,
    seq: Optional[int] = None,
    meta: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    Compute deterministic record hash over canonical fields.

    The exact structure is versioned implicitly by this function.
    Extend by adding fields only in a backward-compatible way.
    """
    if not isinstance(record_id, str) or not record_id.strip():
        raise AuditRecordError("record_id must be non-empty string")
    if not isinstance(event_type, str) or not event_type.strip():
        raise AuditRecordError("event_type must be non-empty string")
    if not isinstance(ts, int):
        raise AuditRecordError("ts must be int")
    if not isinstance(payload, Mapping):
        raise AuditRecordError("payload must be mapping/object")
    if not isinstance(prev_hash, str):
        raise AuditRecordError("prev_hash must be string")
    if meta is not None and not isinstance(meta, Mapping):
        raise AuditRecordError("meta must be mapping/object")

    canonical: Dict[str, Any] = {
        "v": 1,
        "id": record_id.strip(),
        "ts": ts,
        "type": event_type.strip(),
        "prev": prev_hash.strip().lower(),
        "payload": payload,
    }
    if seq is not None:
        if not isinstance(seq, int):
            raise AuditRecordError("seq must be int if provided")
        canonical["seq"] = seq
    if meta is not None and dict(meta):
        canonical["meta"] = dict(meta)

    return _sha256_hex(_canonical_json(canonical))


def compute_record_sig(
    *,
    secret_key: bytes,
    record_id: str,
    ts: int,
    event_type: str,
    payload: Mapping[str, Any],
    prev_hash: str,
    seq: Optional[int] = None,
    meta: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    Compute HMAC-SHA256 signature hex over the same canonical structure as hash input.
    """
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 16:
        raise AuditRecordError("secret_key must be bytes and at least 16 bytes")
    canonical_hash = compute_record_hash(
        record_id=record_id,
        ts=ts,
        event_type=event_type,
        payload=payload,
        prev_hash=prev_hash,
        seq=seq,
        meta=meta,
    )
    mac = hmac.new(bytes(secret_key), canonical_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return mac


def _parse_record(raw: Mapping[str, Any]) -> AuditRecord:
    if not isinstance(raw, Mapping):
        raise AuditRecordError("record must be object")

    def req_str(k: str) -> str:
        v = raw.get(k)
        if not isinstance(v, str) or not v.strip():
            raise AuditRecordError(f"{k} must be non-empty string")
        return v.strip()

    rid = req_str("id")
    et = req_str("type")

    ts = raw.get("ts")
    if not isinstance(ts, int):
        raise AuditRecordError("ts must be int")

    payload = raw.get("payload")
    if not isinstance(payload, dict):
        raise AuditRecordError("payload must be object")

    prev_hash = raw.get("prev_hash")
    if not isinstance(prev_hash, str):
        raise AuditRecordError("prev_hash must be string")

    hval = raw.get("hash")
    if not isinstance(hval, str) or not hval.strip():
        raise AuditRecordError("hash must be non-empty string")

    seq = raw.get("seq")
    if seq is not None and not isinstance(seq, int):
        raise AuditRecordError("seq must be int if provided")

    meta = raw.get("meta") or {}
    if not isinstance(meta, dict):
        raise AuditRecordError("meta must be object if provided")

    sig = raw.get("sig")
    if sig is not None and (not isinstance(sig, str) or not sig.strip()):
        raise AuditRecordError("sig must be non-empty string if provided")

    return AuditRecord(
        id=rid,
        ts=ts,
        type=et,
        payload=payload,
        prev_hash=prev_hash.strip(),
        hash=hval.strip().lower(),
        seq=seq,
        meta=meta,
        sig=sig.strip().lower() if isinstance(sig, str) else None,
    )


def _worst_ok(findings: Sequence[TamperFinding], *, fail_on_warn: bool) -> bool:
    has_fail = any(f.severity == "FAIL" for f in findings)
    if has_fail:
        return False
    if fail_on_warn and any(f.severity == "WARN" for f in findings):
        return False
    return True


class TamperAlarm:
    """
    Main tamper alarm.
    """

    def __init__(self, *, policy: Optional[TamperPolicy] = None, sinks: Optional[Sequence[AlarmSink]] = None) -> None:
        self._policy = policy or TamperPolicy()
        self._sinks: Tuple[AlarmSink, ...] = tuple(sinks or ())

        if self._policy.require_sig_match and self._policy.secret_key is None:
            raise ValueError("require_sig_match=True requires secret_key")

        if self._policy.secret_key is not None and (
            not isinstance(self._policy.secret_key, (bytes, bytearray)) or len(self._policy.secret_key) < 16
        ):
            raise ValueError("secret_key must be bytes and at least 16 bytes")

    def verify_chain(
        self,
        records: Iterable[Mapping[str, Any]],
        *,
        chain_id: str = "default",
        emit_on_any: bool = False,
    ) -> TamperReport:
        """
        Verifies chain integrity.

        emit_on_any:
          - False: emit only when not ok (or warn treated as fail)
          - True: always emit
        """
        findings: List[TamperFinding] = []
        parsed: List[AuditRecord] = []

        seen_ids: set[str] = set()

        # Parse and validate shape
        idx = -1
        for idx, raw in enumerate(records):
            try:
                rec = _parse_record(raw)
                parsed.append(rec)
            except Exception as e:
                findings.append(
                    TamperFinding(
                        severity="FAIL",
                        code="record.malformed",
                        message="Record is malformed and cannot be parsed",
                        record_id=None,
                        index=idx,
                        evidence={"error": str(e), "raw_preview": _safe_preview(raw)},
                    )
                )

        if not parsed and idx >= 0:
            # Only malformed records
            report = TamperReport(
                ok=_worst_ok(findings, fail_on_warn=self._policy.fail_on_warn),
                checked_at_utc=_now_utc(),
                chain_id=chain_id,
                total_records=0,
                findings=tuple(findings),
            )
            self._maybe_emit(report, emit_on_any=emit_on_any)
            return report

        # Content checks
        prev_hash_expected: Optional[str] = None
        last_ts: Optional[int] = None
        last_seq: Optional[int] = None

        now = _now_utc()

        for i, rec in enumerate(parsed):
            # Unique IDs
            if self._policy.require_unique_ids:
                if rec.id in seen_ids:
                    findings.append(
                        TamperFinding(
                            severity="FAIL",
                            code="record.duplicate_id",
                            message="Duplicate record id detected",
                            record_id=rec.id,
                            index=i,
                            evidence={"id": rec.id},
                        )
                    )
                else:
                    seen_ids.add(rec.id)

            # Timestamp monotonic
            if self._policy.require_monotonic_ts:
                if last_ts is not None and rec.ts < last_ts:
                    findings.append(
                        TamperFinding(
                            severity="FAIL",
                            code="chain.ts.non_monotonic",
                            message="Timestamp decreased compared to previous record",
                            record_id=rec.id,
                            index=i,
                            evidence={"prev_ts": last_ts, "ts": rec.ts},
                        )
                    )
                last_ts = rec.ts

            # Future skew flag
            if self._policy.max_future_skew_seconds >= 0:
                if rec.ts > now + int(self._policy.max_future_skew_seconds):
                    findings.append(
                        TamperFinding(
                            severity="WARN",
                            code="record.ts.future_skew",
                            message="Record timestamp is far in the future relative to local clock",
                            record_id=rec.id,
                            index=i,
                            evidence={"ts": rec.ts, "now": now, "max_future_skew_seconds": self._policy.max_future_skew_seconds},
                        )
                    )

            # Sequence monotonic if present
            if self._policy.require_monotonic_seq_if_present and rec.seq is not None:
                if last_seq is not None and rec.seq < last_seq:
                    findings.append(
                        TamperFinding(
                            severity="FAIL",
                            code="chain.seq.non_monotonic",
                            message="Sequence decreased compared to previous record",
                            record_id=rec.id,
                            index=i,
                            evidence={"prev_seq": last_seq, "seq": rec.seq},
                        )
                    )
                last_seq = rec.seq if last_seq is None or rec.seq >= last_seq else last_seq

            # Hash format sanity
            if not _is_hex(rec.hash, min_len=64, max_len=64):
                findings.append(
                    TamperFinding(
                        severity="FAIL",
                        code="record.hash.invalid_format",
                        message="Record hash is not a valid sha256 hex digest",
                        record_id=rec.id,
                        index=i,
                        evidence={"hash": rec.hash},
                    )
                )

            if not _is_hex(rec.prev_hash, min_len=0, max_len=64):
                findings.append(
                    TamperFinding(
                        severity="FAIL",
                        code="record.prev_hash.invalid_format",
                        message="Record prev_hash has invalid format",
                        record_id=rec.id,
                        index=i,
                        evidence={"prev_hash": rec.prev_hash},
                    )
                )

            # Prev link
            if self._policy.require_prev_link:
                if i == 0:
                    if prev_hash_expected is None:
                        # Genesis expected prev hash = "" by default
                        if self._policy.allow_genesis_prev_hash_empty:
                            if rec.prev_hash.strip() != "":
                                findings.append(
                                    TamperFinding(
                                        severity="FAIL",
                                        code="chain.genesis.prev_hash_not_empty",
                                        message="Genesis record prev_hash must be empty",
                                        record_id=rec.id,
                                        index=i,
                                        evidence={"prev_hash": rec.prev_hash},
                                    )
                                )
                        else:
                            # If not allowed, it must still be well-formed; cannot derive expected here.
                            findings.append(
                                TamperFinding(
                                    severity="WARN",
                                    code="chain.genesis.prev_hash_unchecked",
                                    message="Genesis prev_hash not verified by policy setting",
                                    record_id=rec.id,
                                    index=i,
                                    evidence={"prev_hash": rec.prev_hash},
                                )
                            )
                else:
                    # expected must be previous record hash (even if previous record has issues, we can still compare)
                    prev_hash_expected = parsed[i - 1].hash
                    if rec.prev_hash.strip().lower() != (prev_hash_expected or "").strip().lower():
                        findings.append(
                            TamperFinding(
                                severity="FAIL",
                                code="chain.prev_link.mismatch",
                                message="prev_hash does not match previous record hash",
                                record_id=rec.id,
                                index=i,
                                evidence={
                                    "expected_prev_hash": prev_hash_expected,
                                    "actual_prev_hash": rec.prev_hash,
                                    "previous_record_id": parsed[i - 1].id,
                                },
                            )
                        )

            # Hash recompute
            if self._policy.require_hash_match:
                try:
                    recomputed = compute_record_hash(
                        record_id=rec.id,
                        ts=rec.ts,
                        event_type=rec.type,
                        payload=rec.payload,
                        prev_hash=rec.prev_hash,
                        seq=rec.seq,
                        meta=rec.meta,
                    )
                    if rec.hash.strip().lower() != recomputed.strip().lower():
                        findings.append(
                            TamperFinding(
                                severity="FAIL",
                                code="record.hash.mismatch",
                                message="Record hash does not match recomputed canonical hash",
                                record_id=rec.id,
                                index=i,
                                evidence={"expected_hash": recomputed, "actual_hash": rec.hash},
                            )
                        )
                except Exception as e:
                    findings.append(
                        TamperFinding(
                            severity="FAIL",
                            code="record.hash.recompute_error",
                            message="Failed to recompute record hash",
                            record_id=rec.id,
                            index=i,
                            evidence={"error": str(e)},
                        )
                    )

            # Signature check (optional)
            if self._policy.secret_key is not None and rec.sig is not None:
                if not _is_hex(rec.sig, min_len=64, max_len=64):
                    findings.append(
                        TamperFinding(
                            severity="FAIL",
                            code="record.sig.invalid_format",
                            message="Record signature is not valid hex digest",
                            record_id=rec.id,
                            index=i,
                            evidence={"sig": rec.sig},
                        )
                    )
                else:
                    try:
                        expected_sig = compute_record_sig(
                            secret_key=self._policy.secret_key,
                            record_id=rec.id,
                            ts=rec.ts,
                            event_type=rec.type,
                            payload=rec.payload,
                            prev_hash=rec.prev_hash,
                            seq=rec.seq,
                            meta=rec.meta,
                        )
                        if not hmac.compare_digest(rec.sig.lower(), expected_sig.lower()):
                            findings.append(
                                TamperFinding(
                                    severity="FAIL",
                                    code="record.sig.mismatch",
                                    message="Record signature does not match expected HMAC",
                                    record_id=rec.id,
                                    index=i,
                                    evidence={"expected_sig": expected_sig, "actual_sig": rec.sig},
                                )
                            )
                    except Exception as e:
                        findings.append(
                            TamperFinding(
                                severity="FAIL",
                                code="record.sig.verify_error",
                                message="Failed to verify record signature",
                                record_id=rec.id,
                                index=i,
                                evidence={"error": str(e)},
                            )
                        )
            elif self._policy.require_sig_match:
                findings.append(
                    TamperFinding(
                        severity="FAIL",
                        code="record.sig.required_missing",
                        message="Signature required by policy but record has no sig",
                        record_id=rec.id,
                        index=i,
                        evidence={},
                    )
                )

        ok = _worst_ok(findings, fail_on_warn=self._policy.fail_on_warn)

        report = TamperReport(
            ok=ok,
            checked_at_utc=_now_utc(),
            chain_id=chain_id,
            total_records=len(parsed),
            findings=tuple(findings),
        )

        self._maybe_emit(report, emit_on_any=emit_on_any)
        return report

    def raise_if_tampered(self, records: Iterable[Mapping[str, Any]], *, chain_id: str = "default") -> TamperReport:
        report = self.verify_chain(records, chain_id=chain_id, emit_on_any=False)
        if not report.ok:
            raise AuditTamperError("audit chain integrity check failed")
        return report

    def _maybe_emit(self, report: TamperReport, *, emit_on_any: bool) -> None:
        should_emit = emit_on_any or (not report.ok)
        if not should_emit:
            return
        for s in self._sinks:
            try:
                s.emit(report)
            except Exception:
                # Alarm emission must never crash the verifier.
                continue


def _safe_preview(obj: Any, max_len: int = 600) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        s = str(obj)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def records_from_jsonl(path: str, *, max_bytes: int = 8_000_000) -> List[Dict[str, Any]]:
    """
    Load records from JSONL file (one JSON object per line).
    Local file only, no network.

    max_bytes limits total file size read.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be non-empty string")
    st = os.stat(path)
    if st.st_size > max_bytes:
        raise ValueError("file too large")
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise ValueError(f"invalid json at line {line_no}: {e}") from e
            if not isinstance(obj, dict):
                raise ValueError(f"json object expected at line {line_no}")
            out.append(obj)
    return out


def build_record(
    *,
    record_id: str,
    ts: int,
    event_type: str,
    payload: Mapping[str, Any],
    prev_hash: str,
    seq: Optional[int] = None,
    meta: Optional[Mapping[str, Any]] = None,
    secret_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Helper to build a record dict with correct hash (and optional sig).

    This is deterministic and safe for local use.
    """
    hval = compute_record_hash(
        record_id=record_id,
        ts=ts,
        event_type=event_type,
        payload=payload,
        prev_hash=prev_hash,
        seq=seq,
        meta=meta,
    )
    rec: Dict[str, Any] = {
        "id": record_id,
        "ts": ts,
        "type": event_type,
        "payload": dict(payload),
        "prev_hash": prev_hash,
        "hash": hval,
    }
    if seq is not None:
        rec["seq"] = seq
    if meta is not None and dict(meta):
        rec["meta"] = dict(meta)
    if secret_key is not None:
        rec["sig"] = compute_record_sig(
            secret_key=secret_key,
            record_id=record_id,
            ts=ts,
            event_type=event_type,
            payload=payload,
            prev_hash=prev_hash,
            seq=seq,
            meta=meta,
        )
    return rec
