# human-sovereignty-core/audit/replay_detector.py
from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


_TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _utc_now_z() -> str:
    return _utc_now().replace(microsecond=0).strftime(_TIME_FMT)


def _dt_to_iso_z(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.timezone.utc).replace(microsecond=0).strftime(_TIME_FMT)


def _iso_z_to_dt(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, _TIME_FMT).replace(tzinfo=_dt.timezone.utc)


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _normalize_text(s: str) -> str:
    return " ".join(s.strip().split())


@dataclass(frozen=True)
class ReplayPolicy:
    """
    Replay detection policy.

    ttl_seconds:
      How long a replay key is retained before being eligible for purge.
      Must be > 0.

    strict_clock:
      If True, rejects events with created_utc far in the future beyond clock_skew_seconds.

    clock_skew_seconds:
      Allowed future skew if strict_clock is enabled.

    db_busy_timeout_ms:
      SQLite busy timeout.
    """
    ttl_seconds: int = 7 * 24 * 60 * 60  # 7 days
    strict_clock: bool = True
    clock_skew_seconds: int = 120
    db_busy_timeout_ms: int = 5000
    max_metadata_bytes: int = 16 * 1024


@dataclass(frozen=True)
class ReplayEvent:
    """
    Generic event that should be protected from replay.

    kind:
      Category, e.g. "decision_packet", "approval", "audit_record".

    event_id:
      Stable external ID if present (e.g., decision packet id).

    created_utc:
      ISO-8601 in UTC with 'Z', e.g. 2026-01-27T12:00:00Z

    payload_sha256:
      Optional content hash binding, recommended for packets/approvals.

    nonce:
      Optional nonce/unique token if present in protocol.
    """
    kind: str
    event_id: str
    created_utc: str
    payload_sha256: Optional[str] = None
    nonce: Optional[str] = None
    actor_id: Optional[str] = None
    anchor_id: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class ReplayDecision:
    ok: bool
    status: str  # ACCEPTED | REPLAYED | REJECTED
    replay_key: str
    first_seen_utc: Optional[str]
    last_seen_utc: Optional[str]
    seen_count: int
    reason: Optional[str]
    details: Dict[str, Any]


class ReplayDetectorError(Exception):
    pass


class ReplayRejected(ReplayDetectorError):
    pass


class ReplayDetector:
    """
    Persistent replay detector backed by SQLite.

    Guarantees:
    - Atomic accept/replay decision via UNIQUE(replay_key).
    - Survives process restarts.
    - Thread-safe within a single process (connection per call).
    """

    def __init__(self, db_path: Path, policy: Optional[ReplayPolicy] = None):
        self._db_path = Path(db_path).expanduser().resolve()
        self._policy = policy or ReplayPolicy()
        if self._policy.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._lock = threading.Lock()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def policy(self) -> ReplayPolicy:
        return self._policy

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(
            str(self._db_path),
            timeout=max(1.0, self._policy.db_busy_timeout_ms / 1000.0),
            isolation_level=None,  # autocommit, manage transactions manually
            check_same_thread=False,
        )
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        con.execute(f"PRAGMA busy_timeout={int(self._policy.db_busy_timeout_ms)};")
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_keys (
                  replay_key TEXT PRIMARY KEY,
                  kind TEXT NOT NULL,
                  event_id TEXT NOT NULL,
                  payload_sha256 TEXT,
                  nonce TEXT,
                  actor_id TEXT,
                  anchor_id TEXT,
                  first_seen_utc TEXT NOT NULL,
                  last_seen_utc TEXT NOT NULL,
                  seen_count INTEGER NOT NULL,
                  expires_utc TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );
                """
            )
            con.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_replay_keys_expires
                ON replay_keys (expires_utc);
                """
            )
            con.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_replay_keys_kind_event
                ON replay_keys (kind, event_id);
                """
            )

    def compute_replay_key(self, ev: ReplayEvent) -> str:
        """
        Deterministic replay key based on stable identifiers.

        Rules:
        - Always bind 'kind' and 'event_id'.
        - If payload_sha256 is present, bind it.
        - If nonce is present, bind it.
        - If actor_id / anchor_id are present, bind them (helps prevent cross-actor replays).

        Output: sha256 hex.
        """
        if not isinstance(ev.kind, str) or not ev.kind.strip():
            raise ValueError("event.kind must be non-empty string")
        if not isinstance(ev.event_id, str) or not ev.event_id.strip():
            raise ValueError("event.event_id must be non-empty string")
        if not isinstance(ev.created_utc, str) or not ev.created_utc.strip():
            raise ValueError("event.created_utc must be non-empty string")

        base = {
            "kind": _normalize_text(ev.kind),
            "event_id": _normalize_text(ev.event_id),
            "payload_sha256": _normalize_text(ev.payload_sha256) if isinstance(ev.payload_sha256, str) and ev.payload_sha256 else None,
            "nonce": _normalize_text(ev.nonce) if isinstance(ev.nonce, str) and ev.nonce else None,
            "actor_id": _normalize_text(ev.actor_id) if isinstance(ev.actor_id, str) and ev.actor_id else None,
            "anchor_id": _normalize_text(ev.anchor_id) if isinstance(ev.anchor_id, str) and ev.anchor_id else None,
        }
        return _sha256_hex(_canonical_json_bytes(base))

    def _validate_clock(self, ev: ReplayEvent) -> None:
        if not self._policy.strict_clock:
            return
        try:
            created_dt = _iso_z_to_dt(ev.created_utc)
        except Exception as e:
            raise ReplayRejected(f"Invalid created_utc format: {e!r}")
        now = _utc_now()
        if created_dt > now + _dt.timedelta(seconds=int(self._policy.clock_skew_seconds)):
            raise ReplayRejected("created_utc is too far in the future")

    def check_and_record(self, ev: ReplayEvent) -> ReplayDecision:
        """
        Atomically checks if the event is a replay and records it.

        Returns:
        - ACCEPTED if first time.
        - REPLAYED if replay_key already exists and is not expired.
        - REJECTED if event is invalid per policy.
        """
        try:
            self._validate_clock(ev)
        except ReplayRejected as e:
            rk = "0" * 64
            try:
                rk = self.compute_replay_key(ev)
            except Exception:
                pass
            return ReplayDecision(
                ok=False,
                status="REJECTED",
                replay_key=rk,
                first_seen_utc=None,
                last_seen_utc=None,
                seen_count=0,
                reason=str(e),
                details={"kind": ev.kind, "event_id": ev.event_id},
            )

        replay_key = self.compute_replay_key(ev)

        # Metadata size guard
        metadata = ev.metadata if isinstance(ev.metadata, dict) else {}
        meta_json = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        if len(meta_json.encode("utf-8", errors="replace")) > self._policy.max_metadata_bytes:
            meta_json = json.dumps({"note": "metadata_truncated"}, ensure_ascii=False, sort_keys=True)

        now_utc = _utc_now_z()
        expires_dt = _utc_now() + _dt.timedelta(seconds=int(self._policy.ttl_seconds))
        expires_utc = _dt_to_iso_z(expires_dt)

        # Insert-or-update with strict replay decision
        with self._lock:
            with self._connect() as con:
                con.execute("BEGIN IMMEDIATE;")
                try:
                    row = con.execute(
                        "SELECT first_seen_utc, last_seen_utc, seen_count, expires_utc FROM replay_keys WHERE replay_key=?",
                        (replay_key,),
                    ).fetchone()

                    if row is None:
                        con.execute(
                            """
                            INSERT INTO replay_keys (
                              replay_key, kind, event_id, payload_sha256, nonce, actor_id, anchor_id,
                              first_seen_utc, last_seen_utc, seen_count, expires_utc, metadata_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                replay_key,
                                _normalize_text(ev.kind),
                                _normalize_text(ev.event_id),
                                _normalize_text(ev.payload_sha256) if isinstance(ev.payload_sha256, str) and ev.payload_sha256 else None,
                                _normalize_text(ev.nonce) if isinstance(ev.nonce, str) and ev.nonce else None,
                                _normalize_text(ev.actor_id) if isinstance(ev.actor_id, str) and ev.actor_id else None,
                                _normalize_text(ev.anchor_id) if isinstance(ev.anchor_id, str) and ev.anchor_id else None,
                                now_utc,
                                now_utc,
                                1,
                                expires_utc,
                                meta_json,
                            ),
                        )
                        con.execute("COMMIT;")
                        return ReplayDecision(
                            ok=True,
                            status="ACCEPTED",
                            replay_key=replay_key,
                            first_seen_utc=now_utc,
                            last_seen_utc=now_utc,
                            seen_count=1,
                            reason=None,
                            details={"expires_utc": expires_utc},
                        )

                    first_seen_utc, last_seen_utc, seen_count, row_expires_utc = row

                    # If expired, treat as new acceptance by overwriting the record atomically.
                    try:
                        expired = _iso_z_to_dt(str(row_expires_utc)) <= _utc_now()
                    except Exception:
                        expired = False

                    if expired:
                        con.execute(
                            """
                            UPDATE replay_keys
                            SET kind=?,
                                event_id=?,
                                payload_sha256=?,
                                nonce=?,
                                actor_id=?,
                                anchor_id=?,
                                first_seen_utc=?,
                                last_seen_utc=?,
                                seen_count=?,
                                expires_utc=?,
                                metadata_json=?
                            WHERE replay_key=?
                            """,
                            (
                                _normalize_text(ev.kind),
                                _normalize_text(ev.event_id),
                                _normalize_text(ev.payload_sha256) if isinstance(ev.payload_sha256, str) and ev.payload_sha256 else None,
                                _normalize_text(ev.nonce) if isinstance(ev.nonce, str) and ev.nonce else None,
                                _normalize_text(ev.actor_id) if isinstance(ev.actor_id, str) and ev.actor_id else None,
                                _normalize_text(ev.anchor_id) if isinstance(ev.anchor_id, str) and ev.anchor_id else None,
                                now_utc,
                                now_utc,
                                1,
                                expires_utc,
                                meta_json,
                                replay_key,
                            ),
                        )
                        con.execute("COMMIT;")
                        return ReplayDecision(
                            ok=True,
                            status="ACCEPTED",
                            replay_key=replay_key,
                            first_seen_utc=now_utc,
                            last_seen_utc=now_utc,
                            seen_count=1,
                            reason=None,
                            details={"note": "previous_record_expired_replaced", "expires_utc": expires_utc},
                        )

                    # Not expired: replay
                    new_count = int(seen_count) + 1
                    con.execute(
                        """
                        UPDATE replay_keys
                        SET last_seen_utc=?,
                            seen_count=?
                        WHERE replay_key=?
                        """,
                        (now_utc, new_count, replay_key),
                    )
                    con.execute("COMMIT;")
                    return ReplayDecision(
                        ok=False,
                        status="REPLAYED",
                        replay_key=replay_key,
                        first_seen_utc=str(first_seen_utc),
                        last_seen_utc=now_utc,
                        seen_count=new_count,
                        reason="replay_detected",
                        details={"expires_utc": str(row_expires_utc)},
                    )

                except Exception:
                    with contextlib.suppress(Exception):
                        con.execute("ROLLBACK;")
                    raise

    def lookup(self, replay_key: str) -> Optional[Dict[str, Any]]:
        if not isinstance(replay_key, str) or not replay_key.strip():
            return None
        with self._connect() as con:
            row = con.execute(
                """
                SELECT replay_key, kind, event_id, payload_sha256, nonce, actor_id, anchor_id,
                       first_seen_utc, last_seen_utc, seen_count, expires_utc, metadata_json
                FROM replay_keys
                WHERE replay_key=?
                """,
                (replay_key,),
            ).fetchone()
            if row is None:
                return None
            (
                rk, kind, event_id, payload_sha256, nonce, actor_id, anchor_id,
                first_seen_utc, last_seen_utc, seen_count, expires_utc, metadata_json
            ) = row
            try:
                meta = json.loads(metadata_json) if isinstance(metadata_json, str) else {}
            except Exception:
                meta = {}
            return {
                "replay_key": rk,
                "kind": kind,
                "event_id": event_id,
                "payload_sha256": payload_sha256,
                "nonce": nonce,
                "actor_id": actor_id,
                "anchor_id": anchor_id,
                "first_seen_utc": first_seen_utc,
                "last_seen_utc": last_seen_utc,
                "seen_count": int(seen_count),
                "expires_utc": expires_utc,
                "metadata": meta,
            }

    def prune_expired(self, limit: int = 5000) -> Dict[str, Any]:
        """
        Deletes expired records (best-effort bounded by limit).
        Returns pruning stats.
        """
        if limit <= 0:
            limit = 1
        now_utc = _utc_now_z()
        with self._lock:
            with self._connect() as con:
                con.execute("BEGIN IMMEDIATE;")
                try:
                    # SQLite does not allow LIMIT in DELETE in older versions reliably with parameters;
                    # use rowid selection.
                    rows = con.execute(
                        """
                        SELECT rowid
                        FROM replay_keys
                        WHERE expires_utc <= ?
                        ORDER BY expires_utc ASC
                        LIMIT ?
                        """,
                        (now_utc, int(limit)),
                    ).fetchall()
                    rowids = [r[0] for r in rows] if rows else []
                    deleted = 0
                    if rowids:
                        # Build placeholders safely
                        placeholders = ",".join(["?"] * len(rowids))
                        con.execute(f"DELETE FROM replay_keys WHERE rowid IN ({placeholders})", tuple(rowids))
                        deleted = len(rowids)
                    con.execute("COMMIT;")
                    return {"deleted": deleted, "now_utc": now_utc, "limit": int(limit)}
                except Exception:
                    with contextlib.suppress(Exception):
                        con.execute("ROLLBACK;")
                    raise

    def stats(self) -> Dict[str, Any]:
        with self._connect() as con:
            total = con.execute("SELECT COUNT(*) FROM replay_keys").fetchone()[0]
            now_utc = _utc_now_z()
            expired = con.execute("SELECT COUNT(*) FROM replay_keys WHERE expires_utc <= ?", (now_utc,)).fetchone()[0]
            return {
                "db_path": str(self._db_path),
                "total": int(total),
                "expired": int(expired),
                "now_utc": now_utc,
                "policy": dataclasses.asdict(self._policy),
            }


def _parse_event_json(path: Path) -> ReplayEvent:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("event JSON must be an object")
    return ReplayEvent(
        kind=str(raw.get("kind", "")),
        event_id=str(raw.get("event_id", "")),
        created_utc=str(raw.get("created_utc", "")),
        payload_sha256=raw.get("payload_sha256"),
        nonce=raw.get("nonce"),
        actor_id=raw.get("actor_id"),
        anchor_id=raw.get("anchor_id"),
        metadata=raw.get("metadata", {}) if isinstance(raw.get("metadata", {}), dict) else {},
    )


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="replay_detector", add_help=True)
    p.add_argument("--db", required=True, help="Path to sqlite db file")
    p.add_argument("--event", required=True, help="Path to event JSON file")
    p.add_argument("--json", action="store_true", help="Print JSON decision")
    p.add_argument("--prune", action="store_true", help="Prune expired records after decision")
    p.add_argument("--ttl", type=int, default=0, help="Override TTL seconds (optional)")
    args = p.parse_args(argv)

    policy = ReplayPolicy()
    if args.ttl and args.ttl > 0:
        policy = dataclasses.replace(policy, ttl_seconds=int(args.ttl))

    detector = ReplayDetector(Path(args.db), policy=policy)
    ev = _parse_event_json(Path(args.event))

    decision = detector.check_and_record(ev)

    out = dataclasses.asdict(decision)
    if args.prune:
        out["prune"] = detector.prune_expired()
    out["stats"] = detector.stats()

    print(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) if args.json else json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2))

    if decision.status == "ACCEPTED":
        return 0
    if decision.status == "REPLAYED":
        return 10
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
