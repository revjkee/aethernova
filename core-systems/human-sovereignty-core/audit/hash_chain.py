# path: human-sovereignty-core/audit/hash_chain.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


class HashChainError(RuntimeError):
    pass


class ChainIntegrityError(HashChainError):
    pass


class ChainAppendError(HashChainError):
    pass


class ChainConfigError(HashChainError):
    pass


@dataclass(frozen=True)
class ChainConfig:
    chain_id: str = "human-sovereignty-audit-chain-v1"
    hash_algo: str = "sha256"
    fail_closed: bool = True
    max_payload_bytes: int = 512_000
    max_string_len: int = 32_768
    enforce_monotonic_seq: bool = True
    enforce_non_decreasing_time: bool = True
    enable_hmac: bool = False
    hmac_env_key: str = "HUMAN_SOVEREIGNTY_AUDIT_HMAC_SECRET"
    hmac_min_bytes: int = 32


@dataclass(frozen=True)
class HashChainRecord:
    record_id: str
    seq: int
    at_utc: str
    source: str
    event_type: str
    payload: Mapping[str, Any]
    prev_hash: str
    hash: str
    hmac_sig: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "seq": self.seq,
            "at_utc": self.at_utc,
            "source": self.source,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
            "hmac_sig": self.hmac_sig,
        }


@dataclass(frozen=True)
class ChainHead:
    seq: int
    hash: str
    at_utc: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked_records: int
    head: Optional[ChainHead]
    errors: Tuple[str, ...] = field(default_factory=tuple)


class HashChain:
    """
    Append-only audit hash chain.

    Properties:
    - Deterministic canonical hashing of records (payload included).
    - prev_hash linking prevents deletion and reordering without detection.
    - seq enforces ordering (optional strict monotonic).
    - Optional HMAC adds authenticity (not just integrity) if secret is stable.
    """

    def __init__(self, *, config: Optional[ChainConfig] = None, hmac_secret: Optional[bytes] = None) -> None:
        self._cfg = config or ChainConfig()
        self._lock = threading.RLock()
        self._records: List[HashChainRecord] = []

        if self._cfg.hash_algo.lower() not in ("sha256",):
            raise ChainConfigError("unsupported hash_algo")

        self._hmac_secret: Optional[bytes] = None
        if self._cfg.enable_hmac:
            self._hmac_secret = hmac_secret or _load_hmac_secret(self._cfg)

    @property
    def config(self) -> ChainConfig:
        return self._cfg

    def head(self) -> Optional[ChainHead]:
        with self._lock:
            if not self._records:
                return None
            r = self._records[-1]
            return ChainHead(seq=r.seq, hash=r.hash, at_utc=r.at_utc)

    def length(self) -> int:
        with self._lock:
            return len(self._records)

    def records(self) -> Tuple[HashChainRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def append(
        self,
        *,
        source: str,
        event_type: str,
        payload: Optional[Mapping[str, Any]] = None,
        at_utc: Optional[_dt.datetime] = None,
        record_id: Optional[str] = None,
    ) -> HashChainRecord:
        with self._lock:
            now = at_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            now_iso = _iso_utc(now)

            if not source or not str(source).strip():
                raise ChainAppendError("source is required")
            if not event_type or not str(event_type).strip():
                raise ChainAppendError("event_type is required")

            src = str(source).strip()
            et = str(event_type).strip()
            pl = dict(payload or {})

            pl_canon = _canonicalize(pl, max_string_len=self._cfg.max_string_len)

            pl_bytes = len(_json_dumps_canonical(pl_canon).encode("utf-8"))
            if pl_bytes > self._cfg.max_payload_bytes:
                raise ChainAppendError("payload too large")

            if self._records:
                prev = self._records[-1]
                prev_hash = prev.hash
                seq = prev.seq + 1
                if self._cfg.enforce_non_decreasing_time:
                    if now_iso < prev.at_utc:
                        raise ChainAppendError("non-decreasing time violated")
            else:
                prev_hash = _genesis_hash(self._cfg)
                seq = 1

            if self._cfg.enforce_monotonic_seq and self._records:
                if seq != (self._records[-1].seq + 1):
                    raise ChainAppendError("monotonic seq violated")

            rid = record_id or str(uuid.uuid4())

            record_body = {
                "chain_id": self._cfg.chain_id,
                "record_id": rid,
                "seq": seq,
                "at_utc": now_iso,
                "source": src,
                "event_type": et,
                "payload": pl_canon,
                "prev_hash": prev_hash,
            }
            rec_hash = _hash_record(self._cfg, record_body)
            sig = None
            if self._cfg.enable_hmac:
                sig = _hmac_sign(self._cfg, self._hmac_secret, record_body, rec_hash)

            rec = HashChainRecord(
                record_id=rid,
                seq=seq,
                at_utc=now_iso,
                source=src,
                event_type=et,
                payload=pl_canon,
                prev_hash=prev_hash,
                hash=rec_hash,
                hmac_sig=sig,
            )

            self._records.append(rec)
            return rec

    def export_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "chain_id": self._cfg.chain_id,
                "hash_algo": self._cfg.hash_algo,
                "enable_hmac": self._cfg.enable_hmac,
                "records": [r.to_dict() for r in self._records],
            }

    def export_json(self) -> str:
        return _json_dumps_canonical(self.export_dict())

    @classmethod
    def from_export(
        cls,
        data: Union[str, Mapping[str, Any]],
        *,
        config: Optional[ChainConfig] = None,
        hmac_secret: Optional[bytes] = None,
    ) -> "HashChain":
        cfg = config or ChainConfig()
        if isinstance(data, str):
            obj = json.loads(data)
        else:
            obj = dict(data)

        chain = cls(config=cfg, hmac_secret=hmac_secret)

        recs = obj.get("records", [])
        if not isinstance(recs, list):
            raise HashChainError("export format invalid: records must be list")

        with chain._lock:
            for item in recs:
                if not isinstance(item, dict):
                    raise HashChainError("export format invalid: record must be dict")
                chain._records.append(_record_from_dict(item))
        return chain

    def verify(self, *, strict: bool = True) -> VerifyResult:
        """
        Verifies internal chain integrity.

        strict=True:
        - enforce seq continuity
        - enforce time non-decreasing
        - if enable_hmac, require valid hmac_sig on every record

        If fail_closed, any unexpected exception yields ok=False.
        """
        with self._lock:
            try:
                errors: List[str] = []
                if not self._records:
                    return VerifyResult(ok=True, checked_records=0, head=None)

                prev_hash = _genesis_hash(self._cfg)
                prev_seq = 0
                prev_time = ""

                for idx, r in enumerate(self._records):
                    if strict and self._cfg.enforce_monotonic_seq:
                        if r.seq != prev_seq + 1:
                            errors.append(f"seq_violation_at_index_{idx}")
                    if r.prev_hash != prev_hash:
                        errors.append(f"prev_hash_mismatch_at_index_{idx}")

                    if strict and self._cfg.enforce_non_decreasing_time:
                        if prev_time and r.at_utc < prev_time:
                            errors.append(f"time_order_violation_at_index_{idx}")

                    record_body = {
                        "chain_id": self._cfg.chain_id,
                        "record_id": r.record_id,
                        "seq": r.seq,
                        "at_utc": r.at_utc,
                        "source": r.source,
                        "event_type": r.event_type,
                        "payload": _canonicalize(r.payload, max_string_len=self._cfg.max_string_len),
                        "prev_hash": r.prev_hash,
                    }
                    expected_hash = _hash_record(self._cfg, record_body)
                    if not _consteq(expected_hash, r.hash):
                        errors.append(f"hash_mismatch_at_index_{idx}")

                    if self._cfg.enable_hmac:
                        if strict and not r.hmac_sig:
                            errors.append(f"missing_hmac_at_index_{idx}")
                        if r.hmac_sig:
                            expected_sig = _hmac_sign(self._cfg, self._hmac_secret, record_body, expected_hash)
                            if not _consteq(expected_sig, r.hmac_sig):
                                errors.append(f"hmac_mismatch_at_index_{idx}")

                    prev_hash = r.hash
                    prev_seq = r.seq
                    prev_time = r.at_utc

                head = self.head()
                return VerifyResult(ok=len(errors) == 0, checked_records=len(self._records), head=head, errors=tuple(errors))

            except Exception as e:
                if self._cfg.fail_closed:
                    return VerifyResult(
                        ok=False,
                        checked_records=len(self._records),
                        head=self.head(),
                        errors=(f"verify_error:{e.__class__.__name__}",),
                    )
                raise

    def require_integrity(self, *, strict: bool = True) -> VerifyResult:
        res = self.verify(strict=strict)
        if not res.ok:
            raise ChainIntegrityError("; ".join(res.errors))
        return res


def _record_from_dict(d: Mapping[str, Any]) -> HashChainRecord:
    return HashChainRecord(
        record_id=str(d.get("record_id", "")),
        seq=int(d.get("seq", 0)),
        at_utc=str(d.get("at_utc", "")),
        source=str(d.get("source", "")),
        event_type=str(d.get("event_type", "")),
        payload=dict(d.get("payload", {})),
        prev_hash=str(d.get("prev_hash", "")),
        hash=str(d.get("hash", "")),
        hmac_sig=(str(d["hmac_sig"]) if d.get("hmac_sig") is not None else None),
    )


def _hash_record(cfg: ChainConfig, record_body: Mapping[str, Any]) -> str:
    payload = _json_dumps_canonical(_canonicalize(record_body, max_string_len=cfg.max_string_len))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _genesis_hash(cfg: ChainConfig) -> str:
    seed = {"chain_id": cfg.chain_id, "genesis": True, "hash_algo": cfg.hash_algo}
    return hashlib.sha256(_json_dumps_canonical(seed).encode("utf-8")).hexdigest()


def _hmac_sign(cfg: ChainConfig, secret: Optional[bytes], record_body: Mapping[str, Any], rec_hash: str) -> str:
    if not secret:
        raise ChainConfigError("hmac enabled but secret is missing")
    msg = _json_dumps_canonical(
        {
            "chain_id": cfg.chain_id,
            "record": _canonicalize(record_body, max_string_len=cfg.max_string_len),
            "hash": rec_hash,
        }
    ).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _load_hmac_secret(cfg: ChainConfig) -> bytes:
    raw = os.environ.get(cfg.hmac_env_key)
    if raw is None or not raw.strip():
        s = secrets.token_bytes(cfg.hmac_min_bytes)
        return s
    b = raw.encode("utf-8")
    if len(b) < cfg.hmac_min_bytes:
        raise ChainConfigError("hmac secret too short")
    return b


def _iso_utc(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        raise HashChainError("datetime must be timezone-aware")
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _json_dumps_canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonicalize(obj: Any, *, max_string_len: int) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        if len(obj) <= max_string_len:
            return obj
        return obj[:max_string_len] + "...(truncated)"
    if isinstance(obj, bytes):
        return {"__bytes_sha256__": hashlib.sha256(obj).hexdigest(), "len": len(obj)}
    if isinstance(obj, _dt.datetime):
        if obj.tzinfo is None:
            return {"__datetime__": "naive"}
        return {"__datetime__": _iso_utc(obj)}
    if dataclasses.is_dataclass(obj):
        return _canonicalize(dataclasses.asdict(obj), max_string_len=max_string_len)
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            out[str(k)] = _canonicalize(obj[k], max_string_len=max_string_len)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_canonicalize(x, max_string_len=max_string_len) for x in obj]
    return {"__repr__": repr(obj)[:max_string_len]}


def _consteq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(str(a), str(b))
    except Exception:
        return str(a) == str(b)
