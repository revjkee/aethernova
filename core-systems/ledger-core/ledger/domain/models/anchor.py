# ledger-core/ledger/domain/models/anchor.py
from __future__ import annotations

import binascii
import dataclasses as dc
import enum
import json
import time
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# -------------------------------
# Утилиты
# -------------------------------

def _utc_ms() -> int:
    return int(time.time() * 1000)

def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)

def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except Exception:
        return False

def _b16(s: str) -> bytes:
    s = s.removeprefix("0x").removeprefix("0X")
    if len(s) % 2 != 0:
        s = "0" + s
    try:
        return binascii.unhexlify(s.encode("ascii"))
    except binascii.Error as e:
        raise ValueError(f"invalid hex: {e}")

def _hex(b: bytes) -> str:
    return "0x" + binascii.hexlify(b).decode("ascii")

def _non_empty_str(x: Optional[str]) -> str:
    _require(bool(x), "value is required")
    assert x is not None
    return x

def _clamp_ge(n: int, min_value: int, name: str) -> int:
    _require(n >= min_value, f"{name} must be >= {min_value}")
    return n

# -------------------------------
# Типы/Enum
# -------------------------------

class AnchoringStatus(str, enum.Enum):
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    CONFIRMED = "CONFIRMED"
    FINALIZED = "FINALIZED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"

class SigningAlgorithm(str, enum.Enum):
    secp256k1 = "secp256k1"
    ed25519 = "ed25519"
    sr25519 = "sr25519"
    other = "other"

# -------------------------------
# Value Objects
# -------------------------------

@dc.dataclass(frozen=True)
class Sha256:
    value: bytes

    def __post_init__(self) -> None:
        _require(len(self.value) == 32, "Sha256 must be 32 bytes")

    @staticmethod
    def from_hex(s: str) -> "Sha256":
        b = _b16(_non_empty_str(s))
        _require(len(b) == 32, "Sha256 hex must decode to 32 bytes")
        return Sha256(b)

    def hex(self) -> string:
        return _hex(self.value)  # type: ignore[name-defined]

# Workaround for Python typing of 'string' above
string = str
Sha256.hex.__annotations__["return"] = string  # fix typing

@dc.dataclass(frozen=True)
class TxHash:
    value: bytes

    def __post_init__(self) -> None:
        _require(len(self.value) == 32, "TxHash must be 32 bytes")

    @staticmethod
    def from_hex(s: str) -> "TxHash":
        b = _b16(_non_empty_str(s))
        _require(len(b) == 32, "TxHash hex must decode to 32 bytes")
        return TxHash(b)

    def hex(self) -> str:
        return _hex(self.value)

Wei = int  # целочисленное представление wei без плавающей точки

# -------------------------------
# Сущности (записи запроса/результата/ошибки)
# -------------------------------

@dc.dataclass(frozen=True)
class ChainRef:
    name: str
    network: str
    chain_id: int

    def __post_init__(self) -> None:
        _require(self.name != "" and self.network != "", "chain name/network required")
        _clamp_ge(self.chain_id, 0, "chain_id")

@dc.dataclass(frozen=True)
class AnchorPayload:
    hash: Sha256
    content_type: str
    size: int

    def __post_init__(self) -> None:
        _require(self.content_type != "", "content_type required")
        _clamp_ge(self.size, 0, "size")

@dc.dataclass(frozen=True)
class TxParams:
    method: str
    gas: int
    max_fee_wei: Wei
    priority_tip_wei: Optional[Wei] = None
    nonce: Optional[int] = None

    def __post_init__(self) -> None:
        _require(self.method != "", "method required")
        _clamp_ge(self.gas, 1, "gas")
        _clamp_ge(self.max_fee_wei, 0, "max_fee_wei")
        if self.priority_tip_wei is not None:
            _clamp_ge(self.priority_tip_wei, 0, "priority_tip_wei")
        if self.nonce is not None:
            _clamp_ge(self.nonce, 0, "nonce")

@dc.dataclass(frozen=True)
class SignerRef:
    subject: str
    algorithm: SigningAlgorithm
    key_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require(self.subject != "", "subject required")

@dc.dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reasons: Tuple[str, ...] = dc.field(default_factory=tuple)

@dc.dataclass(frozen=True)
class AnchorRequest:
    action: str
    chain: ChainRef
    payload: AnchorPayload
    tx: TxParams
    signer: SignerRef
    headers: Optional[Mapping[str, str]] = None
    policy: Optional[PolicyDecision] = None

    def __post_init__(self) -> None:
        _require(self.action == "anchor.create", "action must be 'anchor.create'")

@dc.dataclass(frozen=True)
class AnchorResult:
    tx_hash: TxHash
    tx_hash_hex: str
    block_number: Optional[int] = None
    block_timestamp: Optional[int] = None  # ms
    confirmations: Optional[int] = None
    explorer_url: Optional[str] = None

    def __post_init__(self) -> None:
        # tx_hash_hex должен соответствовать bytes
        _require(self.tx_hash_hex.lower().startswith("0x"), "tx_hash_hex must be 0x-prefixed")
        _require(_is_hex(self.tx_hash_hex[2:]), "tx_hash_hex must be hex")
        _require(_b16(self.tx_hash_hex).hex() == self.tx_hash.value.hex(), "tx_hash and tx_hash_hex mismatch")
        if self.block_number is not None:
            _clamp_ge(self.block_number, 0, "block_number")
        if self.block_timestamp is not None:
            _clamp_ge(self.block_timestamp, 0, "block_timestamp")
        if self.confirmations is not None:
            _clamp_ge(self.confirmations, 0, "confirmations")

@dc.dataclass(frozen=True)
class AnchorError:
    code: str
    message: str
    retriable: bool = False
    details: Optional[Mapping[str, str]] = None

    def __post_init__(self) -> None:
        _require(self.code != "" and self.message != "", "error code and message required")

@dc.dataclass(frozen=True)
class AttachedSignature:
    alg: str
    signature: bytes
    kid: Optional[str] = None

    def __post_init__(self) -> None:
        _require(self.alg != "", "signature algorithm required")
        _require(len(self.signature) > 0, "signature value required")

# -------------------------------
# Агрегат Anchor
# -------------------------------

@dc.dataclass
class Anchor:
    schema_version: str
    anchor_id: uuid.UUID
    tenant_id: str
    created_at: int  # ms
    updated_at: Optional[int]
    status: AnchoringStatus
    labels: Dict[str, str]
    request: AnchorRequest
    result: Optional[AnchorResult]
    error: Optional[AnchorError]
    signatures: List[AttachedSignature]
    metadata: Dict[str, str]

    # ------------- фабрики -------------

    @staticmethod
    def new(request: AnchorRequest, tenant_id: str, labels: Optional[Mapping[str, str]] = None) -> "Anchor":
        _require(tenant_id != "", "tenant_id required")
        now = _utc_ms()
        return Anchor(
            schema_version="1.0.0",
            anchor_id=uuid.uuid4(),
            tenant_id=tenant_id,
            created_at=now,
            updated_at=None,
            status=AnchoringStatus.PENDING,
            labels=dict(labels or {}),
            request=request,
            result=None,
            error=None,
            signatures=[],
            metadata={},
        )

    # ------------- команды/переходы -------------

    def mark_submitted(self, tx_hash_hex: str) -> None:
        _require(self.status in (AnchoringStatus.PENDING, AnchoringStatus.SUBMITTED), "invalid state for submit")
        txh = TxHash.from_hex(tx_hash_hex)
        self.result = AnchorResult(tx_hash=txh, tx_hash_hex=txh.hex())
        self.status = AnchoringStatus.SUBMITTED
        self.error = None
        self.updated_at = _utc_ms()

    def mark_confirmed(self, block_number: int, block_timestamp_ms: Optional[int] = None, confirmations: Optional[int] = None) -> None:
        _require(self.status in (AnchoringStatus.SUBMITTED, AnchoringStatus.CONFIRMED), "invalid state for confirm")
        _require(self.result is not None, "result required to confirm")
        bn = _clamp_ge(block_number, 0, "block_number")
        bt = block_timestamp_ms if block_timestamp_ms is not None else _utc_ms()
        self.result = dc.replace(self.result, block_number=bn, block_timestamp=_clamp_ge(bt, 0, "block_timestamp"), confirmations=(confirmations if confirmations is None else _clamp_ge(confirmations, 0, "confirmations")))
        self.status = AnchoringStatus.CONFIRMED
        self.updated_at = _utc_ms()

    def finalize(self) -> None:
        _require(self.status in (AnchoringStatus.CONFIRMED, AnchoringStatus.SUBMITTED), "invalid state for finalize")
        self.status = AnchoringStatus.FINALIZED
        self.updated_at = _utc_ms()

    def fail(self, code: str, message: str, retriable: bool = False, details: Optional[Mapping[str, str]] = None) -> None:
        _require(self.status in (AnchoringStatus.PENDING, AnchoringStatus.SUBMITTED, AnchoringStatus.CONFIRMED), "invalid state for fail")
        self.error = AnchorError(code=code, message=message, retriable=retriable, details=dict(details or {}))
        self.status = AnchoringStatus.FAILED
        self.updated_at = _utc_ms()

    def abort(self, message: str = "aborted") -> None:
        _require(self.status in (AnchoringStatus.PENDING, AnchoringStatus.SUBMITTED), "invalid state for abort")
        self.error = AnchorError(code="ABORTED", message=message, retriable=False, details=None)
        self.status = AnchoringStatus.ABORTED
        self.updated_at = _utc_ms()

    def add_signature(self, alg: str, signature: bytes, kid: Optional[str] = None) -> None:
        _require(self.status in (AnchoringStatus.PENDING, AnchoringStatus.SUBMITTED, AnchoringStatus.CONFIRMED), "invalid state for signing")
        self.signatures.append(AttachedSignature(alg=alg, signature=signature, kid=kid))
        self.updated_at = _utc_ms()

    # ------------- вычисляемые свойства -------------

    @property
    def is_terminal(self) -> bool:
        return self.status in (AnchoringStatus.FINALIZED, AnchoringStatus.FAILED, AnchoringStatus.ABORTED)

    @property
    def tx_hash_hex(self) -> Optional[str]:
        return self.result.tx_hash_hex if self.result else None

    # ------------- сериализация (совместимость с Avro v1) -------------

    def to_dict(self) -> Dict[str, Any]:
        """Детерминированная сериализация в словарь (под Avro/JSON)."""
        def m(o: Any) -> Any:
            if isinstance(o, uuid.UUID):
                return str(o)
            if isinstance(o, enum.Enum):
                return o.value
            if isinstance(o, Sha256):
                return o.value  # бинарные поля в Avro — bytes
            if isinstance(o, TxHash):
                return o.value
            if dc.is_dataclass(o):
                return {k: m(v) for k, v in dc.asdict(o).items()}
            if isinstance(o, (list, tuple)):
                return [m(x) for x in o]
            if isinstance(o, dict):
                return {k: m(v) for k, v in o.items()}
            return o

        # Собираем структуру строго по полям Avro
        return {
            "schema_version": self.schema_version,
            "anchor_id": str(self.anchor_id),
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status.value,
            "labels": dict(self.labels) if self.labels else None,
            "request": {
                "action": self.request.action,
                "chain": {
                    "name": self.request.chain.name,
                    "network": self.request.chain.network,
                    "chain_id": self.request.chain.chain_id,
                },
                "payload": {
                    "hash": self.request.payload.hash.value,
                    "content_type": self.request.payload.content_type,
                    "size": self.request.payload.size,
                },
                "tx": {
                    "method": self.request.tx.method,
                    "gas": self.request.tx.gas,
                    "max_fee_wei": int(self.request.tx.max_fee_wei).to_bytes((int(self.request.tx.max_fee_wei).bit_length() + 7) // 8 or 1, "big", signed=False),
                    "priority_tip_wei": None if self.request.tx.priority_tip_wei is None else int(self.request.tx.priority_tip_wei).to_bytes((int(self.request.tx.priority_tip_wei).bit_length() + 7) // 8 or 1, "big", signed=False),
                    "nonce": self.request.tx.nonce,
                },
                "signer": {
                    "subject": self.request.signer.subject,
                    "algorithm": self.request.signer.algorithm.value,
                    "key_id": self.request.signer.key_id,
                },
                "headers": dict(self.request.headers) if self.request.headers else None,
                "policy": None if self.request.policy is None else {"allow": self.request.policy.allow, "reasons": list(self.request.policy.reasons)},
            },
            "result": None if self.result is None else {
                "tx_hash": self.result.tx_hash.value,
                "tx_hash_hex": self.result.tx_hash_hex,
                "block_number": self.result.block_number,
                "block_timestamp": self.result.block_timestamp,
                "confirmations": self.result.confirmations,
                "explorer_url": self.result.explorer_url,
            },
            "error": None if self.error is None else {
                "code": self.error.code,
                "message": self.error.message,
                "retriable": self.error.retriable,
                "details": dict(self.error.details) if self.error.details else None,
            },
            "signatures": [
                {"alg": s.alg, "kid": s.kid, "signature": s.signature}
                for s in self.signatures
            ],
            "metadata": dict(self.metadata) if self.metadata else None,
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Anchor":
        """Инверсная операция к to_dict. Принимает Avro‑совместимую структуру."""
        # request.payload.hash / result.tx_hash приходят как bytes (Avro bytes)
        def as_bytes(v: Any, name: str) -> bytes:
            _require(isinstance(v, (bytes, bytearray)), f"{name} must be bytes")
            return bytes(v)

        req = d["request"]
        chain = ChainRef(
            name=req["chain"]["name"],
            network=req["chain"]["network"],
            chain_id=int(req["chain"]["chain_id"]),
        )
        payload = AnchorPayload(
            hash=Sha256(as_bytes(req["payload"]["hash"], "payload.hash")),
            content_type=req["payload"]["content_type"],
            size=int(req["payload"]["size"]),
        )

        def bytes_to_int(b: Optional[bytes]) -> Optional[int]:
            if b is None:
                return None
            if len(b) == 0:
                return 0
            return int.from_bytes(b, "big", signed=False)

        tx = TxParams(
            method=req["tx"]["method"],
            gas=int(req["tx"]["gas"]),
            max_fee_wei=int(bytes_to_int(as_bytes(req["tx"]["max_fee_wei"], "tx.max_fee_wei"))),  # type: ignore[arg-type]
            priority_tip_wei=bytes_to_int(req["tx"].get("priority_tip_wei")),
            nonce=None if req["tx"].get("nonce") is None else int(req["tx"]["nonce"]),
        )
        signer = SignerRef(
            subject=req["signer"]["subject"],
            algorithm=SigningAlgorithm(req["signer"]["algorithm"]),
            key_id=req["signer"].get("key_id"),
        )
        policy = None
        if req.get("policy") is not None:
            policy = PolicyDecision(bool(req["policy"]["allow"]), tuple(req["policy"].get("reasons", []) or []))

        request = AnchorRequest(
            action=req["action"],
            chain=chain,
            payload=payload,
            tx=tx,
            signer=signer,
            headers=None if req.get("headers") is None else dict(req["headers"]),
            policy=policy,
        )

        result = None
        if d.get("result") is not None:
            r = d["result"]
            txh = TxHash(as_bytes(r["tx_hash"], "result.tx_hash"))
            result = AnchorResult(
                tx_hash=txh,
                tx_hash_hex=r.get("tx_hash_hex") or txh.hex(),
                block_number=None if r.get("block_number") is None else int(r["block_number"]),
                block_timestamp=None if r.get("block_timestamp") is None else int(r["block_timestamp"]),
                confirmations=None if r.get("confirmations") is None else int(r["confirmations"]),
                explorer_url=r.get("explorer_url"),
            )

        error = None
        if d.get("error") is not None:
            e = d["error"]
            error = AnchorError(
                code=e["code"],
                message=e["message"],
                retriable=bool(e.get("retriable", False)),
                details=None if e.get("details") is None else dict(e["details"]),
            )

        sigs = []
        for s in d.get("signatures") or []:
            sigs.append(AttachedSignature(alg=s["alg"], kid=s.get("kid"), signature=as_bytes(s["signature"], "signature")))

        return Anchor(
            schema_version=d.get("schema_version", "1.0.0"),
            anchor_id=uuid.UUID(d["anchor_id"]),
            tenant_id=d["tenant_id"],
            created_at=int(d["created_at"]),
            updated_at=None if d.get("updated_at") is None else int(d["updated_at"]),
            status=AnchoringStatus(d["status"]),
            labels={} if d.get("labels") in (None, {}) else dict(d["labels"]),
            request=request,
            result=result,
            error=error,
            signatures=sigs,
            metadata={} if d.get("metadata") in (None, {}) else dict(d["metadata"]),
        )

    # ------------- JSON удобные helpers (для REST/логов) -------------

    def to_json(self) -> str:
        """JSON для REST/логов: бинарные поля — hex строки, детерминированная сортировка ключей."""
        doc = self.to_dict()

        def conv(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: conv(v) for k, v in obj.items() if v is not None}
            if isinstance(obj, (bytes, bytearray)):
                return "0x" + obj.hex()
            if isinstance(obj, list):
                return [conv(x) for x in obj]
            return obj

        return json.dumps(conv(doc), ensure_ascii=False, separators=(",", ":"), sort_keys=True)

# -------------------------------
# Простой smoke‑тест при прямом запуске
# -------------------------------

if __name__ == "__main__":  # pragma: no cover
    chain = ChainRef("ethereum", "mainnet", 1)
    payload = AnchorPayload(Sha256.from_hex("aa"*32), "application/json", 1024)
    tx = TxParams(method="eth_sendRawTransaction", gas=21000, max_fee_wei=1_000_000_000, priority_tip_wei=1_500_000_000)
    signer = SignerRef("did:key:zTest", SigningAlgorithm.secp256k1, key_id="k1")
    req = AnchorRequest("anchor.create", chain, payload, tx, signer)
    anchor = Anchor.new(req, tenant_id="tenant-a")
    anchor.mark_submitted("0x" + "11"*32)
    anchor.mark_confirmed(block_number=12345678)
    anchor.finalize()
    print(anchor.to_json())
