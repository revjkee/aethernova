# path: human-sovereignty-core/interfaces/ledger_core.py
from __future__ import annotations

import abc
import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Protocol, Tuple


class LedgerError(RuntimeError):
    pass


class LedgerIntegrityError(LedgerError):
    pass


class LedgerWriteError(LedgerError):
    pass


class LedgerReadError(LedgerError):
    pass


class LedgerRecordType(Enum):
    DECISION = "decision"
    APPROVAL = "approval"
    EXECUTION = "execution"
    AUDIT = "audit"
    SYSTEM = "system"


@dataclass(frozen=True)
class LedgerRecord:
    """
    Canonical immutable record stored in ledger.
    """
    record_id: str
    record_type: LedgerRecordType
    at_utc: str
    subject: str
    payload: Mapping[str, Any]
    prev_ref: Optional[str]
    integrity_hash: str
    audit_hash: Optional[str] = None


@dataclass(frozen=True)
class LedgerProof:
    """
    Cryptographic or logical proof of inclusion and integrity.
    The exact semantics depend on implementation (Merkle proof, block hash, etc.).
    """
    record_id: str
    integrity_hash: str
    proof_payload: Mapping[str, Any]


@dataclass(frozen=True)
class LedgerHead:
    """
    Current immutable head of the ledger.
    """
    height: int
    record_id: str
    integrity_hash: str
    at_utc: str


class LedgerCore(abc.ABC):
    """
    Abstract interface for a Human Sovereignty Ledger.

    Hard guarantees required by this interface:
    - Append-only semantics.
    - Immutable historical records.
    - Deterministic integrity hash per record.
    - Ability to verify inclusion and ordering.
    """

    @abc.abstractmethod
    def append(
        self,
        *,
        record_type: LedgerRecordType,
        subject: str,
        payload: Mapping[str, Any],
        at_utc: Optional[_dt.datetime] = None,
        prev_ref: Optional[str] = None,
    ) -> LedgerRecord:
        """
        Append a new immutable record to the ledger.

        Must fail if:
        - integrity constraints are violated
        - ordering is inconsistent
        - append-only property cannot be guaranteed
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, record_id: str) -> LedgerRecord:
        """
        Retrieve a record by its unique identifier.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def head(self) -> LedgerHead:
        """
        Return the current head of the ledger.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def iterate(
        self,
        *,
        from_record_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterable[LedgerRecord]:
        """
        Iterate records in canonical order.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def prove(self, record_id: str) -> LedgerProof:
        """
        Return a proof that the record is included in the ledger
        and has not been tampered with.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def verify_proof(self, proof: LedgerProof) -> bool:
        """
        Verify a proof of inclusion and integrity.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def require_integrity(self) -> None:
        """
        Enforce full ledger integrity check.

        Must raise LedgerIntegrityError if any invariant is broken.
        """
        raise NotImplementedError


class LedgerCoreFactory(Protocol):
    """
    Factory protocol for dependency injection.
    """

    def __call__(self, **kwargs: Any) -> LedgerCore:
        ...
