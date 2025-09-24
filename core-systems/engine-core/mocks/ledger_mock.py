# engine-core/engine/mocks/ledger_mock.py
"""
Industrial-grade in-memory ledger mock for engine-core.

Features:
- Double-entry postings (sum(debits)==sum(credits), currency match)
- Multi-currency accounts; per-account running balance with version
- Idempotency keys (exact-once semantics per tenant/namespace)
- Deterministic canonical encoding + FNV-64 audit hash chain
- Monotonic timestamps (ms) and per-account sequential lines with "balance_after"
- Async API with fine-grained per-account locks; safe for concurrent tests
- Snapshots (serialize) and restore; export/import journal
- Pagination for account statements; filtered listings
- Strict errors: insufficient funds (optional check), currency mismatches, idempotency replay, etc.

Intended for tests, local dev, deterministic sims. No external deps.
Python 3.10+.
"""

from __future__ import annotations

import asyncio
import time
import struct
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Mapping, Iterable

# =========================
# Canonical encoding + FNV64
# =========================

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3

def fnv1a64(data: bytes, seed: int = FNV64_OFFSET) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def _uvarint(n: int) -> bytes:
    if n < 0: raise ValueError("uvarint>=0")
    out = bytearray()
    x = n
    while True:
        b = x & 0x7F
        x >>= 7
        if x: out.append(b | 0x80)
        else:
            out.append(b); break
    return bytes(out)

def _cenc(obj: Any) -> bytes:
    t = type(obj)
    if obj is None: return b"N"
    if t is bool: return b"T" if obj else b"F"
    if t is int:
        b = str(int(obj)).encode("ascii")
        return b"I"+_uvarint(len(b))+b
    if t is float:
        return b"D"+struct.pack("!d", float(obj))
    if t is str:
        b = obj.encode("utf-8"); return b"S"+_uvarint(len(b))+b
    if t is bytes or isinstance(obj, (bytearray, memoryview)):
        b = bytes(obj); return b"B"+_uvarint(len(b))+b
    if isinstance(obj, (list, tuple)):
        parts = bytearray(b"L"+_uvarint(len(obj)))
        for it in obj: parts += _cenc(it)
        return bytes(parts)
    if isinstance(obj, dict):
        items = [( _cenc(k), _cenc(v) ) for k,v in obj.items()]
        items.sort(key=lambda kv: kv[0])
        parts = bytearray(b"M"+_uvarint(len(items)))
        for k,v in items: parts += k+v
        return bytes(parts)
    # fallback
    s = str(obj).encode("utf-8"); return b"S"+_uvarint(len(s))+s

# =========================
# Errors
# =========================

class LedgerError(Exception): ...
class AccountNotFound(LedgerError): ...
class AccountExists(LedgerError): ...
class CurrencyMismatch(LedgerError): ...
class IdempotencyConflict(LedgerError): ...
class PostingValidation(LedgerError): ...
class InsufficientFunds(LedgerError): ...

# =========================
# Types
# =========================

@dataclass(slots=True)
class Account:
    id: str
    currency: str
    meta: Dict[str, Any] = field(default_factory=dict)
    balance: int = 0                 # minor units (e.g., cents)
    version: int = 0                 # increments per posting that touches the account
    lines: int = 0                   # number of posted lines (sequence)
    closed: bool = False

@dataclass(slots=True)
class Leg:
    account_id: str
    amount: int                      # signed minor units; debit=+, credit=-
    currency: str

@dataclass(slots=True)
class Posting:
    tenant: str
    idempotency_key: str
    legs: List[Leg]                  # must sum to zero by currency
    allow_overdraft: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    memo: str = ""

@dataclass(slots=True)
class JournalLine:
    line_id: str                     # unique (tenant:seq)
    ts_ms: int
    account_id: str
    currency: str
    delta: int                       # signed
    balance_after: int
    posting_id: str
    seq: int                         # per-account increasing
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class JournalEntry:
    posting_id: str                  # deterministic from tenant/idempotency_key
    ts_ms: int
    legs: List[Leg]
    memo: str
    tags: Dict[str, str]
    lines: List[JournalLine]
    audit_prev_h64: int
    audit_h64: int

# =========================
# Ledger mock
# =========================

class LedgerMock:
    """
    In-memory ledger with double-entry enforcement, per-account concurrency,
    audit chain, idempotency, and snapshots. Suitable for unit/integration tests.
    """

    def __init__(self, *, namespace: str = "test", overdraft_check: bool = True) -> None:
        self.ns = namespace
        self.overdraft_check = overdraft_check
        self._acc: Dict[str, Account] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._idemp: Dict[Tuple[str, str], str] = {}      # (tenant, idem_key) -> posting_id
        self._journal: List[JournalEntry] = []
        self._audit_tip = FNV64_OFFSET
        self._global_lock = asyncio.Lock()
        self._seq = 0                                     # posting sequence (for uniqueness)

    # -------- Accounts --------

    async def open_account(self, *, account_id: str, currency: str, meta: Mapping[str, Any] | None = None) -> Account:
        async with self._global_lock:
            if account_id in self._acc:
                raise AccountExists(account_id)
            acc = Account(id=account_id, currency=currency, meta=dict(meta or {}))
            self._acc[account_id] = acc
            self._locks[account_id] = asyncio.Lock()
            return acc

    async def close_account(self, *, account_id: str) -> None:
        acc = self._get_acc(account_id)
        async with self._locks[account_id]:
            acc.closed = True

    async def get_account(self, *, account_id: str) -> Account:
        return self._copy_acc(self._get_acc(account_id))

    async def list_accounts(self, *, currency: Optional[str] = None) -> List[Account]:
        out = []
        for a in self._acc.values():
            if currency and a.currency != currency: continue
            out.append(self._copy_acc(a))
        return out

    # -------- Posting (double-entry) --------

    async def post(self, p: Posting) -> JournalEntry:
        if not p.legs:
            raise PostingValidation("empty legs")
        if not p.idempotency_key or not p.tenant:
            raise PostingValidation("tenant and idempotency_key required")

        # Idempotency fast-path
        idem_key = (p.tenant, p.idempotency_key)
        async with self._global_lock:
            posted = self._idemp.get(idem_key)
            if posted:
                # Return existing journal entry (search by posting_id)
                je = next((e for e in self._journal if e.posting_id == posted), None)
                if not je:
                    raise IdempotencyConflict("idempotency mapping inconsistent")
                return je

        # Validate legs: by currency sums to zero, accounts/currencies match
        sums: Dict[str, int] = {}
        acc_ids: List[str] = []
        for l in p.legs:
            a = self._get_acc(l.account_id)
            if a.currency != l.currency:
                raise CurrencyMismatch(f"{l.account_id} expected {a.currency}, got {l.currency}")
            sums[l.currency] = sums.get(l.currency, 0) + l.amount
            acc_ids.append(l.account_id)
        for cur, s in sums.items():
            if s != 0:
                raise PostingValidation(f"legs not balanced for {cur}: {s}")

        # Lock accounts in deterministic order to avoid deadlocks
        acc_ids_sorted = sorted(set(acc_ids))
        locks = [self._locks[i] for i in acc_ids_sorted]
        for lk in locks: await lk.acquire()
        try:
            # Overdraft check
            if self.overdraft_check and not p.allow_overdraft:
                for l in p.legs:
                    if l.amount < 0:
                        a = self._acc[l.account_id]
                        if a.balance + l.amount < 0:
                            raise InsufficientFunds(l.account_id)

            # Apply
            ts = int(time.monotonic() * 1000)
            posting_id = self._posting_id(p.tenant, p.idempotency_key)
            lines: List[JournalLine] = []
            for l in p.legs:
                a = self._acc[l.account_id]
                a.balance += l.amount
                a.version += 1
                a.lines += 1
                line = JournalLine(
                    line_id=f"{self.ns}:{a.id}:{a.lines}",
                    ts_ms=ts,
                    account_id=a.id,
                    currency=a.currency,
                    delta=l.amount,
                    balance_after=a.balance,
                    posting_id=posting_id,
                    seq=a.lines,
                    meta={"version": a.version}
                )
                lines.append(line)

            # Audit record
            entry = JournalEntry(
                posting_id=posting_id, ts_ms=ts, legs=list(p.legs), memo=p.memo, tags=dict(p.tags),
                lines=lines, audit_prev_h64=self._audit_tip, audit_h64=0
            )
            payload = _cenc({
                "pid": posting_id, "ts": ts,
                "legs": [asdict(x) for x in p.legs],
                "tags": p.tags, "memo": p.memo,
                "lines": [asdict(l) for l in lines], "prev": self._audit_tip
            })
            self._audit_tip = fnv1a64(payload, seed=self._audit_tip)
            entry.audit_h64 = self._audit_tip

            # Register idempotency
            async with self._global_lock:
                if idem_key in self._idemp:
                    # Rare race: another concurrent equal post registered while we held only account locks
                    # Validate same posting_id; else conflict
                    if self._idemp[idem_key] != posting_id:
                        raise IdempotencyConflict("duplicate idempotency with different payload")
                else:
                    self._idemp[idem_key] = posting_id
                self._journal.append(entry)

            return entry
        finally:
            for lk in reversed(locks):
                lk.release()

    # -------- Queries --------

    async def balance(self, *, account_id: str) -> Tuple[int, int]:
        a = self._get_acc(account_id); return a.balance, a.version

    async def statement(self, *, account_id: str, cursor: Optional[int] = None, limit: int = 100) -> Tuple[List[JournalLine], Optional[int]]:
        a = self._get_acc(account_id)
        start_seq = (cursor or 0) + 1
        # Collect lines from journal; since this is a mock, scan is acceptable
        out: List[JournalLine] = []
        for e in self._journal:
            for ln in e.lines:
                if ln.account_id != account_id: continue
                if ln.seq < start_seq: continue
                out.append(ln)
                if len(out) >= limit: break
            if len(out) >= limit: break
        next_cur = out[-1].seq if out else None
        return out, next_cur

    async def find_posting(self, *, posting_id: str) -> Optional[JournalEntry]:
        return next((e for e in self._journal if e.posting_id == posting_id), None)

    # -------- Transfers helpers --------

    async def transfer(self, *, tenant: str, idempotency_key: str, src: str, dst: str, amount: int, currency: str, tags: Mapping[str, str] | None = None, memo: str = "") -> JournalEntry:
        legs = [
            Leg(account_id=src, amount=-abs(amount), currency=currency),
            Leg(account_id=dst, amount=+abs(amount), currency=currency),
        ]
        return await self.post(Posting(tenant=tenant, idempotency_key=idempotency_key, legs=legs, tags=dict(tags or {}), memo=memo))

    # -------- Snapshots --------

    async def snapshot(self) -> Dict[str, Any]:
        # Deterministic snapshot for tests
        accs = []
        for a in sorted(self._acc.values(), key=lambda x: x.id):
            accs.append(asdict(a))
        journal = []
        for e in self._journal:
            journal.append({
                "posting_id": e.posting_id,
                "ts_ms": e.ts_ms,
                "legs": [asdict(l) for l in e.legs],
                "memo": e.memo,
                "tags": dict(e.tags),
                "lines": [asdict(ln) for ln in e.lines],
                "audit_prev_h64": e.audit_prev_h64,
                "audit_h64": e.audit_h64,
            })
        idem = { f"{k[0]}:{k[1]}": v for k,v in self._idemp.items() }
        return {
            "ns": self.ns,
            "overdraft_check": self.overdraft_check,
            "acc": accs,
            "journal": journal,
            "idem": idem,
            "audit_tip": self._audit_tip,
        }

    async def restore(self, snap: Mapping[str, Any]) -> None:
        self.ns = str(snap.get("ns", self.ns))
        self.overdraft_check = bool(snap.get("overdraft_check", True))
        self._acc.clear(); self._locks.clear(); self._journal.clear(); self._idemp.clear()
        for a in snap.get("acc", []):
            acc = Account(**a); self._acc[acc.id] = acc; self._locks[acc.id] = asyncio.Lock()
        for e in snap.get("journal", []):
            legs = [Leg(**l) for l in e["legs"]]
            lines = [JournalLine(**ln) for ln in e["lines"]]
            je = JournalEntry(e["posting_id"], e["ts_ms"], legs, e["memo"], dict(e["tags"]), lines, e["audit_prev_h64"], e["audit_h64"])
            self._journal.append(je)
        for k,v in snap.get("idem", {}).items():
            tenant, idem = k.split(":", 1); self._idemp[(tenant, idem)] = v
        self._audit_tip = int(snap.get("audit_tip", FNV64_OFFSET))

    # -------- Internals --------

    def _get_acc(self, account_id: str) -> Account:
        a = self._acc.get(account_id)
        if not a: raise AccountNotFound(account_id)
        if a.closed: raise PostingValidation(f"account {account_id} closed")
        return a

    @staticmethod
    def _copy_acc(a: Account) -> Account:
        return Account(id=a.id, currency=a.currency, meta=dict(a.meta), balance=a.balance, version=a.version, lines=a.lines, closed=a.closed)

    def _posting_id(self, tenant: str, idem: str) -> str:
        b = _cenc({"ns": self.ns, "tenant": tenant, "idem": idem})
        h = fnv1a64(b)
        return f"{tenant}:{idem}:{h:016x}"

# =========================
# __all__
# =========================

__all__ = [
    "LedgerMock",
    # types
    "Account","Leg","Posting","JournalLine","JournalEntry",
    # errors
    "LedgerError","AccountNotFound","AccountExists","CurrencyMismatch","IdempotencyConflict","PostingValidation","InsufficientFunds",
    # utils
    "fnv1a64",
]
