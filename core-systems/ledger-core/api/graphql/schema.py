# -*- coding: utf-8 -*-
"""
Ledger Core GraphQL Schema (Strawberry)
Production-grade schema:
- Custom scalars: Decimal, DateTime, UUID, JSON
- Domain types: Money, Entry, Transaction, enums
- Relay-style pagination and filters
- Mutations: createTransaction, postTransaction, reverseTransaction (idempotent)
- Subscriptions: transactionEvents
- Unified errors (ProblemDetails)
- Global ID helpers
- Simple query complexity guard Extension

Integration (FastAPI):
    from strawberry.fastapi import GraphQLRouter
    from .graphql.schema import schema, build_context
    app.include_router(GraphQLRouter(schema, context_getter=build_context), prefix="/graphql")
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import decimal
import json
import typing as t
import uuid as uuidlib
from dataclasses import dataclass

import strawberry
from strawberry.types import Info
from strawberry.schema.config import StrawberryConfig
from strawberry.extensions import SchemaExtension
from strawberry.scalars import JSON

# =========================
# Custom Scalars
# =========================

@strawberry.scalar(description="Arbitrary-precision decimal as canonical string without exponent")
def Decimal(value: t.Union[str, decimal.Decimal]) -> str:
    if isinstance(value, decimal.Decimal):
        q = value.quantize(value)  # keep scale
        s = format(q, "f")
    else:
        try:
            d = decimal.Decimal(str(value))
        except Exception as e:
            raise ValueError(f"bad decimal: {e}")
        s = format(d, "f")
    if "e" in s.lower():
        raise ValueError("exponent not allowed")
    if len(s.replace("-", "").replace(".", "")) > 38:
        raise ValueError("too many digits")
    return s

@strawberry.scalar(description="RFC 3339 timestamp with timezone (UTC recommended)")
def DateTime(value: t.Union[str, dt.datetime]) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        d = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as e:
        raise ValueError(f"bad datetime: {e}")
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")

@strawberry.scalar(description="UUID v4 as string")
def UUID(value: t.Union[str, uuidlib.UUID]) -> str:
    try:
        u = value if isinstance(value, uuidlib.UUID) else uuidlib.UUID(str(value))
    except Exception as e:
        raise ValueError(f"bad uuid: {e}")
    return str(u)

# JSON scalar is imported from strawberry.scalars.JSON

# =========================
# Global ID helpers (Relay-like)
# =========================

def to_global_id(typename: str, raw_id: str) -> str:
    return base64.b64encode(f"{typename}:{raw_id}".encode("utf-8")).decode("ascii")

def from_global_id(global_id: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(global_id).decode("utf-8")
        typename, raw_id = raw.split(":", 1)
        return typename, raw_id
    except Exception:
        raise ValueError("bad global id")

# =========================
# Domain enums and types
# =========================

@strawberry.enum
class TxStatus(Enum):
    DRAFT = "DRAFT"
    PENDING = "PENDING"
    POSTED = "POSTED"
    FAILED = "FAILED"
    REVERSED = "REVERSED"

@strawberry.enum
class Side(Enum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"

@strawberry.type
class Money:
    currency: str
    amount: Decimal

@strawberry.type
class Entry:
    account_id: UUID
    side: Side
    money: Money
    memo: t.Optional[str]
    attributes: JSON
    subledger: t.Optional[str]

@strawberry.type
class Transaction:
    id: strawberry.ID
    uuid: UUID
    status: TxStatus
    journal: str
    reference: t.Optional[str]
    description: t.Optional[str]
    labels: JSON
    attributes: JSON
    total_debits: t.Optional[Money]
    total_credits: t.Optional[Money]
    created_at: DateTime
    updated_at: DateTime
    posted_at: t.Optional[DateTime]
    etag: t.Optional[str]

# =========================
# Inputs and Filters
# =========================

@strawberry.input
class EntryInput:
    account_id: UUID
    side: Side
    currency: str
    amount: Decimal
    memo: t.Optional[str] = None
    attributes: JSON = strawberry.field(default_factory=dict)
    subledger: t.Optional[str] = None

@strawberry.input
class CreateTransactionInput:
    journal: str
    description: t.Optional[str] = None
    reference: t.Optional[str] = None
    entries: list[EntryInput]
    post_immediately: bool = False
    idempotency_key: t.Optional[str] = None
    effective_at: t.Optional[DateTime] = None

@strawberry.enum
class SortOrder(Enum):
    ASC = "ASC"
    DESC = "DESC"

@strawberry.input
class TransactionsFilter:
    journal: t.Optional[str] = None
    statuses: t.Optional[list[TxStatus]] = None
    created_from: t.Optional[DateTime] = None
    created_to: t.Optional[DateTime] = None
    posted_from: t.Optional[DateTime] = None
    posted_to: t.Optional[DateTime] = None
    label_selector: t.Optional[JSON] = None  # exact match dict

# =========================
# Relay-style pagination
# =========================

@strawberry.type
class PageInfo:
    has_next_page: bool
    has_previous_page: bool
    start_cursor: t.Optional[str]
    end_cursor: t.Optional[str]

@strawberry.type
class TransactionEdge:
    cursor: str
    node: Transaction

@strawberry.type
class TransactionConnection:
    edges: list[TransactionEdge]
    page_info: PageInfo
    total_count: int

# =========================
# ProblemDetails for domain errors
# =========================

@strawberry.type
class ProblemDetails:
    code: str
    message: str
    detail: t.Optional[str] = None

# =========================
# Proofs types (inclusion/root)
# =========================

@strawberry.type
class InclusionProof:
    snapshot_id: str
    tree_size: int
    leaf_index: int
    leaf_hash_hex: str
    audit_path: list[str]
    root_hash_hex: str
    algo: str
    sth_jws: t.Optional[str]

@strawberry.type
class RootProof:
    snapshot_id: str
    tree_size: int
    root_hash_hex: str
    algo: str
    issued_at: int
    sth_jws: t.Optional[str]

# =========================
# Service layer contracts for context
# =========================

@dataclass
class LedgerService:
    async def create_transaction(self, payload: CreateTransactionInput, user: dict[str, t.Any]) -> tuple[dict, t.Optional[ProblemDetails]]:
        raise NotImplementedError

    async def get_transaction(self, tx_uuid: str, user: dict[str, t.Any]) -> t.Optional[dict]:
        raise NotImplementedError

    async def list_transactions(
        self, filt: TransactionsFilter, first: int, after: t.Optional[str], order_by: str, order: SortOrder, user: dict[str, t.Any]
    ) -> tuple[list[dict], int, t.Optional[str], t.Optional[str]]:
        raise NotImplementedError

    async def post_transaction(self, tx_uuid: str, require_balanced: bool, posted_at: t.Optional[str], idempotency_key: t.Optional[str], user: dict[str, t.Any]) -> tuple[dict, t.Optional[ProblemDetails]]:
        raise NotImplementedError

    async def reverse_transaction(self, tx_uuid: str, reason: str, post_compensation: bool, idempotency_key: t.Optional[str], effective_at: t.Optional[str], user: dict[str, t.Any]) -> tuple[dict, t.Optional[ProblemDetails]]:
        raise NotImplementedError

    async def inclusion_proof(self, tx_id: t.Optional[str], leaf_hex: t.Optional[str], snapshot_id: t.Optional[str]) -> InclusionProof:
        raise NotImplementedError

    async def root_proof(self, snapshot_id: t.Optional[str], tree_size: t.Optional[int]) -> RootProof:
        raise NotImplementedError

@dataclass
class EventService:
    async def stream(self, journal: str, statuses: list[str]) -> t.AsyncIterator[dict]:
        raise NotImplementedError

@dataclass
class GQLContext:
    user: dict[str, t.Any]
    ledger: LedgerService
    events: EventService

async def build_context(request) -> GQLContext:
    user = getattr(request, "user", {"sub": "anonymous"})
    # Wire your concrete services here
    raise NotImplementedError("Provide GQLContext with concrete services")

# =========================
# Helpers to map dict -> GraphQL types
# =========================

def money_from(d: t.Optional[dict]) -> t.Optional[Money]:
    if not d:
        return None
    return Money(currency=d["currency"], amount=Decimal(d["amount"]))

def tx_from(d: dict) -> Transaction:
    tid = d.get("id") or d.get("uuid")
    gid = to_global_id("Transaction", tid)
    return Transaction(
        id=gid,
        uuid=UUID(tid),
        status=TxStatus[d["status"]],
        journal=d["journal"],
        reference=d.get("reference"),
        description=d.get("description"),
        labels=d.get("labels") or {},
        attributes=d.get("attributes") or {},
        total_debits=money_from(d.get("total_debits")),
        total_credits=money_from(d.get("total_credits")),
        created_at=DateTime(d["created_at"]),
        updated_at=DateTime(d.get("updated_at", d["created_at"])),
        posted_at=DateTime(d["posted_at"]) if d.get("posted_at") else None,
        etag=d.get("etag"),
    )

# =========================
# Mutations payloads (Union)
# =========================

CreateTxResult = strawberry.union("CreateTxResult", (Transaction, ProblemDetails))
PostTxResult = strawberry.union("PostTxResult", (Transaction, ProblemDetails))
ReverseTxResult = strawberry.union("ReverseTxResult", (Transaction, ProblemDetails))

# =========================
# Query
# =========================

@strawberry.type
class Query:
    @strawberry.field(description="Fetch single transaction by global ID")
    async def transaction(self, info: Info, id: strawberry.ID) -> t.Optional[Transaction]:
        typename, raw = from_global_id(id)
        if typename != "Transaction":
            raise ValueError("bad id type")
        data = await info.context.ledger.get_transaction(raw, info.context.user)
        return tx_from(data) if data else None

    @strawberry.field(description="List transactions with filters and Relay pagination")
    async def transactions(
        self,
        info: Info,
        first: int = strawberry.argument(description="Page size", default=50),
        after: t.Optional[str] = strawberry.argument(description="Opaque cursor", default=None),
        order_by: str = strawberry.argument(description="Field to order by", default="created_at"),
        order: SortOrder = SortOrder.DESC,
        filter: TransactionsFilter = TransactionsFilter(),
    ) -> TransactionConnection:
        rows, total, start_cursor, end_cursor = await info.context.ledger.list_transactions(
            filt=filter, first=min(max(first, 1), 1000), after=after, order_by=order_by, order=order, user=info.context.user
        )
        edges = [TransactionEdge(cursor=r.get("cursor") or to_global_id("Cursor", r["id"]), node=tx_from(r)) for r in rows]
        page_info = PageInfo(
            has_next_page=bool(end_cursor),
            has_previous_page=bool(after),
            start_cursor=start_cursor,
            end_cursor=end_cursor,
        )
        return TransactionConnection(edges=edges, page_info=page_info, total_count=total)

    @strawberry.field(description="Get signed Merkle root (STH)")
    async def root_proof(self, info: Info, snapshot_id: t.Optional[str] = None, tree_size: t.Optional[int] = None) -> RootProof:
        return await info.context.ledger.root_proof(snapshot_id=snapshot_id, tree_size=tree_size)

    @strawberry.field(description="Get inclusion proof for transaction or explicit leaf hash")
    async def inclusion_proof(
        self, info: Info, tx_id: t.Optional[str] = None, leaf_hash_hex: t.Optional[str] = None, snapshot_id: t.Optional[str] = None
    ) -> InclusionProof:
        return await info.context.ledger.inclusion_proof(tx_id=tx_id, leaf_hex=leaf_hash_hex, snapshot_id=snapshot_id)

# =========================
# Mutation
# =========================

@strawberry.type
class Mutation:
    @strawberry.mutation(description="Create a transaction; optionally post immediately. Idempotent by idempotency_key.")
    async def create_transaction(self, info: Info, input: CreateTransactionInput) -> CreateTxResult:
        data, err = await info.context.ledger.create_transaction(payload=input, user=info.context.user)
        if err:
            return err
        return tx_from(data)

    @strawberry.mutation(description="Post an existing transaction")
    async def post_transaction(
        self,
        info: Info,
        id: strawberry.ID,
        require_balanced: bool = True,
        posted_at: t.Optional[DateTime] = None,
        idempotency_key: t.Optional[str] = None,
    ) -> PostTxResult:
        _, raw = from_global_id(id)
        data, err = await info.context.ledger.post_transaction(
            tx_uuid=raw, require_balanced=require_balanced, posted_at=posted_at, idempotency_key=idempotency_key, user=info.context.user
        )
        if err:
            return err
        return tx_from(data)

    @strawberry.mutation(description="Reverse a posted transaction with optional compensation posting")
    async def reverse_transaction(
        self,
        info: Info,
        id: strawberry.ID,
        reason: str,
        post_compensation: bool = True,
        idempotency_key: t.Optional[str] = None,
        effective_at: t.Optional[DateTime] = None,
    ) -> ReverseTxResult:
        _, raw = from_global_id(id)
        data, err = await info.context.ledger.reverse_transaction(
            tx_uuid=raw,
            reason=reason,
            post_compensation=post_compensation,
            idempotency_key=idempotency_key,
            effective_at=effective_at,
            user=info.context.user,
        )
        if err:
            return err
        return tx_from(data)

# =========================
# Subscription
# =========================

@strawberry.type
class TransactionEvent:
    type: str  # TransactionCreated|TransactionPosted|TransactionFailed|TransactionReversed
    transaction: Transaction
    reason: t.Optional[str] = None
    error_code: t.Optional[str] = None
    error_msg: t.Optional[str] = None

@strawberry.type
class Subscription:
    @strawberry.subscription(description="Stream ledger events for a journal")
    async def transaction_events(self, info: Info, journal: str, statuses: t.Optional[list[TxStatus]] = None) -> t.AsyncIterator[TransactionEvent]:
        status_names = [s.name for s in (statuses or [])]
        async for ev in info.context.events.stream(journal=journal, statuses=status_names):
            tx = tx_from(ev["transaction"])
            yield TransactionEvent(type=ev["type"], transaction=tx, reason=ev.get("reason"), error_code=ev.get("error_code"), error_msg=ev.get("error_msg"))

# =========================
# Simple complexity guard
# =========================

class ComplexityGuard(SchemaExtension):
    def __init__(self, *, max_fields: int = 5000) -> None:
        super().__init__()
        self.max_fields = max_fields

    def on_execute(self):
        # naive node count guard
        doc = self.execution_context.graphql_document
        count = sum(len(op.selection_set.selections) for op in doc.definitions if getattr(op, "selection_set", None))
        if count > self.max_fields:
            raise ValueError("query too complex")

# =========================
# Schema
# =========================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=True),
    extensions=[
        lambda: ComplexityGuard(max_fields=5000),
    ],
)
