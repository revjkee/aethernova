# domain-model
# CSMarket Domain Model (DDD)

Version: 1.0
Status: Production-grade domain specification
Scope: CS2 skins marketplace with crypto payments (BTC, ETH, TON), platform commission up to 18 percent, escrow-style settlement, strong auditability.

## 1. Purpose and Non-Goals

### Purpose
This document defines the domain model for CSMarket using Domain-Driven Design (DDD):
- Ubiquitous Language (glossary)
- Bounded Contexts and their responsibilities
- Aggregates, Entities, Value Objects
- Domain Events, Commands, Policies
- State machines and invariants
- Data ownership and integration contracts

### Non-Goals
- UI and API endpoint design
- Infrastructure details (databases, queues, observability implementation)
- Steam integration technicalities beyond domain boundaries

## 2. Ubiquitous Language (Glossary)

- User: Account holder in CSMarket.
- Buyer: User who purchases an item.
- Seller: User who lists and sells an item.
- Steam Account: External identity representing the user in Steam ecosystem.
- Skin: A CS2 in-game item (digital asset) traded in CSMarket.
- Catalog Item: Normalized representation of a tradable skin type.
- Listing: Seller’s offer to sell a specific skin at a price and terms.
- Order: Buyer’s intent to buy a listing (reservation plus execution lifecycle).
- Payment: Crypto transfer intent and its confirmation lifecycle.
- Escrow: Domain concept representing locked value pending settlement.
- Settlement: Distribution of funds after order completion (seller payout, platform fee, refunds).
- Platform Fee: Commission charged by CSMarket (configured up to 18 percent).
- External Fee: Third-party fees (network fees, exchange fees, Steam-related costs) not controlled by CSMarket.
- Risk Score: Domain evaluation of fraud/abuse risk for an order or account.
- Dispute: Formal conflict case about an order outcome.
- AML/KYC: Compliance domain controls; may be optional depending on jurisdiction and business policy.
- Ledger: Authoritative record of money movements inside CSMarket domain.
- Audit Log: Tamper-evident record of domain-relevant actions and decisions.

## 3. Bounded Contexts

CSMarket is split into bounded contexts. Each context owns its data and invariants.

### 3.1 Identity Context
Responsibilities:
- User registration and authentication.
- Account lifecycle (active, restricted, banned).
- Credential policy (login and password).
- Linking Steam Account identity.

Key concepts:
- User, Credential, Session, SteamLink.

Notes:
- Registration uses login and password, no email required.
- Wallet provisioning (if used) belongs to Wallet context; Identity stores only references.

### 3.2 Catalog Context
Responsibilities:
- Normalize and maintain tradable CS2 skin metadata.
- Provide stable identifiers and attributes for pricing and search.

Key concepts:
- CatalogItem, ItemAttributes, Rarity, WearRange.

### 3.3 Inventory Context
Responsibilities:
- Represent ownership and availability of sellable items.
- Track whether a specific item instance is available, reserved, or transferred.

Key concepts:
- InventoryItem (instance), Ownership, Reservation.

Boundary:
- Steam is external. Inventory Context models internal truth about tradability and reservation decisions.

### 3.4 Listings Context
Responsibilities:
- Create and manage listings.
- Enforce listing invariants (price bounds, seller eligibility, item availability).

Key concepts:
- Listing aggregate.

### 3.5 Orders Context
Responsibilities:
- Create orders from listings.
- Drive the order state machine (reserve item, await payment, fulfill, complete, cancel).
- Handle timeouts and idempotency.

Key concepts:
- Order aggregate, OrderState, CancellationReason.

### 3.6 Payments Context
Responsibilities:
- Create payment intents for crypto.
- Confirm on-chain payment and link it to an order.
- Support BTC, ETH, TON with network-specific confirmation rules.

Key concepts:
- PaymentIntent, PaymentReceipt, ConfirmationPolicy.

### 3.7 Settlement and Ledger Context
Responsibilities:
- Compute and execute settlement outcomes:
  - Seller payout
  - Platform fee collection
  - Buyer refund if needed
- Maintain double-entry ledger records for internal accounting.

Key concepts:
- Settlement aggregate, LedgerEntry, Balance, FeePolicy.

### 3.8 Risk and Compliance Context
Responsibilities:
- Risk evaluation and decisioning (allow, hold, block).
- Dispute management workflow.
- Policy enforcement.

Key concepts:
- RiskAssessment, RiskDecision, DisputeCase.

### 3.9 Audit Context
Responsibilities:
- Immutable audit trails for critical events.
- Evidence links (hashes, references) for disputes and compliance.

Key concepts:
- AuditRecord, EvidenceRef.

## 4. Context Map (High-Level)

- Identity -> Orders: provides User status and eligibility signals.
- Catalog -> Listings: provides item metadata for listing creation.
- Inventory -> Listings: validates item availability and locks reservations.
- Listings -> Orders: order creation from active listing.
- Orders -> Payments: requests payment intent, listens for confirmation.
- Orders -> Settlement: triggers settlement after fulfillment.
- Settlement -> Ledger: writes authoritative ledger entries.
- Risk -> Orders/Payments: may hold or block actions.
- Audit listens to domain events from all contexts.

## 5. Aggregates and Domain Objects

### 5.1 Identity Context

#### Aggregate: User
- Aggregate Root: User
- Entities:
  - SteamLink (optional)
- Value Objects:
  - UserId, Login, PasswordHash, UserStatus

UserStatus:
- Active
- Restricted
- Banned

Invariants:
- Login is unique.
- PasswordHash is never reversible.
- Banned users cannot create listings or orders.

### 5.2 Catalog Context

#### Aggregate: CatalogItem
- Aggregate Root: CatalogItem
- Value Objects:
  - CatalogItemId, MarketName, ItemAttributes, WearRange, Rarity

Invariants:
- CatalogItemId is stable.
- MarketName normalization is deterministic and unique per rules.

### 5.3 Inventory Context

#### Aggregate: InventoryItem
Represents a specific tradable instance.
- Aggregate Root: InventoryItem
- Value Objects:
  - InventoryItemId, OwnerUserId, CatalogItemId, ItemState

ItemState:
- Available
- Reserved
- Transferring
- Transferred
- Unavailable

Invariants:
- Only Available can transition to Reserved.
- Reserved must be tied to exactly one OrderId.
- Transferred is terminal.

### 5.4 Listings Context

#### Aggregate: Listing
- Aggregate Root: Listing
- Entities:
  - ListingPrice
- Value Objects:
  - ListingId, SellerUserId, InventoryItemId, Price, Currency, ListingState, Expiration

ListingState:
- Draft
- Active
- Paused
- Sold
- Cancelled
- Expired

Invariants:
- Active listing must reference an InventoryItem in Reserved or Available state as per policy.
- Listing currency must be supported (BTC, ETH, TON) or a configured quote currency if using conversion.
- Seller must be Active and eligible.

### 5.5 Orders Context

#### Aggregate: Order
- Aggregate Root: Order
- Entities:
  - OrderLine (single listing for MVP, extensible to multiple later)
- Value Objects:
  - OrderId, BuyerUserId, SellerUserId, ListingId, Money, OrderState, Deadlines

OrderState:
- Created
- AwaitingPayment
- PaymentConfirmed
- FulfillmentInProgress
- Completed
- Cancelled
- Refunded
- Disputed

Invariants:
- Order is created from exactly one ListingId (MVP).
- Buyer and Seller cannot be the same user.
- An order in Completed cannot transition to other states.
- Cancellation rules depend on state and payment status.

### 5.6 Payments Context

#### Aggregate: PaymentIntent
- Aggregate Root: PaymentIntent
- Value Objects:
  - PaymentIntentId, OrderId, Amount, Currency, Address, Network, PaymentState, ConfirmationDepth

PaymentState:
- Created
- AwaitingOnChain
- Confirmed
- Failed
- Expired

Invariants:
- Exactly one PaymentIntent per Order per attempt; retries create a new intent with linkage.
- Confirmed payment must reference an immutable on-chain receipt.

### 5.7 Settlement and Ledger Context

#### Aggregate: Settlement
- Aggregate Root: Settlement
- Value Objects:
  - SettlementId, OrderId, SettlementState, FeeBreakdown

SettlementState:
- Pending
- Executing
- Completed
- Failed
- Reversed

FeeBreakdown:
- PlatformFee (up to 18 percent)
- NetworkFees (variable)
- OtherExternalFees (optional)

Invariants:
- PlatformFeePercent must be within configured bounds and never exceed 18 percent.
- Settlement sum must balance: BuyerPaid = SellerPayout + PlatformFee + ExternalFees + Refunds.

#### Entity: LedgerEntry
- Double-entry style:
  - debit account
  - credit account
  - amount
  - currency
  - reference (OrderId, SettlementId)

Invariants:
- Ledger entries are append-only.
- Every transaction is balanced within the ledger system.

## 6. State Machines

### 6.1 Listing State Machine
Draft -> Active
Active -> Paused
Paused -> Active
Active -> Sold
Active -> Cancelled
Active -> Expired
Paused -> Cancelled
Draft -> Cancelled

Rules:
- A listing can become Sold only via an Order reaching PaymentConfirmed and item reserved to that order.
- Expiration occurs automatically after Expiration deadline.

### 6.2 Order State Machine
Created -> AwaitingPayment
AwaitingPayment -> PaymentConfirmed
PaymentConfirmed -> FulfillmentInProgress
FulfillmentInProgress -> Completed

Cancellation and exceptions:
AwaitingPayment -> Cancelled (timeout or buyer cancel)
PaymentConfirmed -> Cancelled (only by policy, typically not allowed without refund path)
PaymentConfirmed -> Refunded (if fulfillment fails)
Any state -> Disputed (when dispute opened by buyer/seller)
Disputed -> Completed or Refunded (dispute resolution outcome)

### 6.3 PaymentIntent State Machine
Created -> AwaitingOnChain
AwaitingOnChain -> Confirmed
AwaitingOnChain -> Expired
AwaitingOnChain -> Failed

Rules:
- Confirmed requires meeting network confirmation policy.

## 7. Domain Events

Events are immutable facts published by aggregates. They are the primary integration mechanism between contexts.

Naming convention:
Context.Aggregate.EventName

### 7.1 Identity Events
- Identity.UserRegistered
- Identity.UserStatusChanged
- Identity.SteamLinked
- Identity.SteamUnlinked

### 7.2 Catalog Events
- Catalog.CatalogItemCreated
- Catalog.CatalogItemUpdated

### 7.3 Inventory Events
- Inventory.ItemReserved
- Inventory.ItemReservationReleased
- Inventory.ItemTransferStarted
- Inventory.ItemTransferred
- Inventory.ItemMarkedUnavailable

### 7.4 Listings Events
- Listings.ListingCreated
- Listings.ListingActivated
- Listings.ListingPaused
- Listings.ListingCancelled
- Listings.ListingExpired
- Listings.ListingSold

### 7.5 Orders Events
- Orders.OrderCreated
- Orders.OrderAwaitingPayment
- Orders.OrderPaymentConfirmed
- Orders.OrderFulfillmentStarted
- Orders.OrderCompleted
- Orders.OrderCancelled
- Orders.OrderRefunded
- Orders.OrderDisputeOpened
- Orders.OrderDisputeResolved

### 7.6 Payments Events
- Payments.PaymentIntentCreated
- Payments.PaymentOnChainDetected
- Payments.PaymentConfirmed
- Payments.PaymentExpired
- Payments.PaymentFailed

### 7.7 Settlement and Ledger Events
- Settlement.SettlementStarted
- Settlement.SettlementCompleted
- Settlement.SettlementFailed
- Ledger.LedgerEntryPosted

### 7.8 Risk and Compliance Events
- Risk.RiskAssessmentCompleted
- Risk.RiskDecisionApplied
- Risk.DisputeCaseOpened
- Risk.DisputeCaseClosed

### 7.9 Audit Events
- Audit.AuditRecordWritten

## 8. Commands and Policies

### 8.1 Core Commands (MVP)
Identity:
- RegisterUser(login, password)
- Authenticate(login, password)
- LinkSteamAccount(userId, steamAuthProof)

Catalog:
- UpsertCatalogItem(marketName, attributes)

Inventory:
- SyncInventoryFromSteam(userId, snapshot)
- ReserveInventoryItem(inventoryItemId, orderId)
- ReleaseReservation(inventoryItemId, orderId)

Listings:
- CreateListing(sellerId, inventoryItemId, price, currency, expiration)
- ActivateListing(listingId)
- PauseListing(listingId)
- CancelListing(listingId)

Orders:
- CreateOrder(buyerId, listingId)
- CancelOrder(orderId, reason)
- MarkFulfillmentStarted(orderId)
- CompleteOrder(orderId)
- FailFulfillment(orderId, reason)

Payments:
- CreatePaymentIntent(orderId, amount, currency)
- ConfirmPayment(paymentIntentId, onChainReceipt)

Settlement:
- StartSettlement(orderId)
- ReverseSettlement(settlementId, reason)

Risk:
- EvaluateRisk(orderId)
- OpenDispute(orderId, initiator, reason)

### 8.2 Policies (Domain Rules as Reactions to Events)

Policy: On Orders.OrderCreated
- Reserve inventory item.
- Transition order to AwaitingPayment.
- Emit Orders.OrderAwaitingPayment.

Policy: On Payments.PaymentConfirmed
- Transition order to PaymentConfirmed.
- Start fulfillment.
- Emit Orders.OrderFulfillmentStarted.

Policy: On Orders.OrderCompleted
- Start settlement.
- Emit Settlement.SettlementStarted.

Policy: On Settlement.SettlementCompleted
- Mark listing as Sold.
- Release any remaining locks.
- Emit Listings.ListingSold.

Policy: On Risk.RiskDecisionApplied(block)
- Cancel or hold order depending on state, initiate refund path if payment already confirmed.

## 9. Invariants and Consistency Rules

### 9.1 Money and Fee Invariants
- Platform fee percent is configured and must never exceed 18 percent.
- Fee computation uses exact decimal arithmetic by currency rules.
- All money movements must be reflected in the Ledger.
- Settlement must satisfy balancing equation:
  BuyerPaid = SellerPayout + PlatformFee + ExternalFees + Refunds

### 9.2 Reservation and Concurrency
- A given InventoryItem can be reserved by at most one active order at a time.
- Reservation has a deadline aligned with Order payment deadline.
- Idempotency keys are required for external callbacks (payment confirmations, Steam transfer updates).

### 9.3 Authorization and Eligibility
- Only Active users can list or buy.
- Restricted users may browse but cannot transact.
- Banned users cannot transact and may be blocked from login depending on policy.

### 9.4 Auditability
- Every state change in Orders, Payments, Settlement writes an AuditRecord.
- AuditRecords are append-only.

## 10. Data Ownership and Integration Contracts

### 10.1 Ownership
- Identity owns user status and Steam linking.
- Catalog owns catalog item definitions.
- Inventory owns item instance state and reservations.
- Listings owns listing state and pricing terms.
- Orders owns order lifecycle and deadlines.
- Payments owns payment intents and receipts.
- Settlement and Ledger owns internal accounting and fee finalization.
- Risk owns risk decisions and disputes.
- Audit owns immutable records.

### 10.2 Event Payload (Reference Shape)
All events follow a common envelope:

```json
{
  "event_id": "uuid",
  "event_type": "Orders.OrderCreated",
  "occurred_at": "2026-02-13T12:00:00Z",
  "aggregate_id": "order_id",
  "correlation_id": "uuid",
  "causation_id": "uuid",
  "actor": {
    "type": "user|system",
    "id": "user_id_or_system"
  },
  "data": {}
}
