# payments
# CSMarket Payments Specification

Status: Draft (implementation-ready)
Audience: backend, webapp, telegram bot, security, ops
Scope: Payment intent lifecycle, crypto rails (BTC, ETH, TON), optional Telegram Payments, reconciliation, refunds, auditability.

## 1. Goals

1. Provide a single, consistent payments lifecycle for CSMarket across:
   - Telegram bot UI
   - Telegram Mini App UI
   - Web UI (optional)
2. Support crypto payments:
   - Bitcoin on-chain (BTC)
   - Ethereum on-chain (ETH)
   - TON payments via wallet connection inside Telegram Mini Apps
3. Ensure:
   - Idempotency and replay-safety
   - Clear audit trail for every payment state transition
   - Deterministic reconciliation rules
   - Minimal trust in client-side data

Non-goals:
- Custodial wallet services are out of scope for this document.
- Exchange, trading, or fiat on-ramp flows are out of scope.

## 2. Supported payment rails

### 2.1 BTC on-chain (BIP-21)

Payment request links and QR codes MUST use the Bitcoin URI scheme defined by BIP-21 for interoperability. Source: Bitcoin Wiki BIP-21 page. :contentReference[oaicite:0]{index=0}

Reference guidance on BIP-21 usage in payment processing: Bitcoin Developer Guide. :contentReference[oaicite:1]{index=1}

CSMarket policy:
- Create payment intent server-side.
- Generate a BIP-21 URI (bitcoin:address?amount=... plus optional label/message if used).
- Display URI as text and QR.
- Mark payment as "pending_confirmations" after detecting an on-chain transaction.

### 2.2 ETH on-chain (EIP-681)

Payment request links and QR codes SHOULD use EIP-681 URL format for transaction requests. Source: Ethereum Improvement Proposal EIP-681. :contentReference[oaicite:2]{index=2}

CSMarket policy:
- Create payment intent server-side.
- Generate an EIP-681 URI for ETH transfers (and optionally ERC-20 if later needed).
- Display URI as text and QR.
- Mark payment as "pending_confirmations" after detecting an on-chain transaction.

### 2.3 TON inside Telegram Mini Apps (TON Connect)

TON Connect is the connection protocol used to communicate securely between wallets and apps; TON documentation describes it and states it is mandatory for Telegram Mini Apps. Source: TON documentation. :contentReference[oaicite:3]{index=3}

TON Connect protocol model documentation and SDK references:
- TON Connect protocol docs: :contentReference[oaicite:4]{index=4}
- TON Connect SDK repository reference: :contentReference[oaicite:5]{index=5}

CSMarket policy:
- For Mini App flows, connect wallet via TON Connect.
- Build a TON transaction request using TON Connect-compatible payloads.
- Payment confirmation:
  - Client returns a signed transaction or transaction submission confirmation.
  - Server verifies by querying chain and matching memo or payload-derived identifiers.
- The user remains in control of private keys; signing happens in the wallet UI (as per TON Connect model). :contentReference[oaicite:6]{index=6}

### 2.4 Optional: Telegram Bot Payments (fiat/card)

Telegram provides a Bot Payments platform for sellers; Telegram states it does not collect payment information and takes no commission. Source: Telegram Bot Payments docs. :contentReference[oaicite:7]{index=7}

Telegram also provides a dedicated page for digital goods and services via Bot Payments. Source: Telegram docs. :contentReference[oaicite:8]{index=8}

CSMarket policy (optional integration):
- Only if we decide to support provider-based payments.
- Invoices MUST be issued by server-side logic and verified via Telegram pre-checkout callbacks (implementation details belong to code, not this spec).

## 3. Payment domain model

All rails share the same canonical model.

### 3.1 Entities

PaymentIntent:
- id: UUID
- order_id: UUID (link to marketplace order)
- user_id: UUID
- rail: enum (BTC_ONCHAIN, ETH_ONCHAIN, TON_TONCONNECT, TG_PAYMENTS)
- asset: enum (BTC, ETH, TON)
- amount: decimal (asset-native)
- amount_fiat_quote: optional (for UI display only; not authoritative)
- receive_address: string (if applicable)
- network: string (btc-mainnet, eth-mainnet, ton-mainnet)
- expires_at: timestamp
- status: enum (see 3.2)
- idempotency_key: string
- metadata: jsonb
- created_at, updated_at

PaymentEvent (append-only):
- id: UUID
- payment_intent_id: UUID
- type: enum
- previous_status, new_status
- payload: jsonb (raw provider callbacks, chain tx data, verification results)
- created_at

### 3.2 Status machine

Canonical statuses:
- created
- awaiting_user_action
- pending_detection
- pending_confirmations
- succeeded
- failed
- expired
- cancelled
- refunded (optional, if refunds supported for that rail)

Allowed transitions (high level):
- created -> awaiting_user_action
- awaiting_user_action -> pending_detection
- pending_detection -> pending_confirmations
- pending_confirmations -> succeeded
- any -> failed (with reason)
- awaiting_user_action -> expired (if expires_at reached)
- awaiting_user_action -> cancelled (user cancels)
- succeeded -> refunded (if refund supported)

State transition rule:
- All transitions MUST be performed server-side and recorded as PaymentEvent.
- Client-side status displays are non-authoritative.

## 4. Server responsibilities (authoritative)

### 4.1 Idempotency

- PaymentIntent creation endpoint MUST require an Idempotency-Key header.
- The server MUST ensure the same key returns the same PaymentIntent for a given user and order.
- PaymentEvent insertion MUST be append-only; updates are disallowed except for internal operational fixes with audited admin trail.

### 4.2 Expiration

- expires_at is authoritative.
- Background reconciliation MUST mark intents as expired when the deadline passes and there is no eligible on-chain transaction.

### 4.3 Address allocation and reuse

Design decision:
- Prefer unique receive addresses per PaymentIntent where possible to reduce ambiguous reconciliation.
- If reuse is unavoidable, enforce unique memo/tag (TON) and strict matching on amount plus time window.

This is a project decision, not an external fact.

## 5. Confirmation and reconciliation rules

### 5.1 Detection sources

Design decision:
- Use a server-side indexer or trusted RPC provider per chain to detect inbound payments.
- Store raw transaction identifiers and verification results in PaymentEvent payload.

### 5.2 Matching algorithm (deterministic)

For each rail, define a strict matching rule:

BTC:
- Match by receive_address AND amount within tolerance AND first_seen_time within [created_at, expires_at + grace].
- Mark pending_confirmations when tx found.
- Mark succeeded when confirmations >= policy threshold.

ETH:
- Match by to_address AND value AND within time window.
- For tokens (future), match by contract address and Transfer event fields.

TON:
- Match by destination address AND payload or comment embedding payment_intent_id (or a derived nonce).
- Confirm by chain lookup of transaction hash returned by wallet.

All of the above are project rules, not external facts.

### 5.3 Confirmation thresholds

Design decision:
- Define per-asset confirmation requirements in config:
  - BTC confirmations_required
  - ETH confirmations_required
  - TON finality_rule (for example, block inclusion plus additional safety delay)
These thresholds are operational policy and MUST be configurable.

## 6. Security requirements

### 6.1 Threat model (minimal)

Relevant threats:
- Payment spoofing via forged client callbacks
- Replay attacks on payment creation endpoints
- Address substitution on client side
- Double-spend risk (chain-dependent)
- Race conditions causing duplicate order fulfillment

Controls:
- Server authoritative status machine only
- Idempotency keys on creation
- Strict signature verification for wallet-connected flows where applicable (TON Connect)
- Independent chain verification before marking succeeded
- Append-only audit trail (PaymentEvent)

TON Connect model emphasizes that wallets authorize transactions while keeping user control of keys. Source: TON documentation overview. :contentReference[oaicite:9]{index=9}

### 6.2 Data handling

Design decision:
- Store only what is required to reconcile and audit:
  - tx hash
  - block number
  - confirmations observed
  - provider callback payloads (for Telegram Payments)
- Do not store private keys in any server component.

## 7. Order fulfillment coupling

Design decision:
- Orders MUST NOT be fulfilled on "pending_detection".
- Fulfillment MUST happen only on:
  - payment_intent.status == succeeded
  - and an atomic transaction updates order state + writes PaymentEvent "fulfilled" (separate domain event recommended)

This is a project rule, not an external fact.

## 8. Refunds and chargebacks

Crypto rails:
- Refunds are operationally possible only by sending an outbound transaction; there is no built-in chargeback mechanism on-chain. This statement is a general property of typical on-chain transfers; however this document treats refunds as a project decision and does not rely on it as a verifiable claim.

Telegram Payments (optional):
- Refund/chargeback capabilities depend on provider and Telegram flow; implementation MUST follow Telegram Payments docs and provider docs. Telegram Payments entry points are documented by Telegram. :contentReference[oaicite:10]{index=10}

CSMarket policy:
- Refund support is optional and MUST be implemented behind an explicit admin workflow with audit events.

## 9. Observability and audit

Requirements:
- Every state transition writes a PaymentEvent record.
- Emit metrics:
  - payment_intents_created_total (by rail, asset)
  - payments_succeeded_total
  - payments_failed_total (by reason)
  - reconciliation_lag_seconds
- Structured logs MUST include:
  - payment_intent_id
  - order_id
  - rail
  - tx_hash (when known)

This is a project requirement.

## 10. API surface (logical)

Endpoints (logical, transport-agnostic):
- POST /payments/intents
- GET /payments/intents/{id}
- POST /payments/intents/{id}/cancel
- POST /payments/webhooks/telegram (optional)
- POST /payments/tonconnect/callback (if needed; server verification still required)

Responses MUST never claim "paid" unless server-side verification completed.

## 11. Implementation checklist

1. PaymentIntent storage and PaymentEvent append-only log
2. Idempotency middleware
3. URI generation:
   - BTC BIP-21 (source for scheme definition: BIP-21) :contentReference[oaicite:11]{index=11}
   - ETH EIP-681 (source: EIP-681) :contentReference[oaicite:12]{index=12}
4. TON Connect integration for Mini App flows (sources: TON docs, protocol docs) :contentReference[oaicite:13]{index=13}
5. Chain verification service (per rail)
6. Reconciliation worker (polling or event-driven)
7. Order fulfillment atomicity
8. Metrics and structured logs
9. Admin audit views (read-only) for payment investigations

End of document.
