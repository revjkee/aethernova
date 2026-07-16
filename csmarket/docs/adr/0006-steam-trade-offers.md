# 0006-steam-trade-offers
# ADR 0006: Steam Trade Offers Integration

Status: Accepted
Date: 2026-02-13
Owner: csmarket core team

## Context

csmarket needs a reliable, auditable mechanism to:
- observe incoming and outgoing Steam trade offers
- validate offer contents against internal order state
- accept or decline offers in a controlled way
- track offer lifecycle transitions for customer support, dispute handling, and compliance

Steam provides official Web API documentation and several support documents that describe trade offers and confirmations. However, some operations commonly used by trade bots are not described as official Web API methods for creating/sending offers.

Primary references used for this ADR:
- Steam Web API overview (Steamworks) https://partner.steamgames.com/doc/webapi_overview
- IEconService interface (Steamworks Web API reference) https://partner.steamgames.com/doc/webapi/ieconservice
- Steam trade offers support FAQ https://help.steampowered.com/en/faqs/view/1115-91C5-050C-1D60
- Steam trade and market confirmations FAQ https://help.steampowered.com/en/faqs/view/2E6E-A02C-5581-8904
- Valve Developer Community: Steam Web API, IEconService wiki page https://developer.valvesoftware.com/wiki/Steam_Web_API/IEconService
- Steam community developer entry page https://steamcommunity.com/dev
- Note about sending trade offers not being officially supported by Steam Web API (third party discussion) https://stackoverflow.com/questions/45029182/how-use-steam-api-send-tradeoffer

## Decision

We implement a Steam TradeOffers integration with the following constraints:

1. Official API usage for observing trade offers
- Use IEconService methods for retrieving trade offer lists and details where applicable.
- This is supported as part of Steamworks Web API reference and documented interfaces.
References:
- https://partner.steamgames.com/doc/webapi/ieconservice
- https://developer.valvesoftware.com/wiki/Steam_Web_API/IEconService

2. Sending trade offers is treated as non-official integration surface
- Steam Web API documentation does not clearly describe a supported method to create/send a trade offer from scratch.
- Therefore, any capability to create/send offers through Steam Community endpoints is classified as:
  - non-official
  - high risk for breakage
  - requires feature flags, strict observability, and fast rollback
Reference indicating this limitation:
- https://stackoverflow.com/questions/45029182/how-use-steam-api-send-tradeoffer

If csmarket requires sending offers, we isolate it behind a dedicated adapter boundary and do not depend on it for core marketplace correctness.

3. Confirmations are modeled as a first-class step
- Steam documents trade confirmations as part of the trade process.
References:
- https://help.steampowered.com/en/faqs/view/2E6E-A02C-5581-8904
- https://help.steampowered.com/en/faqs/view/1115-91C5-050C-1D60

We do not assume or document a specific programmatic confirmation protocol beyond what Valve support documents describe.
If additional implementation details are needed, they must be verified against authoritative sources.
If not verifiable: "Не могу подтвердить это".

## Architecture

### Components

1. trade-offers-core (csmarket)
Responsibilities:
- offer polling and state synchronization
- mapping Steam offers to internal Order and TradeSession aggregates
- validation rules and policy gating
- idempotent accept/decline orchestration
- event emission to observability and audit trails

2. steam-adapter (boundary)
Responsibilities:
- all Steam calls (official API and any non-official endpoints if enabled)
- request signing/auth handling and rate limit handling
- strict input validation and output normalization
- circuit breaking and backoff
- feature flags per operation type

3. secrets and identity
- store Web API keys and session secrets only in secret storage
- never log secrets
- rotate credentials on a schedule

Steam Web API overview indicates that protected methods require authentication and should be called from trusted backend applications.
Reference:
- https://partner.steamgames.com/doc/webapi_overview

### Data model

We model each Steam offer as an immutable snapshot plus a derived state machine.

Entities:
- SteamOfferSnapshot
  - offer_id
  - direction (incoming/outgoing)
  - partner_steamid
  - items_give, items_receive (normalized)
  - raw_payload_hash
  - seen_at
- OfferState
  - current_status (created, active, accepted, declined, expired, canceled, unknown)
  - last_transition_at
- OfferLink
  - internal_order_id
  - internal_user_id

State transitions are driven by observed Steam data.
The exact status set must be aligned with the official interface output of IEconService.
If any status field semantics are not confirmed by official documentation: "Не могу подтвердить это".
References for IEconService:
- https://partner.steamgames.com/doc/webapi/ieconservice
- https://developer.valvesoftware.com/wiki/Steam_Web_API/IEconService

### Flow

1. Polling and reconciliation
- periodic poll of offers via official interface where available
- reconcile snapshots and update OfferState
- emit events: OfferObserved, OfferStateChanged

2. Accept/decline
- accept/decline requests are idempotent using a command key:
  - command_id = hash(offer_id, intended_action, internal_order_id)
- write-ahead command record ensures at-least-once execution with safe retries

3. Confirmation handling
- system records "requires_confirmation" as a state derived from observed data and support-documented flow
- no undocumented assumptions about confirmation protocol are embedded in core logic
References:
- https://help.steampowered.com/en/faqs/view/2E6E-A02C-5581-8904

## Security and Compliance

1. Principle of least privilege
- limit Steam credentials to required scope
- keep trade operations in isolated service account

2. Secret handling
- Web API keys and any session secrets are stored only in a secret manager
- all logs and metrics must be scrubbed of tokens and cookies

3. Auditability
- every offer decision is recorded with:
  - who initiated (user or system)
  - policy decision inputs
  - timestamps
  - offer snapshot hash
- audit logs are immutable once written

4. Rate limiting and abuse controls
- adaptive throttling and exponential backoff
- circuit breaker on repeated errors
- per-user and per-partner controls to limit spam offers

Steam Web API is HTTP-based and includes protected methods requiring authentication.
Reference:
- https://partner.steamgames.com/doc/webapi_overview

## Operational Requirements

1. Observability
- metrics:
  - offers_polled_total
  - offer_state_changes_total
  - accept_decline_attempts_total
  - steam_errors_total by code/class
  - reconciliation_lag_seconds
- logs:
  - structured, correlation IDs
- tracing:
  - end-to-end traces for accept/decline commands

2. Rollback strategy
- feature flag for any non-official operations
- ability to disable sending offers instantly without redeploy

3. Failure modes
- Steam API or endpoint downtime
- partial data, delays in state changes
- confirmation-required delays

Trade process and confirmation step are described in Valve support documents.
References:
- https://help.steampowered.com/en/faqs/view/1115-91C5-050C-1D60
- https://help.steampowered.com/en/faqs/view/2E6E-A02C-5581-8904

## Alternatives Considered

1. Use only official Web API, do not send offers
- Pros: lower breakage risk, stays within documented surfaces
- Cons: may limit marketplace UX if outgoing offers are required

2. Use Steam Community endpoints for sending offers
- Pros: enables outgoing offers
- Cons: not clearly supported as official Web API, higher maintenance risk
Reference suggesting non-official status:
- https://stackoverflow.com/questions/45029182/how-use-steam-api-send-tradeoffer

3. Use third party libraries
- Pros: faster implementation
- Cons: adds dependency and may rely on undocumented behavior
Example documentation from a third party library exists, but it is not an authoritative Valve source:
- https://github.com/DoctorMcKay/node-steam-tradeoffer-manager/wiki/TradeOffer

We do not adopt third party libraries as the source of truth for protocol behavior.

## Consequences

1. csmarket correctness does not depend on non-official trade offer sending.
2. If sending is enabled, it is isolated behind steam-adapter with feature flags and rapid rollback.
3. The system prioritizes auditability, idempotency, and safety over aggressive automation.
4. Any step that cannot be supported by authoritative Valve documentation must be explicitly marked "Не могу подтвердить это" in implementation notes and must be gated.

## References

- Steam Web API Overview (Steamworks):
  https://partner.steamgames.com/doc/webapi_overview

- IEconService (Steamworks Web API reference):
  https://partner.steamgames.com/doc/webapi/ieconservice

- IEconService (Valve Developer Community wiki):
  https://developer.valvesoftware.com/wiki/Steam_Web_API/IEconService

- Steam Trade Offers FAQ:
  https://help.steampowered.com/en/faqs/view/1115-91C5-050C-1D60

- Trade and Market Confirmations FAQ:
  https://help.steampowered.com/en/faqs/view/2E6E-A02C-5581-8904

- Steam community developer page:
  https://steamcommunity.com/dev

- Note on lack of official send-tradeoffer API (third party discussion):
  https://stackoverflow.com/questions/45029182/how-use-steam-api-send-tradeoffer
