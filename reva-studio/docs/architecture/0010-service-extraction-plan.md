# ADR 0010: Service Extraction Plan

## Status

Accepted

## Date

2026-03-22

## Owners

- Architecture
- Backend Platform
- DevOps
- Product Engineering

---

## Context

Reva Studio is being developed as a production-grade beauty SaaS platform with the potential to evolve into a multi-tenant system for many salons. The current strategic direction is to keep the system maintainable, secure, observable, and economically viable while preserving delivery speed.

At the current stage, the platform should not be split into many microservices prematurely. Early fragmentation would increase operational cost, deployment complexity, debugging difficulty, data consistency risk, and team coordination overhead. Therefore, the base architectural strategy remains:

- modular monolith first
- strict domain boundaries
- explicit contracts between modules
- asynchronous workflows where justified
- observability and extraction-readiness from day one

This ADR defines a controlled extraction plan so that the system can start as a modular monolith and later evolve into separate services only when objective technical or business signals justify it.

---

## Decision

We will use a phased service extraction strategy.

The system starts as a modular monolith with isolated business modules, shared platform capabilities, and explicit internal interfaces. Service extraction is allowed only when a module meets predefined extraction criteria.

The first production architecture target is not microservices everywhere. The first target is:

- one deployable backend application
- one database cluster
- one Redis cluster
- asynchronous task processing
- strict module boundaries inside the codebase
- clear separation between domain, application, infrastructure, and interfaces
- event-ready integration model

Extraction will follow a staged path:

1. Modular monolith with extraction-ready contracts
2. Internal async boundaries via jobs and domain events
3. Externalized workers for high-load or isolated processing
4. Service extraction for selected bounded contexts
5. Platform-level service mesh and independent scaling only where justified

---

## Architectural Goals

The extraction plan must support the following goals:

- preserve delivery speed in the early product stage
- minimize accidental distributed-system complexity
- allow safe scaling of load-heavy modules
- isolate security-sensitive responsibilities
- improve fault containment where needed
- maintain transactional correctness for booking and payments
- support future multi-tenant SaaS evolution
- keep local development simple
- keep production operations predictable

---

## Non-Goals

This ADR does not mandate immediate extraction of all modules.

This ADR does not introduce:

- distributed transactions across all modules
- a full event-sourced architecture
- Kubernetes-only deployment as a hard requirement
- multiple databases per module at the current stage
- premature team-per-service ownership

---

## Current Baseline

The target baseline architecture before extraction is:

- `backend/` or equivalent application runtime as the main deployable unit
- modular domain structure
- async Python stack
- PostgreSQL as the system of record
- Redis for cache, broker, rate limiting, and ephemeral coordination
- Celery or equivalent async execution for background jobs
- HTTP API for admin, staff, clients, integrations
- Telegram bot integration
- observability hooks from the start

Modules are expected to be isolated by business capability, for example:

- identity and access
- users and profiles
- staff
- services catalog
- bookings
- loyalty
- payments
- notifications
- media
- analytics
- audit and compliance
- tenant management

---

## Extraction Principles

### 1. Domain boundaries before process boundaries

A module cannot become a service if its business responsibility is not clearly bounded.

### 2. Stable contracts before deployment separation

A module must expose stable commands, queries, events, and error semantics before it can be extracted.

### 3. Extraction for reason, not fashion

A service may be extracted only if there is a measurable need.

### 4. Data ownership must be explicit

Each extracted service must own its write model and data lifecycle.

### 5. Synchronous calls are minimized across service boundaries

Critical workflows should avoid fragile chains of synchronous inter-service dependency.

### 6. Observability is mandatory before extraction

A module that cannot be measured, traced, and debugged must not be extracted.

### 7. Reversibility matters

The extraction plan must avoid irreversible decisions until the product and traffic patterns justify them.

---

## Extraction Criteria

A module becomes a candidate for service extraction only if several of the following conditions are true.

### Functional criteria

- the module represents a clear bounded context
- the module has low conceptual overlap with other modules
- the module has explicit internal contracts already in place
- the module can tolerate eventual consistency where needed

### Operational criteria

- the module requires independent scaling
- the module has a different runtime profile from the main application
- the module creates deployment bottlenecks for the monolith
- the module causes unacceptable blast radius during failures

### Data criteria

- the module can own its data without constant cross-module joins
- transactional boundaries can be localized
- reporting dependencies can be served via read models or replicated views

### Security and compliance criteria

- the module handles secrets, payments, or sensitive actions requiring stronger isolation
- access control and audit obligations justify process or network isolation

### Team and delivery criteria

- the module has enough change frequency to justify independent release cadence
- the ownership model is mature enough for separate lifecycle management

### Anti-criteria

A module must not be extracted if:

- extraction is based only on anticipated future scale
- module boundaries are still unstable
- the team lacks observability and operational maturity
- the workflow depends on many cross-module synchronous calls
- data consistency would degrade beyond acceptable business limits

---

## Service Extraction Readiness Checklist

A module is extraction-ready only when all items below are true:

- clear business owner exists
- bounded context documented
- internal API contract documented
- domain events documented
- failure modes documented
- SLO and error budget defined
- health checks implemented
- structured logs implemented
- metrics implemented
- traces implemented
- retry and idempotency strategy defined
- timeout strategy defined
- authorization model defined
- audit requirements defined
- data ownership defined
- migration rollback plan defined
- local development strategy defined
- CI and smoke tests defined
- load expectations documented

---

## Recommended Extraction Order

The following order is recommended for Reva Studio.

### Phase 0. Keep inside modular monolith

These modules should remain inside the main application initially:

- identity and access
- users and profiles
- staff
- services catalog
- bookings
- loyalty
- payments orchestration
- notifications orchestration
- tenant management

Reason:
These modules are deeply tied to product iteration speed, cross-domain consistency, and transactional correctness. In particular, bookings, loyalty, and payments often participate in tightly coupled business workflows.

### Phase 1. Extract processing-heavy or low-coupling workloads

Best first extraction candidates:

- notification delivery worker
- media processing
- reporting and analytics pipeline
- search indexing
- audit log shipping
- export and import jobs

Reason:
These capabilities usually have clearer async boundaries, different runtime profiles, and lower transactional coupling to the core write path.

### Phase 2. Extract security-sensitive or operationally distinct domains

Possible candidates:

- authentication provider or auth gateway
- payment gateway integration service
- webhook ingestion service
- anti-fraud or policy engine
- messaging gateway

Reason:
These modules may benefit from stronger isolation, stricter policy enforcement, or separate deployment cadence.

### Phase 3. Extract core business services only when scale and organization justify it

Possible later candidates:

- booking service
- loyalty service
- tenant service
- customer profile service

Reason:
These are core domains. Extracting them too early introduces consistency, orchestration, and debugging complexity. They should move out only when there is sustained evidence that the monolith is no longer the optimal boundary.

---

## Target Service Candidates

Below is the recommended target map.

### Candidate A: Notification Delivery Service

#### Responsibility

- email delivery
- SMS delivery
- Telegram delivery
- push delivery
- delivery retries
- template rendering pipeline if isolated

#### Why it is a good early candidate

- async by nature
- independently scalable
- low direct coupling to transactional writes
- easy to operate behind queues

#### Data ownership

- delivery attempts
- channel provider status
- message logs
- retry schedule
- template versions if included

---

### Candidate B: Media Processing Service

#### Responsibility

- image optimization
- resizing
- watermarking
- moderation hooks
- file validation
- CDN publishing pipeline

#### Why it is a good early candidate

- compute-heavy
- clear input and output boundaries
- failure isolation is useful
- separate scaling profile

---

### Candidate C: Reporting and Analytics Service

#### Responsibility

- dashboard aggregations
- periodic KPIs
- cohort reports
- retention reports
- salon performance exports

#### Why it is a good early candidate

- read-heavy
- batch-friendly
- does not need to sit in the critical write path
- can evolve toward read replicas or OLAP later

---

### Candidate D: Payment Integration Service

#### Responsibility

- external PSP integrations
- webhook ingestion
- reconciliation
- provider-specific retry logic
- payment state translation

#### Why extraction is conditional

This module is a strong isolation candidate, but it should be extracted only after payment flows stabilize. Too-early extraction may complicate booking confirmation workflows.

---

### Candidate E: Auth or Identity Edge Service

#### Responsibility

- login
- token issuance
- session policy
- device trust checks
- rate limiting
- security audit hooks

#### Why extraction is conditional

Auth isolation can improve security posture, but many early-stage products move faster with auth still inside the monolith. Extract only when policy, integrations, or scale justify it.

---

## Domain Interaction Model

Before extraction, modules interact in-process through explicit application services and domain events.

After extraction, interaction rules are:

- command-style interactions use synchronous APIs only when required for user-facing immediacy
- state propagation uses domain or integration events
- retries must be idempotent
- side effects must be observable
- long-running workflows should use async orchestration

Preferred interaction patterns:

- request-response for immediate validation and user-facing actions
- event publication for downstream side effects
- job queues for heavy background work
- outbox pattern for reliable event emission

---

## Data Strategy

### Initial strategy

At the modular monolith stage:

- one PostgreSQL cluster
- one logical database
- module-owned schemas or clear table ownership conventions
- no direct writes across module boundaries except through explicit application contracts

### Extraction strategy

When a module is extracted:

- it becomes the owner of its write model
- other modules stop writing to its tables
- cross-service reporting uses read models, events, or dedicated reporting flows
- dual-write patterns are prohibited unless protected by an outbox or equivalent reliability mechanism

### Migration rule

No service extraction may proceed without a documented data migration plan covering:

- source tables
- target schema
- backfill strategy
- consistency window
- cutover procedure
- rollback procedure

---

## Transaction Strategy

### Inside modular monolith

Use local ACID transactions for:

- booking creation
- schedule locking
- payment intent registration
- loyalty accrual decisions when part of booking completion flow
- audit persistence

### After extraction

Cross-service ACID is not assumed.

Instead use:

- local transaction per service
- outbox pattern for reliable event publication
- idempotent consumers
- compensating actions where business-acceptable
- explicit workflow states

Critical note:
The booking and payment relationship is business-critical. Until the team proves strong distributed workflow maturity, the booking write path should remain inside one deployable unit.

---

## Observability Requirements

A module cannot be extracted unless the following are already implemented:

### Logs

- structured JSON logs
- correlation IDs
- tenant ID when applicable
- actor ID when applicable
- request and job identifiers

### Metrics

- request rate
- latency
- error rate
- queue depth
- retry count
- task duration
- provider failure rate if integrations exist

### Tracing

- incoming request trace
- DB span visibility
- queue publish and consume spans
- downstream HTTP call spans

### Operational endpoints

- liveness
- readiness
- startup status where relevant

---

## Security Requirements

Every extracted service must implement:

- service-to-service authentication
- least-privilege credentials
- secret isolation
- network segmentation where available
- audit logging for sensitive actions
- rate limiting for exposed entry points
- idempotency protection for external callbacks
- signature validation for provider webhooks
- tenant isolation rules if multi-tenant data is touched

Modules dealing with payments, identity, or compliance-sensitive data require stronger hardening than general background workers.

---

## Deployment Strategy

### Stage 1

Single deployable application plus auxiliary workers.

Example:

- `api`
- `bot`
- `worker`
- `beat`
- `postgres`
- `redis`

### Stage 2

Add extracted async services behind queues.

Example:

- `notification-service`
- `media-service`
- `analytics-service`

### Stage 3

Add externally exposed specialized services only when justified.

Example:

- `payments-gateway-service`
- `auth-edge-service`
- `webhook-ingestion-service`

---

## Local Development Strategy

Local development must remain simple even as services are extracted.

Rules:

- default local mode should support monolith-first startup
- optional services should be enabled through profiles
- developers should be able to run core product flows without the full platform
- integration stubs or mocks are allowed for optional extracted services
- shared contracts must be versioned and tested in CI

---

## CI/CD Strategy

Before extraction:

- monorepo CI
- module-scoped test selection where possible
- contract tests for internal APIs
- migration tests
- smoke tests for core flows

After extraction:

- service-specific pipelines
- compatibility tests for contracts
- consumer-driven contract tests where useful
- deployment smoke tests
- rollback automation
- schema change safety checks

---

## Risk Analysis

### Risk 1. Premature microservice adoption

Impact:
High complexity, slow delivery, hidden operational cost.

Mitigation:
Keep modular monolith baseline until criteria are met.

### Risk 2. Broken transactional workflows

Impact:
Booking inconsistencies, incorrect payment state, loyalty drift.

Mitigation:
Do not extract tightly coupled transactional domains too early. Use outbox and idempotency when extraction happens.

### Risk 3. Cross-service debugging difficulty

Impact:
Longer incident resolution time.

Mitigation:
Mandatory tracing, correlation IDs, and service dashboards before extraction.

### Risk 4. Data ownership ambiguity

Impact:
Duplicate writes, inconsistent state, schema coupling.

Mitigation:
Explicit ownership map and migration plan before any cutover.

### Risk 5. Team operational overload

Impact:
Reduced productivity, unstable releases.

Mitigation:
Extract only a small number of high-value services first.

---

## Decision Rules for Reva Studio

The following rules are binding.

### Rule 1

Bookings remain in the modular monolith until all of the following are true:

- traffic and concurrency prove the need
- schedule consistency risks are fully modeled
- payment flow is operationally stable
- observability maturity is proven
- rollback playbooks are tested

### Rule 2

Payments may be partially isolated by adapter layer first, and only later extracted as a separate service.

### Rule 3

Notifications, media, exports, and analytics are the preferred first extraction candidates.

### Rule 4

No module may be extracted without an approved extraction dossier containing:

- business reason
- architecture diagram
- API contract
- event contract
- data ownership model
- migration plan
- rollback plan
- SLO definition
- security review

### Rule 5

One extracted service at a time. No parallel uncontrolled decomposition.

---

## Implementation Plan

### Step 1. Harden modular boundaries

- remove direct cross-module infrastructure access
- formalize application service interfaces
- formalize domain events
- define ownership per module

### Step 2. Add extraction-readiness infrastructure

- outbox support
- structured logs
- tracing
- queue conventions
- retry and idempotency utilities
- service contract templates

### Step 3. Extract the first low-risk async capability

Recommended first candidate:

- notification delivery service

Success criteria:

- no regression in booking flow
- independent deployability proven
- queue reliability proven
- observability proven

### Step 4. Extract second async capability

Recommended second candidate:

- media processing or analytics pipeline

### Step 5. Re-evaluate core-domain extraction

Only after operational maturity and product scale justify it.

---

## Recommended Technical Conventions

For every extracted service:

- separate container image
- dedicated config namespace
- dedicated health endpoints
- own migration path if it owns data
- explicit API schema
- explicit event schema
- strict timeout and retry policy
- no hidden dependency on monolith internals

For every event:

- unique event type
- version field
- event ID
- occurred-at timestamp
- correlation ID
- causation ID where relevant
- tenant ID where relevant

For every synchronous service call:

- request timeout
- retry policy only for safe operations
- idempotency strategy where needed
- circuit breaking at client side when appropriate

---

## Consequences

### Positive consequences

- faster early-stage delivery
- lower operational overhead
- safer path to future scale
- cleaner domain ownership
- controlled extraction instead of chaotic rewrite
- better balance between product speed and platform quality

### Negative consequences

- some modules will remain coupled at deployment level for a period
- some scale problems will initially be solved vertically rather than through independent services
- architecture discipline is required to keep monolith boundaries clean

### Accepted trade-off

We accept temporary deployment coupling in exchange for delivery speed, transactional correctness, and architectural control.

---

## Extraction Readiness Scorecard

Each candidate module should be scored from 0 to 5 in each category:

- bounded-context clarity
- contract maturity
- observability maturity
- data ownership clarity
- security isolation need
- runtime isolation need
- deployment independence need
- team ownership maturity

Suggested interpretation:

- 0 to 15: do not extract
- 16 to 24: prepare internally
- 25 to 32: pilot extraction possible
- 33 to 40: extraction justified

---

## Initial Recommendation for Reva Studio

At the current Reva Studio stage, the recommended architecture is:

- keep the core product as a modular monolith
- invest heavily in module boundaries and observability
- prepare contracts and async patterns now
- extract only low-risk, high-separation workloads first
- delay extraction of bookings, loyalty, and core customer flows until objective scale and operational maturity justify it

Recommended first extraction sequence:

1. notification delivery
2. media processing
3. analytics and exports
4. payment integrations
5. auth edge if needed
6. booking or loyalty only much later if clearly justified

---

## Related ADRs

- 0001-system-overview
- 0002-modular-monolith-strategy
- 0003-tenancy-model
- 0004-auth-and-rbac
- 0005-booking-consistency
- 0006-payments
- 0007-observability-baseline
- 0008-async-jobs-and-events
- 0009-deployment-environments

---

## Review Trigger

This ADR must be reviewed when any of the following happens:

- sustained production load growth changes scaling needs
- one module repeatedly becomes a deployment bottleneck
- one module requires stricter isolation for security or compliance
- tenant count or salon count grows materially
- team topology changes toward independent domain ownership
- distributed workflow maturity improves enough to support safe extraction

---

## Final Decision Summary

Reva Studio will not adopt broad microservice decomposition at the current stage.

Reva Studio will use a modular monolith as the primary architecture, but all major modules must be designed for future extraction.

Service extraction will be selective, criteria-based, observable, reversible where possible, and driven by business and operational evidence rather than anticipation alone.