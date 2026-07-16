# ADR 0002: Modular Monolith Strategy

Status: Accepted
Date: 2026-03-22
Deciders: Architecture / Platform Leadership
Technical Story: Reva Studio requires a production-grade architecture for a Beauty SaaS platform with booking, loyalty, notifications, analytics, catalog, staff, and future partner expansion.

## Context

Reva Studio is being built as a production-grade Beauty SaaS platform with the following business and technical requirements:

1. Fast delivery of the first production version for a real beauty business with a limited initial team size.
2. High correctness for booking flows, loyalty calculations, staff schedules, reminders, and payments-related states.
3. Ability to evolve toward multi-tenant SaaS, marketplace flows, partner integrations, and AI-assisted features.
4. Low operational overhead at the initial stage.
5. Clear internal boundaries so that the codebase does not degrade into a tightly coupled "big ball of mud".

Martin Fowler explicitly recommends starting with a monolith in many cases because the main early difficulty is not deployment distribution but discovering the right domain boundaries and keeping change inexpensive. Fowler also describes the modular monolith as a valid architecture where internal module boundaries are treated seriously even though deployment remains a single unit. 

According to microservices.io, one of the core problems that architecture must solve is defining stable service or domain boundaries; premature distribution increases operational complexity, including deployment, observability, testing, data consistency, and runtime coordination. 

For the current stage of Reva Studio, the highest-value tradeoff is to preserve strict modular boundaries inside a single deployable backend.

## Decision

We adopt a modular monolith as the target architecture for Reva Studio.

This means:

- One primary backend deployable unit for the business application.
- One shared PostgreSQL database cluster for the application at the current stage.
- Strictly separated business modules inside the codebase.
- Module interaction through explicit application contracts, not arbitrary cross-imports into other modules' internal implementation.
- No direct assumption that "same process" means "free access".
- Design for future extraction of selected modules into services only when operational and domain evidence justifies it.

The architectural principle is:

"A single deployable system with hard internal boundaries."

## Why this decision was made

### 1. Domain boundaries are still being shaped

The system includes domains such as:

- users
- staff
- services_catalog
- bookings
- loyalty
- notifications
- payments
- analytics
- promotions
- tenant management

At this stage, the exact runtime scaling and extraction boundaries are not yet proven by production load and organizational pressure. Fowler's "Monolith First" guidance directly supports this choice: start simple, discover boundaries through real usage, then split only where justified. 

### 2. Transactional consistency matters

Booking creation, time-slot reservation, staff availability validation, loyalty accrual, and notification scheduling involve highly coordinated state transitions. PostgreSQL provides strong transactional guarantees, and using one database inside a modular monolith keeps these flows simpler and more reliable at the early stage. PostgreSQL documents ACID transactions and explicit transactional control, which is directly relevant for booking and financial-adjacent correctness. 

### 3. Operational overhead must remain controlled

Distributed systems add network failures, retries, idempotency concerns, tracing requirements, contract versioning, independent deployment coordination, and data consistency challenges. Those costs are real before the benefits materialize. microservices.io documents these kinds of distributed-data and service-collaboration concerns as central architectural forces in microservices systems. 

### 4. The product still needs fast iteration

A modular monolith allows a smaller team to evolve domain logic, admin features, Telegram integrations, scheduling, loyalty, analytics, and future AI-assistant functions quickly without early platform fragmentation. FastAPI is appropriate for building a single application with clearly separated routers, dependency injection, and modular package structure. SQLAlchemy supports explicit session control and repository/unit-of-work style integration in Python applications. 

## Architectural consequences

### Positive consequences

A modular monolith gives Reva Studio:

- simpler deployment and rollback
- easier local development
- simpler end-to-end testing
- simpler transactional workflows
- lower infrastructure overhead
- better speed of delivery in the early stage
- ability to keep domain boundaries explicit without paying the full price of distribution

These benefits are consistent with the tradeoffs described by Fowler and microservices.io. 

### Negative consequences

A modular monolith also has risks:

- modules may become coupled if boundaries are not enforced
- one deployment artifact can grow too large
- scaling is initially coarser than independently deployed services
- teams may misuse shared database access across modules
- "temporary shortcuts" can destroy modularity faster than in a service architecture

These are known failure modes of poorly governed monoliths and are the reason this ADR defines strict module rules.

## Module strategy

The application must be organized around business modules, not technical layers alone.

Initial strategic module set:

- identity_access
- users
- staff
- services_catalog
- bookings
- loyalty
- notifications
- promotions
- analytics
- payments
- integrations
- platform

Each module owns its own:

- domain model
- application services / use cases
- repository interfaces
- internal policies and invariants
- API contracts exposed to other modules
- migrations or database objects attributable to that module
- tests

A module may depend only on:

1. shared kernel abstractions explicitly approved by architecture
2. its own internals
3. public contracts of another module

A module must not depend on:

1. internal repositories of another module
2. internal ORM models of another module
3. direct table manipulation owned by another module
4. cross-module "utility shortcuts" that leak business semantics

## Code-level boundary rules

The codebase must follow these rules.

### Rule 1. Public interface per module

Every module must expose a narrow public API surface. Other modules may call only that surface.

Example pattern:

```text
src/modules/bookings/
  domain/
  application/
  infrastructure/
  api/
  public.py