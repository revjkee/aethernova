# AI Assistant Domain
Updated: 2026-03-23
Status: Draft
Scope: Reva Studio
Type: Domain specification

## 1. Purpose

This document defines the domain model, boundaries, use cases, architecture constraints, policies, and integration contract for the AI Assistant domain in Reva Studio.

The AI Assistant domain is responsible for intelligent user support inside the Reva Studio platform, including:

- conversational assistance for clients
- booking assistance
- service discovery and recommendation
- FAQ and policy explanation
- staff-side operational assistance
- escalation to human operator
- safe orchestration of external tools and platform actions

This document does not define transport-specific implementation details beyond required contracts.

## 2. Domain goal

The goal of the AI Assistant domain is to provide a controlled and auditable assistant layer that can:

- answer user questions
- guide users to the correct service or action
- reduce manual workload for studio staff
- improve booking conversion
- remain bounded by explicit platform policies
- avoid making unsafe, unauthorized, or unverifiable business decisions

## 3. Strategic role in Reva Studio

Project decision:

The AI Assistant is not the source of truth for bookings, pricing, schedules, or loyalty balances.

The source of truth remains in the corresponding business domains:

- bookings
- staff
- services catalog
- loyalty
- notifications
- users

The assistant may read, explain, suggest, and initiate actions only through approved application services.

## 4. External technical basis

The implementation is expected to rely on an async Python backend and typed schemas.

Relevant official technical capabilities:

- FastAPI is a modern high-performance Python web framework based on type hints and provides dependency injection and OpenAPI documentation generation. :contentReference[oaicite:0]{index=0}
- FastAPI supports `async def` path operations and documents async concurrency patterns. :contentReference[oaicite:1]{index=1}
- aiogram is a fully asynchronous Telegram Bot API framework; its Router supports update routing, and FSM support exists for multi-step conversational flows. :contentReference[oaicite:2]{index=2}
- Pydantic Settings supports loading configuration from environment variables and secrets files, which is appropriate for production configuration management. :contentReference[oaicite:3]{index=3}
- OpenAI Structured Outputs support JSON Schema-constrained responses, which is suitable when assistant output must match a strict machine-readable contract. :contentReference[oaicite:4]{index=4}

## 5. Domain boundaries

### 5.1 In scope

The AI Assistant domain includes:

- conversation session management
- intent detection
- response planning
- answer generation
- safe action proposal
- tool invocation policy
- structured response contracts
- escalation logic
- response audit trail
- prompt and policy versioning
- assistant-side context assembly

### 5.2 Out of scope

The AI Assistant domain does not own:

- booking persistence
- schedule calculation source data
- service pricing source data
- loyalty ledger
- payment execution
- staff payroll logic
- CRM source records
- legal policy ownership

Those concerns belong to their dedicated domains.

## 6. Design principles

Project decision:

1. Assistant is advisory first, transactional second.
2. Every state-changing action must pass through application services.
3. Every machine decision must be explainable at the audit level.
4. Every external call must be policy-gated.
5. Unsafe ambiguity must degrade to clarification or human escalation.
6. The assistant must not fabricate prices, availability, or policy terms.
7. The assistant must operate with bounded context, not raw unrestricted access.

## 7. Primary actors

### 7.1 Client
A beauty studio customer interacting through chat, Telegram bot, web widget, or future mobile channel.

### 7.2 Staff member
An internal studio operator, administrator, or master who needs assistance with operational workflows.

### 7.3 Human operator
A staff user who takes over when the assistant cannot safely complete or continue a flow.

### 7.4 System administrator
A privileged actor who configures policies, prompts, integrations, and audit access.

## 8. Core use cases

### 8.1 Client-facing use cases

- answer service-related questions
- explain available categories and procedures
- guide to booking flow
- collect required booking inputs
- propose relevant service options
- explain preparation rules before appointment
- explain cancellation or rescheduling conditions
- answer loyalty and bonus questions from system-of-record data
- escalate difficult or emotional cases to a human

### 8.2 Staff-facing use cases

- summarize client history for authorized staff
- draft standard responses
- explain internal operational procedures
- help find relevant service data
- assist with schedule-related explanations
- assist with scripted retention flows

### 8.3 Platform use cases

- classify intent
- normalize user input
- construct structured action proposals
- create audit entries
- emit telemetry events
- route unresolved sessions to escalation queue

## 9. Non-goals

The AI Assistant must not:

- modify bookings directly without application-service authorization
- invent service durations, prices, or staff availability
- promise discounts not present in current rules
- provide medical advice beyond approved studio policy wording
- expose hidden internal notes to clients
- execute privileged admin actions without RBAC validation
- rely on model text as system-of-record data

## 10. Capability map

### 10.1 Interpretation capabilities

- language detection
- intent recognition
- entity extraction
- ambiguity detection
- sensitivity detection
- escalation detection

### 10.2 Response capabilities

- concise text answer
- structured card response
- clarifying question generation
- recommended next action
- human handoff message
- refusal for unsupported or unsafe request

### 10.3 Tool-orchestrated capabilities

- check service catalog
- read booking availability through approved service
- retrieve loyalty summary through approved service
- create booking draft or booking request
- create escalation ticket
- log assistant interaction

## 11. Canonical intents

Project decision:

The assistant must classify incoming requests into a bounded intent catalog.

Recommended initial intent set:

- `faq.general`
- `faq.preparation`
- `faq.pricing`
- `faq.cancellation`
- `services.browse`
- `services.recommend`
- `booking.start`
- `booking.modify`
- `booking.cancel`
- `loyalty.balance`
- `loyalty.rules`
- `staff.assist`
- `support.escalation`
- `unknown`

## 12. Canonical entities

Recommended initial entity set:

- `service_id`
- `service_name`
- `category_name`
- `staff_id`
- `staff_name`
- `date`
- `time`
- `duration_minutes`
- `booking_id`
- `client_id`
- `bonus_balance`
- `branch_id`
- `channel`
- `language`
- `confidence_score`

## 13. Bounded context model

The AI Assistant domain consumes read models and approved service interfaces from other domains.

### 13.1 Upstream domains

- Users
- Bookings
- Staff
- Services Catalog
- Loyalty
- Notifications
- Policy/Knowledge content

### 13.2 Downstream effects

The assistant may request downstream actions only through application-level contracts such as:

- create booking draft
- confirm booking request
- schedule follow-up
- create escalation case
- create notification task

## 14. Source-of-truth policy

Project decision:

The assistant may speak about operational facts only when those facts are retrieved from authoritative services or approved static policy documents.

Authoritative data examples:

- service price from services catalog
- available time slots from booking availability service
- loyalty balance from loyalty domain
- cancellation wording from approved policy content

Non-authoritative sources:

- model memory
- prior conversational guess
- paraphrased undocumented staff rule
- stale cached text without freshness control

## 15. Response policy

The assistant response must always resolve into one of these outcomes:

1. direct answer
2. answer plus recommendation
3. clarification request
4. structured action proposal
5. escalation
6. refusal

Recommended response envelope:

```json
{
  "message": "string",
  "intent": "string",
  "confidence": 0.0,
  "outcome": "answer|clarify|propose_action|escalate|refuse",
  "action": null,
  "citations": [],
  "safety_flags": [],
  "requires_human": false
}