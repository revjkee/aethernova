# 0003-outbox-events
# 0003: Outbox Events (Transactional Outbox) for csmarket

Status: Accepted  
Date: 2026-02-13  
Deciders: csmarket core team  
Technical Story: Reliable domain event publishing from PostgreSQL transactions into message broker

## Context

csmarket is expected to:
- Persist business state changes in PostgreSQL.
- Publish domain events for downstream processing (indexing, notifications, analytics, risk checks, search, etc.).
- Remain correct under failures (process crash, broker outage, network partitions, deploy restarts).

Problem:
- Publishing an event to a broker and committing a DB transaction are not atomic operations.
- If we publish first and then commit, consumers may observe events for data that never committed.
- If we commit first and then publish, a crash can lose events and break downstream consistency.

We need a durable mechanism that guarantees that every committed state change that requires an event results in an event being eventually published.

Constraints:
- Primary storage: PostgreSQL.
- Backend stack: Python (FastAPI) with async SQLAlchemy.
- Broker may be introduced (Kafka, RabbitMQ, NATS, etc.), but the publishing contract must be broker-agnostic.
- Consumers must tolerate at-least-once delivery.

## Decision

Adopt Transactional Outbox Pattern:
- Within the same database transaction that changes business state, also insert an outbox record describing the domain event.
- A separate background publisher reads pending outbox records, publishes them to the broker, and marks them as published.
- Publishing is at-least-once; consumer idempotency is required.

This decision applies to all domain events that must not be lost and must reflect committed state.

## Definitions

- Domain Event: an immutable record of something that happened in the domain.
- Outbox Record: a DB row representing an event to be published.
- Publisher: a worker that polls the outbox table and publishes events to the broker.
- At-least-once: events may be delivered more than once; they must not be lost.
- Idempotent Consumer: a consumer that processes the same event multiple times without side effects duplication.

## Data Model

We store outbox events in PostgreSQL.

Table: outbox_events

Fields:
- id (uuid, PK): unique outbox record id.
- event_id (uuid, unique): stable domain event id used as idempotency key for consumers.
- event_type (text): semantic event name (e.g., "listing.created").
- aggregate_type (text): domain aggregate type (e.g., "listing").
- aggregate_id (text): aggregate identifier (string to avoid DB coupling).
- occurred_at (timestamptz): when event occurred in domain time.
- payload (jsonb): event body, including required data or references.
- headers (jsonb): metadata (schema version, correlation id, causation id).
- status (text): "pending" | "publishing" | "published" | "failed".
- publish_attempts (int): number of publish attempts.
- next_attempt_at (timestamptz): scheduled time for the next attempt (for backoff).
- last_error (text): last publish error summary (bounded length).
- locked_by (text): publisher instance id (for leasing).
- locked_at (timestamptz): lease start time.
- published_at (timestamptz): when marked published.
- created_at (timestamptz): row creation time.
- updated_at (timestamptz): row update time.

Recommended indexes:
- (status, next_attempt_at, occurred_at) for polling
- unique(event_id) for idempotency
- (locked_at) for lease recovery

Status transitions:
- pending -> publishing -> published
- pending -> failed (only if terminal)
- publishing -> pending (lease expired recovery)
- publishing -> failed (after max attempts or non-retryable error)

## Publishing Semantics

Publisher loop:
1. Select a batch of eligible records:
   - status = pending
   - next_attempt_at is null or <= now()
   - ordered by occurred_at asc
   - limit N
2. Acquire lease atomically:
   - update selected rows set status=publishing, locked_by=?, locked_at=now()
   - only if status is still pending
3. Publish each event to broker:
   - Use event_id as message key / dedup key where supported
   - Include headers: correlation_id, causation_id, schema_version
4. On success:
   - update row status=published, published_at=now(), updated_at=now(), clear lock fields
5. On retryable error:
   - increment attempts
   - set status=pending
   - compute next_attempt_at using exponential backoff with jitter
   - store last_error (bounded)
   - clear lock fields
6. On non-retryable error or attempts exceeded:
   - set status=failed
   - store last_error
   - clear lock fields

Batching:
- Default batch size N should be configurable.
- Publishing should be sequential per partition key or aggregate if ordering is required.
- Parallel publishing is allowed if order is not required.

Ordering:
- Outbox preserves order per database commit time (occurred_at).
- Broker ordering depends on broker configuration (partitioning / routing).
- If strict ordering per aggregate is required, we must use a deterministic message key of aggregate_id.

## Lease and Concurrency

Multiple publisher instances may run concurrently.

Lease rules:
- A publisher claims rows using a lease to avoid duplicate in-flight publishing.
- Lease timeout must exist (e.g., 60 seconds) to recover from crashes.

Recovery:
- Periodic job resets stuck rows:
  - where status=publishing and locked_at < now() - lease_timeout
  - set status=pending, clear lock fields, set next_attempt_at=now()
This ensures liveness.

Isolation:
- Row updates must be atomic.
- Use SELECT FOR UPDATE SKIP LOCKED where supported to reduce contention.
- Ensure transactions are short.

## Consumer Idempotency

Because at-least-once delivery may duplicate events:
- Each event carries event_id (uuid) as immutable idempotency key.
- Consumers must store processed event_ids in their own dedup store or use broker features.

Minimum consumer requirement:
- Before applying side effects, check if event_id was processed.
- If processed, skip.

## Payload Contract and Versioning

Schema:
- payload must include:
  - schema_version (int)
  - core fields required for downstream work
- headers should include:
  - correlation_id (uuid or string)
  - causation_id (uuid or string)
  - producer (service name)
  - produced_at (timestamptz)

Versioning:
- schema_version increments on breaking changes.
- Consumers must support at least the current and previous version during rollouts.

Size:
- Avoid storing oversized payloads.
- If event requires large data, store references (IDs) and allow consumers to fetch from API.

## Failure Handling

Retry policy:
- Exponential backoff:
  - base delay: 1s
  - max delay: 5m
  - jitter: random 0-20%
- Max attempts configurable (e.g., 50).
- If exceeded, mark failed and alert.

Dead-letter handling:
- failed events must be visible and actionable.
- Provide tooling to:
  - inspect failed events
  - replay failed events after fixing the cause
  - force-publish if safe

Broker outage:
- Outbox grows while broker is down.
- Must monitor backlog size and age.

Database outage:
- Publisher stops; no data loss; resumes when DB returns.

## Observability and Operations

Metrics (minimum):
- outbox_pending_total (count of pending)
- outbox_publishing_total
- outbox_failed_total
- outbox_publish_latency_seconds (occurred_at to published_at)
- outbox_attempts_histogram
- outbox_backlog_age_seconds (oldest pending)

Logs:
- Structured logs per publish attempt:
  - event_id, event_type, aggregate_id, attempt, error_class, latency

Tracing:
- Propagate correlation_id and causation_id into broker headers to tie traces.

Alerts:
- failed_total increasing
- backlog_age above threshold
- publish_latency p95 above threshold
- pending_total above threshold

Runbook (high level):
- If failed_total increases: inspect last_error distribution, broker health, permissions, schema changes.
- If backlog_age increases: scale publisher, check broker throughput, check DB performance.

## Security and Compliance

- payload must not include secrets (private keys, credentials).
- Redact sensitive fields before writing to outbox.
- Access controls:
  - outbox table writable by app
  - outbox publisher read/update permissions
- Audit:
  - published_at and last_error retained for troubleshooting.

Retention:
- published events may be archived or deleted after retention period (e.g., 30 days) using a cleanup job.
- failed events kept longer until resolved.

## Implementation Notes

- Outbox insert must occur in the same transaction as the business write.
- Publisher must be separate from request path (no synchronous dependency on broker).
- Keep publisher id stable per instance (hostname + pid or generated uuid).

## Alternatives Considered

1. Dual-write (DB commit + broker publish in request path)
Rejected: cannot guarantee atomicity without distributed transaction; risk of lost or phantom events.

2. Two-phase commit with broker
Rejected: operational complexity and limited support.

3. CDC-based publishing (logical replication / Debezium)
Not chosen for MVP: powerful but adds infrastructure and operational overhead. Can be revisited later.

## Consequences

Positive:
- Strong guarantee: every committed change produces a durable event.
- Decouples domain writes from broker availability.
- Clear failure recovery and replay.

Negative:
- Additional storage and operational component (publisher).
- At-least-once requires idempotent consumers.
- Need monitoring for backlog and failures.
