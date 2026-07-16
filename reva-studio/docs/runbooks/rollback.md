# Rollback Runbook

## Document Status

Accepted

## Version

1.0

## Last Updated

2026-03-23

## Owners

Platform Engineering
Backend
SRE
DevOps

## Purpose

Этот runbook описывает промышленную процедуру отката для Reva Studio.

Цели rollback-процедуры:

- быстро остановить деградацию сервиса
- минимизировать MTTR
- сократить blast radius
- сохранить корректность данных
- обеспечить воспроизводимые действия во время инцидента
- оставить проверяемый audit trail всех действий

Google SRE прямо рекомендует: если во время rollout обнаружено неожиданное поведение, нужно сначала откатить, а разбираться уже потом, чтобы минимизировать Mean Time to Recovery. :contentReference[oaicite:1]{index=1}

## Scope

Runbook покрывает rollback для:

- backend application release
- Kubernetes rollout
- feature flag rollback
- configuration rollback
- database migration rollback
- emergency mitigation без полного деплоя
- rollback после частичного инцидента или failed release

Runbook не покрывает:

- disaster recovery целого региона
- восстановление из полного backup после катастрофической потери данных
- форензик-расследование после security incident
- юридические и внешние коммуникации

## Definitions

### Rollback

Возврат системы к ранее известному стабильному состоянию.

### Roll-forward

Исправление проблемы новым безопасным изменением вместо возврата на старую версию.

### Kill switch

Аварийное отключение функции через feature flag без нового деплоя. LaunchDarkly документирует kill switch flags как permanent boolean flags для emergency shutoff. :contentReference[oaicite:2]{index=2}

### Reversible migration

Миграция БД, для которой существует корректный и проверенный путь `downgrade()`.

### Forward-fix-only migration

Миграция, которую по operational policy нельзя откатывать назад, и для неё разрешён только стабилизирующий roll-forward.

## Principles

1. Safety first.
2. Restore first, investigate second.
3. One incident commander.
4. One execution channel.
5. All commands are logged.
6. Any DB-impacting rollback must be explicitly classified before execution.
7. If data correctness is at risk, stop writes before rollback.
8. If rollback is slower than kill switch mitigation, use mitigation first.
9. If rollback cannot be proven safe, choose controlled containment and roll-forward plan.
10. Never improvise destructive commands on production without documented approval.

## Authoritative Basis

### Incident response

Google SRE recommends early incident declaration and structured incident management, and separately recommends supervised rollouts with rollback-first behavior when unexpected behavior appears. :contentReference[oaicite:3]{index=3}

### Kubernetes rollback

Kubernetes officially supports rollback through `kubectl rollout undo`, including rollback to previous deployment or a specific revision. :contentReference[oaicite:4]{index=4}

### Rolling updates

Kubernetes documents rolling updates as the standard deployment mechanism for zero-downtime style replacement of Pods. This matters because rollback interacts with the same rollout controller behavior. :contentReference[oaicite:5]{index=5}

### Database migrations

Alembic documents migration scripts via `upgrade()` and `downgrade()` functions. That means rollback policy must explicitly distinguish whether a production migration is approved for downgrade execution. :contentReference[oaicite:6]{index=6}

### Feature-flag mitigation

LaunchDarkly documents kill switch flags as emergency shutoff or circuit breaker flags, allowing risky features or flaky integrations to be disabled without redeploying code. :contentReference[oaicite:7]{index=7}

## Preconditions

Rollback may begin only when all required conditions below are either satisfied or explicitly waived by the incident commander.

### Required inputs

- incident id
- environment
- affected service list
- current deployed version
- last known good version
- deployment timestamp
- suspected failing change
- responsible rollout owner
- current severity
- rollback type
- approval record

### Required roles

- incident commander
- technical executor
- observer or recorder
- product or business approver for customer-facing impact if required
- DBA approver if database rollback is involved

### Required observability

- application health dashboard
- error rate dashboard
- latency dashboard
- saturation dashboard
- deployment history
- logs with correlation ids
- database health view
- queue depth view if async processing exists

## Rollback Classification

Every incident must classify rollback before any execution.

### Type A. Feature flag rollback

Use when:

- code is deployed successfully
- failure is isolated to a known feature path
- kill switch exists
- database schema remains compatible

Preferred action:

- disable the feature immediately
- validate recovery
- keep deployment in place if system stabilizes

### Type B. Configuration rollback

Use when:

- incident is caused by config, secret, environment variable, routing, or policy change
- previous stable config version is known
- app binary itself is not the problem

Preferred action:

- restore previous config
- restart or reload only if required
- validate health

### Type C. Application version rollback

Use when:

- new release introduces regressions
- previous release is known-good
- schema compatibility is preserved or dual-compatible

Preferred action:

- rollback deployment artifact
- validate app startup, readiness, background jobs, and external integrations

### Type D. Database migration rollback

Use only when:

- migration is explicitly marked reversible
- downgrade path has been tested
- data-loss risk is understood
- incident commander and DBA approve

Alembic supports `upgrade()` and `downgrade()` in migration scripts, but this does not by itself prove a given production downgrade is safe; the operational safety decision belongs to the team policy and tested migration plan. :contentReference[oaicite:8]{index=8}

### Type E. Roll-forward instead of rollback

Use when:

- rollback is impossible or unsafe
- state changes already require new corrective code
- migration is forward-fix-only
- external compatibility would break on revert

## Decision Matrix

### Choose feature flag rollback first when all are true

- feature flag exists
- issue is narrow
- blast radius can be stopped without binary rollback
- no schema incompatibility
- mitigation time is shorter than redeploy time

### Choose application rollback when all are true

- current image version is defective
- previous version is verified and available
- schema remains backward-compatible
- queues and workers can safely run old code

### Choose DB rollback only when all are true

- reversible migration confirmed
- downgrade tested
- no irreversible data transformation occurred, or recovery impact is explicitly accepted
- business approves the data risk
- DBA approves the operation

### Choose roll-forward when any are true

- downgrade unsafe
- old binary incompatible with current schema
- required hotfix is smaller and faster than full rollback
- data already requires corrective migration

## Severity Guidance

### SEV-1

Examples:

- full checkout outage
- booking creation unavailable for most users
- severe data corruption risk
- cascading production failures

Action:

- declare incident immediately
- mitigation in minutes, not hours
- use kill switch or rollback first
- freeze unrelated deployments

Google SRE states it is better to declare an incident early than delay incident management while the issue grows. :contentReference[oaicite:9]{index=9}

### SEV-2

Examples:

- materially increased error rate
- partial checkout failures
- background processing failures with user-visible lag

Action:

- rollback strongly preferred if linked to recent change
- choose lowest-risk path that restores SLO quickly

### SEV-3

Examples:

- degraded admin flows
- non-critical feature regression
- low blast radius issue with workaround

Action:

- feature flag mitigation may be sufficient
- app rollback optional depending on business impact

## Stop Conditions

Stop rollback immediately if any of the following occurs:

- rollback target version is not verified
- unexpected schema mismatch appears
- data loss risk becomes non-acceptable
- health degrades further during rollback
- rollback steps diverge from documented procedure
- required approver revokes authorization
- cluster or database control plane becomes unstable

## Production Safety Rules

1. Freeze new deployments to the affected environment.
2. Pause database schema changes.
3. Pause non-essential backfills and maintenance jobs.
4. Stop canary progression if active.
5. Capture current deployment state before changing anything.
6. Preserve logs, metrics windows, deployment revision ids, and current config hash.
7. Use a single operator for production-changing commands.
8. Use read-only observers for validation.

## Required Evidence to Capture Before Execution

- current git SHA
- current container image digest
- current Helm release revision or deployment revision
- current Alembic revision
- config version or secret version
- feature flag state
- alert snapshot
- error rate baseline
- customer impact statement
- rollback approval record

## Standard Rollback Workflow

### Step 1. Declare and coordinate

- declare incident if criteria are met
- assign incident commander
- create incident channel
- designate executor
- record timeline start

### Step 2. Stabilize blast radius

- stop progressive rollout
- disable traffic to affected canary if applicable
- activate kill switch if available
- disable problematic jobs or consumers if they amplify damage

### Step 3. Identify rollback class

Choose exactly one primary path:

- feature flag rollback
- config rollback
- app rollback
- DB rollback
- roll-forward

### Step 4. Validate rollback target

Must confirm:

- target version exists
- image is retrievable
- config artifact is retrievable
- migration state is known
- smoke test checklist exists

### Step 5. Execute rollback

Follow the relevant section below.

### Step 6. Validate recovery

- readiness healthy
- error rate normalizing
- latency normalizing
- critical business flow works
- queues draining
- no new integrity alarms

### Step 7. Monitor hold period

- keep enhanced monitoring
- do not resume normal rollout immediately
- confirm stabilization window is complete

### Step 8. Close rollback phase

- mark system stabilized
- record exact commands used
- preserve metrics windows
- create post-incident action items

## Detailed Procedures

## Procedure A. Feature Flag Rollback

### Use When

- a feature is isolated behind a flag
- disabling it stops the incident
- schema and core paths remain stable

### Steps

1. Identify exact flag name.
2. Confirm targeting rules and current rollout state.
3. Disable the flag or switch affected contexts to safe variation.
4. Record operator, timestamp, old state, new state, and reason.
5. Verify that affected endpoints or UI flows stop invoking the broken path.
6. Run smoke tests.
7. Monitor error rate and latency for recovery.

### Validation

- error signature drops
- affected endpoint stabilizes
- no unexpected impact on unrelated flows
- support team sees customer recovery

LaunchDarkly documents kill switch flags exactly for emergency shutoff scenarios. :contentReference[oaicite:10]{index=10}

## Procedure B. Configuration Rollback

### Use When

- failure is linked to environment variables, secrets, routing, limits, policies, or config files

### Steps

1. Identify last known good config version.
2. Diff current config vs previous stable config.
3. Restore previous config artifact.
4. Reload or restart affected workloads if required.
5. Confirm secret mount or env propagation if relevant.
6. Validate service readiness.
7. Run smoke tests.

### Common Examples

- wrong API endpoint
- broken third-party timeout setting
- invalid credentials
- bad rate-limit values
- broken queue routing
- malformed feature-policy config

## Procedure C. Kubernetes Application Rollback

### Use When

- deployment revision is faulty
- previous deployment revision is healthy
- old app remains compatible with current state

Kubernetes officially supports rollback to a previous rollout or a specific revision through `kubectl rollout undo`. :contentReference[oaicite:11]{index=11}

### Pre-Checks

- confirm namespace
- confirm deployment name
- confirm revision history
- confirm image digest of target revision
- confirm readiness and liveness probes are valid
- confirm DB compatibility

### Commands

Inspect rollout history:

```bash
kubectl rollout history deployment/<deployment-name> -n <namespace>