# Secrets Policy
Updated: 2026-03-23
Status: Approved Draft
Scope: Reva Studio
Owner: Security Architecture
Classification: Internal

## 1. Purpose

This document defines the mandatory security policy for creation, storage, access, rotation, usage, auditing, and revocation of secrets in Reva Studio.

This policy applies to all environments:

- local
- development
- staging
- production
- CI/CD
- one-off operational jobs
- containers
- background workers
- bots
- APIs
- databases
- observability stack
- third-party integrations

The purpose of this policy is to reduce the risk of secret leakage, privilege abuse, unauthorized access, and recovery failure.

OWASP treats secrets management as a dedicated security concern and recommends centralized storage, provisioning, rotation, auditing, and lifecycle control for secrets. :contentReference[oaicite:0]{index=0}

## 2. Definitions

For this policy, a secret is any confidential value that grants access, identity, encryption capability, or privileged execution.

Secrets include, but are not limited to:

- API keys
- bot tokens
- JWT signing keys
- session signing keys
- database passwords
- Redis passwords
- SMTP credentials
- OAuth client secrets
- webhook secrets
- private keys
- encryption keys
- certificate private keys
- CI/CD secrets
- cloud provider credentials
- secrets used during image build
- backup encryption keys

Non-secret configuration is any configuration that does not grant access or confidentiality by itself.

The Twelve-Factor methodology distinguishes deploy-varying config from code and recommends storing config in environment variables rather than hardcoding it in the codebase. :contentReference[oaicite:1]{index=1}

## 3. Policy goals

Reva Studio adopts the following goals:

1. No secret may be hardcoded in source code.
2. No secret may be committed to Git history.
3. No secret may appear in logs, traces, metrics labels, or error payloads.
4. No secret may be shared in plaintext through chat, ticket comments, screenshots, or documentation unless the document is itself a controlled secret-delivery channel.
5. Every secret must have an owner, purpose, scope, and rotation procedure.
6. Every secret must follow least-privilege access.
7. Every production secret must have a revocation path.
8. Every secret-consuming service must access only the secrets it strictly needs.
9. Build-time and runtime secrets must be separated.
10. Secrets must be auditable across their lifecycle.

These goals align with OWASP guidance on lifecycle management, least privilege, access control, automation, rotation, and auditing for secrets. :contentReference[oaicite:2]{index=2}

## 4. Source of truth

Project decision:

Reva Studio defines the following hierarchy of secret sources.

### 4.1 Approved sources by priority

1. Dedicated secret manager approved by the platform owner
2. Deployment platform secret store
3. CI/CD secret store
4. Container orchestration secret mechanism
5. Environment variables injected at runtime
6. Local developer `.env` files outside Git tracking, only for local development

### 4.2 Forbidden sources

- source code constants
- committed `.env` files
- values embedded in Dockerfiles
- secrets passed as plain CLI arguments where they can be exposed in shell history or process listings
- secrets stored in issue trackers, wiki pages, or chat messages without controlled access
- secrets inside test fixtures committed to the repository
- secrets inside screenshots or screen recordings

GitHub explicitly recommends not hardcoding tokens, keys, or app secrets into code and instead using a secret manager or equivalent secret-storage mechanism. :contentReference[oaicite:3]{index=3}

## 5. Secret classification

Project decision:

Every secret must be assigned one of the following classifications.

### 5.1 Critical
Compromise leads to system-wide control, long-lived impersonation, irreversible data exposure, or signing authority.

Examples:

- master encryption key
- JWT signing key for production
- database superuser credential
- cloud root-like credential
- private TLS key
- production bot token with admin scopes

### 5.2 High
Compromise leads to significant service abuse, privileged data access, or operational disruption.

Examples:

- production application DB user
- Redis credential
- SMTP credential
- CI deployment credential
- webhook verification secret

### 5.3 Medium
Compromise affects bounded non-critical access or internal automation with limited blast radius.

Examples:

- staging integration token
- observability ingestion token
- non-production API credential

### 5.4 Low
Local-only or temporary development secret with no production impact.

Examples:

- ephemeral local sandbox token
- disposable dev-only test key

## 6. Mandatory metadata

Every managed secret must have the following metadata recorded in the approved registry or secret inventory:

- secret name
- owning team or person
- system or service using the secret
- environment scope
- data classification
- creation date
- last rotation date
- next rotation due date
- revocation procedure
- recovery notes
- access scope
- whether human access is allowed
- whether automation access is allowed

OWASP recommends inventory, standardization, access control, lifecycle handling, monitoring, and auditing as core parts of secret management. :contentReference[oaicite:4]{index=4}

## 7. Secret generation requirements

Project decision:

Secret values must be generated using approved cryptographically secure mechanisms.

Mandatory rules:

- secrets must be randomly generated unless an external provider defines the value
- human-chosen passwords are forbidden for system-to-system authentication when a generated credential is possible
- secret length and format must match the provider’s security guidance
- private keys must be generated using approved cryptographic tooling
- secrets must not be reused across environments

## 8. Environment separation

Project decision:

Secrets must be isolated by environment.

Mandatory rules:

- local, dev, staging, and production secrets must be different values
- production secrets must never be copied into local development
- staging secrets must not be promoted into production unchanged
- a single shared credential across all environments is forbidden
- environment names must be encoded in secret naming or scoping conventions

The Twelve-Factor methodology states that config varies between deploys and should be separated from code, which supports strict environment separation. :contentReference[oaicite:5]{index=5}

## 9. Access control policy

Project decision:

Access to secrets follows least privilege and need-to-know.

Mandatory rules:

- services may access only secrets required for their runtime behavior
- developers must not receive production secrets unless explicitly authorized
- read access and write access must be separated where the platform supports it
- CI jobs must receive only the secrets needed for that workflow
- human access to critical secrets must be minimized and logged
- shared team credentials are forbidden where individual identity or workload identity is available

OWASP recommends least-privilege access, separation of duties, logging, monitoring, and strong control around who can retrieve and manage secrets. :contentReference[oaicite:6]{index=6}

## 10. Storage rules

### 10.1 General storage rules

Mandatory rules:

- secrets must be stored only in approved secret stores
- secrets at rest must be protected by the storage platform’s security controls
- secret backups must be protected at least as strongly as the primary secret store
- secrets must not be stored in plaintext inside repository files
- secrets must not be written into application-generated cache files, dumps, or artifacts

### 10.2 Environment variables

Project decision:

Environment variables are allowed for runtime injection where a stronger platform-native secret mechanism is unavailable or impractical.

The Twelve-Factor methodology recommends storing config in environment variables and highlights the reduced chance of committing config to the repository compared with config files. :contentReference[oaicite:7]{index=7}

Restriction:

environment variables are not permission-segmented by themselves and must not be treated as a full secret-management system. For high-impact production environments, prefer a dedicated secret manager or platform-native secret store.

### 10.3 Docker Compose secrets

Docker Compose supports top-level `secrets`, grants access per service, and mounts secrets as files under `/run/secrets/<secret_name>`. :contentReference[oaicite:8]{index=8}

Project decision:

For containerized local and controlled deployments, file-mounted secrets are preferred over embedding secrets in images or Dockerfiles.

Mandatory rules:

- secrets must not be copied into container images
- secrets must not be baked into image layers
- secrets must be granted only to services that require them
- applications should read secrets from mounted files where supported

### 10.4 Docker build secrets

Docker documents build secrets as sensitive information consumed during the build and provides dedicated secret mechanisms for build-time use. :contentReference[oaicite:9]{index=9}

Mandatory rules:

- build-time secrets must use dedicated build-secret mechanisms
- build-time secrets must not persist in final image layers
- Dockerfile instructions must not echo or persist secret material
- build logs must not reveal build secrets

### 10.5 Kubernetes Secrets

Kubernetes documents that Secrets are intended for confidential data, while ConfigMaps are for non-confidential data. Kubernetes also states that Secret values are encoded as base64 strings and, by default, stored unencrypted unless encryption at rest is configured. :contentReference[oaicite:10]{index=10}

Project decision:

If Reva Studio is deployed on Kubernetes, Kubernetes Secrets may be used only with additional hardening.

Mandatory rules:

- enable encryption at rest for Secret objects
- restrict Secret access with RBAC
- avoid broad namespace-wide read permissions
- do not confuse base64 encoding with encryption
- use Secrets rather than ConfigMaps for confidential data

## 11. CI/CD secrets policy

GitHub Actions secrets are stored as repository, environment, or organization secrets, and workflows can read a secret only when it is explicitly included in the workflow. GitHub also documents scope, limits, and timing of when secrets are read. :contentReference[oaicite:11]{index=11}

Project decision:

CI/CD secrets must be scoped as narrowly as possible.

Mandatory rules:

- prefer environment-scoped secrets for deployment workflows
- use repository-scoped secrets only when environment scoping is not sufficient
- production deployment secrets must not be exposed to test-only jobs
- third-party actions must be reviewed before being allowed to access secrets
- CI logs must not print secret values
- CI jobs must not write secret values into artifacts
- secrets for pull requests from untrusted forks must remain unavailable unless explicitly approved through a secure workflow design

## 12. Application usage rules

Mandatory rules:

- applications must load secrets through a configuration layer, not scattered ad hoc reads
- secret values must not be re-serialized into user-facing responses
- secret values must not be returned in health endpoints
- secret values must not be embedded into exception strings
- secret values must not be included in telemetry labels or structured logs
- secrets must not be placed in URLs

OWASP notes that sensitive information such as passwords, security tokens, and API keys should not appear in URLs because they can be captured in logs, and sensitive data should not be logged. :contentReference[oaicite:12]{index=12}

## 13. Logging and observability rules

OWASP logging guidance states that logs may contain sensitive information and that logging systems and stored data must be protected. OWASP also warns against inserting sensitive data into log files. :contentReference[oaicite:13]{index=13}

Mandatory rules:

- do not log secret values
- do not log raw tokens, session identifiers, passwords, or private keys
- do not log authorization headers
- do not log full connection strings if they contain credentials
- redact secrets before emitting structured logs
- sanitize log data to reduce log injection risks
- security-relevant access to secret stores must be logged without revealing the secret material

Project decision:

Allowed audit log fields for secret operations:

- actor identity
- action type
- secret logical name
- environment
- result
- correlation id
- timestamp
- source IP or execution identity where available

Forbidden audit log fields:

- plaintext secret value
- reversible encoding of secret value
- full private key material
- raw bearer token

## 14. Rotation policy

OWASP recommends secret rotation and lifecycle handling as part of secrets management. :contentReference[oaicite:14]{index=14}

Project decision:

All secrets must have a defined rotation class.

### 14.1 Rotation classes

#### Class A: immediate rotation on suspicion or incident
Applies when a leak is suspected or confirmed.

#### Class B: scheduled frequent rotation
Examples:

- CI tokens
- deployment credentials
- third-party API keys where the provider supports safe rotation

#### Class C: scheduled standard rotation
Examples:

- database application passwords
- Redis credentials
- internal service API keys

#### Class D: event-driven rotation
Examples:

- bot tokens after staff turnover
- keys after permission model change
- certificates before expiry or after private key suspicion

### 14.2 Mandatory rotation events

Rotate a secret immediately when:

- it appears in Git history
- it appears in a log
- it appears in a screenshot or ticket
- it is shared to an unauthorized person
- a staff member with access leaves the role and the secret is shared
- provider-side suspicion or compromise is reported
- secret scope was broader than intended
- infrastructure containing the secret may have been compromised

## 15. Revocation policy

Project decision:

Every production secret must have a revocation or disablement procedure.

Mandatory rules:

- secret owners must know how to disable or replace the secret
- revocation must be documented for critical and high secrets
- revocation must be testable for high-impact credentials
- where dual-secret rollout is supported, rotate without downtime using staged replacement

## 16. Incident response for secret leakage

Mandatory steps on suspected leakage:

1. identify the secret type and scope
2. determine whether the secret is still valid
3. revoke or rotate the secret
4. identify affected systems and sessions
5. search logs, tickets, artifacts, and Git history for spread
6. invalidate dependent sessions or tokens if required
7. document incident timeline and remediation
8. add preventive control if the leak path was avoidable

Project decision:

A secret leak is a security incident, not a documentation cleanup task.

## 17. Git and repository policy

Mandatory rules:

- `.env` files with real secrets must be ignored by Git
- example files may contain placeholders only
- committed secrets must be treated as compromised even if later removed from the current branch
- history rewriting may reduce exposure but does not replace rotation
- pull requests must not contain plaintext secrets
- repository scanners may be used, but scanning does not replace preventive controls

GitHub documentation explicitly advises against hardcoding credentials in code and supports secure storage through managed secret mechanisms. :contentReference[oaicite:15]{index=15}

## 18. Documentation policy

Project decision:

Documentation may describe secret names, locations, and handling procedures, but must not contain real secret values.

Allowed in docs:

- variable names
- secret file paths
- examples with placeholders
- rotation runbooks
- incident procedures
- ownership matrix

Forbidden in docs:

- real API keys
- real tokens
- real passwords
- real private keys
- copied production connection strings
- screenshots containing real values

## 19. Local development policy

Project decision:

Local development may use `.env` or equivalent local-only secret files only under the following conditions:

- file is excluded from Git
- value is non-production
- value is non-shared unless explicitly approved
- developer machine access is controlled
- local secrets are rotated if accidentally exposed
- onboarding docs use placeholders, not real values

The Twelve-Factor methodology supports environment-based config per deploy, which is consistent with local-only secret injection rather than committing secret-bearing config files. :contentReference[oaicite:16]{index=16}

## 20. Example naming convention

Project decision:

Recommended logical naming convention:

- `REVA__APP__SECRET_KEY`
- `REVA__DB__PASSWORD`
- `REVA__REDIS__PASSWORD`
- `REVA__BOT__TOKEN`
- `REVA__SMTP__PASSWORD`
- `REVA__JWT__PRIVATE_KEY`
- `REVA__THIRD_PARTY__STRIPE__API_KEY`
- `REVA__ENV__STAGING__DEPLOY_TOKEN`

Rules:

- names must reflect system and purpose
- names must avoid embedding the value format
- environment scoping must be explicit where supported
- human-readable logical names are preferred over opaque labels

## 21. Secret file handling policy

Mandatory rules for mounted secret files:

- file permissions must be minimal
- file path must be stable and documented
- application must read secret content and avoid copying it elsewhere
- secret files must not be included in support bundles
- secret files must not be world-readable
- temporary files containing secrets are forbidden unless securely cleaned up

Docker Compose documents secret mounting via files under `/run/secrets/...`, which supports file-based runtime retrieval without embedding the secret in the image. :contentReference[oaicite:17]{index=17}

## 22. Database credential policy

Project decision:

Database credentials must be role-scoped and environment-scoped.

Mandatory rules:

- application runtime must not use database superuser credentials
- migration credentials must be separated from normal application credentials where practical
- read-only workloads should use read-only credentials where supported
- database traffic carrying credentials or sensitive data must use transport protection in production or untrusted networks

OWASP database security guidance warns that unencrypted traffic can expose sensitive information across the network and recommends transport protection. :contentReference[oaicite:18]{index=18}

## 23. Password and key handling distinctions

OWASP provides separate guidance for password storage because user passwords must be protected even if the database is compromised. :contentReference[oaicite:19]{index=19}

Project decision:

Reva Studio distinguishes:

- authentication secrets used by systems
- user passwords
- encryption keys
- signing keys
- session secrets
- API credentials

Rules:

- user passwords must never be stored as reversible plaintext
- private keys must be stored and distributed under stricter controls than regular API keys
- signing keys must have explicit owner and rollover plan
- session secrets must not be logged or exposed to clients

## 24. Build, release, and run separation

The Twelve-Factor methodology requires strict separation between build, release, and run stages. :contentReference[oaicite:20]{index=20}

Project decision:

Reva Studio applies this separation to secrets.

Mandatory rules:

- build-time secrets must not become runtime config by accident
- release metadata must not include plaintext secret values
- runtime secrets must be injected at run time or deploy time through approved channels
- image promotion between environments must not carry embedded secrets

## 25. Compliance checks

Project decision:

The following checks are mandatory for the platform.

### 25.1 Preventive checks
- Git ignore rules for local secret files
- placeholder-only `.env.example`
- CI workflow review for secret scope
- container review for embedded credentials
- secret names documented per service

### 25.2 Detective checks
- search for leaked secrets in logs and artifacts
- review access logs to secret stores
- review CI jobs with secret access
- monitor failed authentication spikes after rotation
- monitor unusual secret read activity where supported

### 25.3 Corrective checks
- rotation runbook tested
- revocation steps documented
- incident template prepared
- replacement deployment procedure documented

## 26. Minimum implementation baseline for Reva Studio

Project decision:

At minimum, Reva Studio must implement:

- no real secrets in Git
- `.env.example` with placeholders only
- environment-separated secrets
- CI/CD secrets stored in the CI platform secret store
- production secrets unavailable to local development by default
- secret redaction in logging
- documented rotation for critical and high secrets
- dedicated handling for build secrets
- service-by-service secret inventory

## 27. Roles and responsibilities

Project decision:

### 27.1 Security Architecture
- defines policy
- approves exceptions
- reviews critical-secret handling
- leads incident response for leaks

### 27.2 Service Owner
- defines required secrets
- minimizes access scope
- maintains rotation procedure
- validates application redaction behavior

### 27.3 DevOps/Platform
- provisions secret-delivery mechanism
- configures environment separation
- enforces CI/CD scoping
- supports revocation and rollout

### 27.4 Developer
- never commits real secrets
- uses placeholders in code and docs
- reports suspected leaks immediately
- follows local-development handling rules

## 28. Exception policy

Project decision:

Exceptions to this policy require:

- written justification
- explicit risk statement
- compensating controls
- owner
- expiry date
- approval by security owner

Expired exceptions are invalid automatically.

## 29. Prohibited patterns summary

The following patterns are forbidden:

- hardcoded secret constants
- real secrets in `.env.example`
- real secrets in README or docs
- secrets in URLs
- secrets in logs
- secrets in screenshots
- production secrets in local machines without authorization
- secrets in Dockerfile `ENV`
- secrets copied into container images
- using ConfigMap for confidential data in Kubernetes
- treating base64 as encryption
- shared production credentials without ownership

Kubernetes explicitly distinguishes Secrets from ConfigMaps and notes that base64 encoding is not the same as encryption. :contentReference[oaicite:21]{index=21}

## 30. Practical examples

### 30.1 Allowed example

```env
REVA__DB__HOST=postgres
REVA__DB__PORT=5432
REVA__DB__NAME=reva_studio
REVA__DB__USER=reva_app
REVA__DB__PASSWORD=[SET_IN_SECRET_STORE]
REVA__BOT__TOKEN=[SET_IN_SECRET_STORE]
REVA__JWT__PRIVATE_KEY_PATH=/run/secrets/reva_jwt_private_key