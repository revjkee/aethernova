# Data Classification Policy

Status: Approved Target Policy
Version: 1.0
Owner: Reva Studio Security Architecture
Applies To: Reva Studio application, APIs, databases, storage, logs, backups, analytics, admin panels, CI/CD artifacts, support workflows
Last Updated: 2026-03-23

## 1. Purpose

This document defines the official data classification policy for Reva Studio.

The purpose of this policy is to:

- classify data consistently across the platform
- define mandatory handling requirements for each data class
- reduce unauthorized disclosure, modification, and destruction risk
- support least-privilege and Zero Trust access design
- create a common language for engineering, product, support, analytics, and operations
- define storage, transmission, logging, backup, retention, and deletion expectations

This policy is a security control document.
It is not a feature specification.

## 2. Normative Basis

This policy is aligned with the following externally recognized security concepts:

- security categorization based on confidentiality, integrity, and availability impact
- information-type mapping and impact assignment
- Zero Trust access philosophy
- managed security logging
- personal data and special-category data protection
- payment data scope reduction

This policy does not claim regulatory sufficiency by itself.
It defines Reva Studio internal baseline controls.

## 3. Scope

This policy applies to all data handled by Reva Studio, including:

- production databases
- replicas
- backups
- caches
- object storage
- search indexes
- analytics stores
- logs and audit trails
- admin exports
- message brokers
- queues
- CI/CD secrets and deployment variables
- local development copies of production-like data
- support screenshots and attachments
- third-party integrations that process platform data

This policy applies to all environments:

- local
- development
- test
- staging
- production
- disaster recovery
- backup archives

## 4. Security Objectives

Every data classification decision shall consider:

- confidentiality impact
- integrity impact
- availability impact

Confidentiality means protection against unauthorized disclosure.
Integrity means protection against unauthorized modification or destruction.
Availability means protection against unauthorized disruption or loss of access.

For Reva Studio, confidentiality is usually the primary driver for client and staff data.
Integrity is usually the primary driver for bookings, payments, loyalty balances, and audit records.
Availability is usually the primary driver for booking operations and payment-dependent workflows.

## 5. Classification Model

Reva Studio uses four operational data classes:

1. Public
2. Internal
3. Confidential
4. Restricted

These operational classes are the platform policy layer.

In addition, every data asset should be evaluated for impact severity across:

- Confidentiality: Low, Moderate, High
- Integrity: Low, Moderate, High
- Availability: Low, Moderate, High

The operational class tells teams how to handle the data.
The CIA impact rating explains why the data is protected at that level.

## 6. Classification Principles

### 6.1 Default Rule

If data has not been classified yet, it must be treated as Confidential until reviewed.

### 6.2 Highest-Component Rule

If a dataset contains fields from different classes, the whole dataset inherits the highest class present.

Example:
A support export containing booking details and phone numbers is not Internal.
It is at least Confidential.

### 6.3 Derived Data Rule

Derived data inherits the highest sensitivity of its source unless it has been irreversibly anonymized and approved for downgrade.

### 6.4 Copy Rule

Copies, caches, temporary files, backups, screenshots, exports, and test fixtures inherit the class of the source data.

### 6.5 Logging Rule

Sensitive fields must not be written to logs unless there is a documented security or audit requirement and the fields are explicitly approved.

### 6.6 Least Privilege Rule

Access is granted strictly by business need, environment, role, and time-bounded purpose.

### 6.7 Zero Trust Rule

Network location alone never grants access.
Identity, device posture if applicable, role, approval path, and context must be evaluated before access.

## 7. Data Classes

## 7.1 Public

### Definition

Data approved for unrestricted disclosure outside the organization.

### Examples

- public marketing page content
- public service catalog meant for anonymous visitors
- published business hours
- publicly released product documentation
- public brand assets approved for external use

### Expected CIA Impact

- Confidentiality: Low
- Integrity: Moderate
- Availability: Low to Moderate

### Handling Requirements

- may be stored in public delivery systems
- integrity protection is still required for official content
- changes must still be governed through normal release controls

## 7.2 Internal

### Definition

Business information not intended for public release, but whose unauthorized disclosure would usually cause limited business harm.

### Examples

- internal runbooks without secrets
- non-public architecture notes
- internal backlog metadata
- deployment topology without credentials
- non-sensitive service usage metrics
- non-customer operational procedures

### Expected CIA Impact

- Confidentiality: Low to Moderate
- Integrity: Moderate
- Availability: Low to Moderate

### Handling Requirements

- no public sharing
- access limited to authenticated workforce and approved contractors
- transmission over approved channels only
- no posting in public issue trackers or public repositories

## 7.3 Confidential

### Definition

Sensitive business or personal data whose unauthorized disclosure, alteration, or misuse may materially harm clients, staff, business operations, or trust.

### Examples

- client names
- phone numbers
- email addresses
- booking history
- service history
- staff schedules
- internal financial reports
- payout details
- loyalty balances
- support tickets containing personal data
- analytics datasets containing identifiable user-level records
- private API responses containing client or staff records

### Expected CIA Impact

- Confidentiality: Moderate to High
- Integrity: Moderate to High
- Availability: Moderate

### Handling Requirements

- encryption in transit is mandatory
- encryption at rest is mandatory for primary stores and backups
- role-based access is mandatory
- least privilege is mandatory
- production access must be auditable
- masking or redaction is required in logs, dashboards, and support tools when full values are not necessary
- exports require explicit business purpose
- copies into lower-trust environments are prohibited unless sanitized or approved

## 7.4 Restricted

### Definition

The most sensitive data class.
Unauthorized disclosure, modification, or misuse may cause severe harm to individuals, severe business impact, financial loss, legal exposure, fraud risk, or security compromise.

### Examples

- passwords and password reset artifacts
- authentication secrets
- API keys
- private signing keys
- database credentials
- encryption master keys and key-encryption keys
- session secrets
- full payment card data if ever received
- sensitive authentication data from payment systems
- government identifiers if processed
- special-category personal data if processed
- high-risk incident evidence
- full audit evidence linked to privileged operations
- direct production database dumps containing full client records
- recovery codes
- privileged admin tokens
- raw backup encryption material

### Expected CIA Impact

- Confidentiality: High
- Integrity: High
- Availability: Moderate to High depending on asset

### Handling Requirements

- strict need-to-know access only
- just-in-time access preferred for human access
- strongest available encryption at rest and in transit
- secrets must be stored only in approved secret-management systems
- no plaintext storage in source control, chat, tickets, logs, screenshots, or notebooks
- no unrestricted export
- access must be individually attributable and fully auditable
- break-glass access must be documented and reviewed
- replication and backup paths must preserve the same class and control level
- local workstation storage is prohibited unless explicitly approved and strongly protected

## 8. Special Data Categories

## 8.1 Personal Data

Personal data means any information relating to an identified or identifiable natural person.

For Reva Studio this commonly includes:

- full name
- phone number
- email
- account identifiers linked to a person
- booking history linked to a person
- message content linked to a person
- support attachments linked to a person
- device identifiers if linkable to a person
- loyalty history linked to a person
- payment metadata linked to a person

Baseline class:
Confidential

Exception:
Public only if intentionally published with documented approval.
Restricted if combined with higher-risk data or if legal or contractual obligations require stronger controls.

## 8.2 Special-Category Personal Data

If Reva Studio ever processes special-category personal data, it must be treated as Restricted unless a stricter legal requirement applies.

Examples may include data revealing:

- health information
- biometric identifiers for unique identification
- racial or ethnic origin
- religious beliefs
- political opinions
- sex-life or sexual-orientation information

Baseline class:
Restricted

Default operational position:
Do not collect unless there is a documented lawful basis, approved product requirement, and dedicated controls.

## 8.3 Payment Data

Reva Studio should minimize payment data scope.

Policy:

- raw cardholder data must not be stored unless the platform is explicitly designed and approved to do so under a valid PCI-aligned control framework
- payment integrations should prefer tokenized or provider-hosted collection models
- where only payment provider tokens, transaction IDs, masked PAN fragments, or status metadata are stored, classify according to actual sensitivity of the stored fields
- any environment that stores, processes, or transmits cardholder data enters a much stricter control scope

Baseline classes:

- payment provider transaction IDs: Confidential
- masked payment references: Confidential
- full PAN or equivalent raw cardholder data: Restricted
- sensitive authentication data: Restricted and generally prohibited from storage after authorization workflow unless a standard explicitly allows otherwise

## 8.4 Credentials and Secrets

All credentials and secrets are Restricted.

Examples:

- passwords
- password hashes
- API tokens
- JWT signing keys
- OAuth client secrets
- database passwords
- cloud keys
- backup encryption keys
- webhook signing secrets

Additional rule:
A credential never becomes lower than Restricted because it is hashed, encoded, or stored in configuration.

## 8.5 Security Logs and Audit Trails

Security logs and audit trails are usually Confidential.
They become Restricted if they contain secrets, direct personal data beyond operational necessity, payment data, or privileged investigative evidence.

Logging rules:

- log events, not secrets
- log identifiers, not full sensitive payloads
- redact tokens, passwords, keys, reset artifacts, and raw payment data
- store privileged access logs in tamper-evident or strongly protected systems where available
- retain sufficient metadata for investigation and accountability

## 8.6 Backups

Backups inherit the highest class of the data they contain.
A full production backup is therefore usually Restricted.

## 8.7 Analytics and BI Data

Analytics data is not automatically low-risk.

Classification rules:

- aggregated and irreversibly anonymized metrics may be Internal or Public if approved
- client-level analytics with identifiers are Confidential
- analytics that include secrets, payment data, or legally sensitive fields are Restricted
- pseudonymized data is not automatically anonymous and must not be downgraded without review

## 9. Classification Matrix

| Data Type | Default Class | Typical C | Typical I | Typical A |
|---|---|---:|---:|---:|
| Public website content | Public | Low | Moderate | Low |
| Internal architecture docs without secrets | Internal | Moderate | Moderate | Low |
| Client profile data | Confidential | High | Moderate | Moderate |
| Booking records | Confidential | High | High | High |
| Staff schedules | Confidential | Moderate | High | High |
| Loyalty balances | Confidential | Moderate | High | Moderate |
| Payment provider tokens and transaction references | Confidential | Moderate | High | Moderate |
| Passwords, secret keys, admin tokens | Restricted | High | High | High |
| Full production backups | Restricted | High | High | Moderate |
| Raw cardholder data if ever present | Restricted | High | High | High |
| Special-category personal data if ever present | Restricted | High | High | Moderate |

## 10. Handling Rules by Lifecycle Stage

## 10.1 Collection

Collect only data that is necessary for a defined business purpose.

Requirements:

- data minimization is mandatory
- every new sensitive field must have an owner and purpose
- every new Restricted field requires security review
- forms and APIs must not request higher-class data without explicit approved need

## 10.2 Storage

Requirements by class:

### Public

- standard storage controls
- integrity monitoring where relevant

### Internal

- authenticated storage only
- no public buckets or public shares

### Confidential

- encrypted at rest
- access control enforced
- audit trail for privileged access
- restricted replication paths
- lower-environment copying prohibited unless sanitized or approved

### Restricted

- strongest approved encryption at rest
- dedicated secret handling path if applicable
- highly restricted access
- mandatory auditability
- no unmanaged workstation storage
- no plaintext in tickets, chat, source control, or screenshots

## 10.3 Transmission

Requirements:

- Public data may be transmitted openly if integrity requirements permit
- Internal, Confidential, and Restricted data must use approved encrypted transport
- Restricted data must not be sent through consumer chat tools or uncontrolled email workflows unless explicitly approved and protected
- service-to-service paths must authenticate both ends where applicable
- outbound integrations must be reviewed for data minimization and contractual fit

## 10.4 Use

Requirements:

- display only the minimum fields required by the user role
- mask or partially reveal values where full disclosure is not necessary
- administrative UI must not expose secrets in readable form
- production data access for debugging must be exceptional and logged
- support workflows must prefer lookup by internal identifier rather than broad data exposure

## 10.5 Logging and Monitoring

Requirements:

- do not log passwords, tokens, keys, reset links, OTP values, raw payment data, or private cryptographic material
- avoid logging full personal records
- use structured logs with field-level redaction
- alerting pipelines must preserve classification rules
- copies of logs sent to third parties must be reviewed for data class fit

## 10.6 Export and Sharing

Requirements:

- export must be approved by role and purpose
- exported file inherits original classification
- export format must preserve protection requirements
- Restricted data export requires explicit approval and audit trail
- sharing with vendors requires approved processor relationship and least-data principle
- ad hoc spreadsheet exports of Confidential or Restricted data should be minimized and time-bounded

## 10.7 Backup and Recovery

Requirements:

- backup classification equals source classification
- encryption at rest is mandatory for Confidential and Restricted backups
- restore operations must be limited and logged
- test restores must not create uncontrolled duplicate copies
- expired backups must be securely deleted according to policy

## 10.8 Retention and Deletion

Requirements:

- retention must be documented per data type
- data must not be kept indefinitely without business, legal, or security basis
- Restricted data should have the shortest feasible retention compatible with obligations
- deletion must cover primary stores, replicas, caches, and derived artifacts where applicable
- classification downgrade does not remove deletion obligations

Exact retention periods are not defined in this policy.
They must be set in a separate retention schedule.

## 11. Access Control Policy by Class

## 11.1 Public

Access model:
Open or broadly accessible.

## 11.2 Internal

Access model:
Authenticated workforce and approved contractors.

## 11.3 Confidential

Access model:
Role-based, least-privilege, need-to-know.

Required controls:

- approved role mapping
- managerial or system-owner approval where applicable
- auditable privileged access
- environment separation
- masked display when full value not needed

## 11.4 Restricted

Access model:
Strongly restricted, named access only where possible.

Required controls:

- explicit authorization
- just-in-time elevation preferred
- full auditability
- dual control or second-person approval for especially sensitive operations where justified
- periodic access review
- immediate revocation on role change or incident trigger

## 12. Environment Rules

## 12.1 Production

Production may process all classes subject to this policy.

## 12.2 Staging

Staging must not receive Restricted production data unless explicitly approved and equally protected.
Confidential production data should be avoided unless sanitized or justified.

## 12.3 Development and Local Machines

Rules:

- production Restricted data is prohibited
- production Confidential data is prohibited unless sanitized or explicitly approved under controlled process
- synthetic or anonymized data is preferred
- local secrets must be managed through approved secret workflows, not hardcoded files committed to version control

## 12.4 Test Fixtures and Seeds

Rules:

- use synthetic data by default
- do not embed real client or staff data
- test credentials must never mirror production credentials
- masked examples must remain non-reversible

## 13. Labeling Standard

Every major data asset should have an explicit classification label.

Recommended metadata fields:

- data_class
- confidentiality_impact
- integrity_impact
- availability_impact
- owner
- system_of_record
- legal_basis_if_applicable
- retention_policy_ref
- deletion_policy_ref
- approved_consumers
- contains_personal_data
- contains_special_category_data
- contains_payment_data
- contains_secrets

Recommended labels:

- CLASS: PUBLIC
- CLASS: INTERNAL
- CLASS: CONFIDENTIAL
- CLASS: RESTRICTED

## 14. Data Asset Registration

The following asset types must be registered and classified:

- database tables
- object storage buckets
- backups
- message topics and queues
- search indexes
- analytics marts
- log streams
- API payload families
- third-party integration feeds
- data exports
- secrets stores
- configuration repositories containing deploy-time variables

Each registered asset must identify:

- owner
- steward if different
- purpose
- environment
- upstream sources
- downstream consumers
- classification
- review date

## 15. Mandatory Protection Baseline

## 15.1 Public

Minimum controls:

- integrity-aware publishing
- normal change control

## 15.2 Internal

Minimum controls:

- authenticated access
- non-public storage
- change control

## 15.3 Confidential

Minimum controls:

- encryption in transit
- encryption at rest
- role-based access control
- access logging for privileged paths
- export control
- masked observability where possible
- data minimization in downstream systems

## 15.4 Restricted

Minimum controls:

- strongest approved encryption at rest and in transit
- secrets management or equivalent hardened storage
- named access and strong accountability
- no plaintext in source control, logs, chat, or tickets
- break-glass procedure where needed
- strict export prohibition or explicit approval path
- periodic access review
- incident-response priority

## 16. Prohibited Practices

The following are prohibited:

- storing secrets in source control
- logging plaintext passwords, tokens, or keys
- sending Restricted data through uncontrolled channels
- copying production dumps to personal devices without explicit approval
- using real client data in demos or test fixtures without approval
- downgrading data class because a file is old, partial, or exported
- classifying pseudonymized data as anonymous without formal review
- treating masked card data as equivalent to raw card data rules in every context without checking actual content
- granting access based only on office network, VPN presence, or machine location

## 17. Incident Handling and Escalation

A suspected exposure of Confidential or Restricted data is a security incident.

Minimum response requirements:

- contain access immediately
- preserve evidence
- identify impacted data class
- identify affected subjects and systems
- assess whether secrets rotation is required
- assess legal, contractual, and notification obligations
- document timeline, scope, cause, and remediation
- review whether classification, retention, or logging controls failed

Restricted data exposure must receive highest priority triage.

## 18. Review and Reclassification

Classification is not permanent.

Reclassification is required when:

- a new field is added
- integration scope changes
- a dataset is joined with more sensitive data
- a new legal obligation applies
- anonymization is introduced or removed
- retention use changes
- a new business process expands access

Mandatory review triggers:

- new product feature involving personal data
- new payment workflow
- new analytics export
- new third-party processor
- new admin capability
- annual policy review

## 19. Ownership

### Security Architecture

Responsible for:

- policy definition
- classification guidance
- review of Restricted assets
- control baseline decisions

### Engineering Owners

Responsible for:

- asset registration
- correct implementation of controls
- environment segregation
- secure handling in code, logs, and storage

### Product and Operations

Responsible for:

- justifying collection need
- minimizing data scope
- ensuring exports and support processes follow classification

### Compliance and Legal if applicable

Responsible for:

- mapping legal obligations
- validating retention and deletion obligations
- supporting incident notification decisions

## 20. Practical Classification Examples for Reva Studio

### Example 1: Anonymous landing page service list

Class:
Public

Reason:
Approved for public disclosure.

### Example 2: Internal ADR on booking architecture without credentials

Class:
Internal

Reason:
Non-public internal design material.

### Example 3: Client record with name, phone, and booking history

Class:
Confidential

Reason:
Personal data with moderate to high confidentiality impact.

### Example 4: Staff payout report with bank transfer details

Class:
Confidential or Restricted depending on contents

Reason:
If it contains personal financial details or high-risk payment details, elevate to Restricted.

### Example 5: Database password stored in deployment secret manager

Class:
Restricted

Reason:
Credential and direct access enabler.

### Example 6: Production audit log showing privileged admin action and affected booking ID

Class:
Confidential

Reason:
Sensitive operational record.
Elevate to Restricted if it includes secrets, high-risk investigative evidence, or unusually sensitive subject data.

### Example 7: Full production PostgreSQL dump

Class:
Restricted

Reason:
Contains mixed high-sensitivity data and inherits highest class.

### Example 8: Aggregated monthly revenue by service category without personal identifiers

Class:
Internal by default

Reason:
Business-sensitive, but not public.
May become Public only after explicit approval.

## 21. Minimum Implementation Checklist

Before a new data store or feature goes live, confirm:

- data owner assigned
- purpose documented
- classification assigned
- CIA impact documented
- personal data presence identified
- special-category data presence identified
- payment data presence identified
- secrets presence identified
- retention rule linked
- deletion path defined
- access roles defined
- logging reviewed for redaction
- export path reviewed
- backup handling reviewed
- incident owner identified

## 22. Final Policy Statement

If data classification is unclear, choose the safer class and escalate for review.

No engineering convenience, analytics speed, support shortcut, or operational habit overrides this rule.

The platform must assume breach-minded design:
minimize what is collected, restrict who can access it, protect it throughout its lifecycle, and leave auditable evidence for sensitive operations.

## 23. References

Normative concepts supporting this policy were derived from:

- NIST FIPS 199, Standards for Security Categorization of Federal Information and Information Systems
- NIST SP 800-60, Guide for Mapping Types of Information and Information Systems to Security Categories
- NIST SP 800-207, Zero Trust Architecture
- NIST SP 800-92, Guide to Computer Security Log Management
- Regulation (EU) 2016/679, including personal data, special categories of personal data, and security of processing
- PCI Security Standards Council definitions for cardholder data and PCI DSS scope