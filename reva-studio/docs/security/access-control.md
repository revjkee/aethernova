# Access Control

## Status
Proposed

## Purpose
This document defines the target access control architecture, policies, responsibilities, constraints, and verification requirements for `reva-studio`.

This specification is intentionally divided into:
- externally grounded access control principles based on NIST and OWASP;
- project-specific decisions marked as `TBD` where business confirmation is still required.

## Normative References
The following references are the primary external basis for this document:

- OWASP Authorization Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

- OWASP Authentication Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

- OWASP Application Security Verification Standard  
  https://owasp.org/www-project-application-security-verification-standard/

- NIST Role Based Access Control project overview  
  https://csrc.nist.gov/projects/role-based-access-control

- NIST The NIST Model for Role-Based Access Control: Towards a Unified Standard  
  https://www.nist.gov/publications/nist-model-role-based-access-control-towards-unified-standard

- NIST SP 800-162 Guide to Attribute Based Access Control (ABAC) Definition and Considerations  
  https://csrc.nist.gov/pubs/sp/800/162/upd2/final

---

## 1. Security Objective

The access control subsystem exists to ensure that every action in `reva-studio` is allowed only when:
- the subject is authenticated where required;
- the subject is authorized for the specific action;
- the request is within tenant, ownership, and business-policy boundaries;
- the decision is enforced consistently at every trust boundary;
- the action is auditable when security or compliance relevance exists.

This document treats access control as a core security function, not as optional presentation logic.

---

## 2. Confirmed Security Principles

The following principles are externally grounded and should be treated as mandatory defaults unless a formally approved exception exists.

### 2.1 Deny by default
If a request is not explicitly allowed by policy, it must be denied.

### 2.2 Least privilege
Subjects should receive only the minimum permissions required to perform their legitimate business tasks.

### 2.3 Validate permissions on every request
Authorization must be enforced server-side for each request and for each sensitive operation. Client-side checks are not a security control.

### 2.4 Prefer policy-based access decisions
Static role checks alone are often insufficient for modern applications. Business context, ownership, tenant scope, resource attributes, and environmental conditions may also be required.

### 2.5 Separate authentication from authorization
Authentication answers who the subject is. Authorization answers what the subject is allowed to do.

### 2.6 Centralize decision logic
Access decisions should be derived from a consistent policy layer, not scattered across controllers, templates, or frontend code.

### 2.7 Secure object access
Every object lookup and operation must be subject to access checks to prevent insecure direct object reference patterns.

### 2.8 Audit sensitive decisions
Access grants, denials, elevation events, membership changes, and privileged operations should be logged in a structured, reviewable way.

---

## 3. Access Control Model

## 3.1 Recommended model
The recommended target model for `reva-studio` is:

- RBAC for coarse-grained role assignment
- ABAC for context-aware policy enforcement
- relationship checks for ownership and tenant scoping
- explicit policy rules for privileged or high-risk operations

This means:
- roles define baseline capabilities;
- attributes and relationships refine the final decision;
- the final result is policy-driven, not role-string-driven.

## 3.2 Why not pure RBAC only
RBAC is suitable for mapping organizational responsibilities and baseline permissions.
However, business workflows in `reva-studio` also require contextual checks such as:
- tenant isolation
- resource ownership
- service or branch scoping
- staff assignment
- booking ownership
- time-based or environment-based restrictions
- admin-only elevated operations

Therefore a pure role-only model is not sufficient for long-term production security.

---

## 4. Terminology

Use these terms consistently across code, API design, documentation, tests, and logs.

### Subject
A user, service account, job worker, integration, or system actor requesting an operation.

### Resource
The target object or domain entity being accessed.

### Action
The operation being requested, such as `read`, `create`, `update`, `delete`, `approve`, `assign`, `refund`, `export`, `impersonate`.

### Policy
A rule or set of rules determining whether a subject may perform an action on a resource under given conditions.

### Role
A named grouping of permissions associated with a business or operational responsibility.

### Permission
A machine-meaningful capability such as `booking.read.any` or `loyalty.adjust.balance`.

### Attribute
A property of the subject, resource, operation, or environment used in policy evaluation.

### Relationship
A direct or indirect linkage between subject and resource, for example:
- creator of resource
- assigned staff member
- tenant owner
- supervisor of staff member
- member of branch

### Enforcement Point
The place where a request is allowed or denied.

### Decision Point
The logic or component that evaluates policy and returns an allow or deny decision.

---

## 5. Domain Boundaries

Access control in `reva-studio` must cover at minimum:

- authentication boundary
- API boundary
- admin boundary
- tenant boundary
- object boundary
- background-job boundary
- storage and media boundary
- export and reporting boundary
- support and impersonation boundary
- internal service-to-service boundary if the platform evolves into distributed services

---

## 6. Separation of Concerns

Access control should be separated into distinct responsibilities.

### Authentication
Determines the identity of the subject.

### Authorization
Determines whether the subject may perform a given action on a resource.

### Session or token handling
Carries identity and security claims but does not itself decide business authorization.

### Policy evaluation
Interprets roles, attributes, and relationships into an allow or deny outcome.

### Enforcement
Stops unauthorized actions at API, service, query, command, and object layers.

---

## 7. Recommended Authorization Architecture

## 7.1 Policy structure
The recommended production structure is:

- subject context
- resource context
- action
- environment context
- policy rules
- decision result
- audit record

## 7.2 Decision workflow
Each protected operation should follow this sequence:

1. resolve authenticated subject or anonymous mode
2. resolve tenant context
3. resolve target resource identity
4. resolve requested action
5. load relevant attributes and relationships
6. evaluate policy
7. return `allow` or `deny`
8. record audit evidence where required

## 7.3 Enforcement layers
Authorization should be enforced at multiple layers:

- API route layer
- application service or command handler layer
- domain policy layer
- repository query scoping layer
- background task execution layer
- outbound integration layer where necessary

One successful check in one layer is not a substitute for missing checks in other critical layers.

---

## 8. Recommended Policy Dimensions

The following dimensions should be supported.

### 8.1 Subject attributes
Examples:
- user id
- tenant id
- role set
- active status
- MFA status if relevant
- branch membership
- employment state
- service account type
- support privilege level

### 8.2 Resource attributes
Examples:
- resource tenant id
- owner id
- assigned staff id
- branch id
- lifecycle state
- sensitivity classification
- publication status
- soft-delete state

### 8.3 Operation attributes
Examples:
- action name
- write or read classification
- high-risk flag
- financial impact flag
- irreversible flag

### 8.4 Environment attributes
Examples:
- time window
- source network zone
- support mode
- emergency mode
- request channel
- device trust level if implemented

---

## 9. Multi-Tenant Security

If `reva-studio` is operated as a multi-tenant system, tenant isolation is mandatory.

### Mandatory tenant rules
- every protected resource must be linked to a tenant boundary or explicitly marked global;
- every query returning tenant-bound resources must be tenant-scoped;
- every mutation must validate tenant compatibility between subject and resource;
- cross-tenant access must be denied unless explicitly designed for platform-level operations;
- platform-level operations must be tightly restricted and audited.

### Global resource rule
Global reference data must be explicitly designated as global.
Nothing is global by accident.

---

## 10. Ownership and Relationship Checks

Role checks alone are insufficient for many user-facing actions.
The system should support relationship-driven policies such as:

- a customer may read only their own bookings;
- a staff member may edit only media or schedules assigned to their branch or scope;
- a manager may access staff data only within their managed branch or tenant scope;
- a global admin may perform cross-tenant actions only when platform privilege is active and logged.

Ownership checks must be implemented as first-class policy rules, not hidden controller conditions.

---

## 11. Roles and Permission Strategy

## 11.1 Recommended direction
Use stable permissions as the primary internal contract and roles as permission bundles.

Recommended pattern:
- roles are human-manageable;
- permissions are machine-enforceable;
- policies evaluate both permissions and contextual constraints.

## 11.2 Example permission naming convention
Use dot-separated permissions with action clarity.

Examples:
- `tenant.read`
- `tenant.update.settings`
- `user.read.self`
- `user.read.any`
- `staff.manage.schedule`
- `booking.create`
- `booking.read.self`
- `booking.read.branch`
- `booking.cancel.self`
- `payment.refund.approve`
- `loyalty.adjust.balance`
- `media.publish`
- `audit.read`
- `support.impersonate`

## 11.3 Role naming guidance
Roles should reflect business responsibilities, not implementation shortcuts.

Possible patterns:
- `customer`
- `staff_member`
- `branch_manager`
- `tenant_admin`
- `platform_support`
- `platform_admin`
- `service_account`

Final role list is `TBD`.

---

## 12. Administrative and Privileged Access

Privileged access must have stronger controls than standard user access.

### High-risk operations include
- role assignment
- permission grants
- tenant ownership transfer
- payment refund approval
- manual loyalty balance adjustment
- export of sensitive data
- impersonation
- deletion of audit-relevant records
- access to security logs
- access to secrets or integration settings

### Additional controls recommended for privileged actions
- explicit permission
- elevated audit logging
- two-person approval where business requires it
- stronger session assurance if implemented
- short-lived elevation for support/admin modes
- reason capture for sensitive actions

Final approval workflow requirements are `TBD`.

---

## 13. Service Accounts and Automation

Non-human actors must not reuse human authorization semantics blindly.

### Rules
- service accounts must have their own identity type;
- service accounts must receive only narrowly scoped permissions;
- secrets and tokens for service accounts must be managed separately from user credentials;
- background workers must execute under explicit system principals or delegated context;
- impersonation of end users by internal services must be explicit, limited, and auditable.

---

## 14. Support Access and Impersonation

If support impersonation exists, it must be treated as high-risk access.

### Mandatory rules
- must require explicit permission;
- must be time-limited;
- must be justified with a recorded reason;
- must be visible in audit logs;
- must clearly mark the session as impersonated;
- must be prohibited for the most sensitive operations unless explicitly approved.

Support impersonation policy is `TBD`, but if implemented it should default to disabled.

---

## 15. Data Access and Query Scoping

Authorization must not depend only on hiding buttons in the UI.

### Query security rules
- list queries must be filtered by policy before data leaves the backend;
- object fetches must verify access to the specific object;
- aggregate analytics and exports must obey tenant and privilege boundaries;
- search endpoints must not leak object existence across unauthorized scopes.

This is especially important for:
- user search
- booking search
- payment search
- media access
- admin dashboards
- export endpoints

---

## 16. API Security Requirements

Every protected API endpoint should define:

- authenticated or anonymous access mode
- required base permission
- required resource policy checks
- tenant scope behavior
- audit requirements
- error behavior

### Error behavior
Authorization failures should not expose unnecessary resource details.
The platform should avoid leaking whether a resource exists if the caller is not allowed to know.

Final `403` vs `404` behavior by endpoint family is `TBD`.

---

## 17. UI and Frontend Rules

Frontend access hints are not security controls.
They are usability features only.

### Frontend may do
- hide unavailable actions
- disable buttons
- show permission-aware navigation
- display explanatory messages

### Frontend must not do
- act as the only authorization layer
- assume a hidden element means a protected operation is secure
- trust role claims without server validation for sensitive behavior

---

## 18. Event, Job, and Async Security

Background processing must preserve security boundaries.

### Rules
- jobs triggered from user actions should carry a trusted actor or delegated context reference where needed;
- jobs must validate that the requested operation is still permitted at execution time when policy-sensitive;
- event consumers must not assume upstream authorization automatically remains valid for every downstream action;
- cross-tenant async processing must be explicitly prevented unless platform policy allows it.

---

## 19. Logging and Audit Requirements

Access control events should be structured and reviewable.

### Log at minimum
- request id
- actor id
- actor type
- tenant id
- target resource type
- target resource id
- requested action
- decision result
- reason code
- policy version or rule id when feasible
- timestamp

### Log at elevated priority
- role grants and revocations
- permission grants and revocations
- impersonation start and stop
- support access
- export actions
- access denials on privileged routes
- unusual policy failures
- emergency overrides if ever implemented

Do not log secrets, raw tokens, or sensitive credential material.

---

## 20. Core Anti-Patterns to Forbid

The following implementation patterns should be treated as defects:

- trusting frontend checks as authorization;
- checking only roles without tenant or ownership context;
- performing authorization only at login time;
- granting broad wildcard admin rights without justification;
- embedding authorization logic ad hoc across controllers;
- inconsistent permission names across services;
- fetching data first and filtering after unauthorized exposure;
- omitting audit logs for privileged actions;
- using direct object identifiers without object-level permission checks;
- sharing service credentials across unrelated jobs or integrations.

---

## 21. Suggested Access Control Components

Recommended internal components:

```text
src/reva_studio/security/access_control/
├── domain/
│   ├── policies/
│   │   ├── base_policy.py
│   │   ├── booking_policy.py
│   │   ├── media_policy.py
│   │   ├── payment_policy.py
│   │   ├── loyalty_policy.py
│   │   └── staff_policy.py
│   ├── models/
│   │   ├── actor_context.py
│   │   ├── resource_context.py
│   │   ├── authorization_decision.py
│   │   └── permission.py
│   └── services/
│       └── authorization_service.py
├── application/
│   ├── guards/
│   ├── decorators/
│   ├── use_cases/
│   └── audit/
├── infrastructure/
│   ├── repositories/
│   ├── adapters/
│   └── logging/
└── presentation/
    ├── api/
    └── admin/