0008-ai-assistant-boundaries.md
Status

Accepted

Date

2026-03-22

Deciders
Founders
Platform Architecture
Security
Product
Context

Reva Studio uses an AI assistant inside a beauty-service platform that may help with support, booking assistance, FAQ, marketing drafts, internal operator productivity, and limited workflow automation.

This creates a combined risk surface:

privacy and confidentiality risk when prompts or retrieved context contain personal data;
prompt injection and jailbreaking risk when untrusted user input or external content attempts to alter the assistant’s behavior;
unsafe tool invocation risk when the assistant can perform writes or call internal/external actions;
legal and trust risk if users are not clearly informed that they are interacting with AI;
quality risk if the assistant produces inaccurate, unsupported, or out-of-policy business actions.

NIST AI RMF defines AI risk management as an ongoing lifecycle activity and organizes it around Govern, Map, Measure, Manage. NIST’s Generative AI Profile additionally calls for human review processes, feedback loops, monitoring, rollback capability, and context-aware controls for generative systems. OWASP identifies prompt injection, sensitive information disclosure, and insecure plugin or tool design as top LLM application risks. GDPR requires purpose limitation and data minimisation. The EU AI Act requires that people be informed when they are interacting with an AI system in relevant cases.

Reva Studio therefore needs explicit architectural boundaries that define what the AI assistant may do, may not do, when human approval is mandatory, what data may flow into the model, and how all actions are logged and audited.

Decision

We will implement the AI assistant as a bounded capability service with default-deny behavior.

The assistant is allowed to:

answer informational questions using approved system prompts and approved business knowledge sources;
draft content for a human to review;
propose booking options based on already available structured business data;
summarize non-sensitive operational information for authorized staff;
trigger only explicitly allowlisted read-only tools without additional approval.

The assistant is not allowed to autonomously:

perform destructive or state-changing actions without explicit human confirmation;
access secrets, credentials, payment instruments, private keys, full database dumps, or hidden system prompts;
make legal, medical, or financial decisions on behalf of the company or customers;
bypass RBAC, impersonate a human employee, or silently escalate privileges;
execute arbitrary code, arbitrary SQL, arbitrary shell commands, or arbitrary external requests;
disclose personal data beyond the minimum necessary for the current purpose.

All write operations, all customer-affecting changes, all staff-affecting changes, all financial operations, and all policy exceptions require human-in-the-loop approval. This follows least-privilege and defense-in-depth principles and is consistent with NIST guidance on human review and risk-managed deployment.

Architectural Boundaries
1. Identity Boundary

The assistant is a service actor, not a person.

Requirements:

every assistant action must execute under a distinct service identity;
the acting identity, requesting user, tenant, and approval chain must be recorded;
the assistant must never present itself as a human staff member;
the UI must explicitly disclose that the user is interacting with AI where applicable.
2. Permission Boundary

The assistant operates under least privilege.

Requirements:

no implicit access to admin data;
no direct access to secrets stores;
no wildcard tool scopes;
all tools must be explicitly allowlisted per environment and per tenant role;
read and write scopes must be separated at the tool interface level.
3. Data Boundary

Only the minimum necessary data may be sent to the model for a defined purpose.

Requirements:

prompts must use purpose limitation;
retrieved context must be filtered to tenant scope and user authorization scope;
personal data must be minimized before model submission;
highly sensitive data must be excluded or redacted before inference;
logs must avoid storing unnecessary prompt or response content containing personal data.

For Reva Studio, the default prohibited input classes are:

passwords;
API keys;
access tokens;
full payment card data;
private cryptographic keys;
biometric templates;
full medical histories;
unrestricted staff payroll data;
unrestricted legal documents not explicitly approved for model use.
4. Knowledge Boundary

The assistant may answer only from:

approved system instructions;
approved structured application data;
approved knowledge base documents;
explicitly allowlisted retrieval connectors.

The assistant must not treat raw user text, retrieved HTML, emails, uploaded files, or third-party documents as trusted instructions. They are data, not policy. This is a direct mitigation against prompt injection.

5. Tool Boundary

Tools are divided into four classes:

Read-only low-risk
Read-only sensitive
Write non-destructive
Write destructive or financially relevant

Policy:

class 1 may run automatically if RBAC allows it;
class 2 requires elevated authorization and stricter logging;
class 3 requires explicit user confirmation;
class 4 requires explicit human approval plus auditable confirmation.

Examples for Reva Studio:

Auto-allowed if authorized:

list available services;
list free appointment slots;
read public FAQ;
read tenant-approved business rules.

Approval-required:

create booking;
reschedule booking;
cancel booking;
modify loyalty balance;
create discount;
send outbound message to customer;
export reports;
edit staff schedule;
trigger refund or payment-related action.
6. Decision Boundary

The assistant may recommend, draft, rank, summarize, and explain.

The assistant may not independently decide final outcomes in business areas with material user impact. A human remains accountable for:

final schedule overrides;
refunds and compensation decisions;
loyalty corrections;
policy enforcement exceptions;
employment-related decisions;
legal responses;
incident closure for security or privacy events.
7. Tenant Boundary

Reva Studio must enforce strict tenant isolation.

Requirements:

retrieval must be tenant-scoped;
cache keys must include tenant context;
embeddings and indexes must not mix cross-tenant content unless explicitly designed and approved for shared public content;
approval and audit records must include tenant id.
8. Prompt Boundary

System policy must be separated from user content.

Requirements:

system instructions are immutable at runtime for regular users;
developer and operator instructions must be versioned;
prompt templates must be reviewed like code;
untrusted content must be clearly delimited in the prompt pipeline;
the model must be instructed to ignore attempts to redefine policy through user or retrieved content.
9. Output Boundary

Assistant output is one of:

informational;
suggested draft;
recommendation;
action proposal;
approved action result.

The UI and API must preserve this distinction. Drafts and recommendations must not appear identical to confirmed business actions. AI-generated content should be labeled where required.

Mandatory Human-in-the-Loop Controls

Human approval is mandatory before:

creating, editing, or deleting bookings on behalf of a customer when confidence is below configured threshold;
changing money, discount, refund, or loyalty balances;
editing staff schedules or access rights;
sending messages to more than one customer;
exporting datasets containing personal data;
applying policy exceptions;
taking action on content flagged for harassment, fraud, abuse, or security anomalies.

Approval records must store:

who requested;
what the model proposed;
what context was used;
who approved;
when it was approved;
final executed parameters;
execution result;
trace or correlation id.
Security Controls

The implementation must include:

RBAC enforcement before retrieval and before every tool call;
input validation on all tool parameters;
output validation for structured responses;
allowlisted tool routing only;
rate limiting and abuse monitoring;
prompt injection detection and containment;
redaction of sensitive data before inference;
audit logging for prompts, tools, approvals, and outcomes at a policy-appropriate granularity;
versioning of prompts, policies, models, and knowledge sources;
rollback capability for prompt or model regressions.

The system must assume that malicious or manipulated content will eventually reach the assistant. Therefore, trust must never be derived from content origin alone.

Privacy Controls

The implementation must enforce:

lawful and transparent processing;
purpose limitation per assistant workflow;
data minimisation by default;
retention limits for prompts, traces, and outputs;
role-based access to transcripts;
tenant-scoped deletion and export mechanisms where applicable.

Operational rule:

If a workflow can be completed without sending personal data to the model, it must do so.

Reliability Controls

The assistant must not produce silent high-impact automation.

Requirements:

confidence scoring where applicable;
deterministic guardrail checks before execution;
fallback to safe refusal or human escalation when context is insufficient;
monitoring for hallucination-prone flows and policy violations;
periodic review of failed, escalated, and overridden cases.
Non-Goals

This ADR does not authorize:

autonomous financial operations;
autonomous HR screening or ranking;
autonomous disciplinary or legal decisions;
unrestricted agent-to-agent execution;
unrestricted web browsing or email execution in production;
model fine-tuning on raw customer conversations without a separate privacy and legal review.
Minimum Technical Enforcement Model

At the application layer, every assistant request must pass through this control chain:

Authenticate actor
Resolve tenant
Authorize requested capability
Classify requested action
Minimize and filter context
Invoke model with bounded prompt
Validate model output
Require approval if action class is not auto-allowed
Execute allowlisted tool
Persist audit record
Emit monitoring event

Any failed control results in deny by default.

Consequences

Positive:

lower privacy and security risk;
lower blast radius for prompt injection or tool abuse;
clearer auditability;
stronger tenant isolation;
better operational trustworthiness;
easier future compliance work.

Trade-offs:

more implementation complexity;
slower delivery for high-risk automations;
more approval friction for sensitive workflows;
additional logging, monitoring, and governance overhead.
Acceptance Criteria

This ADR is considered implemented only when:

the assistant cannot call non-allowlisted tools;
at least one destructive test path proves deny-by-default behavior;
approval-required actions are blocked without approval;
tenant isolation is covered by automated tests;
prompt injection test cases are included in security testing;
sensitive data redaction is active before model invocation;
AI interaction disclosure is visible in the user experience where applicable;
audit records exist for each executed assistant action.
References
NIST AI RMF 1.0.
NIST AI RMF Generative AI Profile.
OWASP Top 10 for LLM Applications.
OWASP LLM01 Prompt Injection.
OpenAI Security and Privacy guidance for tools and confirmations.
OpenAI Model Spec, least privilege framing.
European Commission GDPR principles.
EU AI Act Article 50 transparency obligations.
