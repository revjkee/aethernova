# 0005-escrow-model
# ADR 0005 Escrow model

Status
Proposed

Date
2026-02-13

Owners
csmarket core team

Context
We need a transaction model that reduces counterparty risk between buyer and seller, supports disputes, and provides deterministic accounting for fees and refunds.
The model must be compatible with a marketplace where payment may be processed by external payment providers and delivery may be performed via an external platform integration.

We also need a security baseline for authentication, authorization, logging, and auditability.
For web application security verification we align with OWASP ASVS as a public, industry used verification standard. Source https://owasp.org/www-project-application-security-verification-standard/ and https://github.com/OWASP/ASVS. :contentReference[oaicite:0]{index=0}
For digital identity assurance and authentication considerations we use NIST Digital Identity Guidelines as a reference framework. Source https://pages.nist.gov/800-63-4/. :contentReference[oaicite:1]{index=1}
If card payments are introduced, handling of cardholder data must follow PCI DSS guidance and documentation from PCI SSC. Source https://www.pcisecuritystandards.org/standards/pci-dss/ and https://www.pcisecuritystandards.org/document_library/. :contentReference[oaicite:2]{index=2}
If the business becomes subject to AML requirements in the EU, we must implement relevant obligations per Directive (EU) 2018/843. Source https://eur-lex.europa.eu/eli/dir/2018/843/oj/eng and EU overview https://finance.ec.europa.eu/financial-crime/anti-money-laundering-and-countering-financing-terrorism-eu-level_en. :contentReference[oaicite:3]{index=3}

Decision
Adopt a ledger based escrow model with explicit transaction states.
Funds are captured into an escrow balance controlled by csmarket until a release condition is met.
Release can go to seller, refund to buyer, or split across seller and buyer based on dispute resolution.
Every state change is recorded as an immutable ledger event with idempotency keys.

Goals
1 Reduce settlement risk for buyer and seller
2 Deterministic accounting and fee calculation
3 Strong audit trail for disputes, chargebacks, and compliance
4 Idempotent processing across retries and asynchronous callbacks
5 Extensible to multiple payment methods and multiple delivery channels

Non goals
1 Acting as a bank or providing credit
2 Guaranteeing external delivery or platform side actions
3 Storing raw cardholder data in csmarket systems

Escrow account model
We maintain internal balances for users in a double entry ledger.

Core entities
1 PaymentIntent
Represents intent to pay for an order with a provider.
Fields
id
buyer_id
order_id
amount_total
currency
provider
provider_payment_intent_id
status

2 Order
Represents commercial agreement for a listing.
Fields
id
listing_id
buyer_id
seller_id
price
currency
fee_policy_id
status

3 EscrowHold
Represents the escrowed amount for an order.
Fields
id
order_id
amount_gross
amount_fee_reserved
amount_net_seller
currency
status

4 LedgerAccount
Represents an internal account
buyer_available
buyer_escrow
seller_available
platform_fee
platform_liability
provider_clearing

5 LedgerEntry
Immutable double entry record
Fields
id
idempotency_key
timestamp
debit_account
credit_account
amount
currency
reason
correlation_id
metadata_hash

Transaction states
Order status
Created
AwaitingPayment
PaymentAuthorized
Escrowed
Delivering
Delivered
ReleasePending
Released
Refunded
Disputed
Chargeback
Canceled
Failed

EscrowHold status
None
Active
ReleasePending
Released
RefundPending
Refunded
Frozen

PaymentIntent status
Created
ProviderPending
Authorized
Captured
Failed
Canceled
Reversed

State machine rules
1 Order Created then AwaitingPayment
2 Payment authorized by provider then Order PaymentAuthorized
3 Provider capture confirmed then EscrowHold Active and Order Escrowed
4 Delivery flow starts then Order Delivering
5 Delivery confirmed then Order Delivered and EscrowHold ReleasePending
6 Release executed then EscrowHold Released and Order Released
7 Refund executed then EscrowHold Refunded and Order Refunded
8 Dispute created at any stage from Escrowed to Released then Order Disputed and EscrowHold Frozen
9 Chargeback received from provider then Order Chargeback and ledger reconciliation starts

Ledger postings
All postings are double entry and must balance.
Amounts are examples in variables, not market claims.

Notation
A Gross amount
F Platform fee amount
N Net to seller where N equals A minus F

On capture to escrow
Debit provider_clearing by A
Credit buyer_escrow by A
Reason escrow_capture

Reserve fee inside escrow
Debit buyer_escrow by F
Credit platform_fee by F
Reason fee_reserve

Set seller net receivable
Debit buyer_escrow by N
Credit platform_liability by N
Reason seller_receivable

On release to seller
Debit platform_liability by N
Credit seller_available by N
Reason escrow_release

On refund to buyer before release
Reverse seller receivable if already set
Debit platform_liability by N
Credit buyer_escrow by N
Reason refund_reverse_receivable

Return funds to buyer available
Debit buyer_escrow by A
Credit buyer_available by A
Reason refund_to_buyer

Fee handling policy
Fee reservation is held until release window passes.
If refund occurs before release, fee reservation is reversed unless fee policy states otherwise.
Fee policy is an internal contract and must be explicitly versioned.

Disputes
Dispute triggers escrow freeze.
No release or refund can occur while Frozen unless an admin resolution event is recorded.
Resolution outcomes
1 Full refund
2 Full release
3 Split
Each outcome is executed as ledger postings with a mandatory resolution document reference id.

Chargebacks
Chargebacks are provider initiated reversals.
We create a chargeback case and lock all affected accounts for reconciliation.
Ledger entries record provider reference ids and evidence links.

Security requirements
1 Authentication
Support password based auth with risk based protections.
When designing authentication assurance and identity proofing considerations, use NIST Digital Identity Guidelines as a reference. :contentReference[oaicite:4]{index=4}

2 Authorization
RBAC for admin operations and dispute resolution actions.
Follow OWASP ASVS requirements as a verification baseline for access control and security controls. :contentReference[oaicite:5]{index=5}

3 Idempotency
Every external callback and every internal command must include idempotency_key.
If the same idempotency_key is replayed, the system must return the same result without duplicating ledger entries.

4 Data protection
Secrets stored in a vault solution.
Audit logs are append only and protected from modification.

5 Payments
Do not store raw cardholder data.
If card payments are used, align the environment with PCI DSS documentation and requirements from PCI SSC. :contentReference[oaicite:6]{index=6}

Compliance considerations
1 AML and countering terrorist financing
If the business activities fall within AML regulatory scope in the EU, obligations derive from Directive (EU) 2018/843 and related EU AML framework references. :contentReference[oaicite:7]{index=7}
This ADR does not assert that csmarket is in scope.
That classification is a legal determination.

2 Auditability
Every escrow state transition must be traceable via ledger entries and an immutable event log.

Operational considerations
1 Observability
Metrics
count of orders by status
escrow active total by currency
release latency distribution
refund latency distribution
dispute rate
chargeback count
Logs
structured logs with correlation_id for order_id and payment_intent_id
Traces
end to end trace spanning API, worker, provider callback handler

2 Backpressure and retries
All asynchronous steps use durable queues.
Retries must be safe due to idempotency.

3 Manual override
Admin actions are strictly audited and require explicit reason and attachment reference id.
RBAC gates apply.

Alternatives considered
1 Direct payout without escrow
Rejected because settlement risk is borne by buyer and disputes become harder.

2 External escrow provider only
Rejected for MVP because it limits control of state machine and audit detail.
May be revisited later.

Consequences
Positive
1 Reduced settlement risk through controlled release
2 Deterministic accounting via double entry ledger
3 Strong audit trail for disputes and refunds
4 Idempotent behavior across retries and callbacks

Negative
1 Increased implementation complexity
2 Requires careful security for admin dispute operations
3 Requires rigorous monitoring and reconciliation routines

Implementation outline
1 Introduce ledger core tables and immutable event log
2 Implement payment intent capture handler and escrow postings
3 Implement delivery confirmation integration and release pipeline
4 Implement dispute workflow with freeze and resolution postings
5 Implement reconciliation worker for provider settlement and chargebacks

Acceptance criteria
1 Every escrowed payment produces balanced ledger entries
2 Replaying the same provider callback does not change balances
3 Dispute freeze blocks release and refund until resolution event is recorded
4 Release and refund latencies are measurable and alertable
5 Admin actions are RBAC protected and fully audited

Links
OWASP ASVS https://owasp.org/www-project-application-security-verification-standard/ :contentReference[oaicite:8]{index=8}
OWASP ASVS repository https://github.com/OWASP/ASVS :contentReference[oaicite:9]{index=9}
NIST Digital Identity Guidelines 800-63-4 https://pages.nist.gov/800-63-4/ :contentReference[oaicite:10]{index=10}
PCI DSS standards page https://www.pcisecuritystandards.org/standards/pci-dss/ :contentReference[oaicite:11]{index=11}
PCI SSC document library https://www.pcisecuritystandards.org/document_library/ :contentReference[oaicite:12]{index=12}
Directive (EU) 2018/843 EUR-Lex https://eur-lex.europa.eu/eli/dir/2018/843/oj/eng :contentReference[oaicite:13]{index=13}
EU AML framework overview https://finance.ec.europa.eu/financial-crime/anti-money-laundering-and-countering-financing-terrorism-eu-level_en :contentReference[oaicite:14]{index=14}
