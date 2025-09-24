# File: oblivionvault-core/configs/policies/rego/erasure_eligibility.rego
# Purpose: Industrial-grade Rego policy for data erasure eligibility in oblivionvault-core.
# Enforces compliance (GDPR/CCPA), retention policies, legal holds, security reviews.

package oblivionvault.erasure.eligibility

# ------------------------------
# Default rule: deny erasure
# ------------------------------
default allow = false
default deny_reason = "Not evaluated"

# ------------------------------
# Input schema (example)
# input = {
#   "subject": { "id": "user-123", "roles": ["user"], "tenant": "acme" },
#   "resource": { "type": "vault-record", "id": "rec-456", "createdAt": "2021-08-01T10:00:00Z", "dataTags": ["pii"] },
#   "request": { "time": "2025-08-25T12:00:00Z", "action": "erase" },
#   "flags": { "gdpr": true, "ccpa": true },
#   "legal": { "investigation_hold": false, "retention_period_days": 365 },
#   "security": { "risk_level": "low", "pending_alerts": false },
#   "consent": { "withdrawn": true, "timestamp": "2023-06-01T12:00:00Z" }
# }
# ------------------------------

# ------------------------------
# Helpers
# ------------------------------

import future.keywords.in
import future.keywords.if
import time
import rego.v1

# Duration calculation helper (days between timestamps)
days_between(start, end) = days {
  s := time.parse_rfc3339_ns(start)
  e := time.parse_rfc3339_ns(end)
  delta := (e - s) / 1000000000  # ns -> sec
  days := delta / 86400
}

# Role check
is_admin {
  "admin" in input.subject.roles
}

# Subject verification
subject_verified {
  input.subject.id != ""
  count(input.subject.roles) > 0
}

# ------------------------------
# Conditions for erasure
# ------------------------------

# Condition 1: Retention period satisfied
retention_satisfied {
  created := input.resource.createdAt
  now := input.request.time
  retention := input.legal.retention_period_days
  days_elapsed := days_between(created, now)
  days_elapsed >= retention
}

# Condition 2: No active legal hold
no_legal_hold {
  not input.legal.investigation_hold
}

# Condition 3: Explicit consent withdrawal (if PII)
consent_withdrawn_if_pii {
  "pii" in input.resource.dataTags
  input.consent.withdrawn
}

consent_not_required_if_nonpii {
  not ("pii" in input.resource.dataTags)
}

# Condition 4: Security context safe
security_clear {
  input.security.risk_level == "low"
  not input.security.pending_alerts
}

# Condition 5: Regulatory flags allow
regulatory_applicable {
  input.flags.gdpr == true
  input.flags.ccpa == true
}

# ------------------------------
# Final decision
# ------------------------------

allow if {
  subject_verified
  no_legal_hold
  retention_satisfied
  security_clear
  regulatory_applicable
  (consent_withdrawn_if_pii or consent_not_required_if_nonpii)
}

deny_reason = reason if {
  not allow
  reason := concat("; ", reasons)
  reasons := {
    r |
    some check
    check = {
      "retention":   not retention_satisfied,
      "legal_hold":  not no_legal_hold,
      "consent":     not (consent_withdrawn_if_pii or consent_not_required_if_nonpii),
      "security":    not security_clear,
      "regulatory":  not regulatory_applicable,
      "identity":    not subject_verified,
    }
    k := [k | v := check[k]; v]
    r := sprintf("%v failed", [k])
  }
}

# ------------------------------
# Audit log emission (virtual)
# ------------------------------

audit_event = {
  "subject": input.subject.id,
  "resource": input.resource.id,
  "action": input.request.action,
  "timestamp": input.request.time,
  "decision": allow,
  "reason": deny_reason
}
