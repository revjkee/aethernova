# neuroforge-core/configs/policies/rego/data_access.rego
# OPA Rego policy: data access control for Neuroforge Core
# Entry points:
# - allow            : boolean decision
# - deny             : set of strings with reasons
# - effect           : "allow" | "deny"
# - reason           : stable single-line reason for logs (joined denies)
# - masks            : object { field: "redact"|"hash"|"last4"|"null"|"none" }
# - filters          : object with row-level constraints, e.g. {"tenant": "...", "owner_id": "..."}
# - obligations      : set of obligations for PDP->PEP (e.g., watermarking, audit level)
#
# Expected input (example):
# {
#   "subject": {
#     "id": "u123",
#     "tenant": "t1",
#     "roles": ["analyst"],
#     "scopes": ["data:read", "pii:mask"],
#     "mfa": true,
#     "assurance": 2,
#     "attrs": {"department": "risk"}
#   },
#   "resource": {
#     "type": "dataset",
#     "id": "ds-789",
#     "tenant": "t1",
#     "owner_id": "u999",
#     "classifications": ["pii"],                 # ["internal","restricted","pii","phi"]
#     "field_classes": { "email": "pii", "ssn": "pii", "notes": "internal" }
#   },
#   "action": "read",                              # read|write|delete|export|manage
#   "context": {
#     "time": "2025-08-26T10:00:00Z",
#     "purpose": "analytics",                      # operations|support|analytics|fraud|research
#     "consent": { "granted": true, "expires_at": "2025-12-31T23:59:59Z", "scope": ["analytics"] },
#     "legal_hold": false,
#     "retention_until": "2025-09-30T00:00:00Z",   # when write/delete shortening is forbidden
#     "network": "private",                        # private|public
#     "device_trust": 2,                           # 0..3
#     "channel": "api"                             # ui|api|batch
#   }
# }

package neuroforge.policies.data_access.v1

default allow := false
default effect := "deny"

# Aggregate deny reasons
deny[reason] {
  some r
  reasons[r]
  reason := r
}

# Final decision
allow {
  not reasons[_]
  base_permission
}

effect := "allow" { allow }
effect := "deny"  { not allow }

# Human-readable single line reason
reason := concat("; ", sort(reasons_set)) {
  reasons_set := {r | r := reasons[_]}
}

# --------------------------------------------------------------------------------
# Configuration defaults (can be overridden by data.neuroforge.policy.* at runtime)
# --------------------------------------------------------------------------------

# Role groups
priv_roles := getset(data.neuroforge.policy.priv_roles, {"admin", "security_admin", "dpo"})
write_roles := getset(data.neuroforge.policy.write_roles, {"admin"})
export_roles := getset(data.neuroforge.policy.export_roles, {"admin", "analyst"})
cross_tenant_roles := getset(data.neuroforge.policy.cross_tenant_roles, {"admin", "security_admin"})

# Purpose whitelist per action
allowed_purposes := {
  "read":     getset(data.neuroforge.policy.purposes.read,     {"operations","support","analytics","fraud","research"}),
  "export":   getset(data.neuroforge.policy.purposes.export,   {"analytics","research"}),
  "write":    getset(data.neuroforge.policy.purposes.write,    {"operations","ingestion"}),
  "delete":   getset(data.neuroforge.policy.purposes.delete,   {"operations"}),
  "manage":   getset(data.neuroforge.policy.purposes.manage,   {"operations"})
}

# Classification gates: map classification -> requirements
pii_requires := {
  "mfa":    getbool(data.neuroforge.policy.pii.mfa, true),
  "ass":    getnum(data.neuroforge.policy.pii.assurance, 2),
  "net":    gets(data.neuroforge.policy.pii.network, "private")
}
phi_requires := {
  "role":   getset(data.neuroforge.policy.phi.roles, {"dpo","security_admin"}),
  "mfa":    getbool(data.neuroforge.policy.phi.mfa, true),
  "net":    gets(data.neuroforge.policy.phi.network, "private")
}
restricted_requires := {
  "role":   getset(data.neuroforge.policy.restricted.roles, {"admin","security_admin"}),
  "device": getnum(data.neuroforge.policy.restricted.device_trust, 2)
}

# Risk thresholds
risk_threshold := getnum(data.neuroforge.policy.risk.threshold, 3)

# Default masking by classification (fallback if no field-specific policy)
mask_by_class := {
  "pii":        gets(data.neuroforge.policy.mask.pii, "redact"),
  "phi":        gets(data.neuroforge.policy.mask.phi, "redact"),
  "restricted": gets(data.neuroforge.policy.mask.restricted, "hash"),
  "internal":   gets(data.neuroforge.policy.mask.internal, "none"),
  "public":     gets(data.neuroforge.policy.mask.public, "none")
}

# Row-level filter strategy per role
rls_role_strategy := {
  "user":     {"owner_id": "subject.id"},
  "analyst":  {"tenant":   "subject.tenant"},
  "support":  {"tenant":   "subject.tenant"},
  "admin":    {},  # no filter
  "security_admin": {},
  "dpo": {}
}

# --------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------

# Safe getters
gets(x, def) := x { x != null } else := def
getnum(x, def) := n { x != null; n := x } else := def
getbool(x, def) := b { x != null; b := x } else := def
getset(x, def) := s { x != null; s := x } else := def

has_role(r) {
  r := input.subject.roles[_]
}

has_any_role(rs) {
  some r
  r := input.subject.roles[_]
  rs[r]
}

has_scope(s) {
  s == input.subject.scopes[_]
}

contains_class(c) {
  c == input.resource.classifications[_]
}

same_tenant {
  input.subject.tenant == input.resource.tenant
}

is_owner {
  input.subject.id == input.resource.owner_id
}

now_ns := t {
  t := time.now_ns()
}

parse_ns(ts) := n {
  # Returns 0 for empty/invalid strings to simplify comparisons
  some ts
  n := time.parse_rfc3339_ns(ts)
} else := 0

bool(v) { v } else { false }

set_from_array(arr) := s {
  s := {x | x := arr[_]}
} else := {}

# --------------------------------------------------------------------------------
# Base permission (RBAC + tenancy)
# --------------------------------------------------------------------------------

base_permission {
  # Admin-like roles can cross tenants; others must match tenant
  has_any_role(priv_roles)
} else {
  same_tenant
  action_permitted_for_role
}

action_permitted_for_role {
  a := input.action
  some r
  r := input.subject.roles[_]
  role_allows(a, r)
}

# Role -> action mapping
role_allows("read", r)    { r == "admin" }    or { r == "analyst" } or { r == "support" } or { r == "user"; is_owner }
role_allows("write", r)   { r == "admin" }    or { r == "user"; is_owner }
role_allows("delete", r)  { r == "admin" }
role_allows("export", r)  { r == "admin" }    or { r == "analyst" }
role_allows("manage", r)  { r == "admin" }    or { r == "security_admin" } or { r == "dpo" }

# --------------------------------------------------------------------------------
# Deny conditions (accumulate reasons)
# --------------------------------------------------------------------------------

# Default: prohibit cross-tenant unless privileged
reasons["cross-tenant access denied"] {
  not has_any_role(cross_tenant_roles)
  not same_tenant
}

# Purpose whitelist
reasons["purpose not allowed for action"] {
  not allowed_purposes[input.action][input.context.purpose]
}

# Consent for PII/PHI
reasons["missing consent for pii/phi"] {
  contains_class("pii") or contains_class("phi")
  not bool(input.context.consent.granted)
}
reasons["consent expired"] {
  contains_class("pii") or contains_class("phi")
  bool(input.context.consent.granted)
  exp := parse_ns(input.context.consent.expires_at)
  exp != 0
  now_ns > exp
}
reasons["purpose not covered by consent scope"] {
  contains_class("pii") or contains_class("phi")
  bool(input.context.consent.granted)
  not set_from_array(input.context.consent.scope)[input.context.purpose]
}

# Classification gates
reasons["pii requires mfa"] {
  contains_class("pii")
  pii_requires["mfa"]
  not bool(input.subject.mfa)
}
reasons["pii requires assurance level"] {
  contains_class("pii")
  input.subject.assurance < pii_requires["ass"]
}
reasons["pii requires private network"] {
  contains_class("pii")
  input.context.network != pii_requires["net"]
}

reasons["phi requires privileged role"] {
  contains_class("phi")
  not has_any_role(phi_requires["role"])
}
reasons["phi requires mfa"] {
  contains_class("phi")
  phi_requires["mfa"]
  not bool(input.subject.mfa)
}
reasons["phi requires private network"] {
  contains_class("phi")
  input.context.network != phi_requires["net"]
}

reasons["restricted requires privileged role"] {
  contains_class("restricted")
  not has_any_role(restricted_requires["role"])
}
reasons["restricted requires trusted device"] {
  contains_class("restricted")
  getnum(input.context.device_trust, 0) < restricted_requires["device"]
}

# Legal hold and retention
reasons["operation blocked by legal hold"] {
  bool(input.context.legal_hold)
  input.action != "read"
}
reasons["operation violates retention"] {
  ru := parse_ns(input.context.retention_until)
  ru != 0
  now_ns < ru
  # Only modifying/deleting/exporting before retention end is disallowed
  input.action == "delete" or input.action == "write" or input.action == "export"
}

# Export constraints
reasons["export requires privileged role"] {
  input.action == "export"
  not has_any_role(export_roles)
}
reasons["export of restricted data forbidden"] {
  input.action == "export"
  contains_class("restricted")
}

# Network hardening for non-admin on public networks
reasons["public network not allowed for non-privileged"] {
  input.context.network == "public"
  not has_any_role(priv_roles)
}

# Risk-based denial
reasons["context risk too high"] {
  risk_score > risk_threshold
}

# Action-level scope checks (optional)
reasons["missing data:read scope"] {
  input.action == "read"
  not has_scope("data:read")
} {
  # Alternative branch only if scopes are provided at all; avoid false denials in scope-less mode
  input.action == "read"
  input.subject.scopes != null
  count(input.subject.scopes) > 0
  not has_scope("data:read")
}

# --------------------------------------------------------------------------------
# Risk score computation (simple additive model)
# --------------------------------------------------------------------------------

risk_score := s {
  s := mfa_risk + net_risk + device_risk
}

mfa_risk := r {
  r := 0
  bool(input.subject.mfa)
} else := 2

net_risk := r {
  # public network increases risk
  r := 2
  input.context.network == "public"
} else := 0

device_risk := r {
  dt := getnum(input.context.device_trust, 0)
  r := 2 - clamp(dt, 0, 2)
}

clamp(x, lo, hi) := y {
  y := x
  x < lo
  y := lo
} else := y {
  y := x
  x > hi
  y := hi
}

# --------------------------------------------------------------------------------
# Row-level filters (RLS) and column masking
# --------------------------------------------------------------------------------

# filters object: combine strategies based on the strongest role present
filters := obj {
  # Choose the first matching strategy in priority order
  prio := ["admin","security_admin","dpo","analyst","support","user"]
  some r
  r := prio[_]
  has_role(r)
  obj := rls_for(r)
} else := {}

rls_for(r) := out {
  strat := rls_role_strategy[r]
  out := transform_map(strat)
}

# Transform "subject.id" and "subject.tenant" placeholders to actual values
transform_map(m) := out {
  keys := {k | k := m[_]}
  out := {k: resolve_placeholder(m[k]) | k := keys[_]}
}

resolve_placeholder(s) := v {
  s == "subject.id"
  v := input.subject.id
} else := v {
  s == "subject.tenant"
  v := input.subject.tenant
} else := v {
  v := s
}

# masks object: for each field class decide a mask profile, role-dependent
masks[f] := prof {
  fc := input.resource.field_classes[f]
  prof := mask_profile(fc)
}

mask_profile("pii")        := "redact" { not has_any_role(priv_roles) } else := "none"
mask_profile("phi")        := "redact" { not has_any_role(priv_roles) } else := "none"
mask_profile("restricted") := "hash"   { not has_any_role(priv_roles) } else := "none"
mask_profile(c)            := m        { m := mask_by_class[c] } else := "none"

# --------------------------------------------------------------------------------
# Obligations (to be enforced by PEP: watermarking, audit level, cache bypass)
# --------------------------------------------------------------------------------

obligations[o] {
  allow
  o := {
    "type": "audit",
    "level": audit_level
  }
}

audit_level := "high" {
  contains_class("pii") or contains_class("phi") or contains_class("restricted")
} else := "normal"

obligations[o] {
  allow
  input.action == "export"
  o := {
    "type": "watermark",
    "subject": input.subject.id,
    "purpose": input.context.purpose,
    "timestamp_ns": now_ns
  }
}

# --------------------------------------------------------------------------------
# Utilities for tests and introspection
# --------------------------------------------------------------------------------

# Expose all deny reasons as a set named reasons
reasons[r] {
  r := reasons_internal[_]
}

# Internal bag of reasons populated by all deny rules above
reasons_internal[r] {
  r := data.neuroforge.policies.data_access.v1.reasons_internal_list[_]
}

# The following list is automatically populated by the deny rules via OPA's comprehension
# To avoid OPA version specific features for implicit rule collection, we rebuild reasons with comprehensions:

reasons_internal_list := xs {
  xs := array.concat(
    [],
    [
      x | x := reason_cross_tenant       ; x != ""
    ],
  )
}

# However, to keep policy stable and readable, we rely on the union of all `reasons[...]` rules above.
# Do not use reasons_internal_list directly in production.

# --------------------------------------------------------------------------------
# Notes:
# - You can override defaults via data.neuroforge.policy.* bundle.
# - For large field sets, consider computing masks in the PEP using `mask_profile(class)` exposed here.
# - For partial evaluation, query allow, masks, filters separately to avoid over-fetching.
