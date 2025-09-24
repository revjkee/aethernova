# policy-core/configs/policies/rego/data_access.rego
# Industrial data-access policy for policy-core
# Inputs (contract):
#   input.subject: {
#       id, roles: [string], tenant_id, department, clearance: "public|internal|confidential|restricted|secret",
#       purpose: "analytics|support|fraud|ops|audit|training|export", mfa: bool,
#       consent: {<dataset_or_resource_id>: bool},
#       device_trust: "low|medium|high"
#   }
#   input.resource: {
#       id, type: "dataset|table|view|column", name, owner_tenant_id,
#       classification: "public|internal|confidential|restricted|secret",
#       pii: bool, geo_zone: "global|eea|local",
#       columns: [{name, classification, pii: bool}],
#       tags: [string]
#   }
#   input.action: "read|write|delete|export|metadata"
#   input.context: {
#       request_id, hour: number, out_of_hours: bool,
#       geo_country: string, network: "public|vpn|private",
#       approvals: [string], emergency: bool,
#       allowed_countries: [string] # optional, per env/policy
#   }

package policy_core.data_access

default allow := false

# -------------------------
# Helpers
# -------------------------

rank["public"]       := 0
rank["internal"]     := 1
rank["confidential"] := 2
rank["restricted"]   := 3
rank["secret"]       := 4

clearance_ok := rank[input.subject.clearance] >= rank[input.resource.classification]

pii_required := input.resource.pii == true
pii_column_present := some c
c := input.resource.columns[_]
c.pii == true

sensitive := rank[input.resource.classification] >= rank["confidential"]

mfa_required_for := {"write", "delete"}
break_glass_roles := {"sec_admin", "platform_owner", "dpo"}

# Default geo allow-list if not provided externally.
default allowed_geo := {"global"}
allowed_geo := {x | x := input.context.allowed_countries[_]} else {"global"}

is_cross_tenant := input.subject.tenant_id != input.resource.owner_tenant_id

# Role permissions per resource type -> allowed actions
role_permissions := {
  "admin":     {"dataset": {"read","write","delete","export"}, "table": {"read","write","delete","export"}, "view": {"read","export"}, "column": {"read"}},
  "analyst":   {"dataset": {"metadata"}, "table": {"read","export"}, "view": {"read","export"}, "column": {"read"}},
  "engineer":  {"dataset": {"metadata","read","write"}, "table": {"read","write"}, "view": {"read"}, "column": {"read"}},
  "auditor":   {"dataset": {"metadata","read"}, "table": {"read"}, "view": {"read"}, "column": {"read"}},
  "support":   {"dataset": {"metadata"}, "table": {"read"}, "view": {"read"}, "column": {"read"}},
  "dpo":       {"dataset": {"metadata","read","export"}, "table": {"read","export"}, "view": {"read","export"}, "column": {"read"}}
}

some_role_allows {
  role := input.subject.roles[_]
  perms := role_permissions[role][input.resource.type]
  perms[input.action]
}

# Cross-tenant read only with special role and approval
cross_tenant_ok {
  is_cross_tenant
  role := input.subject.roles[_]
  role == "cross_tenant_viewer"
  approvals_contains("owner_approved")
}

approvals_contains(x) {
  some a
  a := input.context.approvals[_]
  a == x
}

# Business-hour and device constraints (simple, context-provided)
out_of_hours := input.context.out_of_hours == true

device_sufficient := input.subject.device_trust == "high" or input.subject.device_trust == "medium"

# Network restrictions for sensitive data
network_ok := not sensitive; not pii_required
network_ok {
  sensitive
  input.context.network != "public"
}

# Purpose limitation examples
purpose_ok {
  not pii_required
}
purpose_ok {
  pii_required
  input.subject.purpose == "support"
}
purpose_ok {
  pii_required
  input.subject.purpose == "fraud"
}
# analytics on PII must be aggregated or masked (enforced via obligations)
analytics_pii := pii_required and input.subject.purpose == "analytics"

# Consent required for PII unless DPO or explicit approval
consent_ok {
  not pii_required
}
consent_ok {
  pii_required
  input.subject.roles[_] == "dpo"
}
consent_ok {
  pii_required
  approvals_contains("dpo_approved")
}
consent_ok {
  pii_required
  input.subject.consent[input.resource.id] == true
}

# Geo policy
geo_ok {
  allowed_geo == {"global"}
}
geo_ok {
  allowed_geo != {"global"}
  allowed_geo[input.context.geo_country]
}
geo_ok {
  input.resource.geo_zone == "global"
}

# MFA policy
mfa_ok {
  not mfa_required_for[input.action]
}
mfa_ok {
  mfa_required_for[input.action]
  input.subject.mfa == true
}

# Writable actions need higher clearance
clearance_write_ok {
  input.action == "write" or input.action == "delete"
  rank[input.subject.clearance] >= rank["restricted"]
}
clearance_write_ok {
  not (input.action == "write" or input.action == "delete")
}

# Column masking obligations for insufficient clearance
mask_columns[{"column": c.name, "mask": mask_type(c)}] {
  c := input.resource.columns[_]
  needs_mask(c)
}

needs_mask(c) {
  c.pii == true
  not clearance_ok
}
needs_mask(c) {
  rank[c.classification] >= rank["restricted"]
  not clearance_ok
}

mask_type(c) := "hash" { c.pii == true }
mask_type(c) := "nullify" { rank[c.classification] >= rank["secret"] }
mask_type(c) := "partial" { rank[c.classification] == rank["restricted"] }
mask_type(c) := "tokenize" { rank[c.classification] == rank["confidential"]; not c.pii }

# Row-level security filter (example contract for engine)
# Attach tenant and optional geo scoping; environments consume this as a structured filter.
filter := f {
  f := {
    "where": arr
  }
  arr := conds
  conds := [tcond] if {
    tcond := {"column": "tenant_id", "op": "=", "value": input.subject.tenant_id}
  }
  conds := conds_plus if {
    conds0 := [ {"column": "tenant_id", "op": "=", "value": input.subject.tenant_id} ]
    conds_plus := conds0 ++ geo_append
  }
}

geo_append := [] { not (input.resource.geo_zone == "local") }
geo_append := [ {"column": "geo_country", "op": "=", "value": input.context.geo_country} ] { input.resource.geo_zone == "local" }

# -------------------------
# Deny reasons (collect)
# -------------------------

deny[reason] {
  not some_role_allows
  reason := "role_forbids_action"
}

deny[reason] {
  is_cross_tenant
  not cross_tenant_ok
  reason := "tenant_isolation"
}

deny[reason] {
  sensitive
  not clearance_ok
  reason := "insufficient_clearance"
}

deny[reason] {
  pii_required
  not consent_ok
  reason := "consent_required"
}

deny[reason] {
  not network_ok
  reason := "insecure_network_for_sensitive_data"
}

deny[reason] {
  not geo_ok
  reason := "geo_restricted"
}

deny[reason] {
  out_of_hours
  not input.subject.mfa
  reason := "mfa_required_out_of_hours"
}

deny[reason] {
  not mfa_ok
  reason := "mfa_required"
}

deny[reason] {
  input.action == "export"
  pii_required
  not approvals_contains("dpo_approved")
  reason := "pii_export_requires_dpo_approval"
}

deny[reason] {
  (input.action == "write" or input.action == "delete")
  not clearance_write_ok
  reason := "write_delete_requires_restricted_clearance"
}

# -------------------------
# Break-glass (overrides deny, but adds obligations)
# -------------------------

break_glass_ok {
  input.context.emergency == true
  some r
  r := input.subject.roles[_]
  break_glass_roles[r]
  approvals_contains("incident_ticket")  # e.g., IR-XXXX provided
}

# -------------------------
# Allow decision
# -------------------------

allow {
  count(deny) == 0
}

allow {
  count(deny) > 0
  break_glass_ok
}

# -------------------------
# Obligations
# -------------------------

base_obligations[o] {
  o := {"type": "audit", "level": "full", "sink": ["audit", "security"]}
}
base_obligations[o] {
  o := {"type": "watermark", "scope": ["export","render"], "value": input.subject.id}
}
base_obligations[o] {
  o := {"type": "correlate", "trace": true}
}
# Enforce masking when needed
obligations[o] {
  o := {"type": "masking", "columns": mask_columns}
  count(mask_columns) > 0
}
# Analytics on PII must be aggregated or masked
obligations[o] {
  analytics_pii
  o := {"type": "aggregation_required", "min_k_anonymity": 25}
}
# Strong logging for sensitive access
obligations[o] {
  sensitive
  o := {"type": "notify", "recipients": ["data_owner","security"], "channel": "pager"}
}
# Break-glass obligations
obligations[o] {
  break_glass_ok
  o := {"type": "break_glass", "expires_sec": 900, "reason": "emergency_access", "mandatory_ticket": true}
}

# -------------------------
# Result object
# -------------------------

result := {
  "allow": allow,
  "reasons": reasons_array,
  "mask": mask_columns_sorted,
  "filter": filter,
  "obligations": obligations_array,
  "ttl_sec": ttl,
  "decision_id": decision_id
}

decision_id := x { x := input.context.request_id } else := "n/a"

ttl := 900 { allow } else := 0

# Sort arrays for deterministic output
reasons_array := arr {
  arr := sort([r | r := deny[_]])
}

mask_columns_sorted := arr {
  arr := sort([sprintf("%s:%s", [c.column, c.mask]) | c := mask_columns[_]])
  # expand back to objects after sort
} else := []  # no mask

# Reconstruct objects after string sort (stable output)
mask_columns_sorted := [ {"column": split(s, ":")[0], "mask": split(s, ":")[1]} | s := sort([sprintf("%s:%s",[m.column, m.mask]) | m := mask_columns[_]])[_] ]

obligations_array := arr {
  # union of base + dynamic obligations
  all := {o | base_obligations[o]} | {o | obligations[o]}
  arr := [o | o := all[_]]
}
