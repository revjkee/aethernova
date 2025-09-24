package policies.retention

# Industrial-grade retention policy for OblivionVault.
# Evaluate with: opa eval -i input.json -d retention_rules.rego "data.policies.retention.decision"
#
# INPUT (example shape):
# {
#   "dataset": "payments",
#   "jurisdiction": "GDPR",
#   "request": { "type": "erasure", "initiator": "user", "subject_id": "u_123" },
#   "record": {
#     "id": "rec_1",
#     "created_at": "2022-07-01T12:00:00Z",
#     "last_activity_at": "2023-10-10T10:00:00Z",
#     "event_anchor_at": "2023-10-10T10:00:00Z"  # e.g., contract_end, account_close, etc.
#   },
#   "flags": {
#     "legal_hold": false,
#     "fraud_investigation": false,
#     "statutory_retention": false,
#     "auditable_financial": true
#   },
#   "overrides": {
#     "manager_approved": false,
#     "dpo_approved": false
#   },
#   "now": "2025-08-25T00:00:00Z"
# }
#
# DATA (policy config) expected under data.retention.*
# data.retention.datasets.<name> = {
#   "min_age": "7y",                         # minimal age since created_at or last_activity_at
#   "min_age_anchor": "created_at",          # created_at | last_activity_at | event_anchor_at
#   "event_min_age": "3y",                   # optional event-based minimum after event_anchor_at
#   "immutable": false,
#   "erasure": {
#     "allowed": true,                       # allow erasure at all
#     "method": "anonymize",                 # hard_delete | soft_delete | anonymize | tombstone
#     "grace_period": "30d",                 # soft_delete / user reversal window
#     "requires": ["privacy_manager"],       # approvals for erasure
#     "prohibitions": ["auditable_financial","statutory_retention","fraud_investigation"]
#   },
#   "archive": {
#     "enabled": true,
#     "after_age": "5y",                     # move to archive tier
#     "cold_after_age": "7y"
#   },
#   "jurisdictions": {
#     "GDPR": { "min_age": "7y", "erasure_requires": ["dpo"] },
#     "CCPA": { "min_age": "2y" }
#   }
# }
#
# data.retention.jurisdictions.GDPR = {
#   "default_min_age": "3y",
#   "erasure_additional_grounds": ["Art.17(1) GDPR"],
#   "erasure_exemptions": ["Art.17(3) GDPR"]
# }

import future.keywords.every

########################
## Top-level decision ##
########################

# Default decision if nothing else matches.
default decision := {
  "action": "keep",
  "status": "stable",
  "legal_basis": [],
  "approvals_required": [],
  "reasoning": ["default_keep_no_specific_rule"],
  "audit_tags": ["retention:default", sprintf("dataset:%v", [input.dataset])],
}

# 1) Legal hold strictly dominates.
decision := d {
  legal_hold_active
  d := base_decision("keep", "on_hold", ["legal_hold_active"], ["retention:legal_hold"])
}

# 2) Statutory or auditing exclusions block erasure/hard delete.
decision := d {
  exclusions_blocking
  d := base_decision("keep", "excluded", ["statutory_or_audit_exclusion"], ["retention:excluded"])
}

# 3) Dataset immutable -> never purge, maybe archive.
decision := d {
  ds_config.immutable == true
  d := maybe_archive_or_keep("immutable_dataset")
}

# 4) Erasure (subject request) can proceed if allowed, age satisfied, no prohibitions, approvals satisfied.
decision := d {
  is_erasure_request
  erasure_allowed
  age_satisfied_for_erasure
  not erasure_prohibited
  approvals_satisfied
  d := erasure_decision
}

# 5) If archive thresholds reached, move to archive tiers.
decision := d {
  archive_due
  d := archive_decision
}

# 6) If minimal age not yet satisfied, keep.
decision := d {
  not min_age_satisfied
  d := base_decision("keep", "min_age_not_met",
        ["min_age_not_met"], ["retention:min_age"])
}

# 7) If minimal age satisfied and no other blockers, allow purge per policy if configured as automatic lifecycle.
decision := d {
  min_age_satisfied
  auto_purge_allowed
  d := base_decision("purge", "lifecycle_purge",
        ["min_age_met_and_lifecycle_allows_purge"], ["retention:lifecycle_purge"])
}

#################################
## Helpers: config and context ##
#################################

# Dataset configuration
ds_config := data.retention.datasets[input.dataset] {
  data.retention.datasets[input.dataset]
}

# Jurisdiction-specific view merged onto dataset-level
jur_cfg := m {
  some j
  j := input.jurisdiction
  base := if ds_config.jurisdictions[j] then ds_config.jurisdictions[j] else {}
  m := base
} else := {}  # empty if none

# Now timestamp (ns)
now_ns := ts_ns(input.now) { input.now } else := time.now_ns()

#########################
## Predicate utilities ##
#########################

legal_hold_active {
  input.flags.legal_hold == true
}

exclusions_blocking {
  some reason
  reasons := {"statutory_retention", "fraud_investigation"}
  reason := reasons[_]
  input.flags[reason] == true
}

is_erasure_request {
  lower(input.request.type) == "erasure"
}

erasure_allowed {
  ds_config.erasure.allowed == true
}

erasure_prohibited {
  some p
  ds_config.erasure.prohibitions[p]
  input.flags[p] == true
}

# Approvals combining dataset and jurisdictional extras
approvals_required := reqs {
  base := if ds_config.erasure.requires then ds_config.erasure.requires else []
  extra := if jur_cfg.erasure_requires then jur_cfg.erasure_requires else []
  reqs := union_array(base, extra)
}

approvals_satisfied {
  every a in approvals_required {
    input.overrides[ sprintf("%v_approved", [a]) ] == true
  }
} else {
  # If no explicit approvals required, satisfied.
  count(approvals_required) == 0
}

# Auto purge lifecycle flag: dataset erasure allowed, and method hard_delete with no grace
auto_purge_allowed {
  ds_config.erasure.allowed
  ds_config.erasure.method == "hard_delete"
  not ds_config.erasure.grace_period
}

##########################
## Time/age calculations##
##########################

# Minimal age satisfied (created_at / last_activity_at / event_anchor_at with merges)
min_age_satisfied {
  age_ns(anchor_for_min_age) >= duration_ns(min_age_value)
}

min_age_value := v {
  v := choose_age_value(ds_config.min_age, jur_cfg.min_age, data.retention.jurisdictions[input.jurisdiction].default_min_age)
}

age_satisfied_for_erasure {
  # consider both min_age and optional event_min_age
  age_ns(anchor_for_min_age) >= duration_ns(min_age_value)
  cond := not ds_config.event_min_age
  cond
} else {
  # if event_min_age configured, also require it against event_anchor_at
  ds_config.event_min_age
  age_ns(anchor_for_event_age) >= duration_ns(ds_config.event_min_age)
}

anchor_for_min_age := ts_ns(select_anchor(ds_config.min_age_anchor))
anchor_for_event_age := ts_ns(input.record.event_anchor_at)

# Pick anchor timestamp string/number based on policy or fallbacks.
select_anchor("created_at") := input.record.created_at
select_anchor("last_activity_at") := input.record.last_activity_at
select_anchor("event_anchor_at") := input.record.event_anchor_at
# Fallback chain if not set: last_activity_at -> created_at
select_anchor(x) := v {
  not input.record[x]
  v := if input.record.last_activity_at then input.record.last_activity_at else input.record.created_at
}

# Archive due?
archive_due {
  ds_config.archive.enabled == true
  age_ns(anchor_for_min_age) >= duration_ns(ds_config.archive.after_age)
}

# Archive decision object
archive_decision := d {
  tier := "warm"
  when_cold := ds_config.archive.cold_after_age
  status := "archive_due"
  d := {
    "action": "archive",
    "status": status,
    "target_tier": tier,
    "legal_basis": [],
    "approvals_required": [],
    "reasoning": ["archive_after_age"],
    "audit_tags": ["retention:archive", sprintf("dataset:%v", [input.dataset])],
    "effective_at": now_iso(),
    "next_step": if when_cold then "move_to_cold" else null,
    "cold_after": if when_cold then ts_add_iso(anchor_for_min_age, ds_config.archive.cold_after_age) else null
  }
}

# If dataset immutable: never purge; maybe archive if due, else keep.
maybe_archive_or_keep(reason) := d {
  archive_due
  d := archive_decision
} else := d {
  d := base_decision("keep", "immutable", [reason], ["retention:immutable"])
}

######################
## Erasure handling ##
######################

# Compute erasure decision based on method and grace periods.
erasure_decision := d {
  method := ds_config.erasure.method
  method == "hard_delete"
  d := base_decision("purge", "erasure_hard_delete",
        reasoning_with_grounds(["erasure_allowed","min_age_met","no_prohibitions","approvals_satisfied"]),
        ["retention:erasure","erasure:hard"])
} else := d {
  method := ds_config.erasure.method
  method == "soft_delete"
  grace := ds_config.erasure.grace_period
  d := {
    "action": "soft_delete",
    "status": "erasure_soft_delete",
    "legal_basis": legal_basis_erasure(),
    "approvals_required": approvals_required,
    "reasoning": ["erasure_allowed","min_age_met","no_prohibitions","approvals_satisfied","grace_period_started"],
    "audit_tags": ["retention:erasure","erasure:soft"],
    "effective_at": now_iso(),
    "grace_until": ts_add_iso(now_ns, grace)
  }
} else := d {
  method := ds_config.erasure.method
  method == "anonymize"
  d := base_decision("redact", "erasure_anonymize",
        reasoning_with_grounds(["erasure_allowed","min_age_met","no_prohibitions","approvals_satisfied","anonymization"]),
        ["retention:erasure","erasure:anonymize"])
} else := d {
  method := ds_config.erasure.method
  method == "tombstone"
  d := base_decision("tombstone", "erasure_tombstone",
        reasoning_with_grounds(["erasure_allowed","min_age_met","no_prohibitions","approvals_satisfied","tombstone"]),
        ["retention:erasure","erasure:tombstone"])
}

#########################
## Building the object ##
#########################

base_decision(action, status, reasons, tags) := {
  "action": action,
  "status": status,
  "legal_basis": legal_basis_for(action),
  "approvals_required": approvals_required,
  "reasoning": reasons,
  "audit_tags": append(tags, [sprintf("dataset:%v", [input.dataset])]),
  "effective_at": now_iso(),
  "purge_after": purge_after_iso(action)
}

reasoning_with_grounds(rs) := concat_array(rs, legal_grounds_tags())

legal_basis_for(action) := lb {
  grounds := legal_grounds()
  lb := if count(grounds) > 0 then grounds else []
}

legal_grounds() := g {
  j := input.jurisdiction
  cfg := data.retention.jurisdictions[j]
  g := if cfg.erasure_additional_grounds then cfg.erasure_additional_grounds else []
} else := []

legal_grounds_tags() := t {
  j := input.jurisdiction
  cfg := data.retention.jurisdictions[j]
  t := if cfg.erasure_exemptions then cfg.erasure_exemptions else []
} else := []

# Purge-after helper: for soft_delete set grace end; for purge keep null; for archive null.
purge_after_iso(action) := v {
  action == "soft_delete"
  v := ts_add_iso(now_ns, ds_config.erasure.grace_period)
} else := v {
  v := null
}

##############################
## Duration/time primitives ##
##############################

# Convert RFC3339 string or ns number to ns
ts_ns(t) := ns {
  is_number(t)
  ns := t
}
ts_ns(t) := ns {
  is_string(t)
  ns := time.parse_rfc3339_ns(t)
}

now_iso() := time.ns_to_time(now_ns)

# Add duration string to a ns timestamp and return RFC3339 time
ts_add_iso(base, dur) := time.ns_to_time(ts_add_ns(base, duration_ns(dur)))

ts_add_ns(base, add) := out {
  is_number(base)
  out := base + add
} else := out {
  out := ts_ns(base) + add
}

# Age in ns relative to now_ns for a timestamp (ns or RFC3339)
age_ns(ts) := out {
  out := now_ns - ts_ns(ts)
  out >= 0
}

# Choose first non-empty duration string from ordered candidates
choose_age_value(a, b, c) := v {
  a; v := a
} else := v {
  not a; b; v := b
} else := v {
  not a; not b; c; v := c
}

# Convert "<number><unit>" to ns. Units: y, mo, w, d, h, m, s
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "mo")
  n := to_number(replace(su, "mo", ""))
  ns := n * 30 * 24 * 60 * 60 * 1000000000
}
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "y")
  n := to_number(replace(su, "y", ""))
  ns := n * 365 * 24 * 60 * 60 * 1000000000
}
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "w")
  n := to_number(replace(su, "w", ""))
  ns := n * 7 * 24 * 60 * 60 * 1000000000
}
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "d")
  n := to_number(replace(su, "d", ""))
  ns := n * 24 * 60 * 60 * 1000000000
}
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "h")
  n := to_number(replace(su, "h", ""))
  ns := n * 60 * 60 * 1000000000
}
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "m")
  n := to_number(replace(su, "m", ""))
  ns := n * 60 * 1000000000
}
duration_ns(s) := ns {
  su := lower(s)
  endswith(su, "s")
  n := to_number(replace(su, "s", ""))
  ns := n * 1000000000
}

###########################
## Sanity/validation set ##
###########################

# Detect misconfiguration or missing dataset
errors[msg] {
  not data.retention.datasets[input.dataset]
  msg := sprintf("dataset_not_configured:%v", [input.dataset])
}

errors[msg] {
  ds_config.erasure.allowed
  ds_config.erasure.method == "soft_delete"
  not ds_config.erasure.grace_period
  msg := "soft_delete_requires_grace_period"
}

errors[msg] {
  some j
  j := input.jurisdiction
  not data.retention.jurisdictions[j]
  msg := sprintf("jurisdiction_not_configured:%v", [j])
}

#################
## Explanations ##
#################

explain := {
  "min_age_value": min_age_value,
  "min_age_anchor": ds_config.min_age_anchor,
  "age_ns": age_ns(anchor_for_min_age),
  "archive_due": archive_due,
  "erasure_allowed": erasure_allowed,
  "erasure_prohibited": erasure_prohibited,
  "approvals_required": approvals_required
}

##############################
## End of policy definition ##
##############################
