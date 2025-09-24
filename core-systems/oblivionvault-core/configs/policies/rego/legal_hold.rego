package oblivionvault.policies.legal_hold.v1

# ------------------------------------------------------------------------------
# Legal Hold Enforcement Policy (v1)
# ------------------------------------------------------------------------------
# EXPECTED INPUT (fragment):
# input := {
#   "action": "erase" | "delete" | "drop_partitions" | "anonymize" | "...",
#   "target": {
#      "type": "s3"|"posix"|"rdbms"|"kafka",
#      # s3:
#      "bucket": "...", "prefix": "...",
#      # posix:
#      "path": "/mnt/.../file" | "/mnt/.../dir/",
#      # rdbms:
#      "engine": "postgres"|"clickhouse",
#      "database": "...", "table": "...",
#      # kafka:
#      "topic": "...",
#   },
#   "subject": {"subject_id": "..."},
#   "labels": {"allow-erasure": "true", "case_id": "CASE-123", ...},
#   "context": {
#     "env": "prod"|"stage"|"dev",
#     "request_id": "...",
#     "requester": {"id": "user:123", "roles": ["SecOps","DPO"]},
#     "override": {
#        "legal_hold": true|false,
#        "reason": "string",
#        "expires_at": "2025-12-31T23:59:59Z"
#     },
#     "approvals": [
#        {"id": "user:456", "role": "CISO", "ts": "2025-08-24T12:00:00Z"},
#        {"id": "user:789", "role": "HeadOfLegal", "ts": "2025-08-24T12:05:00Z"}
#     ]
#   }
# }
#
# EXPECTED DATA (fragment):
# data.ov.legal_holds := [
#   {
#     "id": "LH-001",
#     "status": "active"|"paused"|"released",
#     "hard": true|false,
#     "created_at": "2025-08-01T00:00:00Z",
#     "expires_at": "2025-12-31T23:59:59Z", # optional
#     "scope": {
#        "any": true|false,
#        "subjects": ["subj-1","subj-2"],
#        "cases": ["CASE-123"],
#        "labels": {"retention-class": ["legal","investigation"]},
#        "s3": [{"bucket":"ov-db-backups","prefix":"incidents/"}],
#        "posix": [{"glob":"/mnt/ov/media/incidents/**"}],
#        "rdbms": [{"engine":"postgres","database":"ov","table":"events"}],
#        "kafka": [{"topic":"ov-audit"}]
#     }
#   },
#   ...
# ]
#
# data.ov.policy.legal_hold := {
#   "enforce_in_envs": ["prod","stage"],
#   "override": {
#      "enabled": true,
#      "forbid_hard": true,                 # hard-hold нельзя override
#      "require_quorum": 2,
#      "allowed_roles": ["CISO","HeadOfLegal","DPO","SecurityOfficer"],
#      "max_override_ttl_hours": 6,
#      "require_justification": true
#   }
# }
# ------------------------------------------------------------------------------

default allow := false

# Public decision surface
deny := {d | some d; deny_internal[d]}
advisory := {w | some w; advisory_internal[w]}
decision_info := {
  "policy": "oblivionvault.policies.legal_hold.v1",
  "version": "1.0.0",
  "env": input.context.env,
  "request_id": input.context.request_id,
  "active_holds": [h.id | h := applicable_holds[_]],
  "override_used": override_requested,
  "override_valid": override_valid
}

# ----------------------------------------------------------------------
# Core decision
# ----------------------------------------------------------------------

# Allow if:
#  A) Legal Hold enforcement not active in this env
#  OR
#  B) No applicable active holds
#  OR
#  C) Holds exist, but valid override is in place (and policy allows it)
allow {
  not env_enforced
} else {
  count(applicable_holds) == 0
} else {
  count(applicable_holds) > 0
  override_valid
  not hard_hold_forbidden
  # even with override, we still produce advisory for audit
}

# If holds exist and not valid override — produce denies
deny_internal[{"reason": r, "hold_id": h.id, "severity": sev}] {
  env_enforced
  h := applicable_holds[_]
  not override_valid
  r := sprintf("Legal Hold active: %s", [h.id])
  sev := cond(h.hard, "critical", "high")
}

# Advisory when override used (for audit/compliance)
advisory_internal[{"message": m, "hold_id": h.id, "note": "override in effect"}] {
  env_enforced
  override_valid
  h := applicable_holds[_]
  m := sprintf("Override applied under quorum for hold %s", [h.id])
}

# Hard-hold override forbidden flag
hard_hold_forbidden {
  override_valid
  some h
  h := applicable_holds[_]
  h.hard
  data.ov.policy.legal_hold.override.forbid_hard
}

# ----------------------------------------------------------------------
# Environment switch
# ----------------------------------------------------------------------
env_enforced {
  data.ov.policy.legal_hold.enforce_in_envs[_] == input.context.env
}

# ----------------------------------------------------------------------
# Applicable holds collector
# ----------------------------------------------------------------------
applicable_holds[h] {
  h := data.ov.legal_holds[_]
  legal_hold_active(h)
  legal_hold_matches_scope(h.scope)
}

# Is hold active (status + time window)
legal_hold_active(h) {
  h.status == "active"
  not hold_expired(h)
}

hold_expired(h) {
  some exp
  exp := h.expires_at
  t := to_ns(exp)
  now := time.now_ns()
  now > t
}

# ----------------------------------------------------------------------
# Scope matching
# ----------------------------------------------------------------------
legal_hold_matches_scope(scope) {
  scope.any == true
} else {
  some s
  scope.subjects[s]
  input.subject.subject_id == s
} else {
  some c
  scope.cases[c]
  input.labels["case_id"] == c
} else {
  match_scope_labels(scope.labels)
} else {
  match_scope_s3(scope.s3)
} else {
  match_scope_posix(scope.posix)
} else {
  match_scope_rdbms(scope.rdbms)
} else {
  match_scope_kafka(scope.kafka)
}

match_scope_labels(lbls) {
  lbls != null
  # every key in lbls must match one of allowed values
  every k := v in lbls {
    iv := input.labels[k]
    some want
    want := v[_]
    iv == want
  }
}

match_scope_s3(entries) {
  entries != null
  some e
  e := entries[_]
  input.target.type == "s3"
  input.target.bucket == e.bucket
  prefix_matches(input.target.prefix, e.prefix)
}

match_scope_posix(entries) {
  entries != null
  some e
  e := entries[_]
  input.target.type == "posix"
  glob_match(e.glob, input.target.path)
}

match_scope_rdbms(entries) {
  entries != null
  some e
  e := entries[_]
  input.target.type == "rdbms"
  input.target.engine == e.engine
  input.target.database == e.database
  input.target.table == e.table
}

match_scope_kafka(entries) {
  entries != null
  some e
  e := entries[_]
  input.target.type == "kafka"
  input.target.topic == e.topic
}

# ----------------------------------------------------------------------
# Override handling (two-person rule, roles, TTL, justification)
# ----------------------------------------------------------------------
override_requested := input.context.override.legal_hold == true

override_valid {
  override_requested
  data.ov.policy.legal_hold.override.enabled
  quorum_ok
  roles_ok
  ttl_ok
  justification_ok
  no_self_approve
}

quorum_ok {
  need := data.ov.policy.legal_hold.override.require_quorum
  count(distinct_approvers) >= need
}

roles_ok {
  allowed := {r | r := data.ov.policy.legal_hold.override.allowed_roles[_]}
  every a in input.context.approvals {
    allowed[a.role]
  }
}

ttl_ok {
  maxh := data.ov.policy.legal_hold.override.max_override_ttl_hours
  exp := input.context.override.expires_at
  exp != ""
  exp_ns := to_ns(exp)
  now := time.now_ns()
  diff_ns := exp_ns - now
  diff_ns > 0
  hours := diff_ns / 3600000000000
  hours <= maxh
}

justification_ok {
  req := data.ov.policy.legal_hold.override.require_justification
  not req
} else {
  req
  j := trim(input.context.override.reason)
  j != ""
  count(split(j, " ")) >= 3
}

no_self_approve {
  requester := input.context.requester.id
  not some a in input.context.approvals { a.id == requester }
}

distinct_approvers := {a.id | a := input.context.approvals[_]}

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
prefix_matches(val, pref) {
  pref == ""  # empty prefix matches all
} else {
  startswith(val, pref)
}

glob_match(pattern, value) {
  pattern != ""
  glob.match(pattern, ["**"], value)
}

to_ns(ts) = ns {
  ns := time.parse_rfc3339_ns(ts)
}

trim(s) = out {
  out := trim_left(trim_right(s, " \t\n\r"), " \t\n\r")
}

cond(b, x, y) = out {
  b
  out := x
} else {
  not b
  out := y
}

# ------------------------------------------------------------------------------
# Default deny for destructive actions when env enforced and target unspecified
# (defensive stance). Produces advisory if action is non-destructive.
# ------------------------------------------------------------------------------
destructive_actions := {"erase", "delete", "drop_partitions"}

deny_internal[{"reason": "Destructive action without target specified", "severity": "medium"}] {
  env_enforced
  destructive_actions[input.action]
  not input.target.type
}

advisory_internal[{"message": "Non-destructive action under Legal Hold; monitor only"}] {
  env_enforced
  not destructive_actions[input.action]
}
