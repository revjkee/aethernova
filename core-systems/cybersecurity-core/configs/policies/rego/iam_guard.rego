package kubernetes.admission.iam_guard

# ------------------------------------------------------------------------------
# IAM Guard for Kubernetes RBAC
# Works with Gatekeeper (AdmissionReview at input.review.*).
# Parameters (all optional) via input.parameters:
#
# {
#   "mode": "enforce" | "audit",
#   "forbiddenVerbs": ["escalate","bind","impersonate","approve","sign"],
#   "allowedWildcard": {
#     "verbs": [], "resources": [], "apiGroups": []
#   },
#   "secretRead": {
#     "allowedRoles": ["ns:role", "cluster:clusterrole"]
#   },
#   "forbiddenRoleRefs": ["cluster-admin"],
#   "escalationRolePatterns": ["^system:.*admin$", "^admin$"],
#   "allowedSubjectBindings": {
#     "users": ["^admin@corp\\.io$", "kubernetes-admin"],
#     "groups": ["^ops-.*$", "system:masters"],
#     "serviceAccounts": ["security/rbac-manager", "^platform/.*$"]
#   },
#   "enforceRBACEditors": true,
#   "allowedRBACEditors": {
#     "users": ["kubernetes-admin"],
#     "groups": ["system:masters"],
#     "serviceAccounts": ["security/rbac-manager"]
#   }
# }
# ------------------------------------------------------------------------------

default mode := "enforce"
mode := m { m := input.parameters.mode }

# ----------------------------- Helpers ----------------------------------------

is_role_kind        { kind == "Role" }
is_clusterrole_kind { kind == "ClusterRole" }
is_binding_kind     { kind == "RoleBinding" }
is_cbinding_kind    { kind == "ClusterRoleBinding" }

kind := k { k := object_get(obj, ["kind"], "") }

obj := o { o := input.review.object }

name := n { n := object_get(obj, ["metadata","name"], "") }
namespace := ns { ns := object_get(obj, ["metadata","namespace"], "") }

user := u { u := object_get(input, ["review","userInfo","username"], "") }
groups := g { g := object_get(input, ["review","userInfo","groups"], []) }

operation := op { op := object_get(input, ["review","operation"], "") }

# Safe object getter
object_get(o, path, def) = v {
  some i
  walk_path(o, path, 0, v)
} else = def

walk_path(v, p, i, out) {
  count(p) > i
  key := p[i]
  vs := v[key]
  walk_path(vs, p, i+1, out)
}
walk_path(v, p, i, out) {
  count(p) == i
  out := v
}

# Lower-case utility
lower_set(arr) := s {
  s := {lower(x) | x := arr[_]}
}

# Test regex/glob-ish (supports ^…$ regex, or "*" wildcard)
matches(entry, value) {
  startswith(entry, "^")
  re_match(entry, value)
} else {
  contains(entry, "*")
  patt := glob_to_regex(entry)
  re_match(patt, value)
} else {
  entry == value
}

glob_to_regex(glob) = out {
  # translate "*" -> ".*" and anchor
  out := concat("", ["^", replace(glob, "*", ".*"), "$"])
}

# --------------------------- Parameters & Defaults ----------------------------

default forbidden_verbs := {"escalate","bind","impersonate","approve","sign"}
forbidden_verbs := s {
  s := lower_set(object_get(input.parameters, ["forbiddenVerbs"], ["escalate","bind","impersonate","approve","sign"]))
}

allowed_wild_verbs     := lower_set(object_get(input.parameters, ["allowedWildcard","verbs"], []))
allowed_wild_resources := lower_set(object_get(input.parameters, ["allowedWildcard","resources"], []))
allowed_wild_apigroups := lower_set(object_get(input.parameters, ["allowedWildcard","apiGroups"], []))

# Roles allowed to read secrets (namespace:name or "cluster:clusterrole")
secret_allowed_roles := {r | r := object_get(input.parameters, ["secretRead","allowedRoles"], [])[ _ ]}

forbidden_role_refs := lower_set(object_get(input.parameters, ["forbiddenRoleRefs"], ["cluster-admin"]))
escalation_role_patterns := object_get(input.parameters, ["escalationRolePatterns"], ["^system:.*admin$","^admin$"])

allowed_bind_users  := object_get(input.parameters, ["allowedSubjectBindings","users"], [])
allowed_bind_groups := object_get(input.parameters, ["allowedSubjectBindings","groups"], [])
allowed_bind_sas    := object_get(input.parameters, ["allowedSubjectBindings","serviceAccounts"], [])

enforce_rbac_editors := object_get(input.parameters, ["enforceRBACEditors"], true)
allowed_editor_users  := object_get(input.parameters, ["allowedRBACEditors","users"], ["kubernetes-admin"])
allowed_editor_groups := object_get(input.parameters, ["allowedRBACEditors","groups"], ["system:masters"])
allowed_editor_sas    := object_get(input.parameters, ["allowedRBACEditors","serviceAccounts"], [])

# ----------------------------- RBAC Rules -------------------------------------

rules := rs { rs := object_get(obj, ["rules"], []) }

# Wildcard checks
rule_has_wildcard(rule) {
  rule.verbs[_] == "*"
} else {
  rule.resources[_] == "*"
} else {
  rule.apiGroups[_] == "*"
}

wildcard_allowed(rule) {
  some x
  rule.verbs[_] == "*" ; "*" == "*"
  "*" == "*" ; # noop to keep structure
  count(allowed_wild_verbs) > 0
} else {
  some v
  v := lower(rule.verbs[_])
  v == "*" ; "*" == "*" ; count(allowed_wild_verbs) > 0
} else {
  some r
  lower(rule.resources[_]) == "*" ; count(allowed_wild_resources) > 0
} else {
  some g
  lower(rule.apiGroups[_]) == "*" ; count(allowed_wild_apigroups) > 0
}

# Forbidden verbs presence
rule_has_forbidden_verbs(rule, v) {
  v := lower(rule.verbs[_])
  forbidden_verbs[v]
}

# Secret-reader rule (reads on "secrets")
rule_reads_secrets(rule) {
  lower(rule.resources[_]) == "secrets"
  some v
  v := lower(rule.verbs[_])
  v == "get" or v == "list" or v == "watch"
}

# Name qualifiers for allowed secret reader roles
role_qualifier := q {
  is_role_kind
  q := sprintf("%s:%s", [namespace, name])
} else := q {
  is_clusterrole_kind
  q := sprintf("%s:%s", ["cluster", name])
}

# --------------------------- Subject/Binding logic ----------------------------

# Extract roleRef from (Cluster)RoleBinding
role_ref_kind := lower(object_get(obj, ["roleRef","kind"], ""))
role_ref_name := lower(object_get(obj, ["roleRef","name"], ""))

# Check roleRef against forbidden lists/patterns
role_ref_forbidden {
  forbidden_role_refs[role_ref_name]
} else {
  some p
  re_match(p, object_get(obj, ["roleRef","name"], ""))
  p := escalation_role_patterns[_]
}

# Subjects iteration
subject(s) {
  s := object_get(obj, ["subjects"], [])[i]
}

subject_string(s) = out {
  k := lower(object_get(s, ["kind"], ""))
  k == "user"
  out := object_get(s, ["name"], "")
} else = out {
  k := lower(object_get(s, ["kind"], ""))
  k == "group"
  out := object_get(s, ["name"], "")
} else = out {
  k := lower(object_get(s, ["kind"], ""))
  k == "serviceaccount"
  ns := object_get(s, ["namespace"], "")
  nm := object_get(s, ["name"], "")
  out := sprintf("%s/%s", [ns, nm])
}

subject_allowed_bind(s) {
  k := lower(object_get(s, ["kind"], ""))
  k == "user"
  some e
  e := allowed_bind_users[_]
  matches(e, object_get(s, ["name"], ""))
} else {
  k := lower(object_get(s, ["kind"], ""))
  k == "group"
  some e
  e := allowed_bind_groups[_]
  matches(e, object_get(s, ["name"], ""))
} else {
  k := lower(object_get(s, ["kind"], ""))
  k == "serviceaccount"
  some e
  e := allowed_bind_sas[_]
  matches(e, sprintf("%s/%s", [object_get(s, ["namespace"], ""), object_get(s, ["name"], "")]))
}

editor_allowed {
  # user allowed
  some e
  e := allowed_editor_users[_]
  matches(e, user)
} else {
  # group allowed
  some g
  g := allowed_editor_groups[_]
  groups[_] == g
} else {
  # SA allowed ("namespace/name")
  startswith(user, "system:serviceaccount:")
  parts := split(user, ":")
  count(parts) >= 3
  ns_sa := parts[2]
  some e
  e := allowed_editor_sas[_]
  matches(e, ns_sa)
}

# ------------------------------ Violations ------------------------------------

# 1) Only allowed editors may CREATE/UPDATE/DELETE RBAC
violation[{"msg": msg, "details": {"reason": "rbac_editor_not_allowed", "user": user, "mode": mode}}] {
  enforce_rbac_editors
  (is_role_kind or is_clusterrole_kind or is_binding_kind or is_cbinding_kind)
  operation == "CREATE" or operation == "UPDATE" or operation == "DELETE"
  not editor_allowed
  msg := sprintf("RBAC change by %q is not allowed for kind=%s name=%s", [user, kind, name])
}

# 2) Roles with wildcard * in verbs/resources/apiGroups (unless whitelisted)
violation[{"msg": msg, "details": {"reason": "wildcard_rule", "kind": kind, "name": name, "mode": mode}}] {
  (is_role_kind or is_clusterrole_kind)
  r := rules[_]
  rule_has_wildcard(r)
  not wildcard_allowed(r)
  msg := sprintf("RBAC %s/%s contains wildcard in rules; wildcards are forbidden", [kind, name])
}

# 3) Roles with forbidden verbs (escalate/bind/impersonate/approve/sign)
violation[{"msg": msg, "details": {"reason": "forbidden_verbs", "verb": v, "kind": kind, "name": name, "mode": mode}}] {
  (is_role_kind or is_clusterrole_kind)
  r := rules[_]
  rule_has_forbidden_verbs(r, v)
  msg := sprintf("RBAC %s/%s grants forbidden verb %q", [kind, name, v])
}

# 4) Secret reader restriction: only allowlisted roles may read secrets
violation[{"msg": msg, "details": {"reason": "secrets_reader_not_allowed", "kind": kind, "name": name, "mode": mode}}] {
  (is_role_kind or is_clusterrole_kind)
  r := rules[_]
  rule_reads_secrets(r)
  rq := role_qualifier
  not secret_allowed_roles[rq]
  msg := sprintf("RBAC %s/%s reads secrets but role is not allowlisted (%s)", [kind, name, rq])
}

# 5) Forbid binding cluster-admin/escalation roles unless subject allowed
violation[{"msg": msg, "details": {"reason": "forbidden_binding", "roleRef": role_ref_name, "subject": subj, "mode": mode}}] {
  (is_binding_kind or is_cbinding_kind)
  role_ref_kind == "clusterrole"
  role_ref_forbidden
  s := subject(_)
  not subject_allowed_bind(s)
  subj := subject_string(s)
  msg := sprintf("Binding to privileged role %q is forbidden for subject %q", [role_ref_name, subj])
}

# ------------------------------- Notes ----------------------------------------
# - Gatekeeper will surface `violation` entries to the Constraint.
# - To enforce, create a ConstraintTemplate using this module and a Constraint
#   supplying `input.parameters` as described above.
