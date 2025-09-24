package policy_core.rate_limit

# ============================================================
# Rate limit policy (industrial)
# - Priority: rule match > namespace > tenant > global default
# - Modes: enforce|monitor (shadow)
# - Exemptions: service accounts, roles, CIDR
# - Output: decision object with descriptor, headers, labels
# - Compatible with Envoy ext_authz / RLS integrations
# ============================================================

import rego.v1
import future.keywords.in
import future.keywords.if
import future.keywords.every
import data as d

default decision := {
  "action": "SHADOW_ALLOW",
  "mode": mode_default,
  "reason": "no_rule_found",
  "descriptor": descriptor,
  "limit": limit_resolved,
  "key": key,
  "labels": labels,
  "headers": headers_advice,
}

# ------------- Input schema (informational) ------------------
# expected input:
# input := {
#   "attributes": {
#     "tenant": "t-123",
#     "namespace": "authz_decisions",
#     "method": "GET",
#     "path": "/api/v1/resource/42",
#     "route": "/api/v1/resource/{id}",
#     "ip": "203.0.113.10",
#     "user_agent": "curl/8.7",
#     "subject": {
#       "id": "u-42",
#       "roles": ["user"],
#       "service_account": false
#     }
#   },
#   "metrics": {
#     "current_rps_by_key": { "<sha256>": 137 },   # optional
#     "window_sec": 1
#   },
#   "now_ns": 0                                     # optional override
# }
#
# data.policy.rate_limit:
# {
#   "mode": "enforce" | "monitor",
#   "defaults": { "rps": 1000, "burst": 200, "window_sec": 1 },
#   "tenants": { "t-123": { "rps": 500, "burst": 100 } },
#   "namespaces": {
#     "authz_decisions": { "rps": 30000, "burst": 3000 },
#     "policy_eval_results": { "rps": 20000, "burst": 2000 }
#   },
#   "exemptions": {
#     "service_accounts": ["svc-*"],            # glob
#     "roles": ["admin","system"],
#     "cidrs": ["10.0.0.0/8","192.168.0.0/16"]
#   },
#   "rules": [
#     {
#       "name": "per-route-authz",
#       "match": {
#         "namespace": "authz_decisions",
#         "route": "^/api/v1/resource/.*$",
#         "method": ["GET","POST"],
#         "tenant": ["t-.*"]                    # regex
#       },
#       "limit": { "rps": 30000, "burst": 3000, "window_sec": 1 },
#       "key": ["tenant","namespace","route","method","ip_bucket"]
#     }
#   ],
#   "headers": { "emit_standard": true, "prefix": "X-RateLimit" }
# }

# ---------------- Mode & defaults ----------------------------

mode_default := mode if {
  some mode
  mode := d.policy.rate_limit.mode
}
else := "monitor"

defaults := def if {
  some def
  def := d.policy.rate_limit.defaults
}
else := {"rps": 1000, "burst": 200, "window_sec": 1}

# ----------------- Input normalization -----------------------

tenant := input.attributes.tenant
namespace := input.attributes.namespace
method := upper(input.attributes.method)
route := route_norm
ip := input.attributes.ip
subject_id := input.attributes.subject.id
subject_roles := array.concat([], input.attributes.subject.roles)

route_norm := r if {
  some r
  r := input.attributes.route
} else := input.attributes.path

# Simple /24 IPv4 bucket for coarse IP limiting (fallback-safe)
ip_bucket := join(".", slice(split(ip, "."), 0, 3)) if is_ipv4(ip)
is_ipv4(x) := count(split(x, ".")) == 4

# ----------------- Exemptions (whitelist) --------------------

exempt_service_account if {
  input.attributes.subject.service_account == true
}

exempt_role if {
  some r
  r in subject_roles
  some wl
  wl := d.policy.rate_limit.exemptions.roles
  r in wl
}

exempt_cidr if {
  some cidr
  cidr in d.policy.rate_limit.exemptions.cidrs
  net.cidr_contains(cidr, ip)
}

# Glob match for service account names
exempt_service_account_name if {
  input.attributes.subject.service_account == true
  some pat
  pat in d.policy.rate_limit.exemptions.service_accounts
  glob.match(pat, [], subject_id)
}

exempt := exempt_service_account
       or exempt_service_account_name
       or exempt_role
       or exempt_cidr

# If exempt — strongly allow with reason
decision := {
  "action": "ALLOW",
  "mode": mode_default,
  "reason": "exempt",
  "descriptor": descriptor,
  "limit": limit_resolved,
  "key": key,
  "labels": labels_with({"exempt": "true"}),
  "headers": headers_advice,
} if exempt

# ----------------- Rule resolution ---------------------------

# Candidate rules that match attributes
matched_rules[rule] if {
  some i
  rule := d.policy.rate_limit.rules[i]
  rule_match(rule.match)
}

rule_match(m) if {
  # namespace
  not m.namespace; true
} else { m.namespace == namespace }

rule_match(m) if {
  # method
  not m.method; true
} else {
  some mm
  mm in m.method
  mm == method
}

rule_match(m) if {
  # route (regex)
  not m.route; true
} else { re_match(m.route, route_norm) }

rule_match(m) if {
  # tenant (regex or list)
  not m.tenant; true
} else {
  # tenant may be list of regex
  some tpat
  tpat in m.tenant
  re_match(tpat, tenant)
}

# Select the most specific rule (longest key selector and explicit limit)
# Tie-break by lexicographic name for determinism
specific_rule := r if {
  some r
  rs := [x | x := matched_rules[_]]
  count(rs) > 0
  r := max_by_rank(rs)
}

max_by_rank(rs) := best {
  some best
  ranks := {x.name: rank(x) | x := rs}
  best_name := max_name(ranks)
  some y
  y in rs
  y.name == best_name
  best := y
}

rank(x) := r if {
  # specificity: number of match fields present + key length bias
  r := count([f | f := ["namespace","route","method","tenant"]; x.match[f] != null]) * 10
     + count(x.key)
}

max_name(m) := best if {
  ks := {k | k := keys(m)[_]}
  best := max(ks)
}

# -------------- Limit resolution (hierarchical) --------------

limit_from_rule := specific_rule.limit if specific_rule != null

limit_from_namespace := d.policy.rate_limit.namespaces[namespace] with default {}
limit_from_tenant := d.policy.rate_limit.tenants[tenant] with default {}

limit_resolved := coalesce_limit([
  limit_from_rule,
  limit_from_namespace,
  limit_from_tenant,
  defaults,
])

coalesce_limit(arr) := out if {
  # take first object having rps
  some x in arr
  x.rps != null
  out := {
    "rps":        x.rps,
    "burst":      coalesce_number(x.burst, 0),
    "window_sec": coalesce_number(x.window_sec, 1),
  }
}

coalesce_number(x, def) := y if { y := x } else := def

# -------------- Descriptor & key (deterministic) -------------

# Descriptor fields for external rate-limiter (Envoy RLS compatible)
descriptor := ds if {
  base := {
    "tenant":    tenant,
    "namespace": namespace,
    "method":    method,
    "route":     route_group,
    "ip_bucket": ip_bucket,
    "subject":   subject_group,
  }
  # keys order from rule.key, else default order
  korder := specific_rule.key if specific_rule != null else ["tenant","namespace","route","method","ip_bucket"]
  ds := [ {"key": k, "value": base[k]} | k := korder; base[k] != "" ]
}

route_group := route_norm
subject_group := subject_group_v if {
  some rs
  rs := input.attributes.subject.roles
  count(rs) > 0
  subject_group_v := sort(rs)[0]
} else := "anonymous"

# SHA-256 of concatenated descriptor key/values
key := crypto.sha256(join("|", [sprintf("%s=%s", [d.key, d.value]) | d := descriptor]))

# -------------- Current usage & decision logic ---------------

window_sec := coalesce_number(input.metrics.window_sec, limit_resolved.window_sec)
current := cur if {
  some cur
  cur := input.metrics.current_rps_by_key[key]
} else := -1  # signal that no live metric supplied

remaining := rem if {
  current >= 0
  lim := limit_resolved.rps + limit_resolved.burst
  tmp := lim - current
  rem := tmp if tmp >= 0 else 0
} else := -1

# Mode-aware verdict:
# - enforce: DENY if current exceeds rps+burst (when metric provided), else SHADOW_ALLOW
# - monitor: always SHADOW_ALLOW
enforce_mode := mode_default == "enforce"

over_limit if {
  current >= 0
  current > (limit_resolved.rps + limit_resolved.burst)
}

decision := {
  "action": "DENY",
  "mode": "enforce",
  "reason": "over_limit",
  "descriptor": descriptor,
  "limit": limit_resolved,
  "key": key,
  "labels": labels_with({"over_limit": "true"}),
  "headers": headers_advice_with_remaining,
} if enforce_mode and over_limit

decision := {
  "action": "ALLOW",
  "mode": "enforce",
  "reason": "within_limit",
  "descriptor": descriptor,
  "limit": limit_resolved,
  "key": key,
  "labels": labels_with({"shadow": "false"}),
  "headers": headers_advice_with_remaining,
} if enforce_mode and not over_limit and current >= 0

# No live metric -> shadow allow (delegate counting to external limiter)
decision := {
  "action": "SHADOW_ALLOW",
  "mode": mode_default,
  "reason": "no_live_metric",
  "descriptor": descriptor,
  "limit": limit_resolved,
  "key": key,
  "labels": labels_with({"shadow": "true"}),
  "headers": headers_advice,  # no remaining available
} if current == -1

# ----------------- Headers advice ----------------------------

emit_headers := h if {
  some h
  h := d.policy.rate_limit.headers
} else := {"emit_standard": true, "prefix": "X-RateLimit"}

headers_advice := {} if not emit_headers.emit_standard
headers_advice := {
  sprintf("%s-Limit",   [emit_headers.prefix]):  sprintf("%d", [limit_resolved.rps]),
  sprintf("%s-Policy",  [emit_headers.prefix]):  sprintf("win=%ds;burst=%d", [window_sec, limit_resolved.burst]),
} if emit_headers.emit_standard

headers_advice_with_remaining := merge(headers_advice, {
  sprintf("%s-Remaining", [emit_headers.prefix]): rems,
}) if {
  emit_headers.emit_standard
  rems := sprintf("%d", [remaining if remaining >= 0 else 0])
}

# ----------------- Labels / Observability --------------------

base_labels := {
  "tenant": tenant,
  "namespace": namespace,
  "method": method,
  "route": route_group,
  "subject": subject_group,
  "mode": mode_default,
}

labels := labels_with({})

labels_with(extra) := merge(base_labels, extra)

# ------------------ Utilities --------------------------------

upper(s) := t if {
  t := upper_ascii(s)
}

# merge two objects
merge(x, y) := z {
  z := object.union(x, y)
}
