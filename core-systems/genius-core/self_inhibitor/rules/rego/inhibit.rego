package genius_core.security.self_inhibitor.inhibit

# -----------------------------------------------------------------------------
# Industrial self-inhibition policy for LLM agent requests
# Inputs:
#   input.request: {
#     actor: {id, roles, tenant, ip, sensitive_access: bool},
#     model: {name, provider},
#     content: {text, lang, length, mime},
#     tools: [{name, args}],
#     urls: [string],
#     action: string,               # e.g. "chat.completions", "tool.invoke"
#     cost: {prompt_tokens, max_tokens, est_tokens}
#   }
#   input.safety: {
#     injection_score: number,      # 0..1
#     toxicity: number,             # 0..1
#     pii: {has: bool, kinds: [string]}
#   }
#   input.usage: {
#     per_user_rpm: {current, limit, reset_at},         # epoch seconds
#     global_concurrency: {current, limit, reset_at},   # epoch seconds
#     tenant_tokens_daily: {used, limit, reset_at}      # epoch seconds
#   }
# data.policies (optional configuration bundle):
#   thresholds, urls{allow,deny,cidr_deny}, models{tenant_allow}, tools{}, quotas{}, pii{}
#
# Output:
#   decision: {
#     allow: bool,
#     reasons: [string],
#     severity: string,                # low|medium|high|critical
#     retry_after: number,             # seconds; 0 if allow or not applicable
#     obligations: [string],           # e.g. ["redact_secrets","sandbox_route"]
#     limits: object                   # echo useful limit context
#   }
# -----------------------------------------------------------------------------

default decision := {
  "allow": true,
  "reasons": [],
  "severity": "low",
  "retry_after": 0,
  "obligations": [],
  "limits": {}
}

# Final decision aggregation
decision := {
  "allow": allow,
  "reasons": reasons_sorted,
  "severity": sev_label,
  "retry_after": max_retry_after,
  "obligations": obligations_sorted,
  "limits": limit_echo,
} {
  reasons := { r | deny[r] }
  reasons_sorted := array.sort(array.from_set(reasons))

  allow := count(reasons) == 0

  # Aggregate obligations (actions the caller must enforce)
  obligations_set := { o | obligation[o] }
  obligations_sorted := array.sort(array.from_set(obligations_set))

  # Severity is the max of all raised severities
  sevs := [ s | s := severity_map[sev(r)] ; deny[r] ]
  sev_score := max(sevs, 0)
  sev_label := severity_label[sev_score]

  # Retry-After is the max of provided suggestions
  ras := [ ra | rate_retry_after(ra) ]
  max_retry_after := max(ras, 0)

  # Echo limits snapshot for observability
  limit_echo := {
    "per_user_rpm": input.usage.per_user_rpm,
    "global_concurrency": input.usage.global_concurrency,
    "tenant_tokens_daily": input.usage.tenant_tokens_daily,
  }
}

# -----------------------------------------------------------------------------
# Configuration with safe defaults if data.policies absent
# -----------------------------------------------------------------------------

threshold_injection_block := getnum(data.policies.thresholds.injection.block, 0.80)
threshold_injection_warn  := getnum(data.policies.thresholds.injection.warn,  0.50)
threshold_toxicity_block  := getnum(data.policies.thresholds.toxicity.block,  0.90)

allowed_models := getlist(data.policies.models.tenant_allow[input.request.actor.tenant], ["*"])
allowed_models_fallback := getlist(data.policies.models.tenant_allow["*"], ["*"])

url_allow := getlist(data.policies.urls.allow, ["*.example.com"])
url_deny  := getlist(data.policies.urls.deny,  ["*.evil.com", "localhost", "127.0.0.1*"])
cidr_deny := getlist(data.policies.urls.cidr_deny, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

pii_block_kinds := getlist(data.policies.pii.block, ["credit_card", "government_id"])
pii_warn_kinds  := getlist(data.policies.pii.warn,  ["email", "phone"])

quota_user_rpm_limit := getnum(input.usage.per_user_rpm.limit, 120)
quota_conc_limit     := getnum(input.usage.global_concurrency.limit, 50)
quota_tokens_limit   := getnum(input.usage.tenant_tokens_daily.limit, 100000000)

# Tools policy (allow/deny and arg constraints)
tool_policies := getobj(data.policies.tools, {})

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Severity mapping
severity_map := {"low":1, "medium":2, "high":3, "critical":4}
severity_label := {1:"low", 2:"medium", 3:"high", 4:"critical"}

# By default each deny is "high"; rules can override with sev_override[r] = "critical"/...
sev(r) := sev_override[r] else "high"

# Provide retry_after suggestions
rate_retry_after(ra) {
  ra := retry_after[r]
}
rate_retry_after(0) { not some r; retry_after := {} }

# Safe getters
getnum(x, def) = out {
  out := x
} else = def { true }

getlist(x, def) = out {
  out := x
  out[_]
} else = def { true }

getobj(x, def) = out {
  out := x
  out == out
} else = def { true }

# String helpers
lower(s) := x { x := lower_ascii(s) }
lower_ascii(s) := x {
  x := translate(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
}

# Glob → anchored regex (simple * and ? support)
re_from_glob(p) := r {
  esc := regex.quote_meta(p)
  star := replace(esc, "\\*", ".*")
  q := replace(star, "\\?", ".")
  r := concat("", ["^", q, "$"])
}

glob_match(p, s) {
  re_match(re_from_glob(p), s)
}

# Extract host from URL (basic; supports http/https/ws/wss)
url_host(u) := h {
  some m
  m := regex.find_string_submatch("^[a-zA-Z][a-zA-Z0-9+.-]*://\\[?([^/\\]:]+)\\]?(?::\\d+)?/?.*$", u)
  count(m) >= 2
  h := m[1]
} else := "" { true }

# -----------------------------------------------------------------------------
# Deny rules and obligations
# -----------------------------------------------------------------------------

# 1) Model allowlist per tenant
deny[sprintf("model '%s' is not allowed for tenant '%s'", [input.request.model.name, input.request.actor.tenant])] {
  model := lower(input.request.model.name)
  not model_allowed(model)
  sev_override[_] := "high"
}
model_allowed(model) {
  some p; glob_match(lower(p), model); p := allowed_models[_]
} else {
  some p; glob_match(lower(p), model); p := allowed_models_fallback[_]
}

# 2) Prompt injection thresholds
deny["prompt injection score above block threshold"] {
  s := getnum(input.safety.injection_score, 0)
  s >= threshold_injection_block
  sev_override[_] := "critical"
}
obligation["sandbox_route"] {
  s := getnum(input.safety.injection_score, 0)
  s >= threshold_injection_warn
  s < threshold_injection_block
}

# 3) Toxicity hard block
deny["toxicity above block threshold"] {
  t := getnum(input.safety.toxicity, 0)
  t >= threshold_toxicity_block
  sev_override[_] := "high"
}

# 4) PII leakage (block certain kinds unless actor has sensitive_access)
deny[sprintf("pii kind '%s' requires sensitive access", [k])] {
  input.safety.pii.has
  k := input.safety.pii.kinds[_]
  k := lower(k)
  pii_block_kinds[_] == k
  not input.request.actor.sensitive_access
  sev_override[_] := "critical"
}
# PII warn → redact obligation
obligation["redact_pii"] {
  input.safety.pii.has
  some k; k := lower(input.safety.pii.kinds[_])
  pii_warn_kinds[_] == k
}

# 5) URL allow/deny (denylist and private CIDR)
deny[sprintf("url '%s' not allowed by policy", [u])] {
  u := input.request.urls[_]
  host := lower(url_host(u))
  # deny by glob
  some d; d := lower(url_deny[_]); glob_match(d, lower(u)) or glob_match(d, host)
  sev_override[_] := "high"
}
deny[sprintf("url '%s' points to private network", [u])] {
  u := input.request.urls[_]
  host := url_host(u)
  ip := host
  some c; c := cidr_deny[_]
  net.cidr_contains(c, ip)
  sev_override[_] := "critical"
}
deny[sprintf("url '%s' not in allowlist", [u])] {
  u := input.request.urls[_]
  host := lower(url_host(u))
  not url_allowed(u, host)
  sev_override[_] := "high"
}
url_allowed(u, host) {
  some a; a := lower(url_allow[_])
  glob_match(a, lower(u)) or glob_match(a, host)
}

# 6) Tool usage restrictions by policy
deny[sprintf("tool '%s' is not allowed", [t.name])] {
  t := input.request.tools[_]
  not tool_is_allowed(t)
  sev_override[_] := "high"
}
tool_is_allowed(t) {
  p := tool_policies[t.name]
  p.allow == true
}
# Tool argument constraints: allowed/deny globs per arg
deny[sprintf("tool '%s' arg '%s' violates pattern policy", [t.name, k])] {
  t := input.request.tools[_]
  p := tool_policies[t.name]
  p.allow == true
  argp := p.args[k]
  v := tostring(t.args[k])
  # deny patterns
  some dg; dg := lower(argp.deny_globs[_]); glob_match(dg, lower(v))
  sev_override[_] := "high"
}
deny[sprintf("tool '%s' arg '%s' not in allow_globs", [t.name, k])] {
  t := input.request.tools[_]
  p := tool_policies[t.name]
  p.allow == true
  argp := p.args[k]
  v := tostring(t.args[k])
  not some ag { ag := lower(argp.allow_globs[_]); glob_match(ag, lower(v)) }
  # allow_globs present but nothing matched
  count(getlist(argp.allow_globs, [])) > 0
  sev_override[_] := "high"
}

# 7) Quotas and concurrency (stateless; relies on input.usage snapshot)
# Per-user RPM
deny[sprintf("per-user rpm exceeded: %d/%d", [input.usage.per_user_rpm.current, quota_user_rpm_limit])] {
  cur := getnum(input.usage.per_user_rpm.current, 0)
  cur >= quota_user_rpm_limit
  retry_after["rpm"] := max(remaining_time(input.usage.per_user_rpm.reset_at), 1)
  sev_override[_] := "high"
}
# Global concurrency
deny[sprintf("global concurrency exceeded: %d/%d", [input.usage.global_concurrency.current, quota_conc_limit])] {
  cur := getnum(input.usage.global_concurrency.current, 0)
  cur >= quota_conc_limit
  retry_after["concurrency"] := max(remaining_time(input.usage.global_concurrency.reset_at), 1)
  sev_override[_] := "high"
}
# Tenant daily tokens
deny[sprintf("tenant daily tokens exceeded: %d/%d", [input.usage.tenant_tokens_daily.used, quota_tokens_limit])] {
  used := getnum(input.usage.tenant_tokens_daily.used, 0)
  used >= quota_tokens_limit
  retry_after["tokens"] := max(remaining_time(input.usage.tenant_tokens_daily.reset_at), 60)
  sev_override[_] := "high"
}

# 8) Input size guardrail
deny[sprintf("input too large: %d chars", [input.request.content.length])] {
  max_len := getnum(data.policies.thresholds.input.max_chars, 30000)
  getnum(input.request.content.length, 0) > max_len
  sev_override[_] := "high"
}
obligation["truncate_input"] {
  warn_len := getnum(data.policies.thresholds.input.warn_chars, 20000)
  l := getnum(input.request.content.length, 0)
  l > warn_len
  l <= getnum(data.policies.thresholds.input.max_chars, 30000)
}

# 9) Secrets hygiene obligation (caller should have applied redaction)
obligation["redact_secrets"] {
  getbool(data.policies.obligations.redact_secrets, true)
}
getbool(x, def) = out {
  out := x
} else = def { true }

# -----------------------------------------------------------------------------
# Utilities: time left until reset
# -----------------------------------------------------------------------------
remaining_time(reset_at) = sec {
  wall := time.now_ns() / 1000000000
  sec := max(0, getnum(reset_at, wall) - wall)
}

max(arr, def) = out {
  count(arr) > 0
  out := max_impl(arr)
} else = def { true }

max_impl(arr) = m {
  m := arr[0]
  not some i { arr[i] > m }
} else = m {
  some i
  m := arr[i]
  not exists_greater(arr, m)
}
exists_greater(arr, m) {
  some j
  arr[j] > m
}

# -----------------------------------------------------------------------------
# End of policy
# -----------------------------------------------------------------------------
