# chronowatch-core/configs/policies/rego/sla_breach.rego
package chronowatch.policies.sla

# Policy detects SLA breaches for services using latency p95, error rate and availability.
# Inputs:
#   input.services: [
#     {
#       "name": "api-gateway",
#       "tier": "gold",                        # optional, defaults to "silver"
#       "metrics": {
#         "window": "5m",                      # optional, defaults to "5m"
#         "p95_latency_ms": 230,               # number
#         "error_rate_pct": 0.4,               # number, percent
#         "availability_pct": 99.95            # number, percent
#       }
#     },
#     ...
#   ]
#
# Optional input history for escalation:
#   input.history[service][dimension].consecutive_failures: number
#
# Optional external policy config:
#   data.sla_policies.tiers: { "gold": {...}, "silver": {...}, "bronze": {...} }
#
# Decisions:
#   breaches: set of objects with detailed breach info
#   critical_or_high: subset of breaches with severity in {"high","critical"}
#   allow_release: boolean gate for CD pipelines (false if any high/critical)
#   deny_release: reasons array for gate failures
#   evaluation: single object with summary and score

default allow_release = true

# -----------------------
# Default tier thresholds
# -----------------------
default_tiers := {
  "gold": {
    "latency_ms_p95": 200,
    "error_rate_pct": 0.5,
    "availability_pct": 99.9
  },
  "silver": {
    "latency_ms_p95": 400,
    "error_rate_pct": 1.0,
    "availability_pct": 99.5
  },
  "bronze": {
    "latency_ms_p95": 800,
    "error_rate_pct": 2.0,
    "availability_pct": 99.0
  }
}

# -----------------------
# Helpers
# -----------------------

# Safe coalesce: if x is defined and not null, return x, else y.
coalesce(x, y) = x { x != null } else = y { x == null }

# Tier config resolution with fallbacks: data.sla_policies -> defaults -> silver
tier_cfg(tier) = cfg {
  cfg := data.sla_policies.tiers[lower(tier)]
} else = cfg {
  cfg := default_tiers[lower(tier)]
} else = cfg {
  cfg := default_tiers["silver"]
}

# Consecutive failures from input history
consecutive(service, dim) = n {
  n := input.history[service][dim].consecutive_failures
} else = 0 { true }

# Escalation steps based on consecutive failures: 0,1,2,3 at 0,2,4,6+
escalation_steps(n) = 3 { n >= 6 }
escalation_steps(n) = 2 { n >= 4; n < 6 }
escalation_steps(n) = 1 { n >= 2; n < 4 }
escalation_steps(n) = 0 { n < 2 }

severity_rank("low") = 1
severity_rank("medium") = 2
severity_rank("high") = 3
severity_rank("critical") = 4

severity_from_rank(1) = "low"
severity_from_rank(2) = "medium"
severity_from_rank(3) = "high"
severity_from_rank(4) = "critical"

# Escalate severity by steps, cap at "critical"
escalate_severity(service, dim, base) = out {
  steps := escalation_steps(consecutive(service, dim))
  r0 := severity_rank(base)
  r  := r0 + steps
  r_cap := r
  r_cap >= 4
  out := severity_from_rank(4)
} else = out {
  steps := escalation_steps(consecutive(service, dim))
  r0 := severity_rank(base)
  r  := r0 + steps
  r < 4
  out := severity_from_rank(r)
}

# Severity calculators
severity_latency(observed, threshold) = "critical" { observed >= threshold * 1.5 }
severity_latency(observed, threshold) = "high"     { observed >= threshold * 1.2; observed < threshold * 1.5 }
severity_latency(observed, threshold) = "medium"   { observed >= threshold; observed < threshold * 1.2 }

severity_error(observed, threshold) = "critical" { observed >= threshold * 1.5 }
severity_error(observed, threshold) = "high"     { observed >= threshold * 1.2; observed < threshold * 1.5 }
severity_error(observed, threshold) = "medium"   { observed >= threshold; observed < threshold * 1.2 }

severity_availability(observed, threshold) = "critical" { observed < threshold - 1.0 }
severity_availability(observed, threshold) = "high"     { observed < threshold - 0.5; observed >= threshold - 1.0 }
severity_availability(observed, threshold) = "medium"   { observed < threshold; observed >= threshold - 0.5 }

# Weighting for score
severity_weight("low") = 10
severity_weight("medium") = 25
severity_weight("high") = 50
severity_weight("critical") = 75

# Build breach object
make_breach(service, dim, observed, threshold, window, tier, base_sev) = b {
  sev := escalate_severity(service, dim, base_sev)
  action := "notify"
  action := "page_oncall" { sev == "high" }
  action := "page_oncall" { sev == "critical" }

  b := {
    "service": service,
    "dimension": dim,                 # "latency_p95_ms" | "error_rate_pct" | "availability_pct"
    "observed": observed,
    "threshold": threshold,
    "window": window,
    "tier": tier,
    "severity": sev,
    "base_severity": base_sev,
    "consecutive": consecutive(service, dim),
    "action": action,
    "labels": {
      "component": "core",
      "policy": "sla",
      "env": coalesce(input.env, "dev")
    }
  }
}

# -----------------------
# Breach detection
# -----------------------

# Latency p95 breach
breaches[b] {
  s := input.services[_]
  svc := s.name
  tier := lower(coalesce(s.tier, "silver"))
  cfg := tier_cfg(tier)
  window := coalesce(s.metrics.window, "5m")

  observed := s.metrics.p95_latency_ms
  threshold := cfg.latency_ms_p95

  observed != null
  threshold != null
  observed > threshold

  base := severity_latency(observed, threshold)
  b := make_breach(svc, "latency_p95_ms", observed, threshold, window, tier, base)
}

# Error rate breach
breaches[b] {
  s := input.services[_]
  svc := s.name
  tier := lower(coalesce(s.tier, "silver"))
  cfg := tier_cfg(tier)
  window := coalesce(s.metrics.window, "5m")

  observed := s.metrics.error_rate_pct
  threshold := cfg.error_rate_pct

  observed != null
  threshold != null
  observed > threshold

  base := severity_error(observed, threshold)
  b := make_breach(svc, "error_rate_pct", observed, threshold, window, tier, base)
}

# Availability breach
breaches[b] {
  s := input.services[_]
  svc := s.name
  tier := lower(coalesce(s.tier, "silver"))
  cfg := tier_cfg(tier)
  window := coalesce(s.metrics.window, "5m")

  observed := s.metrics.availability_pct
  threshold := cfg.availability_pct

  observed != null
  threshold != null
  observed < threshold

  base := severity_availability(observed, threshold)
  b := make_breach(svc, "availability_pct", observed, threshold, window, tier, base)
}

# Subset: high or critical
critical_or_high[b] {
  b := breaches[_]
  b.severity == "high"
} else = b {
  b := breaches[_]
  b.severity == "critical"
}

# Gate decision for CI/CD
allow_release = false {
  critical_or_high[_]
}

# Reasons to deny release
deny_release[reason] {
  b := critical_or_high[_]
  reason := sprintf(
    "SLA breach: service=%v dim=%v observed=%v threshold=%v window=%v severity=%v",
    [b.service, b.dimension, b.observed, b.threshold, b.window, b.severity],
  )
}

# -----------------------
# Summary scoring
# -----------------------

total_weight = sum([ severity_weight(b.severity) | b := breaches[_] ])

compliance_score = score {
  base := 100 - total_weight
  base >= 0
  score := base
} else = score {
  base := 100 - total_weight
  base < 0
  score := 0
}

# -----------------------
# Aggregated evaluation
# -----------------------

evaluation := {
  "allow_release": allow_release,
  "breaches": [b | b := breaches[_]],
  "breaches_by_service": { s: [b | b := breaches[_]; b.service == s] | s := b.service },
  "score": compliance_score
}
