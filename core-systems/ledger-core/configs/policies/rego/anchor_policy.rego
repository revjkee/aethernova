# ledger-core/ops/configs/policies/rego/anchor_policy.rego
package ledger.anchor

# Decision entrypoint (conventional for OPA HTTP API: /v1/data/ledger/anchor/decision)
default decision := {
  "allow": false,
  "reasons": ["no input"],
  "meta": {
    "version": "1.0.0",
    "policy": "anchor_policy",
    "mode": "default-deny"
  }
}

# Main decision: allow if no denies, with reasons list (empty on success) and meta echo
decision := {
  "allow": allow,
  "reasons": reasons,
  "meta": {
    "version": "1.0.0",
    "policy": "anchor_policy",
    "mode": "default-deny",
    "tenant": input.request.tenant_id,
    "subject": input.subject.id,
    "chain": input.request.chain,
    "action": input.request.action,
    "ts": input.context.now
  }
} {
  some _  # ensure block body
  reasons := deny_reasons
  allow := count(reasons) == 0
}

# -----------------------------
# Deny reasons (accumulate)
# -----------------------------
deny_reasons[msg] {
  not has_required_fields
  msg := "missing required fields"
}

deny_reasons[msg] {
  input.request.action != "anchor.create"
  msg := sprintf("unsupported action: %v", [input.request.action])
}

deny_reasons[msg] {
  not subject_allowed
  msg := "subject not authorized for tenant/action"
}

deny_reasons[msg] {
  not chain_enabled
  msg := sprintf("chain disabled or unknown: %v", [input.request.chain])
}

deny_reasons[msg] {
  not payload_hash_valid
  msg := "payload.hash invalid (must be hex sha256)"
}

deny_reasons[msg] {
  not payload_size_valid
  lim := chain_limits.max_payload_bytes
  msg := sprintf("payload.size exceeds limit: %v > %v", [input.request.payload.size, lim])
}

deny_reasons[msg] {
  not content_type_allowed
  msg := sprintf("payload.content_type not allowed: %v", [input.request.payload.content_type])
}

deny_reasons[msg] {
  not fee_within_caps
  caps := chain_limits.fee_caps
  msg := sprintf("fee/gas exceeds caps: gas=%v fee=%v caps=%v", [input.request.tx.gas, input.request.tx.max_fee_wei, caps])
}

deny_reasons[msg] {
  not nonce_monotonic
  msg := "nonce not monotonic"
}

deny_reasons[msg] {
  not ts_within_window
  msg := "timestamp outside allowed skew window"
}

deny_reasons[msg] {
  not method_allowlisted
  msg := sprintf("rpc method not allowlisted: %v", [input.request.tx.method])
}

deny_reasons[msg] {
  not rate_gate_ok
  msg := "rate gate not satisfied (external limiter signal)"
}

deny_reasons[msg] {
  not signer_allowed_on_chain
  msg := "signer not allowed for chain"
}

deny_reasons[msg] {
  input.request.tx.max_fee_wei < chain_limits.fee_caps.min_fee_wei
  msg := sprintf("max_fee_wei below minimum: %v < %v", [input.request.tx.max_fee_wei, chain_limits.fee_caps.min_fee_wei])
}

# -----------------------------
# Predicates
# -----------------------------
has_required_fields {
  input.request.action
  input.request.tenant_id
  input.request.chain
  input.request.payload.hash
  input.request.payload.size
  input.request.payload.content_type
  input.request.tx.gas
  input.request.tx.max_fee_wei
  input.request.tx.method
  input.subject.id
  input.subject.roles
  input.context.now
}

subject_allowed {
  # subject exists and has at least one role permitted for this tenant+action
  some role
  role := input.subject.roles[_]
  allow_roles := data.policies.tenants[input.request.tenant_id].actions["anchor.create"].roles
  allow_roles[role]
}

chain_enabled {
  lim := chain_limits
  lim.enabled == true
}

payload_hash_valid {
  # hex sha256 (64 hex chars)
  h := input.request.payload.hash
  re_match("^[0-9a-fA-F]{64}$", h)
}

payload_size_valid {
  s := input.request.payload.size
  lim := chain_limits.max_payload_bytes
  is_number(s)
  s >= 0
  s <= lim
}

content_type_allowed {
  ct := input.request.payload.content_type
  allowed := chain_limits.allowed_content_types
  allowed[ct]
}

fee_within_caps {
  tx := input.request.tx
  caps := chain_limits.fee_caps
  is_number(tx.gas)
  is_number(tx.max_fee_wei)
  tx.gas >= caps.min_gas
  tx.gas <= caps.max_gas
  tx.max_fee_wei <= caps.max_fee_wei
}

nonce_monotonic {
  # require provided previous nonce context value (from state) to be < current
  prev := input.context.prev_nonce
  curr := input.request.tx.nonce
  is_number(curr)
  (not is_number(prev)) or curr > prev
}

ts_within_window {
  now := input.context.now
  ts := input.request.timestamp
  # if timestamp not provided, accept; else check absolute skew
  (not is_number(ts)) or abs(now - ts) <= chain_limits.time.skew_sec
}

method_allowlisted {
  allow := chain_limits.method_allowlist
  method := input.request.tx.method
  allow[method]
}

rate_gate_ok {
  # external rate limiter places signal in context; default true if absent
  ok := input.context.rate_ok
  not ok == false
}

signer_allowed_on_chain {
  signer := input.subject.id
  chain := input.request.chain
  # allow: either signer is explicitly enabled for chain, or global wildcard
  data.identities.signers[signer].chains[chain] == true
  # optional: tenant cross-check
  data.identities.signers[signer].tenants[input.request.tenant_id] == true
}

# -----------------------------
# Helpers
# -----------------------------
is_number(x) {
  type_name(x) == "number"
}

abs(x) = y {
  x >= 0
  y := x
} else = y {
  y := -1 * x
}

# -----------------------------
# Chain limits accessor
# -----------------------------
chain_limits := limits {
  chain := input.request.chain
  # defaults merged with chain-specific
  base := data.policies.chains.defaults
  specific := data.policies.chains[chain]
  limits := {
    "enabled": value_or_default(specific.enabled, base.enabled),
    "max_payload_bytes": value_or_default(specific.max_payload_bytes, base.max_payload_bytes),
    "allowed_content_types": set_or_default(specific.allowed_content_types, base.allowed_content_types),
    "fee_caps": {
      "min_gas": value_or_default(specific.fee_caps.min_gas, base.fee_caps.min_gas),
      "max_gas": value_or_default(specific.fee_caps.max_gas, base.fee_caps.max_gas),
      "min_fee_wei": value_or_default(specific.fee_caps.min_fee_wei, base.fee_caps.min_fee_wei),
      "max_fee_wei": value_or_default(specific.fee_caps.max_fee_wei, base.fee_caps.max_fee_wei)
    },
    "time": {
      "skew_sec": value_or_default(specific.time.skew_sec, base.time.skew_sec)
    },
    "method_allowlist": set_or_default(specific.method_allowlist, base.method_allowlist)
  }
}

value_or_default(x, d) = out {
  out := x
} else = out {
  out := d
}

set_or_default(x, d) = out {
  out := x
} else = out {
  out := d
}

# -----------------------------
# Example data model (for reference):
# Place into your bundle under data.policies.* and data.identities.*
# -----------------------------
# data.policies = {
#   "tenants": {
#     "tenant-a": {
#       "actions": {
#         "anchor.create": { "roles": { "anchorer": true, "admin": true } }
#       }
#     }
#   },
#   "chains": {
#     "defaults": {
#       "enabled": true,
#       "max_payload_bytes": 65536,
#       "allowed_content_types": { "application/octet-stream": true, "application/json": true },
#       "fee_caps": { "min_gas": 21000, "max_gas": 500000, "min_fee_wei": 1000000000, "max_fee_wei": 300000000000 },
#       "time": { "skew_sec": 300 },
#       "method_allowlist": { "eth_sendRawTransaction": true }
#     },
#     "ethereum": {
#       "fee_caps": { "max_gas": 800000, "max_fee_wei": 500000000000 }
#     },
#     "polygon": {
#       "fee_caps": { "max_fee_wei": 2000000000000 }
#     }
#   }
# }
#
# data.identities = {
#   "signers": {
#     "did:key:zSomeKeyOrAddr": {
#       "tenants": { "tenant-a": true },
#       "chains": { "ethereum": true, "polygon": true }
#     }
#   }
# }

# -----------------------------
# Unit tests (rego) — optional: place in anchor_policy_test.rego
# -----------------------------
# package ledger.anchor
#
# import future.keywords.every
#
# test_allow_minimal_ok {
#   data.policies := test_policies
#   data.identities := test_identities
#   input := {
#     "request": {
#       "action": "anchor.create",
#       "tenant_id": "tenant-a",
#       "chain": "ethereum",
#       "payload": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 1024, "content_type": "application/json"},
#       "tx": {"gas": 300000, "max_fee_wei": 10000000000, "method": "eth_sendRawTransaction", "nonce": 2},
#       "timestamp": 1000
#     },
#     "subject": {"id": "did:key:zSomeKeyOrAddr", "roles": ["anchorer"]},
#     "context": {"now": 1000, "prev_nonce": 1, "rate_ok": true}
#   }
#   decision.allow
#   count(decision.reasons) == 0
# }
#
# test_deny_over_fee {
#   data.policies := test_policies
#   data.identities := test_identities
#   input := {
#     "request": {
#       "action": "anchor.create",
#       "tenant_id": "tenant-a",
#       "chain": "ethereum",
#       "payload": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 1024, "content_type": "application/json"},
#       "tx": {"gas": 900000, "max_fee_wei": 9999999999999, "method": "eth_sendRawTransaction", "nonce": 2},
#       "timestamp": 1000
#     },
#     "subject": {"id": "did:key:zSomeKeyOrAddr", "roles": ["anchorer"]},
#     "context": {"now": 1000, "prev_nonce": 1, "rate_ok": true}
#   }
#   not decision.allow
#   some r in decision.reasons
#   startswith(r, "fee/gas exceeds caps")
# }
#
# test_policies := {
#   "tenants": {"tenant-a": {"actions": {"anchor.create": {"roles": {"anchorer": true}}}}},
#   "chains": {
#     "defaults": {
#       "enabled": true,
#       "max_payload_bytes": 65536,
#       "allowed_content_types": {"application/json": true},
#       "fee_caps": {"min_gas": 21000, "max_gas": 500000, "min_fee_wei": 1000000000, "max_fee_wei": 300000000000},
#       "time": {"skew_sec": 300},
#       "method_allowlist": {"eth_sendRawTransaction": true}
#     },
#     "ethereum": {"fee_caps": {"max_gas": 800000}}
#   }
# }
#
# test_identities := {
#   "signers": {"did:key:zSomeKeyOrAddr": {"tenants": {"tenant-a": true}, "chains": {"ethereum": true}}}
# }
