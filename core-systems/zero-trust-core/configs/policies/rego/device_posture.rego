# File: zero-trust-core/configs/policies/rego/device_posture.rego
package zt.policies.device_posture

# Rego v1 keywords
import future.keywords.in

# =========================
# Public decision document
# =========================
#
# Input contract (пример):
# input: {
#   "user": { "id": "...", "roles": ["user","admin"], "tenant_id": "acme" },
#   "request": { "path": "/admin/keys", "method": "POST", "ip": "203.0.113.10" },
#   "device": {
#     "platform": "windows|macos|linux|ios|android",
#     "os": { "name": "Windows", "version": "10.0.22631", "patch_age_days": 12, "build": "22631.2861" },
#     "disk_encryption": true,
#     "firewall_enabled": true,
#     "screen_lock_timeout_s": 300,
#     "secure_boot": true,
#     "tpm_present": true,
#     "serial_number": "ABC123",
#     "model": "MacBookPro18,4",
#     "edr": { "status": "healthy|degraded|missing", "vendor": "CrowdStrike" },
#     "av":  { "enabled": true, "definitions_age_days": 2 },
#     "mdm": { "managed": true, "vendor": "Intune|Jamf|..."},
#     "attest": {
#       "mdm": { "valid": true, "ts": "2025-08-20T12:00:00Z" },
#       "webauthn": { "attested": true, "aaguid": "..." },
#       "mtls": { "subject_dn": "OU=CorpVPN,O=Example Inc,CN=device-01", "spki_sha256": "..." }
#     },
#     "rooted": false,
#     "jailbroken": false
#   }
# }
#
# Output (пример):
# {
#   "action": "allow|step_up|deny",
#   "allow": true|false,
#   "risk_score": 0..100,
#   "reasons": ["..."],
#   "violations": [{"id":"no_encryption","msg":"Disk encryption disabled","severity":90}, ...],
#   "requirements": ["enable_disk_encryption","enable_firewall", ...],
#   "platform": "windows",
#   "context": { "roles":["admin"], "path":"/admin/keys" }
# }

default result := {
  "action": "deny",
  "allow": false,
  "risk_score": 100,
  "reasons": ["policy_evaluation_failed_or_no_input"],
  "violations": [],
  "requirements": ["contact_support"],
  "platform": platform,
  "context": {"roles": roles, "path": path},
}

result := {
  "action": action,
  "allow": action == "allow",
  "risk_score": risk_score,
  "reasons": [v.msg | v := violations],
  "violations": violations,
  "requirements": reqs,
  "platform": platform,
  "context": {"roles": roles, "path": path},
} {
  valid_input
  risk_score := total_risk
  action := decide_action
  reqs := requirements
}

# =========================
# Input helpers and config
# =========================

valid_input {
  platform != ""
}

platform := lower(input.device.platform) default ""

roles := input.user.roles default []

path := input.request.path default "/"

# Policy configuration with overridable defaults via data.device_posture
max_patch_age_days      := get_num(["device_posture","minimum_requirements","os_patch_max_age_days"], 30)
require_disk_encryption := get_bool(["device_posture","minimum_requirements","disk_encryption"], true)
require_firewall        := get_bool(["device_posture","minimum_requirements","firewall_enabled"], true)
max_screenlock_s        := get_num(["device_posture","minimum_requirements","screen_lock_timeout_s"], 600)

require_mdm_for_roles   := get_strs(["device_posture","require_managed_for_roles"], ["admin","finance"])
require_mtls_for_paths  := get_strs(["device_posture","require_mtls_for_paths"], ["POST:/admin/*"])

deny_models             := get_strs(["device_posture","deny_models"], [])
allow_models            := get_strs(["device_posture","allow_models"], [])

deny_builds             := get_strs(["device_posture","deny_builds"], [])

step_up_min             := get_num(["device_posture","thresholds","step_up_min"], 30)
deny_min                := get_num(["device_posture","thresholds","deny_min"], 70)

# =========================
# Violations catalog
# Each violation is an object with:
# id, msg, severity (0..100), req (optional remediation key)
# =========================

violations[v] {
  not bool(input.device.disk_encryption, true)
  require_disk_encryption
  v := {"id":"no_encryption","msg":"Disk encryption disabled","severity":90,"req":"enable_disk_encryption"}
}

violations[v] {
  require_firewall
  not bool(input.device.firewall_enabled, true)
  v := {"id":"firewall_disabled","msg":"Host firewall disabled","severity":60,"req":"enable_firewall"}
}

violations[v] {
  max_screenlock_s > 0
  to_number(input.device.screen_lock_timeout_s) > max_screenlock_s
  v := {"id":"screen_lock_weak","msg": sprintf("Screen lock timeout too high (> %d s)", [max_screenlock_s]), "severity":40, "req":"reduce_screen_lock_timeout"}
}

violations[v] {
  to_number(input.device.os.patch_age_days) > max_patch_age_days
  v := {"id":"patch_stale","msg": sprintf("OS patches are stale (> %d days)", [max_patch_age_days]), "severity":50, "req":"apply_os_updates"}
}

violations[v] {
  platform == "windows"
  not bool(input.device.secure_boot, true)
  v := {"id":"secure_boot_missing","msg":"Secure Boot not enabled (Windows)","severity":60,"req":"enable_secure_boot"}
}

violations[v] {
  platform == "windows"
  not bool(input.device.tpm_present, true)
  v := {"id":"tpm_missing","msg":"TPM not present (Windows)","severity":50,"req":"require_tpm"}
}

# Root/Jailbreak are hard denies
violations[v] {
  bool(input.device.rooted, false)
  v := {"id":"rooted","msg":"Device is rooted","severity":100,"req":"reimage_or_remove_root"}
}

violations[v] {
  bool(input.device.jailbroken, false)
  v := {"id":"jailbroken","msg":"Device is jailbroken","severity":100,"req":"restore_stock_os"}
}

# EDR/AV posture
violations[v] {
  lower(input.device.edr.status) == "missing"
  v := {"id":"edr_missing","msg":"EDR agent missing","severity":60,"req":"install_edr"}
}

violations[v] {
  lower(input.device.edr.status) == "degraded"
  v := {"id":"edr_degraded","msg":"EDR agent degraded","severity":40,"req":"repair_edr"}
}

violations[v] {
  not bool(input.device.av.enabled, true)
  v := {"id":"av_disabled","msg":"Antivirus disabled","severity":30,"req":"enable_av"}
}

violations[v] {
  to_number(input.device.av.definitions_age_days) > 7
  v := {"id":"av_outdated","msg":"Antivirus definitions older than 7 days","severity":20,"req":"update_av_defs"}
}

# Attestations
violations[v] {
  requires_mdm_for_context
  not bool(input.device.mdm.managed, false)
  v := {"id":"mdm_required","msg":"MDM enrollment required for this role/path","severity":80,"req":"enroll_mdm"}
}

violations[v] {
  bool(input.device.mdm.managed, false)
  not bool(input.device.attest.mdm.valid, false)
  v := {"id":"mdm_attestation_invalid","msg":"MDM attestation invalid or missing","severity":50,"req":"refresh_mdm_attestation"}
}

violations[v] {
  requires_mtls_for_context
  not valid_mtls
  v := {"id":"mtls_required","msg":"mTLS client certificate required for this path","severity":100,"req":"connect_via_corp_vpn"}
}

# Model/build lists
violations[v] {
  allow_models != []
  not (input.device.model in allow_models)
  v := {"id":"model_not_allowed","msg": sprintf("Model not in allow list: %v", [input.device.model]), "severity":70,"req":"use_corporate_model"}
}

violations[v] {
  deny_models != []
  input.device.model in deny_models
  v := {"id":"model_denied","msg": sprintf("Model denied: %v", [input.device.model]), "severity":100,"req":"replace_device"}
}

violations[v] {
  deny_builds != []
  input.device.os.build in deny_builds
  v := {"id":"build_denied","msg": sprintf("OS build denied: %v", [input.device.os.build]), "severity":90,"req":"upgrade_os_build"}
}

# Platform-specific encryption expectations
violations[v] {
  platform == "macos"
  require_disk_encryption
  not bool(input.device.disk_encryption, true)
  v := {"id":"filevault_off","msg":"FileVault disabled (macOS)","severity":90,"req":"enable_filevault"}
}

violations[v] {
  platform == "linux"
  require_disk_encryption
  not bool(input.device.disk_encryption, true)
  v := {"id":"luks_off","msg":"Disk encryption disabled (Linux)","severity":80,"req":"enable_luks"}
}

# =========================
# Derived helpers
# =========================

requires_mdm_for_context {
  r := roles[_]
  lower(r) in [lower(x) | x := require_mdm_for_roles[_]]
}

# Require mTLS for paths matched как METHOD:/admin/* (грубое сопоставление)
requires_mtls_for_context {
  p := input.request.method ++ ":" ++ path
  pattern := require_mtls_for_paths[_]
  glob.match(pattern, [], p)
}

valid_mtls {
  subj := input.device.attest.mtls.subject_dn
  subj != ""
}

# =========================
# Risk aggregation and decision
# =========================

# Total risk is a capped sum of violation severities (0..100)
total_risk := s {
  vs := [v.severity | v := violations]
  sum(vs, raw)
  s := min([100, raw])
}

# Decision logic with hard-fail shortcuts
decide_action := "deny" {
  some v
  v := violations[_]
  v.severity >= 95
} else := "deny" {
  total_risk >= deny_min
} else := "step_up" {
  total_risk >= step_up_min
} else := "allow"

# Requirements derived from violations (unique list of remediation keys)
requirements := distinct([v.req | v := violations; v.req != ""])

# =========================
# Generic helpers
# =========================

# Fetch a number from data.* with default
get_num(path, default) = out {
  out := to_number(n) with data as walk_get(data, path, default)
  not is_null(out)
} else = default

# Fetch boolean from data.* with default
get_bool(path, default) = out {
  out := bool(b, default) with data as walk_get(data, path, default)
} else = default

# Fetch array of strings from data.* with default
get_strs(path, default) = out {
  x := walk_get(data, path, default)
  arr := [sprintf("%v", [i]) | i := x[_]]
  out := arr
} else = default

# Safe extractor from nested object by path with default
walk_get(obj, path, default) = out {
  is_array(path)
  count(path) > 0
  key := path[0]
  rest := path[1:]
  obj[key] != null
  out := walk_get(obj[key], rest, default)
} else = out {
  is_array(path)
  count(path) == 0
  out := obj
} else = default

# Convert to boolean with default
bool(x, default) = out {
  x == true
  out := true
} else = out {
  x == false
  out := false
} else = default

# Convert to number (string/int) with default 0 if not convertible
to_number(x) = n {
  n := to_number_builtin(x)
} else = 0

to_number_builtin(x) = n {
  n := x
  typeof(x) == "number"
} else = n {
  typeof(x) == "string"
  re_match("^[0-9]+$", x)
  n := to_number(x)
}

# Lowercase helper
lower(s) = out {
  out := lower_ascii(sprintf("%v",[s]))
}

# Distinct helper
distinct(xs) = ys {
  ys := {x | x := xs[_]}
  # convert set to array in stable order
  sorted := sort([x | x := ys[_]])
  ys := sorted
}

# =========================
# Tests (inline queries examples)
# =========================
# Example (opa eval):
# opa eval -d device_posture.rego -I \
# 'data.zt.policies.device_posture.result' \
# -i <(cat <<JSON
# {
#   "user": {"roles":["user"]},
#   "request": {"path":"/api/resource","method":"GET"},
#   "device": {
#     "platform":"macos","disk_encryption":true,"firewall_enabled":true,
#     "screen_lock_timeout_s":300,"os":{"patch_age_days":10,"build":"23F79"},
#     "mdm":{"managed":true},"edr":{"status":"healthy"},"av":{"enabled":true,"definitions_age_days":1},
#     "attest":{"mdm":{"valid":true}}
#   }
# }
# JSON
# )
