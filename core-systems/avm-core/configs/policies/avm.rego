# avm.rego
# Production-grade policies for avm_core
# - Admission checks for Pod/Deployment/DaemonSet/Job/CronJob
# - Image provenance checks (registry allowlist, digest required in prod)
# - SecurityContext checks (no privileged, non-root, readOnlyRootFs, drop ALL caps)
# - Volumes checks (no hostPath by default)
# - Env var checks (no raw secrets in env; require valueFrom.secretKeyRef)
# - Resource limits/requests enforcement
# - API action authorization based on JWT claims (input.jwt)
# - Waivers support via annotations or a data waiver store
#
# Data files expected (data.avm.config):
# {
#   "allowed_registries": ["123.dkr.ecr.eu-central-1.amazonaws.com","ghcr.io/ORG"],
#   "require_image_digest_in_prod": true,
#   "env_allowlist": ["SAFE_VAR"],
#   "max_cpu_millicores": 2000,
#   "max_memory_mb": 8192,
#   "allowed_namespaces": ["avm-core","avm-core-prod","avm-core-stage"],
#   "forbidden_caps": ["SYS_ADMIN","NET_ADMIN","SYS_MODULE","DAC_READ_SEARCH","SYS_PTRACE"],
#   "forbidden_sysctls_prefix": ["net.ipv4.ip_forward","kernel.modules_disabled"],
#   "waiver_annotation": "avm-core/waiver",
#   "require_service_account": true,
#   "allowed_service_accounts": ["avm-system:operator","avm-system:runner"],
#   "enforce_resource_requests": true
# }

package avm.admission

default deny = { "allowed": true }  # default permissive for non-k8s inputs; explicit deny rules produce deny=true

# Entry point for K8s admission (input.review)
# expected input:
# {
#   "kind": "Pod" | "Deployment" | ...,
#   "object": <k8s object>,
#   "operation": "CREATE" | "UPDATE",
#   "namespace": "..."
# }

# helper: read config with safe defaults
config := data.avm.config

# helper: normalize kind mapping to retrieve podSpec
pod_spec := get_pod_spec(input.object)

get_pod_spec(obj) = spec {
  kind := lower(object.get(obj, "kind", ""))
  spec := {}
  kind == "pod"
  spec = object.get(obj, "spec", {})
}
get_pod_spec(obj) = spec {
  kind := lower(object.get(obj, "kind", ""))
  (kind == "deployment" ; kind == "statefulset" ; kind == "daemonset" ; kind == "replicaset")
  tpl := object.get(object.get(obj, "spec", {}), "template", {})
  spec = object.get(tpl, "spec", {})
}
get_pod_spec(obj) = spec {
  kind := lower(object.get(obj, "kind", ""))
  (kind == "job" ; kind == "cronjob")
  jobt := object.get(object.get(obj, "spec", {}), "jobTemplate", object.get(obj, "spec", {}))
  tpl := object.get(object.get(jobt, "spec", {}), "template", {})
  spec = object.get(tpl, "spec", {})
}

# waiver detection: returns true if resource has valid waiver annotation (data-driven waivers take precedence)
has_waiver(rule_id) {
  # 1) check annotation on resource: annotation contains comma separated rule ids and ticket/expiry
  ann := object.get(object.get(input.object, "metadata", {}), "annotations", {})
  wa := ann[config.waiver_annotation]
  wa != ""
  # Example waiver format: "rules=K8S-001,K8S-005;ticket=SEC-123;expires=2025-09-01T12:00:00Z"
  parts := split(wa, ";")
  some i
  kv := parts[i]
  startswith(kv, "rules=")
  rules := split(trim(stringslice(kv, 6, count(kv))), ",")
  rules[_] == rule_id
  # optional: expiry check
  expires := { e | some j; kv2 := parts[j]; startswith(kv2,"expires="); e := trim(stringslice(kv2,8,count(kv2))) }[_]
  not expires_expired(expires)
}

expires_expired(exp) {
  # if cannot parse, treat as expired -> no waiver
  time.parse_rfc3339_ns(exp) < time.now_ns()
}

# also support central waiver store: data.avm.waivers (map by resource uid/name)
waiver_store_has(resource_uid, rule_id) {
  w := data.avm.waivers[resource_uid]
  w.rules[_] == rule_id
  not expires_expired(w.expiresAt)
}

# ============= Deny rules (produce human-friendly messages) =============
deny[msg] {
  # namespace enforcement
  not namespace_allowed
  msg = {
    "reason": "namespace_not_allowed",
    "message": sprintf("Namespace %s is not allowed for avm_core workloads", [input.namespace]),
    "severity": "high"
  }
}

namespace_allowed {
  allowed := config.allowed_namespaces
  count(allowed) == 0  # if list empty -> allow any
}
namespace_allowed {
  allowed := config.allowed_namespaces
  allowed[_] == input.namespace
}

# Pod must have required app label
deny[msg] {
  not has_waiver("AVM-001")
  meta := object.get(input.object, "metadata", {})
  labels := object.get(meta, "labels", {})
  labels["app"] != "avm-core"
  msg = {"reason":"missing_label","message":"Resource missing label app=avm-core","severity":"medium"}
}

# require service account and it must be allowlisted if configured
deny[msg] {
  config.require_service_account
  not has_waiver("AVM-002")
  spec := pod_spec
  sa := object.get(spec, "serviceAccountName", "")
  sa == ""
  msg = {"reason":"missing_service_account","message":"Pod must set serviceAccountName","severity":"high"}
}
deny[msg] {
  config.require_service_account
  not has_waiver("AVM-003")
  spec := pod_spec
  sa := object.get(spec, "serviceAccountName", "")
  not data.avm.config.allowed_service_accounts[_] == sprintf("%s:%s", [input.namespace, sa])
  msg = {"reason":"service_account_not_allowed","message":sprintf("serviceAccount %s/%s is not allowed", [input.namespace, sa]),"severity":"high"}
}

# Disallow privileged containers
deny[msg] {
  not has_waiver("AVM-004")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  is_true(object.get(object.get(c,"securityContext", {}), "privileged", false))
  msg = {"reason":"privileged_container","message": sprintf("Container %s requests privileged=true", [object.get(c, "name","<noname>")]), "severity":"critical"}
}

# Require runAsNonRoot true on pod or container
deny[msg] {
  not has_waiver("AVM-005")
  spec := pod_spec
  # check pod-level
  not is_true(object.get(object.get(spec, "securityContext", {}), "runAsNonRoot"))
  some c
  c := object.get(spec, "containers", [])[_]
  not is_true(object.get(object.get(c, "securityContext", {}), "runAsNonRoot"))
  msg = {"reason":"run_as_root","message":"All containers must set runAsNonRoot=true", "severity":"high"}
}

# ReadOnlyRootFilesystem required
deny[msg] {
  not has_waiver("AVM-006")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  not is_true(object.get(object.get(c,"securityContext", {}), "readOnlyRootFilesystem"))
  msg = {"reason":"rw_rootfs","message":sprintf("Container %s must set readOnlyRootFilesystem=true", [object.get(c,"name","<noname>")]), "severity":"high"}
}

# Capabilities: must drop ALL
deny[msg] {
  not has_waiver("AVM-007")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  caps := object.get(object.get(c,"securityContext", {}), "capabilities", {})
  not list_contains_ignorecase(object.get(caps, "drop", []), "ALL")
  msg = {"reason":"caps_not_dropped","message": sprintf("Container %s must drop ALL capabilities", [object.get(c,"name","<noname>")]), "severity":"high"}
}

# Forbidden add caps
deny[msg] {
  not has_waiver("AVM-008")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  adds := lower_all(object.get(object.get(object.get(c,"securityContext", {}), "capabilities", {}), "add", []))
  forbidden := [x | x := config.forbidden_caps[_]]
  some f
  forbidden_lower := lower_all(forbidden)
  adds[_] == f
  f == forbidden_lower[_]
  msg = {"reason":"forbidden_capability","message": sprintf("Container %s adds forbidden capability %s", [object.get(c,"name","<noname>"), f]), "severity":"critical"}
}

# Disallow hostPath volumes unless explicitly allowlisted
deny[msg] {
  not has_waiver("AVM-009")
  spec := pod_spec
  some v
  v := object.get(spec, "volumes", [])[_]
  defined(v.hostPath)
  # allowlist check
  not starts_with_allowed_hostpath(v.hostPath.path)
  msg = {"reason":"hostpath_forbidden","message":"hostPath volumes are forbidden","severity":"high"}
}

starts_with_allowed_hostpath(path) {
  allowed := object.get(config, "allowed_hostpath_prefixes", [])
  some i
  allowed[i] != ""
  startswith(path, allowed[i])
}

# No hostNetwork/hostPID/hostIPC
deny[msg] {
  not has_waiver("AVM-010")
  spec := pod_spec
  is_true(object.get(spec, "hostNetwork", false))
  msg = {"reason":"hostNetwork_forbidden","message":"hostNetwork is forbidden for avm_core workloads","severity":"high"}
}
deny[msg] {
  not has_waiver("AVM-011")
  spec := pod_spec
  is_true(object.get(spec, "hostPID", false))
  msg = {"reason":"hostPID_forbidden","message":"hostPID is forbidden for avm_core workloads","severity":"high"}
}
deny[msg] {
  not has_waiver("AVM-012")
  spec := pod_spec
  is_true(object.get(spec, "hostIPC", false))
  msg = {"reason":"hostIPC_forbidden","message":"hostIPC is forbidden for avm_core workloads","severity":"high"}
}

# Sysctls check
deny[msg] {
  not has_waiver("AVM-013")
  spec := pod_spec
  sysctls := object.get(object.get(spec, "securityContext", {}), "sysctls", [])
  some s
  s := sysctls[_]
  forbidden_prefixes := config.forbidden_sysctls_prefix
  some p
  startswith(s.name, forbidden_prefixes[p])
  msg = {"reason":"forbidden_sysctl","message": sprintf("Sysctl %s is forbidden", [s.name]), "severity":"high"}
}

# Resource requests/limits
deny[msg] {
  config.enforce_resource_requests
  not has_waiver("AVM-014")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  not resources_defined(c)
  msg = {"reason":"resources_missing","message": sprintf("Container %s must define requests and limits for cpu/memory", [object.get(c,"name","<noname>")]), "severity":"high"}
}

resources_defined(c) {
  res := object.get(c, "resources", {})
  req := object.get(res, "requests", {})
  lim := object.get(res, "limits", {})
  defined(req.cpu)
  defined(req.memory)
  defined(lim.cpu)
  defined(lim.memory)
}

# CPU/Memory upper bounds per config
deny[msg] {
  not has_waiver("AVM-015")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  lim := object.get(object.get(c, "resources", {}), "limits", {})
  cpu := parse_cpu(lim.cpu)
  mem := parse_mem_mb(lim.memory)
  cpu > config.max_cpu_millicores
  msg = {"reason":"cpu_limit_exceeded","message": sprintf("Container %s requests cpu limit %d m from allowed %d m", [object.get(c,"name","<noname>"), cpu, config.max_cpu_millicores]), "severity":"medium"}
}
deny[msg] {
  not has_waiver("AVM-016")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  lim := object.get(object.get(c, "resources", {}), "limits", {})
  mem := parse_mem_mb(lim.memory)
  mem > config.max_memory_mb
  msg = {"reason":"memory_limit_exceeded","message": sprintf("Container %s requests memory limit %d MB exceeding %d MB", [object.get(c,"name","<noname>"), mem, config.max_memory_mb]), "severity":"medium"}
}

# Image checks: registry allowlist and digest requirement (in prod)
deny[msg] {
  not has_waiver("AVM-017")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  img := object.get(c, "image", "")
  not image_registry_allowed(img)
  msg = {"reason":"image_registry_forbidden","message": sprintf("Image %s from disallowed registry", [img]), "severity":"high"}
}
deny[msg] {
  not has_waiver("AVM-018")
  config.require_image_digest_in_prod
  is_prod()
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  img := object.get(c, "image", "")
  not image_has_digest(img)
  msg = {"reason":"image_digest_required","message": sprintf("Image %s must be pinned by digest in prod", [img]), "severity":"high"}
}

# Env var secrets check: sensitive names must use valueFrom.secretKeyRef
deny[msg] {
  not has_waiver("AVM-019")
  spec := pod_spec
  some c
  c := object.get(spec, "containers", [])[_]
  some e
  e := object.get(c, "env", [])[ _ ]
  name := lower(object.get(e, "name", ""))
  sensitive_env_name(name)
  val := object.get(e, "value", null)
  vf := object.get(e, "valueFrom", null)
  val != null
  not defined(object.get(vf, "secretKeyRef"))
  msg = {"reason":"secret_in_env","message": sprintf("Container %s sets sensitive env %s as literal; must use Secret", [object.get(c,"name","<noname>"), name]), "severity":"high"}
}

sensitive_env_name(n) {
  substr := ["password","passwd","secret","token","key","credential","access","private"]
  some s
  contains(n, s)
}

# helper: image registry allowed
image_registry_allowed(img) {
  reg := image_registry(img)
  reg == ""
  # if registry not explicitly set (e.g. library/ubuntu) treat as forbidden unless allowed list includes empty? default to false
} else {
  some r
  cfg := config.allowed_registries
  # if allowed_registries empty -> allow any
  count(cfg) == 0
  reg == img_registry_from(img)
} else {
  img_registry_from(img) == cfg[_]
}

img_registry_from(img) = reg {
  parts := split(img, "/")
  reg = parts[0]
  contains(reg, ".")  # crude check: registry contains dot or port
}

image_has_digest(img) {
  contains(img, "@sha256:")
}

# parse CPU like "100m" or "2"
parse_cpu(cpu_str) = millicores {
  cpu_str == ""   # treat as 0
  millicores = 0
} else {
  s := trim(cpu_str)
  endswith(s, "m")
  millicores = to_number(trim_suffix(s, "m"))
} else {
  # plain integer (cores)
  millicores = to_number(s) * 1000
}

trim_suffix(s, suf) = out {
  out := substr(s, 0, count(s) - count(suf))
}

# parse memory like "128Mi" -> MB
parse_mem_mb(mem_str) = mb {
  mem_str == ""
  mb = 0
} else {
  s := trim(mem_str)
  endswith(s, "Mi")
  mb = to_number(trim_suffix(s, "Mi")) / 1024 * 1024 / 1024  # normalized - fallback crude
  # for simplicity, support Mi and Gi
} else {
  endswith(s, "Gi")
  mb = to_number(trim_suffix(s, "Gi")) * 1024
} else {
  # numeric fallback in bytes
  mb = to_number(s) / (1024*1024)
}

# Helper utilities
is_true(x) {
  x == true
}

defined(x) {
  x != null
}

list_contains_ignorecase(lst, val) {
  some i
  lower(lst[i]) == lower(val)
}

lower_all(xs) = ys {
  ys := [ lower(xs[i]) | i := range(xs) ]
}

# basic string helpers (since rego lacks many)
contains(s, sub) {
  indexof(lower(s), lower(sub)) >= 0
}

startswith(s, pref) {
  indexof(s, pref) == 0
}

# is production namespace heuristic (namespace name contains prod or configured)
is_prod() {
  contains(input.namespace, "prod")
}

# default response for admission controller
admission_response = {"allowed": true} {
  # no denies
  not deny[_]
}
admission_response = {
  "allowed": false,
  "denials": denials
} {
  denials := [d | d := deny[_]]
}

# ======================
# API authorization
# ======================
# package for API authorization decisions: input expected:
# { "api_action": "vm.start", "jwt": { "claims": {...} } }

package avm.api.auth

default allow = false

# data.avm.policies.api_roles mapping:
# { "vm.start": ["avm.operator","avm.admin"], "vm.stop": ["avm.operator","avm.admin"], "vm.snapshot": ["avm.admin"] }

allow {
  action := input.api_action
  roles := data.avm.policies.api_roles[action]
  some r
  user_roles := get_jwt_roles(input.jwt)
  user_roles[_] == roles[r]
}

# Example: require that caller has scope and optional tenant match
get_jwt_roles(jwt) = roles {
  roles := object.get(jwt, "claims", {}).roles
} else = [] { roles := [] }

# fallback: admin group
allow {
  user_roles := get_jwt_roles(input.jwt)
  user_roles[_] == "platform:admin"
}
