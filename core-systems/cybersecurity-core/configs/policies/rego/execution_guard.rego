package cybersecurity_core.policies.execution_guard

# Optional: enable future keywords if your OPA is configured accordingly
# import future.keywords.in

###############################################################################
# Policy metadata
###############################################################################

policy_meta := {
  "id": "execution_guard",
  "version": "1.2.0",
  "owner": "secops@your-org.example",
  "description": "Industrial execution guard for processes and containers"
}

###############################################################################
# Entry points
###############################################################################

# Final decision object
decision := {
  "allow": allow,
  "violations": [v | v := violation[_]],
  "policy": policy_meta
}

# Allow when there are no violations or breakglass is active
allow {
  not final_deny
}

final_deny {
  not breakglass
  count(violation) > 0
}

# Breakglass: emergency override with strict scoping
breakglass {
  input.annotations.breakglass == true
  some actor
  actor := input.actor
  actor != ""
  actor in breakglass_actors
}

# Authorized breakglass principals (can be overridden via data.execution_guard.breakglass_actors)
breakglass_actors := s {
  s := { x | x := data.execution_guard.breakglass_actors[_] }
} else = {"secops_oncall", "ir_lead"}

###############################################################################
# Configuration with safe defaults (can be overridden via data.execution_guard.*)
###############################################################################

# Allowed container registries
allowed_registries := s {
  s := { x | x := data.execution_guard.allowed_registries[_] }
} else = {"ghcr.io", "gcr.io", "registry-1.docker.io", "quay.io"}

# Allowed image label keys that MUST be present
required_image_labels := s {
  s := { x | x := data.execution_guard.required_image_labels[_] }
} else = {"org.opencontainers.image.source", "org.opencontainers.image.revision"}

# Enforce image signature (cosign/notary) if true
enforce_image_signature := b {
  b := data.execution_guard.enforce_image_signature
} else = true

# Mutable/development tag patterns to block
mutable_tag_patterns := s {
  s := { x | x := data.execution_guard.mutable_tag_patterns[_] }
} else = {"^latest$", "-latest$", "-dev$", "-snapshot$", "-rc\\d*$", "^main$", "^master$"}

# Allowed capabilities (empty set -> no extra caps allowed)
allowed_caps := s {
  s := { upper(x) | x := data.execution_guard.allowed_caps[_] }
} else = {}

# Minimal required hardening for containers
require_seccomp_runtime_default := b {
  b := data.execution_guard.require_seccomp_runtime_default
} else = true

require_apparmor_runtime_default := b {
  b := data.execution_guard.require_apparmor_runtime_default
} else = true

require_no_privileged := b {
  b := data.execution_guard.require_no_privileged
} else = true

require_no_priv_escalation := b {
  b := data.execution_guard.require_no_priv_escalation
} else = true

require_readonly_rootfs := b {
  b := data.execution_guard.require_readonly_rootfs
} else = true

# Forbidden interpreters and suspicious flags
blocked_interpreters := s {
  s := { x | x := data.execution_guard.blocked_interpreters[_] }
} else = {"/usr/bin/python2", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "bash", "sh"}

suspicious_flags := s {
  s := { x | x := data.execution_guard.suspicious_flags[_] }
} else = {"-EncodedCommand", "-enc", "-e", "-Command", "-c"}

# Forbidden execution paths (world-writable, temp, downloads)
forbidden_paths := s {
  s := { x | x := data.execution_guard.forbidden_paths[_] }
} else = {"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "C:\\Windows\\Temp\\", "C:\\Users\\", "C:\\ProgramData\\Temp\\"}

# Allowed roots for system binaries (if executed from here, relax some checks)
system_bin_roots := s {
  s := { x | x := data.execution_guard.system_bin_roots[_] }
} else = {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\"}

# Denied hashes (known bad)
blocked_hashes := s {
  s := { lower(x) | x := data.execution_guard.blocked_hashes[_] }
} else = {}

# Require root only for these binaries (others must not run with euid==0)
root_required_binaries := s {
  s := { x | x := data.execution_guard.root_required_binaries[_] }
} else = {"/usr/sbin/tcpdump", "/usr/sbin/setcap", "/usr/bin/chown", "C:\\Windows\\System32\\wevtutil.exe"}

# Network egress policy
deny_egress_cidrs := s {
  s := { x | x := data.execution_guard.deny_egress_cidrs[_] }
} else = {"0.0.0.0/0"}  # block direct internet unless explicitly allowed by higher-level network controls

deny_egress_ports := p {
  p := { n | n := to_number(data.execution_guard.deny_egress_ports[_]) }
} else = {23, 25, 135, 137, 138, 139, 445}

# High-entropy / obfuscation threshold for cmdline token
entropy_threshold := n {
  n := to_number(data.execution_guard.entropy_threshold)
} else = 4.2

###############################################################################
# Violations collected into 'violation' set
###############################################################################

# Container image must be from allowed registry and not use mutable/dev tags; must be signature-verified
violation[v] {
  input.container.image != ""
  some reg, tag
  reg := image_registry(input.container.image)
  tag := image_tag(input.container.image)
  not reg in allowed_registries
  v := msg("container.image.registry_not_allowed", sprintf("Image registry '%s' not in allowlist", [reg]), "high")
}

violation[v] {
  input.container.image != ""
  tag := image_tag(input.container.image)
  is_mutable_tag(tag)
  v := msg("container.image.mutable_tag", sprintf("Mutable or dev tag '%s' is not allowed", [tag]), "medium")
}

violation[v] {
  input.container.image != ""
  enforce_image_signature
  not is_true(input.container.image_signature_verified)
  v := msg("container.image.signature_required", "Image signature verification is required", "high")
}

# Container hardening checks
violation[v] {
  require_no_privileged
  is_true(input.container.privileged)
  v := msg("container.privileged_forbidden", "Privileged containers are forbidden", "critical")
}

violation[v] {
  require_no_priv_escalation
  is_true(input.container.allow_privilege_escalation)
  v := msg("container.allow_privilege_escalation_forbidden", "Privilege escalation is forbidden", "high")
}

violation[v] {
  require_readonly_rootfs
  not is_true(input.container.readonly_rootfs)
  v := msg("container.readonly_rootfs_required", "Read-only root filesystem is required", "medium")
}

violation[v] {
  require_seccomp_runtime_default
  not has_value(input.container.seccomp_profile, "runtime/default")
  v := msg("container.seccomp_required", "Seccomp profile 'runtime/default' is required", "high")
}

violation[v] {
  require_apparmor_runtime_default
  not has_value(input.container.apparmor_profile, "runtime/default")
  v := msg("container.apparmor_required", "AppArmor profile 'runtime/default' is required", "medium")
}

violation[v] {
  input.container.cap_add[_] = cap
  not upper(cap) in allowed_caps
  v := msg("container.capability_not_allowed", sprintf("Capability '%s' is not allowed", [cap]), "medium")
}

# Required image labels
violation[v] {
  input.container.image != ""
  some k
  k := required_image_labels[_]
  not input.container.labels[k]
  v := msg("container.image.label_missing", sprintf("Required image label '%s' is missing", [k]), "low")
}

# Process execution path restrictions
violation[v] {
  p := normalized_path(input.process.executable)
  is_forbidden_path(p)
  not startswith_any(p, system_bin_roots)
  v := msg("process.path.forbidden", sprintf("Execution from forbidden path '%s'", [p]), "high")
}

# Root misuse (process runs as euid 0 while not required)
violation[v] {
  input.user.euid == 0
  p := normalized_path(input.process.executable)
  not p in root_required_binaries
  v := msg("process.root.misuse", sprintf("Execution as root for '%s' is not allowed", [p]), "high")
}

# Block known bad hashes
violation[v] {
  some h
  h := lower(input.process.hashes.sha256)
  h != ""
  h in blocked_hashes
  v := msg("process.hash.blocked", sprintf("SHA256 '%s' is blocked", [h]), "critical")
}

# Block dangerous interpreters or suspicious flags/encodings
violation[v] {
  p := filename(input.process.executable)
  p_lower := lower(p)
  any_in_set(p_lower, to_lower_set(blocked_interpreters))
  v := msg("process.interpreter.blocked", sprintf("Interpreter '%s' is blocked", [p]), "high")
}

violation[v] {
  some a
  a := input.process.args[_]
  any_in_set(a, suspicious_flags)
  v := msg("process.args.suspicious", sprintf("Suspicious flag detected: '%s'", [a]), "medium")
}

# Suspicious PowerShell encoding or base64-like blobs in command line
violation[v] {
  p := lower(filename(input.process.executable))
  p == "powershell.exe" or p == "pwsh.exe"
  re_match("(?i)(-enc|-encodedcommand)", join(" ", input.process.args))
  v := msg("process.powershell.encoded", "Encoded PowerShell command detected", "high")
}

violation[v] {
  high_entropy_token_in_cmdline
  v := msg("process.cmdline.high_entropy", "High-entropy token in command line (possible obfuscation)", "medium")
}

# Parent-child suspicious chains (e.g., mshta/rundll32/wscript)
violation[v] {
  pc := lower(filename(input.parent.executable))
  c  := lower(filename(input.process.executable))
  pc in {"wscript.exe","cscript.exe","mshta.exe","rundll32.exe"}
  v := msg("process.parent_child.suspicious", sprintf("Suspicious parent '%s' spawning '%s'", [pc, c]), "high")
}

# Network egress restrictions
violation[v] {
  some dst
  dst := input.requested_network.egress[_]
  dst.port != null
  to_number(dst.port) in deny_egress_ports
  v := msg("egress.port.denied", sprintf("Egress to port %v is denied", [dst.port]), "medium")
}

violation[v] {
  some dst
  dst := input.requested_network.egress[_]
  ip := coalesce(dst.ip, "")
  ip != ""
  cidr := deny_egress_cidrs[_]
  net.cidr_contains(cidr, ip)
  v := msg("egress.cidr.denied", sprintf("Egress to '%s' matches denied CIDR '%s'", [ip, cidr]), "high")
}

###############################################################################
# Helper predicates and functions
###############################################################################

# Build a violation object
msg(code, text, sev) := {
  "code": code,
  "message": text,
  "severity": sev
}

# Returns true if 'x' is truthy boolean
is_true(x) {
  x == true
}

# Normalize path to consistent form (lowercase on Windows)
normalized_path(p) := out {
  out := p
} else := out {
  # fallback
  out := p
}

# Filename from path
filename(p) := out {
  parts := split(p, "/")
  out := parts[count(parts)-1]
} else := out {
  parts := split(p, "\\")
  out := parts[count(parts)-1]
}

# Lower-case string
lower(s) := x {
  x := lower_ascii(s)
}

# Upper-case string
upper(s) := x {
  x := upper_ascii(s)
}

# Any arg is in set
any_in_set(x, s) {
  x in s
}

# Convert a set of strings to lower-case set
to_lower_set(s) := out {
  out := { lower(x) | x := s[_] }
}

# Startswith for any prefix in a set
startswith_any(s, prefixes) {
  some p
  p := prefixes[_]
  startswith(s, p)
}

# Check if path is under forbidden paths
is_forbidden_path(p) {
  startswith_any(p, forbidden_paths)
}

# Get image registry from 'registry/namespace/repo:tag@digest'
image_registry(img) := reg {
  parts := split(img, "/")
  len(parts) > 1
  r := parts[0]
  (contains(r, ".") or contains(r, ":"))  # likely a registry
  reg := r
} else := reg {
  # docker hub implicit
  reg := "registry-1.docker.io"
}

# Extract image tag; default empty if digest-only
image_tag(img) := tag {
  # remove @digest
  base := split(img, "@")[0]
  # tag part
  has_colon := contains(base, ":")
  has_colon
  tag := split(base, ":")[count(split(base, ":"))-1]
} else := tag {
  tag := ""
}

# Determine mutable tags by pattern
is_mutable_tag(tag) {
  tag == ""
} else {
  some pat
  pat := mutable_tag_patterns[_]
  re_match(pat, tag)
}

# Safe has_value equality for strings
has_value(x, want) {
  x == want
}

# Coalesce first non-empty string
coalesce(a, b) := out {
  is_string_nonempty(a)
  out := a
} else := out {
  out := b
}

is_string_nonempty(x) {
  x != null
  x != ""
}

# Entropy detector: simple approximation on a token in cmdline
high_entropy_token_in_cmdline {
  tokens := split(join(" ", input.process.args), " ")
  some t
  t := tokens[_]
  len(t) >= 24
  ent := shannon_entropy(t)
  ent >= entropy_threshold
}

# Shannon entropy approximation for ASCII strings
shannon_entropy(s) := e {
  bs := to_bytes(s)
  n := count(bs)
  n > 0
  # frequency map
  freqs := { b: count({ i | bs[i] == b }) | b := bs[_] }
  e := -sum([ (to_number(freqs[k]) / n) * log2(to_number(freqs[k]) / n) | k := keys(freqs)[_] ])
}

# Log base 2
log2(x) := y {
  y := log(x) / log(2)
}

# Convert string to bytes (best-effort)
to_bytes(s) := out {
  out := [ to_number(x) | x := base64.decode(base64.encode(s))[_] ]
} else := out {
  # fallback: ASCII codes
  out := [ to_number(x) | x := sprintf("%v", [s])[_] ]
}

###############################################################################
# Notes:
# - All configurable lists/flags can be overridden via data.execution_guard.*.
# - The policy is designed to be used as 'deny/violation' style. Enforcement
#   should block when decision.allow == false.
# - Input schema is expected to provide:
#   input.process.{executable,args,hashes.sha256}
#   input.parent.{executable}
#   input.user.{euid}
#   input.container.{image,image_signature_verified,privileged,allow_privilege_escalation,readonly_rootfs,seccomp_profile,apparmor_profile,cap_add,labels}
#   input.requested_network.egress = [ {ip, port}, ... ]
#   input.actor, input.annotations.breakglass
###############################################################################
