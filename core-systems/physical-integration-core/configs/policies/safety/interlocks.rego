# physical-integration-core/configs/policies/safety/interlocks.rego
package physical_integration_core.policies.safety.interlocks

################################################################################
# Helpers: safe defaults and accessors (override via data.safety.*)
################################################################################

# Environment thresholds (critical and reset/hysteresis)
temp_limit_c := v { v := data.safety.thresholds.env.temperature.limit_c } else { v := 85 }
temp_reset_c := v { v := data.safety.thresholds.env.temperature.reset_c } else { v := 80 }
temp_roc_crit_c_per_min := v { v := data.safety.thresholds.env.temperature.roc_crit_c_per_min } else { v := 10 }

pressure_limit_bar := v { v := data.safety.thresholds.env.pressure.limit_bar } else { v := 12 }
pressure_reset_bar := v { v := data.safety.thresholds.env.pressure.reset_bar } else { v := 11 }

gas_limit_ppm := v { v := data.safety.thresholds.env.gas.limit_ppm } else { v := 400 }

vibration_limit_mm_s := v { v := data.safety.thresholds.env.vibration.limit_mm_s } else { v := 18 }

voltage_min_v := v { v := data.safety.thresholds.power.voltage_min_v } else { v := 180 }

speed_limit_rpm := v { v := data.safety.thresholds.motion.speed_limit_rpm } else { v := 30 }

# Operational limits / timeouts
max_heartbeat_age_s := v { v := data.safety.timeouts.max_heartbeat_age_s } else { v := 5 }
cooldown_start_s    := v { v := data.safety.timeouts.cooldown_start_s }    else { v := 300 }
selftest_max_age_h  := v { v := data.safety.timeouts.selftest_max_age_h }  else { v := 24 }

# Redundancy requirements
ups_min_required := v { v := data.safety.power.ups_min_required } else { v := 1 }

# Two-person rule for maintenance overrides (duration is validated by timestamp)
maint_min_approvers := v { v := data.safety.maintenance.min_approvers } else { v := 2 }

# Non-bypassable (even in maintenance) violation codes
non_bypassable := {"E-STOP", "GAS-LEAK", "OVERPRESSURE-CRIT", "OVERTEMP-CRIT", "DOOR-OPEN-MOTION", "GUARD-UNLOCKED", "COMMS-LOST", "ATTESTATION-FAIL"}

################################################################################
# Input normalization
################################################################################

action := a { a := input.action } else { a := "run" }

now_ns := n { n := time.parse_rfc3339_ns(input.time) } else { n := time.now_ns() }

heartbeat_age_s := s { s := input.states.heartbeat_age_s } else { s := 1e9 }

roc_temp_c_per_min := r { r := input.metrics.roc.temperature_c_per_min } else { r := 0 }

avg_speed_rpm := a {
  a := avg(input.sensors.speed_rpm)
} else { a := 0 }

# Booleans/arrays may be absent; treat missing as empty/false
doors_closed := a { a := input.sensors.door_closed } else { a := [] }
guards_locked := a { a := input.sensors.guard_locked } else { a := [] }
estops := a { a := input.sensors.estop } else { a := [] }
ups_ok := a { a := input.power.ups_ok } else { a := [] }

attestation_ok := b { b := input.states.attestation_ok } else { b := true }

env_temp_c := t { t := input.env.temperature_c } else { t := 0 }
env_pressure_bar := p { p := input.env.pressure_bar } else { p := 0 }
env_gas_ppm := g { g := input.env.gas_ppm } else { g := 0 }
vibration_mm_s := v { v := avg(input.sensors.vibration_mm_s) } else { v := 0 }
min_voltage_v := v { v := min_num(input.sensors.voltage_v) } else { v := 230 }

last_alarm_cleared_ns := n {
  n := time.parse_rfc3339_ns(input.states.last_alarm_cleared_at)
} else { n := 0 }

last_selftest_ok_ns := n {
  n := time.parse_rfc3339_ns(input.states.last_self_test_ok)
} else { n := 0 }

# Helpers
avg(arr) = a {
  c := count(arr)
  c > 0
  a := sum(arr) / c
} else = a { a := 0 }

min_num(arr) = m {
  some i
  m := arr[i]
  not less_exists(arr, m)
} else = m { m := 1e9 }

less_exists(arr, m) {
  some i
  arr[i] < m
}

count_true(arr) = n {
  ns := [1 | some i; arr[i]]
  n := count(ns)
}

all_true(arr) {
  not some i
  arr[i] == false
}

n_of_m_ok(arr, n) {
  count_true(arr) >= n
}

seconds_since(ts_ns) = s {
  s := (now_ns - ts_ns) / 1000000000
}

################################################################################
# Maintenance override (soft violations only)
################################################################################

maintenance_requested {
  input.maintenance.requested
}

maintenance_approved {
  maintenance_requested
  count(input.maintenance.approvers) >= maint_min_approvers
  # Approve until future
  exp_ns := time.parse_rfc3339_ns(input.maintenance.approved_until)
  now_ns < exp_ns
}

can_bypass(v) {
  maintenance_approved
  not non_bypassable[v.code]
  v.severity <= 3
}

################################################################################
# Violations (build as set of objects)
################################################################################

# Helper to build a violation object
make_violation(code, severity, message, subsystem) = v {
  v := {
    "code": code,
    "severity": severity,   # 1=info,2=low,3=medium,4=high,5=critical
    "message": message,
    "subsystem": subsystem,
  }
}

# E-STOP pressed (any)
violation[v] {
  some i
  estops[i]
  v := make_violation("E-STOP", 5, "Emergency stop circuit active", "safety")
}

# Communication lost / heartbeat stale
violation[v] {
  heartbeat_age_s > max_heartbeat_age_s
  v := make_violation("COMMS-LOST", 5, sprintf("Control heartbeat stale: %vs > %vs", [heartbeat_age_s, max_heartbeat_age_s]), "control")
}

# Guards/doors integrity while moving
violation[v] {
  avg_speed_rpm > 0
  not n_of_m_ok(doors_closed, 2)  # require 2ooN (>=2 closed)
  v := make_violation("DOOR-OPEN-MOTION", 5, "Motion detected with doors not safely closed (2ooN failed)", "mechanical")
}

violation[v] {
  avg_speed_rpm > 0
  not all_true(guards_locked)
  v := make_violation("GUARD-UNLOCKED", 5, "Motion detected with safety guards unlocked", "mechanical")
}

# Overtemperature (critical)
violation[v] {
  env_temp_c >= temp_limit_c
  v := make_violation("OVERTEMP-CRIT", 5, sprintf("Overtemperature: %.1fC >= %.1fC", [env_temp_c, temp_limit_c]), "environment")
}

# Temperature rate-of-change (runaway reaction)
violation[v] {
  roc_temp_c_per_min >= temp_roc_crit_c_per_min
  v := make_violation("OVERTEMP-ROC", 5, sprintf("Temperature rising too fast: %.1f C/min >= %.1f C/min", [roc_temp_c_per_min, temp_roc_crit_c_per_min]), "environment")
}

# Overpressure (critical)
violation[v] {
  env_pressure_bar >= pressure_limit_bar
  v := make_violation("OVERPRESSURE-CRIT", 5, sprintf("Overpressure: %.2f bar >= %.2f bar", [env_pressure_bar, pressure_limit_bar]), "environment")
}

# Gas leak (critical)
violation[v] {
  env_gas_ppm >= gas_limit_ppm
  v := make_violation("GAS-LEAK", 5, sprintf("Gas concentration high: %d ppm >= %d ppm", [env_gas_ppm, gas_limit_ppm]), "environment")
}

# Excessive vibration (high)
violation[v] {
  vibration_mm_s > vibration_limit_mm_s
  v := make_violation("VIBRATION-HIGH", 4, sprintf("Vibration %.1f mm/s > %.1f mm/s", [vibration_mm_s, vibration_limit_mm_s]), "mechanical")
}

# Undervoltage (high)
violation[v] {
  min_voltage_v < voltage_min_v
  v := make_violation("UNDERVOLTAGE", 4, sprintf("Supply undervoltage: %.0fV < %.0fV", [min_voltage_v, voltage_min_v]), "power")
}

# Power redundancy lost (high): require N UPS OK
violation[v] {
  count_true(ups_ok) < ups_min_required
  v := make_violation("POWER-REDUNDANCY-LOST", 4, sprintf("UPS OK %d < required %d", [count_true(ups_ok), ups_min_required]), "power")
}

# Attestation / secure boot (critical)
violation[v] {
  not attestation_ok
  v := make_violation("ATTESTATION-FAIL", 5, "Platform attestation or secure boot failed", "security")
}

# Restart cooldown after alarms (medium)
violation[v] {
  action == "start"; seconds_since(last_alarm_cleared_ns) < cooldown_start_s
  v := make_violation("COOLDOWN-NOT-ELAPSED", 3, sprintf("Start cooldown not elapsed: %vs < %vs", [seconds_since(last_alarm_cleared_ns), cooldown_start_s]), "process")
}
violation[v] {
  action == "resume"; seconds_since(last_alarm_cleared_ns) < cooldown_start_s
  v := make_violation("COOLDOWN-NOT-ELAPSED", 3, sprintf("Resume cooldown not elapsed: %vs < %vs", [seconds_since(last_alarm_cleared_ns), cooldown_start_s]), "process")
}

# Latch / hysteresis for start/resume (medium)
violation[v] {
  (action == "start" or action == "resume")
  env_temp_c > temp_reset_c
  v := make_violation("TEMP-NOT-RESET", 3, sprintf("Temperature above reset threshold: %.1fC > %.1fC", [env_temp_c, temp_reset_c]), "environment")
}
violation[v] {
  (action == "start" or action == "resume")
  env_pressure_bar > pressure_reset_bar
  v := make_violation("PRESSURE-NOT-RESET", 3, sprintf("Pressure above reset threshold: %.2f bar > %.2f bar", [env_pressure_bar, pressure_reset_bar]), "environment")
}

# Self-test overdue (medium)
violation[v] {
  seconds_since(last_selftest_ok_ns) > selftest_max_age_h * 3600
  v := make_violation("SELFTEST-OVERDUE", 3, sprintf("Self-test older than %dh", [selftest_max_age_h]), "maintenance")
}

# Overspeed (high)
violation[v] {
  avg_speed_rpm > speed_limit_rpm
  v := make_violation("SPEED-LIMIT", 4, sprintf("Speed %.0f rpm > limit %.0f rpm", [avg_speed_rpm, speed_limit_rpm]), "mechanical")
}

################################################################################
# Effective deny list with maintenance bypass for soft issues
################################################################################

deny_all[v] { violation[v] }

deny[v] {
  deny_all[v]
  not can_bypass(v)
}

# Severity helpers
critical_violation {
  some v
  deny[v]
  v.severity >= 4
}

medium_violation {
  some v
  deny[v]
  v.severity == 3
}

################################################################################
# Final decision and outputs
################################################################################

default allow = false

# Run/Start/Resume require zero effective denies
allow {
  (action == "run"  or action == "start" or action == "resume")
  count([v | deny[v]]) == 0
}

# Maintenance: allow if no critical denies (soft ones allowed for safe operations)
allow {
  action == "maintenance"
  not critical_violation
}

# Shutdown is always allowed by policy perspective
allow {
  action == "shutdown"
}

# Safe mode is suggested when there are medium‑severity issues (degradation)
safe_mode {
  medium_violation
}

# Rich verdict object for callers
verdict := {
  "allow": allow,
  "safe_mode": safe_mode,
  "action": action,
  "deny": [v | deny[v]],     # list of violation objects
}
