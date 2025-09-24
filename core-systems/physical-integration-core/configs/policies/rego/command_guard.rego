package physical_integration_core.command_guard

import future.keywords.if

# ===============================
# Метаданные политики
# ===============================
policy_id := "pic/command_guard"
policy_version := "1.4.0"

# ===============================
# Основной результат для интеграции
# ===============================
# decision — детализированный объект; allow — короткий булев флаг для инлайн-проверок.

default allow := false

decision := {
  "policy_id": policy_id,
  "version": policy_version,
  "allow": allow,
  "breakglass_used": breakglass_valid,
  "required_approvals": required_approvals,
  "impact_level": impact_level,
  "deny_hard": hard_deny_reasons,
  "deny_soft": soft_deny_reasons_effective,
  "deny_reasons": deny_reasons,
}

deny_reasons := {r | hard_deny_reasons[r]} ∪ {r | soft_deny_reasons_effective[r]}

# ===============================
# Управляющая логика allow
# ===============================
# 1) Если «break-glass» валиден — пропускаем только при отсутствии жёстких отказов.
# 2) В обычном режиме — отказов не должно быть вовсе.

allow {
  breakglass_valid
  count(hard_deny_reasons) == 0
} else {
  count(deny_reasons) == 0
}

# ===============================
# Собираем причины отказа
# ===============================

# Жёсткие отказы (не перекрываются break-glass)
hard_deny_reasons[r] {
  not input.authn.cert_valid
  r := "authn: invalid or missing mTLS certificate"
}

hard_deny_reasons[r] {
  is_blacklisted_subject
  r := "authz: subject is blacklisted"
}

hard_deny_reasons[r] {
  freeze_active
  r := "env: global freeze in effect"
}

# Мягкие отказы (могут быть перекрыты валидным break-glass)
soft_deny_reasons[r] {
  write_cmd
  not input.authn.mfa
  r := "authn: mfa required for write/high impact"
}

soft_deny_reasons[r] {
  write_cmd
  not has_role("ot-operator")
  r := "authz: role ot-operator is required for write"
}

soft_deny_reasons[r] {
  high_impact
  required_approvals > count(valid_approvals)
  r := sprintf("governance: %d approvals required (have %d)", [required_approvals, count(valid_approvals)])
}

soft_deny_reasons[r] {
  high_impact
  not maintenance_window_active
  not change_ticket_approved
  r := "governance: maintenance window or approved change ticket is required for high-impact command"
}

soft_deny_reasons[r] {
  sod_violation
  r := "compliance: separation of duties violation (requester cannot approve own command)"
}

soft_deny_reasons[r] {
  high_impact
  session_too_old
  r := "authn: session age exceeds maximum for high-impact commands"
}

soft_deny_reasons[r] {
  rate_exceeded
  r := "safety: rate limit exceeded for this device/command tuple"
}

soft_deny_reasons[r] {
  alarm_blocking
  r := "safety: active alarm prevents command (except reset_alarm)"
}

soft_deny_reasons[r] {
  not command_allowed_by_allowlist
  r := "policy: command not in allowlist for device class/protocol"
}

soft_deny_reasons[r] {
  is_modbus_mass_write_without_permit
  r := "policy: modbus mass-write requires explicit permit and approved change"
}

soft_deny_reasons[r] {
  is_firmware_update
  not has_role("ot-maintainer")
  r := "authz: firmware update requires role ot-maintainer"
}

soft_deny_reasons[r] {
  is_firmware_update
  not change_ticket_approved
  r := "governance: firmware update requires approved change ticket"
}

soft_deny_reasons[r] {
  value_out_of_bounds
  r := sprintf("safety: value %.3f out of bounds [%.3f, %.3f]", [cmd_value, bounds_min, bounds_max])
}

soft_deny_reasons[r] {
  delta_too_large
  r := sprintf("safety: delta %.3f exceeds max allowed %.3f", [abs(cmd_value - expected_next), max_delta])
}

# Эффективные мягкие отказы: при валидном break-glass они игнорируются.
soft_deny_reasons_effective[r] {
  not breakglass_valid
  soft_deny_reasons[r]
}

# ===============================
# Хелперы: входные данные и контекст
# ===============================

# Безопасные дефолты и извлечения
env := input.env.environment
impact_level := lower(input.request.impact_level)  # "low"|"medium"|"high"|"critical"
protocol := lower(input.request.channel.protocol)
command := lower(input.request.command)

# Значение команды (если применимо)
cmd_value := v {
  v := input.request.args.value
} else := 0

# Цифровой близнец: границы и ожидаемое значение
bounds_min := m { m := input.context.digital_twin.min } else := 0
bounds_max := m { m := input.context.digital_twin.max } else := 100
expected_next := e { e := input.context.digital_twin.expected_next } else := cmd_value

# Максимально допустимая дельта: либо из data, либо 10% диапазона
max_delta := md {
  md := data.command_guard.tuning.max_delta
} else := (bounds_max - bounds_min) * 0.10

# Freeze‑флаг из внешней конфигурации
freeze_active := f {
  f := data.command_guard.freeze.active
} else := false

# Maintenance‑окно: либо из входа, либо из внешних данных
maintenance_window_active := mw {
  mw := input.context.maintenance_window.active
} else := mw2 {
  mw2 := data.command_guard.maintenance.active
} else := false

# RBAC
has_role(r) {
  some i
  input.authz.roles[i] == r
}

# Валидные approvals (distinct по субъекту, с ролью одобряющего)
valid_approvals[a] {
  some i
  a := input.authz.approvals[i]
  a.role == "ot-approver"
  a.by != input.authn.subject
}

# Разделение обязанностей (SoD): запрет self‑approve
sod_violation {
  some i
  appr := input.authz.approvals[i]
  appr.by == input.authn.subject
}

# Требуемое число одобрений в зависимости от риска/окружения
required_approvals := n {
  high_impact
  env == "prod"
  n := 2
} else := n {
  high_impact
  n := 1
} else := 0

# Уровень воздействия
high_impact {
  impact_level == "high"
} else {
  impact_level == "critical"
} else {
  is_firmware_update
} else {
  command == "mode_change"
} else {
  command == "setpoint_write"  # трактуем как повышенный риск
}

# Запись?
write_cmd {
  command == "write_coil"
} else {
  command == "write_register"
} else {
  command == "setpoint_write"
} else {
  command == "firmware_update"
} else {
  input.request.command_type == "write"
}

# Фирмварь
is_firmware_update {
  command == "firmware_update"
} else {
  command == "fw_update"
} else {
  command == "upgrade_firmware"
}

# Возраст сессии: для high‑impact ограничим, например, 8 часов
session_too_old {
  high_impact
  age := input.authn.session_age_seconds
  age > max_age
}
max_age := ma {
  ma := data.command_guard.authn.max_session_age_seconds_high
} else := 28800  # 8 часов по умолчанию

# Rate‑limit (вход должен приносить факт превышения или счётчики)
rate_exceeded {
  input.context.rate.exceeded == true
} else {
  pm := input.context.rate.per_minute
  lim := rate_limit_per_minute
  pm > lim
}
rate_limit_per_minute := lim {
  lim := data.command_guard.safety.rate_limit_per_minute
} else := 60

# Аварии/интерлоки
alarm_blocking {
  input.context.device_state.alarm_active == true
  command != "reset_alarm"
}

# Allowlist команд по device class и протоколу
device_class := dc { dc := lower(input.request.device.class) } else := "generic"

command_allowed_by_allowlist {
  allowed := allowed_commands_for(device_class, protocol)
  allowed[_] == command
}

# Возвращает разрешённый список команд для класса/протокола (из data или дефолт)
allowed_commands_for(dc, proto) = cmds {
  # Сначала смотрим в data (bundle/ConfigMap и т.п.)
  cmds := data.command_guard.allowlist[dc][proto]
} else = cmds {
  # Дефолты (безопасные)
  proto == "modbus_tcp"
  cmds := {"read_registers", "write_register", "read_coils", "write_coil", "reset_alarm", "setpoint_write"}
} else = cmds {
  proto == "opcua"
  cmds := {"read", "write", "reset_alarm", "mode_change", "setpoint_write"}
} else = cmds {
  proto == "mqtt"
  cmds := {"publish_status", "publish_telemetry", "reset_alarm"}
} else = {"reset_alarm"}  # минимальный дефолт

# Modbus: массовые записи требуют явного разрешения и approved ticket
is_modbus_mass_write_without_permit {
  protocol == "modbus_tcp"
  c := input.request.args.count
  c > mass_write_limit
  not mass_write_permitted
}
mass_write_limit := lim {
  lim := data.command_guard.policy.modbus.max_multi_write_count
} else := 16

mass_write_permitted {
  input.request.args.mass_write == true
  change_ticket_approved
}

# Change‑ticket (вход или внешние данные)
change_ticket_approved {
  t := input.authz.ticket
  t.status == "Approved"
} else {
  t := data.command_guard.change_ticket
  t.status == "Approved"
}

# Break‑glass: допускаем, если включён, не просрочен, есть тикет, и команда не из перечня «жёстко запрещённых»
breakglass_valid {
  bg := input.authz.breakglass
  bg.enabled == true
  not breakglass_expired
  bg.ticket != ""
  not is_firmware_update  # пример жёсткого запрета под break-glass
}

breakglass_expired {
  bg := input.authz.breakglass
  exp := time.parse_rfc3339_ns(bg.expires_at)
  now := time.parse_rfc3339_ns(input.env.time)
  now > exp
}

# Чёрный список субъектов/агентов
is_blacklisted_subject {
  bl := data.command_guard.authz.blacklist
  bl[_] == input.authn.subject
}

# Значение в границах цифрового близнеца
value_out_of_bounds {
  has_numeric_value
  (cmd_value < bounds_min) or (cmd_value > bounds_max)
}

delta_too_large {
  has_numeric_value
  abs(cmd_value - expected_next) > max_delta
}

has_numeric_value {
  t := type_name(cmd_value)
  t == "number"
}

# Жёсткие отказы — соберём в множество
hard_deny_reasons := {r | hard_deny_reasons[r]}
soft_deny_reasons := {r | soft_deny_reasons[r]}

# ===============================
# Утилиты
# ===============================
lower(s) := out {
  out := to_lower(s)
}

# ===============================
# Пример дефолтной конфигурации через data (необязательно)
# Для продакшна задаётся во внешнем bundle/ConfigMap.
# ===============================
default data.command_guard := {
  "authn": {
    "max_session_age_seconds_high": 28800
  },
  "safety": {
    "rate_limit_per_minute": 60
  },
  "policy": {
    "modbus": {
      "max_multi_write_count": 16
    }
  },
  "tuning": {
    "max_delta": 0  # 0 означает: используем 10% от диапазона
  },
  "freeze": {
    "active": false
  },
  "maintenance": {
    "active": false
  },
  "authz": {
    "blacklist": []
  },
  "allowlist": {
    "generic": {
      "modbus_tcp": ["read_registers","write_register","read_coils","write_coil","reset_alarm","setpoint_write"],
      "opcua": ["read","write","reset_alarm","mode_change","setpoint_write"],
      "mqtt": ["publish_status","publish_telemetry","reset_alarm"]
    }
  }
}
