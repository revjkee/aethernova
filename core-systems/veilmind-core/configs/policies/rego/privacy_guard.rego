package veilmind.privacy.guard.v1

# Версия политики
version := "1.0.0"

# Главный выход: структурированное решение для приложения.
# Пример интеграции: OPA response -> сервис применяет mask_fields и уважает obligations.
decision := {
  "version": version,
  "allow": allow,
  "deny_reasons": deny_reasons,
  "mask_fields": mask_fields,
  "obligations": obligations,
}

default allow = false

################################################################################
# Вспомогательные чтения конфигурации (data.privacy.guard.*)
################################################################################

# Безопасные дефолты, если конфиг не задан.
default cfg_purpose_by_role := {}
default cfg_roles := {}
default cfg_field_classes := {}
default cfg_consent_required := {"read": [], "write": ["spi", "health"], "export": ["pii", "spi", "health"], "delete": []}
default cfg_regions := {
  "adequacy_list": ["EEA", "CH", "UK"],
  "export_allowed_pairs": [ {"from": "EEA", "to": "US", "mechanism": "scc"} ]
}
default cfg_masking := { "on_read": ["pii", "spi", "health"] }
default cfg_retention_days := {"profile": 365, "payment": 1825, "audit": 2555}

cfg_purpose_by_role := data.privacy.guard.allowed_purposes_by_role
cfg_roles := data.privacy.guard.roles                  # {role: {allow: {resource_types:[], actions:[]}, pii_read_whitelist: bool}}
cfg_field_classes := data.privacy.guard.field_classification  # {resource_type: {field: "pii|spi|health|pd"}}
cfg_consent_required := data.privacy.guard.consent_required_actions
cfg_regions := data.privacy.guard.region_rules
cfg_masking := data.privacy.guard.masking
cfg_retention_days := data.privacy.guard.retention_days

################################################################################
# Предикаты
################################################################################

user := input.user
req  := input.request
res  := input.resource
act  := input.action
purp := input.purpose
cons := input.consent

# 1) Изоляция тенанта
violation_tenant["tenant_mismatch"] {
  res.tenant_id != user.tenant_id
}

# 2) RBAC/ABAC на тип ресурса и действие
violation_role["role_not_permitted"] {
  not role_permits_action(user.roles, res.type, act)
}

role_permits_action(roles, resource_type, action) {
  some r
  roles[_] == r
  allow_role_action(r, resource_type, action)
}

allow_role_action(role, resource_type, action) {
  cfg := cfg_roles[role]
  cfg.allow.resource_types[_] == resource_type
  cfg.allow.actions[_] == action
}

# 3) Привязка к цели обработки (purpose binding)
violation_purpose["purpose_not_allowed_for_role"] {
  some r
  user.roles[_] == r
  not purpose_allowed_for_role(r, purp)
}

purpose_allowed_for_role(role, purpose) {
  allowed := cfg_purpose_by_role[role]
  allowed[_] == purpose
}

# Специальные ограничения: пример — analytics нельзя для SPI без агрегирования
violation_purpose["analytics_on_spi_requires_masking"] {
  purp == "analytics"
  contains_class(res, ["spi", "health"])
  not input.attributes.aggregated
}

# 4) Согласие субъекта данных (для операций и классов данных)
violation_consent["consent_required_absent"] {
  required_classes_for_action(act)[_] == klass
  contains_class(res, [klass])
  not cons.given
}

required_classes_for_action(a) := cls {
  cls := cfg_consent_required[a]
}

# 5) Региональные правила трансграничной передачи
# Пример: если субъект из EEA, а запрос уходит в страну без адекватности и без механизма — запрет.
violation_region["cross_border_restricted"] {
  subj_region := subject_region()
  req_region := request_region()
  subj_region == "EEA"
  not export_pair_allowed(subj_region, req_region, input.attributes.transfer_mechanism)
}

subject_region() := r {
  r := user.attributes.region
} else := r {
  r := req.country
}

request_region() := r {
  r := req.country
}

export_pair_allowed(from, to, mech) {
  some p
  cfg_regions.export_allowed_pairs[p] == {"from": from, "to": to, "mechanism": mech}
} else {
  cfg_regions.adequacy_list[_] == to
}

# 6) Break-glass (аварийное снятие ограничений) — только с обоснованием и аудитом
break_glass_enabled {
  input.break_glass.enabled
  input.break_glass.justification != ""
  input.break_glass.ticket =~ /^[A-Z]+-\d+$/
}

violation_breakglass["break_glass_missing_justification"] {
  input.break_glass.enabled
  not break_glass_enabled
}

# 7) DLP: поиск запрещенных PII/SPI по типу ресурса и значению полей
violation_dlp[reason] {
  act == "write" or act == "export"
  fc := cfg_field_classes[res.type]
  some k, v
  v := res.fields[k]
  klass := fc[k]
  klass == "spi"  # для примера — запрещаем запись/export явных SPI полей без явного разрешения
  not input.attributes.spi_write_allowed
  reason := sprintf("spi_write_forbidden:%s", [k])
}

################################################################################
# Маскировка при чтении
################################################################################

mask_fields := fields {
  act == "read"
  needs_masking
  fields := fields_to_mask()
} else := [] {
  not (act == "read" and needs_masking)
}

needs_masking {
  not pii_whitelisted_role()
}

pii_whitelisted_role() {
  some r
  user.roles[_] == r
  cfg_roles[r].pii_read_whitelist == true
}

fields_to_mask()[f] {
  fc := cfg_field_classes[res.type]
  some k, klass
  klass := fc[k]
  klass_in_mask(klass)
  f := sprintf("%s.%s", [res.type, k])
}

klass_in_mask(klass) {
  cfg_masking.on_read[_] == klass
}

################################################################################
# Причины отказа и итоговое allow
################################################################################

deny_reasons := rs {
  base := array.concat(
    array.concat(
      object_keys(violation_tenant),
      object_keys(violation_role),
    ),
    array.concat(
      object_keys(violation_purpose),
      array.concat(object_keys(violation_consent), array.concat(object_keys(violation_region), object_keys(violation_breakglass)))
    ),
  )
  rs := array.concat(base, violation_dlp)
}

allow {
  count(deny_reasons) == 0
} else {
  break_glass_enabled
  # При break-glass разрешаем, но оставляем причины в audit и включаем обязательства
}

################################################################################
# Обязательства (обязанности для потребителя решения)
################################################################################

obligations := {
  "audit": true,
  "audit_tags": audit_tags,
  "retention_days": retention_days,
  "legal_basis": legal_basis,
  "duty_to_inform": duty_to_inform,
}

audit_tags := {
  "tenant_id": res.tenant_id,
  "user_id": user.id,
  "action": act,
  "resource_type": res.type,
  "purpose": purp,
  "break_glass": break_glass_enabled,
  "deny_reasons": deny_reasons,
}

retention_days := d {
  some d0
  d0 := cfg_retention_days[res.type]
  d := d0
} else := d {
  d := 365
}

# Упрощенное правовое основание: если есть согласие — consent; иначе legitimate_interest для security|fraud; иначе contract для billing.
legal_basis := b {
  cons.given
  b := "consent"
} else := b {
  purp == "security" or purp == "fraud_prevention"
  b := "legitimate_interest"
} else := b {
  purp == "billing"
  b := "contract"
} else := "unknown"

duty_to_inform := x {
  cons.given
  x := false
} else := true

################################################################################
# Утилиты
################################################################################

# Возвращает массив ключей объекта как список строк
object_keys(obj) := ks {
  ks := [k | k := object.get(obj, _, null); k != null]
}

# Проверяет, содержит ли ресурс поля указанного класса
contains_class(rsrc, classes) {
  fc := cfg_field_classes[rsrc.type]
  some k
  c := fc[k]
  classes[_] == c
}
