# path: zero-trust-core/examples/policies/access_policy.rego
package authz

# -----------------------------------------------------------------------------
# Версия политики
# -----------------------------------------------------------------------------
version := "access-policy-v1.0.0"

# -----------------------------------------------------------------------------
# Главное решение: возвращаем объект для совместимости с клиентом
#   POST /v1/data/authz/allow  → {"result": {"allow": bool, "obligations": {...}, "version": "..." }}
# По умолчанию — запрет.
# -----------------------------------------------------------------------------

# Permit ветка: когда выполнены условия permit, вернем объект с allow: true
allow = resp {
  permit
  resp := {
    "allow": true,
    "obligations": obligations(),
    "version": version,
  }
}

# Deny ветка: когда permit не выполняется, вернем причины отказа и version
allow = resp {
  not permit
  resp := {
    "allow": false,
    "obligations": {
      "deny_reasons": deny_reasons(),   # массив строк
      "advice": "zero-trust-default-deny"
    },
    "version": version,
  }
}

# -----------------------------------------------------------------------------
# Высокоуровневое правило разрешения.
# Требования: включена политика, нет kill-switch, действие разрешено ролью,
# контекстные проверки пройдены, MFA выполнен, риск допустим, рабочие часы.
# Альтернатива: break-glass с ограничениями.
# -----------------------------------------------------------------------------
permit {
  policy_enabled
  not kill_switch
  action_allowed_by_role
  tenant_ok
  ip_ok
  device_ok
  risk_ok
  time_ok
  mfa_ok
}

# Разрешение по break-glass (узкий канал; не обходит kill_switch).
# Требует явного флага у субъекта и ограничивает действия.
permit {
  policy_enabled
  not kill_switch
  break_glass
  ip_ok
  device_ok
  # break-glass обязателен MFA, если доступ к конфиденциальным данным
  not (mfa_required and not mfa_ok)
}

# -----------------------------------------------------------------------------
# Настройки политики (могут быть переопределены сервером через input.environment.attributes.*)
# -----------------------------------------------------------------------------
policy_enabled := true
kill_switch := b {
  # Если бекенд прокидывает флаг: input.environment.attributes.kill_switch == true
  b := bool_attr(input.environment.attributes, "kill_switch", false)
}

risk_threshold := t {
  t := number_attr(input.environment.attributes, "risk_threshold", 70)
}

# Список разрешенных сетей для тенанта; если пусто — проверка по IP считается пройденной
tenant_cidrs := cidrs {
  cidrs := array_attr(input.environment.attributes, "ip_allow", [])
}

# Рабочие часы: если enforce_working_hours=false, проверка пропускается
working_hours_enforced := bool_attr(input.environment.attributes, "enforce_working_hours", false)
work_start_h := number_attr(input.environment.attributes, "work_start_h", 8)
work_end_h   := number_attr(input.environment.attributes, "work_end_h", 19)
current_hour := number_attr(input.environment.attributes, "hour", -1)  # если -1, считаем проверку пройденной

# MFA требуется при высоком риске, высокой классификации или для мутаций
mfa_required {
  classification_at_least("confidential")
} else {
  input.action.name != "read"
} else {
  bool_attr(input.resource.attributes, "requires_mfa", false)
}

# MFA считается пройденным, если есть признак mfa=true в среде
# или у субъекта есть свежая отметка mfa_recent_s <= 300
mfa_ok {
  bool_attr(input.environment.attributes, "mfa", false)
} else {
  mr := number_attr(input.subject.attributes, "mfa_recent_s", 0)
  mr > 0
  mr <= 300
}

# -----------------------------------------------------------------------------
# RBAC/ABAC
# -----------------------------------------------------------------------------
# Роли (строка в нижнем регистре)
role := lower(string_attr(input.subject.attributes, "role", ""))

is_admin        { role == "admin" }
is_security_eng { role == "security_engineer" }
is_employee     { role == "employee" }
is_service      { role == "service" }

# Тип ресурса и его классификация
resource_type := lower(input.resource.type)
resource_classification := lower(string_attr(input.resource.attributes, "classification", "public"))

# Ранги классификации для сравнений
classification_rank["public"]       = 0
classification_rank["internal"]     = 1
classification_rank["confidential"] = 2
classification_rank["secret"]       = 3

classification_at_least(level) {
  rl := classification_rank[resource_classification]
  tl := classification_rank[level]
  rl >= tl
}

# Разрешенные по роли действия и уровни
action_allowed_by_role {
  is_admin
}

action_allowed_by_role {
  is_security_eng
  input.action.name == "read" or input.action.name == "update"
  not classification_at_least("secret")
}

action_allowed_by_role {
  is_employee
  input.action.name == "read"
  not classification_at_least("confidential")
}

action_allowed_by_role {
  is_service
  input.action.name == "read" or input.action.name == "write"
  resource_type == "token" or resource_type == "job" or resource_type == "queue"
}

# -----------------------------------------------------------------------------
# Контекстные проверки
# -----------------------------------------------------------------------------
tenant_ok {
  # Тенант задан; пустой разрешается только для тестов
  tid := string_attr(input, "tenant_id", "")
  tid != ""
} else {
  # Разрешаем no-tenant, если явно указан флаг для примеров
  bool_attr(input.environment.attributes, "allow_no_tenant", false)
}

ip_ok {
  # Если список пуст — проверка пройдена
  count(tenant_cidrs) == 0
} else {
  ip := string_attr(input.environment, "ip", "")
  ip != ""
  some i
  cidr := tenant_cidrs[i]
  net.cidr_contains(cidr, ip)
}

device_ok {
  d := object_attr(input.environment.attributes, "device", {})
  # по умолчанию считаем ок, если нет данных о девайсе
  count(keys(d)) == 0
} else {
  d := object_attr(input.environment.attributes, "device", {})
  bool_attr(d, "attested", true)
  not bool_attr(d, "jailbroken", false)
  bool_attr(d, "os_up_to_date", true)
}

risk_ok {
  rs := number_attr(input.environment.attributes, "risk_score", 0)
  rs <= risk_threshold
} else {
  # если риск не указан — допускаем
  not has_key(input.environment.attributes, "risk_score")
}

time_ok {
  not working_hours_enforced
} else {
  h := current_hour
  h == -1     # час не прокинут — пропускаем
} else {
  h := current_hour
  h >= work_start_h
  h <= work_end_h
}

break_glass {
  bool_attr(input.subject.attributes, "break_glass", false)
  # Разрешаем только read/update и только до "confidential"
  input.action.name == "read" or input.action.name == "update"
  not classification_at_least("secret")
}

# -----------------------------------------------------------------------------
# Обязательства для разрешенной операции
# -----------------------------------------------------------------------------
obligations() = obj {
  ttl_map := {"public": 3600, "internal": 1800, "confidential": 900, "secret": 300}
  cls := resource_classification
  ttl := object.get(ttl_map, cls, 900)

  # Дополнительные маски для полей (пример)
  mask_fields := array_attr(input.resource.attributes, "pii_fields", [])

  obj := {
    "session_ttl_s": ttl,
    "mask_fields": mask_fields,
    "correlation_id": string_attr(input, "correlation_id", ""),
    "tenant_id": string_attr(input, "tenant_id", ""),
    "classification": cls,
  }
}

# -----------------------------------------------------------------------------
# Сбор причин отказа (для диагностики, не раскрывает внутренние детали)
# -----------------------------------------------------------------------------
deny_reasons()[r] {
  not policy_enabled
  r := "policy_disabled"
}
deny_reasons()[r] {
  kill_switch
  r := "kill_switch_active"
}
deny_reasons()[r] {
  not tenant_ok
  r := "tenant_invalid"
}
deny_reasons()[r] {
  not action_allowed_by_role
  r := "action_not_allowed_for_role"
}
deny_reasons()[r] {
  not ip_ok
  r := "ip_not_allowlisted"
}
deny_reasons()[r] {
  not device_ok
  r := "device_not_compliant"
}
deny_reasons()[r] {
  mfa_required
  not mfa_ok
  r := "mfa_required"
}
deny_reasons()[r] {
  not risk_ok
  r := "risk_too_high"
}
deny_reasons()[r] {
  not time_ok
  r := "outside_working_hours"
}
deny_reasons()[r] {
  # Если ничего не сработало, фиксируем общий отказ
  r := "default_deny"
  not any_specific_reason
}

any_specific_reason {
  some _; deny_reasons_specific[_]
}

deny_reasons_specific[r] {
  not tenant_ok; r := "tenant_invalid"
} else { not action_allowed_by_role; r := "action_not_allowed_for_role" } else { not ip_ok; r := "ip_not_allowlisted" } else { not device_ok; r := "device_not_compliant" } else { mfa_required; not mfa_ok; r := "mfa_required" } else { not risk_ok; r := "risk_too_high" } else { not time_ok; r := "outside_working_hours" }

# -----------------------------------------------------------------------------
# Утилиты безопасного доступа к атрибутам
# -----------------------------------------------------------------------------
has_key(obj, key) {
  _ := obj[key]
}

string_attr(obj, key, def) = v {
  is_object(obj)
  v0 := object.get(obj, key, def)
  v := to_string(v0)
} else = def

number_attr(obj, key, def) = v {
  is_object(obj)
  v0 := object.get(obj, key, def)
  v := to_number(v0)
} else = def

bool_attr(obj, key, def) = v {
  is_object(obj)
  v0 := object.get(obj, key, def)
  is_boolean(v0)
  v := v0
} else = def

array_attr(obj, key, def) = v {
  is_object(obj)
  v0 := object.get(obj, key, def)
  is_array(v0)
  v := v0
} else = def

object_attr(obj, key, def) = v {
  is_object(obj)
  v0 := object.get(obj, key, def)
  is_object(v0)
  v := v0
} else = def

to_string(x) = s {
  s := sprintf("%v", [x])
}

# -----------------------------------------------------------------------------
# Примеры использования (комментарий):
#
# POST /v1/data/authz/allow
# input:
# {
#   "tenant_id": "tenant-001",
#   "subject": {"id":"u-1", "attributes":{"role":"admin"}},
#   "action": {"name":"read", "attributes":{}},
#   "resource":{"id":"doc-7","type":"document","attributes":{"classification":"internal"}},
#   "environment":{
#     "ip":"203.0.113.10",
#     "attributes":{
#       "mfa": true,
#       "risk_score": 20,
#       "ip_allow": ["0.0.0.0/0"],
#       "enforce_working_hours": false
#     }
#   },
#   "correlation_id":"req-123"
# }
#
# result:
# {"allow": true, "obligations": {"session_ttl_s":1800, ...}, "version":"access-policy-v1.0.0"}
# -----------------------------------------------------------------------------
