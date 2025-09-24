package policy_core.tenancy.v1

# ============================================================
# CONTRACT (ожидаемый input)
#
# input := {
#   "action": "read|create|update|delete|admin",
#   "method": "GET|POST|...",
#   "path": "/api/v1/tenants/t1/resources/r1",
#   "resource": {
#     "kind": "entity|policy|secret|...",
#     "tenant_id": "t1:sub",
#     "owner_id": "u123",
#     "data_class": "public|internal|confidential|secret",
#     "attributes": {}
#   },
#   "auth": {
#     "sub": "u123",
#     "roles": ["reader","editor"],                 # глобальные роли (опционально)
#     "role_bindings": [                            # предпочтительно: привязки ролей к арендам
#       {"role":"admin","tenant":"t1"},
#       {"role":"editor","tenant":"t1:sub"}
#     ],
#     "scopes": ["policy.read","policy.write"],     # OIDC/JWT scopes
#     "tenant": "t1",                               # базовая арендная принадлежность субъекта
#     "tenants": ["t1","t1:sub"],                   # список аренд, где субъект состоит
#     "mfa": true,                                  # второй фактор пройден
#     "ip": "10.0.0.5"
#   },
#   "env": {
#     "environment": "dev|staging|prod",
#     "time": "2025-08-28T08:00:00Z"
#   }
# }
#
# Конфиг по умолчанию можно переопределить данными в data.policy_core.tenancy.*
# ============================================================

default allow := false

# Экспортируемое решение для удобства интеграции:
decision := {
  "allow": allow,
  "reasons": reasons,          # массив строк (пусто при allow=true)
  "obligations": obligations,  # массив предписаний
  "mask": mask                 # маскирование полей ответа
}

reasons := [m | m := deny[_]]

# Обязательства и маскирование формируются независимо — полезны и при allow, и при deny
obligations := array.concat(
  mfa_obligation,
  audit_obligations
)

mask := redact_mask

# ------------------------------------------------------------
# Константы и значения по умолчанию (перекрываются data.*)
# ------------------------------------------------------------

# Уровни ролей (чем выше — тем больше прав)
role_levels := coalesce_object(data.policy_core.tenancy.role_levels, {
  "bot": 10,
  "reader": 20,
  "editor": 30,
  "admin": 40,
  "owner": 50
})

# Минимальная роль для действия
action_min_role := coalesce_object(data.policy_core.tenancy.action_min_role, {
  "read": "reader",
  "create": "editor",
  "update": "editor",
  "delete": "admin",
  "admin": "admin"
})

# Обязательные скоупы на действие
action_required_scopes := coalesce_object(data.policy_core.tenancy.action_required_scopes, {
  "read":   ["policy.read"],
  "create": ["policy.write"],
  "update": ["policy.write"],
  "delete": ["policy.admin"],
  "admin":  ["policy.admin"]
})

# Скоупы для кросс-арендного доступа
cross_tenant_scopes := coalesce_array(data.policy_core.tenancy.cross_tenant_scopes, ["cross_tenant.read", "cross_tenant.admin"])

# Классы данных и требования к ролям/скоупам
data_class_requirements := coalesce_object(data.policy_core.tenancy.data_class_requirements, {
  "public":       {"min_role_read":"bot",    "min_role_write":"editor", "require_mfa": false},
  "internal":     {"min_role_read":"reader", "min_role_write":"editor", "require_mfa": false},
  "confidential": {"min_role_read":"reader", "min_role_write":"admin",  "require_mfa": true},
  "secret":       {"min_role_read":"admin",  "min_role_write":"owner",  "require_mfa": true}
})

# Маскирование по классам данных
redact_by_class := coalesce_object(data.policy_core.tenancy.redact_by_class, {
  "public":       [],
  "internal":     ["password","token","secret","authorization"],
  "confidential": ["password","token","secret","authorization","email","phone"],
  "secret":       ["*"]  # полностью скрыть чувствительные поля, звезда означает «все приватные атрибуты»
})

# ------------------------------------------------------------
# Главный permit: нет ни одного deny -> allow
# ------------------------------------------------------------
allow {
  not deny[_]
}

# ------------------------------------------------------------
# DENY-правила с объяснениями
# ------------------------------------------------------------

deny["missing action"] {
  not input.action
}

deny["missing resource tenant"] {
  not res_tenant_id
}

deny["unknown action"] {
  not action_min_role[input.action]
}

deny[concat("insufficient role: need >=", [need, ", have =", have, ", tenant =", res_tenant_id])] {
  need := min_role_for_action_and_class
  have := role_for_tenant_level(res_tenant_id)
  have < role_levels[need]
}

deny["required scopes not present for action"] {
  required := action_required_scopes[input.action]
  not scopes_contain_all(required)
}

deny["cross-tenant access requires special scope"] {
  not same_or_parent_tenant(input.auth, res_tenant_id)
  not scope_in(cross_tenant_scopes)
}

deny["MFA required for this operation"] {
  mfa_required
  not bool(input.auth.mfa)
}

deny["write requires ownership or elevated role"] {
  write_action
  not subject_is_owner_or_elevated
}

deny["secret resource requires admin in same or parent tenant"] {
  res_data_class == "secret"
  not same_or_parent_tenant(input.auth, res_tenant_id)
}

# Пример ограничения по окружению: админ-операции в prod без отдельного admin-скоупа запрещены
deny["admin in prod requires explicit policy.admin scope"] {
  env_is("prod")
  input.action == "admin"
  not scope_in(["policy.admin"])
}

# ------------------------------------------------------------
# ОБЯЗАТЕЛЬСТВА И МАСКИРОВАНИЕ
# ------------------------------------------------------------

mfa_obligation := [{"type": "require_mfa"}] {
  mfa_required
  not bool(input.auth.mfa)
}

audit_obligations := [
  {"type": "audit", "level": lvl, "reason": reason}
] {
  lvl := audit_level
  reason := audit_reason
}

audit_level := lvl {
  some lvl
  lvl := "high"
  res_data_class == "secret"
} else := lvl {
  lvl := "medium"
  res_data_class == "confidential"
} else := "low"

audit_reason := reason {
  write_action
  reason := "write operation"
} else := reason {
  not same_or_parent_tenant(input.auth, res_tenant_id)
  reason := "cross-tenant access"
} else := "read"

# Маска полей ответа
redact_mask := fields {
  dc := res_data_class
  fields := redact_by_class[dc]
}

# ------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ПРЕДИКАТЫ И ФУНКЦИИ
# ------------------------------------------------------------

# Получить tenant_id ресурса
res_tenant_id := tid {
  tid := input.resource.tenant_id
}

# Класс данных ресурса (по умолчанию internal)
res_data_class := dc {
  dc := lower(input.resource.data_class)
} else := "internal"

# Минимальная роль с учётом действия и класса данных
min_role_for_action_and_class := need {
  base := action_min_role[input.action]
  # Для write/update/delete смотрим min_role_write класса данных
  write_action
  need := max_role(base, data_class_requirements[res_data_class].min_role_write)
} else := need {
  # Для read проверяем min_role_read класса данных
  input.action == "read"
  need := max_role(action_min_role["read"], data_class_requirements[res_data_class].min_role_read)
} else := need {
  # Прочие действия — базовая минимальная роль
  need := action_min_role[input.action]
}

# true если действие изменяет данные
write_action {
  input.action == "create"  # create
} else {
  input.action == "update"
} else {
  input.action == "delete"
}

# Требуется ли MFA
mfa_required {
  data_class_requirements[res_data_class].require_mfa
} else {
  input.action == "admin"
}

# Пользователь — владелец ресурса или обладает повышенной ролью
subject_is_owner_or_elevated {
  input.auth.sub == input.resource.owner_id
} else {
  role_for_tenant_level(res_tenant_id) >= role_levels["admin"]
}

# Роль субъекта (уровень) для конкретной аренды
role_for_tenant_level(tid) := lvl {
  # 1) Привязанные роли к аренде (или её предкам) имеют приоритет
  some i
  rb := input.auth.role_bindings[i]
  tenant_match(rb.tenant, tid)
  lvl := max([ role_levels[rb.role] | rb := input.auth.role_bindings[_]; tenant_match(rb.tenant, tid); role_levels[rb.role] ])
} else := lvl {
  # 2) Если привязок нет — берём максимальную из глобальных ролей auth.roles
  roles := default_array(input.auth.roles, [])
  lvl := max_default([ role_levels[r] | r := roles[_]; role_levels[r] ], 0)
} else := 0

# Сравнение ролей: выбрать "более строгую" (с большим уровнем)
max_role(a, b) := out {
  al := role_levels[a]
  bl := role_levels[b]
  out := a
  al >= bl
} else := out {
  out := b
}

# Проверка совпадения или родительской аренды.
# Имена аренд разделены двоеточием: "org:unit:team"
same_or_parent_tenant(auth, target) {
  # Входит в список tenants
  target == auth.tenant
} else {
  arr := default_array(auth.tenants, [])
  arr[_] == target
} else {
  # Является потомком базовой аренды субъекта
  tenant_is_descendant(target, auth.tenant)
}

tenant_is_descendant(child, parent) {
  parent != ""
  startswith(concat(":", [parent, ""]), concat(":", [child, ""]))
}

tenant_match(binding_tenant, target_tenant) {
  # Полное совпадение или binding_tenant — предок target_tenant
  binding_tenant == target_tenant
} else {
  tenant_is_descendant(target_tenant, binding_tenant)
}

# Скоупы: наличие всех требуемых
scopes_contain_all(req) {
  every r in req {
    scope_in([r])
  }
}

# Содержится ли хотя бы один скоуп из списка
scope_in(candidates) {
  some s
  s := candidates[_]
  arr := default_array(input.auth.scopes, [])
  arr[_] == s
}

# -----------------------------------------
# Утилиты
# -----------------------------------------

# Значение по умолчанию для массива
default_array(x, def) := out {
  out := x
  is_array(x)
} else := def

# Взять максимум из не пустого множества чисел
max(arr) := m {
  m := max_default(arr, -1)
}

# Максимум с дефолтом для пустого
max_default(arr, d) := m {
  count(arr) > 0
  m := max_inner(arr)
} else := d

max_inner(arr) := m {
  m := arr[0]
  not any_greater(arr, m)
} else := m {
  some i
  ai := arr[i]
  any_greater(arr, ai)
  m := max_inner([x | x := arr[_]; x > ai])
}

any_greater(arr, v) {
  some j
  arr[j] > v
}

# Слияние объекта с дефолтом
coalesce_object(x, def) := out {
  is_object(x)
  out := x
} else := def

# Слияние массива с дефолтом
coalesce_array(x, def) := out {
  is_array(x)
  out := x
} else := def

# Булево из любого типа
bool(x) {
  x == true
}

# Нормализация строки к нижнему регистру
lower(s) := out {
  out := lower_ascii(s)
}

# ------------------------------------------------------------
# SELF-TEST sanity (можно оставить выключенным, включив data.policy_core.tenancy.selftest=true)
# ------------------------------------------------------------

deny["selftest: action not provided"] {
  data.policy_core.tenancy.selftest == true
  not input.action
}
