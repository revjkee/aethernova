# cybersecurity-core/configs/policies/rego/rls.rego
package cybersecurity.rls.v1

# Rego RLS/ABAC для cybersecurity-core.
# Ожидаемый input (пример):
# {
#   "action": "list|search|read|create|update|delete",
#   "subject": {
#     "id": "u-123",
#     "roles": ["viewer","analyst"],
#     "tenants": ["t-1","t-2"],
#     "groups": ["g-ir","g-blue"],
#     "claims": {
#       "clearance": 3,             # необязательно, максимум по роли
#       "breakglass": false,
#       "org_admin": false
#     },
#     "mfa": true
#   },
#   "resource": {
#     "type": "event|alert|case|asset|indicator|report",
#     "tenant_id": "t-1",
#     "owner_id": "u-123",
#     "assigned_to": ["g-ir"],
#     "classification": "confidential",  # public|internal|confidential|secret|strict
#     "global": false
#   },
#   "context": {
#     "device_risk": "low|medium|high",
#     "ip": "203.0.113.10",
#     "now_ns": 0,                  # опционально, иначе time.now_ns()
#     "justification": "..."        # для breakglass
#   }
# }

# =========================
#        Константы
# =========================

default allow := false
default decision := {}
default deny_reasons := []

valid_resource_types := {"event", "alert", "case", "asset", "indicator", "report"}

# Соответствие уровня секретности числовому рангу
class_rank := {
  "public": 1,
  "internal": 2,
  "confidential": 3,
  "secret": 4,
  "strict": 5
}

# Ролевая максимальная "планка" допуска (clearance)
role_clearance := {
  "viewer": 2,
  "service": 3,
  "analyst": 3,
  "secops": 4,
  "admin": 5
}

# Доступные действия по ролям ( '*' означает любые )
role_actions := {
  "viewer":  {"list", "search", "read"},
  "service": {"list", "search", "read", "create"},
  "analyst": {"list", "search", "read", "update", "create"},
  "secops":  {"list", "search", "read", "update", "delete", "create"},
  "admin":   {"*"}
}

# Ролевые окна видимости по времени, дней (для list/search)
role_window_days := {
  "viewer": 90,
  "service": 180,
  "analyst": 365,
  "secops": 365,
  "admin": 3650
}

# =========================
#     Удобные алиасы
# =========================

subject := input.subject
resource := input.resource
ctx := input.context
act := lower(input.action)

now_ns := when_now_ns
when_now_ns := {
  some n
  # внешний "контекстный" now_ns приоритетнее (для тестов/реплея)
  n := ctx.now_ns
} else := time.now_ns()

# =========================
#      Вспомогательные
# =========================

has_role(r) {
  subject.roles[_] == r
}

any_role(allow_set) {
  some r
  subject.roles[_] == r
  (allow_set[r] == true)  # allow_set как map ролей->true
}

# множество разрешенных действий, агрегированное по всем ролям
permitted_actions := s {
  s := {a |
    some r
    subject.roles[_] == r
    acts := role_actions[r]
    # '*' -> любые действия
    (acts == {"*"}) => a := "*"
    (acts != {"*"}) => acts[a]
  }
}

# Проверка действия (учет '*')
action_permitted {
  permitted_actions["*"]
} else {
  permitted_actions[act]
}

# Максимальный допуск по ролям
default max_role_clearance := 0
max_role_clearance := m {
  vals := [ role_clearance[r] | subject.roles[_] == r; role_clearance[r] ]
  count(vals) > 0
  m := max(vals)
}

claimed_clearance := to_number(subject.claims.clearance)
final_clearance := m {
  claimed_clearance > 0
  # итоговый допуск — не выше планки роли
  m := min([max_role_clearance, claimed_clearance])
} else := max_role_clearance

# Ранг классификации ресурса
resource_class_rank := m {
  m := class_rank[lower(resource.classification)]
} else := 3  # по умолчанию "confidential"

# Преобразование дней в наносекунды
days_ns(d) := d * 24 * 60 * 60 * 1000000000

# Временное окно для list/search: нижняя граница по ролям
window_lower_ns := now_ns - days_ns(window_days)
window_days := m {
  vals := [ role_window_days[r] | subject.roles[_] == r; role_window_days[r] ]
  count(vals) > 0
  m := max(vals)
} else := 90

# Разрешенные аренды (tenants) субъекта
allowed_tenants := tset {
  tset := { t | subject.tenants[_] == t }
}

# Принципы (идентификаторы), которыми субъект может "владеть" или быть "назначен"
principals := pset {
  base := { subject.id }
  groups := { g | subject.groups[_] == g }
  pset := base | groups
}

# Строгий контекстный deny для высокого риска устройства
high_risk_deny {
  lower(ctx.device_risk) == "high"
  act != "create"  # создание может быть заблокировано иначе (но здесь блокируем чтение/листинг)
}

# breakglass: требует MFA, явного обоснования и флага
breakglass_enabled {
  subject.claims.breakglass == true
  subject.mfa == true
  count(ctx.justification) >= 16
}

# Межарендный доступ администратора (org_admin) — расширение за пределы subject.tenants
cross_tenant_admin {
  subject.claims.org_admin == true
  has_role("admin")
}

# Проверка tenancy для одиночного ресурса
tenancy_ok {
  resource.global == true
} else {
  allowed_tenants[resource.tenant_id]
} else {
  cross_tenant_admin
}

# Проверка уровня секретности
classification_ok {
  resource_class_rank <= final_clearance
}

# Доп. условия владения/назначения (для write-операций)
ownership_or_assignment {
  resource.owner_id == subject.id
} else {
  some g
  resource.assigned_to[_] == g
  principals[g]
}

# =========================
#   Правила разрешения
# =========================

# Блокирующие причины
deny_reasons[r] {
  not valid_resource_types[resource.type]
  r := "unsupported_resource_type"
}
deny_reasons[r] {
  not action_permitted
  r := "action_not_permitted_for_roles"
}
deny_reasons[r] {
  high_risk_deny
  r := "device_risk_high"
}
deny_reasons[r] {
  act != "list"
  act != "search"
  not tenancy_ok
  r := "tenant_mismatch"
}
deny_reasons[r] {
  act != "create"
  not classification_ok
  r := "insufficient_clearance"
}
# Для write действий требуется повышенный доступ
deny_reasons[r] {
  act == "update"
  not (has_role("analyst") or has_role("secops") or has_role("admin"))
  r := "write_requires_elevated_role"
}
deny_reasons[r] {
  act == "delete"
  not (has_role("secops") or has_role("admin"))
  r := "delete_requires_secops_or_admin"
}
deny_reasons[r] {
  (act == "update" or act == "delete")
  not (ownership_or_assignment or has_role("secops") or has_role("admin"))
  r := "write_requires_owner_or_assignment_or_secops_admin"
}

# Разрешение
allow {
  count(deny_reasons) == 0
}

# =========================
#    RLS-ограничения
# =========================
# Возвращается только для list/search; для read/update/delete RLS не требуется (единичный ресурс).
# Ограничения структурированы как:
# constraints := {
#   "resource_type": "...",
#   "where_all": [ {field, op, value}, ... ],  # должны выполниться все
#   "where_any": [ {field, op, value}, ... ],  # достаточно одного (OR)
#   "time_lower_bound_rfc3339": "...",
#   "tenants": ["t-1","t-2"],
#   "breakglass": true|false
# }

rls_constraints := obj {
  act == "list" or act == "search"

  # tenants
  tns := {t | allowed_tenants[t]}
  tns_arr := [t | t := tns[_]]

  # обязательные предикаты (AND)
  wa := [
    {"field": "tenant_id", "op": "in", "value": tns_arr},
    {"field": "classification_rank", "op": "<=", "value": final_clearance}
  ]

  # временное окно по ролям
  lb_ns := window_lower_ns
  lb_rfc3339 := time.format_rfc3339_ns(lb_ns)
  wa2 := [{"field": "timestamp", "op": ">=", "value": lb_rfc3339}]

  # предикаты владения/назначения (OR) зависят от resource.type и ролей
  any := resource_any_predicates

  obj := {
    "resource_type": resource.type,
    "where_all": wa ++ wa2,     # используем определение ниже для конкатенации
    "where_any": any,
    "time_lower_bound_rfc3339": lb_rfc3339,
    "tenants": tns_arr,
    "breakglass": breakglass_enabled
  }
}

# Конкатенация массивов (безопасно, если одна из частей пустая)
wa ++ wb := out {
  out := [x | wa[_] = x] ++ [y | wb[_] = y]
}

# any-of предикаты по типу ресурса и ролям
resource_any_predicates := ps {
  # админам и secops достаточно только аренды/классификации/времени
  (has_role("admin") or has_role("secops")) 
  ps := []
} else := ps {
  # для alert/case — владелец/назначенная группа/tenant-public
  (resource.type == "alert" or resource.type == "case")
  ps := [
    {"field": "owner_id", "op": "in", "value": [x | principals[x]]},
    {"field": "assigned_to", "op": "containsAny", "value": [x | principals[x]]},
    {"field": "visibility", "op": "in", "value": ["tenant", "public"]}
  ]
} else := ps {
  # для event/indicator/report/asset — достаточно tenant/public
  valid_resource_types[resource.type]
  ps := [
    {"field": "visibility", "op": "in", "value": ["tenant", "public"]}
  ]
}

# =========================
#      Итоговое решение
# =========================

decision := {
  "allow": allow,
  "constraints": rls_constraints with_default_empty,
  "deny_reasons": [r | deny_reasons[r]],
  "audit": audit_record
}

# Если constraints не применимы, вернуть пустую карту
with_default_empty := c {
  some x
  x := rls_constraints
  c := x
} else := {}

audit_record := {
  "ts": time.format_rfc3339_ns(now_ns),
  "subject": {
    "id": subject.id,
    "roles": subject.roles,
    "tenants": subject.tenants
  },
  "action": act,
  "resource_type": resource.type,
  "tenant": resource.tenant_id,
  "clearance": final_clearance,
  "device_risk": lower(ctx.device_risk),
  "breakglass": breakglass_enabled
}
