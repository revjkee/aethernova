package policy.authz

# ============================================================================
# Industrial AuthZ Policy (OPA Rego)
# Entry points:
#   - allow: boolean          — итоговое решение
#   - deny:  set(string)      — коды причин отказа (детерминированные)
#   - reasons: set(object)    — подробные причины с i18n-ключами и деталями
#   - effective_permissions:  set(string) — вычисленные разрешенные действия субъекта над ресурсом
#
# Требуемая форма input (пример, ключевые поля):
# input := {
#   "tenant": "acme",
#   "user": {
#       "id": "u1",
#       "roles": ["analyst"],
#       "attrs": {"dept": "sales", "clearance": "internal", "mfa": true, "geo": "EU"},
#       "scopes": ["policy:read", "policy:write"],
#       "consents": ["pii_read"]
#   },
#   "resource": {
#       "type": "document",
#       "id": "doc-42",
#       "tenant": "acme",
#       "owner": "u2",
#       "labels": {"classification": "internal", "pii": true, "dept": "sales"}
#   },
#   "action": "read",  # пример: read|write|delete|approve
#   "env": {
#       "ip": "203.0.113.10",
#       "weekday": "Mon",
#       "hour": 14,         # 0..23 (UTC или локаль — на стороне адаптера)
#       "risk": "low"       # low|medium|high (вычисляется upstream)
#   },
#   "quota": {
#       "minute_requests": 12,
#       "minute_limit": 100
#   }
# }
#
# Справочники в data.authz.* (примерная структура, наполняется из внешних источников):
# data.authz.roles: {
#   "admin":        {"permissions": {"*": ["*"]}},
#   "analyst":      {"permissions": {"document": ["read", "search"], "policy": ["read"]}},
#   "approver":     {"permissions": {"document": ["approve", "read"]}}
# }
# data.authz.classification: {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
# data.authz.networks: {
#   "allow": ["10.0.0.0/8", "192.168.0.0/16"],
#   "deny":  ["203.0.113.0/24"]
# }
# data.authz.time_windows: {
#   "restricted_actions": {
#     "delete": {"start": 0, "end": 6} # запрет опасных действий ночью 00–06
#   }
# }
# data.authz.pii: {
#   "consent_scopes": {"read": "pii_read", "write": "pii_write"}
# }
# ============================================================================

default allow = false

# Базовая проверка: есть ли у пользователя право на действие над типом ресурса через RBAC.
base_rbac_ok {
  some role
  role := input.user.roles[_]
  # Пермишены роли
  perms := data.authz.roles[role].permissions
  # Разрешение по точному типу или по джокеру "*"
  actions := perms[input.resource.type]
  actions[_] == input.action
} else {
  some role
  role := input.user.roles[_]
  perms := data.authz.roles[role].permissions
  wildcard := perms["*"]
  wildcard[_] == "*"
} else = false

# Tenant изоляция: субъект и ресурс должны совпадать по tenant (если задан).
tenant_ok {
  not input.tenant
} else {
  input.resource.tenant == input.tenant
}

# ABAC: отделы совпадают, либо владелец ресурса — пользователь, либо присутствует явное исключение в ролях.
abac_ok {
  input.resource.owner == input.user.id
} else {
  input.user.attrs.dept == input.resource.labels.dept
} else {
  some role
  role := input.user.roles[_]
  role == "admin"  # пример исключения
} else = false

# Классификационный контроль: clearance пользователя >= classification ресурса.
classification_ok {
  not input.resource.labels.classification
} else {
  cl := data.authz.classification[input.user.attrs.clearance]
  rl := data.authz.classification[input.resource.labels.classification]
  cl >= rl
}

# PII: если ресурс помечен как PII и действие не только на чтение метаданных — требуется соответствующий consent/scope.
pii_ok {
  not input.resource.labels.pii
} else {
  required := data.authz.pii.consent_scopes[input.action]
  not required  # для действий без требований
} else {
  required := data.authz.pii.consent_scopes[input.action]
  required == ""  # явное отсутствие
} else {
  required := data.authz.pii.consent_scopes[input.action]
  # Проверяем либо consent, либо OAuth scope
  input.user.consents[_] == required
} else {
  required := data.authz.pii.consent_scopes[input.action]
  input.user.scopes[_] == required
}

# RBA (risk-based): при высоком риске требуем MFA и запрещаем опасные действия из «плохих» сетей.
risk_ok {
  input.env.risk == "low"
} else {
  input.env.risk == "medium"
} else {
  # High risk: нужен MFA и IP не из deny-list
  input.env.risk == "high"
  input.user.attrs.mfa == true
  not ip_in_list(input.env.ip, data.authz.networks.deny)
}

# Сетевые ограничения: если allow-list задан — IP должен попадать в одно из CIDR.
network_ok {
  not data.authz.networks.allow
} else {
  ip_in_list(input.env.ip, data.authz.networks.allow)
}

# Временные окна: некоторые опасные действия запрещены ночью.
time_window_ok {
  not data.authz.time_windows.restricted_actions[input.action]
} else {
  tw := data.authz.time_windows.restricted_actions[input.action]
  # Разрешено, если текущее время вне запретного интервала
  not hour_in_range(input.env.hour, tw.start, tw.end)
}

# Квоты (best-effort): если лимит задан и превышен — запрет.
quota_ok {
  not input.quota
} else {
  not input.quota.minute_limit
} else {
  input.quota.minute_requests <= input.quota.minute_limit
}

# Совокупное разрешение:
allow {
  base_rbac_ok
  tenant_ok
  abac_ok
  classification_ok
  pii_ok
  risk_ok
  network_ok
  time_window_ok
  quota_ok
  # Дополнительные пользовательские предикаты могут быть подключены ниже
  not deny[_]  # гарантия отсутствия перечисленных запретов
}

# ---------------------------
# Причины отказов (детерминированные)
# ---------------------------

deny[code] {
  not base_rbac_ok
  code := "RBAC_DENY"
}

deny[code] {
  not tenant_ok
  code := "TENANT_MISMATCH"
}

deny[code] {
  not abac_ok
  code := "ABAC_DENY"
}

deny[code] {
  not classification_ok
  code := "CLASSIFICATION_TOO_LOW"
}

deny[code] {
  not pii_ok
  code := "PII_CONSENT_REQUIRED"
}

deny[code] {
  not risk_ok
  code := "RISK_POLICY_BLOCK"
}

deny[code] {
  not network_ok
  code := "NETWORK_NOT_ALLOWED"
}

deny[code] {
  not time_window_ok
  code := "ACTION_FORBIDDEN_AT_THIS_TIME"
}

deny[code] {
  not quota_ok
  code := "QUOTA_EXCEEDED"
}

# Полные reasons для локализации и аудита.
reasons[reason] {
  reason := {
    "code": "RBAC_DENY",
    "i18n_key": "authz.rbac_denied",
    "details": {"role": input.user.roles, "action": input.action, "type": input.resource.type}
  }
  not base_rbac_ok
}
reasons[reason] {
  reason := {
    "code": "TENANT_MISMATCH",
    "i18n_key": "authz.tenant_mismatch",
    "details": {"tenant": input.tenant, "resource_tenant": input.resource.tenant}
  }
  not tenant_ok
}
reasons[reason] {
  reason := {
    "code": "ABAC_DENY",
    "i18n_key": "authz.abac_denied",
    "details": {"dept_user": input.user.attrs.dept, "dept_resource": input.resource.labels.dept, "owner": input.resource.owner}
  }
  not abac_ok
}
reasons[reason] {
  reason := {
    "code": "CLASSIFICATION_TOO_LOW",
    "i18n_key": "authz.classification_low",
    "details": {
      "user_clearance": input.user.attrs.clearance,
      "resource_classification": input.resource.labels.classification
    }
  }
  not classification_ok
}
reasons[reason] {
  reason := {
    "code": "PII_CONSENT_REQUIRED",
    "i18n_key": "authz.pii_consent_required",
    "details": {"action": input.action}
  }
  not pii_ok
}
reasons[reason] {
  reason := {
    "code": "RISK_POLICY_BLOCK",
    "i18n_key": "authz.risk_block",
    "details": {"risk": input.env.risk, "mfa": input.user.attrs.mfa}
  }
  not risk_ok
}
reasons[reason] {
  reason := {
    "code": "NETWORK_NOT_ALLOWED",
    "i18n_key": "authz.network_not_allowed",
    "details": {"ip": input.env.ip}
  }
  not network_ok
}
reasons[reason] {
  reason := {
    "code": "ACTION_FORBIDDEN_AT_THIS_TIME",
    "i18n_key": "authz.forbidden_time",
    "details": {"action": input.action, "hour": input.env.hour}
  }
  not time_window_ok
}
reasons[reason] {
  reason := {
    "code": "QUOTA_EXCEEDED",
    "i18n_key": "authz.quota_exceeded",
    "details": {
      "used": input.quota.minute_requests,
      "limit": input.quota.minute_limit
    }
  }
  not quota_ok
}

# ---------------------------
# Вычисление эффективных прав (для UI/кэша)
# ---------------------------

effective_permissions[act] {
  some role
  role := input.user.roles[_]
  perms := data.authz.roles[role].permissions
  acts := perms[input.resource.type]
  act := acts[_]
}

effective_permissions[act] {
  some role
  role := input.user.roles[_]
  perms := data.authz.roles[role].permissions
  perms["*"][_] == "*"
  act := input.action  # джокер — считаем текущее действие потенциально доступным
}

# ---------------------------
# Хелперы (side-effect free, пригодны для partial eval)
# ---------------------------

# Проверка IP в любом из CIDR (deny/allow листы).
ip_in_list(ip, cidrs) {
  some i
  net.cidr_contains(cidrs[i], ip)
}

# Принадлежит ли час [start, end) в циклическом 0..23 интервале.
hour_in_range(h, start, end) {
  start <= end
  h >= start
  h < end
} else {
  start > end
  h >= start
} else {
  start > end
  h < end
}

# Удобные алиасы package-уровня (если в движке объявлены entrypoints)
allow := allow
deny := deny
reasons := reasons
