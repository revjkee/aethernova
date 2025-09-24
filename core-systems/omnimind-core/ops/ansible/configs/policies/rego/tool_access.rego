# =====================================================================
# OmniMind Core — Tool Access Policy (OPA/Rego)
# Версия: 1.0.0
# Модель: deny-by-default, объяснимость, минимально необходимый доступ.
#
# Ожидаемые внешние данные:
# - data.org.tenants[tenant_id]                : объект тенанта
# - data.org.roles[user_id]                    : список ролей пользователя
# - data.tools.registry[tool_id]               : запись инструмента (классы риска, разрешенные окружения и т.д.)
# - data.security.allow_cidrs                  : список CIDR, белый список исходящих IP
# - data.security.block_countries              : список ISO стран, запрещенных для вызовов
# - data.security.sensitivity_policies         : карта правил для уровней чувствительности
# - data.limits.rate                           : лимиты частоты на роль/инструмент/тенанта
#
# Ожидаемый формат входа (input):
# {
#   "subject": {
#     "user_id": "u-123",
#     "tenant_id": "t-omni",
#     "roles": ["ml-engineer"],           # если не задано, берутся из data.org.roles[user_id]
#     "attributes": {
#       "country": "SE",
#       "ip": "203.0.113.10",
#       "mfa": true
#     }
#   },
#   "resource": {
#     "tool_id": "web_search",
#     "scope": ["read"],                  # требуемые действия/области
#     "env": "prod",                      # prod|stage|dev
#     "sensitivity": "pii",               # none|internal|pii|regulated
#     "content_tags": ["health","finance"]# метки содержимого (для модерации/сектора)
#   },
#   "context": {
#     "now": "2025-08-18T10:15:20Z",
#     "weekday": "mon",                   # опционально; иначе вычислим
#     "hour": 10,                         # 0..23, опционально
#     "request_id": "req-abc",
#     "geoip_country": "SE",
#     "ip": "203.0.113.10"
#   },
#   "usage": {
#     "rate": {                           # телеметрия для квот/частоты
#       "per_minute": 12,
#       "per_hour": 180
#     },
#     "token_estimate": 12000
#   },
#   "consents": {
#     "dlp": true,                        # согласие на DLP-маскирование
#     "legal_ack": true                   # юридическое подтверждение (если требуется)
#   },
#   "moderation": {
#     "score": 0.12,                      # 0..1, риск нарушений контента
#     "blocked": false
#   }
# }
#
# Результат (decision):
# {
#   "allow": true|false,
#   "reason": ["...","..."],              # список причин
#   "obligations": {                      # обязательства для исполнителя
#     "redact_pii": true,
#     "max_tokens": 8192,
#     "approval_required": false,
#     "mask_secrets": true,
#     "rate_limit_hint": "60rpm",
#     "route": "low_risk_pool",           # рекомендованный маршрут/кластер
#     "audit": { "level": "standard" }    # стандартный/расширенный
#   },
#   "risk": {
#     "score": 37,                        # 0..100
#     "class": "low|medium|high|critical"
#   }
# }
# =====================================================================

package omnimind.policies.tool_access

default decision := {
  "allow": false,
  "reason": ["default deny"],
  "obligations": {"audit": {"level": "standard"}},
  "risk": {"score": 100, "class": "critical"}
}

# Главная точка входа
decision := result {
  reasons := array.concat([], [])
  base := {"allow": false, "reason": reasons, "obligations": {}, "risk": {"score": 0, "class": "low"}}

  valid := validate_input
  not valid.error

  # Сбор данных субъекта, инструмента и окружения
  tenant := input.subject.tenant_id
  user_roles := roles_for(input.subject.user_id, input.subject.roles)
  tool := data.tools.registry[input.resource.tool_id]
  env := input.resource.env

  # Базовые проверки
  checks := [
    check_tenant_exists(tenant),
    check_tool_exists(tool),
    check_env_allowed(tool, env),
    check_geoip_allowed,
    check_cidr_allowed,
    check_scopes(user_roles, tool, input.resource.scope),
    check_mfa_required(user_roles, tool),
    check_time_window(tool),
    check_moderation_block,
    check_sensitivity(tenant, tool, input.resource.sensitivity),
    check_legal_ack(tool),
    check_rate_limits(user_roles, tenant, tool)
  ]

  # Агрегируем причины и статус
  deny_reasons := [c.msg | c := checks; c.allow == false]
  allow := count(deny_reasons) == 0

  # Скоринг риска и обязательства
  risk := compute_risk(user_roles, tool)
  obligations := compute_obligations(tool, risk)

  result := {
    "allow": allow,
    "reason": allow_reason(allow, checks),
    "obligations": obligations,
    "risk": risk
  }
}

# ------------------------------
# Валидация входа
# ------------------------------
validate_input := out {
  missing := {p |
    some p
    p := required_paths[_]
    not path_exists(input, p)
  }
  out := {"error": count(missing) > 0, "missing": missing}
}

required_paths := [
  ["subject","user_id"],
  ["subject","tenant_id"],
  ["resource","tool_id"],
  ["resource","env"]
]

path_exists(obj, path) {
  v := object.get(obj, path[0], null)
  count(path) == 1; v != null
} else {
  v := object.get(obj, path[0], null)
  v != null
  path_exists(v, path[1:])
}

# ------------------------------
# Вспомогательные функции
# ------------------------------

roles_for(user_id, roles) := rs {
  some rs
  defaulted := data.org.roles[user_id]
  rs := roles
  not roles_provided := roles != null
} else := rs {
  roles == null
  rs := data.org.roles[user_id]
} else := rs {
  # если нет в data и роли явно не передали — пустой список
  roles == null
  not data.org.roles[user_id]
  rs := []
}

in_list(x, arr) {
  some i
  arr[i] == x
}

any_in(arr, arr2) {
  some i
  some j
  arr[i] == arr2[j]
}

# ------------------------------
# Блоки проверок (возвращают объект)
# ------------------------------

check_tenant_exists(tenant) := {"allow": true, "msg": "tenant ok"} {
  data.org.tenants[tenant]
} else := {"allow": false, "msg": sprintf("unknown tenant: %v", [tenant])}

check_tool_exists(tool) := {"allow": true, "msg": "tool ok"} {
  tool.id != ""
} else := {"allow": false, "msg": "tool not registered"}

check_env_allowed(tool, env) := {"allow": true, "msg": "env ok"} {
  not tool.envs
} else := {"allow": true, "msg": "env ok"} {
  tool.envs[env]
} else := {"allow": false, "msg": sprintf("env %v not allowed for tool", [env])}

check_geoip_allowed := {"allow": true, "msg": "geo ok"} {
  not data.security.block_countries
} else := {"allow": true, "msg": "geo ok"} {
  not in_list(input.context.geoip_country, data.security.block_countries)
} else := {"allow": false, "msg": sprintf("country %v blocked", [input.context.geoip_country])}

check_cidr_allowed := {"allow": true, "msg": "cidr ok"} {
  not data.security.allow_cidrs
} else := {"allow": true, "msg": "cidr ok"} {
  ip := input.context.ip
  some cidr
  cidr := data.security.allow_cidrs[_]
  net.cidr_contains(cidr, ip)
} else := {"allow": false, "msg": "source ip not in allowlist"}

check_scopes(user_roles, tool, requested) := {"allow": true, "msg": "scopes ok"} {
  not tool.scopes
} else := {"allow": true, "msg": "scopes ok"} {
  # RBAC: любая роль субъекта должна пересекаться с ролевой матрицей инструмента
  some r
  r := user_roles[_]
  tool.rbac[r]
  # и все запрошенные скоупы должны входить в разрешенные для роли
  allowed := tool.rbac[r].scopes
  forall(requested, func(x) { in_list(x, allowed) })
} else := {"allow": false, "msg": "scope not permitted for roles"}

forall(arr, f) {
  not exists(arr, func(x) { not f(x) })
}

exists(arr, f) {
  some i
  f(arr[i])
}

check_mfa_required(user_roles, tool) := {"allow": true, "msg": "mfa ok"} {
  not tool.mfa_required
} else := {"allow": true, "msg": "mfa ok"} {
  tool.mfa_required == true
  input.subject.attributes.mfa == true
} else := {"allow": false, "msg": "mfa required"}

check_time_window(tool) := {"allow": true, "msg": "time ok"} {
  not tool.time_windows
} else := {"allow": true, "msg": "time ok"} {
  # пример формата: tool.time_windows = {"mon-fri":{"start":8,"end":20}}
  hour := time.get_hour(parse_rfc3339(input.context.now))
  wd := weekday(parse_rfc3339(input.context.now))
  win := tool.time_windows[wd]
  hour >= win.start
  hour <  win.end
} else := {"allow": false, "msg": "outside allowed time window"}

parse_rfc3339(s) := t { t := time.parse_rfc3339_ns(s) }

weekday(t) := wd {
  i := time.weekday(t) # 0..6; 0=Sun
  wd := ["sun","mon","tue","wed","thu","fri","sat"][i]
}

check_moderation_block := {"allow": true, "msg": "moderation ok"} {
  not input.moderation.blocked
} else := {"allow": false, "msg": "content blocked by moderation"}

check_sensitivity(tenant, tool, level) := {"allow": true, "msg": "sensitivity ok"} {
  # соответствие чувствительности и класса инструмента
  not data.security.sensitivity_policies[level]
} else := {"allow": true, "msg": "sensitivity ok"} {
  policy := data.security.sensitivity_policies[level]
  # пример: policy = {"allowed_tool_classes":["low","standard"], "require_dlp":true}
  in_list(tool.class, policy.allowed_tool_classes)
  (not policy.require_dlp) or input.consents.dlp == true
} else := {"allow": false, "msg": "sensitivity mismatch or DLP consent missing"}

check_legal_ack(tool) := {"allow": true, "msg": "legal ok"} {
  not tool.legal_ack_required
} else := {"allow": true, "msg": "legal ok"} {
  tool.legal_ack_required == true
  input.consents.legal_ack == true
} else := {"allow": false, "msg": "legal acknowledgement required"}

check_rate_limits(user_roles, tenant, tool) := {"allow": true, "msg": "rate ok"} {
  not data.limits.rate
} else := {"allow": true, "msg": "rate ok"} {
  # Ищем наиболее строгий лимит
  lim := rate_limit_for(user_roles, tenant, tool)
  pm := input.usage.rate.per_minute
  ph := input.usage.rate.per_hour
  pm <= lim.per_minute
  ph <= lim.per_hour
} else := {"allow": false, "msg": "rate exceeded"}

rate_limit_for(user_roles, tenant, tool) := lim {
  # Иерархия: per-user-role+tool -> per-tenant+tool -> per-tool -> defaults
  some r
  r := user_roles[_]
  lim := data.limits.rate.role_tool[r][tool.id]
} else := lim {
  lim := data.limits.rate.tenant_tool[tenant][tool.id]
} else := lim {
  lim := data.limits.rate.tool[tool.id]
} else := lim {
  lim := data.limits.rate.defaults
}

# ------------------------------
# Скоринг риска и обязательства
# ------------------------------
compute_risk(user_roles, tool) := out {
  # Базовый риск по классу инструмента: low|standard|sensitive|critical
  base := {
    "low": 10,
    "standard": 20,
    "sensitive": 40,
    "critical": 60
  }[tool.class]

  pii_boost := {
    true: 20,
    false: 0
  }[input.resource.sensitivity == "pii" or input.resource.sensitivity == "regulated"]

  country_boost := {
    true: 10,
    false: 0
  }[data.security.block_countries[input.context.geoip_country]]

  mod_boost := ceil(input.moderation.score * 20)

  score := clamp(base + pii_boost + country_boost + mod_boost, 0, 100)
  cls := risk_class(score)

  out := {"score": score, "class": cls}
}

risk_class(score) := "low" { score < 25 }
risk_class(score) := "medium" { score >= 25; score < 50 }
risk_class(score) := "high" { score >= 50; score < 75 }
risk_class(score) := "critical" { score >= 75 }

clamp(x, lo, hi) := y {
  y := x
  x < lo => y := lo
  x > hi => y := hi
}

ceil(x) := y {
  # упрощенный ceil для небольших значений
  y := int(x)
  x > y
  y := y + 1
} else := y { y := int(x) }

compute_obligations(tool, risk) := obj {
  max_tokens := max_tokens_for(tool, risk)
  approval := risk.class == "high" or risk.class == "critical"
  redact := input.resource.sensitivity == "pii" or input.resource.sensitivity == "regulated"
  audit_level := cond(approval, "extended", "standard")
  route := route_hint(tool, risk)

  obj := {
    "redact_pii": redact,
    "max_tokens": max_tokens,
    "approval_required": approval,
    "mask_secrets": true,
    "rate_limit_hint": rate_hint(tool),
    "audit": {"level": audit_level},
    "route": route
  }
}

max_tokens_for(tool, risk) := n {
  base := 8192
  n := base
  risk.class == "high" => n := 4096
  risk.class == "critical" => n := 2048
}

rate_hint(tool) := h {
  # Подсказка исполнителю о желательном лимите
  default := "60rpm"
  h := coalesce(tool.rate_hint, default)
}

route_hint(tool, risk) := r {
  r := "standard_pool"
  tool.class == "sensitive" => r := "restricted_pool"
  tool.class == "critical"  => r := "isolation_pool"
  risk.class == "high"      => r := "low_risk_pool"
  risk.class == "critical"  => r := "manual_review_pool"
}

coalesce(x, y) := z { x != null; x != ""; z := x } else := z { z := y }

cond(pred, a, b) := out { pred; out := a } else := out { not pred; out := b }

allow_reason(allow, checks) := rs {
  allow
  rs := ["allowed"] ++ [c.msg | c := checks]
} else := rs {
  not allow
  rs := ["denied"] ++ [c.msg | c := checks; c.allow == false]
}

# ------------------------------
# Минимальные встроенные данные по умолчанию (для безопасных дефолтов)
# В реальном проде будут загружены через data.* из внешнего источника.
# ------------------------------

# Если нет записи инструмента в data.tools.registry — check_tool_exists провалится.
# Пример структуры для справки:
# data.tools.registry = {
#   "web_search": {
#     "id": "web_search",
#     "class": "standard",                # low|standard|sensitive|critical
#     "envs": {"prod": true, "stage": true, "dev": true},
#     "mfa_required": false,
#     "rbac": {
#       "ml-engineer": {"scopes": ["read"]},
#       "analyst": {"scopes": ["read"]},
#       "admin": {"scopes": ["read","write"]}
#     },
#     "time_windows": {                   # опционально
#       "mon": {"start": 8, "end": 20},
#       "tue": {"start": 8, "end": 20},
#       "wed": {"start": 8, "end": 20},
#       "thu": {"start": 8, "end": 20},
#       "fri": {"start": 8, "end": 20}
#     },
#     "legal_ack_required": false,
#     "rate_hint": "120rpm"
#   }
# }

# Пример чувствительности
# data.security.sensitivity_policies = {
#   "none":       {"allowed_tool_classes": ["low","standard"], "require_dlp": false},
#   "internal":   {"allowed_tool_classes": ["low","standard"], "require_dlp": false},
#   "pii":        {"allowed_tool_classes": ["low","standard","sensitive"], "require_dlp": true},
#   "regulated":  {"allowed_tool_classes": ["sensitive","critical"], "require_dlp": true}
# }

# Пример лимитов
# data.limits.rate = {
#   "defaults": {"per_minute": 60, "per_hour": 3000},
#   "tool": {
#     "web_search": {"per_minute": 120, "per_hour": 6000}
#   },
#   "tenant_tool": {
#     "t-omni": {"web_search": {"per_minute": 200, "per_hour": 8000}}
#   },
#   "role_tool": {
#     "admin": {"web_search": {"per_minute": 300, "per_hour": 12000}}
#   }
# }
