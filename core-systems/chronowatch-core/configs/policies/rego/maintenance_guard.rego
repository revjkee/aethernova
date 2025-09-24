package chronowatch.policies.maintenance_guard

# -----------------------------------------------------------------------------
# INPUT SCHEMA (ожидается от интеграции шлюза/sidecar)
#
# input := {
#   "request": {
#     "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | ...,
#     "path": ["api","schedules"],                 # массив сегментов URL
#     "headers": {"x-maintenance-bypass": "1"},    # необязательно
#     "time": "2025-08-28T12:00:00Z",              # RFC3339 (опционально)
#     "now_ns": 1693224000000000000,               # now в наносекундах (опционально)
#     "weekday": "thu",                            # для weekly окон (опционально)
#     "mins_local": 720                            # минуты с полуночи локального TZ (опционально)
#   },
#   "auth": {
#     "roles": ["admin","maintainer","reader"],    # произвольные роли
#     "scopes": ["maintenance:override"],          # произвольные скоупы
#     "is_admin": true                             # удобный флаг (опционально)
#   },
#   "config": {
#     "maintenance": {
#       "enabled": true,
#       "mode": "deny-writes",                     # "read-only"|"deny-writes"|"full-freeze"
#       "exempt_roles": ["admin"],                 # роли, игнорирующие блокировку
#       "exempt_paths": ["/healthz","/readyz","/metrics"], # явные исключения
#       "windows": [
#         {"type":"fixed","start":"2025-09-01T10:00:00Z","end":"2025-09-01T12:00:00Z"},
#         {"type":"weekly","days":["sat","sun"],"start_min":120,"end_min":210}
#       ]
#     }
#   }
# }
#
# ПРИМЕЧАНИЯ:
# - Если нет request.now_ns, используется request.time (RFC3339). Если нет обоих, используется time.now_ns().
# - Для weekly окон рекомендуется передавать request.weekday ("mon".."sun") и request.mins_local (минуты локального времени).
# -----------------------------------------------------------------------------

default allow := false

# Главное решение: разрешено, если нет ни одной причины отказа
allow {
  not deny[_]
}

# Развёрнутый ответ, удобен для логов и дебага
decision := {
  "allow": allow,
  "mode": mode_resolved,
  "maintenance_enabled": maintenance_enabled,
  "in_maintenance": maintenance_active,
  "override": has_override,
  "exempt_path": is_exempt_path,
  "exempt_role": has_exempt_role,
  "path": path_str,
  "method": method,
  "reasons": deny,
}

# -----------------------------------------------------------------------------
# DENY-правила (кумулятивные причины)
# -----------------------------------------------------------------------------

# Блокировка при full-freeze: всё, кроме исключений и override
deny[msg] {
  maintenance_enabled
  maintenance_active
  mode_resolved == "full-freeze"
  not (is_exempt_path or has_override or has_exempt_role)
  msg := "maintenance_active: full-freeze blocks request"
}

# Read-only и deny-writes: запрещаем write-методы, кроме исключений и override
deny[msg] {
  maintenance_enabled
  maintenance_active
  mode_resolved != "full-freeze"
  is_write_method
  not (is_exempt_path or has_override or has_exempt_role)
  msg := sprintf("maintenance_active: %s blocks write method %s", [mode_resolved, method])
}

# -----------------------------------------------------------------------------
# Настройки/контекст
# -----------------------------------------------------------------------------

maintenance_enabled := cfg.enabled
mode_resolved := m {
  m := cfg.mode
} else := "deny-writes"

cfg := c {
  c := input.config.maintenance
} else := {
  "enabled": false,
  "mode": "deny-writes",
  "exempt_roles": [],
  "exempt_paths": ["/healthz","/readyz","/metrics"],
  "windows": []
}

# -----------------------------------------------------------------------------
# Определение активности окна обслуживания
# -----------------------------------------------------------------------------

maintenance_active := true {
  maintenance_enabled
  in_any_window
}

in_any_window {
  some i
  w := cfg.windows[i]
  in_window(w)
}

in_window(w) {
  w.type == "fixed"
  now := now_ns()
  start := time.parse_rfc3339_ns(w.start)
  end := time.parse_rfc3339_ns(w.end)
  start <= now
  now < end
}

in_window(w) {
  w.type == "weekly"
  # Требуются weekday и mins_local от интеграции
  wd := lower_weekday()
  mins := local_minutes()
  day_included(w, wd)
  start := w.start_min
  end := w.end_min
  start <= mins
  mins < end
}

day_included(w, wd) {
  some j
  w.days[j] == wd
}

# -----------------------------------------------------------------------------
# Метод, путь, исключения, override
# -----------------------------------------------------------------------------

method := m { m := input.request.method } else := ""

# write-методы
is_write_method {
  re_match("(?i)^(post|put|patch|delete)$", method)
}

# read-only методы
is_read_method {
  re_match("(?i)^(get|head|options)$", method)
}

# Преобразуем path-массив в строку "/a/b/c"
path_str := p {
  segments := input.request.path
  p := "/" + concat("/", segments)
} else := "/"

# Явные исключения путей из конфигурации + стандартные безопасные префиксы
is_exempt_path {
  some i
  cfg.exempt_paths[i] == path_str
} else {
  startswith(path_str, "/docs")
} else {
  path_str == "/openapi.json"
} else {
  startswith(path_str, "/redoc")
}

# Исключение по роли
has_exempt_role {
  some i, j
  cfg.exempt_roles[i] == input.auth.roles[j]
}

# Override: через админ-флаг, скоуп или заголовок
has_override {
  input.auth.is_admin == true
} else {
  some i
  input.auth.scopes[i] == "maintenance:override"
} else {
  hdr := input.request.headers["x-maintenance-bypass"]
  hdr == "1"
} else {
  hdr2 := input.request.headers["X-Maintenance-Bypass"]
  hdr2 == "1"
}

# -----------------------------------------------------------------------------
# Вспомогательные функции времени/строк
# -----------------------------------------------------------------------------

# now в наносекундах из input или системный
now_ns() := n {
  n := input.request.now_ns
} else := n {
  # Приоритет: request.time RFC3339
  t := input.request.time
  n := time.parse_rfc3339_ns(t)
} else := n {
  # Fallback: текущее системное время OPA
  n := time.now_ns()
}

# День недели из input (ожидается "mon".."sun")
lower_weekday() := wd {
  wd := input.request.weekday
} else := "?"

# Местные минуты от полуночи (из input)
local_minutes() := m {
  m := input.request.mins_local
}

# -----------------------------------------------------------------------------
# Безопасные дефолты: если weekly окна сконфигурированы,
# но нет необходимых полей (weekday/mins_local),
# политика НЕ активирует блокировку по weekly окнам.
# -----------------------------------------------------------------------------

# Если тип=weekly, а контекст времени неполный — in_window(w) не срабатывает,
# так как lower_weekday() == "?" или отсутствуют mins_local.
# Это предотвращает ложные срабатывания при некорректной интеграции.

# -----------------------------------------------------------------------------
# Совместимый boolean-флаг «в read-only сейчас» (удобно для маршрутизации логики на стороне сервиса)
# -----------------------------------------------------------------------------
readonly_now := true {
  maintenance_enabled
  maintenance_active
  mode_resolved != "full-freeze"
}
