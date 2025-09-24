package zerotrust.policies.risk_based_mfa

# Политика риск-ориентированного MFA для Zero Trust.
# Версия: 1.1.0
# Вход (input) ожидается в форме:
# {
#   "subject": {
#     "id": "u-123",
#     "role": "admin|engineer|employee|service",
#     "groups": ["gA","gB"],
#     "status": "active|suspended",
#     "mfa_enrolled_methods": ["webauthn","totp","push"],
#     "break_glass": false
#   },
#   "device": {
#     "managed": true,
#     "trust_level": "high|medium|low",
#     "compliant": true
#   },
#   "session": {
#     "age_seconds": 120,
#     "auth_strength": ["password","webauthn","mfa"], # пройденные факторы
#     "mfa_recent_seconds": 90
#   },
#   "context": {
#     "ip": "203.0.113.10",
#     "ip_risk": "low|medium|high|abuse|botnet|blacklist",
#     "asn": 64500,
#     "geo": {"country":"SE","city":"Stockholm"},
#     "prev_geo": {"country":"SE","city":"Stockholm","age_seconds": 3600},
#     "hour_utc": 10,
#     "weekday": 4,
#     "user_agent": "Mozilla/5.0"
#   },
#   "resource": {
#     "id": "app-xyz",
#     "action": "read|write|admin",
#     "sensitivity": "public|internal|confidential|restricted"
#   },
#   "trace": {"request_id":"...","tenant_id":"..."}
# }
#
# Выход (decision):
# {
#   "action": "allow|deny",
#   "risk_score": 0..100,
#   "reasons": ["..."],
#   "obligations": {
#     "mfa": {
#       "required": true|false,
#       "level": "low|medium|high|none",
#       "methods": ["webauthn","totp","push"],
#       "ttl_seconds": 300
#     }
#   },
#   "ttl_seconds": 300,
#   "trace": {"request_id":"...","tenant_id":"..."}
# }

default decision := {
  "action": "deny",
  "risk_score": 100,
  "reasons": ["policy_default_deny"],
  "obligations": {"mfa": {"required": true, "level": "high", "methods": [], "ttl_seconds": 300}},
  "ttl_seconds": 60,
  "trace": trace_fields
}

# -----------------------------
# Главная точка принятия решения
# -----------------------------
decision := out {
  not hard_deny
  rs := risk_score
  lvl := mfa_level(rs)
  req := mfa_required(rs)
  mth := select_methods(lvl)
  ttl := mfa_ttl(lvl)
  reasons := decision_reasons(rs, req, lvl)

  out := {
    "action": action_value(req),          # allow, но с обязательством MFA при необходимости
    "risk_score": rs,
    "reasons": reasons,
    "obligations": {
      "mfa": {
        "required": req,
        "level": lvl,
        "methods": mth,
        "ttl_seconds": ttl
      }
    },
    "ttl_seconds": session_ttl(rs),
    "trace": trace_fields
  }
}

# Жёсткий отказ (до расчёта MFA)
hard_deny {
  subj_status == "suspended"
}
hard_deny {
  ip_risk in {"abuse", "botnet", "blacklist"}
}
hard_deny {
  resource_sensitivity == "restricted"
  not device_managed
}
hard_deny {
  resource_action == "admin"
  not device_compliant
}

# -----------------------------
# Источники и безопасные геттеры
# -----------------------------
subj := object.get(input, "subject", {})
subj_role := object.get(subj, "role", "employee")
subj_groups := object.get(subj, "groups", [])
subj_status := object.get(subj, "status", "active")
subj_break_glass := object.get(subj, "break_glass", false)
subj_methods := object.get(subj, "mfa_enrolled_methods", [])

dev := object.get(input, "device", {})
device_managed := object.get(dev, "managed", false)
device_trust := object.get(dev, "trust_level", "low")
device_compliant := object.get(dev, "compliant", false)

sess := object.get(input, "session", {})
sess_age := to_number(object.get(sess, "age_seconds", 0))
sess_auth := object.get(sess, "auth_strength", [])
sess_mfa_recent := to_number(object.get(sess, "mfa_recent_seconds", 10_000))

ctx := object.get(input, "context", {})
ip_risk := object.get(ctx, "ip_risk", "low")
asn := to_number(object.get(ctx, "asn", 0))
geo := object.get(ctx, "geo", {})
prev_geo := object.get(ctx, "prev_geo", {})
hour_utc := to_number(object.get(ctx, "hour_utc", 12))
weekday := to_number(object.get(ctx, "weekday", 3))

res := object.get(input, "resource", {})
resource_sensitivity := object.get(res, "sensitivity", "internal")
resource_action := object.get(res, "action", "read")

trace_fields := {
  "request_id": object.get(object.get(input, "trace", {}), "request_id", ""),
  "tenant_id":  object.get(object.get(input, "trace", {}), "tenant_id", "")
}

# -----------------------------
# Риск‑скоринг (0..100)
# -----------------------------
risk_score := min([100, base + adj]) {
  base := base_risk
  adj := sum([role_risk, sensitivity_risk, device_risk, ip_rep_risk, geo_risk, time_risk, session_risk])
}

# Базовый риск (низкий дефолт)
base_risk := 5

# Роль/привилегии
role_risk := r {
  subj_role == "admin"; r := 25
} else := r {
  subj_role == "engineer"; r := 10
} else := r {
  subj_role == "service"; r := 8
} else := 0

# Чувствительность ресурса
sensitivity_risk := r {
  resource_sensitivity == "restricted"; r := 35
} else := r {
  resource_sensitivity == "confidential"; r := 20
} else := r {
  resource_sensitivity == "internal"; r := 5
} else := 0

# Доверие к устройству
device_risk := r {
  not device_managed; r := 15
} else := r {
  device_trust == "low"; r := 10
} else := r {
  device_trust == "medium"; r := 5
} else := 0

# IP‑репутация
ip_rep_risk := r {
  ip_risk == "high"; r := 25
} else := r {
  ip_risk == "medium"; r := 12
} else := 0

# Гео‑аномалии (упрощённо: новая страна быстро -> "impossible travel")
geo_risk := r {
  country := object.get(geo, "country", "")
  prev_country := object.get(prev_geo, "country", country)
  prev_age := to_number(object.get(prev_geo, "age_seconds", 86_400))
  country != "" ; prev_country != "" ; country != prev_country ; prev_age < 18_000
  r := 20
} else := r {
  # Новая страна без скорости
  country := object.get(geo, "country", "")
  prev_country := object.get(prev_geo, "country", country)
  country != prev_country
  r := 10
} else := 0

# Время суток (ночные часы — общий риск)
time_risk := r {
  hour_utc >= 0 ; hour_utc <= 5
  r := 8
} else := 0

# Сессия: давность MFA и слабая аутентификация
session_risk := r {
  not mfa_satisfied_recent
  "webauthn" notin sess_auth
  r := 12
} else := r {
  not mfa_satisfied_recent
  r := 8
} else := 0

mfa_satisfied_recent {
  sess_mfa_recent <= 300   # 5 минут
}

# -----------------------------
# Пороговая логика MFA
# -----------------------------
# Исключения (минимизация препятствий)
mfa_exempt {
  subj_break_glass
}
mfa_exempt {
  subj_role == "service"
  resource_action != "admin"
  device_managed
  ip_risk == "low"
}

# Требуется ли MFA
mfa_required(rs) := false {
  mfa_exempt
  rs < 70
  mfa_satisfied_recent
  strong_session
}
mfa_required(rs) := true {
  not mfa_exempt
  rs >= 40
}
mfa_required(rs) := true {
  not mfa_exempt
  resource_sensitivity in {"confidential","restricted"}
}
mfa_required(rs) := true {
  not mfa_exempt
  resource_action == "admin"
}
# Иначе не требуется
mfa_required(rs) := false {
  rs < 40
  mfa_satisfied_recent
  strong_session
}

strong_session {
  "webauthn" in sess_auth
} else {
  "mfa" in sess_auth
}

# Уровень MFA по риску/контексту
mfa_level(rs) := "high" {
  rs >= 70
} else := "medium" {
  rs >= 40
} else := "low" {
  rs >= 20
} else := "none"

# TTL требования MFA (step‑up) по уровню
mfa_ttl(level) := 120 { level == "high" }
mfa_ttl(level) := 300 { level == "medium" }
mfa_ttl(level) := 600 { level == "low" }
mfa_ttl(level) := 0   { level == "none" }

# Итоговый action
action_value(req) := "allow" {
  not req
}
action_value(req) := "allow" {
  req
  # PDP отдаёт allow + obligation: клиент должен предъявить MFA в течение TTL
}

# Выбор методов MFA по уровню и доступности у пользователя
select_methods(level) := methods {
  preferred := preferred_methods
  some arr
  methods := {
    "high":   choose(preferred, ["webauthn","totp"]),
    "medium": choose(preferred, ["webauthn","push","totp"]),
    "low":    choose(preferred, ["push","totp","webauthn"]),
    "none":   []
  }[level]
}

preferred_methods := pm {
  # Приоритет: webauthn/passkey > totp > push
  base := ["webauthn","totp","push"]
  pm := [m | some i; m := base[i]; m in subj_methods]
}

# Берём упорядоченный список кандидатов, фильтруем по доступному у субъекта
choose(avail, candidates) := out {
  out := [m | m := candidates[_]; m in avail]
}

# -----------------------------
# Причины (для аудита и объяснимости)
# -----------------------------
decision_reasons(rs, req, lvl) := reasons {
  base := set()
  reasons_set := base
    ∪ ({ "ip_reputation_high" | ip_risk == "high" })
    ∪ ({ "geo_change_fast" | geo_fast_change })
    ∪ ({ "device_unmanaged" | not device_managed })
    ∪ ({ "device_low_trust" | device_trust == "low" })
    ∪ ({ "resource_confidential" | resource_sensitivity == "confidential" })
    ∪ ({ "resource_restricted" | resource_sensitivity == "restricted" })
    ∪ ({ "role_admin" | subj_role == "admin" })
    ∪ ({ "time_night" | hour_utc >= 0 ; hour_utc <= 5 })
    ∪ ({ "session_weak_or_stale" | not mfa_satisfied_recent or not strong_session })
  reasons_full := array.concat(
    ["risk_score=" ++ to_string(rs), "mfa_required=" ++ to_string(req), "mfa_level=" ++ lvl],
    sort(reasons_set)
  )
  reasons := reasons_full
}

geo_fast_change {
  country := object.get(geo, "country", "")
  prev_country := object.get(prev_geo, "country", country)
  prev_age := to_number(object.get(prev_geo, "age_seconds", 86_400))
  country != "" ; prev_country != "" ; country != prev_country ; prev_age < 18_000
}

# -----------------------------
# Вспомогательные
# -----------------------------
to_number(x) := n {
  n := to_number_impl(x)
}

to_number_impl(x) = n {
  n := x
  is_number(x)
} else = n {
  n := to_number_builtin(x)
}

to_number_builtin(x) = n {
  n := to_number_str(x)
} else = 0

to_number_str(x) = n {
  s := sprintf("%v", [x])
  n := to_number_str2(s)
}

to_number_str2(s) = n {
  # попытка парсинга, при неудаче 0
  n := number(s)
} else = 0

session_ttl(rs) := 300 { rs < 40 }
session_ttl(rs) := 180 { rs >= 40; rs < 70 }
session_ttl(rs) := 120 { rs >= 70 }
