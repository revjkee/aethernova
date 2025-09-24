package ztc.policies.risk_mfa

# Open Policy Agent / Rego — риск-ориентированная MFA-политика.
# Вход (схема усечена; поля опциональны):
# input := {
#   "now": 1699999999,                       # epoch seconds (предпочтительно задавать извне для детерминизма)
#   "user": {
#     "id": "...", "groups": ["employees"], "risk_level": "low|medium|high",
#     "risk_score": 0..100, "mfa": {"methods": ["webauthn_platform","webauthn_roaming","totp","sms"]},
#     "roles": ["admin","devops"], "tenant": "example"
#   },
#   "resource": {"id":"svc-1","sensitivity":"low|medium|high","scope":["prod","payments"]},
#   "session": {
#     "previous_failures": 0, "velocity": {"logins_1h": 1},
#     "last_mfa_ts": 1699900000, "binding": {"cookie": true, "client_cert": true}
#   },
#   "network": {
#     "ip":"203.0.113.10","country":"SE","asn":12345,
#     "reputation":{"score":0..100,"denylist":false},
#     "anonymous":{"tor":false,"vpn":false,"proxy":false}
#   },
#   "geo": {"city":"Stockholm","country":"SE"},
#   "risk": {"impossible_travel": false, "travel": {"speed_kmh": 0}},
#   "device": {
#     "ownership":"corporate|byod","platform":"windows|macos|linux|ios|android",
#     "posture":{"hard_fail":false,"score":0..100}, "first_seen_age_days": 90,
#     "mTLS":{"present": true, "eku_clientAuth": true},
#     "mfa":{"capabilities": ["webauthn_platform","webauthn_roaming"]}
#   }
# }

import future.keywords.every
import future.keywords.in

default decision := {
  "action": "allow",
  "mfa": {"required": false, "level": "none", "methods": [], "reasons": []},
  "risk": {"score": 0, "reasons": []},
  "ttl_seconds": settings.default_ttl
}

# -----------------------
# Настройки (можно вынести в data.zero_trust.rbmfa)
# -----------------------

settings := data.zero_trust.rbmfa.with_default({
  "thresholds": {"medium": 40, "high": 80, "hard_deny": 95},
  "weights": {
    "new_device": 20, "anon_network": 35, "asn_risky": 25, "ip_rep_low": 30, "ip_rep_mid": 10,
    "impossible_travel": 40, "velocity": 20, "prev_fail": 10, "byod": 10,
    "posture_low": 25, "posture_mid": 10, "user_risk_med": 20, "user_risk_high": 40,
    "sensitivity_bonus_mtls": -25, "posture_strong_bonus": -15
  },
  "deny": {
    "countries": ["RU","KP","IR"],              # пример
    "asn_deny": [9009, 12389],                   # пример
    "iprep_black_cutoff": 20
  },
  "risk": {"new_device_window_days": 14, "impossible_speed_kmh": 900},
  "grace": {"mfa_recent_sec": 86400},
  "methods": {
    "preferences": ["webauthn_platform","webauthn_roaming","totp","oath_hotp","push"],
    "phishing_resistant": ["webauthn_platform","webauthn_roaming"],
    "allow_sms": false
  },
  "policy": {
    "require_phish_resistant_for_high": true,
    "require_mtls_for_high_resources": true
  },
  "ttls": {"allow": 300, "step_up": 120, "deny": 30},
  "default_ttl": 120
})

# Позволяет переопределять часть настроек через data.zero_trust.rbmfa
with_default(base) = merged {
  some _
  merged := (is_object(data.zero_trust.rbmfa) ? object.union(base, data.zero_trust.rbmfa) : base)
}

# -----------------------
# Предикаты и вспом. функции
# -----------------------

now := (is_number(input.now) ? input.now : time.now_ns() / 1000000000)

is_admin := "admin" in input.user.roles

country := lower(input.network.country)
asn := input.network.asn

is_banned_country := country != "" and country in settings.deny.countries
is_asn_denied := is_number(asn) and asn in settings.deny.asn_deny

is_anonymous_network := any_true([get(input.network.anonymous.tor), get(input.network.anonymous.vpn), get(input.network.anonymous.proxy)])

iprep := getn(input.network.reputation.score, 100)
ip_on_deny := get(input.network.reputation.denylist)
iprep_black := iprep <= settings.deny.iprep_black_cutoff

impossible_travel := bool_or(get(input.risk.impossible_travel), (getn(input.risk.travel.speed_kmh, 0) > settings.risk.impossible_speed_kmh))

prev_fails := getn(input.session.previous_failures, 0)
velocity_logins := getn(input.session.velocity.logins_1h, 0)

new_device_window := settings.risk.new_device_window_days
is_new_device := is_number(input.device.first_seen_age_days) and input.device.first_seen_age_days <= new_device_window

byod := input.device.ownership == "byod"

posture_hard_fail := bool_or(get(input.device.posture.hard_fail), false)
posture_score := getn(input.device.posture.score, 0)
posture_low := posture_score > 0 and posture_score < 60
posture_mid := posture_score >= 60 and posture_score < 80
posture_strong := posture_score >= 90

mtls_present := bool_and(get(input.device.mTLS.present), get(input.device.mTLS.eku_clientAuth))

user_risk_level := lower(gets(input.user.risk_level, "low"))
user_risk_score := getn(input.user.risk_score, 0)

sensitivity := lower(gets(input.resource.sensitivity, "low"))

# Грейс по недавнему MFA
mfa_recent := some ts {
  ts := getn(input.session.last_mfa_ts, 0)
  ts > 0
  now - ts <= settings.grace.mfa_recent_sec
}

# Веса/баллы
w(cond, weight) = weight { cond }
w(cond, weight) = 0 { not cond }

credit(cond, v) = (-1 * v) { cond }
credit(cond, v) = 0 { not cond }

# Удобные геттеры
get(x) := false { x == null } else := x { x != null }
getn(x, d) := d { not is_number(x) } else := x { is_number(x) }
gets(x, d) := d { not is_string(x) } else := x { is_string(x) }

bool_or(a, b) := true { a } else := true { b } else := false { not a; not b }
bool_and(a, b) := true { a; b } else := false { true }

# -----------------------
# Подсчёт риска
# -----------------------

risk_score := sum([
  w(is_new_device, settings.weights.new_device),
  w(is_anonymous_network, settings.weights.anon_network),
  w(iprep < 50, settings.weights.ip_rep_mid),
  w(iprep < 30, settings.weights.ip_rep_low),
  w(impossible_travel, settings.weights.impossible_travel),
  w(velocity_logins >= 10, settings.weights.velocity),
  w(prev_fails >= 3, settings.weights.prev_fail),
  w(byod, settings.weights.byod),
  w(posture_low, settings.weights.posture_low),
  w(posture_mid, settings.weights.posture_mid),
  w(user_risk_level == "medium" or (user_risk_score >= 40 and user_risk_score < 80), settings.weights.user_risk_med),
  w(user_risk_level == "high" or user_risk_score >= 80, settings.weights.user_risk_high),
  credit(mtls_present and posture_strong, settings.weights.sensitivity_bonus_mtls),
  credit(posture_strong, settings.weights.posture_strong_bonus)
])

# Причины (для аудита)
risk_reasons[r] {
  r := "NEW_DEVICE"
  is_new_device
}
risk_reasons[r] {
  r := "ANON_NETWORK"
  is_anonymous_network
}
risk_reasons[r] {
  r := "IP_REP_LOW"
  iprep < 50
}
risk_reasons[r] {
  r := "IMPOSSIBLE_TRAVEL"
  impossible_travel
}
risk_reasons[r] {
  r := "VELOCITY"
  velocity_logins >= 10
}
risk_reasons[r] {
  r := "PREV_FAILS"
  prev_fails >= 3
}
risk_reasons[r] {
  r := "BYOD"
  byod
}
risk_reasons[r] {
  r := "POSTURE_LOW"
  posture_low
}
risk_reasons[r] {
  r := "POSTURE_MID"
  posture_mid
}
risk_reasons[r] {
  r := "USER_RISK"
  user_risk_level == "medium" or user_risk_level == "high" or user_risk_score >= 40
}
risk_reasons[r] {
  r := "BONUS_MTLS_STRONG"
  mtls_present
  posture_strong
}

# -----------------------
# Жёсткие блокировки (hard-fail)
# -----------------------

hard_fail_reasons[r] {
  r := "POSTURE_HARD_FAIL"
  posture_hard_fail
}
hard_fail_reasons[r] {
  r := "BANNED_COUNTRY"
  is_banned_country
}
hard_fail_reasons[r] {
  r := "ASN_DENY"
  is_asn_denied
}
hard_fail_reasons[r] {
  r := "IP_DENY"
  ip_on_deny
}
hard_fail_reasons[r] {
  r := "IP_REP_BLACK"
  iprep_black
}
hard_fail_reasons[r] {
  r := "RISK_EXTREME"
  risk_score >= settings.thresholds.hard_deny
}
hard_fail := count({r | r := hard_fail_reasons[r]}) > 0

# -----------------------
# Требование MFA / Step-up
# -----------------------

risk_medium := risk_score >= settings.thresholds.medium
risk_high := risk_score >= settings.thresholds.high

sensitive_resource := sensitivity == "high" or ("prod" in input.resource.scope)

require_mtls_for_high := settings.policy.require_mtls_for_high_resources and sensitive_resource

# Если ресурс высокорисковый, требуем mTLS как pre-check
mtls_mandatory_fail := require_mtls_for_high and not mtls_present

# Grace: при низком риске и недавнем MFA разрешаем без step-up
grace_ok := mfa_recent and not risk_high and not hard_fail

# Требование step-up MFA
step_up := not hard_fail and not grace_ok and (
  risk_medium or
  is_new_device or
  is_anonymous_network or
  impossible_travel or
  (prev_fails >= 3) or
  (sensitive_resource and not mtls_present)
)

# Уровень MFA и допустимые методы
phish_resistant_required := (settings.policy.require_phish_resistant_for_high and risk_high) or sensitive_resource

available_methods := {m |
  m := x
  x := input.user.mfa.methods[_]
} union {m |
  m := y
  y := input.device.mfa.capabilities[_]
}

# Блокируем SMS по умолчанию
allowed_methods_base := {m |
  m := settings.methods.preferences[_]
  not (m == "sms" and not settings.methods.allow_sms)
}

allowed_methods := {m |
  m := x
  x := allowed_methods_base[_]
  x in available_methods
}

allowed_phish_resistant := {m |
  m := x
  x := settings.methods.phishing_resistant[_]
  x in allowed_methods
}

method_candidates := [m |
  m := settings.methods.preferences[i]
  m in allowed_methods
]

method_candidates_pr := [m |
  m := settings.methods.preferences[i]
  m in allowed_phish_resistant
]

chosen_methods := (phish_resistant_required ? method_candidates_pr : method_candidates)

no_compatible_mfa := step_up and count(chosen_methods) == 0

# -----------------------
# Финальное решение
# -----------------------

deny := hard_fail or mtls_mandatory_fail or no_compatible_mfa

allow := not deny and not step_up

mfa_payload := {
  "required": step_up,
  "level": (phish_resistant_required ? "high" : (risk_medium ? "medium" : "low")),
  "methods": chosen_methods,
  "reasons": array.sort([r | r := risk_reasons[r]])
}

deny_reasons := array.sort(
  [r | r := hard_fail_reasons[r]]
  ++ (mtls_mandatory_fail ? ["MTLS_REQUIRED_FOR_RESOURCE"] : [])
  ++ (no_compatible_mfa ? ["NO_COMPATIBLE_MFA"] : [])
)

# TTL: короче при deny, средний при step_up, длиннее при allow
ttl := (deny ? settings.ttls.deny : (step_up ? settings.ttls.step_up : settings.ttls.allow))

decision := {
  "action": (deny ? "deny" : (step_up ? "step_up" : "allow")),
  "mfa": (deny ? {"required": true, "level": mfa_payload.level, "methods": chosen_methods, "reasons": deny_reasons} : mfa_payload),
  "risk": {"score": risk_score, "reasons": array.sort([r | r := risk_reasons[r]])},
  "ttl_seconds": ttl,
  "audit": {
    "user": gets(input.user.id, ""),
    "resource": gets(input.resource.id, ""),
    "country": country,
    "asn": asn,
    "iprep": iprep,
    "sensitivity": sensitivity,
    "mtls": mtls_present,
    "posture_score": posture_score
  }
}
