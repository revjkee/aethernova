# policy-core/configs/policies/rego/geo_fencing.rego
# Статус: НЕ ВЕРИФИЦИРОВАНО — значения входных полей и структура data.* зависят от вашей реализации.
# Версия политики: v1.2.0

package policy_core.geo_fencing.v1

default allow := false
default obligations := []
default reasons := {}
default decision := {
  "allow": allow,
  "obligations": obligations,
  "reasons": reasons,
  "meta": {
    "policy_id": "policy-core.geo-fencing",
    "policy_version": "v1.2.0"
  }
}

################################################################################
# ВХОДНЫЕ ДАННЫЕ (ОЖИДАЕМАЯ СХЕМА)
#
# input: {
#   "subject": {
#     "id": "user-123",
#     "roles": ["analyst", "operator"],
#     "mfa": true,
#     "device": {"platform": "ios", "jailbroken": false},
#     "country_code": "SE"
#   },
#   "resource": {
#     "type": "policy",
#     "action": "read",
#     "id": "policy:abc",
#     "required_geo_zone": "core-eu"   # опционально: конкретная зона
#   },
#   "env": {
#     "now": "2025-08-28T06:12:00Z",    # RFC3339
#     "ip": "203.0.113.10",
#     "country_code": "SE",
#     "network": {"vpn": false, "tor": false, "asn": 12345},
#     "geolocation": {"lat": 59.3293, "lon": 18.0686, "accuracy_m": 50}
#   }
# }
#
# data.geo.zones: {
#   "core-eu": {
#     "active": true,
#     "shape": {"type": "polygon", "points": [[lat,lon], ...]},
#     # или: "shape": {"type": "circle", "center": [lat,lon], "radius_m": 50000}
#     "allowed_countries": ["SE","NO","FI","DK","DE"],
#     "time_windows": [
#       {"days": ["Mon","Tue","Wed","Thu","Fri"], "start": "08:00", "end": "20:00", "tz_offset_min": 0}
#     ],
#     "restricted_roles": ["external"],
#     "exceptions": {
#       "subjects": ["user-override-1"],
#       "resources": ["policy:public"]
#     },
#     "require_mfa": true,
#     "risk": {"threshold": 60}  # 0..100
#   }
# }
################################################################################

############################
# ПЕРВИЧНАЯ ВАЛИДАЦИЯ ВХОДА
############################

valid_input {
  input.subject.id
  input.subject.roles
  input.env.now
  input.env.geolocation.lat
  input.env.geolocation.lon
  input.resource.type
  input.resource.action
}

# Если вход невалиден — формируем причину
reasons["invalid_input"] := "Missing required fields" {
  not valid_input
}

############################
# ТЕКУЩЕЕ ВРЕМЯ (ns, UTC)
############################

now_ns := t {
  parsed := time.parse_rfc3339_ns(input.env.now)
  t := parsed
}

#################################
# РИСК-ОЦЕНКА (0..100, чем выше — тем рискованнее)
#################################

risk_base := r {
  not valid_input
  r := 100
}

risk_base := r {
  valid_input
  cc_subject := lower(input.subject.country_code)
  cc_env := lower(input.env.country_code)
  vpn := bool(input.env.network.vpn)
  tor := bool(input.env.network.tor)
  jail := bool(input.subject.device.jailbroken)

  # Базовая шкала
  mismatch := if cc_subject != "" and cc_env != "" and cc_subject != cc_env then 20 else 0
  vpn_w := if vpn then 25 else 0
  tor_w := if tor then 50 else 0
  jail_w := if jail then 30 else 0

  # Низкая точность геолокации повышает риск
  acc := number_default(input.env.geolocation.accuracy_m, 1000)
  acc_penalty := if acc > 1000 then 10 else 0

  r := clamp(mismatch + vpn_w + tor_w + jail_w + acc_penalty, 0, 100)
}

############################
# СООТНЕСЕНИЕ С ЗОНАМИ
############################

# Собираем кандидатные зоны: активные и подходящие по требованию ресурса (если указано)
candidate_zones[zid] := z {
  data.geo.zones[zid] == z
  z.active == true
  # Если ресурс требует конкретную зону — фильтруем
  some req
  req := input.resource.required_geo_zone
  req == null; true
} {
  data.geo.zones[input.resource.required_geo_zone] == z
  z.active == true
  zid := input.resource.required_geo_zone
}

# Проверка: субъект находится внутри геозоны (по координатам env.geolocation)
inside_zone(z) {
  z.shape.type == "polygon"
  pts := ensure_polygon(z.shape.points)
  point_in_polygon([input.env.geolocation.lat, input.env.geolocation.lon], pts)
}
inside_zone(z) {
  z.shape.type == "circle"
  center := z.shape.center
  radius := number_default(z.shape.radius_m, 0)
  haversine_meters(center, [input.env.geolocation.lat, input.env.geolocation.lon]) <= radius
}

# Страна разрешена (если указаны allowed_countries)
country_ok(z) {
  not z.allowed_countries
}
country_ok(z) {
  some _; lower(input.env.country_code) == lower(z.allowed_countries[_])
}

# Роли не запрещены (restricted_roles)
roles_ok(z) {
  not z.restricted_roles
}
roles_ok(z) {
  not any_intersect(input.subject.roles, z.restricted_roles)
}

# Исключения: субъект или ресурс в белом списке
exception_ok(z) {
  z.exceptions.subjects[_] == input.subject.id
} {
  z.exceptions.resources[_] == input.resource.id
}

# Временные окна допуска (если заданы)
time_ok(z) {
  not z.time_windows
}
time_ok(z) {
  some i
  win := z.time_windows[i]
  # День недели
  dow_ok := not win.days or day_in_window(now_ns, win.days, number_default(win.tz_offset_min, 0))
  # Часы
  hh_ok := time_in_window(now_ns, win.start, win.end, number_default(win.tz_offset_min, 0))
  dow_ok
  hh_ok
}

# Требование MFA (если зона требует и риск выше порога)
need_mfa(z) {
  bool_default(z.require_mfa, false)
  threshold := number_default(z.risk.threshold, 50)
  risk_base >= threshold
}

############################
# ОСНОВНАЯ ЛОГИКА РЕШЕНИЯ
############################

# Жёсткие отсечки
reasons["tor_blocked"] := "Access via TOR is forbidden" {
  bool(input.env.network.tor)
}

# Кандидатная зона, где все проверки проходят
valid_zone[zid] {
  zid := candidate
  z := candidate_zones[candidate]
  inside_zone(z)
  country_ok(z)
  roles_ok(z)
  time_ok(z)
}

# Обязательства (обязанности) — например, требование MFA
obligations contains {"type": "require_mfa", "reason": "High risk in zone"} {
  some zid
  z := candidate_zones[zid]
  valid_zone[zid]
  need_mfa(z)
  not bool(input.subject.mfa)
}

# Позволяем, если есть хотя бы одна валидная зона и нет блокирующих причин
allow {
  valid_input
  count({zid | valid_zone[zid]}) > 0
  # Если требуется MFA — она должна быть выполнена или добавлена как обязательство,
  # но в строгом режиме можно потребовать фактическое наличие MFA.
  not reasons["tor_blocked"]
}

# Причины отказа — детальная диагностика
reasons["outside_zone"] := "Coordinates are outside all active geo zones" {
  valid_input
  count({zid | candidate_zones[zid]}) > 0
  count({zid | valid_zone[zid]}) == 0
}

reasons["country_denied"] := "Country is not permitted for the zone" {
  valid_input
  some zid
  z := candidate_zones[zid]
  not country_ok(z)
}

reasons["role_restricted"] := "Role is restricted in the zone" {
  valid_input
  some zid
  z := candidate_zones[zid]
  not roles_ok(z)
}

reasons["time_window_denied"] := "Access outside allowed time windows" {
  valid_input
  some zid
  z := candidate_zones[zid]
  not time_ok(z)
}

# Исключение может переопределить отказ
allow {
  valid_input
  some zid
  z := candidate_zones[zid]
  exception_ok(z)
}

# Расширенная мета-информация решения
decision := d {
  d := {
    "allow": allow,
    "obligations": obligations,
    "reasons": reasons,
    "meta": {
      "policy_id": "policy-core.geo-fencing",
      "policy_version": "v1.2.0",
      "risk": risk_base,
      "zones_considered": {zid | candidate_zones[zid]},
      "zones_valid": {zid | valid_zone[zid]}
    }
  }
}

##########################################
# УТИЛИТЫ: геометрия, время, типобезопасность
##########################################

# Преобразование списка точек к валидному полигону (минимум 3 точки)
ensure_polygon(pts) = out {
  count(pts) >= 3
  out := pts
}

# Точка внутри полигона (ray casting), формат: point = [lat, lon], poly = [[lat,lon],...]
point_in_polygon(point, poly) {
  crossings := count({i |
    i := indices(poly)[_]
    j := (i + 1) % count(poly)
    yi := poly[i][0]; xi := poly[i][1]
    yj := poly[j][0]; xj := poly[j][1]
    # Проверяем пересечение луча по широте с ребром
    ((xi > point[1]) != (xj > point[1])) &&
    (point[0] < (yj - yi) * (point[1] - xi) / (xj - xi + 0.000000001) + yi)
  })
  # Нечётное число пересечений — внутри
  mod(crossings, 2) == 1
}

# Haversine дистанция в метрах между [lat,lon]
haversine_meters(a, b) = d {
  lat1 := rad(a[0]); lon1 := rad(a[1])
  lat2 := rad(b[0]); lon2 := rad(b[1])
  dlat := lat2 - lat1
  dlon := lon2 - lon1
  h := sin(dlat/2)^2 + cos(lat1) * cos(lat2) * sin(dlon/2)^2
  r := 6371000 # средний радиус Земли, м
  d := 2 * r * asin(min(1, sqrt(h)))
}

rad(x) = y { y := x * 3.141592653589793 / 180 }

# Время: проверка дня недели
day_in_window(ns, days, tz_off_min) {
  # локальное время с учётом сдвига (в минутах)
  ns_loc := ns + int(tz_off_min) * 60 * 1000000000
  w := time.weekday(ns_loc)  # 0..6 (зависит от реализации OPA)
  day := weekday_name(w)
  some i; day == days[i]
}

weekday_name(w) = d {
  mapping := {"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed", "4": "Thu", "5": "Fri", "6": "Sat"}
  d := mapping[tostring(w)]
}

# Время: проверка попадания в окно часов "HH:MM".."HH:MM" с учётом tz_offset_min
time_in_window(ns, start_s, end_s, tz_off_min) {
  ns_loc := ns + int(tz_off_min) * 60 * 1000000000
  clk := time.clock(ns_loc)  # [hh, mm, ss]
  hh := clk[0]; mm := clk[1]
  cur := hh*60 + mm
  s := parse_hhmm(start_s)
  e := parse_hhmm(end_s)
  # Окно может переходить через полуночь
  (s <= e and cur >= s and cur < e) or
  (s > e and (cur >= s or cur < e))
}

parse_hhmm(s) = m {
  parts := split(s, ":")
  hh := to_number(parts[0])
  mm := to_number(parts[1])
  m := hh*60 + mm
}

# Безопасные конверсии/значения по умолчанию
to_number(x) = n { n := to_number_internal(x) }
to_number_internal(x) = n { n := x } {
  n := to_number_fallback(x)
}
to_number_fallback(x) = n {
  n := to_number_try(x)
} else = 0

number_default(x, d) = out { out := x } else = d
bool(x) { x == true }
bool_default(x, d) { x == true } else = d

# Пересечение множеств (списков)
any_intersect(xs, ys) {
  some i, j
  xs[i] == ys[j]
}

# mod для целых
mod(a, b) = r {
  r := a - (a / b) * b
}

# min для двух значений
min(a, b) = c { c := a; a <= b } else = b

# clamp
clamp(x, lo, hi) = y {
  y := lo
  x < lo
} else = y {
  y := hi
  x > hi
} else = y {
  y := x
}

# Приведение строк к нижнему регистру (безопасно)
lower(s) = o { o := lower_internal(s) } else = ""
lower_internal(s) = o { o := lower_ascii(s) }

# to_number_try — попытка численной конверсии
to_number_try(x) = n {
  n := to_number_builtin(x)
} else = 0

# Заглушки под встроенные (для совместимости разных версий, если нужно)
lower_ascii(s) = o { o := lower_builtin(s) }
lower_builtin(s) = o { o := lower(s) }  # при необходимости заменить

to_number_builtin(x) = n { n := to_number(x) }  # тождественно

################################################################################
# ПРИМЕЧАНИЯ
# - Политика deny-by-default.
# - Для строгого режима MFA можно изменить правило allow, требуя input.subject.mfa == true.
# - Конфигурация зон (data.geo.zones) управляет формой, странами, окнами времени и порогами риска.
################################################################################
