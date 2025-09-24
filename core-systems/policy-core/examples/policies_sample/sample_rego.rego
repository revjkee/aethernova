package policy_core.examples.policies_sample

# Rego: промышленный пример политики для Policy Core
# Покрывает RBAC+ABAC, route-based свойства, IP/Time/mTLS проверки,
# и формирование обязательств (headers/rate_limit) для PEP.

import future.keywords.in
import future.keywords.every
import input as req
import data

# ---------------------------
# Метаданные политики
# ---------------------------
policy_version := "2025.08.28"
policy_id := "policy-core/sample"
policy_namespace := "default"

# ---------------------------
# Значения по умолчанию (entrypoints)
# ---------------------------
default allow := false
default effect := "deny"
default reasons := {}
default obligations := {}

# ---------------------------
# Главная логика решения
# ---------------------------

# Разрешить, если все проверки прошли
allow {
    checks := {
        "rbac": check_rbac,
        "abac": check_abac,
        "tenant": check_tenant_isolation,
        "route": check_route_policy,
        "ip": check_ip,
        "time": check_time_window,
        "mtls": check_mtls,
    }
    failures := {k | some k; checks[k] == false}
    count(failures) == 0
}

# Эффект
effect := "allow" { allow }
effect := "deny" { not allow }

# Причины отказа (диагностика)
reasons["rbac_failed"] { not check_rbac }
reasons["abac_failed"] { not check_abac }
reasons["tenant_violation"] { not check_tenant_isolation }
reasons["route_unmatched"] { not check_route_policy }
reasons["ip_not_allowed"] { not check_ip }
reasons["outside_time_window"] { not check_time_window }
reasons["mtls_required"] { not check_mtls }

# Обязательства для PEP (заголовки/лимиты/редакции)
obligations := result {
    result := merge_objects(
      default_obligations,
      route_obligations,   # из data.http.routes[].obligations
      rate_limit_obligation # из data.http.routes[].rate_limit
    )
}

# Консолидированное решение (для отладки/логирования)
decision := {
    "policy": {
        "id": policy_id,
        "namespace": policy_namespace,
        "version": policy_version,
    },
    "effect": effect,
    "allow": allow,
    "action": action,
    "route": route_id,
    "reasons": [r | r := reasons[_]],
    "obligations": obligations,
}

# ---------------------------
# RBAC
# ---------------------------

# Пользовательские роли и скоупы
user_roles := {r | r := req.user.roles[_]} default {{}}
user_scopes := {s | s := req.user.scopes[_]} default {{}}

# Действие определяется маршрутом (ниже)
action := route.action

# Админ-скоупы (имя набора можно вынести в data)
admin_scopes := {"admin", "root", "policies:publish"}

# RBAC проходит, если:
#  1) есть админ-скоуп, ИЛИ
#  2) пересекаются роли с требуемыми для action, ИЛИ
#  3) пересекаются скоупы с требуемыми для action
check_rbac {
    count(user_scopes & admin_scopes) > 0
} else {
    required_roles := rbac_required_roles[action]
    count(user_roles & required_roles) > 0
} else {
    required_scopes := rbac_required_scopes[action]
    count(user_scopes & required_scopes) > 0
}

# Требуемые роли/скоупы из data.rbac.bindings / data.rbac.scope_bindings
rbac_required_roles[action] := rs {
    some rs
    rs := {x | x := data.rbac.bindings[action].roles[_]}
} default {{}}

rbac_required_scopes[action] := ss {
    some ss
    ss := {x | x := data.rbac.bindings[action].scopes[_]}
} default {{}}

# ---------------------------
# ABAC (владение/атрибуты)
# ---------------------------

# Изменяющие действия (настраиваемые, можно задавать в data.abac.write_actions)
is_write_action {
    some a
    a := action
    startswith(a, "write.")  # convention: write.* для операций записи
} else {
    data.abac.write_actions[action]
} default {
    # fallback: считаем запрос изменяющим, если метод не в GET/HEAD
    not (upper(req.method) == "GET" or upper(req.method) == "HEAD")
}

# Проверка владельца либо дополнительных атрибутов (например, tags, sensitivity)
check_abac {
    not is_write_action  # чтение — разрешено на основе RBAC/тенанта/маршрута
} else {
    # Для записи владелец должен совпадать ИЛИ пройти политика разрешающих атрибутов
    req.resource.owner == req.user.id
} else {
    allow_by_attributes
}

allow_by_attributes {
    some pol in data.abac.policies
    # пример атрибутного правила: совпадение тега или уровня допуска
    required := pol.required
    # tenant/tag/sensitivity могут быть в req.resource.attributes
    res_attrs := req.resource.attributes
    ok := all_true([
        attr_implies(res_attrs, "tag", required.tag),
        attr_implies(res_attrs, "sensitivity", required.sensitivity),
    ])
    ok
}

attr_implies(attrs, key, required) {
    not required  # нет требования
} else {
    # required может быть скаляром или массивом
    val := attrs[key]
    is_array(required)  => (count({x | x := required[_]; x == val}) > 0 or (is_set(val) and count(required & val) > 0))
    not is_array(required) => val == required
} else = false

# ---------------------------
# Изоляция тенантов
# ---------------------------

check_tenant_isolation {
    # если ресурс/пользователь задают tenant — должны совпасть
    not req.user.tenant
    not req.resource.tenant
} else {
    req.user.tenant == req.resource.tenant
} else {
    # допускается кросс-тенант, если маршрут помечен allow_cross_tenant
    route.allow_cross_tenant == true
}

# ---------------------------
# Политика маршрута (method+path -> route)
# ---------------------------

# Поиск маршрута в data.http.routes по методу и glob-пути
route := r {
    some i
    r := data.http.routes[i]
    upper(req.method) == upper(r.methods[_])
    glob_match(r.path, req.path)
}

route_id := route.id default "unmatched"

# Если маршрут не найден — провал
check_route_policy {
    route.id
}

# ---------------------------
# IP / сеть
# ---------------------------

# Если маршрут задаёт allowlist — IP должен быть в списках
check_ip {
    not route.ip_allowlist
} else {
    remote_ip := coalesce(req.conn.remote_ip, "")
    some cidr in route.ip_allowlist
    net.cidr_contains(cidr, remote_ip)
}

# ---------------------------
# Временное окно (UTC)
# ---------------------------

# В ok, если окно не задано; иначе текущее время UTC внутри [start,end)
check_time_window {
    not route.time_window
} else {
    now := current_time()
    start := parse_hhmm(coalesce(route.time_window.start, "00:00"))
    end := parse_hhmm(coalesce(route.time_window.end, "24:00"))
    time_between(now, start, end)
}

# ---------------------------
# mTLS
# ---------------------------

check_mtls {
    not route.require_mtls
} else {
    req.conn.mtls.present == true
}

# ---------------------------
# Обязательства (headers/rate_limit/редакции)
# ---------------------------

default_obligations := {
    "headers": {
        "x-policy-id": policy_id,
        "x-policy-version": policy_version,
        "x-policy-namespace": policy_namespace,
        "x-action": action,
    } with_correlation
}

with_correlation := out {
    hdr := {}
    cid := req.context.correlation_id
    not cid
    out := hdr
} else := out {
    hdr := {"x-correlation-id": req.context.correlation_id}
    out := hdr
}

# Обязательства из маршрута (headers/extra)
route_obligations := out {
    not route.obligations
    out := {}
} else := out {
    # сливаем headers из route в приоритет с дефолтом
    rh := route.obligations.headers
    out := {
        "headers": merge_objects(default_obligations.headers, rh),
    }
}

# Rate limit из маршрута (key=user/tenant/ip/global)
rate_limit_obligation := out {
    not route.rate_limit
    out := {}
} else := out {
    spec := route.rate_limit
    k := rl_key(spec.key)
    out := {
        "rate_limit": {
            "key": k,
            "limit": spec.limit,
            "window_s": spec.window_s,
        }
    }
}

rl_key("user") := s { s := coalesce(req.user.id, "anonymous") }
rl_key("tenant") := s { s := coalesce(req.user.tenant, "default") }
rl_key("ip") := s { s := coalesce(req.conn.remote_ip, "0.0.0.0") }
rl_key(_) := "global"  # по умолчанию

# ---------------------------
# Вспомогательные функции
# ---------------------------

# Глоб сопоставление пути, позволяет использовать **, *, ? в route.path
glob_match(pattern, path) := true {
    glob.match(pattern, ["/"], path)
}

# Слияние произвольного количества объектов
merge_objects(objs...) := out {
    out := {}
    every i in [0..count(objs)-1] {
        out := object.union(out, objs[i])
    }
}

# Все элементы булевского массива истинны
all_true(xs) {
    every i in xs { xs[i] }
}

# Приведение к верхнему регистру (на случай отсутствия Upper)
upper(s) := t {
    t := upper_ascii(s)
}

# Временные функции
current_time() := { "h": h, "m": m } {
    ns := coalesce(req.context.now_ns, time.now_ns())
    # time.date: [year, month, day, hour, minute, second, ns]
    parts := time.date(ns)
    h := parts[3]
    m := parts[4]
}

parse_hhmm(s) := { "h": h, "m": m } {
    parts := split(s, ":")
    h := to_number(parts[0])
    m := to_number(parts[1])
}

time_between(now, start, end) {
    n := now.h*60 + now.m
    s := start.h*60 + start.m
    e := end.h*60 + end.m
    n >= s
    n < e
}

# Безопасный coalesce
coalesce(x, y) := z {
    x != null
    z := x
} else := z {
    z := y
}

# Проверки типов
is_array(x) { type_name(x) == "array" }
is_set(x) { type_name(x) == "set" }

# ---------------------------
# ДАННЫЕ/КОНФИГ (ожидаемые контуры)
# ---------------------------
#
# data.rbac.bindings = {
#   "read.profile":  { "roles": ["viewer","admin"], "scopes": ["profile:read"] },
#   "write.profile": { "roles": ["editor","admin"], "scopes": ["profile:write"] }
# }
#
# data.abac = {
#   "write_actions": { "write.profile": true },
#   "policies": [
#     { "required": { "tag": ["public","team-only"], "sensitivity": "low" } }
#   ]
# }
#
# data.http.routes = [
#   {
#     "id": "get_profile",
#     "methods": ["GET"],
#     "path": "/v1/profiles/*",
#     "action": "read.profile",
#     "require_mtls": false,
#     "ip_allowlist": [],
#     "time_window": null,
#     "rate_limit": { "key": "user", "limit": 300, "window_s": 60 },
#     "obligations": { "headers": { "cache-control": "no-store" } }
#   },
#   {
#     "id": "update_profile",
#     "methods": ["PUT","PATCH"],
#     "path": "/v1/profiles/*",
#     "action": "write.profile",
#     "require_mtls": true,
#     "ip_allowlist": ["10.0.0.0/8","192.168.0.0/16"],
#     "time_window": { "start": "07:00", "end": "20:00" },
#     "rate_limit": { "key": "user", "limit": 60, "window_s": 60 }
#   }
# ]
#
# data.networks = { "trusted": ["10.0.0.0/8", "192.168.0.0/16"] }
#
# Пример input:
# {
#   "method": "GET",
#   "path": "/v1/profiles/123",
#   "user": {"id": "u1", "roles": ["viewer"], "scopes": ["profile:read"], "tenant": "t1"},
#   "resource": {"type": "profile", "id": "123", "owner": "u1", "tenant": "t1",
#                "attributes": {"tag": "public", "sensitivity": "low"}},
#   "conn": {"remote_ip": "10.1.2.3", "mtls": {"present": true}},
#   "context": {"correlation_id": "c-123", "now_ns": 1735449600000000000}
# }
