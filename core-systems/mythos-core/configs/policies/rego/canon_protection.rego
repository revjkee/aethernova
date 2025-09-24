package mythos.canon.protection

# -----------------------------------------------------------------------------
# Входные данные (ожидаемые поля):
#
# input.request: {
#   "env": "dev" | "stage" | "prod",
#   "action": "create" | "update" | "delete" | "merge_proposal" | "release",
#   "resource": {
#     "kind": "tablet" | "angel" | "canon" | "chronicle" | "proposal" | "release",
#     "id": "string",
#     "payload": object,            # содержимое создаваемого/обновляемого объекта
#     "change_set": {               # при update/merge: патч/дифф
#       "ops": [ { "op": "...", "path": "...", "value": any } ]
#     },
#     "version": "vX.Y.Z"
#   },
#   "actor": {
#     "id": "u_123",
#     "org": "aethernova" | "neurocity" | "...",
#     "roles": ["admin","sre","core-platform","lore-keeper","maintainer","developer","qa","viewer"]
#   },
#   "context": {
#     "time": "RFC3339 timestamp",
#     "trace_id": "hex-след",
#     "change_ticket": "JIRA-123",
#     "approvals": [ { "by": "u_42", "role": "sre" }, { "by": "u_7", "role": "core-platform" } ],
#     "signature_present": true,    # для release: cryptographic signature check уже выполнен внешним шагом
#     "breakglass": false,          # аварийный обход заморозки, допускается только для SRE
#     "notes": "строка"
#   }
# }
#
# input.policy:
#   {
#     "freeze_windows": [ { "start": "RFC3339", "end": "RFC3339" } ],
#     "immutable_fields": { "tablet": ["id","created_at"], "angel": ["id","created_at"], ... },
#     "protected_kinds": ["tablet","angel","canon","chronicle"],
#     "approval_roles": ["sre","core-platform","lore-keeper"],
#     "min_approvals_prod": 2
#   }
#
# output:
#   - deny[msg] правила ниже
#   - result: { "allow": bool, "reasons": [string] }
# -----------------------------------------------------------------------------

default result := {"allow": false, "reasons": reasons}
reasons := {m | deny[m]}

# Разрешение: если нет ни одного deny
allow if count({m | deny[m]}) == 0

# Экспорт агрегированного решения (удобно для CI/webhook)
result.allow if allow

# -----------------------------------------------------------------------------
# Базовые проверки среды, трассируемости и аудита
# -----------------------------------------------------------------------------

deny[msg] {
  not has_nonempty_string(input.request.context.trace_id)
  msg := "missing trace_id"
}

deny[msg] {
  input.request.env == "prod"
  not has_nonempty_string(input.request.context.change_ticket)
  msg := "prod requires change_ticket"
}

# -----------------------------------------------------------------------------
# Запрет прямых destructive-операций с каноном
# -----------------------------------------------------------------------------

# В prod запрещены create/update/delete для protected_kinds, кроме merge_proposal и release
deny[msg] {
  input.request.env == "prod"
  input.request.resource.kind == kind
  kind_in_protected(kind)
  input.request.action == act
  act_in({"create", "update", "delete"}, act)
  msg := sprintf("direct %q on %q is forbidden in prod; use proposals + release", [act, kind])
}

# В stage delete запрещен, кроме помеченного soft_delete=true
deny[msg] {
  input.request.env == "stage"
  input.request.action == "delete"
  input.request.resource.kind == kind
  kind_in_protected(kind)
  not is_soft_delete(input.request.resource.payload)
  msg := "delete in stage requires soft_delete=true"
}

# -----------------------------------------------------------------------------
# Окна заморозки (freeze windows). Нарушение возможно только с breakglass от SRE.
# -----------------------------------------------------------------------------

deny[msg] {
  input.request.env == "prod"
  is_change_action(input.request.action)
  within_freeze_window
  not allow_breakglass
  msg := "change within freeze window is forbidden"
}

within_freeze_window {
  some fw
  fw := input.policy.freeze_windows[_]
  now := request_time_ns()
  start := parse_time_ns(fw.start)
  end := parse_time_ns(fw.end)
  now >= start
  now <= end
}

allow_breakglass {
  input.request.context.breakglass == true
  some r
  r := input.request.actor.roles[_]
  r == "sre"
}

# -----------------------------------------------------------------------------
# Требования к одобрениям (2-из-N) для merge_proposal и release в prod
# -----------------------------------------------------------------------------

deny[msg] {
  input.request.env == "prod"
  input.request.action == act
  act_in({"merge_proposal", "release"}, act)
  not has_min_approvals(input.request.context.approvals, input.policy.approval_roles, input.policy.min_approvals_prod)
  msg := sprintf("not enough approvals (%d required) from roles %v", [input.policy.min_approvals_prod, input.policy.approval_roles])
}

# Проверка подписи релиза
deny[msg] {
  input.request.env == "prod"
  input.request.action == "release"
  not input.request.context.signature_present
  msg := "release requires cryptographic signature"
}

# -----------------------------------------------------------------------------
# Защита неизменяемых полей для update/merge_proposal
# -----------------------------------------------------------------------------

deny[msg] {
  is_update_like_action
  kind := input.request.resource.kind
  fields := input.policy.immutable_fields[kind]
  some f
  f := fields[_]
  touches_path(input.request.resource.change_set.ops, f)
  msg := sprintf("immutable field %q modified for kind %q", [f, kind])
}

is_update_like_action {
  act := input.request.action
  act == "update" or act == "merge_proposal"
}

# -----------------------------------------------------------------------------
# Проверка на секреты в payload (чёрный список ключей + эвристики значения)
# -----------------------------------------------------------------------------

deny[msg] {
  contains_secrets(input.request.resource.payload)
  msg := "payload contains potential secrets (keys or high-entropy strings)"
}

# -----------------------------------------------------------------------------
# Разрешённые типы операций/ресурсов
# -----------------------------------------------------------------------------

deny[msg] {
  not valid_action(input.request.action)
  msg := sprintf("unknown action %q", [input.request.action])
}

deny[msg] {
  not valid_kind(input.request.resource.kind)
  msg := sprintf("unknown kind %q", [input.request.resource.kind])
}

# -----------------------------------------------------------------------------
# Утилиты и предикаты
# -----------------------------------------------------------------------------

valid_action(a) {
  a == "create"  ; a == "update" ; a == "delete" ; a == "merge_proposal" ; a == "release"
}

valid_kind(k) {
  k == "tablet" ; k == "angel" ; k == "canon" ; k == "chronicle" ; k == "proposal" ; k == "release"
}

kind_in_protected(k) {
  some i
  i := input.policy.protected_kinds[_]
  i == k
}

act_in(set, a) {
  set[a]
}

has_nonempty_string(x) {
  x != null
  x != ""
  is_string(x)
}

is_string(x) {
  type_name(x) == "string"
}

is_soft_delete(obj) {
  obj.soft_delete == true
}

is_change_action(a) {
  a == "create" or a == "update" or a == "delete" or a == "merge_proposal" or a == "release"
}

# Одобрения: минимум N от заданных ролей, и уникальные пользователи
has_min_approvals(approvals, roles, n) {
  count(approved_ids) >= n
  approved_ids := { a.by |
    some i
    a := approvals[i]
    roles[_] == a.role
    has_nonempty_string(a.by)
  }
}

# Проверка затрагивания пути в diff ops (RFC6902 / JSON Patch)
touches_path(ops, path) {
  some i
  op := ops[i]
  has_nonempty_string(op.path)
  startswith(trim_prefix(op.path, "/"), path)
}

trim_prefix(s, p) = out {
  startswith(s, p)
  out := substring(s, count(p), -1)
} else = s

# Эвристика утечки секретов: ключи из списка, либо подозрительные значения
contains_secrets(x) {
  some k, v
  walk(x, [k, v])
  is_string(k)
  lower := lower_ascii(k)
  re_match(`(?i)(password|passwd|secret|token|apikey|api_key|privatekey|private_key|credential)`, lower)
} else {
  some _k, v
  walk(x, [_k, v])
  is_string(v)
  looks_like_secret_value(v)
}

# Высокоэнтропийные/длинные значения, похожие на ключи/токены
looks_like_secret_value(v) {
  # длинные base64/hex
  re_match(`^[A-Za-z0-9+/_-]{32,}$`, v)
} else {
  re_match(`^[A-Fa-f0-9]{40,}$`, v)
}

lower_ascii(s) = out {
  out := lower(s)
}

# Парсинг времени
parse_time_ns(ts) = t {
  t := time.parse_rfc3339_ns(ts)
}

request_time_ns() = t {
  some ts
  ts := input.request.context.time
  t := time.parse_rfc3339_ns(ts)
} else = t {
  t := time.now_ns()
}

# -----------------------------------------------------------------------------
# Диагностические правила (не влияют на allow), могут использоваться для логов
# -----------------------------------------------------------------------------

info[msg] {
  allow
  msg := sprintf("allow action=%q kind=%q id=%q by=%q env=%q", [input.request.action, input.request.resource.kind, input.request.resource.id, input.request.actor.id, input.request.env])
}

# -----------------------------------------------------------------------------
# Конец политики
# -----------------------------------------------------------------------------
