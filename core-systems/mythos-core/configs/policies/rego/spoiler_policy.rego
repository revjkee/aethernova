# mythos-core/configs/policies/rego/spoiler_policy.rego
package mythos.policies.spoiler

# Для современного синтаксиса "in", "every", "if"
import future.keywords.in

################################################################################
# ВХОД: ожидаемая структура (док):
#
# input := {
#   "content": {
#     "id": "c_123",
#     "text": "string?",                 # текст (опционально)
#     "tags": ["spoiler","story"],       # произвольные метки
#     "markup": { "has_brackets": bool, "has_bars": bool }, # быстрые флаги парсера
#     "metadata": {
#        "mod_flags": ["leak","spoiler"?], # флаги модерации
#        "keywords": ["datamine", ...],    # предвычисленные ключевые слова (опционально)
#        "release_refs": [                 # контент ссылается на сущности с релизами/эмбарго
#           {"id":"quest_omega","type":"quest"},
#        ]
#     },
#     "channel": { "id": "ch1", "type":"public|private|guild|internal", "spoilers_allowed": bool },
#     "visibility": "public|private"
#   },
#   "context": {
#     "now": "RFC3339 timestamp",         # текущее время (UTC)
#     "region": "EU|US|...?",
#     "user": {
#       "id": "u1",
#       "role": "user|moderator|admin|dev|qa|creator|trusted_tester",
#       "preferences": { "spoiler_mode": "hide|warn|show" }
#     }
#   }
# }
#
# ВЫХОД (решение): decision := {
#   "allow": bool,
#   "actions": ["require_warning","redact_markup", ...],
#   "reasons": [ { "code":"...", "message":"...", ... }, ... ],
#   "severity": "none|low|medium|high"
# }
################################################################################

########################
# Конфигурация по умолчанию (может быть переопределена data.mythos.spoiler_config)
########################

default config := {
  "version": "1.0",
  "default_mode": "warn",                      # когда нет предпочтения пользователя
  "whitelist_roles": {                         # роли, для которых спойлеры разрешены
    "admin": true, "moderator": true, "dev": true, "qa": true, "creator": true, "trusted_tester": true
  },
  "spoiler_tags": {"spoiler": true, "story_spoiler": true, "plot": true},
  "leak_keywords_re": [
    "(?i)\\bleak(s|ed|ing)?\\b",
    "(?i)\\bdata\\s*mine(d|s|ing)?\\b",
    "(?i)\\bunreleased\\b",
    "(?i)\\binternal\\s*build\\b"
  ],
  "markup_patterns_re": [
    "(?i)\\[\\s*spoiler\\s*\\]",     # [spoiler]
    "(?s)\\|\\|.+?\\|\\|"            # ||spoiler||
  ],
  "embargo_hours_default": 72,                  # если не задано в релизе
  # Карта релизов для ссылочных сущностей (может прийти из data)
  "releases": {
    # "quest_omega": {
    #   "default_release_at": "2025-02-01T00:00:00Z",
    #   "regions": { "EU":"2025-02-02T00:00:00Z" },
    #   "embargo_hours": 96
    # }
  }
}

# Берем внешний конфиг, если он доступен; иначе оставляем дефолт
config := data.mythos.spoiler_config with input as input else config

########################
# Главный артефакт решения
########################

decision := {
  "allow": allow,
  "actions": actions,
  "reasons": reasons,
  "severity": sev_label
}

default allow := true

# Собираем действия
actions := sorted(actions_set)
actions_set := {a |
  some _; a := action_require_warning; require_warning
} ∪ {a |
  some _; a := "redact_markup"; redact_markup_required
}

# Причины (объекты) — пригодны для логирования и UI
reasons := sorted(reasons_set)
reasons_set := {r | r := reason_embargo if embargo_active}
          ∪   {r | r := reason_leak if leak_detected}
          ∪   {r | r := reason_tag if has_spoiler_tag}
          ∪   {r | r := reason_markup if markup_detected}
          ∪   {r | r := reason_modflag if modflag_spoiler}

reason_embargo := {
  "code": "embargo_active",
  "message": "Content references unreleased material under embargo.",
  "until": embargo_until,
  "refs": release_ref_ids
}

reason_leak := {
  "code": "leak_indicator",
  "message": "Leak/datamining indicators detected."
}

reason_tag := {
  "code": "spoiler_tag",
  "message": "Spoiler tag present on content."
}

reason_markup := {
  "code": "spoiler_markup",
  "message": "Spoiler markup present (e.g., [spoiler] or ||text||)."
}

reason_modflag := {
  "code": "moderation_flag",
  "message": "Moderator flag indicates spoiler/leak."
}

########################
# Исключения / контекст
########################

exempt_role := config.whitelist_roles[lower(input.context.user.role)]
exempt_channel := input.content.channel.spoilers_allowed == true
exempt_private := input.content.visibility == "private"  # приватные диалоги могут быть отдельной политикой

exempt := exempt_role or exempt_channel or exempt_private

########################
# Режим пользователя и маппинг в действия
########################

mode := m {
  m := lower(input.context.user.preferences.spoiler_mode)
} else := config.default_mode

# Условия, требующие предупреждение
require_warning {
  not exempt
  severity >= 2       # medium/high → предупреждение минимум
}

# Условия, требующие запрета (deny), зависят от режима
deny_if_hide {
  mode == "hide"
  not exempt
  severity >= 1       # любой спойлер при hide блокируется
}

deny_if_warn {
  mode == "warn"
  not exempt
  severity >= 3       # только high (эмбарго/утечки) блокируются, остальное — предупреждение
}

# Формируем итоговый allow/deny
allow {
  not deny_if_hide
  not deny_if_warn
}

########################
# Оценка признаков спойлера
########################

# Метки
has_spoiler_tag {
  some t
  t := lower(input.content.tags[_])
  config.spoiler_tags[t]
}

# Разметка
markup_detected {
  some p
  re_match(config.markup_patterns_re[p], input.content.text)
} else {
  input.content.markup.has_brackets == true
} else {
  input.content.markup.has_bars == true
}

# Модераторские флаги
modflag_spoiler {
  some f
  f := lower(input.content.metadata.mod_flags[_])
  f == "spoiler" or f == "leak"
}

# "Утечки" и схожие ключевые слова
leak_detected {
  some rx
  re_match(config.leak_keywords_re[rx], input.content.text)
} else {
  some kw
  kw := lower(input.content.metadata.keywords[_])
  re_match("(?i)\\b(leak|datamine|unreleased|internal)\\b", kw)
}

########################
# Релизы/эмбарго (регионально)
########################

# Список ID ссылок на сущности с релизом
release_ref_ids := [r.id | r := input.content.metadata.release_refs[_]]

# Определяем активное эмбарго, если контент ссылается на релизы
embargo_active {
  not exempt
  count(release_ref_ids) > 0
  embargo_until != ""  # вычислили время
  now_ns < parse_rfc3339_ns(embargo_until)
}

# Конкретный срок эмбарго (макс среди всех refs)
embargo_until := max_until {
  some i
  ts := [effective_embargo_until(rid) | rid := release_ref_ids[_]; effective_embargo_until(rid) != ""]
  max_until := max_ts(ts)
} else := ""

# Время теперь из контекста (обязательный инпут) — так детерминируются тесты
now_ns := parse_rfc3339_ns(input.context.now)

# Эффективный срок эмбарго для одной сущности
effective_embargo_until(rid) := until {
  rel := config.releases[rid]
  base := rel.default_release_at
  region := input.context.region
  # если в конфиге есть региональный релиз — применяем его
  rel_at := coalesce(rel.regions[region], base)
  emb_h := coalesce_number(rel.embargo_hours, config.embargo_hours_default)
  until := rfc3339_add_hours(rel_at, emb_h)
}

########################
# Severity (none/low/medium/high) — числовой скор, потом маппинг в ярлык
########################

# Правила начисления "очков риска"
score := total {
  base := 0
  s1 := cond_score(has_spoiler_tag, 1, 0)
  s2 := cond_score(markup_detected, 1, 0)
  s3 := cond_score(leak_detected, 3, 0)
  s4 := cond_score(embargo_active, 3, 0)
  s5 := cond_score(modflag_spoiler, 2, 0)
  total := base + s1 + s2 + s3 + s4 + s5
}

severity := sev {
  # 0 → none, 1-2 → low, 3-4 → medium, >=5 → high
  s := score
  sev := 0          { s == 0 }
  sev := 1          { s >= 1; s <= 2 }
  sev := 2          { s >= 3; s <= 4 }
  sev := 3          { s >= 5 }
}

sev_label := lbl {
  lbl := "none"   { severity == 0 }
  lbl := "low"    { severity == 1 }
  lbl := "medium" { severity == 2 }
  lbl := "high"   { severity == 3 }
}

# Если спойлер-разметка обнаружена и режим не "show", рекомендуем редактирование/замену на предупреждение
redact_markup_required {
  not exempt
  markup_detected
  mode != "show"
}

# Если требуется предупреждение — действие с кодом (для UI)
action_require_warning := "require_warning"

########################
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
########################

# Безопасные "слияния" значений
coalesce(x, y) := out {
  out := x
} else := out {
  out := y
}

coalesce_number(x, y) := out {
  to_number(x)
  out := x
} else := out {
  out := y
}

# Преобразование в число (если строка)
to_number(x) = n {
  n := to_number_internal(x)
}
to_number_internal(x) = n {
  n := x
} else = n {
  n := to_number_unsafe(x)
}
to_number_unsafe(x) = n {
  # пробуем parse
  re_match("^-?\\d+(\\.\\d+)?$", x)
  n := to_number_builtin(x)
}
to_number_builtin(x) = n {
  n := to_number(x)  # будет перехвачено предыдущей веткой; оставлено для совместимости
}

# Часы к RFC3339
rfc3339_add_hours(t, h) := out {
  ts := parse_rfc3339_ns(t)
  ns := int(h) * 60 * 60 * 1_000_000_000
  out := ns_to_rfc3339(ts + ns)
}

# RFC3339 → ns
parse_rfc3339_ns(t) := n {
  n := time.parse_rfc3339_ns(t)
}

# ns → RFC3339 (UTC)
ns_to_rfc3339(n) := s {
  s := time.rfc3339_ns(n)
}

# Максимум по строковым RFC3339
max_ts(ts) := out {
  some i
  parsed := [parse_rfc3339_ns(ts[_])]
  out := time.rfc3339_ns(max(parsed))
}

# Условный скор
cond_score(cond, yes, no) := out {
  cond
  out := yes
} else := out {
  out := no
}

# Понижение регистра (безопасно к null)
lower(x) := y {
  y := lower_builtin(x)
} else := y {
  y := ""
}
lower_builtin(x) := y {
  y := lower(x)
}
