package mythos.policies.content.v1

# =========================
# Entry: decision (object)
# =========================
# Input contract (пример):
# input: {
#   "tenant": "t-123",
#   "user": {"id":"u-1","role":"editor","trust":"low|normal|high"},
#   "context": {"resource":"lore|chat|profile","action":"create|update","path":"/api/v1/..."},
#   "content": {
#     "text": "...",            # предпочтительно plain text (до санитайзера)
#     "html": "<p>...</p>",     # необязательно
#     "attachments": [ {"filename":"...", "mime":"...", "size":12345} ]
#   },
#   "signals": {
#     "classifiers": { "toxicity":0.12, "hate":0.01, "sexual":0.03, "violence":0.0, "self_harm":0.0, "threat":0.0, "spam":0.0 },
#     "url_domains": ["example.com","bad.tld"],  # из парсера URL (в приложении)
#     "url_risk": {"bad.tld":"high"}             # опционально
#   },
#   "tenant_overrides": { ... }  # переопределение порогов/листов по арендатору (необязательно)
# }
#
# Output:
# decision: {
#   allow:     boolean,
#   severity:  "low"|"medium"|"high"|"critical",
#   actions:   ["allow","review","mask_pii","quarantine_attachments","block"] (минимально достаточный набор),
#   reasons:   [ {code, message, details, weight} ],
#   tags:      {"pii":true,"attachments":true,...},
#   applied:   { thresholds: {...}, feature_flags: {...} }
# }

default decision := {
  "allow": false,
  "severity": "low",
  "actions": ["review"],
  "reasons": [{"code":"NO_INPUT","message":"Content object missing","details":{}, "weight": 1}],
  "tags": {},
  "applied": {"thresholds": thresholds, "feature_flags": feature_flags},
}

# Если вход корректный — считаем итог.
decision := {
  "allow": allow,
  "severity": severity,
  "actions": actions,
  "reasons": reasons,
  "tags": tags,
  "applied": {"thresholds": applied_thresholds, "feature_flags": feature_flags},
} {
  valid_input
  reasons := collected_reasons
  tags    := collected_tags
  score   := total_weight(reasons)
  severity := severity_from_score(score)
  block_required := any_block(reasons)
  allow_after_mask := only_pii(reasons)  # допускаем после маски PII
  allow := not block_required and (count(reasons) == 0 or allow_after_mask or trusted_bypass)
  actions := decide_actions(block_required, allow_after_mask, has_attachments_violation, reasons)
  applied_thresholds := thresholds_effective
}

# -----------------------------
# Feature flags (версионирование логики)
# -----------------------------
feature_flags := {
  "pii_masking_enabled": true,
  "allow_trusted_high":  false,  # доверенным нельзя обходить блокирующие нарушения
}

# -----------------------------
# Пороговые значения (по умолчанию)
# Могут переопределяться через input.tenant_overrides.thresholds.*
# -----------------------------
thresholds := {
  "toxicity": 0.85,
  "hate":     0.80,
  "sexual":   0.80,
  "violence": 0.80,
  "threat":   0.70,
  "self_harm":0.70,
  "spam":     0.90,
  "max_len_text": 20000,     # символов
  "max_attach_mb": 25,       # MiB per file
  "max_attachments": 16
}

# Итоговые пороги с учётом override арендатора
thresholds_effective[k] := v {
  v := input.tenant_overrides.thresholds[k]
} else := v {
  v := thresholds[k]
}

# -----------------------------
# Веса нарушений -> суммарный балл серьёзности
# -----------------------------
weights := {
  "PII_EMAIL": 1,
  "PII_PHONE": 1,
  "PII_CARD":  3,
  "CLASS_TOXICITY": 3,
  "CLASS_HATE":     4,
  "CLASS_SEXUAL":   3,
  "CLASS_VIOLENCE": 3,
  "CLASS_THREAT":   4,
  "CLASS_SELF_HARM":4,
  "CLASS_SPAM":     2,
  "URL_BAD_REPUTATION": 3,
  "URL_BANNED_TLD":    2,
  "ATTACH_DANGEROUS_MIME": 4,
  "ATTACH_TOO_LARGE":      2,
  "ATTACH_TOO_MANY":       1,
  "LEN_TOO_LONG":          1,
  "LEXICON_MATCH":         3
}

# -----------------------------
# Валидность входа
# -----------------------------
valid_input {
  input.content
}

# -----------------------------
# Утилиты
# -----------------------------
lower_text := lower(coalesce(input.content.text, ""))
coalesce(x, y) = out {
  out := x
} else = out {
  out := y
}

mb_to_bytes(m) = out { out := m * 1024 * 1024 }

# Trusted / admin bypass (только для неблокирующих нарушений)
trusted_bypass {
  input.user.role == "admin"
} else {
  input.user.trust == "high"
  not any_block(collected_reasons)
  feature_flags["allow_trusted_high"] == true
}

# -----------------------------
# Детектор: PII
# -----------------------------
email_re := `(?i)(?:[a-z0-9._%+\-]+)@(?:[a-z0-9\-]+\.)+[a-z]{2,}`
phone_re := `(?:(?:\+?\d[\s\-()]*){7,}\d)`
card_re  := `\b(?:\d[ -]*?){13,19}\b`

has_email { re_match(email_re, lower_text) }
has_phone { re_match(phone_re, lower_text) }
has_card  { re_match(card_re,  input.content.text) }

violation[{"code":"PII_EMAIL","message":"Email detected in text","details":{}, "weight": weights["PII_EMAIL"], "block": false}] { has_email }
violation[{"code":"PII_PHONE","message":"Phone number detected in text","details":{}, "weight": weights["PII_PHONE"], "block": false}] { has_phone }
violation[{"code":"PII_CARD","message":"Possible payment card detected","details":{}, "weight": weights["PII_CARD"], "block": true}] { has_card }

# -----------------------------
# Детектор: длина текста
# -----------------------------
violation[{"code":"LEN_TOO_LONG","message":sprintf("Text exceeds max length: %d", [len(lower_text)]), "details":{"limit": thresholds_effective["max_len_text"]}, "weight": weights["LEN_TOO_LONG"], "block": false}] {
  len(lower_text) > thresholds_effective["max_len_text"]
}

# -----------------------------
# Детектор: вложения
# -----------------------------
dangerous_mime_prefixes := {"application/x-dosexec", "application/x-msdownload", "application/x-sh", "application/java-archive"}
banned_ext := {".exe",".bat",".cmd",".com",".js",".jar",".scr",".ps1",".vbs"}

has_attachments_violation {
  some v in [x | x := attach_violation[_]]
  v == true
}

attach_violation[v] {
  some a in input.content.attachments
  is_dangerous_mime(a.mime)
  v := true
}

attach_violation[v] {
  some a in input.content.attachments
  endswith(lower(a.filename), ext)
  ext := banned_ext[_]
  v := true
}

attach_violation[v] {
  some a in input.content.attachments
  sz := to_number(a.size)
  sz > mb_to_bytes(thresholds_effective["max_attach_mb"])
  v := true
}

attach_violation[v] {
  count(input.content.attachments) > thresholds_effective["max_attachments"]
  v := true
}

is_dangerous_mime(mime) {
  some p in dangerous_mime_prefixes
  startswith(lower(mime), p)
}

# Причины по вложениям
violation[{"code":"ATTACH_DANGEROUS_MIME","message":"Attachment has dangerous MIME or extension","details":{}, "weight": weights["ATTACH_DANGEROUS_MIME"], "block": true}] {
  attach_violation[_]
}

violation[{"code":"ATTACH_TOO_LARGE","message":"Attachment exceeds size limit","details":{"limit_mb": thresholds_effective["max_attach_mb"]}, "weight": weights["ATTACH_TOO_LARGE"], "block": false}] {
  some a in input.content.attachments
  to_number(a.size) > mb_to_bytes(thresholds_effective["max_attach_mb"])
}

violation[{"code":"ATTACH_TOO_MANY","message":"Too many attachments","details":{"limit": thresholds_effective["max_attachments"]}, "weight": weights["ATTACH_TOO_MANY"], "block": false}] {
  count(input.content.attachments) > thresholds_effective["max_attachments"]
}

# -----------------------------
# Детектор: URL/доменная репутация
# -----------------------------
banned_tlds := {"zip","mov","country","click"}  # пример; финальный список из data/overrides
# Внешние списки берём из data-модуля (если присутствуют)
bad_domains[dom] { dom := data.mythos.policies.reputation.bad_domains[_] }
bad_domains[dom] { dom := input.tenant_overrides.bad_domains[_] }

# Отметим плохую репутацию
violation[{"code":"URL_BAD_REPUTATION","message":sprintf("Domain flagged: %v", [d]), "details":{}, "weight": weights["URL_BAD_REPUTATION"], "block": true}] {
  some d in input.signals.url_domains
  bad_domains[d]
}
violation[{"code":"URL_BANNED_TLD","message":sprintf("Banned TLD: %v", [t]), "details":{}, "weight": weights["URL_BANNED_TLD"], "block": false}] {
  some d in input.signals.url_domains
  some t
  t := tld_of(d)
  banned_tlds[t]
}

tld_of(d) = t {
  parts := split(lower(d), ".")
  count(parts) > 0
  t := parts[count(parts)-1]
}

# -----------------------------
# Детектор: ML-классификаторы (пороговые)
# -----------------------------
class_over(name, prob, code, weight_key, block_flag) {
  prob >= thresholds_effective[name]
  violation[{
    "code": code,
    "message": sprintf("Classifier %s over threshold (%.2f)", [name, prob]),
    "details": {"score": prob, "threshold": thresholds_effective[name]},
    "weight": weights[weight_key],
    "block": block_flag
  }]
}

_ { class_over("toxicity",  input.signals.classifiers.toxicity,  "CLASS_TOXICITY",  "CLASS_TOXICITY",  false) }
_ { class_over("hate",      input.signals.classifiers.hate,      "CLASS_HATE",      "CLASS_HATE",      true) }
_ { class_over("sexual",    input.signals.classifiers.sexual,    "CLASS_SEXUAL",    "CLASS_SEXUAL",    false) }
_ { class_over("violence",  input.signals.classifiers.violence,  "CLASS_VIOLENCE",  "CLASS_VIOLENCE",  false) }
_ { class_over("threat",    input.signals.classifiers.threat,    "CLASS_THREAT",    "CLASS_THREAT",    true) }
_ { class_over("self_harm", input.signals.classifiers.self_harm, "CLASS_SELF_HARM", "CLASS_SELF_HARM", true) }
_ { class_over("spam",      input.signals.classifiers.spam,      "CLASS_SPAM",      "CLASS_SPAM",      false) }

# -----------------------------
# Детектор: лексикон (внешние списки)
# -----------------------------
# Ожидаем списки в data.mythos.policies.lexicon.{denylist, allowlist, sensitive_terms}
deny_term[term] { term := data.mythos.policies.lexicon.denylist[_] }
sensitive_term[term] { term := data.mythos.policies.lexicon.sensitive_terms[_] }
allow_term[term] { term := data.mythos.policies.lexicon.allowlist[_] }

contains_term(term) {
  term != ""
  contains(lower_text, lower(term))
}

# Прямой запрет по denylist
violation[{"code":"LEXICON_MATCH","message":sprintf("Term is denied: %q",[t]),"details":{}, "weight": weights["LEXICON_MATCH"], "block": true}] {
  t := deny_term[_]
  contains_term(t)
}

# Пометка чувствительных терминов как review (не блок)
violation[{"code":"LEXICON_MATCH","message":sprintf("Sensitive term flagged: %q",[t]),"details":{}, "weight": weights["LEXICON_MATCH"], "block": false}] {
  t := sensitive_term[_]
  contains_term(t)
  not contains_term(allow_term[_])
}

# -----------------------------
# Агрегация причин/тегов
# -----------------------------
collected_reasons := s {
  s := {r | r := violation[_]}
}

collected_tags := {
  "pii":    has_email or has_phone or has_card,
  "length": len(lower_text) > thresholds_effective["max_len_text"],
  "attachments": has_attachments_violation,
  "urls":   count(input.signals.url_domains) > 0,
}

# Любая блокирующая причина?
any_block := true {
  some r in collected_reasons
  r.block == true
}

# Только PII (и без иных нарушений)?
only_pii := true {
  some _; has_email or has_phone or has_card
  not non_pii_violation
}
non_pii_violation {
  some r in collected_reasons
  not startswith(r.code, "PII_")
}

# -----------------------------
# Суммарный балл и уровень серьёзности
# -----------------------------
total_weight(reasons) = s {
  ws := [ w | r := reasons[_]; w := weight_of(r.code) ]
  s := sum(ws)
}

weight_of(code) = w {
  w := weights[code]
} else = 1 { true }

severity_from_score(s) = "low"     { s < 3 }
severity_from_score(s) = "medium"  { s >= 3; s < 6 }
severity_from_score(s) = "high"    { s >= 6; s < 10 }
severity_from_score(s) = "critical"{ s >= 10 }

# -----------------------------
# Рекомендованные действия
# -----------------------------
decide_actions(block_required, allow_after_mask, attach_viols, reasons) = acts {
  block_required
  acts := ["block"]
} else = acts {
  allow_after_mask
  attach_viols
  acts := ["mask_pii","quarantine_attachments","review"]
} else = acts {
  allow_after_mask
  not attach_viols
  acts := ["mask_pii","allow"]
} else = acts {
  not block_required
  some _; count(reasons) > 0
  acts := ["review"]
} else = acts {
  acts := ["allow"]
}

# -----------------------------
# Примеры безопасных значений по умолчанию (на случай отсутствия полей)
# -----------------------------
to_number(x) = n {
  n := x
} else = 0 { true }
