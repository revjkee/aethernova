# omnimind-core/ops/ansible/configs/policies/rego/content_safety.rego
# Industrial content safety policy for OPA (Rego).
# Package provides a single entrypoint: data.policies.content_safety.decision
# Inputs:
#   input = {
#     "tenant_id": "acme-inc",
#     "actor": {"id":"u-123","role":"user","org":"acme-inc"},
#     "context": {"env":"prod","ip":"1.2.3.4","locale":"ru-RU","channel":"api"},
#     "content": {"text":"...", "mime":"text/plain", "lang":"auto", "meta":{"filename":"","source":"chat"}},
#     "intent": "user_generation|assistant_output|file_upload|profile_update",
#     "mode": "standard|strict|relaxed"    # optional; default via data.config
#   }
# Data dependencies (config & dictionaries) are read from:
#   data.content_safety.config
#   data.content_safety.regexes
#   data.content_safety.lexicon
#   data.content_safety.tenants
#
# Outputs:
#   decision = {
#     "allow": bool,
#     "action": "allow|review|block|redact",
#     "score": number,            # 0..100
#     "severity": "low|medium|high|critical",
#     "categories": {<cat>: {"hit": bool, "score": number}},
#     "reasons": [string],
#     "redactions": [{"start":int,"end":int,"type":string,"value":string}],
#     "explain": {"signals":[...], "matched": {"regex":[...], "lexemes":[...]}, "mode": string, "tenant": string}
#   }

package policies.content_safety

default decision := {
  "allow": true,
  "action": "allow",
  "score": 0,
  "severity": "low",
  "categories": {},
  "reasons": [],
  "redactions": [],
  "explain": {"signals": [], "matched": {"regex": [], "lexemes": []}, "mode": mode(), "tenant": tenant_id()}
}

# -------- Helpers --------

norm(s) := lower(trim(s))

empty(x) { x == "" } else { x == null } else { not x }

tenant_id() := tid {
  some tid
  tid := input.tenant_id
} else := "default"

mode() := m {
  m := input.mode
} else := cfg("default_mode")

cfg(key) := v {
  v := data.content_safety.config[key]
}

tenant_cfg(key) := v {
  v := data.content_safety.tenants[tenant_id()][key]
}

opt(key, def) := out {
  some v
  v := tenant_cfg(key)
  out := v
} else := def

text() := t {
  c := input.content
  t := to_string(c.text)
}

mime() := m {
  m := input.content.mime
} else := "text/plain"

intent() := i {
  i := input.intent
} else := "user_generation"

# Normalize language if provided; otherwise "auto"
lang() := l {
  l := input.content.lang
} else := "auto"

# Score utilities
cap(n, lo, hi) := x {
  x := max([lo, min([hi, n])])
}

risk_to_severity(r) := "low"     { r < 25 }
risk_to_severity(r) := "medium"  { r >= 25; r < 50 }
risk_to_severity(r) := "high"    { r >= 50; r < 75 }
risk_to_severity(r) := "critical"{ r >= 75 }

# Percent thresholds by mode (overridable per tenant)
thresholds := {
  "strict":   {"block": 40, "review": 20, "redact": 10},
  "standard": {"block": 60, "review": 35, "redact": 15},
  "relaxed":  {"block": 80, "review": 50, "redact": 20},
}

block_thr() := t {
  m := mode()
  t := opt(sprintf("threshold_%s_block", [m]), thresholds[m].block)
}
review_thr() := t {
  m := mode()
  t := opt(sprintf("threshold_%s_review", [m]), thresholds[m].review)
}
redact_thr() := t {
  m := mode()
  t := opt(sprintf("threshold_%s_redact", [m]), thresholds[m].redact)
}

# -------- Dictionaries & Regexes (from data.*) --------
# Expected data.content_safety.regexes = { "pii_email": "...", "url": "...", ... }
re(name) := r { r := data.content_safety.regexes[name] }

lex(name) := l { l := data.content_safety.lexicon[name] } # arrays e.g. ["слово1","слово2",...]

# -------- Signal extractors --------

# PII detectors
pii_email := m { some i; m := re_match_index(re("pii_email"), text())[i] }
pii_phone := m { some i; m := re_match_index(re("pii_phone"), text())[i] }
pii_card  := m { some i; m := re_match_index(re("pii_card"),  text())[i] }
pii_ip    := m { some i; m := re_match_index(re("pii_ip"),    text())[i] }
pii_iban  := m { some i; m := re_match_index(re("pii_iban"),  text())[i] }

# URLs / files
has_url   { re_match(re("url"), text()) }
has_file  { re_match(re("file_ext"), text()) }

# Profanity / Hate / Harassment
hit_lexicon(cat, token) {
  token := t
  t := lex(cat)[_]
  re_match(sprintf("(^|\\W)%s(\\W|$)", [t]), lower(text()))
}

# Safety categories with weights (configurable)
cat_weight("self_harm")  := 30
cat_weight("violence")   := 25
cat_weight("sexual")     := 35
cat_weight("hate")       := 40
cat_weight("harassment") := 25
cat_weight("weapons")    := 20
cat_weight("drugs")      := 20
cat_weight("crime")      := 30
cat_weight("extremism")  := 45
cat_weight("malware")    := 50

# Category match predicates (regex + lexeme)
category_hit("self_harm", s) {
  re_match(re("self_harm"), s)
} else {
  hit_lexicon("self_harm", _)
}

category_hit("violence", s) {
  re_match(re("violence"), s)
} else {
  hit_lexicon("violence", _)
}

category_hit("sexual", s) {
  re_match(re("sexual"), s)
} else {
  hit_lexicon("sexual"), not re_match(re("sexual_health_allowed"), s)
}

category_hit("hate", s) {
  re_match(re("hate"), s)
} else {
  hit_lexicon("hate", _)
}

category_hit("harassment", s) {
  re_match(re("harassment"), s)
} else {
  hit_lexicon("harassment", _)
}

category_hit("weapons", s) {
  re_match(re("weapons"), s)
}

category_hit("drugs", s) {
  re_match(re("drugs"), s)
}

category_hit("crime", s) {
  re_match(re("crime"), s)
}

category_hit("extremism", s) {
  re_match(re("extremism"), s)
}

category_hit("malware", s) {
  re_match(re("malware"), s)
}

# -------- Scoring --------

# Base risk from categories (sum with cap 100)
base_risk := r {
  s := lower(text())
  totals := [cat_weight(cat) |
    cat := c;
    c := {"self_harm","violence","sexual","hate","harassment","weapons","drugs","crime","extremism","malware"}[_];
    category_hit(c, s)
  ]
  r := cap(sum(totals), 0, 100)
}

# PII risk
pii_risk := r {
  hits := count({ "email": pii_email | true } |
                  "phone": pii_phone | true ;
                  "card": pii_card | true ;
                  "ip": pii_ip | true ;
                  "iban": pii_iban | true)
  r := cap(hits * 10, 0, 30)
} else := 0

# Link/file risk bump
link_risk := 5 { has_url } else := 0
file_risk := 10 { has_file } else := 0

# Intent modifier (assistant output stricter)
intent_mod := m {
  intent() == "assistant_output"
  m := 1.15
} else := 1.0

# Tenant mode multiplier (strict/relaxed)
mode_mod := m {
  m := {"strict": 1.2, "standard": 1.0, "relaxed": 0.85}[mode()]
}

# Final score
final_score := score {
  raw := base_risk + pii_risk + link_risk + file_risk
  mod := raw * intent_mod * mode_mod
  score := cap(to_number(mod), 0, 100)
}

# -------- Redactions (PII) --------
redaction_item(t, m) := {"start": m.start, "end": m.end, "type": t, "value": substring(text(), m.start, m.end-m.start)}

redactions[redaction_item("pii_email", m)] { m := pii_email }
redactions[redaction_item("pii_phone", m)] { m := pii_phone }
redactions[redaction_item("pii_card",  m)] { m := pii_card }
redactions[redaction_item("pii_ip",    m)] { m := pii_ip }
redactions[redaction_item("pii_iban",  m)] { m := pii_iban }

has_redactions { count(redactions) > 0 }

# -------- Category map for output --------
catmap[c] := {"hit": true, "score": cat_weight(c)} {
  s := lower(text()); c := cat
  cat := {"self_harm","violence","sexual","hate","harassment","weapons","drugs","crime","extremism","malware"}[_]
  category_hit(cat, s)
}

# -------- Action selection --------
action := "block" { final_score >= block_thr() }
action := "review" { final_score >= review_thr(); final_score < block_thr() }
action := "redact" { has_redactions; final_score >= redact_thr(); final_score < review_thr() }
action := "allow" { final_score < redact_thr(); not any_category_prohibited() }

# Certain categories are always block in strict (e.g., extremism + malware)
any_category_prohibited() {
  mode() == "strict"
  some c
  c := {"extremism","malware"}[_]
  catmap[c].hit
}

# -------- Reasons / Explain --------
reasons[r] {
  r := sprintf("pii_detected (count=%d)", [count(redactions)])
  has_redactions
}
reasons["category_hits"] { count(catmap) > 0 }
reasons[sprintf("has_url=%v", [has_url])] { has_url }
reasons[sprintf("has_file=%v", [has_file])] { has_file }

matched_regexes[{"name": n}] { some n; re_match(re(n), text()) }

lex_hits[l] {
  some name; some w
  w := lex(name)[_]
  re_match(sprintf("(^|\\W)%s(\\W|$)", [w]), lower(text()))
  l := {"list": name, "word": w}
}

# -------- Final decision object --------
decision := out {
  sc := final_score
  act := action
  sev := risk_to_severity(sc)
  base := {
    "allow": act == "allow" or act == "redact" or act == "review",
    "action": act,
    "score": sc,
    "severity": sev,
    "categories": catmap,
    "reasons": array.concat(["mode=" ++ mode()], array.concat({"": []}[""], [x | x := reasons[_]])),
    "redactions": redactions,
    "explain": {
      "signals": [
        {"name":"base_risk","value": base_risk},
        {"name":"pii_risk","value": pii_risk},
        {"name":"link_risk","value": link_risk},
        {"name":"file_risk","value": file_risk},
        {"name":"intent_mod","value": intent_mod},
        {"name":"mode_mod","value": mode_mod}
      ],
      "matched": {"regex": [m | m := matched_regexes[_]], "lexemes": [h | h := lex_hits[_]]},
      "mode": mode(),
      "tenant": tenant_id()
    }
  }

  # Tenant override: hard block or allow-list
  out := apply_tenant_overrides(base)
}

apply_tenant_overrides(base) := out {
  t := data.content_safety.tenants[tenant_id()]
  not t.hard_allow
  not t.hard_block
  out := base
} else := out {
  t := data.content_safety.tenants[tenant_id()]
  t.hard_block
  out := base with base.allow as false with base.action as "block" with base.reasons as array.concat(base.reasons, ["tenant_hard_block"])
} else := out {
  t := data.content_safety.tenants[tenant_id()]
  t.hard_allow
  out := base with base.allow as true with base.action as "allow" with base.reasons as array.concat(base.reasons, ["tenant_hard_allow"])
}

# -------- Rego builtins helpers --------
to_number(x) = n {
  n := to_number_internal(x)
} else = 0

to_number_internal(x) = n {
  n := x
  is_number(n)
} else = n {
  n := to_number(cast_string(x))
}

cast_string(x) = s {
  is_string(x)
  s := x
} else = s {
  s := sprintf("%v", [x])
}

# -------- Default configuration scaffold (override via data) --------
# Example shapes (provide via data.content_safety.* in your bundle):
# data.content_safety.config = {
#   "default_mode": "standard"
# }
# data.content_safety.regexes = {
#   "pii_email": "(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
#   "pii_phone": "(?i)(\\+?\\d[\\d\\s().-]{7,}\\d)",
#   "pii_card":  "\\b(?:\\d[ -]*?){13,19}\\b",
#   "pii_ip":    "\\b(?:(?:2(5[0-5]|[0-4]\\d))|1?\\d?\\d)(?:\\.(?:2(5[0-5]|[0-4]\\d)|1?\\d?\\d)){3}\\b",
#   "pii_iban":  "\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b",
#   "url":       "(?i)\\bhttps?://[-A-Z0-9+&@#/%?=~_|!:,.;]*[-A-Z0-9+&@#/%=~_|]\\b",
#   "file_ext":  "(?i)\\b\\w+\\.(exe|bat|cmd|ps1|sh|js|jar|zip|rar|7z|iso|dll)\\b",
#   "self_harm": "(?i)\\b(самоуб[ий]|повредить себя|суицид)\\b",
#   "violence":  "(?i)\\b(убить|насилие|покалечить)\\b",
#   "sexual":    "(?i)\\b(порн|эротик|сексуал|инцест)\\b",
#   "sexual_health_allowed": "(?i)\\b(контрацепц|здоровь[еия] сексуальн|половая гигиена)\\b",
#   "hate":      "(?i)\\b(ненависть к|дегуманизац|выродк|расист)\\b",
#   "harassment":"(?i)\\b(оскорб|травл|унизи|угрожа)\\b",
#   "weapons":   "(?i)\\b(оружи[ея]|взрывчат|бомб|пистолет|винтовк)\\b",
#   "drugs":     "(?i)\\b(наркот|героин|метамфетамин|кокаин)\\b",
#   "crime":     "(?i)\\b(взлом|краж|подделк|мошеннич)\\b",
#   "extremism": "(?i)\\b(экстремизм|террор|ИГИЛ|нацист|джихад)\\b",
#   "malware":   "(?i)\\b(малвар|вредоносн|кейлогг|эксплойт)\\b"
# }
# data.content_safety.lexicon = {
#   "hate": ["дегуманизация","расовая ненависть"],
#   "harassment": ["идиот","тупой"],
#   "sexual": ["порнография","эротика"],
#   "self_harm": ["хочу умереть","резать себя"],
#   "violence": ["убью","зарежу"]
# }
# data.content_safety.tenants = {
#   "default": {"hard_allow": false, "hard_block": false},
#   "acme-inc": {"hard_allow": false, "hard_block": false}
# }
