package policy_core.pii_guard.v1

# ------------------------------------------------------------
# Политика защиты PII: детект, классификация, риск, решение
# Требуемая версия OPA: 0.48+ (walk, time.now_ns, object.keys, type_name)
# Вход (пример, не исчерпывающий):
# input := {
#   "action": "export" | "read" | "write" | "share",
#   "resource": {
#     "type": "document" | "event" | "record",
#     "storage": {"public": false, "encrypted_at_rest": true}
#   },
#   "data": {... произвольный JSON ...},
#   "ctx": {
#     "region": "SE",
#     "dest": {"region": "US", "domain_category": "unknown" | "trusted" | "ads"},
#     "transport": {"tls": true},
#     "crypto": {"pfs": true},
#     "controls": {"dpo_approved": false, "tokenization_ready": true}
#   },
#   "legal": {
#     "basis": "consent" | "contract" | "legitimate_interest" | "none",
#     "scc_in_place": false
#   },
#   "policy": {
#     "risk": {"deny_threshold": 70, "warn_threshold": 50},
#     "redaction": {"enabled": true, "mask_char": "*"}
#   }
# }
# ------------------------------------------------------------

# -------------------------- Константы -----------------------

default version := "1.0.0"
default policy_id := "policy-core.pii-guard.v1"

default deny := []
default obligations := []
default findings := []
default classification := {"label": "public", "types": [], "count": 0}
default risk := {"score": 0, "breakdown": {}}
default sanitized := {"data": input.data}

eu_countries := {"SE","FI","NO","DK","DE","FR","NL","BE","PL","ES","IT","PT","IE","AT","CZ","SK","HU","EE","LV","LT","RO","BG","HR","SI","LU","GR","CY","MT"}

# -------------------------- Утилиты типов -------------------

is_string(x) { type_name(x) == "string" }
is_array(x)  { type_name(x) == "array"  }
is_object(x) { type_name(x) == "object" }

# -------------------------- Детекторы PII -------------------

is_email(s) {
  is_string(s)
  re_match("(?i)^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", s)
}

is_phone(s) {
  is_string(s)
  re_match("^\\+?[0-9][0-9()\\-\\s]{6,}[0-9]$", s)
}

# Luhn для карт
luhn_valid(digits) {
  total := sum([v |
    some i
    d := to_number(substr(digits, i, 1))
    # справа налево: чётные позиции удваиваем
    idx_from_right := (count(digits) - i)
    v := if(idx_from_right % 2 == 0, (if(d*2 > 9, d*2 - 9, d*2)), d)
  ])
  total % 10 == 0
}

digits_only(s) = out {
  out := concat("", [c | some i; c := substr(s, i, 1); re_match("[0-9]", c)])
}

is_card_number(s) {
  is_string(s)
  cleaned := digits_only(s)
  count(cleaned) >= 12
  count(cleaned) <= 19
  luhn_valid(cleaned)
}

is_iban(s) {
  is_string(s)
  re_match("(?i)^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$", s)
}

# Упрощенная SSN (US) и SE personnummer
is_ssn_us(s) {
  is_string(s)
  re_match("^(?!000|666)[0-8][0-9]{2}-?(?!00)[0-9]{2}-?(?!0000)[0-9]{4}$", s)
}

is_se_personnummer(s) {
  is_string(s)
  re_match("^[0-9]{6,8}[-+][0-9]{4}$", s)
}

is_passport_generic(s) {
  is_string(s)
  # Общая маска для паспортов: 2 буквы + 6-8 цифр или серия-номер
  re_match("(?i)^[A-Z]{1,2}[0-9]{6,8}$", s) or re_match("^[0-9]{2}\\s?[0-9]{2}\\s?[0-9]{6}$", s)
}

is_eth_address(s) {
  is_string(s)
  re_match("(?i)^0x[0-9a-f]{40}$", s)
}

is_ton_address(s) {
  is_string(s)
  # Допускаем форматы ton:<base64url> или адреса, начинающиеся на EQ/0Q (упрощенно)
  re_match("^(?i)ton:[A-Za-z0-9_-]{48,}$", s) or re_match("^[EQ0Q][A-Za-z0-9_-]{47,}$", s)
}

# Определение типа PII по строке
pii_type(s) = t {
  is_email(s)
  t := "email"
} else = t {
  is_phone(s)
  t := "phone"
} else = t {
  is_card_number(s)
  t := "card_pan"
} else = t {
  is_iban(s)
  t := "iban"
} else = t {
  is_ssn_us(s)
  t := "ssn_us"
} else = t {
  is_se_personnummer(s)
  t := "se_personnummer"
} else = t {
  is_passport_generic(s)
  t := "passport"
} else = t {
  is_eth_address(s)
  t := "eth_address"
} else = t {
  is_ton_address(s)
  t := "ton_address"
} else = t {
  t := ""
}

# -------------------------- Сканирование --------------------

# Все найденные PII: type, path, value
findings[f] {
  some p, v
  walk(input.data, [p, v])
  is_string(v)
  t := pii_type(v)
  t != ""
  f := {"type": t, "path": p, "value": v}
}

# Сводка типов
types_set := { f.type | f := findings[_] }
types := sort(array.concat([], types_set))

# Классификация уровня чувствительности
classification := {
  "label": label,
  "types": types,
  "count": count(findings)
} {
  some _

  restricted := {"card_pan","iban","ssn_us","se_personnummer","passport"}
  confidential := {"email","phone","eth_address","ton_address"}

  label :=  cond(
              count(types_set & restricted) > 0, "restricted",
              cond(count(types_set & confidential) > 0, "confidential", "public")
            )
}

cond(test, a, b) = out {
  test
  out := a
} else = out {
  not test
  out := b
}

# -------------------------- Риск-модель ---------------------

risk := {
  "score": score,
  "breakdown": breakdown
} {
  base := 0

  # Вес по типам PII
  w_type := sum([ weight_for_type(t) | t := types[_] ])

  # Вес по действию
  w_action := weight_for_action(input.action)

  # Контроль транспортного шифрования и PFS
  w_transport := if(bool(input.ctx.transport.tls), 0, 15)
  w_pfs := if(bool(input.ctx.crypto.pfs), 0, 10)

  # Хранилище
  w_storage := if(bool(input.resource.storage.encrypted_at_rest), 0, 10) +
               if(bool(input.resource.storage.public), 15, 0)

  # Назначение/домен
  dest_cat := input.ctx.dest.domain_category
  w_dest := {
    "trusted": 0,
    "unknown": 10,
    "ads": 20
  }[dest_cat] else 10

  # Трансграничная передача из ЕС
  in_eu := input.ctx.region == eu for some eu in eu_countries
  out_eu := not (input.ctx.dest.region == eu for some eu in eu_countries)
  cross_border := in_eu and out_eu
  legal_ok := input.legal.scc_in_place == true or input.legal.basis == "consent" or input.legal.basis == "contract"
  w_xborder := if(cross_border and not legal_ok, 20, 0)

  # Итоговый скор (ограничим 0..100)
  raw := base + w_type + w_action + w_transport + w_pfs + w_storage + w_dest + w_xborder
  score := min([100, raw])

  breakdown := {
    "types": w_type,
    "action": w_action,
    "transport_tls": w_transport,
    "pfs": w_pfs,
    "storage": w_storage,
    "dest": w_dest,
    "cross_border": w_xborder
  }
}

weight_for_type(t) = w {
  w := {
    "card_pan": 30,
    "iban": 20,
    "ssn_us": 25,
    "se_personnummer": 25,
    "passport": 20,
    "email": 8,
    "phone": 8,
    "eth_address": 5,
    "ton_address": 5
  }[t] else 0
}

weight_for_action(a) = w {
  w := {
    "read": 5,
    "write": 8,
    "share": 15,
    "export": 20
  }[a] else 10
}

# -------------------------- Запреты -------------------------

# 1) Запрет хранения PII в публичном хранилище
deny[msg] {
  count(findings) > 0
  input.resource.storage.public == true
  msg := {
    "code": "PUBLIC_STORAGE_PII",
    "message": "Найдено PII, запрещено публичное хранилище"
  }
}

# 2) Запрет экспорта/шеринга при риске >= порога
deny[msg] {
  input.action == "export" or input.action == "share"
  risk.score >= threshold
  threshold := (input.policy.risk.deny_threshold else 70)
  msg := {
    "code": "HIGH_RISK_EXPORT",
    "message": sprintf("Риск %d превышает порог %d для действия %s", [risk.score, threshold, input.action])
  }
}

# 3) Запрет на restricted без DPO approval
deny[msg] {
  classification.label == "restricted"
  not bool(input.ctx.controls.dpo_approved)
  msg := {
    "code": "DPO_REQUIRED",
    "message": "Для данных уровня restricted требуется одобрение DPO"
  }
}

# 4) Запрет трансграничной передачи ЕС -> вне ЕС без основания
deny[msg] {
  # из ЕС
  input.ctx.region == eu for some eu in eu_countries
  # вне ЕС
  not (input.ctx.dest.region == eu for some eu in eu_countries)
  # нет правового основания
  not input.legal.scc_in_place
  not (input.legal.basis == "consent" or input.legal.basis == "contract")
  msg := {
    "code": "CROSS_BORDER_BLOCKED",
    "message": "Нет правового основания для передачи данных из ЕС за пределы ЕС"
  }
}

# 5) Запрет отсутствия шифрования канала при наличии PII
deny[msg] {
  count(findings) > 0
  not bool(input.ctx.transport.tls)
  msg := {
    "code": "TLS_REQUIRED",
    "message": "Передача PII без TLS запрещена"
  }
}

# -------------------------- Обязательства -------------------

# Требование редактирования при чтении/записи, если PII есть
obligations[_] {
  count(findings) > 0
  input.action == "read" or input.action == "write"
  (input.policy.redaction.enabled else true)
  {"type": "redact", "target": "body", "mask_char": (input.policy.redaction.mask_char else "*")}
}

# Требование шифрования at-rest
obligations[_] {
  count(findings) > 0
  not bool(input.resource.storage.encrypted_at_rest)
  {"type": "encrypt_at_rest"}
}

# Требование токенизации, если инфраструктура готова
obligations[_] {
  count(findings) > 0
  bool(input.ctx.controls.tokenization_ready)
  {"type": "tokenize", "scope": "pii_fields"}
}

# -------------------------- Sanitize ------------------------

# sanitize(x) -> y: рекурсивная редакция строк
sanitize(x) = y {
  is_string(x)
  t := pii_type(x)
  t != ""
  y := mask_value(x, t)
} else = y {
  is_string(x)
  pii_type(x) == ""
  y := x
} else = y {
  is_array(x)
  y := [sanitize(e) | e := x[_]]
} else = y {
  is_object(x)
  ks := object.keys(x)
  y := {k: sanitize(x[k]) | k := ks[_]}
} else = y {
  # прочие типы
  y := x
}

# Маскирование по типу
mask_value(s, t) = out {
  mc := (input.policy.redaction.mask_char else "*")
  t == "email"
  parts := split(s, "@")
  user := parts[0]
  dom := parts[1]
  shown := min([3, count(user)])
  out := sprintf("%s%s@%s", [substr(user, 0, shown), repeat(mc, max([0, count(user)-shown])), dom])
} else = out {
  mc := (input.policy.redaction.mask_char else "*")
  t == "phone"
  d := digits_only(s)
  keep := min([4, count(d)])
  out := sprintf("%s%s", [repeat(mc, max([0, count(d)-keep])), substr(d, count(d)-keep, keep)])
} else = out {
  mc := (input.policy.redaction.mask_char else "*")
  t == "card_pan"
  d := digits_only(s)
  out := sprintf("%s%s%s", [substr(d,0,4), repeat(mc, max([0, count(d)-8])), substr(d, count(d)-4, 4)])
} else = out {
  mc := (input.policy.redaction.mask_char else "*")
  t == "iban"
  out := re_replace("(?<=^[A-Z]{2}[0-9]{2}).*", repeat(mc, 12), upper(s))
} else = out {
  mc := (input.policy.redaction.mask_char else "*")
  # по умолчанию: замаскировать все, оставить 3 символа
  keep := min([3, count(s)])
  out := sprintf("%s%s", [substr(s, 0, keep), repeat(mc, max([0, count(s)-keep]))])
}

# Повтор символа n раз
repeat(ch, n) = out {
  out := concat("", [ch | i := range(n)])
}

# Очищенная копия данных
sanitized := {"data": sanitize(input.data)}

# -------------------------- Решение allow -------------------

allow {
  count(deny) == 0
}

# -------------------------- Аудит ---------------------------

audit := {
  "policy_id": policy_id,
  "version": version,
  "timestamp_ns": time.now_ns(),
  "decision": cond(allow, "allow", "deny"),
  "classification": classification,
  "risk": risk,
  "deny": deny,
  "obligations": obligations,
  "findings_count": count(findings)
}

# -------------------------- Тесты (OPA 'opa test') ----------

# Примеры тестов; можно сохранить отдельно как pii_guard_test.rego
# test_allow_public_no_pii {
#   not is_email("hello")
#   data.policy_core.pii_guard.v1.with_input({
#     "action":"read",
#     "resource":{"storage":{"public":false,"encrypted_at_rest":true}},
#     "data":{"msg":"hello"},
#     "ctx":{"region":"SE","dest":{"region":"SE","domain_category":"trusted"},"transport":{"tls":true},"crypto":{"pfs":true},"controls":{"dpo_approved":false,"tokenization_ready":true}},
#     "legal":{"basis":"consent","scc_in_place":false},
#     "policy":{"risk":{"deny_threshold":70},"redaction":{"enabled":true}}
#   }).allow
# }
