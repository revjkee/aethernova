package neuroforge.policies.prompt_guard

# Unverified: Эта политика предоставляет промышленный «Prompt Guard» для входящих промптов LLM.
# Внешняя конфигурация: data.policies.prompt_guard.config (см. default_config).
# Вход (пример):
# input := {
#   "tenant": "t-123",
#   "principal": {"id": "u-42", "scopes": ["prompt:write"]},
#   "metadata": {
#     "channel": "api", "ip": "203.0.113.10", "language": "en",
#     "model": "gpt-4o", "attachments": 0
#   },
#   "prompt": "your text here"
# }

default allow := false

# Главное решение: структурированный объект
decision := {
  "allow": allow,
  "risk_score": score,
  "violations": violations_sorted,
  "labels": labels,
  "redacted_prompt": redacted,
  "config_id": conf.id,
  "version": "1.0.0"
}

# Разрешаем только если нет нарушений уровня block и итоговый риск < порога
allow {
  count(violations_block) == 0
  score < conf.block_score
}

# Рейтинг риска: сумма рисков по нарушениям, но ограниченная max_score
score := s {
  base := sum([v.risk | v := violations])
  s := min([base, conf.max_score])
}

# Отсортированные нарушения по убыванию severity и типу
violations_sorted := sort(violations)

# Метки классификации
labels := {l | v := violations; l := v.label}

# Редакция промпта по конфигурации (маскируем секреты/PII/ключевые токены)
redacted := redact_prompt(input.prompt, conf)

# -----------------------------
# Конфигурация и дефолты
# -----------------------------
conf := merge_objects(default_config, data.policies.prompt_guard.config)  # overlay из data (если есть)

default_config := {
  "id": "default",
  "block_score": 100,
  "max_score": 200,
  "max_length": 12000,
  "min_length": 1,
  "allowed_languages": ["en", "ru", "sv", "de", "fr"],
  "banned_tokens": [
    "(?i)ignore(\\s+all|\\s+previous)?\\s+instructions",
    "(?i)jailbreak",
    "(?i)act\\s+as\\s+(?:DAN|developer mode|sysadmin)",
    "(?i)no\\s+ethical\\s+constraints",
    "(?i)output\\s+raw\\s+system\\s*prompt",
    "(?i)disregard\\s+all\\s+policies",
    "(?i)prompt\\s*injection",
    "(?i)exfiltrate\\s+data",
    "(?i)write\\s+malware|ransomware|keylogger|backdoor"
  ],
  "secret_patterns": [
    "(?i)aws(.{0,20})?secret(.{0,20})?key[\"': ]+[A-Za-z0-9/+=]{40}",
    "AKIA[0-9A-Z]{16}",
    "(?i)google(.{0,10})?api(.{0,10})?key[\"': ]+AIza[0-9A-Za-z\\-_]{35}",
    "(?i)slack(?:_bot)?_token[\"': ]+xox[abpr]-[0-9A-Za-z-]{10,48}",
    "-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY-----",
    "(?i)password[\"': ]+[\\S]{6,}",
    "(?i)secret[\"': ]+[\\S]{6,}"
  ],
  "pii_patterns": [
    # email
    "(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
    # телефон (упрощенно, международные префиксы + цифры/разделители)
    "(?i)\\b\\+?[0-9]{1,3}[\\s.-]?(?:\\(?[0-9]{2,4}\\)?[\\s.-]?[0-9]{2,4}[\\s.-]?[0-9]{2,4})\\b",
    # кредитная карта (13-19 цифр с разделителями)
    "\\b(?:\\d[ -]*?){13,19}\\b",
    # IBAN (очень упрощенно)
    "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\b"
  ],
  "exfil_tokens": [
    "(?i)/etc/passwd",
    "(?i)ssh_config",
    "(?i)known_hosts",
    "(?i)\\.env",
    "(?i)service\\s+account\\s+token",
    "(?i)kubeconfig",
    "(?i)credentials\\.json"
  ],
  "sanitize": {
    "mask_token": "[REDACTED]",
    "redact_secret": true,
    "redact_pii": true
  }
}

# -----------------------------
# Нарушения: формируем набор объектов
# -----------------------------

# Общий список нарушений
violations[v] {
  v := length_violation
} else { 
  v := language_violation
} else {
  v := token_violation
} else {
  v := secret_violation
} else {
  v := pii_violation
} else {
  v := exfil_violation
}

# Блокирующие нарушения
violations_block[v] {
  v := secret_violation
} else {
  v := token_violation_block
}

# 1) Проверка длины
length_violation := {
  "type": "length",
  "label": "oversize",
  "severity": sev,
  "risk": risk,
  "message": sprintf("prompt length %d exceeds max_length %d", [strlen(input.prompt), conf.max_length])
} {
  strlen(input.prompt) > conf.max_length
  sev := "high"
  risk := 80
} else := {
  "type": "length",
  "label": "undersize",
  "severity": "low",
  "risk": 5,
  "message": "prompt length is below minimal threshold"
} {
  strlen(input.prompt) < conf.min_length
}

# 2) Язык: если указан и не разрешен
language_violation := {
  "type": "language",
  "label": "lang_not_allowed",
  "severity": "low",
  "risk": 10,
  "message": sprintf("language %q is not in allowed set", [lower(input.metadata.language)])
} {
  input.metadata.language != null
  not allowed_language(lower(input.metadata.language), conf.allowed_languages)
}

allowed_language(lang, allowed) {
  some i
  allowed[i] == lang
}

# 3) Jailbreak / запрещенные токены
token_violation := {
  "type": "jailbreak",
  "label": "prompt_injection",
  "severity": "high",
  "risk": 40,
  "message": msg
} {
  re_match_any(conf.banned_tokens, input.prompt)
  msg := "prompt contains jailbreak/injection patterns"
}

# Отдельно выделяем блокирующую версию (чтобы попасть в violations_block)
token_violation_block := token_violation

# 4) Секреты
secret_violation := {
  "type": "secret",
  "label": "credential_leak",
  "severity": "critical",
  "risk": 100,
  "message": "prompt contains secret-like material (credentials or private keys)"
} {
  re_match_any(conf.secret_patterns, input.prompt)
}

# 5) PII (не блокирует, но накапливает риск)
pii_violation := {
  "type": "pii",
  "label": "personal_data",
  "severity": "medium",
  "risk": 30,
  "message": "prompt appears to contain PII (email/phone/card/IBAN)"
} {
  re_match_any(conf.pii_patterns, input.prompt)
}

# 6) Эксфильтрация системных/конфигурационных данных
exfil_violation := {
  "type": "exfil",
  "label": "data_exfiltration",
  "severity": "medium",
  "risk": 20,
  "message": "prompt requests or references sensitive system paths/files"
} {
  re_match_any(conf.exfil_tokens, input.prompt)
}

# -----------------------------
# Хелперы и утилиты
# -----------------------------

# Проверка: строка матчит любой из паттернов из списка
re_match_any(patterns, s) {
  some i
  re_match(patterns[i], s)
}

# Минимальная безопасная «редакция» промпта по секретам/PII
redact_prompt(s, cfg) := out {
  sm := cfg.sanitize
  mask := sm.mask_token
  s1 := cond_replace(sm.redact_secret, cfg.secret_patterns, s, mask)
  s2 := cond_replace(sm.redact_pii, cfg.pii_patterns, s1, mask)
  out := s2
}

# Условная замена: если enabled=true, последовательно применяем regex.replace по каждому паттерну
cond_replace(enabled, patterns, s, mask) := out {
  enabled
  out := replace_all(patterns, s, mask)
} else := s {
  not enabled
}

# Последовательное применение replace по всем паттернам
replace_all(patterns, s, mask) := out {
  out := fold(patterns, s, func(acc, p) { regex.replace(p, acc, mask) })
}

# Полезные функции stdlib
strlen(x) := n { n := count([_ | _ = x[_]]) }  # совместимый способ подсчёта длины

lower(s) := t { t := lower_ascii(s) }

# Упрощенный lower для ASCII (для безопасности работы без расширений)
lower_ascii(s) := out {
  out := tolower(s)
} else := s {
  # если окружение не поддерживает tolower (крайне маловероятно)
  true
}

# -----------------------------
# Сортировка нарушений
# -----------------------------
# Преобразуем severity в вес для сортировки
sev_weight("critical") := 4
sev_weight("high") := 3
sev_weight("medium") := 2
sev_weight("low") := 1
sev_weight(_) := 0

# Ключ сортировки: (severity_weight desc, type asc)
sort(vs) := out {
  out := sort_by(vs, func(a, b) {
    wa := sev_weight(a.severity)
    wb := sev_weight(b.severity)
    # Сортируем по убыванию severity; при равенстве — по алфавиту type
    more := wa > wb
    less := wa < wb
    equal := wa == wb
    result := {"lt": not more and (less or (equal and a.type < b.type))}
    result
  })
}

# Универсальный мердж двух объектов (overlay b поверх a)
merge_objects(a, b) := out {
  is_object(b)
  out := object.union(a, b)
} else := a {
  not is_object(b)
}

# Проверки типов (совместимость со старыми рантаймами)
is_object(x) {
  object.get(x, "__probe__", null) == null
} else = false {
  true
}
