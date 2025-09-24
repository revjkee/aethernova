# ledger-core/ops/configs/policies/rego/tx_validation.rego

package ledgercore.tx.validation

# =========================
# Конфигурация по умолчанию
# =========================

# Внешняя конфигурация может перегружать эти значения через data.ledgercore.config.*
default cfg := {
  "currencies": {"USD": 2, "EUR": 2, "SEK": 2, "GBP": 2, "JPY": 0},
  "amount_limits": {
    "per_tx_minor_max": 10_000_00,     # например: 10000.00
    "per_tx_minor_min": 1,             # > 0
    "per_day_minor_max": 100_000_00,   # 100000.00
    "per_day_count_max": 500
  },
  "risk": {
    "high_risk_countries": {"IR","KP","SY","CU"},
    "sanctions_list": {},              # список account_id или counterparty_id
    "velocity": {
      "window_seconds": 3600,         # 1h
      "minor_threshold": 20_000_00,   # 20000.00 / час
      "count_threshold": 200
    },
    "scoring": {
      "amount_breakpoints_minor": [1_000_00, 5_000_00, 10_000_00],
      "weights": {
        "amount": 40,
        "velocity": 25,
        "country": 20,
        "mcc": 10,
        "misc": 5
      },
      "review_threshold": 60,
      "reject_threshold": 85
    }
  },
  "double_entry": {
    "epsilon_minor": 0                   # строгое равенство дебет=кредит
  },
  "time": {
    "skew_seconds": 120,                 # допустимый дрейф времени клиента
    "max_future_seconds": 5              # запрет будущих дат > 5s
  }
}

cfg_currencies := coalesce(data.ledgercore.config.currencies, cfg.currencies)
cfg_amount_limits := coalesce(data.ledgercore.config.amount_limits, cfg.amount_limits)
cfg_risk := coalesce(data.ledgercore.config.risk, cfg.risk)
cfg_double_entry := coalesce(data.ledgercore.config.double_entry, cfg.double_entry)
cfg_time := coalesce(data.ledgercore.config.time, cfg.time)

# ==============
# Входные данные
# ==============
# Ожидаемый input:
# {
#   "tx": {
#     "id": "uuid",
#     "type": "payment|refund|transfer|fee|adjustment",
#     "posted_at": "2025-08-15T10:01:02Z",
#     "amount_minor": 12345,                     # положительная величина операции верхнего уровня (информативно)
#     "currency": "SEK",
#     "entries": [
#       {"account_id":"acc1","direction":"debit","amount_minor":12345,"currency":"SEK"},
#       {"account_id":"acc2","direction":"credit","amount_minor":12345,"currency":"SEK"}
#     ],
#     "meta": {
#       "country": "SE",
#       "mcc": "5814",
#       "counterparty_id": "cp_123",
#       "signature": "base64",
#       "digest": "hex"
#     }
#   },
#   "context": {
#     "now": "2025-08-15T10:01:10Z",
#     "seen_ids": {"uuid1": true},              # идемпотентность
#     "accounts": {
#       "acc1": {"status":"active","kind":"asset"},
#       "acc2": {"status":"active","kind":"liability"}
#     },
#     "stats": {
#       "by_day_minor_sum": 500_00,             # сумма по исходному счету за день
#       "by_day_count": 2,
#       "velocity_window_minor_sum": 8_000_00,
#       "velocity_window_count": 40
#     }
#   }
# }

# =========================
# Главные результаты/правила
# =========================

# allow — true, если нет deny
allow {
  count(deny) == 0
}

# Структурный ответ
result := {
  "allow": allow,
  "deny": deny,
  "risk": {
    "score": risk_score,
    "reasons": risk_reasons
  },
  "advice": advice
}

# Совет по обработке (hold/review) из риск‑скоринга
advice := {"hold": false, "review": true} {
  risk_score >= cfg_risk.scoring.review_threshold
  risk_score < cfg_risk.scoring.reject_threshold
}
advice := {"hold": true, "review": false} {
  risk_score >= cfg_risk.scoring.reject_threshold
}
advice := {"hold": false, "review": false} {
  risk_score < cfg_risk.scoring.review_threshold
}

# ==============
# DENY правила
# ==============

deny[msg] {
  not has_required_fields
  msg := "schema: required fields missing or wrong types"
}

deny[msg] {
  not currency_supported
  msg := sprintf("currency: unsupported or wrong scale: %s", [input.tx.currency])
}

deny[msg] {
  not amount_positive
  msg := "amount: must be > 0 (minor units)"
}

deny[msg] {
  not posted_time_valid
  msg := "time: posted_at is too far in future or outside allowed skew"
}

deny[msg] {
  is_duplicate
  msg := sprintf("idempotency: duplicate tx id %s", [input.tx.id])
}

deny[msg] {
  not entries_non_empty
  msg := "entries: must contain at least 2 entries"
}

deny[msg] {
  not entries_currency_match
  msg := "entries: currency mismatch with tx.currency"
}

deny[msg] {
  not double_entry_balanced
  msg := "double-entry: debit and credit totals must balance"
}

deny[msg] {
  some e in input.tx.entries
  not account_active(e.account_id)
  msg := sprintf("account: %s not active", [e.account_id])
}

deny[msg] {
  exceeds_per_tx_limit
  msg := "limits: per-tx amount exceeds configured maximum"
}

deny[msg] {
  exceeds_daily_sum
  msg := "limits: daily amount limit exceeded"
}

deny[msg] {
  exceeds_daily_count
  msg := "limits: daily count limit exceeded"
}

deny[msg] {
  exceeds_velocity_sum
  msg := "limits: velocity sum in window exceeded"
}

deny[msg] {
  exceeds_velocity_count
  msg := "limits: velocity count in window exceeded"
}

deny[msg] {
  sanctioned_party
  msg := "sanctions: counterparty/account is sanctioned"
}

deny[msg] {
  high_risk_country_block
  msg := sprintf("geo: high-risk country blocked: %s", [lower(input.tx.meta.country)])
}

deny[msg] {
  not signature_valid
  msg := "integrity: signature/digest validation failed"
}

# =========================
# РИСК-СКОРИНГ/ПРИЧИНЫ
# =========================

risk_score := sum([
  risk_amount_component,
  risk_velocity_component,
  risk_country_component,
  risk_mcc_component,
  risk_misc_component,
])

risk_reasons := {r |
  some i
  r := risk_reason[i]
}

risk_reason := array.concat(
  amount_reasons,
  array.concat(velocity_reasons,
    array.concat(country_reasons,
      array.concat(mcc_reasons, misc_reasons))))

# ----- amount component
risk_amount_component := w * bucket_score {
  w := cfg_risk.scoring.weights.amount
  bucket_score := bucketize_amount(input.tx.amount_minor, cfg_risk.scoring.amount_breakpoints_minor)
}

amount_reasons := [sprintf("amount_bucket:%d", [bucketize_amount(input.tx.amount_minor, cfg_risk.scoring.amount_breakpoints_minor)])]

# ----- velocity
risk_velocity_component := w * vscore {
  w := cfg_risk.scoring.weights.velocity
  vscore := velocity_score
}
velocity_score := s {
  s := 0
  s := s + ifelse(exceeds_velocity_sum, 3, 0)
  s := s + ifelse(exceeds_velocity_count, 2, 0)
}
velocity_reasons := vr {
  vr := []
  vr := append_if(vr, exceeds_velocity_sum, "velocity:sum_exceeded")
  vr := append_if(vr, exceeds_velocity_count, "velocity:count_exceeded")
}

# ----- country
risk_country_component := w * c {
  w := cfg_risk.scoring.weights.country
  c := ifelse(high_risk_country_flag, 3, 0)
}
country_reasons := cr {
  cr := []
  cr := append_if(cr, high_risk_country_flag, "geo:high_risk_country")
}

# ----- mcc (примерная эвристика)
risk_mcc_component := w * m {
  w := cfg_risk.scoring.weights.mcc
  m := ifelse(is_high_risk_mcc, 2, 0)
}
mcc_reasons := mr {
  mr := []
  mr := append_if(mr, is_high_risk_mcc, sprintf("mcc:%s_high_risk", [input.tx.meta.mcc]))
}

# ----- misc
risk_misc_component := w * mm {
  w := cfg_risk.scoring.weights.misc
  mm := ifelse(partially_unbalanced_hint, 1, 0)
}
misc_reasons := r {
  r := []
  r := append_if(r, partially_unbalanced_hint, "double-entry:near_unbalanced")
}

# ======================
# Примитивные проверки
# ======================

has_required_fields {
  input.tx.id
  is_string(input.tx.id)
  input.tx.type
  is_string(input.tx.type)
  is_string(input.tx.currency)
  is_number(input.tx.amount_minor)
  input.tx.entries
  is_array(input.tx.entries)
  input.context.now
  is_string(input.context.now)
}

currency_supported {
  scale := cfg_currencies[input.tx.currency]
  is_number(scale)
}

amount_positive {
  input.tx.amount_minor >= cfg_amount_limits.per_tx_minor_min
}

posted_time_valid {
  now := parse_rfc3339ns(input.context.now)
  posted := parse_rfc3339ns(input.tx.posted_at)
  # не в далёком будущем
  posted <= now + cfg_time.max_future_seconds
  # допустимый дрейф клиента назад/вперёд
  abs(now - posted) <= (24*60*60 + cfg_time.skew_seconds)  # 1 день + дрейф
}

is_duplicate {
  input.context.seen_ids[input.tx.id]
}

entries_non_empty {
  count(input.tx.entries) >= 2
}

entries_currency_match {
  forall(input.tx.entries, func(e) { e.currency == input.tx.currency })
}

double_entry_balanced {
  eps := cfg_double_entry.epsilon_minor
  debit := sum([e.amount_minor | e := input.tx.entries[_]; lower(e.direction) == "debit"])
  credit := sum([e.amount_minor | e := input.tx.entries[_]; lower(e.direction) == "credit"])
  abs(debit - credit) <= eps
}

# намёк на дисбаланс, но не жёсткий deny (для риска)
partially_unbalanced_hint {
  debit := sum([e.amount_minor | e := input.tx.entries[_]; lower(e.direction) == "debit"])
  credit := sum([e.amount_minor | e := input.tx.entries[_]; lower(e.direction) == "credit"])
  abs(debit - credit) > 0
}

account_active(acc_id) {
  s := input.context.accounts[acc_id].status
  lower(s) == "active"
}

exceeds_per_tx_limit {
  input.tx.amount_minor > cfg_amount_limits.per_tx_minor_max
}

exceeds_daily_sum {
  sum_day := input.context.stats.by_day_minor_sum
  (sum_day + input.tx.amount_minor) > cfg_amount_limits.per_day_minor_max
}

exceeds_daily_count {
  cnt := input.context.stats.by_day_count
  (cnt + 1) > cfg_amount_limits.per_day_count_max
}

exceeds_velocity_sum {
  v := input.context.stats.velocity_window_minor_sum
  (v + input.tx.amount_minor) > cfg_risk.velocity.minor_threshold
}

exceeds_velocity_count {
  c := input.context.stats.velocity_window_count
  (c + 1) > cfg_risk.velocity.count_threshold
}

sanctioned_party {
  some sid
  sl := cfg_risk.sanctions_list
  sl[sid]
  sid == coalesce(input.tx.meta.counterparty_id, "")
} else {
  # также блокируем, если сам счёт в санкционном списке
  some e
  sl := cfg_risk.sanctions_list
  sl[e.account_id]
  e := input.tx.entries[_]
}

high_risk_country_flag {
  c := upper(coalesce(input.tx.meta.country, ""))
  cfg_risk.high_risk_countries[c]
}

# Жёсткая блокировка по странам (примерная модель)
high_risk_country_block {
  high_risk_country_flag
  input.tx.type == "transfer"  # пример: блокируем p2p в санкционные юрисдикции
}

# Простейшая проверка подписи/хэша (делегируется внешнему верификатору через context)
signature_valid {
  # Если подпись/хэш отсутствуют в настройках, пропускаем (полезно для dev)
  not has_signature_requirements
} else {
  has_signature_requirements
  # В контексте внешний сервис уже проверил подпись/хэш
  # expect: context.integrity.valid == true
  input.context.integrity.valid == true
}

has_signature_requirements {
  input.context.integrity.require == true
}

# Простая эвристика по MCC
is_high_risk_mcc {
  some code
  code := input.tx.meta.mcc
  startswith(code, "6")  # пример: MCC 6xxx — условно высокий риск
} else = false

# ======================
# Утилиты/функции
# ======================

# безопасные операции
coalesce(x, d) := y { y := x } else := d

append_if(arr, cond, v) := out {
  cond
  out := array.concat(arr, [v])
} else := arr

# Проверка forall
forall(arr, f) {
  not exists(arr, func(x) { not f(x) })
}

exists(arr, f) {
  some i
  f(arr[i])
}

# Парсинг времени (секунды)
parse_rfc3339ns(s) := t {
  t := time.parse_rfc3339_ns(s) / 1000000000
}

# Абсолютное значение
abs(x) := y {
  x >= 0
  y := x
} else := y {
  y := -x
}

# Бакетизация по сумме
bucketize_amount(a, breaks) := b {
  # 0: < b0, 1: [b0,b1), 2: [b1,b2), ... , N: >= b_{N-1}
  b := count([x | x := breaks[_]; a >= x])
}

# ======================
# Тестовые данные (opa test)
# ======================

# Пример позитивного теста (можно запускать: opa test .)
test_allow_payment_ok {
  input := {
    "tx": {
      "id": "tx_ok",
      "type": "payment",
      "posted_at": "2025-08-15T10:00:00Z",
      "amount_minor": 100_00,
      "currency": "SEK",
      "entries": [
        {"account_id":"a1","direction":"debit","amount_minor":100_00,"currency":"SEK"},
        {"account_id":"a2","direction":"credit","amount_minor":100_00,"currency":"SEK"}
      ],
      "meta": {"country":"SE","mcc":"5814"}
    },
    "context": {
      "now": "2025-08-15T10:00:02Z",
      "seen_ids": {},
      "accounts": {"a1":{"status":"active"}, "a2":{"status":"active"}},
      "stats": {"by_day_minor_sum":0,"by_day_count":0,"velocity_window_minor_sum":0,"velocity_window_count":0},
      "integrity": {"require": false}
    }
  }
  allow with input as input
  result.allow with input as input
  count(deny) == 0 with input as input
}

# Негативный тест: несбалансировано
test_deny_unbalanced {
  input := {
    "tx": {
      "id": "tx_bad",
      "type": "payment",
      "posted_at": "2025-08-15T10:00:00Z",
      "amount_minor": 100_00,
      "currency": "SEK",
      "entries": [
        {"account_id":"a1","direction":"debit","amount_minor":100_00,"currency":"SEK"},
        {"account_id":"a2","direction":"credit","amount_minor":90_00,"currency":"SEK"}
      ],
      "meta": {"country":"SE","mcc":"5814"}
    },
    "context": {
      "now": "2025-08-15T10:00:02Z",
      "seen_ids": {},
      "accounts": {"a1":{"status":"active"}, "a2":{"status":"active"}},
      "stats": {"by_day_minor_sum":0,"by_day_count":0,"velocity_window_minor_sum":0,"velocity_window_count":0},
      "integrity": {"require": false}
    }
  }
  not allow with input as input
  some m
  deny[m] with input as input
}
