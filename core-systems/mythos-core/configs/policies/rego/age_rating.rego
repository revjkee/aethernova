# mythos-core/configs/policies/rego/age_rating.rego
package mythos.policies.age_rating

# Rego >= 0.27: future.keywords для and/or/not/in с общеупотребимой семантикой
import future.keywords

default allow := false

# Главное экспортируемое решение: объект для аудита и исполнения
decision := {
  "allow": allow,
  "required_age": required_age,
  "subject_age": subject_age,
  "reasons": reasons,
  "obligations": obligations,
  "advice": advice,
}

################################################################################
# ВХОДНЫЕ ДАННЫЕ (пример структуры)
#
# input = {
#   "subject": {
#     "age": 17,                        # опционально; при отсутствии вычисляем из birthdate
#     "birthdate": "2008-06-01",        # ISO-8601; при наличии имеет приоритет на вычисление возраста
#     "country": "SE",                  # ISO-3166-1 alpha-2
#     "roles": ["user"],                # роли субъекта
#     "parental_controls": {
#       "enabled": true,
#       "max_rating": "PG-13"           # верхний допустимый порог по семейной политике
#     }
#   },
#   "resource": {
#     "type": "video",
#     "ratings": {                      # любой поднабор
#       "mpaa": "PG-13",
#       "pegi": 16,
#       "esrb": "T"
#     },
#     "tags": ["violence","alcohol"],   # внутренние теговые риски
#     "publisher_labels": ["mature"]    # ярлыки издателя
#   },
#   "context": {
#     "now": "2025-08-27T12:00:00Z",    # текущий момент (для вычисления возраста по дате рождения)
#     "purpose": "consumption"          # consumption|moderation|compliance
#   }
# }
################################################################################

##############################
# Таблицы соответствий рейтингов
##############################

# Преобразование MPAA -> минимальный возраст по внутренней политике
mpaa_min_age := {
  "G": 0,
  "PG": 10,
  "PG-13": 13,
  "R": 17,
  "NC-17": 18
}

# Преобразование PEGI -> минимальный возраст
pegi_min_age := {
  3: 3,
  7: 7,
  12: 12,
  16: 16,
  18: 18
}

# Преобразование ESRB -> минимальный возраст
# Примечание: соответствия определены политикой продукта; они не претендуют на юридические трактовки.
esrb_min_age := {
  "EC": 3,        # Early Childhood
  "E": 6,         # Everyone
  "E10+": 10,     # Everyone 10+
  "T": 13,        # Teen
  "M": 17,        # Mature
  "AO": 18        # Adults Only
}

# Теги контента -> минимальный возраст по политике риска
tag_min_age := {
  "violence": 16,
  "strong_violence": 18,
  "horror": 16,
  "profanity": 12,
  "alcohol": 18,
  "tobacco": 18,
  "drugs": 18,
  "nudity": 18,
  "sex": 18,
  "gambling": 18
}

# Ярлыки издателя -> минимальный возраст
label_min_age := {
  "kids": 0,
  "family": 10,
  "teen": 13,
  "mature": 17,
  "adult": 18
}

# Разрешенные служебные обходы по ролям при специальных целях
bypass_roles := {
  "moderation": {"moderator", "admin", "compliance"},
  "compliance": {"admin", "compliance"},
}

#########################################
# Региональные переопределения (структура)
#########################################
# Словарь country->(tag->min_age). По умолчанию пусто: без переопределений.
# Заполняется организацией при необходимости; значения трактуются как политика продукта.
region_tag_overrides := {
  # Пример:
  # "US": {"alcohol": 21},
  # "AE": {"alcohol": 21}
}

#########################################
# Вспомогательные функции
#########################################

# Нормализация строкового рейтинга к верхнему регистру
norm(s) := upper(s)

# Безопасное извлечение поля
get(obj, key, def) := v {
  some v
  obj[key] == v
} else := def

# Максимум элементов множества чисел (или 0)
max_num(ns) := m {
  count(ns) == 0
  m := 0
} else := m {
  m := max(ns)
}

# Вычисление возраста субъекта (в целых годах)
subject_age := age {
  # Приоритет: birthdate -> age
  bd := get(get(input, "subject", {}), "birthdate", "")
  bd != ""
  now := get(get(input, "context", {}), "now", "")
  age := years_between(bd, now)
} else := age {
  age := get(get(input, "subject", {}), "age", 0)
}

# Грубая разница полных лет между датами (ISO-8601)
years_between(birth_iso, now_iso) := years {
  # Если не удаётся распарсить, возвращаем 0
  some y, m, d, ny, nm, nd
  split(birth_iso, "-", parts)
  count(parts) >= 3
  y := to_number(parts[0])
  m := to_number(parts[1])
  d := to_number(substring(parts[2], 0, 2))

  n_parts := split(now_iso, "-", nps)
  count(nps) >= 3
  ny := to_number(nps[0])
  nm := to_number(nps[1])
  nd := to_number(substring(nps[2], 0, 2))

  base := ny - y
  adjust := 0
  nm < m => adjust := 1
  nm == m ; nd < d => adjust := 1
  years := base - adjust
} else := 0

# Минимальный возраст по MPAA
age_from_mpaa(a) := n {
  mpaa := get(get(input, "resource", {}), "ratings", {})["mpaa"]
  mpaa != null
  key := norm(mpaa)
  n := get(mpaa_min_age, key, 0)
} else := 0

# Минимальный возраст по PEGI
age_from_pegi() := n {
  pegi := get(get(input, "resource", {}), "ratings", {})["pegi"]
  pegi != null
  n := get(pegi_min_age, pegi, 0)
} else := 0

# Минимальный возраст по ESRB
age_from_esrb() := n {
  esrb := get(get(input, "resource", {}), "ratings", {})["esrb"]
  esrb != null
  key := norm(esrb)
  n := get(esrb_min_age, key, 0)
} else := 0

# Минимальный возраст по тегам (с учетом региональных переопределений)
age_from_tags := max_num({ a |
  tags := get(get(input, "resource", {}), "tags", [])
  t := tags[_]
  # базовая политика
  base := get(tag_min_age, t, 0)
  # региональная настройка
  c := get(get(input, "subject", {}), "country", "")
  override := get(get(region_tag_overrides, c, {}), t, base)
  a := override
})

# Минимальный возраст по ярлыкам издателя
age_from_labels := max_num({ a |
  labels := get(get(input, "resource", {}), "publisher_labels", [])
  l := labels[_]
  a := get(label_min_age, l, 0)
})

# Максимальный допустимый порог из родительского контроля (если включен)
parental_cap := cap {
  pc := get(get(input, "subject", {}), "parental_controls", {})
  get(pc, "enabled", false)
  mr := get(pc, "max_rating", "")
  mr != ""
  # преобразуем к "требуемому возрасту" и используем как "потолок" разрешенного контента
  # Интерпретируем строку max_rating через известные словари; если не нашли — кап не применяется.
  cap_mpaa := get(mpaa_min_age, norm(mr), -1)
  cap_esrb := get(esrb_min_age, norm(mr), -1)
  candidates := {x | x := cap_mpaa; x >= 0} union {x | x := cap_esrb; x >= 0}
  count(candidates) > 0
  cap := min(candidates)
}

#########################################
# Итоговый требуемый возраст
#########################################

required_age := max_num({
  age_from_mpaa(_)
} union {
  age_from_pegi()
} union {
  age_from_esrb()
} union {
  age_from_tags
} union {
  age_from_labels
})

#########################################
# Причины (объяснимость)
#########################################

reasons := reasons_all {
  base := array.concat(
    [], [
      reason_mpaa,
      reason_pegi,
      reason_esrb,
      reason_tags,
      reason_labels,
      reason_parental
    ]
  )
  reasons_all := [r | base[_] != "" ; r := base[_]]
}

reason_mpaa := txt {
  a := age_from_mpaa(_)
  a > 0
  r := get(get(input, "resource", {}), "ratings", {})["mpaa"]
  txt := sprintf("rating.mpaa=%v -> min_age=%v", [r, a])
} else := ""

reason_pegi := txt {
  a := age_from_pegi()
  a > 0
  r := get(get(input, "resource", {}), "ratings", {})["pegi"]
  txt := sprintf("rating.pegi=%v -> min_age=%v", [r, a])
} else := ""

reason_esrb := txt {
  a := age_from_esrb()
  a > 0
  r := get(get(input, "resource", {}), "ratings", {})["esrb"]
  txt := sprintf("rating.esrb=%v -> min_age=%v", [r, a])
} else := ""

reason_tags := txt {
  a := age_from_tags
  a > 0
  tags := get(get(input, "resource", {}), "tags", [])
  txt := sprintf("tags=%v -> min_age=%v", [tags, a])
} else := ""

reason_labels := txt {
  a := age_from_labels
  a > 0
  labels := get(get(input, "resource", {}), "publisher_labels", [])
  txt := sprintf("labels=%v -> min_age=%v", [labels, a])
} else := ""

reason_parental := txt {
  cap := parental_cap
  txt := sprintf("parental_controls.max_rating -> cap_age=%v", [cap])
} else := ""

#########################################
# Обходы (служебные назначения)
#########################################

# Разрешаем служебные обходы для модерации/комплаенса при наличии соответствующих ролей
bypass_allowed {
  purpose := get(get(input, "context", {}), "purpose", "consumption")
  roles := get(get(input, "subject", {}), "roles", [])
  allowed := get(bypass_roles, purpose, {})
  some r
  r := roles[_]
  allowed[r]
}

#########################################
# Обязательства (обработка отказов/частичный доступ)
#########################################

obligations := obj {
  # Требование верификации возраста при отсутствии данных
  need_age_verification := subject_age == 0
  # Кап родительского контроля активен и ресурс его превышает
  over_parental := exceeded_parental
  # Если отказ, можно вернуть безопасные меры: обрезка превью, отключение звука и т. п.
  obj := {
    "require_age_verification": need_age_verification,
    "respect_parental_controls": over_parental,
    "mask_preview": not allow,
    "preview_seconds": cond_int(not allow, 30, 0)
  }
}

cond_int(cond, a, b) := out {
  cond
  out := a
} else := out {
  not cond
  out := b
}

exceeded_parental {
  required_age > parental_cap
}

#########################################
# Совет (необязательная диагностическая нагрузка)
#########################################

advice := a {
  not allow
  a := {
    "message": "Access denied by age policy",
    "required_age": required_age,
    "subject_age": subject_age,
    "factors": reasons
  }
} else := a {
  allow
  a := {
    "message": "Access granted",
    "required_age": required_age,
    "subject_age": subject_age
  }
}

#########################################
# Итоговое решение allow
#########################################

# Разрешение при достаточном возрасте, отсутствии превышения родительского CAP, либо при служебном обходе
allow {
  bypass_allowed
} else {
  subject_age >= required_age
  not exceeded_parental
}

################################################################################
# ПРИМЕЧАНИЯ
# 1) Таблицы соответствий определяют внутреннюю политику продукта и не являются
#    юридическими нормами. Для правовой соответствия используйте региональные
#    переопределения (region_tag_overrides) и внешние регуляторные слои.
# 2) Политика возвращает детальные причины и обязательства для UI/аудита;
#    чувствительные детали не включаются.
################################################################################
