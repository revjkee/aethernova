package lib.helpers

# Используем future.keywords для современного синтаксиса Rego.
# (Совместимо с OPA/Gatekeeper v3+)
import future.keywords.every
import future.keywords.if
import future.keywords.in

################################################################################
# 0) БАЗОВЫЕ ФУНКЦИИ ВВОДА / НОРМАЛИЗАЦИИ
################################################################################

# Возвращает полный review-объект Gatekeeper (совместимо с разными источниками)
review := input.review

# Объект (k8s resource) в admission review
obj := review.object

# Метаданные объекта
metadata(o) := o.metadata if o.metadata
metadata(o) := {}        if not o.metadata

# kind / apiVersion с безопасными значениями по умолчанию
kind(o) := o.kind        if o.kind
kind(_) := ""

apiVersion(o) := o.apiVersion if o.apiVersion
apiVersion(_) := ""

# Имя/namespace
name(o) := m.name        if m := metadata(o); m.name
name(_) := ""

namespace(o) := m.namespace if m := metadata(o); m.namespace
namespace(_) := ""

# Группы/версии/ресурсы из review (иногда полезно)
gvr := {
  "group":   review.gvk.group,
  "version": review.gvk.version,
  "kind":    review.gvk.kind,
}

################################################################################
# 1) ОПРЕДЕЛЕНИЕ ЯВЛЯЕТСЯ ЛИ РЕСУРС РАБОЧЕЙ НАГРУЗКОЙ И ПОЛУЧЕНИЕ POD-ШАБЛОНА
################################################################################

is_pod(o) {
  lower(kind(o)) == "pod"
}

is_workload(o) {
  lk := lower(kind(o))
  lk == "deployment"    or
  lk == "statefulset"   or
  lk == "daemonset"     or
  lk == "replicaset"    or
  lk == "job"           or
  lk == "cronjob"
}

# Возвращает PodSpec для Pod
podspec_from_pod(o) := o.spec if is_pod(o)

# Возвращает PodSpec из типичных контроллеров
podspec_from_workload(o) := o.spec.template.spec if is_workload(o) and o.spec and o.spec.template and o.spec.template.spec

# CronJob -> JobTemplate -> PodSpec
podspec_from_cronjob(o) := o.spec.jobTemplate.spec.template.spec if lower(kind(o)) == "cronjob" and o.spec and o.spec.jobTemplate and o.spec.jobTemplate.spec and o.spec.jobTemplate.spec.template and o.spec.jobTemplate.spec.template.spec

# Унифицированный доступ к PodSpec: Pod или Workload
podspec(o) := podspec_from_pod(o)     if is_pod(o)
podspec(o) := podspec_from_workload(o) if is_workload(o)
podspec(o) := podspec_from_cronjob(o)  if lower(kind(o)) == "cronjob"

has_podspec(o) {
  podspec(o)
}

################################################################################
# 2) ИТЕРАТОРЫ ПО КОНТЕЙНЕРАМ/INIT-КОНТЕЙНЕРАМ/EPHEMERAL
################################################################################

containers(o) := ps.containers      if ps := podspec(o); ps.containers
containers(_) := []

init_containers(o) := ps.initContainers if ps := podspec(o); ps.initContainers
init_containers(_) := []

ephemeral_containers(o) := ps.ephemeralContainers if ps := podspec(o); ps.ephemeralContainers
ephemeral_containers(_) := []

all_containers(o) := cs {
  cs := concat_arrays([containers(o), init_containers(o), ephemeral_containers(o)])
}

# Вспомогательная: склеивает массивы
concat_arrays(arrs) := out {
  out := []
  every a in arrs {
    out := array.concat(out, a)
  }
}

################################################################################
# 3) СТРОКИ/СЕТЫ/КАРТЫ: УТИЛИТЫ
################################################################################

lower(s) := lower_s {
  lower_s := lower_ascii(s)
}

# Безопасное взятие ключа (map_get)
map_get(m, k, def) := v  if m[k]; v := m[k]
map_get(_, _, def)  := def

# Проверка пустоты
is_empty(x) {
  count(x) == 0
}

# Уникальные элементы списка
unique(xs) := arr {
  s := {x | x := xs[_]}
  arr := [x | x := s[_]]
}

# Пересечение множеств списков строк
intersect(a, b) := out {
  set_a := {x | x := a[_]}
  set_b := {y | y := b[_]}
  out   := [z | z := set_a[_]; z in set_b]
}

# Разность множеств
diff(a, b) := out {
  set_b := {y | y := b[_]}
  out   := [x | x := a[_]; not x in set_b]
}

# Есть ли пересечение хоть одного элемента
any_intersect(a, b) {
  intersect(a, b)[_]
}

################################################################################
# 4) LABEL/ANNOTATION/OWNERREFS/SELECTORS
################################################################################

labels(o) := m.labels if m := metadata(o); m.labels
labels(_) := {}

annotations(o) := m.annotations if m := metadata(o); m.annotations
annotations(_) := {}

owner_references(o) := m.ownerReferences if m := metadata(o); m.ownerReferences
owner_references(_) := []

# Проверка наличия набора меток с точными значениями
labels_match(o, required) {
  l := labels(o)
  every k in keys(required) {
    l[k] == required[k]
  }
}

# Проверка наличия ключей аннотаций
has_annotations(o, required_keys) {
  a := annotations(o)
  every k in required_keys {
    a[k]
  }
}

################################################################################
# 5) ИСКЛЮЧЕНИЯ ПО НAMESPACE/ANNOTATION/ЛЕЙБЛАМ
################################################################################

in_exempt_namespaces(o, exempt_ns) {
  ns := namespace(o)
  ns in exempt_ns
}

has_exempt_annotation(o, key_values) {
  a := annotations(o)
  some k
  some v
  key_values[k] == v
  a[k] == v
}

has_exempt_label(o, key_values) {
  l := labels(o)
  some k
  some v
  key_values[k] == v
  l[k] == v
}

################################################################################
# 6) ОБРАБОТКА ОБРАЗОВ, РЕГИСТРИ ВАЛИДАЦИЯ
################################################################################

# Возвращает список всех образов из всех типов контейнеров
all_images(o) := imgs {
  imgs := [c.image | c := all_containers(o)[_]; c.image]
}

# Парсинг docker image "registry/repo:tag@digest" в части
image_parts(img) := out {
  # выделяем digest (если есть)
  digest := ""
  rest   := img
  some i
  i := indexof(img, "@")
  i >= 0
  digest := substring(img, i+1, -1)
  rest   := substring(img, 0, i)

  # раздел tag (после :)
  tag := ""
  rest2 := rest
  some j
  j := last_index_of(rest, ":")
  j >= 0
  # убедимся, что ":" не часть схемы в реестре (обычно порт), но оставим как есть
  # берём всё после последнего ":"
  tag := substring(rest, j+1, -1)
  # если в правой части присутствует "/" — это не tag, а часть пути с портом; откатим
  # простая эвристика:
  not contains(tag, "/")
  rest2 := substring(rest, 0, j)

  registry := ""
  repo     := rest2
  # Если есть "/", левая часть может быть реестром/портом
  some k
  k := indexof(rest2, "/")
  k >= 0
  left  := substring(rest2, 0, k)
  right := substring(rest2, k+1, -1)
  # если в left есть '.' или ':' — считаем это реестром
  cond := contains(left, ".") or contains(left, ":") or left == "localhost"
  registry := left        if cond
  repo     := right       if cond

  # Если нет "/", тогда repo остаётся целиком, registry пуст
  out := {"registry": registry, "repository": repo, "tag": tag, "digest": digest}
}

# Простой contains для строк
contains(s, sub) {
  indexof(s, sub) >= 0
}

# Индекс первого вхождения
indexof(s, sub) := i if i := indexof(s, sub)
indexof(_, _) := -1

# Индекс ПОСЛЕДНЕГО вхождения подстроки
last_index_of(s, sub) := idx {
  idx := -1
  some i
  i := indexof(s, sub)
  i >= 0
  rest := substring(s, i+1, -1)
  next := last_index_of(rest, sub)
  idx  := i if next == -1
  idx  := i + 1 + next if next >= 0
}

################################################################################
# 7) РЕСУРСЫ: CPU/MEM PARSERS, BYTES/CORES
################################################################################

# Парсинг CPU (например "100m", "0.5", "2")
cpu_millicores(s) := n {
  is_number(s)
  # уже число ядeр => перевести в millicores
  n := int(s * 1000)
} else := n {
  endswith(lower(s), "m")
  base := trim_suffix(lower(s), "m")
  n := to_number(base)
} else := n {
  # plain cores
  not endswith(lower(s), "m")
  n := int(to_number(s) * 1000)
}

# Парсинг Memory (например "128Mi", "1Gi", "100M", "1024Ki", "200m" - не для mem)
# Возвращает в байтах
mem_bytes(s) := n {
  u := lower(s)
  # Двоичные суффиксы
  endswith(u, "ki"); n := int(to_number(trim_suffix(u, "ki")) * 1024)
} else := n {
  endswith(u, "mi"); n := int(to_number(trim_suffix(u, "mi")) * 1024 * 1024)
} else := n {
  endswith(u, "gi"); n := int(to_number(trim_suffix(u, "gi")) * 1024 * 1024 * 1024)
} else := n {
  endswith(u, "ti"); n := int(to_number(trim_suffix(u, "ti")) * 1024 * 1024 * 1024 * 1024)
} else := n {
  endswith(u, "pi"); n := int(to_number(trim_suffix(u, "pi")) * 1024 * 1024 * 1024 * 1024 * 1024)
} else := n {
  endswith(u, "ei"); n := int(to_number(trim_suffix(u, "ei")) * 1024 * 1024 * 1024 * 1024 * 1024 * 1024)
} else := n {
  # Десятичные суффиксы
  endswith(u, "k");  n := int(to_number(trim_suffix(u, "k"))  * 1000)
} else := n {
  endswith(u, "m");  n := int(to_number(trim_suffix(u, "m"))  * 1000 * 1000)
} else := n {
  endswith(u, "g");  n := int(to_number(trim_suffix(u, "g"))  * 1000 * 1000 * 1000)
} else := n {
  endswith(u, "t");  n := int(to_number(trim_suffix(u, "t"))  * 1000 * 1000 * 1000 * 1000)
} else := n {
  endswith(u, "p");  n := int(to_number(trim_suffix(u, "p"))  * 1000 * 1000 * 1000 * 1000 * 1000)
} else := n {
  endswith(u, "e");  n := int(to_number(trim_suffix(u, "e"))  * 1000 * 1000 * 1000 * 1000 * 1000 * 1000)
} else := n {
  # без суффиксов — считаем байты
  n := int(to_number(u))
}

endswith(s, suf) {
  sl := count(s)
  tl := count(suf)
  tl <= sl
  substring(s, sl - tl, sl) == suf
}

trim_suffix(s, suf) := out {
  sl := count(s)
  tl := count(suf)
  out := substring(s, 0, sl - tl)
}

# Возвращает requests/limits по CPU/Memory в удобном виде
container_resources(c) := {
  "cpu_request_m":  cpu_millicores(map_get(map_get(c, "resources", {}), "requests", {})["cpu"], 0),
  "cpu_limit_m":    cpu_millicores(map_get(map_get(c, "resources", {}), "limits",   {})["cpu"], 0),
  "mem_request_b":  mem_bytes(map_get(map_get(c, "resources", {}), "requests", {})["memory"], 0),
  "mem_limit_b":    mem_bytes(map_get(map_get(c, "resources", {}), "limits",   {})["memory"], 0),
} if c

# Перегрузка cpu_millicores/mem_bytes с дефолтом
cpu_millicores(s, def) := def if not s
cpu_millicores(s, _)   := cpu_millicores(s) if s

mem_bytes(s, def) := def if not s
mem_bytes(s, _)   := mem_bytes(s) if s

################################################################################
# 8) ПОРТЫ, ПРОТОКОЛЫ
################################################################################

container_ports(c) := ps {
  ps := [p | p := c.ports[_]]
} else := []

# Валидность диапазона портов
is_valid_port(p) {
  p >= 1
  p <= 65535
}

# Валидные протоколы
is_valid_protocol(proto) {
  lower(proto) == "tcp" or lower(proto) == "udp" or lower(proto) == "sctp"
}

################################################################################
# 9) SECURITY CONTEXT / CAPABILITIES / USER/GROUP / SECCOMP / APPARMOR
################################################################################

# ContainerSecurityContext
csec(c) := c.securityContext if c.securityContext
csec(_) := {}

# PodSecurityContext
psec(o) := ps.securityContext if ps := podspec(o); ps.securityContext
psec(_) := {}

# Linux Capabilities
cap_add(c)  := map_get(map_get(csec(c), "capabilities", {}), "add", [])
cap_drop(c) := map_get(map_get(csec(c), "capabilities", {}), "drop", [])

# runAsUser/runAsGroup/fsGroup (унаследование: container > pod)
run_as_user(c, o) := u if u := csec(c).runAsUser
run_as_user(_, o) := u if u := psec(o).runAsUser

run_as_group(c, o) := g if g := csec(c).runAsGroup
run_as_group(_, o) := g if g := psec(o).runAsGroup

fs_group(o) := g if g := psec(o).fsGroup

# readOnlyRootFilesystem
readonly_rootfs(c) {
  csec(c).readOnlyRootFilesystem == true
}

# allowPrivilegeEscalation
allow_priv_escalation(c) := b if b := csec(c).allowPrivilegeEscalation
allow_priv_escalation(_) := true  # по умолчанию в k8s true, если не задано

# privileged
is_privileged(c) := true if csec(c).privileged == true
is_privileged(_) := false

# seccompProfile на уровне PodSpec (k8s >= 1.19+)
seccomp_profile_pod(o) := p if p := psec(o).seccompProfile
seccomp_profile_container(c) := p if p := csec(c).seccompProfile

# apparmor аннотации (k8s)
apparmor_profile(o, cname) := annotations(o)[sprintf("container.apparmor.security.beta.kubernetes.io/%s", [cname])]

################################################################################
# 10) ППОЛИТИКИ И СЕТЕВЫЕ НАСТРОЙКИ POD
################################################################################

host_network(o) {
  ps := podspec(o)
  ps.hostNetwork == true
}

host_pid(o) {
  ps := podspec(o)
  ps.hostPID == true
}

host_ipc(o) {
  ps := podspec(o)
  ps.hostIPC == true
}

# capabilities baseline/restricted множества (примерные)
cap_baseline := {
  "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
  "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID",
  "SYS_CHROOT"
}

cap_restricted := {
  # Пусто — максимально жёсткий профиль: все должны быть сброшены
}

# Проверка, что все add capabilities находятся в разрешённом множестве
caps_add_subset_of(c, allowed) {
  every x in cap_add(c) { upper(x) in allowed }
}

upper(s) := upper_ascii(s)

################################################################################
# 11) ДОП. ВАЛИДАЦИИ: DNS1123, SEMVER, ДУБЛИКАТЫ
################################################################################

# Упрощённая DNS-1123 label проверка
is_dns1123_label(s) {
  re_match("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", s)
  count(s) <= 63
}

# SemVer сравнение: возвращает -1/0/1 как компаратор
semver_cmp(a, b) := r {
  pa := semver_parse(a)
  pb := semver_parse(b)
  r := -1 if pa.major < pb.major
  r :=  1 if pa.major > pb.major
  r := -1 if pa.major == pb.major; pa.minor < pb.minor
  r :=  1 if pa.major == pb.major; pa.minor > pb.minor
  r := -1 if pa.major == pb.major; pa.minor == pb.minor; pa.patch < pb.patch
  r :=  1 if pa.major == pb.major; pa.minor == pb.minor; pa.patch > pb.patch
  r :=  0 if pa.major == pb.major; pa.minor == pb.minor; pa.patch == pb.patch
}

semver_parse(s) := {"major": ma, "minor": mi, "patch": pa} {
  parts := split(trim_prefix(lower(s), "v"), ".")
  ma := to_int_default(parts[0], 0)
  mi := to_int_default(map_get(parts, 1, "0"), 0)
  pa := to_int_default(map_get(parts, 2, "0"), 0)
}

to_int_default(s, d) := d if not is_number_string(s)
to_int_default(s, _) := int(s) if is_number_string(s)

is_number_string(s) {
  re_match("^[0-9]+$", s)
}

trim_prefix(s, pre) := out {
  startswith(s, pre)
  out := substring(s, count(pre), -1)
} else := s

startswith(s, pre) {
  count(pre) <= count(s)
  substring(s, 0, count(pre)) == pre
}

# Дубликаты в списке
duplicates(xs) := dups {
  seen := {}
  dups := [x |
    x := xs[_];
    (x in seen; true) else { seen := seen ∪ {x}; false }
  ]
  dups != []
}

################################################################################
# 12) ПРИМЕРНЫЕ ХЕЛПЕРЫ ДЛЯ ПРАКТИК ПОЛИТИК
################################################################################

# Требовать imagePullPolicy=Always, если тег :latest
violates_pull_policy_latest(o, viol) {
  c := all_containers(o)[_]
  img := c.image
  parts := image_parts(img)
  parts.tag == "latest"
  ipp := map_get(c, "imagePullPolicy", "IfNotPresent")
  ipp != "Always"
  viol := {
    "container": map_get(c, "name", ""),
    "image": img,
    "reason": "latest tag requires imagePullPolicy=Always",
  }
}

# Запретить hostNetwork/hostPID/hostIPC
violates_host_namespaces(o, viol) {
  host_network(o)
  viol := {"field": "spec.hostNetwork", "reason": "hostNetwork not allowed"}
} else := viol {
  host_pid(o)
  viol := {"field": "spec.hostPID", "reason": "hostPID not allowed"}
} else := viol {
  host_ipc(o)
  viol := {"field": "spec.hostIPC", "reason": "hostIPC not allowed"}
}

# Пример: запрет привилегированных контейнеров
violates_privileged(c) {
  is_privileged(c)
}

# Пример: требовать readOnlyRootFilesystem=true
violates_readonly_rootfs(c) {
  not readonly_rootfs(c)
}

# Пример: добавленные capabilities вне разрешённого профиля
violates_capabilities(c, allowed_set) {
  some x
  x := cap_add(c)[_]
  upper(x) not in allowed_set
}

# Пример: проверка диапазонов портов и протоколов
violates_ports(c, viol) {
  p := container_ports(c)[_]
  (p.containerPort; not is_valid_port(p.containerPort))
  viol := {"container": map_get(c, "name", ""), "port": p.containerPort, "reason": "invalid port"}
} else := viol {
  p := container_ports(c)[_]
  proto := lower(map_get(p, "protocol", "tcp"))
  not is_valid_protocol(proto)
  viol := {"container": map_get(c, "name", ""), "port": map_get(p, "containerPort", 0), "reason": sprintf("invalid protocol: %s", [proto])}
}

################################################################################
# 13) УНИВЕРСАЛЬНЫЕ ФОРМАТТЕРЫ ОШИБОК/ПРЕДУПРЕЖДЕНИЙ
################################################################################

format_violation(msg, field, details) := {
  "msg": msg,
  "field": field,
  "details": details,
  "resource": {
    "kind": kind(obj),
    "name": name(obj),
    "namespace": namespace(obj),
    "apiVersion": apiVersion(obj),
  },
}

# Быстрый рендер в человекочитаемую строку
render_violation(v) := sprintf("%s [field=%s] %v (kind=%s ns=%s name=%s)", [
  map_get(v, "msg", ""),
  map_get(v, "field", ""),
  map_get(v, "details", {}),
  map_get(map_get(v, "resource", {}), "kind", ""),
  map_get(map_get(v, "resource", {}), "namespace", ""),
  map_get(map_get(v, "resource", {}), "name", ""),
])

################################################################################
# 14) ПРИМЕР: СБОРКА КОМБО-НАРУШЕНИЙ ДЛЯ CONTROLLERS/POds
################################################################################

collect_container_violations(o, allowed_caps) := out {
  out := [
    {"container": map_get(c, "name", ""), "type": "privileged"} |
    c := all_containers(o)[_];
    violates_privileged(c)
  ]

  out := array.concat(out, [
    {"container": map_get(c, "name", ""), "type": "readonly_rootfs"} |
    c := all_containers(o)[_];
    violates_readonly_rootfs(c)
  ])

  out := array.concat(out, [
    {"container": map_get(c, "name", ""), "type": "capabilities", "add": cap_add(c)} |
    c := all_containers(o)[_];
    violates_capabilities(c, allowed_caps)
  ])

  out := array.concat(out, [
    {"container": map_get(c, "name", ""), "type": "ports", "detail": v} |
    c := all_containers(o)[_];
    v := violates_ports(c, _)
  ])
}

################################################################################
# 15) БЕЗОПАСНЫЕ КОНВЕРТЕРЫ/ГЕТТЕРЫ
################################################################################

# Преобразование в число (с дефолтом)
to_number(s) := n {
  is_number(s)
  n := s
} else := n {
  is_string(s)
  n := to_float_compat(s)
} else := 0

# Совместимость с OPA: одни сборки не поддерживают to_number для float-строк
to_float_compat(s) := n {
  re_match("^[0-9]+(\\.[0-9]+)?$", s)
  parts := split(s, ".")
  n := int(parts[0]) if count(parts) == 1
  n := (int(parts[0]) + (to_frac(parts[1]))) if count(parts) == 2
} else := 0

to_frac(p) := f {
  # "5" -> 0.5, "25" -> 0.25 (строго для дробной части)
  base := to_int_default(p, 0)
  denom := pow10(count(p))
  f := base / denom
}

pow10(n) := r {
  r := 1
  every _i in [1..n] {
    r := r * 10
  }
}

################################################################################
# 16) КЭНАРИИ: БЕЗОПАСНЫЕ ПРОВЕРКИ СУЩЕСТВОВАНИЯ ПОЛЕЙ
################################################################################

has_field(o, p) {
  # p как массив ключей, например ["spec","template","spec","containers"]
  v := o
  every k in p {
    v[k]
    v := v[k]
  }
}

################################################################################
# 17) ПРИМЕР: ОБЩИЕ ПАТТЕРНЫ ДЛЯ CONSTRAINTS (ГОТОВЫЕ КРУПИЦЫ)
################################################################################

# Выдаёт нарушения за latest-пулл-полиси
violations_pull_policy_latest := [
  format_violation(
    "image with :latest must set imagePullPolicy=Always",
    "spec.*.containers[*].imagePullPolicy",
    v,
  )
  |
  v := violates_pull_policy_latest(obj, _)
]

# Выдаёт нарушения по host* namespace
violations_host_ns := [
  format_violation(
    "host namespace usage is not allowed",
    v.field,
    {"reason": v.reason},
  )
  |
  v := violates_host_namespaces(obj, _)
]

# Итоговый набор helper-нарушений
helper_violations(allowed_caps) := all {
  all := array.concat(
    violations_pull_policy_latest,
    violations_host_ns,
  )

  # Добавим контейнерные:
  cviol := collect_container_violations(obj, allowed_caps)
  all := array.concat(all, [
    format_violation(
      "container security violation",
      "spec.*.containers[*]",
      v,
    ) | v := cviol[_]
  ])
}
