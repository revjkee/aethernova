package cybersecurity.network_guard

default allow := false

# Главный объект решения: агрегирует причины/обязательства/правила
decision := {
  "allow": allow,
  "policy_version": "1.0.0",
  "tenant": tenant_id,
  "matched_rules": matched_rules,
  "reasons": reasons_array,
  "obligations": obligations
}

tenant_id := input.tenant_id else := "default"

# Получение конфигурации арендатора или "default"
tenant_cfg := t {
  t := data.network_guard.tenants[tenant_id]
} else := t {
  t := data.network_guard.tenants["default"]
}

# ===============================
# Основная логика разрешения
# ===============================

# Приоритет 0: breakglass (экстренное разрешение) при валидном токене
allow {
  is_breakglass
  reasons["breakglass_override"]
  obligations_log_info
}

# Приоритет 1: quarantine при высоком риске (явный deny)
deny_reason["risk_quarantine"] {
  risk_quarantine
}

# Приоритет 2: явные deny-правила из конфигурации
deny_reason[r.id] {
  r := some_rule_deny
  rule_matches(r)
}

# Приоритет 3: глобальный blocklist (CIDR/FQDN)
deny_reason["blocklist_cidr"] {
  dst_ip := destination_ip
  cidr := tenant_cfg.blocklist.cidrs[_]
  net.cidr_contains(cidr, dst_ip)
}
deny_reason["blocklist_domain"] {
  d := lower(destination_domain)
  sfx := tenant_cfg.blocklist.domains.suffixes[_]
  endswith(d, lower(sfx))
} {
  d := lower(destination_domain)
  ex := tenant_cfg.blocklist.domains.exact[_]
  d == lower(ex)
}

# Если есть причины deny — финальный запрет
deny {
  count(deny_reason) > 0
}

# Приоритет 4: явные allow-правила
allow {
  r := some_rule_allow
  rule_matches(r)
  reasons[r.id]
  obligations_log_info
}

# Приоритет 5: режим egress
# allowlist: разрешаем только домены/подсети из allowlist
allow {
  egress_mode_is_allowlist
  allowed_by_allowlist
  allowed_global_ports
  not dns_restricted_violation
  obligations_log_info
}

# blocklist: разрешаем всё, что не попало в deny и не нарушает глобальные политики
allow {
  egress_mode_is_blocklist
  allowed_global_ports
  not dns_restricted_violation
  obligations_log_info
}

# По умолчанию — отказ
deny {
  not allow
}

# ===============================
# Причины/обязательства/совпавшие правила
# ===============================

reasons[k] {
  k := deny_reason[_]
}
reasons[k] {
  k := reasons_allow[_]
}
reasons_array := arr {
  arr := [r | r := reasons[_]]
}

matched_rules[r.id] {
  r := some_rule_allow
  rule_matches(r)
}
matched_rules[r.id] {
  r := some_rule_deny
  rule_matches(r)
}

obligations := obs {
  some o
  o := {
    "action": "log",
    "level": "info",
    "sink": tenant_cfg.logging.sink,            # например: kafka/opensearch
    "stream": tenant_cfg.logging.stream,        # например: "security.network.decisions"
  }
  obs := [o] ++ alerting_obligations
}

alerting_obligations := arr {
  arr := [o | o := block_alert] ++ [o | o := risk_alert]
}
block_alert := {
  "action": "alert",
  "severity": "high",
  "reason": "deny",
} {
  deny
}
risk_alert := {
  "action": "alert",
  "severity": "critical",
  "reason": "risk_quarantine",
} {
  risk_quarantine
}

obligations_log_info {
  true
}

# ===============================
# Удобные алиасы input.*
# ===============================

source_ns := s { s := input.source.namespace }
source_svc := s { s := input.source.service }
source_labels := l { l := input.source.labels }

destination_ns := s { s := input.destination.namespace }
destination_svc := s { s := input.destination.service }
destination_labels := l { l := input.destination.labels }
destination_ip := ip { ip := input.destination.ip }
destination_domain := d { d := input.destination.domain }
destination_port := p { p := to_number(input.destination.port) }
destination_proto := pr { pr := lower(input.destination.protocol) }

ctx_weekday := wd { wd := input.context.weekday }    # например: "Mon".."Sun"
ctx_time_hhmm := tm { tm := input.context.time }     # "HH:MM"
ctx_breakglass_token := bg { bg := input.override.token }
ctx_breakglass := b { b := input.override.breakglass }

risk_score := s { s := to_number(input.risk.score) }

# ===============================
# Breakglass и риск
# ===============================

is_breakglass {
  ctx_breakglass
  token := ctx_breakglass_token
  token != ""
  token == tenant_cfg.breakglass.token
}

risk_quarantine {
  thr := tenant_cfg.risk.quarantine_threshold
  risk_score >= thr
}

# ===============================
# Режимы egress
# ===============================

egress_mode_is_allowlist {
  tenant_cfg.egress.mode == "allowlist"
}

egress_mode_is_blocklist {
  tenant_cfg.egress.mode == "blocklist"
}

allowed_by_allowlist {
  some ok
  ok := allowlist_domain_ok or allowlist_cidr_ok
}

allowlist_domain_ok {
  d := lower(destination_domain)
  sfx := tenant_cfg.allowlist.domains.suffixes[_]
  endswith(d, lower(sfx))
} {
  d := lower(destination_domain)
  ex := tenant_cfg.allowlist.domains.exact[_]
  d == lower(ex)
}

allowlist_cidr_ok {
  dst_ip := destination_ip
  cidr := tenant_cfg.allowlist.cidrs[_]
  net.cidr_contains(cidr, dst_ip)
}

# ===============================
# Глобальные ограничения портов/протоколов
# ===============================

allowed_global_ports {
  allowed_port_proto(destination_port, destination_proto)
}

allowed_port_proto(p, proto) {
  some spec
  spec := tenant_cfg.global.allowed_ports_by_proto[proto][_]
  port_spec_match(p, spec)
}

port_spec_match(p, spec) {
  # spec может быть числом
  is_number(spec)
  to_number(spec) == p
} {
  # spec как объект диапазона: {"start": 1024, "end": 65535}
  spec.start <= p
  p <= spec.end
}

# ===============================
# DNS ограничения (пример: разрешать UDP/53 только к одобренным DNS)
# ===============================

dns_restricted_violation {
  destination_proto == "udp"
  destination_port == 53
  not dns_target_approved
}

dns_target_approved {
  # Разрешаем, если IP попадает в список одобренных DNS
  dst_ip := destination_ip
  net.cidr_contains(tenant_cfg.dns.allowed_cidrs[_], dst_ip)
} {
  # Или FQDN совпадает с одобренными именами
  d := lower(destination_domain)
  endswith(d, lower(tenant_cfg.dns.allowed_suffixes[_]))
}

# ===============================
# Явные правила allow/deny
# ===============================

some_rule_allow := r {
  r := tenant_cfg.policies[_]
  r.effect == "allow"
}

some_rule_deny := r {
  r := tenant_cfg.policies[_]
  r.effect == "deny"
}

rule_matches(r) {
  src_ok(r.src)
  dst_ok(r.dst)
  time_ok(r.time_windows)
}

src_ok(src) {
  ns_ok(src.namespaces, source_ns)
  svc_ok(src.services, source_svc)
  labels_ok(src.labels, source_labels)
}

dst_ok(dst) {
  ns_ok(dst.namespaces, destination_ns)
  svc_ok(dst.services, destination_svc)
  labels_ok(dst.labels, destination_labels)
  nets_ok(dst.cidrs, destination_ip)
  domains_ok(dst.domains, destination_domain)
  ports_ok(dst.ports, destination_port)
  protos_ok(dst.protocols, destination_proto)
}

ns_ok(allowed, ns) {
  allowed == null; ns == ns
} {
  allowed != null
  allowed[_] == ns
}

svc_ok(allowed, svc) {
  allowed == null; svc == svc
} {
  allowed != null
  allowed[_] == svc
}

nets_ok(cidrs, ip) {
  cidrs == null; ip == ip
} {
  cidrs != null
  some c
  c := cidrs[_]
  net.cidr_contains(c, ip)
}

domains_ok(dom_cfg, d) {
  dom_cfg == null; d == d
} {
  dom_cfg != null
  d != ""
  some s
  s := dom_cfg.suffixes[_]
  endswith(lower(d), lower(s))
} {
  dom_cfg != null
  d != ""
  some e
  e := dom_cfg.exact[_]
  lower(d) == lower(e)
}

ports_ok(ports, p) {
  ports == null; p == p
} {
  ports != null
  some spec
  spec := ports[_]
  port_spec_match(p, spec)
}

protos_ok(protos, pr) {
  protos == null; pr == pr
} {
  protos != null
  some pp
  pp := lower(protos[_])
  pp == pr
}

labels_ok(sel, labels) {
  sel == null; labels == labels
} {
  sel != null
  every k := sel {
    label_selector_match(k, sel[k], labels)
  }
}

label_selector_match(k, cond, labels) {
  cond.exists == true
  labels[k]
} {
  cond.eq != null
  labels[k] == cond.eq
} {
  cond.in != null
  labels[k] == cond.in[_]
} {
  cond.re != null
  re_match(cond.re, labels[k])
}

# ===============================
# Временные окна
# ===============================

time_ok(windows) {
  windows == null
} {
  windows != null
  some w
  w := windows[_]
  weekday_match(w.days)
  clock_match(w.start, w.end)
}

weekday_match(days) {
  days == null
} {
  days != null
  wd := ctx_weekday
  days[_] == wd
}

clock_match(start, end) {
  st := parse_hhmm(start)
  en := parse_hhmm(end)
  now := parse_hhmm(ctx_time_hhmm)
  st <= now
  now <= en
}

parse_hhmm(s) = m {
  parts := split(s, ":")
  h := to_number(parts[0])
  mm := to_number(parts[1])
  m := h*60 + mm
}

# ===============================
# Причины deny/allow
# ===============================

deny_reason[r] {
  r := "risk_quarantine"
  risk_quarantine
}
deny_reason[r] {
  r := k
  k := keys({x | x := deny_ids[_]})[_]
}
deny_ids[rid] {
  rid := some_rule_deny.id
  rule_matches(some_rule_deny)
}
reasons_allow[rid] {
  rid := some_rule_allow.id
  rule_matches(some_rule_allow)
}

# ===============================
# Утилиты
# ===============================

lower(s) := ls {
  ls := lower_ascii(s)
} else := s {
  not is_string(s)
}

is_number(x) {
  to_number(x) == to_number(x)
}
