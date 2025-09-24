package datafabric.lineage.guard

# Вход (пример):
# input = {
#   "action": "publish",    # "build" | "publish" | "export"
#   "env": "prod",          # "dev" | "staging" | "prod"
#   "graph": {
#     "nodes": [
#       { "id":"s3://raw/events/2025-08-14",
#         "kind":"dataset",                 # dataset | table | view | stream
#         "owner":"ingest-team",
#         "classification":"internal",      # public|internal|confidential|restricted
#         "pii": true,
#         "pii_level":"strong",             # none|weak|strong
#         "retention":"P30D",
#         "legal_hold": false,
#         "schema_hash":"sha256:...",
#         "tags": ["raw","events"],
#         "controls": { "dlp": false, "k_anonymity":0, "l_diversity":0 }
#       },
#       { "id":"s3://enriched/events_v1",
#         "kind":"dataset",
#         "owner":"ingest-team",
#         "classification":"internal",
#         "pii": true,
#         "pii_level":"weak",
#         "retention":"P180D",
#         "legal_hold": false,
#         "schema_hash":"sha256:...",
#         "tags": ["enriched"],
#         "controls": { "dlp": true, "k_anonymity": 10, "l_diversity": 2 }
#       }
#     ],
#     "edges": [
#       { "from":"s3://raw/events/2025-08-14", "to":"s3://enriched/events_v1",
#         "transform": {
#           "ops": ["parse_json","normalize","mask_email","hash_ip"],
#           "udfs": [],
#           "agg": false
#         }
#       }
#     ]
#   },
#   "sinks": [
#     # только при export/publish: перечисление целевых мест публикации
#     { "type":"s3", "target":"s3://public-datasets/events.csv", "public": true, "dlp_scan_id": "scan-123", "approvals": ["DPO"] }
#   ],
#   "policies": {
#     "min_retention_by_class": { "public":"P7D","internal":"P30D","confidential":"P180D","restricted":"P365D" },
#     "class_rank": { "public":0,"internal":1,"confidential":2,"restricted":3 },
#     "allowed_transforms": {
#       "pii_weak_ok": ["mask_email","truncate","generalize","hash_ip","bucketize_age"],
#       "pii_strong_required": ["tokenize","k_anonymize","noise","differential_privacy"]
#     },
#     "export_requirements": {
#       "public": { "pii_allowed": false, "dlp_required": true, "approvals": ["DPO","Security"] },
#       "partner": { "pii_allowed": true, "dlp_required": true, "contract_required": true }
#     },
#     "legal_hold_inherits": true,
#     "require_schema_hash": true
#   }
# }

default allow := false

# Итоговое решение с причинами и действиями
decision := {
  "allow": allow,
  "reasons": reasons,
  "required_actions": required_actions
}

# Разрешено, если нет причин отказа
allow {
  count(reasons) == 0
}

# Список причин отказов
reasons := sorted(reasons_raw)

# Требуемые действия для комплаенса (подсказки автоматизации)
required_actions := sorted(ractions)
ractions[act] { act := required_action[_] }

# --------------------------- Денай‑правила (агрегируем причины) ---------------------------

# 0) Валидация формы входа
reasons_raw["invalid.action"] {
  not input.action
}
reasons_raw["invalid.env"] {
  not input.env
}
reasons_raw["invalid.graph.nodes.empty"] {
  count(input.graph.nodes) == 0
}
reasons_raw["invalid.graph.edges.cycle"] {
  has_cycle
}
reasons_raw["invalid.node.missing_schema_hash"] {
  input.policies.require_schema_hash
  some n
  node := nodes[n]
  not is_nonempty_string(node.schema_hash)
}

# 1) Нельзя понижать классификацию относительно любого родителя
reasons_raw[sprintf("classification.downgrade:%s->%s for %s", [pclass, cclass, child.id])] {
  parent := parents[child.id][_]
  pclass := parent.classification
  cclass := child.classification
  higher_class(pclass, cclass)
}

# 2) Ретеншн дочернего не короче минимального из родителей
reasons_raw[sprintf("retention.too_short:%s<%s for %s", [child.retention, min_parent_ret(child.id), child.id])] {
  min_parent := min_parent_ret(child.id)
  less_iso_duration(child.retention, min_parent)
}

# 3) Legal hold наследуется
reasons_raw[sprintf("legal_hold.inherited for %s", [child.id])] {
  input.policies.legal_hold_inherits
  some p
  p := parents[child.id][_]
  p.legal_hold
  not child.legal_hold
}

# 4) PII наследуется по умолчанию до доказательства де‑идентификации
reasons_raw[sprintf("pii.deidentification.insufficient for %s", [child.id])] {
  some edge
  edge := edges_map[child.id][_]
  src := node_by_id(edge.from)
  child := node_by_id(edge.to)
  src.pii
  # если родитель strong PII, нужен один из строгих трансформов
  src.pii_level == "strong"
  not has_any(edge.transform.ops, input.policies.allowed_transforms.pii_strong_required)
}
reasons_raw[sprintf("pii.weak_missing_controls for %s k=%v l=%v", [child.id, child.controls.k_anonymity, child.controls.l_diversity])] {
  child := nodes[_]
  child.pii
  child.pii_level == "weak"
  not (child.controls.k_anonymity >= 5)
}

# 5) Недопустимые трансформации поверх PII (прямой join без маскирования)
reasons_raw[sprintf("transform.join_unmasked:%s", [t.to])] {
  edge := edges[_]
  t := edge
  # считаем, что join обозначен ops: ["join"]
  has(edge.transform.ops, "join")
  # любой из источников — PII, но в ops нет маскировок
  src := node_by_id(edge.from)
  dst := node_by_id(edge.to)
  (src.pii or dst.pii)
  not has_any(edge.transform.ops, ["mask_email","generalize","tokenize","k_anonymize","noise"])
}

# 6) Экспорт/публикация наружу с нарушением требований
reasons_raw[sprintf("export.public.pii_forbidden target:%s", [s.target])] {
  input.action == "export"
  some s
  s := input.sinks[_]
  s.public
  child := any_sink_node
  child.pii
}
reasons_raw[sprintf("export.public.dlp_required_missing target:%s", [s.target])] {
  input.action == "export"
  some s
  s := input.sinks[_]
  s.public
  not s.dlp_scan_id
}
reasons_raw[sprintf("export.public.approvals_missing target:%s", [s.target])] {
  input.action == "export"
  some s
  s := input.sinks[_]
  s.public
  not contains_all(s.approvals, input.policies.export_requirements.public.approvals)
}

# 7) Несогласованные владельцы при смешении датасетов с различной ответственностью
reasons_raw[sprintf("ownership.mismatch parent:%s child:%s", [p.owner, c.owner])] {
  some id
  p := parents[id][_]
  c := node_by_id(id)
  p.owner != c.owner
  # разрешим в dev/staging, но требуем action в required_actions
  input.env == "prod"
}

# 8) Запрещенные UDF без аудита
reasons_raw[sprintf("udf.unaudited:%s", [u])] {
  some e
  e := edges[_]
  some u
  u := e.transform.udfs[_]
  not startswith(u, "audited:")
}

# --------------------------- Required actions (мягкие предписания) ---------------------------

required_action["set.legal_hold.child"] {
  input.policies.legal_hold_inherits
  some p
  p := parents[child.id][_]
  p.legal_hold
  not child.legal_hold
}

required_action[sprintf("dlp.scan:%s", [s.target])] {
  input.action == "export"
  some s
  s := input.sinks[_]
  s.public
  not s.dlp_scan_id
}

required_action[sprintf("seek.approvals:%s", [concat(",", missing)])] {
  input.action == "export"
  some s
  s := input.sinks[_]
  s.public
  missing := set_diff(input.policies.export_requirements.public.approvals, s.approvals)
  count(missing) > 0
}

required_action[sprintf("align.owners:parent=%s,child=%s", [p.owner, c.owner])] {
  some id
  p := parents[id][_]
  c := node_by_id(id)
  p.owner != c.owner
  input.env != "prod"
}

# --------------------------- Вспомогательные структуры/функции ---------------------------

nodes := {n.id: n | n := input.graph.nodes[_]}
edges := input.graph.edges
edges_map[to] := [e | e := edges[_]; e.to == to]
parents[to] := [node_by_id(e.from) | e := edges[_]; e.to == to]

node_by_id(id) := nodes[id]

# любые узлы, которые направляются в sinks (для простоты берём все children)
any_sink_node := nodes[_]

class_rank(c) := r {
  r := input.policies.class_rank[c]
}

higher_class(a, b) {
  class_rank(a) > class_rank(b)
}

# Минимальный ретеншн среди родителей (ISO8601 durations, сравнение через parse)
min_parent_ret(id) := minR {
  ps := parents[id]
  rs := [p.retention | p := ps[_]; is_duration(p.retention)]
  minR := min_duration(rs)
}

# Проверка на цикл через подсчёт топологической сортировки (упрощённо):
has_cycle {
  # если есть ребра, но число уникальных вершин на выходе топосорта меньше числа вершин → цикл
  count(input.graph.edges) > 0
  topo_count < count(input.graph.nodes)
}

topo_count := count(toposort([] , nodeset, edges))
nodeset := {n.id | n := input.graph.nodes[_]}

toposort(sorted, remaining, es) = out {
  remaining == {}
  out := sorted
} else = out {
  # выбираем узлы без входящих рёбер
  roots := { x | x := remaining[_]; not has_incoming(x, es) }
  count(roots) == 0
  out := sorted   # тупик, цикл
} else = out {
  roots := { x | x := remaining[_]; not has_incoming(x, es) }
  next := roots
  new_remaining := set_diff(remaining, next)
  new_edges := [ e | e := es[_]; not (e.from in next) ]
  out := toposort(array.concat(sorted, array.fromset(next)), new_remaining, new_edges)
}

has_incoming(x, es) {
  some e
  e := es[_]
  e.to == x
}

# Множества/строки/массивы
set_diff(a, b) := d {
  d := {x | x := a[_]; not contains(b, x)}
}
contains(arr, v) {
  some i
  arr[i] == v
}
contains_all(arr, req) {
  not exists_missing(arr, req)
}
exists_missing(arr, req) {
  some x
  x := req[_]
  not contains(arr, x)
}
has(arr, v) { contains(arr, v) }
has_any(arr, subset) {
  some x
  x := subset[_]
  contains(arr, x)
}
is_nonempty_string(x) {
  x != null
  x != ""
}

# --------------------------- Работа с длительностями (ISO8601) ---------------------------
is_duration(d) {
  startswith(d, "P")
}

less_iso_duration(a, b) {
  da := parse_duration_days(a)
  db := parse_duration_days(b)
  da < db
}

min_duration(rs) := m {
  ds := [parse_duration_days(x) | x := rs[_]]
  m := rs[indexof(ds, min(ds))]
}

# Упрощенный парсер: PnD | PnW | PnM | PnY (оцениваем в днях)
parse_duration_days("P" ++ rest) := days {
  some n
  endswith(rest, "D"); nd := trim_suffix(rest, "D"); n := to_number(nd); days := n
} else := days {
  endswith(rest, "W"); nw := trim_suffix(rest, "W"); days := to_number(nw) * 7
} else := days {
  endswith(rest, "M"); nm := trim_suffix(rest, "M"); days := to_number(nm) * 30
} else := days {
  endswith(rest, "Y"); ny := trim_suffix(rest, "Y"); days := to_number(ny) * 365
} else := 0

trim_suffix(s, suf) := out {
  l := count(s)
  ls := count(suf)
  out := substring(s, 0, l - ls)
}

# --------------------------- Тесты (rego.unit) ---------------------------

# deny downgrade
test_classification_downgrade_denied {
  input := {
    "action":"build","env":"prod",
    "graph":{
      "nodes":[
        {"id":"a","classification":"confidential","pii":false,"pii_level":"none","retention":"P180D","legal_hold":false,"schema_hash":"sha256:x","owner":"t","kind":"dataset"},
        {"id":"b","classification":"internal","pii":false,"pii_level":"none","retention":"P180D","legal_hold":false,"schema_hash":"sha256:y","owner":"t","kind":"dataset"}
      ],
      "edges":[{"from":"a","to":"b","transform":{"ops":[],"udfs":[],"agg":false}}]
    },
    "policies":{
      "class_rank":{"public":0,"internal":1,"confidential":2,"restricted":3},
      "min_retention_by_class":{"public":"P7D","internal":"P30D","confidential":"P180D","restricted":"P365D"},
      "allowed_transforms":{"pii_weak_ok":[],"pii_strong_required":["tokenize"]},
      "export_requirements":{"public":{"pii_allowed":false,"dlp_required":true,"approvals":["DPO","Security"]}},
      "legal_hold_inherits":true,
      "require_schema_hash":true
    }
  }
  reasons_raw[_]
  some r
  r := reasons[_]
  startswith(r, "classification.downgrade:")
  allow == false
}

# allow if no reasons
test_allow_clean_graph {
  input := {
    "action":"build","env":"staging",
    "graph":{
      "nodes":[
        {"id":"raw","classification":"internal","pii":true,"pii_level":"strong","retention":"P30D","legal_hold":false,"schema_hash":"sha256:x","owner":"t","kind":"dataset"},
        {"id":"enr","classification":"internal","pii":true,"pii_level":"weak","retention":"P180D","legal_hold":false,"schema_hash":"sha256:y","owner":"t","kind":"dataset","controls":{"k_anonymity":10,"l_diversity":2}}
      ],
      "edges":[{"from":"raw","to":"enr","transform":{"ops":["tokenize","normalize"],"udfs":[],"agg":false}}]
    },
    "policies":{
      "class_rank":{"public":0,"internal":1,"confidential":2,"restricted":3},
      "min_retention_by_class":{"public":"P7D","internal":"P30D","confidential":"P180D","restricted":"P365D"},
      "allowed_transforms":{"pii_weak_ok":["mask_email"],"pii_strong_required":["tokenize","k_anonymize"]},
      "export_requirements":{"public":{"pii_allowed":false,"dlp_required":true,"approvals":["DPO","Security"]}},
      "legal_hold_inherits":true,
      "require_schema_hash":true
    }
  }
  count(reasons) == 0
  allow == true
}
