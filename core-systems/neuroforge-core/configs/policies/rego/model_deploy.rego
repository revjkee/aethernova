package neuroforge.policies.model_deploy

# Политика допуска выпуска ML-модели (OPA/Gatekeeper/Conftest совместима).
# Ожидается, что на уровне OPA передан объект input. См. схему ниже.

# ------------------------------ ДЕФОЛТЫ ------------------------------

default allow := false

# Разрешаем только если нет нарушений и риск не превышает порог среды
allow {
  count(violation) == 0
  risk_score <= max_risk
}

# Выходные поля для удобства (если движок читает произвольные атрибуты)
result := {
  "allow": allow,
  "violations": violation,
  "warnings": warnings,
  "risk_score": risk_score,
  "env": env,
}

# ------------------------------ КОНФИГ ------------------------------

# Конфигурация поступает в data.neuroforge.policy:
# data.neuroforge.policy.default
# data.neuroforge.policy.envs[env]
#
# Пример (YAML/JSON):
# neuroforge:
#   policy:
#     default:
#       max_risk: 20
#       allowed_registries: ["ghcr.io/your-org", "registry.example.com"]
#       require_digest_in_prod: true
#       slsa_min_level: 2
#       vulns_thresholds: { critical: 0, high: 0, medium: 10, low: 999 }
#       licenses_allowlist: ["Apache-2.0","MIT","BSD-3-Clause"]
#       pii: { dlp_required: true, max_retention_days: 30 }
#       fairness: { min_accuracy: 0.6, max_dp_diff: 0.1, max_eo_diff: 0.1 }
#       gpu: { allowed_types: ["nvidia-a10","nvidia-a100"], max_count: 4, cuda_min: "12.0" }
#       runtime: { require_tls_prod: true, forbid_auth_none_prod: true, forbid_cors_any_prod: true, forbid_public_egress_prod: true }
#       k8s: { require_np: true, require_sm: true, require_rootless: true, require_seccomp: "RuntimeDefault" }
#       rollout: { canary_max: 0.2, require_two_approvers_prod: true, maint_window_cron: "0 0 * * 6" }
#       residency: { allowed_regions: ["eu-central-1","eu-north-1"] }
#       budgets: { require_cost_center: true }
#     envs:
#       dev:    { max_risk: 50, vulns_thresholds: { critical: 0, high: 5, medium: 50, low: 999 } }
#       stage:  { max_risk: 30 }
#       prod:   { max_risk: 15 }

config := c {
  # базовая
  base := object.get(data.neuroforge.policy, "default", {})
  # покомпонентные для текущей среды (env)
  env_cfg := object.get(object.get(data.neuroforge.policy, "envs", {}), env, {})
  c := merge(base, env_cfg)
}

# ------------------------------ ВСПОМОГАТЕЛЬНЫЕ ------------------------------

env := lower(input.environment)
max_risk := to_number(object.get(config, "max_risk", 20))

# безопасный доступ к атрибутам
get(obj, path, def) := v {
  v := walk_get(obj, path)
} else := def

walk_get(obj, path) = v {
  is_array(path)
  v := walk_get(obj, path[0], path[1:])
} {
  is_string(path)
  v := object.get(obj, path, undefined)
} {
  count(path) == 0
  v := obj
}

is_array(x) { x == [x[_]] }
is_string(x) { x == sprintf("%v", [x]) }

to_number(x) = n {
  n := to_number_internal(x)
} else = 0

to_number_internal(x) = n {
  n := x
  is_number(n)
} {
  is_string(x)
  n := to_number(json.marshal(x))
}

startswith(s, pfx) { count(split(s, pfx)) > 1; indexof(s, pfx) == 0 }

# сравнение версий CUDA "12.4" >= "12.0"
version_gte(a, b) {
  as := [to_number(x) | x := split(a, ".")[_]]
  bs := [to_number(x) | x := split(b, ".")[_]]
  count(as) >= 2
  count(bs) >= 2
  as[0] > bs[0]  # major
} {
  as := [to_number(x) | x := split(a, ".")[_]]
  bs := [to_number(x) | x := split(b, ".")[_]]
  count(as) >= 2
  count(bs) >= 2
  as[0] == bs[0]
  as[1] >= bs[1] # minor
}

# Сумма массивов чисел
sum_all(arr) = s {
  s := sum([to_number(x) | x := arr[_]])
}

# Подсчёт vuln по тяжести (поддержка двух схем)
vuln_counts := {
  "critical": crit,
  "high": high,
  "medium": med,
  "low": low
} {
  # схема 1: summary.counts
  sc := get(input.security, "vulns.summary", {})
  crit := to_number(object.get(sc, "critical", 0))
  high := to_number(object.get(sc, "high", 0))
  med  := to_number(object.get(sc, "medium", 0))
  low  := to_number(object.get(sc, "low", 0))
} else = m {
  # схема 2: список уязвимостей
  lst := get(input.security, "vulns.items", [])
  m := {
    "critical": count([v | v := lst[_]; lower(object.get(v, "severity", "")) == "critical"]),
    "high":     count([v | v := lst[_]; lower(object.get(v, "severity", "")) == "high"]),
    "medium":   count([v | v := lst[_]; lower(object.get(v, "severity", "")) == "medium"]),
    "low":      count([v | v := lst[_]; lower(object.get(v, "severity", "")) == "low"]),
  }
}

# Окно обслуживания (крон) — мягкое предупреждение (упрощённая проверка по дню недели)
in_maint_window {
  cron := object.get(object.get(config, "rollout", {}), "maint_window_cron", "")
  cron != ""
  # Простейшая эвристика: если в кроне указан день недели 6 (суббота)
  contains(cron, " 6")
}

# ------------------------------ НАРУШЕНИЯ ------------------------------

# 1) Реестр/образ/теги
violation[msg] {
  allowed := object.get(config, "allowed_registries", [])
  img := get(input.artifacts, "image", "")
  not some a in allowed { startswith(img, a) }
  msg := sprintf("image: registry not allowed: %q; allowed: %v", [img, allowed])
}

violation[msg] {
  # Запрещаем mutable теги
  img := get(input.artifacts, "image", "")
  contains(lower(img), ":latest")
  msg := sprintf("image: mutable tag 'latest' is forbidden: %q", [img])
}

violation[msg] {
  # В prod обязателен digest
  env == "prod"
  require := object.get(config, "require_digest_in_prod", true)
  require
  img := get(input.artifacts, "image", "")
  not contains(img, "@sha256:")
  msg := sprintf("image: prod requires digest-pinned image: %q", [img])
}

# 2) Подпись/аттестации/SLSA
violation[msg] {
  not get(input.artifacts, "cosign.verified", false)
  msg := "supply-chain: image signature (cosign) is not verified"
}

violation[msg] {
  min := to_number(object.get(config, "slsa_min_level", 2))
  level := to_number(get(input.artifacts, "slsa.level", 0))
  level < min
  msg := sprintf("supply-chain: SLSA level %v < required %v", [level, min])
}

# 3) SBOM и лицензии
violation[msg] {
  not get(input.security, "sbom.present", false)
  msg := "sbom: SBOM is required (CycloneDX/SPDX) but missing"
}

violation[msg] {
  allow := object.get(config, "licenses_allowlist", [])
  some l in get(input.security, "licenses", [])
  not l == _
  not some ok in allow { ok == l }
  msg := sprintf("license: %q is not in allowlist %v", [l, allow])
}

# 4) Уязвимости/секреты
violation[msg] {
  th := object.get(config, "vulns_thresholds", {"critical":0,"high":0,"medium":10,"low":999})
  vuln_counts.critical > to_number(object.get(th, "critical", 0))
  msg := sprintf("vulns: critical=%v exceeds limit=%v", [vuln_counts.critical, object.get(th,"critical",0)])
}
violation[msg] {
  th := object.get(config, "vulns_thresholds", {"critical":0,"high":0,"medium":10,"low":999})
  vuln_counts.high > to_number(object.get(th, "high", 0))
  msg := sprintf("vulns: high=%v exceeds limit=%v", [vuln_counts.high, object.get(th,"high",0)])
}
violation[msg] {
  get(input.security, "secrets_found", 0) > 0
  msg := "secrets: hardcoded credentials detected in artifacts"
}

# 5) PII/DLP и легальные согласования
violation[msg] {
  get(input.model, "pii", false)
  require_dlp := object.get(object.get(config, "pii", {}), "dlp_required", true)
  require_dlp
  not get(input.controls, "dlp.enabled", false)
  msg := "pii: DLP must be enabled for models processing personal data"
}
violation[msg] {
  get(input.model, "pii", false)
  days := to_number(get(input.controls, "retention_days", 0))
  maxd := to_number(object.get(object.get(config, "pii", {}), "max_retention_days", 30))
  days > maxd
  msg := sprintf("pii: retention_days=%v exceeds max=%v", [days, maxd])
}
violation[msg] {
  get(input.model, "pii", false)
  not get(input.legal, "dpia_approved", false)
  msg := "pii: DPIA/Legal approval is required"
}

# 6) Карточка модели/линейка/метрики/fairness
violation[msg] {
  not get(input.model, "card.exists", false)
  msg := "model-card: missing"
}
violation[msg] {
  not get(input.model, "dataset.lineage_complete", false)
  msg := "dataset: lineage is incomplete"
}
violation[msg] {
  min_acc := to_number(object.get(object.get(config,"fairness",{}), "min_accuracy", 0.6))
  acc := to_number(get(input.metrics, "eval.accuracy", 0))
  acc < min_acc
  msg := sprintf("metrics: accuracy=%v < min=%v", [acc, min_acc])
}
violation[msg] {
  # demographic parity difference / equalized odds
  max_dp := to_number(object.get(object.get(config,"fairness",{}), "max_dp_diff", 0.1))
  dp := to_number(get(input.metrics, "fairness.dp_diff", 0))
  dp > max_dp
  msg := sprintf("fairness: demographic_parity_diff=%v > max=%v", [dp, max_dp])
}
violation[msg] {
  max_eo := to_number(object.get(object.get(config,"fairness",{}), "max_eo_diff", 0.1))
  eo := to_number(get(input.metrics, "fairness.eo_diff", 0))
  eo > max_eo
  msg := sprintf("fairness: equalized_odds_diff=%v > max=%v", [eo, max_eo])
}

# 7) Ресурсы/GPU/CUDA
violation[msg] {
  gpu := object.get(config, "gpu", {})
  req_gpu := to_number(get(input.resources, "gpu.count", 0))
  req_gpu > to_number(object.get(gpu, "max_count", 4))
  msg := sprintf("resources: gpu.count=%v exceeds max=%v", [req_gpu, object.get(gpu,"max_count",4)])
}
violation[msg] {
  # тип GPU должен быть из списка
  gpu := object.get(config, "gpu", {})
  allowed := object.get(gpu, "allowed_types", [])
  t := lower(get(input.resources, "gpu.type", ""))
  allowed != []  # если список задан
  not some a in allowed { lower(a) == t }
  msg := sprintf("resources: gpu.type=%q not in allowed=%v", [t, allowed])
}
violation[msg] {
  # версия CUDA
  gpu := object.get(config, "gpu", {})
  minv := object.get(gpu, "cuda_min", "")
  minv != ""
  reqv := get(input.runtime, "cuda.version", "")
  reqv != ""
  not version_gte(reqv, minv)
  msg := sprintf("runtime: CUDA %q < min %q", [reqv, minv])
}

# 8) Безопасность инференса (TLS/Auth/CORS/egress)
violation[msg] {
  env == "prod"
  req := object.get(config, "runtime", {})
  object.get(req, "require_tls_prod", true)
  not get(input.runtime, "inference.tls.enabled", false)
  msg := "runtime: TLS must be enabled in prod"
}
violation[msg] {
  env == "prod"
  req := object.get(config, "runtime", {})
  object.get(req, "forbid_auth_none_prod", true)
  lower(get(input.runtime, "inference.auth.mode", "none")) == "none"
  msg := "runtime: auth=none is forbidden in prod"
}
violation[msg] {
  env == "prod"
  req := object.get(config, "runtime", {})
  object.get(req, "forbid_cors_any_prod", true)
  some o in get(input.runtime, "inference.cors.allowedOrigins", ["*"])
  o == "*"
  msg := "runtime: CORS * is forbidden in prod"
}
violation[msg] {
  env == "prod"
  req := object.get(config, "runtime", {})
  object.get(req, "forbid_public_egress_prod", true)
  get(input.network, "egress.internet", false)
  msg := "network: public egress is forbidden in prod"
}

# 9) Pod Security / K8s гигиена
violation[msg] {
  object.get(object.get(config,"k8s",{}), "require_np", true)
  not get(input.k8s, "networkPolicy.enabled", false)
  msg := "k8s: NetworkPolicy is required"
}
violation[msg] {
  object.get(object.get(config,"k8s",{}), "require_sm", true)
  not get(input.k8s, "serviceMonitor.enabled", false)
  msg := "k8s: ServiceMonitor is required for metrics"
}
violation[msg] {
  object.get(object.get(config,"k8s",{}), "require_rootless", true)
  not get(input.k8s, "securityContext.runAsNonRoot", false)
  msg := "k8s: runAsNonRoot must be true"
}
violation[msg] {
  req := object.get(object.get(config,"k8s",{}), "require_seccomp", "RuntimeDefault")
  req != ""
  get(input.k8s, "securityContext.seccompProfile.type", "") != req
  msg := sprintf("k8s: seccompProfile.type must be %q", [req])
}
violation[msg] {
  # capabilities должны быть пустыми (или только NET_BIND_SERVICE при необходимости)
  caps := get(input.k8s, "securityContext.capabilities.add", [])
  some c in caps
  not c == _
  lower(c) != "net_bind_service"
  msg := sprintf("k8s: extra capability forbidden: %v", [c])
}

# 10) Стратегия раскатки/аппрувалы
violation[msg] {
  env == "prod"
  maxp := to_number(object.get(object.get(config,"rollout",{}), "canary_max", 0.2))
  p := to_number(get(input.rollout, "canary.weight", 0))
  p > maxp
  msg := sprintf("rollout: canary weight=%v > max=%v", [p, maxp])
}
violation[msg] {
  env == "prod"
  object.get(object.get(config,"rollout",{}), "require_two_approvers_prod", true)
  approvers := get(input.change, "approvers", [])
  count(approvers) < 2
  msg := "change: at least two approvers required in prod"
}
violation[msg] {
  # emergency override допускается только при высоком инциденте и роли SRE+CTO
  get(input.change, "type", "standard") == "emergency"
  sev := lower(get(input.incident, "severity", "low"))
  not (sev == "critical" or sev == "high")
  msg := "change: emergency allowed only for incident severity high/critical"
}
violation[msg] {
  get(input.change, "type", "standard") == "emergency"
  roles := { r | r := get(input.change, "approver_roles", [])[_] }
  not ("sre" in roles and "cto" in roles)
  msg := "change: emergency requires approvers with roles SRE and CTO"
}

# 11) Резидентность данных/бюджеты/теги
violation[msg] {
  regions := get(input.dataflows, "external_regions", [])
  allowed := object.get(object.get(config,"residency",{}), "allowed_regions", [])
  allowed != []
  some r in regions
  not some a in allowed { a == r }
  msg := sprintf("residency: region %q not allowed; allowed=%v", [r, allowed])
}
violation[msg] {
  object.get(object.get(config,"budgets",{}), "require_cost_center", true)
  get(input.metadata, "cost_center", "") == ""
  msg := "metadata: cost_center tag is required"
}

# 12) Мониторинг дрифта/алертов/SLO
violation[msg] {
  not get(input.monitoring, "drift.enabled", false)
  msg := "monitoring: drift detection must be enabled"
}
violation[msg] {
  not get(input.slo, "defined", false)
  msg := "slo: SLO must be defined"
}
violation[msg] {
  not get(input.rollback, "plan_url", "") != ""
  msg := "release: rollback plan URL must be provided"
}

# ------------------------------ ПРЕДУПРЕЖДЕНИЯ ------------------------------

warnings[msg] {
  not in_maint_window
  msg := "rollout: current time seems outside maintenance window (heuristic)"
}
warnings[msg] {
  env != "prod"
  vuln_counts.medium > 0
  msg := sprintf("vulns: medium=%v present (allowed in non-prod)", [vuln_counts.medium])
}
warnings[msg] {
  # distroless рекомендуется
  img := get(input.artifacts, "image", "")
  not contains(lower(img), "distroless")
  msg := "harden: consider distroless/wolfi base image"
}

# ------------------------------ РИСК ------------------------------

# Базовый риск по среде
base_risk := r {
  r := {"dev": 5, "stage": 8, "prod": 10}[env]
} else := 5

risk_score := total {
  total := base_risk
    + risk_supply_chain
    + risk_vulns
    + risk_runtime
    + risk_k8s
    + risk_pii
}

risk_supply_chain := s {
  s := 0
  not get(input.artifacts, "cosign.verified", false)
  s := s + 5
} else := 0

risk_vulns := s {
  s := vuln_counts.critical * 10 + vuln_counts.high * 2 + min([vuln_counts.medium, 10]) * 1
}

risk_runtime := s {
  s := 0
  env == "prod"
  not get(input.runtime, "inference.tls.enabled", false)
  s := s + 5
} else := 0

risk_k8s := s {
  s := 0
  not get(input.k8s, "networkPolicy.enabled", false)
  s := s + 3
  not get(input.k8s, "securityContext.runAsNonRoot", false)
  s := s + 3
}

risk_pii := s {
  s := 0
  get(input.model, "pii", false)
  not get(input.controls, "dlp.enabled", false)
  s := s + 5
} else := 0

# ------------------------------ СХЕМА ОЖИДАНИЙ ------------------------------
# input:
# {
#   "environment": "dev|stage|prod",
#   "artifacts": {
#     "image": "ghcr.io/your-org/app@sha256:...",
#     "cosign": {"verified": true},
#     "slsa": {"level": 2}
#   },
#   "security": {
#     "sbom": {"present": true},
#     "licenses": ["Apache-2.0"],
#     "vulns": { "summary": {"critical":0,"high":0,"medium":3,"low":12} },
#     "secrets_found": 0
#   },
#   "model": {
#     "pii": false,
#     "card": {"exists": true},
#     "dataset": {"lineage_complete": true}
#   },
#   "metrics": {
#     "eval": {"accuracy": 0.82},
#     "fairness": {"dp_diff": 0.04, "eo_diff": 0.05}
#   },
#   "resources": { "gpu": {"count":1,"type":"nvidia-a100"}, "cpu":{"millicores":4000}, "mem":{"gb":16} },
#   "runtime": {
#     "cuda": {"version":"12.2"},
#     "inference": {
#       "tls": {"enabled": true},
#       "auth": {"mode": "jwt"},
#       "cors": {"allowedOrigins": ["https://example.com"] }
#     }
#   },
#   "network": { "egress": {"internet": false} },
#   "k8s": {
#     "networkPolicy": {"enabled": true},
#     "serviceMonitor": {"enabled": true},
#     "securityContext": {
#       "runAsNonRoot": true,
#       "seccompProfile": {"type":"RuntimeDefault"},
#       "capabilities": {"add": []}
#     }
#   },
#   "rollout": { "canary": {"weight": 0.1} },
#   "change": { "type":"standard", "approvers": ["alice","bob"], "approver_roles":["sre","owner"] },
#   "incident": { "severity": "low" },
#   "dataflows": { "external_regions": ["eu-north-1"] },
#   "metadata": { "cost_center":"ML-42" },
#   "monitoring": { "drift": {"enabled": true} },
#   "slo": { "defined": true },
#   "rollback": { "plan_url": "https://runbook/rollback" }
# }
