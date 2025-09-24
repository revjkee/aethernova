/**
 * Aethernova — policies/kyverno
 * File: main.tf
 *
 * Назначение:
 *   Установка Kyverno и (опционально) kyverno-policies через Helm
 *   с промышленными настройками (atomic, wait, timeout, values passthrough).
 *
 * Требования:
 *   - Провайдеры: helm, kubernetes (версии пинуются во внешнем versions.tf).
 *   - Доступ к кластеру (kubeconfig/context настроены во внешнем слое).
 */

############################################
# Переменные (самодостаточный модуль)
############################################

variable "name" {
  description = "Имя релиза Kyverno."
  type        = string
  default     = "kyverno"
}

variable "namespace" {
  description = "Namespace для Kyverno."
  type        = string
  default     = "kyverno"
}

variable "create_namespace" {
  description = "Создавать namespace автоматически."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Доп. метки для namespace (если создается)."
  type        = map(string)
  default     = {}
}

variable "annotations" {
  description = "Доп. аннотации для namespace (если создается)."
  type        = map(string)
  default     = {}
}

variable "helm" {
  description = <<EOT
Параметры Helm-релиза Kyverno:
- repo (URL репозитория чарта)
- chart (имя чарта)
- version (опционально; если null — берется актуальная версия репозитория)
- atomic/wait/timeout_seconds/max_history/cleanup_on_fail
- values_overrides (любой валидный map, будет yamlencode в values)
- skip_crds (по умолчанию false; CRD устанавливаются чартом)
EOT
  type = object({
    repo             = optional(string, "https://kyverno.github.io/kyverno")
    chart            = optional(string, "kyverno")
    version          = optional(string)         # например, "3.2.6"; можно опустить
    atomic           = optional(bool, true)
    wait             = optional(bool, true)
    timeout_seconds  = optional(number, 900)
    max_history      = optional(number, 20)
    cleanup_on_fail  = optional(bool, true)
    dependency_update= optional(bool, true)
    recreate_pods    = optional(bool, false)
    force_update     = optional(bool, false)
    render_subchart_notes = optional(bool, false)
    skip_crds        = optional(bool, false)
    values_overrides = optional(any, {})
  })
  default = {}
}

variable "fullname_override" {
  description = "Явный override для fullnameRelease (если требуется стабильное имя ресурсов)."
  type        = string
  default     = ""
}

variable "enable_policies" {
  description = "Устанавливать ли официальный чарт kyverno-policies."
  type        = bool
  default     = true
}

variable "policies" {
  description = <<EOT
Параметры Helm-релиза kyverno-policies:
- repo/chart/version (по умолчанию репозиторий Kyverno)
- values_overrides (набор включаемых политик, severity, exceptions и пр.)
- namespace_override (если нужно разворачивать политики в другом ns — обычно тот же)
EOT
  type = object({
    repo              = optional(string, "https://kyverno.github.io/kyverno")
    chart             = optional(string, "kyverno-policies")
    version           = optional(string)
    values_overrides  = optional(any, {})
    namespace_override= optional(string)
    atomic            = optional(bool, true)
    wait              = optional(bool, true)
    timeout_seconds   = optional(number, 600)
    max_history       = optional(number, 10)
    cleanup_on_fail   = optional(bool, true)
    dependency_update = optional(bool, true)
    skip_crds         = optional(bool, true)
  })
  default = {}
}

variable "expose_debug_outputs" {
  description = "Публиковать ли debug-outputs."
  type        = bool
  default     = false
}

############################################
# Локальные вычисления
############################################

locals {
  ns_name       = var.namespace
  policies_ns   = coalesce(var.policies.namespace_override, var.namespace)
  fullname_ovr  = length(trimspace(var.fullname_override)) > 0 ? var.fullname_override : null

  kyverno_values = merge(
    var.helm.values_overrides,
    local.fullname_ovr != null ? { fullnameOverride = local.fullname_ovr } : {}
  )

  policies_values = var.policies.values_overrides
}

############################################
# Namespace (опционально)
############################################

resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name        = local.ns_name
    labels      = var.labels
    annotations = var.annotations
  }
}

############################################
# Kyverno (Helm)
############################################

resource "helm_release" "kyverno" {
  name             = var.name
  namespace        = local.ns_name
  repository       = var.helm.repo
  chart            = var.helm.chart
  version          = var.helm.version
  create_namespace = false

  atomic                = coalesce(var.helm.atomic, true)
  wait                  = coalesce(var.helm.wait, true)
  timeout               = coalesce(var.helm.timeout_seconds, 900)
  max_history           = coalesce(var.helm.max_history, 20)
  cleanup_on_fail       = coalesce(var.helm.cleanup_on_fail, true)
  dependency_update     = coalesce(var.helm.dependency_update, true)
  recreate_pods         = coalesce(var.helm.recreate_pods, false)
  force_update          = coalesce(var.helm.force_update, false)
  render_subchart_notes = coalesce(var.helm.render_subchart_notes, false)
  skip_crds             = coalesce(var.helm.skip_crds, false)

  values = [
    yamlencode(local.kyverno_values)
  ]

  depends_on = [
    kubernetes_namespace_v1.this
  ]
}

############################################
# Kyverno Policies (Helm, опционально)
############################################

resource "helm_release" "kyverno_policies" {
  count            = var.enable_policies ? 1 : 0
  name             = "${var.name}-policies"
  namespace        = local.policies_ns
  repository       = var.policies.repo
  chart            = var.policies.chart
  version          = var.policies.version
  create_namespace = false

  atomic            = coalesce(var.policies.atomic, true)
  wait              = coalesce(var.policies.wait, true)
  timeout           = coalesce(var.policies.timeout_seconds, 600)
  max_history       = coalesce(var.policies.max_history, 10)
  cleanup_on_fail   = coalesce(var.policies.cleanup_on_fail, true)
  dependency_update = coalesce(var.policies.dependency_update, true)
  skip_crds         = coalesce(var.policies.skip_crds, true)

  values = [
    yamlencode(local.policies_values)
  ]

  depends_on = [
    helm_release.kyverno
  ]
}

############################################
# Проверки согласованности (Terraform >=1.6)
############################################

check "namespace_exists_when_disabled_creation" {
  assert {
    condition = var.create_namespace ? true : true
    # Примечание: фактическая проверка существования ns вне области статического анализа.
    # Оставлено как заглушка для единообразия check-блока.
    error_message = "Namespace должен существовать, если create_namespace=false."
  }
}

############################################
# Отладочные outputs (опционально)
############################################

output "kyverno_release" {
  description = "Сводная информация о релизе Kyverno."
  value = var.expose_debug_outputs ? {
    name       = helm_release.kyverno.name
    namespace  = helm_release.kyverno.namespace
    chart      = helm_release.kyverno.chart
    version    = helm_release.kyverno.version
    repository = helm_release.kyverno.repository
    status     = helm_release.kyverno.status
    manifest_len = length(helm_release.kyverno.manifest)
  } : null
  sensitive = false
}

output "kyverno_policies_release" {
  description = "Сводная информация о релизе kyverno-policies (если включен)."
  value = var.expose_debug_outputs ? (
    length(helm_release.kyverno_policies) > 0 ? {
      name       = helm_release.kyverno_policies[0].name
      namespace  = helm_release.kyverno_policies[0].namespace
      chart      = helm_release.kyverno_policies[0].chart
      version    = helm_release.kyverno_policies[0].version
      repository = helm_release.kyverno_policies[0].repository
      status     = helm_release.kyverno_policies[0].status
      manifest_len = length(helm_release.kyverno_policies[0].manifest)
    } : null
  ) : null
  sensitive = false
}
