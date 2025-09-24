// path: aethernova-chain-core/ops/terraform/modules/k8s-observability/loki-stack/main.tf
// SPDX-License-Identifier: Apache-2.0

#############################
# Helm values (typed map)   #
#############################

locals {
  # Базовые значения для subcharts loki / grafana / promtail
  values_base = {
    loki = {
      enabled     = true
      # Простейшая персистентность (настраивается переменными модуля)
      persistence = {
        enabled          = var.loki_persistence_enabled
        storageClassName = var.loki_storage_class
        size             = var.loki_pvc_size
      }
    }

    grafana = {
      enabled       = var.grafana_enabled
      adminPassword = var.grafana_admin_password # sensitive в variables.tf
      persistence = {
        enabled          = var.grafana_persistence_enabled
        storageClassName = var.grafana_storage_class
        size             = var.grafana_pvc_size
      }
    }

    promtail = {
      # Важно: Promtail переведён в LTS и имеет объявленный EOL; делаем опциональным
      enabled = var.promtail_enabled
      # Пример: можно передать tolerations/affinity через var.promtail_overrides
    }
  }

  # Тонкие переопределения сверху (передаются как map(any))
  values_overrides = coalesce(var.extra_values, {})

  # Итоговые значения для чарта (плоское merge верхнего уровня; внутри чарт сам сольёт с defaults)
  values = merge(local.values_base, local.values_overrides)
}

#########################################
# Helm release: grafana/loki-stack      #
#########################################

resource "helm_release" "loki_stack" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = var.create_namespace

  repository = var.repository_url   # по умолчанию: https://grafana.github.io/helm-charts
  chart      = "loki-stack"
  version    = var.chart_version    # например: "2.10.2" (пример версии чарта на момент написания)

  # Безопасная стратегия деплоя
  atomic            = true
  dependency_update = true
  wait              = true
  timeout           = var.timeout_seconds

  # Основные значения как YAML
  values = [
    yamlencode(local.values),
    # Дополнительные values-файлы (если заданы); порядок важен
    for f in var.values_files : file(f)
  ]

  # Мета
  max_history = var.max_history
}
