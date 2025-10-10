// path: aethernova-chain-core/ops/terraform/modules/k8s-observability/grafana/versions.tf
// SPDX-License-Identifier: Apache-2.0
// Purpose: Pin Terraform/Core provider constraints for the Grafana-on-Kubernetes module.
// Notes:
// - Модуль НЕ конфигурирует провайдеры; он только объявляет требования и алиасы.
// - Алиасы позволяют передавать разные контексты кластеров/доступов из корня.

terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      # Закрепляем в пределах мажорной ветки 2.x для предсказуемости будущих апгрейдов.
      version = ">= 2.0.0, < 3.0.0"
      # Примеры в корне:
      # provider "helm" { alias = "primary" ... }
      # provider "helm" { alias = "ops"     ... }
      configuration_aliases = [
        helm.primary,
        helm.ops
      ]
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.0, < 3.0.0"
      # Если модуль создаёт k8s-объекты (ConfigMap, Secret и т.д.), алиасы помогут
      # разделить контексты (рабочий кластер vs. административный).
      configuration_aliases = [
        kubernetes.primary,
        kubernetes.ops
      ]
    }

    # Опционально: для провижининга дашбордов/датасорсов через API Grafana.
    grafana = {
      source  = "grafana/grafana"
      version = ">= 1.0.0, < 4.0.0"
      configuration_aliases = [
        grafana.dashboards
      ]
    }
  }
}
