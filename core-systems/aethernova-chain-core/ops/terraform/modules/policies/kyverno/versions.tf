// path: aethernova-chain-core/ops/terraform/modules/policies/kyverno/versions.tf
// SPDX-License-Identifier: Apache-2.0
// Purpose: Pin Terraform/Core provider constraints for the Kyverno policies module.
// Notes:
// - Этот модуль НЕ конфигурирует провайдеры; он только объявляет требования и алиасы.
// - Провайдеры настраиваются в корневом модуле и передаются сюда явным образом через `providers`.
// - `helm` используется для установки Kyverno (если установка выполняется этим или соседним модулем).
// - `kubernetes` используется для управления объектами Kyverno (Policy/ClusterPolicy и пр.) через ресурсы провайдера.

terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      // Держимся в пределах мажора 2.x для предсказуемых апгрейдов.
      version = ">= 2.0.0, < 3.0.0"
      // Примеры алиасов, задаваемых в корневом модуле:
      // provider "helm" { alias = "primary" ... }
      // provider "helm" { alias = "ops"     ... }
      configuration_aliases = [
        helm.primary,
        helm.ops
      ]
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      // Управление k8s-ресурсами и CRD через kubernetes_manifest (включая Kyverno-политики).
      version = ">= 2.0.0, < 3.0.0"
      // Примеры алиасов, задаваемых в корневом модуле:
      // provider "kubernetes" { alias = "primary" ... }
      // provider "kubernetes" { alias = "ops"     ... }
      configuration_aliases = [
        kubernetes.primary,
        kubernetes.ops
      ]
    }
  }
}
