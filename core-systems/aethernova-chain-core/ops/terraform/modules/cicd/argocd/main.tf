#############################################
# modules/cicd/argocd/main.tf
# Промышленная установка Argo CD + декларативный проект/приложение
#############################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.11.0"
    }
  }
}

#############################################
# Входные переменные (без внешних файлов)
#############################################

variable "kubeconfig_path" {
  description = "Путь к kubeconfig для подключения к кластеру"
  type        = string
  default     = "~/.kube/config"
}

variable "namespace" {
  description = "Namespace, в котором разворачивается Argo CD"
  type        = string
  default     = "argocd"
}

variable "argo_cd_chart_version" {
  description = "Версия Helm-чарта argo/argo-cd (опционально). Если не задано — будет выбран последний релиз из репозитория."
  type        = string
  default     = ""
}

variable "raw_chart_version" {
  description = "Версия Helm-чарта itscontained/raw (опционально)."
  type        = string
  default     = ""
}

#############################################
# Провайдеры
#############################################

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

#############################################
# Namespace для Argo CD
#############################################

resource "kubernetes_namespace" "argocd" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "argocd"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

#############################################
# Установка Argo CD через Helm
# Чарт: argo/argo-cd (репо https://argoproj.github.io/argo-helm)
# CRD устанавливаются чартом (crds.install=true)
#############################################

resource "helm_release" "argocd" {
  name             = "argo-cd"
  namespace        = var.namespace
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  # version        = var.argo_cd_chart_version != "" ? var.argo_cd_chart_version : null
  # Примечание: Если version не задан — Helm возьмет последний доступный релиз в репозитории.

  create_namespace   = false
  atomic             = true
  cleanup_on_fail    = true
  dependency_update  = true
  disable_openapi_validation = false
  wait               = true
  timeout            = 600

  # Минимально необходимые значения: установка и сохранение CRD чартом
  values = [
    yamlencode({
      crds = {
        install = true
        keep    = true
      }
      # Пример безопасных дефолтов. При необходимости дополняйте.
      controller = {
        replicas = 1
      }
      server = {
        replicas = 1
        service = {
          type = "ClusterIP"
        }
      }
      repoServer = {
        replicas = 1
      }
      applicationSet = {
        enabled  = true
        replicas = 1
      }
      # Пример: включить Prometheus ServiceMonitor при наличии CRD
      metrics = {
        enabled = true
      }
    })
  ]

  depends_on = [kubernetes_namespace.argocd]
}

#############################################
# Bootstrap ресурсов Argo CD (AppProject и пример Application)
# Используем чарт itscontained/raw, который принимает произвольные манифесты
# Это позволяет создать CR (AppProject/Application) в тот же прогон, минуя
# план-тайм схему CRD у провайдера kubernetes.
#############################################

resource "helm_release" "argocd_bootstrap" {
  name       = "argocd-bootstrap"
  namespace  = var.namespace
  repository = "https://charts.itscontained.io"
  chart      = "raw"
  # version  = var.raw_chart_version != "" ? var.raw_chart_version : null

  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 600

  # Определяем AppProject и демонстрационное Application в values
  values = [
    <<-YAML
    resources:
      - apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata:
          name: platform-baseline
          namespace: ${var.namespace}
          labels:
            app.kubernetes.io/managed-by: terraform
        spec:
          description: "Baseline project for platform apps"
          sourceRepos:
            - "https://github.com/argoproj/*"
          destinations:
            - server: "https://kubernetes.default.svc"
              namespace: "*"
          clusterResourceWhitelist:
            - group: "*"
              kind: "*"
          namespaceResourceWhitelist:
            - group: "*"
              kind: "*"

      - apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: guestbook
          namespace: ${var.namespace}
          labels:
            app.kubernetes.io/managed-by: terraform
          finalizers:
            - resources-finalizer.argocd.argoproj.io
        spec:
          project: platform-baseline
          destination:
            server: "https://kubernetes.default.svc"
            namespace: guestbook
          source:
            repoURL: "https://github.com/argoproj/argocd-example-apps"
            path: "helm-guestbook"
            targetRevision: "HEAD"
            helm:
              releaseName: "guestbook"
          syncPolicy:
            automated:
              prune: true
              selfHeal: true
            syncOptions:
              - CreateNamespace=true
    YAML
  ]

  depends_on = [helm_release.argocd]
}

#############################################
# Выводы
#############################################

output "argocd_namespace" {
  description = "Namespace, в котором установлен Argo CD"
  value       = var.namespace
}

output "argocd_helm_release" {
  description = "Имя релиза Argo CD"
  value       = helm_release.argocd.name
}

output "argocd_bootstrap_release" {
  description = "Имя релиза bootstrap-ресурсов (AppProject/Application)"
  value       = helm_release.argocd_bootstrap.name
}
