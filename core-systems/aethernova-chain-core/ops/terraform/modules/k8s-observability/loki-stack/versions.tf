############################################################
# Loki Stack — versions.tf (industrial-grade)
# Требуется Terraform 1.8+ для совместимости с современными провайдерами
# и провайдер-определёнными функциями (при их использовании).
############################################################

terraform {
  required_version = ">= 1.8.0, < 2.0.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      # Линейка 3.x (миграция на terraform-plugin-framework, см. релизы 3.0.0+)
      version = ">= 3.0.0, < 4.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      # Современная линейка 2.x (актуальные ресурсы/фиксы Kubernetes API)
      version = ">= 2.36.0, < 3.0.0"
    }
  }
}

# Примечание:
# - Конкретные minor/patch версии чарта Loki указываются в конфигурации helm_release,
#   а не здесь. Этот файл отвечает только за версии Terraform и провайдеров.
