terraform {
  # Требуем современные версии Terraform CLI для совместимости с актуальными провайдерами
  required_version = ">= 1.12.0, < 2.0.0"

  required_providers {
    # Управление GitHub (репозитории, команды, Actions и т.д.)
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }

    # Управление GitLab (группы, проекты, раннеры и т.д.)
    gitlab = {
      source  = "gitlabhq/gitlab"
      version = "~> 18.0"
    }

    # Деплой раннеров в Kubernetes-кластере
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }

    # Управление Helm-чартами (например, ARC/GitLab Runner чарты)
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }

    # Облачные провайдеры (если раннеры создаются IaaS/PaaS-ресурсами)
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0.0, < 5.0.0"
    }

    google = {
      source  = "hashicorp/google"
      version = ">= 7.0.0, < 8.0.0"
    }
  }
}
