terraform {
  # Поддержка стабильной ветки Terraform 1.x без перехода на 2.0
  required_version = ">= 1.0.0, < 2.0.0"

  required_providers {
    # Управление ресурсами Kubernetes (манифесты, CRD и т.д.)
    kubernetes = {
      source  = "hashicorp/kubernetes"
      # Патч-обновления в пределах линии 2.38.x, зафиксированной по последним релизам 2.x
      version = "~> 2.38"
    }

    # Установка и управление Helm-чартами
    helm = {
      source  = "hashicorp/helm"
      # Разрешаем минорные обновления в пределах мажора 3.x (совместим с Terraform >= 1.0)
      version = "~> 3.0"
    }
  }
}
