// Path: aethernova-chain-core/ops/terraform/modules/_templates/versions.tf
// Purpose: Единый промышленный шаблон ограничений версий Terraform и провайдеров.
// Facts:
// - required_version ограничивает версию Terraform CLI. :contentReference[oaicite:1]{index=1}
// - Версии провайдеров задаются ТОЛЬКО в terraform.required_providers (а не в provider-блоках). :contentReference[oaicite:2]{index=2}
// - Синтаксис версионных ограничений описан в официальном справочнике. :contentReference[oaicite:3]{index=3}
// - Фактический выбор конкретных версий фиксируйте в .terraform.lock.hcl и коммитьте в VCS. :contentReference[oaicite:4]{index=4}

terraform {
  // Рекомендуем жёстко задавать нижнюю границу CLI, совместимую с используемыми фичами,
  // и удерживаться в пределах 1.x (на момент подготовки шаблона).
  // Синтаксис ограничений: "оператор версия", разделение запятыми. :contentReference[oaicite:5]{index=5}
  required_version = ">= 1.6.0, < 2.0.0"

  // Все провайдеры объявляются здесь: адрес в реестре и допустимый диапазон версий.
  // Адрес провайдера имеет форму hostname/namespace/type (пример: registry.terraform.io/hashicorp/kubernetes). :contentReference[oaicite:6]{index=6}
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.0, < 3.0.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.0.0, < 3.0.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0, < 5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0, < 4.0.0"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0.0, < 4.0.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.0.0, < 3.0.0"
    }
    external = {
      source  = "hashicorp/external"
      version = ">= 2.0.0, < 3.0.0"
    }
    http = {
      source  = "hashicorp/http"
      version = ">= 3.0.0, < 4.0.0"
    }
  }

  // Примечание по экосистеме:
  // Если вы используете OpenTofu, блок остаётся terraform { } согласно совместимости 1.x. :contentReference[oaicite:7]{index=7}
}

// ВАЖНО: точные версии провайдеров закрепляются автоматически в .terraform.lock.hcl при `terraform init`.
// Обязательно коммитьте lock-файл, чтобы обеспечить воспроизводимость сборок в CI/CD. :contentReference[oaicite:8]{index=8}
