// aethernova-chain-core/ops/terraform/modules/networking/vpc-gcp/versions.tf
// Контролируем версии Terraform и провайдеров согласно best practices HashiCorp.
// При изменении диапазонов выполните `terraform init -upgrade` в корне,
// чтобы обновить .terraform.lock.hcl.

// Документация по required_version и required_providers:
// - Terraform block: https://developer.hashicorp.com/terraform/language/terraform
// - Provider requirements: https://developer.hashicorp.com/terraform/language/providers/requirements
// - Version constraints: https://developer.hashicorp.com/terraform/language/expressions/version-constraints

terraform {
  // Закрепляем на стабильной ветке 1.x (совместимо с современными провайдерами).
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    // Основной провайдер GCP. Переход на 7.x подтверждён GA и имеет breaking changes;
    // поэтому задаём «>=7.0,<8.0» для предсказуемых минорных апдейтов без скачка на 8.x.
    google = {
      source  = "hashicorp/google"
      version = ">= 7.0.0, < 8.0.0"
    }

    // Дополнительный провайдер с бета-ресурсами/полями GCP.
    // Держим в одном мажоре с google для согласованности API.
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 7.0.0, < 8.0.0"
    }
  }
}
