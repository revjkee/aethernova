############################################################
# Path: ops/terraform/modules/security/iam/versions.tf
# Purpose: Version pinning & provider requirements for IAM module
#
# Verified references (официальные источники для перепроверки):
# - required_providers / version constraints:
#   https://developer.hashicorp.com/terraform/language/providers/requirements
#   https://developer.hashicorp.com/terraform/language/expressions/version-constraints
# - Dependency lock file (практики фиксации версий):
#   https://developer.hashicorp.com/terraform/language/files/dependency-lock
# - Using providers in modules / configuration_aliases:
#   https://developer.hashicorp.com/terraform/language/modules/develop/providers
# - AWS provider (registry page):
#   https://registry.terraform.io/providers/hashicorp/aws/latest
# - random provider (registry page):
#   https://registry.terraform.io/providers/hashicorp/random/latest
# - tls provider (registry page):
#   https://registry.terraform.io/providers/hashicorp/tls/latest
############################################################

terraform {
  # Совместимость с современными возможностями провайдеров и modules.
  # См. "Specifying a Required Terraform Version".
  # https://developer.hashicorp.com/terraform/language/settings#specifying-a-required-terraform-version
  required_version = ">= 1.6.0"

  # Обязательные провайдеры для данного IAM-модуля.
  # Версионные ограничения даны в формате semver-constraints (>= low, < next-major),
  # чтобы минимизировать риск ломающих изменений (см. ссылки на constraints выше).
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
      # Модуль умеет принимать несколько конфигураций (алиасов) провайдера AWS из корня:
      # передавайте, например, aws.primary, aws.replica, aws.audit.
      # Документация по configuration_aliases:
      # https://developer.hashicorp.com/terraform/language/modules/develop/providers#provider-aliases-within-modules
      configuration_aliases = [
        aws.primary,
        aws.replica,
        aws.audit
      ]
    }

    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0, < 4.0.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0, < 5.0.0"
    }
  }
}

# Пояснения:
# 1) required_version использует semver-ограничение (>= 1.6.0), см. HashiCorp docs.
#    https://developer.hashicorp.com/terraform/language/settings#specifying-a-required-terraform-version
#
# 2) required_providers:
#    - Синтаксис и назначение описаны в официальной документации:
#      https://developer.hashicorp.com/terraform/language/providers/requirements
#    - Версионные ограничения документированы здесь:
#      https://developer.hashicorp.com/terraform/language/expressions/version-constraints
#    - Рекомендация фиксировать зависимости в .terraform.lock.hcl:
#      https://developer.hashicorp.com/terraform/language/files/dependency-lock
#
# 3) configuration_aliases:
#    Модуль объявляет, какие алиасы провайдера он готов принять из корня (aws.primary, aws.replica, aws.audit).
#    Подробности: https://developer.hashicorp.com/terraform/language/modules/develop/providers#provider-aliases-within-modules
#
# Примечание:
# - Конкретные «последние» версии провайдеров зависят от вашего момента времени и окружения.
#   Актуальные версии и их изменения проверяйте на страницах реестра провайдеров:
#   AWS:   https://registry.terraform.io/providers/hashicorp/aws/latest
#   random:https://registry.terraform.io/providers/hashicorp/random/latest
#   tls:   https://registry.terraform.io/providers/hashicorp/tls/latest
# - Утверждать конкретный «последний» номер версии без проверки реестра я не могу —
#   Не могу подтвердить это.
