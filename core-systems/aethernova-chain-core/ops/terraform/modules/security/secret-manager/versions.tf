############################################################
# aethernova-chain-core/ops/terraform/modules/security/secret-manager/versions.tf
#
# Источники (проверяемые):
# - Provider requirements (required_providers/source): https://developer.hashicorp.com/terraform/language/providers/requirements
# - Terraform block / required_version: https://developer.hashicorp.com/terraform/language/terraform
# - Version constraints (~>, >=, <): https://developer.hashicorp.com/terraform/language/expressions/version-constraints
# - AWS Secrets Manager ресурсы: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret
# - Random provider: https://registry.terraform.io/providers/hashicorp/random/latest
# - Time provider: https://registry.terraform.io/providers/hashicorp/time/latest
# - Child modules must declare provider requirements: https://developer.hashicorp.com/terraform/language/block/provider
############################################################

terraform {
  # Требуемая версия Terraform CLI:
  # - ">= 1.6.0, < 2.0.0" — гарантирует доступность синтаксиса и поведения 1.x,
  #   блокируя потенциально несовместимый мейджор 2.x (см. docs по required_version и constraints).
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # Провайдер AWS — необходим для aws_secretsmanager_* ресурсов.
    # source фиксируется на официальном "hashicorp/aws" (см. Provider Requirements).
    # Версия закреплена в пределах мажора 5 (семантика ~>): обновления патч/минор без перехода на 6.x.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }

    # Random — для генерации паролей/сидов/суффиксов секретов и пр.
    # Закрепляемся в мажоре 3.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }

    # Time — для управления временем ротации/границами обновлений (delay/offset и т.д.).
    # Фиксация на мажоре 0.13 (актуальная линейка 0.x).
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}

# ПРИМЕЧАНИЯ ДЛЯ ПРОМЫШЛЕННОГО ИСПОЛЬЗОВАНИЯ:
# 1) Дочерние модули НЕ наследуют требования к провайдерам; их нужно объявлять здесь (см. Provider Block Reference).
# 2) required_version управляет ТОЛЬКО версией Terraform CLI, а не версией провайдеров
#    (см. Terraform block reference). Для провайдеров используйте required_providers.
# 3) Для воспроизводимости закрепляйте версии и поддерживайте .terraform.lock.hcl в VCS.
