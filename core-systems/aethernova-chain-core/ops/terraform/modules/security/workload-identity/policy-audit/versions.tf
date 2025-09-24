# aethernova-chain-core/ops/terraform/modules/security/policy-audit/versions.tf
#
# Источники (проверяемые):
# - Provider Requirements (required_providers/source):
#   https://developer.hashicorp.com/terraform/language/providers/requirements
# - Terraform block / required_version и область действия:
#   https://developer.hashicorp.com/terraform/language/terraform
# - Version constraints синтаксис (~>, >=, <):
#   https://developer.hashicorp.com/terraform/language/expressions/version-constraints
# - AWS provider IAM policy resources (пример: aws_iam_policy):
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy
# - Создание IAM-политик (гайд):
#   https://developer.hashicorp.com/terraform/tutorials/aws/aws-iam-policy
# - Факт существования актуальной ветки 6.x AWS-провайдера (релизы):
#   https://github.com/hashicorp/terraform-provider-aws/releases
# - Пояснение о провайдерах от AWS PG:
#   https://docs.aws.amazon.com/prescriptive-guidance/latest/getting-started-terraform/providers.html

terraform {
  # Ограничиваем Terraform CLI на стабильную ветку 1.x:
  # - Минимум 1.6 для современных конструкций и поведения.
  # - Жёсткое верхнее < 2.0.0, т.к. мажор 2.x может внести несовместимости.
  #   (required_version управляет только версией CLI, не провайдерами.)
  #   Документация: language/terraform + version-constraints.
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # Официальный AWS-провайдер от HashiCorp.
    # Фиксация на мажоре 6 (релизы 6.x подтверждены в официальном репозитории).
    # Семантика ограничений: "~> 6.0" разрешит 6.y.z, но не 7.0.0+.
    # Документация: provider requirements + version constraints.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Пояснения для продакшена:
# 1) Дочерние модули обязаны явно объявлять требования к провайдерам (они не наследуются автоматически).
#    См. Provider Requirements.
# 2) required_version относится только к версии Terraform CLI (а не к версиям провайдеров);
#    версии провайдеров закрепляются в required_providers. См. Terraform block reference.
# 3) Policy-audit модуль, как правило, использует ресурсы IAM/организаций/CloudTrail/Config и пр. через aws-провайдер.
#    Пример декларации ресурсов IAM-политик: aws_iam_policy / data "aws_iam_policy_document" (см. ссылки выше).
# 4) Для воспроизводимости храните .terraform.lock.hcl в VCS и управляйте обновлениями провайдеров по политике версии.
