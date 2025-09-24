// path: aethernova-chain-core/ops/terraform/modules/networking/firewall/versions.tf
// SPDX-License-Identifier: Apache-2.0

terraform {
  // Требуемая версия Terraform CLI.
  // Жесткая «вилка» в пределах 1.x для предсказуемого поведения планирования.
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      // Ограничение версии провайдера AWS в рамках мажорной ветки 5.x.
      // Выберите конкретный нижний порог под ваш CI (примерно с 5.50.0+),
      // здесь — безопасное окно без перехода на 6.x.
      version = ">= 5.50.0, < 6.0.0"

      // Модуль НЕ настраивает провайдеры, а лишь объявляет,
      // какие алиасы он готов принять от корня.
      // Примеры в root:
      // provider "aws" { alias = "primary"    region = "eu-central-1" }
      // provider "aws" { alias = "inspection" region = "eu-west-1"   }
      // provider "aws" { alias = "logs"       region = "eu-central-1" }
      // module "firewall" {
      //   source = "./modules/networking/firewall"
      //   providers = {
      //     aws.primary    = aws.primary
      //     aws.inspection = aws.inspection
      //     aws.logs       = aws.logs
      //   }
      // }
      configuration_aliases = [
        aws.primary,     // основной аккаунт/регион для ресурсов Firewall
        aws.inspection,  // сегмент/регион инспекции трафика
        aws.logs         // выделенный аккаунт/регион для логирования
      ]
    }
  }
}

// Примечания по совместимости:
// - В этом модуле предполагается использование ресурсов AWS Network Firewall:
//   aws_networkfirewall_firewall, aws_networkfirewall_firewall_policy,
//   aws_networkfirewall_rule_group.
// - Настройка конкретных провайдеров (provider "aws" {...}) в модулях запрещена;
//   конфигурации и алиасы задаются только в корне.
