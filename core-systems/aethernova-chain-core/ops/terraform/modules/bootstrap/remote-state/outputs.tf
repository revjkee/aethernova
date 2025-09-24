###############################################################################
# Remote State — Outputs (S3 + DynamoDB + KMS)
#
# Ожидаемые ресурсы (рекомендуемые имена внутри модуля):
#   - aws_s3_bucket.remote_state
#   - aws_dynamodb_table.remote_state_lock
#   - aws_kms_key.remote_state        (опционально, если включено шифрование)
#   - aws_kms_alias.remote_state      (опционально)
#
# Ожидаемые переменные:
#   - var.region       (string)   : регион AWS, где создан backend (напр. "eu-central-1")
#   - var.key_prefix   (string)   : префикс ключей state (напр. "terraform/states")
#   - var.tags         (map(string)) : теги, примененные к ресурсам
#
# Назначение:
#   - Выдача минимально необходимого набора данных для:
#       1) terraform init -backend-config
#       2) генерации IAM политики read-only на state
#       3) автоматизаций в CI/CD (агрегированные карты и JSON-строки)
###############################################################################

############################
# S3 Bucket — basic outputs
############################
output "s3_bucket_name" {
  description = "Имя S3 бакета для Terraform remote state."
  value       = aws_s3_bucket.remote_state.bucket
}

output "s3_bucket_arn" {
  description = "ARN S3 бакета для Terraform remote state."
  value       = aws_s3_bucket.remote_state.arn
}

#########################################
# DynamoDB Lock Table — basic outputs
#########################################
output "dynamodb_table_name" {
  description = "Имя DynamoDB таблицы для блокировок Terraform state."
  value       = aws_dynamodb_table.remote_state_lock.name
}

output "dynamodb_table_arn" {
  description = "ARN DynamoDB таблицы для блокировок Terraform state."
  value       = aws_dynamodb_table.remote_state_lock.arn
}

#####################
# KMS — basic outputs
#####################
# Если шифрование включено и ключ создан модулем.
output "kms_key_id" {
  description = "KMS Key ID, используемый для шифрования объектов state (если применимо)."
  value       = try(aws_kms_key.remote_state.key_id, null)
  sensitive   = false
}

output "kms_key_arn" {
  description = "KMS Key ARN, используемый для шифрования объектов state (если применимо)."
  value       = try(aws_kms_key.remote_state.arn, null)
  sensitive   = false
}

output "kms_alias_arn" {
  description = "KMS Alias ARN для ключа (если определен)."
  value       = try(aws_kms_alias.remote_state.arn, null)
  sensitive   = false
}

###########################
# Common / meta information
###########################
output "region" {
  description = "Регион AWS, где размещены backend-ресурсы."
  value       = var.region
}

output "key_prefix" {
  description = "Префикс ключей Terraform state в бакете (без имени файла, только путь)."
  value       = var.key_prefix
}

output "tags_effective" {
  description = "Итоговый набор тегов, примененных в модуле."
  value       = var.tags
}

#############################################
# Backend config for `terraform init`
# Удобные мапы: подставьте workspace и относительный key при инициализации.
#############################################
# Базовый конфиг для backend s3 без указания file key.
output "backend_base_config" {
  description = <<EOT
Базовый набор параметров для -backend-config при terraform init.
Включает bucket, region и dynamodb_table. Параметры key и kms_key_id могут
быть заданы отдельно в зависимости от окружения/воркспейса.
EOT
  value = {
    backend         = "s3"
    bucket          = aws_s3_bucket.remote_state.bucket
    region          = var.region
    dynamodb_table  = aws_dynamodb_table.remote_state_lock.name
    encrypt         = true
  }
}

# Полный конфиг backend с учетом KMS и префикса ключей.
# Для конкретного окружения дополните ключом: "${var.key_prefix}/env/<env>.tfstate"
output "backend_full_config_template" {
  description = <<EOT
Шаблон полного backend-конфига. Поле key следует задать извне (напр., через CI),
например: "${var.key_prefix}/env/prod.tfstate".
Если KMS не используется, kms_key_id будет null — это допустимо.
EOT
  value = {
    backend         = "s3"
    bucket          = aws_s3_bucket.remote_state.bucket
    region          = var.region
    dynamodb_table  = aws_dynamodb_table.remote_state_lock.name
    encrypt         = true
    kms_key_id      = try(aws_kms_key.remote_state.key_id, null)
    key_prefix      = var.key_prefix
  }
}

# Готовая строка JSON с backend-конфигом (без key), удобно для CLI/скриптов.
output "backend_base_config_json" {
  description = "JSON строка с базовым backend-конфигом (без key)."
  value = jsonencode({
    backend        = "s3"
    bucket         = aws_s3_bucket.remote_state.bucket
    region         = var.region
    dynamodb_table = aws_dynamodb_table.remote_state_lock.name
    encrypt        = true
  })
}

######################################################
# IAM Policy — read-only доступ к Terraform state
# (для CI джоб, которые только читают state — без записи)
######################################################
output "state_readonly_iam_policy_json" {
  description = "Готовая IAM-политика (JSON) на read-only доступ к S3 state и DynamoDB lock-таблице."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3ListBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.remote_state.arn
      },
      {
        Sid      = "S3GetStateObjects"
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:GetObjectAcl",
          "s3:GetObjectVersion",
          "s3:GetObjectTagging"
        ]
        Resource = "${aws_s3_bucket.remote_state.arn}/*"
      },
      {
        Sid      = "DynamoDBDescribeLockTable"
        Effect   = "Allow"
        Action   = [
          "dynamodb:DescribeTable",
          "dynamodb:ListTagsOfResource"
        ]
        Resource = aws_dynamodb_table.remote_state_lock.arn
      },
      {
        Sid      = "DynamoDBGetLockItems"
        Effect   = "Allow"
        Action   = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.remote_state_lock.arn
      }
    ]
  })
}

######################################################
# Aggregated — сводные выходы для документации/автоматизаций
######################################################
output "remote_state_descriptor" {
  description = "Сводное описание backend-ресурсов и параметров."
  value = {
    backend           = "s3"
    s3_bucket_name    = aws_s3_bucket.remote_state.bucket
    s3_bucket_arn     = aws_s3_bucket.remote_state.arn
    dynamodb_name     = aws_dynamodb_table.remote_state_lock.name
    dynamodb_arn      = aws_dynamodb_table.remote_state_lock.arn
    kms_key_id        = try(aws_kms_key.remote_state.key_id, null)
    kms_key_arn       = try(aws_kms_key.remote_state.arn, null)
    kms_alias_arn     = try(aws_kms_alias.remote_state.arn, null)
    region            = var.region
    key_prefix        = var.key_prefix
    tags              = var.tags
  }
}

# Человекочитаемая подсказка для README/операторов CI.
output "backend_hints" {
  description = "Подсказки по использованию backend-конфига (человекочитаемая строка)."
  value = <<EOT
Использование:
  terraform init \\
    -backend-config="bucket=${aws_s3_bucket.remote_state.bucket}" \\
    -backend-config="region=${var.region}" \\
    -backend-config="dynamodb_table=${aws_dynamodb_table.remote_state_lock.name}" \\
    -backend-config="encrypt=true" \\
    -backend-config="key=${var.key_prefix}/env/<workspace>.tfstate"\\
    ${try(aws_kms_key.remote_state.key_id, null) != null ? "-backend-config=\"kms_key_id=${aws_kms_key.remote_state.key_id}\"" : "# kms_key_id не установлен"}

Где <workspace> — имя окружения/воркспейса (например: dev, stage, prod).
EOT
}
