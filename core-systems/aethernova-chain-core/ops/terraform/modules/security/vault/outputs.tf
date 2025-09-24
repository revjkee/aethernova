############################################################
# File: aethernova-chain-core/ops/terraform/modules/security/vault/outputs.tf
# Purpose: Industrial-grade outputs for Vault module on AWS
# Notes:
#  - Не раскрываем секреты (root token, recovery keys).
#  - Маркируем чувствительные значения при необходимости (sensitive = true).
#  - Используем precondition для валидации важных значений.
############################################################

# Публичная точка входа API (через NLB/ALB)
output "vault_api_dns_name" {
  description = "Public DNS name of the Vault API load balancer (NLB/ALB)."
  value       = aws_lb.vault_api.dns_name

  precondition {
    condition     = length(aws_lb.vault_api.dns_name) > 0
    error_message = "vault_api_dns_name is empty; check aws_lb.vault_api."
  }
}

output "vault_api_endpoint" {
  description = "HTTPS endpoint for Vault API (computed from LB DNS)."
  value       = "https://${aws_lb.vault_api.dns_name}"

  precondition {
    condition     = length(aws_lb.vault_api.dns_name) > 0
    error_message = "Cannot construct endpoint without aws_lb.vault_api.dns_name."
  }
}

# Полезно для Route53
output "vault_api_lb_zone_id" {
  description = "Hosted zone ID of the Vault API load balancer."
  value       = aws_lb.vault_api.zone_id
}

# Слушатель HTTPS (если на ALB/NLB c TLS-termination)
output "vault_api_listener_https_arn" {
  description = "ARN of the HTTPS listener that fronts Vault API."
  value       = aws_lb_listener.vault_https.arn
}

# Target group (для health checks и балансировки)
output "vault_api_target_group_arn" {
  description = "ARN of the target group used by the API LB."
  value       = aws_lb_target_group.vault_api.arn
}

# KMS для auto-unseal (ID/ARN/alias)
output "vault_kms_key_id" {
  description = "KMS Key ID used for Vault auto-unseal (AWS KMS)."
  value       = aws_kms_key.vault_unseal.key_id
}

output "vault_kms_key_arn" {
  description = "KMS Key ARN used for Vault auto-unseal (AWS KMS)."
  value       = aws_kms_key.vault_unseal.arn
}

output "vault_kms_alias_arn" {
  description = "ARN of the KMS alias attached to the auto-unseal key."
  value       = aws_kms_alias.vault_unseal.arn
}

# Security Group (сетевой периметр Vault)
output "vault_security_group_id" {
  description = "Security Group ID protecting Vault nodes."
  value       = aws_security_group.vault.id
}

# IAM (минимально необходимый контур)
output "vault_iam_role_arn" {
  description = "IAM role ARN attached to Vault nodes (for instance profile/IRSA)."
  value       = aws_iam_role.vault.arn
}

output "vault_iam_instance_profile_arn" {
  description = "IAM instance profile ARN used by Vault EC2/ASG nodes (if applicable)."
  value       = aws_iam_instance_profile.vault.arn
}

# Логи
output "vault_cloudwatch_log_group_arn" {
  description = "CloudWatch Log Group ARN for Vault server logs."
  value       = aws_cloudwatch_log_group.vault.arn
}

# DNS (если выпускается запись в Route53)
output "vault_route53_record_fqdn" {
  description = "Route53 FQDN that resolves to Vault API LB (if created)."
  value       = aws_route53_record.vault_api.fqdn
}

# Удобная ссылка на эндпоинт метрик (Prometheus формат)
output "vault_metrics_endpoint" {
  description = "Prometheus-formatted metrics endpoint proxied via LB."
  value       = "https://${aws_lb.vault_api.dns_name}/v1/sys/metrics?format=prometheus"

  precondition {
    condition     = length(aws_lb.vault_api.dns_name) > 0
    error_message = "Cannot construct metrics endpoint without LB DNS."
  }
}

# Служебно-операционные выходы
output "vault_asg_name" {
  description = "Autoscaling Group name that manages Vault nodes (if ASG is used)."
  value       = aws_autoscaling_group.vault.name
}

output "vault_launch_template_id" {
  description = "Launch Template ID used by Vault ASG (if defined)."
  value       = aws_launch_template.vault.id
}
