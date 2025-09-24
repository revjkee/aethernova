output "db_instance_id" {
  description = "Идентификатор RDS инстанса"
  value       = aws_db_instance.this.id
  sensitive   = false
}

output "db_instance_endpoint" {
  description = "Endpoint базы данных"
  value       = aws_db_instance.this.endpoint
  sensitive   = false
}

output "db_instance_port" {
  description = "Порт подключения к базе данных"
  value       = aws_db_instance.this.port
  sensitive   = false
}

output "db_instance_arn" {
  description = "ARN RDS инстанса"
  value       = aws_db_instance.this.arn
  sensitive   = false
}

output "db_security_group_ids" {
  description = "Список ID групп безопасности, связанных с RDS"
  value       = aws_db_instance.this.vpc_security_group_ids
  sensitive   = false
}

output "db_subnet_group" {
  description = "Имя группы подсетей для RDS"
  value       = aws_db_subnet_group.this.name
  sensitive   = false
}

output "db_username" {
  description = "Имя пользователя базы данных"
  value       = var.username
  sensitive   = false
}

output "rds_multi_az" {
  description = "Включен ли Multi-AZ"
  value       = aws_db_instance.this.multi_az
  sensitive   = false
}

output "rds_backup_retention_period" {
  description = "Период хранения бэкапов в днях"
  value       = aws_db_instance.this.backup_retention_period
  sensitive   = false
}
