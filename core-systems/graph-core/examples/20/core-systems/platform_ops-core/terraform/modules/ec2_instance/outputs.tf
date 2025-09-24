output "instance_id" {
  description = "ID созданного EC2 инстанса"
  value       = aws_instance.this.id
}

output "public_ip" {
  description = "Публичный IP адрес EC2 инстанса (если назначен)"
  value       = aws_instance.this.public_ip
  sensitive   = false
}

output "private_ip" {
  description = "Приватный IP адрес EC2 инстанса"
  value       = aws_instance.this.private_ip
}

output "arn" {
  description = "ARN EC2 инстанса"
  value       = aws_instance.this.arn
}

output "availability_zone" {
  description = "Зона доступности, где развернут EC2 инстанс"
  value       = aws_instance.this.availability_zone
}

output "root_block_device_id" {
  description = "ID корневого блочного устройства EC2"
  value       = aws_instance.this.root_block_device[0].volume_id
}

output "ebs_block_device_ids" {
  description = "Список ID дополнительных EBS томов"
  value       = [for b in aws_instance.this.ebs_block_device : b.volume_id]
}

output "security_groups" {
  description = "Назначенные группы безопасности для EC2 инстанса"
  value       = aws_instance.this.security_groups
}

output "tags" {
  description = "Теги, назначенные EC2 инстансу"
  value       = aws_instance.this.tags
}
