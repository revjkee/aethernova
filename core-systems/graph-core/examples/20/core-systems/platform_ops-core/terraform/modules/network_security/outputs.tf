output "security_group_id" {
  description = "ID созданной Security Group"
  value       = aws_security_group.this.id
  sensitive   = false
}

output "security_group_arn" {
  description = "ARN созданной Security Group"
  value       = aws_security_group.this.arn
  sensitive   = false
}

output "network_acl_id" {
  description = "ID созданного Network ACL"
  value       = aws_network_acl.this.id
  sensitive   = false
}

output "network_acl_arn" {
  description = "ARN созданного Network ACL"
  value       = aws_network_acl.this.arn
  sensitive   = false
}

output "security_group_ingress_rules" {
  description = "Ingress правила Security Group"
  value       = aws_security_group.this.ingress
  sensitive   = false
}

output "security_group_egress_rules" {
  description = "Egress правила Security Group"
  value       = aws_security_group.this.egress
  sensitive   = false
}

output "network_acl_associations" {
  description = "Ассоциации Network ACL с подсетями"
  value       = aws_network_acl_association.this[*].id
  sensitive   = false
}
