output "vpc_id" {
  description = "ID созданного VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR блок созданного VPC"
  value       = aws_vpc.main.cidr_block
}

output "vpc_default_security_group_id" {
  description = "ID дефолтной группы безопасности VPC"
  value       = aws_vpc.main.default_security_group_id
}

output "vpc_main_route_table_id" {
  description = "ID основной таблицы маршрутизации VPC"
  value       = aws_vpc.main.main_route_table_id
}

output "vpc_default_network_acl_id" {
  description = "ID дефолтного сетевого ACL VPC"
  value       = aws_vpc.main.default_network_acl_id
}

output "tags" {
  description = "Теги, применённые к VPC"
  value       = aws_vpc.main.tags
}
