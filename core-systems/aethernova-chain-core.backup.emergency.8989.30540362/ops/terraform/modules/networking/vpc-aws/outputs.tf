// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/networking/vpc-aws
// File:   outputs.tf
// Note:   Предполагаются ресурсы с типовыми именами:
//         - aws_vpc.this
//         - aws_subnet.public / aws_subnet.private / aws_subnet.database (optional)
//         - aws_internet_gateway.this
//         - aws_nat_gateway.this
//         - aws_route_table.public / aws_route_table.private / aws_route_table.database (optional)
//         - aws_vpn_gateway.this (optional)
//         - aws_network_acl.public / aws_network_acl.private / aws_network_acl.database (optional)
//         - aws_default_security_group.this / aws_security_group.* (optional)
//
//         При необходимости скорректируйте имена в соответствии с реализацией модуля.

// -----------------------------
// Core VPC identifiers
// -----------------------------

output "vpc_id" {
  description = "ID созданной VPC."
  value       = aws_vpc.this.id
}

output "vpc_arn" {
  description = "ARN созданной VPC."
  value       = aws_vpc.this.arn
}

output "vpc_cidr_block" {
  description = "Основной CIDR-блок VPC."
  value       = aws_vpc.this.cidr_block
}

output "vpc_secondary_cidr_blocks" {
  description = "Список дополнительных CIDR-блоков VPC (при наличии)."
  value       = aws_vpc.this.cidr_block_association_set[*].cidr_block
}

// -----------------------------
// Availability Zones
// -----------------------------

output "availability_zones" {
  description = "Список AZ, использованных для подсетей."
  value       = distinct(compact([
    for s in concat(
      try(aws_subnet.public[*], []),
      try(aws_subnet.private[*], []),
      try(aws_subnet.database[*], [])
    ) : s.availability_zone
  ]))
}

// -----------------------------
// Subnets: IDs
// -----------------------------

output "public_subnet_ids" {
  description = "ID публичных подсетей."
  value       = try(aws_subnet.public[*].id, [])
}

output "private_subnet_ids" {
  description = "ID приватных подсетей."
  value       = try(aws_subnet.private[*].id, [])
}

output "database_subnet_ids" {
  description = "ID подсетей уровня базы данных (если создаются)."
  value       = try(aws_subnet.database[*].id, [])
}

// -----------------------------
// Subnets: CIDR blocks
// -----------------------------

output "public_subnet_cidrs" {
  description = "CIDR-блоки публичных подсетей."
  value       = try(aws_subnet.public[*].cidr_block, [])
}

output "private_subnet_cidrs" {
  description = "CIDR-блоки приватных подсетей."
  value       = try(aws_subnet.private[*].cidr_block, [])
}

output "database_subnet_cidrs" {
  description = "CIDR-блоки подсетей уровня базы данных (если создаются)."
  value       = try(aws_subnet.database[*].cidr_block, [])
}

// -----------------------------
// Internet/NAT/Egress
// -----------------------------

output "internet_gateway_id" {
  description = "ID Internet Gateway (если создается)."
  value       = try(aws_internet_gateway.this.id, null)
}

output "nat_gateway_ids" {
  description = "ID NAT-шлюзов (если создаются)."
  value       = try(aws_nat_gateway.this[*].id, [])
}

output "nat_eip_allocation_ids" {
  description = "Allocation ID EIP для NAT (если создаются)."
  value       = try(aws_eip.nat[*].id, [])
}

// -----------------------------
// Route Tables
// -----------------------------

output "public_route_table_ids" {
  description = "ID таблиц маршрутизации для публичных подсетей."
  value       = try(aws_route_table.public[*].id, [])
}

output "private_route_table_ids" {
  description = "ID таблиц маршрутизации для приватных подсетей."
  value       = try(aws_route_table.private[*].id, [])
}

output "database_route_table_ids" {
  description = "ID таблиц маршрутизации для DB-подсетей (если создаются)."
  value       = try(aws_route_table.database[*].id, [])
}

// -----------------------------
// NACLs
// -----------------------------

output "public_network_acl_ids" {
  description = "ID NACL для публичных подсетей (если создаются)."
  value       = try(aws_network_acl.public[*].id, [])
}

output "private_network_acl_ids" {
  description = "ID NACL для приватных подсетей (если создаются)."
  value       = try(aws_network_acl.private[*].id, [])
}

output "database_network_acl_ids" {
  description = "ID NACL для DB-подсетей (если создаются)."
  value       = try(aws_network_acl.database[*].id, [])
}

// -----------------------------
// Security Groups
// -----------------------------

output "default_security_group_id" {
  description = "ID default Security Group в пределах VPC."
  value       = try(aws_default_security_group.this.id, null)
  sensitive   = false
}

output "security_group_ids" {
  description = "ID пользовательских Security Group, созданных модулем (если создаются)."
  value       = try(flatten([
    for k, sg in aws_security_group.sg : sg.id
  ]), [])
  sensitive   = false
}

// -----------------------------
// VPC Endpoints (Gateway/Interface)
// -----------------------------

output "vpc_endpoint_interface_ids" {
  description = "ID интерфейсных VPC Endpoint-ов (если создаются)."
  value       = try([for k, ep in aws_vpc_endpoint.interface : ep.id], [])
}

output "vpc_endpoint_gateway_ids" {
  description = "ID gateway VPC Endpoint-ов (если создаются)."
  value       = try([for k, ep in aws_vpc_endpoint.gateway : ep.id], [])
}

// -----------------------------
// VPN / TGW (optional)
// -----------------------------

output "vpn_gateway_id" {
  description = "ID виртуального VPN-шлюза (если создается)."
  value       = try(aws_vpn_gateway.this.id, null)
}

output "tgw_attachment_id" {
  description = "ID присоединения к Transit Gateway (если создается)."
  value       = try(aws_ec2_transit_gateway_vpc_attachment.this.id, null)
}

// -----------------------------
// Tags & Metadata
// -----------------------------

output "vpc_tags" {
  description = "Теги VPC."
  value       = aws_vpc.this.tags_all
}

output "subnet_tags" {
  description = "Теги подсетей (public/private/database)."
  value = {
    public   = try([for s in aws_subnet.public   : s.tags_all], [])
    private  = try([for s in aws_subnet.private  : s.tags_all], [])
    database = try([for s in aws_subnet.database : s.tags_all], [])
  }
}

// -----------------------------
// Derived Maps
// -----------------------------

output "subnets_by_az" {
  description = "Подсети, сгруппированные по AZ, для public/private/database."
  value = {
    public = try({
      for s in aws_subnet.public :
      s.availability_zone => concat(try([s.id], []), try(tolist([]), []))
    }, {})
    private = try({
      for s in aws_subnet.private :
      s.availability_zone => concat(try([s.id], []), try(tolist([]), []))
    }, {})
    database = try({
      for s in aws_subnet.database :
      s.availability_zone => concat(try([s.id], []), try(tolist([]), []))
    }, {})
  }
}

// -----------------------------
// Backward compatibility shims
// -----------------------------

output "subnets" {
  description = "Совокупный список всех подсетей (совместимость со старыми потребителями)."
  value       = flatten([try(aws_subnet.public[*].id, []), try(aws_subnet.private[*].id, []), try(aws_subnet.database[*].id, [])])
}

output "cidr_blocks" {
  description = "Совокупный список всех CIDR-блоков подсетей (совместимость со старыми потребителями)."
  value       = flatten([try(aws_subnet.public[*].cidr_block, []), try(aws_subnet.private[*].cidr_block, []), try(aws_subnet.database[*].cidr_block, [])])
}
