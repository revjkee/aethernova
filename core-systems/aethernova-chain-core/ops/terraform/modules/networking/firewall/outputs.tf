// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/networking/firewall
// File:   outputs.tf
// Purpose: Cross-cloud firewall outputs (AWS / Azure / GCP / K8s). All references are guarded by `try(...)`.
//
// Assumed (optional) resources (rename here if your module uses different names):
// - AWS:    aws_security_group.this[*], aws_security_group_rule.*,
//           aws_network_acl.*,
//           aws_networkfirewall_firewall.this, aws_networkfirewall_firewall_policy.this,
//           aws_networkfirewall_rule_group.*, aws_wafv2_web_acl.this
// - Azure:  azurerm_network_security_group.this[*], azurerm_network_security_rule.*,
//           azurerm_firewall.this, azurerm_web_application_firewall_policy.this
// - GCP:    google_compute_firewall.this[*], google_compute_security_policy.this
// - K8s:    kubernetes_network_policy.this[*]
//
// NOTE: Keep provider configuration at the root module; this file only exports data from resources created in this module.

// -----------------------------
// Generic / meta
// -----------------------------
output "firewall_module_enabled" {
  description = "Флаг: созданы ли в модуле какие-либо firewall-ресурсы (по совокупности)."
  value = (
    length(try(aws_security_group.this, [])) > 0
    || length(try(azurerm_network_security_group.this, [])) > 0
    || length(try(google_compute_firewall.this, [])) > 0
    || length(try(kubernetes_network_policy.this, [])) > 0
    || try(aws_networkfirewall_firewall.this.arn, null) != null
    || try(azurerm_firewall.this.id, null) != null
    || try(google_compute_security_policy.this.id, null) != null
  )
}

output "firewall_provider_detected" {
  description = "Обнаруженный(ые) стек(и) провайдеров, по которым есть артефакты firewall."
  value = compact([
    length(try(aws_security_group.this, [])) > 0
      || try(aws_networkfirewall_firewall.this.arn, null) != null
      || try(aws_wafv2_web_acl.this.arn, null) != null ? "aws" : "",
    length(try(azurerm_network_security_group.this, [])) > 0
      || try(azurerm_firewall.this.id, null) != null ? "azurerm" : "",
    length(try(google_compute_firewall.this, [])) > 0
      || try(google_compute_security_policy.this.id, null) != null ? "google" : "",
    length(try(kubernetes_network_policy.this, [])) > 0 ? "kubernetes" : ""
  ])
}

// -----------------------------
// AWS — Security Groups / NACL / Network Firewall / WAFv2
// -----------------------------
output "aws_security_group_ids" {
  description = "ID Security Group (AWS), созданные модулем."
  value       = try([for sg in aws_security_group.this : sg.id], [])
}

output "aws_security_group_arns" {
  description = "ARN Security Group (AWS), созданные модулем."
  value       = try([for sg in aws_security_group.this : sg.arn], [])
}

output "aws_security_group_names" {
  description = "Имена Security Group (AWS)."
  value       = try([for sg in aws_security_group.this : sg.name], [])
}

output "aws_security_group_rule_counts" {
  description = "Количество ingress/egress правил по SG (AWS)."
  value = try({
    for sg in aws_security_group.this :
    sg.id => {
      ingress = length(try(sg.ingress, []))
      egress  = length(try(sg.egress,  []))
    }
  }, {})
}

output "aws_network_acl_ids" {
  description = "ID NACL (AWS), если модуль их создаёт."
  value       = try([for nacl in aws_network_acl.this : nacl.id], [])
}

output "aws_network_firewall_arn" {
  description = "ARN AWS Network Firewall (если создаётся)."
  value       = try(aws_networkfirewall_firewall.this.arn, null)
}

output "aws_network_firewall_name" {
  description = "Имя AWS Network Firewall (если создаётся)."
  value       = try(aws_networkfirewall_firewall.this.name, null)
}

output "aws_network_firewall_policy_arn" {
  description = "ARN политики AWS Network Firewall (если создаётся)."
  value       = try(aws_networkfirewall_firewall_policy.this.arn, null)
}

output "aws_network_firewall_rule_group_arns" {
  description = "ARN rule group'ов AWS Network Firewall (если создаются)."
  value = try(flatten([
    for k, rg in aws_networkfirewall_rule_group.this : [rg.arn]
  ]), [])
}

output "aws_network_firewall_subnet_mappings" {
  description = "Карты привязки AWS Network Firewall к подсетям (subnet -> endpoint ID), если поддерживается."
  value = try({
    for m in aws_networkfirewall_firewall.this.subnet_mapping :
    m.subnet_id => m.firewall_subnet_id
  }, {})
}

output "aws_wafv2_web_acl_arn" {
  description = "ARN AWS WAFv2 Web ACL (если создаётся)."
  value       = try(aws_wafv2_web_acl.this.arn, null)
}

output "aws_wafv2_web_acl_name" {
  description = "Имя AWS WAFv2 Web ACL (если создаётся)."
  value       = try(aws_wafv2_web_acl.this.name, null)
}

// -----------------------------
// Azure — NSG / Azure Firewall / WAF Policy
// -----------------------------
output "azurerm_nsg_ids" {
  description = "ID Network Security Group (Azure), созданные модулем."
  value       = try([for nsg in azurerm_network_security_group.this : nsg.id], [])
}

output "azurerm_nsg_names" {
  description = "Имена NSG (Azure)."
  value       = try([for nsg in azurerm_network_security_group.this : nsg.name], [])
}

output "azurerm_firewall_id" {
  description = "ID Azure Firewall (если создаётся)."
  value       = try(azurerm_firewall.this.id, null)
}

output "azurerm_firewall_name" {
  description = "Имя Azure Firewall (если создаётся)."
  value       = try(azurerm_firewall.this.name, null)
}

output "azurerm_waf_policy_id" {
  description = "ID Azure WAF Policy (если создаётся)."
  value       = try(azurerm_web_application_firewall_policy.this.id, null)
}

output "azurerm_waf_policy_name" {
  description = "Имя Azure WAF Policy (если создаётся)."
  value       = try(azurerm_web_application_firewall_policy.this.name, null)
}

// -----------------------------
// GCP — VPC Firewall / Cloud Armor
// -----------------------------
output "gcp_firewall_rule_ids" {
  description = "ID правил брандмауэра VPC (GCP), созданных модулем."
  value       = try([for r in google_compute_firewall.this : r.id], [])
}

output "gcp_firewall_rule_names" {
  description = "Имена правил брандмауэра VPC (GCP)."
  value       = try([for r in google_compute_firewall.this : r.name], [])
}

output "gcp_cloud_armor_policy_id" {
  description = "ID Cloud Armor security policy (если создаётся)."
  value       = try(google_compute_security_policy.this.id, null)
}

output "gcp_cloud_armor_policy_name" {
  description = "Имя Cloud Armor security policy (если создаётся)."
  value       = try(google_compute_security_policy.this.name, null)
}

// -----------------------------
// Kubernetes — NetworkPolicy
// -----------------------------
output "kubernetes_network_policy_names" {
  description = "Имена созданных Kubernetes NetworkPolicy."
  value       = try([for np in kubernetes_network_policy.this : np.metadata[0].name], [])
}

output "kubernetes_network_policy_namespaces" {
  description = "Неймспейсы созданных Kubernetes NetworkPolicy."
  value       = try([for np in kubernetes_network_policy.this : np.metadata[0].namespace], [])
}

// -----------------------------
// Derived aggregates / tags / labels
// -----------------------------
output "firewall_rule_total_count" {
  description = "Суммарное число правил на уровне облаков (приближённо по доступным сущностям)."
  value = (
    // AWS SG: ingress+egress (метаданные SG в state)
    try(reduce([
      for sg in aws_security_group.this :
      length(try(sg.ingress, [])) + length(try(sg.egress, []))
    ], 0, sum, 0), 0)
    +
    // Azure NSG rules (при наличии экспонирования в ресурсе)
    try(length(azurerm_network_security_rule.this), 0)
    +
    // GCP VPC firewall rules
    try(length(google_compute_firewall.this), 0)
  )
}

output "resource_tags_labels" {
  description = "Сводные теги/ярлыки по основным объектам firewall."
  value = {
    aws = {
      security_groups = try([for sg in aws_security_group.this : sg.tags_all], [])
      wafv2           = try(aws_wafv2_web_acl.this.tags_all, null)
      network_acl     = try([for n in aws_network_acl.this : n.tags_all], [])
      network_fw      = try(aws_networkfirewall_firewall.this.tags_all, null)
    }
    azurerm = {
      nsg      = try([for n in azurerm_network_security_group.this : n.tags], [])
      firewall = try(azurerm_firewall.this.tags, null)
      waf      = try(azurerm_web_application_firewall_policy.this.tags, null)
    }
    gcp = {
      vpc_firewall = try([for r in google_compute_firewall.this : r.labels], [])
      armor        = try(google_compute_security_policy.this.labels, null)
    }
    kubernetes = {
      network_policy = try([for np in kubernetes_network_policy.this : np.metadata[0].labels], [])
    }
  }
}

// -----------------------------
// Backward compatibility
// -----------------------------
output "security_group_ids" {
  description = "Алиас для совместимости: AWS Security Group IDs."
  value       = try([for sg in aws_security_group.this : sg.id], [])
}

output "nsg_ids" {
  description = "Алиас для совместимости: Azure NSG IDs."
  value       = try([for nsg in azurerm_network_security_group.this : nsg.id], [])
}

output "gcp_vpc_firewall_ids" {
  description = "Алиас для совместимости: GCP VPC firewall rule IDs."
  value       = try([for r in google_compute_firewall.this : r.id], [])
}
