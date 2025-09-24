###########################################################
# modules/security/policy-audit/outputs.tf
# Industrial-grade outputs for multi-cloud policy auditing
#
# SOURCES:
# - AWS Access Analyzer:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer
#   https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
# - AWS Config:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder
#   https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html
# - AWS Security Hub:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_account
#   https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html
# - Azure Policy:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/policy_assignment
#   https://learn.microsoft.com/azure/governance/policy/overview
# - GCP Org/Project Policy & SCC:
#   https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/organization_policy
#   https://cloud.google.com/security-command-center/docs
###########################################################

#########################
# Общие диагностические #
#########################

output "clouds_enabled" {
  description = "Какие провайдеры активны в модуле."
  value = compact([
    try(var.enable_aws ? "aws" : "", ""),
    try(var.enable_azure ? "azure" : "", ""),
    try(var.enable_gcp ? "gcp" : "", "")
  ])
}

output "module_name_prefix" {
  description = "Префикс имён, применённый в модуле (если используется)."
  value       = try(var.name_prefix, null)
}

############################
# --------- AWS -----------#
############################

# IAM Access Analyzer
output "aws_access_analyzers" {
  description = "Map: analyzer_key => { id, arn, analyzer_name, type, tags }."
  value = try({
    for k, a in aws_accessanalyzer_analyzer.this : k => {
      id            = try(a.id, null)
      arn           = try(a.arn, null)
      analyzer_name = try(a.analyzer_name, null)
      type          = try(a.type, null) # ACCOUNT | ORGANIZATION
      tags          = try(a.tags, {})
    }
  }, {})
}

output "aws_access_analyzer_archive_rules" {
  description = "Архивные правила Access Analyzer: map rule_key => { analyzer, filter }."
  value = try({
    for k, r in aws_accessanalyzer_archive_rule.this : k => {
      analyzer = try(r.analyzer_name, null)
      filter   = try(r.filter, [])
    }
  }, {})
}

# AWS Config
output "aws_config_recorder" {
  description = "Состояние Config Recorder (если включён)."
  value = try({
    name                 = aws_config_configuration_recorder.this.name
    role_arn             = try(aws_config_configuration_recorder.this.role_arn, null)
    recording_group      = try(aws_config_configuration_recorder.this.recording_group[0], null)
    delivery_channel_name= try(aws_config_delivery_channel.this.name, null)
    status               = try(aws_config_configuration_recorder_status.this.is_enabled, null)
  }, null)
}

output "aws_config_rules" {
  description = "Список/карта правил AWS Config (managed/custom): rule_key => { name, arn, id, scope, source, tags }."
  value = try({
    for k, r in aws_config_config_rule.this : k => {
      name  = try(r.name, null)
      arn   = try(r.arn, null)
      id    = try(r.id, null)
      scope = try(r.scope[0], null)
      source= try(r.source[0], null)
      tags  = try(r.tags, {})
    }
  }, {})
}

output "aws_config_conformance_packs" {
  description = "Conformance Packs: pack_key => { name, template_s3_uri|body_hash }."
  value = try({
    for k, p in aws_config_conformance_pack.this : k => {
      name          = try(p.name, null)
      template_s3_uri = try(p.template_s3_uri, null)
      # Если использовался template_body, выводим хэш длины для диагностики, без тела.
      template_body_len = try(length(p.template_body), null)
    }
  }, {})
}

output "aws_config_aggregators" {
  description = "Aggregators (межаккаунтный/межрегиональный обзор соответствия): key => { name, account_aggregation_sources, organization_aggregation_source }."
  value = try({
    for k, a in aws_config_configuration_aggregator.this : k => {
      name = try(a.name, null)
      account_aggregation_sources     = try(a.account_aggregation_source, [])
      organization_aggregation_source = try(a.organization_aggregation_source[0], null)
    }
  }, {})
}

# AWS Security Hub
output "aws_security_hub" {
  description = "Параметры Security Hub: { account_id, hub_arn, auto_enable_controls }."
  value = try({
    account_id           = data.aws_caller_identity.current.account_id
    hub_arn              = try(aws_securityhub_account.this.arn, null)
    auto_enable_controls = try(aws_securityhub_account.this.auto_enable_controls, null)
  }, null)
}

output "aws_security_hub_standards" {
  description = "Подписки на стандарты Security Hub: std_key => { standards_arn, standards_subscription_arn }."
  value = try({
    for k, s in aws_securityhub_standards_subscription.this : k => {
      standards_arn              = try(s.standards_arn, null)
      standards_subscription_arn = try(s.arn, null)
    }
  }, {})
}

output "aws_security_hub_controls" {
  description = "Статусы контролей Security Hub (если управляются в модуле): control_key => { standards_control_arn, control_status, disabled_reason }."
  value = try({
    for k, c in aws_securityhub_standards_control.this : k => {
      standards_control_arn = try(c.standards_control_arn, null)
      control_status        = try(c.control_status, null)       # e.g., ENABLED/DISABLED
      disabled_reason       = try(c.disabled_reason, null)
    }
  }, {})
}

output "aws_security_hub_aggregator" {
  description = "Aggregator для кросс-аккаунтного/кросс-регионального обзора Security Hub."
  value = try({
    linking_mode = try(aws_securityhub_finding_aggregator.this.linking_mode, null)
    regions      = try(aws_securityhub_finding_aggregator.this.linked_region, [])
    arn          = try(aws_securityhub_finding_aggregator.this.arn, null)
  }, null)
}

############################
# -------- Azure ----------#
############################

output "azure_policy_definitions" {
  description = "Определения политик: def_key => { id, name, display_name, mode }."
  value = try({
    for k, d in azurerm_policy_definition.this : k => {
      id           = try(d.id, null)
      name         = try(d.name, null)
      display_name = try(d.display_name, null)
      mode         = try(d.mode, null) # e.g., All, Indexed
    }
  }, {})
}

output "azure_policy_set_definitions" {
  description = "Инициативы (Policy Set): set_key => { id, name, display_name, policy_type }."
  value = try({
    for k, s in azurerm_policy_set_definition.this : k => {
      id           = try(s.id, null)
      name         = try(s.name, null)
      display_name = try(s.display_name, null)
      policy_type  = try(s.policy_type, null)
    }
  }, {})
}

output "azure_policy_assignments" {
  description = "Назначения политик: assign_key => { id, name, scope, definition_id, enforcement_mode, identity }."
  value = try({
    for k, a in azurerm_policy_assignment.this : k => {
      id               = try(a.id, null)
      name             = try(a.name, null)
      scope            = try(a.scope, null)
      definition_id    = try(a.policy_definition_id != null ? a.policy_definition_id : a.policy_set_definition_id, null)
      enforcement_mode = try(a.enforcement_mode, null) # Default/DoNotEnforce
      identity         = try(a.identity[0], null)
    }
  }, {})
}

output "azure_policy_exemptions" {
  description = "Исключения для политик: ex_key => { id, name, scope, exemption_category, expires_on }."
  value = try({
    for k, e in azurerm_policy_exemption.this : k => {
      id                 = try(e.id, null)
      name               = try(e.name, null)
      scope              = try(e.scope, null)
      exemption_category = try(e.exemption_category, null) # Waiver/Mitigated
      expires_on         = try(e.expires_on, null)
    }
  }, {})
}

############################
# ---------- GCP ----------#
############################

output "gcp_organization_policies" {
  description = "Policy constraints уровня организации: org_policy_key => { constraint, id, boolean_policy, list_policy }."
  value = try({
    for k, p in google_organization_policy.this : k => {
      id             = try(p.id, null)
      constraint     = try(p.constraint, null)
      boolean_policy = try(p.boolean_policy[0], null)
      list_policy    = try(p.list_policy[0], null)
    }
  }, {})
}

output "gcp_project_policies" {
  description = "Policy constraints уровня проекта: proj_policy_key => { project, constraint, id, boolean_policy, list_policy }."
  value = try({
    for k, p in google_project_organization_policy.this : k => {
      id             = try(p.id, null)
      project        = try(p.project, null)
      constraint     = try(p.constraint, null)
      boolean_policy = try(p.boolean_policy[0], null)
      list_policy    = try(p.list_policy[0], null)
    }
  }, {})
}

output "gcp_folder_policies" {
  description = "Policy constraints уровня папки: folder_policy_key => { folder, constraint, id }."
  value = try({
    for k, p in google_folder_organization_policy.this : k => {
      id         = try(p.id, null)
      folder     = try(p.folder, null)
      constraint = try(p.constraint, null)
    }
  }, {})
}

output "gcp_scc_sources" {
  description = "Security Command Center Sources: src_key => { name, display_name, description }."
  value = try({
    for k, s in google_scc_source.this : k => {
      name        = try(s.name, null)
      display_name= try(s.display_name, null)
      description = try(s.description, null)
    }
  }, {})
}

output "gcp_scc_notification_configs" {
  description = "SCC notifications: notif_key => { name, description, pubsub_topic }."
  value = try({
    for k, n in google_scc_notification_config.this : k => {
      name         = try(n.name, null)
      description  = try(n.description, null)
      pubsub_topic = try(n.pubsub_topic, null)
    }
  }, {})
}

#########################################
# Унифицированные сводки и счётчики     #
#########################################

output "counts_by_provider_and_service" {
  description = "Диагностические счётчики по провайдерам/сервисам аудита."
  value = {
    aws = {
      access_analyzers      = try(length(aws_accessanalyzer_analyzer.this), 0)
      access_archive_rules  = try(length(aws_accessanalyzer_archive_rule.this), 0)
      config_rules          = try(length(aws_config_config_rule.this), 0)
      conformance_packs     = try(length(aws_config_conformance_pack.this), 0)
      config_aggregators    = try(length(aws_config_configuration_aggregator.this), 0)
      security_hub_standards= try(length(aws_securityhub_standards_subscription.this), 0)
      security_hub_controls = try(length(aws_securityhub_standards_control.this), 0)
    }
    azure = {
      policy_definitions     = try(length(azurerm_policy_definition.this), 0)
      policy_set_definitions = try(length(azurerm_policy_set_definition.this), 0)
      policy_assignments     = try(length(azurerm_policy_assignment.this), 0)
      policy_exemptions      = try(length(azurerm_policy_exemption.this), 0)
    }
    gcp = {
      org_policies     = try(length(google_organization_policy.this), 0)
      project_policies = try(length(google_project_organization_policy.this), 0)
      folder_policies  = try(length(google_folder_organization_policy.this), 0)
      scc_sources      = try(length(google_scc_source.this), 0)
      scc_notifications= try(length(google_scc_notification_config.this), 0)
    }
  }
}

# Единая сводка ключевых артефактов аудита по всем облакам
output "policy_audit_summary" {
  description = "Унифицированная сводка артефактов аудита политик (без чувствительных данных)."
  value = {
    aws = {
      access_analyzers = try([
        for k, a in aws_accessanalyzer_analyzer.this : {
          key   = k
          name  = try(a.analyzer_name, null)
          type  = try(a.type, null)
          arn   = try(a.arn, null)
        }
      ], [])
      config = {
        recorder_enabled = try(aws_config_configuration_recorder_status.this.is_enabled, null)
        rules            = try([for k, r in aws_config_config_rule.this : r.name], [])
        conformance_packs= try([for k, p in aws_config_conformance_pack.this : p.name], [])
      }
      security_hub = {
        hub_arn    = try(aws_securityhub_account.this.arn, null)
        standards  = try([for k, s in aws_securityhub_standards_subscription.this : s.standards_arn], [])
      }
    }
    azure = {
      assignments = try([
        for k, a in azurerm_policy_assignment.this : {
          key          = k
          name         = try(a.name, null)
          scope        = try(a.scope, null)
          definition_id= try(a.policy_definition_id != null ? a.policy_definition_id : a.policy_set_definition_id, null)
          enforce      = try(a.enforcement_mode, null)
        }
      ], [])
      exemptions = try([
        for k, e in azurerm_policy_exemption.this : {
          key     = k
          name    = try(e.name, null)
          scope   = try(e.scope, null)
          expires = try(e.expires_on, null)
        }
      ], [])
    }
    gcp = {
      org_policies = try([
        for k, p in google_organization_policy.this : {
          key        = k
          constraint = try(p.constraint, null)
        }
      ], [])
      project_policies = try([
        for k, p in google_project_organization_policy.this : {
          key        = k
          project    = try(p.project, null)
          constraint = try(p.constraint, null)
        }
      ], [])
      scc = {
        sources = try([for k, s in google_scc_source.this : s.display_name], [])
      }
    }
  }
}
