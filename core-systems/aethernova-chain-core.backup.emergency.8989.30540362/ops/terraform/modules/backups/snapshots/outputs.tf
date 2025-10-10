###########################################################
# File: ops/terraform/modules/backups/snapshots/outputs.tf
# Purpose: Industrial outputs for multi-cloud snapshots
# Notes:
# - Предполагается, что ресурсы объявлены в модуле с count/for_each,
#   поэтому ссылки вида <resource>.this[*] существуют (даже при 0).
# - Не выводим секреты; только идентификаторы, ссылки, статусы.
###########################################################

###########################################################
# Locals: presence flags & normalized collections
###########################################################

locals {
  ############################
  # AWS — EBS snapshots
  ############################
  aws_ebs_ids         = tolist(aws_ebs_snapshot.this[*].id)
  aws_ebs_arns        = tolist(aws_ebs_snapshot.this[*].arn)
  aws_ebs_vol_ids     = tolist(aws_ebs_snapshot.this[*].volume_id)
  aws_ebs_sizes_gb    = tolist(aws_ebs_snapshot.this[*].volume_size)
  aws_ebs_encrypted   = tolist(aws_ebs_snapshot.this[*].encrypted)
  aws_ebs_kms_key_ids = tolist(aws_ebs_snapshot.this[*].kms_key_id)
  aws_ebs_start_times = tolist(aws_ebs_snapshot.this[*].start_time)
  aws_ebs_tier        = tolist(aws_ebs_snapshot.this[*].storage_tier)

  ############################
  # AWS — RDS snapshots
  ############################
  aws_rds_ids      = tolist(aws_db_snapshot.this[*].id)
  aws_rds_arns     = tolist(aws_db_snapshot.this[*].db_snapshot_arn)
  aws_rds_instance = tolist(aws_db_snapshot.this[*].db_instance_identifier)
  aws_rds_encr     = tolist(aws_db_snapshot.this[*].encrypted)
  aws_rds_kms      = tolist(aws_db_snapshot.this[*].kms_key_id)
  aws_rds_engine   = tolist(aws_db_snapshot.this[*].engine)
  aws_rds_type     = tolist(aws_db_snapshot.this[*].type)

  ############################
  # AWS — Backup (Vault/Plan)
  ############################
  aws_backup_vault_arns  = tolist(aws_backup_vault.this[*].arn)
  aws_backup_vault_names = tolist(aws_backup_vault.this[*].name)
  aws_backup_vault_kms   = tolist(aws_backup_vault.this[*].kms_key_arn)

  aws_backup_plan_arns   = tolist(aws_backup_plan.this[*].arn)
  aws_backup_plan_ids    = tolist(aws_backup_plan.this[*].id)
  aws_backup_plan_names  = tolist(aws_backup_plan.this[*].name)
  aws_backup_plan_rules  = try(aws_backup_plan.this[0].rule, [])

  ############################
  # GCP — Compute snapshots
  ############################
  gcp_snap_ids        = tolist(google_compute_snapshot.this[*].id)
  gcp_snap_names      = tolist(google_compute_snapshot.this[*].name)
  gcp_snap_selflinks  = tolist(google_compute_snapshot.this[*].self_link)
  gcp_snap_src_disk   = tolist(google_compute_snapshot.this[*].source_disk)
  gcp_snap_locations  = tolist(google_compute_snapshot.this[*].storage_locations)
  gcp_snap_size_gb    = tolist(google_compute_snapshot.this[*].disk_size_gb)
  gcp_snap_status     = tolist(google_compute_snapshot.this[*].status)

  # GCP — snapshot schedule via Resource Policy
  gcp_policy_ids      = tolist(google_compute_resource_policy.this[*].id)
  gcp_policy_names    = tolist(google_compute_resource_policy.this[*].name)
  gcp_policy_selflink = tolist(google_compute_resource_policy.this[*].self_link)

  ############################
  # Azure — Managed Disk snapshots
  ############################
  az_snap_ids        = tolist(azurerm_snapshot.this[*].id)
  az_snap_names      = tolist(azurerm_snapshot.this[*].name)
  az_snap_location   = tolist(azurerm_snapshot.this[*].location)
  az_snap_size_gb    = tolist(azurerm_snapshot.this[*].disk_size_gb)
  az_snap_create_opt = tolist(azurerm_snapshot.this[*].create_option)
  az_snap_src_uri    = tolist(azurerm_snapshot.this[*].source_uri)
  az_snap_account    = try(tolist(azurerm_snapshot.this[*].storage_account_type), [])

  ############################
  # Presence (per provider)
  ############################
  have_aws = length(local.aws_ebs_ids) > 0 || length(local.aws_rds_ids) > 0 || length(local.aws_backup_vault_arns) > 0 || length(local.aws_backup_plan_arns) > 0
  have_gcp = length(local.gcp_snap_ids) > 0 || length(local.gcp_policy_ids) > 0
  have_az  = length(local.az_snap_ids)  > 0

  ############################
  # Unified snapshots (list of objects)
  ############################
  unified_aws_ebs = [
    for idx, id in local.aws_ebs_ids : {
      provider     = "aws"
      kind         = "ebs"
      id           = id
      arn          = try(local.aws_ebs_arns[idx], null)
      name         = id
      source_id    = try(local.aws_ebs_vol_ids[idx], null)
      size_gb      = try(local.aws_ebs_sizes_gb[idx], null)
      created_at   = try(local.aws_ebs_start_times[idx], null)
      encrypted    = try(local.aws_ebs_encrypted[idx], null)
      kms_key_id   = try(local.aws_ebs_kms_key_ids[idx], null)
      region       = null
      link         = try(local.aws_ebs_arns[idx], null)
      tier         = try(local.aws_ebs_tier[idx], null)
    }
  ]

  unified_aws_rds = [
    for idx, id in local.aws_rds_ids : {
      provider     = "aws"
      kind         = "rds"
      id           = id
      arn          = try(local.aws_rds_arns[idx], null)
      name         = id
      source_id    = try(local.aws_rds_instance[idx], null)
      size_gb      = null
      created_at   = null
      encrypted    = try(local.aws_rds_encr[idx], null)
      kms_key_id   = try(local.aws_rds_kms[idx], null)
      region       = null
      link         = try(local.aws_rds_arns[idx], null)
      engine       = try(local.aws_rds_engine[idx], null)
      snapshot_type= try(local.aws_rds_type[idx], null)
    }
  ]

  unified_gcp = [
    for idx, id in local.gcp_snap_ids : {
      provider     = "gcp"
      kind         = "pd"
      id           = id
      arn          = null
      name         = try(local.gcp_snap_names[idx], null)
      source_id    = try(local.gcp_snap_src_disk[idx], null)
      size_gb      = try(local.gcp_snap_size_gb[idx], null)
      created_at   = null
      encrypted    = null
      kms_key_id   = null
      region       = null
      link         = try(local.gcp_snap_selflinks[idx], null)
      status       = try(local.gcp_snap_status[idx], null)
      locations    = try(local.gcp_snap_locations[idx], null)
    }
  ]

  unified_azure = [
    for idx, id in local.az_snap_ids : {
      provider     = "azure"
      kind         = "managed-disk"
      id           = id
      arn          = null
      name         = try(local.az_snap_names[idx], null)
      source_id    = try(local.az_snap_src_uri[idx], null)
      size_gb      = try(local.az_snap_size_gb[idx], null)
      created_at   = null
      encrypted    = null
      kms_key_id   = null
      region       = try(local.az_snap_location[idx], null)
      link         = id
      storage_account_type = try(local.az_snap_account[idx], null)
      create_option        = try(local.az_snap_create_opt[idx], null)
    }
  ]

  snapshots_unified = concat(local.unified_aws_ebs, local.unified_aws_rds, local.unified_gcp, local.unified_azure)
}

###########################################################
# High-level, provider-agnostic outputs
###########################################################

output "snapshots_overview" {
  description = "Сводка по провайдерам: есть ли ресурсы снапшотов/бэкапов"
  value = {
    aws   = local.have_aws
    gcp   = local.have_gcp
    azure = local.have_az
  }
}

output "snapshots" {
  description = "Унифицированный список снапшотов (AWS EBS/RDS, GCP PD, Azure Managed Disk). Поля: provider, kind, id, arn|link, source_id, size_gb, created_at, encrypted, kms_key_id, region, status/locations/storage_account_type."
  value       = local.snapshots_unified
}

###########################################################
# AWS-specific outputs (EBS, RDS, AWS Backup)
###########################################################

output "aws_ebs_snapshot_ids" {
  description = "AWS EBS snapshot IDs"
  value       = local.aws_ebs_ids
}

output "aws_ebs_snapshot_arns" {
  description = "AWS EBS snapshot ARNs"
  value       = local.aws_ebs_arns
}

output "aws_ebs_snapshot_meta" {
  description = "EBS snapshot meta per index"
  value = [
    for i in range(length(local.aws_ebs_ids)) : {
      id           = local.aws_ebs_ids[i]
      arn          = try(local.aws_ebs_arns[i], null)
      volume_id    = try(local.aws_ebs_vol_ids[i], null)
      volume_size  = try(local.aws_ebs_sizes_gb[i], null)
      encrypted    = try(local.aws_ebs_encrypted[i], null)
      kms_key_id   = try(local.aws_ebs_kms_key_ids[i], null)
      start_time   = try(local.aws_ebs_start_times[i], null)
      storage_tier = try(local.aws_ebs_tier[i], null)
    }
  ]
}

output "aws_rds_snapshots" {
  description = "RDS instance snapshots"
  value = [
    for i in range(length(local.aws_rds_ids)) : {
      id                      = local.aws_rds_ids[i]
      arn                     = try(local.aws_rds_arns[i], null)
      db_instance_identifier  = try(local.aws_rds_instance[i], null)
      engine                  = try(local.aws_rds_engine[i], null)
      type                    = try(local.aws_rds_type[i], null)
      encrypted               = try(local.aws_rds_encr[i], null)
      kms_key_id              = try(local.aws_rds_kms[i], null)
    }
  ]
}

output "aws_backup_vault" {
  description = "AWS Backup vault (name/arn/kms)"
  value = {
    arn        = try(local.aws_backup_vault_arns[0], null)
    name       = try(local.aws_backup_vault_names[0], null)
    kms_key_arn= try(local.aws_backup_vault_kms[0], null)
  }
}

output "aws_backup_plan" {
  description = "AWS Backup plan (id/arn/name) + rules"
  value = {
    id    = try(local.aws_backup_plan_ids[0], null)
    arn   = try(local.aws_backup_plan_arns[0], null)
    name  = try(local.aws_backup_plan_names[0], null)
    rules = [
      for r in local.aws_backup_plan_rules : {
        rule_name        = try(r.rule_name, null)
        schedule         = try(r.schedule, null)
        target_vault_name= try(r.target_vault_name, null)
        lifecycle        = try(r.lifecycle, null)
      }
    ]
  }
}

###########################################################
# GCP-specific outputs (Compute Snapshot / Resource Policy)
###########################################################

output "gcp_compute_snapshots" {
  description = "GCP Persistent Disk snapshots"
  value = [
    for i in range(length(local.gcp_snap_ids)) : {
      id               = local.gcp_snap_ids[i]
      name             = try(local.gcp_snap_names[i], null)
      self_link        = try(local.gcp_snap_selflinks[i], null)
      source_disk      = try(local.gcp_snap_src_disk[i], null)
      disk_size_gb     = try(local.gcp_snap_size_gb[i], null)
      status           = try(local.gcp_snap_status[i], null)
      storage_locations= try(local.gcp_snap_locations[i], null)
    }
  ]
}

output "gcp_snapshot_policies" {
  description = "GCP snapshot Resource Policy (schedule)"
  value = [
    for i in range(length(local.gcp_policy_ids)) : {
      id        = local.gcp_policy_ids[i]
      name      = try(local.gcp_policy_names[i], null)
      self_link = try(local.gcp_policy_selflink[i], null)
    }
  ]
}

###########################################################
# Azure-specific outputs (Managed Disk Snapshot)
###########################################################

output "azure_snapshots" {
  description = "Azure Managed Disk snapshots"
  value = [
    for i in range(length(local.az_snap_ids)) : {
      id                   = local.az_snap_ids[i]
      name                 = try(local.az_snap_names[i], null)
      location             = try(local.az_snap_location[i], null)
      disk_size_gb         = try(local.az_snap_size_gb[i], null)
      create_option        = try(local.az_snap_create_opt[i], null)
      source_uri           = try(local.az_snap_src_uri[i], null)
      storage_account_type = try(local.az_snap_account[i], null)
    }
  ]
}
