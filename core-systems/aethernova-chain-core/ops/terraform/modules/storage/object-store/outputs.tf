#############################################
# File: ops/terraform/modules/storage/object-store/outputs.tf
# Purpose: Industrial, multi-cloud-safe outputs for object storage
# Notes:
# - Uses splat + tolist + try() to avoid evaluation errors when resources are optional
# - Supports AWS S3, Google Cloud Storage, Azure Blob
# - Does NOT expose secrets; only identifiers, endpoints, flags
#############################################

#############################################
# Helper locals to detect presence and extract attributes
#############################################

locals {
  # AWS S3 (resource names may be count/for_each based)
  aws_bucket_ids        = tolist(aws_s3_bucket.this[*].id)
  aws_bucket_arns       = tolist(aws_s3_bucket.this[*].arn)
  aws_bucket_names      = tolist(aws_s3_bucket.this[*].bucket)
  aws_bucket_domains    = tolist(aws_s3_bucket.this[*].bucket_domain_name)
  aws_bucket_reg_domains= tolist(aws_s3_bucket.this[*].bucket_regional_domain_name)
  aws_bucket_region     = tolist(aws_s3_bucket.this[*].bucket_region)

  # Optional AWS sub-resources
  aws_versioning_status = try(tolist(aws_s3_bucket_versioning.this[*].status)[0], null)
  aws_sse_algo          = try(tolist(aws_s3_bucket_server_side_encryption_configuration.this[*].rule[0].apply_server_side_encryption_by_default[0].sse_algorithm)[0], null)
  aws_sse_kms_key_id    = try(tolist(aws_s3_bucket_server_side_encryption_configuration.this[*].rule[0].apply_server_side_encryption_by_default[0].kms_key_id)[0], try(tolist(aws_s3_bucket_server_side_encryption_configuration.this[*].rule[0].apply_server_side_encryption_by_default[0].kms_master_key_id)[0], null))
  aws_log_bucket        = try(tolist(aws_s3_bucket_logging.this[*].target_bucket)[0], null)
  aws_log_prefix        = try(tolist(aws_s3_bucket_logging.this[*].target_prefix)[0], null)
  aws_website_endpoint  = try(tolist(aws_s3_bucket_website_configuration.this[*].website_endpoint)[0], null)
  aws_replication_role  = try(tolist(aws_s3_bucket_replication_configuration.this[*].role)[0], null)

  # GCS
  gcs_bucket_ids        = tolist(google_storage_bucket.this[*].id)
  gcs_bucket_names      = tolist(google_storage_bucket.this[*].name)
  gcs_bucket_urls       = tolist(google_storage_bucket.this[*].url)
  gcs_bucket_self_links = tolist(google_storage_bucket.this[*].self_link)
  gcs_bucket_location   = tolist(google_storage_bucket.this[*].location)
  gcs_storage_class     = tolist(google_storage_bucket.this[*].storage_class)
  gcs_versioning_enabled= try(tolist(google_storage_bucket.this[*].versioning[0].enabled)[0], null)
  gcs_log_bucket        = try(tolist(google_storage_bucket.this[*].logging[0].log_bucket)[0], null)
  gcs_log_prefix        = try(tolist(google_storage_bucket.this[*].logging[0].log_object_prefix)[0], null)

  # Azure Blob
  az_sa_ids             = tolist(azurerm_storage_account.this[*].id)
  az_sa_names           = tolist(azurerm_storage_account.this[*].name)
  az_primary_blob_ep    = try(tolist(azurerm_storage_account.this[*].primary_blob_endpoint)[0], null)
  az_primary_web_ep     = try(tolist(azurerm_storage_account.this[*].primary_web_endpoint)[0], null)

  az_container_ids      = tolist(azurerm_storage_container.this[*].id)
  az_container_names    = tolist(azurerm_storage_container.this[*].name)
  az_container_access   = try(tolist(azurerm_storage_container.this[*].container_access_type)[0], null)

  # Presence flags
  have_aws = length(local.aws_bucket_ids) > 0
  have_gcs = length(local.gcs_bucket_ids) > 0
  have_az  = length(local.az_container_ids) > 0

  # Unified view
  provider = (
    local.have_aws ? "aws" :
    local.have_gcs ? "gcp" :
    local.have_az  ? "azure" :
    null
  )

  # Unified name/id
  unified_name = try(local.aws_bucket_names[0],
                 try(local.gcs_bucket_names[0],
                 try(local.az_container_names[0], null)))
  unified_id   = try(local.aws_bucket_ids[0],
                 try(local.gcs_bucket_ids[0],
                 try(local.az_container_ids[0], null)))

  # Unified endpoint (best-effort)
  unified_endpoint = (
    local.have_aws ? try(local.aws_bucket_reg_domains[0], try(local.aws_bucket_domains[0], null)) :
    local.have_gcs ? try(local.gcs_bucket_urls[0], try(local.gcs_bucket_self_links[0], null)) :
    local.have_az  ? local.az_primary_blob_ep :
    null
  )
}

#############################################
# Unified, provider-agnostic outputs
#############################################

output "object_store_provider" {
  description = "Which provider is used: aws | gcp | azure"
  value       = local.provider
}

output "object_store_name" {
  description = "Bucket/Container name"
  value       = local.unified_name
}

output "object_store_id" {
  description = "Resource ID (bucket/container)"
  value       = local.unified_id
}

output "object_store_endpoint" {
  description = "Primary endpoint (S3 regional domain / GCS URL / Azure primary_blob_endpoint)"
  value       = local.unified_endpoint
}

output "object_store_summary" {
  description = "Convenience summary for consumers"
  value = {
    provider = local.provider
    name     = local.unified_name
    id       = local.unified_id
    endpoint = local.unified_endpoint
  }
}

#############################################
# AWS S3 specific
#############################################

output "s3_bucket_arn" {
  description = "S3 bucket ARN (AWS)"
  value       = try(local.aws_bucket_arns[0], null)
}

output "s3_bucket_domain_name" {
  description = "Virtual-hosted–style domain (bucket.s3.amazonaws.com)"
  value       = try(local.aws_bucket_domains[0], null)
}

output "s3_bucket_regional_domain_name" {
  description = "Regional domain (bucket.s3.<region>.amazonaws.com)"
  value       = try(local.aws_bucket_reg_domains[0], null)
}

output "s3_bucket_region" {
  description = "Region where the S3 bucket resides"
  value       = try(local.aws_bucket_region[0], null)
}

output "s3_website_endpoint" {
  description = "Static website endpoint if configured"
  value       = local.aws_website_endpoint
}

output "s3_versioning_status" {
  description = "Versioning status: Enabled | Suspended | null"
  value       = local.aws_versioning_status
}

output "s3_encryption" {
  description = "Server-side encryption settings (algorithm, kms_key_id)"
  value = {
    sse_algorithm = local.aws_sse_algo
    kms_key_id    = local.aws_sse_kms_key_id
  }
  sensitive = false
}

output "s3_logging" {
  description = "Access log target (if configured)"
  value = {
    target_bucket = local.aws_log_bucket
    target_prefix = local.aws_log_prefix
  }
}

output "s3_replication_role" {
  description = "IAM role ARN used by S3 replication (if configured)"
  value       = local.aws_replication_role
}

#############################################
# Google Cloud Storage specific
#############################################

output "gcs_bucket_url" {
  description = "Bucket URL (https://storage.googleapis.com/...)"
  value       = try(local.gcs_bucket_urls[0], null)
}

output "gcs_bucket_self_link" {
  description = "API self_link for the GCS bucket"
  value       = try(local.gcs_bucket_self_links[0], null)
}

output "gcs_location" {
  description = "Bucket location/region"
  value       = try(local.gcs_bucket_location[0], null)
}

output "gcs_storage_class" {
  description = "Storage class (STANDARD/NEARLINE/COLDLINE/ARCHIVE)"
  value       = try(local.gcs_storage_class[0], null)
}

output "gcs_versioning_enabled" {
  description = "Whether object versioning is enabled"
  value       = local.gcs_versioning_enabled
}

output "gcs_logging" {
  description = "Bucket logging target (if configured)"
  value = {
    log_bucket       = local.gcs_log_bucket
    log_object_prefix= local.gcs_log_prefix
  }
}

#############################################
# Azure Blob Storage specific
#############################################

output "azure_storage_account_id" {
  description = "Azure Storage Account ID"
  value       = try(local.az_sa_ids[0], null)
}

output "azure_storage_account_name" {
  description = "Azure Storage Account name"
  value       = try(local.az_sa_names[0], null)
}

output "azure_primary_blob_endpoint" {
  description = "Primary Blob endpoint (https://<account>.blob.core.windows.net/)"
  value       = local.az_primary_blob_ep
}

output "azure_primary_web_endpoint" {
  description = "Primary web endpoint (if static website is enabled)"
  value       = local.az_primary_web_ep
}

output "azure_container_id" {
  description = "Blob container resource ID"
  value       = try(local.az_container_ids[0], null)
}

output "azure_container_name" {
  description = "Blob container name"
  value       = try(local.az_container_names[0], null)
}

output "azure_container_access_type" {
  description = "Access level for the container (private, blob, container)"
  value       = local.az_container_access
}
