// path: aethernova-chain-core/ops/terraform/modules/registry/ecr/main.tf
// SPDX-License-Identifier: Apache-2.0

############################################################
# Inputs expected (declare in variables.tf of this module) #
############################################################
# variable "tags" { type = map(string)  default = {} }
# variable "repositories" {
#   description = "Map of repo_name => settings"
#   type = map(object({
#     scan_on_push         = optional(bool, true)            # ECR repo-level scanning
#     image_tag_mutability = optional(string, "IMMUTABLE")   # MUTABLE | IMMUTABLE
#     kms_key_id           = optional(string, null)          # If set -> KMS encryption
#     force_delete         = optional(bool, false)           # Allow repo destroy with images
#     tags                 = optional(map(string), {})       # Per-repo tags
#   }))
#   default = {}
# }
# variable "repository_policies" { type = map(string) default = {} }   # repo_name => JSON policy (string)
# variable "lifecycle_policies"  { type = map(string) default = {} }   # repo_name => JSON policy (string)
# variable "enable_default_lifecycle_policy" { type = bool default = false }
# variable "default_lifecycle_policy" { type = string default = null }  # JSON string
#
# # Registry-level (account) options — optional:
# variable "replication_configuration" {
#   description = <<EOT
# Configure registry replication. Example:
# {
#   rules = [
#     {
#       destinations = [
#         { region = "eu-central-1", registry_id = "111122223333" },
#         { region = "eu-west-1",    registry_id = "111122223333" }
#       ]
#       repository_filters = [
#         { filter = "prod/*", filter_type = "PREFIX_MATCH" },
#         { filter = "mirror/*", filter_type = "PREFIX_MATCH" }
#       ]
#     }
#   ]
# }
# EOT
#   type = object({
#     rules = list(object({
#       destinations = list(object({
#         region      = string
#         registry_id = string
#       }))
#       repository_filters = optional(list(object({
#         filter      = string
#         filter_type = string # e.g. PREFIX_MATCH
#       })), [])
#     }))
#   })
#   default = null
# }
#
# variable "registry_scanning" {
#   description = <<EOT
# Registry scanning configuration. Example:
# {
#   scan_type = "ENHANCED" # or "BASIC"
#   rules = [
#     {
#       scan_frequency     = "CONTINUOUS_SCAN" # or SCAN_ON_PUSH | MANUAL (per AWS constraints)
#       repository_filters = [
#         { filter = "prod*", filter_type = "WILDCARD" }
#       ]
#     }
#   ]
# }
# EOT
#   type = object({
#     scan_type = string
#     rules = optional(list(object({
#       scan_frequency     = string
#       repository_filters = list(object({
#         filter      = string
#         filter_type = string # e.g. WILDCARD
#       }))
#     })), [])
#   })
#   default = null
# }

#################
# Local helpers #
#################

locals {
  repo_names = toset(keys(var.repositories))

  # Only keep lifecycle policies whose keys are valid repo names
  lifecycle_policies_explicit = {
    for name, json in var.lifecycle_policies :
    name => json if contains(local.repo_names, name)
  }

  # Optionally add a default lifecycle policy where none is supplied
  lifecycle_policies_defaulted = (
    var.enable_default_lifecycle_policy && var.default_lifecycle_policy != null
  ) ? {
    for name in local.repo_names :
    name => var.default_lifecycle_policy if !contains(keys(local.lifecycle_policies_explicit), name)
  } : {}

  lifecycle_policies_effective = merge(
    local.lifecycle_policies_explicit,
    local.lifecycle_policies_defaulted
  )

  # Only keep repository policies for existing repos
  repository_policies_effective = {
    for name, json in var.repository_policies :
    name => json if contains(local.repo_names, name)
  }
}

###########################
# ECR repositories (many) #
###########################

resource "aws_ecr_repository" "this" {
  for_each = var.repositories

  name                 = each.key
  image_tag_mutability = upper(try(each.value.image_tag_mutability, "IMMUTABLE"))

  image_scanning_configuration {
    scan_on_push = try(each.value.scan_on_push, true)
  }

  # Encryption: AES256 by default; switch to KMS if kms_key_id is provided
  dynamic "encryption_configuration" {
    for_each = each.value.kms_key_id != null ? [each.value.kms_key_id] : []
    content {
      encryption_type = "KMS"
      kms_key         = encryption_configuration.value
    }
  }

  dynamic "encryption_configuration" {
    for_each = each.value.kms_key_id == null ? [1] : []
    content {
      encryption_type = "AES256"
    }
  }

  force_delete = try(each.value.force_delete, false)

  tags = merge(
    var.tags,
    try(each.value.tags, {})
  )
}

###################################
# Repository policies (per-repo)  #
###################################

resource "aws_ecr_repository_policy" "this" {
  for_each  = local.repository_policies_effective
  repository = aws_ecr_repository.this[each.key].name
  policy     = each.value
}

#################################
# Lifecycle policies (per-repo) #
#################################

resource "aws_ecr_lifecycle_policy" "this" {
  for_each  = local.lifecycle_policies_effective
  repository = aws_ecr_repository.this[each.key].name
  policy     = each.value
}

########################################################
# (Optional) Registry-level replication configuration  #
########################################################

resource "aws_ecr_replication_configuration" "this" {
  count = var.replication_configuration == null ? 0 : 1

  replication_configuration {
    dynamic "rules" {
      for_each = var.replication_configuration == null ? [] : var.replication_configuration.rules
      content {
        dynamic "destinations" {
          for_each = rules.value.destinations
          content {
            region      = destinations.value.region
            registry_id = destinations.value.registry_id
          }
        }
        dynamic "repository_filters" {
          for_each = try(rules.value.repository_filters, [])
          content {
            filter      = repository_filters.value.filter
            filter_type = repository_filters.value.filter_type
          }
        }
      }
    }
  }
}

#####################################################################
# (Optional) Registry-level scanning configuration (BASIC/ENHANCED) #
#####################################################################

resource "aws_ecr_registry_scanning_configuration" "this" {
  count     = var.registry_scanning == null ? 0 : 1
  scan_type = var.registry_scanning.scan_type

  dynamic "rule" {
    for_each = try(var.registry_scanning.rules, [])
    content {
      scan_frequency = rule.value.scan_frequency
      dynamic "repository_filter" {
        for_each = rule.value.repository_filters
        content {
          filter      = repository_filter.value.filter
          filter_type = repository_filter.value.filter_type
        }
      }
    }
  }
}
