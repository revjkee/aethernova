/**
 * Module: vpc-gcp
 * File: variables.tf
 * Purpose: Strongly-typed, validated inputs for creating a production-grade
 *          Google Cloud VPC and its subnets with optional secondary ranges
 *          and Flow Logs settings.
 *
 * Notes:
 * - Keep this file free from provider/resource declarations.
 * - All validations are deterministic and do not depend on environment.
 */

terraform {
  required_version = ">= 1.5.0"
}

#############################
# Core project/network vars #
#############################

variable "project_id" {
  description = "GCP Project ID where the VPC will be created."
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must be a non-empty string."
  }
}

variable "network_name" {
  description = "Name of the VPC network (must be unique within the project)."
  type        = string

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.network_name))
    error_message = "network_name must match ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"
  }
}

variable "description" {
  description = "Optional human-readable description for the VPC."
  type        = string
  default     = ""
}

#################################
# Network-level configuration   #
#################################

variable "auto_create_subnetworks" {
  description = "If true, uses legacy auto mode subnets. For production, prefer false (custom mode)."
  type        = bool
  default     = false
}

variable "routing_mode" {
  description = "VPC dynamic routing mode. Allowed: GLOBAL or REGIONAL."
  type        = string
  default     = "GLOBAL"

  validation {
    condition     = contains(["GLOBAL", "REGIONAL"], upper(var.routing_mode))
    error_message = "routing_mode must be either GLOBAL or REGIONAL."
  }
}

variable "mtu" {
  description = "Optional MTU for the VPC (bytes). If null, provider default is used."
  type        = number
  default     = null

  validation {
    condition     = var.mtu == null || (var.mtu >= 1300 && var.mtu <= 9216)
    error_message = "mtu must be null or between 1300 and 9216 bytes."
  }
}

variable "delete_default_routes_on_create" {
  description = "If true, delete the default 0.0.0.0/0 route upon VPC creation."
  type        = bool
  default     = false
}

variable "labels" {
  description = "Resource labels to apply where supported."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for k, v in var.labels :
      can(regex("^[a-z0-9_-]{1,63}$", k)) && can(regex("^[a-z0-9_-]{0,63}$", v))
    ])
    error_message = "labels keys/values must be <=63 chars and match ^[a-z0-9_-]+$."
  }
}

######################################
# Subnet & secondary range variables #
######################################

/**
 * Subnet definition:
 * - name:                      required, subnet name
 * - region:                    required, e.g. europe-west1
 * - ip_cidr_range:             required, primary CIDR
 * - purpose:                   optional, for specialized subnets (e.g. PRIVATE, REGIONAL_MANAGED_PROXY)
 * - role:                      optional, role when purpose is SPECIAL (e.g. ACTIVE)
 * - stack_type:                optional, "IPV4_ONLY" or "IPV4_IPV6"
 * - private_ip_google_access:  optional, bool
 * - enable_flow_logs:          optional, bool
 * - flow_logs_config:          optional object:
 *      - aggregation_interval:  e.g. INTERVAL_5_MIN, INTERVAL_10_MIN
 *      - flow_sampling:         number between 0.0 and 1.0
 *      - metadata:              e.g. EXCLUDE_ALL_METADATA, INCLUDE_ALL_METADATA
 *      - metadata_fields:       optional list of metadata fields when selective
 * - secondary_ip_ranges:       optional list(object({ name, range }))
 */
variable "subnets" {
  description = <<-EOT
    List of custom subnets to create in the VPC. Each item defines region, primary CIDR,
    optional secondary ranges, and Flow Logs settings.
  EOT

  type = list(object({
    name                     = string
    region                   = string
    ip_cidr_range            = string
    purpose                  = optional(string)
    role                     = optional(string)
    stack_type               = optional(string)
    private_ip_google_access = optional(bool, true)
    enable_flow_logs         = optional(bool, false)
    flow_logs_config = optional(object({
      aggregation_interval = optional(string, "INTERVAL_5_MIN")
      flow_sampling        = optional(number, 0.5)
      metadata             = optional(string, "INCLUDE_ALL_METADATA")
      metadata_fields      = optional(list(string), [])
    }), null)
    secondary_ip_ranges = optional(list(object({
      name  = string
      range = string
    })), [])
  }))

  default = []

  # Primary validations
  validation {
    condition = alltrue([
      for s in var.subnets :
      s.name != "" && can(regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", s.name))
    ])
    error_message = "Each subnet.name must be non-empty and match ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$."
  }

  validation {
    condition = alltrue([
      for s in var.subnets :
      can(regex("^[a-z]+-[a-z0-9]+[0-9]$", s.region))
    ])
    error_message = "Each subnet.region must be a valid GCP region (e.g., europe-west1)."
  }

  validation {
    condition = alltrue([
      for s in var.subnets :
      can(cidrhost(s.ip_cidr_range, 0))
    ])
    error_message = "Each subnet.ip_cidr_range must be a valid IPv4 CIDR."
  }

  # Secondary ranges validations
  validation {
    condition = alltrue([
      for s in var.subnets :
      alltrue([
        for r in coalesce(s.secondary_ip_ranges, []) :
        r.name != "" && can(cidrhost(r.range, 0))
      ])
    ])
    error_message = "secondary_ip_ranges entries must have non-empty name and valid IPv4 CIDR."
  }

  # Flow logs validations
  validation {
    condition = alltrue([
      for s in var.subnets :
      s.flow_logs_config == null ||
      (
        (s.flow_logs_config.flow_sampling >= 0 && s.flow_logs_config.flow_sampling <= 1) &&
        contains(
          ["INTERVAL_5_MIN", "INTERVAL_10_MIN", "INTERVAL_15_MIN"],
          coalesce(s.flow_logs_config.aggregation_interval, "INTERVAL_5_MIN")
        ) &&
        contains(
          ["EXCLUDE_ALL_METADATA", "INCLUDE_ALL_METADATA", "CUSTOM_METADATA"],
          coalesce(s.flow_logs_config.metadata, "INCLUDE_ALL_METADATA")
        )
      )
    ])
    error_message = "flow_logs_config must have flow_sampling in [0,1], a valid aggregation_interval, and valid metadata setting."
  }

  # stack_type validation (guard against typos)
  validation {
    condition = alltrue([
      for s in var.subnets :
      s.stack_type == null || contains(["IPV4_ONLY", "IPV4_IPV6"], upper(s.stack_type))
    ])
    error_message = "stack_type, when set, must be IPV4_ONLY or IPV4_IPV6."
  }
}

#########################################
# Advanced / optional organizational IO #
#########################################

variable "shared_vpc_host" {
  description = "Marks this project as a Shared VPC host (organizational setting outside this module's scope)."
  type        = bool
  default     = false
}

variable "uniform_firewall_policy_enforcement" {
  description = "If true, indicates intent to use organization-level uniform firewall policies (enforcement outside this module)."
  type        = bool
  default     = false
}

##################
# Output toggles #
##################

variable "export_network_self_link" {
  description = "If true, module will output the network self_link (useful for cross-module wiring)."
  type        = bool
  default     = true
}

variable "export_subnet_self_links" {
  description = "If true, module will output created subnet self_links keyed by subnet name."
  type        = bool
  default     = true
}
