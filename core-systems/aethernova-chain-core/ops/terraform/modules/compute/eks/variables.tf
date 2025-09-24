/**
 * Module: compute/eks
 * File: variables.tf
 * Purpose: Strongly-typed, production-grade input surface for EKS cluster creation,
 *          incl. cluster, networking, encryption, logging, addons, node groups,
 *          Fargate profiles, and aws-auth mappings. Validations ensure safer plans.
 *
 * Notes:
 * - No provider/resource blocks here.
 * - Keep version matrix in callers; this module focuses on input contracts.
 */

terraform {
  required_version = ">= 1.6.0"
}

############################
# Core cluster parameters  #
############################

variable "cluster_name" {
  description = "EKS cluster name. Must be unique per region/account."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{1,60}[a-z0-9])?$", var.cluster_name))
    error_message = "cluster_name must be 3-62 chars, lowercase alphanumerics and hyphens, start/end with alphanumeric."
  }
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS control plane. Example: 1.29"
  type        = string
  default     = "1.29"
  validation {
    condition     = contains(["1.27","1.28","1.29","1.30","1.31"], var.cluster_version)
    error_message = "cluster_version must be one of: 1.27, 1.28, 1.29, 1.30, 1.31."
  }
}

variable "region" {
  description = "AWS region used by the cluster."
  type        = string
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d$", var.region))
    error_message = "region must look like: eu-west-1, us-east-1, etc."
  }
}

############################
# Networking & access      #
############################

variable "vpc_id" {
  description = "VPC ID where the EKS cluster will be created (vpc-xxxxxxxx)."
  type        = string
  validation {
    condition     = can(regex("^vpc-([0-9a-f]{8}|[0-9a-f]{17})$", var.vpc_id))
    error_message = "vpc_id must match vpc-xxxxxxxx or vpc-xxxxxxxxxxxxxxxxx."
  }
}

variable "subnet_ids" {
  description = "List of subnets for the EKS control plane and node groups."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2 && alltrue([for s in var.subnet_ids : can(regex("^subnet-([0-9a-f]{8}|[0-9a-f]{17})$", s))])
    error_message = "Provide at least two valid subnet IDs (subnet-xxxxxxxx)."
  }
}

variable "endpoint_private_access" {
  description = "Enable private API server endpoint access."
  type        = bool
  default     = true
}

variable "endpoint_public_access" {
  description = "Enable public API server endpoint access."
  type        = bool
  default     = false
}

variable "endpoint_public_access_cidrs" {
  description = "CIDR allowlist for public endpoint (only used if endpoint_public_access = true)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
  validation {
    condition     = alltrue([for c in var.endpoint_public_access_cidrs : can(cidrhost(c, 0))])
    error_message = "endpoint_public_access_cidrs must be a list of valid IPv4 CIDRs."
  }
}

variable "cluster_security_group_additional_ingress" {
  description = "Additional ingress rules for cluster SG."
  type = list(object({
    description               = optional(string, "")
    from_port                 = number
    to_port                   = number
    protocol                  = string
    cidr_blocks               = optional(list(string), [])
    source_security_group_ids = optional(list(string), [])
  }))
  default = []
  validation {
    condition = alltrue([
      for r in var.cluster_security_group_additional_ingress :
      r.from_port >= 0 && r.to_port >= r.from_port &&
      contains(["tcp","udp","icmp","-1"], lower(r.protocol)) &&
      alltrue([for c in coalesce(r.cidr_blocks, []) : can(cidrhost(c, 0))]) &&
      alltrue([for sg in coalesce(r.source_security_group_ids, []) : can(regex("^sg-([0-9a-f]{8}|[0-9a-f]{17})$", sg))])
    ])
    error_message = "Ingress rules invalid: ports/protocol/cidrs/sg-ids must be valid."
  }
}

############################
# Cluster logging & tags   #
############################

variable "enabled_cluster_log_types" {
  description = "Control-plane log types."
  type        = list(string)
  default     = ["api","audit","authenticator","controllerManager","scheduler"]
  validation {
    condition = alltrue([
      for t in var.enabled_cluster_log_types :
      contains(["api","audit","authenticator","controllerManager","scheduler"], t)
    ])
    error_message = "Log types must be subset of: api,audit,authenticator,controllerManager,scheduler."
  }
}

variable "tags" {
  description = "Tags to apply to taggable EKS resources."
  type        = map(string)
  default     = {}
  validation {
    condition = alltrue([for k, v in var.tags :
      length(k) > 0 && length(v) <= 256
    ])
    error_message = "Tag keys must be non-empty; values <= 256 chars."
  }
}

############################
# Encryption config        #
############################

variable "cluster_encryption" {
  description = "Secrets encryption configuration for EKS (KMS)."
  type = object({
    enabled       = bool
    kms_key_arn   = optional(string)
    resources     = optional(list(string), ["secrets"])
  })
  default = {
    enabled   = false
    resources = ["secrets"]
  }
  validation {
    condition = var.cluster_encryption.enabled == false || (var.cluster_encryption.enabled == true && can(regex("^arn:aws:kms:[a-z0-9-]+:\\d{12}:key\\/[0-9a-f-]+$", coalesce(var.cluster_encryption.kms_key_arn, ""))))
    error_message = "When encryption is enabled, kms_key_arn must be a valid KMS Key ARN."
  }
}

############################
# Addons                   #
############################

variable "addons" {
  description = "Managed addons configuration."
  type = list(object({
    name                = string
    version             = optional(string)       # e.g., v1.16.0-eksbuild.1
    resolve_conflicts   = optional(string, "OVERWRITE") # OVERWRITE|PRESERVE|NONE
    service_account_role_arn = optional(string)
    # Raw JSON/YAML string for addon config (e.g., for VPC CNI custom settings)
    configuration_values = optional(string, "")
    tags                 = optional(map(string), {})
  }))
  default = []
  validation {
    condition = alltrue([
      for a in var.addons :
      a.name != "" &&
      contains(["OVERWRITE","PRESERVE","NONE"], upper(coalesce(a.resolve_conflicts, "OVERWRITE"))) &&
      (a.service_account_role_arn == null || can(regex("^arn:aws:iam::\\d{12}:role\\/.+$", a.service_account_role_arn)))
    ])
    error_message = "Each addon must have name; resolve_conflicts in {OVERWRITE,PRESERVE,NONE}; optional IRSA role must be valid ARN."
  }
}

############################
# Node groups (managed)    #
############################

/**
 * node_groups is a map of node group IDs to specs.
 * - capacity_type: ON_DEMAND | SPOT
 * - instance_types: list of EC2 types
 * - ami_type: AL2_x86_64, AL2_ARM_64, BOTTLEROCKET_x86_64, BOTTLEROCKET_ARM_64
 * - desired/min/max: scaling bounds
 * - update_config: max_unavailable or max_unavailable_percentage
 * - taints: [{key,value,effect}] ; effect in {NO_SCHEDULE, PREFER_NO_SCHEDULE, NO_EXECUTE}
 * - labels: k8s node labels
 * - subnet_ids: override for NG placement
 * - launch_template: optional LT settings
 */
variable "node_groups" {
  description = "EKS managed node groups configuration."
  type = map(object({
    capacity_type  = optional(string, "ON_DEMAND")
    instance_types = list(string)
    ami_type       = optional(string, "AL2_x86_64")
    disk_size      = optional(number, 50)
    desired_size   = number
    min_size       = number
    max_size       = number
    max_pods_per_node = optional(number, null)
    labels         = optional(map(string), {})
    taints         = optional(list(object({
      key    = string
      value  = optional(string, "")
      effect = string
    })), [])
    subnet_ids     = optional(list(string), null)
    tags           = optional(map(string), {})
    update_config  = optional(object({
      max_unavailable            = optional(number)
      max_unavailable_percentage = optional(number)
    }), null)
    launch_template = optional(object({
      id               = optional(string)
      name             = optional(string)
      version          = optional(string, "$Latest")
      tags             = optional(map(string), {})
      ebs_optimized    = optional(bool, null)
      metadata_options = optional(object({
        http_endpoint            = optional(string) # enabled|disabled
        http_put_response_hop_limit = optional(number)
        http_tokens              = optional(string) # optional|required
      }), null)
    }), null)
  }))
  default = {}
  validation {
    condition = alltrue([
      for ng_name, ng in var.node_groups :
      contains(["ON_DEMAND","SPOT"], upper(ng.capacity_type)) &&
      ng.desired_size >= ng.min_size && ng.max_size >= ng.desired_size &&
      contains(["AL2_x86_64","AL2_ARM_64","BOTTLEROCKET_x86_64","BOTTLEROCKET_ARM_64"], ng.ami_type) &&
      (ng.subnet_ids == null || alltrue([for s in ng.subnet_ids : can(regex("^subnet-([0-9a-f]{8}|[0-9a-f]{17})$", s))])) &&
      alltrue([for t in ng.taints : contains(["NO_SCHEDULE","PREFER_NO_SCHEDULE","NO_EXECUTE"], upper(t.effect))]) &&
      (
        ng.update_config == null ||
        (
          (try(ng.update_config.max_unavailable, null) == null || ng.update_config.max_unavailable >= 0) &&
          (try(ng.update_config.max_unavailable_percentage, null) == null || (ng.update_config.max_unavailable_percentage >= 0 && ng.update_config.max_unavailable_percentage <= 100))
        )
      )
    ])
    error_message = "Invalid node_groups: capacity_type/ami_type/scaling/taints/subnets/update_config must satisfy constraints."
  }
}

############################
# Fargate profiles         #
############################

variable "fargate_profiles" {
  description = "EKS Fargate profiles keyed by profile name."
  type = map(object({
    selectors = list(object({
      namespace = string
      labels    = optional(map(string), {})
    }))
    subnet_ids                = optional(list(string), null)
    pod_execution_role_arn    = optional(string)
    tags                      = optional(map(string), {})
  }))
  default = {}
  validation {
    condition = alltrue([
      for name, fp in var.fargate_profiles :
      name != "" &&
      length(fp.selectors) > 0 &&
      (fp.subnet_ids == null || alltrue([for s in fp.subnet_ids : can(regex("^subnet-([0-9a-f]{8}|[0-9a-f]{17})$", s))])) &&
      (fp.pod_execution_role_arn == null || can(regex("^arn:aws:iam::\\d{12}:role\\/.+$", fp.pod_execution_role_arn)))
    ])
    error_message = "Fargate profile invalid: name/selectors required; optional subnets and role ARNs must be valid."
  }
}

############################
# IAM / aws-auth mappings  #
############################

variable "cluster_role_arn" {
  description = "Pre-created IAM role ARN for EKS cluster (optional). If null, module may create one."
  type        = string
  default     = null
  validation {
    condition     = var.cluster_role_arn == null || can(regex("^arn:aws:iam::\\d{12}:role\\/.+$", var.cluster_role_arn))
    error_message = "cluster_role_arn must be a valid IAM Role ARN."
  }
}

variable "enable_cluster_creator_admin_permissions" {
  description = "If true, the cluster creator (caller) will be granted system:masters via aws-auth."
  type        = bool
  default     = false
}

variable "aws_auth_roles" {
  description = "aws-auth: list of role mappings."
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  default = []
  validation {
    condition = alltrue([
      for r in var.aws_auth_roles :
      can(regex("^arn:aws:iam::\\d{12}:role\\/.+$", r.rolearn)) &&
      length(r.username) > 0 &&
      length(r.groups) >= 1
    ])
    error_message = "aws_auth_roles entries must contain valid role ARN, non-empty username, and at least one group."
  }
}

variable "aws_auth_users" {
  description = "aws-auth: list of user mappings."
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  default = []
  validation {
    condition = alltrue([
      for u in var.aws_auth_users :
      can(regex("^arn:aws:iam::\\d{12}:user\\/.+$", u.userarn)) &&
      length(u.username) > 0 &&
      length(u.groups) >= 1
    ])
    error_message = "aws_auth_users entries must contain valid user ARN, non-empty username, and at least one group."
  }
}

variable "aws_auth_accounts" {
  description = "aws-auth: list of account IDs to grant access (rarely used)."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.aws_auth_accounts : can(regex("^\\d{12}$", a))])
    error_message = "Each account ID must be a 12-digit number."
  }
}

############################
# Timeouts & toggles       #
############################

variable "create_timeout" {
  description = "Timeout for EKS cluster creation (e.g., 30m, 1h)."
  type        = string
  default     = "60m"
  validation {
    condition     = can(regex("^\\d+[smhd]$", var.create_timeout))
    error_message = "create_timeout must be like 30m, 1h, 45m, etc."
  }
}

variable "update_timeout" {
  description = "Timeout for EKS cluster update."
  type        = string
  default     = "120m"
  validation {
    condition     = can(regex("^\\d+[smhd]$", var.update_timeout))
    error_message = "update_timeout must be like 30m, 1h, 45m, etc."
  }
}

variable "delete_timeout" {
  description = "Timeout for EKS cluster deletion."
  type        = string
  default     = "90m"
  validation {
    condition     = can(regex("^\\d+[smhd]$", var.delete_timeout))
    error_message = "delete_timeout must be like 30m, 1h, 45m, etc."
  }
}

variable "enable_kubernetes_network_policy" {
  description = "If true, enforces cluster-level network policy (addon/CNI dependent)."
  type        = bool
  default     = false
}

variable "restrict_default_security_groups" {
  description = "If true, applies restrictive defaults to cluster and node SGs (implemented in resources)."
  type        = bool
  default     = true
}

############################
# Output controls          #
############################

variable "export_cluster_oidc_issuer" {
  description = "If true, output cluster OIDC issuer URL (for IRSA)."
  type        = bool
  default     = true
}

variable "export_cluster_primary_security_group" {
  description = "If true, output cluster primary security group id."
  type        = bool
  default     = true
}

############################
# Cross-field guards       #
############################

locals {
  _public_endpoint_ok = (
    var.endpoint_public_access == false ||
    (var.endpoint_public_access == true && length(var.endpoint_public_access_cidrs) > 0)
  )
}

# Hint for downstream resources to add preconditions using locals:
# - Ensure at least 2 subnets in different AZs for HA (enforced where subnets' AZs known).
# - Ensure encryption.kms_key_arn when encryption.enabled is true (validated above).
