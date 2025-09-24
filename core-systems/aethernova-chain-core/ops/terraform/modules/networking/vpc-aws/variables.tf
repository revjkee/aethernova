/**
 * Module: networking/vpc-aws
 * File:  variables.tf
 * Purpose:
 *   Industrial-grade variable schema for AWS VPC module used in Aethernova.
 *   Strong typing, sane defaults, and validations for secure & reproducible infra.
 */

############################################
# Core identification & tagging
############################################

variable "name" {
  description = "Logical name of the VPC (used in tags and some resource names where applicable)."
  type        = string
}

variable "environment" {
  description = "Environment identifier, e.g. dev, staging, prod."
  type        = string
}

variable "tags" {
  description = "Global tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "resource_tags" {
  description = <<EOT
Fine-grained tags per resource class. All maps are merged over 'tags'.
Recognized keys (optional): vpc, igw, nat_gw, eip, subnet_public, subnet_private, subnet_intra, subnet_database,
subnet_elasticache, route_table, nacl, sg, endpoint, flow_logs, dhcp_options.
EOT
  type = object({
    vpc               = optional(map(string), {})
    igw               = optional(map(string), {})
    nat_gw            = optional(map(string), {})
    eip               = optional(map(string), {})
    subnet_public     = optional(map(string), {})
    subnet_private    = optional(map(string), {})
    subnet_intra      = optional(map(string), {})
    subnet_database   = optional(map(string), {})
    subnet_elasticache= optional(map(string), {})
    route_table       = optional(map(string), {})
    nacl              = optional(map(string), {})
    sg                = optional(map(string), {})
    endpoint          = optional(map(string), {})
    flow_logs         = optional(map(string), {})
    dhcp_options      = optional(map(string), {})
  })
  default = {}
}

############################################
# Region / AZ control
############################################

variable "region" {
  description = "AWS region for the VPC (provider region should match unless using multiple providers)."
  type        = string
}

variable "allowed_azs" {
  description = "Optional allowlist of AZ names to use (e.g. [\"eu-central-1a\",\"eu-central-1b\"]). If empty, data source/provider decides."
  type        = list(string)
  default     = []
}

variable "az_count" {
  description = "If > 0 and 'allowed_azs' is empty, pick this many AZs from the region for subnet spreading."
  type        = number
  default     = 0
  validation {
    condition     = var.az_count >= 0 && var.az_count <= 6
    error_message = "az_count must be between 0 and 6."
  }
}

############################################
# VPC addressing & DNS
############################################

variable "vpc_cidr" {
  description = "Primary IPv4 CIDR block for the VPC."
  type        = string
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR (e.g. 10.0.0.0/16)."
  }
}

variable "secondary_cidrs" {
  description = "Optional additional IPv4 CIDR blocks to associate with the VPC."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.secondary_cidrs : can(cidrhost(c, 0))])
    error_message = "All secondary_cidrs must be valid IPv4 CIDRs."
  }
}

variable "enable_ipv6" {
  description = "Whether to enable IPv6 CIDR assignment to the VPC."
  type        = bool
  default     = false
}

variable "assign_ipv6_address_on_creation" {
  description = "If true, auto-assign IPv6 address on subnet ENI creation (for subnets where IPv6 is enabled)."
  type        = bool
  default     = false
}

variable "dns_hostnames" {
  description = "Enable DNS hostnames in the VPC."
  type        = bool
  default     = true
}

variable "dns_support" {
  description = "Enable DNS support in the VPC."
  type        = bool
  default     = true
}

variable "instance_tenancy" {
  description = "VPC instance tenancy setting."
  type        = string
  default     = "default"
  validation {
    condition     = contains(["default", "dedicated"], var.instance_tenancy)
    error_message = "instance_tenancy must be either 'default' or 'dedicated'."
  }
}

############################################
# Subnet topology
############################################
# For each subnet tier, supply CIDRs (one per AZ you intend to use).
# Length of lists should match number of AZs chosen (either allowed_azs or az_count result).

variable "public_subnet_cidrs" {
  description = "List of public subnet CIDRs; typically one per AZ."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.public_subnet_cidrs : can(cidrhost(c, 0))])
    error_message = "All public_subnet_cidrs must be valid IPv4 CIDRs."
  }
}

variable "private_subnet_cidrs" {
  description = "List of private application subnet CIDRs; typically one per AZ."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.private_subnet_cidrs : can(cidrhost(c, 0))])
    error_message = "All private_subnet_cidrs must be valid IPv4 CIDRs."
  }
}

variable "intra_subnet_cidrs" {
  description = "List of intra (no internet) subnet CIDRs; optional."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.intra_subnet_cidrs : can(cidrhost(c, 0))])
    error_message = "All intra_subnet_cidrs must be valid IPv4 CIDRs."
  }
}

variable "database_subnet_cidrs" {
  description = "List of DB subnet CIDRs (for RDS/Aurora); optional."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.database_subnet_cidrs : can(cidrhost(c, 0))])
    error_message = "All database_subnet_cidrs must be valid IPv4 CIDRs."
  }
}

variable "elasticache_subnet_cidrs" {
  description = "List of ElastiCache subnet CIDRs; optional."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.elasticache_subnet_cidrs : can(cidrhost(c, 0))])
    error_message = "All elasticache_subnet_cidrs must be valid IPv4 CIDRs."
  }
}

############################################
# Internet/NAT egress
############################################

variable "create_internet_gateway" {
  description = "Create and attach an Internet Gateway to the VPC."
  type        = bool
  default     = true
}

variable "enable_nat_gateway" {
  description = "Provision NAT Gateway(s) for private subnets' egress."
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single shared NAT Gateway (true) or one per AZ (false)."
  type        = bool
  default     = true
}

variable "re-use_nat_eips" {
  description = "If true, use provided allocation IDs for NAT EIPs instead of creating new."
  type        = bool
  default     = false
}

variable "nat_eip_allocation_ids" {
  description = "Optional list of existing EIP allocation IDs to assign to NAT Gateways (order should match NAT count)."
  type        = list(string)
  default     = []
}

############################################
# Network ACLs & Security
############################################

variable "manage_default_security_group" {
  description = "If true, manage and restrict the default security group."
  type        = bool
  default     = true
}

variable "create_network_acls" {
  description = "Whether to create NACLs per subnet tier (public/private/intra/database/elasticache)."
  type        = bool
  default     = true
}

############################################
# VPC Endpoints
############################################

variable "gateway_endpoints" {
  description = <<EOT
Map of Gateway endpoints (currently S3/DynamoDB) to enable.
Example: { s3 = true, dynamodb = false }
EOT
  type = map(bool)
  default = {
    s3        = true
    dynamodb  = false
  }
}

variable "interface_endpoints" {
  description = <<EOT
Configuration for Interface Endpoints as a map keyed by service name, e.g. "com.amazonaws.eu-central-1.ec2".
Fields:
  subnet_tier: which subnet tier to place endpoints into: "private" | "intra" | "database" | "elasticache".
  private_dns_enabled: enable private DNS for the endpoint.
  security_group_ids: optional list of SG IDs to attach to the endpoints ENIs.
EOT
  type = map(object({
    subnet_tier          = string
    private_dns_enabled  = optional(bool, true)
    security_group_ids   = optional(list(string), [])
  }))
  default = {}
}

############################################
# Flow Logs
############################################

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs."
  type        = bool
  default     = true
}

variable "flow_logs_destination_type" {
  description = "Flow Logs destination: 's3' or 'cloud-watch-logs'."
  type        = string
  default     = "cloud-watch-logs"
  validation {
    condition     = contains(["s3", "cloud-watch-logs"], var.flow_logs_destination_type)
    error_message = "flow_logs_destination_type must be 's3' or 'cloud-watch-logs'."
  }
}

variable "flow_logs_traffic_type" {
  description = "Captured traffic type: ACCEPT | REJECT | ALL."
  type        = string
  default     = "ALL"
  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.flow_logs_traffic_type)
    error_message = "flow_logs_traffic_type must be one of ACCEPT, REJECT, ALL."
  }
}

variable "flow_logs_log_format" {
  description = "Optional custom log format for flow logs. If empty, AWS default format is used."
  type        = string
  default     = ""
}

# CloudWatch Logs destination config
variable "flow_logs_log_group_name" {
  description = "CloudWatch Log Group name for flow logs (required if destination is cloud-watch-logs and you want to control the name)."
  type        = string
  default     = ""
}

variable "flow_logs_log_retention_days" {
  description = "Retention in days for the CloudWatch Log Group. If 0, provider/module default applies."
  type        = number
  default     = 90
}

variable "flow_logs_iam_role_arn" {
  description = "IAM Role ARN for VPC Flow Logs delivery to CloudWatch (optional; when empty, module may create one)."
  type        = string
  default     = ""
}

# S3 destination config
variable "flow_logs_s3_bucket_arn" {
  description = "S3 bucket ARN to deliver flow logs (required if destination is s3)."
  type        = string
  default     = ""
}

variable "flow_logs_s3_bucket_prefix" {
  description = "S3 key prefix for flow logs."
  type        = string
  default     = "vpc-flow-logs/"
}

############################################
# DHCP options (optional)
############################################

variable "create_dhcp_options" {
  description = "Create custom DHCP options set and associate to VPC."
  type        = bool
  default     = false
}

variable "dhcp_options" {
  description = <<EOT
DHCP options payload (applied only if create_dhcp_options = true).
domain_name: e.g. ec2.internal or custom
domain_name_servers: e.g. [\"AmazonProvidedDNS\"]
ntp_servers, netbios_name_servers, netbios_node_type are optional.
EOT
  type = object({
    domain_name          = optional(string)
    domain_name_servers  = optional(list(string))
    ntp_servers          = optional(list(string))
    netbios_name_servers = optional(list(string))
    netbios_node_type    = optional(number)
    tags                 = optional(map(string), {})
  })
  default = {}
}

############################################
# Route 53 private zones association (optional)
############################################

variable "route53_zone_associations" {
  description = <<EOT
Associate existing Private Hosted Zones with this VPC.
Provide list of zone IDs to associate. Caller must have permissions in the hosted zone account if cross-account.
EOT
  type    = list(string)
  default = []
}

############################################
# Transit Gateway (optional)
############################################

variable "tgw_attachment" {
  description = <<EOT
Optional Transit Gateway attachment configuration.
enable: whether to create an attachment
subnet_tier: which subnets to use for the attachment (typically 'intra' or 'private')
tgw_id: target Transit Gateway ID
appliance_mode_support: 'enable' or 'disable'
dns_support: 'enable' or 'disable'
ipv6_support: 'enable' or 'disable'
EOT
  type = object({
    enable                 = bool
    subnet_tier            = optional(string, "intra")
    tgw_id                 = optional(string)
    appliance_mode_support = optional(string, "disable")
    dns_support            = optional(string, "enable")
    ipv6_support           = optional(string, "disable")
    tags                   = optional(map(string), {})
  })
  default = {
    enable = false
  }
}

############################################
# Reachability Analyzer (optional)
############################################

variable "reachability_analyzer" {
  description = <<EOT
Optional Reachability Analyzer paths for continuous validation.
Each entry defines a path template; concrete ARNs/IDs should be provided by the caller module (e.g., SGs, ENIs).
Fields are passthrough to aws_ec2_network_insights_path.
EOT
  type = list(object({
    source_arn                 = string
    destination_arn            = string
    protocol                   = optional(string)   # TCP|UDP|ICMP etc.
    destination_port           = optional(number)
    source_port                = optional(number)
    filter_at_destination      = optional(bool, true)
    filter_at_source           = optional(bool, true)
    tags                       = optional(map(string), {})
  }))
  default = []
}

############################################
# Controls & advanced
############################################

variable "enable_default_vpc_cleanup" {
  description = "If true, the module may remove default VPC dependencies in the account/region (safe ops only)."
  type        = bool
  default     = false
}

variable "fail_if_subnet_length_mismatch" {
  description = "If true, enforce equal list lengths across subnet tiers and AZs (strict topology)."
  type        = bool
  default     = true
}

variable "route_table_strategy" {
  description = <<EOT
Route table strategy:
 - 'per-tier' : one route table per subnet tier (public/private/intra/...),
 - 'per-subnet': dedicated route table for each subnet.
EOT
  type        = string
  default     = "per-tier"
  validation {
    condition     = contains(["per-tier", "per-subnet"], var.route_table_strategy)
    error_message = "route_table_strategy must be 'per-tier' or 'per-subnet'."
  }
}

variable "vpc_endpoint_policy_json" {
  description = "Optional JSON string of a common IAM endpoint policy attached to all created VPC endpoints."
  type        = string
  default     = ""
}

variable "enable_s3_endpoint_private_dns" {
  description = "Controls Private DNS on S3 interface endpoint, when such endpoint is requested (rare; usually S3 uses gateway endpoint)."
  type        = bool
  default     = false
}

############################################
# Outputs control
############################################

variable "expose_debug_outputs" {
  description = "If true, expose additional outputs useful for debugging (e.g., computed AZs)."
  type        = bool
  default     = false
}
