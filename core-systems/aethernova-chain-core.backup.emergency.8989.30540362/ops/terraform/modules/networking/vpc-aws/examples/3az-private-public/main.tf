############################################
# modules/networking/vpc-aws/examples/3az-private-public/main.tf
############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

############################################
# Provider & Region
############################################
variable "region" {
  type        = string
  description = "AWS region to deploy into"
  default     = "eu-central-1"
}

variable "profile" {
  type        = string
  description = "AWS shared credentials profile name"
  default     = null
}

provider "aws" {
  region  = var.region
  profile = var.profile
}

############################################
# Inputs (production-friendly toggles)
############################################
variable "name" {
  type        = string
  description = "Base name/prefix for VPC-related resources"
  default     = "aethernova-core"
}

variable "cidr" {
  type        = string
  description = "VPC CIDR block"
  default     = "10.40.0.0/16"
}

variable "az_count" {
  type        = number
  description = "How many AZs to use (3 recommended)"
  default     = 3
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 6
    error_message = "az_count must be between 2 and 6."
  }
}

variable "single_nat_gateway" {
  type        = bool
  description = "Cost-saving: true = single NAT GW, false = one NAT per AZ"
  default     = false
}

variable "enable_ipv6" {
  type        = bool
  description = "Enable IPv6 addressing"
  default     = true
}

variable "enable_endpoints" {
  type        = bool
  description = "Create common VPC Endpoints (S3, DynamoDB, STS, EC2, ECR, SSM, CloudWatch, Logs)"
  default     = true
}

variable "env" {
  type        = string
  description = "Environment tag"
  default     = "prod"
}

variable "cost_center" {
  type        = string
  description = "CostCenter tag"
  default     = "aethernova"
}

############################################
# Availability Zones & Subnet planning
############################################
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Pick first N AZs deterministically
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Derive /20 for public and /20 for private per AZ from /16
  #  - 10.40.0.0/16 -> public: 10.40.0.0/20, 10.40.16.0/20, 10.40.32.0/20 ...
  #  - 10.40.0.0/16 -> private: 10.40.128.0/20, 10.40.144.0/20, 10.40.160.0/20 ...
  public_subnets = [
    for i in range(var.az_count) : cidrsubnet(var.cidr, 4, i) # /16 -> /20 (newbits=4)
  ]

  private_subnets = [
    for i in range(var.az_count) : cidrsubnet(var.cidr, 4, i + 8) # offset to upper half
  ]

  # Optional IPv6 /64 per subnet using prefix indices 0..N
  public_ipv6_prefixes  = [for i in range(var.az_count) : i]
  private_ipv6_prefixes = [for i in range(var.az_count) : i + 8]

  common_tags = {
    Name        = "${var.name}-vpc"
    Environment = var.env
    CostCenter  = var.cost_center
    ManagedBy   = "Terraform"
    Module      = "networking/vpc-aws"
    Example     = "3az-private-public"
  }
}

############################################
# CloudWatch Log Group for VPC Flow Logs
############################################
resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/${var.name}/flow-logs"
  retention_in_days = 30
  tags              = local.common_tags
}

############################################
# VPC (terraform-aws-modules/vpc/aws)
# NOTE: This example uses a battle-tested upstream module.
############################################
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = var.name
  cidr = var.cidr

  azs             = local.azs
  public_subnets  = local.public_subnets
  private_subnets = local.private_subnets

  enable_dns_support   = true
  enable_dns_hostnames = true
  create_igw           = true

  # NAT
  enable_nat_gateway     = true
  single_nat_gateway     = var.single_nat_gateway
  one_nat_gateway_per_az = !var.single_nat_gateway

  # IPv6
  enable_ipv6 = var.enable_ipv6
  # Auto-assign IPv6 prefixes to subnets, /64 per subnet
  public_subnet_ipv6_prefixes               = var.enable_ipv6 ? local.public_ipv6_prefixes : null
  private_subnet_ipv6_prefixes              = var.enable_ipv6 ? local.private_ipv6_prefixes : null
  public_subnet_assign_ipv6_address_on_creation  = var.enable_ipv6
  private_subnet_assign_ipv6_address_on_creation = var.enable_ipv6

  # Flow Logs -> CloudWatch Logs (with external log group created above)
  enable_flow_log                           = true
  flow_log_destination_type                 = "cloud-watch-logs"
  create_flow_log_cloudwatch_log_group      = false
  flow_log_cloudwatch_log_group_name        = aws_cloudwatch_log_group.vpc_flow.name
  # Let the module create the IAM role for flow logs
  create_flow_log_cloudwatch_iam_role       = true
  flow_log_max_aggregation_interval         = 60
  flow_log_log_format                       = "${timestamp} ${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${pkt-srcaddr} ${pkt-dstaddr} ${action} ${log-status} ${tcp-flags} ${pkt-src-aws-service} ${pkt-dst-aws-service}"

  # Default NACLs and SGs left managed by the module defaults.
  # If your org mandates strict NACLs, add manage_default_network_acl and rules here.

  # VPC Endpoints (gateway + interface)
  enable_s3_endpoint       = var.enable_endpoints
  enable_dynamodb_endpoint = var.enable_endpoints

  vpc_endpoints = var.enable_endpoints ? {
    # Interface endpoints (private, via ENI)
    ec2 = {
      service             = "ec2"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    ec2messages = {
      service             = "ec2messages"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    ssm = {
      service             = "ssm"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    ssm_messages = {
      service             = "ssmmessages"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    sts = {
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    logs = {
      service             = "logs"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
    monitoring = {
      service             = "monitoring"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.vpc.vpc_endpoint_security_group_id]
    }
  } : {}

  # Tags
  tags = local.common_tags

  public_subnet_tags = merge(local.common_tags, {
    Tier = "public"
  })

  private_subnet_tags = merge(local.common_tags, {
    Tier = "private"
  })
}

############################################
# Useful Outputs
############################################
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "public_subnets" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

output "private_subnets" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "nat_gateway_ids" {
  description = "NAT Gateway IDs (if created)"
  value       = try(module.vpc.natgw_ids, [])
}

output "vpc_cidr" {
  description = "VPC IPv4 CIDR"
  value       = var.cidr
}

output "ipv6_enabled" {
  description = "Whether IPv6 is enabled"
  value       = var.enable_ipv6
}
