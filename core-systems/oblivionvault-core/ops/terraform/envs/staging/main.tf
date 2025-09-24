###############################################################################
# oblivionvault-core/ops/terraform/envs/staging/main.tf
# Industrial-grade staging environment on AWS
###############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws    = { source = "hashicorp/aws",    version = "~> 5.60" }
    random = { source = "hashicorp/random", version = "~> 3.6"  }
  }

  # Remote state (adjust bucket/table/region if needed)
  backend "s3" {
    bucket         = "oblivionvault-tfstate"
    key            = "oblivionvault-core/staging/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "oblivionvault-tf-locks"
    encrypt        = true
  }
}

###############################################################################
# Variables (inline for a single-file env; may be split to variables.tf later)
###############################################################################

variable "aws_region" {
  description = "AWS region for staging"
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "oblivionvault-core"
}

variable "environment" {
  description = "Environment identifier"
  type        = string
  default     = "staging"
}

# RDS instance size and storage may be adjusted per non-prod budget
variable "rds_instance_class" {
  type        = string
  default     = "db.t4g.medium"
}

variable "rds_allocated_storage" {
  type        = number
  default     = 50
}

variable "rds_max_allocated_storage" {
  type        = number
  default     = 200
}

# Redis node size for staging
variable "redis_node_type" {
  type        = string
  default     = "cache.t4g.small"
}

###############################################################################
# Provider & common tags
###############################################################################

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Platform-Team"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

###############################################################################
# Locals (naming, versions, networking)
###############################################################################

locals {
  name   = "${var.project_name}-${var.environment}"
  region = var.aws_region

  eks_version = "1.30"

  # Networking plan (RFC1918 /16 with three /20 tiers)
  vpc_cidr        = "10.120.0.0/16"
  azs             = slice(data.aws_availability_zones.available.names, 0, 3)

  public_subnets  = ["10.120.0.0/20",  "10.120.16.0/20", "10.120.32.0/20"]
  private_subnets = ["10.120.128.0/20","10.120.144.0/20","10.120.160.0/20"]
  intra_subnets   = ["10.120.64.0/20", "10.120.80.0/20", "10.120.96.0/20"]

  # DB and Redis defaults
  db_name     = "ovc_staging"
  db_user     = "ovc_staging"
  redis_ports = { tcp = 6379 }

  # Common labels for k8s subnets
  elb_public_tag   = { "kubernetes.io/role/elb"          = "1" }
  elb_private_tag  = { "kubernetes.io/role/internal-elb" = "1" }
}

###############################################################################
# VPC (Public/Private/Intra) with NAT and k8s-friendly tags
###############################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name}-vpc"
  cidr = local.vpc_cidr
  azs  = local.azs

  public_subnets  = local.public_subnets
  private_subnets = local.private_subnets
  intra_subnets   = local.intra_subnets

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  create_igw             = true
  create_elasticache_subnet_group = true
  create_database_subnet_group    = true

  public_subnet_tags  = local.elb_public_tag
  private_subnet_tags = local.elb_private_tag

  manage_default_security_group = true
  default_security_group_name   = "${local.name}-default-sg"
  default_security_group_ingress = [
    {
      description = "intra-vpc"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = [local.vpc_cidr]
    }
  ]
  default_security_group_egress = [
    {
      description = "all-out"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

###############################################################################
# EKS Cluster with IRSA and core addons
###############################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.13"

  cluster_name    = local.name
  cluster_version = local.eks_version

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  enable_irsa = true

  # Encrypt secrets at rest with a dedicated KMS key managed by module
  create_kms_key                = true
  kms_key_enable_default_policy = true
  kms_key_administrators        = [data.aws_caller_identity.current.arn]

  # Core addons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent          = true
      before_compute       = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_ENI_TARGET          = "2"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  # Managed node groups
  eks_managed_node_group_defaults = {
    ami_type   = "AL2_x86_64"
    disk_size  = 60
    min_size   = 0
    max_size   = 8
    desired_size = 0
  }

  eks_managed_node_groups = {
    ondemand = {
      desired_size  = 3
      min_size      = 2
      max_size      = 6
      instance_types = ["t3.large", "t3a.large"]
      capacity_type  = "ON_DEMAND"
      labels = {
        workload = "general"
        tier     = "base"
      }
    }

    spot = {
      desired_size   = 2
      min_size       = 0
      max_size       = 8
      capacity_type  = "SPOT"
      instance_types = ["t3.large", "t3a.large", "m5.large", "m6g.large"]
      labels = {
        workload = "spot"
        tier     = "elastic"
      }
      taints = [{
        key    = "spot"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

###############################################################################
# IAM Roles for Service Accounts (IRSA): ALB Controller, ExternalDNS, Cert-Manager
###############################################################################

module "irsa_alb_controller" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                              = "${local.name}-alb-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

module "irsa_external_dns" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                     = "${local.name}-external-dns"
  attach_external_dns_policy    = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

module "irsa_cert_manager" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                     = "${local.name}-cert-manager"
  attach_cert_manager_policy    = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["cert-manager:cert-manager"]
    }
  }
}

###############################################################################
# ECR repository for application images
###############################################################################

module "ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.6"

  repository_name                 = var.project_name
  repository_image_scan_on_push   = true
  repository_force_delete         = var.environment != "prod"
  repository_encryption_configuration = {
    encryption_type = "AES256"
  }

  lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 30 images"
        selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }
        action       = { type = "expire" }
      }
    ]
  })
}

###############################################################################
# Security Groups (RDS, Redis)
###############################################################################

module "sg_rds" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.2"

  name        = "${local.name}-rds-sg"
  description = "RDS access from VPC"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = [local.vpc_cidr]
  ingress_rules       = ["postgresql-tcp"]
  egress_rules        = ["all-all"]
}

module "sg_redis" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.2"

  name        = "${local.name}-redis-sg"
  description = "Redis access from VPC"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = [local.vpc_cidr]
  ingress_with_cidr_blocks = [{
    from_port   = local.redis_ports.tcp
    to_port     = local.redis_ports.tcp
    protocol    = "tcp"
    cidr_blocks = local.vpc_cidr
    description = "Redis TCP"
  }]
  egress_rules = ["all-all"]
}

###############################################################################
# Subnet groups for RDS and ElastiCache
###############################################################################

resource "aws_db_subnet_group" "rds" {
  name       = "${local.name}-db-subnets"
  subnet_ids = module.vpc.private_subnets
  tags       = { Name = "${local.name}-db-subnets" }
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name}-redis-subnets"
  subnet_ids = module.vpc.private_subnets
  tags       = { Name = "${local.name}-redis-subnets" }
}

###############################################################################
# RDS PostgreSQL 16 (Multi-AZ, encrypted, monitored)
###############################################################################

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.9"

  identifier = "${local.name}-pg"

  engine               = "postgres"
  engine_version       = "16.3"
  family               = "postgres16"
  major_engine_version = "16"

  instance_class            = var.rds_instance_class
  allocated_storage         = var.rds_allocated_storage
  max_allocated_storage     = var.rds_max_allocated_storage
  storage_encrypted         = true
  kms_key_id                = module.eks.kms_key_arn

  multi_az                  = true
  publicly_accessible       = false
  deletion_protection       = false
  skip_final_snapshot       = true

  db_name                   = local.db_name
  username                  = local.db_user
  manage_master_user_password = true   # Secrets Manager managed

  vpc_security_group_ids    = [module.sg_rds.security_group_id]
  db_subnet_group_name      = aws_db_subnet_group.rds.name

  enabled_cloudwatch_logs_exports = ["postgresql"]
  performance_insights_enabled    = true
  performance_insights_retention_period = 7

  create_monitoring_role = true
  monitoring_interval    = 60

  backup_window      = "02:00-03:00"
  maintenance_window = "Mon:03:00-Mon:04:00"

  parameters = [
    { name = "max_connections", value = "200" },
    { name = "shared_buffers",  value = "512MB" }
  ]
}

###############################################################################
# ElastiCache Redis (replication group, Multi-AZ)
###############################################################################

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = replace("${local.name}-redis", "_", "-")
  description                   = "Redis for ${local.name}"
  engine                        = "redis"
  engine_version                = "7.1"
  node_type                     = var.redis_node_type
  parameter_group_name          = "default.redis7"
  port                          = local.redis_ports.tcp

  subnet_group_name             = aws_elasticache_subnet_group.redis.name
  security_group_ids            = [module.sg_redis.security_group_id]

  automatic_failover_enabled    = true
  multi_az_enabled              = true

  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  auth_token                    = random_password.redis_auth.result

  # two primaries (disabled) vs. one primary + replicas.
  # For staging: 1 primary + 1 replica
  num_node_groups               = 1
  replicas_per_node_group       = 1

  lifecycle {
    ignore_changes = [auth_token] # prevents unwanted rotation on plan
  }
}

resource "random_password" "redis_auth" {
  length  = 32
  special = false
}

###############################################################################
# CloudWatch log group for application logs
###############################################################################

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project_name}/${var.environment}/app"
  retention_in_days = 30
}

###############################################################################
# Outputs
###############################################################################

output "region" {
  value = local.region
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnets" {
  value = module.vpc.private_subnets
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "eks_oidc_provider_arn" {
  value = module.eks.oidc_provider_arn
}

output "ecr_repository_url" {
  value = module.ecr.repository_url
}

output "rds_endpoint" {
  value = module.rds.db_instance_endpoint
}

output "rds_secret_arn" {
  description = "Secrets Manager ARN with master credentials"
  value       = module.rds.db_instance_master_user_secret_arn
}

output "redis_primary_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "redis_reader_endpoint" {
  value = aws_elasticache_replication_group.redis.reader_endpoint_address
}
