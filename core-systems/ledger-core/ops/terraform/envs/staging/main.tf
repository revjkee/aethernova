########################################
# ledger-core/ops/terraform/envs/staging/main.tf
########################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  backend "s3" {
    bucket         = var.tf_state_bucket            # например: "aethernova-tfstate"
    key            = "ledger-core/staging/terraform.tfstate"
    region         = var.aws_region
    dynamodb_table = var.tf_lock_table              # например: "aethernova-tf-locks"
    encrypt        = true
    kms_key_id     = var.tf_state_kms_key_arn       # необязательно, но рекомендуется
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.56"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

########################################
# Providers & Globals
########################################

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "ledger-core"
      Environment = "staging"
      Owner       = var.owner_tag
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix   = "ledger-stg"
  vpc_cidr      = var.vpc_cidr
  azs           = slice(data.aws_availability_zones.available.names, 0, 2)
  tags_common   = { "app.kubernetes.io/part-of" = "ledger", "stage" = "staging" }
  eks_version   = var.eks_version
  db_name       = "ledger"
  db_username   = "ledger"
  db_instance   = "db.t4g.medium"
  kms_alias     = "alias/${local.name_prefix}-kms"
  allowed_api_cidrs = var.eks_api_allowed_cidrs
}

data "aws_availability_zones" "available" {
  state = "available"
}

########################################
# KMS (encryption for S3/RDS as needed)
########################################

resource "aws_kms_key" "main" {
  description             = "KMS CMK for ${local.name_prefix} staging"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  tags                    = local.tags_common
}

resource "aws_kms_alias" "main" {
  name          = local.kms_alias
  target_key_id = aws_kms_key.main.key_id
}

########################################
# VPC
########################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name_prefix}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 4, i)]
  public_subnets  = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 8, i + 32)]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  map_public_ip_on_launch = false

  manage_default_network_acl = true
  manage_default_security_group = true

  enable_flow_log = true
  flow_log_destination_type = "s3"
  flow_log_max_aggregation_interval = 60
  flow_log_file_format = "parquet"
  flow_log_traffic_type = "ALL"
  flow_log_destination_arn = module.logs_bucket.s3_bucket_arn

  tags = merge(local.tags_common, {
    "kubernetes.io/cluster/${local.name_prefix}-eks" = "shared"
  })
}

########################################
# S3: logs/artifacts bucket
########################################

module "logs_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.2"

  bucket        = "${local.name_prefix}-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  server_side_encryption = {
    sse_algorithm     = "aws:kms"
    kms_master_key_id = aws_kms_key.main.arn
  }

  versioning = {
    enabled = true
  }

  lifecycle_rule = [
    {
      id      = "expire-old-logs"
      enabled = true
      filter  = { prefix = "logs/" }
      transition = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 90, storage_class = "GLACIER" }
      ]
      expiration = { days = 365 }
    }
  ]

  tags = local.tags_common
}

########################################
# EKS Cluster
########################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.11"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = local.eks_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access_cidrs = local.allowed_api_cidrs

  kms_key_enable_default_policy = true
  kms_key_owners                = [data.aws_caller_identity.current.arn]
  kms_key_administrators        = [data.aws_caller_identity.current.arn]

  cluster_addons = {
    coredns = { resolve_conflicts = "OVERWRITE" }
    kube-proxy = { resolve_conflicts = "OVERWRITE" }
    vpc-cni = {
      resolve_conflicts = "OVERWRITE"
      most_recent       = true
      configuration_values = jsonencode({
        env = { ENABLE_PREFIX_DELEGATION = "true" }
      })
    }
    aws-ebs-csi-driver = {
      resolve_conflicts = "OVERWRITE"
      most_recent       = true
    }
  }

  eks_managed_node_group_defaults = {
    ami_type       = "AL2_ARM_64"
    disk_size      = 50
    instance_types = ["t4g.large"]
    capacity_type  = "ON_DEMAND"
  }

  eks_managed_node_groups = {
    ng-default = {
      min_size     = 2
      max_size     = 6
      desired_size = 3
      subnet_ids   = module.vpc.private_subnets
      tags         = local.tags_common
    }
  }

  # Security groups: restrict node egress; cluster SG later used for DB allow
  node_security_group_additional_rules = {
    egress_ephemeral = {
      description      = "Allow egress ephemeral ports"
      type             = "egress"
      from_port        = 1024
      to_port          = 65535
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
    }
  }

  tags = local.tags_common
}

# Kubernetes & Helm providers, authenticated via EKS
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = module.eks.cluster_token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = module.eks.cluster_token
  }
}

########################################
# IRSA for ledger-core app to access S3 (artifacts)
########################################

module "irsa_ledger_core" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name_prefix = "${local.name_prefix}-ledger-irsa"
  attach_policy_json = true
  policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3ArtifactsRW"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          module.logs_bucket.s3_bucket_arn,
          "${module.logs_bucket.s3_bucket_arn}/*"
        ]
      }
    ]
  })

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["ledger-core/ledger-core"]
    }
  }

  tags = local.tags_common
}

########################################
# RDS PostgreSQL (staging)
########################################

module "db_subnets" {
  source  = "terraform-aws-modules/vpc/aws//modules/db-subnets"
  version = "~> 5.8"

  name       = "${local.name_prefix}-db-subnets"
  vpc_id     = module.vpc.vpc_id
  subnets    = module.vpc.private_subnets
  create_egress_only_igw = false
  tags       = local.tags_common
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.5"

  identifier = "${local.name_prefix}-pg"

  engine               = "postgres"
  engine_version       = "15.6"
  family               = "postgres15"
  major_engine_version = "15"
  instance_class       = local.db_instance
  allocated_storage    = 50
  max_allocated_storage = 150

  db_name  = local.db_name
  username = local.db_username
  port     = 5432

  manage_master_user_password = true
  create_db_subnet_group      = false
  db_subnet_group_name        = module.db_subnets.db_subnet_group_name

  vpc_security_group_ids = [aws_security_group.db.id]

  multi_az               = false
  publicly_accessible    = false
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.main.arn

  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"
  backup_retention_period = 7
  deletion_protection    = false
  skip_final_snapshot    = true

  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.main.arn

  tags = local.tags_common
}

resource "aws_security_group" "db" {
  name        = "${local.name_prefix}-db-sg"
  description = "PostgreSQL access from EKS nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "Allow Postgres from EKS node SG"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags_common
}

########################################
# Secrets Manager: DATABASE_URL for app
########################################

data "aws_secretsmanager_secret_version" "db_creds" {
  secret_id = module.rds.db_instance_master_user_secret_arn
}

locals {
  db_password = jsondecode(data.aws_secretsmanager_secret_version.db_creds.secret_string)["password"]
  database_url = "postgresql://${local.db_username}:${local.db_password}@${module.rds.db_instance_address}:${module.rds.db_instance_port}/${local.db_name}"
}

resource "aws_secretsmanager_secret" "ledger_database_url" {
  name                    = "${local.name_prefix}/database_url"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.main.arn
  tags                    = local.tags_common
}

resource "aws_secretsmanager_secret_version" "ledger_database_url_v" {
  secret_id     = aws_secretsmanager_secret.ledger_database_url.id
  secret_string = jsonencode({ DATABASE_URL = local.database_url })
}

########################################
# (Optional) Helm bootstrap examples (commented)
########################################
# module "metrics_server" {
#   source  = "terraform-aws-modules/helm/aws"
#   version = "~> 2.11"
#   cluster_name = module.eks.cluster_name
#   chart  = "metrics-server"
#   repo   = "https://kubernetes-sigs.github.io/metrics-server/"
#   name   = "metrics-server"
#   namespace = "kube-system"
# }

########################################
# Variables
########################################

variable "aws_region" {
  description = "AWS region for staging"
  type        = string
  default     = "eu-north-1"
}

variable "owner_tag" {
  description = "Owner tag for resources"
  type        = string
  default     = "platform-team"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.60.0.0/16"
}

variable "eks_version" {
  description = "EKS Kubernetes version"
  type        = string
  default     = "1.30"
}

variable "eks_api_allowed_cidrs" {
  description = "CIDRs allowed to reach public EKS API"
  type        = list(string)
  default     = ["0.0.0.0/0"] # сузьте в реальном стейджинге (VPN/office IPs)
}

# Remote state backend wiring (safest via TF_VAR_*)
variable "tf_state_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
}

variable "tf_lock_table" {
  description = "DynamoDB table for Terraform state locking"
  type        = string
}

variable "tf_state_kms_key_arn" {
  description = "Optional KMS key ARN for state at rest"
  type        = string
  default     = null
}

########################################
# Outputs
########################################

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name"
}

output "eks_cluster_endpoint" {
  value       = module.eks.cluster_endpoint
  description = "EKS API endpoint"
}

output "eks_oidc_provider_arn" {
  value       = module.eks.oidc_provider_arn
  description = "EKS OIDC provider ARN"
}

output "rds_endpoint" {
  value       = module.rds.db_instance_endpoint
  description = "RDS PostgreSQL endpoint"
}

output "artifacts_bucket" {
  value       = module.logs_bucket.s3_bucket_id
  description = "S3 bucket for artifacts/logs"
}

output "database_url_secret_arn" {
  value       = aws_secretsmanager_secret.ledger_database_url.arn
  description = "Secrets Manager secret ARN with DATABASE_URL"
}

output "irsa_role_arn" {
  value       = module.irsa_ledger_core.iam_role_arn
  description = "IRSA role ARN for ledger-core SA"
}
