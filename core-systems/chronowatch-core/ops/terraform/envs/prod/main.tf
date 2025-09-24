terraform {
  required_version = "~> 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.62.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6.2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.5"
    }
  }

  # Remote state backend — S3 + DynamoDB locking
  backend "s3" {
    bucket         = "cw-prod-tfstate"        # Замените на ваш bucket
    key            = "chronowatch-core/prod/terraform.tfstate"
    region         = "eu-north-1"             # Стокгольм (пример)
    encrypt        = true
    dynamodb_table = "cw-prod-tf-locks"       # Таблица блокировок
    kms_key_id     = "alias/aws/s3"           # Или ваш CMK
  }
}

#========================
# Провайдеры и базовые настройки
#========================
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project        = "Chronowatch-Core"
      Environment    = "prod"
      Owner          = "platform-ops"
      CostCenter     = "core-prod"
      Compliance     = "gdpr"
      DataClass      = "confidential"
      Terraform      = "true"
      ManagedBy      = "terraform"
    }
  }
}

# Kubernetes/Helm провайдеры подключаются к EKS после его создания через data source
provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

#========================
# Локальные значения и входные переменные
#========================
locals {
  name_prefix = "cw-prod"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)

  # Общие теги, пробрасываются в модули где есть поддержка
  common_tags = {
    Project     = "Chronowatch-Core"
    Environment = "prod"
    Tier        = "core"
  }
}

variable "aws_region" {
  description = "AWS region for prod"
  type        = string
  default     = "eu-north-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.20.0.0/16"
}

variable "eks_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.30"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "16.3"
}

variable "db_name" {
  description = "Default database name"
  type        = string
  default     = "chronowatch"
}

variable "db_username" {
  description = "Master username (pull from Secrets Manager/SSM in prod)"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Master password (pull from Secrets Manager/SSM in prod)"
  type        = string
  sensitive   = true
}

variable "allowed_office_cidrs" {
  description = "Office VPN/Jump CIDRs for admin access (bastion/SSM)"
  type        = list(string)
  default     = []
}

#========================
# Data sources
#========================
data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

#========================
# Ключ шифрования (KMS CMK) для критичных ресурсов
#========================
module "kms_cmk_core" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 2.2.0"

  aliases               = ["alias/${local.name_prefix}-core"]
  description           = "KMS CMK for ${local.name_prefix} data at rest"
  enable_default_policy = true
  key_owners            = [data.aws_caller_identity.current.arn]
  tags                  = local.common_tags
}

#========================
# Сеть: VPC с 3 AZ, приватные/публичные сабсети и NAT GW
#========================
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8.1"

  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = local.azs
  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]           # /20
  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]       # /20

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.common_tags
}

#========================
# EKS кластер с IRSA, системными аддонами и managed node groups
#========================
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.20.0"

  cluster_name                    = "${local.name_prefix}-eks"
  cluster_version                 = var.eks_version
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = module.kms_cmk_core.key_arn
  }

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
        }
      })
    }
    eks-pod-identity-agent = {
      most_recent = true
    }
  }

  eks_managed_node_groups = {
    general = {
      instance_types = ["m6i.large", "m6a.large"]
      min_size       = 3
      max_size       = 10
      desired_size   = 3

      capacity_type  = "ON_DEMAND"
      ami_type       = "AL2_x86_64"

      disk_size = 50

      labels = {
        workload = "general"
      }

      tags = merge(local.common_tags, {
        "NodeGroup" = "general"
      })
    }

    compute = {
      instance_types = ["c6i.xlarge", "c7i.xlarge"]
      min_size       = 2
      max_size       = 8
      desired_size   = 2
      capacity_type  = "SPOT"
      disk_size      = 80
      labels = {
        workload = "compute"
      }
      taints = [{
        key    = "dedicated"
        value  = "compute"
        effect = "NO_SCHEDULE"
      }]
      tags = merge(local.common_tags, {
        "NodeGroup" = "compute"
      })
    }
  }

  tags = local.common_tags
}

# Данные для подключения k8s провайдера
data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}
data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

#========================
# Безопасность: Security Groups
#========================
module "sg_rds" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1.2"

  name        = "${local.name_prefix}-rds-sg"
  description = "RDS security group"
  vpc_id      = module.vpc.vpc_id

  ingress_with_source_security_group_id = [
    {
      description              = "EKS nodes to RDS"
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      source_security_group_id = module.eks.node_security_group_id
    }
  ]

  egress_rules = ["all-all"]
  tags         = local.common_tags
}

module "sg_redis" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1.2"

  name        = "${local.name_prefix}-redis-sg"
  description = "Redis security group"
  vpc_id      = module.vpc.vpc_id

  ingress_with_source_security_group_id = [
    {
      description              = "EKS nodes to Redis"
      from_port                = 6379
      to_port                  = 6379
      protocol                 = "tcp"
      source_security_group_id = module.eks.node_security_group_id
    }
  ]
  egress_rules = ["all-all"]
  tags         = local.common_tags
}

#========================
# RDS PostgreSQL: Multi-AZ, KMS, Performance Insights
#========================
module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.7.0"

  identifier = "${local.name_prefix}-pg"

  engine               = "postgres"
  engine_version       = var.db_engine_version
  family               = "postgres16" # для параметрической группы
  major_engine_version = "16"

  instance_class = var.db_instance_class
  allocated_storage     = 100
  max_allocated_storage = 500

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  multi_az               = true
  publicly_accessible    = false
  port                   = 5432
  manage_master_user_password = false

  vpc_security_group_ids = [module.sg_rds.security_group_id]
  subnet_ids             = module.vpc.private_subnets

  storage_encrypted = true
  kms_key_id        = module.kms_cmk_core.key_arn

  performance_insights_enabled = true
  performance_insights_kms_key_id = module.kms_cmk_core.key_arn

  deletion_protection = true
  skip_final_snapshot = false

  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  backup_retention_period = 7

  tags = local.common_tags
}

#========================
# ElastiCache Redis: кластер для кэша/сессий
#========================
module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.6.0"

  cluster_id           = "${local.name_prefix}-redis"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = "cache.r6g.large"
  num_cache_nodes      = 1
  port                 = 6379
  parameter_group_name = "default.redis7"

  subnet_group_name = "${local.name_prefix}-redis-subnets"
  subnet_ids        = module.vpc.private_subnets

  security_group_ids = [module.sg_redis.security_group_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token_enabled         = false # рекомендовано Secrets Manager + user groups для Redis 6 ACL

  tags = local.common_tags
}

#========================
# S3 bucket для артефактов/релизов
#========================
module "s3_release" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.4.0"

  bucket = "${local.name_prefix}-releases"
  acl    = "private"

  force_destroy = false

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = module.kms_cmk_core.key_arn
      }
    }
  }

  versioning = {
    enabled = true
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = local.common_tags
}

#========================
# Observability базовая интеграция (лог-группы)
#========================
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${module.eks.cluster_name}/cluster"
  retention_in_days = 30
  kms_key_id        = module.kms_cmk_core.key_arn
  tags              = local.common_tags
}

#========================
# Примеры IRSA для доступа к S3/SSM (минимально необходимые политики)
#========================
module "irsa_release_reader" {
  source  = "terraform-aws-modules/iam-role-for-service-accounts-eks/aws"
  version = "~> 5.39.0"

  name                          = "${local.name_prefix}-irsa-release-reader"
  attach_policy_json            = true
  policy_json                   = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          module.s3_release.s3_bucket_arn,
          "${module.s3_release.s3_bucket_arn}/*"
        ]
      }
    ]
  })
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["chronowatch-core:release-reader"]
    }
  }
  tags = local.common_tags
}

#========================
# Выходные значения
#========================
output "region" {
  value       = var.aws_region
  description = "AWS region"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Private subnet IDs"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name"
}

output "eks_oidc_provider_arn" {
  value       = module.eks.oidc_provider_arn
  description = "OIDC provider ARN for IRSA"
}

output "rds_endpoint" {
  value       = module.rds.db_instance_endpoint
  description = "RDS endpoint"
  sensitive   = false
}

output "redis_endpoint" {
  value       = module.redis.primary_endpoint_address
  description = "Redis primary endpoint"
}

output "s3_release_bucket" {
  value       = module.s3_release.s3_bucket_id
  description = "Release bucket name"
}
