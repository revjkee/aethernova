# omnimind-core/ops/ansible/playbooks/modules/prod/main.tf
# Production infrastructure for omnimind-core on AWS

terraform {
  required_version = "~> 1.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Рекомендуется настроить backend вне кода либо через partial-config.
  backend "s3" {
    bucket         = "CHANGE_ME-tfstate"
    key            = "omnimind-core/prod/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "CHANGE_ME-tf-locks"
    encrypt        = true
  }
}

# -------------------------- VARIABLES --------------------------

variable "project" {
  description = "Project tag/name"
  type        = string
  default     = "omnimind-core"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-north-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "azs" {
  description = "AZ suffixes to use"
  type        = list(string)
  default     = ["a", "b", "c"]
}

variable "public_subnets" {
  description = "Public subnets CIDRs"
  type        = list(string)
  default     = ["10.20.0.0/20", "10.20.16.0/20", "10.20.32.0/20"]
}

variable "private_subnets" {
  description = "Private subnets CIDRs (for workloads)"
  type        = list(string)
  default     = ["10.20.64.0/19", "10.20.96.0/19", "10.20.128.0/19"]
}

variable "intra_subnets" {
  description = "Intra/DB subnets (no NAT egress)"
  type        = list(string)
  default     = ["10.20.192.0/22", "10.20.196.0/22", "10.20.200.0/22"]
}

variable "eks_version" {
  description = "EKS version"
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
  default     = "16.4"
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "allowed_office_cidrs" {
  description = "Office/VPN CIDRs allowed to bastion/ALB if exposed"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional resource tags"
  type        = map(string)
  default     = {}
}

# -------------------------- PROVIDERS & LOCALS --------------------------

provider "aws" {
  region = var.region

  default_tags {
    tags = merge({
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
    }, var.tags)
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "${var.project}-${var.environment}"
  azs_full    = [for z in var.azs : "${var.region}${z}"]

  # Common labels to pass to modules
  common_tags = merge({
    Name        = local.name_prefix
    CostCenter  = "platform"
    Confidential= "true"
  }, var.tags)
}

# -------------------------- KMS KEYS --------------------------

resource "aws_kms_key" "data" {
  description             = "KMS key for ${local.name_prefix} data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_kms_key" "logs" {
  description             = "KMS key for ${local.name_prefix} logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# -------------------------- NETWORK: VPC --------------------------

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"

  name = local.name_prefix
  cidr = var.vpc_cidr

  azs             = local.azs_full
  public_subnets  = var.public_subnets
  private_subnets = var.private_subnets
  intra_subnets   = var.intra_subnets

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_security_group = true
  default_security_group_name   = "${local.name_prefix}-default-sg"
  default_security_group_ingress = [
    {
      description = "intra-vpc"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = [var.vpc_cidr]
    }
  ]
  default_security_group_egress = [
    {
      description = "all egress"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]

  enable_flow_log                      = true
  flow_log_destination_type            = "cloud-watch-logs"
  flow_log_cloudwatch_log_group_name   = "/aws/vpc/${local.name_prefix}-flowlogs"
  flow_log_cloudwatch_iam_role_arn     = null
  flow_log_max_aggregation_interval    = 60
  flow_log_cloudwatch_log_group_kms_key_id = aws_kms_key.logs.arn
  flow_log_cloudwatch_log_group_retention_in_days = 30

  tags = local.common_tags
}

# -------------------------- ECR --------------------------

resource "aws_ecr_repository" "core" {
  name                 = "${local.name_prefix}/core"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key        = aws_kms_key.data.arn
  }
  tags = local.common_tags
}

# -------------------------- S3 (object store for app data) --------------------------

module "s3" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.1"

  bucket = "${local.name_prefix}-data"
  force_destroy = false

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.data.arn
      }
    }
  }

  versioning = {
    status = true
  }

  lifecycle_rule = [
    {
      id      = "expire-noncurrent"
      enabled = true
      noncurrent_version_expiration = {
        noncurrent_days = 30
      }
    }
  ]

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true

  tags = local.common_tags
}

# -------------------------- EKS --------------------------

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = var.eks_version

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_endpoint_public_access  = false
  cluster_endpoint_private_access = true

  create_cloudwatch_log_group = true
  cluster_log_retention_in_days = 30
  cluster_log_kms_key_id = aws_kms_key.logs.arn
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Managed Node Groups
  eks_managed_node_groups = {
    system = {
      ami_type       = "AL2_x86_64"
      instance_types = ["t3.large"]
      min_size       = 2
      max_size       = 6
      desired_size   = 3
      labels         = { role = "system" }
      taints         = []
      update_config  = { max_unavailable = 1 }
      tags           = local.common_tags
    }

    general = {
      ami_type       = "AL2_x86_64"
      instance_types = ["m6g.large", "m6g.xlarge"]
      capacity_type  = "SPOT"
      min_size       = 2
      max_size       = 10
      desired_size   = 4
      labels         = { role = "general" }
      taints         = []
      update_config  = { max_unavailable = 1 }
      tags           = local.common_tags
    }
  }

  tags = local.common_tags
}

# Для провайдеров Kubernetes/Helm — используем kubeconfig из EKS
data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

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

# -------------------------- RDS PostgreSQL (Multi-AZ) --------------------------

resource "aws_db_subnet_group" "rds" {
  name       = "${local.name_prefix}-rds-subnets"
  subnet_ids = module.vpc.intra_subnets
  tags       = local.common_tags
}

resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "RDS security group"
  vpc_id      = module.vpc.vpc_id
  tags        = local.common_tags
}

# Разрешаем доступ к БД только с нод EKS и с Bastion (через SSM, если понадобится)
resource "aws_security_group_rule" "rds_from_nodes" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.rds.id
  source_security_group_id = module.eks.node_security_group_id
  description              = "PostgreSQL from EKS nodes"
}

resource "aws_security_group_rule" "rds_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.rds.id
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_db_parameter_group" "postgres" {
  name        = "${local.name_prefix}-pg16"
  family      = "postgres16"
  description = "Parameter group for ${local.name_prefix} PostgreSQL"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }
  tags = local.common_tags
}

resource "random_password" "db_master" {
  length           = 24
  special          = true
  override_characters = "!@#%^*-_+=?"
}

resource "aws_secretsmanager_secret" "db" {
  name = "${local.name_prefix}/rds/master"
  kms_key_id = aws_kms_key.data.id
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    username = "omni_admin"
    password = random_password.db_master.result
  })
}

resource "aws_db_instance" "postgres" {
  identifier              = "${local.name_prefix}-db"
  engine                  = "postgres"
  engine_version          = var.db_engine_version
  instance_class          = var.db_instance_class
  allocated_storage       = 200
  max_allocated_storage   = 1000
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.data.arn

  multi_az                = true
  db_subnet_group_name    = aws_db_subnet_group.rds.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  parameter_group_name    = aws_db_parameter_group.postgres.name

  username                = jsondecode(aws_secretsmanager_secret_version.db.secret_string)["username"]
  password                = jsondecode(aws_secretsmanager_secret_version.db.secret_string)["password"]

  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  deletion_protection     = true
  skip_final_snapshot     = false
  auto_minor_version_upgrade = true

  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.logs.arn

  monitoring_interval     = 60
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = local.common_tags
}

# -------------------------- ElastiCache Redis (HA replication group) --------------------------

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name_prefix}-redis-subnets"
  subnet_ids = module.vpc.intra_subnets
  description = "Redis subnets"
}

resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis-sg"
  description = "ElastiCache Redis SG"
  vpc_id      = module.vpc.vpc_id
  tags        = local.common_tags
}

resource "aws_security_group_rule" "redis_from_nodes" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  security_group_id        = aws_security_group.redis.id
  source_security_group_id = module.eks.node_security_group_id
  description              = "Redis from EKS nodes"
}

resource "aws_security_group_rule" "redis_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.redis.id
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "random_password" "redis_auth" {
  length  = 24
  special = true
}

resource "aws_secretsmanager_secret" "redis" {
  name      = "${local.name_prefix}/redis/auth"
  kms_key_id = aws_kms_key.data.id
  tags      = local.common_tags
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id     = aws_secretsmanager_secret.redis.id
  secret_string = jsonencode({ password = random_password.redis_auth.result })
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${local.name_prefix}-redis"
  description                   = "Redis for ${local.name_prefix}"
  engine                        = "redis"
  engine_version                = "7.1"
  node_type                     = var.redis_node_type
  parameter_group_name          = "default.redis7"
  port                          = 6379

  # Multi-AZ with cluster mode disabled (one primary, replicas across AZs)
  automatic_failover_enabled    = true
  multi_az_enabled              = true
  replicas_per_node_group       = 2
  num_node_groups               = 1

  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  auth_token                    = jsondecode(aws_secretsmanager_secret_version.redis.secret_string)["password"]
  kms_key_id                    = aws_kms_key.data.arn

  subnet_group_name             = aws_elasticache_subnet_group.redis.name
  security_group_ids            = [aws_security_group.redis.id]

  snapshot_retention_limit      = 7
  snapshot_window               = "01:00-02:00"

  maintenance_window            = "sun:02:00-sun:03:00"
  auto_minor_version_upgrade    = true

  tags = local.common_tags
}

# -------------------------- Bastion (SSM Session Manager) --------------------------

module "bastion" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 5.7"

  name = "${local.name_prefix}-bastion"

  ami_type       = "amazon-linux-2023"
  instance_type  = "t3.micro"
  subnet_id      = element(module.vpc.public_subnets, 0)
  vpc_security_group_ids = [module.vpc.default_security_group_id]

  associate_public_ip_address = true
  create_iam_instance_profile = true
  iam_role_policies = {
    SSMCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  user_data = <<-EOT
              #!/bin/bash
              dnf -y install postgresql15
              EOT

  monitoring             = true
  enable_volume_tags     = true
  root_block_device = [{
    volume_type = "gp3"
    volume_size = 16
    encrypted   = true
    kms_key_id  = aws_kms_key.data.arn
  }]

  tags = merge(local.common_tags, { Role = "bastion" })
}

# -------------------------- OPTIONAL: ALB SG to restrict from office/VPN --------------------------

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "ALB SG (if used by controllers)"
  vpc_id      = module.vpc.vpc_id
  tags        = local.common_tags
}

resource "aws_security_group_rule" "alb_ingress_https" {
  count                    = length(var.allowed_office_cidrs) > 0 ? 1 : 0
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  cidr_blocks              = var.allowed_office_cidrs
  description              = "Restrict ALB to office/VPN ranges"
}

resource "aws_security_group_rule" "alb_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.alb.id
  cidr_blocks       = ["0.0.0.0/0"]
}

# -------------------------- OUTPUTS --------------------------

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Private subnets"
}

output "intra_subnets" {
  value       = module.vpc.intra_subnets
  description = "Intra/DB subnets"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name"
}

output "eks_oidc_provider_arn" {
  value       = module.eks.oidc_provider_arn
  description = "EKS OIDC provider ARN (for IRSA)"
}

output "rds_endpoint" {
  value       = aws_db_instance.postgres.address
  description = "RDS endpoint"
}

output "redis_primary_endpoint" {
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  description = "Redis primary endpoint"
}

output "s3_bucket" {
  value       = module.s3.s3_bucket_id
  description = "S3 bucket name"
}

output "ecr_repository_url" {
  value       = aws_ecr_repository.core.repository_url
  description = "ECR repo URL"
}

output "bastion_instance_id" {
  value       = module.bastion.id
  description = "Bastion EC2 instance ID (connect via SSM)"
}
