# veilmind-core/ops/terraform/envs/staging/main.tf
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws        = { source = "hashicorp/aws",        version = "~> 5.50" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.31" }
    helm       = { source = "hashicorp/helm",       version = "~> 2.12" }
    random     = { source = "hashicorp/random",     version = "~> 3.6" }
    tls        = { source = "hashicorp/tls",        version = "~> 4.0" }
  }

  backend "s3" {
    bucket         = "CHANGE_ME-tfstate"
    key            = "veilmind-core/staging/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "CHANGE_ME-tf-locks"
    encrypt        = true
  }
}

# ---------------------------
# Provider & globals
# ---------------------------
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  project     = "veilmind-core"
  environment = "staging"
  name_prefix = "${local.project}-${local.environment}"

  vpc_cidr = "10.60.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 2)

  tags = {
    Project      = local.project
    Environment  = local.environment
    Owner        = "platform@veilmind.example"
    Terraform    = "true"
    ZeroTrust    = "true"
  }
}

# ---------------------------
# VPC (2 AZ, NAT, Flow Logs)
# ---------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.name_prefix}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [cidrsubnet(local.vpc_cidr, 4, 0), cidrsubnet(local.vpc_cidr, 4, 1)]
  public_subnets  = [cidrsubnet(local.vpc_cidr, 4, 8), cidrsubnet(local.vpc_cidr, 4, 9)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_flow_log                         = true
  flow_log_destination_type               = "cloud-watch-logs"
  flow_log_cloudwatch_log_group_name      = "/aws/vpc/${local.name_prefix}"
  flow_log_cloudwatch_log_group_retention = 14

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/cluster/${local.name_prefix}-eks" = "shared"
  }
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
    "kubernetes.io/cluster/${local.name_prefix}-eks" = "shared"
  }
}

# ---------------------------
# EKS (IRSA, addons, MNG)
# ---------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.13"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = var.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs

  enable_irsa = true

  cluster_addons = {
    coredns                 = { most_recent = true }
    kube-proxy              = { most_recent = true }
    vpc-cni                 = { most_recent = true }
    eks-pod-identity-agent  = { most_recent = true }
    aws-ebs-csi-driver      = { most_recent = true }
    metrics-server          = { most_recent = true }
  }

  eks_managed_node_groups = {
    default = {
      instance_types = var.node_instance_types
      capacity_type  = "ON_DEMAND"
      min_size       = 2
      max_size       = 5
      desired_size   = 2
      subnets        = module.vpc.private_subnets
      disk_size      = 50
      labels = {
        "workload" = "general"
      }
      tags = {
        "eks:nodegroup-name" = "${local.name_prefix}-mng-default"
      }
    }
  }

  enable_cluster_creator_admin_permissions = true
}

# ---------------------------
# SG for DB/Redis - only from EKS nodes
# ---------------------------
resource "aws_security_group" "db" {
  name        = "${local.name_prefix}-db-sg"
  description = "Allow PostgreSQL from EKS worker nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "PostgreSQL from EKS nodes"
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

  tags = local.tags
}

resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis-sg"
  description = "Allow Redis TLS from EKS worker nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Redis (TLS) from EKS nodes"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# ---------------------------
# RDS PostgreSQL (TLS/at-rest, Secrets Manager)
# ---------------------------
module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.4"

  identifier = "${local.name_prefix}-pg"

  engine               = "postgres"
  engine_version       = "15"
  instance_class       = var.db_instance_class
  allocated_storage    = 50
  max_allocated_storage = 200

  family                         = "postgres15"
  create_db_parameter_group      = true
  create_db_option_group         = false
  deletion_protection            = false
  skip_final_snapshot            = true
  backup_retention_period        = 7
  copy_tags_to_snapshot          = true
  performance_insights_enabled   = true
  monitoring_interval            = 60

  subnet_ids               = module.vpc.private_subnets
  create_db_subnet_group   = true
  multi_az                 = false
  publicly_accessible      = false
  iam_database_authentication_enabled = false

  storage_encrypted = true
  kms_key_id        = null

  manage_master_user_password = true # хранит пароль в AWS Secrets Manager

  vpc_security_group_ids = [aws_security_group.db.id]
}

# ---------------------------
# ElastiCache Redis (TLS, AUTH)
# ---------------------------
resource "random_password" "redis_auth" {
  length  = 32
  special = false
}

module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 5.7"

  # Replication group (single primary for staging)
  replication_group_id          = "${local.name_prefix}-redis"
  engine                        = "redis"
  engine_version                = "7.1"
  node_type                     = var.redis_node_type
  number_cache_clusters         = 1
  automatic_failover_enabled    = false
  multi_az_enabled              = false

  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  auth_token                    = random_password.redis_auth.result

  create_subnet_group           = true
  subnet_ids                    = module.vpc.private_subnets
  security_group_ids            = [aws_security_group.redis.id]

  parameter_group_name          = null
}

# ---------------------------
# S3 bucket (app data, blocked public access)
# ---------------------------
module "s3_appdata" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.1"

  bucket = lower(replace("${local.name_prefix}-appdata-${data.aws_caller_identity.current.account_id}", "_", "-"))

  acl                      = "private"
  force_destroy            = false
  attach_deny_insecure_transport_policy = true

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = { sse_algorithm = "AES256" }
    }
  }

  lifecycle_rule = [
    {
      id      = "multipart-abort"
      enabled = true
      abort_incomplete_multipart_upload = { days_after_initiation = 7 }
    }
  ]
}

# ---------------------------
# OIDC for GitHub Actions (keyless)
# ---------------------------
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    data.tls_certificate.github.certificates[0].sha1_fingerprint
  ]
}

data "aws_iam_policy_document" "gha_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/*", "repo:${var.github_repo}:ref:refs/tags/*"]
    }
  }
}

resource "aws_iam_role" "gha_deploy" {
  name               = "${local.name_prefix}-gha-deploy"
  assume_role_policy = data.aws_iam_policy_document.gha_assume.json
  description        = "GitHub Actions deploy role for ${local.name_prefix}"
  tags               = local.tags
}

# Минимально необходимые права для деплоя в EKS (kubectl через update-kubeconfig) и чтения метаданных
data "aws_iam_policy_document" "gha_deploy" {
  statement {
    sid     = "EKSDescribe"
    actions = ["eks:DescribeCluster"]
    resources = [module.eks.cluster_arn]
  }
  statement {
    sid       = "ListGetBasic"
    actions   = ["ec2:DescribeSubnets", "ec2:DescribeVpcs", "ec2:DescribeSecurityGroups", "iam:GetRole", "iam:ListAttachedRolePolicies"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "gha_deploy" {
  name        = "${local.name_prefix}-gha-deploy"
  description = "Minimal permissions for GitHub Actions to interact with EKS metadata"
  policy      = data.aws_iam_policy_document.gha_deploy.json
}

resource "aws_iam_role_policy_attachment" "gha_deploy_attach" {
  role       = aws_iam_role.gha_deploy.name
  policy_arn = aws_iam_policy.gha_deploy.arn
}

# ---------------------------
# (Optional) Kubeconfig providers (for post-provision Helm/bootstrap)
# ---------------------------
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

# ---------------------------
# Outputs
# ---------------------------
output "region" {
  value = data.aws_region.current.name
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_oidc_provider_arn" {
  value = module.eks.oidc_provider_arn
}

output "deploy_role_arn" {
  value = aws_iam_role.gha_deploy.arn
}

output "db_endpoint" {
  value = module.db.db_instance_endpoint
}

output "db_secret_arn" {
  value = module.db.master_user_secret_arn
}

output "redis_primary_endpoint" {
  value = module.redis.primary_endpoint_address
}

output "s3_appdata_bucket" {
  value = module.s3_appdata.s3_bucket_id
}

# ---------------------------
# Variables
# ---------------------------
variable "aws_region" {
  type        = string
  description = "AWS region for staging"
  default     = "eu-north-1"
}

variable "cluster_version" {
  type        = string
  description = "EKS version"
  default     = "1.29"
}

variable "cluster_endpoint_public_access_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to access EKS control plane endpoint"
  default     = ["0.0.0.0/0"]
}

variable "node_instance_types" {
  type        = list(string)
  description = "Instance types for EKS managed node group"
  default     = ["t3.large"]
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class"
  default     = "db.t4g.medium"
}

variable "redis_node_type" {
  type        = string
  description = "ElastiCache node type"
  default     = "cache.t4g.small"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository in format org/repo for OIDC trust"
  default     = "your-org/veilmind-core"
}
