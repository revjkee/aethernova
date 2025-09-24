terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50" # Unverified
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30" # Unverified
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13" # Unverified
    }
  }

  backend "s3" {
    bucket         = "UNVERIFIED-your-tfstate-bucket"
    key            = "neuroforge-core/staging/terraform.tfstate"
    region         = "us-east-1" # Unverified
    dynamodb_table = "UNVERIFIED-your-tf-locks"
    encrypt        = true
  }
}

# -----------------------------
# Variables (staging defaults)
# -----------------------------
variable "project" {
  description = "Project name for tagging"
  type        = string
  default     = "neuroforge-core"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "staging"
}

variable "aws_region" {
  description = "AWS region for staging"
  type        = string
  default     = "us-east-1" # Unverified
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.40.0.0/16"
}

variable "eks_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.29" # Unverified
}

variable "node_instance_types" {
  description = "Instance types for managed node group"
  type        = list(string)
  default     = ["t3.large"]
}

variable "desired_size" {
  type    = number
  default = 3
}

variable "min_size" {
  type    = number
  default = 2
}

variable "max_size" {
  type    = number
  default = 6
}

variable "github_oidc_subjects" {
  description = "Allowed sub claims for IRSA/GitHub or other OIDC subjects"
  type        = list(string)
  default     = []
}

# -----------------------------
# Providers & identity
# -----------------------------
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "platform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -----------------------------
# Locals
# -----------------------------
locals {
  name = "${var.project}-${var.environment}"

  tags = {
    Name        = local.name
    Project     = var.project
    Environment = var.environment
  }
}

# -----------------------------
# Networking: VPC
# -----------------------------
data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0" # Unverified

  name = local.name
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  private_subnets = ["10.40.1.0/24", "10.40.2.0/24"]
  public_subnets  = ["10.40.101.0/24", "10.40.102.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.tags
}

# -----------------------------
# KMS keys (EKS secrets & S3)
# -----------------------------
resource "aws_kms_key" "eks" {
  description             = "KMS key for ${local.name} EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

resource "aws_kms_key" "s3" {
  description             = "KMS key for ${local.name} S3 encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${local.name}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# -----------------------------
# ECR repository
# -----------------------------
module "ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.6" # Unverified

  repository_name               = "${local.name}"
  repository_force_delete       = false
  create_lifecycle_policy       = true
  repository_lifecycle_policy   = jsonencode({ rules = [{ rulePriority = 1, description = "keep last 30", selection = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }, action = { type = "expire" } }] })
  encryption_configuration      = { encryption_type = "KMS", kms_key = aws_kms_key.s3.arn }
  image_scanning_configuration  = { scanOnPush = true }
  tags                          = local.tags
}

# -----------------------------
# S3 bucket (app data)
# -----------------------------
module "s3_app" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.1" # Unverified

  bucket = "${local.name}-app"
  acl    = "private"

  force_destroy       = false
  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = aws_kms_key.s3.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  versioning = {
    enabled = true
  }

  lifecycle_rule = [
    {
      id      = "retention-logs"
      enabled = true
      filter  = { prefix = "logs/" }
      noncurrent_version_expiration = { days = 30 }
      transition = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 90, storage_class = "GLACIER" }
      ]
    }
  ]

  tags = local.tags
}

# -----------------------------
# CloudWatch log group (app)
# -----------------------------
resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/eks/${local.name}/application"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.s3.arn
  tags              = local.tags
}

# -----------------------------
# EKS cluster
# -----------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8" # Unverified

  cluster_name                   = local.name
  cluster_version                = var.eks_version
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = false

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_encryption_config = [{
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.eks.arn
  }]

  cluster_addons = {
    coredns = {
      preserve    = true
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        enableNetworkPolicy = "true"
      })
    }
  }

  eks_managed_node_groups = {
    default = {
      instance_types = var.node_instance_types
      desired_size   = var.desired_size
      min_size       = var.min_size
      max_size       = var.max_size

      ami_type = "AL2_x86_64" # Unverified
      capacity_type = "ON_DEMAND"

      labels = {
        role = "general"
      }

      taints = []
    }
  }

  tags = local.tags
}

# -----------------------------
# IRSA example: Otel Collector
# -----------------------------
data "aws_iam_policy_document" "otel_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = concat(
        ["system:serviceaccount:observability:otel-collector"],
        var.github_oidc_subjects
      )
    }
  }
}

resource "aws_iam_role" "otel" {
  name               = "${local.name}-otel-collector"
  assume_role_policy = data.aws_iam_policy_document.otel_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "otel_policy" {
  statement {
    sid       = "WriteToCloudWatch"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "otel" {
  name   = "${local.name}-otel-policy"
  policy = data.aws_iam_policy_document.otel_policy.json
}

resource "aws_iam_role_policy_attachment" "otel_attach" {
  role       = aws_iam_role.otel.name
  policy_arn = aws_iam_policy.otel.arn
}

# -----------------------------
# Kubernetes/Helm providers (optional wiring)
# -----------------------------
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

# Example (commented): install aws-load-balancer-controller with IRSA via Helm
# module "alb_controller" {
#   source  = "terraform-aws-modules/helm/aws"
#   version = "~> 2.11" # Unverified
#   name    = "aws-load-balancer-controller"
#   chart   = "aws-load-balancer-controller"
#   repository = "https://aws.github.io/eks-charts"
#   namespace  = "kube-system"
#   create_namespace = false
#   values = [
#     yamlencode({
#       clusterName = module.eks.cluster_name
#       serviceAccount = {
#         name = "aws-load-balancer-controller"
#         annotations = {
#           "eks.amazonaws.com/role-arn" = aws_iam_role.alb.arn
#         }
#       }
#     })
#   ]
#   depends_on = [module.eks]
# }

# -----------------------------
# Outputs
# -----------------------------
output "region" {
  value       = var.aws_region
  description = "AWS region in use"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Private subnets for workloads"
}

output "public_subnets" {
  value       = module.vpc.public_subnets
  description = "Public subnets for load balancers"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name"
}

output "eks_cluster_endpoint" {
  value       = module.eks.cluster_endpoint
  description = "EKS cluster API endpoint"
}

output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "ECR repository URL"
}

output "s3_app_bucket" {
  value       = module.s3_app.s3_bucket_id
  description = "Application S3 bucket name"
}

output "otel_role_arn" {
  value       = aws_iam_role.otel.arn
  description = "IRSA role ARN for otel-collector"
}
