terraform {
  # Terraform 1.x: фиксируем нижнюю границу и отсечение будущего 2.x
  # Docs (version constraints): https://developer.hashicorp.com/terraform/language/expressions/version-constraints
  # Docs (terraform block):     https://developer.hashicorp.com/terraform/language/terraform
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # Kubernetes provider — подтвержденная мажорная линия 2.x (напр., v2.38.0 в Jul 2025)
    # Registry docs: https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs
    # GitHub releases: https://github.com/hashicorp/terraform-provider-kubernetes
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.30.0, < 3.0.0"
    }

    # Helm provider — подтвержденная мажорная линия 3.x (напр., v3.0.2 в Jun 2025)
    # Registry docs: https://registry.terraform.io/providers/hashicorp/helm/latest/docs
    # GitHub releases: https://github.com/hashicorp/terraform-provider-helm
    helm = {
      source  = "hashicorp/helm"
      version = ">= 3.0.0, < 4.0.0"
    }
  }
}
