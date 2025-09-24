// path: aethernova-chain-core/ops/terraform/modules/networking/vpc-aws/versions.tf
// SPDX-License-Identifier: Apache-2.0
// Purpose: Pin Terraform/Core provider constraints for the vpc-aws module.
// Notes:
// - Module-level files MUST NOT configure providers (only declare constraints).
// - Aliased providers are declared so callers can pass multiple AWS configurations
//   (e.g., cross-region peering, centralized egress, shared services, etc.).

terraform {
  // Terraform Core: LTS-ish window with 1.x cap for stability
  // Tested with 1.7/1.8 lines; hard-cap <2.0 for predictable planning behavior.
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      // AWS provider 5.x includes stable VPC/IPAM/VPN features and bugfixes;
      // upper-bound <6.0.0 to avoid unreviewed breaking changes.
      version = ">= 5.50.0, < 6.0.0"

      // Declare aliases the module can accept from the root to support multi-account/region usage.
      // Example in root:
      // provider "aws" { alias = "primary"  region = "eu-central-1" }
      // provider "aws" { alias = "secondary" region = "eu-west-1"   }
      // module "vpc" {
      //   source    = "./modules/networking/vpc-aws"
      //   providers = {
      //     aws.primary   = aws.primary
      //     aws.secondary = aws.secondary
      //   }
      // }
      configuration_aliases = [
        aws.primary,
        aws.secondary
      ]
    }
  }
}
