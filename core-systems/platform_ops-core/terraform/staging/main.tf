module "vpc" {
  source      = "../../modules/vpc"
  environment = "staging"
  cidr_block  = "10.10.0.0/16"
}
