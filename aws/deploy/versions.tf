terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = "soc-copilot" # dedicated deployer identity — never the default profile
  default_tags {
    tags = {
      project   = "soc-copilot"
      managedby = "terraform"
    }
  }
}
