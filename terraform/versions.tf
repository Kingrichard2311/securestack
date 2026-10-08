# SecureStack
# Author: Richard Lamy
#
# A learning project: I built it to practise Terraform and AWS security
# alongside my cybersecurity studies. The comments explain WHY I did each
# thing (not just what), so I can walk someone through it.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Terraform keeps a "state" file that remembers what it has built. Mine just
  # lives on my laptop, which is fine for a solo demo. On a real team you'd
  # store it in S3 with locking so two people can't change things at once.
}

provider "aws" {
  region = var.aws_region

  # Every resource gets these labels automatically - handy for finding
  # (and cleaning up) everything this project created.
  default_tags {
    tags = {
      Project   = "SecureStack"
      Owner     = "Richard Lamy"
      ManagedBy = "Terraform"
    }
  }
}
