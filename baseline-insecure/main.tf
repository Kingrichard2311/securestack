# ============================================================================
#  DO NOT DEPLOY THIS. IT IS DELIBERATELY INSECURE.
#
#  This is the "before" picture for my project evaluation. It builds roughly
#  the same things as ../terraform, but with common cloud misconfigurations.
#  I only ever SCAN it (see tests/compare_scans.py) to measure how many
#  problems the hardened version fixes. It is never applied to AWS.
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}

# --- Network: everything is public ---
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # mistake: hands out public IPs to everything
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- Firewall: wide open ---
resource "aws_security_group" "web" {
  name        = "insecure-web-sg"
  description = "Open to everything"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Every port from anywhere"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Anything out"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Permissions: an admin role "to make it work" ---
resource "aws_iam_role" "web" {
  name = "insecure-web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "admin" {
  name = "admin-everything"
  role = aws_iam_role.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "web" {
  name = "insecure-web-profile"
  role = aws_iam_role.web.name
}

# --- Server: public, unencrypted, old metadata service, secret in the script ---
resource "aws_instance" "web" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true # mistake: directly reachable from the internet
  iam_instance_profile        = aws_iam_instance_profile.web.name

  # mistake: no metadata_options block, so the old IMDSv1 is allowed

  root_block_device {
    encrypted = false # mistake: disk not encrypted
  }

  # mistake: a password hard-coded in the startup script
  user_data = <<-EOT
    #!/bin/bash
    export DB_PASSWORD="Password123!"
  EOT
}

# --- Logging: bucket and trail with weak settings ---
resource "aws_s3_bucket" "logs" {
  bucket = "insecure-demo-logs-bucket"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = false # mistake: bucket could be made public
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_cloudtrail" "main" {
  name                       = "insecure-trail"
  s3_bucket_name             = aws_s3_bucket.logs.id
  enable_log_file_validation = false # mistake: logs could be tampered with unnoticed
  is_multi_region_trail      = false # mistake: other regions not recorded
}

# There is deliberately no GuardDuty, no alarm and no flow logs here.
