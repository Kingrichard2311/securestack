# Settings I can change without editing the main code.

variable "aws_region" {
  description = "Which AWS region to build in"
  type        = string
  default     = "eu-west-2" # London
}

variable "project_name" {
  description = "Prefix used in the names of everything I create"
  type        = string
  default     = "securestack"
}

variable "vpc_cidr" {
  description = "IP range for my private network (the VPC)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "IP ranges for the two public subnets (the load balancer lives here)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "IP ranges for the two private subnets (the web server lives here)"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "instance_type" {
  description = "Size of the web server (small = cheap)"
  type        = string
  default     = "t3.micro"
}

# No default on purpose: I have to give a real email, otherwise the security
# alerts would go nowhere. See example.tfvars.
variable "alert_email" {
  description = "Email address that receives the security alarm"
  type        = string

  validation {
    condition     = can(regex("@", var.alert_email))
    error_message = "alert_email must be a real email address."
  }
}
