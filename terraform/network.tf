# --- Networking ---
# The idea: the internet can only reach the load balancer. The web server sits
# in a PRIVATE subnet with no public IP address and no route out to the
# internet, so there is nothing on it for an attacker to connect to directly.

# I pin the two zones I want (a and b) so the layout is predictable.
data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "zone-name"
    values = ["${var.aws_region}a", "${var.aws_region}b"]
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

# The internet gateway is the "front door" of the VPC.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

# Every VPC comes with a default security group that allows lots of traffic.
# Declaring it with no rules means it blocks everything, so nothing can
# accidentally end up using it.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

# --- Public subnets (load balancer) ---
resource "aws_subnet" "public" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # The load balancer doesn't need things in here to get public IPs handed out.
  map_public_ip_on_launch = false

  tags = { Name = "${var.project_name}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- Private subnets (web server) ---
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${var.project_name}-private-${count.index}" }
}

# This route table has no route to the internet at all - only the automatic
# "local" route that lets things inside the VPC talk to each other.
# (A real app that needs updates would use a NAT gateway, but that costs
# money every hour, so I left it out of this demo.)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- VPC Flow Logs ---
# Records who talked to who on the network (not the contents). It's the kind
# of evidence I'd want if I ever had to investigate an incident.
#tfsec:ignore:aws-cloudwatch-log-group-customer-key
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  #checkov:skip=CKV_AWS_158:Uses AWS default encryption. A custom KMS key adds complexity I left out of this demo.
  name              = "/${var.project_name}/vpc-flow-logs"
  retention_in_days = 365
}

resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}
