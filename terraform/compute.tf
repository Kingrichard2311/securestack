# --- Web server ---
# One small EC2 server in a private subnet. It runs a tiny web page (see
# app/user_data.sh) so the load balancer has something real to show.

# Finds the newest standard Amazon Linux 2023 image, so I don't have to
# hard-code an image ID that changes per region.
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "app" {
  #checkov:skip=CKV2_AWS_41:This server needs no AWS permissions, so it has no IAM role at all. Least privilege taken to the limit.
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[0].id
  vpc_security_group_ids      = [aws_security_group.app.id]
  associate_public_ip_address = false # no public IP - can't be reached from the internet directly
  ebs_optimized               = true
  monitoring                  = true

  # Forces the newer, safer version of the EC2 metadata service (IMDSv2).
  # Without it, an attacker who could trick the server into making a request
  # for them (an "SSRF" attack) might steal its AWS credentials. It is one of
  # the most commonly flagged AWS misconfigurations.
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  # Encrypts the server's disk.
  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  # This script runs once when the server first boots and starts the web page.
  user_data                   = file("${path.module}/app/user_data.sh")
  user_data_replace_on_change = true

  tags = { Name = "${var.project_name}-app" }
}

# Tells the load balancer to send traffic to this server.
resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app.id
  port             = 8080
}
