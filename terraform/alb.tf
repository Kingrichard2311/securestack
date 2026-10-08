# --- Load balancer ---
# The load balancer is the public face of the project. Visitors talk to it,
# and it passes their requests on to the web server in the private subnet.

#tfsec:ignore:aws-elb-alb-not-public
resource "aws_lb" "main" {
  #checkov:skip=CKV_AWS_91:Access logs need another S3 bucket - skipped to keep the demo simple.
  #checkov:skip=CKV_AWS_150:Deletion protection is off so I can run terraform destroy and clean up after a demo.
  #checkov:skip=CKV2_AWS_28:A web application firewall (WAF) costs extra - skipped for the demo.
  #checkov:skip=CKV2_AWS_20:Redirecting HTTP to HTTPS needs an HTTPS listener, which needs a domain and certificate (see the listener below).
  name               = "${var.project_name}-alb"
  internal           = false # public on purpose - it's the website's front door
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  # Throws away badly-formed HTTP headers instead of passing them on.
  drop_invalid_header_fields = true

  tags = { Name = "${var.project_name}-alb" }
}

resource "aws_lb_target_group" "app" {
  #checkov:skip=CKV_AWS_378:This is only the private hop from the load balancer to the server, inside the VPC. HTTPS here would need certificates on the server.
  name     = "${var.project_name}-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  # The load balancer calls /health every 30 seconds to check the server is OK.
  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

#tfsec:ignore:aws-elb-http-not-used
resource "aws_lb_listener" "http" {
  #checkov:skip=CKV_AWS_2:HTTPS needs a domain name and certificate. I didn't buy a domain for a demo - known limitation.
  #checkov:skip=CKV_AWS_103:This is about the TLS version on HTTPS listeners. Mine is plain HTTP for now (see above).
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  # NOTE: In a real project this would be HTTPS (port 443) with a certificate
  # from AWS Certificate Manager. That needs a domain name, so for this demo
  # I'm being upfront that it's plain HTTP.
}
