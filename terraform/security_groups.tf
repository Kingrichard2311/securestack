# --- Security groups ---
# These are firewall rules attached to each resource. My rule of thumb: each
# layer only accepts traffic from the layer in front of it, and nothing else.
#   Internet -> load balancer (port 80) -> web server (port 8080)
# The web server has NO rule letting anything else in, and NO SSH at all.

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Load balancer: web traffic in from the internet, out to the app server only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project_name}-alb-sg" }
}

resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "App server: only accepts traffic from the load balancer"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project_name}-app-sg" }
}

# The load balancer IS meant to be public, so this is the one place where
# "open to the whole internet" is correct. The scanners flag it, so I've marked
# it as a deliberate choice with the reason next to it.
#tfsec:ignore:aws-ec2-no-public-ingress-sgr
resource "aws_security_group_rule" "alb_http_in" {
  #checkov:skip=CKV_AWS_260:A public web load balancer must accept HTTP from the internet - this is intentional.
  type              = "ingress"
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from the internet"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

# The load balancer can only send traffic on to the app server (not anywhere).
resource "aws_security_group_rule" "alb_to_app" {
  type                     = "egress"
  security_group_id        = aws_security_group.alb.id
  description              = "Forward to the app server only"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
}

# The app server only trusts the load balancer's security group - not an IP
# range - so nothing else in the network can reach it either.
resource "aws_security_group_rule" "app_from_alb" {
  type                     = "ingress"
  security_group_id        = aws_security_group.app.id
  description              = "App traffic from the load balancer only"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
}
