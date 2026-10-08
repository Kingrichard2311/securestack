#!/bin/bash
# Runs once when the server first boots. It creates a small web page and
# starts a basic Python web server on port 8080 to serve it.
# (Python is already installed on Amazon Linux, so this needs no internet.)

mkdir -p /opt/securestack

# The page visitors see
cat > /opt/securestack/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecureStack</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0;
           display: flex; justify-content: center; padding: 3rem 1rem; }
    .card { max-width: 560px; background: #1e293b; padding: 2rem; border-radius: 12px; }
    h1 { margin-top: 0; color: #38bdf8; }
    li { margin: 0.4rem 0; }
    small { color: #94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>SecureStack is running</h1>
    <p>This page is served from a private server, behind a load balancer,
       all built with Terraform.</p>
    <ul>
      <li>Server has no public IP and no SSH</li>
      <li>Only the load balancer is reachable from the internet</li>
      <li>Every code change is security-scanned before it is accepted</li>
      <li>GuardDuty and CloudTrail are watching the account</li>
    </ul>
    <small>Built by Richard Lamy - cloud security learning project</small>
  </div>
</body>
</html>
HTML

# The load balancer checks this file to see if the server is healthy
echo "ok" > /opt/securestack/health

# Run the web server as a service so it starts on boot and restarts if it crashes
cat > /etc/systemd/system/securestack.service <<'UNIT'
[Unit]
Description=SecureStack demo web page
After=network.target

[Service]
WorkingDirectory=/opt/securestack
ExecStart=/usr/bin/python3 -m http.server 8080
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now securestack
