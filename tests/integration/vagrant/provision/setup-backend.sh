#!/usr/bin/env bash
# setup-backend.sh — Provisioner for the backend VM (192.168.57.30)
#
# In 3-VM transit mode the backend hosts the real services that traffic
# from the client traverses through the agent to reach. We install:
#   - iperf3 server (port 5201)
#   - nginx HTTP server (ports 80, 443) — used for L4 LB / L7 inspection
#   - sshd (port 22)                   — used for SSH brute-force tests
#   - openssl s_server (port 8443)     — minimal TLS endpoint
#
# Plus a small helper script that dumps the backend's MAC + ARP table so
# the agent (and tests) can populate L2-DSR maps without guessing.
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive

AGENT_IP="${AGENT_IP:-192.168.57.10}"
HTTP_PORT="${BACKEND_HTTP_PORT:-80}"
HTTPS_PORT="${BACKEND_HTTPS_PORT:-443}"
S_SERVER_PORT="${BACKEND_S_SERVER_PORT:-8443}"
IPERF_PORT="${BACKEND_IPERF_PORT:-5201}"

# ── [1/5] Base packages ──────────────────────────────────────────────
echo "=== [1/5] Installing base packages ==="
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    ca-certificates curl jq openssl \
    iperf3 nginx openssh-server \
    iproute2 tcpdump net-tools \
    netcat-openbsd

# ── [2/5] iperf3 systemd service ─────────────────────────────────────
echo "=== [2/5] Configuring iperf3 server on :${IPERF_PORT} ==="
sudo tee /etc/systemd/system/iperf3-backend.service >/dev/null <<UNIT
[Unit]
Description=iperf3 server (eBPFsentinel backend)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/iperf3 -s -p ${IPERF_PORT}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now iperf3-backend.service

# ── [3/5] nginx (HTTP + HTTPS w/ self-signed cert) ───────────────────
echo "=== [3/5] Configuring nginx on :${HTTP_PORT} / :${HTTPS_PORT} ==="
sudo mkdir -p /etc/nginx/tls /var/www/backend
echo "backend-ok" | sudo tee /var/www/backend/index.html >/dev/null

if [ ! -f /etc/nginx/tls/server.key ]; then
    sudo openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/nginx/tls/server.key \
        -out    /etc/nginx/tls/server.crt \
        -days 365 -subj "/CN=ebpf-backend"
    sudo chmod 600 /etc/nginx/tls/server.key
fi

sudo tee /etc/nginx/sites-available/backend.conf >/dev/null <<CONF
server {
    listen ${HTTP_PORT} default_server;
    listen [::]:${HTTP_PORT} default_server;
    server_name _;
    root /var/www/backend;
    location / { try_files \$uri \$uri/ =404; }
    location /healthz { return 200 "ok\n"; add_header Content-Type text/plain; }
}

server {
    listen ${HTTPS_PORT} ssl default_server;
    listen [::]:${HTTPS_PORT} ssl default_server;
    server_name _;
    ssl_certificate /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;
    root /var/www/backend;
    location / { try_files \$uri \$uri/ =404; }
    location /healthz { return 200 "ok\n"; add_header Content-Type text/plain; }
}
CONF
sudo ln -sf /etc/nginx/sites-available/backend.conf /etc/nginx/sites-enabled/backend.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx

# ── [4/5] sshd (already installed) + dedicated test user ─────────────
echo "=== [4/5] Provisioning sshd test user ==="
if ! id -u testuser >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash testuser
    echo "testuser:testpass" | sudo chpasswd
fi
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl reload ssh || sudo systemctl reload sshd

# ── [4b/5] openssl s_server systemd unit ─────────────────────────────
echo "=== [4b/5] Configuring openssl s_server on :${S_SERVER_PORT} ==="
sudo tee /etc/systemd/system/s-server-backend.service >/dev/null <<UNIT
[Unit]
Description=openssl s_server (eBPFsentinel backend TLS endpoint)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/openssl s_server -accept ${S_SERVER_PORT} \
    -cert /etc/nginx/tls/server.crt -key /etc/nginx/tls/server.key \
    -www -quiet
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now s-server-backend.service

# ── [4c/5] openssl s_server systemd unit on :853 (DoT endpoint) ──────
# Minimal TLS listener used by the DoH/DoT detection suite. The cert
# is the same self-signed one nginx ships with; the listener does not
# implement DNS-over-TLS — the agent only inspects the ClientHello.
echo "=== [4c/5] Configuring DoT-style listener on :853 ==="
sudo tee /etc/systemd/system/dot-backend.service >/dev/null <<'UNIT'
[Unit]
Description=openssl s_server on :853 (eBPFsentinel DoT-style endpoint)
After=network-online.target nginx.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/openssl s_server -accept 853 \
    -cert /etc/nginx/tls/server.crt -key /etc/nginx/tls/server.key \
    -quiet
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now dot-backend.service || true

# ── [5/5] ARP / MAC capture helper (used by tests + agent) ───────────
echo "=== [5/5] Installing ARP capture helper /usr/local/bin/backend-arp ==="
sudo tee /usr/local/bin/backend-arp >/dev/null <<'EOS'
#!/usr/bin/env bash
# Prints "<ip> <mac>" for the backend's primary inter-VM NIC.
# Used by the agent to populate the BACKEND_MAC eBPF map for L2 DSR.
set -euo pipefail
IFACE="${1:-eth1}"
mac="$(cat "/sys/class/net/${IFACE}/address")"
ip="$(ip -4 -o addr show "${IFACE}" | awk '{print $4}' | cut -d/ -f1 | head -1)"
echo "${ip} ${mac}"
EOS
sudo chmod +x /usr/local/bin/backend-arp

echo ""
echo "=== Backend VM provisioning complete ==="
echo "  iperf3       on :${IPERF_PORT}"
echo "  nginx HTTP   on :${HTTP_PORT}"
echo "  nginx HTTPS  on :${HTTPS_PORT}"
echo "  s_server     on :${S_SERVER_PORT}"
echo "  sshd         on :22 (testuser/testpass)"
echo "  arp helper   /usr/local/bin/backend-arp"
