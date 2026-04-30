#!/usr/bin/env bash
# BlindSpot — automated setup
# Run as root on Ubuntu / Debian:  sudo bash setup.sh
set -euo pipefail

# ── Root check ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root — sudo bash setup.sh"
    exit 1
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Gather config ─────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════"
echo "  BlindSpot — Setup"
echo "═══════════════════════════════════════════"
echo ""

read -rp  "Domain name          (e.g. example.com):         " DOMAIN
read -rp  "Dashboard path       (e.g. my-secret-path):      " VIEWER_PATH
read -rsp "Dashboard password   (input hidden):              " DASHBOARD_PASSWORD
echo ""
read -rp  "E-mail for Let's Encrypt (leave blank to skip):  " LE_EMAIL
echo ""

if [[ -z "$DOMAIN" || -z "$VIEWER_PATH" || -z "$DASHBOARD_PASSWORD" ]]; then
    echo "ERROR: domain, path, and password are all required."
    exit 1
fi

# ── Install system dependencies ───────────────────────────────────────────────

echo "[1/6] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip certbot

pip3 install -q --break-system-packages flask gunicorn

# ── Let's Encrypt certificate ─────────────────────────────────────────────────

echo "[2/6] Requesting TLS certificate for $DOMAIN..."

if [[ -n "$LE_EMAIL" ]]; then
    certbot certonly --standalone -d "$DOMAIN" \
        --non-interactive --agree-tos \
        --email "$LE_EMAIL"
else
    certbot certonly --standalone -d "$DOMAIN" \
        --non-interactive --agree-tos \
        --register-unsafely-without-email
fi

CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

# ── Patch collector.py ────────────────────────────────────────────────────────

echo "[3/6] Writing configuration into collector.py..."

# Use Python for the replacement so special characters in the password
# are handled safely without breaking sed patterns.
export _DOMAIN="$DOMAIN"
export _VIEWER="$VIEWER_PATH"
export _PASS="$DASHBOARD_PASSWORD"
export _CERT="$CERT_FILE"
export _KEY="$KEY_FILE"

python3 << 'PYEOF'
import re, os, json

domain   = os.environ["_DOMAIN"]
viewer   = os.environ["_VIEWER"]
password = os.environ["_PASS"]
cert     = os.environ["_CERT"]
key      = os.environ["_KEY"]

with open("collector.py") as f:
    src = f.read()

# json.dumps produces a correctly escaped Python string literal for any input
src = re.sub(r'COLLECT_URL\s*=\s*"[^"]*"',
             f'COLLECT_URL  = "https://{domain}/a"', src)
src = re.sub(r'CERT_FILE\s*=\s*"[^"]*"',
             f'CERT_FILE    = {json.dumps(cert)}', src)
src = re.sub(r'KEY_FILE\s*=\s*"[^"]*"',
             f'KEY_FILE     = {json.dumps(key)}', src)
src = re.sub(r'VIEWER_PATH\s*=\s*"[^"]*"',
             f'VIEWER_PATH = {json.dumps(viewer)}', src)
src = re.sub(r'DASHBOARD_PASSWORD\s*=\s*"[^"]*"',
             f'DASHBOARD_PASSWORD = {json.dumps(password)}', src)

with open("collector.py", "w") as f:
    f.write(src)

print("  collector.py updated.")
PYEOF

unset _DOMAIN _VIEWER _PASS _CERT _KEY

# ── systemd service ───────────────────────────────────────────────────────────

echo "[4/6] Creating systemd service..."

GUNICORN_BIN="$(which gunicorn)"
SERVICE_FILE="/etc/systemd/system/blindspot.service"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=BlindSpot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$GUNICORN_BIN -w 1 \\
  --bind 0.0.0.0:443 \\
  --certfile $CERT_FILE \\
  --keyfile  $KEY_FILE \\
  collector:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable blindspot
systemctl start blindspot

echo "  Service started."

# ── Let's Encrypt renewal hooks ───────────────────────────────────────────────

echo "[5/6] Configuring certificate auto-renewal hooks..."

mkdir -p /etc/letsencrypt/renewal-hooks/pre
mkdir -p /etc/letsencrypt/renewal-hooks/post

cat > /etc/letsencrypt/renewal-hooks/pre/stop-blindspot.sh << 'EOF'
#!/bin/sh
systemctl stop blindspot
EOF

cat > /etc/letsencrypt/renewal-hooks/post/start-blindspot.sh << 'EOF'
#!/bin/sh
systemctl start blindspot
EOF

chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-blindspot.sh
chmod +x /etc/letsencrypt/renewal-hooks/post/start-blindspot.sh

# Verify renewal works
certbot renew --dry-run --quiet

echo "  Renewal hooks installed and tested."

# ── Verify the collector is responding ───────────────────────────────────────

echo "[6/6] Verifying collector endpoint..."
sleep 2

if curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "https://$DOMAIN/a" \
    -H "Content-Type: application/json" \
    -d '{"uri":"setup-test"}' | grep -q "200"; then
    echo "  Collector endpoint OK."
else
    echo "  WARNING: collector did not respond with 200."
    echo "  Check logs: journalctl -u blindspot -f"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════"
echo "  Setup complete!"
echo "═══════════════════════════════════════════"
echo ""
echo "  Dashboard : https://$DOMAIN/$VIEWER_PATH"
echo "  Collector : https://$DOMAIN/a"
echo "  Logs      : journalctl -u blindspot -f"
echo ""
