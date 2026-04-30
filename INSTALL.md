# Installation Guide

## Prerequisites

- A Linux VPS (Ubuntu / Debian) with a public IP
- A domain name with an A-record pointing to that IP
- Root or sudo access
- Ports **80** and **443** open in your firewall

---

## Automated setup (recommended)

`setup.sh` installs all dependencies, obtains a Let's Encrypt certificate, patches `collector.py`, creates a systemd service that auto-restarts, and configures certificate auto-renewal — all in one step.

```bash
git clone https://github.com/brainkok/blindspot.git /opt/blindspot
cd /opt/blindspot
sudo bash setup.sh
```

The script will ask for:

| Prompt | Example |
|---|---|
| Domain name | `example.com` |
| Dashboard path | `my-secret-path` |
| Dashboard password | *(hidden input)* |
| Let's Encrypt e-mail | `you@example.com` *(optional)* |

When finished it prints the dashboard URL and a log command. Done.

---

## Manual setup

Follow these steps if you prefer to configure everything yourself.

### 1. Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip certbot
pip3 install flask gunicorn
```

### 2. Clone the repo

```bash
git clone https://github.com/brainkok/blindspot.git /opt/blindspot
cd /opt/blindspot
```

### 3. Issue a TLS certificate

Make sure port 80 is free, then run:

```bash
sudo certbot certonly --standalone -d yourdomain.com
```

Certbot places the files at:

```
/etc/letsencrypt/live/yourdomain.com/fullchain.pem
/etc/letsencrypt/live/yourdomain.com/privkey.pem
```

### 4. Configure collector.py

Open `collector.py` and set these variables at the top:

```python
COLLECT_URL  = "https://yourdomain.com/a"
CERT_FILE    = "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
KEY_FILE     = "/etc/letsencrypt/live/yourdomain.com/privkey.pem"

VIEWER_PATH        = "your-hard-to-guess-path"
DASHBOARD_PASSWORD = "your-strong-password"
```

The server refuses to start if `DASHBOARD_PASSWORD` is empty.

### 5. Create a systemd service

```bash
sudo nano /etc/systemd/system/blindspot.service
```

```ini
[Unit]
Description=BlindSpot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/blindspot
ExecStart=/usr/local/bin/gunicorn -w 1 \
  --bind 0.0.0.0:443 \
  --certfile /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  --keyfile  /etc/letsencrypt/live/yourdomain.com/privkey.pem \
  collector:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable blindspot
sudo systemctl start blindspot
```

View logs:

```bash
sudo journalctl -u blindspot -f
```

### 6. Certificate auto-renewal

Let's Encrypt certificates expire after 90 days. The service must be stopped during renewal so Certbot can use port 80. Add hooks:

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/pre
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post

echo '#!/bin/sh
systemctl stop blindspot' \
  | sudo tee /etc/letsencrypt/renewal-hooks/pre/stop-blindspot.sh

echo '#!/bin/sh
systemctl start blindspot' \
  | sudo tee /etc/letsencrypt/renewal-hooks/post/start-blindspot.sh

sudo chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-blindspot.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/start-blindspot.sh
```

Test the renewal (dry run):

```bash
sudo certbot renew --dry-run
```

### 7. Verify

```bash
curl -sk -X POST https://yourdomain.com/a \
  -H 'Content-Type: application/json' \
  -d '{"uri":"test","cookies":"c=1"}'
# Expected: {"status":"ok"}
```

Then open `https://yourdomain.com/<VIEWER_PATH>` in a browser and log in.
