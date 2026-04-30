# BlindSpot

> **For authorized security testing only.** See [DISCLAIMER.md](DISCLAIMER.md).

A lightweight, single-file Flask server for blind XSS testing. When a payload fires on a target page the server captures cookies, URI, user agent, referrer, and a full-page screenshot, and displays everything in a password-protected dashboard.

---

## Features

- Single Python file, minimal dependencies (Flask only)
- HTTPS via Let's Encrypt
- Password-protected dashboard
- Session cookie with `HttpOnly`, `Secure`, `SameSite=Strict`
- Captures: cookies · URI · user agent · referrer · DOM · iframe status · screenshot
- Dark / light theme dashboard
- Payload reference page with one-click copy

---

## Installation

```bash
git clone https://github.com/brainkok/blindspot.git /opt/blindspot
cd /opt/blindspot
sudo bash setup.sh
```

`setup.sh` handles everything: Python dependencies, Let's Encrypt certificate, service configuration, and certificate auto-renewal. See **[INSTALL.md](INSTALL.md)** for a full breakdown and manual setup instructions.

---

## Configuration

Open `collector.py` and set the two required variables at the top:

```python
# URL path to the dashboard — make this hard to guess
VIEWER_PATH = "your-hard-to-guess-path"

# Dashboard password — required, the server refuses to start without it
DASHBOARD_PASSWORD = "your-strong-password"
```

Other variables you may want to change:

| Variable | Default | Description |
|---|---|---|
| `COLLECT_URL` | `https://example.com/a` | Public URL of the collector endpoint |
| `CAPTURES_DIR` | `iuvhlijuhrthuyureh/` | Directory where captures are stored |
| `LISTEN_PORT` | `443` | Port to listen on |
| `CERT_FILE` | `/etc/letsencrypt/…/fullchain.pem` | TLS certificate |
| `KEY_FILE` | `/etc/letsencrypt/…/privkey.pem` | TLS private key |

---

## Running

**Direct:**

```bash
sudo python3 collector.py
```

**Production (recommended — gunicorn with TLS):**

```bash
sudo gunicorn -w 1 \
  --bind 0.0.0.0:443 \
  --certfile /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  --keyfile  /etc/letsencrypt/live/yourdomain.com/privkey.pem \
  collector:app
```

Run as a systemd service for automatic restart on failure or reboot.

---

## Usage

1. Navigate to `https://yourdomain.com/<VIEWER_PATH>` and log in.
2. Go to **Payloads** and copy a payload suited for the injection point.
3. Inject the payload into the target application.
4. When the payload fires, the capture appears in **Captures**.

The collector endpoint is `/a` and the payload script is served from `/b.js`.

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md). Only use this tool on systems you own or have explicit written permission to test.
