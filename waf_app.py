from flask import Flask, request, render_template_string, redirect, url_for, session
import re, datetime, time, hashlib
 
app = Flask(__name__)
app.secret_key = 'shieldwaf-demo-secret'
 
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  WAF RULE ENGINE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 
RULES = {
    # â”€â”€ Original 5 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "XSS":               re.compile(r"<script.*?>.*?</script>|<.*?on\w+=.*?>|javascript:", re.IGNORECASE | re.DOTALL),
    "SQL_INJECTION":     re.compile(r"('|\")\s*(OR|AND)\s*\d+=\d+|--|\bUNION\b|\bSELECT\b|\bDROP\b", re.IGNORECASE),
    "PATH_TRAVERSAL":    re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    "COMMAND_INJECTION": re.compile(r";\s*(ls|cat|rm|pwd|whoami|wget|curl|bash|sh|python)\b", re.IGNORECASE),
    "SENSITIVE_FILE":    re.compile(r"/etc/(passwd|shadow|hosts)|/proc/|\.env|/root/", re.IGNORECASE),
    # â”€â”€ New 5 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "HEADER_INJECTION":  re.compile(r"[\r\n]+(Set-Cookie|Location|Content-Type|X-|HTTP/)[\s:]", re.IGNORECASE),
    "SSRF":              re.compile(r"(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|file://|gopher://)", re.IGNORECASE),
    "OPEN_REDIRECT":     re.compile(r"(//[^/]|https?://(?!localhost)[a-z0-9.\-]+\.[a-z]{2,})", re.IGNORECASE),
    "CSRF":              None,   # handled via token validation in route
    "BRUTE_FORCE":       None,   # handled via rate-limiting in route
}
 
SEVERITY = {
    "XSS":              ("CRITICAL", "red"),
    "SQL_INJECTION":    ("CRITICAL", "red"),
    "BRUTE_FORCE":      ("CRITICAL", "red"),
    "PATH_TRAVERSAL":   ("HIGH",     "amber"),
    "COMMAND_INJECTION":("HIGH",     "amber"),
    "SSRF":             ("HIGH",     "amber"),
    "CSRF":             ("HIGH",     "amber"),
    "HEADER_INJECTION": ("MEDIUM",   "blue"),
    "OPEN_REDIRECT":    ("MEDIUM",   "blue"),
    "SENSITIVE_FILE":   ("MEDIUM",   "blue"),
}
 
# â”€â”€ In-memory state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
blocked_log    = []
allowed_log    = []
login_attempts = {}   # ip -> [timestamps]
BRUTE_LIMIT    = 5
BRUTE_WINDOW   = 30   # seconds
RULE_STATES    = {name: True for name in RULES}
 
def log_block(rule, payload, endpoint=""):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    blocked_log.append({
        'time': ts, 'rule': rule,
        'payload': payload,
        'ip': request.remote_addr or '127.0.0.1',
        'endpoint': endpoint or request.path
    })
 
def log_allow(endpoint=""):
    allowed_log.append({'time': datetime.datetime.now().strftime('%H:%M:%S'),
                        'endpoint': endpoint or request.path})

def is_rule_active(name):
    return RULE_STATES.get(name, True)

def check_waf(value):
    for name, pattern in RULES.items():
        if not is_rule_active(name):
            continue
        if pattern and pattern.search(value):
            return name
    return None
 
def is_brute_force(ip):
    now = time.time()
    attempts = [t for t in login_attempts.get(ip, []) if now - t < BRUTE_WINDOW]
    attempts.append(now)
    login_attempts[ip] = attempts
    return len(attempts) > BRUTE_LIMIT
 
def make_csrf_token():
    raw = f"{session.get('user','anon')}-{int(time.time()//60)}"
    return hashlib.md5(raw.encode()).hexdigest()
 
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  SHARED CSS + BASE RENDERER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 
SHARED_CSS = """
<style>
:root{--bg:#080c10;--bg2:#0d1117;--bg3:#111820;--border:rgba(0,255,128,0.15);--border2:rgba(0,255,128,0.35);--green:#00ff80;--green2:#00c964;--red:#ff3b5c;--amber:#ffb038;--blue:#38b2ff;--purple:#b06aff;--muted:#4a6070;--text:#c8d8e4;--text2:#7a9ab0}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(0,255,128,0.06) 0%,transparent 60%),repeating-linear-gradient(0deg,transparent,transparent 39px,rgba(0,255,128,0.03) 40px),repeating-linear-gradient(90deg,transparent,transparent 39px,rgba(0,255,128,0.03) 40px);pointer-events:none;z-index:0}
nav{position:sticky;top:0;z-index:100;background:rgba(8,12,16,0.93);backdrop-filter:blur(14px);border-bottom:1px solid var(--border);padding:0 1.8rem;display:flex;align-items:center;gap:1.5rem;height:58px;flex-wrap:wrap}
.nav-brand{font-family:'Syne',sans-serif;font-weight:800;font-size:1.05rem;color:var(--green);text-decoration:none;display:flex;align-items:center;gap:8px;letter-spacing:.05em;white-space:nowrap}
.nav-brand::before{content:'â¬¡';font-size:1.2rem}
.nav-links{display:flex;gap:.15rem;margin-left:auto;flex-wrap:wrap}
.nav-links a{color:var(--text2);text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:.75rem;padding:5px 12px;border-radius:4px;border:1px solid transparent;transition:all .2s;letter-spacing:.04em;white-space:nowrap}
.nav-links a:hover,.nav-links a.active{color:var(--green);border-color:var(--border2);background:rgba(0,255,128,0.06)}
.status-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s infinite;display:inline-block;margin-right:5px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
main{position:relative;z-index:1;padding:2.5rem 2rem;max-width:1200px;margin:0 auto}
.page-header{margin-bottom:2.5rem}
.page-header h1{font-size:2.2rem;font-weight:800;background:linear-gradient(135deg,var(--green) 0%,var(--blue) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1.2;margin-bottom:.4rem}
.page-header p{color:var(--text2);font-family:'JetBrains Mono',monospace;font-size:.82rem}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.5rem;transition:border-color .25s}
.card:hover{border-color:var(--border2)}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
.grid-5{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem}
@media(max-width:1000px){.grid-5{grid-template-columns:repeat(3,1fr)}.grid-4{grid-template-columns:repeat(2,1fr)}}
@media(max-width:700px){.grid-5,.grid-4,.grid-2{grid-template-columns:1fr}}
.metric{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:1.1rem 1.3rem}
.metric-label{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text2);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.4rem}
.metric-value{font-family:'Syne',sans-serif;font-size:1.9rem;font-weight:700}
.metric-value.green{color:var(--green)}.metric-value.red{color:var(--red)}.metric-value.amber{color:var(--amber)}.metric-value.blue{color:var(--blue)}.metric-value.purple{color:var(--purple)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:.78rem;font-weight:500;text-decoration:none;cursor:pointer;border:1px solid;transition:all .2s;letter-spacing:.03em;background:none}
.btn-danger{color:var(--red);border-color:rgba(255,59,92,.4);background:rgba(255,59,92,.08)}.btn-danger:hover{background:rgba(255,59,92,.18);border-color:var(--red)}
.btn-safe{color:var(--green);border-color:rgba(0,255,128,.4);background:rgba(0,255,128,.06)}.btn-safe:hover{background:rgba(0,255,128,.14);border-color:var(--green)}
.btn-primary{color:var(--blue);border-color:rgba(56,178,255,.4);background:rgba(56,178,255,.06)}.btn-primary:hover{background:rgba(56,178,255,.14);border-color:var(--blue)}
.btn-amber{color:var(--amber);border-color:rgba(255,176,56,.4);background:rgba(255,176,56,.06)}.btn-amber:hover{background:rgba(255,176,56,.14);border-color:var(--amber)}
.badge{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:.66rem;font-weight:600;padding:3px 8px;border-radius:4px;text-transform:uppercase;letter-spacing:.08em}
.badge-red{background:rgba(255,59,92,.14);color:var(--red);border:1px solid rgba(255,59,92,.28)}
.badge-green{background:rgba(0,255,128,.1);color:var(--green);border:1px solid rgba(0,255,128,.22)}
.badge-amber{background:rgba(255,176,56,.1);color:var(--amber);border:1px solid rgba(255,176,56,.22)}
.badge-blue{background:rgba(56,178,255,.1);color:var(--blue);border:1px solid rgba(56,178,255,.22)}
table{width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace;font-size:.77rem}
th{color:var(--text2);font-size:.67rem;letter-spacing:.1em;text-transform:uppercase;padding:10px 14px;border-bottom:1px solid var(--border);text-align:left;font-weight:500}
td{padding:10px 14px;border-bottom:1px solid rgba(0,255,128,0.05);color:var(--text);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,255,128,0.025)}
.section-title{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--green2);letter-spacing:.12em;text-transform:uppercase;margin-bottom:1rem;display:flex;align-items:center;gap:8px}
.section-title::after{content:'';flex:1;height:1px;background:var(--border)}
.glow-line{height:1px;background:linear-gradient(90deg,transparent,var(--green),transparent);opacity:.35;margin:2rem 0}
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.f1{animation:fadeUp .45s ease both}.f2{animation:fadeUp .45s .09s ease both}.f3{animation:fadeUp .45s .18s ease both}.f4{animation:fadeUp .45s .27s ease both}
code{font-family:'JetBrains Mono',monospace;background:rgba(0,255,128,.07);color:var(--green);padding:1px 5px;border-radius:3px;font-size:.84em;word-break:break-all}
.form-group{margin-bottom:1rem}
.form-label{display:block;font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--text2);margin-bottom:.4rem;letter-spacing:.06em;text-transform:uppercase}
.form-input{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.84rem;padding:9px 12px;outline:none;transition:border-color .2s}
.form-input:focus{border-color:var(--border2)}
.form-input::placeholder{color:var(--muted)}
.alert{padding:.8rem 1rem;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:.8rem;margin-bottom:1rem;border:1px solid}
.alert-red{background:rgba(255,59,92,.1);border-color:rgba(255,59,92,.3);color:var(--red)}
.alert-green{background:rgba(0,255,128,.07);border-color:rgba(0,255,128,.2);color:var(--green)}
.alert-amber{background:rgba(255,176,56,.08);border-color:rgba(255,176,56,.25);color:var(--amber)}
.rule-row{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--border)}
.rule-row:last-child{border-bottom:none}
.rule-icon{width:34px;height:34px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.95rem;flex-shrink:0}
.rule-name{font-weight:600;font-size:.88rem}
.rule-desc{font-size:.75rem;color:var(--text2);font-family:'JetBrains Mono',monospace;margin-top:2px}
.rule-meta{margin-left:auto;display:flex;gap:6px;align-items:center;flex-shrink:0}
.bar-wrap{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text2);width:150px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:6px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .8s ease}
.bar-count{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text2);width:24px;text-align:right}
</style>
"""
 
NAV_LINKS = [
    ('/', 'home', 'Home'),
    ('/dashboard', 'dash', 'Dashboard'),
    ('/rules', 'rules', 'Rules'),
    ('/login', 'login', 'Login Demo'),
    ('/test-rules', 'test', 'Test Suite'),
    ('/logs', 'logs', 'Logs'),
]
 
def render_page(title, body, active='', extra_css=''):
    nav_html = ''
    for href, key, label in NAV_LINKS:
        cls = ' class="active"' if key == active else ''
        nav_html += f'<a href="{href}"{cls}>{label}</a>'
 
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ShieldWAF &mdash; {title}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet"/>
{SHARED_CSS}
{extra_css}
</head>
<body>
<nav>
  <a href="/" class="nav-brand"><span class="status-dot"></span>ShieldWAF</a>
  <div class="nav-links">{nav_html}</div>
</nav>
{body}
</body>
</html>"""
 
def blocked_page(rule, payload, endpoint='', status=403):
    log_block(rule, payload, endpoint)
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    sev, col = SEVERITY.get(rule, ('HIGH', 'amber'))
    body = f"""
<main>
<div style="min-height:70vh;display:flex;align-items:center;justify-content:center">
  <div style="text-align:center;max-width:580px" class="f1">
    <div style="font-size:4.5rem;margin-bottom:1.2rem">&#x1f6ab;</div>
    <h1 style="font-size:2.4rem;font-weight:800;color:var(--red);margin-bottom:.5rem">Request Blocked</h1>
    <p style="color:var(--text2);font-family:'JetBrains Mono',monospace;font-size:.81rem;line-height:1.75">
      ShieldWAF detected a malicious pattern in your request.<br/>This incident has been logged.
    </p>
    <div style="background:var(--bg3);border:1px solid rgba(255,59,92,.25);border-radius:8px;padding:1rem 1.3rem;margin:1.8rem auto;text-align:left;font-family:'JetBrains Mono',monospace;font-size:.76rem;max-width:440px">
      <div style="color:var(--red);margin-bottom:8px;font-size:.8rem">&#x2715; THREAT DETECTED</div>
      <div><span style="color:var(--text2)">rule     : </span><span class="badge badge-{col}">{rule}</span></div>
      <div style="margin-top:5px"><span style="color:var(--text2)">severity : </span><span style="color:var(--{col})">{sev}</span></div>
      <div style="margin-top:5px"><span style="color:var(--text2)">payload  : </span><span style="color:var(--amber)">{payload[:60]}{'...' if len(payload)>60 else ''}</span></div>
      <div style="margin-top:5px"><span style="color:var(--text2)">endpoint : </span><span style="color:var(--text)">{endpoint or request.path}</span></div>
      <div style="margin-top:5px"><span style="color:var(--text2)">time     : </span><span style="color:var(--text)">{ts}</span></div>
      <div style="margin-top:5px"><span style="color:var(--text2)">action   : </span><span style="color:var(--red)">BLOCKED ({status})</span></div>
    </div>
    <div style="display:flex;gap:.8rem;justify-content:center;flex-wrap:wrap">
      <a href="/" class="btn btn-primary">&#x2190; Home</a>
      <a href="/dashboard" class="btn btn-amber">Dashboard</a>
      <a href="/logs" class="btn btn-safe">View Logs</a>
    </div>
  </div>
</div>
</main>"""
    return render_page('Blocked', body), status
 
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  ROUTES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 
@app.route('/')
def home():
    body = """
<style>
.hero{padding:4.5rem 2rem 3rem;text-align:center;max-width:840px;margin:0 auto;position:relative;z-index:1}
.hero-eyebrow{font-family:'JetBrains Mono',monospace;font-size:.73rem;color:var(--green2);letter-spacing:.2em;text-transform:uppercase;margin-bottom:1rem}
.hero h1{font-size:clamp(2.3rem,5vw,3.8rem);font-weight:800;line-height:1.1;margin-bottom:1.1rem;background:linear-gradient(135deg,#fff 0%,var(--green) 50%,var(--blue) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero>p{color:var(--text2);font-size:1rem;max-width:520px;margin:0 auto 2rem;line-height:1.75}
.hero-btns{display:flex;gap:.8rem;justify-content:center;flex-wrap:wrap;margin-bottom:2.5rem}
.terminal{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:1rem 1.3rem;font-family:'JetBrains Mono',monospace;font-size:.76rem;max-width:560px;margin:0 auto;text-align:left}
.tb-dots{display:flex;gap:6px;margin-bottom:10px}
.tb-dot{width:9px;height:9px;border-radius:50%}
.tb-line{line-height:1.9}
.fg{display:grid;grid-template-columns:repeat(3,1fr);gap:1.1rem;max-width:1100px;margin:0 auto}
@media(max-width:720px){.fg{grid-template-columns:1fr}}
.fc{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.4rem;transition:all .25s}
.fc:hover{border-color:var(--border2);transform:translateY(-2px)}
.fc-icon{font-size:1.3rem;margin-bottom:.7rem}
.fc h3{font-size:.92rem;font-weight:700;margin-bottom:.35rem}
.fc p{font-size:.77rem;color:var(--text2);line-height:1.65;font-family:'JetBrains Mono',monospace}
.count-strip{display:flex;gap:.8rem;justify-content:center;flex-wrap:wrap;margin:2rem 0}
.cs{text-align:center;padding:.9rem 1.4rem;background:var(--bg2);border:1px solid var(--border);border-radius:8px;min-width:90px}
.cs-num{font-size:1.9rem;font-weight:800;color:var(--green)}
.cs-lbl{font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--text2);text-transform:uppercase;letter-spacing:.1em;margin-top:2px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
</style>
<section class="hero f1">
  <p class="hero-eyebrow">&#x25cf; Active &amp; Protecting</p>
  <h1>Web Application<br/>Firewall Engine</h1>
  <p>Real-time threat detection across 10 attack vectors. Guarding XSS, SQLi, Brute Force, SSRF, CSRF, Header Injection and more.</p>
  <div class="hero-btns">
    <a href="/dashboard" class="btn btn-safe">&#x25b6; Dashboard</a>
    <a href="/login" class="btn btn-amber">&#x1f512; Login Demo</a>
    <a href="/test-rules" class="btn btn-danger">&#x1f9ea; Test Suite</a>
    <a href="/rules" class="btn btn-primary">&#x25a0; All Rules</a>
  </div>
  <div class="terminal">
    <div class="tb-dots"><span class="tb-dot" style="background:#ff5f57"></span><span class="tb-dot" style="background:#febc2e"></span><span class="tb-dot" style="background:#28c840"></span></div>
    <div class="tb-line"><span style="color:var(--green)">$</span> shieldwaf --status</div>
    <div class="tb-line"><span style="color:var(--green2)">&#x2714;</span> <span style="color:var(--text)">Rules loaded: </span><span style="color:var(--amber)">10</span> &nbsp;|&nbsp; Engine: <span style="color:var(--green)">ACTIVE</span></div>
    <div class="tb-line"><span style="color:var(--green2)">&#x2714;</span> Brute-force rate limiter: <span style="color:var(--green)">ON</span> &nbsp;(5 req / 30s)</div>
    <div class="tb-line"><span style="color:var(--green2)">&#x2714;</span> CSRF token validation: <span style="color:var(--green)">ON</span></div>
    <div class="tb-line"><span style="color:var(--green2)">&#x2714;</span> SSRF / Open-Redirect guard: <span style="color:var(--green)">ON</span></div>
    <div class="tb-line"><span style="color:var(--green)">$</span> <span style="animation:blink 1s steps(1) infinite;display:inline-block">&#x2588;</span></div>
  </div>
</section>
<div style="height:1px;background:linear-gradient(90deg,transparent,var(--green),transparent);opacity:.28;margin:0 2rem"></div>
<main>
  <div class="count-strip f2">
    <div class="cs"><div class="cs-num">10</div><div class="cs-lbl">WAF Rules</div></div>
    <div class="cs"><div class="cs-num" style="color:var(--red)">5</div><div class="cs-lbl">New Attacks</div></div>
    <div class="cs"><div class="cs-num" style="color:var(--blue)">7</div><div class="cs-lbl">Pages</div></div>
    <div class="cs"><div class="cs-num" style="color:var(--amber)">&#x221e;</div><div class="cs-lbl">Uptime</div></div>
  </div>
  <p class="section-title f3">Protection Layers</p>
  <div class="fg f3">
    <div class="fc"><div class="fc-icon">&#x1f4dc;</div><h3>XSS Prevention</h3><p>Blocks script injection and HTML event-based attacks before they reach your app.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f5c4;</div><h3>SQL Injection</h3><p>Detects UNION, boolean-based injections, DROP/SELECT abuse in all query params.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f512;</div><h3>Brute Force</h3><p>Rate-limits login per IP. Blocks after 5 failed attempts within a 30-second window.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f310;</div><h3>SSRF Guard</h3><p>Blocks requests targeting localhost, cloud metadata endpoints, and internal ranges.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f6e1;</div><h3>CSRF Protection</h3><p>Validates anti-CSRF tokens on every state-changing POST request to the server.</p></div>
    <div class="fc"><div class="fc-icon">&#x21aa;</div><h3>Open Redirect</h3><p>Prevents redirect params from sending users to malicious external domains.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f4e8;</div><h3>Header Injection</h3><p>Strips CRLF sequences and forged headers from all user-supplied input fields.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f4c1;</div><h3>Path Traversal</h3><p>Blocks <code>../../</code> sequences designed to escape the web root directory.</p></div>
    <div class="fc"><div class="fc-icon">&#x26a1;</div><h3>Command Injection</h3><p>Identifies embedded shell commands and neutralises them before execution.</p></div>
    <div class="fc"><div class="fc-icon">&#x1f50f;</div><h3>Sensitive Files</h3><p>Stops requests targeting <code>/etc/passwd</code>, <code>.env</code>, and critical system paths.</p></div>
  </div>
</main>"""
    return render_page('Home', body, 'home')
 
 
# â”€â”€ Search â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/search')
def search():
    q = request.args.get('q', '')
    rule = check_waf(q)
    if rule:
        return blocked_page(rule, q, '/search')
    log_allow('/search')
    body = f"""
<main>
  <div class="page-header f1"><h1>Search</h1><p>// WAF inspection passed</p></div>
  <div class="card f2" style="max-width:580px">
    <p class="section-title">Result</p>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.84rem;line-height:2.1">
      <span style="color:var(--green)">&#x2714;</span> Query cleared WAF inspection<br/>
      <span style="color:var(--text2)">Term &nbsp;&nbsp;: </span><code>{q}</code><br/>
      <span style="color:var(--text2)">Status : </span><span class="badge badge-green">ALLOWED</span>
    </div>
    <div style="margin-top:1.4rem;display:flex;gap:.7rem;flex-wrap:wrap">
      <a href="/" class="btn btn-primary">&#x2190; Home</a>
      <a href="/test-rules" class="btn btn-safe">Test Suite</a>
    </div>
  </div>
</main>"""
    return render_page('Search', body)
 
 
# â”€â”€ Login (Brute Force + CSRF demo) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/login', methods=['GET'])
def login_get():
    token = make_csrf_token()
    session['csrf_token'] = token
    msg = request.args.get('msg', '')
    alert = ''
    if   msg == 'wrong': alert = '<div class="alert alert-amber">&#x26a0; Wrong username or password.</div>'
    elif msg == 'ok':    alert = '<div class="alert alert-green">&#x2714; Login successful! (demo â€” no real session)</div>'
 
    extra = """<style>
.login-wrap{min-height:75vh;display:flex;align-items:center;justify-content:center;padding:2rem}
.login-box{width:100%;max-width:400px}
.login-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:2rem}
.waf-note{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:.75rem 1rem;font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text2);margin-top:1.2rem;line-height:1.7}
</style>"""
 
    body = f"""
<div class="login-wrap">
  <div class="login-box f1">
    <div style="text-align:center;margin-bottom:1.6rem">
      <div style="font-size:2.5rem;margin-bottom:.6rem">&#x1f512;</div>
      <h2 style="font-size:1.55rem;font-weight:800;margin-bottom:.25rem">Secure Login</h2>
      <p style="font-family:'JetBrains Mono',monospace;font-size:.73rem;color:var(--text2)">// Protected by brute-force &amp; CSRF detection</p>
    </div>
    <div class="login-card">
      {alert}
      <form method="POST" action="/login">
        <input type="hidden" name="csrf_token" value="{token}"/>
        <div class="form-group">
          <label class="form-label">Username</label>
          <input class="form-input" type="text" name="username" placeholder="admin" autocomplete="off"/>
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input class="form-input" type="password" name="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;"/>
        </div>
        <button type="submit" class="btn btn-safe" style="width:100%;justify-content:center;margin-top:.6rem">Login &rarr;</button>
      </form>
      <div class="waf-note">
        <span style="color:var(--green)">&#x25cf;</span> Rate-limit: 5 attempts / 30s per IP<br/>
        <span style="color:var(--green)">&#x25cf;</span> CSRF token validated on every POST<br/>
        <span style="color:var(--amber)">hint:</span> credentials are <code>admin</code> / <code>password123</code>
      </div>
    </div>
    <div style="margin-top:1rem;display:flex;gap:.6rem;flex-wrap:wrap;justify-content:center">
      <a href="/test-rules" class="btn btn-danger" style="font-size:.72rem">&#x1f9ea; Test Brute Force</a>
      <a href="/test-rules" class="btn btn-amber" style="font-size:.72rem">&#x1f6e1; Test CSRF</a>
    </div>
  </div>
</div>"""
    return render_page('Login Demo', body, 'login', extra)
 
@app.route('/login', methods=['POST'])
def login_post():
    ip = request.remote_addr or '127.0.0.1'
 
    # CSRF check
    submitted = request.form.get('csrf_token', '')
    expected  = session.get('csrf_token', '')
    if is_rule_active('CSRF') and (not submitted or submitted != expected):
        return blocked_page('CSRF', f'token={submitted or "MISSING"}', '/login')
 
    # Brute force check
    if is_rule_active('BRUTE_FORCE') and is_brute_force(ip):
        return blocked_page('BRUTE_FORCE', f'IP {ip} exceeded {BRUTE_LIMIT} attempts/{BRUTE_WINDOW}s', '/login', 429)
 
    # WAF check on inputs
    user = request.form.get('username', '')
    pwd  = request.form.get('password', '')
    rule = check_waf(user) or check_waf(pwd)
    if rule:
        return blocked_page(rule, f'login input: {user}', '/login')
 
    if user == 'admin' and pwd == 'password123':
        log_allow('/login')
        return redirect(url_for('login_get', msg='ok'))
    return redirect(url_for('login_get', msg='wrong'))
 
 
# â”€â”€ SSRF demo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    rule = check_waf(url)
    if rule:
        return blocked_page(rule, url, '/fetch')
    log_allow('/fetch')
    body = f"""
<main>
  <div class="page-header f1"><h1>URL Fetch</h1><p>// SSRF-protected fetch endpoint</p></div>
  <div class="card f2" style="max-width:600px">
    <p class="section-title">Fetch Result</p>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.83rem;line-height:2.1">
      <span style="color:var(--green)">&#x2714;</span> URL passed SSRF inspection<br/>
      <span style="color:var(--text2)">URL &nbsp;&nbsp;: </span><code>{url}</code><br/>
      <span style="color:var(--text2)">Status : </span><span class="badge badge-green">ALLOWED</span>
    </div>
    <div style="margin-top:1.4rem;display:flex;gap:.7rem;flex-wrap:wrap">
      <a href="/" class="btn btn-primary">&#x2190; Home</a>
      <a href="/test-rules" class="btn btn-safe">Test Suite</a>
    </div>
  </div>
</main>"""
    return render_page('Fetch', body)
 
 
# â”€â”€ Open Redirect demo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/redirect')
def open_redirect():
    dest = request.args.get('to', '/')
    rule = check_waf(dest)
    if rule:
        return blocked_page(rule, dest, '/redirect')
    if is_rule_active('OPEN_REDIRECT'):
        if dest.startswith('/') and not dest.startswith('//'):
            log_allow('/redirect')
            return redirect(dest)
        return blocked_page('OPEN_REDIRECT', dest, '/redirect')
    log_allow('/redirect')
    return redirect(dest)
 
 
# â”€â”€ Header Injection demo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/header-test')
def header_test():
    name = request.args.get('name', '')
    rule = check_waf(name)
    if rule:
        return blocked_page(rule, name, '/header-test')
    log_allow('/header-test')
    body = f"""
<main>
  <div class="page-header f1"><h1>Header Test</h1><p>// Header injection check passed</p></div>
  <div class="card f2" style="max-width:560px">
    <p class="section-title">Result</p>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.83rem;line-height:2.1">
      <span style="color:var(--green)">&#x2714;</span> Header param cleared WAF inspection<br/>
      <span style="color:var(--text2)">Name &nbsp;: </span><code>{name}</code><br/>
      <span style="color:var(--text2)">Status : </span><span class="badge badge-green">ALLOWED</span>
    </div>
    <a href="/" class="btn btn-primary" style="margin-top:1.2rem">&#x2190; Home</a>
  </div>
</main>"""
    return render_page('Header Test', body)
 
 
# â”€â”€ Dashboard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/dashboard')
def dashboard():
    tb = len(blocked_log)
    ta = len(allowed_log)
    total = tb + ta
    rate  = round(tb / total * 100) if total else 0
 
    breakdown = {}
    for log in blocked_log:
        breakdown[log['rule']] = breakdown.get(log['rule'], 0) + 1
 
    bar_cols = ['var(--red)','var(--amber)','var(--blue)','var(--green)','var(--purple)',
                'var(--red)','var(--amber)','var(--blue)','var(--green)','var(--purple)']
    bars = ''
    for i, (rule, count) in enumerate(sorted(breakdown.items(), key=lambda x:-x[1])):
        pct = int(count / max(tb,1) * 100)
        bars += f'<div class="bar-wrap"><span class="bar-label">{rule}</span><div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{bar_cols[i%10]}"></div></div><span class="bar-count">{count}</span></div>'
 
    rows = ''
    for log in list(reversed(blocked_log))[:8]:
        _, col = SEVERITY.get(log['rule'], ('HIGH','amber'))
        rows += f'<tr><td style="color:var(--text2)">{log["time"]}</td><td><span class="badge badge-{col}">{log["rule"]}</span></td><td style="color:var(--text2)">{log.get("endpoint","/")}</td><td><code>{log["payload"][:30]}{"â€¦" if len(log["payload"])>30 else ""}</code></td></tr>'
 
    body = f"""
<main>
  <div class="page-header f1"><h1>Dashboard</h1><p>// Real-time WAF activity &amp; threat intelligence</p></div>
  <div class="grid-5 f1">
    <div class="metric"><div class="metric-label">Total Requests</div><div class="metric-value blue">{total}</div></div>
    <div class="metric"><div class="metric-label">Threats Blocked</div><div class="metric-value red">{tb}</div></div>
    <div class="metric"><div class="metric-label">Requests Allowed</div><div class="metric-value green">{ta}</div></div>
    <div class="metric"><div class="metric-label">Block Rate</div><div class="metric-value amber">{rate}%</div></div>
    <div class="metric"><div class="metric-label">Rules Active</div><div class="metric-value purple">10</div></div>
  </div>
  <div class="glow-line"></div>
  <div class="grid-2 f2">
    <div class="card">
      <p class="section-title">Threat Breakdown</p>
      {bars if bars else '<p style="color:var(--text2);font-family:JetBrains Mono,monospace;font-size:.8rem">No threats yet â€” run the Test Suite.</p>'}
    </div>
    <div class="card">
      <p class="section-title">Recent Blocks</p>
      {'<table><thead><tr><th>Time</th><th>Rule</th><th>Endpoint</th><th>Payload</th></tr></thead><tbody>' + rows + '</tbody></table>' if rows else '<p style="color:var(--text2);font-family:JetBrains Mono,monospace;font-size:.8rem">No blocked requests yet.</p>'}
    </div>
  </div>
  <div style="margin-top:1.4rem;display:flex;gap:.8rem;flex-wrap:wrap" class="f3">
    <a href="/test-rules" class="btn btn-danger">&#x1f9ea; Test Suite</a>
    <a href="/login" class="btn btn-amber">&#x1f512; Login Demo</a>
    <a href="/logs" class="btn btn-primary">&#x1f4cb; Full Log</a>
  </div>
</main>"""
    return render_page('Dashboard', body, 'dash')
 
 
# â”€â”€ Rules page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/rules')
def rules_page():
    RULE_META = [
        ("XSS",              "CRITICAL", "red",   "&#x1f4dc;", "Cross-Site Scripting",       "Matches &lt;script&gt;, event handlers, javascript: URIs in any input param"),
        ("SQL_INJECTION",    "CRITICAL", "red",   "&#x1f5c4;", "SQL Injection",               "Matches OR/AND tricks, UNION, SELECT, DROP, SQL comment sequences (--)"),
        ("BRUTE_FORCE",      "CRITICAL", "red",   "&#x1f512;", "Brute Force Login",           "Rate-limits per IP - blocks after 5 login attempts within 30 seconds"),
        ("PATH_TRAVERSAL",   "HIGH",     "amber", "&#x1f4c1;", "Path Traversal",              "Blocks ../../ sequences attempting to escape the web root directory"),
        ("COMMAND_INJECTION", "HIGH",    "amber", "&#x26a1;",  "Command Injection",           "Matches ; ls, ; cat, ; wget and other OS shell command patterns"),
        ("SSRF",             "HIGH",     "amber", "&#x1f310;", "Server-Side Request Forgery", "Blocks localhost, 127.x, 10.x, 169.254.x (cloud metadata), file:// and gopher://"),
        ("CSRF",             "HIGH",     "amber", "&#x1f6e1;", "Cross-Site Request Forgery",  "Validates anti-CSRF token presence and correctness on all POST requests"),
        ("HEADER_INJECTION", "MEDIUM",   "blue",  "&#x1f4e8;", "HTTP Header Injection",       "Detects CRLF (\\r\\n) sequences used to inject forged HTTP response headers"),
        ("OPEN_REDIRECT",    "MEDIUM",   "blue",  "&#x21aa;",  "Open Redirect",               "Blocks redirect params pointing to external domains or protocol-relative URLs"),
        ("SENSITIVE_FILE",   "MEDIUM",   "blue",  "&#x1f50f;", "Sensitive File Access",       "Blocks /etc/passwd, /etc/shadow, /root/, .env and /proc/ path references"),
    ]

    active_count = sum(1 for enabled in RULE_STATES.values() if enabled)
    rows = ''
    for rule, sev, col, icon, name, desc in RULE_META:
        rgb = '255,59,92' if col == 'red' else ('255,176,56' if col == 'amber' else '56,178,255')
        enabled = is_rule_active(rule)
        toggle_label = 'ACTIVE' if enabled else 'INACTIVE'
        toggle_class = 'badge badge-green rule-switch' if enabled else 'badge badge-red rule-switch'
        rows += (
            f'<div class="rule-row">'
            f'<div class="rule-icon" style="background:rgba({rgb},.12)">{icon}</div>'
            f'<div><div class="rule-name">{name}</div><div class="rule-desc">{desc}</div></div>'
            f'<div class="rule-meta"><span class="badge badge-{col}">{sev}</span>'
            f'<form method="POST" action="/rules/toggle/{rule}" class="rule-toggle-form" style="margin:0"><button type="submit" class="{toggle_class}" title="Click to toggle {rule}">{toggle_label}</button></form>'
            f'</div></div>'
        )

    extra = """<style>
.rule-switch{cursor:pointer;background:none}
.rule-switch:disabled{opacity:.55;cursor:wait}
.rule-help{margin-bottom:1rem;font-family:'JetBrains Mono',monospace;font-size:.74rem;color:var(--text2)}
</style>"""
    body = f"""
<main>
  <div class="page-header f1"><h1>WAF Rules</h1><p id="rule-summary">// {active_count}/{len(RULE_META)} rules active - toggle any rule and re-run attacks from Test Suite</p></div>
  <div class="rule-help f1">Use <code>Disable</code> to simulate "no rule" behavior, then switch back to <code>Enable</code> to see the same payload blocked.</div>
  <div class="card f2" style="max-width:980px">{rows}</div>
  <div style="margin-top:1.4rem;display:flex;gap:.8rem;flex-wrap:wrap" class="f3">
    <a href="/test-rules" class="btn btn-danger">Test All Rules</a>
    <a href="/dashboard" class="btn btn-primary">Dashboard</a>
  </div>
  <script>
  (function() {{
    const forms = document.querySelectorAll('.rule-toggle-form');
    const summary = document.getElementById('rule-summary');

    forms.forEach((form) => {{
      form.addEventListener('submit', async (event) => {{
        event.preventDefault();
        const button = form.querySelector('button');
        if (!button) return;

        button.disabled = true;
        try {{
          const response = await fetch(form.action, {{
            method: 'POST',
            headers: {{
              'X-Requested-With': 'XMLHttpRequest',
              'Accept': 'application/json'
            }}
          }});
          if (!response.ok) throw new Error('toggle failed');
          const data = await response.json();
          if (!data.ok) throw new Error('toggle failed');

          button.textContent = data.active ? 'ACTIVE' : 'INACTIVE';
          button.className = data.active ? 'badge badge-green rule-switch' : 'badge badge-red rule-switch';
          button.title = 'Click to toggle ' + data.rule;

          if (summary) {{
            summary.textContent = '// ' + data.active_count + '/' + data.total + ' rules active - toggle any rule and re-run attacks from Test Suite';
          }}
        }} catch (error) {{
          alert('Could not toggle this rule. Please try again.');
        }} finally {{
          button.disabled = false;
        }}
      }});
    }});
  }})();
  </script>
</main>"""
    return render_page('Rules', body, 'rules', extra)


@app.route('/rules/toggle/<rule_name>', methods=['POST'])
def toggle_rule(rule_name):
    if rule_name not in RULE_STATES:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'ok': False, 'error': 'unknown_rule'}, 404
        return redirect(url_for('rules_page'))

    RULE_STATES[rule_name] = not RULE_STATES[rule_name]
    if rule_name == 'BRUTE_FORCE':
        login_attempts.clear()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return {
            'ok': True,
            'rule': rule_name,
            'active': RULE_STATES[rule_name],
            'active_count': sum(1 for enabled in RULE_STATES.values() if enabled),
            'total': len(RULE_STATES),
        }
    return redirect(url_for('rules_page'))

@app.route('/test-rules')
def test_rules():
    bad_token = 'invalid_csrf_token_xyz'
    extra = """<style>
.tg{display:grid;grid-template-columns:repeat(2,1fr);gap:1.1rem}
@media(max-width:700px){.tg{grid-template-columns:1fr}}
.tc{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.4rem;transition:all .22s}
.tc:hover{border-color:var(--border2);transform:translateY(-1px)}
.tc-head{display:flex;align-items:center;gap:10px;margin-bottom:.75rem}
.tc-icon{width:34px;height:34px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.95rem;flex-shrink:0}
.tc h3{font-size:.88rem;font-weight:700;margin-bottom:2px}
.tc p{font-family:'JetBrains Mono',monospace;font-size:.71rem;color:var(--text2);margin-bottom:.8rem;line-height:1.6}
.tc .payload{display:block;background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:7px 10px;margin-bottom:.85rem;font-size:.69rem;word-break:break-all;color:var(--green);font-family:'JetBrains Mono',monospace}
.safe-row{background:var(--bg2);border:1px solid rgba(0,255,128,.2);border-radius:10px;padding:1.3rem;grid-column:1/-1;display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
</style>"""
 
    body = f"""
<main>
  <div class="page-header f1"><h1>Test Suite</h1><p>// Simulate attacks â€” every blocked request is logged to the dashboard</p></div>
 
  <p class="section-title f2">&#x25a0; Original Rules</p>
  <div class="tg f2">
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,59,92,.12)">&#x1f4dc;</div><div><h3>XSS Attack</h3><span class="badge badge-red">CRITICAL</span></div></div>
      <p>Sends a &lt;script&gt;alert(1)&lt;/script&gt; payload via query param to test XSS detection.</p>
      <span class="payload">/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</span>
      <a href="/search?q=<script>alert(1)</script>" class="btn btn-danger">&#x25b6; Fire XSS</a>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,59,92,.12)">&#x1f5c4;</div><div><h3>SQL Injection</h3><span class="badge badge-red">CRITICAL</span></div></div>
      <p>Sends a classic boolean SQLi payload targeting the search endpoint query parameter.</p>
      <span class="payload">/search?q=' OR 1=1--</span>
      <a href="/search?q=' OR 1=1--" class="btn btn-danger">&#x25b6; Fire SQLi</a>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,176,56,.12)">&#x1f4c1;</div><div><h3>Path Traversal</h3><span class="badge badge-amber">HIGH</span></div></div>
      <p>Uses ../../ sequences to attempt escape from the web root and read server files.</p>
      <span class="payload">/search?q=../../etc/passwd</span>
      <a href="/search?q=../../etc/passwd" class="btn btn-amber">&#x25b6; Fire Path</a>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,176,56,.12)">&#x26a1;</div><div><h3>Command Injection</h3><span class="badge badge-amber">HIGH</span></div></div>
      <p>Embeds a shell command <code>; ls -la /</code> attempting OS command execution via input.</p>
      <span class="payload">/search?q=; ls -la /</span>
      <a href="/search?q=; ls -la /" class="btn btn-amber">&#x25b6; Fire CMD</a>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(56,178,255,.12)">&#x1f50f;</div><div><h3>Sensitive File</h3><span class="badge badge-blue">MEDIUM</span></div></div>
      <p>References /etc/passwd in the query to test sensitive system path detection.</p>
      <span class="payload">/search?q=/etc/passwd</span>
      <a href="/search?q=/etc/passwd" class="btn btn-primary">&#x25b6; Fire File</a>
    </div>
  </div>
 
  <div class="glow-line f3"></div>
  <p class="section-title f3">&#x2b50; New Attack Rules</p>
  <div class="tg f3">
    <div class="tc" id="brute">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,59,92,.12)">&#x1f512;</div><div><h3>Brute Force Login</h3><span class="badge badge-red">CRITICAL</span></div></div>
      <p>Visit the login page and click submit 6+ times quickly. WAF blocks your IP after 5 attempts in 30 seconds.</p>
      <span class="payload">POST /login â€” rapid repeat submissions per IP</span>
      <a href="/login" class="btn btn-danger">&#x25b6; Go to Login &rarr; Spam Submit</a>
    </div>
    <div class="tc" id="csrf">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,176,56,.12)">&#x1f6e1;</div><div><h3>CSRF Attack</h3><span class="badge badge-amber">HIGH</span></div></div>
      <p>Submits the login form with a forged/invalid CSRF token, simulating a cross-site request from a malicious page.</p>
      <span class="payload">POST /login â€” csrf_token=invalid_token_xyz</span>
      <form method="POST" action="/login" style="margin-top:.3rem">
        <input type="hidden" name="csrf_token" value="{bad_token}"/>
        <input type="hidden" name="username" value="admin"/>
        <input type="hidden" name="password" value="password123"/>
        <button type="submit" class="btn btn-amber">&#x25b6; Fire CSRF Attack</button>
      </form>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(255,176,56,.12)">&#x1f310;</div><div><h3>SSRF Attack</h3><span class="badge badge-amber">HIGH</span></div></div>
      <p>Passes an internal URL to the fetch endpoint, attempting to reach a private service at 127.0.0.1.</p>
      <span class="payload">/fetch?url=http://127.0.0.1/admin</span>
      <a href="/fetch?url=http://127.0.0.1/admin" class="btn btn-amber">&#x25b6; Fire SSRF</a>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(56,178,255,.12)">&#x21aa;</div><div><h3>Open Redirect</h3><span class="badge badge-blue">MEDIUM</span></div></div>
      <p>Passes an external URL to the redirect endpoint to bounce the user to a phishing domain.</p>
      <span class="payload">/redirect?to=https://evil.example.com</span>
      <a href="/redirect?to=https://evil.example.com" class="btn btn-primary">&#x25b6; Fire Redirect</a>
    </div>
    <div class="tc">
      <div class="tc-head"><div class="tc-icon" style="background:rgba(56,178,255,.12)">&#x1f4e8;</div><div><h3>Header Injection</h3><span class="badge badge-blue">MEDIUM</span></div></div>
      <p>Injects a CRLF sequence to forge a Set-Cookie response header via the name parameter.</p>
      <span class="payload">/header-test?name=foo%0d%0aSet-Cookie:+evil=1</span>
      <a href="/header-test?name=foo%0d%0aSet-Cookie: evil=1" class="btn btn-primary">&#x25b6; Fire Header</a>
    </div>
  </div>
 
  <div class="glow-line f4"></div>
  <div class="tg f4" style="grid-template-columns:1fr">
    <div class="safe-row">
      <div style="flex:1;min-width:180px">
        <h3 style="font-size:.9rem;font-weight:700;margin-bottom:.3rem">&#x2714; Safe Request â€” Should Pass</h3>
        <p style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--text2);margin:0">Sends a benign query confirming the WAF allows legitimate traffic.</p>
      </div>
      <a href="/search?q=hello+world+safe+query" class="btn btn-safe">&#x25b6; Send Safe Request</a>
    </div>
  </div>
 
  <div style="margin-top:1.8rem;display:flex;gap:.8rem;flex-wrap:wrap" class="f4">
    <a href="/dashboard" class="btn btn-primary">&#x1f4ca; Dashboard</a>
    <a href="/logs" class="btn btn-amber">&#x1f4cb; Full Log</a>
    <a href="/" class="btn btn-safe">&#x2190; Home</a>
  </div>
</main>"""
    return render_page('Test Suite', body, 'test', extra)
 
 
# â”€â”€ Logs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/logs')
def logs():
    rows = ''
    for i, log in enumerate(reversed(blocked_log), 1):
        _, col = SEVERITY.get(log['rule'], ('HIGH','amber'))
        rows += f'<tr><td style="color:var(--muted)">{i}</td><td style="color:var(--text2)">{log["time"]}</td><td><span class="badge badge-{col}">{log["rule"]}</span></td><td style="color:var(--text2)">{log.get("endpoint","/")}</td><td><code>{log["payload"][:48]}{"â€¦" if len(log["payload"])>48 else ""}</code></td><td><span class="badge badge-red">BLOCKED</span></td></tr>'
 
    table = f'<table><thead><tr><th>#</th><th>Time</th><th>Rule</th><th>Endpoint</th><th>Payload</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>' if rows else '<div style="text-align:center;padding:3.5rem 1rem"><div style="font-size:3rem;margin-bottom:1rem">&#x1f4cb;</div><p style="color:var(--text2);font-family:JetBrains Mono,monospace;font-size:.82rem">No blocked requests yet.<br/>Run the test suite to generate entries.</p><a href="/test-rules" class="btn btn-danger" style="margin-top:1.4rem;display:inline-flex">&#x1f9ea; Test Suite</a></div>'
 
    body = f"""
<main>
  <div class="page-header f1" style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem">
    <div><h1>Threat Log</h1><p>// {len(blocked_log)} blocked request{'s' if len(blocked_log)!=1 else ''} recorded</p></div>
    <a href="/logs/clear" class="btn btn-danger" style="margin-top:.4rem">&#x1f5d1; Clear</a>
  </div>
  <div class="card f2">{table}</div>
</main>"""
    return render_page('Logs', body, 'logs')
 
@app.route('/logs/clear')
def clear_logs():
    blocked_log.clear()
    allowed_log.clear()
    return redirect(url_for('logs'))
 
 
if __name__ == '__main__':
    app.run(debug=True)
