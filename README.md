# mini_waf

Simple Flask-based demo Web Application Firewall (WAF).

## Quick Run (PowerShell)

```powershell
cd C:\Users\harki\OneDrive\Desktop\mini_waf
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python waf_app.py
```

Open http://127.0.0.1:5000 in your browser.

## Notes

- App entry point: `waf_app.py`
- Debug mode is enabled in the script for local development.
