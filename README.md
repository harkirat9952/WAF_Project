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

## Deployment Notes

This project is a Flask server app. A plain Netlify site deploy expects static files (for example `index.html`) and does not run this Flask server directly, which is why you can see a successful build but still get a 404 page.

### Recommended: Deploy on Render

1. Open Render dashboard and choose **New +** -> **Blueprint**.
2. Select this GitHub repo (`harkirat9952/WAF_Project`).
3. Render will auto-read [`render.yaml`](./render.yaml) and prefill settings.
4. Click **Apply** to deploy.

Manual fallback (if you choose Web Service instead of Blueprint):
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn waf_app:app --bind 0.0.0.0:$PORT`

Render will provide a public URL where your Flask app routes (`/`, `/rules`, `/dashboard`, etc.) work normally.
