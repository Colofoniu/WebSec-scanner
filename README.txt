# WebSec Scanner v3.0
### Real Security Audit Tool for Windows

---

## How to Build the .EXE (One-Time Setup)

### Requirements
- Windows 10 or 11
- Python 3.8+ → https://python.org/downloads
  ⚠️ During install: CHECK "Add Python to PATH"

### Steps

1. Extract this folder anywhere on your PC
2. Double-click **BUILD_EXE.bat**
3. Wait ~2 minutes for it to complete
4. Your EXE will be at: `dist\WebSecScanner.exe`
5. Copy `WebSecScanner.exe` anywhere — it's fully portable!

---

## What It Scans (Real Checks)

### 🌐 DNS Analysis
- A, AAAA, MX, NS, TXT, CAA records (via Cloudflare DoH)
- SPF, DMARC, DKIM email security records
- Subdomain enumeration + takeover detection (dangling CNAMEs)

### 📋 Security Headers
- Content-Security-Policy, HSTS, X-Frame-Options
- X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- CORS configuration, Cross-Origin policies

### 📁 Sensitive File Exposure
- .git/config, .git/HEAD, .env
- phpinfo.php, backup.sql, database.sql
- .htaccess, web.config, .htpasswd, .DS_Store
- Admin panels: /admin, /wp-admin, /phpmyadmin, etc.
- API endpoints: /api/v1, /graphql, /swagger.json, etc.

### 🔒 TLS / Cryptography
- HTTPS enforcement + HTTP→HTTPS redirect
- TLS version (flags SSLv2/3, TLSv1.0/1.1)
- Cipher suite strength
- SSL certificate validity
- Mixed content detection
- CAA DNS record

### 🍪 Session / Cookie Security
- Secure flag, HttpOnly flag, SameSite attribute
- Clickjacking protection (X-Frame-Options / CSP)

### 🔍 HTML Analysis
- Suspicious HTML comments (passwords, tokens, API keys)
- Secrets exposed in page source / JavaScript
- CSRF token presence in forms
- Password field autocomplete settings
- CMS detection (WordPress, Drupal, Joomla, Shopify, Magento)
- JS library fingerprinting (jQuery, React, Angular, Vue, Bootstrap)

### ⚙️ Misconfiguration
- Directory listing on /uploads/, /files/, /logs/, etc.
- Stack traces / server version on error pages
- Open redirect testing (10+ parameters)

### ☁️ Cloud Security
- Public S3 buckets (AWS)
- Public Google Cloud Storage buckets

---

## Notes
- All checks are PASSIVE — no exploit payloads are sent
- Internet connection required for DNS (uses Cloudflare DoH)
- Some checks may be blocked by WAFs or firewalls
- Only scan websites you own or have written permission to test

---

## Troubleshooting

**"Python not found"** → Reinstall Python and check "Add to PATH"

**Build fails with SSL error** → Run: `pip install --upgrade certifi`

**EXE is flagged by antivirus** → This is a false positive common with
PyInstaller-packaged apps. Add an exception or build from source yourself.

**Scan shows no results** → The target may be blocking requests.
Try a different site to verify the tool works.
