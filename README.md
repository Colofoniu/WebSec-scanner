WebSec Scanner is an open-source, enterprise-grade passive security audit tool for Windows, built in Python with a native desktop GUI. It performs real security checks against any target website — no proxies, no payloads, no simulations — just genuine HTTP, DNS, TLS, and network analysis.
What it checks:
The scanner covers 27 real audit categories including security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy and more), TLS/SSL configuration (protocol version, cipher strength, certificate validity, SANs), DNS records (A, AAAA, MX, NS, CAA, SPF, DMARC, DKIM with policy enforcement), cookie security flags (Secure, HttpOnly, SameSite, prefix hardening), sensitive file and directory exposure (.env, .git/config, backup.sql, phpinfo.php and 40+ more), admin panel and API endpoint discovery, subdomain enumeration with dangling CNAME takeover detection, WAF and CDN fingerprinting, cloud bucket exposure (AWS S3, Google Cloud Storage, Azure Blob), open redirect testing, HTML source analysis for secrets (AWS keys, GitHub tokens, API keys), CSRF token detection, Subresource Integrity checks, common port scanning (Redis, MongoDB, MySQL, RDP, Elasticsearch and more), email security (SPF, DMARC policy level, DKIM), rate limiting detection, and server/framework version disclosure.
Key features:

Fully passive — no exploit payloads sent to the target
Parallel scanning engine using Python ThreadPoolExecutor for speed
Real-time results displayed as checks complete
Category sidebar with issue counts and severity badges
Filter results by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
Evidence panel — click any finding to see raw evidence
Security score (0–100) with risk level rating
Export reports to HTML, JSON, or CSV
STOP button to cancel mid-scan
Single portable .exe — no installation required

Built with: Python 3.8+ · tkinter · Cloudflare DNS over HTTPS · stdlib only (no third-party dependencies)
To build: install Python, double-click BUILD_EXE.bat, get a portable WebSecScanner.exe.

For educational and authorized testing purposes only. Always obtain written permission before scanning any website you do not own.
