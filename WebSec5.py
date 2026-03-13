"""
WebSec Scanner v5.0 - Enterprise Grade Security Audit Tool
Real passive security checks: HTTP, DNS, TLS, Headers, Files, Cloud, Ports, Email, etc.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import socket
import ssl
import urllib.request
import urllib.parse
import http.client
import json
import re
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
import queue

VERSION = "5.0"

CONFIG = {
    "timeout":            7,
    "max_threads":        12,
    "user_agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "max_response_bytes": 600_000,
    "rate_limit_delay":   0.05,
    "doh_server":         "https://cloudflare-dns.com/dns-query",
    "doh_fallback":       "https://dns.google/resolve",
}

# ── Colours ───────────────────────────────────────────────────────────────────
BG       = "#07080f"
BG2      = "#0c1220"
BG3      = "#101929"
BG4      = "#141f31"
BORDER   = "#1c2d42"
BORDER2  = "#243448"
ACCENT   = "#00c8ff"
ACCENT2  = "#0077aa"
TEXT     = "#9ab4cc"
TEXT_B   = "#cce4f8"
DIM      = "#3a5570"
DIM2     = "#2a3f55"

SEV_COLOR = {
    "CRITICAL": "#ff2255",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#f5c400",
    "LOW":      "#22cc66",
    "INFO":     "#3a6888",
    "PASS":     "#22cc66",
}

# ── Wordlists ─────────────────────────────────────────────────────────────────
SENSITIVE_FILES = [
    ("/.git/config",            ".git/config exposed",         "CRITICAL"),
    ("/.git/HEAD",              ".git/HEAD exposed",           "CRITICAL"),
    ("/.git/COMMIT_EDITMSG",    ".git/COMMIT_EDITMSG exposed", "HIGH"),
    ("/.env",                   ".env file exposed",           "CRITICAL"),
    ("/.env.production",        ".env.production exposed",     "CRITICAL"),
    ("/.env.local",             ".env.local exposed",          "CRITICAL"),
    ("/.env.backup",            ".env.backup exposed",         "CRITICAL"),
    ("/config.php",             "config.php exposed",          "CRITICAL"),
    ("/configuration.php",      "configuration.php exposed",   "CRITICAL"),
    ("/wp-config.php",          "wp-config.php exposed",       "CRITICAL"),
    ("/wp-config.php.bak",      "wp-config backup exposed",    "CRITICAL"),
    ("/wp-config.php~",         "wp-config.php~ exposed",      "CRITICAL"),
    ("/backup.sql",             "backup.sql exposed",          "CRITICAL"),
    ("/database.sql",           "database.sql exposed",        "CRITICAL"),
    ("/dump.sql",               "dump.sql exposed",            "CRITICAL"),
    ("/db.sql",                 "db.sql exposed",              "CRITICAL"),
    ("/backup.zip",             "backup.zip exposed",          "HIGH"),
    ("/backup.tar.gz",          "backup.tar.gz exposed",       "HIGH"),
    ("/.htpasswd",              ".htpasswd exposed",           "CRITICAL"),
    ("/phpinfo.php",            "phpinfo.php exposed",         "HIGH"),
    ("/info.php",               "info.php exposed",            "HIGH"),
    ("/test.php",               "test.php exposed",            "MEDIUM"),
    ("/server-status",          "Apache server-status",        "MEDIUM"),
    ("/server-info",            "Apache server-info",          "MEDIUM"),
    ("/_profiler",              "Symfony profiler exposed",    "HIGH"),
    ("/debug/pprof",            "Go pprof endpoint exposed",   "MEDIUM"),
    ("/.DS_Store",              ".DS_Store exposed",           "MEDIUM"),
    ("/.htaccess",              ".htaccess exposed",           "MEDIUM"),
    ("/web.config",             "web.config exposed",          "HIGH"),
    ("/elmah.axd",              "ELMAH error log exposed",     "HIGH"),
    ("/trace.axd",              "Trace.axd exposed",           "HIGH"),
    ("/package.json",           "package.json exposed",        "MEDIUM"),
    ("/composer.json",          "composer.json exposed",       "MEDIUM"),
    ("/requirements.txt",       "requirements.txt exposed",    "LOW"),
    ("/.well-known/security.txt","security.txt present",       "INFO"),
    ("/crossdomain.xml",        "crossdomain.xml exposed",     "LOW"),
    ("/README.md",              "README.md exposed",           "INFO"),
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/admin/login", "/user/login", "/signin",
    "/cpanel", "/phpmyadmin", "/pma", "/manager",
    "/backend", "/dashboard", "/console", "/portal",
    "/auth", "/secure", "/private", "/internal",
]

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/rest", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/v1", "/v2", "/.well-known/openid-configuration",
    "/metrics", "/actuator", "/actuator/health",
    "/actuator/info", "/actuator/env",
    "/health", "/healthz", "/ready", "/debug", "/status",
]

DIR_PATHS = [
    "/images/", "/uploads/", "/files/", "/assets/",
    "/static/", "/backup/", "/logs/", "/data/",
    "/tmp/", "/temp/", "/cache/", "/old/",
    "/archive/", "/media/", "/documents/",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "goto",
    "target", "redir", "destination", "forward",
    "redirect_to", "return_url", "returnUrl",
]

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api",
    "dev", "staging", "test", "old", "blog",
    "shop", "portal", "app", "beta", "cdn",
    "static", "media", "vpn", "remote", "git",
    "gitlab", "jenkins", "jira", "confluence",
]

RISKY_PROVIDERS = [
    "github.io", "herokuapp.com", "azurewebsites.net",
    "s3.amazonaws.com", "shopify.com", "fastly.net",
    "surge.sh", "netlify.app", "vercel.app", "ghost.io",
    "tumblr.com", "wordpress.com", "zendesk.com",
]

SECURITY_HEADERS = [
    ("content-security-policy",      "Content-Security-Policy",       "HIGH"),
    ("strict-transport-security",    "HSTS",                          "HIGH"),
    ("x-frame-options",              "X-Frame-Options",               "MEDIUM"),
    ("x-content-type-options",       "X-Content-Type-Options",        "MEDIUM"),
    ("x-xss-protection",             "X-XSS-Protection",              "LOW"),
    ("referrer-policy",              "Referrer-Policy",               "LOW"),
    ("permissions-policy",           "Permissions-Policy",            "LOW"),
    ("cross-origin-opener-policy",   "Cross-Origin-Opener-Policy",    "MEDIUM"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy",  "MEDIUM"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy",  "LOW"),
    ("expect-ct",                    "Expect-CT",                     "LOW"),
]

WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "cf-cache-status", "cloudflare"],
    "AWS WAF":     ["x-amz-cf-id", "x-amzn-requestid"],
    "Akamai":      ["x-akamai-request-id", "x-check-cacheable"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":     ["x-iinfo", "incap_ses", "visid_incap"],
    "F5 BIG-IP":   ["bigipserver", "f5_st"],
    "ModSecurity": ["mod_security", "owasp"],
}

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Data classes ──────────────────────────────────────────────────────────────
class Finding:
    def __init__(self, category, check, result, detail, severity, evidence=""):
        self.category  = category
        self.check     = check
        self.result    = result
        self.detail    = detail
        self.severity  = severity
        self.evidence  = evidence
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {k: getattr(self, k)
                for k in ("category","check","result","detail","severity","evidence","timestamp")}


class ScanResult:
    def __init__(self, target):
        self.target     = target
        self.start_time = datetime.now()
        self.end_time   = None
        self.findings: List[Finding] = []
        self.metadata: Dict          = {}

    def add(self, f): self.findings.append(f)
    def complete(self): self.end_time = datetime.now()

    @property
    def duration(self):
        return (self.end_time - self.start_time).total_seconds() if self.end_time else 0

    @property
    def summary(self):
        fails = [f for f in self.findings if f.result == "FAIL"]
        return {"total":    len(self.findings),
                "fail":     len(fails),
                "critical": sum(1 for f in fails if f.severity == "CRITICAL"),
                "high":     sum(1 for f in fails if f.severity == "HIGH"),
                "medium":   sum(1 for f in fails if f.severity == "MEDIUM"),
                "low":      sum(1 for f in fails if f.severity == "LOW")}

    @property
    def score(self):
        s = self.summary
        return max(0, 100 - s["critical"]*15 - s["high"]*6 - s["medium"]*3 - s["low"]*1)

    @property
    def risk_level(self):
        sc = self.score
        if sc >= 85: return "LOW RISK"
        if sc >= 65: return "MODERATE"
        if sc >= 40: return "HIGH RISK"
        return "CRITICAL"


# ── Network layer ─────────────────────────────────────────────────────────────
class Net:
    @staticmethod
    def request(method, url, timeout=None, extra_headers=None,
                max_bytes=None, follow_redirects=True, max_redirects=5):
        if timeout   is None: timeout   = CONFIG["timeout"]
        if max_bytes is None: max_bytes = CONFIG["max_response_bytes"]
        hdrs = {"User-Agent":      CONFIG["user_agent"],
                "Accept":          "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection":      "close"}
        if extra_headers: hdrs.update(extra_headers)

        current_url = url
        for _ in range(max_redirects + 1):
            try:
                p    = urllib.parse.urlparse(current_url)
                host = p.netloc
                path = (p.path or "/") + (("?" + p.query) if p.query else "")
                conn = (http.client.HTTPSConnection(host, timeout=timeout, context=_SSL_CTX)
                        if p.scheme == "https"
                        else http.client.HTTPConnection(host, timeout=timeout))
                try:
                    conn.request(method, path, headers=hdrs)
                    resp = conn.getresponse()
                    resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
                    code = resp.status
                    if follow_redirects and code in (301, 302, 303, 307, 308):
                        loc = resp_hdrs.get("location", "")
                        if loc:
                            conn.close()
                            if not loc.startswith(("http://","https://")):
                                loc = urllib.parse.urljoin(current_url, loc)
                            current_url = loc
                            continue
                    body = ""
                    if method.upper() != "HEAD":
                        body = resp.read(max_bytes).decode("utf-8", errors="replace")
                    return code, resp_hdrs, body, current_url
                finally:
                    conn.close()
            except socket.timeout:
                return None, {}, f"Timeout ({timeout}s)", current_url
            except Exception as e:
                return None, {}, str(e), current_url
        return None, {}, "Too many redirects", current_url

    @staticmethod
    def get(url, timeout=None, max_bytes=None):
        return Net.request("GET", url, timeout=timeout, max_bytes=max_bytes)

    @staticmethod
    def dns(name, qtype, timeout=5):
        for srv in [CONFIG["doh_server"], CONFIG["doh_fallback"]]:
            try:
                url = f"{srv}?name={urllib.parse.quote(name)}&type={qtype}"
                req = urllib.request.Request(url, headers={
                    "Accept": "application/dns-json",
                    "User-Agent": CONFIG["user_agent"]})
                with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                    return [a["data"] for a in json.loads(r.read()).get("Answer", [])]
            except Exception:
                continue
        return []

    @staticmethod
    def ssl_info(host, port=443, timeout=8):
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with _SSL_CTX.wrap_socket(sock, server_hostname=host) as s:
                    c = s.cipher()
                    return {"cert": s.getpeercert(), "cipher": c,
                            "version": s.version(), "bits": c[2] if c else 0}
        except Exception:
            return {}

    @staticmethod
    def port_check(host, port, timeout=2):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False


# ── Scanner engine ────────────────────────────────────────────────────────────
class Scanner:
    def __init__(self, target, on_progress=None, on_finding=None):
        self.target      = target
        self.on_progress = on_progress
        self.on_finding  = on_finding
        self.result      = ScanResult(target)
        self._stop       = False
        p = urllib.parse.urlparse(target)
        self.scheme = p.scheme
        self.host   = p.hostname or ""
        self.origin = f"{p.scheme}://{self.host}" + (f":{p.port}" if p.port else "")

    def stop(self): self._stop = True

    def _p(self, msg):
        if self.on_progress and not self._stop: self.on_progress(msg)

    def _f(self, category, check, result, detail, severity, evidence=""):
        if self._stop: return
        f = Finding(category, check, result, detail, severity, evidence)
        self.result.add(f)
        if self.on_finding: self.on_finding(f)
        self._p(f"[{category}] {check}")

    def run(self):
        self._p("Initializing scan…")
        is_https = self.scheme == "https"

        # 1. HTTPS
        self._f("Cryptography", "HTTPS enforced",
                "PASS" if is_https else "FAIL",
                "Site uses HTTPS — encrypted in transit" if is_https
                else "Site uses plain HTTP — traffic is unencrypted",
                "INFO" if is_https else "CRITICAL")

        # 2. HTTP→HTTPS redirect
        if is_https and not self._stop:
            self._p("Testing HTTP → HTTPS redirect…")
            code, hdrs, _, final = Net.get(
                self.origin.replace("https://", "http://"), timeout=5, max_bytes=500)
            redirected = final.startswith("https://")
            self._f("Cryptography", "HTTP → HTTPS redirect",
                    "PASS" if redirected else "FAIL",
                    "HTTP correctly redirects to HTTPS" if redirected
                    else "HTTP does NOT redirect to HTTPS",
                    "INFO" if redirected else "HIGH")

        # 3. Fetch main page
        if self._stop: self.result.complete(); return self.result
        self._p("Fetching main page…")
        status, headers, body, final_url = Net.get(self.origin)
        if not status:
            self._f("Reconnaissance", "Site reachable", "FAIL",
                    f"Cannot reach: {body}", "HIGH")
            self.result.complete(); return self.result

        self._f("Reconnaissance", "Site reachable", "PASS",
                f"HTTP {status}  ·  Final URL: {final_url}", "INFO")
        self.result.metadata["server"]  = headers.get("server", "")
        self.result.metadata["powered"] = headers.get("x-powered-by", "")

        # 4. Security headers
        if not self._stop:
            self._p("Analyzing security headers…")
            for hdr, name, sev in SECURITY_HEADERS:
                val = headers.get(hdr, "")
                self._f("Security Headers", name,
                        "PASS" if val else "FAIL",
                        f"Value: {val[:120]}" if val else f"Header missing",
                        "INFO" if val else sev,
                        evidence=f"{hdr}: {val}" if val else "")

        # 5. Server disclosure
        if not self._stop:
            server  = headers.get("server", "")
            powered = headers.get("x-powered-by", "")
            exposed = bool(re.search(r"[\d.]+", server)) or bool(powered)
            self._f("Reconnaissance", "Server version disclosure",
                    "FAIL" if exposed else "PASS",
                    server or powered or "No version info disclosed",
                    "MEDIUM" if exposed else "INFO")

        # 6. CORS
        if not self._stop:
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                self._f("API Security", "CORS wildcard (*)", "FAIL",
                        "Any origin can read responses — CORS misconfiguration",
                        "HIGH", evidence="Access-Control-Allow-Origin: *")
            elif acao:
                self._f("API Security", "CORS configuration", "PASS",
                        f"Origin restricted to: {acao}", "INFO")
            else:
                self._f("API Security", "CORS absent", "INFO",
                        "No CORS header (may be intentional)", "INFO")

        # 7. Cookie security
        if not self._stop: self._check_cookies(headers)

        # 8. Clickjacking
        if not self._stop:
            xfo = headers.get("x-frame-options", "")
            csp = headers.get("content-security-policy", "")
            ok  = bool(xfo) or "frame-ancestors" in csp
            self._f("Client-Side Security", "Clickjacking protection",
                    "PASS" if ok else "FAIL",
                    f"Protected via: {xfo or 'CSP frame-ancestors'}" if ok
                    else "Missing X-Frame-Options and CSP frame-ancestors",
                    "INFO" if ok else "HIGH")

        # 9. HSTS details
        if not self._stop:
            hsts = headers.get("strict-transport-security", "")
            if hsts:
                m   = re.search(r"max-age=(\d+)", hsts)
                age = int(m.group(1)) if m else 0
                pre = "preload" in hsts
                sub = "includeSubDomains" in hsts
                self._f("Security Headers", "HSTS max-age",
                        "PASS" if age >= 31536000 else "FAIL",
                        f"max-age={age:,}" +
                        (" (preload)" if pre else "") +
                        (" (includeSubDomains)" if sub else ""),
                        "INFO" if age >= 31536000 else "MEDIUM")

        # 10. Content-type sniffing
        if not self._stop:
            xcto = headers.get("x-content-type-options", "")
            ct   = headers.get("content-type", "")
            self._f("Security Headers", "MIME-type sniffing (nosniff)",
                    "PASS" if "nosniff" in xcto else "FAIL",
                    f"Content-Type: {ct} — nosniff {'set' if 'nosniff' in xcto else 'MISSING'}",
                    "INFO" if "nosniff" in xcto else "MEDIUM")

        # 11. WAF detection
        if not self._stop: self._detect_waf(headers, body)

        # 12. Sensitive files (parallel)
        if not self._stop:
            self._p("Scanning sensitive files & backups…")
            self._scan_files_parallel()

        # 13. robots.txt + sitemap
        if not self._stop: self._check_robots()

        # 14. Admin panels
        if not self._stop:
            self._p("Scanning admin panels…")
            self._scan_paths(ADMIN_PATHS, "Reconnaissance", "Admin panels", "MEDIUM")

        # 15. API endpoints
        if not self._stop:
            self._p("Scanning API endpoints…")
            self._scan_api_paths()

        # 16. Directory listing
        if not self._stop: self._check_dir_listing()

        # 17. Open redirect
        if not self._stop: self._check_open_redirect()

        # 18. HTML analysis
        if not self._stop and body:
            self._p("Analyzing HTML source…")
            self._analyze_html(body, is_https)

        # 19. Error page disclosure
        if not self._stop: self._check_error_page()

        # 20. Deprecated / info-leaking headers
        if not self._stop: self._check_deprecated_headers(headers)

        # 21. SSL/TLS
        if not self._stop and is_https:
            self._p("Analyzing SSL/TLS configuration…")
            self._check_ssl()

        # 22. DNS (parallel)
        if not self._stop: self._check_dns()

        # 23. Subdomains
        if not self._stop: self._check_subdomains()

        # 24. Cloud buckets
        if not self._stop: self._check_cloud_buckets()

        # 25. Common ports
        if not self._stop: self._check_ports()

        # 26. Rate limiting
        if not self._stop: self._check_rate_limit()

        # 27. Response timing
        if not self._stop: self._check_response_time()

        self.result.complete()
        return self.result

    # ── Cookie checks ─────────────────────────────────────────────────────
    def _check_cookies(self, headers):
        raw = headers.get("set-cookie", "")
        if not raw:
            self._f("Session Management", "Cookie flags", "INFO",
                    "No Set-Cookie on main page — cookies likely set post-login", "INFO")
            return
        has_s  = bool(re.search(r";\s*secure",   raw, re.I))
        has_ho = bool(re.search(r";\s*httponly", raw, re.I))
        has_ss = bool(re.search(r";\s*samesite", raw, re.I))
        has_pre= bool(re.search(r"__Host-|__Secure-", raw))
        for label, flag, ok, sev, msg in [
            ("Cookie Secure flag",   "Secure",   has_s,  "HIGH",   "can be sent over HTTP"),
            ("Cookie HttpOnly flag", "HttpOnly", has_ho, "HIGH",   "readable via JS (XSS)"),
            ("Cookie SameSite attr", "SameSite", has_ss, "MEDIUM", "CSRF risk"),
        ]:
            self._f("Session Management", label,
                    "PASS" if ok else "FAIL",
                    f"{flag} flag present" if ok else f"Missing {flag} — {msg}",
                    "INFO" if ok else sev)
        self._f("Session Management", "Cookie prefix hardening",
                "PASS" if has_pre else "INFO",
                "__Host-/__Secure- prefix detected" if has_pre
                else "No __Host-/__Secure- cookie prefix", "INFO")

    # ── WAF detection ─────────────────────────────────────────────────────
    def _detect_waf(self, headers, body):
        all_hdrs = str(headers).lower()
        body_low = (body[:2000] if body else "").lower()
        detected = [w for w, sigs in WAF_SIGNATURES.items()
                    if any(s.lower() in all_hdrs or s.lower() in body_low for s in sigs)]
        self._f("Reconnaissance", "WAF / CDN detection", "INFO",
                f"Detected: {', '.join(detected)}" if detected
                else "No common WAF/CDN signatures found", "INFO",
                evidence=", ".join(detected))
        if detected: self.result.metadata["waf"] = detected

    # ── Parallel file scan ─────────────────────────────────────────────────
    def _scan_files_parallel(self):
        q = queue.Queue()

        def check(path, name, sev):
            if self._stop: return
            code, _, _, _ = Net.get(self.origin + path, timeout=4, max_bytes=300)
            if code == 200:
                good = sev == "INFO"
                q.put((name, "PASS" if good else "FAIL",
                       f"{'Present' if good else 'EXPOSED'} at {path}",
                       "INFO" if good else sev))
            else:
                good = sev == "INFO"
                q.put((name, "FAIL" if good else "PASS",
                       f"Not accessible (HTTP {code})", "INFO"))

        with ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as ex:
            futs = [ex.submit(check, p, n, s) for p, n, s in SENSITIVE_FILES]
            for f in as_completed(futs):
                try: f.result()
                except Exception: pass

        while not q.empty():
            if self._stop: break
            name, result, detail, sev = q.get()
            self._f("Misconfiguration", name, result, detail, sev)

    # ── robots.txt ─────────────────────────────────────────────────────────
    def _check_robots(self):
        self._p("Checking robots.txt and sitemap…")
        code, _, rbody, _ = Net.get(self.origin + "/robots.txt", timeout=5, max_bytes=10000)
        if code == 200:
            disallows = re.findall(r"Disallow:\s*(.+)", rbody, re.I)
            sensitive = [d.strip() for d in disallows
                         if re.search(r"admin|backup|config|private|api|secret|db", d, re.I)]
            self._f("Reconnaissance", "robots.txt",
                    "FAIL" if sensitive else "INFO",
                    f"{len(disallows)} Disallow rule(s)" +
                    (f" — sensitive paths: {', '.join(sensitive[:3])}" if sensitive else ""),
                    "MEDIUM" if sensitive else "INFO",
                    evidence="\n".join(f"Disallow: {d}" for d in disallows[:10]))
        else:
            self._f("Reconnaissance", "robots.txt", "INFO", "Not found", "INFO")
        code2, _, _, _ = Net.get(self.origin + "/sitemap.xml", timeout=5, max_bytes=500)
        self._f("Reconnaissance", "sitemap.xml", "INFO",
                "Present — enumerates site structure" if code2 == 200 else "Not found", "INFO")

    # ── Admin panel scan ────────────────────────────────────────────────────
    def _scan_paths(self, paths, category, label, sev):
        found = []
        for p in paths:
            if self._stop: break
            code, _, _, _ = Net.get(self.origin + p, timeout=3, max_bytes=200)
            if code in (200, 301, 302, 401, 403):
                found.append(f"{p} [{code}]")
            time.sleep(CONFIG["rate_limit_delay"])
        self._f(category, f"{label} detection",
                "FAIL" if found else "PASS",
                "Found: " + ", ".join(found) if found else f"No common {label.lower()} paths",
                sev if found else "INFO",
                evidence="\n".join(found))

    # ── API endpoint scan ───────────────────────────────────────────────────
    def _scan_api_paths(self):
        open_ep, auth_ep = [], []
        for p in API_PATHS:
            if self._stop: break
            code, hdrs, body, _ = Net.get(self.origin + p, timeout=3, max_bytes=500)
            ct = hdrs.get("content-type", "")
            if code == 200:
                lbl = f"{p} [{code}]" + (f" ({ct[:30]})" if "json" in ct or "xml" in ct else "")
                open_ep.append(lbl)
            elif code in (401, 403):
                auth_ep.append(f"{p} [{code}]")
            time.sleep(CONFIG["rate_limit_delay"])
        if open_ep:
            self._f("API Security", "Unauthenticated API access", "FAIL",
                    f"Open: {', '.join(open_ep[:5])}", "HIGH",
                    evidence="\n".join(open_ep))
        if auth_ep:
            self._f("API Security", "Protected API endpoints", "INFO",
                    f"Auth-protected: {', '.join(auth_ep[:5])}", "INFO")
        if not open_ep and not auth_ep:
            self._f("API Security", "API endpoint discovery", "PASS",
                    "No common API paths found", "INFO")

    # ── Directory listing ───────────────────────────────────────────────────
    def _check_dir_listing(self):
        self._p("Checking directory listing…")
        found = []
        for p in DIR_PATHS:
            if self._stop: break
            code, _, body, _ = Net.get(self.origin + p, timeout=4, max_bytes=5000)
            if code == 200 and re.search(
                    r"Index of|Directory listing|Parent Directory|\[DIR\]", body, re.I):
                found.append(p)
            time.sleep(CONFIG["rate_limit_delay"])
        self._f("Misconfiguration", "Directory listing",
                "FAIL" if found else "PASS",
                "Enabled at: " + ", ".join(found) if found else "Not detected",
                "HIGH" if found else "INFO")

    # ── Open redirect ───────────────────────────────────────────────────────
    def _check_open_redirect(self):
        self._p("Testing open redirect…")
        for param in REDIRECT_PARAMS:
            if self._stop: break
            test = f"{self.origin}/?{param}=https://evil.example.com"
            code, hdrs, _, final = Net.get(test, timeout=4, max_bytes=500)
            loc = hdrs.get("location", "")
            if "evil.example.com" in loc or "evil.example.com" in final:
                self._f("Server Security", "Open redirect", "FAIL",
                        f"Confirmed via ?{param}= parameter",
                        "HIGH", evidence=f"GET {test}\n→ {loc or final}")
                return
            time.sleep(CONFIG["rate_limit_delay"])
        self._f("Server Security", "Open redirect", "PASS",
                "No open redirect on common parameters", "INFO")

    # ── HTML analysis ───────────────────────────────────────────────────────
    def _analyze_html(self, body, is_https):
        # Suspicious comments
        comments = re.findall(r"<!--[\s\S]*?-->", body)
        bad = [c for c in comments
               if re.search(r"password|secret|key|token|todo|fixme|hack|debug|api_key|private", c, re.I)]
        self._f("Reconnaissance", "Suspicious HTML comments",
                "FAIL" if bad else "PASS",
                f"{len(bad)} suspicious: {bad[0][:80]}" if bad
                else f"{len(comments)} comments, none suspicious",
                "MEDIUM" if bad else "INFO")

        # Secrets in source
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}',                                           "AWS Access Key"),
            (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}',                  "GitHub Token"),
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][^"\']{12,}["\']',    "API Key"),
            (r'(?:secret[_-]?key|secret)\s*[:=]\s*["\'][^"\']{12,}["\']', "Secret Key"),
            (r'(?:access[_-]?token)\s*[:=]\s*["\'][^"\']{12,}["\']',      "Access Token"),
            (r'(?:password|passwd)\s*[:=]\s*["\'][^"\']{6,}["\']',        "Password"),
        ]
        found_secrets = []
        for pat, label in secret_patterns:
            for m in re.findall(pat, body, re.I):
                found_secrets.append(f"{label}: {str(m)[:60]}")
        self._f("Client-Side Security", "Secrets in page source",
                "FAIL" if found_secrets else "PASS",
                f"{len(found_secrets)} potential secret(s)" if found_secrets
                else "No obvious secrets found",
                "CRITICAL" if found_secrets else "INFO",
                evidence="\n".join(found_secrets[:5]))

        # Mixed content
        mixed = is_https and bool(re.search(r'(?:src|href|action)=["\']http://', body))
        self._f("Cryptography", "Mixed content (HTTP on HTTPS)",
                "FAIL" if mixed else "PASS",
                "HTTP resources on HTTPS page" if mixed else "No mixed content detected",
                "MEDIUM" if mixed else "INFO")

        # CMS detection
        cms_map = [
            (r"wp-content|wp-includes|wp-json",    "WordPress"),
            (r"Drupal|/sites/default/",            "Drupal"),
            (r"Joomla|/components/com_",           "Joomla"),
            (r"shopify|myshopify",                 "Shopify"),
            (r"Magento|mage/",                     "Magento"),
            (r"typo3",                             "TYPO3"),
            (r"__doPostBack|DotNetNuke",           "ASP.NET / DNN"),
            (r"csrfmiddlewaretoken",               "Django"),
            (r"next\.js|__NEXT_DATA__",            "Next.js"),
            (r"nuxt|__nuxt",                       "Nuxt.js"),
        ]
        cms_found = [name for pat, name in cms_map if re.search(pat, body, re.I)]
        if cms_found: self.result.metadata["cms"] = cms_found
        self._f("Reconnaissance", "Technology stack", "INFO",
                f"Detected: {', '.join(cms_found)} — check for known CVEs" if cms_found
                else "No common CMS/framework fingerprint", "INFO")

        # CSRF
        forms = re.findall(r"<form[^>]*>", body, re.I)
        csrf  = bool(re.search(r"csrf|_token|nonce|__RequestVerificationToken", body, re.I))
        if forms:
            self._f("CSRF", "CSRF token in forms",
                    "PASS" if csrf else "FAIL",
                    f"{len(forms)} form(s) — {'CSRF token detected' if csrf else 'NO CSRF token'}",
                    "INFO" if csrf else "HIGH")

        # Subresource Integrity
        scripts = re.findall(r'<script[^>]+src=["\'][^"\']+["\'][^>]*>', body, re.I)
        ext_no_sri = [s for s in scripts if "http" in s and "integrity=" not in s]
        if ext_no_sri:
            self._f("3rd Party Dependencies", "Subresource Integrity (SRI)",
                    "FAIL",
                    f"{len(ext_no_sri)} external script(s) missing SRI integrity attribute",
                    "MEDIUM", evidence="\n".join(ext_no_sri[:3]))

        # JS libraries
        lib_pats = [
            (r"jquery[./-]([\d.]+)", "jQuery"),
            (r"bootstrap[./-]([\d.]+)", "Bootstrap"),
            (r"angular[/@]([\d.]+)", "Angular"),
            (r"react[./-]([\d.]+)", "React"),
            (r"vue(?:\.min)?\.js", "Vue.js"),
            (r"lodash[./-]([\d.]+)", "Lodash"),
        ]
        libs = []
        for pat, name in lib_pats:
            m = re.search(pat, body, re.I)
            if m:
                ver = m.group(1) if m.lastindex else ""
                libs.append(f"{name} {ver}".strip())
        if libs:
            self._f("3rd Party Dependencies", "JS libraries detected", "INFO",
                    f"Libraries: {', '.join(libs)} — verify against CVE database", "INFO",
                    evidence="\n".join(libs))

        # Password autocomplete
        pwd = re.findall(r'<input[^>]*type=["\']?password["\']?[^>]*>', body, re.I)
        if pwd:
            no_ac = any(re.search(r'autocomplete=["\']?off', f, re.I) for f in pwd)
            self._f("Authentication", "Password autocomplete",
                    "PASS" if no_ac else "INFO",
                    f"{len(pwd)} password field(s) — autocomplete={'off' if no_ac else 'enabled'}",
                    "INFO")

    # ── Error page disclosure ───────────────────────────────────────────────
    def _check_error_page(self):
        self._p("Testing error page disclosure…")
        code, hdrs, body, _ = Net.get(
            self.origin + "/websec-nonexistent-xyz987abc", timeout=5)
        if not body: return
        patterns = [
            (r"stack trace|stacktrace",            "Stack trace",       "HIGH"),
            (r"<b>Fatal error</b>|Parse error",    "PHP fatal error",   "HIGH"),
            (r"Traceback.*most recent call",        "Python traceback",  "HIGH"),
            (r"Exception in thread|\.java:\d+",    "Java exception",    "HIGH"),
            (r"at System\.|at Microsoft\.",         ".NET stack trace",  "HIGH"),
            (r"(apache|nginx|iis)\s*[\d./]+",      "Server version",    "MEDIUM"),
            (r"(php|asp\.net|ruby|django|rails|laravel)\s*[\d.]+",
                                                    "Framework version", "MEDIUM"),
            (r"ORA-\d{5}|SQLSTATE|mysql.*error",   "Database error",    "HIGH"),
            (r"debug.*=.*true|DEBUG\s*=\s*True",   "Debug mode active", "HIGH"),
        ]
        found_issues = False
        for pat, label, sev in patterns:
            if re.search(pat, body, re.I):
                self._f("Misconfiguration", f"{label} on error page", "FAIL",
                        f"{label} exposed on error page", sev)
                found_issues = True
        if not found_issues:
            self._f("Misconfiguration", "Error page disclosure", "PASS",
                    "No stack traces or version info on error page", "INFO")

    # ── Deprecated headers ──────────────────────────────────────────────────
    def _check_deprecated_headers(self, headers):
        issues = []
        deprecated_map = [
            ("x-webkit-csp",   "X-WebKit-CSP deprecated — use Content-Security-Policy"),
            ("public-key-pins", "HPKP deprecated — risk of permanent site lockout"),
            ("p3p",             "P3P deprecated and ignored by modern browsers"),
        ]
        for hdr, msg in deprecated_map:
            if headers.get(hdr): issues.append(msg)
        if issues:
            self._f("Security Headers", "Deprecated headers present",
                    "INFO", " | ".join(issues), "INFO")

        # Info leaking headers
        leak = []
        for hdr in ["x-aspnet-version", "x-aspnetmvc-version", "x-generator",
                    "x-drupal-cache", "x-wordpress-revision"]:
            val = headers.get(hdr, "")
            if val: leak.append(f"{hdr}: {val}")
        if leak:
            self._f("Reconnaissance", "Info-leaking response headers", "FAIL",
                    f"Version info in headers: {'; '.join(leak)}", "MEDIUM",
                    evidence="\n".join(leak))

    # ── SSL/TLS ─────────────────────────────────────────────────────────────
    def _check_ssl(self):
        info = Net.ssl_info(self.host)
        if not info:
            self._f("Cryptography", "SSL/TLS handshake", "FAIL",
                    "Could not complete SSL handshake", "CRITICAL")
            return

        ver  = info.get("version", "")
        weak = ver in ("SSLv2","SSLv3","TLSv1","TLSv1.1")
        self._f("Cryptography", "TLS version",
                "FAIL" if weak else "PASS",
                f"Protocol: {ver} {'(DEPRECATED)' if weak else '(current)'}",
                "HIGH" if weak else "INFO")

        bits = info.get("bits", 0)
        self._f("Cryptography", "Cipher suite strength",
                "FAIL" if bits < 128 else "PASS",
                f"Cipher: {info['cipher'][0] if info.get('cipher') else 'unknown'} / {bits} bits",
                "HIGH" if bits < 128 else ("MEDIUM" if bits < 256 else "INFO"))

        cert = info.get("cert", {})
        if cert:
            not_after  = cert.get("notAfter", "")
            subject    = dict(x[0] for x in cert.get("subject", []))
            issuer     = dict(x[0] for x in cert.get("issuer", []))
            cn         = subject.get("commonName", "?")
            org        = issuer.get("organizationName", "?")
            self_signed = subject == issuer
            self._f("Cryptography", "SSL certificate",
                    "FAIL" if self_signed else "PASS",
                    f"CN={cn}  Issuer={org}  Expires={not_after}" +
                    ("  ← SELF-SIGNED!" if self_signed else ""),
                    "HIGH" if self_signed else "INFO",
                    evidence=f"Subject: {subject}\nIssuer: {issuer}")
            san   = cert.get("subjectAltName", [])
            names = [v for k, v in san if k == "DNS"]
            if names:
                self._f("Cryptography", "Certificate SANs", "INFO",
                        f"{len(names)} SAN(s): {', '.join(names[:6])}", "INFO")

    # ── DNS ─────────────────────────────────────────────────────────────────
    def _check_dns(self):
        self._p("Querying DNS records (parallel)…")
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(Net.dns, self.host, t): t
                    for t in ["A","AAAA","MX","NS","TXT","CAA"]}
            dns = {}
            for f in as_completed(futs):
                t = futs[f]
                try: dns[t] = f.result()
                except Exception: dns[t] = []

        ips = dns.get("A", [])
        if ips:
            self.result.metadata["ip"] = ips[0]
            self._f("Reconnaissance", "Server IP / hosting", "INFO",
                    f"Resolves to: {', '.join(ips)}", "INFO")
        if dns.get("AAAA"):
            self._f("Reconnaissance", "IPv6 support", "INFO",
                    f"IPv6: {', '.join(dns['AAAA'][:3])}", "INFO")
        if dns.get("MX"):
            self._f("Reconnaissance", "Mail servers (MX)", "INFO",
                    f"{len(dns['MX'])} MX: {', '.join(dns['MX'][:3])}", "INFO")
        if dns.get("NS"):
            self._f("Reconnaissance", "Nameservers (NS)", "INFO",
                    ", ".join(dns["NS"][:4]), "INFO")

        caa = dns.get("CAA", [])
        self._f("Cryptography", "CAA DNS record",
                "PASS" if caa else "FAIL",
                f"CAA: {', '.join(caa)}" if caa
                else "No CAA — any CA can issue certificates",
                "INFO" if caa else "MEDIUM")

        txt  = dns.get("TXT", [])
        spf  = next((r for r in txt if "v=spf1" in r), None)
        self._f("Email Security", "SPF record",
                "PASS" if spf else "FAIL",
                f"SPF: {spf[:100]}" if spf else "No SPF record — email spoofing risk",
                "INFO" if spf else "MEDIUM", evidence=spf or "")

        dmarc_recs = Net.dns(f"_dmarc.{self.host}", "TXT")
        dmarc = next((r for r in dmarc_recs if "v=DMARC1" in r), None)
        self._f("Email Security", "DMARC record",
                "PASS" if dmarc else "FAIL",
                f"DMARC: {dmarc[:100]}" if dmarc else "No DMARC — phishing risk",
                "INFO" if dmarc else "MEDIUM")
        if dmarc:
            pol = re.search(r"p=(none|quarantine|reject)", dmarc)
            if pol:
                p = pol.group(1)
                self._f("Email Security", "DMARC policy",
                        "PASS" if p=="reject" else ("FAIL" if p=="none" else "INFO"),
                        f"Policy: {p} " + {
                            "reject":     "(strongest — emails rejected)",
                            "quarantine": "(moderate — emails quarantined)",
                            "none":       "(monitoring only — NO enforcement!)"
                        }.get(p, ""),
                        "INFO" if p=="reject" else ("MEDIUM" if p=="quarantine" else "HIGH"))

        dkim_found = False
        with ThreadPoolExecutor(max_workers=4) as ex:
            sels = ["default","google","mail","k1","selector1","selector2","dkim","smtp"]
            df   = {ex.submit(Net.dns, f"{s}._domainkey.{self.host}", "TXT"): s for s in sels}
            for f in as_completed(df):
                sel = df[f]
                try:
                    if any("v=DKIM1" in r for r in f.result()):
                        dkim_found = True
                        self._f("Email Security", "DKIM record", "PASS",
                                f"DKIM found (selector: {sel})", "INFO")
                        break
                except Exception: pass
        if not dkim_found:
            self._f("Email Security", "DKIM record", "INFO",
                    "No common DKIM selector found (may use custom selector)", "INFO")

    # ── Subdomains ───────────────────────────────────────────────────────────
    def _check_subdomains(self):
        self._p("Enumerating subdomains for takeover risk…")
        q = queue.Queue()

        def chk(sub):
            if self._stop: return
            fqdn  = f"{sub}.{self.host}"
            cname = Net.dns(fqdn, "CNAME")
            a     = Net.dns(fqdn, "A")
            if cname:
                tgt = cname[0]
                dng = any(p in tgt for p in RISKY_PROVIDERS)
                q.put(("Subdomain Security", f"{fqdn} CNAME",
                       "FAIL" if dng else "INFO",
                       f"→ {tgt}" + ("  ⚠ DANGLING — possible takeover!" if dng else ""),
                       "HIGH" if dng else "INFO",
                       f"CNAME: {fqdn} → {tgt}"))
            elif a:
                q.put(("Subdomain Security", fqdn, "INFO",
                       f"Resolves to {', '.join(a)}", "INFO", ""))

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(chk, s) for s in SUBDOMAINS]
            for f in as_completed(futs):
                try: f.result()
                except Exception: pass

        while not q.empty():
            if self._stop: break
            cat, chk2, res, det, sev, ev = q.get()
            self._f(cat, chk2, res, det, sev, ev)

    # ── Cloud buckets ────────────────────────────────────────────────────────
    def _check_cloud_buckets(self):
        self._p("Checking cloud storage exposure…")
        buckets = [
            (f"https://s3.amazonaws.com/{self.host}",            "AWS S3"),
            (f"https://{self.host}.s3.amazonaws.com",            "AWS S3 vhost"),
            (f"https://storage.googleapis.com/{self.host}",     "Google Cloud Storage"),
            (f"https://{self.host}.blob.core.windows.net",      "Azure Blob Storage"),
        ]
        found = False
        for url, provider in buckets:
            if self._stop: break
            code, _, _, _ = Net.get(url, timeout=4, max_bytes=500)
            if code == 200:
                found = True
                self._f("Cloud Security", f"Public {provider} bucket", "FAIL",
                        f"Publicly accessible: {url}", "CRITICAL", evidence=url)
            time.sleep(CONFIG["rate_limit_delay"])
        if not found:
            self._f("Cloud Security", "Cloud bucket exposure", "PASS",
                    "No public cloud buckets found (AWS S3, GCS, Azure)", "INFO")

    # ── Port scan ────────────────────────────────────────────────────────────
    def _check_ports(self):
        self._p("Scanning common ports…")
        ports = {
            21:    ("FTP",           "MEDIUM"),
            22:    ("SSH",           "INFO"),
            23:    ("Telnet",        "HIGH"),
            25:    ("SMTP",          "LOW"),
            80:    ("HTTP",          "INFO"),
            443:   ("HTTPS",         "INFO"),
            445:   ("SMB",           "CRITICAL"),
            3306:  ("MySQL",         "CRITICAL"),
            3389:  ("RDP",           "CRITICAL"),
            5432:  ("PostgreSQL",    "CRITICAL"),
            5900:  ("VNC",           "CRITICAL"),
            6379:  ("Redis",         "CRITICAL"),
            8080:  ("HTTP-alt",      "MEDIUM"),
            8443:  ("HTTPS-alt",     "LOW"),
            9200:  ("Elasticsearch", "CRITICAL"),
            27017: ("MongoDB",       "CRITICAL"),
        }
        open_ports, risky = [], []
        with ThreadPoolExecutor(max_workers=14) as ex:
            futs = {ex.submit(Net.port_check, self.host, port, 2): (port, svc, sev)
                    for port, (svc, sev) in ports.items()}
            for f in as_completed(futs):
                port, svc, sev = futs[f]
                try:
                    if f.result():
                        open_ports.append(f"{port}/{svc}")
                        if sev in ("HIGH", "CRITICAL"):
                            risky.append(f"{port}/{svc} [{sev}]")
                except Exception: pass

        if open_ports:
            self._f("Server Security", "Open port scan", "INFO",
                    f"Open: {', '.join(sorted(open_ports, key=lambda x: int(x.split('/')[0])))}",
                    "INFO", evidence="\n".join(open_ports))
        if risky:
            crit_sev = "CRITICAL" if any("CRITICAL" in r for r in risky) else "HIGH"
            self._f("Server Security", "Dangerous exposed ports", "FAIL",
                    f"Internet-accessible risk ports: {', '.join(risky)}",
                    crit_sev, evidence="\n".join(risky))
        if not open_ports:
            self._f("Server Security", "Port scan", "INFO",
                    "Common dangerous ports appear closed or filtered", "INFO")

    # ── Rate limiting ────────────────────────────────────────────────────────
    def _check_rate_limit(self):
        self._p("Testing rate limiting…")
        codes = []
        for _ in range(8):
            if self._stop: break
            code, _, _, _ = Net.get(self.origin, timeout=2, max_bytes=500)
            codes.append(code)
            time.sleep(0.1)
        limited = any(c in (429, 503) for c in codes)
        self._f("Server Security", "Rate limiting",
                "PASS" if limited else "FAIL",
                "Rate limiting detected (HTTP 429/503)" if limited
                else "No rate limiting — brute-force / flood risk",
                "INFO" if limited else "MEDIUM")

    # ── Response time ─────────────────────────────────────────────────────────
    def _check_response_time(self):
        self._p("Measuring response time…")
        times = []
        for _ in range(3):
            if self._stop: break
            t0 = time.time()
            Net.get(self.origin, timeout=5, max_bytes=1000)
            times.append(time.time() - t0)
            time.sleep(0.2)
        if times:
            avg = sum(times) / len(times)
            self._f("Server Security", "Response time", "INFO",
                    f"Average: {avg*1000:.0f} ms over {len(times)} requests",
                    "INFO")


# ── Report Generator ──────────────────────────────────────────────────────────
class Report:
    @staticmethod
    def to_json(r: ScanResult) -> str:
        return json.dumps({
            "version":  VERSION, "target": r.target,
            "start":    r.start_time.isoformat(),
            "end":      r.end_time.isoformat() if r.end_time else None,
            "duration": round(r.duration, 2),
            "score":    r.score, "risk": r.risk_level,
            "metadata": r.metadata, "summary": r.summary,
            "findings": [f.to_dict() for f in r.findings],
        }, indent=2)

    @staticmethod
    def to_csv(r: ScanResult) -> str:
        lines = ["Category,Check,Result,Severity,Detail"]
        for f in r.findings:
            d = f.detail.replace('"', '""')
            lines.append(f'"{f.category}","{f.check}","{f.result}","{f.severity}","{d}"')
        return "\n".join(lines)

    @staticmethod
    def to_html(r: ScanResult) -> str:
        s   = r.summary
        sc  = r.score
        rl  = r.risk_level
        col = (SEV_COLOR["LOW"] if sc >= 85 else
               SEV_COLOR["MEDIUM"] if sc >= 65 else
               SEV_COLOR["HIGH"] if sc >= 40 else SEV_COLOR["CRITICAL"])
        rows = ""
        for f in r.findings:
            c  = SEV_COLOR.get(f.severity, "#3a6888")
            bg = {"CRITICAL":"#2a0010","HIGH":"#1f1400","MEDIUM":"#1e1b00",
                  "LOW":"#001a0c"}.get(f.severity,"#080f18")
            rows += f"""<tr style="background:{bg}">
<td style="color:#3a6888;font-size:11px">{f.category}</td>
<td style="color:#cce4f8">{f.check}</td>
<td><span style="background:{c}22;color:{c};border:1px solid {c}44;
    padding:2px 8px;border-radius:3px;font-size:10px">{f.severity}</span></td>
<td style="color:{'#ff2255' if f.result=='FAIL' else '#22cc66'}">{f.result}</td>
<td style="color:#6a8faa;font-size:12px">{f.detail[:120]}</td></tr>\n"""

        return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>WebSec Report — {r.target}</title>
<style>
body{{font-family:'Courier New',monospace;background:#07080f;color:#9ab4cc;margin:0;padding:24px}}
.w{{max-width:1200px;margin:0 auto}}
h1{{color:#cce4f8;font-size:20px;margin:0 0 4px}}
.score{{font-size:52px;font-weight:bold;color:{col};line-height:1}}
.risk{{font-size:18px;color:{col};letter-spacing:3px}}
.grid{{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin:16px 0}}
.card{{background:#0c1220;border:1px solid #1c2d42;border-radius:6px;padding:14px;text-align:center}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{background:#101929;color:#3a5570;font-size:9px;letter-spacing:2px;
    padding:8px 12px;text-align:left;border-bottom:1px solid #1c2d42}}
td{{padding:8px 12px;border-bottom:1px solid #0c1220;vertical-align:top;font-size:12px}}
</style></head><body><div class="w">
<div style="background:#0c1220;border:1px solid #1c2d42;border-radius:8px;
            padding:20px 24px;margin-bottom:20px;display:flex;align-items:center;gap:24px">
  <div>
    <h1>🛡 WebSec Scanner v{VERSION}</h1>
    <div style="color:#3a5570;font-size:10px;letter-spacing:2px">ENTERPRISE SECURITY AUDIT REPORT</div>
    <div style="margin-top:12px;color:#3a5570;font-size:11px">
      Target: <span style="color:#9ab4cc">{r.target}</span> &nbsp;·&nbsp;
      Scanned: {r.start_time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp; Duration: {r.duration:.1f}s
    </div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div class="score">{sc}<span style="font-size:20px;color:#3a5570">/100</span></div>
    <div class="risk">{rl}</div>
  </div>
</div>
<div class="grid">
{"".join(f'<div class="card"><div style="font-size:26px;font-weight:bold;color:{c}">{v}</div><div style="font-size:9px;color:#2a3f55;letter-spacing:2px;margin-top:4px">{lbl}</div></div>'
 for lbl, v, c in [
   ("TOTAL", s["total"], "#3a5570"),
   ("ISSUES", s["fail"], "#ff2255"),
   ("CRITICAL", s["critical"], SEV_COLOR["CRITICAL"]),
   ("HIGH", s["high"], SEV_COLOR["HIGH"]),
   ("MEDIUM", s["medium"], SEV_COLOR["MEDIUM"]),
   ("LOW", s["low"], SEV_COLOR["LOW"]),
 ])}
</div>
<table>
<tr><th>CATEGORY</th><th>CHECK</th><th>SEVERITY</th><th>RESULT</th><th>DETAIL</th></tr>
{rows}
</table>
<div style="margin-top:24px;color:#1c2d42;font-size:11px;text-align:center">
  Generated by WebSec Scanner v{VERSION} · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div></div></body></html>"""


# ── GUI ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"WebSec Scanner v{VERSION}  —  Enterprise Security Audit")
        self.geometry("1280x840")
        self.minsize(1024, 720)
        self.configure(bg=BG)
        self.scanner: Optional[Scanner]    = None
        self.result:  Optional[ScanResult] = None
        self.findings: List[Finding]       = []
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._quit)

    # ── UI Build ───────────────────────────────────────────────────────────
    def _build(self):
        self._titlebar()
        self._header()
        self._urlbar()
        self._toolbar()
        self._body()
        self._detail_bar()
        self._statusbar()

    def _titlebar(self):
        bar = tk.Frame(self, bg="#050710", height=26)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar,
                 text=f"WEBSEC SCANNER  v{VERSION}  ·  ENTERPRISE SECURITY AUDIT TOOL",
                 bg="#050710", fg=DIM2,
                 font=("Courier", 8)).pack(expand=True, pady=6)

    def _header(self):
        hdr = tk.Frame(self, bg=BG2, pady=14)
        hdr.pack(fill="x")
        inner = tk.Frame(hdr, bg=BG2)
        inner.pack(padx=28, fill="x")

        # Left side: icon + title
        left_grp = tk.Frame(inner, bg=BG2)
        left_grp.pack(side="left")

        icon_frame = tk.Frame(left_grp, bg=ACCENT2, width=48, height=48)
        icon_frame.pack(side="left", padx=(0,14))
        icon_frame.pack_propagate(False)
        tk.Label(icon_frame, text="🛡", bg=ACCENT2,
                 font=("Segoe UI Emoji", 22)).place(relx=.5, rely=.5, anchor="center")

        info = tk.Frame(left_grp, bg=BG2)
        info.pack(side="left")
        tk.Label(info, text="WebSec Enterprise Scanner",
                 bg=BG2, fg=TEXT_B,
                 font=("Courier", 14, "bold")).pack(anchor="w")
        tk.Label(info,
                 text="DNS · TLS · HEADERS · FILES · PORTS · SUBDOMAINS · EMAIL SECURITY · CLOUD · RATE LIMIT",
                 bg=BG2, fg=DIM,
                 font=("Courier", 8)).pack(anchor="w", pady=(3,0))

        # Right side: score
        right_grp = tk.Frame(inner, bg=BG2)
        right_grp.pack(side="right")
        self.score_var = tk.StringVar(value="")
        self.risk_var  = tk.StringVar(value="")
        self.score_lbl = tk.Label(right_grp, textvariable=self.score_var,
                                  bg=BG2, fg=ACCENT, font=("Courier", 28, "bold"))
        self.score_lbl.pack(anchor="e")
        self.risk_lbl = tk.Label(right_grp, textvariable=self.risk_var,
                                 bg=BG2, fg=DIM, font=("Courier", 9))
        self.risk_lbl.pack(anchor="e")

    def _urlbar(self):
        wrap = tk.Frame(self, bg=BG, pady=12)
        wrap.pack(fill="x", padx=28)
        frm = tk.Frame(wrap, bg=BG3,
                       highlightbackground=BORDER2, highlightthickness=1,
                       pady=3, padx=8)
        frm.pack(fill="x")

        tk.Label(frm, text="TARGET", bg=BG3, fg=DIM,
                 font=("Courier", 8)).pack(side="left", padx=(6,4), pady=9)
        tk.Frame(frm, bg=BORDER, width=1, height=22).pack(side="left", padx=6, pady=7)

        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(frm, textvariable=self.url_var, bg=BG3,
                                  fg=TEXT_B, insertbackground=ACCENT,
                                  relief="flat", font=("Courier", 12), bd=0)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=9)
        self.url_entry.insert(0, "https://")
        self.url_entry.bind("<Return>", lambda e: self._start())

        self.stop_btn = tk.Button(frm, text="◼ STOP", command=self._stop,
                                  bg="#200a0a", fg="#ff4455", relief="flat",
                                  font=("Courier", 9, "bold"), padx=12, pady=6,
                                  cursor="hand2", state="disabled",
                                  activebackground="#300a0a")
        self.stop_btn.pack(side="right", padx=4)

        self.scan_btn = tk.Button(frm, text="SCAN  →", command=self._start,
                                  bg=ACCENT2, fg="white", relief="flat",
                                  font=("Courier", 10, "bold"), padx=22, pady=6,
                                  cursor="hand2", activebackground=ACCENT,
                                  activeforeground="white")
        self.scan_btn.pack(side="right", padx=4)

    def _toolbar(self):
        bar = tk.Frame(self, bg=BG, pady=5)
        bar.pack(fill="x", padx=28)

        tk.Label(bar, text="FILTER:", bg=BG, fg=DIM2,
                 font=("Courier", 8)).pack(side="left", padx=(0,8))

        self.filter_var = tk.StringVar(value="ALL")
        for lbl in ("ALL","FAIL","CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            col = SEV_COLOR.get(lbl, ACCENT) if lbl not in ("ALL","FAIL") else ACCENT
            tk.Radiobutton(bar, text=lbl, variable=self.filter_var, value=lbl,
                           command=self._refresh,
                           bg=BG, fg=col, selectcolor=BG4,
                           activebackground=BG, activeforeground=col,
                           font=("Courier", 8), indicatoron=False,
                           relief="flat", padx=8, pady=3,
                           highlightthickness=1,
                           highlightbackground=BORDER).pack(side="left", padx=2)

        self.export_btn = tk.Button(bar, text="📊 EXPORT", command=self._export,
                                    bg=BG4, fg=DIM, relief="flat",
                                    font=("Courier", 8), padx=10, pady=3,
                                    cursor="hand2", state="disabled",
                                    highlightthickness=1, highlightbackground=BORDER)
        self.export_btn.pack(side="right", padx=3)

        tk.Button(bar, text="↩ NEW", command=self._reset,
                  bg=BG4, fg=DIM, relief="flat",
                  font=("Courier", 8), padx=10, pady=3, cursor="hand2",
                  highlightthickness=1, highlightbackground=BORDER).pack(side="right", padx=3)

    def _body(self):
        self.paned = tk.PanedWindow(self, orient="horizontal",
                                    bg=BG, sashwidth=5, sashrelief="flat")
        self.paned.pack(fill="both", expand=True, padx=14, pady=(4,0))

        # Left: categories
        left = tk.Frame(self.paned, bg=BG)
        self.paned.add(left, minsize=230)
        tk.Label(left, text="CATEGORIES", bg=BG, fg=DIM2,
                 font=("Courier", 8), pady=5).pack(anchor="w", padx=8)
        csb = tk.Scrollbar(left, orient="vertical")
        self.cat_list = tk.Listbox(left, bg=BG2, fg=TEXT,
                                   selectbackground=ACCENT2, selectforeground=TEXT_B,
                                   relief="flat", bd=0, font=("Courier", 10),
                                   activestyle="none", highlightthickness=0,
                                   yscrollcommand=csb.set)
        csb.config(command=self.cat_list.yview)
        self.cat_list.pack(side="left", fill="both", expand=True, padx=(4,0))
        csb.pack(side="right", fill="y")
        self.cat_list.bind("<<ListboxSelect>>", lambda _: self._refresh())

        # Right: treeview
        right = tk.Frame(self.paned, bg=BG)
        self.paned.add(right, minsize=600)
        cols = ("check","result","severity","detail")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("check",    text="CHECK")
        self.tree.heading("result",   text="RESULT")
        self.tree.heading("severity", text="SEV")
        self.tree.heading("detail",   text="DETAIL")
        self.tree.column("check",    width=250, minwidth=160, anchor="w")
        self.tree.column("result",   width=70,  minwidth=60,  anchor="center")
        self.tree.column("severity", width=85,  minwidth=60,  anchor="center")
        self.tree.column("detail",   width=430, minwidth=200, anchor="w")

        sty = ttk.Style()
        sty.theme_use("clam")
        sty.configure("Treeview", background=BG2, foreground=TEXT,
                       fieldbackground=BG2, rowheight=27, font=("Courier", 9))
        sty.configure("Treeview.Heading", background=BG3, foreground=DIM,
                       font=("Courier", 8, "bold"), relief="flat", borderwidth=0)
        sty.map("Treeview", background=[("selected", ACCENT2)],
                foreground=[("selected", TEXT_B)])

        for sev, col in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=col)

        vsb = ttk.Scrollbar(right, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(right, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.bind("<<TreeviewSelect>>", self._on_row)

    def _detail_bar(self):
        self.detail_var = tk.StringVar(value="")
        bar = tk.Frame(self, bg=BG3, height=50)
        bar.pack(fill="x", padx=14, pady=(3,3))
        bar.pack_propagate(False)
        tk.Label(bar, textvariable=self.detail_var, bg=BG3, fg=TEXT,
                 font=("Courier", 9), anchor="w", justify="left",
                 wraplength=1200).pack(fill="x", padx=14, pady=8)

    def _statusbar(self):
        bar = tk.Frame(self, bg="#050710", height=26)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        self.status_var = tk.StringVar(value="Ready  —  enter a URL and press SCAN")
        tk.Label(bar, textvariable=self.status_var, bg="#050710", fg=DIM,
                 font=("Courier", 8), anchor="w").pack(side="left", padx=14)
        self.prog = ttk.Progressbar(bar, length=220, mode="indeterminate")
        self.prog.pack(side="right", padx=14, pady=5)
        self.stats_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self.stats_var, bg="#050710", fg=DIM,
                 font=("Courier", 8)).pack(side="right", padx=8)

    # ── Actions ────────────────────────────────────────────────────────────
    def _start(self):
        raw = self.url_var.get().strip()
        if not raw or raw == "https://":
            messagebox.showwarning("WebSec", "Enter a target URL."); return
        url = raw if raw.startswith("http") else "https://" + raw
        try:
            p = urllib.parse.urlparse(url)
            if not p.hostname: raise ValueError("No hostname")
        except Exception as e:
            messagebox.showerror("Invalid URL", str(e)); return

        self._reset_results()
        self.scan_btn.config(state="disabled", text="SCANNING…")
        self.stop_btn.config(state="normal")
        self.export_btn.config(state="disabled")
        self.prog.start(10)
        self.status_var.set(f"Scanning {url} …")
        self.scanner = Scanner(url, self._on_prog, self._on_find)
        threading.Thread(target=self._thread, daemon=True).start()

    def _thread(self):
        try:
            self.result = self.scanner.run()
            self.after(0, self._done)
        except Exception as e:
            self.after(0, lambda: self._err(str(e)))

    def _on_prog(self, msg): self.after(0, lambda: self.status_var.set(msg))
    def _on_find(self, f):   self.after(0, lambda: self._add(f))

    def _add(self, f: Finding):
        self.findings.append(f)
        self._insert(f)
        self._rebuild_cats()

    def _done(self):
        self.prog.stop()
        self.scan_btn.config(state="normal", text="SCAN  →")
        self.stop_btn.config(state="disabled")
        self.export_btn.config(state="normal")
        if self.result:
            s  = self.result.summary
            sc = self.result.score
            rl = self.result.risk_level
            col = (SEV_COLOR["LOW"] if sc >= 85 else
                   SEV_COLOR["MEDIUM"] if sc >= 65 else
                   SEV_COLOR["HIGH"] if sc >= 40 else SEV_COLOR["CRITICAL"])
            self.score_var.set(f"{sc}/100")
            self.risk_var.set(rl)
            self.score_lbl.config(fg=col)
            self.risk_lbl.config(fg=col)
            self.status_var.set(
                f"✓  Scan complete  ·  {s['total']} checks  ·  {s['fail']} issues  ·  {self.result.duration:.1f}s")
            self.stats_var.set(
                f"CRIT:{s['critical']}  HIGH:{s['high']}  MED:{s['medium']}  LOW:{s['low']}")

    def _err(self, msg):
        self.prog.stop()
        self.scan_btn.config(state="normal", text="SCAN  →")
        self.stop_btn.config(state="disabled")
        self.status_var.set(f"✗  Error: {msg}")

    def _stop(self):
        if self.scanner: self.scanner.stop()
        self.stop_btn.config(state="disabled")
        self.prog.stop()
        self.scan_btn.config(state="normal", text="SCAN  →")
        self.status_var.set("Scan stopped by user")

    def _export(self):
        if not self.result: return
        fn = filedialog.asksaveasfilename(
            title="Export Report", defaultextension=".html",
            filetypes=[("HTML","*.html"),("JSON","*.json"),("CSV","*.csv"),("All","*.*")])
        if not fn: return
        try:
            ext = os.path.splitext(fn)[1].lower()
            content = (Report.to_html(self.result) if ext == ".html" else
                       Report.to_csv(self.result)  if ext == ".csv"  else
                       Report.to_json(self.result))
            with open(fn, "w", encoding="utf-8") as fh: fh.write(content)
            messagebox.showinfo("Exported", f"Report saved:\n{fn}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _quit(self):
        if self.scanner: self.scanner.stop()
        self.destroy()

    # ── Table ──────────────────────────────────────────────────────────────
    def _reset_results(self):
        self.findings = []
        self.result = self.scanner = None
        self.tree.delete(*self.tree.get_children())
        self.cat_list.delete(0, "end")
        self.score_var.set(""); self.risk_var.set("")
        self.stats_var.set(""); self.detail_var.set("")
        self.export_btn.config(state="disabled")

    def _reset(self):
        if self.scanner: self.scanner.stop()
        self._reset_results()
        self.url_var.set("https://")
        self.status_var.set("Ready  —  enter a URL and press SCAN")
        self.stop_btn.config(state="disabled")
        self.scan_btn.config(state="normal", text="SCAN  →")
        self.prog.stop()

    def _insert(self, f: Finding):
        flt = self.filter_var.get()
        if flt == "FAIL" and f.result != "FAIL": return
        if flt not in ("ALL","FAIL") and flt in SEV_COLOR and f.severity != flt: return
        tag = f.severity if f.result == "FAIL" else ("PASS" if f.result == "PASS" else "INFO")
        self.tree.insert("", "end",
                         values=(f.check, f.result, f.severity, f.detail[:140]),
                         tags=(tag,))

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        cat = self._sel_cat()
        for f in self.findings:
            if cat and f.category != cat: continue
            self._insert(f)

    def _sel_cat(self):
        sel = self.cat_list.curselection()
        if not sel: return None
        return self.cat_list.get(sel[0]).split("  ")[0].strip()

    def _rebuild_cats(self):
        sel = self.cat_list.curselection()
        sv  = self.cat_list.get(sel[0]).split("  ")[0] if sel else None
        cats: Dict[str, dict] = {}
        for f in self.findings:
            if f.category not in cats:
                cats[f.category] = {"total":0,"fail":0,"crit":0}
            cats[f.category]["total"] += 1
            if f.result == "FAIL":       cats[f.category]["fail"] += 1
            if f.severity == "CRITICAL": cats[f.category]["crit"] += 1
        self.cat_list.delete(0, "end")
        for cat in sorted(cats):
            d = cats[cat]
            badge = (f"  🔴{d['fail']}" if d["crit"] else
                     f"  ⚠ {d['fail']}" if d["fail"] else "")
            self.cat_list.insert("end", f"{cat}{badge}")
        if sv:
            for i in range(self.cat_list.size()):
                if self.cat_list.get(i).startswith(sv):
                    self.cat_list.selection_set(i); break

    def _on_row(self, _):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0], "values")
        if len(vals) < 4: return
        check, result, sev, detail = vals[0], vals[1], vals[2], vals[3]
        ev = next((f.evidence for f in self.findings
                   if f.check == check and f.result == result), "")
        ev_txt = f"  |  Evidence: {ev[:120]}" if ev else ""
        self.detail_var.set(f"[{sev}] {check}  →  {result}  |  {detail}{ev_txt}")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
