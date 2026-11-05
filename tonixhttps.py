#!/usr/bin/env python3
"""
tonix_https.py - TONIX HTTPS: AI-assisted web security tool (advanced)

  * Passive audit: headers, cookies, CORS, redirects, TLS/certificate, exposed
    sensitive files, technology fingerprint  (GET requests only - no exploitation)
  * Gemini AI analysis + interactive AI chat about the scan results
  * Exportable reports (Markdown / HTML / JSON):
      - Website-Owner (client) remediation report
      - Bug-bounty submission report (per finding, with curl reproduction steps)
    Reports are generated even when the AI is unavailable (built-in fallback text).

Only use against systems you own or are authorized to test.

Install:  pip install requests colorama
Run:      python3 tonix_https.py          (python3 tonix_https.py --reset-key to change key)
"""

import getpass
import hashlib
import html
import json
import os
import re
import shutil
import socket
import ssl
import sys
import threading
import time
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    from colorama import Fore, Style, init as colorama_init
except ImportError as exc:
    sys.exit(f"Missing dependency: {exc.name}. Run: pip install requests colorama")

colorama_init(autoreset=True)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

__version__ = "3.0"

BANNER = r"""
████████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗    ██╗  ██╗████████╗████████╗██████╗ ███████╗
╚══██╔══╝██╔═══██╗████╗  ██║██║╚██╗██╔╝    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝
   ██║   ██║   ██║██╔██╗ ██║██║ ╚███╔╝     ███████║   ██║      ██║   ██████╔╝███████╗
   ██║   ██║   ██║██║╚██╗██║██║ ██╔██╗     ██╔══██║   ██║      ██║   ██╔═══╝ ╚════██║
   ██║   ╚██████╔╝██║ ╚████║██║██╔╝ ██╗    ██║  ██║   ██║      ██║   ██║     ███████║
   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚══════╝

                       TONIX HTTPS
                    WEB SECURITY TOOL
"""

def print_banner():
    """Print the banner centred for the current terminal width.
    Wide terminal  -> the exact ASCII art, block-centred.
    Narrow terminal (e.g. phone) -> compact boxed banner so nothing wraps."""
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    lines = BANNER.strip("\n").splitlines()
    is_art = lambda l: any(ch in l for ch in "█╔╗╚╝═║")  # noqa: E731
    art_w = max(len(l) for l in lines if is_art(l))
    out = []
    if cols >= art_w:
        pad = " " * ((cols - art_w) // 2)          # one shared pad keeps the art's shape intact
        for l in lines:
            if not l.strip():
                out.append("")
            elif is_art(l):
                out.append(pad + l)
            else:
                out.append(l.strip().center(cols))  # title lines centred on their own
    else:
        inner = max(len("WEB SECURITY TOOL"), len("TONIX HTTPS")) + 4
        box = ["╔" + "═" * inner + "╗",
               "║" + "TONIX HTTPS".center(inner) + "║",
               "║" + "WEB SECURITY TOOL".center(inner) + "║",
               "╚" + "═" * inner + "╝"]
        out = [""] + [b.center(cols) if cols >= len(b) else b[:cols] for b in box]
    print(Fore.CYAN + "\n".join(out) + Style.RESET_ALL + "\n")


# ---- API KEY SETUP (checked in this order) ---------------------------------------
API_KEY = ""   # 1) paste your Gemini key here (private copy only), or
               # 2) export GEMINI_API_KEY="...", or
               # 3) just run: it asks once and saves to ~/.tonix_https_key
KEY_FILE = os.path.join(os.path.expanduser("~"), ".tonix_https_key")

TIMEOUT = 10
AI_TIMEOUT = 90
MAX_BODY = 64 * 1024
USER_AGENT = f"TonixHTTPS/{__version__} (authorized security audit)"

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "PASS": 4}
SEV_UI = {
    "HIGH": (Fore.RED, "🔴"), "MEDIUM": (Fore.YELLOW, "🟡"), "LOW": (Fore.GREEN, "🟢"),
    "INFO": (Fore.CYAN, "🔵"), "PASS": (Fore.GREEN, "🟢"),
}

AI_HEADER_WHITELIST = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials", "Server", "X-Powered-By", "Via", "Content-Type",
]

BOUNTY_NOTE = {
    "header": "Missing/weak security headers are usually rated Informational/Low and are often out of "
              "scope on their own. Submit only with a working proof of impact (e.g. a clickjacking PoC "
              "page, or an XSS that the CSP would have blocked) and read the program's scope first.",
    "tls": "TLS/certificate issues are commonly informational unless they enable a demonstrable attack. "
           "Check the program's rules.",
    "file": "Confirmed exposure of sensitive files is frequently accepted (often High/Critical). Do NOT "
            "download, use or share any secrets; report promptly with minimal evidence (URL, status, size).",
    "cookie": "Cookie-flag issues are typically Low and mainly accepted when the cookie is a session token.",
    "transport": "Missing HTTPS/redirect is usually Low-Medium depending on the data the site handles.",
    "info": "Informational only; typically not eligible for a bounty.",
}
BOUNTY_SEVERITY = {"header": "Low / Informational", "tls": "Informational - Low", "file": "Medium - High",
                   "cookie": "Low", "transport": "Low - Medium", "info": "Informational"}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    sev: str
    name: str
    status: str
    fix: str = ""
    kind: str = "header"
    repro: str = ""
    evidence: str = ""


@dataclass
class Scan:
    url: str
    final_url: str = ""
    status: int = 0
    reason: str = ""
    elapsed_ms: int = 0
    redirects: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    cert: dict = field(default_factory=dict)
    protocol: str = ""
    cipher: str = ""
    fatal: str = ""
    started: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def add(self, sev, name, status, fix="", kind="header", repro="", evidence=""):
        self.findings.append(Finding(sev, name, status, fix, kind, repro, evidence))

    def sorted(self):
        return sorted(self.findings, key=lambda f: SEV_ORDER[f.sev])

    def counts(self):
        c = {k: 0 for k in SEV_ORDER}
        for f in self.findings:
            c[f.sev] += 1
        return c

    def grade(self):
        c = self.counts()
        score = max(0, 100 - c["HIGH"] * 15 - c["MEDIUM"] * 6 - c["LOW"] * 2)
        letter = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
        return letter, score

    @property
    def host(self):
        return urlparse(self.final_url or self.url).hostname or "target"


# --------------------------------------------------------------------------- #
# Input helpers
# --------------------------------------------------------------------------- #
def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("No URL was entered.")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{p.scheme}'. Use http or https.")
    if not p.hostname or not re.fullmatch(r"[A-Za-z0-9.\-_]+|\[[0-9A-Fa-f:]+\]", p.hostname):
        raise ValueError("The URL contains an invalid hostname.")
    try:
        p.port  # noqa: B018
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")
    return p._replace(fragment="").geturl()


def flush_stdin():
    """Drop stray keystrokes (e.g. an extra Enter) so prompts don't auto-submit empty."""
    try:
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:  # noqa: BLE001 - not a tty / Windows
        pass


def ask_url():
    for _ in range(3):
        flush_stdin()
        raw = input(f"{Fore.CYAN}[?] Enter Your Target URL (e.g., example.com) > {Style.RESET_ALL}").strip()
        if not raw:
            print(f"{Fore.YELLOW}[!] Please type a website, e.g. example.com{Style.RESET_ALL}")
            continue
        try:
            return normalize_url(raw)
        except ValueError as exc:
            print(f"{Fore.RED}[ERROR] Invalid URL: {exc}{Style.RESET_ALL}")
    return None


# --------------------------------------------------------------------------- #
# Passive scan modules
# --------------------------------------------------------------------------- #
def fetch_limited(session, url, verify=True):
    r = session.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=False, stream=True)
    try:
        body = r.raw.read(MAX_BODY, decode_content=True)
    finally:
        r.close()
    return r, body


def check_headers(sc: Scan, h):
    cmd = f"curl -sI {sc.final_url}"
    add = lambda sev, name, status, fix="": sc.add(sev, name, status, fix, "header", cmd)  # noqa: E731
    https = urlparse(sc.final_url).scheme == "https"

    if not https:
        sc.add("HIGH", "Transport Security", "VULNERABLE - site served over plain HTTP (no encryption)",
               "Enable HTTPS and redirect all HTTP traffic to it.", "transport", cmd)

    name, val = "Strict-Transport-Security", h.get("Strict-Transport-Security")
    if https:
        if not val:
            add("HIGH", name, "VULNERABLE - header missing (SSL-stripping / downgrade risk)",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", val, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                add("MEDIUM", name, f"WEAK - max-age too short ({age}s). Value: {val}",
                    "Raise max-age to at least 31536000 (1 year).")
            elif "includesubdomains" not in val.lower():
                add("LOW", name, f"PARTIAL - missing includeSubDomains. Value: {val}",
                    "Add includeSubDomains once all subdomains support HTTPS.")
            else:
                add("PASS", name, f"SECURE - {val}")

    name, val = "X-Content-Type-Options", h.get("X-Content-Type-Options")
    if not val:
        add("MEDIUM", name, "VULNERABLE - header missing (MIME-sniffing possible)", "Add: X-Content-Type-Options: nosniff")
    elif val.strip().lower() != "nosniff":
        add("MEDIUM", name, f"IMPROPER - value: {val}", "Set the value to exactly: nosniff")
    else:
        add("PASS", name, "SECURE - nosniff")

    csp = h.get("Content-Security-Policy", "")
    name, val = "X-Frame-Options", h.get("X-Frame-Options")
    if val and val.strip().upper() in ("DENY", "SAMEORIGIN"):
        add("PASS", name, f"SECURE - {val}")
    elif "frame-ancestors" in csp.lower():
        add("PASS", name, "SECURE - clickjacking handled via CSP frame-ancestors")
    elif val:
        add("MEDIUM", name, f"WEAK - value '{val}' gives little protection", "Use: X-Frame-Options: DENY (or SAMEORIGIN).")
    else:
        add("HIGH", name, "VULNERABLE - header missing (clickjacking risk)",
            "Add: X-Frame-Options: DENY (or CSP: frame-ancestors 'none')")

    name = "Content-Security-Policy"
    if not csp:
        add("HIGH", name, "VULNERABLE - header missing (no browser-side XSS mitigation)",
            "Deploy a CSP, e.g.: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    else:
        low, issues = csp.lower(), []
        if "'unsafe-inline'" in low:
            issues.append("allows 'unsafe-inline'")
        if "'unsafe-eval'" in low:
            issues.append("allows 'unsafe-eval'")
        if re.search(r"(^|[\s;])\*([\s;]|$)", low):
            issues.append("uses a wildcard (*) source")
        if "default-src" not in low and "script-src" not in low:
            issues.append("no default-src/script-src directive")
        if issues:
            add("MEDIUM", name, "WEAK - policy " + ", ".join(issues),
                "Remove unsafe-inline/unsafe-eval (use nonces/hashes) and avoid wildcards.")
        else:
            add("PASS", name, "SECURE - policy present, no obvious weaknesses")

    name, val = "X-XSS-Protection", h.get("X-XSS-Protection")
    if val is None:
        add("MEDIUM", name, "MISSING - legacy browsers get no XSS filter",
            "Add: X-XSS-Protection: 1; mode=block (and rely on a strong CSP).")
    elif val.strip().startswith("0"):
        add("PASS", name, "DISABLED - acceptable with a strong CSP")
    elif "mode=block" not in val.lower():
        add("MEDIUM", name, f"WEAK - enabled without mode=block. Value: {val}", "Use: X-XSS-Protection: 1; mode=block")
    else:
        add("PASS", name, f"SECURE - {val}")

    name, val = "Referrer-Policy", h.get("Referrer-Policy")
    if not val:
        add("MEDIUM", name, "MISSING - full URLs may leak to third parties",
            "Add: Referrer-Policy: strict-origin-when-cross-origin")
    elif val.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"):
        add("MEDIUM", name, f"WEAK - '{val}' leaks referrer data", "Use strict-origin-when-cross-origin or no-referrer.")
    else:
        add("PASS", name, f"SECURE - {val}")

    name = "Permissions-Policy"
    if not (h.get("Permissions-Policy") or h.get("Feature-Policy")):
        add("LOW", name, "MISSING - browser features (camera, mic, geolocation) not restricted",
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()")
    else:
        add("PASS", name, "SECURE - policy set")

    name = "Server"
    exposed = [f"{n}: {v}" for n, v in (("Server", h.get("Server")), ("X-Powered-By", h.get("X-Powered-By")),
                                         ("X-AspNet-Version", h.get("X-AspNet-Version"))) if v]
    if not exposed:
        add("PASS", name, "SECURE - no server banner / stack disclosed")
    elif any(re.search(r"\d+\.\d+", e) for e in exposed):
        add("MEDIUM", name, "INFORMATION DISCLOSURE - version exposed: " + " | ".join(exposed),
            "Hide versions (Apache: ServerTokens Prod; Nginx: server_tokens off; PHP: expose_php=Off) "
            "and remove X-Powered-By.")
    else:
        add("LOW", name, "INFO - technology disclosed (no version): " + " | ".join(exposed),
            "Consider removing/genericising these headers to reduce fingerprinting.")

    acao = h.get("Access-Control-Allow-Origin", "")
    if acao == "*" and h.get("Access-Control-Allow-Credentials", "").lower() == "true":
        add("HIGH", "CORS", "VULNERABLE - wildcard origin with credentials allowed",
            "Reflect only an explicit allow-list of trusted origins.")
    elif acao == "*":
        add("LOW", "CORS", "INFO - any origin allowed (Access-Control-Allow-Origin: *)",
            "Restrict to trusted origins unless this is a public API.")


def check_cookies(sc: Scan, resp):
    try:
        cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        cookies = []
    https = urlparse(sc.final_url).scheme == "https"
    for c in cookies:
        name, low = c.split("=", 1)[0].strip(), c.lower()
        missing = [flag for flag, bad in (("Secure", https and "secure" not in low),
                                          ("HttpOnly", "httponly" not in low),
                                          ("SameSite", "samesite" not in low)) if bad]
        if missing:
            sev = "MEDIUM" if ("Secure" in missing or "HttpOnly" in missing) else "LOW"
            sc.add(sev, f"Cookie '{name}'", f"WEAK - missing flags: {', '.join(missing)}",
                   "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies.", "cookie",
                   f"curl -sI {sc.final_url} | grep -i set-cookie")
        else:
            sc.add("PASS", f"Cookie '{name}'", "SECURE - Secure/HttpOnly/SameSite present", kind="cookie")


def check_http_redirect(sc: Scan, session):
    p = urlparse(sc.final_url)
    if p.scheme != "https":
        return
    host = p.hostname + (f":{p.port}" if p.port and p.port not in (80, 443) else "")
    cmd = f"curl -sI http://{host}/"
    try:
        r = session.get(f"http://{host}/", timeout=TIMEOUT, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            sc.add("PASS", "HTTP -> HTTPS redirect", f"SECURE - {r.status_code} to {loc}", kind="transport")
        else:
            sc.add("MEDIUM", "HTTP -> HTTPS redirect", f"WEAK - http://{host}/ answered {r.status_code} without HTTPS redirect",
                   "Add a permanent redirect from HTTP to HTTPS and enable HSTS.", "transport", cmd)
    except requests.exceptions.RequestException:
        sc.add("INFO", "Port 80", "Plain HTTP not reachable (acceptable)", kind="transport")


def _probe_proto(host, port, version):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx.minimum_version = ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host):
            return True
    except (ssl.SSLError, ConnectionError):
        return False
    except OSError:
        return None


def check_tls(sc: Scan, host, port):
    cmd = f"openssl s_client -connect {host}:{port} -servername {host} </dev/null"
    cert = proto = cipher = None
    verified = True
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            cert, proto, cipher = s.getpeercert(), s.version(), s.cipher()
    except ssl.SSLCertVerificationError as exc:
        verified = False
        sc.add("HIGH", "TLS Certificate", f"VULNERABLE - validation failed: {exc.verify_message}",
               "Install a valid CA-signed certificate matching the hostname, with the full chain, not expired.",
               "tls", cmd)
    except (ssl.SSLError, OSError) as exc:
        sc.add("HIGH", "TLS Handshake", f"VULNERABLE - handshake failed: {exc}",
               "Check the server speaks TLS on this port and supports TLS 1.2/1.3.", "tls", cmd)
        return
    if not verified:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
                proto, cipher = s.version(), s.cipher()
        except (ssl.SSLError, OSError):
            pass

    if cert:
        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        na = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        nb = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc)
        days = (na - datetime.now(timezone.utc)).days
        issuer = iss.get("organizationName") or iss.get("commonName", "n/a")
        sc.cert = {"subject": subj.get("commonName"), "issuer": issuer, "valid_from": nb.strftime("%Y-%m-%d"),
                   "valid_to": na.strftime("%Y-%m-%d"), "days_remaining": days}
        sc.add("INFO", "TLS Certificate", f"Subject {subj.get('commonName', 'n/a')} | Issuer {issuer} | "
               f"valid {nb:%Y-%m-%d} -> {na:%Y-%m-%d} ({days} days left)", kind="tls", repro=cmd)
        if days < 0:
            sc.add("HIGH", "Certificate Expiry", f"VULNERABLE - certificate EXPIRED {-days} day(s) ago",
                   "Renew immediately and automate renewal (ACME/Let's Encrypt).", "tls", cmd)
        elif days <= 14:
            sc.add("HIGH", "Certificate Expiry", f"VULNERABLE - expires in {days} day(s)",
                   "Renew now and automate renewal.", "tls", cmd)
        elif days <= 30:
            sc.add("MEDIUM", "Certificate Expiry", f"WEAK - expires in {days} days", "Schedule renewal and automate it.", "tls", cmd)
        else:
            sc.add("PASS", "Certificate Expiry", f"SECURE - valid for {days} more days", kind="tls")
        if iss == subj:
            sc.add("HIGH", "Self-signed Certificate", "VULNERABLE - issuer equals subject",
                   "Use a certificate from a trusted public CA.", "tls", cmd)

    sc.protocol, sc.cipher = proto or "", (cipher[0] if cipher else "")
    if proto:
        if proto in ("TLSv1.3", "TLSv1.2"):
            sc.add("PASS", "TLS Protocol", f"SECURE - negotiated {proto}", kind="tls")
        else:
            sc.add("HIGH", "TLS Protocol", f"VULNERABLE - weak protocol negotiated: {proto}",
                   "Disable everything below TLS 1.2.", "tls", cmd)
    if cipher:
        cname, _, bits = cipher
        if re.search(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon", cname, re.I) or (bits and bits < 128):
            sc.add("HIGH", "Cipher Suite", f"VULNERABLE - weak cipher {cname} ({bits} bits)",
                   "Restrict to AEAD suites (AES-GCM, ChaCha20-Poly1305).", "tls", cmd)
        else:
            sc.add("PASS", "Cipher Suite", f"SECURE - {cname} ({bits} bits)", kind="tls")
    for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        res = _probe_proto(host, port, ver)
        if res is True:
            sc.add("HIGH", f"Deprecated {label}", f"VULNERABLE - {label} is enabled",
                   f"Disable {label}; allow TLS 1.2 and 1.3 only.", "tls", cmd)
        elif res is False:
            sc.add("PASS", f"Deprecated {label}", f"SECURE - {label} disabled", kind="tls")


# (path, severity, description, content-validator, fix)
_is_env = lambda b: bool(re.search(rb"^[A-Z0-9_]{3,}\s*=", b, re.M))  # noqa: E731
SENSITIVE = [
    (".git/HEAD", "HIGH", "Git repository exposed (source code leak)",
     lambda b: b.lstrip().startswith(b"ref:") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None,
     "Block /.git/ at the web server and remove it from the web root."),
    (".git/config", "HIGH", "Git config exposed", lambda b: b"[core]" in b,
     "Block /.git/ at the web server and remove it from the web root."),
    (".svn/entries", "HIGH", "SVN metadata exposed", lambda b: re.match(rb"^\d+\s", b) is not None,
     "Remove .svn directories from production."),
    (".env", "HIGH", "Environment file exposed (likely secrets)", _is_env,
     "Move .env outside the web root, deny access, and ROTATE every secret in it."),
    (".htpasswd", "HIGH", "Password file exposed", lambda b: bool(re.search(rb"^[^:\s]+:\$?[A-Za-z0-9./$]+", b, re.M)),
     "Move outside the web root and rotate the credentials."),
    ("wp-config.php.bak", "HIGH", "WordPress config backup exposed", lambda b: b"<?php" in b or b"DB_PASSWORD" in b,
     "Delete backups from the web root; rotate DB credentials."),
    ("config.php.bak", "HIGH", "Config backup exposed", lambda b: b"<?php" in b or b"password" in b.lower(),
     "Delete backups from the web root; rotate credentials."),
    ("backup.sql", "HIGH", "Database dump exposed", lambda b: bool(re.search(rb"CREATE TABLE|INSERT INTO|mysqldump", b, re.I)),
     "Remove dumps from the web root; rotate exposed credentials."),
    ("dump.sql", "HIGH", "Database dump exposed", lambda b: bool(re.search(rb"CREATE TABLE|INSERT INTO|mysqldump", b, re.I)),
     "Remove dumps from the web root; rotate exposed credentials."),
    ("backup.zip", "HIGH", "Backup archive exposed", lambda b: b.startswith(b"PK\x03\x04"),
     "Remove archives from the web root; store backups offline."),
    ("backup.tar.gz", "HIGH", "Backup archive exposed", lambda b: b.startswith(b"\x1f\x8b"),
     "Remove archives from the web root; store backups offline."),
    ("phpinfo.php", "MEDIUM", "phpinfo() page exposed", lambda b: b"phpinfo()" in b or b"PHP Version" in b,
     "Delete phpinfo files from production."),
    ("server-status", "MEDIUM", "Apache server-status exposed", lambda b: b"Apache Server Status" in b,
     "Restrict mod_status to localhost/admin IPs."),
    (".DS_Store", "LOW", "macOS .DS_Store exposed", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"),
     "Remove .DS_Store files and block dotfiles."),
    ("robots.txt", "INFO", "robots.txt present", None, ""),
    ("sitemap.xml", "INFO", "sitemap.xml present", None, ""),
    (".well-known/security.txt", "INFO", "security.txt present (good practice)", None, ""),
]
INTERESTING = re.compile(r"admin|backup|private|secret|config|internal|staging|test|login|db|sql", re.I)


def check_exposed_files(sc: Scan, session, prog):
    p = urlparse(sc.final_url)
    base = f"{p.scheme}://{p.netloc}/"
    baseline = None
    try:
        r, body = fetch_limited(session, base + f"{uuid.uuid4().hex}-nonexistent")
        baseline = (r.status_code, hashlib.md5(body).hexdigest())
    except requests.exceptions.RequestException:
        pass

    def probe(entry):
        path, sev, desc, validator, fix = entry
        try:
            r, body = fetch_limited(session, base + path)
        except requests.exceptions.RequestException:
            return entry, None
        if r.status_code != 200 or not body:
            return entry, None
        if baseline and baseline[0] == 200 and hashlib.md5(body).hexdigest() == baseline[1]:
            return entry, None
        ctype = r.headers.get("Content-Type", "")
        if validator is not None and not validator(body):
            return entry, None
        if validator is None and "text/html" in ctype and path.endswith((".txt", ".xml")):
            return entry, None
        return entry, (len(body), ctype, body)

    hits, done = 0, 0
    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = [pool.submit(probe, e) for e in SENSITIVE]
        for fut in as_completed(futs):
            done += 1
            prog.target = 62 + int(36 * done / len(SENSITIVE))
            entry, res = fut.result()
            if not res:
                continue
            size, ctype, body = res
            path, sev, desc, _, fix = entry
            hits += 1
            # Evidence deliberately excludes file CONTENT (it may hold secrets).
            sc.add(sev, f"/{path}", f"{'VULNERABLE' if sev in ('HIGH', 'MEDIUM', 'LOW') else 'FOUND'} - {desc}", fix, "file",
                   'curl -s -o /dev/null -w "%{http_code}\\n" ' + base + path,
                   f"HTTP 200, {size}+ bytes, {ctype or 'unknown type'}")
            if path == "robots.txt":
                dis = [l.split(":", 1)[1].strip() for l in body.decode("utf-8", "replace").splitlines()
                       if l.lower().startswith("disallow:")]
                juicy = [d for d in dis if d and INTERESTING.search(d)]
                if juicy:
                    sc.add("LOW", "robots.txt", "INFO - advertises sensitive-looking paths: " + ", ".join(juicy[:6]),
                           "robots.txt is public; protect these paths with authentication, not obscurity.", "info",
                           f"curl -s {base}robots.txt")
    if not any(f.kind == "file" and f.sev in ("HIGH", "MEDIUM", "LOW") for f in sc.findings):
        sc.add("PASS", "Exposed Files", f"SECURE - none of {len(SENSITIVE)} common sensitive paths exposed", kind="file")


def fingerprint(sc: Scan, body: bytes):
    m = re.search(rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body[:MAX_BODY], re.I)
    if m:
        gen = m.group(1).decode("utf-8", "replace")
        sev = "LOW" if re.search(r"\d+\.\d+", gen) else "INFO"
        sc.add(sev, "Technology Fingerprint", f"INFO - generator meta tag reveals: {gen}",
               "Remove the generator meta tag / hide version numbers." if sev == "LOW" else "",
               "info", f"curl -s {sc.final_url} | grep -i generator")


class Progress:
    def __init__(self):
        self.target = 0
        self.finished = False


def run_scan(sc: Scan, prog: Progress):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    verify = True
    try:
        prog.target = 5
        try:
            r = session.get(sc.url, timeout=TIMEOUT, allow_redirects=True)
        except requests.exceptions.SSLError as exc:
            sc.add("HIGH", "TLS Certificate", f"VULNERABLE - TLS validation failed: {exc}",
                   "Install a valid CA-signed certificate that matches the hostname.", "tls")
            verify = False
            warnings.simplefilter("ignore")
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:  # noqa: BLE001
                pass
            r = session.get(sc.url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        sc.final_url, sc.status, sc.reason = r.url, r.status_code, r.reason
        sc.elapsed_ms = int(r.elapsed.total_seconds() * 1000)
        sc.redirects = [f"{h.status_code} {h.url}" for h in r.history]
        sc.headers = dict(r.headers)
        prog.target = 25
        check_headers(sc, r.headers)
        check_cookies(sc, r)
        fingerprint(sc, r.content)
        prog.target = 35
        check_http_redirect(sc, session)
        prog.target = 45
        p = urlparse(sc.final_url)
        if p.scheme == "https":
            check_tls(sc, p.hostname, p.port or 443)
        prog.target = 62
        check_exposed_files(sc, session, prog)
    except requests.exceptions.ConnectTimeout:
        sc.fatal = f"Connection timed out after {TIMEOUT}s (host unreachable or firewalled)."
    except requests.exceptions.ReadTimeout:
        sc.fatal = f"The server did not respond within {TIMEOUT}s."
    except requests.exceptions.TooManyRedirects:
        sc.fatal = "Too many redirects (possible redirect loop)."
    except requests.exceptions.SSLError as exc:
        sc.fatal = f"SSL/TLS error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        sc.fatal = f"Target unreachable (DNS failure, refused, or reset). Details: {exc}"
    except (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema) as exc:
        sc.fatal = f"Invalid URL: {exc}"
    except requests.exceptions.RequestException as exc:
        sc.fatal = f"Request failed: {exc}"
    except Exception as exc:  # noqa: BLE001 - never crash with a traceback
        sc.fatal = f"Unexpected error: {type(exc).__name__}: {exc}"
    finally:
        prog.target = 100
        prog.finished = True


def draw_bar(pct, width=30):
    filled = int(width * pct / 100)
    bar = f"{Fore.GREEN}{'█' * filled}{Style.DIM}{'-' * (width - filled)}{Style.RESET_ALL}"
    sys.stdout.write(f"\r{Fore.GREEN}[SCANNING] [{bar}{Fore.GREEN}] {pct}% Completed{Style.RESET_ALL}")
    sys.stdout.flush()


def scan_with_progress(url) -> Scan:
    sc, prog = Scan(url), Progress()
    worker = threading.Thread(target=run_scan, args=(sc, prog), daemon=True)
    worker.start()
    shown = 0
    while shown < 100:
        if shown < prog.target:
            shown += 1
            draw_bar(shown)
            time.sleep(0.02)
        else:
            time.sleep(0.05)
    worker.join()
    print("\n")
    return sc


# --------------------------------------------------------------------------- #
# Terminal output
# --------------------------------------------------------------------------- #
def print_scan(sc: Scan):
    print("=" * 80)
    print(f"{Style.BRIGHT}  TARGET      : {sc.url}\n  FINAL URL   : {sc.final_url}\n"
          f"  HTTP STATUS : {sc.status} {sc.reason}   ({sc.elapsed_ms} ms)")
    if sc.redirects:
        print(f"  REDIRECTS   : {' -> '.join(sc.redirects)}")
    if sc.protocol:
        print(f"  TLS         : {sc.protocol} / {sc.cipher}")
    print("=" * 80 + "\n")
    n = 0
    for f in sc.sorted():
        colour, icon = SEV_UI[f.sev]
        if f.sev == "PASS":
            print(f"{colour}{icon} [PASS]   {f.name}: {f.status}")
            continue
        n += 1
        print(f"\n{colour}{Style.BRIGHT}{icon} [{f.sev}] Finding #{n}{Style.RESET_ALL}")
        print(f"{colour}   Vulnerability Status : {f.status}")
        print(f"{colour}   Header / Check Name  : {f.name}")
        if f.evidence:
            print(f"{colour}   Evidence             : {f.evidence}")
        if f.fix:
            print(f"{colour}   Fix Recommendation   : {f.fix}")
    c = sc.counts()
    letter, score = sc.grade()
    print("\n" + "=" * 80)
    print(f"{Style.BRIGHT}  SUMMARY{Style.RESET_ALL}   Grade: {letter} ({score}/100)")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        print(f"  {SEV_UI[sev][0]}{SEV_UI[sev][1]} {sev:<7}: {c[sev]}")
    print(f"  {Fore.GREEN}🟢 PASSED : {c['PASS']}")
    print("=" * 80 + "\n")


def print_ai_text(text: str, title: str = ""):
    if title:
        print("=" * 80 + f"\n{Style.BRIGHT}{Fore.CYAN}  {title}\n" + "=" * 80)
    in_code = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
            print(f"{Style.DIM}{line}")
        elif in_code:
            print(f"{Fore.WHITE}{line}")
        elif line.lstrip().startswith("#"):
            print(f"{Style.BRIGHT}{Fore.CYAN}{line.lstrip('# ').strip().upper()}")
        else:
            print(line.replace("**", ""))
    print()


# --------------------------------------------------------------------------- #
# Gemini REST client (plain `requests`, no SDK)
# --------------------------------------------------------------------------- #
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


class AIError(Exception):
    pass


class InvalidKeyError(AIError):
    pass


class RateLimitError(AIError):
    def __init__(self, msg, retry_after=None):
        super().__init__(msg)
        self.retry_after = retry_after


class ModelError(AIError):
    """Model missing / unsupported / overloaded - try the next model."""


def gemini_request(method, path, key, payload=None, timeout=15):
    try:
        resp = requests.request(method, f"{GEMINI_BASE}/{path}", json=payload, timeout=timeout,
                                headers={"x-goog-api-key": key, "Content-Type": "application/json"})
    except requests.exceptions.Timeout:
        raise AIError("The AI request timed out.")
    except requests.exceptions.ConnectionError:
        raise AIError("Could not reach the Gemini API (check your internet connection).")
    except requests.exceptions.RequestException as exc:
        raise AIError(f"AI request failed: {exc}")
    if resp.status_code == 200:
        try:
            return resp.json()
        except ValueError:
            raise AIError("Gemini returned an unreadable response.")
    try:
        err = resp.json().get("error", {})
    except ValueError:
        err = {}
    msg, code = err.get("message", ""), resp.status_code
    if code == 401 or (code == 400 and "api key" in msg.lower()):
        raise InvalidKeyError("Invalid API key. Create one at https://aistudio.google.com/app/apikey")
    if code == 403:
        raise AIError("API key rejected (permission denied). Check that the Gemini API is enabled for this key.")
    if code == 429:
        retry = None
        for d in err.get("details", []) or []:
            m = re.match(r"(\d+(?:\.\d+)?)s", str(d.get("retryDelay", "")))
            if m:
                retry = float(m.group(1))
        raise RateLimitError("API quota or rate limit exceeded.", retry)
    if code in (404, 500, 502, 503, 504) or (code == 400 and "not supported" in msg.lower()):
        raise ModelError(f"Model unavailable (HTTP {code}).")
    raise AIError(f"Gemini API error (HTTP {code}): {msg or 'unknown error'}")


def rank_models(names):
    """Best text-capable Gemini models first: stable flash -> flash-lite -> pro, then previews."""
    bad = ("embedding", "tts", "image", "live", "audio", "vision", "robotics", "computer-use", "omni",
           "aqa", "imagen", "veo", "learnlm", "gemma", "native", "thinking")
    ranked = []
    for n in names:
        low = n.lower()
        if "gemini" not in low or any(b in low for b in bad):
            continue
        m = re.search(r"gemini-(\d+(?:\.\d+)?)-(flash-lite|flash|pro)", low)
        if m:
            ver, fam = float(m.group(1)), m.group(2)
        elif "gemini-flash-latest" in low:
            ver, fam = 99.0, "flash"
        elif "gemini-pro-latest" in low:
            ver, fam = 99.0, "pro"
        else:
            continue
        preview = 1 if re.search(r"preview|exp", low) else 0
        ranked.append(((preview, {"flash": 0, "flash-lite": 1, "pro": 2}[fam], -ver, len(low)), n))
    return [n for _, n in sorted(ranked)]


class AIClient:
    def __init__(self, key):
        self.key, self.models, self.idx = key, [], 0

    def connect(self):
        data = gemini_request("GET", "models?pageSize=1000", self.key)
        names = [m["name"] for m in data.get("models", [])
                 if "generateContent" in m.get("supportedGenerationMethods", [])]
        self.models = rank_models(names)
        override = os.environ.get("TONIX_GEMINI_MODEL", "").strip()
        if override:
            self.models.insert(0, override if override.startswith("models/") else f"models/{override}")
        if not self.models:
            raise AIError("No usable Gemini text models are available for this key.")
        return self.models[0]

    @property
    def model(self):
        return self.models[min(self.idx, len(self.models) - 1)]

    def ask(self, contents, system=None, timeout=AI_TIMEOUT):
        payload = {"contents": contents, "generationConfig": {"temperature": 0.4}}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        if self.idx >= len(self.models):
            self.idx = 0
        last = None
        while self.idx < len(self.models):
            for attempt in (1, 2):
                try:
                    data = gemini_request("POST", f"{self.models[self.idx]}:generateContent", self.key, payload, timeout)
                    return self._text(data)
                except RateLimitError as exc:
                    last = exc
                    if attempt == 1 and exc.retry_after and exc.retry_after <= 25:
                        print(f"{Fore.YELLOW}[*] Rate limited - retrying in {int(exc.retry_after) + 1}s...{Style.RESET_ALL}")
                        time.sleep(exc.retry_after + 1)
                        continue
                    break
                except ModelError as exc:
                    last = exc
                    break
            nxt = self.idx + 1
            if nxt < len(self.models):
                print(f"{Fore.YELLOW}[*] Switching AI model -> {self.models[nxt]}{Style.RESET_ALL}")
            self.idx = nxt
        if isinstance(last, RateLimitError):
            raise AIError("Gemini quota/rate limit exceeded on all available models. Wait a minute and retry from the "
                          "menu, or check your quota at https://aistudio.google.com/")
        raise AIError("No Gemini model could answer right now. Try again shortly.")

    @staticmethod
    def _text(data):
        try:
            text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"]).strip()
        except (KeyError, IndexError, TypeError):
            text = ""
        if not text:
            reason = (data.get("promptFeedback") or {}).get("blockReason", "unknown")
            raise AIError(f"The AI returned no text (blocked or empty; reason: {reason}).")
        return text


def find_saved_key():
    if API_KEY.strip():
        return API_KEY.strip(), "script"
    env = os.environ.get("GEMINI_API_KEY", "").strip()
    if env:
        return env, "environment"
    try:
        with open(KEY_FILE, encoding="utf-8") as fh:
            if fh.read().strip():
                fh.seek(0)
                return fh.read().strip(), "saved file"
    except OSError:
        pass
    return None, None


def save_key(key):
    try:
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key)
        print(f"{Fore.GREEN}[+] Key saved to {KEY_FILE} - you will not be asked again.{Style.RESET_ALL}")
    except OSError as exc:
        print(f"{Fore.YELLOW}[!] Could not save the key ({exc}).{Style.RESET_ALL}")


def setup_ai():
    """Return a connected AIClient, or None to continue without AI."""
    key, source = find_saved_key()
    if key:
        print(f"{Fore.CYAN}[*] Using API key from {source}. Validating...{Style.RESET_ALL}")
        client = AIClient(key)
        try:
            print(f"{Fore.GREEN}[+] AI ready. Model: {client.connect()}{Style.RESET_ALL}\n")
            return client
        except InvalidKeyError as exc:
            print(f"{Fore.RED}[ERROR] {exc}\n{Fore.YELLOW}        Saved key is invalid - enter a new one.{Style.RESET_ALL}\n")
        except AIError as exc:
            print(f"{Fore.RED}[ERROR] {exc}\n{Fore.YELLOW}[!] Continuing without AI.{Style.RESET_ALL}\n")
            return None
    for attempt in range(1, 4):
        key = getpass.getpass(f"{Fore.CYAN}[?] Enter Your AI API Key > {Style.RESET_ALL}").strip()
        if not key:
            print(f"{Fore.YELLOW}[!] No key entered - continuing without AI.{Style.RESET_ALL}\n")
            return None
        client = AIClient(key)
        try:
            model = client.connect()
        except AIError as exc:
            print(f"{Fore.RED}[ERROR] {exc}{Style.RESET_ALL}")
            if isinstance(exc, InvalidKeyError) and attempt < 3:
                print(f"{Fore.YELLOW}        Try again ({attempt}/3) or press Enter to skip AI.{Style.RESET_ALL}\n")
                continue
            return None
        print(f"{Fore.GREEN}[+] API key accepted. Model: {model}{Style.RESET_ALL}")
        if not API_KEY.strip():
            save_key(key)
        print()
        return client
    return None


# --------------------------------------------------------------------------- #
# AI prompts
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """You are TONIX AI, a senior defensive web-application security analyst built into a scanning tool.
The user is authorized to assess the target. Rules:
- Base every statement strictly on the SCAN DATA provided. If something was not checked or is unknown, say so. Never invent findings.
- Be honest about severity and about whether bug bounty programs would accept an issue.
- Give remediation (config snippets are welcome) but NEVER exploit code, payloads, or attack instructions beyond
  conceptual impact descriptions.
- Be concise and practical. Reply in the same language/style the user writes in (English, Malayalam, Manglish...)."""


def scan_context(sc: Scan) -> str:
    hdr = "\n".join(f"{k}: {sc.headers[k]}" for k in AI_HEADER_WHITELIST if k in sc.headers) or "(none of the tracked headers)"
    cookies = sc.headers.get("Set-Cookie", "")
    cnote = "none" if not cookies else "present (values redacted)"
    fl = "\n".join(f"- [{f.sev}] {f.name}: {f.status}" + (f" | evidence: {f.evidence}" if f.evidence else "") +
                   (f" | fix: {f.fix}" if f.fix else "") for f in sc.sorted())
    letter, score = sc.grade()
    return (f"TARGET: {sc.url}\nFINAL URL: {sc.final_url}\nHTTP STATUS: {sc.status}\nGRADE: {letter} ({score}/100)\n"
            f"TLS: {sc.protocol} {sc.cipher} | cert: {json.dumps(sc.cert)}\nSET-COOKIE: {cnote}\n\n"
            f"RESPONSE HEADERS (whitelisted):\n{hdr}\n\nFINDINGS:\n{fl}")


def ai_analysis(ai: AIClient, sc: Scan) -> str:
    prompt = (f"{scan_context(sc)}\n\nWrite a concise AI Security Analysis (max ~350 words, mobile-friendly):\n"
              "## Executive Summary\n## Top Risks (prioritised, with realistic conceptual impact)\n## Quick Wins\n"
              "Only use the data above.")
    return ai.ask([{"role": "user", "parts": [{"text": prompt}]}], SYSTEM_PROMPT)


def ai_owner_narrative(ai, sc):
    prompt = (f"{scan_context(sc)}\n\nWrite the narrative sections of a professional Website Security Assessment "
              "report for the website OWNER (non-expert managers + engineers). Use exactly these Markdown headings:\n"
              "## Executive Summary\n## Business Risk Overview\n## Prioritised Remediation Roadmap\n"
              "(Immediate / Within 30 days / Hardening, with Nginx and Apache snippets where relevant)\n"
              "## Verification Steps\nOnly use the data above; do not repeat the raw finding table.")
    return ai.ask([{"role": "user", "parts": [{"text": prompt}]}], SYSTEM_PROMPT)


def ai_bounty_narrative(ai, sc, items):
    names = "\n".join(f"- {f.name}: {f.status}" for f in items)
    prompt = (f"{scan_context(sc)}\n\nFor EACH of these findings write a bug-bounty style analysis:\n{names}\n\n"
              "Use a '### <finding name>' heading per finding, then three short labelled paragraphs: "
              "**Impact** (realistic, conceptual), **Honest Severity** (CVSS-style reasoning, do not inflate), "
              "**Triage Notes** (would typical programs accept it alone? what extra evidence is needed?). No exploit code.")
    return ai.ask([{"role": "user", "parts": [{"text": prompt}]}], SYSTEM_PROMPT)


# --------------------------------------------------------------------------- #
# Report builders (Markdown -> HTML / JSON), with AI-free fallbacks
# --------------------------------------------------------------------------- #
HEADER_SNIPPETS = """# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
server_tokens off;

# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
ServerTokens Prod"""


def issues(sc):
    return [f for f in sc.sorted() if f.sev in ("HIGH", "MEDIUM", "LOW")]


def fallback_owner_narrative(sc):
    letter, score = sc.grade()
    c, top = sc.counts(), issues(sc)[:3]
    top_txt = "; ".join(f"{f.name} ({f.sev})" for f in top) or "no significant issues"
    lines = ["## Executive Summary",
             f"A passive security assessment of {sc.final_url or sc.url} resulted in an overall grade of **{letter} ({score}/100)** "
             f"with {c['HIGH']} high, {c['MEDIUM']} medium and {c['LOW']} low-risk findings. Most important items: {top_txt}.",
             "", "## Prioritised Remediation Roadmap"]
    for label, sevs in (("Immediate (HIGH)", ("HIGH",)), ("Within 30 days (MEDIUM)", ("MEDIUM",)), ("Hardening (LOW)", ("LOW",))):
        items = [f for f in issues(sc) if f.sev in sevs]
        if items:
            lines.append(f"### {label}")
            lines += [f"- **{f.name}** - {f.fix or f.status}" for f in items]
    lines += ["", "### Reference configuration (test CSP in Report-Only mode first)", "```", HEADER_SNIPPETS, "```",
              "", "## Verification Steps",
              "Re-run this tool after changes and confirm headers with `curl -sI " + (sc.final_url or sc.url) + "`."]
    return "\n".join(lines)


def md_findings(sc):
    out, n = [], 0
    for f in issues(sc):
        n += 1
        out += [f"### [{f.sev}] {n}. {f.name}", f"- **Status:** {f.status}"]
        if f.evidence:
            out.append(f"- **Evidence:** {f.evidence}")
        if f.fix:
            out.append(f"- **Recommended fix:** {f.fix}")
        if f.repro:
            out.append(f"- **How to verify:** `{f.repro}`")
        out.append("")
    return "\n".join(out) or "No issues were identified by the automated checks."


def build_owner_md(sc, narrative):
    letter, score = sc.grade()
    c = sc.counts()
    cert = ""
    if sc.cert:
        cert = (f"\n## TLS Certificate\n- Subject: {sc.cert.get('subject')}\n- Issuer: {sc.cert.get('issuer')}\n"
                f"- Valid: {sc.cert.get('valid_from')} to {sc.cert.get('valid_to')} ({sc.cert.get('days_remaining')} days left)\n"
                f"- Negotiated: {sc.protocol} / {sc.cipher}\n")
    passed = "\n".join(f"- {f.name}: {f.status}" for f in sc.sorted() if f.sev == "PASS") or "- (none)"
    hdrs = "\n".join(f"{k}: {sc.headers[k]}" for k in AI_HEADER_WHITELIST if k in sc.headers) or "(none)"
    return f"""# Website Security Assessment Report

- **Target:** {sc.final_url or sc.url}
- **Assessment date:** {sc.started}
- **Prepared by:** TONIX HTTPS v{__version__} (automated, passive assessment)
- **Overall grade:** {letter} ({score}/100)

{narrative}

## Scope & Methodology
Passive, non-intrusive checks only: HTTP response headers, cookies, CORS, redirects, TLS configuration, and
publicly reachable well-known paths (GET requests; no exploitation, no authentication, no brute force, file
contents are never stored). Not covered: business logic, authentication flows, injection testing, server internals.

## Risk Summary
| Severity | Count |
|---|---|
| HIGH | {c['HIGH']} |
| MEDIUM | {c['MEDIUM']} |
| LOW | {c['LOW']} |
| PASSED checks | {c['PASS']} |

## Detailed Findings
{md_findings(sc)}
{cert}
## Passed Checks
{passed}

## Evidence - Response Headers
```
{hdrs}
```

## Disclaimer
Automated results may contain false positives or miss issues. This report is not a full penetration test.
Assessment was performed only against systems the tester is authorized to assess.
"""


def build_bounty_md(sc, narrative, items):
    letter, score = sc.grade()
    parts = [f"# Bug Bounty Submission Draft - {sc.host}\n",
             f"- **Asset:** {sc.final_url or sc.url}\n- **Date tested:** {sc.started}\n"
             f"- **Method:** passive requests only (no exploitation, no data access)\n"
             f"- **Tool:** TONIX HTTPS v{__version__}\n",
             "> Review the program's scope and rules before submitting. Remove any finding that is out of scope.\n"]
    if narrative:
        parts += ["## AI Impact & Triage Analysis", narrative, ""]
    if not items:
        parts.append("No MEDIUM/HIGH findings were identified, so there is nothing worth submitting from this scan.")
    for i, f in enumerate(items, 1):
        note = BOUNTY_NOTE.get(f.kind, BOUNTY_NOTE["info"])
        parts += [f"---\n\n## Report #{i}: {f.name} - {f.status.split(' - ')[-1][:90]}",
                  f"**Vulnerability type:** {f.name}", f"**Affected asset:** {sc.final_url or sc.url}",
                  f"**Suggested severity (honest):** {BOUNTY_SEVERITY.get(f.kind, 'Informational')}  (tool rating: {f.sev})",
                  "", "### Description", f"{f.status}.", "",
                  "### Steps to Reproduce", "1. Run the following command and observe the result:", "```",
                  f.repro or f"curl -sI {sc.final_url}", "```"]
        if f.evidence:
            parts.append(f"2. Observed evidence: {f.evidence}")
        parts += ["", "### Recommended Remediation", f.fix or "See report.", "",
                  "### Triage Note", note, ""]
    return "\n".join(parts)


def md_inline(t):
    t = html.escape(t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)


def md_to_html(md):
    out, lines, i, in_code, lst = [], md.splitlines(), 0, False, None

    def close():
        nonlocal lst
        if lst:
            out.append(f"</{lst}>")
            lst = None

    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("```"):
            close()
            out.append("</code></pre>" if in_code else "<pre><code>")
            in_code = not in_code
            i += 1
            continue
        if in_code:
            out.append(html.escape(lines[i]))
            i += 1
            continue
        if not s:
            close()
            i += 1
            continue
        if s == "---":
            close()
            out.append("<hr>")
            i += 1
            continue
        m = re.match(r"(#{1,4})\s+(.*)", s)
        if m:
            close()
            out.append(f"<h{len(m.group(1))}>{md_inline(m.group(2))}</h{len(m.group(1))}>")
            i += 1
            continue
        if s.startswith("|"):
            close()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            if rows:
                out.append("<div class='tw'><table><thead><tr>" + "".join(f"<th>{md_inline(c)}</th>" for c in rows[0]) +
                           "</tr></thead><tbody>" +
                           "".join("<tr>" + "".join(f"<td>{md_inline(c)}</td>" for c in r) + "</tr>" for r in rows[1:]) +
                           "</tbody></table></div>")
            continue
        m = re.match(r"[-*]\s+(.*)", s)
        if m:
            if lst != "ul":
                close()
                out.append("<ul>")
                lst = "ul"
            out.append(f"<li>{md_inline(m.group(1))}</li>")
            i += 1
            continue
        m = re.match(r"\d+[.)]\s+(.*)", s)
        if m:
            if lst != "ol":
                close()
                out.append("<ol>")
                lst = "ol"
            out.append(f"<li>{md_inline(m.group(1))}</li>")
            i += 1
            continue
        if s.startswith(">"):
            close()
            out.append(f"<blockquote>{md_inline(s.lstrip('> '))}</blockquote>")
            i += 1
            continue
        close()
        out.append(f"<p>{md_inline(s)}</p>")
        i += 1
    close()
    body = "\n".join(out)
    return re.sub(r"\[(HIGH|MEDIUM|LOW|INFO)\]", r"<span class='sev \1'>\1</span>", body)


HTML_TMPL = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#fff;--fg:#1b1f24;--mut:#57606a;--card:#f6f8fa;--bd:#d0d7de;--ac:#0969da}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--ac:#58a6ff}}}}
body{{background:var(--bg);color:var(--fg);font:16px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;max-width:860px;margin:0 auto;padding:20px}}
h1{{border-bottom:2px solid var(--ac);padding-bottom:8px}}h2{{margin-top:2em;border-bottom:1px solid var(--bd);padding-bottom:4px}}
pre{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px;overflow-x:auto;font-size:13px}}
code{{background:var(--card);padding:1px 5px;border-radius:4px;font-size:90%}}pre code{{background:none;padding:0}}
.tw{{overflow-x:auto}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid var(--bd);padding:6px 10px;text-align:left}}th{{background:var(--card)}}
blockquote{{border-left:4px solid var(--ac);margin:1em 0;padding:4px 12px;color:var(--mut)}}
.sev{{color:#fff;border-radius:4px;padding:1px 8px;font-size:80%;font-weight:700}}
.HIGH{{background:#cf222e}}.MEDIUM{{background:#bf8700}}.LOW{{background:#1a7f37}}.INFO{{background:#0969da}}
@media print{{body{{max-width:none}}}}
</style></head><body>
{body}
</body></html>"""


def reports_dir():
    dl = os.path.expanduser("~/storage/downloads")
    base = dl if os.path.isdir(dl) and os.access(dl, os.W_OK) else os.getcwd()
    d = os.path.join(base, "tonix_reports")
    os.makedirs(d, exist_ok=True)
    return d


def save_report(sc, label, md):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = os.path.join(reports_dir(), f"tonix_{re.sub(r'[^A-Za-z0-9.-]', '_', sc.host)}_{label}_{stamp}")
    paths = []
    with open(stem + ".md", "w", encoding="utf-8") as fh:
        fh.write(md)
    paths.append(stem + ".md")
    title = md.splitlines()[0].lstrip("# ").strip()
    with open(stem + ".html", "w", encoding="utf-8") as fh:
        fh.write(HTML_TMPL.format(title=html.escape(title), body=md_to_html(md)))
    paths.append(stem + ".html")
    with open(stem + ".json", "w", encoding="utf-8") as fh:
        json.dump({"tool": f"TONIX HTTPS {__version__}", "report": label, "scan": asdict(sc),
                   "grade": "%s (%s/100)" % sc.grade()}, fh, indent=2, default=str)
    paths.append(stem + ".json")
    return paths


def show_saved(paths):
    print(f"{Fore.GREEN}[+] Report saved:{Style.RESET_ALL}")
    for p in paths:
        print(f"    {p}")
    print(f"{Fore.CYAN}    Open the .html file in your browser (Share / Print -> Save as PDF to send it).")
    print(f"    Termux: run `termux-setup-storage` once so reports save to your Downloads folder.{Style.RESET_ALL}\n")


# --------------------------------------------------------------------------- #
# Menu actions
# --------------------------------------------------------------------------- #
def generate_owner_report(ai, sc, cache):
    narrative = cache.get("owner")
    if not narrative and ai:
        print(f"{Fore.CYAN}[*] AI is writing the report narrative...{Style.RESET_ALL}")
        try:
            narrative = cache["owner"] = ai_owner_narrative(ai, sc)
        except AIError as exc:
            print(f"{Fore.YELLOW}[!] AI unavailable ({exc}) - using built-in report text.{Style.RESET_ALL}")
    show_saved(save_report(sc, "owner_report", build_owner_md(sc, narrative or fallback_owner_narrative(sc))))


def generate_bounty_report(ai, sc, cache):
    items = [f for f in issues(sc) if f.sev in ("HIGH", "MEDIUM")]
    narrative = cache.get("bounty")
    if items and not narrative and ai:
        print(f"{Fore.CYAN}[*] AI is writing impact & triage analysis...{Style.RESET_ALL}")
        try:
            narrative = cache["bounty"] = ai_bounty_narrative(ai, sc, items)
        except AIError as exc:
            print(f"{Fore.YELLOW}[!] AI unavailable ({exc}) - using built-in triage notes.{Style.RESET_ALL}")
    show_saved(save_report(sc, "bounty_report", build_bounty_md(sc, narrative, items)))


def chat_mode(ai, sc):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== TONIX AI CHAT ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Ask anything about this scan (e.g. 'how do I fix CSP?', 'which finding first?').")
    print(f"Commands: /exit = back to menu, /clear = reset chat{Style.RESET_ALL}\n")
    system = SYSTEM_PROMPT + "\n\nSCAN DATA:\n" + scan_context(sc)
    history = []
    while True:
        try:
            flush_stdin()
            msg = input(f"{Fore.CYAN}[you] > {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if not msg:
            continue
        if msg.lower() in ("/exit", "/back", "exit", "back", "/menu"):
            return
        if msg.lower() == "/clear":
            history.clear()
            print(f"{Fore.GREEN}[+] Chat cleared.{Style.RESET_ALL}")
            continue
        history.append({"role": "user", "parts": [{"text": msg}]})
        try:
            print(f"{Fore.CYAN}[*] thinking...{Style.RESET_ALL}")
            reply = ai.ask(history[-20:], system)
        except AIError as exc:
            print(f"{Fore.RED}[ERROR] {exc}{Style.RESET_ALL}\n")
            history.pop()
            continue
        history.append({"role": "model", "parts": [{"text": reply}]})
        print(f"{Fore.GREEN}{Style.BRIGHT}[AI]{Style.RESET_ALL}")
        print_ai_text(reply)


def menu(ai, sc, cache):
    while True:
        print(f"{Style.BRIGHT}{Fore.CYAN}==================== MENU ===================={Style.RESET_ALL}")
        print(" [1] Chat with AI about this scan")
        print(" [2] Website-Owner report  (MD + HTML + JSON)")
        print(" [3] Bug-Bounty submission report")
        print(" [4] Generate ALL reports")
        print(" [5] Re-run AI analysis")
        print(" [6] Scan another target")
        print(" [0] Exit")
        try:
            flush_stdin()
            ch = input(f"{Fore.CYAN}Choose > {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            return "exit"
        if ch == "1":
            if ai:
                chat_mode(ai, sc)
            else:
                print(f"{Fore.YELLOW}[!] AI is not available (no valid API key).{Style.RESET_ALL}\n")
        elif ch == "2":
            generate_owner_report(ai, sc, cache)
        elif ch == "3":
            generate_bounty_report(ai, sc, cache)
        elif ch == "4":
            generate_owner_report(ai, sc, cache)
            generate_bounty_report(ai, sc, cache)
        elif ch == "5":
            if not ai:
                print(f"{Fore.YELLOW}[!] AI is not available.{Style.RESET_ALL}\n")
                continue
            try:
                print(f"{Fore.CYAN}[*] AI analyzing...{Style.RESET_ALL}")
                cache["analysis"] = ai_analysis(ai, sc)
                print_ai_text(cache["analysis"], "AI SECURITY ANALYSIS")
            except AIError as exc:
                print(f"{Fore.RED}[ERROR] {exc}{Style.RESET_ALL}\n")
        elif ch == "6":
            return "again"
        elif ch == "0":
            return "exit"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    print_banner()
    if "--reset-key" in sys.argv:
        try:
            os.remove(KEY_FILE)
            print(f"{Fore.GREEN}[+] Saved API key removed.{Style.RESET_ALL}\n")
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] No saved key found.{Style.RESET_ALL}\n")
        except OSError as exc:
            print(f"{Fore.RED}[ERROR] {exc}{Style.RESET_ALL}\n")

    try:
        ai = setup_ai()
        while True:
            url = ask_url()
            if not url:
                print(f"{Fore.RED}[ERROR] No valid URL entered.{Style.RESET_ALL}")
                return 2
            print()
            sc = scan_with_progress(url)
            if sc.fatal and not sc.status:
                print(f"{Fore.RED}{Style.BRIGHT}[ERROR] {sc.fatal}{Style.RESET_ALL}\n")
                if input(f"{Fore.CYAN}Try another target? (y/n) > {Style.RESET_ALL}").strip().lower().startswith("y"):
                    continue
                return 2
            if sc.fatal:
                print(f"{Fore.YELLOW}[!] Scan finished with a problem: {sc.fatal}{Style.RESET_ALL}")
            print_scan(sc)
            cache = {}
            if ai:
                print(f"{Fore.CYAN}[*] AI is analyzing the scan...{Style.RESET_ALL}\n")
                try:
                    cache["analysis"] = ai_analysis(ai, sc)
                    print_ai_text(cache["analysis"], "AI SECURITY ANALYSIS")
                except AIError as exc:
                    print(f"{Fore.RED}[ERROR] AI analysis failed: {exc}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}        The scan above is still valid. Retry from the menu [5].{Style.RESET_ALL}\n")
            if menu(ai, sc, cache) == "exit":
                break
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}")
        return 130
    except EOFError:
        print(f"\n{Fore.YELLOW}[!] Input closed.{Style.RESET_ALL}")
        return 130
    print(f"{Fore.GREEN}Stay safe - only test what you are authorized to test.{Style.RESET_ALL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
