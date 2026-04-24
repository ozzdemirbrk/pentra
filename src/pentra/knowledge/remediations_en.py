"""Detailed English remediation guides.

Each finding type has a 5-section step-by-step guide:
    1. **Problem summary** — repeats the title
    2. **Why it matters** — risk context + attack scenario
    3. **How to fix** — server variants (Nginx/Apache/IIS/Cloudflare)
    4. **Verification** — post-fix test command
    5. **References** — links to trusted documentation

The report template offers these guides as a "Show detailed guide" collapsible
card. If no guide is defined for a finding, the short `remediation` string is
used instead.
"""

from __future__ import annotations

from collections.abc import Callable

from pentra.models import Finding

# Reuse shared dataclass definitions from the TR module (single source of truth)
from pentra.knowledge.remediations_tr import FixStep, RemediationGuide, _TitleMatcher

# =====================================================================
# Guides
# =====================================================================
_CSP_GUIDE = RemediationGuide(
    problem_summary="The Content-Security-Policy (CSP) header is missing from the response.",
    why_important=(
        "CSP is the most effective browser-level defense against XSS and data "
        "injection attacks. Without the header, if an attacker injects payload "
        "the browser will execute every incoming script indiscriminately. "
        "Attack scenario: if there is an XSS vulnerability in a form, a link "
        "clicked by the victim can steal cookies/sessions. CSP can prevent this."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "Add to the `server` block in `nginx.conf` or the relevant site file. "
            "Start with Report-Only first, monitor errors, then enforce:",
            code=(
                "add_header Content-Security-Policy-Report-Only "
                '"default-src \'self\'; '
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                'report-uri /csp-report" always;'
            ),
        ),
        FixStep(
            "Apache",
            "Add to `httpd.conf` or `.htaccess`:",
            code=(
                'Header always set Content-Security-Policy-Report-Only '
                '"default-src \'self\'; script-src \'self\'; '
                'style-src \'self\' \'unsafe-inline\'"'
            ),
        ),
        FixStep(
            "IIS (web.config)",
            "Add under `<system.webServer><httpProtocol><customHeaders>`:",
            code=(
                '<add name="Content-Security-Policy" value="default-src \'self\'; '
                'script-src \'self\'; style-src \'self\' \'unsafe-inline\'" />'
            ),
        ),
        FixStep(
            "Cloudflare Dashboard",
            "Rules → Transform Rules → Modify Response Header → set "
            "`Content-Security-Policy`. This is applied at the CDN level and "
            "can be configured without touching the origin server.",
        ),
    ),
    verification=(
        "Verify the fix: `curl -I https://yoursite.com | grep -i "
        "content-security-policy` should show the header. In the browser, "
        "DevTools → Network → select the request → Response Headers."
    ),
    references=(
        ("MDN CSP", "https://developer.mozilla.org/docs/Web/HTTP/CSP"),
        ("OWASP CSP Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
        ("CSP Evaluator", "https://csp-evaluator.withgoogle.com/"),
    ),
)

_HSTS_GUIDE = RemediationGuide(
    problem_summary="The Strict-Transport-Security (HSTS) header is missing.",
    why_important=(
        "Without HSTS, the browser may try to connect over HTTP instead of "
        "HTTPS on the first visit. An on-path attacker (cafe Wi-Fi, fellow "
        "passenger) can intercept that first HTTP request and perform an SSL "
        "stripping attack — the user sees a fake HTTP site, enters their "
        "password, and the attacker reads it. HSTS tells the browser to "
        "ALWAYS use HTTPS on this domain."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "Only in the HTTPS server block, for includeSubDomains + preload:",
            code=(
                'add_header Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains; preload" always;'
            ),
        ),
        FixStep(
            "Apache",
            "Inside `<VirtualHost *:443>` in `httpd.conf`:",
            code=(
                'Header always set Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains; preload"'
            ),
        ),
        FixStep(
            "IIS (web.config)",
            "Under customHeaders for the site with HTTPS binding:",
            code=(
                '<add name="Strict-Transport-Security" '
                'value="max-age=31536000; includeSubDomains; preload" />'
            ),
        ),
        FixStep(
            "Cloudflare",
            "SSL/TLS → Edge Certificates → HSTS → 'Enable HSTS'. "
            "Max Age: 12 months, Include Subdomains: on, Preload: on. "
            "Cloudflare applies it automatically.",
        ),
    ),
    verification=(
        "`curl -I https://yoursite.com | grep -i strict-transport` should show "
        "`max-age=31536000`. To apply for the HSTS preload list: "
        "https://hstspreload.org"
    ),
    references=(
        ("MDN HSTS", "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"),
        ("HSTS Preload", "https://hstspreload.org/"),
    ),
)

_XFO_GUIDE = RemediationGuide(
    problem_summary="The X-Frame-Options header is missing — exposed to clickjacking.",
    why_important=(
        "Without this header, an attacker can embed your site in an invisible "
        "iframe and trick the user into clicking a fake button that actually "
        "triggers an unwanted action on your site (this is called "
        "**clickjacking**). Example: the user thinks they are clicking 'Get a "
        "free gift' but they are actually clicking 'Delete account' on your site."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "",
            code='add_header X-Frame-Options "SAMEORIGIN" always;',
        ),
        FixStep(
            "Apache",
            "",
            code='Header always set X-Frame-Options "SAMEORIGIN"',
        ),
        FixStep(
            "IIS (web.config)",
            "",
            code='<add name="X-Frame-Options" value="SAMEORIGIN" />',
        ),
        FixStep(
            "Modern Alternative — CSP frame-ancestors",
            "Using CSP instead of (or alongside) X-Frame-Options is preferred "
            "in modern browsers:",
            code="Content-Security-Policy: frame-ancestors 'self';",
        ),
    ),
    verification=(
        "`curl -I https://yoursite.com | grep -i x-frame` → should return "
        "`X-Frame-Options: SAMEORIGIN`."
    ),
    references=(
        ("MDN X-Frame-Options", "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"),
        ("OWASP Clickjacking", "https://owasp.org/www-community/attacks/Clickjacking"),
    ),
)

_XCTO_GUIDE = RemediationGuide(
    problem_summary="The X-Content-Type-Options header is missing — MIME sniffing risk.",
    why_important=(
        "Browsers sometimes ignore the `Content-Type` header and guess what "
        "the file is based on its content (MIME sniffing). In this case, an "
        "attacker could have a file uploaded as `.jpg` executed as a script "
        "by the browser. The `nosniff` directive disables this behavior — "
        "the browser uses the content-type the server declares."
    ),
    fix_steps=(
        FixStep("Nginx", "", code='add_header X-Content-Type-Options "nosniff" always;'),
        FixStep("Apache", "", code='Header always set X-Content-Type-Options "nosniff"'),
        FixStep("IIS (web.config)", "", code='<add name="X-Content-Type-Options" value="nosniff" />'),
        FixStep(
            "Django", "Added via middleware (default in 3.0+):",
            code='SECURE_CONTENT_TYPE_NOSNIFF = True',
        ),
    ),
    verification="`curl -I https://yoursite.com | grep -i x-content-type` → should show `nosniff`.",
    references=(
        ("MDN X-Content-Type-Options", "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ),
)

_REFERRER_GUIDE = RemediationGuide(
    problem_summary="The Referrer-Policy header is missing — referer information is leaking.",
    why_important=(
        "When a user navigates from your site to another site via a link, by "
        "default the browser tells the target site which page they came from "
        "(the `Referer` header). If the URL contains sensitive data (session "
        "token, search query, ID, etc.) this leaks to third parties. "
        "`Referrer-Policy` restricts this behavior."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "`strict-origin-when-cross-origin` is balanced (same site: full "
            "URL, different site: origin only):",
            code='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        ),
        FixStep(
            "Apache", "",
            code='Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        ),
        FixStep("IIS (web.config)", "",
            code='<add name="Referrer-Policy" value="strict-origin-when-cross-origin" />'),
    ),
    verification="`curl -I https://yoursite.com | grep -i referrer-policy`",
    references=(
        ("MDN Referrer-Policy", "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"),
    ),
)

_SERVER_LEAK_GUIDE = RemediationGuide(
    problem_summary="The server version is leaked via the `Server` header.",
    why_important=(
        "An attacker uses this information to learn the target's exact "
        "version and try version-specific CVEs/exploits. Example: an attacker "
        "seeing `Server: Apache/2.4.41` will look up known vulnerabilities in "
        "2.4.41. Hiding the version does not add real security (defense in "
        "depth) but it shrinks the reconnaissance surface — the attacker has "
        "to guess."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "In the `http` block (in the main `nginx.conf`):",
            code="server_tokens off;",
        ),
        FixStep(
            "Apache",
            "In `httpd.conf`:",
            code="ServerTokens Prod\nServerSignature Off",
        ),
        FixStep(
            "IIS",
            "Remove the Server header in `web.config` via the URL Rewrite module. "
            "Or use `<security><requestFiltering removeServerHeader=\"true\" />`:",
            code='<system.webServer>\n  <security>\n    <requestFiltering removeServerHeader="true" />\n  </security>\n</system.webServer>',
        ),
        FixStep(
            "Cloudflare",
            "Rules → Transform Rules → Modify Response Header → Remove → `Server`. "
            "The origin server's header is removed at the CDN layer.",
        ),
    ),
    verification="`curl -I https://yoursite.com | grep -i '^server:'` should show only minimal information like `Server: nginx`, with no version number.",
    references=(
        ("Nginx server_tokens", "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"),
        ("Apache ServerTokens", "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"),
    ),
)

_HTTP_ONLY_GUIDE = RemediationGuide(
    problem_summary="The site is served over HTTP (unencrypted).",
    why_important=(
        "HTTP traffic can be read by anyone eavesdropping on the network — "
        "passwords, cookies, form data are exposed. Modern browsers now mark "
        "HTTP sites as 'Not Secure'. On the SEO side, Google uses HTTPS as a "
        "ranking factor. Migrating to HTTPS is no longer optional."
    ),
    fix_steps=(
        FixStep(
            "Obtaining a certificate (Let's Encrypt — Free)",
            "Automatic installation via `certbot` + 90-day automatic renewal:",
            code="sudo apt install certbot python3-certbot-nginx\n"
                 "sudo certbot --nginx -d yoursite.com -d www.yoursite.com",
        ),
        FixStep(
            "Nginx — 301 redirect from HTTP to HTTPS",
            "",
            code="server {\n"
                 "    listen 80;\n"
                 "    server_name yoursite.com www.yoursite.com;\n"
                 '    return 301 https://$server_name$request_uri;\n'
                 "}",
        ),
        FixStep(
            "Apache — redirect via mod_rewrite",
            "In `.htaccess` or a VirtualHost:",
            code="RewriteEngine On\n"
                 "RewriteCond %{HTTPS} !=on\n"
                 "RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]",
        ),
        FixStep(
            "Cloudflare — One Click",
            "SSL/TLS → Edge Certificates → 'Always Use HTTPS' → On. "
            "Cloudflare redirects all HTTP requests to HTTPS. "
            "A free certificate is included.",
        ),
    ),
    verification=(
        "`curl -I http://yoursite.com` → should return a `301` response with "
        "`Location: https://...`. In the browser, typing the HTTP URL should "
        "automatically switch to HTTPS."
    ),
    references=(
        ("Let's Encrypt", "https://letsencrypt.org/"),
        ("Mozilla SSL Config Generator", "https://ssl-config.mozilla.org/"),
    ),
)

_SECURITY_TXT_GUIDE = RemediationGuide(
    problem_summary="The /.well-known/security.txt file is missing.",
    why_important=(
        "When security researchers find a vulnerability, they need to know "
        "how to reach you. The `security.txt` standard (RFC 9116) lets "
        "researchers automatically discover your security contact. Without "
        "the file, a researcher either tries to find you via social media "
        "(may get lost) or posts publicly (worse). A small file makes a "
        "big difference."
    ),
    fix_steps=(
        FixStep(
            "Content",
            "Publish the following as `/.well-known/security.txt`:",
            code="Contact: mailto:security@yoursite.com\n"
                 "Expires: 2027-01-01T00:00:00Z\n"
                 "Preferred-Languages: en, tr\n"
                 "Canonical: https://yoursite.com/.well-known/security.txt",
        ),
        FixStep(
            "Web Server Configuration",
            "Place the file in the `/.well-known/` directory. The path works "
            "out of the box on most servers — Nginx/Apache serve it as a "
            "static file. Content-Type must be text/plain.",
        ),
    ),
    verification="`curl https://yoursite.com/.well-known/security.txt` should return the content (200 + text/plain).",
    references=(
        ("RFC 9116 (security.txt)", "https://www.rfc-editor.org/rfc/rfc9116.html"),
        ("securitytxt.org", "https://securitytxt.org/"),
    ),
)

_REDIS_OPEN_GUIDE = RemediationGuide(
    problem_summary="The Redis server is accessible without a password.",
    why_important=(
        "If Redis is open without auth, an attacker can read and delete all "
        "data. Worse: by combining `CONFIG SET dir /home/redis/.ssh` + "
        "`CONFIG SET dbfilename authorized_keys` + `SET x \"ssh-rsa...\"` + "
        "`SAVE`, they can write an SSH key on the server and take full "
        "control. Since 2017, thousands of internet-exposed Redis instances "
        "have fallen victim to ransomware."
    ),
    fix_steps=(
        FixStep(
            "1. Strong password + localhost bind",
            "Edit `/etc/redis/redis.conf` and restart Redis:",
            code="# Access only from localhost\n"
                 "bind 127.0.0.1 ::1\n"
                 "# Strong password — 32+ characters, random\n"
                 'requirepass "<64 character random string>"\n'
                 "# Keep protected mode enabled\n"
                 "protected-mode yes\n"
                 "# Disable dangerous commands\n"
                 'rename-command FLUSHDB ""\n'
                 'rename-command FLUSHALL ""\n'
                 'rename-command CONFIG ""',
        ),
        FixStep(
            "2. Use ACL (Redis 6+)",
            "Modern approach — separate user per application:",
            code="ACL SETUSER myapp on >strong_password ~myapp:* +@read +@write -@dangerous",
        ),
        FixStep(
            "3. Firewall",
            "If remote Redis is needed (cloud), only from application IPs:",
            code="sudo ufw allow from <app_ip> to any port 6379\n"
                 "sudo ufw deny 6379",
        ),
        FixStep(
            "4. TLS",
            "Redis 6+ supports TLS — mandatory in production:",
            code="tls-port 6380\n"
                 "tls-cert-file /path/to/cert.pem\n"
                 "tls-key-file /path/to/key.pem",
        ),
    ),
    verification=(
        "`redis-cli -h <ip> PING` without a password should return a "
        "NOAUTH error. With the password, `redis-cli -a <password> PING` → PONG."
    ),
    references=(
        ("Redis Security", "https://redis.io/docs/management/security/"),
        ("Redis ACL", "https://redis.io/docs/management/security/acl/"),
    ),
)

_MONGODB_OPEN_GUIDE = RemediationGuide(
    problem_summary="The MongoDB server is accessible without a password.",
    why_important=(
        "Before MongoDB 3.6, auth was DISABLED by default — millions of old "
        "instances are still exposed. Without auth, an attacker can read and "
        "delete all collections. Since 2017, 'MongoDB ransomware' attacks "
        "have been very common: the attacker deletes all data and leaves a "
        "'send bitcoin to recover' message."
    ),
    fix_steps=(
        FixStep(
            "1. Admin user + enable auth",
            "Start MongoDB without `--auth`, create the admin, then restart with `--auth`:",
            code='mongosh\n'
                 'use admin\n'
                 'db.createUser({\n'
                 '  user: "admin",\n'
                 '  pwd: "<strong-password>",\n'
                 '  roles: [{ role: "root", db: "admin" }]\n'
                 '})',
        ),
        FixStep(
            "2. Config file",
            "`/etc/mongod.conf`:",
            code="security:\n"
                 "  authorization: enabled\n"
                 "net:\n"
                 "  bindIp: 127.0.0.1  # Only localhost\n"
                 "  port: 27017",
        ),
        FixStep(
            "3. Restart + test",
            "",
            code="sudo systemctl restart mongod\n"
                 "mongosh  # connection without auth should now be rejected for most commands",
        ),
        FixStep(
            "4. Separate user per application",
            "The root user is for administration only. Minimum-privilege user per application:",
            code='use mydatabase\n'
                 'db.createUser({\n'
                 '  user: "myapp",\n'
                 '  pwd: "<app-password>",\n'
                 '  roles: [{ role: "readWrite", db: "mydatabase" }]\n'
                 '})',
        ),
    ),
    verification=(
        "Running `mongosh --host <ip>` without auth and then `show dbs` "
        "should return 'command listDatabases requires authentication'."
    ),
    references=(
        ("MongoDB Security Checklist", "https://www.mongodb.com/docs/manual/administration/security-checklist/"),
    ),
)

_ELASTICSEARCH_OPEN_GUIDE = RemediationGuide(
    problem_summary="The Elasticsearch cluster is accessible without a password.",
    why_important=(
        "When ES is open, an attacker can pull all index data via `_search` "
        "and delete data via `DELETE`. Since 2017, ES cluster leaks have "
        "been a leading cause of internet data breaches — millions of user "
        "records, health data, and financial information have leaked this way."
    ),
    fix_steps=(
        FixStep(
            "1. Enable X-Pack Security (free in ES 6.8+)",
            "`elasticsearch.yml`:",
            code="xpack.security.enabled: true\n"
                 "xpack.security.transport.ssl.enabled: true",
        ),
        FixStep(
            "2. Generate passwords",
            "",
            code="cd /usr/share/elasticsearch\n"
                 "bin/elasticsearch-setup-passwords auto",
        ),
        FixStep(
            "3. Bind to localhost (if remote access is not required)",
            "",
            code="network.host: 127.0.0.1\n"
                 "http.port: 9200",
        ),
        FixStep(
            "4. Firewall",
            "",
            code="sudo ufw deny 9200\n"
                 "sudo ufw allow from <app_ip> to any port 9200",
        ),
    ),
    verification=(
        "`curl http://<ip>:9200/` unauthenticated should return a "
        "`missing authentication credentials` error. "
        "`curl -u elastic:<password> http://<ip>:9200/` should return cluster info."
    ),
    references=(
        ("Elastic Security", "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html"),
    ),
)

_MYSQL_DEFAULT_GUIDE = RemediationGuide(
    problem_summary="MySQL root user is accessible with default/empty password.",
    why_important=(
        "If MySQL root is password-less, an attacker can read, modify, and "
        "delete all databases. With `SELECT ... INTO OUTFILE` they can write "
        "files to the server (via the UDF technique they may even gain full "
        "server access). Running production MySQL with default credentials "
        "is serious negligence."
    ),
    fix_steps=(
        FixStep(
            "1. mysql_secure_installation",
            "Ready-made automated script — changes the root password, removes "
            "anonymous users, the test DB, and remote root access:",
            code="sudo mysql_secure_installation",
        ),
        FixStep(
            "2. Manual — change the root password",
            "",
            code="mysql -u root\n"
                 "mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY '<strong-password>';\n"
                 "mysql> FLUSH PRIVILEGES;",
        ),
        FixStep(
            "3. Remove remote root",
            "Root account accessible only from localhost:",
            code="mysql> DROP USER IF EXISTS 'root'@'%';\n"
                 "mysql> DROP USER IF EXISTS 'root'@'::';\n"
                 "mysql> FLUSH PRIVILEGES;",
        ),
        FixStep(
            "4. Bind to localhost",
            "`/etc/mysql/my.cnf`:",
            code="[mysqld]\n"
                 "bind-address = 127.0.0.1",
        ),
    ),
    verification=(
        "`mysql -u root` without a password should give `Access denied`. "
        "`mysql -u root -p` should let you in when you enter the password."
    ),
    references=(
        ("MySQL Security Guidelines", "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"),
    ),
)

_SSH_DEFAULT_GUIDE = RemediationGuide(
    problem_summary="SSH is accessible with default credentials (root:root / admin:admin).",
    why_important=(
        "SSH brute-force is the most common attack type on the internet — "
        "botnets that try thousands of attempts per second are always "
        "scanning. Leaving SSH open with default credentials means the "
        "server will be compromised within minutes. After compromise: "
        "ransomware, crypto miner installation, botnet enrollment, lateral "
        "movement to neighboring systems."
    ),
    fix_steps=(
        FixStep(
            "1. URGENT — Change the password",
            "",
            code="sudo passwd root   # Long, random, 16+ characters",
        ),
        FixStep(
            "2. RECOMMENDED — Disable SSH password auth entirely, use keys only",
            "`/etc/ssh/sshd_config`:",
            code="PasswordAuthentication no\n"
                 "PermitRootLogin no          # Root cannot log in at all\n"
                 "PubkeyAuthentication yes\n"
                 "ChallengeResponseAuthentication no",
        ),
        FixStep(
            "3. SSH key generation (on the client)",
            "",
            code="# On Windows in PowerShell or Git Bash:\n"
                 "ssh-keygen -t ed25519 -a 100 -C 'email@domain.com'\n"
                 "# Copy the public key to the server:\n"
                 "ssh-copy-id user@server.com",
        ),
        FixStep(
            "4. Install fail2ban — brute-force protection",
            "",
            code="sudo apt install fail2ban\n"
                 "sudo systemctl enable --now fail2ban\n"
                 "# In /etc/fail2ban/jail.local the sshd jail is enabled by default",
        ),
        FixStep(
            "5. Change the SSH port (defense-in-depth)",
            "Port 22 is constantly scanned. A different port like 22xxx reduces "
            "automated attack surface. In `sshd_config`:",
            code="Port 22876   # Pick a random 4-5 digit port",
        ),
    ),
    verification=(
        "`ssh root@server` → should return 'Permission denied (publickey)' "
        "(no password prompt). With a key you should be able to log in."
    ),
    references=(
        ("DigitalOcean SSH Hardening", "https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu"),
        ("Mozilla OpenSSH Guidelines", "https://infosec.mozilla.org/guidelines/openssh"),
    ),
)

_WIFI_OPEN_GUIDE = RemediationGuide(
    problem_summary="Unencrypted (Open) Wi-Fi network detected.",
    why_important=(
        "On unencrypted Wi-Fi all traffic can be eavesdropped by anyone "
        "nearby — passwords, cookies, and form data on non-HTTPS sites are "
        "exposed. An attacker can also spin up a fake access point (Evil "
        "Twin) to lure users and redirect all their traffic. Not setting a "
        "password for guest Wi-Fi is not an option — even guest Wi-Fi must "
        "be encrypted."
    ),
    fix_steps=(
        FixStep(
            "1. Log in to the router admin panel",
            "Open the router IP in the browser (usually **192.168.1.1** or "
            "**192.168.0.1**). Log in with the admin username + password. "
            "If you don't know it, check the sticker on the bottom of the router.",
        ),
        FixStep(
            "2. Enable encryption",
            "In the menu go to **Wireless → Security**. Security mode: "
            "pick **WPA3-Personal** (if available) or **WPA2-Personal (AES/CCMP)**. "
            "NEVER use WEP or 'Open'.",
        ),
        FixStep(
            "3. Set a strong password",
            "At least 12 characters, mixed. A Wi-Fi password is usually "
            "entered once, so make it long. Example structure: combine 3-4 "
            "random words.",
            code="Acceptable: Rainy-Sunday-Cat-Water42!\n"
                 "Very strong: correct-horse-battery-staple-99",
        ),
        FixStep(
            "4. Set up a guest network",
            "Modern routers have a 'Guest Network' feature — enable it. "
            "Guests connect to this network and don't have access to your "
            "main network. This way a guest's malware-infected device "
            "cannot reach your smart TV or printer.",
        ),
        FixStep(
            "5. Disable WPS",
            "WPS (the 'easy connect' button) is vulnerable to brute-force "
            "attacks. Disable WPS in the router settings — modern devices "
            "already connect more securely via QR code.",
        ),
    ),
    verification=(
        "View the Wi-Fi settings — a lock icon should appear next to the "
        "network. Try connecting with a new device; it should prompt for a password."
    ),
    references=(
        ("EFF: Create a Strong Password", "https://ssd.eff.org/module/creating-new-password"),
        ("CISA: Secure Wireless Networks", "https://www.cisa.gov/news-events/news/securing-wireless-networks"),
    ),
)

_WIFI_WEP_GUIDE = RemediationGuide(
    problem_summary="Wi-Fi network with WEP encryption — broken algorithm.",
    why_important=(
        "WEP encryption has been broken since 2007. A modern laptop + "
        "aircrack-ng can recover the WEP key in minutes. This network "
        "should be considered effectively unencrypted — an attacker can "
        "join the network and reach internal systems (printer, NAS, "
        "smart home devices)."
    ),
    fix_steps=(
        FixStep(
            "URGENT — Disable WEP, switch to WPA2/3",
            "Router admin panel → Wireless → Security: "
            "**WPA2-Personal (AES)** or **WPA3-Personal**. Never leave WEP.",
        ),
        FixStep(
            "Separate network for legacy devices",
            "If your old Wi-Fi devices do not support WPA2, set up a "
            "separate Guest Network for them — keep your main network on "
            "WPA2/3. Or replace the old devices.",
        ),
        FixStep(
            "Is the router modern?",
            "Pre-2010 routers don't support WPA3, and some don't even "
            "support WPA2 well. Buying a new router (50-150 USD) is a "
            "good investment. Wi-Fi 6 (802.11ax) capable models are preferred.",
        ),
    ),
    verification="Wi-Fi settings → security type should say 'WPA2' or 'WPA3', not 'WEP'.",
    references=(
        ("Aircrack-ng tutorial", "https://www.aircrack-ng.org/doku.php?id=tutorial"),
    ),
)

_WIFI_OLD_WPA_GUIDE = RemediationGuide(
    problem_summary="Legacy WPA (TKIP) encrypted network — weaker than WPA2.",
    why_important=(
        "The original WPA (with TKIP) arrived in 2004 but its weaknesses "
        "have been known since 2012. Migrating to WPA2 (AES/CCMP) is "
        "required for security. TKIP is more exposed to brute-force and "
        "packet injection attacks than WPA2-AES."
    ),
    fix_steps=(
        FixStep(
            "Switch to WPA2 or WPA3",
            "Router panel → Wireless → Security: **WPA2-Personal (AES/CCMP)** "
            "or **WPA3-Personal**. DO NOT USE mixed mode (WPA/WPA2) — "
            "pick WPA2 only or WPA3 only.",
        ),
        FixStep(
            "Refresh the password",
            "When moving from WPA to WPA2/3, also change the password — "
            "the old password was part of the old security model.",
        ),
    ),
    verification="Wi-Fi settings → should say 'WPA2' or 'WPA3', not 'WPA' alone.",
    references=(
        ("Cisco: WPA vs WPA2 vs WPA3", "https://www.cisco.com/c/en/us/products/wireless/what-is-wpa3.html"),
    ),
)

_EXPOSED_ENV_GUIDE = RemediationGuide(
    problem_summary=".env file accessible from the web root — critical secrets exposed.",
    why_important=(
        ".env files typically contain DB passwords, API keys, and secret "
        "keys. This file should not be under the web root — but due to "
        "incorrect deployment it often ends up there. An attacker can "
        "`curl https://yoursite.com/.env` and download all secrets, then "
        "quickly access your database, email provider, and AWS account."
    ),
    fix_steps=(
        FixStep(
            "1. URGENT — Move the file out of the web root",
            "",
            code="# On the server:\n"
                 "mv /var/www/html/.env /var/www/.env   # ONE level ABOVE the web root",
        ),
        FixStep(
            "2. ROTATE all secrets (assume leaked)",
            "If .env was seen, assume the attacker has it. Reset all "
            "passwords, API keys, and secret keys:",
            code="# DB password\nALTER USER webapp WITH PASSWORD '<new-password>';\n"
                 "# Laravel APP_KEY regenerate\nphp artisan key:generate\n"
                 "# Rotate AWS credentials (from the IAM console)",
        ),
        FixStep(
            "Nginx — block access as a backup",
            "Last-resort defense if a deploy bug happens again:",
            code="location ~ /\\.env {\n    deny all;\n    return 404;\n}",
        ),
        FixStep(
            "Apache — with .htaccess",
            "",
            code='<FilesMatch "^\\.env">\n'
                 '    Require all denied\n'
                 '</FilesMatch>',
        ),
    ),
    verification=(
        "`curl https://yoursite.com/.env` → should return 404 or 403, not the file content."
    ),
    references=(
        ("OWASP: Sensitive Data Exposure", "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"),
        ("12-Factor App — Config", "https://12factor.net/config"),
    ),
)

_SQL_INJECTION_GUIDE = RemediationGuide(
    problem_summary="SQL Injection vulnerability — parameter is concatenated into the SQL query as a raw string.",
    why_important=(
        "SQL injection is one of the most critical vulnerabilities in web "
        "applications (OWASP Top 10 #3). With specially crafted input, an "
        "attacker can bypass login, pull the entire DB content (`UNION "
        "SELECT`), create privileged users, and even (with the right "
        "privileges) run commands on the server. Since 2011 it has been "
        "the most common data breach vector."
    ),
    fix_steps=(
        FixStep(
            "PRIMARY — Parameterized queries (prepared statements)",
            "ALWAYS use parameter binding INSTEAD of string concatenation:",
            code="# WRONG (vulnerable to SQLi)\n"
                 "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
                 "# CORRECT (parameterized)\n"
                 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        ),
        FixStep(
            "Use an ORM",
            "SQLAlchemy, Django ORM, Prisma, etc. — prefer them over raw "
            "SQL. ORMs parameterize by default.",
            code="# Django\n"
                 "User.objects.filter(id=user_id)  # automatically safe",
        ),
        FixStep(
            "Input validation (defense in depth)",
            "Convert to the expected type, check length. For example, if a "
            "number is expected, cast to int(); if it fails, reject.",
        ),
        FixStep(
            "Database user least-privilege",
            "The application user should have READ/WRITE only on the required "
            "tables. Privileges like DROP, CREATE, GRANT MUST NOT be granted — "
            "this limits the damage of SQLi.",
        ),
        FixStep(
            "WAF (temporary defense)",
            "WAFs such as Cloudflare or ModSecurity block SQLi patterns, but "
            "THEY DO NOT REPLACE FIXING THE CODE — moving to parameterized "
            "queries is mandatory.",
        ),
    ),
    verification=(
        "Re-run the probe after the fix — no SQL error should be returned. "
        "Manual test: `?id=1'` → a normal page or a controlled error, "
        "never 'You have an error in your SQL syntax'."
    ),
    references=(
        ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
        ("Bobby Tables", "https://bobby-tables.com/"),
    ),
)

_XSS_GUIDE = RemediationGuide(
    problem_summary="Reflected XSS — user input is reflected back into the response without escaping.",
    why_important=(
        "The attacker crafts a special URL, the user clicks it, and the "
        "attacker's JS runs in the user's browser: steal session cookies, "
        "show a fake login form, send requests on behalf of the user. It "
        "is the most common path to phishing + account takeover."
    ),
    fix_steps=(
        FixStep(
            "PRIMARY — Context-aware escaping",
            "Escape user input before writing it to HTML. Each context "
            "requires different escaping:",
            code="# HTML body → html.escape\n"
                 "import html\n"
                 "safe = html.escape(user_input)  # < → &lt;\n\n"
                 "# Inside JS string → json.dumps\n"
                 "import json\n"
                 'safe_js = json.dumps(user_input)  # " → \\"',
        ),
        FixStep(
            "Use framework autoescape",
            "Modern frameworks autoescape by default:",
            code="{# Jinja2 — autoescape is on by default #}\n"
                 "<p>{{ user_input }}</p>         {# safe #}\n"
                 "<p>{{ user_input | safe }}</p>  {# DANGEROUS — disables escaping #}\n\n"
                 "// React — JSX escapes by default\n"
                 "<p>{userInput}</p>           // safe\n"
                 "<p dangerouslySetInnerHTML=...>  // DANGEROUS",
        ),
        FixStep(
            "Content Security Policy (CSP)",
            "A CSP header reduces the impact of XSS (blocks inline scripts). "
            "See the missing-CSP guide.",
        ),
        FixStep(
            "HttpOnly + SameSite cookies",
            "Mark the session cookie as HttpOnly + Secure + SameSite — XSS "
            "JS cannot read the cookie.",
            code="Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict",
        ),
    ),
    verification="Re-run the probe — the payload should now come back escaped (&lt; &gt;).",
    references=(
        ("OWASP XSS", "https://owasp.org/www-community/attacks/xss/"),
        ("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    ),
)

_PATH_TRAVERSAL_GUIDE = RemediationGuide(
    problem_summary="Path traversal / directory traversal — the path parameter can escape the directory.",
    why_important=(
        "By sending payloads like `../../etc/passwd` or "
        "`../../../windows/win.ini`, an attacker can read any file the web "
        "application has access to — source code, configuration, session "
        "files, and in some cases even SSH private keys. This opens the "
        "way to full system reconnaissance."
    ),
    fix_steps=(
        FixStep(
            "Allowlist-based filename validation",
            "Specify allowed files and reject the rest:",
            code="ALLOWED = {'product-1.pdf', 'product-2.pdf', ...}\n"
                 "if filename not in ALLOWED:\n"
                 "    return 403",
        ),
        FixStep(
            "Normalize the path with realpath and verify it stays inside the root",
            "The most reliable check:",
            code="from pathlib import Path\n"
                 "allowed_root = Path('/var/www/uploads').resolve()\n"
                 "user_file = (allowed_root / filename).resolve()\n"
                 "if not user_file.is_relative_to(allowed_root):\n"
                 "    return 403   # path traversal attempt",
        ),
        FixStep(
            "Filter ../ and /../ characters (but insufficient alone!)",
            "Not sufficient by itself but an extra layer:",
            code="if '..' in filename or '/' in filename or '\\\\' in filename:\n"
                 "    return 400",
        ),
        FixStep(
            "At the web server level",
            "Nginx — block sensitive directories:",
            code="location ~ \\.\\.\\/ { return 400; }\n"
                 "location /etc { deny all; }",
        ),
    ),
    verification="Re-run the probe: `?file=../../../etc/passwd` → should NOT return `/etc/passwd` content; 400/403 instead.",
    references=(
        ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
    ),
)

_SSL_OLD_PROTOCOL_GUIDE = RemediationGuide(
    problem_summary="Legacy TLS/SSL version (SSLv3/TLSv1.0/TLSv1.1) is supported.",
    why_important=(
        "These versions are exposed to known attacks: POODLE (SSLv3), "
        "BEAST (TLS 1.0), Lucky 13. Modern browsers have dropped support "
        "for TLS 1.0/1.1 since 2020. Leaving them enabled is a problem "
        "both for security and compliance (PCI-DSS, HIPAA)."
    ),
    fix_steps=(
        FixStep(
            "Nginx — TLS 1.2 and 1.3 only",
            "",
            code="ssl_protocols TLSv1.2 TLSv1.3;\n"
                 "ssl_prefer_server_ciphers off;  # for TLS 1.3\n"
                 "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\n"
                 "           ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;",
        ),
        FixStep(
            "Apache",
            "",
            code="SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                 "SSLHonorCipherOrder on\n"
                 "SSLCipherSuite HIGH:!aNULL:!MD5:!3DES",
        ),
        FixStep(
            "IIS (PowerShell)",
            "",
            code="# Disable SSLv3 and legacy TLS\n"
                 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server" -Name Enabled -Value 0\n'
                 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name Enabled -Value 0',
        ),
        FixStep(
            "Cloudflare",
            "SSL/TLS → Edge Certificates → Minimum TLS Version: 1.2.",
        ),
    ),
    verification=(
        "Online test: https://www.ssllabs.com/ssltest/ → under Protocol Support, "
        "TLS 1.0 and 1.1 should be 'No'. Command line: "
        "`openssl s_client -connect yoursite.com:443 -tls1 2>&1 | grep -i error`"
    ),
    references=(
        ("Mozilla SSL Config", "https://ssl-config.mozilla.org/"),
        ("SSL Labs Test", "https://www.ssllabs.com/ssltest/"),
    ),
)

_SSL_CERT_PROBLEM_GUIDE = RemediationGuide(
    problem_summary="SSL certificate validation problem (expired, self-signed, hostname mismatch, etc.).",
    why_important=(
        "The browser shows a 'Your connection is not secure' warning — users "
        "either abandon the site or (worse) become used to clicking past the "
        "warning. The second scenario reduces the user's caution during real "
        "MITM attacks."
    ),
    fix_steps=(
        FixStep(
            "Let's Encrypt (free, automatic renewal)",
            "",
            code="sudo apt install certbot python3-certbot-nginx\n"
                 "sudo certbot --nginx -d yoursite.com -d www.yoursite.com\n"
                 "# Automatic renewal via cron (certbot installs it by default)",
        ),
        FixStep(
            "If the certificate chain is missing",
            "Usually caused by a missing 'intermediate certificate'. "
            "Get fullchain.pem from your CA and point ssl_certificate to it in Nginx:",
            code="ssl_certificate     /etc/letsencrypt/live/yoursite.com/fullchain.pem;\n"
                 "ssl_certificate_key /etc/letsencrypt/live/yoursite.com/privkey.pem;",
        ),
        FixStep(
            "Hostname mismatch",
            "The certificate's SAN (Subject Alternative Name) field must "
            "include all domains in use. Pass every domain with -d to certbot: "
            "`-d yoursite.com -d www.yoursite.com -d api.yoursite.com`.",
        ),
        FixStep(
            "If expired",
            "Let's Encrypt certbot renews automatically. Manual renewal:",
            code="sudo certbot renew --force-renewal",
        ),
    ),
    verification=(
        "In the browser → the address bar should show a lock icon. Command: "
        "`openssl s_client -connect yoursite.com:443 -servername yoursite.com "
        "</dev/null 2>/dev/null | openssl x509 -noout -dates`"
    ),
    references=(
        ("Let's Encrypt", "https://letsencrypt.org/"),
        ("SSL Checker", "https://www.ssllabs.com/ssltest/"),
    ),
)

_POSTGRES_DEFAULT_GUIDE = RemediationGuide(
    problem_summary="PostgreSQL accepts default credentials (postgres:postgres / postgres:'').",
    why_important=(
        "The PostgreSQL default user `postgres` is a superuser — an attacker "
        "can read and delete all databases, and run commands on the server "
        "via `COPY TO PROGRAM`. Running production PostgreSQL with default "
        "credentials is a critical mistake."
    ),
    fix_steps=(
        FixStep(
            "1. Change the password",
            "",
            code="sudo -u postgres psql\n"
                 "postgres=# ALTER USER postgres WITH PASSWORD '<long-random-password>';\n"
                 "postgres=# \\q",
        ),
        FixStep(
            "2. Restrict remote connections — pg_hba.conf",
            "`/etc/postgresql/<ver>/main/pg_hba.conf`:",
            code="# Local: peer (unix socket auth)\n"
                 "local   all   postgres   peer\n"
                 "# Remote: scram-sha-256 password required (md5 is legacy, insecure)\n"
                 "host    all   all        127.0.0.1/32   scram-sha-256",
        ),
        FixStep(
            "3. Configure listen_addresses",
            "`postgresql.conf`:",
            code="listen_addresses = 'localhost'\n"
                 "password_encryption = scram-sha-256",
        ),
        FixStep(
            "4. Firewall",
            "",
            code="sudo ufw deny 5432\n"
                 "sudo ufw allow from <app_ip> to any port 5432",
        ),
        FixStep(
            "5. Separate user per application",
            "The postgres superuser is only for administration. Minimum-privilege user for the app:",
            code="CREATE USER myapp WITH PASSWORD '<password>';\n"
                 "GRANT CONNECT ON DATABASE mydb TO myapp;\n"
                 "GRANT USAGE ON SCHEMA public TO myapp;\n"
                 "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO myapp;",
        ),
    ),
    verification=(
        "`psql -U postgres -h <ip> -W` should not work without a password. "
        "`psql -U postgres -h <ip>` should prompt for the password."
    ),
    references=(
        ("PostgreSQL Authentication", "https://www.postgresql.org/docs/current/auth-methods.html"),
    ),
)

_EXPOSED_GIT_GUIDE = RemediationGuide(
    problem_summary=".git repository accessible from the web root — all source code is leaking.",
    why_important=(
        "If an attacker can reach `.git/config` and `.git/HEAD`, they can "
        "reconstruct the whole git repository with tools like `git-dumper` "
        "and extract the commit history. This means: all source code + "
        "passwords accidentally committed in the past + API keys + "
        "internal business logic = full exposure."
    ),
    fix_steps=(
        FixStep(
            "URGENT — Remove .git from the web root",
            "Fix the deployment pipeline. Do not copy `.git` to production "
            "with the source code. Correct deploy: `git archive`, "
            "`rsync --exclude='.git'`, CI/CD pipelines (GitHub Actions, etc.).",
            code="# Emergency fix — delete .git on the server\n"
                 "sudo rm -rf /var/www/html/.git",
        ),
        FixStep(
            "Web server — block `.git/` access (backup defense)",
            "Nginx:",
            code="location ~ /\\.git {\n"
                 "    deny all;\n"
                 "    return 404;\n"
                 "}",
        ),
        FixStep(
            "Apache (.htaccess)",
            "",
            code='RedirectMatch 404 /\\.git(/|$)',
        ),
        FixStep(
            "Rotate leaked secrets from history",
            "If `.git` was accessed, assume ALL secrets in past commits are "
            "leaked: DB passwords, API keys, JWT secret, AWS credentials. "
            "Use `truffleHog` or `gitleaks` to find historical leaks.",
        ),
    ),
    verification="`curl -I https://yoursite.com/.git/config` → should return 404 or 403.",
    references=(
        ("git-dumper", "https://github.com/arthaud/git-dumper"),
        ("gitleaks", "https://github.com/gitleaks/gitleaks"),
    ),
)

_EXPOSED_SQL_DUMP_GUIDE = RemediationGuide(
    problem_summary="Database backup (.sql) downloadable from the web root.",
    why_important=(
        "This is full exposure: table schema + ALL data (user accounts, "
        "password hashes for offline brute-forcing, order details, "
        "messages). If the admin user's password hash is stolen, offline "
        "cracking attempts begin."
    ),
    fix_steps=(
        FixStep(
            "URGENT — Delete the file, change DB passwords",
            "If a SQL dump was observed, assume the attacker has it. Force "
            "reset all DB passwords and hashed user passwords (force users "
            "to reset their password).",
            code="sudo rm /var/www/html/backup.sql\n"
                 "# Change DB passwords\n"
                 "# Send a 'reset your password' email to users",
        ),
        FixStep(
            "Don't keep backups under the web root",
            "Backups must always be in a non-web-accessible directory "
            "(`/var/backups/`) or external storage (encrypted S3 bucket, "
            "Backblaze B2).",
            code="# Correct backup directory\n"
                 "/var/backups/db/  # not web-accessible\n"
                 "# Automated backup script + rotation\n"
                 "mysqldump mydb | gzip > /var/backups/db/$(date +%F).sql.gz",
        ),
        FixStep(
            "Nginx — block .sql extensions",
            "",
            code='location ~ \\.(sql|bak|old|backup)$ {\n'
                 '    deny all;\n'
                 '    return 404;\n'
                 "}",
        ),
    ),
    verification="`curl -I https://yoursite.com/backup.sql` → 404.",
    references=(
        ("OWASP Backup Files", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"),
    ),
)

_EXPOSED_WP_CONFIG_GUIDE = RemediationGuide(
    problem_summary="WordPress wp-config.php backup (.bak/.save) is public — DB password and secrets exposed.",
    why_important=(
        "wp-config.php contains WordPress's DB connection password, table "
        "prefix, and 8 security secret keys. If a backup file is seen, the "
        "attacker can access the DB directly and hijack sessions using the "
        "secret keys."
    ),
    fix_steps=(
        FixStep(
            "URGENT — Delete backups, rotate all passwords",
            "",
            code="rm /var/www/html/wp-config.php.bak\n"
                 "rm /var/www/html/wp-config.php.save\n\n"
                 "# Change the DB password (in MySQL)\n"
                 "ALTER USER wp_user WITH PASSWORD '<new>';\n"
                 "# Update wp-config.php (DB_PASSWORD)\n\n"
                 "# Regenerate WordPress secret keys\n"
                 "curl -s https://api.wordpress.org/secret-key/1.1/salt/\n"
                 "# Paste the output into wp-config.php",
        ),
        FixStep(
            "Block editor backup files",
            "Nginx:",
            code='location ~ \\.(bak|save|swp|orig|tmp)$ {\n'
                 '    deny all;\n'
                 '    return 404;\n'
                 "}",
        ),
        FixStep(
            "Move wp-config.php one level above the web root",
            "WordPress supports this — safer:",
            code="# If WP is installed in /var/www/html/\n"
                 "mv wp-config.php ../wp-config.php\n"
                 "# WP automatically looks one directory up",
        ),
    ),
    verification="`curl -I https://yoursite.com/wp-config.php.bak` → 404.",
    references=(
        ("WordPress Hardening", "https://wordpress.org/documentation/article/hardening-wordpress/"),
    ),
)

_EXPOSED_HTACCESS_GUIDE = RemediationGuide(
    problem_summary=".htaccess file is readable over the web.",
    why_important=(
        ".htaccess holds Apache configuration directives — RewriteRules, "
        "AuthType, IP whitelist/blacklist. If read, the attacker learns "
        "the application's routing logic and (if any) the path to the HTTP "
        "basic auth credentials file."
    ),
    fix_steps=(
        FixStep(
            "Apache — directory protection rule",
            "Apache blocks .htaccess reads by default. If not blocked:",
            code='<FilesMatch "^\\.ht">\n'
                 '    Require all denied\n'
                 '</FilesMatch>',
        ),
        FixStep(
            "If possible, use httpd.conf instead of .htaccess",
            "`.htaccess` is weaker than httpd.conf for both performance and "
            "security. Each request searches for .htaccess in the directory. "
            "If you have root access, move the rules into a `<Directory>` "
            "block in httpd.conf.",
        ),
    ),
    verification="`curl -I https://yoursite.com/.htaccess` → 403 or 404.",
    references=(
        ("Apache Security Tips", "https://httpd.apache.org/docs/2.4/misc/security_tips.html"),
    ),
)

_EXPOSED_DS_STORE_GUIDE = RemediationGuide(
    problem_summary=".DS_Store file in the web root — macOS metadata is leaking.",
    why_important=(
        ".DS_Store is a binary index file macOS creates for every directory "
        "displayed in Finder. It contains ALL file names in the folder. If "
        "visible on the web, an attacker can discover your hidden backup "
        "files, admin folders, and test scripts."
    ),
    fix_steps=(
        FixStep(
            "Delete the files",
            "",
            code="find /var/www/html -name '.DS_Store' -delete",
        ),
        FixStep(
            "Prevent them from entering Git (.gitignore)",
            "",
            code="echo '**/.DS_Store' >> .gitignore\n"
                 "git rm --cached **/.DS_Store  # if already committed",
        ),
        FixStep(
            "Web server block",
            "Nginx:",
            code='location ~ \\.DS_Store$ { return 404; }',
        ),
        FixStep(
            "Prevent creation on network drives in macOS",
            "",
            code="defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true",
        ),
    ),
    verification="`curl -I https://yoursite.com/.DS_Store` → 404.",
    references=(
        ("Apple Tech Note", "https://support.apple.com/en-us/HT208209"),
    ),
)

_EXPOSED_SERVER_STATUS_GUIDE = RemediationGuide(
    problem_summary="Apache /server-status page is publicly accessible.",
    why_important=(
        "/server-status exposes sensitive operational data such as active "
        "HTTP connections, recent requests, uptime, loaded modules, and the "
        "virtual host list. It significantly expands an attacker's "
        "reconnaissance surface."
    ),
    fix_steps=(
        FixStep(
            "Apache — disable or restrict /server-status",
            "In `httpd.conf` or the relevant VirtualHost:",
            code="# Fully disable\n"
                 "<Location /server-status>\n"
                 "    Require all denied\n"
                 "</Location>\n\n"
                 "# Or allow only localhost (for internal monitoring)\n"
                 "<Location /server-status>\n"
                 "    Require host localhost\n"
                 "    Require ip 127.0.0.1\n"
                 "</Location>",
        ),
        FixStep(
            "Remove the mod_status module entirely (if not needed)",
            "",
            code="sudo a2dismod status\n"
                 "sudo systemctl restart apache2",
        ),
    ),
    verification="`curl -I https://yoursite.com/server-status` → 403 or 404.",
    references=(
        ("Apache mod_status", "https://httpd.apache.org/docs/2.4/mod/mod_status.html"),
    ),
)

_EXPOSED_PHPINFO_GUIDE = RemediationGuide(
    problem_summary="phpinfo.php is publicly accessible — PHP configuration exposed.",
    why_important=(
        "The phpinfo() output shows the server's PHP version, installed "
        "extensions, environment variables (may include hidden API keys), "
        "file paths, and sometimes even DB connection info. It is a "
        "developer tool — it must never be in production."
    ),
    fix_steps=(
        FixStep(
            "URGENT — Delete the file",
            "",
            code="find /var/www -name 'phpinfo.php' -delete\n"
                 "find /var/www -name 'info.php' -delete\n"
                 "find /var/www -name 'test.php' -delete",
        ),
        FixStep(
            "Assume environment variables are leaked",
            "If phpinfo dumped $_ENV, the values likely came from .env or "
            "the system environment — rotate DB_PASSWORD, API_KEY, and all "
            "other secrets.",
        ),
        FixStep(
            "expose_php = Off (php.ini)",
            "Stop PHP from leaking its own version info in the HTTP header:",
            code="; /etc/php/X.X/apache2/php.ini\n"
                 "expose_php = Off",
        ),
    ),
    verification="`curl -I https://yoursite.com/phpinfo.php` → 404.",
    references=(
        ("PHP Security", "https://www.php.net/manual/en/security.php"),
    ),
)

_EXPOSED_ADMIN_GUIDE = RemediationGuide(
    problem_summary="Admin panel (/admin) is publicly accessible.",
    why_important=(
        "Admin panels are the top target for attackers — brute-force "
        "password attempts, known CVEs (Joomla admin takeover, Drupal SQL "
        "injection), default credentials. A public panel = under constant "
        "attack."
    ),
    fix_steps=(
        FixStep(
            "Move behind VPN or an IP allowlist",
            "Access the admin panel only from the office IP or via VPN.",
            code="# Nginx — allow only specific IPs\n"
                 "location /admin {\n"
                 "    allow 203.0.113.0/24;   # Office IP\n"
                 "    allow 127.0.0.1;        # Localhost\n"
                 "    deny all;\n"
                 "    proxy_pass http://backend;\n"
                 "}",
        ),
        FixStep(
            "Make the URL unpredictable",
            "A custom path like `/company-name-panel-xyz12` instead of "
            "`/admin`. Not sufficient on its own, but reduces the "
            "automated scan surface.",
        ),
        FixStep(
            "Strong password + MFA + rate limit + fail2ban",
            "Admin accounts: 16+ character passwords, mandatory 2FA, IP "
            "blocks on failed logins (fail2ban, Cloudflare Rate Limiting).",
        ),
        FixStep(
            "Extra layer with HTTP Basic Auth",
            "Require a password at the web server layer BEFORE the "
            "application login:",
            code="# Nginx\n"
                 "location /admin {\n"
                 "    auth_basic 'Restricted';\n"
                 "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
                 "    proxy_pass http://backend;\n"
                 "}",
        ),
    ),
    verification="From outside `curl -I https://yoursite.com/admin` → 403/401; from the VPN 200.",
    references=(
        ("OWASP Admin Interface", "https://owasp.org/www-community/attacks/Brute_force_attack"),
    ),
)

_EXPOSED_PHPMYADMIN_GUIDE = RemediationGuide(
    problem_summary="phpMyAdmin is publicly accessible.",
    why_important=(
        "phpMyAdmin is the top target of brute-force attacks. Paths like "
        "'phpmyadmin', 'pma', and 'mysql-admin' are scanned every second. "
        "phpMyAdmin also has its own history of vulnerabilities "
        "(CVE-2020-10804, CVE-2018-19968, etc.) — even when up-to-date "
        "the attack surface is large."
    ),
    fix_steps=(
        FixStep(
            "Remove phpMyAdmin (best solution)",
            "Modern alternatives: MySQL Workbench (desktop), Adminer "
            "(single file, lightweight), the `mysql` CLI directly. Evaluate "
            "whether phpMyAdmin is really necessary.",
            code="sudo apt remove phpmyadmin\n"
                 "sudo rm -rf /var/www/html/phpmyadmin",
        ),
        FixStep(
            "If required, move behind a VPN",
            "",
            code="# Nginx — only from the VPN subnet\n"
                 "location /pma-xyz123 {\n"
                 "    allow 10.8.0.0/24;   # VPN subnet\n"
                 "    deny all;\n"
                 "    alias /var/www/phpmyadmin;\n"
                 "}",
        ),
        FixStep(
            "Change the path + HTTP Basic Auth + fail2ban",
            "Use an unpredictable path instead of `/phpmyadmin`, add extra "
            "auth at the web layer, block IPs on failed logins.",
        ),
    ),
    verification="`curl -I https://yoursite.com/phpmyadmin` → 404 or auth required.",
    references=(
        ("phpMyAdmin Security", "https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation"),
    ),
)

_X_POWERED_BY_GUIDE = RemediationGuide(
    problem_summary="The X-Powered-By header leaks the application framework version.",
    why_important=(
        "Headers like `X-Powered-By: PHP/7.4.3` give attackers the exact "
        "version of the target software. The attacker then looks up CVEs "
        "specific to that version and tries exploits. Hiding it is not "
        "definitive security, but it shrinks the reconnaissance surface."
    ),
    fix_steps=(
        FixStep(
            "PHP — disable expose_php",
            "`php.ini`:",
            code="expose_php = Off",
        ),
        FixStep(
            "Nginx — remove all Powered-By headers",
            "",
            code='more_clear_headers "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version";',
        ),
        FixStep(
            "Express.js (Node.js)",
            "",
            code="app.disable('x-powered-by');",
        ),
        FixStep(
            "IIS — ASP.NET version headers",
            "`web.config`:",
            code='<system.webServer>\n'
                 '  <httpProtocol>\n'
                 '    <customHeaders>\n'
                 '      <remove name="X-Powered-By" />\n'
                 '      <remove name="X-AspNet-Version" />\n'
                 '      <remove name="X-AspNetMvc-Version" />\n'
                 '    </customHeaders>\n'
                 '  </httpProtocol>\n'
                 '</system.webServer>',
        ),
        FixStep(
            "Cloudflare",
            "Rules → Transform Rules → Modify Response Header → Remove → "
            "`X-Powered-By`.",
        ),
    ),
    verification="`curl -I https://yoursite.com/ | grep -i powered` should not show the header.",
    references=(
        ("OWASP Fingerprinting", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"),
    ),
)

# --- Port-based guides ---

_PORT_RDP_GUIDE = RemediationGuide(
    problem_summary="RDP (Remote Desktop, port 3389) is open.",
    why_important=(
        "RDP is one of the most attacked services on the internet. Critical "
        "vulnerabilities like BlueKeep (CVE-2019-0708), DejaBlue, NLA "
        "bypass, and CredSSP. Brute-force and password spray attacks are "
        "constant. 55% of 2020-2022 ransomware attacks started through "
        "public RDP."
    ),
    fix_steps=(
        FixStep(
            "REMOVE RDP from the public, put it behind a VPN",
            "This is the most critical step. Set up a VPN (WireGuard, "
            "OpenVPN, Tailscale) → RDP is reachable only from the VPN "
            "subnet. Port 3389 must be fully closed to the outside.",
        ),
        FixStep(
            "Windows Firewall — block port 3389",
            "",
            code="# PowerShell (admin)\n"
                 "New-NetFirewallRule -DisplayName 'Block-RDP-Public' "
                 "-Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block",
        ),
        FixStep(
            "Port change (not security, but noise reduction)",
            "A random port (e.g. 50189) instead of 3389. Registry:",
            code='Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
                 '-Name PortNumber -Value 50189',
        ),
        FixStep(
            "Require NLA (Network Level Authentication)",
            "Registry or Group Policy → 'Require use of specific security "
            "layer for RDP connections' → 'SSL (TLS 1.0)' + 'Require NLA' → Enabled.",
        ),
        FixStep(
            "Strong password + MFA + Account lockout",
            "Admin account password 16+ chars. MFA such as Azure AD / Duo. "
            "Group Policy → 'Account lockout threshold' → 5 failed attempts.",
        ),
    ),
    verification="From outside `Test-NetConnection yoursite.com -Port 3389` → Failed. Over VPN it should work.",
    references=(
        ("CISA RDP Alert", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-073a"),
    ),
)

_PORT_SMB_GUIDE = RemediationGuide(
    problem_summary="SMB (port 445, microsoft-ds) is open.",
    why_important=(
        "Exposing SMB publicly is on CISA's 'top 10 most dangerous "
        "misconfigurations' list. Critical vulnerabilities like "
        "EternalBlue (CVE-2017-0144), SMBGhost (CVE-2020-0796), and "
        "PrintNightmare all happen over SMB. The 2017 WannaCry attack "
        "spread via this exact vulnerability."
    ),
    fix_steps=(
        FixStep(
            "CLOSE public SMB — the only safe way",
            "SMB must not be exposed to the internet. Block port 445 from "
            "outside in the firewall, and allow only necessary subnets on "
            "the internal network.",
            code="# Windows Firewall\n"
                 "New-NetFirewallRule -DisplayName 'Block-SMB-Public' "
                 "-Direction Inbound -Protocol TCP -LocalPort 445 -Action Block",
        ),
        FixStep(
            "Fully disable SMBv1",
            "SMBv1 (deprecated) is the most attack-prone version. "
            "EternalBlue targets it.",
            code='Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol',
        ),
        FixStep(
            "Require SMB signing",
            "",
            code='Set-SmbServerConfiguration -RequireSecuritySignature $true',
        ),
        FixStep(
            "Consider SFTP/Nextcloud instead of SMB",
            "For file sharing, SFTP + per-user directories or Nextcloud "
            "(self-hosted) are far more secure than SMB.",
        ),
    ),
    verification="From outside telnet/Test-NetConnection to port 445 → should have no access.",
    references=(
        ("Microsoft: Disable SMBv1", "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"),
    ),
)

_PORT_FTP_GUIDE = RemediationGuide(
    problem_summary="FTP (port 21) is open — unencrypted file transfer.",
    why_important=(
        "FTP is from 1985 and is unencrypted. Username, password, and file "
        "content can be read by anyone sniffing the network. Anonymous FTP "
        "may also be configured — nameless access. There is almost no "
        "legitimate reason to use FTP in 2025."
    ),
    fix_steps=(
        FixStep(
            "Use SFTP (over SSH) instead of FTP",
            "SFTP is modern, encrypted, and uses SSH's already-open port "
            "22. Clients like FileZilla and WinSCP support SFTP.",
            code="# Client connection example\n"
                 "sftp user@server.com\n"
                 "# Or select 'SFTP' protocol in PuTTY/FileZilla",
        ),
        FixStep(
            "FTPS (FTP over TLS) as an alternative",
            "If compatibility with legacy FTP clients is required, use "
            "FTPS (explicit TLS):",
            code="# vsftpd.conf\n"
                 "ssl_enable=YES\n"
                 "force_local_data_ssl=YES\n"
                 "force_local_logins_ssl=YES",
        ),
        FixStep(
            "Remove the FTP service",
            "",
            code="sudo systemctl stop vsftpd\n"
                 "sudo systemctl disable vsftpd\n"
                 "sudo apt remove vsftpd",
        ),
        FixStep(
            "Disable anonymous FTP (if in use)",
            "",
            code="# vsftpd.conf\n"
                 "anonymous_enable=NO\n"
                 "local_enable=YES",
        ),
    ),
    verification="`curl ftp://yoursite.com` → should not connect. `sftp user@yoursite.com` → should work.",
    references=(
        ("SFTP Hardening", "https://infosec.mozilla.org/guidelines/openssh"),
    ),
)

_PORT_TELNET_GUIDE = RemediationGuide(
    problem_summary="Telnet (port 23) is open — unencrypted remote access.",
    why_important=(
        "Telnet is even older than FTP (1969!) and is completely "
        "unencrypted. Passwords and all commands are in plaintext. Being "
        "open after 2020 is a serious sign of negligence. Modern OSes keep "
        "Telnet support disabled by default."
    ),
    fix_steps=(
        FixStep(
            "Switch to SSH — remove Telnet entirely",
            "SSH has replaced Telnet since 1995. Modern, encrypted, "
            "strong auth.",
            code="# Linux\n"
                 "sudo systemctl stop telnet\n"
                 "sudo systemctl disable telnet\n"
                 "sudo apt remove telnetd\n\n"
                 "# Make sure SSH is open\n"
                 "sudo systemctl enable --now ssh",
        ),
        FixStep(
            "Windows — disable even the Telnet client",
            "",
            code='Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient',
        ),
    ),
    verification="`telnet yoursite.com 23` → connection refused.",
    references=(
        ("RFC on deprecating Telnet", "https://www.rfc-editor.org/rfc/rfc4949.html"),
    ),
)

_PORT_VNC_GUIDE = RemediationGuide(
    problem_summary="VNC (port 5900) is open — weakly-encrypted remote desktop.",
    why_important=(
        "The default VNC protocol (RFB) only uses weak DES encryption for "
        "the password, while screen traffic is usually unencrypted. Older "
        "versions of TightVNC and RealVNC are exposed to brute-force and "
        "DoS vulnerabilities. Publicly exposed VNC often runs with default "
        "passwords."
    ),
    fix_steps=(
        FixStep(
            "Move behind a VPN or SSH tunnel",
            "VNC must not be exposed publicly. Connect via an SSH tunnel:",
            code="# On the client:\n"
                 "ssh -L 5901:localhost:5900 user@server\n"
                 "# The VNC client connects to localhost:5901 — encrypted",
        ),
        FixStep(
            "Use RDP (Windows) or NoMachine (Linux) instead of VNC",
            "RDP supports native encryption + NLA. NoMachine runs over "
            "SSH, much more secure than VNC.",
        ),
        FixStep(
            "If not in use, stop the VNC service",
            "",
            code="sudo systemctl stop vncserver\n"
                 "sudo systemctl disable vncserver",
        ),
        FixStep(
            "If used — strong password + TLS",
            "TigerVNC or modern RealVNC support TLS. Force TLS in the "
            "config, password at least 16 characters.",
        ),
    ),
    verification="From outside `telnet yoursite.com 5900` → no connection. Via SSH tunnel from inside it should work.",
    references=(
        ("VNC Security", "https://tigervnc.org/doc/vncserver.html"),
    ),
)

_PORT_GENERIC_GUIDE = RemediationGuide(
    problem_summary="An open TCP port was detected.",
    why_important=(
        "Every open port is an attack surface. Any port that isn't truly "
        "required must be closed — the minimum exposure principle. Even "
        "required ports should be restricted in the firewall to specific "
        "IPs/subnets."
    ),
    fix_steps=(
        FixStep(
            "Ask if it is truly needed",
            "What service is running on this port? Does the service need "
            "to be public? If it is only used locally, change the bind "
            "address to `127.0.0.1` so it is not reachable externally.",
        ),
        FixStep(
            "Firewall — default deny, allow what is necessary",
            "",
            code="# Linux (ufw)\n"
                 "sudo ufw default deny incoming\n"
                 "sudo ufw allow from <app_ip> to any port <port>\n"
                 "sudo ufw enable",
        ),
        FixStep(
            "Windows Firewall",
            "",
            code="New-NetFirewallRule -DisplayName 'Block-Port-X' "
                 "-Direction Inbound -LocalPort <PORT> -Action Block",
        ),
        FixStep(
            "Keep the service software up to date",
            "Open port + old software = critical CVE risk. Enable automatic "
            "security updates (`unattended-upgrades`, Windows Update).",
        ),
    ),
    verification="From outside `nc -zv yoursite.com <port>` → should be blocked / timeout.",
    references=(
        ("NIST Firewall Guide", "https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final"),
    ),
)


# =====================================================================
# Finding title → guide key mapping
# =====================================================================

# (guide_key, matcher, guide) — matcher returns True if the title matches
_PATTERN_MATCHERS: tuple[tuple[str, _TitleMatcher, RemediationGuide], ...] = (
    ("csp_missing", lambda t: "CSP missing" in t, _CSP_GUIDE),
    ("hsts_missing", lambda t: "HSTS missing" in t, _HSTS_GUIDE),
    ("xfo_missing", lambda t: "X-Frame-Options missing" in t, _XFO_GUIDE),
    ("xcto_missing", lambda t: "X-Content-Type-Options missing" in t, _XCTO_GUIDE),
    ("referrer_missing", lambda t: "Referrer-Policy missing" in t, _REFERRER_GUIDE),
    ("server_leak", lambda t: "Version leak: Server" in t, _SERVER_LEAK_GUIDE),
    ("http_only", lambda t: "Served over HTTP" in t, _HTTP_ONLY_GUIDE),
    ("security_txt", lambda t: "security.txt missing" in t, _SECURITY_TXT_GUIDE),
    ("redis_open", lambda t: "Redis is accessible without a password" in t, _REDIS_OPEN_GUIDE),
    ("mongodb_open", lambda t: "MongoDB is accessible without a password" in t, _MONGODB_OPEN_GUIDE),
    ("elasticsearch_open", lambda t: "Elasticsearch is accessible without a password" in t, _ELASTICSEARCH_OPEN_GUIDE),
    ("mysql_default", lambda t: "MySQL accepts default credentials" in t, _MYSQL_DEFAULT_GUIDE),
    ("ssh_default", lambda t: "SSH accepts default credentials" in t, _SSH_DEFAULT_GUIDE),
    ("env_exposed", lambda t: ".env file publicly accessible" in t, _EXPOSED_ENV_GUIDE),
    ("wifi_open", lambda t: "Unencrypted Wi-Fi network" in t, _WIFI_OPEN_GUIDE),
    ("wifi_wep", lambda t: "Wi-Fi network with WEP encryption" in t, _WIFI_WEP_GUIDE),
    ("wifi_old_wpa", lambda t: "Wi-Fi network with legacy WPA encryption" in t, _WIFI_OLD_WPA_GUIDE),

    # Web probes — Level 2 attack detection
    ("sql_injection", lambda t: "SQL Injection" in t, _SQL_INJECTION_GUIDE),
    ("xss_reflected", lambda t: "Reflected XSS" in t, _XSS_GUIDE),
    ("path_traversal", lambda t: "Path traversal" in t, _PATH_TRAVERSAL_GUIDE),
    ("ssl_old_protocol", lambda t: "Old TLS version supported" in t, _SSL_OLD_PROTOCOL_GUIDE),
    ("ssl_cert_problem", lambda t: "SSL certificate issue" in t, _SSL_CERT_PROBLEM_GUIDE),
    ("x_powered_by_leak",
     lambda t: ("Version leak: X-Powered-By" in t
                or "Version leak: X-AspNet" in t),
     _X_POWERED_BY_GUIDE),

    # Exposed files
    ("exposed_git", lambda t: ".git repository" in t or ".git/HEAD" in t, _EXPOSED_GIT_GUIDE),
    ("exposed_sql_dump",
     lambda t: "Database backup" in t or "Database dump" in t,
     _EXPOSED_SQL_DUMP_GUIDE),
    ("exposed_wp_config",
     lambda t: "WordPress configuration" in t,
     _EXPOSED_WP_CONFIG_GUIDE),
    ("exposed_htaccess", lambda t: ".htaccess file accessible" in t, _EXPOSED_HTACCESS_GUIDE),
    ("exposed_ds_store", lambda t: ".DS_Store leaked" in t, _EXPOSED_DS_STORE_GUIDE),
    ("exposed_server_status", lambda t: "server-status public" in t, _EXPOSED_SERVER_STATUS_GUIDE),
    ("exposed_phpinfo", lambda t: "phpinfo.php public" in t, _EXPOSED_PHPINFO_GUIDE),
    ("exposed_admin", lambda t: "Admin panel" in t, _EXPOSED_ADMIN_GUIDE),
    ("exposed_phpmyadmin", lambda t: "phpMyAdmin public" in t, _EXPOSED_PHPMYADMIN_GUIDE),

    # DB parity
    ("postgres_default_creds",
     lambda t: "PostgreSQL accepts default credentials" in t,
     _POSTGRES_DEFAULT_GUIDE),

    # Port-specific — order is critical: specific first, generic last
    ("port_rdp", lambda t: "Open port: 3389" in t, _PORT_RDP_GUIDE),
    ("port_smb",
     lambda t: "Open port: 445" in t or "Open port: 139" in t,
     _PORT_SMB_GUIDE),
    ("port_ftp", lambda t: "Open port: 21" in t, _PORT_FTP_GUIDE),
    ("port_telnet", lambda t: "Open port: 23" in t, _PORT_TELNET_GUIDE),
    ("port_vnc", lambda t: "Open port: 5900" in t, _PORT_VNC_GUIDE),
    # Generic port catch-all — MUST be LAST (so specific ones match first)
    ("port_generic", lambda t: t.startswith("Open port:"), _PORT_GENERIC_GUIDE),
)


def get_guide(finding: Finding) -> RemediationGuide | None:
    """Return the detailed guide for the given finding if one exists, else None.

    The report template is invoked with this value; if None, only the short
    `remediation` string is shown — if a value is returned, a "Show detailed
    guide" collapsible card is presented.
    """
    for _key, matcher, guide in _PATTERN_MATCHERS:
        if matcher(finding.title):
            return guide
    return None


def get_guide_by_key(key: str) -> RemediationGuide | None:
    """For tests and direct access — fetch a guide by key."""
    for k, _matcher, guide in _PATTERN_MATCHERS:
        if k == key:
            return guide
    return None
