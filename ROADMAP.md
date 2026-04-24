# Pentra Roadmap

> Pentra is a **Level 2 non-destructive vulnerability assessment** tool. This
> roadmap lists tests and features that fit the manifesto (no exploits, no
> attacks, no harm) and can be added in reasonable time.

**Current release:** `v1.0.0-beta`
**Next major version:** `v2.0`

---

## 🟢 Tier 1 — Quick wins (~1-3 hours each)

Single-request probes with immediate user value.

### Web
- **CORS misconfiguration** — Send `Origin: evil.com`, detect reflective `Access-Control-Allow-Origin`
- **Open redirect** — `?redirect=http://external.com` → inspect 3xx Location header
- **CSRF token absence** — Parse HTML forms, check for hidden token input
- **HTTP/Host Header Injection** — Send `Host: evil.com`, detect reflection or redirect
- **robots.txt / sitemap.xml analysis** — Report `Disallow` paths and sitemap URLs (often leaks admin panels)
- **Exposed API documentation** — Probe `/swagger.json`, `/api-docs`, `/v2/api-docs`, `/openapi.json`
- **GraphQL introspection enabled** — If `/graphql` exists, attempt `__schema` query

### Cloud
- **Public S3/Blob bucket** — Check `bucketname.s3.amazonaws.com` for `ListBucketResult` XML

### Network
- **SMB null-session** — Port 445 anonymous bind → share listing availability (detection only)
- **SNMP default community** — Single GET with `public` / `private` → response means open community string
- **NetBIOS name enumeration** — UDP 137 → leak of computer/domain name

---

## 🟡 Tier 2 — Moderate effort (~0.5-2 days each)

More code required but still Level 2.

### Web
- **Blind boolean-based SQLi** — Response difference between `AND 1=1` and `AND 1=2` (no time-based — DoS risk)
- **Technology fingerprinting** — Cookie/header/HTML pattern matching (Wappalyzer-style)
- **Exposed package manifests** — `/package.json`, `/composer.json`, `/Gemfile`, `/requirements.txt` + known vulnerable versions
- **WAF detection** — Probe for WAF signatures (informational)
- **Favicon hash fingerprint** — MD5 hash → Shodan database lookup for tech identification

### DNS / Email security
- **SPF/DMARC/DKIM missing** — TXT record queries → phishing risk
- **DNS zone transfer (AXFR)** — Attempt AXFR against nameservers → subdomain leak
- **Subdomain enumeration** — Certificate Transparency logs (crt.sh) passive lookup

### Network
- **LDAP anonymous bind** — Port 389/636 → rootDSE query → base DN / naming context leak

---

## 🔴 Tier 3 — Major projects (~1-3 weeks each)

Architectural changes required; valuable long-term.

- **DOM XSS detection** — Headless browser (Playwright) integration (+200 MB to PyInstaller output)
- **Authenticated scan mode** — Login flow + cookie jar + multi-user sessions
  - Unlocks CSRF, IDOR, Session fixation, Broken Access Control tests
  - May conflict with the "beginner wizard" goal — planned as **Advanced Mode**
- **Cloud authenticated IAM scan** — ScoutSuite/Prowler-class functionality
  - AWS/Azure/GCP SDKs + credential management
- **Kubernetes security** — kube-hunter-class manifest logic
- **Bluetooth Low Energy passive scan** — Requires adapter + different protocol stack

---

## ❌ Never to be added (manifesto violations)

- **Active attacks:** MITM, ARP/DNS spoofing, VLAN hopping, deauthentication, rogue AP/DHCP
- **Cryptographic cracking:** WEP/WPA crack, WPS brute force, password brute force beyond 3 default attempts
- **Denial of service:** Application layer DoS, rate limiting tests, resource exhaustion
- **Post-exploitation:** Active Directory attacks (Kerberoasting, DCSync, BloodHound), privilege escalation, persistence, lateral movement
- **Credential theft:** Mimikatz, LSASS dumps
- **Exploitation:** Cache poisoning, HTTP smuggling, RCE, deserialization exploits
- **Evasion:** IDS/IPS/firewall bypass, stealth mode
- **Authenticated cloud full-scope:** IMDS abuse, cloud privilege escalation
- **SAST/SCA:** Pentra is a runtime black-box scanner — code analysis is a separate category (Bandit, Dependabot, Snyk)

---

## 💡 Planned release cadence

| Version | Contents |
|---|---|
| **v1.0.0-beta (current)** | Stabilization, .exe distribution, GitHub release pipeline |
| **v1.0 stable** | Beta feedback fixes, code signing (optional) |
| **v2.0** | All Tier 1 items (11 tests) + highest-value Tier 2 (Blind SQLi, SPF/DMARC, AXFR, tech fingerprint) |
| **v2.5** | Remaining Tier 2 items |
| **v3.0** | One Tier 3 item — most likely **Advanced Mode: Authenticated Scanning** |

---

## 📝 Notes for contributors

Every new probe must follow the **Level 2 rules**:
1. **Single-shot** — don't re-try the same vulnerability 1000 times
2. **Minimum proof** — just enough to confirm the issue exists
3. **Read, don't write** — no persistent changes on the target

Code review rejects changes that cross into Level 3 (exploit execution, shell
spawning, data exfiltration, persistence, lateral movement, credential theft).
See the project's manifesto for the full set of principles.

**Community PRs are welcome** — please open an issue first for larger changes so
we can discuss the manifesto alignment before you invest time in code.
