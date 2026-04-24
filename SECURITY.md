# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Pentra, please report it
responsibly. **Do not open a public issue for security reports.**

### Preferred channels

- **Private email:** [hello@burakozdemir.online](mailto:hello@burakozdemir.online)
- **GitHub Security Advisory:** use the "Report a vulnerability" button on
  the repository's *Security* tab (private disclosure)

### What to include

Please provide as much of the following as possible:

- A clear description of the vulnerability and its potential impact
- Steps to reproduce (commands, inputs, environment)
- Affected version (git commit SHA, release tag, or `pentra --version`)
- Your operating system and Python version
- Suggested remediation, if you have one

### What to expect

- **Acknowledgement:** within 3 business days
- **Initial assessment:** within 7 business days (severity, impact, scope)
- **Fix timeline:** depends on severity; critical issues are prioritised
- **Credit:** with your consent, you will be credited in the release notes

---

## Scope

Pentra is a **vulnerability assessment** (Level 2 non-destructive probing)
tool for Windows. It is designed to be used **only on systems the user owns
or is explicitly authorised to scan**.

### In scope

- Bugs in Pentra's own code (authorisation, scope validation, rate limiting,
  audit log, report generation, update flow)
- Issues that could allow Pentra to be misused against unauthorised targets
- Vulnerabilities in how Pentra handles scan output, reports, or stored data
- Credentials or secrets leaking from Pentra's local storage

### Out of scope

- Vulnerabilities in third-party dependencies (report those upstream; we
  will update Pentra once the upstream fix is available)
- Misuse of Pentra against targets the user does not own or is not
  authorised to scan — this is the user's legal responsibility
- Findings produced by Pentra during legitimate scans of the user's own
  systems (those are the tool's purpose)

---

## Responsible use

Pentra is **not** an attack tool. The project explicitly forbids:

- Exploit execution, shell spawning, or remote code execution
- Credential brute forcing (beyond at most 2-3 default credential attempts)
- Data exfiltration (DB dumps, file downloads, etc.)
- Persistence, lateral movement, evasion, or log tampering

Pull requests that introduce any of the above will be rejected in code
review, regardless of the contributor's intent.

---

## Supported versions

During the pre-1.0 beta period, only the latest release receives security
fixes. After 1.0, the last two minor versions will be supported.

| Version | Supported |
| ------- | --------- |
| 1.0.0-beta or later | ✅ |
| Earlier pre-release builds | ❌ |

---

## Legal

Users are solely responsible for complying with the laws of their
jurisdiction when using Pentra. Unauthorised scanning may constitute a
criminal offence (in Turkey: TCK Art. 243-245; similar laws exist in
most jurisdictions).
