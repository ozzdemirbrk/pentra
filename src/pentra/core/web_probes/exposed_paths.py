"""Exposed Paths probe — hassas dosya/klasörlerin public erişimini kontrol eder.

Üç katmanlı false-positive savunması:

    1. **Soft-404 baseline**: Probe başında rastgele bir yol istenir. 200 dönerse
       sunucu 404 yerine catch-all sayfa veriyor demektir; sonraki probe'lar bu
       baseline'la karşılaştırılır (boyut + ilk 500 karakter). Benzer = atla.

    2. **Content-Type filtresi**: `.env`, `.sql`, `.htaccess` gibi teknik dosyalar
       `text/html` dönüyorsa büyük ihtimalle HTML anasayfa — sahte pozitif.

    3. **Spesifik içerik validator'ı**: Her path için yalnızca gerçek dosyanın
       üreteceği içerik pattern'i aranır.
"""

from __future__ import annotations

import dataclasses
import re
import secrets
from collections.abc import Callable
from urllib.parse import urljoin

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity


Validator = Callable[[requests.Response], tuple[bool, str]]


def _is_html(response: requests.Response) -> bool:
    ctype = response.headers.get("Content-Type", "").lower()
    return "html" in ctype


def _env_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    lines = response.text[:4096].splitlines()
    env_like = [
        line for line in lines
        if re.match(r"^[A-Z_][A-Z_0-9]*\s*=", line)
    ]
    if len(env_like) >= 2:
        return True, "\n".join(env_like[:5])
    return False, ""


def _git_config_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    stripped = response.text.lstrip()[:200]
    if stripped.startswith("[core]") or stripped.startswith("[remote"):
        return True, stripped
    return False, ""


def _git_head_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    text = response.text.strip()
    if re.match(r"^ref:\s+refs/heads/\S+$", text) and len(text) < 100:
        return True, text
    return False, ""


def _sql_dump_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    upper = response.text[:8192].upper()
    keywords = ("CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MYSQL DUMP", "-- POSTGRESQL")
    for kw in keywords:
        if kw in upper:
            idx = upper.find(kw)
            return True, response.text[max(0, idx - 20):idx + 200]
    return False, ""


def _wp_config_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    text = response.text[:4096]
    has_php = text.lstrip().startswith("<?php")
    has_db = any(k in text for k in ("DB_NAME", "DB_PASSWORD", "DB_USER", "DB_HOST"))
    if has_php and has_db:
        return True, text[:300]
    return False, ""


def _config_json_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    text = response.text[:4096].lstrip()
    if text.startswith("{") and '"' in text and ":" in text:
        return True, text[:200]
    return False, ""


def _config_yml_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    lines = response.text[:4096].splitlines()
    yml_like = [line for line in lines if re.match(r"^\s*[a-zA-Z_][\w-]*:\s*\S", line)]
    if len(yml_like) >= 2:
        return True, "\n".join(yml_like[:5])
    return False, ""


def _htaccess_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    upper = response.text[:4096].upper()
    keywords = ("REWRITEENGINE", "REWRITERULE", "AUTHTYPE", "REQUIRE", "<IFMODULE")
    if any(kw in upper for kw in keywords):
        return True, response.text[:200]
    return False, ""


def _ds_store_validator(response: requests.Response) -> tuple[bool, str]:
    if _is_html(response):
        return False, ""
    content = response.content[:16] if response.content else b""
    if b"Bud1" in content or b"\x00\x00\x00\x01Bud1" in content:
        return True, "[.DS_Store binary, Bud1 magic detected]"
    return False, ""


def _phpinfo_validator(response: requests.Response) -> tuple[bool, str]:
    text = response.text[:4096]
    if "phpinfo()" in text or re.search(r"<title>phpinfo\(\)", text, re.I):
        return True, "phpinfo() output detected"
    match = re.search(r"PHP Version \d+\.\d+\.\d+", text)
    if match:
        return True, match.group(0)
    return False, ""


def _server_status_validator(response: requests.Response) -> tuple[bool, str]:
    text = response.text[:4096]
    if "Apache Server Status" in text:
        return True, "Apache Server Status page"
    if "Server uptime:" in text and "Server Version:" in text:
        return True, "server-status output"
    return False, ""


def _admin_validator(response: requests.Response) -> tuple[bool, str]:
    text = response.text[:8192].lower()
    hints = (
        "admin panel", "admin login", "dashboard",
        "<title>admin", "adminlogin", "admin-password",
        "login</title>", "<h1>login",
    )
    for hint in hints:
        if hint in text:
            return True, f"Panel hint: `{hint}`"
    if re.search(r'<form[^>]*action=[^>]*(login|admin|auth)', text):
        return True, "Login form detected"
    return False, ""


def _phpmyadmin_validator(response: requests.Response) -> tuple[bool, str]:
    text = response.text[:8192]
    hints = ("phpMyAdmin", "pma_username", "pmahomme", "pma_password")
    for h in hints:
        if h in text:
            return True, f"phpMyAdmin signature: `{h}`"
    return False, ""


# ---------------------------------------------------------------------
# Path kayıtları — i18n anahtarları
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class _PathCheck:
    path: str
    severity: Severity
    #: i18n key prefix. title/desc/remediation = `{key_prefix}.title` vs.
    key_prefix: str
    validator: Validator


_SENSITIVE_PATHS: tuple[_PathCheck, ...] = (
    _PathCheck("/.env", Severity.CRITICAL, "finding.web.exposed_env", _env_validator),
    _PathCheck("/.git/config", Severity.HIGH, "finding.web.exposed_git_config", _git_config_validator),
    _PathCheck("/.git/HEAD", Severity.HIGH, "finding.web.exposed_git_head", _git_head_validator),
    _PathCheck("/backup.sql", Severity.CRITICAL, "finding.web.exposed_backup_sql", _sql_dump_validator),
    _PathCheck("/database.sql", Severity.CRITICAL, "finding.web.exposed_database_sql", _sql_dump_validator),
    _PathCheck("/dump.sql", Severity.CRITICAL, "finding.web.exposed_dump_sql", _sql_dump_validator),
    _PathCheck("/wp-config.php.bak", Severity.CRITICAL, "finding.web.exposed_wp_config_bak", _wp_config_validator),
    _PathCheck("/wp-config.php.save", Severity.CRITICAL, "finding.web.exposed_wp_config_save", _wp_config_validator),
    _PathCheck("/config.json", Severity.HIGH, "finding.web.exposed_config_json", _config_json_validator),
    _PathCheck("/config.yml", Severity.HIGH, "finding.web.exposed_config_yml", _config_yml_validator),
    _PathCheck("/.htaccess", Severity.MEDIUM, "finding.web.exposed_htaccess", _htaccess_validator),
    _PathCheck("/.DS_Store", Severity.LOW, "finding.web.exposed_ds_store", _ds_store_validator),
    _PathCheck("/server-status", Severity.MEDIUM, "finding.web.exposed_server_status", _server_status_validator),
    _PathCheck("/phpinfo.php", Severity.HIGH, "finding.web.exposed_phpinfo", _phpinfo_validator),
    _PathCheck("/admin", Severity.INFO, "finding.web.exposed_admin", _admin_validator),
    _PathCheck("/phpmyadmin", Severity.LOW, "finding.web.exposed_phpmyadmin", _phpmyadmin_validator),
)


# ---------------------------------------------------------------------
# Soft-404 baseline
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class _Baseline:
    status: int
    length: int
    snippet: str


def _capture_baseline(base_url: str, session: requests.Session, timeout: float) -> _Baseline | None:
    random_path = f"/pentra-nonexistent-{secrets.token_hex(8)}"
    full = urljoin(base_url.rstrip("/") + "/", random_path.lstrip("/"))
    try:
        response = session.get(full, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None
    return _Baseline(
        status=response.status_code,
        length=len(response.content or b""),
        snippet=response.text[:500] if response.text else "",
    )


def _looks_like_baseline(response: requests.Response, baseline: _Baseline) -> bool:
    if response.status_code != baseline.status:
        return False
    actual_length = len(response.content or b"")
    if baseline.length > 0:
        diff_ratio = abs(actual_length - baseline.length) / baseline.length
        if diff_ratio < 0.1:
            return True
    snippet = response.text[:500] if response.text else ""
    if snippet and baseline.snippet and snippet == baseline.snippet:
        return True
    return False


# ---------------------------------------------------------------------
# Ana probe sınıfı
# ---------------------------------------------------------------------
class ExposedPathsProbe(WebProbeBase):
    name: str = "exposed_paths"
    description_key: str = "probe.web.exposed_paths.description"

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        base = url.rstrip("/")

        # 1. Soft-404 baseline
        baseline = _capture_baseline(base, session, self.timeout)

        # 2. Her hassas yolu test et
        for check in _SENSITIVE_PATHS:
            full_url = urljoin(base + "/", check.path.lstrip("/"))

            try:
                response = session.get(
                    full_url, timeout=self.timeout, allow_redirects=False,
                )
            except requests.RequestException:
                continue

            if response.status_code not in (200, 204):
                continue

            if baseline is not None and _looks_like_baseline(response, baseline):
                continue

            is_real, evidence_snippet = check.validator(response)
            if not is_real:
                continue

            findings.append(
                Finding(
                    scanner_name="web_scanner",
                    severity=check.severity,
                    title=t(f"{check.key_prefix}.title"),
                    description=t(f"{check.key_prefix}.desc"),
                    target=full_url,
                    remediation=t(f"{check.key_prefix}.remediation"),
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=full_url,
                        response_status=response.status_code,
                        response_snippet=evidence_snippet[:200],
                        why_vulnerable=t("evidence.web.exposed_paths.validator_match"),
                        extra={"content_type": response.headers.get("Content-Type", "")},
                    ),
                ),
            )

        # 3. security.txt — ters mantık (yoksa uyar)
        security_url = urljoin(base + "/", ".well-known/security.txt")
        try:
            sec_response = session.get(
                security_url, timeout=self.timeout, allow_redirects=False,
            )
            is_missing = (
                sec_response.status_code == 404
                or (baseline is not None and _looks_like_baseline(sec_response, baseline))
            )
            if is_missing:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.INFO,
                        title=t("finding.web.security_txt_missing.title"),
                        description=t("finding.web.security_txt_missing.desc"),
                        target=security_url,
                        remediation=t("finding.web.security_txt_missing.remediation"),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=security_url,
                            response_status=sec_response.status_code,
                            why_vulnerable=t("evidence.web.exposed_paths.not_found"),
                        ),
                    ),
                )
        except requests.RequestException:
            pass

        return findings
