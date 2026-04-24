"""SQL Injection probe — error-based tespit."""

from __future__ import annotations

import re
from urllib.parse import urlencode

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

_PARAMS_TO_TEST: tuple[str, ...] = (
    "id", "user", "username", "email", "search", "q", "query",
    "name", "category", "cat", "product", "item", "pid", "uid",
)

_SYNTAX_BREAKING_PAYLOADS: tuple[str, ...] = (
    "'",
    "\"",
    "\\'",
    "' --",
    "1'\"`",
)

# (regex, DBMS i18n key)
_SQL_ERROR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"You have an error in your SQL syntax", re.I), "label.web.sql_injection.mysql"),
    (re.compile(r"mysql_fetch_(array|assoc|row|object)", re.I), "label.web.sql_injection.mysql_php"),
    (re.compile(r"mysql_num_rows", re.I), "label.web.sql_injection.mysql_php"),
    (re.compile(r"Warning.*mysql_", re.I), "label.web.sql_injection.mysql_php_warning"),
    (re.compile(r"MySqlException", re.I), "label.web.sql_injection.mysql_dotnet"),

    (re.compile(r"PostgreSQL.*ERROR", re.I), "label.web.sql_injection.postgresql"),
    (re.compile(r"pg_query\(\)", re.I), "label.web.sql_injection.postgresql_php"),
    (re.compile(r"PSQLException", re.I), "label.web.sql_injection.postgresql_jdbc"),

    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "label.web.sql_injection.mssql"),
    (re.compile(r"Unclosed quotation mark after", re.I), "label.web.sql_injection.mssql"),
    (re.compile(r"\[SQL Server\].*Driver", re.I), "label.web.sql_injection.mssql_odbc"),
    (re.compile(r"System\.Data\.SqlClient\.SqlException", re.I), "label.web.sql_injection.mssql_dotnet"),

    (re.compile(r"ORA-[0-9]{4,5}", re.I), "label.web.sql_injection.oracle"),
    (re.compile(r"Oracle error", re.I), "label.web.sql_injection.oracle"),
    (re.compile(r"OracleException", re.I), "label.web.sql_injection.oracle_dotnet"),

    (re.compile(r"SQLite.*Exception", re.I), "label.web.sql_injection.sqlite"),
    (re.compile(r"sqlite3\.OperationalError", re.I), "label.web.sql_injection.sqlite_python"),
    (re.compile(r"near \".*\": syntax error", re.I), "label.web.sql_injection.sqlite"),

    (re.compile(r"SQLSTATE\[\d+\]", re.I), "label.web.sql_injection.generic_sqlstate"),
    (re.compile(r"ODBC.*Driver.*error", re.I), "label.web.sql_injection.generic_odbc"),
)


class SqlInjectionProbe(WebProbeBase):
    name: str = "sql_injection"
    description_key: str = "probe.web.sql_injection.description"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        reported_params: set[str] = set()

        for param in _PARAMS_TO_TEST:
            if param in reported_params:
                continue

            for payload in _SYNTAX_BREAKING_PAYLOADS:
                full_url = self._build_url_with_param(url, param, payload)

                try:
                    response = session.get(
                        full_url, timeout=self.timeout, allow_redirects=False,
                    )
                except requests.RequestException:
                    continue

                matched_pattern, dbms = self._match_sql_error(response.text)
                if matched_pattern is None:
                    continue

                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.CRITICAL,
                        title=t(
                            "finding.web.sql_injection.title",
                            param=param, dbms=dbms,
                        ),
                        description=t(
                            "finding.web.sql_injection.desc",
                            param=param, payload=payload, dbms=dbms,
                            matched_pattern=matched_pattern,
                        ),
                        target=full_url,
                        remediation=t("finding.web.sql_injection.remediation"),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=full_url,
                            response_status=response.status_code,
                            response_snippet=self._extract_error_context(
                                response.text, matched_pattern,
                            ),
                            why_vulnerable=f"{dbms} error pattern matched",
                            extra={"payload": payload, "param": param, "dbms": dbms},
                        ),
                    ),
                )
                reported_params.add(param)
                break

        return findings

    # -----------------------------------------------------------------
    @staticmethod
    def _match_sql_error(body: str) -> tuple[str | None, str]:
        """Yanıt gövdesinde SQL hata pattern'i var mı bak.

        Returns:
            (matched_text, translated_dbms_label) ya da (None, "")
        """
        snippet = body[:16384]
        for pattern, dbms_key in _SQL_ERROR_PATTERNS:
            match = pattern.search(snippet)
            if match:
                return match.group(0), t(dbms_key)
        return None, ""

    @staticmethod
    def _extract_error_context(body: str, matched_text: str) -> str:
        idx = body.find(matched_text)
        if idx == -1:
            return body[:200]
        start = max(0, idx - 50)
        end = min(len(body), idx + len(matched_text) + 100)
        return body[start:end]

    @staticmethod
    def _build_url_with_param(base_url: str, param: str, payload: str) -> str:
        separator = "&" if "?" in base_url else "?"
        encoded = urlencode({param: payload})
        return f"{base_url}{separator}{encoded}"
