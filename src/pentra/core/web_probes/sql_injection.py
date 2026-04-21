"""SQL Injection probe — error-based tespit.

Tek karakter (`'`) veya bozuk payload gönderilir; yanıtta bilinen SQL hata
mesajı pattern'leri aranır. Zafiyet kanıtı = hata pattern'i + HTTP 200/500.

**Seviye 2 kuralı**: `DROP TABLE`, `UNION SELECT`, veri çekme yok — sadece
sintaks hatasıyla tetiklenen veritabanı hata mesajı aranır.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity

# Yaygın kullanıcı girdisi parametreleri — SQL injection'a açık olma ihtimali yüksek
_PARAMS_TO_TEST: tuple[str, ...] = (
    "id", "user", "username", "email", "search", "q", "query",
    "name", "category", "cat", "product", "item", "pid", "uid",
)

# Bozuk payload'lar — DB hata mesajı tetiklemek için
_SYNTAX_BREAKING_PAYLOADS: tuple[str, ...] = (
    "'",           # Klasik tek tırnak
    "\"",          # Çift tırnak
    "\\'",         # Escape denemesi
    "' --",        # Tek tırnak + yorum
    "1'\"`",       # Karışık tırnaklar
)

# DB hata pattern'leri — compile edilmiş regex listesi
# Her eşleşme bir DBMS'ye işaret eder
_SQL_ERROR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # MySQL
    (re.compile(r"You have an error in your SQL syntax", re.I), "MySQL"),
    (re.compile(r"mysql_fetch_(array|assoc|row|object)", re.I), "MySQL (PHP)"),
    (re.compile(r"mysql_num_rows", re.I), "MySQL (PHP)"),
    (re.compile(r"Warning.*mysql_", re.I), "MySQL (PHP warning)"),
    (re.compile(r"MySqlException", re.I), "MySQL (.NET)"),

    # PostgreSQL
    (re.compile(r"PostgreSQL.*ERROR", re.I), "PostgreSQL"),
    (re.compile(r"pg_query\(\)", re.I), "PostgreSQL (PHP)"),
    (re.compile(r"PSQLException", re.I), "PostgreSQL (JDBC)"),

    # Microsoft SQL Server
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "MSSQL"),
    (re.compile(r"Unclosed quotation mark after", re.I), "MSSQL"),
    (re.compile(r"\[SQL Server\].*Driver", re.I), "MSSQL (ODBC)"),
    (re.compile(r"System\.Data\.SqlClient\.SqlException", re.I), "MSSQL (.NET)"),

    # Oracle
    (re.compile(r"ORA-[0-9]{4,5}", re.I), "Oracle"),
    (re.compile(r"Oracle error", re.I), "Oracle"),
    (re.compile(r"OracleException", re.I), "Oracle (.NET)"),

    # SQLite
    (re.compile(r"SQLite.*Exception", re.I), "SQLite"),
    (re.compile(r"sqlite3\.OperationalError", re.I), "SQLite (Python)"),
    (re.compile(r"near \".*\": syntax error", re.I), "SQLite"),

    # Generic
    (re.compile(r"SQLSTATE\[\d+\]", re.I), "Generic (SQLSTATE)"),
    (re.compile(r"ODBC.*Driver.*error", re.I), "Generic ODBC"),
)


class SqlInjectionProbe(WebProbeBase):
    name: str = "sql_injection"
    description: str = "SQL Injection (error-based) tespit"
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
                        title=f"SQL Injection: `{param}` parametresi ({dbms})",
                        description=(
                            f"`{param}` parametresine `{payload}` gönderildiğinde yanıt "
                            f"gövdesinde {dbms} veritabanı hata mesajı tespit edildi "
                            f"(`{matched_pattern}`). Bu, parametrenin SQL sorgusuna "
                            f"parametreli (prepared statement) değil, düz string olarak "
                            f"yapıştırıldığını gösterir. Saldırgan bu parametreyi kullanarak "
                            f"kimlik doğrulama atlama, veritabanı içeriği okuma veya "
                            f"(yetkiye göre) değiştirme saldırısı yapabilir."
                        ),
                        target=full_url,
                        remediation=(
                            "Bu parametreyi veritabanı sorgusunda **parametreli sorgu "
                            "(prepared statement / parameterized query)** ile kullanın. "
                            "String concatenation yerine `?` placeholder + bind değişkeni. "
                            "ORM kullanıyorsanız raw SQL yerine ORM metodlarını tercih edin. "
                            "Acil geçici çözüm: WAF (Cloudflare, ModSecurity) ekleyin, "
                            "ama bu sadece geçici — kod seviyesinde parametrik sorgu şart."
                        ),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=full_url,
                            response_status=response.status_code,
                            response_snippet=self._extract_error_context(
                                response.text, matched_pattern,
                            ),
                            why_vulnerable=f"{dbms} hata mesajı yanıta düştü",
                            extra={"payload": payload, "param": param, "dbms": dbms},
                        ),
                    ),
                )
                reported_params.add(param)
                break  # Bir probe yeterli kanıt; diğer payload'ları atla

        return findings

    # -----------------------------------------------------------------
    @staticmethod
    def _match_sql_error(body: str) -> tuple[str | None, str]:
        """Yanıt gövdesinde SQL hata pattern'i var mı bak."""
        # İlk 16KB'de ara — tam body'yi işlemek gereksiz
        snippet = body[:16384]
        for pattern, dbms in _SQL_ERROR_PATTERNS:
            match = pattern.search(snippet)
            if match:
                return match.group(0), dbms
        return None, ""

    @staticmethod
    def _extract_error_context(body: str, matched_text: str) -> str:
        """Eşleşen hatayı saran ~150 karakterlik bağlam döndürür (kanıt için)."""
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
