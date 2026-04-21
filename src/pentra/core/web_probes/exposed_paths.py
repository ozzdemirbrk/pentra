"""Exposed Paths probe — hassas dosya/klasörlerin public erişimini kontrol eder.

Yaygın "yanlışlıkla sunulmuş" yolların listesini dener. 200 yanıtı +
içerik parmak izi (ör. `.env` içinde `=` karakteri, `.git/config` içinde
`[core]`) → zafiyet raporu.

**Seviye 2 kuralı:** Her yol tek seferlik denenir; dosya içeriği tamamen
indirilmez — sadece ilk 200 bayt örneklenir.
"""

from __future__ import annotations

from urllib.parse import urljoin

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity


# (path, severity, title, description, optional content fingerprint)
_SENSITIVE_PATHS: tuple[tuple[str, Severity, str, str, str], ...] = (
    # path, severity, title, description, content signature (boş = sadece 200 yeter)
    (
        "/.env",
        Severity.CRITICAL,
        ".env dosyası public erişilebilir",
        "`.env` dosyası web kökünden erişilebilir. Bu dosyada genellikle veritabanı "
        "parolaları, API anahtarları, secret key'ler bulunur.",
        "=",
    ),
    (
        "/.git/config",
        Severity.HIGH,
        ".git deposu public erişilebilir",
        "`.git/config` dosyası public. Saldırgan tüm kaynak kodunu indirebilir "
        "(`.git/` dizininden `git-dumper` ile) ve gizli dosya geçmişine ulaşabilir.",
        "[core]",
    ),
    (
        "/.git/HEAD",
        Severity.HIGH,
        ".git/HEAD public",
        "`.git/HEAD` public — kaynak kodu çıkarma saldırısına açık.",
        "ref:",
    ),
    (
        "/.svn/entries",
        Severity.HIGH,
        ".svn deposu public",
        "`.svn/entries` public — eski SVN depolarında kaynak kodu sızar.",
        "",
    ),
    (
        "/backup.sql",
        Severity.CRITICAL,
        "Veritabanı yedeği public",
        "`/backup.sql` erişilebilir. Tüm DB şeması + veriler sızabilir.",
        "",
    ),
    (
        "/database.sql",
        Severity.CRITICAL,
        "Veritabanı yedeği public",
        "`/database.sql` erişilebilir. DB içeriği sızabilir.",
        "",
    ),
    (
        "/dump.sql",
        Severity.CRITICAL,
        "Veritabanı dump'ı public",
        "`/dump.sql` erişilebilir.",
        "",
    ),
    (
        "/wp-config.php.bak",
        Severity.CRITICAL,
        "WordPress yapılandırması (.bak) sızmış",
        "`wp-config.php.bak` erişilebilir. DB parolası ve secret key'ler içerir.",
        "",
    ),
    (
        "/wp-config.php.save",
        Severity.CRITICAL,
        "WordPress yapılandırması (.save) sızmış",
        "`wp-config.php.save` erişilebilir.",
        "",
    ),
    (
        "/config.json",
        Severity.HIGH,
        "config.json public",
        "Uygulama yapılandırması dışarıya sızıyor olabilir — sırlar içerebilir.",
        "",
    ),
    (
        "/config.yml",
        Severity.HIGH,
        "config.yml public",
        "Uygulama yapılandırması dışarıya sızıyor olabilir — sırlar içerebilir.",
        "",
    ),
    (
        "/.htaccess",
        Severity.MEDIUM,
        ".htaccess dosyası erişilebilir",
        "`.htaccess` Apache yapılandırması normalde okunamamalı. Erişilebilir olması "
        "uygulama yapılandırması bilgisi sızdırır.",
        "",
    ),
    (
        "/.DS_Store",
        Severity.LOW,
        ".DS_Store sızmış (macOS meta veri)",
        "`.DS_Store` dosyası macOS tarafından oluşturulur ve klasör içindeki dosya "
        "listesini içerir. Saldırgan gizli dosya adlarını öğrenebilir.",
        "",
    ),
    (
        "/server-status",
        Severity.MEDIUM,
        "Apache server-status public",
        "`/server-status` sayfası aktif bağlantıları, istekleri, vhosts bilgisini "
        "dışa açar — saldırganın keşif yüzeyini büyütür.",
        "",
    ),
    (
        "/admin",
        Severity.INFO,
        "Admin paneli tespit edildi",
        "`/admin` yolu yanıt veriyor. Bu bir zafiyet değil ama saldırganın odak "
        "noktası olur; güçlü kimlik doğrulama + IP kısıtlaması önerilir.",
        "",
    ),
    (
        "/phpmyadmin",
        Severity.LOW,
        "phpMyAdmin public",
        "`/phpmyadmin` erişilebilir. Brute-force hedefi olur; IP kısıtlaması + "
        "güçlü parola + ideally VPN arkasına çekme önerilir.",
        "",
    ),
    (
        "/phpinfo.php",
        Severity.HIGH,
        "phpinfo.php public",
        "`phpinfo.php` erişilebilir. PHP yapılandırması, yollar, environment değişkenleri, "
        "yüklü eklentiler vb. hassas bilgiler sızıyor.",
        "PHP Version",
    ),
    # security.txt ayrı ele alınır (ters mantık: varsa iyi, yoksa uyar)
)


class ExposedPathsProbe(WebProbeBase):
    name: str = "exposed_paths"
    description: str = "Hassas dosya/klasörlerin public erişim kontrolü"

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        base = url.rstrip("/")

        for path, severity, title, description, signature in _SENSITIVE_PATHS:
            full_url = urljoin(base + "/", path.lstrip("/"))

            try:
                response = session.get(
                    full_url, timeout=self.timeout, allow_redirects=False,
                )
            except requests.RequestException:
                continue

            if not self._is_exposed(response, signature):
                continue

            snippet = response.text[:200] if response.content else ""
            findings.append(
                Finding(
                    scanner_name="web_scanner",
                    severity=severity,
                    title=title,
                    description=description,
                    target=full_url,
                    remediation=_build_remediation(path),
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=full_url,
                        response_status=response.status_code,
                        response_snippet=snippet,
                        why_vulnerable=(
                            f"{response.status_code} yanıtı alındı"
                            + (f" + `{signature}` imzası içeriyor" if signature else "")
                        ),
                    ),
                ),
            )

        # security.txt — ters mantık: yoksa uyar
        security_txt_url = urljoin(base + "/", ".well-known/security.txt")
        try:
            sec_response = session.get(
                security_txt_url, timeout=self.timeout, allow_redirects=False,
            )
            if sec_response.status_code == 404:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.INFO,
                        title="security.txt yok",
                        description=(
                            "`/.well-known/security.txt` dosyası yok. Güvenlik "
                            "araştırmacılarının size zafiyet bildirebilmesi için "
                            "bu dosyayı yayınlayın."
                        ),
                        target=security_txt_url,
                        remediation=_REMEDIATION_FOR_SECURITY_TXT,
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=security_txt_url,
                            response_status=404,
                            why_vulnerable="Dosya yok (404)",
                        ),
                    ),
                )
        except requests.RequestException:
            pass

        return findings

    @staticmethod
    def _is_exposed(response: requests.Response, signature: str) -> bool:
        """200 yanıtı + (varsa) içerik imzası eşleşmesi."""
        if response.status_code != 200:
            return False
        if not signature:
            return True
        # İçerik küçük olabilir — yalnızca ilk 2KB'a bak
        text = response.text[:2048] if response.content else ""
        return signature in text


_REMEDIATION_FOR_SECURITY_TXT = (
    "`/.well-known/security.txt` dosyası oluşturun. İçeriği örnek: "
    "`Contact: mailto:security@example.com`, `Expires: 2027-01-01T00:00:00Z`. "
    "Detaylar: https://securitytxt.org"
)


def _build_remediation(path: str) -> str:
    """Path'e göre Türkçe onarım önerisi."""
    if path.startswith("/.git"):
        return (
            "Web kökünde `.git/` dizini BULUNMAMALI. Deploy sürecinde `.git` klasörünü "
            "hariç tutun (`.gitignore` server tarafında işe yaramaz — dosyaları hiç kopyalamayın). "
            "Nginx: `location ~ /\\.git { deny all; }` · Apache: `RedirectMatch 404 /\\.git`"
        )
    if path == "/.env":
        return (
            "`.env` dosyası kesinlikle web kökünde olmamalı — uygulamanın bir üst "
            "dizininde tutun. Acil çözüm olarak sunucuda erişimi engelleyin ve "
            "dosyadaki tüm parolaları/anahtarları DEĞİŞTİRİN (sızmış kabul edin)."
        )
    if path.endswith(".sql"):
        return "Yedek dosyalarını asla web dizininde tutmayın. Hemen silin ve veritabanı parolalarını değiştirin."
    if "wp-config" in path:
        return (
            "Yedek dosyalarını web dizininde tutmayın. Hemen silin ve WordPress "
            "DB parolasını + secret key'leri değiştirin (sızmış sayın)."
        )
    if path == "/phpinfo.php":
        return "phpinfo.php'yi silin — geliştirme araçları production'da olmamalı."
    if path == "/.htaccess":
        return "Sunucu yapılandırmasını `.htaccess` dosyalarına public erişimi engelleyecek şekilde düzeltin."
    if path == "/.DS_Store":
        return "`.DS_Store` dosyasını deploy'dan hariç tutun. `.gitignore`'a ekleyin: `**/.DS_Store`"
    if path == "/server-status":
        return "Apache `mod_status` modülünü kapatın veya sadece localhost'a izin verecek şekilde kısıtlayın."
    if path == "/admin":
        return "Admin paneline sadece VPN veya belirli IP'ler üzerinden erişime izin verin. Güçlü parola + MFA zorunlu."
    if path == "/phpmyadmin":
        return (
            "phpMyAdmin'i kaldırın veya VPN arkasına taşıyın. Public erişim "
            "brute-force + zafiyet denemesinin ilk hedefi olur."
        )
    return "Bu kaynağa public erişimi engelleyin; yalnızca yetkili IP'ler üzerinden erişilebilir olmalı."
