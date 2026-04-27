"""Detailed Turkish remediation guides.

A five-section step-by-step guide for every finding type:
    1. **Problem summary** — repeats the title
    2. **Why it matters** — risk context + attack scenario
    3. **How to fix** — server variants (Nginx/Apache/IIS/Cloudflare)
    4. **Verification** — post-fix test command
    5. **References** — trusted documentation links

The report template presents these as a "Show detailed guide" expandable card.
If no guide is defined for a finding, the short `remediation` string is used.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from pentra.models import Finding


@dataclasses.dataclass(frozen=True)
class FixStep:
    """A single remediation step for a specific server/service."""

    platform: str  # "Nginx" / "Apache" / "IIS (web.config)" / "Cloudflare Dashboard"
    instructions: str  # Turkish description (Markdown-light: ** bold, ` code `)
    code: str = ""  # Copy-paste snippet (optional)


@dataclasses.dataclass(frozen=True)
class RemediationGuide:
    """Full guide for a finding type."""

    problem_summary: str
    why_important: str
    fix_steps: tuple[FixStep, ...]
    verification: str  # "Düzeltmeyi doğrulayın: `curl -I https://...`"
    references: tuple[tuple[str, str], ...]  # ((title, url), ...)


# =====================================================================
# Guides
# =====================================================================
_CSP_GUIDE = RemediationGuide(
    problem_summary="Content-Security-Policy (CSP) header'ı yanıtta yok.",
    why_important=(
        "CSP, tarayıcı seviyesinde XSS ve data injection saldırılarına karşı en "
        "etkili savunmadır. Header yoksa saldırgan injection yaparsa tarayıcı "
        "hiç ayrım yapmadan gelen her script'i çalıştırır. Saldırı senaryosu: "
        "bir formda XSS açığı varsa, saldırganın kullanıcıya tıklattığı link "
        "ile cookie/session çalınır. CSP bunu engelleyebilir."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "`nginx.conf` veya ilgili site dosyasında `server` bloğuna ekleyin. "
            "Önce Report-Only ile başlayın, hataları izleyip gerçeğe geçin:",
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
            "`httpd.conf` veya `.htaccess` dosyasına ekleyin:",
            code=(
                'Header always set Content-Security-Policy-Report-Only '
                '"default-src \'self\'; script-src \'self\'; '
                'style-src \'self\' \'unsafe-inline\'"'
            ),
        ),
        FixStep(
            "IIS (web.config)",
            "`<system.webServer><httpProtocol><customHeaders>` altına ekleyin:",
            code=(
                '<add name="Content-Security-Policy" value="default-src \'self\'; '
                'script-src \'self\'; style-src \'self\' \'unsafe-inline\'" />'
            ),
        ),
        FixStep(
            "Cloudflare Dashboard",
            "Rules → Transform Rules → Modify Response Header → "
            "`Content-Security-Policy` set et. Bu CDN seviyesinde uygulanır, "
            "sunucu yapılandırmasına dokunmadan kurulabilir.",
        ),
    ),
    verification=(
        "Düzeltmeyi doğrulayın: `curl -I https://siteniz.com | grep -i "
        "content-security-policy` çıktısında header görünmeli. Tarayıcıda "
        "DevTools → Network → ilgili isteği seç → Response Headers."
    ),
    references=(
        ("MDN CSP", "https://developer.mozilla.org/docs/Web/HTTP/CSP"),
        ("OWASP CSP Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
        ("CSP Evaluator", "https://csp-evaluator.withgoogle.com/"),
    ),
)

_HSTS_GUIDE = RemediationGuide(
    problem_summary="Strict-Transport-Security (HSTS) header'ı yok.",
    why_important=(
        "HSTS yoksa tarayıcı, ilk ziyarette HTTPS yerine HTTP'ye bağlanmaya "
        "çalışabilir. Ağ üzerindeki saldırgan (kafe wifi'si, yolcu) bu ilk "
        "HTTP isteğini yakalayıp SSL stripping saldırısı yapabilir — kullanıcı "
        "sahte bir HTTP sitesi görür, parolasını girer, saldırgan okur. "
        "HSTS tarayıcıya 'bu domain'de HER ZAMAN HTTPS kullan' diye söyler."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "Sadece HTTPS server bloğunda, includeSubDomains + preload için:",
            code=(
                'add_header Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains; preload" always;'
            ),
        ),
        FixStep(
            "Apache",
            "`httpd.conf` içinde `<VirtualHost *:443>` altına:",
            code=(
                'Header always set Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains; preload"'
            ),
        ),
        FixStep(
            "IIS (web.config)",
            "HTTPS binding'i olan site için customHeaders altına:",
            code=(
                '<add name="Strict-Transport-Security" '
                'value="max-age=31536000; includeSubDomains; preload" />'
            ),
        ),
        FixStep(
            "Cloudflare",
            "SSL/TLS → Edge Certificates → HSTS → 'Enable HSTS'. "
            "Max Age: 12 months, Include Subdomains: on, Preload: on. "
            "Cloudflare otomatik uygular.",
        ),
    ),
    verification=(
        "`curl -I https://siteniz.com | grep -i strict-transport` çıktısında "
        "`max-age=31536000` görünmeli. HSTS preload listesine başvurmak için: "
        "https://hstspreload.org"
    ),
    references=(
        ("MDN HSTS", "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"),
        ("HSTS Preload", "https://hstspreload.org/"),
    ),
)

_XFO_GUIDE = RemediationGuide(
    problem_summary="X-Frame-Options header'ı yok — clickjacking'e açık.",
    why_important=(
        "Bu header olmadan saldırgan, sitenizi görünmez bir iframe içine "
        "gömebilir ve kullanıcıyı sahte bir butona tıklatarak sizin sitenizde "
        "istenmeyen eylem yaptırabilir (bu saldırıya **clickjacking** denir). "
        "Örnek: kullanıcı 'Ücretsiz hediye al' butonuna bastığını sanırken "
        "aslında sizin sitenizdeki 'Hesabı sil' butonuna tıklar."
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
            "Modern Alternatif — CSP frame-ancestors",
            "X-Frame-Options yerine (veya yanında) CSP kullanımı modern "
            "tarayıcılarda tercih edilir:",
            code="Content-Security-Policy: frame-ancestors 'self';",
        ),
    ),
    verification=(
        "`curl -I https://siteniz.com | grep -i x-frame` → "
        "`X-Frame-Options: SAMEORIGIN` dönmeli."
    ),
    references=(
        ("MDN X-Frame-Options", "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"),
        ("OWASP Clickjacking", "https://owasp.org/www-community/attacks/Clickjacking"),
    ),
)

_XCTO_GUIDE = RemediationGuide(
    problem_summary="X-Content-Type-Options header'ı yok — MIME sniffing riski.",
    why_important=(
        "Tarayıcılar bazen `Content-Type` header'ını yok sayıp dosyanın "
        "içeriğine bakarak ne olduğunu tahmin eder (MIME sniffing). Bu "
        "durumda saldırgan `.jpg` uzantısıyla yüklenmiş bir dosyayı "
        "tarayıcıya script olarak çalıştırabilir. `nosniff` direktifi bu "
        "davranışı kapatır — tarayıcı server'ın söylediği content-type'ı kullanır."
    ),
    fix_steps=(
        FixStep("Nginx", "", code='add_header X-Content-Type-Options "nosniff" always;'),
        FixStep("Apache", "", code='Header always set X-Content-Type-Options "nosniff"'),
        FixStep("IIS (web.config)", "", code='<add name="X-Content-Type-Options" value="nosniff" />'),
        FixStep(
            "Django", "Middleware'e eklenir (3.0+ için default):",
            code='SECURE_CONTENT_TYPE_NOSNIFF = True',
        ),
    ),
    verification="`curl -I https://siteniz.com | grep -i x-content-type` → `nosniff` görünmeli.",
    references=(
        ("MDN X-Content-Type-Options", "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ),
)

_REFERRER_GUIDE = RemediationGuide(
    problem_summary="Referrer-Policy header'ı yok — referer bilgisi sızıyor.",
    why_important=(
        "Kullanıcı sitenizden başka bir siteye link ile geçtiğinde, varsayılan "
        "olarak tarayıcı 'hangi sayfadan geldiğini' (`Referer` header'ı) hedef "
        "siteye söyler. Eğer URL'de hassas veri (session token, arama sorgusu, "
        "ID vb.) varsa bu üçüncü taraflara sızar. `Referrer-Policy` bu "
        "davranışı kısıtlar."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "`strict-origin-when-cross-origin` dengelidir (aynı site: full URL, "
            "farklı site: sadece origin):",
            code='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        ),
        FixStep(
            "Apache", "",
            code='Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        ),
        FixStep("IIS (web.config)", "",
            code='<add name="Referrer-Policy" value="strict-origin-when-cross-origin" />'),
    ),
    verification="`curl -I https://siteniz.com | grep -i referrer-policy`",
    references=(
        ("MDN Referrer-Policy", "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"),
    ),
)

_SERVER_LEAK_GUIDE = RemediationGuide(
    problem_summary="Sunucu versiyonu `Server` header'ında açığa çıkıyor.",
    why_important=(
        "Saldırgan bu bilgiye bakarak hedefin tam sürümünü öğrenir ve ona özel "
        "CVE'leri/exploitleri dener. Örnek: `Server: Apache/2.4.41` gören "
        "saldırgan 2.4.41 sürümünde bilinen zafiyetleri arar. Versiyonu "
        "gizlemek güvenliği artırmaz (defense in depth) ama keşif yüzeyini "
        "küçültür — saldırgan tahminde bulunmak zorunda kalır."
    ),
    fix_steps=(
        FixStep(
            "Nginx",
            "`http` bloğunda (ana `nginx.conf` içinde):",
            code="server_tokens off;",
        ),
        FixStep(
            "Apache",
            "`httpd.conf` içinde:",
            code="ServerTokens Prod\nServerSignature Off",
        ),
        FixStep(
            "IIS",
            "`web.config` içinde URL Rewrite modülü ile Server header'ını sil. "
            "Ya da `<security><requestFiltering removeServerHeader=\"true\" />`:",
            code='<system.webServer>\n  <security>\n    <requestFiltering removeServerHeader="true" />\n  </security>\n</system.webServer>',
        ),
        FixStep(
            "Cloudflare",
            "Rules → Transform Rules → Modify Response Header → Remove → `Server`. "
            "Orjin sunucunun header'ı CDN'de kaldırılır.",
        ),
    ),
    verification="`curl -I https://siteniz.com | grep -i '^server:'` komutunda sadece `Server: nginx` gibi minimum bilgi olmalı, versiyon numarası gözükmemeli.",
    references=(
        ("Nginx server_tokens", "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"),
        ("Apache ServerTokens", "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"),
    ),
)

_HTTP_ONLY_GUIDE = RemediationGuide(
    problem_summary="Site HTTP üzerinden sunuluyor (şifresiz).",
    why_important=(
        "HTTP trafiği ağı dinleyen herhangi biri tarafından okunabilir — parolalar, "
        "çerezler, form verileri açıkta. Modern tarayıcılar artık HTTP siteleri "
        "'Güvenli Değil' olarak işaretliyor. SEO tarafı için Google HTTPS'yi "
        "ranking faktörü olarak kullanıyor. HTTPS geçişi artık opsiyonel değil."
    ),
    fix_steps=(
        FixStep(
            "Sertifika Alma (Let's Encrypt — Ücretsiz)",
            "`certbot` ile otomatik kurulum + 90 günlük otomatik yenileme:",
            code="sudo apt install certbot python3-certbot-nginx\n"
                 "sudo certbot --nginx -d siteniz.com -d www.siteniz.com",
        ),
        FixStep(
            "Nginx — HTTP'den HTTPS'ye 301 yönlendirme",
            "",
            code="server {\n"
                 "    listen 80;\n"
                 "    server_name siteniz.com www.siteniz.com;\n"
                 '    return 301 https://$server_name$request_uri;\n'
                 "}",
        ),
        FixStep(
            "Apache — mod_rewrite ile yönlendirme",
            "`.htaccess` veya VirtualHost içinde:",
            code="RewriteEngine On\n"
                 "RewriteCond %{HTTPS} !=on\n"
                 "RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]",
        ),
        FixStep(
            "Cloudflare — Tek Tıkla",
            "SSL/TLS → Edge Certificates → 'Always Use HTTPS' → On. "
            "Cloudflare tüm HTTP isteklerini HTTPS'ye yönlendirir. "
            "Sertifika da ücretsiz gelir.",
        ),
    ),
    verification=(
        "`curl -I http://siteniz.com` → `301` yanıtı + `Location: https://...` görünmeli. "
        "Tarayıcıda HTTP URL'yi yazdığında otomatik HTTPS'ye geçilmeli."
    ),
    references=(
        ("Let's Encrypt", "https://letsencrypt.org/"),
        ("Mozilla SSL Config Generator", "https://ssl-config.mozilla.org/"),
    ),
)

_SECURITY_TXT_GUIDE = RemediationGuide(
    problem_summary="/.well-known/security.txt dosyası yok.",
    why_important=(
        "Güvenlik araştırmacıları bir zafiyet bulduğunda size nasıl ulaşacaklarını "
        "bilmelidir. `security.txt` standardı (RFC 9116), araştırmacıların güvenlik "
        "iletişim bilgisini otomatik bulabilmesini sağlar. Dosya yoksa araştırmacı "
        "ya sosyal medyadan bulmaya çalışır (kaybolabilir) ya da public açığa atar "
        "(daha kötü). Küçük bir dosya büyük fark yaratır."
    ),
    fix_steps=(
        FixStep(
            "İçerik",
            "Aşağıdaki metni `/.well-known/security.txt` olarak yayınlayın:",
            code="Contact: mailto:security@siteniz.com\n"
                 "Expires: 2027-01-01T00:00:00Z\n"
                 "Preferred-Languages: tr, en\n"
                 "Canonical: https://siteniz.com/.well-known/security.txt",
        ),
        FixStep(
            "Web Sunucusu Düzenleme",
            "Dosyayı `/.well-known/` dizinine yerleştirin. Yol çoğu sunucuda "
            "otomatik çalışır — Nginx/Apache static file olarak serve eder. "
            "Content-Type: text/plain olmalı.",
        ),
    ),
    verification="`curl https://siteniz.com/.well-known/security.txt` içeriği döndürmeli (200 + text/plain).",
    references=(
        ("RFC 9116 (security.txt)", "https://www.rfc-editor.org/rfc/rfc9116.html"),
        ("securitytxt.org", "https://securitytxt.org/"),
    ),
)

_REDIS_OPEN_GUIDE = RemediationGuide(
    problem_summary="Redis sunucusu parolasız erişilebilir.",
    why_important=(
        "Redis auth'suz açıksa saldırgan tüm veriyi okuyabilir, silebilir. "
        "Daha kötüsü: `CONFIG SET dir /home/redis/.ssh` + `CONFIG SET dbfilename "
        "authorized_keys` + `SET x \"ssh-rsa...\"` + `SAVE` kombinasyonuyla "
        "sunucuya SSH anahtar yazıp tam sistem kontrolü alabilir. 2017'den beri "
        "internet'e açık Redis'lerin binlercesi ransomware'e kurban oldu."
    ),
    fix_steps=(
        FixStep(
            "1. Güçlü parola + localhost bağlama",
            "`/etc/redis/redis.conf` düzenleyip Redis'i yeniden başlat:",
            code="# Sadece localhost'tan erişim\n"
                 "bind 127.0.0.1 ::1\n"
                 "# Güçlü parola — 32+ karakter, rastgele\n"
                 'requirepass "<64 karakter rastgele dizi>"\n'
                 "# Protected mode aktif kalsın\n"
                 "protected-mode yes\n"
                 "# Tehlikeli komutları devre dışı bırak\n"
                 'rename-command FLUSHDB ""\n'
                 'rename-command FLUSHALL ""\n'
                 'rename-command CONFIG ""',
        ),
        FixStep(
            "2. ACL (Redis 6+) kullanımı",
            "Modern yaklaşım — her uygulama için ayrı kullanıcı:",
            code="ACL SETUSER myapp on >guclu_parola ~myapp:* +@read +@write -@dangerous",
        ),
        FixStep(
            "3. Güvenlik duvarı",
            "Uzak Redis gerekiyorsa (bulut) sadece uygulama IP'lerinden:",
            code="sudo ufw allow from <app_ip> to any port 6379\n"
                 "sudo ufw deny 6379",
        ),
        FixStep(
            "4. TLS",
            "Redis 6+ TLS destekler — production'da şart:",
            code="tls-port 6380\n"
                 "tls-cert-file /path/to/cert.pem\n"
                 "tls-key-file /path/to/key.pem",
        ),
    ),
    verification=(
        "`redis-cli -h <ip> PING` parolasız CHANNELS error dönmeli (NOAUTH). "
        "Parolayla `redis-cli -a <parola> PING` → PONG."
    ),
    references=(
        ("Redis Security", "https://redis.io/docs/management/security/"),
        ("Redis ACL", "https://redis.io/docs/management/security/acl/"),
    ),
)

_MONGODB_OPEN_GUIDE = RemediationGuide(
    problem_summary="MongoDB sunucusu parolasız erişilebilir.",
    why_important=(
        "MongoDB 3.6 öncesi varsayılan olarak auth YOKTU — milyonlarca eski instance "
        "hâlâ açıkta. Auth olmadan saldırgan tüm koleksiyonları okuyabilir, silebilir. "
        "2017'den beri 'MongoDB ransomware' saldırıları çok yaygın: saldırgan tüm "
        "veriyi silip yerine 'bitcoin gönder, veri iade edilir' mesajı bırakıyor."
    ),
    fix_steps=(
        FixStep(
            "1. Admin kullanıcı + auth aktif",
            "MongoDB'yi `--auth` olmadan başlatın, admin oluşturun, sonra `--auth`'la restart:",
            code='mongosh\n'
                 'use admin\n'
                 'db.createUser({\n'
                 '  user: "admin",\n'
                 '  pwd: "<güçlü-parola>",\n'
                 '  roles: [{ role: "root", db: "admin" }]\n'
                 '})',
        ),
        FixStep(
            "2. Config dosyası",
            "`/etc/mongod.conf`:",
            code="security:\n"
                 "  authorization: enabled\n"
                 "net:\n"
                 "  bindIp: 127.0.0.1  # Sadece localhost\n"
                 "  port: 27017",
        ),
        FixStep(
            "3. Yeniden başlat + test",
            "",
            code="sudo systemctl restart mongod\n"
                 "mongosh  # auth'suz bağlantı artık çoğu komut için reddedilmeli",
        ),
        FixStep(
            "4. Uygulama başına ayrı kullanıcı",
            "Root kullanıcı sadece yönetim için. Her uygulama için minimum yetkili kullanıcı:",
            code='use mydatabase\n'
                 'db.createUser({\n'
                 '  user: "myapp",\n'
                 '  pwd: "<uygulama-parolası>",\n'
                 '  roles: [{ role: "readWrite", db: "mydatabase" }]\n'
                 '})',
        ),
    ),
    verification=(
        "`mongosh --host <ip>` auth'suz çalıştırıp `show dbs` denediğinizde "
        "'command listDatabases requires authentication' dönmeli."
    ),
    references=(
        ("MongoDB Security Checklist", "https://www.mongodb.com/docs/manual/administration/security-checklist/"),
    ),
)

_ELASTICSEARCH_OPEN_GUIDE = RemediationGuide(
    problem_summary="Elasticsearch cluster parolasız erişilebilir.",
    why_important=(
        "ES açık olduğunda saldırgan `_search` ile tüm indeks verisini çekebilir, "
        "`DELETE` ile silebilir. 2017'den bu yana ES cluster leak'leri internet "
        "veri sızıntılarının önde gelen sebebi — milyonlarca kullanıcı kaydı, "
        "sağlık verisi, finansal bilgi bu şekilde açığa çıktı."
    ),
    fix_steps=(
        FixStep(
            "1. X-Pack Security aktif (ES 6.8+ ücretsiz)",
            "`elasticsearch.yml`:",
            code="xpack.security.enabled: true\n"
                 "xpack.security.transport.ssl.enabled: true",
        ),
        FixStep(
            "2. Parola oluşturma",
            "",
            code="cd /usr/share/elasticsearch\n"
                 "bin/elasticsearch-setup-passwords auto",
        ),
        FixStep(
            "3. Localhost'a bağla (uzak erişim gerekmiyorsa)",
            "",
            code="network.host: 127.0.0.1\n"
                 "http.port: 9200",
        ),
        FixStep(
            "4. Güvenlik duvarı",
            "",
            code="sudo ufw deny 9200\n"
                 "sudo ufw allow from <app_ip> to any port 9200",
        ),
    ),
    verification=(
        "`curl http://<ip>:9200/` authenticated olmadan `missing authentication "
        "credentials` hatası vermeli. `curl -u elastic:<parola> http://<ip>:9200/` "
        "cluster info döndürmeli."
    ),
    references=(
        ("Elastic Security", "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html"),
    ),
)

_MYSQL_DEFAULT_GUIDE = RemediationGuide(
    problem_summary="MySQL root kullanıcı varsayılan/boş parola ile erişilebilir.",
    why_important=(
        "MySQL root parolasız ise saldırgan tüm veritabanlarını okur, değiştirir, "
        "siler. `SELECT ... INTO OUTFILE` ile sunucuya dosya yazabilir (UDF "
        "tekniği ile sunucuya tam erişim bile alabilir). Üretim sunucusunda "
        "varsayılan parolayla MySQL çalıştırmak ciddi bir ihmaldir."
    ),
    fix_steps=(
        FixStep(
            "1. mysql_secure_installation",
            "Hazır otomatik script — root parolasını değiştirir, anonim kullanıcıları, "
            "test DB'sini, uzak root erişimini temizler:",
            code="sudo mysql_secure_installation",
        ),
        FixStep(
            "2. Manuel — root parolasını değiştir",
            "",
            code="mysql -u root\n"
                 "mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY '<güçlü-parola>';\n"
                 "mysql> FLUSH PRIVILEGES;",
        ),
        FixStep(
            "3. Uzak root'u kaldır",
            "Root hesabı sadece localhost'tan erişilebilir olsun:",
            code="mysql> DROP USER IF EXISTS 'root'@'%';\n"
                 "mysql> DROP USER IF EXISTS 'root'@'::';\n"
                 "mysql> FLUSH PRIVILEGES;",
        ),
        FixStep(
            "4. Localhost'a bağla",
            "`/etc/mysql/my.cnf`:",
            code="[mysqld]\n"
                 "bind-address = 127.0.0.1",
        ),
    ),
    verification=(
        "`mysql -u root` parolasız `Access denied` vermeli. "
        "`mysql -u root -p` parola sorunca girilmeli."
    ),
    references=(
        ("MySQL Security Guidelines", "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"),
    ),
)

_SSH_DEFAULT_GUIDE = RemediationGuide(
    problem_summary="SSH varsayılan parola (root:root / admin:admin) ile erişilebilir.",
    why_important=(
        "SSH brute-force saldırısı internetteki en yaygın saldırı türüdür — "
        "saniyede binlerce deneme yapan botnet'ler her zaman tarama halindedir. "
        "Varsayılan parolayla SSH açık tutmak, sunucunun birkaç dakika içinde "
        "ele geçirilmesi demektir. Ele geçirildikten sonra: ransomware, crypto "
        "miner kurulumu, botnet'e katılım, yan sistemlere sıçrama (lateral movement)."
    ),
    fix_steps=(
        FixStep(
            "1. ACİL — Parola değiştir",
            "",
            code="sudo passwd root   # Uzun, rastgele, 16+ karakter",
        ),
        FixStep(
            "2. ÖNERİLEN — Parola ile SSH'yi TAMAMEN kapat, sadece key kullan",
            "`/etc/ssh/sshd_config`:",
            code="PasswordAuthentication no\n"
                 "PermitRootLogin no          # Root hiç giremesin\n"
                 "PubkeyAuthentication yes\n"
                 "ChallengeResponseAuthentication no",
        ),
        FixStep(
            "3. SSH key oluşturma (istemci tarafında)",
            "",
            code="# Windows'ta PowerShell veya Git Bash'te:\n"
                 "ssh-keygen -t ed25519 -a 100 -C 'email@domain.com'\n"
                 "# Public key'i sunucuya kopyala:\n"
                 "ssh-copy-id user@sunucu.com",
        ),
        FixStep(
            "4. fail2ban kur — brute-force koruma",
            "",
            code="sudo apt install fail2ban\n"
                 "sudo systemctl enable --now fail2ban\n"
                 "# /etc/fail2ban/jail.local içinde sshd jail'i varsayılan aktif",
        ),
        FixStep(
            "5. SSH portunu değiştir (defense-in-depth)",
            "22 portu sürekli taranır. 22xxx gibi değişik port, otomatik saldırı yüzeyini azaltır. "
            "`sshd_config`'te:",
            code="Port 22876   # Rastgele 4-5 haneli port seç",
        ),
    ),
    verification=(
        "`ssh root@sunucu` → 'Permission denied (publickey)' dönmeli "
        "(parola bile sorulmamalı). Key ile girdiğinizde girilmeli."
    ),
    references=(
        ("DigitalOcean SSH Hardening", "https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu"),
        ("Mozilla OpenSSH Guidelines", "https://infosec.mozilla.org/guidelines/openssh"),
    ),
)

_WIFI_OPEN_GUIDE = RemediationGuide(
    problem_summary="Şifresiz (Open) Wi-Fi ağı tespit edildi.",
    why_important=(
        "Şifresiz Wi-Fi'de tüm trafik ortamdaki herhangi biri tarafından dinlenebilir "
        "— HTTPS olmayan sitelerdeki parolalar, çerezler, form verileri açıkta. "
        "Ayrıca saldırgan sahte bir kablosuz ağ oluşturup (Evil Twin) kullanıcıları "
        "ağa çekebilir ve tüm trafiği yönlendirebilir. Misafir Wi-Fi diye şifre "
        "koymamak bir seçenek değil — misafir Wi-Fi bile şifreli olmalı."
    ),
    fix_steps=(
        FixStep(
            "1. Router yönetim paneline gir",
            "Tarayıcıda router IP'sini aç (genelde **192.168.1.1** veya **192.168.0.1**). "
            "Admin kullanıcı adı + parolasıyla gir. Bilmiyorsan router'ın altındaki "
            "sticker'a bak.",
        ),
        FixStep(
            "2. Şifreleme ayarını aç",
            "Menüde **Kablosuz (Wireless) → Güvenlik** bölümüne git. Güvenlik modu: "
            "**WPA3-Personal** seç (varsa) ya da **WPA2-Personal (AES/CCMP)**. "
            "WEP ve 'Open' seçeneklerini ASLA kullanma.",
        ),
        FixStep(
            "3. Güçlü bir parola belirle",
            "En az 12 karakter, karışık. Wi-Fi parolası genelde bir kez girilir, "
            "uzun olsun. Örnek yapı: 3-4 rastgele kelime birleştir.",
            code="Kabul edilebilir: Yagmurlu-Pazar-Kedi-Su42!\n"
                 "Çok güçlü:         correct-horse-battery-staple-99",
        ),
        FixStep(
            "4. Misafir ağı kur",
            "Modern router'larda 'Guest Network' özelliği var — etkinleştirin. "
            "Misafirler bu ağa bağlansın, ana ağınıza erişim olmasın. Böylece "
            "misafirin malware'li cihazı sizin akıllı TV'nize/yazıcınıza erişemez.",
        ),
        FixStep(
            "5. WPS'i kapat",
            "WPS ('kolay bağlanma' tuşu) brute-force saldırısına açıktır. Router "
            "ayarlarında WPS'i kapatın — modern cihazlar QR kod ile daha güvenli "
            "bağlanıyor zaten.",
        ),
    ),
    verification=(
        "Wi-Fi ayarlarını görüntüle → ağın yanında kilit ikonu görünmeli. "
        "Yeni bir cihazla bağlanmayı dene, parola isteyecektir."
    ),
    references=(
        ("EFF: Create a Strong Password", "https://ssd.eff.org/module/creating-new-password"),
        ("CISA: Secure Wireless Networks", "https://www.cisa.gov/news-events/news/securing-wireless-networks"),
    ),
)

_WIFI_WEP_GUIDE = RemediationGuide(
    problem_summary="WEP şifrelemeli Wi-Fi ağı — kırık algoritma.",
    why_important=(
        "WEP şifrelemesi 2007'den beri kırık. Modern bir dizüstü + aircrack-ng "
        "birkaç dakikada WEP anahtarını çözer. Bu ağ pratik olarak şifresiz "
        "sayılmalı — saldırgan ağa bağlanıp iç sistemlere erişebilir (yazıcı, "
        "NAS, akıllı ev cihazları)."
    ),
    fix_steps=(
        FixStep(
            "ACİL — WEP'i kapat, WPA2/3'e geç",
            "Router yönetim paneli → Kablosuz → Güvenlik: "
            "**WPA2-Personal (AES)** veya **WPA3-Personal**. WEP'i asla bırakma.",
        ),
        FixStep(
            "Eski cihazlar için ayrı ağ",
            "Eğer eski Wi-Fi cihazlarınız WPA2'yi desteklemiyorsa, onlar için "
            "ayrı bir Guest Network kurun — ana ağınız WPA2/3 kalsın. Veya "
            "eski cihazları değiştirin.",
        ),
        FixStep(
            "Router modern mi?",
            "2010 öncesi router'lar WPA3'ü, bazıları iyi WPA2'yi bile "
            "desteklemez. Yeni bir router almak (500-1500 TL) iyi yatırımdır. "
            "Wi-Fi 6 (802.11ax) destekli modeller tercih edilir.",
        ),
    ),
    verification="Wi-Fi ayarları → güvenlik türü 'WPA2' veya 'WPA3' yazmalı, 'WEP' değil.",
    references=(
        ("Aircrack-ng tutorial", "https://www.aircrack-ng.org/doku.php?id=tutorial"),
    ),
)

_WIFI_OLD_WPA_GUIDE = RemediationGuide(
    problem_summary="Eski WPA (TKIP) şifrelemeli ağ — WPA2'den zayıf.",
    why_important=(
        "Orijinal WPA (TKIP ile) 2004'te geldi ama 2012'den beri zayıflıkları "
        "biliniyor. WPA2'ye (AES/CCMP) geçiş güvenlik için şart. TKIP brute-force "
        "ve packet injection saldırılarına WPA2-AES'ten daha açık."
    ),
    fix_steps=(
        FixStep(
            "WPA2 veya WPA3'e geç",
            "Router paneli → Kablosuz → Güvenlik: **WPA2-Personal (AES/CCMP)** "
            "veya **WPA3-Personal**. Mixed mode (WPA/WPA2) KULLANMAYIN — "
            "sadece WPA2 veya sadece WPA3 seçin.",
        ),
        FixStep(
            "Parolayı yenile",
            "WPA'dan WPA2/3'e geçerken parolayı da değiştir — eski parola "
            "eski güvenlik modelinin parçasıydı.",
        ),
    ),
    verification="Wi-Fi ayarları → 'WPA2' veya 'WPA3' yazmalı, 'WPA' tek başına değil.",
    references=(
        ("Cisco: WPA vs WPA2 vs WPA3", "https://www.cisco.com/c/en/us/products/wireless/what-is-wpa3.html"),
    ),
)

_EXPOSED_ENV_GUIDE = RemediationGuide(
    problem_summary=".env dosyası web kökünden erişilebilir — kritik sırlar ifşa.",
    why_important=(
        ".env dosyasında genellikle DB parolaları, API anahtarları, secret key'ler "
        "bulunur. Bu dosya web root'unda olmamalı — ama yanlış deploy kurgusu "
        "sonucu çoğu zaman oraya düşer. Saldırgan `curl https://siteniz.com/.env` "
        "ile tüm sırları indirir, kısa sürede veritabanınıza, e-posta sağlayıcınıza, "
        "AWS hesabınıza erişir."
    ),
    fix_steps=(
        FixStep(
            "1. ACİL — Dosyayı web kökünden kaldır",
            "",
            code="# Sunucuda:\n"
                 "mv /var/www/html/.env /var/www/.env   # Web root'un BİR ÜST dizinine",
        ),
        FixStep(
            "2. Tüm sırları DEĞİŞTİR (sızmış sayın)",
            ".env görüldüyse saldırgan kopyalamış olabilir. Tüm parolaları, API "
            "anahtarlarını, secret key'leri sıfırlayın:",
            code="# DB parolası\nALTER USER webapp WITH PASSWORD '<yeni-parola>';\n"
                 "# Laravel APP_KEY yenile\nphp artisan key:generate\n"
                 "# AWS credential rotate (IAM console'dan)",
        ),
        FixStep(
            "Nginx — yedek olarak erişimi engelle",
            "Deploy hatası tekrar ederse son savunma:",
            code="location ~ /\\.env {\n    deny all;\n    return 404;\n}",
        ),
        FixStep(
            "Apache — .htaccess ile",
            "",
            code='<FilesMatch "^\\.env">\n'
                 '    Require all denied\n'
                 '</FilesMatch>',
        ),
    ),
    verification=(
        "`curl https://siteniz.com/.env` → 404 veya 403 dönmeli, dosya içeriği değil."
    ),
    references=(
        ("OWASP: Sensitive Data Exposure", "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"),
        ("12-Factor App — Config", "https://12factor.net/config"),
    ),
)

_SQL_INJECTION_GUIDE = RemediationGuide(
    problem_summary="SQL Injection zafiyeti — parametre SQL sorgusuna düz string olarak yapıştırılıyor.",
    why_important=(
        "SQL injection web uygulamalarının en kritik zafiyetlerinden biri (OWASP "
        "Top 10 #3). Saldırgan özel hazırlanmış input ile login atlayabilir, tüm "
        "DB içeriğini çekebilir (`UNION SELECT`), yetkili kullanıcı oluşturabilir, "
        "hatta yetki varsa sunucuya komut çalıştırabilir. 2011'den beri en yaygın "
        "veri sızıntı vektörü."
    ),
    fix_steps=(
        FixStep(
            "PRİMER — Parametreli sorgular (prepared statements)",
            "String birleştirme YERINE mutlaka parameter binding kullan:",
            code="# YANLIŞ (SQLi'ye açık)\n"
                 "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
                 "# DOĞRU (parametreli)\n"
                 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        ),
        FixStep(
            "ORM kullan",
            "SQLAlchemy, Django ORM, Prisma vb. — raw SQL yerine tercih edin. "
            "ORM default olarak parametrelendirir.",
            code="# Django\n"
                 "User.objects.filter(id=user_id)  # otomatik güvenli",
        ),
        FixStep(
            "Input validation (katmanlı savunma)",
            "Beklenen tipe dönüştür, uzunluk kontrol et. Ör. sayı bekliyorsa "
            "int()'e çevir; başarısızsa reddet.",
        ),
        FixStep(
            "Veritabanı kullanıcısı least-privilege",
            "Uygulama kullanıcısı sadece gerekli tablolara READ/WRITE yetkili. "
            "DROP, CREATE, GRANT gibi yetkiler OLMAMALI — SQLi'de sınır çizer.",
        ),
        FixStep(
            "WAF (geçici savunma)",
            "Cloudflare, ModSecurity gibi WAF'lar SQLi pattern'lerini engeller "
            "ama SAHIPLEYICIYI YAZILIMDAN KAÇIRMAZ — mutlaka parametreli sorguya geç.",
        ),
    ),
    verification=(
        "Düzeltme sonrası probe'u tekrar çalıştır — SQL hata mesajı dönmemeli. "
        "Manuel test: `?id=1'` → normal sayfa veya controlled error, asla "
        "'You have an error in your SQL syntax' dönmemeli."
    ),
    references=(
        ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
        ("Bobby Tables", "https://bobby-tables.com/"),
    ),
)

_XSS_GUIDE = RemediationGuide(
    problem_summary="Reflected XSS — kullanıcı girdisi yanıtta kaçışsız yansıtılıyor.",
    why_important=(
        "Saldırgan özel URL hazırlar, kullanıcı tıklar, tarayıcısında saldırganın "
        "JS kodu çalışır: session cookie çalma, fake login formu göster, kullanıcı "
        "adına istek gönder. Phishing + account takeover'ın en yaygın yolu."
    ),
    fix_steps=(
        FixStep(
            "PRİMER — Context-aware escaping",
            "Kullanıcı girdisini HTML'e yazmadan önce escape et. Her context "
            "farklı escape gerektirir:",
            code="# HTML body → html.escape\n"
                 "import html\n"
                 "safe = html.escape(user_input)  # < → &lt;\n\n"
                 "# JS string içinde → json.dumps\n"
                 "import json\n"
                 'safe_js = json.dumps(user_input)  # " → \\"',
        ),
        FixStep(
            "Framework autoescape kullan",
            "Modern framework'lerde varsayılan otomatik escape:",
            code="{# Jinja2 — default autoescape açık #}\n"
                 "<p>{{ user_input }}</p>         {# güvenli #}\n"
                 "<p>{{ user_input | safe }}</p>  {# TEHLİKELİ — escape'i kapatır #}\n\n"
                 "// React — JSX default escape\n"
                 "<p>{userInput}</p>           // güvenli\n"
                 "<p dangerouslySetInnerHTML=...>  // TEHLİKELİ",
        ),
        FixStep(
            "Content Security Policy (CSP)",
            "CSP header'ı XSS'in etkisini azaltır (inline script'i engeller). "
            "CSP eksik rehberine bakın.",
        ),
        FixStep(
            "HttpOnly + SameSite cookies",
            "Session cookie'yi HttpOnly + Secure + SameSite yap — XSS JS ile "
            "cookie okuyamaz.",
            code="Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict",
        ),
    ),
    verification="Probe'u tekrar çalıştır — payload artık escape edilmiş (&lt; &gt;) dönmeli.",
    references=(
        ("OWASP XSS", "https://owasp.org/www-community/attacks/xss/"),
        ("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    ),
)

_PATH_TRAVERSAL_GUIDE = RemediationGuide(
    problem_summary="Path traversal / directory traversal — yol parametresi dizin dışına çıkabiliyor.",
    why_important=(
        "Saldırgan `../../etc/passwd`, `../../../windows/win.ini` tipi payload "
        "göndererek web uygulamasının erişebildiği herhangi bir dosyayı okuyabilir "
        "— kaynak kod, yapılandırma, session dosyaları, hatta bazı durumlarda "
        "SSH private key. Sistemin tam keşfine yol açar."
    ),
    fix_steps=(
        FixStep(
            "Allowlist ile dosya adı doğrulama",
            "İzin verilen dosyaları belirtin, diğerleri reddedin:",
            code="ALLOWED = {'product-1.pdf', 'product-2.pdf', ...}\n"
                 "if filename not in ALLOWED:\n"
                 "    return 403",
        ),
        FixStep(
            "realpath ile yolu normalize et, kök içinde olduğunu doğrula",
            "En güvenilir kontrol:",
            code="from pathlib import Path\n"
                 "allowed_root = Path('/var/www/uploads').resolve()\n"
                 "user_file = (allowed_root / filename).resolve()\n"
                 "if not user_file.is_relative_to(allowed_root):\n"
                 "    return 403   # path traversal denemesi",
        ),
        FixStep(
            "../ ve /../ karakterleri filtrele (ama yetersiz!)",
            "Tek başına yeterli değil ama ek savunma:",
            code="if '..' in filename or '/' in filename or '\\\\' in filename:\n"
                 "    return 400",
        ),
        FixStep(
            "Web sunucusu seviyesinde",
            "Nginx — hassas dizinleri engelle:",
            code="location ~ \\.\\.\\/ { return 400; }\n"
                 "location /etc { deny all; }",
        ),
    ),
    verification="Probe tekrar: `?file=../../../etc/passwd` → `/etc/passwd` içeriği DÖNMEMELI; 400/403 olmalı.",
    references=(
        ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
    ),
)

_SSL_OLD_PROTOCOL_GUIDE = RemediationGuide(
    problem_summary="Eski TLS/SSL sürümü (SSLv3/TLSv1.0/TLSv1.1) destekleniyor.",
    why_important=(
        "Bu sürümler bilinen saldırılara açık: POODLE (SSLv3), BEAST (TLS 1.0), "
        "Lucky 13. Modern tarayıcılar 2020'den beri TLS 1.0/1.1'i desteklemiyor. "
        "Eski sürümleri açık bırakmak hem güvenlik hem uyumluluk (PCI-DSS, HIPAA) "
        "için sorun."
    ),
    fix_steps=(
        FixStep(
            "Nginx — sadece TLS 1.2 ve 1.3",
            "",
            code="ssl_protocols TLSv1.2 TLSv1.3;\n"
                 "ssl_prefer_server_ciphers off;  # TLS 1.3 için\n"
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
            code="# SSLv3 ve eski TLS'leri kapat\n"
                 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server" -Name Enabled -Value 0\n'
                 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name Enabled -Value 0',
        ),
        FixStep(
            "Cloudflare",
            "SSL/TLS → Edge Certificates → Minimum TLS Version: 1.2.",
        ),
    ),
    verification=(
        "Online test: https://www.ssllabs.com/ssltest/ → Protocol Support'ta "
        "TLS 1.0, 1.1 'No' olmalı. Komut satırı: "
        "`openssl s_client -connect siteniz.com:443 -tls1 2>&1 | grep -i error`"
    ),
    references=(
        ("Mozilla SSL Config", "https://ssl-config.mozilla.org/"),
        ("SSL Labs Test", "https://www.ssllabs.com/ssltest/"),
    ),
)

_SSL_CERT_PROBLEM_GUIDE = RemediationGuide(
    problem_summary="SSL sertifika doğrulama sorunu (süresi dolmuş, self-signed, hostname uyuşmazlığı vb.).",
    why_important=(
        "Tarayıcı 'Bu bağlantı güvenli değil' uyarısı gösterir — kullanıcılar siteyi "
        "terk eder veya (daha kötüsü) uyarıyı geçmeyi alışkanlık haline getirir. "
        "İkinci senaryo gerçek MITM saldırılarında kullanıcının dikkatini azaltır."
    ),
    fix_steps=(
        FixStep(
            "Let's Encrypt (ücretsiz, otomatik yenileme)",
            "",
            code="sudo apt install certbot python3-certbot-nginx\n"
                 "sudo certbot --nginx -d siteniz.com -d www.siteniz.com\n"
                 "# Cron ile otomatik yenileme (certbot default kurar)",
        ),
        FixStep(
            "Sertifika zinciri eksik ise",
            "Genelde 'intermediate certificate' eksikliğinden kaynaklanır. "
            "CA'nizden fullchain.pem alın, Nginx için ssl_certificate'a o'nu gösterin:",
            code="ssl_certificate     /etc/letsencrypt/live/siteniz.com/fullchain.pem;\n"
                 "ssl_certificate_key /etc/letsencrypt/live/siteniz.com/privkey.pem;",
        ),
        FixStep(
            "Hostname uyuşmazlığı",
            "Sertifikanın SAN (Subject Alternative Name) alanında tüm kullanılan "
            "domain'ler olmalı. Certbot'a tüm domain'leri -d ile ver: "
            "`-d siteniz.com -d www.siteniz.com -d api.siteniz.com`.",
        ),
        FixStep(
            "Süresi dolmuş ise",
            "Let's Encrypt certbot otomatik yeniler. Manuel yenileme:",
            code="sudo certbot renew --force-renewal",
        ),
    ),
    verification=(
        "Tarayıcıda site → adres çubuğunda kilit ikonu. Komut: "
        "`openssl s_client -connect siteniz.com:443 -servername siteniz.com "
        "</dev/null 2>/dev/null | openssl x509 -noout -dates`"
    ),
    references=(
        ("Let's Encrypt", "https://letsencrypt.org/"),
        ("SSL Checker", "https://www.ssllabs.com/ssltest/"),
    ),
)

_POSTGRES_DEFAULT_GUIDE = RemediationGuide(
    problem_summary="PostgreSQL varsayılan parola (postgres:postgres / postgres:'') kabul ediliyor.",
    why_important=(
        "PostgreSQL default user `postgres` superuser'dır — saldırgan tüm DB'leri "
        "okuyabilir, siler, `COPY TO PROGRAM` ile sunucuda komut çalıştırabilir. "
        "Üretimde varsayılan parolayla PostgreSQL çalıştırmak kritik bir hatadır."
    ),
    fix_steps=(
        FixStep(
            "1. Parola değiştir",
            "",
            code="sudo -u postgres psql\n"
                 "postgres=# ALTER USER postgres WITH PASSWORD '<uzun-rastgele-parola>';\n"
                 "postgres=# \\q",
        ),
        FixStep(
            "2. Uzak bağlantıları kısıtla — pg_hba.conf",
            "`/etc/postgresql/<ver>/main/pg_hba.conf`:",
            code="# Local: peer (unix socket auth)\n"
                 "local   all   postgres   peer\n"
                 "# Remote: scram-sha-256 parola zorunlu (md5 eski, güvensiz)\n"
                 "host    all   all        127.0.0.1/32   scram-sha-256",
        ),
        FixStep(
            "3. listen_addresses ayarla",
            "`postgresql.conf`:",
            code="listen_addresses = 'localhost'\n"
                 "password_encryption = scram-sha-256",
        ),
        FixStep(
            "4. Güvenlik duvarı",
            "",
            code="sudo ufw deny 5432\n"
                 "sudo ufw allow from <app_ip> to any port 5432",
        ),
        FixStep(
            "5. Uygulama başına ayrı kullanıcı",
            "postgres superuser sadece admin için. Uygulamaya minimum yetkili kullanıcı:",
            code="CREATE USER myapp WITH PASSWORD '<parola>';\n"
                 "GRANT CONNECT ON DATABASE mydb TO myapp;\n"
                 "GRANT USAGE ON SCHEMA public TO myapp;\n"
                 "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO myapp;",
        ),
    ),
    verification=(
        "`psql -U postgres -h <ip> -W` parolasız çalışmamalı. "
        "`psql -U postgres -h <ip>` parola sormalı."
    ),
    references=(
        ("PostgreSQL Authentication", "https://www.postgresql.org/docs/current/auth-methods.html"),
    ),
)

_EXPOSED_GIT_GUIDE = RemediationGuide(
    problem_summary=".git deposu web kökünden erişilebilir — tüm kaynak kod sızıyor.",
    why_important=(
        "Saldırgan `.git/config` ve `.git/HEAD`'e ulaşabiliyorsa, `git-dumper` "
        "gibi araçlarla tüm git depoyu yeniden kurabilir ve commit geçmişini "
        "çıkarabilir. Bu: tüm kaynak kod + geçmişte yanlışlıkla commit edilmiş "
        "parolalar + API anahtarları + iç iş mantığı = tam ifşa demektir."
    ),
    fix_steps=(
        FixStep(
            "ACİL — .git dizinini web kökünden kaldır",
            "Deploy sürecini düzelt. Production'a kaynak kodu ile birlikte `.git` "
            "kopyalamayın. Doğru deploy: `git archive`, `rsync --exclude='.git'`, "
            "CI/CD pipeline (GitHub Actions vb.).",
            code="# Acil çözüm — server'da .git'i sil\n"
                 "sudo rm -rf /var/www/html/.git",
        ),
        FixStep(
            "Web sunucusu — `.git/` erişimini engelle (yedek savunma)",
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
            "Geçmişte sızmış sırları rotate et",
            "`.git` erişilmişse geçmiş commit'lerdeki TÜM sırları sızmış say: "
            "DB parolaları, API anahtarları, JWT secret, AWS credentials. "
            "`truffleHog` veya `gitleaks` ile geçmişte sızdırılmış sırları bul.",
        ),
    ),
    verification="`curl -I https://siteniz.com/.git/config` → 404 veya 403 dönmeli.",
    references=(
        ("git-dumper", "https://github.com/arthaud/git-dumper"),
        ("gitleaks", "https://github.com/gitleaks/gitleaks"),
    ),
)

_EXPOSED_SQL_DUMP_GUIDE = RemediationGuide(
    problem_summary="Veritabanı yedeği (.sql) web kökünden indirilebiliyor.",
    why_important=(
        "Bu tam ifşa: tablo şeması + TÜM veri (kullanıcı hesapları, parolalar "
        "hash'li olsa bile offline brute-force için), sipariş detayları, mesajlar. "
        "Admin kullanıcının parola hash'i ele geçerse offline kırma denemesi başlar."
    ),
    fix_steps=(
        FixStep(
            "ACİL — Dosyayı sil, DB parolalarını değiştir",
            "SQL dump görüldüyse saldırgan kopyalamış sayılmalı. Tüm DB parolalarını, "
            "hash edilmiş kullanıcı parolalarını zorla sıfırla (kullanıcıları "
            "parola değişimine yönlendir).",
            code="sudo rm /var/www/html/backup.sql\n"
                 "# DB parolalarını değiştir\n"
                 "# Kullanıcılara 'parolanızı değiştirin' e-postası",
        ),
        FixStep(
            "Yedekleri web kökünde tutma",
            "Yedekler her zaman web erişimi olmayan bir dizinde (`/var/backups/`) "
            "veya dış depolamada (S3 encrypted bucket, Backblaze B2) olmalı.",
            code="# Doğru yedek dizini\n"
                 "/var/backups/db/  # web tarafından erişilemez\n"
                 "# Otomatik yedek script + rotation\n"
                 "mysqldump mydb | gzip > /var/backups/db/$(date +%F).sql.gz",
        ),
        FixStep(
            "Nginx — .sql uzantılarını engelle",
            "",
            code='location ~ \\.(sql|bak|old|backup)$ {\n'
                 '    deny all;\n'
                 '    return 404;\n'
                 "}",
        ),
    ),
    verification="`curl -I https://siteniz.com/backup.sql` → 404.",
    references=(
        ("OWASP Backup Files", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"),
    ),
)

_EXPOSED_WP_CONFIG_GUIDE = RemediationGuide(
    problem_summary="WordPress wp-config.php yedeği (.bak/.save) public — DB parolası ve secret'lar ifşa.",
    why_important=(
        "wp-config.php WordPress'in DB bağlantı parolasını, table prefix'ini ve "
        "8 adet güvenlik secret key'ini içerir. Yedek dosyası görüldüyse saldırgan "
        "DB'ye direkt erişebilir, secret key'lerle session hijack yapabilir."
    ),
    fix_steps=(
        FixStep(
            "ACİL — Yedekleri sil, tüm parolaları yenile",
            "",
            code="rm /var/www/html/wp-config.php.bak\n"
                 "rm /var/www/html/wp-config.php.save\n\n"
                 "# DB parolasını değiştir (MySQL'de)\n"
                 "ALTER USER wp_user WITH PASSWORD '<yeni>';\n"
                 "# wp-config.php güncelle (DB_PASSWORD)\n\n"
                 "# WordPress secret key'leri yenile\n"
                 "curl -s https://api.wordpress.org/secret-key/1.1/salt/\n"
                 "# Çıktıyı wp-config.php'ye yapıştır",
        ),
        FixStep(
            "Editor yedek dosyalarını engelle",
            "Nginx:",
            code='location ~ \\.(bak|save|swp|orig|tmp)$ {\n'
                 '    deny all;\n'
                 '    return 404;\n'
                 "}",
        ),
        FixStep(
            "wp-config.php'yi web kökünün bir üstüne taşı",
            "WordPress bunu destekler — daha güvenli:",
            code="# /var/www/html/ içinde WP kurulu ise\n"
                 "mv wp-config.php ../wp-config.php\n"
                 "# WP otomatik bir üst dizinde arar",
        ),
    ),
    verification="`curl -I https://siteniz.com/wp-config.php.bak` → 404.",
    references=(
        ("WordPress Hardening", "https://wordpress.org/documentation/article/hardening-wordpress/"),
    ),
)

_EXPOSED_HTACCESS_GUIDE = RemediationGuide(
    problem_summary=".htaccess dosyası web üzerinden okunabilir.",
    why_important=(
        ".htaccess Apache yapılandırma direktiflerini içerir — RewriteRule'lar, "
        "AuthType, IP whitelist/blacklist. Okunduğunda saldırgan uygulamanın "
        "route mantığını ve (varsa) HTTP basic auth credentials dosya yolunu görür."
    ),
    fix_steps=(
        FixStep(
            "Apache — kendi dizin koruma kuralı",
            "Apache default olarak .htaccess okumasını engeller. Eğer engellenmiyorsa:",
            code='<FilesMatch "^\\.ht">\n'
                 '    Require all denied\n'
                 '</FilesMatch>',
        ),
        FixStep(
            "Mümkünse .htaccess yerine httpd.conf kullan",
            "`.htaccess` performans ve güvenlik açısından httpd.conf'tan daha "
            "zayıf. Her istek dizinde .htaccess arar. Root erişiminiz varsa "
            "kuralları httpd.conf `<Directory>` bloğuna taşıyın.",
        ),
    ),
    verification="`curl -I https://siteniz.com/.htaccess` → 403 veya 404.",
    references=(
        ("Apache Security Tips", "https://httpd.apache.org/docs/2.4/misc/security_tips.html"),
    ),
)

_EXPOSED_DS_STORE_GUIDE = RemediationGuide(
    problem_summary=".DS_Store dosyası web kökünde — macOS meta verisi sızıyor.",
    why_important=(
        ".DS_Store macOS'un Finder'da görüntülenen her dizin için oluşturduğu "
        "binary bir index dosyasıdır. Klasördeki TÜM dosya adlarını içerir. "
        "Web'de görünürse saldırgan gizli backup dosyalarınızı, admin klasörlerinizi, "
        "test scriptlerinizi keşfedebilir."
    ),
    fix_steps=(
        FixStep(
            "Dosyaları sil",
            "",
            code="find /var/www/html -name '.DS_Store' -delete",
        ),
        FixStep(
            "Git'e girmesini engelle (.gitignore)",
            "",
            code="echo '**/.DS_Store' >> .gitignore\n"
                 "git rm --cached **/.DS_Store  # zaten commit edilmişse",
        ),
        FixStep(
            "Web sunucusu engeli",
            "Nginx:",
            code='location ~ \\.DS_Store$ { return 404; }',
        ),
        FixStep(
            "macOS'ta ağ sürücülerde oluşmasını engelle",
            "",
            code="defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true",
        ),
    ),
    verification="`curl -I https://siteniz.com/.DS_Store` → 404.",
    references=(
        ("Apple Tech Note", "https://support.apple.com/en-us/HT208209"),
    ),
)

_EXPOSED_SERVER_STATUS_GUIDE = RemediationGuide(
    problem_summary="Apache /server-status sayfası public erişilebilir.",
    why_important=(
        "/server-status aktif HTTP bağlantıları, son istekler, uptime, "
        "yüklenen modüller, virtual host listesi gibi hassas işletim bilgisini "
        "dışa açar. Saldırgan tarama + keşif yüzeyini büyük ölçüde genişletir."
    ),
    fix_steps=(
        FixStep(
            "Apache — /server-status'u kapat veya kısıtla",
            "`httpd.conf` veya ilgili VirtualHost içinde:",
            code="# Tamamen kapat\n"
                 "<Location /server-status>\n"
                 "    Require all denied\n"
                 "</Location>\n\n"
                 "# Ya da sadece localhost'a izin (iç monitoring için)\n"
                 "<Location /server-status>\n"
                 "    Require host localhost\n"
                 "    Require ip 127.0.0.1\n"
                 "</Location>",
        ),
        FixStep(
            "mod_status modülünü tamamen kaldır (kullanmıyorsanız)",
            "",
            code="sudo a2dismod status\n"
                 "sudo systemctl restart apache2",
        ),
    ),
    verification="`curl -I https://siteniz.com/server-status` → 403 veya 404.",
    references=(
        ("Apache mod_status", "https://httpd.apache.org/docs/2.4/mod/mod_status.html"),
    ),
)

_EXPOSED_PHPINFO_GUIDE = RemediationGuide(
    problem_summary="phpinfo.php public erişilebilir — PHP yapılandırması ifşa.",
    why_important=(
        "phpinfo() çıktısı sunucunun PHP sürümünü, yüklü eklentileri, "
        "environment değişkenlerini (gizli API key'ler olabilir), dosya yollarını, "
        "hatta bazen DB bağlantı bilgilerini gösterir. Geliştirici aracıdır — "
        "production'da kesinlikle olmamalıdır."
    ),
    fix_steps=(
        FixStep(
            "ACİL — Dosyayı sil",
            "",
            code="find /var/www -name 'phpinfo.php' -delete\n"
                 "find /var/www -name 'info.php' -delete\n"
                 "find /var/www -name 'test.php' -delete",
        ),
        FixStep(
            "Environment değişkenlerini sızmış kabul et",
            "phpinfo $_ENV'i dökerse muhtemelen .env veya sistem ortamından "
            "geldi — DB_PASSWORD, API_KEY gibi tüm sırları rotate edin.",
        ),
        FixStep(
            "expose_php = Off (php.ini)",
            "PHP'nin kendi versiyon bilgisini HTTP header'ında sızdırmasını engelle:",
            code="; /etc/php/X.X/apache2/php.ini\n"
                 "expose_php = Off",
        ),
    ),
    verification="`curl -I https://siteniz.com/phpinfo.php` → 404.",
    references=(
        ("PHP Security", "https://www.php.net/manual/en/security.php"),
    ),
)

_EXPOSED_ADMIN_GUIDE = RemediationGuide(
    problem_summary="Yönetim paneli (/admin) public erişilebilir.",
    why_important=(
        "Admin panelleri saldırganların birinci hedefidir — brute-force parola "
        "denemeleri, bilinen CVE'ler (Joomla admin takeover, Drupal SQL injection), "
        "default credentials. Public panel = sürekli saldırı altında."
    ),
    fix_steps=(
        FixStep(
            "VPN veya IP allowlist arkasına taşı",
            "Admin panele sadece ofis IP'sinden veya VPN üzerinden erişim.",
            code="# Nginx — sadece belirli IP'lere izin\n"
                 "location /admin {\n"
                 "    allow 203.0.113.0/24;   # Ofis IP'si\n"
                 "    allow 127.0.0.1;        # Localhost\n"
                 "    deny all;\n"
                 "    proxy_pass http://backend;\n"
                 "}",
        ),
        FixStep(
            "URL'yi tahmin edilemez hale getir",
            "`/admin` yerine `/company-name-panel-xyz12` gibi özel yol. "
            "Güvenlik tek başına yeterli değil ama otomatik tarama yüzeyini daralttır.",
        ),
        FixStep(
            "Kuvvetli parola + MFA + rate limit + fail2ban",
            "Yönetici hesapları: 16+ karakter parola, 2FA zorunlu, "
            "başarısız girişlerde IP bloğu (fail2ban, Cloudflare Rate Limiting).",
        ),
        FixStep(
            "HTTP Basic Auth ile ekstra katman",
            "Uygulama login'inden ÖNCE web server katmanında parola iste:",
            code="# Nginx\n"
                 "location /admin {\n"
                 "    auth_basic 'Restricted';\n"
                 "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
                 "    proxy_pass http://backend;\n"
                 "}",
        ),
    ),
    verification="Dışarıdan `curl -I https://siteniz.com/admin` → 403/401; VPN'den 200.",
    references=(
        ("OWASP Admin Interface", "https://owasp.org/www-community/attacks/Brute_force_attack"),
    ),
)

_EXPOSED_PHPMYADMIN_GUIDE = RemediationGuide(
    problem_summary="phpMyAdmin public erişilebilir.",
    why_important=(
        "phpMyAdmin brute-force saldırılarının birinci hedefidir. 'phpmyadmin', "
        "'pma', 'mysql-admin' gibi path'ler her saniye taranıyor. Ayrıca phpMyAdmin'in "
        "kendi zafiyet geçmişi var (CVE-2020-10804, CVE-2018-19968 vb.) — güncel "
        "tutulsa bile hedef yüzeyi büyük."
    ),
    fix_steps=(
        FixStep(
            "phpMyAdmin'i kaldır (en iyi çözüm)",
            "Modern alternatifler: MySQL Workbench (desktop), Adminer (tek dosya, "
            "hafif), direkt `mysql` CLI. phpMyAdmin gerçekten gerekli mi değerlendir.",
            code="sudo apt remove phpmyadmin\n"
                 "sudo rm -rf /var/www/html/phpmyadmin",
        ),
        FixStep(
            "Gerekliyse VPN arkasına taşı",
            "",
            code="# Nginx — sadece VPN subnet'inden\n"
                 "location /pma-xyz123 {\n"
                 "    allow 10.8.0.0/24;   # VPN subnet\n"
                 "    deny all;\n"
                 "    alias /var/www/phpmyadmin;\n"
                 "}",
        ),
        FixStep(
            "Path'i değiştir + HTTP Basic Auth + fail2ban",
            "`/phpmyadmin` yerine tahmin edilemez path, web katmanında ek auth, "
            "başarısız login'lerde IP bloklama.",
        ),
    ),
    verification="`curl -I https://siteniz.com/phpmyadmin` → 404 veya auth zorunlu.",
    references=(
        ("phpMyAdmin Security", "https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation"),
    ),
)

_X_POWERED_BY_GUIDE = RemediationGuide(
    problem_summary="X-Powered-By header'ı uygulama framework versiyonunu sızdırıyor.",
    why_important=(
        "`X-Powered-By: PHP/7.4.3` gibi header'lar saldırgana hedef yazılımın "
        "tam sürümünü verir. Saldırgan o sürüme özgü CVE'leri arar, exploit dener. "
        "Gizlemek kesin güvenlik değil ama keşif yüzeyini küçültür."
    ),
    fix_steps=(
        FixStep(
            "PHP — expose_php kapat",
            "`php.ini`:",
            code="expose_php = Off",
        ),
        FixStep(
            "Nginx — tüm Powered-By header'ını kaldır",
            "",
            code='more_clear_headers "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version";',
        ),
        FixStep(
            "Express.js (Node.js)",
            "",
            code="app.disable('x-powered-by');",
        ),
        FixStep(
            "IIS — ASP.NET version header'ı",
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
    verification="`curl -I https://siteniz.com/ | grep -i powered` komutunda header görünmemeli.",
    references=(
        ("OWASP Fingerprinting", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"),
    ),
)

# --- Port-based guides ---

_PORT_RDP_GUIDE = RemediationGuide(
    problem_summary="RDP (Remote Desktop, port 3389) açık.",
    why_important=(
        "RDP internet'te en çok saldırıya uğrayan servislerden biri. BlueKeep "
        "(CVE-2019-0708), DejaBlue, NLA bypass, CredSSP gibi kritik zafiyetler. "
        "Ayrıca brute-force ve parola sprey saldırıları sürekli. 2020-2022 "
        "ransomware saldırılarının %55'i public RDP üzerinden başladı."
    ),
    fix_steps=(
        FixStep(
            "RDP'yi public'ten KALDIR, VPN arkasına al",
            "Bu en kritik adım. VPN kurulumu (WireGuard, OpenVPN, Tailscale) "
            "→ RDP sadece VPN subnet'inden erişilebilir. 3389 portu dışarıya "
            "tamamen kapalı olmalı.",
        ),
        FixStep(
            "Windows Firewall — 3389 portunu block",
            "",
            code="# PowerShell (admin)\n"
                 "New-NetFirewallRule -DisplayName 'Block-RDP-Public' "
                 "-Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block",
        ),
        FixStep(
            "Port değiştirme (güvenlik değil, gürültü azaltma)",
            "3389 yerine random port (ör. 50189). Kayıt defteri:",
            code='Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
                 '-Name PortNumber -Value 50189',
        ),
        FixStep(
            "NLA (Network Level Authentication) zorunlu",
            "Kayıt defteri veya Grup Politikası → 'Require use of specific "
            "security layer for RDP connections' → 'SSL (TLS 1.0)' + "
            "'Require NLA' → Enabled.",
        ),
        FixStep(
            "Kuvvetli parola + MFA + Account lockout",
            "Admin hesap parolası 16+ karakter. Azure AD / Duo gibi MFA. "
            "Group Policy → 'Account lockout threshold' → 5 failed attempts.",
        ),
    ),
    verification="Dışarıdan `Test-NetConnection siteniz.com -Port 3389` → Failed. VPN ile bağlanınca çalışmalı.",
    references=(
        ("CISA RDP Alert", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-073a"),
    ),
)

_PORT_SMB_GUIDE = RemediationGuide(
    problem_summary="SMB (port 445, microsoft-ds) açık.",
    why_important=(
        "SMB public'e açılmış olması CISA'nın 'en tehlikeli 10 konfigürasyon "
        "hatası' listesinde. EternalBlue (CVE-2017-0144), SMBGhost (CVE-2020-0796), "
        "PrintNightmare gibi kritik zafiyetlerin tümü SMB üzerinden. 2017 WannaCry "
        "saldırısı bu zafiyetle yayıldı."
    ),
    fix_steps=(
        FixStep(
            "Public SMB'yi KAPATMAK — tek güvenli yol",
            "SMB internet'e açık olmamalı. Firewall'da 445 portunu dışarıdan block, "
            "iç ağda bile sadece gerekli subnet'lere izin ver.",
            code="# Windows Firewall\n"
                 "New-NetFirewallRule -DisplayName 'Block-SMB-Public' "
                 "-Direction Inbound -Protocol TCP -LocalPort 445 -Action Block",
        ),
        FixStep(
            "SMBv1'i tamamen devre dışı bırak",
            "SMBv1 (kullanımdan kalkmış) en saldırıya açık sürüm. EternalBlue bunu "
            "hedefler.",
            code='Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol',
        ),
        FixStep(
            "SMB signing zorunlu",
            "",
            code='Set-SmbServerConfiguration -RequireSecuritySignature $true',
        ),
        FixStep(
            "SMB yerine SFTP/Nextcloud değerlendir",
            "Dosya paylaşımı için SFTP + kullanıcı başına dizin veya Nextcloud "
            "(self-hosted) SMB'den çok daha güvenli.",
        ),
    ),
    verification="Dışarıdan port 445'e telnet/Test-NetConnection → erişim olmamalı.",
    references=(
        ("Microsoft: Disable SMBv1", "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"),
    ),
)

_PORT_FTP_GUIDE = RemediationGuide(
    problem_summary="FTP (port 21) açık — şifrelenmemiş dosya transferi.",
    why_important=(
        "FTP 1985'ten kalma, şifrelenmemiş bir protokol. Kullanıcı adı, parola, "
        "dosya içeriği ağı dinleyen herkes tarafından okunabilir. Ayrıca anonim "
        "FTP yapılandırılmış olabilir — isimsiz erişim. 2025'te FTP kullanmanın "
        "neredeyse hiç meşru sebebi yok."
    ),
    fix_steps=(
        FixStep(
            "FTP yerine SFTP (SSH üzerinden) kullan",
            "SFTP modern, şifreli, SSH'in zaten açık olan 22 portunu kullanır. "
            "FileZilla, WinSCP gibi istemciler SFTP destekler.",
            code="# Client bağlantı örneği\n"
                 "sftp user@sunucu.com\n"
                 "# veya PuTTY/FileZilla'da 'SFTP' protokolü seç",
        ),
        FixStep(
            "FTPS (FTP over TLS) alternatif",
            "Eski FTP istemcileri ile uyumluluk gerekiyorsa FTPS (explicit TLS):",
            code="# vsftpd.conf\n"
                 "ssl_enable=YES\n"
                 "force_local_data_ssl=YES\n"
                 "force_local_logins_ssl=YES",
        ),
        FixStep(
            "FTP servisini kaldır",
            "",
            code="sudo systemctl stop vsftpd\n"
                 "sudo systemctl disable vsftpd\n"
                 "sudo apt remove vsftpd",
        ),
        FixStep(
            "Anonim FTP'yi devre dışı bırak (kullanılıyorsa)",
            "",
            code="# vsftpd.conf\n"
                 "anonymous_enable=NO\n"
                 "local_enable=YES",
        ),
    ),
    verification="`curl ftp://siteniz.com` → bağlanamamalı. `sftp user@siteniz.com` → çalışmalı.",
    references=(
        ("SFTP Hardening", "https://infosec.mozilla.org/guidelines/openssh"),
    ),
)

_PORT_TELNET_GUIDE = RemediationGuide(
    problem_summary="Telnet (port 23) açık — şifrelenmemiş uzaktan erişim.",
    why_important=(
        "Telnet FTP'den bile eski (1969!) ve tamamen şifresiz. Parola ve tüm "
        "komutlar açık metinde. 2020'den sonra açık olması ciddi bir ihmal "
        "göstergesidir. Modern OS'lar Telnet desteğini default kapalı tutar."
    ),
    fix_steps=(
        FixStep(
            "SSH'e geç — Telnet'i tamamen kaldır",
            "SSH 1995'ten beri Telnet'in yerine. Modern, şifreli, güçlü auth.",
            code="# Linux\n"
                 "sudo systemctl stop telnet\n"
                 "sudo systemctl disable telnet\n"
                 "sudo apt remove telnetd\n\n"
                 "# SSH açık olduğundan emin ol\n"
                 "sudo systemctl enable --now ssh",
        ),
        FixStep(
            "Windows — Telnet istemcisini bile kapat",
            "",
            code='Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient',
        ),
    ),
    verification="`telnet siteniz.com 23` → connection refused.",
    references=(
        ("RFC on deprecating Telnet", "https://www.rfc-editor.org/rfc/rfc4949.html"),
    ),
)

_PORT_VNC_GUIDE = RemediationGuide(
    problem_summary="VNC (port 5900) açık — zayıf şifreli uzaktan masaüstü.",
    why_important=(
        "VNC default protokolü (RFB) yalnızca parola için zayıf DES şifreleme "
        "kullanır, ekran trafiği genelde şifresizdir. TightVNC, RealVNC'in eski "
        "sürümleri brute-force ve DoS zafiyetlerine açık. Public'e açık VNC "
        "çoğunlukla default parolayla çalışır."
    ),
    fix_steps=(
        FixStep(
            "VPN veya SSH tünel arkasına taşı",
            "VNC public'e açık olmamalı. SSH tünel ile bağlan:",
            code="# Client'ta:\n"
                 "ssh -L 5901:localhost:5900 user@sunucu\n"
                 "# VNC client'ı localhost:5901'e bağlar — şifreli",
        ),
        FixStep(
            "VNC yerine RDP (Windows) veya NoMachine (Linux)",
            "RDP native şifreleme + NLA destekler. NoMachine SSH üzerinden "
            "çalışır, VNC'den çok daha güvenli.",
        ),
        FixStep(
            "Kullanılmıyorsa VNC servisini kapat",
            "",
            code="sudo systemctl stop vncserver\n"
                 "sudo systemctl disable vncserver",
        ),
        FixStep(
            "Kullanılacaksa — güçlü parola + TLS",
            "TigerVNC veya modern RealVNC TLS destekler. Config'de TLS zorla, "
            "password en az 16 karakter.",
        ),
    ),
    verification="Dışarıdan `telnet siteniz.com 5900` → bağlantı olmamalı. İçeriden SSH tüneliyle çalışmalı.",
    references=(
        ("VNC Security", "https://tigervnc.org/doc/vncserver.html"),
    ),
)

_PORT_GENERIC_GUIDE = RemediationGuide(
    problem_summary="Açık bir TCP portu tespit edildi.",
    why_important=(
        "Her açık port bir saldırı yüzeyidir. Gerçekten gerekli olmayan her port "
        "kapalı olmalı — minimum exposure prensibi. Gerekli portlar bile güvenlik "
        "duvarıyla belirli IP/subnet'lere kısıtlanmalı."
    ),
    fix_steps=(
        FixStep(
            "Gerçekten gerekli mi sor",
            "Bu port hangi servisi çalıştırıyor? Bu servis public'e açık "
            "kalmalı mı? Eğer sadece localhost kullanıyorsa bağlama adresini "
            "`127.0.0.1` yap — dışarı erişim olmasın.",
        ),
        FixStep(
            "Güvenlik duvarı — default deny, gerekli olanı allow",
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
            "Servis yazılımını güncel tut",
            "Açık port + eski yazılım = kritik CVE riski. Otomatik güvenlik "
            "güncellemesi aç (`unattended-upgrades`, Windows Update).",
        ),
    ),
    verification="Dışarıdan `nc -zv siteniz.com <port>` → engellenmiş / timeout olmalı.",
    references=(
        ("NIST Firewall Guide", "https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final"),
    ),
)


# =====================================================================
# Finding title -> guide key mapping
# =====================================================================
_TitleMatcher = Callable[[str], bool]

# (guide_key, matcher, guide) — matcher returns True on title pattern match
_PATTERN_MATCHERS: tuple[tuple[str, _TitleMatcher, RemediationGuide], ...] = (
    ("csp_missing", lambda t: "CSP eksik" in t, _CSP_GUIDE),
    ("hsts_missing", lambda t: "HSTS eksik" in t, _HSTS_GUIDE),
    ("xfo_missing", lambda t: "X-Frame-Options eksik" in t, _XFO_GUIDE),
    ("xcto_missing", lambda t: "X-Content-Type-Options eksik" in t, _XCTO_GUIDE),
    ("referrer_missing", lambda t: "Referrer-Policy eksik" in t, _REFERRER_GUIDE),
    ("server_leak", lambda t: "Versiyon sızıntısı: Server" in t, _SERVER_LEAK_GUIDE),
    ("http_only", lambda t: "HTTP üzerinden sunuluyor" in t, _HTTP_ONLY_GUIDE),
    ("security_txt", lambda t: "security.txt yok" in t, _SECURITY_TXT_GUIDE),
    ("redis_open", lambda t: "Redis parolasız" in t, _REDIS_OPEN_GUIDE),
    ("mongodb_open", lambda t: "MongoDB parolasız" in t, _MONGODB_OPEN_GUIDE),
    ("elasticsearch_open", lambda t: "Elasticsearch parolasız" in t, _ELASTICSEARCH_OPEN_GUIDE),
    ("mysql_default", lambda t: "MySQL varsayılan parola" in t, _MYSQL_DEFAULT_GUIDE),
    ("ssh_default", lambda t: "SSH varsayılan parola" in t, _SSH_DEFAULT_GUIDE),
    ("env_exposed", lambda t: ".env dosyası public" in t, _EXPOSED_ENV_GUIDE),
    ("wifi_open", lambda t: "Şifresiz Wi-Fi" in t, _WIFI_OPEN_GUIDE),
    ("wifi_wep", lambda t: "WEP şifrelemeli Wi-Fi" in t, _WIFI_WEP_GUIDE),
    ("wifi_old_wpa", lambda t: "Eski WPA şifrelemeli" in t, _WIFI_OLD_WPA_GUIDE),

    # Web probes — Level 2 attack detection
    ("sql_injection", lambda t: "SQL Injection" in t, _SQL_INJECTION_GUIDE),
    ("xss_reflected", lambda t: "Reflected XSS" in t, _XSS_GUIDE),
    ("path_traversal", lambda t: "Path traversal" in t, _PATH_TRAVERSAL_GUIDE),
    ("ssl_old_protocol", lambda t: "Eski TLS sürümü destekleniyor" in t, _SSL_OLD_PROTOCOL_GUIDE),
    ("ssl_cert_problem", lambda t: "SSL sertifika sorunu" in t, _SSL_CERT_PROBLEM_GUIDE),
    ("x_powered_by_leak",
     lambda t: ("Versiyon sızıntısı: X-Powered-By" in t
                or "Versiyon sızıntısı: X-AspNet" in t),
     _X_POWERED_BY_GUIDE),

    # Exposed files
    ("exposed_git", lambda t: ".git deposu" in t or ".git/HEAD" in t, _EXPOSED_GIT_GUIDE),
    ("exposed_sql_dump",
     lambda t: "Veritabanı yedeği" in t or "Veritabanı dump" in t,
     _EXPOSED_SQL_DUMP_GUIDE),
    ("exposed_wp_config",
     lambda t: "WordPress yapılandırma" in t,
     _EXPOSED_WP_CONFIG_GUIDE),
    ("exposed_htaccess", lambda t: ".htaccess dosyası erişilebilir" in t, _EXPOSED_HTACCESS_GUIDE),
    ("exposed_ds_store", lambda t: ".DS_Store sızmış" in t, _EXPOSED_DS_STORE_GUIDE),
    ("exposed_server_status", lambda t: "server-status public" in t, _EXPOSED_SERVER_STATUS_GUIDE),
    ("exposed_phpinfo", lambda t: "phpinfo.php public" in t, _EXPOSED_PHPINFO_GUIDE),
    ("exposed_admin", lambda t: "Admin paneli" in t, _EXPOSED_ADMIN_GUIDE),
    ("exposed_phpmyadmin", lambda t: "phpMyAdmin public" in t, _EXPOSED_PHPMYADMIN_GUIDE),

    # DB parity
    ("postgres_default_creds",
     lambda t: "PostgreSQL varsayılan parola" in t,
     _POSTGRES_DEFAULT_GUIDE),

    # Port-specific — order matters: specific first, generic last
    ("port_rdp", lambda t: "Açık port: 3389" in t, _PORT_RDP_GUIDE),
    ("port_smb",
     lambda t: "Açık port: 445" in t or "Açık port: 139" in t,
     _PORT_SMB_GUIDE),
    ("port_ftp", lambda t: "Açık port: 21" in t, _PORT_FTP_GUIDE),
    ("port_telnet", lambda t: "Açık port: 23" in t, _PORT_TELNET_GUIDE),
    ("port_vnc", lambda t: "Açık port: 5900" in t, _PORT_VNC_GUIDE),
    # Generic port catch-all — MUST be last (specifics need to match first)
    ("port_generic", lambda t: t.startswith("Açık port:"), _PORT_GENERIC_GUIDE),
)


def get_guide(finding: Finding) -> RemediationGuide | None:
    """Return the detailed guide for the given finding, or None if missing.

    The report template calls this; on None only the short `remediation`
    is shown, on a non-None return a "Show detailed guide" expandable card
    is added.
    """
    for _key, matcher, guide in _PATTERN_MATCHERS:
        if matcher(finding.title):
            return guide
    return None


def get_guide_by_key(key: str) -> RemediationGuide | None:
    """Test ve doğrudan erişim için — key ile rehber al."""
    for k, _matcher, guide in _PATTERN_MATCHERS:
        if k == key:
            return guide
    return None
