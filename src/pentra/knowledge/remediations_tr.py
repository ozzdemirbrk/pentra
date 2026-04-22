"""Detaylı Türkçe onarım rehberleri.

Her finding tipi için 5 bölümlü adım-adım rehber:
    1. **Sorun özeti** — title'ı tekrarlar
    2. **Niye önemli** — risk context + saldırı senaryosu
    3. **Nasıl düzeltirim** — sunucu varyantları (Nginx/Apache/IIS/Cloudflare)
    4. **Doğrulama** — fix sonrası test komutu
    5. **Referanslar** — güvenilir dokümantasyon linkleri

Rapor şablonu bu rehberleri "Detaylı rehberi göster" açılır kartı olarak sunar.
Bir finding için rehber tanımlı değilse kısa `remediation` string'i kullanılır.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from pentra.models import Finding


@dataclasses.dataclass(frozen=True)
class FixStep:
    """Belirli bir sunucu/servis için tek bir onarım adımı."""

    platform: str  # "Nginx" / "Apache" / "IIS (web.config)" / "Cloudflare Dashboard"
    instructions: str  # Türkçe açıklama (Markdown-light: ** kalın, ` kod `)
    code: str = ""  # Copy-paste snippet (opsiyonel)


@dataclasses.dataclass(frozen=True)
class RemediationGuide:
    """Bir finding tipi için tam rehber."""

    problem_summary: str
    why_important: str
    fix_steps: tuple[FixStep, ...]
    verification: str  # "Düzeltmeyi doğrulayın: `curl -I https://...`"
    references: tuple[tuple[str, str], ...]  # ((başlık, url), ...)


# =====================================================================
# Rehberler
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

# =====================================================================
# Finding title → guide key eşlemesi
# =====================================================================
_TitleMatcher = Callable[[str], bool]

# (guide_key, matcher, guide) — matcher title pattern döndürür
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
)


def get_guide(finding: Finding) -> RemediationGuide | None:
    """Verilen finding için detaylı rehber varsa döndürür, yoksa None.

    Rapor şablonu bu değerle çağırılır; None ise sadece kısa `remediation`
    gösterilir, değer dönüyorsa "Detaylı rehberi göster" açılır kart sunulur.
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
