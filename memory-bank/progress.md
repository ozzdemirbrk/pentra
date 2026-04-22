# progress.md — İlerleme Durumu

> **Ne çalışıyor, ne kaldı, bilinen sorunlar, proje kararlarının evrimi.**

---

## Son Güncelleme
**2026-04-22** — Faz 5 Batch 1 tamamlandı. DB auth probe'ları (Redis, Elasticsearch, MongoDB) ve NetworkScanner entegrasyonu eklendi. 267 test yeşil (+15 yeni). Commit bcd3391.

---

## 1. Genel Durum

```
Faz 0: Planlama & Kurulum             ██████████  %100
Faz 1: Güvenlik Katmanı               ██████████  %100 (124 test)
Faz 2: MVP (localhost tarama)         ██████████  %100 (154 test, E2E çalıştı)
Faz 3: Web Scanner (Seviye 2 probing) ██████████  %100 (208 test, false positive fix dahil)
Faz 4: Servis versiyon + CVE          ██████████  %100 (252 test, E2E 0 FP)
Faz 5: DB probe + yerel ağ + Wi-Fi    ████████░░  %75 (DB + Default creds + Wi-Fi hazır)
Faz 6: Akıllı rapor + PDF + geçmiş    ░░░░░░░░░░  %0
Faz 7: Paketleme (.exe) + dağıtım     ░░░░░░░░░░  %0
```

**Toplam tamamlanma**: ~%68 (planlama, iskelet, güvenlik, MVP, web probe, CVE, DB probe başladı)

**Yol haritası revize edildi (2026-04-21)**: Kullanıcı "sadece port mu tarayacağız?" diye sordu. Cevap: hayır. Seviye 1 (pasif) → Seviye 2 (non-destructive probing) geçişi yapılacak. Detay için CLAUDE.md § 2.

## 2. Çalışan Kısımlar ✅

- ✅ **Proje vizyonu ve kapsamı** netleştirildi
- ✅ **Teknoloji yığını** seçildi ve gerekçelendirildi
- ✅ **CLAUDE.md** hafıza dosyası oluşturuldu
- ✅ **memory-bank/** altı çekirdek dosya oluşturuldu:
  - projectbrief.md
  - productContext.md
  - activeContext.md
  - systemPatterns.md
  - techContext.md
  - progress.md (bu dosya)
- ✅ **Mimari tasarım** belgelendi (3 katmanlı + 2 çapraz-kesen)
- ✅ **Güvenlik kuralları** netleştirildi (exploit yok, RFC1918 dışı için ek onay, audit log)
- ✅ **pyproject.toml** — paket metadata + black/ruff/mypy/pytest ayarları
- ✅ **requirements.txt / requirements-dev.txt** — tüm prod + dev bağımlılıklar
- ✅ **src/pentra/** paket iskeleti — tüm alt paketler + `__main__`, `app.py`, `config.py`
- ✅ **tests/** çatısı — conftest.py, unit/integration/fixtures klasörleri, ilk smoke test
- ✅ **.gitignore** — Python + proje özel (raporlar, audit.log, *.db gitignore'lu)
- ✅ **README.md, LICENSE** (placeholder)
- ✅ **.pre-commit-config.yaml, .editorconfig** — commit öncesi lint/format otomasyonu
- ✅ **src/pentra/models.py** — Target, ScanDepth, ScopeDecision, AuthorizationRequest/Token, Finding, AuditEvent, Severity (100% coverage)
- ✅ **src/pentra/safety/scope_validator.py** — RFC1918 + loopback + DENIED aralıklar, URL DNS çözümü, CIDR sınırları (92% coverage)
- ✅ **src/pentra/core/rate_limiter.py** — Thread-safe TokenBucket (acquire + wait_for + timeout) (98% coverage)
- ✅ **src/pentra/safety/authorization.py** — HMAC-SHA256 imzalı, hedef-bağlı, TTL'li, iptal edilebilir token'lar (100% coverage)
- ✅ **src/pentra/storage/audit_log.py** — Hash-zincirli append-only log + verify_integrity (88% coverage)
- ✅ **124 unit test yeşil** — genel coverage %89.98
- ✅ **core/scanner_base.py** — QObject soyut Scanner + Qt sinyalleri
- ✅ **core/scan_orchestrator.py** — Chain of Responsibility: scope → auth → scanner seçimi
- ✅ **core/network_scanner.py** — python-nmap wrapper, TCP connect scan, riskli port haritası
- ✅ **reporting/** — ReportBuilder + HtmlExporter + Jinja2 şablonu (Türkçe, modern görünüm)
- ✅ **gui/wizard.py + 5 ekran** — Yetki onayı, hedef, derinlik, canlı ilerleme, rapor
- ✅ **app.py** — Tüm bağımlılıkları enjekte edip wizard'ı başlatan ana giriş
- ✅ **E2E test başarılı** — localhost tarama → 4 bulgu → HTML rapor masaüstüne
- ✅ **154 test yeşil** (yeni: orchestrator 10, network_scanner 8, report 12)

## 3. Yapılması Gerekenler 📋

### Faz 0 — Kurulum ✅ (neredeyse tamamlandı)
- [x] `pyproject.toml` + `requirements.txt` + `requirements-dev.txt`
- [x] `src/pentra/` paket yapısı (boş `__init__.py`'ler + `app.py`, `config.py`)
- [x] `.gitignore`, `README.md` (placeholder), `LICENSE` (placeholder)
- [x] pre-commit config + ruff/black/mypy ayarları
- [x] tests/ çatısı + conftest.py + smoke test
- [x] `scripts/setup_dev.py` — venv kurulum otomasyonu
- [x] Git repo init + ilk commit (yerel — 8e22ff2)
- [x] GitHub'a push (github.com/ozzdemirbrk/pentra — GCM cached cred ile)

### Faz 1 — Güvenlik Katmanı ✅
- [x] `models.py` — ortak tip tanımları
- [x] `safety/authorization.py` — AuthorizationManager sınıfı (HMAC-SHA256, TTL, revoke)
- [x] `safety/scope_validator.py` — RFC1918 + loopback + DENIED aralıklar + DNS
- [x] `core/rate_limiter.py` — thread-safe token bucket
- [x] `storage/audit_log.py` — hash-zincirli denetim izi
- [x] Birim testler — 124 test yeşil, genel coverage %89.98

### Faz 2 — MVP ✅
- [x] `app.py` + `gui/wizard.py` — QApplication iskeleti + WizardContext
- [x] 5 ekran: authorization, target_select, depth_select, progress, report (localhost için)
- [x] `core/scanner_base.py` — soyut Scanner (QObject + sinyaller + token doğrulama + audit log)
- [x] `core/scan_orchestrator.py` — Chain of Responsibility: scope → auth → scanner factory
- [x] `core/network_scanner.py` — localhost port taraması (python-nmap, -sT -F --open)
- [x] `reporting/` — ReportBuilder + HtmlExporter + Jinja2 şablonu (Türkçe, modern)
- [x] Uçtan uca akış: aç → onay → bu bilgisayarı tara → HTML rapor masaüstüne
- [x] Unit + integration testleri (154 test yeşil)

### Faz 3 — Web Scanner (Seviye 2 probing) ✅
Kullanıcının "URL testi, sızabiliyor mu?" sorusunun ilk cevabı.
- [x] `core/web_scanner.py` — WebScanner iskeleti + probe registry
- [x] `core/web_probes/base.py` — WebProbeBase soyut sınıfı + evidence helper
- [x] `core/web_probes/security_headers.py` — CSP/HSTS/X-Frame/X-Content-Type + versiyon sızıntısı
- [x] `core/web_probes/ssl_tls.py` — SSLv3/TLSv1/TLSv1.1 handshake + sertifika doğrulama
- [x] `core/web_probes/exposed_paths.py` — 17+ hassas yol + content signature + security.txt
- [x] `core/web_probes/path_traversal.py` — 10 param × 4 payload + Linux/Windows kanıt
- [x] `core/web_probes/sql_injection.py` — Error-based, 20+ DBMS pattern
- [x] `core/web_probes/xss.py` — Reflected XSS + 4 context + canary token
- [x] GUI: URL seçeneği aktif, QLineEdit input, yetki onay checkbox'ı
- [x] `app.py` scanner factory — URL → WebScanner, diğerleri → NetworkScanner
- [x] Unit testler — 47 yeni probe testi, 201 toplam test yeşil
- [x] E2E manuel test (zonguldak.bel.tr) — başarılı
- [x] **False positive fix** (soft-404 baseline + content validator + Content-Type filtresi)
  — zonguldak.bel.tr'de 3 CRITICAL FP → 0 FP, 7 gerçek bulgu
- [x] 208 test yeşil (15 yeni exposed_paths testi dahil)

### Faz 4 — Servis Versiyonu + CVE Eşleştirme
- [x] `knowledge/nvd_client.py` — NVD REST 2.0 API client (keyword + CPE search, rate limit, cache)
- [x] `knowledge/cve_mapper.py` — servis adı normalleştirme + CPE prefix haritası + fallback
- [x] `-sV` nmap argümanı Quick/Standard/Deep'te aktif
- [x] NetworkScanner: her port için CVE lookup, severity CVSS'e göre yükseltme
- [x] WebScanner: Server header versiyon → CVE zenginleştirme
- [x] Rapor şablonu CVE kartları (CVSS renk kodu, NVD link)
- [x] Standart derinlik aktif (depth_select)
- [x] `.env` desteği (python-dotenv) — NVD_API_KEY gizli kalır
- [x] 252 test yeşil (42 yeni knowledge testi)
- [x] CPE-based arama canlı doğrulandı (Apache 2.4.41 → 77 CVE)
- [x] E2E test (zonguldak.bel.tr): ilk raporda 10 eski IIS 5.0 CVE'si gözüktü (FP)
- [x] Fix: CPE 0 döndüğünde keyword fallback kaldırıldı (tanınmış servisler için)
- [x] Fix sonrası E2E: 7 gerçek bulgu, 0 FP. IIS 10.0 için CVE yok (doğru — NVD'de kayıt yok)
- [ ] Default credentials check modülü → Faz 5'e ertelendi

### Faz 5 — DB probe + Default Creds + Wi-Fi + Ağ Derinliği

**Batch 1 ✅ (commit bcd3391)**
- [x] `core/service_probes/base.py` — ServiceProbeBase soyut sınıf
- [x] Redis auth probe (port 6379, RESP PING)
- [x] Elasticsearch auth probe (port 9200, HTTP cluster_name imza)
- [x] MongoDB auth probe (port 27017, pymongo list_database_names)
- [x] NetworkScanner entegrasyonu — açık DB portlarında probe çalışır
- [x] 15 yeni test (267 toplam)

**Batch 2 ✅ (commit 5222b4f)**
- [x] MySQL default creds probe (port 3306, root:'', root:root — max 2 deneme)
- [x] PostgreSQL default creds probe (port 5432, postgres:postgres, postgres:'' — max 2)
- [x] SSH default creds probe (port 22, root:root, admin:admin, pi:raspberry — max 3)
- [x] NetworkScanner registry: 8 portta 6 probe (3306, 5432, 22, 6379, 9200, 27017-9)
- [x] 13 yeni test (280 toplam)

**Batch 3 ✅ (bu turda commit)**
- [x] `core/wifi_scanner.py` — netsh wlan parser (EN + TR etiket desteği)
- [x] Finding seviyeleri: Open/WEP → HIGH, eski WPA → MEDIUM, WPA2/3 → INFO
- [x] target_select.py: Wi-Fi radyo butonu aktif
- [x] app.py factory: TargetType.WIFI → WifiScanner
- [x] 15 yeni test (295 toplam) — netsh çıktı parse + değerlendirme
- [ ] WPS açık tespiti → netsh güvenilir raporlamadığı için kapsam dışı (v2'de monitor mode + wash ile)

**Batch 4 (Yerel ağ keşfi)**
- [ ] IP_RANGE ve LOCAL_NETWORK target tipleri GUI'de aktif
- [ ] NetworkScanner: CIDR girdisi için ping sweep + paralel port scan
- [ ] Cihaz başına özet (host → açık portlar → servis/versiyon)
- [ ] Otomatik yerel ağ tespiti (ipconfig/route parse ile CIDR önerme)

### Faz 6 — Akıllı Rapor + PDF + Geçmiş
- [ ] CVSS skoru (her bulgu için)
- [ ] Executive summary (teknik olmayan)
- [ ] PDF exporter (xhtml2pdf)
- [ ] Markdown exporter

- [ ] **Detaylı onarım rehberleri** (`knowledge/remediations_tr.py`)
  Her bulgu için mevcut 1-2 cümlelik öneri yerine adım adım rehber:
    1. **Sorun özeti** (1 cümle — bulgu başlığını tekrarla)
    2. **Niye önemli** (risk context + gerçek saldırı senaryosu örneği)
    3. **Nasıl düzeltirim** (sunucu tipine göre varyant):
       - Nginx config snippet (copy-paste ready)
       - Apache httpd.conf / .htaccess snippet
       - IIS web.config XML snippet veya PowerShell cmdlet
       - Cloudflare/CDN dashboard adımları (eğer uygunsa)
    4. **Doğrulama** (fix sonrası test etmek için komut — ör. `curl -I URL`)
    5. **Referanslar** (MDN, OWASP, sunucu resmi doc link'i)
  Rapor şablonu bu bölümleri açılır/kapanır ("Detaylı rehberi göster") kart olarak
  göstersin — temel özet hemen, detay isteyenler için genişletilebilir.

- [ ] SQLite'ta geçmiş taramalar + karşılaştırma ("geçen tarama göre şu değişmiş")

### Faz 7 — Paketleme
- [ ] `scripts/build_exe.py` — PyInstaller script
- [ ] İkon ve logo (tasarım gerekli)
- [ ] Inno Setup script — Windows installer
- [ ] Nmap + Npcap bundle
- [ ] GitHub Releases workflow
- [ ] Kullanım kılavuzu (PDF, Türkçe)
- [ ] Kod imzalama sertifikası değerlendirmesi

## 4. Bilinen Sorunlar / Araştırma Gerekenler ⚠️

| # | Konu | Durum |
|---|---|---|
| 1 | WeasyPrint'in Windows GTK bağımlılığı — alternatif değerlendir | Açık |
| 2 | SQLCipher pip kurulum sorunu — Fernet uygulama-katmanı alternatifi | Açık |
| 3 | PyInstaller .exe boyutu (~100-200MB) — kabul edilebilir mi? | Açık |
| 4 | Scapy + Npcap ilk kurulum deneyimi — bundle mı, downloader mı? | Açık |
| 5 | Windows SmartScreen uyarısı — kod imzalama sertifikası gerekli mi? | Açık |
| 6 | CVE veritabanı kaynağı — offline NVD kopyası mı, online API mı? | Açık |

## 5. Proje Kararlarının Evrimi

### 2026-04-20 — İlk Karar Turu
- **Platform**: Masaüstü ✅ (Web ve CLI alternatifleri elendi; masaüstü ham paket ihtiyacı + rapor gizliliği için en uygun)
- **OS**: Windows-only v1 ✅ (Linux/macOS v2'ye ertelendi — kapsam kontrolü için)
- **Dil**: Python ✅ (pentest ekosistem dominansı + hızlı prototipleme)
- **GUI framework**: PySide6 ✅ (PyQt6 yerine LGPL lisansı için)
- **Arayüz dili**: Türkçe-only v1 ✅ (hedef kitle öncelik)
- **Wi-Fi kapsamı**: v1'de pasif listeleme, v2'de monitor mode ✅ (donanım kısıtları)
- **Rapor depolama**: Yalnızca yerel ✅ (bulut seçeneği elendi — gizlilik tasarım prensibi)
- **Exploit çalıştırma**: Asla ✅ (sadece tespit — etik + yasal)

### Beklenen Kararlar
- CVE kaynağı (NVD offline vs API) — Faz 3 öncesi
- SQLite şifreleme yöntemi — Faz 1 öncesi
- PDF kütüphanesi (WeasyPrint vs xhtml2pdf) — Faz 5 öncesi
- Kod imzalama — Faz 6 öncesi
- Lisans — Halka sürüm öncesi

## 6. Takım ve Sorumluluk

| Rol | Kişi |
|---|---|
| Ürün sahibi & geliştirici | Kullanıcı (ozzdemirbrk@gmail.com) |
| Kod asistanı | Claude Code (Opus 4.7) |
| Kullanıcı testi | (henüz belirlenmedi) |
| Güvenlik gözden geçirme | (bağımsız denetim — v1.0 öncesi yapılmalı) |

## 7. Başarı Metrikleri (Takip Edilecek)

- **Kod kapsamı**: `safety/` ve `core/` için ≥%80 (pytest-cov)
- **Tip kapsamı**: mypy strict mode geçer (ignore sayısı takip)
- **Lint**: ruff 0 uyarı, black formatlı
- **.exe boyutu**: hedef ≤150MB
- **Kullanım zamanı** (kullanıcı testi): aç → rapor süresi ≤15 dk hızlı modda
- **Kullanıcı geri bildirimi**: (MVP sonrası en az 3 kullanıcıdan yazılı geri bildirim)

## 8. Notlar

- Her önemli değişiklikten sonra bu dosya ve `activeContext.md` güncellenir
- Kullanıcı **"update memory bank"** derse 6 çekirdek dosya gözden geçirilir
- Tarihler **YYYY-MM-DD** formatında yazılır (relatif tarih kullanılmaz — hafıza sonradan okunduğunda yorumlanmaz)
