# activeContext.md — Aktif Çalışma Durumu

> **Şu anki odak, son değişiklikler, bir sonraki adımlar. Bu dosya en sık güncellenir.**

---

## Son Güncelleme
**2026-04-22** — Faz 5 %100 tamam (4 batch). 312 test yeşil. Kullanıcı E2E test yapıyor. Sırada Faz 6 (akıllı rapor + PDF + detaylı onarım rehberleri) var.

---

## 1. Şu Anki Odak

**Aşama**: 🧪 **Faz 5 E2E test bekleniyor — sonra Faz 6 başlayacak**

**Faz 5 özeti** (commit'ler: bcd3391, 5222b4f, 570c23f, 614fbde, 5923bcc):
- Batch 1: Redis + Elasticsearch + MongoDB auth probe
- Batch 2: MySQL + PostgreSQL + SSH default credentials probe
- Batch 3: Wi-Fi pasif scanner (netsh wlan parser, EN+TR)
- Batch 4: LOCAL_NETWORK (otomatik /24 tespit) + IP_RANGE (manuel CIDR/IP)

**Scanner kapsamı** (tüm target tipleri aktif):
- Localhost, URL, Wi-Fi, yerel ağ, IP aralığı → her biri çalışır durumda
- 8 portta otomatik service probe (22, 3306, 5432, 6379, 9200, 27017-19)
- NetworkScanner her açık port için CVE lookup (NVD)

**Sıradaki Faz 6 — Akıllı Rapor + PDF + Detaylı Rehberler**:
- CVSS bazlı risk skoru (genel + her bulgu için)
- Executive summary (teknik olmayan özet)
- PDF exporter (xhtml2pdf)
- Markdown exporter
- **Detaylı onarım rehberleri** (knowledge/remediations_tr.py) — kullanıcının özel isteği:
  her bulgu için Nginx/Apache/IIS/Cloudflare varyantlı adım adım rehber
- SQLite'ta geçmiş taramalar + "geçen tarama göre ne değişti" diff

## 2. Son Değişiklikler (Kronolojik)

| Tarih | Ne Yapıldı |
|---|---|
| 2026-04-20 | Proje fikri tartışıldı; 3 kritik soru kullanıcıya soruldu (OS, Wi-Fi, dil) |
| 2026-04-20 | Kullanıcı onayladı: Windows-only v1, Türkçe-only v1, Wi-Fi pasif |
| 2026-04-21 | `CLAUDE.md` ve `memory-bank/` 6 çekirdek dosya oluşturuldu |
| 2026-04-21 | `pyproject.toml` + requirements dosyaları (prod + dev) |
| 2026-04-21 | `src/pentra/` paket iskeleti (tüm alt paketler + `app.py`, `config.py`) |
| 2026-04-21 | `tests/` çatısı + conftest.py + smoke test |
| 2026-04-21 | `.gitignore`, README, LICENSE placeholder, .pre-commit-config.yaml, .editorconfig |
| 2026-04-21 | `scripts/setup_dev.py` — dev ortamı bootstrap script |
| 2026-04-21 | Git repo init + ilk commit (hash 8e22ff2, 37 dosya, main branch) |
| 2026-04-21 | GitHub push tamamlandı — kullanıcı GCM cached cred ile push'ladı (repo: github.com/ozzdemirbrk/pentra) |
| 2026-04-21 | `models.py` — ortak dataclass/enum tanımları (Target, ScanDepth, Severity, ...) |
| 2026-04-21 | `safety/scope_validator.py` + 45 test — RFC1918 + URL DNS + CIDR kontrolü |
| 2026-04-21 | `core/rate_limiter.py` + 15 test — thread-safe TokenBucket |
| 2026-04-21 | `safety/authorization.py` + 20 test — HMAC-SHA256 imzalı token sistemi |
| 2026-04-21 | `storage/audit_log.py` + 22 test — hash-zincirli denetim izi |
| 2026-04-21 | pytest: 124 test yeşil, coverage %89.98 (safety + models %100) |
| 2026-04-21 | Faz 2 tüm modüller: scanner_base, scan_orchestrator, network_scanner, reporting, 5 wizard ekranı, app.py |
| 2026-04-21 | E2E manuel test başarılı — localhost'ta 4 port, HTML rapor masaüstüne |
| 2026-04-21 | PySide6 + python-nmap + sslyze + requests vb. kurulumu (impacket hariç — Windows Defender sorunu) |
| 2026-04-21 | Faz 2 commit (79a4c99) + push |
| 2026-04-21 | Yol haritası revize: Seviye 1/2/3 çerçevesi; Faz 3 = Web Scanner (probe'lı) |
| 2026-04-21 | Faz 3 tüm probe'ları (security headers, SSL/TLS, exposed paths, path traversal, SQLi, XSS) |
| 2026-04-21 | E2E (zonguldak.bel.tr): 3 CRITICAL FP tespit edildi (soft-404 kaynaklı) |
| 2026-04-21 | Fix: soft-404 baseline + content validator + Content-Type filtresi (commit 27850c7) |
| 2026-04-21 | Fix sonrası E2E: 0 FP, 7 gerçek bulgu (CSP, HSTS, Referrer-Policy, X-Content-Type, X-Frame, Server leak, security.txt yok) |

## 3. Bir Sonraki Adımlar (Faz 3 — Web Scanner)

### 🎯 Öncelik 1 — Web Scanner iskeleti
- [ ] `core/web_scanner.py` — `ScannerBase` türevi, modüler probe sınıfları
- [ ] Probe modülleri şu interface'i uygular: `run(url) → list[Finding]`

### 🎯 Öncelik 2 — Temel probe'lar (basit, hızlı kazanç)
- [ ] **Security headers** probe — CSP, HSTS, X-Frame, X-Content-Type-Options eksikleri
- [ ] **SSL/TLS** probe — sslyze kullanarak Heartbleed/POODLE/zayıf cipher
- [ ] **Exposed paths** probe — `/.env`, `/.git/config`, `/wp-config.bak`, `/admin` vb. listesi

### 🎯 Öncelik 3 — İleri probe'lar (kanıt gerektiren)
- [ ] **SQL injection** probe — davranış değişikliği tespiti
- [ ] **XSS** probe — yansıtılmış girdi + kaçış kontrolü
- [ ] **Directory traversal** probe — `../../etc/passwd` davranışı

### 🎯 Öncelik 4 — GUI entegrasyonu
- [ ] `target_select.py` — URL seçeneği aktif, input alanı + anında DNS resolve göster
- [ ] Scanner factory: URL TargetType → WebScanner

### 🎯 Öncelik 5 — Test + E2E
- [ ] Her probe için mocked HTTP unit test
- [ ] Entegrasyon testi: test için basit vulnerable HTTP server
- [ ] Manuel E2E: örnek site (kendi Docker sandbox'ımız veya `scanme.nmap.org`)

## 4. Aktif Kararlar ve Değerlendirmeler

### Henüz Karar Verilmemiş (Bekleyen)
- ❓ **Lisans**: MIT / GPL / özel — MVP sonrası
- ❓ **Uygulama ikonu ve marka**: Tasarlanmadı
- ❓ **CVE veritabanı kaynağı**: NVD JSON feed mi, offline yerel kopya mı, yoksa online API (rate-limited) mi?
- ❓ **İlk dağıtım kanalı**: GitHub Releases mi, yoksa basit web sayfası mı?
- ❓ **SQLite şifreleme anahtarı**: Kullanıcının parolasıyla türetme (PBKDF2) mi, makine anahtarı mı?
- ❓ **Kod imzalama sertifikası**: .exe imzalanacak mı? (Windows SmartScreen uyarısı için önemli; maliyet ~100-500 $/yıl)

### Kesinleşmiş Kararlar
- ✅ Windows-only (v1)
- ✅ Türkçe-only (v1)
- ✅ Python 3.11+ / PySide6
- ✅ Rapor yerele yazılır (bulut yok — tasarımsal)
- ✅ Exploit yok, sadece tespit
- ✅ RFC1918 dışı hedef için ekstra onay
- ✅ Wi-Fi v1'de sadece pasif listeleme

## 5. Aktif Desenler ve Tercihler

### Kullanıcı Etkileşim Deseni
Kullanıcı siber güvenlik konusunda sınırlı bilgiye sahip. Her teknik karardan önce:
1. Türkçe olarak seçenekleri açıkla
2. Her seçeneğin **nedenini** belirt
3. Önerini sun
4. Onay bekle, ondan sonra uygula

### Kod Yazım Deseni
- **Güvenlik-önce**: Her yeni tarayıcı modülü, önce `safety/` katmanından geçmek zorunda
- **Test-önce**: `safety/` ve `core/` modüllerinde kod yazmadan önce test yaz
- **Kullanıcı dili = Türkçe**: Hata mesajı, log, rapor — hepsi Türkçe
- **Log seviyeleri**: Her tarama adımı `INFO`; güvenlik olayları `WARNING`/`ERROR`; audit ayrı dosyada

## 6. Öğrenilenler ve Proje İçgörüleri

- Kullanıcı siber güvenlik terminolojisine yabancı, ama net iletişim kurabiliyor — soru sormaya açık
- Kullanıcı **plan-önce, onay-sonra-uygula** akışını tercih ediyor (proje başlangıcında kurdu)
- Kullanıcının ana endişesi **verinin dışarı çıkması** — bu mimari kararın temel taşı (yerel-only)
- Projeye "Pentra" adı kullanıcı tarafından verildi (dizin ismi); resmi marka kararı daha verilmedi

## 7. Engeller / Riskler

- ⚠️ **WeasyPrint Windows'ta GTK bağımlılığı ister** — alternatif: `reportlab` veya `xhtml2pdf`. Araştırma gerekli.
- ⚠️ **Scapy Windows'ta WinPcap/Npcap ister** — kullanıcının Npcap kurması gerekebilir; installer ile birlikte dağıtılabilir mi?
- ⚠️ **PyInstaller çıktısı büyük olabilir** (~100-200 MB) — kabul edilebilir mi kontrol edilecek
- ⚠️ **SQLCipher pip'ten kurulumu sorunlu** — alternatif: SQLite + uygulama katmanında Fernet şifreleme
- ⚠️ **Windows SmartScreen** imzasız .exe'yi uyaracak — ilk dağıtımda kullanıcıya ne yapacağı anlatılmalı
