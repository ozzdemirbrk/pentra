# activeContext.md — Aktif Çalışma Durumu

> **Şu anki odak, son değişiklikler, bir sonraki adımlar. Bu dosya en sık güncellenir.**

---

## Son Güncelleme
**2026-04-21** — Faz 2 MVP tamamlandı + yol haritası revize edildi. Kullanıcının "sızabiliyor mu test etsin" açıklamasıyla **Seviye 2 (non-destructive probing)** çerçevesi netleşti. CLAUDE.md § 2'ye yazıldı.

---

## 1. Şu Anki Odak

**Aşama**: 🌐 **Faz 3 — E2E test bekleniyor, sonra Faz 4**

Web Scanner + 6 probe tamamlandı (security headers, SSL/TLS, exposed paths, path traversal, SQL injection, XSS). 201 test yeşil. Kullanıcı gerçek bir URL ile uygulamayı çalıştırıp raporu doğruladıktan sonra Faz 4'e geçeceğiz.

**Faz 4 planı**: Servis versiyon tespiti (-sV) + NVD CVE eşleştirme + default credentials check.

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
