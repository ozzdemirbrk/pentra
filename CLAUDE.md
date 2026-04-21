# Pentra — Proje Hafızası (CLAUDE.md)

> Bu dosya Claude Code tarafından her oturumda otomatik okunur. Hafıza sıfırlandığında önce buradaki bilgiler, sonra `memory-bank/` klasöründeki 6 çekirdek dosya okunmalıdır.

---

## 1. Proje Kimliği

**Pentra**, Windows masaüstünde çalışan, **yeni başlayanlar için sihirbaz (wizard) arayüzlü** bir sızma testi (pentest) uygulamasıdır. Kullanıcıya ne/nerede test etmek istediğini adım adım sorar, seçilen derinlikte taramayı yapar ve **yalnızca yerel masaüstüne** (uzak sunucuya DEĞİL) rapor yazar.

**Hedef kitle:** Siber güvenlik bilgisi sınırlı olan, kendi sistemlerini (localhost, ev ağı, kendi web sitesi) test etmek isteyen kullanıcı.

**Kullanıcı dili:** Türkçe. Tüm arayüz, raporlar, loglar, kod yorumları ve git mesajları Türkçe. Kod tanımlayıcıları (değişken, fonksiyon, sınıf isimleri) standart Python konvansiyonuna göre İngilizce.

---

## 2. 🚨 Pentra'nın 3-Seviye Çerçevesi (Kimlik Tanımı)

Pentra **vulnerability assessment (zafiyet denetimi)** aracıdır — **attack tool değil**. Bu ayrım 3 seviyede netleşir:

### Seviye 1 — Pasif Tespit
- Port taraması, servis adı çözümleme, versiyon tespiti
- "Port X açık" kadar bilgi verir — zafiyetin gerçekten var olduğunu kanıtlamaz

### Seviye 2 — **Non-Destructive Probing** ✅ (Pentra'nın yapacağı)
Tek bir test paketi gönderilip tepkisi gözlemlenir. Zafiyet **var mı** öğrenilir:
- **Default credentials check**: `admin:admin`, boş parola tek seferlik dener → kabul edildiyse rapor → anında koparır
- **SQL injection probe**: `' OR '1'='1` tarzı payload + davranış değişikliği tespiti (veri çekmez)
- **XSS probe**: Benign payload + yansıma/kaçış kontrolü (gerçek saldırı yok)
- **Directory traversal**: `../../etc/passwd` → sızıyor mu bak (içeriği indirmez)
- **Known CVE check**: Servis+versiyon → NVD eşleştirme (exploit fırlatmaz)
- **SSL/TLS zafiyet**: Heartbleed/POODLE/zayıf cipher/eksik HSTS (bellek okumaz)
- **Auth bypass**: `/admin` auth'suz erişilebilir mi, JWT `alg:none` kabul ediyor mu (işlem yapmaz)
- **Exposed config**: `/.env`, `/.git/config`, `/wp-config.php.bak` public mi (indirmez)
- **Open DB check**: MongoDB/Redis parolasız mı (koleksiyon çekmez)

**3 kural Seviye 2 için her zaman geçerli:**
1. **Tek seferlik** — aynı zafiyeti 1000 kez denemeyiz
2. **Kanıt yeterli** — zafiyetin var olduğunu göstermek için minimum paket
3. **Oku, yazma** — hiçbir test sunucuda kalıcı değişiklik bırakmaz

### Seviye 3 — Aktif Sömürü ❌ (Pentra yapmaz)
- Exploit fırlatma (Metasploit tarzı), shell açma
- Veri çekme (DB dump), parola kırma, brute force
- Persistence, lateral movement, iz silme
- Her sürümde yasaktır. Kod review'da bu kategoriye giren değişiklikler reddedilir.

**Referans araçlar:** Nessus, OpenVAS, Qualys — bunlar Seviye 2'de çalışır, Pentra da aynı sınıftadır.

## 3. Kritik Güvenlik Kuralları (Her Zaman Geçerli)

1. **Yetkisiz hedefe paket gönderilmez.** Her tarama öncesi kullanıcıdan yazılı yetki onayı alınır (AuthorizationScreen).
2. **Seviye 3 (aktif sömürü) KOD'da BULUNMAZ.** CVE eşleştirme, versiyon tespiti, probe evet; payload fırlatma, shell açma, veri çekme hayır.
3. **Kapsam doğrulama zorunlu.** Hedef IP yalnızca RFC1918 özel ağ aralığında (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) veya `127.0.0.0/8` olabilir. Dış IP için ayrı ek onay ekranı ve "sahiplik beyanı" şart.
4. **Rate limiting zorunlu.** Her tarama motorunda paket/saniye sınırı; kullanıcı yanlışlıkla DoS yaratmasın. Probe'lar özellikle rate-limited.
5. **Rapor yerelde kalır.** Masaüstüne `Pentra_Rapor_YYYY-MM-DD_HH-MM.{pdf,html,md}` olarak kaydedilir. Hiçbir zaman dışarı gönderilmez.
6. **Denetim izi şart.** Her tarama + her probe `audit.log` dosyasına imzalı olarak yazılır.
7. **Saldırgan kodun bu projede yeri yoktur.** Stealth/evasion, persistence, C2, credential harvesting, lateral movement modülleri eklenmez.

---

## 3. Teknoloji Stack

| Katman | Araç | Versiyon |
|---|---|---|
| Dil | Python | 3.11+ |
| GUI | PySide6 (Qt6) | 6.6+ |
| Ağ taraması | python-nmap | 0.7+ |
| Paket manipülasyonu | scapy | 2.5+ |
| HTTP | requests | 2.31+ |
| SSH/SFTP | paramiko | 3.4+ |
| SMB/LDAP | impacket | 0.12+ |
| SSL/TLS analizi | sslyze | 5.2+ |
| Rapor şablonu | Jinja2 | 3.1+ |
| PDF üretimi | WeasyPrint | 60+ |
| Veritabanı | SQLite + SQLCipher (pysqlcipher3) | — |
| Loglama | structlog | 24+ |
| Test | pytest, pytest-qt | son |
| Paketleme | PyInstaller | 6+ |
| Platform | Windows 10/11 (v1) | — |

---

## 4. Klasör Yapısı (Hedeflenen)

```
Pentra/
├── CLAUDE.md                       # ← bu dosya
├── memory-bank/                    # Cline Memory Bank (6 çekirdek)
│   ├── projectbrief.md
│   ├── productContext.md
│   ├── activeContext.md
│   ├── systemPatterns.md
│   ├── techContext.md
│   └── progress.md
├── memory.md                       # orijinal Memory Bank spesifikasyonu (silinmez)
├── README.md
├── LICENSE
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── src/
│   └── pentra/
│       ├── __init__.py
│       ├── __main__.py              # python -m pentra girişi
│       ├── app.py                   # QApplication başlangıcı
│       ├── config.py                # sabitler, ayarlar
│       ├── gui/
│       │   ├── wizard.py            # ana sihirbaz kontrolcüsü
│       │   ├── screens/
│       │   │   ├── authorization.py # Ekran 1 — Yetki Onayı
│       │   │   ├── target_select.py # Ekran 2 — Hedef Seçimi
│       │   │   ├── depth_select.py  # Ekran 3 — Derinlik Seçimi
│       │   │   ├── progress.py      # Ekran 4 — Canlı İlerleme
│       │   │   └── report.py        # Ekran 5 — Rapor Önizleme
│       │   └── widgets/             # ortak Qt widget'ları
│       ├── core/
│       │   ├── scanner_base.py      # soyut Scanner sınıfı
│       │   ├── network_scanner.py   # host discovery + port scan
│       │   ├── host_scanner.py      # servis/versiyon + temel CVE eşleme
│       │   ├── web_scanner.py       # HTTP başlıkları, SSL/TLS, yaygın zafiyet
│       │   ├── wifi_scanner.py      # pasif Wi-Fi listeleme (v1 sınırlı)
│       │   └── rate_limiter.py      # paket/saniye kısıtlayıcı
│       ├── safety/
│       │   ├── authorization.py     # yetki onayı doğrulayıcı
│       │   └── scope_validator.py   # RFC1918 + kapsam kontrol
│       ├── reporting/
│       │   ├── report_builder.py
│       │   ├── templates/           # Jinja2 HTML şablonları (TR)
│       │   └── exporters/           # md, html, pdf export
│       ├── storage/
│       │   ├── database.py          # SQLite + SQLCipher
│       │   ├── models.py            # Scan, Finding, Target
│       │   └── audit_log.py         # imzalı denetim izi
│       ├── knowledge/
│       │   ├── cve_mapper.py        # servis+versiyon → bilinen CVE
│       │   └── remediations_tr.py   # Türkçe onarım önerileri
│       └── utils/
│           ├── logging_config.py
│           └── network_utils.py
├── resources/
│   ├── icons/
│   ├── styles/                      # Qt stylesheet
│   └── translations/                # .ts dosyaları (v2 EN için hazırlık)
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
└── scripts/
    ├── build_exe.py                 # PyInstaller ile .exe üretme
    └── setup_dev.py                 # dev ortamı kurulum
```

---

## 5. Uygulama Akışı (5-Ekran Sihirbaz)

```
[1] Yetki Onayı      → zorunlu checkbox + sahiplik beyanı
[2] Hedef Seçimi     → localhost | yerel ağ | IP aralığı | URL | Wi-Fi
[3] Derinlik Seçimi  → 🟢 Hızlı | 🟡 Standart | 🔴 Derin (her biri açıklamalı)
[4] Canlı İlerleme   → adım adım + Türkçe açıklama
[5] Rapor            → masaüstüne PDF/HTML/MD kaydet
```

Her ekran bağımsız bir `QWizardPage` olarak implemente edilir; `Wizard` sınıfı aralarındaki veriyi `WizardContext` dataclass'ı ile taşır.

---

## 6. Kodlama Konvansiyonları

- **Format**: Black (line-length 100), isort
- **Lint**: ruff
- **Type hints**: zorunlu (mypy --strict)
- **Docstring**: sadece public API için, Google stili
- **Yorumlar**: Sadece WHY için, Türkçe; WHAT yazılmaz
- **Test kapsamı**: `core/`, `safety/`, `reporting/` için ≥80%
- **Commit mesajı**: `<alan>: <özet>` — örn. `core: nmap tarayıcısı için rate limit eklendi`
- **Branch**: `main` (kararlı), `feature/<isim>`, `fix/<isim>`

---

## 7. Çalıştırma & Komutlar

```bash
# Dev ortamı kurulumu (venv içinde)
pip install -r requirements.txt -r requirements-dev.txt

# Uygulamayı başlat
python -m pentra

# Testler
pytest                       # hepsi
pytest tests/unit            # sadece unit

# Lint + format
ruff check src tests
black src tests
mypy src

# Windows .exe üretimi
python scripts/build_exe.py  # dist/Pentra.exe çıktısı verir
```

---

## 8. Sürüm Planı (Revize — 2026-04-21)

- **v0.1 (MVP)** ✅: Yetki onayı + localhost port taraması + basit HTML rapor
- **v0.2 — Faz 3**: Web Scanner (Seviye 2 probing): HTTP header, SSL/TLS, exposed paths, SQLi/XSS probe
- **v0.3 — Faz 4**: Servis versiyonu (-sV) + NVD CVE eşleştirme + default credentials check
- **v0.4 — Faz 5**: DB servis probe'ları (MongoDB/Redis/MySQL auth check) + yerel ağ keşfi + Wi-Fi pasif
- **v0.5 — Faz 6**: Akıllı rapor (CVSS, exec summary) + PDF export + SQLite geçmiş
- **v1.0**: Paketleme (PyInstaller .exe), kullanım kılavuzu, kod imzalama
- **v2.0**: Linux/macOS desteği, İngilizce arayüz, derin Wi-Fi (monitor mode + harici adaptör)

---

## 9. Hafıza Sistemi Kullanımı

- Bu `CLAUDE.md` + `memory-bank/*.md` birlikte çalışır
- **Her oturum başında**: CLAUDE.md → memory-bank/projectbrief.md → productContext.md → activeContext.md → systemPatterns.md → techContext.md → progress.md sırasıyla oku
- **Önemli değişiklik sonrası**: `memory-bank/activeContext.md` ve `memory-bank/progress.md` güncellenmeli
- Kullanıcı **"update memory bank"** derse: 6 çekirdek dosyanın **hepsi** baştan gözden geçirilip güncellenir
- `memory.md` (orijinal Cline spesifikasyonu) referans olarak tutulur, değiştirilmez

---

## 10. Kullanıcı Hakkında Önemli Notlar

- Kullanıcı siber güvenlik konusunda **sınırlı bilgiye** sahiptir. Teknik kararları açıklamadan sunma — önce nedenini Türkçe anlat, sonra seçim sun.
- Kullanıcı büyük değişiklikleri **önce planlamayı, onay aldıktan sonra uygulamayı** tercih eder (bu projenin başlangıcında da bu akış takip edildi).
- Belirsiz durumda **soru sor, varsayım yapma**.
