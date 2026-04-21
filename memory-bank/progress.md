# progress.md — İlerleme Durumu

> **Ne çalışıyor, ne kaldı, bilinen sorunlar, proje kararlarının evrimi.**

---

## Son Güncelleme
**2026-04-21** — Faz 0 tamamlandı. Proje iskeleti, bağımlılık dosyaları, test çatısı, lint/format yapılandırması hazır. Git init ve ilk commit kullanıcı onayını bekliyor.

---

## 1. Genel Durum

```
Faz 0: Planlama & Kurulum       ██████████  %100 (iskelet, config, test çatısı hazır)
Faz 1: Güvenlik Katmanı         ░░░░░░░░░░  %0
Faz 2: MVP (localhost tarama)   ░░░░░░░░░░  %0
Faz 3: Tüm hedef tipleri        ░░░░░░░░░░  %0
Faz 4: Web + Wi-Fi (pasif)      ░░░░░░░░░░  %0
Faz 5: Rapor + CVE + Türkçe öneri ░░░░░░░░░░ %0
Faz 6: Paketleme & dağıtım      ░░░░░░░░░░  %0
```

**Toplam tamamlanma**: ~%15 (planlama, dokümantasyon, iskelet)

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

## 3. Yapılması Gerekenler 📋

### Faz 0 — Kurulum ✅ (neredeyse tamamlandı)
- [x] `pyproject.toml` + `requirements.txt` + `requirements-dev.txt`
- [x] `src/pentra/` paket yapısı (boş `__init__.py`'ler + `app.py`, `config.py`)
- [x] `.gitignore`, `README.md` (placeholder), `LICENSE` (placeholder)
- [x] pre-commit config + ruff/black/mypy ayarları
- [x] tests/ çatısı + conftest.py + smoke test
- [ ] `scripts/setup_dev.py` — venv kurulum otomasyonu (opsiyonel, ertelenebilir)
- [ ] Git repo init + ilk commit (kullanıcı onayı bekleniyor)

### Faz 1 — Güvenlik Katmanı (ÖNCELİK — kod başlar başlamaz)
- [ ] `safety/authorization.py` — AuthorizationManager sınıfı
- [ ] `safety/scope_validator.py` — RFC1918 + allowlist + kullanıcı onayı zinciri
- [ ] `core/rate_limiter.py` — token bucket algoritması
- [ ] `storage/audit_log.py` — imzalı append-only log
- [ ] Birim testler (%100 kapsam hedefi)

### Faz 2 — MVP
- [ ] `app.py` + `gui/wizard.py` — QApplication iskeleti
- [ ] 5 ekran: authorization, target_select, depth_select, progress, report (sadece localhost için)
- [ ] `core/scanner_base.py` — soyut Scanner
- [ ] `core/network_scanner.py` — localhost port taraması
- [ ] Basit HTML rapor şablonu
- [ ] Uçtan uca akış: aç → onay → bu bilgisayarı tara → rapor

### Faz 3 — Tüm Hedef Tipleri
- [ ] Yerel ağ keşfi (ARP scan, ICMP sweep)
- [ ] IP aralığı desteği (CIDR notasyonu)
- [ ] Host scanner (servis/versiyon tespiti)
- [ ] `knowledge/cve_mapper.py` — versiyon → CVE (NVD JSON feed)

### Faz 4 — Web + Wi-Fi Pasif
- [ ] `core/web_scanner.py` — HTTP başlıkları, SSL/TLS (sslyze), güvenlik header eksikleri
- [ ] `core/wifi_scanner.py` — çevre ağları listele (Windows `netsh wlan`)

### Faz 5 — Tam Rapor
- [ ] Jinja2 HTML şablonu (Türkçe, profesyonel görünüm)
- [ ] PDF exporter (WeasyPrint veya xhtml2pdf)
- [ ] Markdown exporter
- [ ] `knowledge/remediations_tr.py` — bulgu tipi → Türkçe onarım adımları
- [ ] Yönetici özeti + detay bölümleri

### Faz 6 — Paketleme
- [ ] `scripts/build_exe.py` — PyInstaller script
- [ ] İkon ve logo (tasarım gerekli)
- [ ] Inno Setup script
- [ ] Nmap + Npcap bundle
- [ ] GitHub Releases workflow
- [ ] Kullanım kılavuzu (PDF, Türkçe)

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
