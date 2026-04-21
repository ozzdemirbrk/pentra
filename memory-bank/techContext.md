# techContext.md — Teknik Bağlam

> **Teknolojiler, bağımlılıklar, geliştirme ortamı, araç kullanımı.**

---

## 1. Teknoloji Yığını (Detaylı)

### 1.1. Dil ve Çalışma Ortamı
| Bileşen | Versiyon | Rol |
|---|---|---|
| Python | 3.11+ | Tek programlama dili |
| venv | stdlib | İzole geliştirme ortamı |
| pip-tools | son | `requirements.txt` kilitleme |

**Neden Python 3.11+?** `tomllib` stdlib'de, pattern matching, daha hızlı, daha iyi hata mesajları. Pentest ekosistemi Python dominant.

### 1.2. GUI
| Bileşen | Versiyon | Rol |
|---|---|---|
| PySide6 | 6.6+ | Qt6 Python binding (LGPL) |
| qt-material (opsiyonel) | — | Hazır modern tema |

**Neden PySide6 (PyQt6 yerine)?** LGPL lisansı — ticari dağıtımda daha esnek. Resmi Qt binding'i.

### 1.3. Tarama / Ağ
| Bileşen | Versiyon | Rol |
|---|---|---|
| python-nmap | 0.7+ | nmap wrapper (nmap sistem kurulumu gerekir) |
| scapy | 2.5+ | Ham paket oluşturma/yakalama |
| requests | 2.31+ | HTTP client (web scanner) |
| urllib3 | — | requests'in bağımlılığı, TLS kontrolü |
| paramiko | 3.4+ | SSH istemci (zayıf auth tespiti) |
| impacket | 0.12+ | SMB/LDAP protokolleri |
| sslyze | 5.2+ | SSL/TLS konfigürasyon analizi |
| dnspython | 2.4+ | DNS kayıtları |
| netaddr | 1.0+ | IP aralık işlemleri |

### 1.4. Rapor
| Bileşen | Versiyon | Rol |
|---|---|---|
| Jinja2 | 3.1+ | HTML şablonlama |
| WeasyPrint | 60+ | HTML→PDF (alternatif: xhtml2pdf) |
| markdown-it-py | 3+ | MD rendering |

**⚠️ WeasyPrint Windows bağımlılığı**: GTK3 runtime gerektirir. Kurulum zahmetli. Alternatif olarak `xhtml2pdf` değerlendirilebilir (saf Python ama daha sınırlı CSS).

### 1.5. Veri Saklama
| Bileşen | Versiyon | Rol |
|---|---|---|
| SQLite | 3.40+ (Python ile gelir) | Yerel veritabanı |
| pysqlcipher3 | 1.2+ | DB şifreleme (alternatif: uygulama katmanı Fernet) |
| cryptography | 42+ | Fernet, imza, anahtar türetme |

### 1.6. Yardımcılar
| Bileşen | Versiyon | Rol |
|---|---|---|
| pydantic | 2.5+ | Ayar/model doğrulama |
| structlog | 24+ | Yapılandırılmış loglama |
| rich | 13+ | CLI alt komutlar için şık çıktı |
| click | 8.1+ | CLI arayüzü (opsiyonel gelişmiş mod) |

### 1.7. Geliştirme ve Test
| Bileşen | Versiyon | Rol |
|---|---|---|
| pytest | 8+ | Test çalıştırıcı |
| pytest-qt | 4.3+ | Qt widget testleri |
| pytest-cov | 4+ | Kapsam raporu |
| pytest-mock | 3+ | Mocking |
| ruff | 0.2+ | Lint |
| black | 24+ | Kod formatlayıcı |
| mypy | 1.8+ | Statik tip denetimi |
| pre-commit | 3+ | Commit öncesi otomasyonlar |

### 1.8. Paketleme
| Bileşen | Versiyon | Rol |
|---|---|---|
| PyInstaller | 6+ | Tek `.exe` üretimi |
| Inno Setup (harici) | 6+ | Windows installer (ileride) |

## 2. Sistem Bağımlılıkları (Python Dışı)

Windows kullanıcısının **kurulu olması gereken** harici araçlar:

| Araç | Neden | Nereden |
|---|---|---|
| **Nmap** (zorunlu) | python-nmap bu exe'yi çağırır | nmap.org |
| **Npcap** (zorunlu) | scapy için ham paket erişimi | npcap.com (WinPcap yerine) |
| **GTK3 Runtime** (WeasyPrint kullanılırsa) | PDF üretimi | github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer |

**Plan**: v1.0 installer içinde Nmap ve Npcap'i "kur" seçeneği olarak sunulacak (bundle edilecek veya downloader ile).

## 3. Geliştirme Ortamı

### 3.1. Önerilen Kurulum
```bash
# 1. Python 3.11+ kur (Microsoft Store veya python.org)
# 2. Nmap ve Npcap kur
# 3. Depo al
git clone <repo-url>
cd Pentra

# 4. venv oluştur ve aktive et
python -m venv .venv
.venv\Scripts\activate

# 5. Bağımlılıkları kur
pip install -r requirements.txt -r requirements-dev.txt

# 6. Pre-commit hook'ları kur
pre-commit install

# 7. Çalıştır
python -m pentra
```

### 3.2. IDE: VS Code (önerilen) veya PyCharm
Önerilen VS Code eklentileri:
- Python (Microsoft)
- Pylance
- Ruff
- Qt for Python (PySide6 autocomplete)
- GitLens

### 3.3. .editorconfig / Format
- LF satır sonları (Windows'ta bile — git autocrlf false)
- 4 space indent
- UTF-8 encoding
- Satır sonu whitespace trim

## 4. Teknik Kısıtlar

### 4.1. Platform Kısıtları
- **Yönetici yetkisi gerekli**: Ham paket gönderme (scapy) ve bazı nmap modları için. UAC prompt'u kabul edilmeden tarama yapılamaz.
- **Windows Defender / SmartScreen**: İmzasız .exe ilk açılışta uyarı verir. Dokümantasyonda "Daha fazla bilgi → Yine de çalıştır" yönergesi.
- **Firewall**: Windows Firewall bazı scapy paketlerini engelleyebilir; uygulama kurulumunda exception eklenmesi gerekebilir.

### 4.2. Performans Kısıtları
- Port taraması için **rate limit**: varsayılan 500 paket/sn, kullanıcı ağında gecikme yaratmamak için
- **Tek makinede** çalışır — dağıtık tarama yok
- Ağ topolojisi ve latency'ye bağlı: yerel ev ağında tarama ~10-30 saniye, internet hedefinde daha uzun

### 4.3. Etik/Yasal Kısıtlar
- Yalnızca kullanıcının yazılı yetkisi olan hedefler taranır
- Türkiye'de TCK 243-245 kapsamında; yurtdışında CFAA, GDPR vb. kullanıcının sorumluluğu
- Exploit çalıştırma yok (tasarımsal)
- Uygulama kullanım şartları ve yasal uyarı İlk açılışta gösterilir ve onaylanmadan kullanılamaz

## 5. Bağımlılık Yönetimi

- `requirements.txt` — üretim bağımlılıkları (sabitlenmiş versiyonlar, `pip-compile` ile)
- `requirements-dev.txt` — test/lint araçları
- Güvenlik güncellemesi için `pip-audit` aylık çalıştırılır
- Major versiyon yükseltmeleri ayrı PR'da test edilir

## 6. Loglama Stratejisi

| Log | Dosya | Seviye | İçerik |
|---|---|---|---|
| Uygulama | `%APPDATA%/Pentra/app.log` | INFO+ | Genel akış, hatalar |
| Audit (denetim) | `%APPDATA%/Pentra/audit.log` | ALL | Her tarama isteği, hedefi, sonucu — imzalı |
| Debug (dev) | stderr | DEBUG+ | Sadece `--debug` flag ile |

Log rotasyonu: `logging.handlers.RotatingFileHandler`, 10MB × 5 dosya.

## 7. Güvenlik Teknik Önlemleri

- **Anahtar yönetimi**: DB şifreleme anahtarı, kullanıcı parolasından PBKDF2-HMAC-SHA256 ile türetilir (iterations ≥ 600.000)
- **Kod imzalama (v2+)**: Windows kod imzalama sertifikası — SmartScreen reputation için
- **Bağımlılık taraması**: CI'da `pip-audit` + `safety check`
- **Supply chain**: `requirements.txt` hash'li (`--require-hashes`)

## 8. Dağıtım

### v0.x (iç test)
- `dist/Pentra.exe` — PyInstaller onedir veya onefile
- GitHub Releases'a yüklenir
- SHA256 imza `.sha256` dosyası ile

### v1.0+
- Inno Setup ile `.msi` installer
- Nmap + Npcap installer'ları bundle
- Kod imzalama sertifikası ile imzalı
- Otomatik güncelleme mekanizması (opsiyonel — kullanıcı onayıyla)
