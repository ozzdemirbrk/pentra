# systemPatterns.md — Sistem Mimarisi ve Desenler

> **Kod nasıl organize edilir, bileşenler nasıl konuşur, hangi tasarım desenleri kullanılır.**

---

## 1. Mimari Genel Bakış

Pentra **3 katmanlı + 2 çapraz-kesen** mimaride çalışır:

```
┌─────────────────────────────────────────────────────────┐
│  GUI KATMANI (PySide6)                                  │
│  QWizard → QWizardPage'ler → Widget'lar                 │
└───────────────┬─────────────────────────────────────────┘
                │  Signals/Slots (Qt) + dataclass DTOs
┌───────────────▼─────────────────────────────────────────┐
│  ORKESTRASYON (Core)                                    │
│  ScanOrchestrator → Scanner'lar → Finding toplama       │
└───────────────┬─────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────┐
│  TARAMA KATMANI (Core/Knowledge)                        │
│  NetworkScanner | HostScanner | WebScanner | WifiScanner│
│  + CVEMapper + RemediationDB                            │
└─────────────────────────────────────────────────────────┘
          ▲                    ▲
          │                    │
┌─────────┴──────────┐  ┌──────┴────────────┐
│ ÇAPRAZ: SAFETY     │  │ ÇAPRAZ: STORAGE   │
│ Authorization      │  │ Database (SQLite) │
│ ScopeValidator     │  │ AuditLog          │
│ RateLimiter        │  │ ReportExporter    │
└────────────────────┘  └───────────────────┘
```

**Kural**: `core/` modülleri `gui/`'yi bilmez; `gui/` `storage/`'ı bilmez. İletişim signals/slots üzerinden.

## 2. Kritik Tasarım Desenleri

### 2.1. Strategy Pattern — Tarayıcılar
Tüm tarayıcılar `ScannerBase` soyut sınıfından türer:

```python
class ScannerBase(ABC):
    @abstractmethod
    def scan(self, target: Target, depth: ScanDepth) -> list[Finding]: ...

class NetworkScanner(ScannerBase): ...
class HostScanner(ScannerBase): ...
class WebScanner(ScannerBase): ...
class WifiScanner(ScannerBase): ...
```

Orkestratör hedef tipine göre doğru Scanner'ı seçer. Yeni bir tarama tipi eklemek = yeni bir sınıf yazmak.

### 2.2. Chain of Responsibility — Güvenlik Bariyerleri
Her tarama talebi bir zincirden geçer:

```
Request → AuthorizationCheck → ScopeValidator → RateLimiter → Scanner
              ↓ fail             ↓ fail             ↓ fail
           Reject              Reject            Reject
```

Herhangi bir halka `False` dönerse tarama başlamaz. Hiçbir bypass yok.

### 2.3. Observer Pattern — Canlı İlerleme
`Scanner`, Qt sinyalleri ile durumunu yayınlar:

```python
class ScannerBase(QObject):
    progress_updated = Signal(int, str)   # (yüzde, Türkçe açıklama)
    finding_discovered = Signal(Finding)
    scan_completed = Signal()
    error_occurred = Signal(str)
```

GUI katmanı bu sinyallere bağlanır, kullanıcıya gösterir.

### 2.4. Builder Pattern — Rapor Oluşturma
`ReportBuilder` zincirlemeyle rapor kurar:

```python
report = (ReportBuilder()
    .with_scan_metadata(scan)
    .with_executive_summary(findings)
    .with_detailed_findings(findings)
    .with_remediations(findings, language="tr")
    .build())

exporter = PDFExporter()
exporter.export(report, desktop_path)
```

### 2.5. Repository Pattern — Veri Erişimi
SQLite'a doğrudan erişim yok; `ScanRepository`, `FindingRepository` üzerinden:

```python
class ScanRepository:
    def save(self, scan: Scan) -> int: ...
    def load(self, scan_id: int) -> Scan: ...
    def list_recent(self, limit: int) -> list[Scan]: ...
```

### 2.6. Wizard Pattern — Kullanıcı Akışı
PySide6'nın `QWizard` sınıfı kullanılır. Her ekran bir `QWizardPage`. Sayfalar arası veri `WizardContext` dataclass'ıyla taşınır:

```python
@dataclass
class WizardContext:
    authorization_accepted: bool = False
    target: Target | None = None
    depth: ScanDepth | None = None
    scan_id: int | None = None
    findings: list[Finding] = field(default_factory=list)
```

## 3. Bileşenler Arası İlişki

```
gui/wizard.py
    │ başlatır
    ▼
gui/screens/authorization.py ──onay──▶ safety/authorization.py (logs)
    │ İleri
    ▼
gui/screens/target_select.py ──validate──▶ safety/scope_validator.py
    │ İleri
    ▼
gui/screens/depth_select.py
    │ İleri  (ScanRequest oluşturulur)
    ▼
gui/screens/progress.py ──başlat──▶ core/scan_orchestrator.py
                                          │
                                          ├──▶ core/network_scanner.py
                                          │       ├─▶ core/rate_limiter.py
                                          │       └─▶ knowledge/cve_mapper.py
                                          │
                                          ├──▶ storage/audit_log.py (her adım)
                                          │
                                          └──▶ storage/database.py (bulgular)
    │ tamamlandı
    ▼
gui/screens/report.py ──üret──▶ reporting/report_builder.py
                                      │
                                      └──▶ reporting/exporters/{pdf,html,md}.py
                                              │
                                              └──▶ Masaüstü dosyası
```

## 4. Kritik İmplementasyon Yolları

### Yol 1: Yeni bir Scanner Eklemek
1. `core/your_scanner.py` dosyası oluştur, `ScannerBase`'den türet
2. `scan()` metodunu implement et; sinyalleri yay
3. `core/rate_limiter.py`'ı kullan — doğrudan socket yok
4. Her bulgu için `Finding` dataclass'ı döndür; `cve_id` varsa `knowledge/cve_mapper.py` ile zenginleştir
5. `core/scan_orchestrator.py`'a yeni tarayıcıyı register et
6. Testler: `tests/unit/core/test_your_scanner.py` (mock ağ)

### Yol 2: Yeni Bir Hedef Tipi Eklemek
1. `models.py`'da `TargetType` enum'una ekle
2. `safety/scope_validator.py`'a doğrulama kuralı ekle
3. `gui/screens/target_select.py`'ya yeni seçenek radyo butonu
4. Orkestratöre hangi Scanner'ın çalışacağını söyle

### Yol 3: Yeni Bir Rapor Formatı Eklemek
1. `reporting/exporters/your_format.py` — `BaseExporter`'dan türet
2. `reporting/templates/your_template.j2` (varsa şablon)
3. `gui/screens/report.py`'ya yeni "Kaydet" butonu

## 5. Thread Modeli

- **Ana thread**: Qt UI
- **Worker thread**: `QThread` içinde Scanner'lar çalışır
- **Scanner içinde**: gerekirse `ThreadPoolExecutor` (ör. 50 IP'ye paralel port taraması)
- **UI güncelleme**: kesinlikle ana thread'den; worker sinyal emit eder, slot ana thread'de çalışır

## 6. Hata Yönetimi Stratejisi

- **Tarama içi hatalar**: Scanner yakalar, `Finding(severity='info', type='scan_error')` olarak rapora ekler. Tarama devam eder.
- **Yetki/kapsam hataları**: Tarama hiç başlamaz; kullanıcıya Türkçe uyarı diyaloğu.
- **Sistem hataları** (disk dolu, izin yok): Üst katmanda `@safe_qt_action` dekoratörü ile yakalanır, dostane mesaj gösterilir.
- **Beklenmeyen exception'lar**: `utils/logging_config.py`'da global handler, `audit.log`'a stack trace yazar + kullanıcıya hata raporu oluşturma seçeneği.

## 7. Konfigürasyon Yönetimi

- `src/pentra/config.py` — sabit değerler (varsayılan rate limit, timeout'lar)
- `%APPDATA%/Pentra/config.json` — kullanıcı tercihleri (tema, dil, son hedef)
- Kullanıcı tercihleri Pydantic model'le şema doğrulanır

## 8. Genişletilebilirlik Noktaları

v2 için şimdiden düşünülmüş uzatma noktaları:
- `core/scanner_base.py` — yeni tarayıcılar kolay eklenir
- `reporting/exporters/` — yeni format (JSON, SARIF)
- `resources/translations/` — Qt Linguist için .ts dosyaları
- `knowledge/remediations_tr.py` — `remediations_en.py`, `remediations_de.py` eklenebilir

## 9. Probe Pattern (Seviye 2 — Faz 3+ için)

Her Seviye 2 probe için standart şablon — yeni probe eklerken aynısı kullanılır:

```python
class WebProbeBase(ABC):
    """Tek bir zafiyet için non-destructive test."""
    name: str  # "sql_injection", "exposed_env", vb.

    @abstractmethod
    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        """Tek probe çalıştır, bulguları döndür.

        KURALLAR (ihlal edilirse kod review red):
        1. Tek test paketi gönder (döngü yok, aynı endpoint'e tekrar yok)
        2. Response'u yorumla — veri çekme yok
        3. Timeout kısa (~5sn) — yanıt yoksa bırak
        4. Bağlantı açıksa kapat
        5. Her find'ta 'evidence' alanı: hangi request, hangi response
        """
```

**Probe'ları dizme (ordering)**: WebScanner tüm probe'ları sıralı çalıştırır, **paralel değil**. Rate limiter'dan her probe için token alınır. Böylece rate limit global — 10 probe × 1 hedef = 10 paket, DoS değil.

**Kanıt zorunlu**: Her Finding.evidence dict'i içine şunlar gider:
- `request`: hangi HTTP method, hangi path, hangi payload
- `response_snippet`: yanıtın ilk 200 karakteri (veri çekmek değil — minimum kanıt)
- `why_vulnerable`: Türkçe açıklama, neden zafiyet olduğu

---

## 10. Yapmayacağımız Şeyler (Anti-Desenler)

- ❌ Singleton (test edilmesi zor) — gerekli yerlerde Dependency Injection
- ❌ God object (tek dev `ScanManager`) — sorumlulukları Scanner'lara böl
- ❌ Magic strings (port numaraları, path'ler) — `config.py`'da sabit
- ❌ `print()` — her yerde `structlog`
- ❌ UI'da iş mantığı — Scanner'ı doğrudan çağıran UI yok, orkestratör üzerinden
