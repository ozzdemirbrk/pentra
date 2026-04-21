# productContext.md — Pentra Ürün Bağlamı

> **Bu projenin neden var olduğu, hangi sorunu çözdüğü ve kullanıcı deneyimi hedefleri.**

---

## 1. Neden Var?

Veri sızıntıları ve hacklenmeler 2020'lerde sıradanlaştı. Ama bireysel kullanıcı ve küçük işletmelerin elinde **kendi güvenliğini ölçecek bir araç yok**:

- **Profesyonel araçlar** (Nessus, Burp Pro, Metasploit) — pahalı, uzman gerektirir, bulutta çalışır
- **Ücretsiz araçlar** (nmap, OpenVAS) — güçlü ama CLI, terminal bilmeyen kullanabilez
- **Tarayıcı eklentileri** — yüzeysel, sadece web odaklı
- **Antivirüs** — zafiyet değil, malware arar; farklı problem

Pentra, bu boşluğu doldurmak için var: **"ev kullanıcısı kendi ağını/bilgisayarını tarayabilsin."**

## 2. Hangi Problemleri Çözer?

### Problem 1: "Nereden başlayacağımı bilmiyorum"
- **Çözüm**: 5-ekran sihirbaz. Her ekran tek bir soru sorar. Her seçeneği Türkçe açıklar.

### Problem 2: "Terminal ve komut satırını bilmiyorum"
- **Çözüm**: Grafik arayüz; komut satırına hiç girilmez.

### Problem 3: "Sonuçları anlamıyorum — 'CVE-2023-XXXX' bana ne anlatır?"
- **Çözüm**: Her bulguda:
  - 🎯 **Ne var?** (Türkçe)
  - ⚠️ **Ne anlama geliyor?** (risk seviyesi + etkisi)
  - 🔧 **Ne yapmalıyım?** (adım adım onarım önerisi)

### Problem 4: "Raporum bulutta tutulur mu, kim görür?"
- **Çözüm**: Rapor **yalnızca masaüstüne** yazılır. Uygulama dışarı hiçbir şey göndermez. Kullanıcı tam kontrolde.

### Problem 5: "Ücretsiz bir şey istiyorum ama güvenilir olsun"
- **Çözüm**: Açık kaynak Python kütüphaneleri (nmap, scapy) üzerine kurulu; kullanıcı isterse kodu inceleyebilir.

## 3. Nasıl Çalışmalı?

### 3.1. Giriş
Kullanıcı `Pentra.exe`'ye çift tıklar. UAC yönetici onayı açılır (ham paket için). Kabul edilir.

### 3.2. Ekran 1 — Yetki Onayı
> "Bu aracı yalnızca **sahibi olduğunuz** veya **yazılı yetkiye sahip olduğunuz** sistemlerde kullanın. Yetkisiz tarama Türkiye'de TCK Madde 243 uyarınca suçtur."
>
> ☐ Sahibi olduğum / yetkim olan sistemleri tarayacağımı onaylıyorum.

İki checkbox işaretlenmeden **İleri** butonu pasif.

### 3.3. Ekran 2 — Hedef Seçimi

| Seçenek | Açıklama | Örnek |
|---|---|---|
| 🖥️ Bu bilgisayar | Kullandığınız bilgisayarı tarar | 127.0.0.1 |
| 🏠 Yerel ağım | Ev/ofis ağınızdaki tüm cihazları keşfeder | 192.168.1.0/24 |
| 🌐 Belirli IP | Tek bir IP veya aralık | 192.168.1.50 |
| 🔗 Web sitesi | Bir URL'nin güvenlik durumu | https://site.com |
| 📡 Wi-Fi ağları | Çevrenizdeki Wi-Fi ağlarını listeler | (pasif) |

### 3.4. Ekran 3 — Derinlik

| Seviye | Süre | Yapılanlar |
|---|---|---|
| 🟢 Hızlı | ~5 dk | Açık portlar, yaygın servisler — pasif |
| 🟡 Standart | ~30 dk | + Servis/versiyon tespiti, temel zafiyet |
| 🔴 Derin | ~2 saat | + Ayrıntılı zafiyet taraması, zayıf kimlik kontrolü |

Her seviyenin **ne yaptığı** ve **ne yapmadığı** Türkçe listelenir.

### 3.5. Ekran 4 — Canlı İlerleme

```
[████████░░░░░░░░] %52
✅ Host keşfi tamamlandı — 7 aktif cihaz bulundu
✅ Port taraması tamamlandı — 23 açık port
⏳ Servis versiyonları tespit ediliyor...
```

Her adımın yanında **"Bu ne demek?"** butonu; tıklayınca Türkçe açıklama.

### 3.6. Ekran 5 — Rapor

- Yönetici özeti (kaç bulgu, ne kadar kritik)
- Her bulgu için kart: seviye, ne var, risk, onarım
- "Masaüstüne Kaydet" butonu → PDF + HTML + MD

## 4. Kullanıcı Deneyimi (UX) Hedefleri

### 4.1. İlkeler
- **Açıklık sessizlikten iyidir**: Her seçeneğin ne yapacağı önceden açıklanır
- **Güvenlik bariyerleri açık**: Kullanıcı neden onay verdiğini bilir
- **Hata mesajları rehber olsun**: "Bağlantı başarısız" değil, "Hedef cihaz kapalı olabilir veya firewall engelliyor olabilir. Kontrol edin..."
- **Teknik terim = hover ipucu**: "Port", "CVE", "SSL handshake" gibi terimler ℹ️ ikonu ile açıklanır
- **Geri alınabilir**: Kullanıcı istediği zaman iptal edebilir; hiçbir değişiklik kalıcı değil

### 4.2. Tasarım Tonu
- Profesyonel ama dostane
- Koyu tema varsayılan (gece uzun taramalar için rahat)
- Renk kodu: 🟢 iyi, 🟡 dikkat, 🔴 kritik (uluslararası anlaşılır)
- Emoji/ikon kullan, ama fazla abartma — ciddiyet korunmalı

### 4.3. Erişilebilirlik
- Yazı boyutu ayarlanabilir
- Klavye ile tam navigasyon (Tab/Enter)
- Ekran okuyucu uyumluluğu (Qt'nin native desteği)

## 5. Kullanıcı Persona (Ana)

**Ahmet, 34, sistem yöneticisi değil — ama evinde 10+ IoT cihaz var**
- Bilgisayar ve internet konusunda ortanın üstü
- Güvenlik hakkında "güvenli parola, antivirüs" kadar bilir
- Haber bültenlerinde "2 milyon kullanıcının verisi sızdı" gördükçe kaygılanır
- Komut satırına girmez; grafik arayüz ister
- Türkçe ister
- Ücretsiz ister
- Verinin dışarı çıkmamasını ister

Pentra **doğrudan Ahmet için** tasarlanır.

## 6. Ne YAPAR — "Sızabiliyor mu?" Sorusunun Cevabı

Pentra **Seviye 2 (non-destructive probing)** aracıdır. "Sızabiliyor mu?" sorusunu şöyle cevaplar:

**Faz 3+'ta yapılacak probe çeşitleri (hepsi Seviye 2):**
- ✅ **Default credentials**: SSH/MySQL/Redis/RDP vb. `admin:admin` dener, kabul edildiyse rapor, anında kopar
- ✅ **SQL injection probe**: Login formuna `' OR '1'='1` gönderir, davranış değişikliği varsa rapor
- ✅ **XSS probe**: Benign payload gönderir, kaçış yapılmadıysa rapor
- ✅ **Directory traversal**: `../../etc/passwd` ister, sızıntı varsa rapor
- ✅ **SSL/TLS zafiyet**: Heartbleed/POODLE/zayıf cipher/eksik HSTS tespiti
- ✅ **Auth bypass**: `/admin` path'i auth'suz erişilebilir mi, JWT `alg:none` kabul ediyor mu
- ✅ **Exposed config**: `/.env`, `/.git/config`, `/wp-config.bak` public mi
- ✅ **DB open check**: MongoDB/Redis/Elasticsearch parolasız bağlanıyor mu
- ✅ **Known CVE**: Versiyon + NVD → "Apache 2.2.3 için 23 CVE var" gibi rapor

Her probe **kanıt üretir**, **saldırı yapmaz**. Test paketi → tepki → sonuç → koparır → raporlar.

---

## 7. Ne YAPMAZ? (Tasarımsal + Etik Sınırlar)

- 🚫 **Exploit fırlatmaz** (Metasploit tarzı) — kanıt için probe yeter, shell açmaya gerek yok
- 🚫 **Veri çekmez** — DB'ye bağlanırsa sadece "bağlandım" der, içeriği okumaz
- 🚫 **Parola kırmaz / brute force yapmaz** — 1-2 default dener, sonra bırakır
- 🚫 **Otomatik onarım yapmaz** — kullanıcıya ne yapacağını söyler, ama müdahale etmez
- 🚫 **Başkalarını test etmek için değildir** — yetki bariyerleri bunu engeller
- 🚫 **Sürekli izleme (SIEM) değildir** — tek seferlik tarama yapar
- 🚫 **Antivirüs değildir** — malware aramaz, zafiyet arar
- 🚫 **Stealth/evasion yapmaz** — IDS/IPS'e yakalanmamak için obfuscation yok
- 🚫 **İz silmez** — log'lara yazar, silmez
