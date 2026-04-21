# Pentra

> Yeni başlayanlar için Windows masaüstü sızma testi aracı — sihirbaz arayüzlü, Türkçe, yerel rapor.

**⚠️ Proje henüz geliştirme aşamasında (Pre-Alpha). Kararlı sürüm yayınlanmadı.**

---

## 🎯 Pentra Nedir?

Pentra, kendi bilgisayarınızın veya yerel ağınızın güvenlik durumunu **ücretsiz, bulutsuz, Türkçe** olarak kontrol etmenizi sağlayan bir masaüstü uygulamasıdır. Terminal bilgisi, siber güvenlik uzmanlığı gerektirmez; adım adım sihirbaz sizi yönlendirir.

### Özellikler
- 🖥️ **5-ekran sihirbaz** — yetki onayı, hedef seçimi, derinlik ayarı, canlı ilerleme, rapor
- 🎯 **5 hedef tipi** — bu bilgisayar, yerel ağ, belirli IP, web sitesi, Wi-Fi ağları
- ⚡ **3 derinlik** — Hızlı (5dk), Standart (30dk), Derin (2 saat)
- 📄 **Yerel rapor** — masaüstüne PDF + HTML + Markdown; **hiçbir veri dışarı gönderilmez**
- 🇹🇷 **%100 Türkçe** — arayüz, bulgular, onarım önerileri
- 🛡️ **Sadece tespit** — exploit çalıştırmaz, yetkisiz tarama bariyerleri vardır

---

## 🚧 Geliştirme Durumu

Şu an **Faz 0 (Kurulum)** aşamasında. Detaylı ilerleme için [`memory-bank/progress.md`](memory-bank/progress.md) dosyasına bakın.

---

## 🔧 Geliştirme Ortamı Kurulumu

**Ön koşullar:**
- Python 3.11+
- [Nmap](https://nmap.org/download.html) (Windows installer)
- [Npcap](https://npcap.com/) (scapy için)

```bash
# Depoyu al
git clone <repo-url>
cd Pentra

# Sanal ortam oluştur
python -m venv .venv
.venv\Scripts\activate

# Bağımlılıkları kur
pip install -r requirements-dev.txt

# Pre-commit hook'larını kur (opsiyonel ama önerilir)
pre-commit install

# Çalıştır
python -m pentra

# Testleri çalıştır
pytest
```

---

## ⚖️ Etik Kullanım

**Pentra yalnızca sahibi olduğunuz veya yazılı izne sahip olduğunuz sistemler için kullanılmalıdır.** Yetkisiz tarama Türkiye'de **TCK Madde 243** uyarınca suçtur; diğer ülkelerde eşdeğer düzenlemeler vardır.

Uygulama başlatıldığında yetki onay ekranı bu sorumluluğu teyit etmeden tarama başlatmaz.

---

## 📋 Lisans

Henüz belirlenmedi. v1.0 öncesi netleşecektir.

---

## 📫 İletişim

Hata bildirimi ve öneriler için GitHub Issues kullanın.
