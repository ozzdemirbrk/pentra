# projectbrief.md — Pentra Temel Tanım

> **Bu dosya tüm diğer memory-bank dosyalarının kaynağıdır. Kapsam çatışması olursa burası esas alınır.**

---

## 1. Proje Adı
**Pentra** — yeni başlayanlar için sihirbaz arayüzlü Windows sızma testi aracı.

## 2. Tek Cümle Özet
Kullanıcıya adım adım "neyi/nereyi test etmek istersin?" diye soran, seçilen hedefi yetkili olduğu doğrulandıktan sonra tarayan ve sonuçları **yalnızca yerel masaüstüne** detaylı Türkçe rapor olarak yazan bir masaüstü uygulaması.

## 3. Çözdüğü Problem
Bireysel kullanıcılar ve küçük işletmeler kendi bilgisayarlarının/ağlarının güvenlik durumunu **kontrol edemiyor** çünkü:
- Mevcut pentest araçları (Kali, Metasploit, Burp vb.) **uzman kullanıcı için** tasarlanmış — yeni başlayan için dik öğrenme eğrisi
- Ticari tarayıcılar (Nessus, Qualys) **pahalı** ve bulut tabanlı — hassas bulgular dışarı çıkıyor
- Sonuçlar teknik ve **Türkçe onarım önerisi yok**

Pentra bu üç sorunu da çözer: ücretsiz, yerel, Türkçe, yeni başlayan dostu.

## 4. Temel Gereksinimler (Zorunlu)

### 4.1. Fonksiyonel
- **F1**: Kullanıcıya grafik sihirbazla hedef tipi sordurur (localhost / yerel ağ / IP aralığı / URL / Wi-Fi)
- **F2**: 3 tarama derinliği sunar (Hızlı / Standart / Derin) — her biri Türkçe açıklamalı
- **F3**: Her tarama öncesi yetki onayı alır; kapsam dışı hedefler için ek onay ister
- **F4**: Tarama sırasında canlı ilerleme gösterir, her adımı Türkçe açıklar
- **F5**: Bitince masaüstüne 3 formatta rapor yazar: PDF, HTML, Markdown
- **F6**: Raporda her bulgu için Türkçe onarım önerisi içerir
- **F7**: Geçmiş taramaları yerel SQLite'ta (şifreli) saklar, geri yükleyebilir

### 4.2. Fonksiyonel Olmayan
- **NF1**: Rapor dışarı **gönderilmez** — yalnızca yerel dosya
- **NF2**: Tek `.exe` olarak dağıtılabilir (PyInstaller)
- **NF3**: Arayüz %100 Türkçe (v1); kod tabanı çeviriye hazır olmalı
- **NF4**: Hızlı tarama ≤5 dk, standart ≤30 dk, derin ≤2 saat (tipik ev ağı için)
- **NF5**: DoS etkisi yaratmayacak şekilde rate-limited

### 4.3. Güvenlik/Etik (Mutlak Kısıtlar)
- **S1**: Exploit çalıştırılmaz — yalnızca tespit
- **S2**: RFC1918 dışı hedefler için ek onay ekranı
- **S3**: Her tarama `audit.log` dosyasına kaydedilir
- **S4**: Stealth/evasion/persistence modülleri **eklenmez**

## 5. Kapsam Dışı (v1 İçin)

- 🚫 Linux ve macOS desteği (v2)
- 🚫 İngilizce arayüz (v2)
- 🚫 Derin Wi-Fi pentesti — handshake capture, deauth, WPA kırma (v2, monitor mode gerektirir)
- 🚫 Otomatik exploit / payload delivery (hiçbir sürümde)
- 🚫 Bulut senkronizasyonu (hiçbir sürümde — tasarımsal karar)
- 🚫 Çok kullanıcı / ekip modu
- 🚫 Mobil uygulama

## 6. Başarı Kriterleri

- ✅ Bilgisayarında çalıştırıp "Yerel ağımı tara" diyen bir kullanıcı **15 dakika içinde** anlamlı Türkçe bir rapor görebilmeli
- ✅ Rapor çıktısı bir güvenlik uzmanı tarafından okunduğunda da teknik olarak doğru olmalı
- ✅ Yeni kullanıcı hiçbir teknik terim bilmeden akışı tamamlayabilmeli
- ✅ Yetkisiz tarama başlatılamamalı (doğrulama bariyerleri geçilemez)
- ✅ `.exe` çift tıklamayla çalışmalı (Python kurulu olmasına gerek yok)

## 7. Hedef Platform (v1)

- Windows 10 (build 19041+) ve Windows 11
- x64 mimarisi
- Yönetici yetkisi ile çalışır (ham paket için gerekli); UAC promptu normal akışın parçası

## 8. Proje Sahipliği

- **Sahibi**: ozzdemirbrk@gmail.com
- **Geliştirici**: aynı kullanıcı + Claude Code asistan iş birliği
- **Lisans planı**: Belirlenmedi (MVP sonrası karar — muhtemelen MIT veya özel)
