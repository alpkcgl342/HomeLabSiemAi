# Yapay Zeka Destekli Ev Ağı SIEM Projesi — Proje Raporu

> **Durum:** Bu rapor, sentetik veri ve otomatik testlerle elde edilen sonuçları içerir.
> `▢` ile işaretli alanları kendi Security Onion kurulumunuzdan aldığınız sonuçlarla doldurun.

## Özet

Bu projede ev ağı trafiğini izlemek için açık kaynak **Security Onion** platformu üzerinde yerel
bir SIEM (Security Information and Event Management) ortamı kuruldu. Ev ağına özgü tehditler
için 18 Suricata ve 8 Sigma kuralı yazıldı. İmza tabanlı tespitlerin yetersiz kaldığı durumlar
için Python ile davranışsal analizler ve makine öğrenmesi (Isolation Forest) tabanlı anomali
tespiti geliştirildi. Tüm bulgular, yerel çalışan bir büyük dil modeli (Ollama) ile önceliklendirilip
açıklandı ve haftalık Türkçe/İngilizce rapora dönüştürüldü. Kurallar "detection-as-code"
yaklaşımıyla GitHub'da tutulmakta ve her değişiklikte otomatik olarak test edilmektedir.

**Anahtar kelimeler:** SIEM, Security Onion, Suricata, Zeek, Sigma, MITRE ATT&CK, LLM, Ollama, anomali tespiti

## 1. Giriş ve amaç

Akıllı TV, IP kamera, NAS gibi IoT cihazlarının artmasıyla ev ağları kurumsal ağlara benzer
risklerle karşı karşıya kaldı. Ancak evlerde ağ trafiğini izleyen bir güvenlik ekibi yoktur.
Bu projenin amaçları şunlardır:

1. Ev ağı trafiğini toplayan ve saklayan bir SIEM ortamı kurmak.
2. Ev ağına özgü tehditler için tespit kuralları yazmak ve bu kuralları MITRE ATT&CK ile eşlemek.
3. Teknik bilgisi olmayan bir ev kullanıcısının da anlayabileceği yapay zeka destekli raporlar üretmek.
4. Bunları gizliliği koruyarak, yani verinin evden çıkmadığı bir yapıda gerçekleştirmek.

## 2. Kapsam ve tehdit modeli

| Tehdit | Örnek senaryo | Tespit katmanı |
|---|---|---|
| Ele geçirilmiş IoT cihazı | Kameranın C2 sunucusuna düzenli bağlanması | Beaconing analizi, Suricata 9100018 |
| Veri sızdırma | NAS'tan gece saatlerinde GB'larca yükleme | Exfil analizi, Sigma büyük yükleme |
| DNS tünelleme | TXT sorgularıyla veri kaçırma | DNS entropi analizi, Suricata 9100005, Sigma |
| Yetkisiz cihaz | Ağa bağlanan "kali" cihazı | Envanter karşılaştırması, Sigma DHCP |
| Keşif | Ağ içi port taraması | Suricata 9100001/9100002, tarama analizi |
| Dışarıya açık servis | İnternetten Telnet/RDP denemesi | Suricata 9100007/9100008 |
| Sosyal mühendislik | "Teknik destek" dolandırıcısının AnyDesk ile bağlanması | Suricata 9100013/9100015 |
| Kaynak istismarı | Kripto madenciliği | Suricata 9100016, Sigma madencilik havuzu |

## 3. Mimari

Ayrıntılı diyagram: [architecture.md](../architecture.md)

* **Trafik toplama:** Yönetilebilir switch üzerinde port mirroring kullanıldı. Modem uplink portu, PC'deki ikinci ağ kartına yansıtıldı.
* **Sensör ve SIEM:** Security Onion, sanal makinede EVAL modunda çalıştırıldı. Bu modda imza tabanlı IDS için Suricata, protokol logları için Zeek, depolama için Elasticsearch ve Sigma kuralları için ElastAlert kullanılıyor.
* **Yapay zeka asistanı:** Python ile yazılan `homesiem` paketi ve Ollama, Docker üzerinde çalıştırıldı.
* **Raporlama:** Haftalık Markdown rapor ve makine tarafından okunabilir `findings.json` üretildi.

Security Onion bir Linux dağıtımı olduğu için Docker Compose ile kurulamaz. Bu yüzden SIEM
sanal makinede, yapay zeka bileşenleri ise Docker'da çalıştırıldı.

## 4. Kurulum (özet)

| Adım | Açıklama |
|---|---|
| 1 | Security Onion ISO'su indirildi, imzası doğrulandı |
| 2 | VM oluşturuldu: 4 vCPU, ▢ GB RAM, 200 GB disk, 2 ağ kartı (yönetim + promiscuous dinleme) |
| 3 | EVAL kurulumu yapıldı, yönetim IP'si ▢ olarak atandı |
| 4 | `HOME_NET` ve `DNS_SERVERS` değişkenleri tanımlandı |
| 5 | Özel kurallar Detections ekranından eklendi |
| 6 | `docker compose up -d ollama` komutu çalıştırıldı ve `llama3.1:8b` modeli indirildi |
| 7 | Loglar `fetch_so_logs.sh` ile çekildi, `homesiem analyze` ile rapor üretildi |

Kullanılan donanım: ▢ (CPU, RAM, switch modeli)

## 5. Tespit kuralları

Tam liste ve MITRE eşlemesi: [detection-catalog.md](../detection-catalog.md)

* **Suricata (18 kural, SID 9100001–9100018):** Ağ paketleri üzerinde gerçek zamanlı çalışan imzalar. Her kural `metadata` alanında MITRE taktik ve teknik ID'si taşır. Bu sayede Security Onion'ın ATT&CK Navigator görünümünde ve yapay zeka raporunda otomatik olarak eşlenir.
* **Sigma (8 kural):** Zeek logları üzerinde çalışan, platformdan bağımsız kurallar. Aynı kurallar Splunk, Elastic veya Wazuh gibi başka SIEM'lere de dönüştürülebilir.
* **Davranışsal analizler:** İmzaların yakalayamadığı, zamana yayılan davranışlar için yazıldı:
  - **Beaconing:** Bağlantılar arasındaki sürelerin değişim katsayısı (CV) ölçülür. CV ≤ 0.15 ise trafik makine düzenliliğinde kabul edilir.
  - **DNS tünelleme:** Alt alan adlarının Shannon entropisine ve benzersiz alt alan adı sayısına bakılır.
  - **Port taraması:** Kayan zaman penceresinde bir kaynağın ulaştığı benzersiz hedef:port çiftleri sayılır.
  - **Veri sızdırma:** Dışarı giden toplam veri hacmi ölçülür; gece saatlerindeki yüklemelere daha fazla ağırlık verilir.
  - **Yeni cihaz:** DHCP kayıtları `assets.yaml` envanteriyle karşılaştırılır. Rastgele (gizlilik) MAC adresi kullanan cihazlar daha düşük önemle raporlanır.
* **Makine öğrenmesi:** Her cihaz ve her saat için 7 özellikli bir vektör oluşturuldu: bağlantı sayısı, giden/gelen bayt, benzersiz hedef, benzersiz port, harici trafik oranı ve gece bayrağı. Isolation Forest bu vektörlerle etiketsiz veriden "normal" davranışı öğrenir ve sapmaları gerekçeleriyle raporlar.

## 6. Yapay zeka modülü

* **Model:** Ollama üzerinde yerel olarak `llama3.1:8b` çalıştırıldı (değiştirilebilir). Ev trafiği hassas veri olduğu için bulut API'si tercih edilmedi.
* **Görevler:**
  1. **Triyaj:** Her bulgu için 1-10 arası risk puanı, açıklama ve önerilen aksiyon üretilir. Model JSON çıktı verir.
  2. **Yönetici özeti:** Teknik olmayan okuyucu için kısa bir özet ve 3 öncelikli öneri yazılır.
  3. **Soru-cevap:** `homesiem ask "En şüpheli cihaz hangisi?"` gibi sorular cevaplanır.
* **Güvenlik:** DNS adı ya da DHCP host adı gibi log alanları saldırgan tarafından kontrol edilebilir.
  Bu alanlar modele yalnızca JSON veri olarak verilir ve sistem talimatı modele bu alanlardaki
  talimatları yok saymasını söyler (prompt injection önlemi). Model çıktısı hiçbir zaman komut
  olarak çalıştırılmaz.
* **Dayanıklılık:** Ollama erişilemezse sistem kural tabanlı triyaja geçer ve rapor yine üretilir.
* **Not:** Security Onion'ın ticari Pro sürümünde de bir yapay zeka asistanı bulunuyor. Bu proje,
  benzer bir yeteneği ücretsiz ve tamamen yerel olarak sunan açık kaynak bir alternatif niteliğindedir.

## 7. Test ve doğrulama

### 7.1 Otomatik testler (CI)

| Test | Sonuç |
|---|---|
| Suricata 7 sözdizimi kontrolü | 18/18 kural yüklendi ✔ |
| Scapy ile üretilen PCAP'in Suricata'da tekrar oynatılması | **18/18 kural tetiklendi** ✔ |
| `sigma check` | 8 kural, 0 hata ✔ |
| Sigma → Elasticsearch/Lucene dönüşümü | Başarılı ✔ |
| Python birim/uçtan uca testleri (pytest) | 9/9 başarılı ✔ |

### 7.2 Sentetik veri seti sonuçları

`homesiem demo` komutu, 6 cihazlı bir ev ağının 3 günlük trafiğini üretir (yaklaşık 13.000 bağlantı
ve 11.000 DNS sorgusu) ve bu trafiğin içine 5 saldırı senaryosu yerleştirir:

| Senaryo | Tespit edildi mi? | Tespit eden | Önem |
|---|---|---|---|
| Kameranın her ~300 sn'de C2 sunucusuna bağlanması | ✔ (CV = 0.011) | analytics:beaconing | high |
| Laptoptan DNS tünelleme (420 TXT sorgusu) | ✔ | analytics:dns + Suricata 9100005 | high |
| "kali" cihazının ağa katılıp NAS'ı taraması | ✔ | new_devices + port_scan + Suricata 9100001/9100009 | high |
| NAS'tan gece saat 03:00'te 2,4 GB yükleme | ✔ | analytics:exfil | high |
| DoH, AnyDesk, internetten Telnet denemesi | ✔ | Suricata | low–high |

Normal cihazlarda beaconing için yanlış pozitif oluşmadı (test edildi). Isolation Forest ise
saldırgan cihaz da dahil olmak üzere birkaç düşük/orta önemli anomali raporladı. Akıllı TV'nin
akşam saatlerindeki yoğun trafiği gibi bulgular, ince ayar gerektiren tipik yanlış pozitiflerdir.

Örnek rapor: [sample-report.tr.md](sample-report.tr.md)

### 7.3 Canlı ortam testleri

`scripts/simulation/run_safe_tests.sh` ile kendi ağımda yaptığım testlerin sonuçları:

| Test | Suricata | Sigma | Analitik | AI risk | Not |
|---|---|---|---|---|---|
| portscan | ▢ | – | ▢ | ▢ | |
| ssh_bruteforce | ▢ | – | – | ▢ | |
| doh | ▢ | – | – | ▢ | |
| dns_tunnel | ▢ | ▢ | ▢ | ▢ | |
| dyndns | ▢ | ▢ | – | ▢ | |
| remote_tool | ▢ | – | – | ▢ | |

## 8. Gerçek ağdan gözlemler

▢ Bir haftalık gerçek trafik üzerinde aşağıdaki gözlemleri doldurun:

* Toplam bağlantı / DNS sorgusu / alarm sayısı: ▢
* En çok trafik üreten cihaz: ▢
* Yanlış pozitifler ve yapılan ince ayarlar (ör. akıllı TV telemetrisi, bulut yedekleme): ▢
* Yapay zeka değerlendirmesinin isabeti (ör. 20 bulgunun kaçında öneri doğruydu): ▢

## 9. Kısıtlar

* Kablosuz istemciler arasındaki trafik switch'e uğramadığı için görülmeyebilir.
* TLS şifreli olduğundan içerik görünmez. Analiz meta verilerle (SNI, JA3, hacim, zamanlama) yapılır.
* 7-8B parametreli yerel modeller büyük bulut modellerine göre daha zayıf akıl yürütür ve
  GPU olmadan yavaş çalışır.
* Sentetik veri gerçek ağ çeşitliliğini tam olarak yansıtmaz. Eşik değerleri gerçek veriyle ayarlanmalıdır.

## 10. Gelecek çalışmalar

* GeoIP ve tehdit istihbaratı (abuse.ch, OTX) ile zenginleştirme
* Yüksek riskli bulgular için Telegram ve e-posta bildirimi
* Doğrulanmış bulgulardan LLM yardımıyla otomatik Sigma kuralı önerisi
* Rapor geçmişi için dashboard

## 11. Etik

Yalnızca proje sahibine ait ev ağı izlendi ve hanede yaşayanlar bilgilendirildi. Repoya gerçek log
konulmadı. Paylaşılan tüm örnekler sentetiktir ya da `sanitize_logs.py` ile anonimleştirilmiştir.
Testlerde yalnızca belgeleme amaçlı IP aralıkları (RFC 5737) ve `.example` alan adları kullanıldı.

## Kaynakça

1. Security Onion Documentation — https://docs.securityonion.net
2. Suricata User Guide — https://docs.suricata.io
3. Zeek Documentation — https://docs.zeek.org
4. Sigma Specification — https://github.com/SigmaHQ/sigma-specification
5. MITRE ATT&CK — https://attack.mitre.org
6. Ollama — https://ollama.com
7. Liu, Ting & Zhou, "Isolation Forest", IEEE ICDM 2008
