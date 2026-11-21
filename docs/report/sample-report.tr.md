> `homesiem demo` komutunun sentetik veri üzerindeki örnek çıktısıdır (kural tabanlı triyaj, Ollama kapalı). Ollama çalışırken özet ve analiz alanlarını LLM yazar.

# Ev Ağı Güvenlik Raporu

| | |
|---|---|
| **Dönem** | 2026-11-18 12:00 → 2026-11-21 11:59 |
| **Oluşturulma** | 2026-11-21 12:34 UTC |
| **Yapay zeka modeli** | rule-based fallback (Ollama offline) |

## Yönetici özeti

5 cihazda toplam **15 bulgu**. En yüksek risk: Periodic beaconing from 192.168.1.30 to 203.0.113.66:8443 every ~300s.
- Cihazı ve hedefi belirleyin (whois/VirusTotal); tanımıyorsanız modemde engelleyin.
- Sorguları yapan süreci bulun; ana alan adını Pi-hole/modem DNS'inde engelleyin.
- Taramayı siz yaptıysanız yok sayın; aksi halde cihazı ağdan ayırıp zararlı taraması yapın.

_Yapay zeka özeti kullanılamadı (Ollama kapalı) - kural tabanlı özet gösteriliyor._

## Genel bakış

| Metrik | Değer |
|---|---:|
| Bağlantı | 12,989 |
| DNS sorgusu | 11,132 |
| DHCP kiralaması | 6 |
| Suricata alarmı (tekilleştirilmiş) | 6 |
| Toplam bulgu | 15 |
| Görülen iç cihaz | 6 |

### Önem derecesine göre bulgular

| critical | high | medium | low | info |
|---:|---:|---:|---:|---:|
| 0 | 6 | 8 | 1 | 0 |

## Bulgular

| # | Risk | Önem | Bulgu | Cihaz | Kaynak | MITRE |
|---:|:---:|---|---|---|---|---|
| 1 | **8**/10 | high | Port scan from 192.168.1.66: 1031 host:port pairs in 5 min | 192.168.1.66 | analytics:port_scan | [T1046](https://attack.mitre.org/techniques/T1046/) |
| 2 | **8**/10 | high | Periodic beaconing from 192.168.1.30 to 203.0.113.66:8443 every ~300s | 192.168.1.30 | analytics:beaconing | [T1071](https://attack.mitre.org/techniques/T1071/), [T1573](https://attack.mitre.org/techniques/T1573/) |
| 3 | **8**/10 | high | Possible DNS tunneling from 192.168.1.10 via *.cdn-sync.example | 192.168.1.10 | analytics:dns | [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048](https://attack.mitre.org/techniques/T1048/) |
| 4 | **7**/10 | high | Large upload: 2.40 GB from 192.168.1.40 to 198.51.100.200 (mostly at night) | 192.168.1.40 | analytics:exfil | [T1048](https://attack.mitre.org/techniques/T1048/), [T1567](https://attack.mitre.org/techniques/T1567/) |
| 5 | **7**/10 | high | HOMENET Inbound Telnet attempt to home device | 203.0.113.9 | suricata | [T1190](https://attack.mitre.org/techniques/T1190/) |
| 6 | **7**/10 | high | HOMENET Possible SSH brute force | 192.168.1.66 | suricata | [T1110](https://attack.mitre.org/techniques/T1110/) |
| 7 | **5**/10 | medium | HOMENET Unusually long DNS query (possible tunneling) | 192.168.1.10 | suricata | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| 8 | **5**/10 | medium | Unusual traffic profile for 192.168.1.20 (4 anomalous hour(s)) | 192.168.1.20 | analytics:anomaly | - |
| 9 | **5**/10 | medium | Unusual traffic profile for 192.168.1.30 (2 anomalous hour(s)) | 192.168.1.30 | analytics:anomaly | - |
| 10 | **5**/10 | medium | HOMENET Remote access tool (AnyDesk) connection | 192.168.1.10 | suricata | [T1219](https://attack.mitre.org/techniques/T1219/) |
| 11 | **5**/10 | medium | HOMENET Possible internal TCP SYN port scan | 192.168.1.66 | suricata | [T1046](https://attack.mitre.org/techniques/T1046/) |
| 12 | **5**/10 | medium | Unknown device joined the network: kali (3c:22:fb:66:00:66) | 192.168.1.66 | analytics:new_devices | [T1200](https://attack.mitre.org/techniques/T1200/) |
| 13 | **5**/10 | medium | Unusual traffic profile for 192.168.1.40 (1 anomalous hour(s)) | 192.168.1.40 | analytics:anomaly | - |
| 14 | **5**/10 | medium | Unusual traffic profile for 192.168.1.66 (1 anomalous hour(s)) | 192.168.1.66 | analytics:anomaly | - |
| 15 | **3**/10 | low | HOMENET DNS-over-HTTPS provider contacted (possible DNS bypass) | 192.168.1.11 | suricata | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |

## Detaylar

### 1. Port scan from 192.168.1.66: 1031 host:port pairs in 5 min

- **Risk:** 8/10 · **Önem:** high · **Adet:** 1031
- **Zaman:** 2026-11-21 09:15 → 2026-11-21 09:16
- **Yapay zeka analizi:** Bir cihaz kısa sürede çok sayıda port/host taradı.
- **Önerilen aksiyon:** Taramayı siz yaptıysanız yok sayın; aksi halde cihazı ağdan ayırıp zararlı taraması yapın.

<details><summary>Kanıt</summary>

```json
{
  "unique_targets": 1031,
  "target_hosts": [
    "192.168.1.40"
  ],
  "failed_or_rejected": 1031
}
```
</details>

### 2. Periodic beaconing from 192.168.1.30 to 203.0.113.66:8443 every ~300s

- **Risk:** 8/10 · **Önem:** high · **Adet:** 841
- **Zaman:** 2026-11-18 14:00 → 2026-11-21 11:58
- **Yapay zeka analizi:** Tek bir dış sunucuya düzenli, makine benzeri bağlantılar - zararlı yazılım iletişimine benzer, ancak güncelleme/telemetri ajanları da böyle davranabilir.
- **Önerilen aksiyon:** Cihazı ve hedefi belirleyin (whois/VirusTotal); tanımıyorsanız modemde engelleyin.

<details><summary>Kanıt</summary>

```json
{
  "dest_ip": "203.0.113.66",
  "dest_port": 8443,
  "mean_interval_s": 299.9,
  "coefficient_of_variation": 0.011,
  "avg_bytes_out": 320
}
```
</details>

### 3. Possible DNS tunneling from 192.168.1.10 via *.cdn-sync.example

- **Risk:** 8/10 · **Önem:** high · **Adet:** 420
- **Zaman:** 2026-11-20 02:00 → 2026-11-20 02:17
- **Yapay zeka analizi:** Tek bir alan adı altında çok sayıda rastgele görünen alt alan adı - DNS tünelleme veya DGA zararlısının tipik belirtisi.
- **Önerilen aksiyon:** Sorguları yapan süreci bulun; ana alan adını Pi-hole/modem DNS'inde engelleyin.

<details><summary>Kanıt</summary>

```json
{
  "parent_domain": "cdn-sync.example",
  "unique_subdomains": 420,
  "high_entropy_ratio": 0.64,
  "avg_entropy": 3.87,
  "txt_queries": 420,
  "example": "0151052a8626b2c33d82710ae90ec9.c9ada3fc1adb00f23d.147.t.cdn-sync.example"
}
```
</details>

### 4. Large upload: 2.40 GB from 192.168.1.40 to 198.51.100.200 (mostly at night)

- **Risk:** 7/10 · **Önem:** high · **Adet:** 45
- **Zaman:** 2026-11-19 03:00 → 2026-11-19 03:44
- **Yapay zeka analizi:** Bir cihaz internete alışılmadık miktarda veri yükledi.
- **Önerilen aksiyon:** Bilinen bir yedekleme/senkronizasyon mu kontrol edin; değilse cihazı ağdan ayırın.

<details><summary>Kanıt</summary>

```json
{
  "dest_ip": "198.51.100.200",
  "bytes_out": 2403231965,
  "night_bytes_out": 2403231965,
  "upload_download_ratio": 180.6,
  "dest_ports": [
    443
  ]
}
```
</details>

### 5. HOMENET Inbound Telnet attempt to home device

- **Risk:** 7/10 · **Önem:** high · **Adet:** 1
- **Zaman:** 2026-11-18 17:00 → 2026-11-18 17:00
- **Yapay zeka analizi:** Bir Suricata imzası ağ trafiğiyle eşleşti.
- **Önerilen aksiyon:** Alarmı Security Onion (Alerts/Hunt) içinde açın, PCAP'i inceleyin; kuralı ayarlayın veya yükseltin.

<details><summary>Kanıt</summary>

```json
{
  "sid": 9100007,
  "category": "Attempted Administrator Privilege Gain",
  "src_ip": "203.0.113.9",
  "dest_ip": "192.168.1.30",
  "dest_port": 23
}
```
</details>

### 6. HOMENET Possible SSH brute force

- **Risk:** 7/10 · **Önem:** high · **Adet:** 1
- **Zaman:** 2026-11-21 09:16 → 2026-11-21 09:16
- **Yapay zeka analizi:** Bir Suricata imzası ağ trafiğiyle eşleşti.
- **Önerilen aksiyon:** Alarmı Security Onion (Alerts/Hunt) içinde açın, PCAP'i inceleyin; kuralı ayarlayın veya yükseltin.

<details><summary>Kanıt</summary>

```json
{
  "sid": 9100009,
  "category": "Attempted Administrator Privilege Gain",
  "src_ip": "192.168.1.66",
  "dest_ip": "192.168.1.40",
  "dest_port": 22
}
```
</details>

### 7. HOMENET Unusually long DNS query (possible tunneling)

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 7
- **Zaman:** 2026-11-20 02:00 → 2026-11-20 02:15
- **Yapay zeka analizi:** Bir Suricata imzası ağ trafiğiyle eşleşti.
- **Önerilen aksiyon:** Alarmı Security Onion (Alerts/Hunt) içinde açın, PCAP'i inceleyin; kuralı ayarlayın veya yükseltin.

<details><summary>Kanıt</summary>

```json
{
  "sid": 9100005,
  "category": "Potentially Bad Traffic",
  "src_ip": "192.168.1.10",
  "dest_ip": "192.168.1.1",
  "dest_port": 53,
  "dest_ips": [
    "192.168.1.1"
  ]
}
```
</details>

### 8. Unusual traffic profile for 192.168.1.20 (4 anomalous hour(s))

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 4
- **Zaman:** - → -
- **Yapay zeka analizi:** Bu cihazın trafiği ağın normal davranışından belirgin şekilde sapıyor.
- **Önerilen aksiyon:** Belirtilen saatlerdeki bağlantılarını Security Onion Hunt ekranında inceleyin.

<details><summary>Kanıt</summary>

```json
{
  "worst_hour": "2026-11-20 08:00",
  "anomaly_score": 0.616,
  "top_reasons": [],
  "anomalous_hours": [
    "2026-11-20 08:00",
    "2026-11-20 05:00",
    "2026-11-20 04:00",
    "2026-11-19 03:00"
  ]
}
```
</details>

### 9. Unusual traffic profile for 192.168.1.30 (2 anomalous hour(s))

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 2
- **Zaman:** - → -
- **Yapay zeka analizi:** Bu cihazın trafiği ağın normal davranışından belirgin şekilde sapıyor.
- **Önerilen aksiyon:** Belirtilen saatlerdeki bağlantılarını Security Onion Hunt ekranında inceleyin.

<details><summary>Kanıt</summary>

```json
{
  "worst_hour": "2026-11-20 20:00",
  "anomaly_score": 0.638,
  "top_reasons": [
    "bytes_in_mb=19.5 (network median 3.6)",
    "connections=82.0 (network median 36.0)",
    "unique_dsts=46.0 (network median 25.0)"
  ],
  "anomalous_hours": [
    "2026-11-20 20:00",
    "2026-11-19 03:00"
  ]
}
```
</details>

### 10. HOMENET Remote access tool (AnyDesk) connection

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 1
- **Zaman:** 2026-11-19 23:00 → 2026-11-19 23:00
- **Yapay zeka analizi:** Bir Suricata imzası ağ trafiğiyle eşleşti.
- **Önerilen aksiyon:** Alarmı Security Onion (Alerts/Hunt) içinde açın, PCAP'i inceleyin; kuralı ayarlayın veya yükseltin.

<details><summary>Kanıt</summary>

```json
{
  "sid": 9100013,
  "category": "Potential Corporate Privacy Violation",
  "src_ip": "192.168.1.10",
  "dest_ip": "198.51.100.90",
  "dest_port": 443
}
```
</details>

### 11. HOMENET Possible internal TCP SYN port scan

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 1
- **Zaman:** 2026-11-21 09:16 → 2026-11-21 09:16
- **Yapay zeka analizi:** Bir Suricata imzası ağ trafiğiyle eşleşti.
- **Önerilen aksiyon:** Alarmı Security Onion (Alerts/Hunt) içinde açın, PCAP'i inceleyin; kuralı ayarlayın veya yükseltin.

<details><summary>Kanıt</summary>

```json
{
  "sid": 9100001,
  "category": "Attempted Information Leak",
  "src_ip": "192.168.1.66",
  "dest_ip": "192.168.1.40",
  "dest_port": 445
}
```
</details>

### 12. Unknown device joined the network: kali (3c:22:fb:66:00:66)

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 1
- **Zaman:** 2026-11-21 09:13 → 2026-11-21 09:13
- **Yapay zeka analizi:** Envanterde olmayan bir cihaz ağa katıldı.
- **Önerilen aksiyon:** Cihazı tanımlayın; meşruysa assets.yaml'a ekleyin, değilse Wi-Fi şifresini değiştirin.

<details><summary>Kanıt</summary>

```json
{
  "mac": "3c:22:fb:66:00:66",
  "ip": "192.168.1.66",
  "hostname": "kali",
  "randomised_mac": false
}
```
</details>

### 13. Unusual traffic profile for 192.168.1.40 (1 anomalous hour(s))

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 1
- **Zaman:** - → -
- **Yapay zeka analizi:** Bu cihazın trafiği ağın normal davranışından belirgin şekilde sapıyor.
- **Önerilen aksiyon:** Belirtilen saatlerdeki bağlantılarını Security Onion Hunt ekranında inceleyin.

<details><summary>Kanıt</summary>

```json
{
  "worst_hour": "2026-11-19 03:00",
  "anomaly_score": 0.757,
  "top_reasons": [
    "bytes_out_mb=2403.3 (network median 0.2)",
    "bytes_in_mb=16.4 (network median 3.6)",
    "night=1.0 (network median 0.0)"
  ],
  "anomalous_hours": [
    "2026-11-19 03:00"
  ]
}
```
</details>

### 14. Unusual traffic profile for 192.168.1.66 (1 anomalous hour(s))

- **Risk:** 5/10 · **Önem:** medium · **Adet:** 1
- **Zaman:** - → -
- **Yapay zeka analizi:** Bu cihazın trafiği ağın normal davranışından belirgin şekilde sapıyor.
- **Önerilen aksiyon:** Belirtilen saatlerdeki bağlantılarını Security Onion Hunt ekranında inceleyin.

<details><summary>Kanıt</summary>

```json
{
  "worst_hour": "2026-11-21 09:00",
  "anomaly_score": 0.789,
  "top_reasons": [
    "unique_ports=1031.0 (network median 4.0)",
    "connections=1031.0 (network median 36.0)"
  ],
  "anomalous_hours": [
    "2026-11-21 09:00"
  ]
}
```
</details>

### 15. HOMENET DNS-over-HTTPS provider contacted (possible DNS bypass)

- **Risk:** 3/10 · **Önem:** low · **Adet:** 3
- **Zaman:** 2026-11-19 08:00 → 2026-11-21 08:00
- **Yapay zeka analizi:** Bir Suricata imzası ağ trafiğiyle eşleşti.
- **Önerilen aksiyon:** Alarmı Security Onion (Alerts/Hunt) içinde açın, PCAP'i inceleyin; kuralı ayarlayın veya yükseltin.

<details><summary>Kanıt</summary>

```json
{
  "sid": 9100004,
  "category": "Potential Corporate Privacy Violation",
  "src_ip": "192.168.1.11",
  "dest_ip": "198.51.100.77",
  "dest_port": 443,
  "dest_ips": [
    "198.51.100.77"
  ]
}
```
</details>


## En çok trafik üreten cihazlar

| Cihaz | Bağlantı | Giden | Gelen |
|---|---:|---:|---:|
| 192.168.1.40 | 2541 | 2.3 GB | 312.9 MB |
| 192.168.1.10 | 2668 | 15.6 MB | 296.0 MB |
| 192.168.1.30 | 3305 | 14.4 MB | 309.1 MB |
| 192.168.1.11 | 2488 | 13.3 MB | 275.9 MB |
| 192.168.1.20 | 956 | 5.1 MB | 104.7 MB |
| 192.168.1.66 | 1031 | 0 B | 0 B |

## En çok sorgulanan alan adları

| Alan adı | Sorgu |
|---|---:|
| ntp.org | 769 |
| cloudflare.com | 768 |
| youtube.com | 745 |
| instagram.com | 738 |
| github.com | 735 |
| apple.com | 720 |
| hepsiburada.com | 716 |
| wikipedia.org | 715 |
| google.com | 709 |
| netflix.com | 695 |

## MITRE ATT&CK kapsamı

| Teknik | Bulgular |
|---|---:|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | 3 |
| [T1046](https://attack.mitre.org/techniques/T1046/) | 2 |
| [T1048](https://attack.mitre.org/techniques/T1048/) | 2 |
| [T1071](https://attack.mitre.org/techniques/T1071/) | 1 |
| [T1573](https://attack.mitre.org/techniques/T1573/) | 1 |
| [T1567](https://attack.mitre.org/techniques/T1567/) | 1 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | 1 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | 1 |
| [T1219](https://attack.mitre.org/techniques/T1219/) | 1 |
| [T1200](https://attack.mitre.org/techniques/T1200/) | 1 |

---
_homenet-siem-ai tarafından oluşturuldu. Yapay zeka hatalı olabilir - bulguları her zaman Security Onion üzerinden doğrulayın._