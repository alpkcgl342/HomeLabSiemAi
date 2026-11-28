# Setting up Security Onion at home

> Security Onion is a full Linux distribution, not a Docker Compose app. It runs its own
> containers internally. So the plan is: **Security Onion in a VM** on your PC, and the
> **AI assistant + Ollama in Docker** next to it.

> **Version:** this guide uses **Security Onion 3.4.0** (released 2026-11-02).
> Security Onion 2.4 reached end of life on 2026-10-01 - do not install 2.4 anymore.

## 1. Hardware

Minimum specs from the [official hardware page](https://docs.securityonion.net/en/3/main/hardware):

| Install type | CPU | RAM | Disk | NICs | When to use |
|---|---|---|---|---|---|
| IMPORT | 2 | 4 GB | 100 GB | 1 | Analyse PCAP/EVTX files only (no live traffic) |
| **EVAL** | 4 | 8 GB | 200 GB | 2 | **Home lab with live traffic** (used in this project) |
| STANDALONE | 4 | 24 GB | 200 GB | 2 | Long-running "production" (32 GB+ recommended) |

Reference lab used for this project: Windows 11 host, 32 GB RAM, 12 threads, wired Ethernet,
VirtualBox + Docker Desktop side by side. The VM gets **12 GB RAM / 4 vCPU / 200 GB dynamic disk**,
which leaves room for Ollama (~6 GB with `llama3.1:8b`).

> **Docker Desktop + VirtualBox:** Docker Desktop enables Hyper-V/WSL2, so VirtualBox runs on
> top of Hyper-V (green turtle icon in the VM status bar). It works, but is slower - expect
> kernel messages such as `sched: DL replenish lagged too much`; they are harmless.

## 2. Getting the traffic to the sensor

The sensor only sees what reaches its sniffing NIC. Options, from best to simplest:

1. **Managed switch with port mirroring** (e.g. cheap "easy smart" 5/8-port switches).
   Put it between the router and the rest of the LAN, mirror the router uplink port to
   the port where the PC's **second NIC** (a USB-Ethernet adapter works) is plugged in.
2. **Bridged promiscuous NIC on a wired host (no extra hardware - our starting point):**
   the VM sees the host PC's own traffic plus LAN broadcast/multicast (DHCP, ARP, mDNS, SSDP),
   which is enough to detect new devices and test every rule from the host.
   This does **not** work on Wi-Fi - Wi-Fi drivers do not pass promiscuous traffic to VMs.
3. **PCAP import:** capture with Wireshark/tcpdump anywhere, then `sudo so-import-pcap file.pcap`.

## 3. Install in VirtualBox (step by step)

### 3.1 Download and verify the ISO

Follow [DOWNLOAD_AND_VERIFY_ISO.md](https://github.com/Security-Onion-Solutions/securityonion/blob/3/main/DOWNLOAD_AND_VERIFY_ISO.md)
(the ISO is ~12 GB). On Windows the quickest check is the SHA256 hash:

```powershell
Get-FileHash $HOME\Downloads\securityonion-3.4.0-20261102.iso -Algorithm SHA256
# must equal: DFC4C87668836852A328EC7A0B755C8C1511FF0E43D423DEE23047A95F676D99
```

You do **not** need balenaEtcher - that is only for installing on physical hardware from USB.
Antivirus may flag files under `SecurityOnion\agrules\`; these are detection rules, not malware.

### 3.2 Create the VM

| Setting | Value |
|---|---|
| ISO image | `securityonion-3.4.0-20261102.iso` (ISO image field, **not** the VM folder field) |
| Type / version | Linux / Oracle Linux 9.x (64-bit) |
| Unattended installation | **Off** (VirtualBox ticks it automatically after you pick the ISO - untick it) |
| RAM / CPU | 12288 MB / 4 (minimum 8192 MB) |
| Disk | 200 GB VDI, **not** pre-allocated |
| Adapter 1 (management) | Bridged Adapter → your wired NIC, promiscuous: Deny |
| Adapter 2 (sniffing) | Bridged Adapter → same NIC, **Advanced → Promiscuous Mode: Allow All** |

Inside the VM, Adapter 1 becomes **enp0s3** and Adapter 2 becomes **enp0s8** - compare the MAC
addresses shown by VirtualBox with the ones in the setup wizard to be sure.

### 3.3 OS installation

1. Boot → **Install Security Onion 3.4.0** (first entry).
2. Type `yes` at the "ALL DATA WILL BE LOST" warning (this only wipes the virtual disk).
3. Create the Linux admin user. **Use only lowercase letters and digits for the user name and
   only letters and digits for the password** - see the keyboard warning below.
4. When it finishes, **eject the ISO** (*Devices → Optical Drives → Remove disk*) before rebooting.
   If the ISO stays attached, the boot menu times out into the installer again and asks for `yes`
   - **never type `yes` on a system you already installed**; eject the ISO and reset instead.

> **Keyboard layout pitfall (non-US keyboards, e.g. Turkish):** the ISO installer and rescue
> environment use a **US** layout, while the installed console may use your local layout. A user
> name or password containing symbols (`_`, `@`, `.`, Turkish letters) can therefore be stored
> differently from what you type later. In our lab a user name ending in `_` was typed as `__`
> at the login prompt, which looked like a wrong password. `ls /mnt/sysroot/home` (3.5) shows the real name.

### 3.4 Setup wizard choices (EVAL)

Log in on the console; the wizard starts automatically. Navigation: arrows, **Space** to tick,
**Tab** to buttons, **Enter** to confirm.

| Screen | Choice |
|---|---|
| Welcome / option | Yes → **Install** |
| Installation type | **EVAL** |
| License | type `AGREE` to accept the Elastic License 2.0 (read it first) |
| Install mode | **Standard** (internet access) |
| Hostname | e.g. `homelab-so` (letters, digits, hyphen - no underscore) |
| Management NIC | **enp0s3** |
| IP address | static, e.g. `192.168.1.250/24` (ping it first - it must be unused) |
| Gateway | your router, e.g. `192.168.1.1` |
| DNS | your router (`192.168.1.1`) - avoids rule 9100003 firing on the sensor's own lookups |
| Internet connection | **Direct** |
| Docker IP range | keep default |
| Monitor interface | tick **enp0s8** with **Space** |
| Web admin e-mail / password | any address (no mail is sent); letters + digits for the password |
| Web access | **IP** |
| Allowed IP or subnet | your analyst PC only, e.g. `192.168.1.100` (reserve it in the router's DHCP) |
| Telemetry | your choice (this project disables it to keep all data local) |

The final install takes 20-45 minutes. Afterwards open `https://192.168.1.250` from the allowed PC.

### 3.5 Forgot the Linux password? (ISO rescue)

1. *Devices → Optical Drives* → attach the ISO, *Machine → Reset*.
2. **Troubleshooting → Rescue** → `1` (Continue) → Enter for a shell.
3. `ls /mnt/sysroot/home` shows the real user name.
4. `chroot /mnt/sysroot` → `passwd <user>` → `touch /.autorelabel` → `exit` → `exit`.
5. **Eject the ISO** before the VM boots again (see the warning above). The first boot runs an
   SELinux relabel and can take 10-20 minutes.

## 4. Configure network variables

> Menu names below were written for 2.4 and may be worded slightly differently in 3.x.

In SOC → *Administration → Configuration* (Suricata variables):

* `HOME_NET` = `[192.168.1.0/24]` (your LAN)
* `DNS_SERVERS` = `[192.168.1.1]` (router or Pi-hole) - rule 9100003 depends on it.

## 5. Load this repo's rules

**Suricata (NIDS):** SOC → *Detections* → blue **+** button → engine *Suricata* → paste each
rule from [`rules/suricata/homenet.rules`](../rules/suricata/homenet.rules) → enable.

**Sigma:** SOC → *Detections* → **+** → engine *ElastAlert/Sigma* → paste each YAML from
[`rules/sigma/zeek/`](../rules/sigma/zeek/) → enable. Security Onion converts them automatically.

Then generate test traffic (see [testing-detections.md](testing-detections.md)) and watch *Alerts*.

> Recent 2.4.x releases pause automatic Suricata rule syncing when a *custom ruleset*
> is configured ("Sync Block"). Adding rules one by one through Detections avoids this;
> read the release notes of your version if you choose a ruleset URL instead.

## 6. Connect the AI assistant

### Option A - copy logs (simplest, works everywhere)

Security Onion 3 EVAL uses **Suricata as its metadata engine** (no Zeek): connections, DNS and DHCP
are `flow`/`dns`/`dhcp` events inside `/nsm/suricata/eve-*.json`, next to the alerts. The assistant
reads them directly (`metadata: auto` picks Suricata when no Zeek logs are present).

Windows (PowerShell, uses the built-in OpenSSH client):

```powershell
.\scripts\fetch_so_logs.ps1 -SoUser <linux-user> -Hours 24
```

Linux/macOS: `SO_HOST=192.168.1.250 SO_USER=<linux-user> DAYS=1 scripts/fetch_so_logs.sh`

Then in `config/config.yaml`:

```yaml
source:
  type: files
  files:
    suricata_eve: ../so-logs/suricata/eve*.json
    metadata: auto
```

> Sigma alerts (ElastAlert) are stored only in Elasticsearch (`logs-detections.alerts-so`), so
> they are not in the copied files. Use option B to include them.

### Option B - query Elasticsearch directly

1. In SOC → *Administration → Configuration → firewall*, add your PC's IP to the host group
   that allows the Elasticsearch REST port (9200).
2. Create a dedicated, read-only user for the assistant.
3. In `config/config.yaml` set `source.type: elasticsearch`, the URL, and export the
   credentials as `HOMESIEM_ES_USER` / `HOMESIEM_ES_PASSWORD` (do not commit them).
4. The default `queries:` match Security Onion 3.4 EVAL (`suricata.conn`, `suricata.dns`,
   `suricata.dhcp`, `suricata.alert`, `sigma.alert`); with Zeek, check the names in *Hunt*.
   Port 9200 is not open to analysts by default - add a custom port group (TCP 9200) and host group
   (your PC) under *Administration → Configuration → firewall*.

### Run

```bash
cp config/config.example.yaml config/config.yaml   # edit source / home_net / language
docker compose up -d ollama panel                  # panel: http://localhost:8080
```

Open the panel and press **Run analysis** (it reads `config/config.yaml` via `HOMESIEM_CONFIG`).
The CLI does the same from a terminal:

```bash
docker compose exec ollama ollama pull llama3.1:8b
docker compose run --rm assistant -c /work/config/config.yaml analyze
docker compose run --rm assistant -c /work/config/config.yaml ask "Which device should I worry about?"
```

To get a weekly report automatically, add a cron job / Windows Task Scheduler entry that runs
`fetch_so_logs.sh` followed by the `analyze` command every Monday morning.
