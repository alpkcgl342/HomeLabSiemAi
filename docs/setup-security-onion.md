# Setting up Security Onion at home

> Security Onion is a full Linux distribution, not a Docker Compose app. It runs its own
> containers internally. So the plan is: **Security Onion in a VM** on your PC, and the
> **AI assistant + Ollama in Docker** next to it.

## 1. Hardware

Minimum specs from the official documentation (check the current values before buying anything):

| Install type | CPU | RAM | Disk | NICs | When to use |
|---|---|---|---|---|---|
| IMPORT | 2 | 4 GB | 50 GB+ | 1 | Analyse PCAP files only (no live traffic) - good first step |
| **EVAL** | 4 | 8 GB | 200 GB | 2 | **Home lab with live traffic** (recommended here) |
| STANDALONE | 4 | 24 GB | 200 GB | 2 | Long-running home "production" |

So the host PC needs roughly 16 GB RAM (8 GB for the VM + Ollama + OS) and ~250 GB free disk.
A GPU is optional; without one, a 7-8B model on the CPU takes about 10-60 s per answer.

## 2. Getting the traffic to the sensor

The sensor only sees what reaches its sniffing NIC. Options, from best to simplest:

1. **Managed switch with port mirroring** (e.g. cheap "easy smart" 5/8-port switches).
   Put it between the router and the rest of the LAN, mirror the router uplink port to
   the port where the PC's **second NIC** (a USB-Ethernet adapter works) is plugged in.
2. **OpenWrt router**: mirror with `tcpdump`/`iptables TEE` or send PCAPs to Security Onion periodically.
3. **No special hardware**: capture with Wireshark/tcpdump on a device, then use the
   IMPORT install or `so-import-pcap` to analyse PCAP files.

Wi-Fi traffic between two wireless clients usually never touches the switch; mirroring
the router uplink still covers all internet-bound traffic, which is what matters most.

## 3. VM creation (VirtualBox / VMware / Proxmox)

1. Download the Security Onion ISO from the official site and **verify its signature**.
2. Create a VM: 4 vCPU, 8-12 GB RAM, 200 GB disk, **2 network adapters**:
   * Adapter 1 (management): bridged to your normal LAN NIC, static IP e.g. `192.168.1.250`.
   * Adapter 2 (sniffing): bridged to the mirror-port NIC, **Promiscuous mode: Allow All**.
3. Boot the ISO, install, reboot, and run setup → choose **EVAL**.
4. When asked which IPs may access the web interface, enter your PC's IP (or `192.168.1.0/24`).
5. Open `https://192.168.1.250` and log in.

## 4. Configure network variables

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

```bash
SO_HOST=192.168.1.250 SO_USER=<your-so-user> DAYS=7 scripts/fetch_so_logs.sh
cp config/config.example.yaml config/config.yaml
# edit: zeek_dir: ../so-logs/zeek   suricata_eve: ../so-logs/eve.merged.json
```

### Option B - query Elasticsearch directly

1. In SOC → *Administration → Configuration → firewall*, add your PC's IP to the host group
   that allows the Elasticsearch REST port (9200).
2. Create a dedicated, read-only user for the assistant.
3. In `config/config.yaml` set `source.type: elasticsearch`, the URL, and export the
   credentials as `HOMESIEM_ES_USER` / `HOMESIEM_ES_PASSWORD` (do not commit them).
4. Check field/dataset names in *Hunt* (e.g. `event.dataset:conn`) and adjust `queries:` if
   your version differs.

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
