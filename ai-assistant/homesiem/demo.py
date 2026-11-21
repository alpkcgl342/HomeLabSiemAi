"""Synthetic home-network dataset for demos, tests and CI.

Generates Zeek JSON logs (conn/dns/dhcp) and a Suricata eve.json that look like
three days of a typical home network, with five attack scenarios injected:

1. IP camera beaconing to a C2 server every ~5 min        -> analytics:beaconing
2. Laptop exfiltrating data via DNS tunneling (TXT)        -> analytics:dns + Suricata
3. Unknown "kali" device joins and port-scans the NAS     -> new_devices + port_scan + Suricata
4. NAS uploads 2+ GB to an unknown server at 03:00         -> analytics:exfil
5. Misc Suricata hits (DoH bypass, AnyDesk, inbound telnet)

Only documentation IP ranges (RFC 5737) and the reserved ``.example`` TLD are used.
"""
from __future__ import annotations

import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

DEVICES = {
    "192.168.1.10": ("a4:83:e7:10:00:10", "ayse-laptop"),
    "192.168.1.11": ("f0:99:b6:11:00:11", "mehmet-phone"),
    "192.168.1.20": ("70:2a:d5:20:00:20", "living-room-tv"),
    "192.168.1.30": ("9c:8e:cd:30:00:30", "garden-camera"),
    "192.168.1.40": ("00:11:32:40:00:40", "home-nas"),
}
ROUTER = "192.168.1.1"
ATTACKER = ("192.168.1.66", "3c:22:fb:66:00:66", "kali")
C2 = "203.0.113.66"
EXFIL_DST = "198.51.100.200"
NORMAL_DOMAINS = ["google.com", "youtube.com", "whatsapp.net", "instagram.com", "github.com",
                  "wikipedia.org", "trendyol.com", "hepsiburada.com", "ntp.org", "spotify.com",
                  "netflix.com", "microsoft.com", "apple.com", "cloudflare.com", "x.com"]
NORMAL_DSTS = [f"198.51.100.{i}" for i in range(1, 60)]


def _uid(rng: random.Random) -> str:
    return "C" + "".join(rng.choices(string.ascii_letters + string.digits, k=17))


def _conn(rng, ts, src, dst, dport, proto="tcp", service=None, ob=0, rb=0, state="SF", dur=1.0):
    return {"ts": ts.timestamp(), "uid": _uid(rng), "id.orig_h": src, "id.orig_p": rng.randint(32768, 60999),
            "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "service": service,
            "duration": dur, "orig_bytes": ob, "resp_bytes": rb, "conn_state": state}


def _dns(rng, ts, src, query, qtype="A"):
    return {"ts": ts.timestamp(), "uid": _uid(rng), "id.orig_h": src, "id.orig_p": rng.randint(32768, 60999),
            "id.resp_h": ROUTER, "id.resp_p": 53, "proto": "udp", "query": query,
            "qtype_name": qtype, "rcode_name": "NOERROR"}


def _alert(ts, src, dst, dport, sid, msg, sev, cat, mitre, proto="TCP"):
    return {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000", "event_type": "alert",
            "src_ip": src, "src_port": 50000, "dest_ip": dst, "dest_port": dport, "proto": proto,
            "alert": {"action": "allowed", "signature_id": sid, "rev": 1, "signature": msg,
                      "category": cat, "severity": sev,
                      "metadata": {"mitre_technique_id": [mitre]}}}


def generate(out_dir: str | Path, days: int = 3, seed: int = 7, tz: str = "UTC") -> Path:
    rng = random.Random(seed)
    out = Path(out_dir)
    (out / "zeek").mkdir(parents=True, exist_ok=True)
    (out / "suricata").mkdir(parents=True, exist_ok=True)
    start = (datetime.now(timezone.utc) - timedelta(days=days)).replace(minute=0, second=0, microsecond=0)
    conns, dns, dhcp, alerts = [], [], [], []

    # ---------------------------------------------------------------- normal traffic
    for ip, (mac, name) in DEVICES.items():
        dhcp.append({"ts": start.timestamp() + rng.randint(0, 600), "mac": mac, "assigned_addr": ip,
                     "host_name": name, "msg_types": ["DISCOVER", "OFFER", "REQUEST", "ACK"]})
    for hour in range(days * 24):
        base = start + timedelta(hours=hour)
        active = 7 <= base.hour <= 23
        for ip in DEVICES:
            n = rng.randint(25, 70) if active else rng.randint(2, 8)
            if ip == "192.168.1.20" and not (18 <= base.hour <= 23):
                n = rng.randint(1, 3)
            for _ in range(n):
                ts = base + timedelta(seconds=rng.uniform(0, 3600))
                dom = rng.choice(NORMAL_DOMAINS)
                dns.append(_dns(rng, ts, ip, rng.choice(["", "www.", "api.", "cdn."]) + dom))
                ob = int(rng.lognormvariate(8, 1.2))
                rb = int(ob * rng.uniform(2, 40))
                conns.append(_conn(rng, ts + timedelta(milliseconds=30), ip, rng.choice(NORMAL_DSTS),
                                   rng.choice([443, 443, 443, 80, 853]), service="ssl", ob=ob, rb=rb,
                                   dur=rng.uniform(0.1, 30)))
            # local traffic (DNS to router, NAS shares)
            conns.append(_conn(rng, base + timedelta(seconds=rng.uniform(0, 3600)), ip, ROUTER, 53,
                               proto="udp", service="dns", ob=60, rb=120, dur=0.01))

    # ---------------------------------------------------------------- 1) camera beaconing
    t = start + timedelta(hours=2)
    while t < start + timedelta(days=days):
        conns.append(_conn(rng, t, "192.168.1.30", C2, 8443, service="ssl", ob=rng.randint(310, 330),
                           rb=rng.randint(180, 200), dur=0.4))
        t += timedelta(seconds=300 + rng.uniform(-6, 6))

    # ---------------------------------------------------------------- 2) DNS tunneling from laptop
    t = start + timedelta(days=1, hours=14)
    for i in range(420):
        chunk = "".join(rng.choices("0123456789abcdef", k=48))
        q = f"{chunk[:30]}.{chunk[30:]}.{i}.t.cdn-sync.example"
        dns.append(_dns(rng, t, "192.168.1.10", q, qtype="TXT"))
        if i % 60 == 0:
            alerts.append(_alert(t, "192.168.1.10", ROUTER, 53, 9100005,
                                 "HOMENET Unusually long DNS query (possible tunneling)", 2,
                                 "Potentially Bad Traffic", "T1071.004", proto="UDP"))
        t += timedelta(seconds=rng.uniform(1, 4))

    # ---------------------------------------------------------------- 3) rogue device + scan
    ip, mac, name = ATTACKER
    t = start + timedelta(days=2, hours=21, minutes=13)
    dhcp.append({"ts": t.timestamp(), "mac": mac, "assigned_addr": ip, "host_name": name,
                 "msg_types": ["DISCOVER", "OFFER", "REQUEST", "ACK"]})
    t += timedelta(minutes=2)
    for port in list(range(1, 1025)) + [1433, 3306, 3389, 5432, 5900, 8080, 8443]:
        conns.append(_conn(rng, t, ip, "192.168.1.40", port, ob=0, rb=0,
                           state=rng.choice(["REJ", "REJ", "S0"]), dur=0.0))
        t += timedelta(milliseconds=rng.randint(20, 120))
    alerts.append(_alert(t, ip, "192.168.1.40", 445, 9100001,
                         "HOMENET Possible internal TCP SYN port scan", 2, "Attempted Information Leak", "T1046"))
    alerts.append(_alert(t + timedelta(seconds=40), ip, "192.168.1.40", 22, 9100009,
                         "HOMENET Possible SSH brute force", 1, "Attempted Administrator Privilege Gain", "T1110"))

    # ---------------------------------------------------------------- 4) night-time exfil from NAS
    local = (start + timedelta(days=1)).astimezone(ZoneInfo(tz))
    t = local.replace(hour=3, minute=0).astimezone(timezone.utc)  # 03:00 local time
    for _ in range(45):
        conns.append(_conn(rng, t, "192.168.1.40", EXFIL_DST, 443, service="ssl",
                           ob=rng.randint(48_000_000, 60_000_000), rb=rng.randint(200_000, 400_000), dur=55))
        t += timedelta(seconds=60)

    # ---------------------------------------------------------------- 5) misc Suricata hits
    for d in range(days):
        ts = start + timedelta(days=d, hours=20)
        alerts.append(_alert(ts, "192.168.1.11", "198.51.100.77", 443, 9100004,
                             "HOMENET DNS-over-HTTPS provider contacted (possible DNS bypass)", 3,
                             "Potential Corporate Privacy Violation", "T1071.004"))
    alerts.append(_alert(start + timedelta(days=1, hours=11), "192.168.1.10", "198.51.100.90", 443, 9100013,
                         "HOMENET Remote access tool (AnyDesk) connection", 2,
                         "Potential Corporate Privacy Violation", "T1219"))
    alerts.append(_alert(start + timedelta(hours=5), "203.0.113.9", "192.168.1.30", 23, 9100007,
                         "HOMENET Inbound Telnet attempt to home device", 1,
                         "Attempted Administrator Privilege Gain", "T1190"))

    def dump(path: Path, rows: list[dict], key: str):
        rows.sort(key=lambda r: r[key] if isinstance(r[key], float) else r[key])
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    dump(out / "zeek" / "conn.log", conns, "ts")
    dump(out / "zeek" / "dns.log", dns, "ts")
    dump(out / "zeek" / "dhcp.log", dhcp, "ts")
    dump(out / "suricata" / "eve.json", alerts, "timestamp")
    return out
