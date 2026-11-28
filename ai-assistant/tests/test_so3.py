"""Security Onion 3.x data shapes (taken from a real SO 3.4 EVAL lab, values anonymised)."""
from __future__ import annotations

import json

from homesiem.sources import FileSource, to_alert, to_conn, to_dhcp, to_dns

SO_CONN = {
    "@timestamp": "2026-11-28T12:57:08.424Z",
    "source": {"ip": "192.168.1.110", "port": 42714},
    "destination": {"ip": "198.51.100.7", "port": 443},
    "network": {"transport": "tcp"},
    "client": {"ip_bytes": 321}, "server": {"ip_bytes": 4096},
    "connection": {"start": "2026-11-28T12:56:37.653657+0000", "end": "2026-11-28T12:56:47.653657+0000",
                   "state": "closed"},
    "event": {"dataset": "suricata.conn"},
}

SO_DNS_REQ = {"@timestamp": "2026-11-28T12:38:54.844Z", "source": {"ip": "192.168.1.100"},
              "dns": {"query": {"name": "homesiem-test.duckdns.org", "type_name": "A", "type": "request"}},
              "event": {"dataset": "suricata.dns"}}
SO_DNS_RESP = {**SO_DNS_REQ, "dns": {"query": {"name": "homesiem-test.duckdns.org", "type": "response"}}}

SO_SURICATA_ALERT = {
    "@timestamp": "2026-11-28T12:38:54.844Z",
    "source": {"ip": "192.168.1.100"}, "destination": {"ip": "8.8.4.4", "port": 53},
    "rule": {"name": "ET DYN_DNS DYNAMIC_DNS Query to a *.duckdns .org Domain", "uuid": "2042936",
             "category": "Potentially Bad Traffic", "metadata": {"mitre_technique_id": ["T1568"]}},
    "event": {"severity": 2, "severity_label": "medium", "module": "suricata", "dataset": "suricata.alert"},
}

SO_SIGMA_ALERT = {
    "@timestamp": "2026-11-28T12:39:54.000Z", "sigma_level": "medium",
    "rule": {"name": "HOMENET Dynamic DNS or Tunnelling Service Lookup",
             "uuid": "30abc651-4a12-4c78-9207-9ace8dfc2c91"},
    "event_data": {"source": {"ip": "8.8.8.8", "port": 53}, "destination": {"ip": "192.168.1.250", "port": 55341}},
    "event": {"severity": 3, "severity_label": "medium", "module": "sigma", "dataset": "sigma.alert"},
}

SO_DHCP = {
    "@timestamp": "2026-11-28T12:56:37.554Z",
    "message": json.dumps({"event_type": "dhcp", "dhcp": {"type": "request", "client_mac": "02:00:5e:10:20:30",
                                                         "assigned_ip": "0.0.0.0", "requested_ip": "192.168.1.110"}}),
    "host": {"mac": "02:00:5e:10:20:30"},
    "dhcp": {"assigned_ip": "0.0.0.0", "type": "request"},
    "event": {"dataset": "suricata.dhcp"},
}


def test_so3_conn_fields():
    c = to_conn(SO_CONN)
    assert c and c.orig_bytes == 321 and c.resp_bytes == 4096 and c.duration == 10.0 and c.conn_state == "closed"


def test_so3_dns_keeps_only_requests():
    assert to_dns(SO_DNS_REQ).query == "homesiem-test.duckdns.org"
    assert to_dns(SO_DNS_RESP) is None


def test_so3_suricata_alert():
    a = to_alert(SO_SURICATA_ALERT)
    assert a.severity == "medium" and a.source == "suricata" and a.mitre == ["T1568"] and a.host == "192.168.1.100"


def test_so3_sigma_alert_points_at_home_device():
    a = to_alert(SO_SIGMA_ALERT)
    assert a.source == "sigma" and a.severity == "medium"
    assert a.host == "192.168.1.250"  # answer packet: home device is the destination


def test_so3_dhcp_uses_embedded_message():
    lease = to_dhcp(SO_DHCP)
    assert lease.mac == "02:00:5e:10:20:30" and lease.ip == "192.168.1.110"


def test_filesource_reads_raw_eve_metadata(tmp_path):
    lines = [
        {"timestamp": "2026-11-28T12:56:37.653657+0000", "event_type": "flow", "src_ip": "192.168.1.110",
         "src_port": 42714, "dest_ip": "198.51.100.7", "dest_port": 443, "proto": "TCP",
         "flow": {"bytes_toserver": 500, "bytes_toclient": 9000, "start": "2026-11-28T12:56:37.653657+0000",
                  "end": "2026-11-28T12:56:39.653657+0000", "state": "closed"}},
        {"timestamp": "2026-11-28T12:38:54.844473+0000", "event_type": "dns", "src_ip": "192.168.1.100",
         "dns": {"version": 3, "type": "request", "queries": [{"rrname": "a.duckdns.org", "rrtype": "A"}]}},
        {"timestamp": "2026-11-28T12:38:54.900000+0000", "event_type": "dns", "src_ip": "8.8.4.4",
         "dns": {"version": 3, "type": "response", "queries": [{"rrname": "a.duckdns.org", "rrtype": "A"}]}},
        {"timestamp": "2026-11-28T12:56:37.554661+0000", "event_type": "dhcp", "src_ip": "0.0.0.0",
         "dhcp": {"type": "request", "client_mac": "02:00:5e:10:20:30", "assigned_ip": "0.0.0.0",
                  "requested_ip": "192.168.1.110", "hostname": "kali"}},
        {"timestamp": "2026-11-28T12:38:54.844473+0000", "event_type": "alert", "src_ip": "192.168.1.100",
         "dest_ip": "8.8.4.4", "dest_port": 53,
         "alert": {"signature_id": 9100006, "signature": "HOMENET DNS lookup of dynamic DNS / tunnel service",
                   "severity": 2, "category": "Potentially Bad Traffic",
                   "metadata": {"mitre_technique_id": ["T1568"]}}},
    ]
    eve = tmp_path / "eve-2026-11-28-12:16.json"
    eve.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    ds = FileSource(str(tmp_path / "no-zeek"), str(tmp_path / "eve-*.json")).load()
    assert len(ds.conns) == 1 and ds.conns[0].orig_bytes == 500 and ds.conns[0].duration == 2.0
    assert [q.query for q in ds.dns] == ["a.duckdns.org"]
    assert ds.dhcp[0].hostname == "kali" and ds.dhcp[0].ip == "192.168.1.110"
    assert len(ds.alerts) == 1 and ds.alerts[0].mitre == ["T1568"]
