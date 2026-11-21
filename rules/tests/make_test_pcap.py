"""Build a synthetic PCAP that should trigger every custom Suricata rule.

    python rules/tests/make_test_pcap.py /tmp/homenet-test.pcap

Only RFC 5737 documentation IPs and reserved names are used; nothing is sent
on the network - packets are only written to a file.
"""
from __future__ import annotations

import sys

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS

LAN_PC, LAN_CAM, ROUTER = "192.168.1.10", "192.168.1.30", "192.168.1.1"
ROGUE, INET, ATTACKER = "192.168.1.66", "198.51.100.20", "203.0.113.9"

pkts = []
t = 1_763_700_000.0


def add(p):
    global t
    t += 0.01
    p.time = t
    pkts.append(p)


def tcp_session(src, dst, dport, client_payloads=(), server_payloads=(), sport=40000):
    """3-way handshake + client data + server data."""
    cs, ss = 1000, 5000
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=cs))
    add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=cs + 1))
    cs += 1
    ss += 1
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cs, ack=ss))
    for data in client_payloads:
        add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=cs, ack=ss) / Raw(bytes(data)))
        cs += len(bytes(data))
        add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=ss, ack=cs))
    for data in server_payloads:
        add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=ss, ack=cs) / Raw(bytes(data)))
        ss += len(bytes(data))
        add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cs, ack=ss))
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=cs, ack=ss))
    add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=ss, ack=cs + 1))


def client_hello(sni: str) -> bytes:
    ch = TLSClientHello(ciphers=[0x1301, 0xC02F], ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())])])
    return bytes(TLS(msg=[ch]))


def dns_query(src, dst, name, qtype="A", sport=53000):
    add(IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(id=sport, rd=1, qd=DNSQR(qname=name, qtype=qtype)))


# 9100001 internal SYN scan
for port in range(1, 121):
    add(IP(src=ROGUE, dst="192.168.1.40") / TCP(sport=51000, dport=port, flags="S"))
# 9100002 ICMP sweep
for host in range(2, 40):
    add(IP(src=ROGUE, dst=f"192.168.1.{host}") / ICMP(type=8))
# 9100003 DNS bypass (laptop asks 8.8.8.8-like resolver directly)
dns_query(LAN_PC, INET, "example.com")
# 9100004 / 9100014 DoH
tcp_session(LAN_PC, INET, 443, [client_hello("cloudflare-dns.com")], sport=40001)
tcp_session(LAN_PC, INET, 443, [client_hello("dns.google")], sport=40002)
# 9100005 long DNS query
dns_query(LAN_PC, ROUTER, "a" * 40 + "." + "b" * 40 + "." + "c" * 20 + ".t.cdn-sync.example", "TXT", sport=53001)
# 9100006 dynamic DNS
dns_query(LAN_PC, ROUTER, "my-c2-box.duckdns.org", sport=53002)
# 9100007 inbound telnet
add(IP(src=ATTACKER, dst=LAN_CAM) / TCP(sport=40100, dport=23, flags="S"))
# 9100008 inbound RDP
add(IP(src=ATTACKER, dst=LAN_PC) / TCP(sport=40101, dport=3389, flags="S"))
# 9100009 SSH brute force (15 attempts)
for i in range(15):
    add(IP(src=ROGUE, dst="192.168.1.40") / TCP(sport=42000 + i, dport=22, flags="S"))
# 9100010 SSDP from internet
add(IP(src=ATTACKER, dst=ROUTER) / UDP(sport=40102, dport=1900) / Raw(b"M-SEARCH * HTTP/1.1\r\n\r\n"))
# 9100011 cleartext FTP password
tcp_session(LAN_PC, INET, 21, [b"USER ayse\r\n", b"PASS hunter2\r\n"], [b"220 ready\r\n"], sport=40003)
# 9100012 EXE over HTTP
body = b"MZ" + b"\x90" * 60 + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 64
tcp_session(LAN_PC, INET, 80, [b"GET /update.exe HTTP/1.1\r\nHost: files.example\r\n\r\n"],
            [b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
             + str(len(body)).encode() + b"\r\n\r\n" + body], sport=40004)
# 9100013 / 9100015 remote access tools
tcp_session(LAN_PC, INET, 443, [client_hello("relay-1.net.anydesk.com")], sport=40005)
tcp_session(LAN_PC, INET, 443, [client_hello("router1.teamviewer.com")], sport=40006)
# 9100016 Stratum mining
tcp_session(LAN_PC, INET, 3333, [b'{"id":1,"method":"mining.subscribe","params":["xmrig/6.0"]}\n'], sport=40007)
# 9100017 Tor
add(IP(src=LAN_PC, dst=INET) / TCP(sport=40008, dport=9001, flags="S"))
# 9100018 outbound telnet from camera
add(IP(src=LAN_CAM, dst=INET) / TCP(sport=40009, dport=23, flags="S"))

out = sys.argv[1] if len(sys.argv) > 1 else "homenet-test.pcap"
wrpcap(out, pkts)
print(f"wrote {len(pkts)} packets to {out}")
