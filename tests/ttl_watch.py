#!/usr/bin/env python3
"""Counts outgoing IPv4 packets with data by protocol and TTL until killed: ttl_watch.py IFACE OUT_FILE"""
import signal
import socket
import sys
from collections import Counter

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind((sys.argv[1], 0))
print("ready", flush=True)
counts = Counter()


def finish(*_):
    with open(sys.argv[2], "w") as out:
        for (proto, ttl), count in sorted(counts.items()):
            out.write(f"{proto} {ttl} {count}\n")
    sys.exit(0)


signal.signal(signal.SIGTERM, finish)
while True:
    frame, addr = sock.recvfrom(65535)
    if addr[2] != socket.PACKET_OUTGOING or frame[12:14] != b"\x08\x00":
        continue
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    if ip[9] == 6:
        hlen = (ip[ihl + 12] >> 4) * 4
        if total - ihl - hlen > 0:
            counts[("tcp", ip[8])] += 1
    elif ip[9] == 17:
        counts[("udp", ip[8])] += 1
