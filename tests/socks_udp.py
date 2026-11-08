#!/usr/bin/env python3
"""Sends one datagram through a SOCKS5 proxy and waits for the echo: socks_udp.py PROXY_PORT HOST PORT"""
import socket
import struct
import sys

proxy_port, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
ctl = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
ctl.sendall(b"\x05\x01\x00")
assert ctl.recv(2) == b"\x05\x00"
ctl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
reply = ctl.recv(64)
assert reply[1] == 0, f"associate refused: {reply!r}"
relay = (socket.inet_ntoa(reply[4:8]) if reply[3] == 1 else "127.0.0.1", struct.unpack("!H", reply[-2:])[0])
if relay[0] == "0.0.0.0":
    relay = ("127.0.0.1", relay[1])
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(3)
message = b"real-datagram"
udp.sendto(b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port) + message, relay)
data, _ = udp.recvfrom(4096)
sys.exit(0 if data.endswith(message) else 1)
