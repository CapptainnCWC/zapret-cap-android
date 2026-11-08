#!/usr/bin/env python3
"""Проверяет прокси настоящим сервером Telegram: шлёт req_pq_multi и ждёт resPQ.
На этот запрос сервер отвечает без авторизации, так что аккаунт не нужен.

  mtproto_probe.py PORT SECRET DC[,DC...] [--media] [--proto abridged|intermediate|secure]
  DC со знаком минус не нужен: --media сам сделает индекс отрицательным."""
import argparse
import hashlib
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAGS = {"abridged": b"\xef" * 4, "intermediate": b"\xee" * 4, "secure": b"\xdd" * 4}
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463


def ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError(f"closed after {len(data)}/{count} bytes")
        data += chunk
    return data


def probe(port, secret, dc_idx, proto, timeout):
    started = time.monotonic()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    tag = TAGS[proto]
    while True:
        rnd = bytearray(os.urandom(64))
        if rnd[0] != 0xEF and bytes(rnd[:4]) not in TAGS.values() and rnd[4:8] != b"\0\0\0\0":
            break
    rnd[56:60] = tag
    rnd[60:62] = struct.pack("<h", dc_idx)
    enc = ctr(hashlib.sha256(bytes(rnd[8:40]) + secret).digest(), bytes(rnd[40:56]))
    encrypted = enc.update(bytes(rnd))
    reverse = bytes(rnd[8:56])[::-1]
    dec = ctr(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:48])
    sock.sendall(bytes(rnd[:56]) + encrypted[56:64])

    nonce = os.urandom(16)
    message = struct.pack("<I", REQ_PQ_MULTI) + nonce
    msg_id = (int(time.time() * (2 ** 32))) & ~3
    body = b"\0" * 8 + struct.pack("<qi", msg_id, len(message)) + message
    if proto == "abridged":
        frame = bytes([len(body) // 4]) + body
    elif proto == "intermediate":
        frame = struct.pack("<I", len(body)) + body
    else:
        padding = os.urandom(os.urandom(1)[0] % 16)
        frame = struct.pack("<I", len(body) + len(padding)) + body + padding
    sock.sendall(enc.update(frame))

    if proto == "abridged":
        first = dec.update(read_exact(sock, 1))[0]
        words = first if first < 0x7f else int.from_bytes(dec.update(read_exact(sock, 3)), "little")
        length = words * 4
    else:
        length = struct.unpack("<I", dec.update(read_exact(sock, 4)))[0] & 0x7fffffff
    if length > 64 * 1024:
        raise ValueError(f"bad length {length}")
    reply = dec.update(read_exact(sock, length))
    sock.close()
    if len(reply) == 4:
        raise ValueError(f"transport error {struct.unpack('<i', reply)[0]}")
    ctor = struct.unpack("<I", reply[20:24])[0]
    if reply[:8] != b"\0" * 8 or ctor != RES_PQ or reply[24:40] != nonce:
        raise ValueError(f"unexpected reply ctor=0x{ctor:08x} nonce_ok={reply[24:40] == nonce}")
    return time.monotonic() - started


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("secret")
    ap.add_argument("dcs")
    ap.add_argument("--media", action="store_true")
    ap.add_argument("--proto", default="intermediate", choices=TAGS)
    ap.add_argument("--timeout", type=float, default=15)
    args = ap.parse_args()
    secret = bytes.fromhex(args.secret)
    failed = 0
    for dc in map(int, args.dcs.split(",")):
        label = f"DC{dc}{' media' if args.media else ''} {args.proto}"
        try:
            took = probe(args.port, secret, -dc if args.media else dc, args.proto, args.timeout)
            print(f"  ok    {label}: resPQ за {took:.2f} с")
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {label}: {type(exc).__name__}: {exc}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
