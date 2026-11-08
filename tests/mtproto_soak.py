#!/usr/bin/env python3
"""Долгие сессии через прокси: держит соединения открытыми и время от времени шлёт req_pq_multi.
Показывает, сколько живёт соединение и кто его оборвал. mtproto_probe.py проверяет только первый ответ,
а настоящий клиент держит соединение часами, поэтому обрывы видны только так.

  mtproto_soak.py PORT SECRET [--seconds 300] [--every 20] [--dcs 2,4,1,-2,-1]
  Минус перед номером означает соединение для медиа."""
import argparse
import hashlib
import os
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAG = b"\xdd" * 4
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463


def ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


class Session:
    """Клиент MTProxy с ключом dd: как Telegram, шлёт кадры со случайным дополнением."""

    def __init__(self, port, secret, dc_idx, timeout):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        while True:
            rnd = bytearray(os.urandom(64))
            if rnd[0] != 0xEF and rnd[4:8] != b"\0\0\0\0":
                break
        rnd[56:60] = TAG
        rnd[60:62] = struct.pack("<h", dc_idx)
        self.enc = ctr(hashlib.sha256(bytes(rnd[8:40]) + secret).digest(), bytes(rnd[40:56]))
        encrypted = self.enc.update(bytes(rnd))
        reverse = bytes(rnd[8:56])[::-1]
        self.dec = ctr(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:48])
        self.sock.sendall(bytes(rnd[:56]) + encrypted[56:64])

    def read(self, count):
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError(f"закрыто сервером или прокси, прочитано {len(data)} из {count}")
            data += chunk
        return data

    def request(self):
        nonce = os.urandom(16)
        message = struct.pack("<I", REQ_PQ_MULTI) + nonce
        body = b"\0" * 8 + struct.pack("<qi", int(time.time() * (2 ** 32)) & ~3, len(message)) + message
        padding = os.urandom(os.urandom(1)[0] % 16)
        self.sock.sendall(self.enc.update(struct.pack("<I", len(body) + len(padding)) + body + padding))
        started = time.monotonic()
        length = struct.unpack("<I", self.dec.update(self.read(4)))[0] & 0x7fffffff
        if length > 64 * 1024:
            raise ValueError(f"странная длина {length}")
        reply = self.dec.update(self.read(length))
        if len(reply) == 4:
            raise ValueError(f"ошибка транспорта {struct.unpack('<i', reply)[0]}")
        if struct.unpack("<I", reply[20:24])[0] != RES_PQ or reply[24:40] != nonce:
            raise ValueError("чужой ответ")
        return time.monotonic() - started


def worker(port, secret, dc_idx, seconds, every, timeout, results, lock):
    finish = time.monotonic() + seconds
    connections = 0
    while time.monotonic() < finish:
        connections += 1
        opened = time.monotonic()
        rounds = 0
        reason = "конец проверки"
        slowest = 0.0
        try:
            session = Session(port, secret, dc_idx, timeout)
            while time.monotonic() < finish:
                slowest = max(slowest, session.request())
                rounds += 1
                time.sleep(min(every, max(0.0, finish - time.monotonic())))
            session.sock.close()
        except Exception as error:
            reason = f"{type(error).__name__}: {error}"
        with lock:
            results.append((dc_idx, connections, time.monotonic() - opened, rounds, slowest, reason))
            print(f"DC{dc_idx:>4} #{connections}: {time.monotonic() - opened:6.1f} с, ответов {rounds:3}, "
                  f"медленнейший {slowest:5.2f} с: {reason}", flush=True)
        if reason != "конец проверки":
            time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("secret")
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--every", type=float, default=20)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--dcs", default="2,4,1,-2,-1")
    args = ap.parse_args()
    secret = bytes.fromhex(args.secret)
    results = []
    lock = threading.Lock()
    threads = [threading.Thread(target=worker, args=(args.port, secret, int(dc), args.seconds, args.every,
                                                     args.timeout, results, lock))
               for dc in args.dcs.split(",")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    broken = sum(1 for r in results if r[5] != "конец проверки")
    print(f"Соединений: {len(results)}, оборвалось: {broken}")


if __name__ == "__main__":
    main()
