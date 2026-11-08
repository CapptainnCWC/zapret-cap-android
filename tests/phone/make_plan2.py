#!/usr/bin/env python3
"""Второй круг: вид фейка и TTL по отдельности для списка Discord (general) и списка YouTube (google).

  make_plan2.py TTL,TTL,... > plan2.txt     TTL выбираются по результатам первого круга для этой сети
"""
import sys

ttls = [int(t) for t in sys.argv[1].split(",")]
ROOT = "/data/local/tmp/zc/assets"
L, F = f"{ROOT}/lists", f"{ROOT}/fake"
EXCL = f"-K t,h -H {L}/vpn-list-exclude.txt"
GOOGLE_BIN = f"{F}/tls_clienthello_www_google_com.bin"
SFERUM_BIN = f"{F}/tls_clienthello_www_sferum_ru.bin"


def plan(name, general, google):
    print(f"{name}|{EXCL} -An -K t,h -H {L}/vpn-list-google.txt {google} -An -K t,h -H {L}/vpn-list-general.txt {general}")


print("direct|")
FAKES = {
    "plain": lambda t: f"-f -1 -t {t}",
    "tlsgoogle": lambda t: f"-f -1 -l {GOOGLE_BIN} -t {t}",
    "randsni": lambda t: f"-f -1 -Q rand -n www.google.com -t {t}",
    "split+tlsgoogle": lambda t: f"-s 1 -f -1 -O 1 -l {GOOGLE_BIN} -t {t}",
    "split+sferum": lambda t: f"-s 1 -f -1 -O 1 -l {SFERUM_BIN} -t {t}",
    "hostfake": lambda t: f"-s 0+h -f 0+he -O 0+h -Q orig -n www.google.com -t {t}",
}
for t in ttls:
    for name, fake in FAKES.items():
        plan(f"f {name} t{t}", fake(t), fake(t))

# Без фейка для YouTube и с фейком для Discord: близкие серверы Google фейк не получат вообще
for t in ttls:
    for name, fake in (("plain", FAKES["plain"]), ("tlsgoogle", FAKES["tlsgoogle"]), ("randsni", FAKES["randsni"])):
        plan(f"mix disorder+{name} t{t}", fake(t), "-d 1+s")
        plan(f"mix oob+{name} t{t}", fake(t), "-s 1 -o 1+s")
plan("nofake oob", "-o 1+s", "-o 1+s")
plan("nofake tlsrec+split2", "-r 1+s -s 1 -s 0+hm", "-r 1+s -s 1 -s 0+hm")
