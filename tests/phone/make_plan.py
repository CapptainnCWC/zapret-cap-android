#!/usr/bin/env python3
"""Строит план для phone-matrix.sh: уникальные конфиги приложения и варианты для проверки.

  make_plan.py ASSETS_DIR > plan.txt     формат строки: имя|аргументы ciadpi
"""
import pathlib
import sys

assets = pathlib.Path(sys.argv[1])
ROOT = "/data/local/tmp/zc/assets"
seen = {}


def expand(lines):
    groups = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    text = " -An ".join(groups)
    return text.replace("%LISTS%", ROOT + "/lists").replace("%FAKE%", ROOT + "/fake")


def add(name, args):
    if args in seen:
        print(f"# {name} == {seen[args]}", file=sys.stderr)
        return
    seen[args] = name
    print(f"{name}|{args}")


print("direct|")
files = sorted((assets / "strategies").glob("*.vpn"))
base = {}
for f in files:
    args = expand(f.read_text().splitlines())
    base[f.stem] = args
    add(f.stem, args)

# Варианты без фейков и с другими разбиениями: им не мешает близкий сервер
LISTS = f"{ROOT}/lists"
FAKE = f"{ROOT}/fake"
EXCL = f"-K t,h -H {LISTS}/vpn-list-exclude.txt"


def lists_group(action):
    return (f"{EXCL} -An -K t,h -H {LISTS}/vpn-list-general.txt {action} "
            f"-An -K t,h -H {LISTS}/vpn-list-google.txt {action}")


for name, action in {
    "x split1": "-s 1",
    "x split sni-mid": "-s 0+hm",
    "x split2 sni": "-s 1 -s 0+hm",
    "x disorder sni": "-d 1+s",
    "x disorder1": "-d 1",
    "x disorder2": "-d 2",
    "x disoob": "-q 1+s",
    "x tlsrec sni": "-r 1+s",
    "x tlsrec split2": "-r 1+s -s 1 -s 0+hm",
    "x disorder+tlsrec2": "-d 1 -d 0+hm -r 1+s",
    "x split+oob": "-s 1 -o 1+s",
}.items():
    add(name, lists_group(action))

# Фейки с разным TTL: сервер ближе TTL получает фейк и рвёт соединение, а DPI дальше TTL его не видит
for ttl in (2, 3, 4, 5, 6, 7, 10, 12):
    add(f"x fake ttl{ttl}", lists_group(f"-s 1 -f -1 -O 1 -l {FAKE}/tls_clienthello_www_google_com.bin -t {ttl}"))

# Варианты vpn combo с другим TTL: окно TTL на мобильной сети своё
for ttl in (3, 4, 7, 8, 10):
    add(f"x combo ttl{ttl}", f"{EXCL} -An -K t,h -H {LISTS}/vpn-list-google.txt -f -1 -l {FAKE}/tls_clienthello_www_google_com.bin -t {ttl} "
        f"-An -K t,h -H {LISTS}/vpn-list-general.txt -f -1 -t {ttl}")
