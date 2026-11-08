#!/usr/bin/env python3
"""Сводка результатов phone-matrix.sh: что открывается по категориям и насколько стабильно.

  report.py FILE.tsv [FILE.tsv ...]
"""
import collections
import statistics
import sys

CATS = ["search", "yt", "discord", "tg", "cf", "web"]
rows = []
for path in sys.argv[1:]:
    for line in open(path, encoding="utf-8", errors="replace"):
        p = line.rstrip("\n").split("\t")
        if len(p) < 11:
            continue
        rows.append(dict(label=p[0], round=p[1], name=p[2], cat=p[3], host=p[4], code=p[5], tconn=float(p[6] or 0),
                         ttls=float(p[7] or 0), total=float(p[8] or 0), size=int(float(p[9] or 0)), rc=p[10],
                         err=p[11] if len(p) > 11 else ""))


def ok(r):
    return r["rc"] == "0" and r["code"] not in ("000", "0")


# Попытка не считается, если в ту же секунду не прошёл и контроль без обхода: тогда виновата сеть, а не конфиг.
# В старых прогонах контроля нет, для них проверяется только то, что обход не затрагивает.
UNTOUCHED = {"ya.ru", "yandex.ru", "vk.com", "github.com", "www.wikipedia.org", "duckduckgo.com"}
void = set()
attempts = {}
for r in rows:
    attempts.setdefault((r["label"], r["round"], r["name"]), []).append(r)
for key, rs in attempts.items():
    ctrl = [r for r in rs if r["cat"] == "ctrl"] or [r for r in rs if r["host"] in UNTOUCHED]
    if ctrl and not any(ok(r) for r in ctrl):
        void.add(key)
if void:
    print(f"Отброшено попыток из-за сбоя самой сети: {len(void)} из {len(attempts)}")
    for key in sorted(void):
        print("  ", *key)
rows = [r for r in rows if (r["label"], r["round"], r["name"]) not in void and r["cat"] != "ctrl" and r["host"] != "www.tbank.ru"]


for label in sorted({r["label"] for r in rows}):
    sub = [r for r in rows if r["label"] == label]
    rounds = len({r["round"] for r in sub})
    print(f"\n===== {label}: кругов {rounds}, строк {len(sub)}")
    names = {}
    for r in sub:
        names.setdefault(r["name"], []).append(r)
    table = []
    for name, rs in names.items():
        row = {"name": name, "ok": sum(map(ok, rs)), "n": len(rs)}
        for c in CATS:
            cr = [r for r in rs if r["cat"] == c]
            row[c] = (sum(map(ok, cr)), len(cr))
        tls = [r["ttls"] for r in rs if ok(r) and r["ttls"] > 0]
        row["tls"] = statistics.median(tls) if tls else 0
        table.append(row)
    table.sort(key=lambda t: (-t["ok"] / max(t["n"], 1), t["tls"]))
    print(f"{'конфиг':28} {'всего':>9} " + " ".join(f"{c:>8}" for c in CATS) + "   tls,с")
    for t in table:
        cells = " ".join(f"{t[c][0]:>3}/{t[c][1]:<4}" for c in CATS)
        print(f"{t['name'][:28]:28} {t['ok']:>4}/{t['n']:<4} {cells}  {t['tls']:.2f}")
    direct = {r["host"]: 0 for r in sub}
    print("\nхосты: успехов без обхода / в лучшем конфиге / среднее по конфигам, типичная ошибка")
    best = table[0]["name"]
    hosts = {}
    for r in sub:
        hosts.setdefault((r["cat"], r["host"]), []).append(r)
    for (cat, host), rs in sorted(hosts.items()):
        d = [r for r in rs if r["name"] == "direct"]
        b = [r for r in rs if r["name"] == best]
        errs = collections.Counter(r["rc"] for r in rs if not ok(r))
        print(f"  {cat:8} {host:32} direct {sum(map(ok,d))}/{len(d)}  best {sum(map(ok,b))}/{len(b)}  "
              f"все {100*sum(map(ok,rs))//max(len(rs),1):>3}%  rc={dict(errs.most_common(3))}")
