#!/usr/bin/env python3
"""Translate Flowseal general*.bat strategies into ciadpi (ByeDPI) arguments for the
app's VPN mode, which needs no root. Output: one .vpn file per strategy.

Usage: tools/bat2vpn.py [BAT_DIR] [ASSETS_DIR]    defaults: tools/bat app/src/main/assets

Without root an app can't craft packets, it only has ordinary sockets. So this is an
approximation, not a translation. docs/PORTING.md lists what becomes what and why.
Each output line is one ciadpi group, the first group that matches a connection wins.
"""
import re
import sys
from pathlib import Path

from bat2conf import Blobs, Profile, read_bat, split_profiles

FAKE_TTL = 8
# ms the fake stays in place of the real data: the kernel retransmits it meanwhile, which stands in for
# --dpi-desync-repeats. Measured on a real network: one fake got through 17 of 24 times, a held one 24 of 24
FAKE_HOLD = 350
HOLD = ["--fake-hold", str(FAKE_HOLD)]
# nfqws1 sends udp fakes with the normal ttl, ciadpi would use 8 unless told otherwise
UDP_FAKE_TTL = 64
RANDOM_SNI = "????????.com"
HOSTLISTS = {"list-general.txt", "list-google.txt"}


def fake_path(value):
    m = re.fullmatch(r"%BIN%([A-Za-z0-9_]+\.bin)", value)
    if not m:
        raise ValueError(f"unexpected fake: {value}")
    return "%FAKE%/" + m.group(1)


def marker(pos):
    """nfqws1 position marker -> ciadpi position."""
    if re.fullmatch(r"-?\d+", pos):
        return pos
    if pos == "midsld":
        return "0+hm"  # middle of the host instead of the middle of its second level
    m = re.fullmatch(r"sniext([+-]\d+)?", pos)
    if m:
        # sniext is the start of SNI extension data. the name itself goes 5 bytes further
        return f"{int(m.group(1) or 0) - 5}+h"
    if pos == "host":
        return "0+h"
    if pos == "endhost":
        return "0+he"
    raise ValueError(f"unknown position marker: {pos}")


def tls_mod_args(mod):
    args = []
    for item in filter(None, (mod or "").split(",")):
        if item == "rnd":
            args += ["-Q", "rand"]
        elif item == "rndsni":
            args += ["-n", RANDOM_SNI]
        elif item.startswith("sni="):
            args += ["-n", item[4:]]
        elif item not in ("dupsid", "none"):  # ciadpi has no dupsid
            raise ValueError(f"unknown tls mod: {item}")
    return args


# Filled in by the app at start time, the same switch as IPSet Filter in service.bat:
# %IPSET% - ipset-all.txt in the chosen mode (a placeholder address in "none", the group loses its -j in "any")


class VpnProfile:
    def __init__(self, options):
        self.p = Profile(options, Blobs())

    def ipset(self):
        return any(f.startswith("--ipset=") for f in self.p.filters)

    def game(self):
        # The game filter exists in Windows for Steam games and is off by default. On a phone
        # it makes no sense, so these profiles are not carried over
        return any("%GameFilter" in f for f in self.p.filters)

    def has_exclude(self):
        return any(f.startswith("--hostlist-exclude=") for f in self.p.filters)

    def hosts(self):
        if self.ipset():
            return ["-j", "%IPSET%"]
        names = []
        for f in self.p.filters:
            if f.startswith("--hostlist="):
                name = f.rsplit("/", 1)[1]
                if name in HOSTLISTS:
                    names.append(name)
            elif f.startswith("--hostlist-domains="):
                return ["-H", ":" + f.split("=", 1)[1]]
        if len(names) > 1:
            raise ValueError(f"more than one hostlist: {names}")
        return ["-H", f"%LISTS%/vpn-{names[0]}"] if names else []

    # --- tcp

    def tls_decoy(self):
        """(fake data args) for TLS. ciadpi sends one fake only, so a real ClientHello is
        preferred over service fakes such as 0x00000000 or stun that go before it."""
        p = self.p
        fakes = p.tls_fake_args() if "fake" in p.modes else []
        if fakes:
            def real_hello(item):
                return item[0] == "fake_default_tls" or "tls_clienthello" in item[0]
            blob, mod = next((f for f in fakes if real_hello(f)), fakes[0])
            # tls_fake_args returned a blob name, find the file behind it
            args = []
            if blob != "fake_default_tls" and not blob.startswith("0x"):
                args += ["-l", f"%FAKE%/{blob}.bin"]
            return args + tls_mod_args(mod)
        pattern = p.opt.get("--dpi-desync-split-seqovl-pattern")
        if pattern and not pattern.startswith("0x"):
            return ["-l", fake_path(pattern)]
        return None

    def http_decoy(self):
        p = self.p
        fakes = p.multi["--dpi-desync-fake-http"] if "fake" in p.modes else []
        if fakes:
            return ["-l", fake_path(fakes[-1])]
        if "fake" in p.modes:
            return []  # built-in http fake
        return self.tls_decoy()

    def actions(self, decoy):
        p = self.p
        modes = [m for m in p.modes if m not in ("syndata", "fake")]  # syndata needs raw sockets
        second = modes[0] if modes else None
        pos = [marker(x) for x in p.split_pos().split(",")]

        if second == "hostfakesplit":
            # the same picture for DPI: the ClientHello is real, the host in it is not
            mods = p.opt.get("--dpi-desync-hostfakesplit-mod", "")
            host = re.search(r"host=([^,]+)", mods)
            args = ["-s", "0+h", "-f", "0+he", "-O", "0+h", "-Q", "orig"]
            if host:
                args += ["-n", host.group(1)]
            return args + ["-t", str(FAKE_TTL)] + HOLD

        if decoy is not None:
            if second == "multidisorder" or second is None:
                # a low ttl fake and the real data share sequence numbers, the kernel retransmits
                # the real part in one piece, so its order can't be changed afterwards
                args = ["-f", "-1"]
            else:
                # multisplit, fakedsplit: the first piece is real, the fake starts at the same offset
                # so together for DPI they read as a complete ClientHello with another SNI
                args = ["-s", pos[0], "-f", "-1", "-O", pos[0]]
            return args + decoy + ["-t", str(FAKE_TTL)] + HOLD

        if second == "multidisorder":
            return [a for x in pos for a in ("-d", x)]
        if second in ("multisplit", "fakedsplit"):
            return [a for x in pos for a in ("-s", x)]
        return []

    def tcp_groups(self):
        hosts = self.hosts()
        tls = self.actions(self.tls_decoy())
        http = self.actions(self.http_decoy())
        if tls == http:
            return [["-K", "t,h"] + hosts + tls]
        return [["-K", "t"] + hosts + tls, ["-K", "h"] + hosts + http]

    # --- udp

    def udp_groups(self):
        p = self.p
        if p.modes != ["fake"]:
            raise ValueError(f"unsupported udp desync: {p.modes}")
        ranges = next((f.split("=", 1)[1].split(",") for f in p.filters if f.startswith("--filter-udp=")), ["443"])
        repeats = p.repeats or "1"
        # ciadpi doesn't look inside udp: no hostlist and no protocol check, so the fake goes
        # before the first packet of any flow on these ports
        fakes = []
        for option in ("--dpi-desync-fake-quic", "--dpi-desync-fake-discord", "--dpi-desync-fake-stun",
                       "--dpi-desync-fake-unknown-udp"):
            fakes = p.multi[option] or fakes
        args = ["-a", repeats, "-t", str(UDP_FAKE_TTL)]
        if fakes:
            args += ["-l", fake_path(fakes[-1])]
        ipset = ["-j", "%IPSET%"] if self.ipset() else []
        return [["-K", "u", "-V", r] + ipset + args for r in ranges]

    def groups(self):
        return self.tcp_groups() if self.p.is_tcp else self.udp_groups()


IPSET_EXCLUDE = ["-j", "%LISTS%/vpn-ipset-exclude.txt"]


def strategy_groups(profiles):
    """Windows goes through profiles in order and so does ciadpi, except that excluded
    domains must be caught just before the first profile that excludes them. Excluded
    addresses (local networks, ipset-exclude.txt) go first: no profile in Windows touches them."""
    groups = [IPSET_EXCLUDE]
    excluded = False
    seen = set()
    open_udp = set()  # udp ports that already get a fake for any address
    for options in profiles:
        profile = VpnProfile(options)
        if profile.game():
            continue
        if not profile.p.is_tcp:
            ports = set(next((f.split("=", 1)[1].split(",") for f in profile.p.filters
                              if f.startswith("--filter-udp=")), ["443"]))
            if profile.ipset() and ports <= open_udp:
                # ciadpi can't check a host name in udp, so the hostlist profile for these ports
                # already took every address and this one would never be reached
                continue
            if not profile.ipset():
                open_udp |= ports
        if profile.has_exclude() and profile.p.is_tcp and not excluded:
            groups.append(["-K", "t,h", "-H", "%LISTS%/vpn-list-exclude.txt"])
            excluded = True
        for group in profile.groups():
            key = tuple(group)
            if key not in seen:
                seen.add(key)
                groups.append(group)
    return groups


def render(title, groups, note=""):
    lines = [f"# {title}", "# Сгенерировано tools/bat2vpn.py. Каждая строка - группа ciadpi." + note, ""]
    # ciadpi adds a final group without filters by itself, it lets everything else through
    lines += [" ".join(g) for g in groups]
    return "\n".join(lines) + "\n"


# ByeDPI's own ideas which have no twin in the Windows set: all of them come from its README.
# They need no fakes, so a server closer than the fake TTL can't break them. LIST is the group's own host list:
# --auto starts a new group and filters aren't inherited, so every step of the chain has to repeat it
AUTO_ON = ["-A", "torst,ssl_err", "-K", "t,h", "-H", "LIST"]
EXTRA = {
    "vpn fake": ["-f", "-1", "-t", str(FAKE_TTL)] + HOLD,
    "vpn disorder": ["-d", "1", "-r", "1+s"],
    "vpn split": ["-s", "1+s"],
    "vpn tlsrec": ["-s", "1+s", "-r", "1+s"],
    "vpn oob": ["-o", "1+s"],
    # one connection tries the next step by itself when the previous one gets a reset or no ServerHello
    "vpn auto": ["-d", "1", "-r", "1+s"] + AUTO_ON + ["-s", "1+s", "-o", "1+s"] + AUTO_ON + ["-f", "-1", "-t", str(FAKE_TTL)] + HOLD,
}
QUIC_GROUP = ["-K", "u", "-V", "443", "-a", "6", "-t", str(UDP_FAKE_TTL), "-l", "%FAKE%/quic_initial_www_google_com.bin"]


def extras():
    for name, actions in EXTRA.items():
        groups = [IPSET_EXCLUDE, QUIC_GROUP,
                  ["-K", "t,h", "-H", "%LISTS%/vpn-list-exclude.txt"],
                  in_list("%LISTS%/vpn-list-general.txt", actions),
                  in_list("%LISTS%/vpn-list-google.txt", actions)]
        yield name, groups
    # На настоящей сети списки хотят разного: YouTube проходит с фейком TLS и TTL 6, Discord с простым фейком и TTL 5.
    # TTL 8 из остальных конфигов там доходит до близких серверов Google и ломает их. См. docs/PORTING.md
    yield "vpn combo", [IPSET_EXCLUDE, QUIC_GROUP,
                        ["-K", "u", "-V", "19294-19344", "-a", "6", "-t", str(UDP_FAKE_TTL), "-l", "%FAKE%/ACTIVE_DISCORD_UDP.bin"],
                        ["-K", "u", "-V", "50000-50100", "-a", "6", "-t", str(UDP_FAKE_TTL), "-l", "%FAKE%/ACTIVE_DISCORD_UDP.bin"],
                        ["-K", "t,h", "-H", "%LISTS%/vpn-list-exclude.txt"],
                        in_list("%LISTS%/vpn-list-google.txt", ["-f", "-1", "-l", "%FAKE%/tls_clienthello_www_google_com.bin", "-t", "6"] + HOLD),
                        in_list("%LISTS%/vpn-list-general.txt", ["-f", "-1", "-t", "5"] + HOLD)]


def in_list(hostlist, actions):
    return ["-K", "t,h", "-H", hostlist] + [hostlist if a == "LIST" else a for a in actions]


def clean_list(src, dst):
    """ciadpi drops lines with ^ and treats comments as hosts. Subdomains match there anyway."""
    hosts = []
    for line in src.read_text(encoding="utf-8").splitlines():
        line = line.strip().lstrip("^!")
        if line and not line.startswith("#"):
            hosts.append(line.lower())
    dst.write_text("\n".join(hosts) + "\n", encoding="utf-8")


def main():
    bat_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "tools/bat")
    assets = Path(sys.argv[2] if len(sys.argv) > 2 else "app/src/main/assets")
    out = assets / "strategies"
    out.mkdir(parents=True, exist_ok=True)
    for name in ("list-general.txt", "list-google.txt", "list-exclude.txt"):
        clean_list(assets / "lists" / name, assets / "lists" / f"vpn-{name}")

    unique = {}
    count = 0
    for path in sorted(bat_dir.glob("general*.bat")):
        _, profiles = split_profiles(read_bat(path))
        groups = strategy_groups(profiles)
        text = render(path.stem, groups)
        (out / (path.stem + ".vpn")).write_text(text, encoding="utf-8")
        unique.setdefault(tuple(map(tuple, groups)), []).append(path.stem)
        count += 1
    for name, groups in extras():
        (out / (name + ".vpn")).write_text(render(name, groups, " Своя идея ByeDPI, в Windows-версии аналога нет."), encoding="utf-8")
    print(f"translated {count} strategies, {len(unique)} differ for ciadpi")
    for names in unique.values():
        if len(names) > 1:
            print("  same:", ", ".join(names))


if __name__ == "__main__":
    main()
