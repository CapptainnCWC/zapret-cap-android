#!/usr/bin/env python3
"""Translate Flowseal general*.bat strategies (winws / nfqws1 options) into
.conf strategy files for nfqws2 (--lua-desync).

Usage: tools/bat2conf.py [BAT_DIR] [OUT_DIR]
       defaults: tools/bat strategies

The rules below follow nfqws1 source code (nfq/desync.c, nfq/nfqws.c, nfq/params.c),
docs/PORTING.md explains each of them. An option the translator doesn't know is a
hard error: when upstream strategies start using something new it must be mapped
by hand, not silently dropped.
"""
import re
import shlex
import sys
from pathlib import Path

# nfqws1 defaults (nfq/params.h)
BADSEQ_INCREMENT_DEFAULT = -10000
BADSEQ_ACK_INCREMENT_DEFAULT = -66000
TS_INCREMENT_DEFAULT = -600000
DEFAULT_SPLIT_POS = "2"

# what nfqws1 recognizes on UDP. everything else, including wireguard non-initiation
# packets and dns/dtls that nfqws2 knows about, is "unknown" for it
UDP_KNOWN = {
    "quic": "quic_initial",
    "wireguard": "wireguard_initiation",
    "dht": "dht",
    "discord": "discord_ip_discovery",
    "stun": "stun",
}
ZERO_64 = "zero_64"
ZERO_256 = "zero_256"
BLOB_ZERO_64 = "--blob=zero_64:0x" + "00" * 64
BLOB_ZERO_256 = "--blob=zero_256:0x" + "00" * 256

PASSTHROUGH = {
    "--filter-tcp", "--filter-udp", "--filter-l3", "--filter-l7",
    "--hostlist", "--hostlist-exclude", "--hostlist-domains", "--hostlist-exclude-domains",
    "--ipset", "--ipset-exclude",
}
REPEATABLE = {
    "--dpi-desync-fake-http", "--dpi-desync-fake-unknown", "--dpi-desync-fake-quic",
    "--dpi-desync-fake-discord", "--dpi-desync-fake-stun", "--dpi-desync-fake-unknown-udp",
}
SINGLE = {
    "--dpi-desync", "--dpi-desync-repeats", "--dpi-desync-fooling", "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl", "--dpi-desync-split-seqovl-pattern", "--dpi-desync-cutoff",
    "--dpi-desync-any-protocol", "--dpi-desync-badseq-increment", "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-hostfakesplit-mod", "--ip-id",
}


class Blobs:
    """Tracks which blob files a strategy needs and maps option values to blob names."""

    def __init__(self):
        self.files = {}
        self.extra = []

    def ref(self, value):
        if value.startswith("0x"):
            return value
        m = re.fullmatch(r"%BIN%([A-Za-z0-9_]+)\.bin", value)
        if not m:
            raise ValueError(f"unexpected blob value: {value}")
        name = m.group(1)
        self.files[name] = f"--blob={name}:@%FAKE%/{name}.bin"
        return name

    def named(self, name, definition):
        if definition not in self.extra:
            self.extra.append(definition)
        return name

    def lines(self):
        return [self.files[k] for k in sorted(self.files)] + self.extra


def read_bat(path):
    """Return winws command line tokens (without the executable)."""
    text = path.read_text(encoding="utf-8").replace("\r", "")
    m = re.search(r'winws\.exe"\s*(.*)', text, flags=re.S)
    if not m:
        raise ValueError("winws.exe command not found")
    cmd = m.group(1).replace("^\n", " ").replace("^!", "!").split("\n")[0]
    return shlex.split(cmd)


def split_opt(token):
    if not token.startswith("--"):
        raise ValueError(f"unexpected token: {token}")
    name, sep, value = token.partition("=")
    return name, (value if sep else "")


def to_path(value):
    return value.replace("%LISTS%", "%LISTS%/")


def split_profiles(tokens):
    ports = {"tcp": None, "udp": None}
    profiles, cur = [], []
    for token in tokens:
        name, value = split_opt(token)
        if name == "--wf-tcp":
            ports["tcp"] = value
        elif name == "--wf-udp":
            ports["udp"] = value
        elif name == "--new":
            profiles.append(cur)
            cur = []
        else:
            cur.append((name, value))
    profiles.append(cur)
    return ports, profiles


def parse_hostfakesplit_mod(value):
    mods = {}
    for item in value.split(","):
        key, _, val = item.partition("=")
        if key not in ("host", "altorder"):
            raise ValueError(f"unknown hostfakesplit mod: {item}")
        mods[key] = val
    if mods.get("altorder", "0") not in ("0", "1"):
        raise ValueError(f"unsupported altorder: {value}")
    return mods


class Profile:
    def __init__(self, options, blobs):
        self.blobs = blobs
        self.filters = []
        self.opt = {}
        self.multi = {k: [] for k in REPEATABLE}
        self.tls_fakes = None  # None - not specified
        self.tls_mod_last = None  # nfqws1 dp->tls_mod_last, None - never set
        for name, value in options:
            if name in PASSTHROUGH:
                self.filters.append(f"{name}={to_path(value)}" if value else name)
            elif name in REPEATABLE:
                self.multi[name].append(value)
            elif name == "--dpi-desync-fake-tls":
                # a new fake inherits the mods set so far...
                if self.tls_fakes is None:
                    self.tls_fakes = []
                self.tls_fakes.append({"value": value, "mod": self.tls_mod_last})
            elif name == "--dpi-desync-fake-tls-mod":
                # ...and a mod option updates the last fake and all the following ones
                self.tls_mod_last = value
                if self.tls_fakes:
                    self.tls_fakes[-1]["mod"] = value
            elif name in SINGLE:
                self.opt[name] = value
            else:
                raise ValueError(f"unknown option {name}={value}")

        self.modes = self.opt.get("--dpi-desync", "").split(",")
        self.any_proto = self.opt.get("--dpi-desync-any-protocol") == "1"
        self.repeats = self.opt.get("--dpi-desync-repeats")
        self.is_tcp = any(f.startswith("--filter-tcp") for f in self.filters)
        self.has_hostlist = any(f.startswith(("--hostlist=", "--hostlist-domains=")) for f in self.filters)
        self.l7 = next((f.split("=", 1)[1].split(",") for f in self.filters if f.startswith("--filter-l7=")), None)

        self.common = []
        if self.opt.get("--ip-id"):
            self.common.append(f"ip_id={self.opt['--ip-id']}")

    # --- pieces of a lua instance

    def fooling(self):
        args = []
        for fool in filter(None, self.opt.get("--dpi-desync-fooling", "").split(",")):
            if fool == "ts":
                args.append(f"tcp_ts={TS_INCREMENT_DEFAULT}")
            elif fool == "badseq":
                inc = self.opt.get("--dpi-desync-badseq-increment", BADSEQ_INCREMENT_DEFAULT)
                args += [f"tcp_seq={inc}", f"tcp_ack={BADSEQ_ACK_INCREMENT_DEFAULT}"]
            elif fool == "md5sig":
                args.append("tcp_md5")
            else:
                raise ValueError(f"unknown fooling: {fool}")
        return args

    def rep(self):
        return [f"repeats={self.repeats}"] if self.repeats and self.repeats != "1" else []

    def tcp_common(self):
        # nfqws1 always wrote the timestamp option first when it rebuilt a tcp segment
        return ["tcp_ts_up"] + self.common

    def out_range(self):
        cutoff = self.opt.get("--dpi-desync-cutoff")
        if not cutoff:
            return []
        m = re.fullmatch(r"n(\d+)", cutoff)
        if not m:
            raise ValueError(f"unsupported cutoff: {cutoff}")
        n = int(m.group(1))
        if self.is_tcp:
            # winws doesn't capture empty ACKs (DIVERT_TCP_NOT_EMPTY), so its packet counter goes
            # SYN=1, first data=2, ... nfqws2 on linux sees them all and would be off by one or
            # more. the data packet counter gives what the strategy really meant : first n-2 data packets
            return [f"--out-range=<d{n - 1}"]
        return [f"--out-range=<n{n}"]

    # --- tcp

    def tcp_fake(self, blob, extra=()):
        return "--lua-desync=" + ":".join(
            ["fake", f"blob={blob}"] + self.fooling() + self.rep() + self.tcp_common() + list(extra))

    def tls_fake_args(self):
        if self.tls_fakes is None:
            # default fake. nfqws1 randomizes it unless mods were set explicitly
            mod = self.tls_mod_last if self.tls_mod_last is not None else "rnd,rndsni,dupsid"
            return [("fake_default_tls", mod)]
        result = []
        for fake in self.tls_fakes:
            value = fake["value"]
            blob = "fake_default_tls" if value == "!" else self.blobs.ref(value)
            mod = fake["mod"]
            if value == "!" and mod is None:
                mod = "rnd,rndsni,dupsid"
            result.append((blob, mod))
        return result

    def fakes_tcp(self):
        out = []
        tls = []
        for blob, mod in self.tls_fake_args():
            extra = [f"tls_mod={mod}"] if mod and mod != "none" else []
            tls.append(self.tcp_fake(blob, extra))
        out += ["--payload=tls_client_hello"] + tls

        http = self.multi["--dpi-desync-fake-http"]
        names = [self.blobs.ref(v) for v in http] if http else ["fake_default_http"]
        out += ["--payload=http_req"] + [self.tcp_fake(n) for n in names]

        if self.any_proto:
            unknown = self.multi["--dpi-desync-fake-unknown"]
            if unknown:
                names = [self.blobs.ref(v) for v in unknown]
            else:
                names = [self.blobs.named(ZERO_256, BLOB_ZERO_256)]
            # nfqws2 knows more tcp protocols than nfqws1, here they are all "unknown" as they were
            payload = "payload=~empty,tls_client_hello,http_req"
            out += ["--payload=all"] + [self.tcp_fake(n, [payload]) for n in names]
        return out

    def split_pos(self):
        return self.opt.get("--dpi-desync-split-pos", DEFAULT_SPLIT_POS)

    def seqovl_args(self):
        args = []
        seqovl = self.opt.get("--dpi-desync-split-seqovl")
        if seqovl and seqovl != "0":
            args.append(f"seqovl={seqovl}")
            pattern = self.opt.get("--dpi-desync-split-seqovl-pattern")
            if pattern:
                args.append(f"seqovl_pattern={self.blobs.ref(pattern)}")
        return args

    def split_instance(self, func, args):
        """Instance of a segment sender on http/tls and, with any-protocol, on everything else."""
        if self.any_proto:
            return ["--payload=all", "--lua-desync=" + ":".join([func] + args + ["payload=~empty"])]
        return ["--payload=tls_client_hello,http_req", "--lua-desync=" + ":".join([func] + args)]

    def second_stage_tcp(self, mode):
        if mode == "multisplit":
            # fooling and repeats of the options belong to fakes only : nfqws1 uses plain rawsend() here
            return self.split_instance("multisplit", [f"pos={self.split_pos()}"] + self.seqovl_args() + self.tcp_common())
        if mode == "multidisorder":
            # segment order of multidisorder_legacy is the one of nfqws1
            return self.split_instance("multidisorder_legacy", [f"pos={self.split_pos()}"] + self.seqovl_args() + self.tcp_common())
        if mode == "fakedsplit":
            return self.fakedsplit()
        if mode == "hostfakesplit":
            mods = parse_hostfakesplit_mod(self.opt.get("--dpi-desync-hostfakesplit-mod", "altorder=0"))
            func = "hostfakesplit_alt" if mods.get("altorder") == "1" else "hostfakesplit"
            args = [f"host={mods['host']}"] if mods.get("host") else []
            # only makes sense where a host exists - other payloads went untouched in nfqws1 too
            return ["--payload=tls_client_hello,http_req",
                    "--lua-desync=" + ":".join([func] + args + self.fooling() + self.rep() + self.tcp_common())]
        raise ValueError(f"unknown second stage: {mode}")

    def fakedsplit(self):
        args = self.seqovl_args()
        pattern = self.opt.get("--dpi-desync-fakedsplit-pattern")
        if pattern:
            args.append(f"pattern={self.blobs.ref(pattern)}")
        args += self.fooling() + self.rep() + self.tcp_common()
        pos = self.split_pos().split(",")
        if len(pos) > 1:
            # fakedsplit takes one position. nfqws1 prefers the first relative marker and then an absolute one
            raise ValueError("fakedsplit with a position list is not used by any strategy, map it first")
        return self.split_instance("fakedsplit", [f"pos={pos[0]}"] + args)

    def actions_tcp(self):
        out = []
        modes = self.modes
        if modes[0] == "syndata":
            syndata = ["syndata"] + self.common
            out.append("--lua-desync=" + ":".join(syndata))
            modes = modes[1:]
        if modes and modes[0] == "fake":
            out += self.fakes_tcp()
            modes = modes[1:]
        if len(modes) > 1:
            raise ValueError(f"too many desync modes: {self.modes}")
        if modes:
            out += self.second_stage_tcp(modes[0])
        return out

    # --- udp

    def udp_fake(self, blob, extra=()):
        return "--lua-desync=" + ":".join(["fake", f"blob={blob}"] + self.rep() + self.common + list(extra))

    def actions_udp(self):
        if self.modes != ["fake"]:
            raise ValueError(f"unsupported udp desync: {self.modes}")
        # the same defaults as dp_fake_defaults() in nfqws1
        table = [
            ("quic", self.multi["--dpi-desync-fake-quic"], "fake_default_quic"),
            ("wireguard", [], None),
            ("dht", [], None),
            ("discord", self.multi["--dpi-desync-fake-discord"], None),
            ("stun", self.multi["--dpi-desync-fake-stun"], None),
        ]
        groups = []  # [(payload names, blob names)] with neighbours that use same blobs merged
        for proto, values, default in table:
            if self.l7 is not None and proto not in self.l7:
                continue
            if self.l7 is None and self.has_hostlist and proto != "quic":
                continue  # nothing except quic has a hostname to pass the hostlist
            if values:
                names = [self.blobs.ref(v) for v in values]
            elif default:
                names = [default]
            else:
                names = [self.blobs.named(ZERO_64, BLOB_ZERO_64)]
            if groups and groups[-1][1] == names:
                groups[-1][0].append(UDP_KNOWN[proto])
            else:
                groups.append(([UDP_KNOWN[proto]], names))

        out = []
        for payloads, names in groups:
            out.append("--payload=" + ",".join(payloads))
            out += [self.udp_fake(n) for n in names]
        if self.any_proto and (self.l7 is None or "unknown" in self.l7):
            values = self.multi["--dpi-desync-fake-unknown-udp"]
            names = [self.blobs.ref(v) for v in values] if values else [self.blobs.named(ZERO_64, BLOB_ZERO_64)]
            payload = "payload=~empty," + ",".join(UDP_KNOWN.values())
            out.append("--payload=all")
            out += [self.udp_fake(n, [payload]) for n in names]
        return out

    def render(self):
        actions = self.actions_tcp() if self.is_tcp else self.actions_udp()
        return " ".join(self.filters + self.out_range() + actions)


def translate(path):
    tokens = read_bat(path)
    ports, profiles = split_profiles(tokens)
    blobs = Blobs()
    rendered = [Profile(p, blobs).render() for p in profiles]
    lines = [
        f"# {path.stem}",
        f"# Сгенерировано tools/bat2conf.py из {path.name}. Не правьте вручную: своя стратегия - это новый файл.",
        f"PORTS_TCP={ports['tcp']}",
        f"PORTS_UDP={ports['udp']}",
        "",
    ] + blobs.lines() + [""]
    for i, profile in enumerate(rendered):
        if i:
            lines.append("--new")
        lines.append(profile)
    return "\n".join(lines) + "\n"


def main():
    bat_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "tools/bat")
    out_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "strategies")
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(bat_dir.glob("general*.bat")):
        (out_dir / (path.stem + ".conf")).write_text(translate(path), encoding="utf-8")
        count += 1
    print(f"translated {count} strategies to {out_dir}")


if __name__ == "__main__":
    main()
