#!/usr/bin/env bash
# Проверяет конфиги режима VPN на компьютере с Linux: настоящий ciadpi, настоящая сеть между двумя сетевыми
# пространствами. В отличие от эмулятора здесь честно работает TTL: сервер отбрасывает пакеты с малым TTL,
# как отбросил бы их маршрутизатор по дороге, поэтому видно, восстанавливается ли соединение после фейка.
# Обходит ли конфиг настоящий DPI, здесь не проверить. Прав администратора не требует.
#
#   tests/vpn-sandbox-test.sh [ИМЯ_КОНФИГА...]
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="$REPO/app/src/main/assets"

if [ "${SANDBOX_STAGE:-}" != inside ]; then
	WORK="$(mktemp -d "${TMPDIR:-/tmp}/zapret-vpn-sandbox.XXXXXX")"
	trap 'rm -rf "$WORK"' EXIT
	src="$REPO/native/third_party/byedpi"
	gcc -O2 -std=gnu99 -D_GNU_SOURCE -D_DEFAULT_SOURCE -I"$src" -w \
		"$src"/packets.c "$src"/main.c "$src"/conev.c "$src"/proxy.c "$src"/desync.c "$src"/mpool.c "$src"/extend.c -o "$WORK/ciadpi" || exit 1
	SANDBOX_STAGE=inside WORK="$WORK" unshare --user --map-root-user --net --mount --pid --fork --mount-proc --kill-child bash "${BASH_SOURCE[0]}" "$@"
	exit $?
fi

SERVER_IP=198.51.100.2
CLIENT_IP=198.51.100.1
PORT=1080

ip link set lo up
printf '127.0.0.1 localhost\n%s discord.com www.youtube.com example.org\n' "$SERVER_IP" > "$WORK/hosts"
mount --bind "$WORK/hosts" /etc/hosts

cat > "$WORK/server.py" <<'PY'
import http.server, socket, socketserver, ssl, sys, threading
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True
w = sys.argv[1]
plain = S(("0.0.0.0", 80), H); tls = S(("0.0.0.0", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(w + "/cert.pem", w + "/key.pem")
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=plain.serve_forever, daemon=True).start()
def echo(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", port))
    while True:
        d, a = u.recvfrom(4096)
        if d.startswith(b"real"): u.sendto(d, a)
for p in (443, 50050): threading.Thread(target=echo, args=(p,), daemon=True).start()
tls.serve_forever()
PY
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 -subj /CN=test >/dev/null 2>&1

# сервер отбрасывает всё с TTL ниже 40: до него такие пакеты в настоящей сети не дошли бы
unshare --net bash -c '
	until ip link show veth1 >/dev/null 2>&1; do sleep 0.05; done
	ip link set lo up; ip addr add '"$SERVER_IP"'/24 dev veth1; ip link set veth1 up
	nft add table ip f; nft add chain ip f in "{ type filter hook prerouting priority -300; }"; nft add rule ip f in ip ttl lt 40 drop
	exec python3 '"$WORK"'/server.py '"$WORK"'
' >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.3
ip link add veth0 type veth peer name veth1 netns "$SERVER_PID"
ip addr add "$CLIENT_IP/24" dev veth0
ip link set veth0 up
for _ in $(seq 1 50); do
	curl -sk -m 1 -o /dev/null "https://$SERVER_IP/" && break
	sleep 0.1
done

# списки, которые приложение готовит перед запуском движка (BypassSettings.apply)
LISTS="$WORK/lists"
mkdir -p "$LISTS"
cp "$ASSETS"/lists/* "$LISTS"/
cp "$LISTS/ipset-exclude.txt" "$LISTS/vpn-ipset-exclude.txt"
echo "203.0.113.113/32" > "$LISTS/vpn-ipset-all.txt"

load_args()
{
	# то же, что Data.vpnArgs в приложении
	local line first=1 token words
	ARGS=()
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in ''|'#'*) continue ;; esac
		[ "$first" = 1 ] || ARGS+=("-An")
		first=0
		read -r -a words <<< "$line"
		for token in "${words[@]}"; do
			token="${token//%LISTS%/$LISTS}"
			token="${token//%FAKE%/$ASSETS/fake}"
			# IPSet в режиме none, как по умолчанию в приложении и в Windows-версии
			token="${token//%IPSET%/$LISTS/vpn-ipset-all.txt}"
			ARGS+=("$token")
		done
	done < "$1"
}

check_url()
{
	curl -sk -m 8 --socks5 "127.0.0.1:$PORT" -o /dev/null -w '%{http_code}' "$1" 2>/dev/null | grep -q '^200$'
}

FAILED=0
printf '%-30s %-6s %-6s %-6s %-6s %-5s %-8s %s\n' config https youtube http other udp tcp-low udp-fakes
names=()
if [ $# -gt 0 ]; then
	names=("$@")
else
	for file in "$ASSETS"/strategies/*.vpn; do names+=("$(basename "$file" .vpn)"); done
fi
for name in "${names[@]}"; do
	load_args "$ASSETS/strategies/$name.vpn"
	"$WORK/ciadpi" -i 127.0.0.1 -p "$PORT" "${ARGS[@]}" >"$WORK/ciadpi.log" 2>&1 &
	PROXY=$!
	sleep 0.2
	python3 "$REPO/tests/ttl_watch.py" veth0 "$WORK/ttl.txt" > "$WORK/watch.out" &
	WATCH=$!
	until grep -q ready "$WORK/watch.out" 2>/dev/null; do sleep 0.02; done
	https=FAIL youtube=FAIL http=FAIL other=FAIL udp=FAIL
	check_url https://discord.com && https=ok
	check_url https://www.youtube.com && youtube=ok
	check_url http://discord.com && http=ok
	check_url https://example.org && other=ok
	python3 "$REPO/tests/socks_udp.py" "$PORT" "$SERVER_IP" 443 2>/dev/null && udp=ok
	sleep 0.1
	kill "$WATCH"; wait "$WATCH" 2>/dev/null
	kill "$PROXY" 2>/dev/null; wait "$PROXY" 2>/dev/null
	low="$(awk '$1 == "tcp" && $2 < 40 { n += $3 } END { print n + 0 }' "$WORK/ttl.txt")"
	udpn="$(awk '$1 == "udp" { n += $3 } END { print n + 0 }' "$WORK/ttl.txt")"
	printf '%-30s %-6s %-6s %-6s %-6s %-5s %-8s %s\n' "$name" "$https" "$youtube" "$http" "$other" "$udp" "$low" "$udpn"
	case "$https$youtube$http$other$udp" in *FAIL*) FAILED=$((FAILED + 1)) ;; esac
done
echo
echo "Конфигов с ошибками: $FAILED из ${#names[@]}"
kill "$SERVER_PID" 2>/dev/null
[ "$FAILED" = 0 ]
