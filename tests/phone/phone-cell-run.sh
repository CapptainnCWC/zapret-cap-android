#!/system/bin/sh
# Прогон на мобильной сети: сначала есть ли белый список, затем приёмы движка, затем настоящий VPN.
#   phone-cell-run.sh TAG ROUNDS "конфиги для VPN через ;"
ROOT=/data/local/tmp/zc
TAG=$1; ROUNDS=${2:-2}; VPNCONF=$3
mkdir -p "$ROOT/out" "$ROOT/tmp"
exec >> "$ROOT/out/$TAG.log" 2>&1
log() { echo "$(date +%T) $*"; }
RX="-n org.zapretcap.app/.TestReceiver"
restore() { svc wifi enable; sleep 15; settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1; }
setsid sh -c "sleep 1800; svc wifi enable; sleep 15; settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1; am broadcast $RX --es cmd stop; echo watchdog >> $ROOT/out/$TAG.log" </dev/null >/dev/null 2>&1 &
rm -f "$ROOT/out/$TAG.done"
am broadcast $RX --es cmd stop >/dev/null 2>&1
log "wifi resolve (адреса с Wi-Fi нужны как запасные)"
sh "$ROOT/phone-matrix.sh" "wifi-$TAG" 0 "$ROOT/plan.txt"
log "wifi off"
svc wifi disable
i=0; until [ "$(curl -s -o /dev/null -m 4 -w '%{http_code}' http://connectivitycheck.gstatic.com/generate_204)" = 204 ] || [ $i -gt 20 ]; do i=$((i+1)); sleep 3; done
log "cell up after $i tries: $(ip -o -4 addr | grep rmnet | awk '{print $2,$4}' | tr '\n' ' ')"
g=$(curl -s -o /dev/null -m 6 -w '%{http_code}/%{exitcode}' https://www.gstatic.com/generate_204)
c=$(curl -s -o /dev/null -m 6 -w '%{http_code}/%{exitcode}' https://www.cloudflare.com/)
y=$(curl -s -o /dev/null -m 6 -w '%{http_code}/%{exitcode}' https://ya.ru/)
log "whitelist check: gstatic=$g cloudflare=$c ya=$y"
sh "$ROOT/phone-white.sh" "$TAG-cell"
sh "$ROOT/phone-matrix.sh" "cell-$TAG" "$ROUNDS" "$ROOT/plan.txt"
sh "$ROOT/phone-hops.sh" "cell-$TAG"
log "cell vpn"
sh "$ROOT/phone-vpn.sh" "cellvpn-$TAG" 2 "$VPNCONF"
g=$(curl -s -o /dev/null -m 6 -w '%{http_code}/%{exitcode}' https://www.gstatic.com/generate_204)
log "whitelist check at end: gstatic=$g"
restore
pkill -f "sleep 1800" 2>/dev/null
log finished
touch "$ROOT/out/$TAG.done"
