#!/system/bin/sh
# Этап 2: настоящее приложение и настоящий VPN на Wi-Fi и на мобильной сети, включая смену сети.
#   phone-stage2.sh TAG "конфиг1;конфиг2" КОНФИГ_ДЛЯ_СМЕНЫ_СЕТИ
ROOT=/data/local/tmp/zc
TAG=$1; CONFIGS=$2; SW=$3
mkdir -p "$ROOT/out" "$ROOT/tmp"
exec >> "$ROOT/out/$TAG.log" 2>&1
log() { echo "$(date +%T) $*"; }
RX="-n org.zapretcap.app/.TestReceiver"
setsid sh -c "sleep 840; svc wifi enable; sleep 15; settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1; am broadcast $RX --es cmd stop; echo watchdog >> $ROOT/out/$TAG.log" </dev/null >/dev/null 2>&1 &
rm -f "$ROOT/out/$TAG.done"
log "wifi vpn"
sh "$ROOT/phone-vpn.sh" "wifi-$TAG" 1 "$CONFIGS"
log "wifi vpn snapshot"
am broadcast $RX --es cmd start --es strategy "$SW" >/dev/null 2>&1
sleep 5
sh "$ROOT/phone-white.sh" "$TAG-wifi-vpn"
am broadcast $RX --es cmd stop >/dev/null 2>&1
sleep 3
log "wifi off"
svc wifi disable
sleep 6
sh "$ROOT/phone-white.sh" "$TAG-cell-novpn"
# Белый список кончился: самое время прогнать все конфиги на обычном мобильном интернете
if [ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' https://www.gstatic.com/generate_204)" = 204 ]; then
  log "no whitelist: matrix"
  sh "$ROOT/phone-matrix.sh" "cell-$TAG-open" 1 "$ROOT/plan.txt"
else
  log "whitelist active"
fi
log "cell vpn"
sh "$ROOT/phone-vpn.sh" "cell-$TAG" 1 "$CONFIGS"
am broadcast $RX --es cmd start --es strategy "$SW" >/dev/null 2>&1
sleep 5
sh "$ROOT/phone-white.sh" "$TAG-cell-vpn"
am broadcast $RX --es cmd stop >/dev/null 2>&1
sleep 2
log "wifi on"
svc wifi enable
sleep 18
settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1
log "switch test"
sh "$ROOT/phone-switch.sh" "$TAG" "$SW"
settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1
pkill -f "sleep 840" 2>/dev/null
log finished
touch "$ROOT/out/$TAG.done"
