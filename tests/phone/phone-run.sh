#!/system/bin/sh
# Весь прогон: Wi-Fi, затем мобильная сеть, затем возврат Wi-Fi и отладки. Запускается один раз и живёт без adb.
#   phone-run.sh ROUNDS_WIFI ROUNDS_CELL PLAN TAG [MAX_SECONDS]
ROOT=/data/local/tmp/zc
RW=$1; RC=$2; PLAN=$3; TAG=${4:-run}; MAX=${5:-7200}
mkdir -p "$ROOT/out"
exec >> "$ROOT/out/$TAG.log" 2>&1
log() { echo "$(date +%T) $*"; }
restore() {
  svc wifi enable
  sleep 15
  settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1
}
# Сторож в своём сеансе: вернёт связь, даже если основной скрипт упадёт или зависнет
WD=$!
trap 'restore; exit 1' TERM INT
log "start tag=$TAG net=$(dumpsys connectivity | grep -m1 -oE 'ni\{[A-Z]+[^}]*\}')"
rm -f "$ROOT/out/$TAG.done"
if [ "$RW" -gt 0 ]; then
  log "wifi phase"
  sh "$ROOT/phone-matrix.sh" "wifi-$TAG" "$RW" "$PLAN"
  sh "$ROOT/phone-hops.sh" "wifi-$TAG"
fi
if [ "$RC" -gt 0 ]; then
  log "cell phase"
  svc wifi disable
  i=0
  until [ "$(curl -s -o /dev/null -m 4 -w '%{http_code}' http://connectivitycheck.gstatic.com/generate_204)" = 204 ] || [ $i -gt 20 ]; do
    i=$((i+1)); sleep 3
  done
  log "cell up after $i tries: $(ip -o -4 addr | grep -E 'rmnet' | awk '{print $2,$4}' | tr '\n' ' ')"
  sh "$ROOT/phone-matrix.sh" "cell-$TAG" "$RC" "$PLAN"
  sh "$ROOT/phone-hops.sh" "cell-$TAG"
fi
restore
kill "$WD" 2>/dev/null
pkill -f "sleep $MAX" 2>/dev/null
log "finished"
touch "$ROOT/out/$TAG.done"
