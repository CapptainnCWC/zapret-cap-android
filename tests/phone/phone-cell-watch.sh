#!/system/bin/sh
# Лёгкое наблюдение за мобильной сетью без обхода: урезает ли оператор доступ сам и помогает ли переподключение.
#   phone-cell-watch.sh LABEL WATCH_SECONDS       результат: $ROOT/out/LABEL.watch
ROOT=/data/local/tmp/zc
LABEL=$1; WATCH=${2:-360}
OUT=$ROOT/out/$LABEL.watch
: > "$OUT"
setsid sh -c "sleep 780; svc wifi enable; sleep 15; settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1; echo watchdog >> $OUT" </dev/null >/dev/null 2>&1 &
ev() { echo "$(date +%T) EVENT $*" >> "$OUT"; }
signal() { dumpsys telephony.registry 2>/dev/null | grep -m1 -oE 'rsrp=[-0-9]+ rsrq=[-0-9]+ rssnr=[-0-9]+'; }
code() { curl -s -o /dev/null --connect-timeout 2 -m 3 -w '%{http_code}/%{exitcode}' "$1" 2>/dev/null; }
tick() {
  a=$(code https://www.gstatic.com/generate_204)
  b=$(code https://1.1.1.1/cdn-cgi/trace)
  c=$(code https://ya.ru/)
  echo "$(date +%T) gstatic=$a cf=$b ya=$c $(signal)" >> "$OUT"
  case "$a$b" in *204/0*|*200/0*) return 0;; esac
  return 1
}
watch_for() {  # секунды; выход раньше времени после 60 секунд подряд без доступа
  end=$(( $(date +%s) + $1 )); bad=0
  while [ "$(date +%s)" -lt "$end" ]; do
    if tick; then bad=0; else bad=$((bad+1)); fi
    [ "$bad" -ge 12 ] && return 1
    sleep 3
  done
  return 0
}
ev "start wifi still on, delay"
sleep 60
ev wifi-off
svc wifi disable
sleep 3
ev "iface: $(ip -o -4 addr | grep rmnet | awk '{print $2,$4}' | tr '\n' ' ') $(dumpsys connectivity 2>/dev/null | grep -m1 -oE 'ni\{MOBILE[^}]*\}')"
if watch_for "$WATCH"; then
  ev "no-cut in $WATCH s"
else
  ev "cut detected: snapshot, then reconnecting mobile data"
  sh "$ROOT/phone-white.sh" "$LABEL"
  svc data disable
  sleep 6
  svc data enable
  sleep 6
  ev "reconnected: $(ip -o -4 addr | grep rmnet | awk '{print $2,$4}' | tr '\n' ' ')"
  watch_for 150 && ev "survived 150 s after reconnect" || ev "cut again after reconnect"
fi
ev wifi-on
svc wifi enable
sleep 15
settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1
pkill -f "sleep 780" 2>/dev/null
ev done
