#!/system/bin/sh
# Как VPN переживает смену сети: один запрос в секунду, в это время Wi-Fi выключается и включается снова.
# Важно время от смены сети до первого успешного запроса и зависшие запросы.
#   phone-switch.sh LABEL CONFIG                    результат: $ROOT/out/LABEL.switch
ROOT=/data/local/tmp/zc
LABEL=$1; NAME=$2
OUT=$ROOT/out/$LABEL.switch
: > "$OUT"
RX="-n org.zapretcap.app/.TestReceiver"
ev() { echo "$(date +%s.%N | cut -c1-14) EVENT $*" >> "$OUT"; }
req() {
  s=$(date +%s.%N | cut -c1-14)
  r=$(curl -s -o /dev/null --http1.1 --connect-timeout 8 -m 20 -w '%{http_code} %{exitcode} %{time_total}' https://$1/ 2>/dev/null)
  echo "$s $1 $r" >> "$OUT"
}
am broadcast $RX --es cmd start --es strategy "$NAME" >/dev/null 2>&1
sleep 5
ev "start $NAME"
# Долгое простаивающее соединение, как у мессенджера. Важно, когда оно закроется после смены сети: приложение должно
# сразу узнать об обрыве и переподключиться, а не ждать минуты, пока истечёт тайм-аут.
ip=$(cat "$ROOT"/out/*.resolve 2>/dev/null | grep '^ya.ru ' | cut -d' ' -f2 | grep -v none | head -1)
( (sleep 100) | nc -w 110 "$ip" 80 >/dev/null 2>&1; ev idle-tcp-closed rc=$? ) &
t=0
while [ $t -lt 100 ]; do
  case $t in
    20) ev wifi-off; svc wifi disable;;
    60) ev wifi-on; svc wifi enable;;
  esac
  (req ya.ru) &
  (req vk.com) &
  sleep 1
  t=$((t+1))
done
sleep 20
settings put global adb_wifi_enabled 0; sleep 2; settings put global adb_wifi_enabled 1
am broadcast $RX --es cmd stop >/dev/null 2>&1
ev done
