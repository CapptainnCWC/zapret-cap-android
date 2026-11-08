#!/system/bin/sh
# Проверка настоящего пути: приложение включает VPN, а curl из adb shell идёт через туннель, как любое приложение.
# Здесь участвуют и DNS через туннель, и hev-socks5-tunnel, и сам движок.
#   phone-vpn.sh LABEL ROUNDS "конфиг1;конфиг2"     результат: $ROOT/out/LABEL.tsv
ROOT=/data/local/tmp/zc
LABEL=$1; ROUNDS=${2:-1}; CONFIGS=$3
OUT=$ROOT/out/$LABEL.tsv
UA='Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36'
RX="-n org.zapretcap.app/.TestReceiver"
log() { echo "$(date +%T) $*"; }

vpn_up() { dumpsys connectivity 2>/dev/null | grep -q 'ni{VPN'; }

probe() {  # круг конфиг категория хост путь
  curl -sS -o /dev/null --http1.1 -A "$UA" --connect-timeout 6 -m 14 \
    -w "$LABEL\t$1\t$2\t$3\t$4\t%{http_code}\t%{time_namelookup}\t%{time_appconnect}\t%{time_total}\t%{size_download}\t%{exitcode}\t%{errormsg}\n" \
    "https://$4$5" 2>/dev/null
}

r=1
while [ "$r" -le "$ROUNDS" ]; do
  echo "$CONFIGS" | tr ';' '\n' > "$ROOT/tmp/vpn-$LABEL.list"
  while read -r name; do
    [ -z "$name" ] && continue
    am broadcast $RX --es cmd start --es strategy "$name" >/dev/null 2>&1
    i=0; until vpn_up || [ $i -gt 20 ]; do i=$((i+1)); sleep 0.5; done
    sleep 2
    if ! vpn_up; then
      printf '%s\t%s\t%s\tengine\tengine\t0\t0\t0\t0\t0\t98\tvpn-not-up\n' "$LABEL" "$r" "$name" >> "$OUT"
      continue
    fi
    (
      while read -r cat host path; do
        case "$cat" in \#*|'') continue;; esac
        probe "$r" "$name" "$cat" "$host" "$path" >> "$OUT" &
      done < "$ROOT/targets.txt"
      wait
    )
    echo "vpn $r $name $(date +%T)" > "$ROOT/tmp/vpn-$LABEL.progress"
  done < "$ROOT/tmp/vpn-$LABEL.list"
  r=$((r+1))
done
am broadcast $RX --es cmd stop >/dev/null 2>&1
sleep 2
log "vpn $LABEL finished"
