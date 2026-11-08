#!/system/bin/sh
# Прогон конфигов на телефоне. Работает под пользователем shell без adb, поэтому переживает отключение Wi-Fi.
#   phone-matrix.sh LABEL ROUNDS PLAN        результат: $ROOT/out/LABEL.tsv
ROOT=/data/local/tmp/zc
LABEL=$1
ROUNDS=${2:-1}
PLAN=${3:-$ROOT/plan.txt}
OUT=$ROOT/out/$LABEL.tsv
RESOLVE=$ROOT/out/$LABEL.resolve
PORT=21080
UA='Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36'
TMP=$ROOT/tmp/$LABEL
mkdir -p "$ROOT/out" "$TMP"

log() { echo "$(date +%T) $*"; }

# Адреса те же, что у приложений через VPN: не от DNS провайдера. Заглушка в нём сломала бы любой конфиг.
resolve_all() {
  : > "$RESOLVE"
  while read -r cat host path; do
    case "$cat" in \#*|'') continue;; esac
    (
      ip=$(curl -s -m 8 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$host&type=A" | grep -o '"data":"[0-9.]*"' | head -1 | cut -d'"' -f4)
      [ -z "$ip" ] && ip=$(curl -s -m 8 "https://8.8.8.8/resolve?name=$host&type=1" | grep -o '"data":"[0-9.]*"' | head -1 | cut -d'"' -f4)
      # DoH бывает закрыт: тогда берём адрес из прогона по другой сети, а не считаем сайт закрытым
      [ -z "$ip" ] && ip=$(cat "$ROOT"/out/*.resolve 2>/dev/null | grep "^$host " | cut -d' ' -f2 | grep -v none | head -1)
      sys=$(ping -c1 -W1 -w1 "$host" 2>/dev/null | head -1 | sed -n 's/^PING [^(]*(\([0-9.]*\)).*/\1/p')
      echo "$host ${ip:-none} ${sys:-none}" >> "$RESOLVE"
    ) &
  done < "$ROOT/targets.txt"
  wait
}

probe() {  # имя круг категория хост путь порт
  ip=$(grep "^$4 " "$RESOLVE" | cut -d' ' -f2)
  [ "$ip" = "none" ] || [ -z "$ip" ] && { printf '%s\t%s\t%s\t%s\t%s\t0\t0\t0\t0\t0\t6\tno-dns\n' "$LABEL" "$2" "$1" "$3" "$4"; return; }
  proxy=""
  [ -n "$6" ] && proxy="--socks5 127.0.0.1:$6"
  curl -sS -o /dev/null --http1.1 -A "$UA" --connect-timeout 6 -m 14 $proxy \
    --resolve "$4:443:$ip" \
    -w "$LABEL\t$2\t$1\t$3\t$4\t%{http_code}\t%{time_connect}\t%{time_appconnect}\t%{time_total}\t%{size_download}\t%{exitcode}\t%{errormsg}\n" \
    "https://$4$5" 2>/dev/null
}

run_one() {  # круг имя аргументы
  round=$1 name=$2 args=$3
  pid=""
  port=""
  if [ "$name" != "direct" ]; then
    port=$PORT
    # shellcheck disable=SC2086
    "$ROOT/ciadpi" -i 127.0.0.1 -p "$port" $args > "$TMP/engine.log" 2>&1 &
    pid=$!
    i=0
    until ss -ltn 2>/dev/null | grep -q ":$port "; do
      i=$((i+1))
      if [ $i -gt 30 ] || ! kill -0 "$pid" 2>/dev/null; then
        printf '%s\t%s\t%s\tengine\tengine\t0\t0\t0\t0\t0\t99\t%s\n' "$LABEL" "$round" "$name" "$(head -c 120 "$TMP/engine.log" | tr '\n\t' '  ')" >> "$OUT"
        kill "$pid" 2>/dev/null
        return
      fi
      sleep 0.1
    done
  fi
  # отдельная оболочка: её wait ждёт только curl, а не сам движок
  (
    while read -r cat host path; do
      case "$cat" in \#*|'') continue;; esac
      probe "$name" "$round" "$cat" "$host" "$path" "$port" >> "$OUT" &
    done < "$ROOT/targets.txt"
    # Контроль без обхода в ту же секунду: если не прошёл и он, виновата сеть (покрытие), а не конфиг
    probe "$name" "$round" ctrl www.gstatic.com /generate_204 "" >> "$OUT" &
    probe "$name" "$round" ctrl ya.ru / "" >> "$OUT" &
    wait
  )
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
  wait 2>/dev/null
}

# Уровень сигнала: плохие результаты на мобильной сети надо сверять с покрытием в тот момент
signal() {
  dumpsys telephony.registry 2>/dev/null | grep -m1 -oE 'CellSignalStrengthLte: rssi=[-0-9]+ rsrp=[-0-9]+ rsrq=[-0-9]+ rssnr=[-0-9]+'
}

log "matrix $LABEL rounds=$ROUNDS signal: $(signal)"
resolve_all
log "resolved $(wc -l < "$RESOLVE")"
total=$(grep -c '|' "$PLAN")
r=1
while [ "$r" -le "$ROUNDS" ]; do
  n=0
  # чётные круги идут в обратном порядке: иначе конфиг в конце всегда проверялся бы последним по времени
  if [ $((r % 2)) -eq 0 ]; then ORDER=$(awk '{a[NR]=$0} END{for(i=NR;i>0;i--)print a[i]}' "$PLAN"); else ORDER=$(cat "$PLAN"); fi
  echo "$ORDER" > "$TMP/order"
  while IFS='|' read -r name args; do
    [ -z "$name" ] && continue
    n=$((n+1))
    run_one "$r" "$name" "$args"
    echo "$r $n/$total $name $(date +%T)" > "$TMP/progress"
    [ $((n % 10)) -eq 0 ] && log "$r $n/$total signal: $(signal)"
  done < "$TMP/order"
  log "round $r done signal: $(signal)"
  r=$((r+1))
done
log "matrix $LABEL finished"
