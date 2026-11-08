#!/system/bin/sh
# Сколько прыжков до серверов: фейк с TTL больше этого числа дойдёт до сайта и сломает соединение.
#   phone-hops.sh LABEL     результат: $ROOT/out/LABEL.hops
ROOT=/data/local/tmp/zc
OUT=$ROOT/out/$1.hops
: > "$OUT"
for host in www.google.com ya.ru www.youtube.com i.ytimg.com discord.com www.cloudflare.com vk.com web.telegram.org; do
  ip=$(grep "^$host " "$ROOT/out/$1.resolve" 2>/dev/null | cut -d' ' -f2)
  [ -z "$ip" ] || [ "$ip" = none ] && { echo "$host none" >> "$OUT"; continue; }
  (
    t=1; path=""
    while [ $t -le 24 ]; do
      line=$(ping -c1 -W1 -t "$t" "$ip" 2>/dev/null | sed -n 2p)
      case "$line" in
        *"bytes from"*) echo "$host $ip reached=$t $line" >> "$OUT"; exit;;
        *"exceeded"*) path="$path $t:$(echo "$line" | awk '{print $2}')";;
      esac
      t=$((t+1))
    done
    echo "$host $ip reached=none path=$path" >> "$OUT"
  ) &
done
wait
