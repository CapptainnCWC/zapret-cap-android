#!/system/bin/sh
# Что проходит в режиме белых списков, без обхода: TCP и UDP до разных адресов и разные DNS.
# Одна строка на проверку, чтобы сравнить типы трафика в одну и ту же минуту.
#   phone-white.sh LABEL      результат: $ROOT/out/LABEL.white
ROOT=/data/local/tmp/zc
OUT=$ROOT/out/$1.white
QUIC=$ROOT/assets/fake/quic_initial_www_google_com.bin
tcp() {  # имя хост адрес
  r=$(curl -s -o /dev/null --connect-timeout 3 -m 5 --resolve "$2:443:$3" -w 'code=%{http_code} rc=%{exitcode} conn=%{time_connect} tls=%{time_appconnect}' "https://$2/" 2>/dev/null)
  echo "$(date +%T) TCP  $1 $3 $r" >> "$OUT"
}
udp() {  # имя файл адрес порт: сколько байт пришло в ответ
  n=$(timeout 3 nc -u -w 2 "$3" "$4" < "$2" 2>/dev/null | wc -c)
  echo "$(date +%T) UDP  $1 $3:$4 reply_bytes=$n" >> "$OUT"
}
# адреса из любого прошлого прогона: в режиме белого списка DoH для их получения недоступен
ip_of() { cat "$ROOT"/out/*.resolve 2>/dev/null | grep "^$1 " | cut -d' ' -f2 | grep -v none | head -1; }
echo "$(date +%T) iface=$(ip -o -4 addr | grep rmnet | awk '{print $2,$4}' | tr '\n' ' ') dns=$(getprop net.dns1) $(dumpsys connectivity 2>/dev/null | grep -m1 -oE 'ni\{MOBILE[^}]*\}')" >> "$OUT"
dumpsys connectivity 2>/dev/null | grep -m3 -oE 'DnsAddresses: \[[^]]*\]' >> "$OUT"
for h in ya.ru vk.com www.ozon.ru www.google.com www.youtube.com i.ytimg.com youtubei.googleapis.com discord.com; do
  tcp "$h" "$h" "$(ip_of "$h")" &
done
wait
# Системное разрешение имён: что видит браузер без VPN
for h in ya.ru www.youtube.com discord.com; do
  r=$(curl -s -o /dev/null --connect-timeout 4 -m 6 -w 'ip=%{remote_ip} code=%{http_code} rc=%{exitcode} dns=%{time_namelookup}' "https://$h/" 2>/dev/null)
  echo "$(date +%T) SYS  $h $r" >> "$OUT"
done
# QUIC: настоящий Initial к серверам Google и другим, ответ значит, что UDP доходит
for h in www.youtube.com www.google.com i.ytimg.com; do
  udp "quic-$h" "$QUIC" "$(ip_of "$h")" 443 &
done
udp quic-cloudflare "$QUIC" 1.1.1.1 443 &
udp quic-ya "$QUIC" "$(ip_of ya.ru)" 443 &
wait
# DNS: те, что задаёт VPN, и те, что могут быть в белом списке
for d in 1.1.1.1 8.8.8.8 77.88.8.8 77.88.8.1 195.208.4.1 "$(getprop net.dns1)"; do
  [ -z "$d" ] && continue
  udp "dns-ya" "$ROOT/dns-ya.bin" "$d" 53 &
  udp "dns-youtube" "$ROOT/dns-youtube.bin" "$d" 53 &
done
wait
echo "$(date +%T) ---" >> "$OUT"
