#!/usr/bin/env bash
# Компилирует ядро прокси для компьютера. Запуск: tests/tgproxy-test.sh unit
#                                                 tests/tgproxy-test.sh cli [опции TgProxyCli]
set -eu
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${TGPROXY_BUILD:-$REPO/app/build/tgproxy-host}"
JAVA_HOME="${JAVA_HOME:-$HOME/Android/jdk}"
jar_of() { find "$HOME/.gradle/caches/modules-2" -name "$1" | grep -v sources | sort -V | tail -n1; }
CP="$(jar_of 'okhttp-4.12.0.jar'):$(jar_of 'okio-jvm-3.6.0.jar'):$(jar_of 'kotlin-stdlib-1.9.10.jar')"
rm -rf "$OUT"
mkdir -p "$OUT"
# при ошибке компиляции останавливаемся, а не запускаем старую сборку
build_log="$("$JAVA_HOME/bin/javac" -nowarn -Xlint:none --release 17 -cp "$CP" -d "$OUT" \
	"$REPO"/app/src/main/java/org/zapretcap/tgproxy/*.java "$REPO"/tests/tgproxy/*.java 2>&1)" || {
	printf '%s\n' "$build_log"
	exit 1
}
case "${1:-unit}" in
	unit) shift || true; exec "$JAVA_HOME/bin/java" -cp "$OUT:$CP" org.zapretcap.tgproxy.TgProxyUnit "$@" ;;
	cli) shift; exec "$JAVA_HOME/bin/java" -cp "$OUT:$CP" org.zapretcap.tgproxy.TgProxyCli "$@" ;;
esac
