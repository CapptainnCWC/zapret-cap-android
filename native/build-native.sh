#!/usr/bin/env bash
# Собирает нативные части APK из исходников в third_party:
#   libciadpi.so             ByeDPI, движок обхода (исполняемый файл)
#   libhev-socks5-tunnel.so  мост между VPN-интерфейсом и ciadpi (библиотека JNI)
#   libnfqws2.so             nfqws2 из zapret2, движок режима root (исполняемый файл)
#
# Исполняемые файлы называются lib*.so, потому что запускать программы Android разрешает
# только из папки нативных библиотек приложения, а туда попадают файлы только с таким именем.
#
#   native/build-native.sh NDK_DIR OUT_DIR [ABI...]
set -euo pipefail

NDK="$1"
OUT="$2"
shift 2
ABIS=("$@")
[ ${#ABIS[@]} -gt 0 ] || ABIS=(arm64-v8a armeabi-v7a x86_64 x86)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TP="$HERE/third_party"
BUILD="$HERE/build"
API=24
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
JOBS="$(nproc)"

# страницы 16 КБ: без этого приложение не запустится на новых устройствах с такими страницами
PAGE_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
OPT_FLAGS="-Os -ffunction-sections -fdata-sections -fPIE"
# пути к исходникам попадают в сообщения assert; без замены в APK был бы путь к папке на компьютере сборщика.
# Отдельной переменной в кавычках: в пути может быть пробел
PREFIX_MAP="-ffile-prefix-map=$TP/=third_party/"
LD_FLAGS="-pie -Wl,--gc-sections -s $PAGE_FLAGS"

build_ciadpi()
{
	local src="$TP/byedpi"
	# shellcheck disable=SC2086
	$CC $OPT_FLAGS "$PREFIX_MAP" $CPU -std=gnu99 -D_GNU_SOURCE -D_DEFAULT_SOURCE -I"$src" -Wno-everything \
		"$src"/packets.c "$src"/main.c "$src"/conev.c "$src"/proxy.c "$src"/desync.c "$src"/mpool.c "$src"/extend.c \
		$LD_FLAGS -o "$OUT/$ABI/libciadpi.so"
}

# nfqws2 для режима root: настоящий движок zapret2, тот же, что в Linux-версии. Библиотеки netfilter и Lua
# собираются из исходников и линкуются статически: на телефоне их нет.
build_nfqws2()
{
	local work="$WORK/nfq" src="$TP/../nfq2" lua="$TP/lua/src"
	local nfnl="$TP/libnfnetlink" mnl="$TP/libmnl" nfq="$TP/libnetfilter_queue"
	local f objs want=0
	mkdir -p "$work/lua" "$work/lib"
	# библиотеки netfilter ждут config.h от autoconf: нужен только признак видимости символов
	printf '#define HAVE_VISIBILITY_HIDDEN 1\n' > "$work/config.h"
	# shellcheck disable=SC2086
	{
		for f in "$lua"/*.c; do
			case "$(basename "$f")" in lua.c|luac.c|onelua.c) continue ;; esac
			want=$((want + 1))
			$CC $OPT_FLAGS "$PREFIX_MAP" $CPU -DLUA_USE_POSIX -Wno-everything -c "$f" -o "$work/lua/$(basename "$f" .c).o" &
		done
		for f in "$nfnl"/src/*.c "$mnl"/src/*.c "$nfq"/src/*.c "$nfq"/src/extra/*.c; do
			want=$((want + 1))
			$CC $OPT_FLAGS "$PREFIX_MAP" $CPU -D_GNU_SOURCE -DNFNL_EXPORT= -Wno-everything \
				-I"$work" -I"$nfnl/include" -I"$mnl/include" -I"$nfq/include" -I"$nfq/src" \
				-c "$f" -o "$work/lib/$(echo "$f" | md5sum | cut -c1-8)-$(basename "$f" .c).o" &
		done
		wait
	}
	objs="$(ls "$work"/lua/*.o "$work"/lib/*.o)"
	# компиляция идёт параллельно, и ошибка одного файла иначе всплыла бы только при линковке
	if [ "$(printf '%s\n' "$objs" | wc -l)" != "$want" ]; then
		echo "nfqws2: не все файлы библиотек собрались" >&2
		return 1
	fi
	# shellcheck disable=SC2086
	$CC $OPT_FLAGS "$PREFIX_MAP" $CPU -std=gnu99 -D_GNU_SOURCE -Wno-everything \
		-I"$src" -I"$lua" -I"$nfnl/include" -I"$mnl/include" -I"$nfq/include" \
		"$src"/*.c "$src"/crypto/*.c "$src"/andr/*.c $objs \
		-lz -lm -llog $LD_FLAGS -o "$OUT/$ABI/libnfqws2.so"
}

# ndk-build не работает, если в пути к проекту есть пробел (например, диск «ssd 500»).
# Тогда исходники hev копируются во временную папку без пробелов и собираются там.
HEV_SRC="$TP/hev-socks5-tunnel"
HEV_TMP=""
if [[ "$HERE" == *" "* ]]; then
	HEV_TMP="$(mktemp -d "${TMPDIR:-/tmp}/zapret-cap-ndk.XXXXXX")"
	trap 'rm -rf "$HEV_TMP"' EXIT
	cp -a "$HEV_SRC" "$HEV_TMP/"
	HEV_SRC="$HEV_TMP/hev-socks5-tunnel"
fi

build_hev()
{
	local work="$WORK/hev"
	[ -z "$HEV_TMP" ] || work="$HEV_TMP/out/$ABI"
	# имя класса Java, в котором библиотека регистрирует свои функции
	"$NDK/ndk-build" -s -j"$JOBS" -C "$HEV_SRC" \
		NDK_PROJECT_PATH="$HEV_SRC" \
		APP_BUILD_SCRIPT="$HEV_SRC/Android.mk" \
		NDK_APPLICATION_MK="$HEV_SRC/Application.mk" \
		NDK_OUT="$work/obj" NDK_LIBS_OUT="$work/libs" \
		APP_ABI="$ABI" APP_PLATFORM="android-$API" APP_MODULES=hev-socks5-tunnel \
		APP_CFLAGS="-O3 -DPKGNAME=org/zapretcap/app -DCLSNAME=TunBridge -ffile-prefix-map=$HEV_SRC/=third_party/hev-socks5-tunnel/"
	cp "$work/libs/$ABI/libhev-socks5-tunnel.so" "$OUT/$ABI/"
}

for ABI in "${ABIS[@]}"; do
	CPU=""
	case "$ABI" in
		arm64-v8a) TARGET=aarch64-linux-android ;;
		armeabi-v7a) TARGET=armv7a-linux-androideabi; CPU="-mthumb" ;;
		x86_64) TARGET=x86_64-linux-android ;;
		x86) TARGET=i686-linux-android ;;
		*) echo "unknown ABI: $ABI" >&2; exit 1 ;;
	esac
	echo "== $ABI"
	CC="$TC/bin/clang --target=$TARGET$API"
	WORK="$BUILD/$ABI"
	rm -rf "$WORK" "${OUT:?}/$ABI"
	mkdir -p "$WORK" "$OUT/$ABI"
	build_ciadpi
	build_hev
	build_nfqws2
	"$TC/bin/llvm-strip" -s "$OUT/$ABI/libciadpi.so" "$OUT/$ABI/libnfqws2.so"
	ls -la "$OUT/$ABI" | awk 'NR>1 && $NF ~ /lib/ { print "   " $5, $NF }'
done
