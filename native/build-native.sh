#!/usr/bin/env bash
# Собирает нативные части APK из исходников в third_party:
#   libciadpi.so             ByeDPI, движок обхода (исполняемый файл)
#   libhev-socks5-tunnel.so  мост между VPN-интерфейсом и ciadpi (библиотека JNI)
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
	"$TC/bin/llvm-strip" -s "$OUT/$ABI/libciadpi.so"
	ls -la "$OUT/$ABI" | awk 'NR>1 && $NF ~ /lib/ { print "   " $5, $NF }'
done
