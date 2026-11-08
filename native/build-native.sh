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
LD_FLAGS="-pie -Wl,--gc-sections -s $PAGE_FLAGS"

build_ciadpi()
{
	local src="$TP/byedpi"
	# shellcheck disable=SC2086
	$CC $OPT_FLAGS $CPU -std=gnu99 -D_GNU_SOURCE -D_DEFAULT_SOURCE -I"$src" -Wno-everything \
		"$src"/packets.c "$src"/main.c "$src"/conev.c "$src"/proxy.c "$src"/desync.c "$src"/mpool.c "$src"/extend.c \
		$LD_FLAGS -o "$OUT/$ABI/libciadpi.so"
}

build_hev()
{
	# имя класса Java, в котором библиотека регистрирует свои функции
	"$NDK/ndk-build" -s -j"$JOBS" -C "$TP/hev-socks5-tunnel" \
		NDK_PROJECT_PATH="$TP/hev-socks5-tunnel" \
		APP_BUILD_SCRIPT="$TP/hev-socks5-tunnel/Android.mk" \
		NDK_APPLICATION_MK="$TP/hev-socks5-tunnel/Application.mk" \
		NDK_OUT="$WORK/hev/obj" NDK_LIBS_OUT="$WORK/hev/libs" \
		APP_ABI="$ABI" APP_PLATFORM="android-$API" APP_MODULES=hev-socks5-tunnel \
		APP_CFLAGS="-O3 -DPKGNAME=org/zapretcap/app -DCLSNAME=TunBridge"
	cp "$WORK/hev/libs/$ABI/libhev-socks5-tunnel.so" "$OUT/$ABI/"
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
