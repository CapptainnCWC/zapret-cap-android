#!/system/bin/sh
# Проверка режима root в эмуляторе. Там su пускает только оболочку adb, поэтому отладочная сборка
# кладёт свои root-скрипты в files/root-bridge, а этот цикл выполняет их от root:
#
#   adb root
#   adb shell run-as org.zapretcap.app mkdir -p files/root-bridge   (или mkdir от root)
#   adb push tests/root-bridge.sh /data/local/tmp/ && adb shell sh /data/local/tmp/root-bridge.sh
#
# На настоящем телефоне с Magisk или KernelSU мост не нужен: приложение вызывает su само.
PKG=org.zapretcap.app
D=/data/data/$PKG/files/root-bridge
OWNER=$(stat -c %u /data/data/$PKG)
mkdir -p $D && chown $OWNER:$OWNER $D
echo "root-bridge: жду скрипты в $D"
while true; do
	for f in $D/*.sh; do
		[ -f "$f" ] || continue
		b=${f%.sh}
		sh "$f" > "$b.out" 2>&1
		echo $? > "$b.rc.tmp"
		chown $OWNER:$OWNER "$b.out" "$b.rc.tmp"
		chmod 644 "$b.out" "$b.rc.tmp"
		mv "$b.rc.tmp" "$b.rc"
		rm -f "$f"
		echo "root-bridge: $(basename "$b") -> $(cat "$b.rc")"
	done
	sleep 0.1
done
