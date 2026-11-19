# Библиотека hev-socks5-tunnel находит этот класс и его методы по имени при загрузке
-keep class org.zapretcap.app.TunBridge { *; }

# DNS режима root запускается через app_process по имени класса
-keep class org.zapretcap.app.DnsMain { public static void main(java.lang.String[]); }
# youtubedl-android: классы вызываются из Kotlin и читают ответы через jackson
-keep class com.yausername.** { *; }
# распаковка Python: commons-compress создаёт обработчики полей ZIP по списку классов через рефлексию,
# после переименования R8 он падал на «class ... is not a concrete class»
-keep class org.apache.commons.compress.** { *; }
-keep class org.apache.commons.io.** { *; }
-keep class com.fasterxml.jackson.** { *; }
-dontwarn org.apache.commons.compress.**
-dontwarn com.fasterxml.jackson.**
-dontwarn java.beans.**
