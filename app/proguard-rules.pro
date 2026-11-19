# Библиотека hev-socks5-tunnel находит этот класс и его методы по имени при загрузке
-keep class org.zapretcap.app.TunBridge { *; }

# DNS режима root запускается через app_process по имени класса
-keep class org.zapretcap.app.DnsMain { public static void main(java.lang.String[]); }
# youtubedl-android: классы вызываются из Kotlin и читают ответы через jackson
-keep class com.yausername.** { *; }
-dontwarn com.fasterxml.jackson.**
-dontwarn java.beans.**
