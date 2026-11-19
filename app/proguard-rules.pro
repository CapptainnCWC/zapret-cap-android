# Библиотека hev-socks5-tunnel находит этот класс и его методы по имени при загрузке
-keep class org.zapretcap.app.TunBridge { *; }

# youtubedl-android: классы вызываются из Kotlin и читают ответы через jackson
-keep class com.yausername.** { *; }
-dontwarn com.fasterxml.jackson.**
-dontwarn java.beans.**
