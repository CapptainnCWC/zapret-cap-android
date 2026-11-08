package org.zapretcap.app;

import android.os.Handler;
import android.os.Looper;

/** Что сейчас работает. Экран только показывает это состояние, менять его могут службы и потоки. */
final class AppState {
    enum Phase {OFF, STARTING, ON}

    interface Listener {
        void onStateChanged();
    }

    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static Listener listener;

    static volatile Phase phase = Phase.OFF;
    static volatile String strategy;
    static volatile String error;

    static volatile Phase tgPhase = Phase.OFF;
    static volatile org.zapretcap.tgproxy.TgWsProxy tgProxy;
    static volatile String tgError;

    private AppState() {
    }

    static void setListener(Listener newListener) {
        listener = newListener;
    }

    static void set(Phase newPhase, String newStrategy, String newError) {
        phase = newPhase;
        strategy = newStrategy;
        error = newError;
        notifyListener();
    }

    static void setTg(Phase newPhase, org.zapretcap.tgproxy.TgWsProxy proxy, String newError) {
        tgPhase = newPhase;
        tgProxy = proxy;
        tgError = newError;
        notifyListener();
    }

    private static void notifyListener() {
        MAIN.post(() -> {
            if (listener != null) {
                listener.onStateChanged();
            }
        });
    }
}
