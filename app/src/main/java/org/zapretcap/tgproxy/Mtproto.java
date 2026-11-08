package org.zapretcap.tgproxy;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Протокол MTProto obfuscated2: разбор приветствия клиента и шифры обеих сторон. */
final class Mtproto {
    static final int HANDSHAKE_LEN = 64;
    private static final int SKIP_LEN = 8;
    private static final int PREKEY_LEN = 32;
    private static final int IV_LEN = 16;
    private static final int PROTO_TAG_POS = 56;
    private static final int DC_IDX_POS = 60;

    static final byte[] TAG_ABRIDGED = {(byte) 0xef, (byte) 0xef, (byte) 0xef, (byte) 0xef};
    static final byte[] TAG_INTERMEDIATE = {(byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee};
    static final byte[] TAG_SECURE = {(byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd};

    static final Map<Integer, String> DC_DEFAULT_IPS = new HashMap<>();
    static final Map<Integer, String> DC_TEST_IPS = new HashMap<>();

    static final String WS_PATH = "/apiws";
    static final String WS_PATH_TEST = WS_PATH + "_test";

    private static final byte[][] RESERVED_STARTS = {
            {0x48, 0x45, 0x41, 0x44}, {0x50, 0x4F, 0x53, 0x54}, {0x47, 0x45, 0x54, 0x20},
            {(byte) 0xee, (byte) 0xee, (byte) 0xee, (byte) 0xee},
            {(byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd},
            {0x16, 0x03, 0x01, 0x02}, {0x4F, 0x50, 0x54, 0x49},
    };
    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        DC_DEFAULT_IPS.put(1, "149.154.175.50");
        DC_DEFAULT_IPS.put(2, "149.154.167.51");
        DC_DEFAULT_IPS.put(3, "149.154.175.100");
        DC_DEFAULT_IPS.put(4, "149.154.167.91");
        DC_DEFAULT_IPS.put(5, "149.154.171.5");
        DC_DEFAULT_IPS.put(203, "91.105.192.100");
        DC_TEST_IPS.put(1, "149.154.175.10");
        DC_TEST_IPS.put(2, "149.154.167.40");
        DC_TEST_IPS.put(3, "149.154.175.117");
    }

    private Mtproto() {
    }

    static final class Handshake {
        final int dc;
        final boolean media;
        final byte[] protoTag;
        final byte[] prekeyAndIv;

        Handshake(int dc, boolean media, byte[] protoTag, byte[] prekeyAndIv) {
            this.dc = dc;
            this.media = media;
            this.protoTag = protoTag;
            this.prekeyAndIv = prekeyAndIv;
        }
    }

    /** Потоковый AES-CTR. Каждый экземпляр продолжает свою гамму с места, где остановился. */
    static final class AesCtr {
        private final Cipher cipher;

        AesCtr(byte[] key, byte[] iv) {
            try {
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        byte[] update(byte[] data) {
            return update(data, 0, data.length);
        }

        byte[] update(byte[] data, int offset, int length) {
            byte[] out = new byte[length];
            try {
                int written = cipher.update(data, offset, length, out, 0);
                if (written != length) {
                    // CTR потоковый: провайдер, придерживающий хвост блока, сломал бы весь протокол
                    throw new IllegalStateException("AES-CTR buffered output: " + written + "/" + length);
                }
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
            return out;
        }
    }

    static final class CryptoCtx {
        final AesCtr cltDec;
        final AesCtr cltEnc;
        final AesCtr tgEnc;
        final AesCtr tgDec;

        CryptoCtx(AesCtr cltDec, AesCtr cltEnc, AesCtr tgEnc, AesCtr tgDec) {
            this.cltDec = cltDec;
            this.cltEnc = cltEnc;
            this.tgEnc = tgEnc;
            this.tgDec = tgDec;
        }
    }

    static byte[] sha256(byte[] first, byte[] second) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(first);
            digest.update(second);
            return digest.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** null: неверный ключ или неизвестный протокол. */
    static Handshake tryHandshake(byte[] handshake, byte[] secret) {
        byte[] prekeyAndIv = Arrays.copyOfRange(handshake, SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
        byte[] prekey = Arrays.copyOf(prekeyAndIv, PREKEY_LEN);
        byte[] iv = Arrays.copyOfRange(prekeyAndIv, PREKEY_LEN, PREKEY_LEN + IV_LEN);
        byte[] decrypted = new AesCtr(sha256(prekey, secret), iv).update(handshake);

        byte[] tag = Arrays.copyOfRange(decrypted, PROTO_TAG_POS, PROTO_TAG_POS + 4);
        if (!Arrays.equals(tag, TAG_ABRIDGED) && !Arrays.equals(tag, TAG_INTERMEDIATE) && !Arrays.equals(tag, TAG_SECURE)) {
            return null;
        }
        int dcIdx = (short) ((decrypted[DC_IDX_POS] & 0xff) | (decrypted[DC_IDX_POS + 1] << 8));
        return new Handshake(Math.abs(dcIdx), dcIdx < 0, tag, prekeyAndIv);
    }

    private static boolean reserved(byte[] rnd) {
        if ((rnd[0] & 0xff) == 0xEF) {
            return true;
        }
        for (byte[] start : RESERVED_STARTS) {
            if (rnd[0] == start[0] && rnd[1] == start[1] && rnd[2] == start[2] && rnd[3] == start[3]) {
                return true;
            }
        }
        return rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0;
    }

    static byte[] generateRelayInit(byte[] protoTag, int dcIdx) {
        byte[] rnd = new byte[HANDSHAKE_LEN];
        do {
            RANDOM.nextBytes(rnd);
        } while (reserved(rnd));

        byte[] key = Arrays.copyOfRange(rnd, SKIP_LEN, SKIP_LEN + PREKEY_LEN);
        byte[] iv = Arrays.copyOfRange(rnd, SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
        byte[] encrypted = new AesCtr(key, iv).update(rnd);

        byte[] tail = new byte[8];
        System.arraycopy(protoTag, 0, tail, 0, 4);
        tail[4] = (byte) dcIdx;
        tail[5] = (byte) (dcIdx >> 8);
        byte[] filler = new byte[2];
        RANDOM.nextBytes(filler);
        tail[6] = filler[0];
        tail[7] = filler[1];

        byte[] result = rnd.clone();
        for (int i = 0; i < 8; i++) {
            result[PROTO_TAG_POS + i] = (byte) (tail[i] ^ encrypted[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i]);
        }
        return result;
    }

    private static byte[] reversed(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = data[data.length - 1 - i];
        }
        return out;
    }

    static CryptoCtx buildCryptoCtx(byte[] clientPrekeyAndIv, byte[] secret, byte[] relayInit) {
        byte[] zero = new byte[HANDSHAKE_LEN];

        byte[] cltDecKey = sha256(Arrays.copyOf(clientPrekeyAndIv, PREKEY_LEN), secret);
        byte[] cltDecIv = Arrays.copyOfRange(clientPrekeyAndIv, PREKEY_LEN, PREKEY_LEN + IV_LEN);
        byte[] cltEncPrekeyIv = reversed(clientPrekeyAndIv);
        byte[] cltEncKey = sha256(Arrays.copyOf(cltEncPrekeyIv, PREKEY_LEN), secret);
        byte[] cltEncIv = Arrays.copyOfRange(cltEncPrekeyIv, PREKEY_LEN, PREKEY_LEN + IV_LEN);

        AesCtr cltDec = new AesCtr(cltDecKey, cltDecIv);
        AesCtr cltEnc = new AesCtr(cltEncKey, cltEncIv);
        // клиентская гамма уже потрачена на 64 байта приветствия
        cltDec.update(zero);

        byte[] relayEncKey = Arrays.copyOfRange(relayInit, SKIP_LEN, SKIP_LEN + PREKEY_LEN);
        byte[] relayEncIv = Arrays.copyOfRange(relayInit, SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
        byte[] relayDec = reversed(Arrays.copyOfRange(relayInit, SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN));

        AesCtr tgEnc = new AesCtr(relayEncKey, relayEncIv);
        AesCtr tgDec = new AesCtr(Arrays.copyOf(relayDec, PREKEY_LEN),
                Arrays.copyOfRange(relayDec, PREKEY_LEN, PREKEY_LEN + IV_LEN));
        tgEnc.update(zero);

        return new CryptoCtx(cltDec, cltEnc, tgEnc, tgDec);
    }

    static String[] wsDomains(int dc, boolean media) {
        int name = dc == 203 ? 2 : dc;
        if (!media) {
            return new String[]{"kws" + name + ".web.telegram.org"};
        }
        return new String[]{"kws" + name + "-1.web.telegram.org", "kws" + name + ".web.telegram.org"};
    }
}
