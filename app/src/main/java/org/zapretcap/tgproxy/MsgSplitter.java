package org.zapretcap.tgproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Делит поток TCP на отдельные пакеты MTProto: каждый уходит своим кадром WebSocket. */
final class MsgSplitter {
    private static final int ABRIDGED = 0xEFEFEFEF;
    private static final int INTERMEDIATE = 0xEEEEEEEE;
    private static final int PADDED_INTERMEDIATE = 0xDDDDDDDD;
    private static final int INCOMPLETE = -1;

    private final int proto;
    private byte[] cipher = new byte[0];
    private byte[] plain = new byte[0];
    private boolean disabled;

    MsgSplitter(byte[] protoTag) {
        proto = (protoTag[0] & 0xff) << 24 | (protoTag[1] & 0xff) << 16 | (protoTag[2] & 0xff) << 8 | (protoTag[3] & 0xff);
    }

    List<byte[]> split(byte[] chunk, byte[] plainChunk) {
        if (chunk.length == 0) {
            return Collections.emptyList();
        }
        if (disabled) {
            return Collections.singletonList(chunk);
        }
        cipher = concat(cipher, chunk);
        plain = concat(plain, plainChunk);

        List<byte[]> parts = new ArrayList<>();
        int offset = 0;
        while (offset < cipher.length) {
            int length = nextPacketLen(offset, cipher.length - offset);
            if (length == INCOMPLETE) {
                break;
            }
            if (length <= 0) {
                // длина не разбирается: дальше весь поток идёт как есть
                parts.add(Arrays.copyOfRange(cipher, offset, cipher.length));
                offset = cipher.length;
                disabled = true;
                break;
            }
            parts.add(offset == 0 && length == cipher.length ? cipher : Arrays.copyOfRange(cipher, offset, offset + length));
            offset += length;
        }
        if (offset > 0) {
            cipher = Arrays.copyOfRange(cipher, offset, cipher.length);
            plain = Arrays.copyOfRange(plain, offset, plain.length);
        }
        return parts;
    }

    List<byte[]> flush() {
        if (cipher.length == 0) {
            return Collections.emptyList();
        }
        List<byte[]> tail = Collections.singletonList(cipher);
        cipher = new byte[0];
        plain = new byte[0];
        return tail;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        if (first.length == 0) {
            return second;
        }
        byte[] out = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }

    private int nextPacketLen(int offset, int available) {
        if (proto == ABRIDGED) {
            return nextAbridgedLen(offset, available);
        }
        if (proto == INTERMEDIATE || proto == PADDED_INTERMEDIATE) {
            return nextIntermediateLen(offset, available);
        }
        return 0;
    }

    private int nextAbridgedLen(int offset, int available) {
        int first = plain[offset] & 0xff;
        int headerLen;
        long payload;
        if (first == 0x7F || first == 0xFF) {
            if (available < 4) {
                return INCOMPLETE;
            }
            payload = ((plain[offset + 1] & 0xffL) | (plain[offset + 2] & 0xffL) << 8 | (plain[offset + 3] & 0xffL) << 16) * 4;
            headerLen = 4;
        } else {
            payload = (first & 0x7FL) * 4;
            headerLen = 1;
        }
        if (payload <= 0) {
            return 0;
        }
        long packet = headerLen + payload;
        return available < packet ? INCOMPLETE : (int) packet;
    }

    private int nextIntermediateLen(int offset, int available) {
        if (available < 4) {
            return INCOMPLETE;
        }
        long payload = ((plain[offset] & 0xffL) | (plain[offset + 1] & 0xffL) << 8
                | (plain[offset + 2] & 0xffL) << 16 | (plain[offset + 3] & 0xffL) << 24) & 0x7FFFFFFFL;
        if (payload <= 0) {
            return 0;
        }
        long packet = 4 + payload;
        return available < packet ? INCOMPLETE : (int) Math.min(packet, Integer.MAX_VALUE);
    }
}
