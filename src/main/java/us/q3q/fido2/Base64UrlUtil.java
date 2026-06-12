package us.q3q.fido2;

/**
 * Base64url encoding (RFC 4648) without padding, for compact NDEF URL query values.
 */
public final class Base64UrlUtil {

    private static final byte[] ALPHABET = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };

    private Base64UrlUtil() {
    }

    /**
     * @return number of characters written
     */
    public static short encode(byte[] in, short inOff, short len, byte[] out, short outOff) {
        short pos = outOff;
        short i = 0;
        while (i < len) {
            final short remaining = (short) (len - i);
            final int b0 = in[(short) (inOff + i)] & 0xFF;
            if (remaining >= 3) {
                final int b1 = in[(short) (inOff + i + 1)] & 0xFF;
                final int b2 = in[(short) (inOff + i + 2)] & 0xFF;
                final int triple = (b0 << 16) | (b1 << 8) | b2;
                out[pos++] = ALPHABET[(triple >> 18) & 0x3F];
                out[pos++] = ALPHABET[(triple >> 12) & 0x3F];
                out[pos++] = ALPHABET[(triple >> 6) & 0x3F];
                out[pos++] = ALPHABET[triple & 0x3F];
                i = (short) (i + 3);
            } else if (remaining == 2) {
                final int b1 = in[(short) (inOff + i + 1)] & 0xFF;
                final int pair = (b0 << 8) | b1;
                out[pos++] = ALPHABET[(pair >> 10) & 0x3F];
                out[pos++] = ALPHABET[(pair >> 4) & 0x3F];
                out[pos++] = ALPHABET[(pair << 2) & 0x3F];
                i = (short) (i + 2);
            } else {
                out[pos++] = ALPHABET[(b0 >> 2) & 0x3F];
                out[pos++] = ALPHABET[(b0 << 4) & 0x3F];
                i = (short) (i + 1);
            }
        }
        return (short) (pos - outOff);
    }
}
