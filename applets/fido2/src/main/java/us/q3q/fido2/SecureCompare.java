package us.q3q.fido2;

/**
 * Constant-time byte-array comparison for secret-dependent checks.
 */
public final class SecureCompare {
    private SecureCompare() {
    }

    public static boolean eq(byte[] a, short offA, byte[] b, short offB, short len) {
        short diff = 0;
        for (short i = 0; i < len; i++) {
            diff |= (short) (a[(short) (offA + i)] ^ b[(short) (offB + i)]);
        }
        return diff == 0;
    }
}
