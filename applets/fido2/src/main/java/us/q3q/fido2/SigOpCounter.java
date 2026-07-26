package us.q3q.fido2;

import javacard.framework.JCSystem;

/**
 * 32-bit monotonic counter with wear-leveling, so no single flash byte is rewritten too often.
 *
 * <p><b>Layout (67 bytes):</b> {@code firstBytes[0..2]} are the high 24 bits; the low 8 bits
 * live in one of the 64 {@code lastBytes} slots, selected by {@code firstBytes[2] & 0x3F}.
 * The packed value is {@code firstBytes[0] firstBytes[1] firstBytes[2] lastBytes[idx]}. A
 * normal increment only rewrites that one low byte; when it overflows we bump the high bytes
 * and move to the next slot (resetting it), which advances {@code firstBytes[2]} and so keeps
 * the packed value strictly increasing. The hottest byte is written 256 times in a row but
 * carries only 1/64 of the total write load.
 *
 * <p>Every increment is persisted immediately in a transaction (no RAM batching): a power
 * loss mid-operation must never roll the counter backwards.
 */
public final class SigOpCounter {
    private final byte[] firstBytes;
    private final byte[] lastBytes;

    public SigOpCounter() {
        firstBytes = new byte[3];
        lastBytes = new byte[64];
    }

    /**
     * Atomically increase the counter value, persisting to EEPROM.
     *
     * @param amt Amount by which to increase the counter
     * @return false if the counter has hit max - true otherwise
     */
    public boolean increment(short amt) {
        return incrementInternal(amt, true);
    }

    private boolean incrementInternal(short amt, boolean transactional) {
        boolean ok = false;

        if (transactional) {
            JCSystem.beginTransaction();
        }
        short lbIdx = (short)(0x3F & firstBytes[2]);
        try {
            short curLast = (short)(lastBytes[lbIdx] & 0xFF);
            short amountLeftInLast = (short)(0x00FF - curLast);
            if (amountLeftInLast < amt) {
                // Increase the higher-order bytes and move to next lower-order byte slot
                if (firstBytes[2] == (byte) 0xFF) {
                    if (firstBytes[1] == (byte) 0xFF) {
                        if (firstBytes[0] == (byte) 0xFF) {
                            // Completely full up.
                            return false;
                        }
                        firstBytes[0]++;
                        firstBytes[1] = 0;
                    } else {
                        firstBytes[1]++;
                    }
                    firstBytes[2] = 0;
                } else {
                    firstBytes[2]++;
                }
                lastBytes[(short)(0x3F & firstBytes[2])] = (byte)(amt - amountLeftInLast);
            } else {
                // Straightforward increase of lower-order byte
                lastBytes[lbIdx] = (byte)(lastBytes[lbIdx] + amt);
            }
            ok = true;
        } finally {
            if (transactional) {
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }
        }

        return true;
    }

    /**
     * Packs counter as a 32-bit (4 byte) integer into the output.
     *
     * @param outBuf Buffer into which to encode counter
     * @param outOffset Offset at which to start writing counter
     */
    public void pack(byte[] outBuf, short outOffset) {
        outBuf[outOffset++] = firstBytes[0];
        outBuf[outOffset++] = firstBytes[1];
        outBuf[outOffset++] = firstBytes[2];
        outBuf[outOffset++] = lastBytes[(short)(0x3F & firstBytes[2])];
    }

    /**
     * Returns true if the counter still has its initial value
     *
     * @return true if the counter is zero
     */
    public boolean isZero() {
        return firstBytes[0] == 0 && firstBytes[1] == 0
                && firstBytes[2] == 0 && lastBytes[0] == 0;
    }
}
