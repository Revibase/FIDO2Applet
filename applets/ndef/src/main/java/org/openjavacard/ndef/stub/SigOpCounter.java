package org.openjavacard.ndef.stub;

import javacard.framework.JCSystem;

/**
 * 32-bit always-increasing counter that avoids writing to the same flash location too often.
 *
 * <p>Duplicate of the FIDO2 wear-leveled counter (67 bytes EEPROM). Independent of the
 * FIDO2 counter. Every increment is persisted immediately: an NDEF tap is a full power
 * cycle with no deselect callback, so a RAM-only bump would be lost. The wear-leveled
 * layout keeps the common case to a single byte write.
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
        short lbIdx = (short) (0x3F & firstBytes[2]);
        try {
            short curLast = (short) (lastBytes[lbIdx] & 0xFF);
            short amountLeftInLast = (short) (0x00FF - curLast);
            if (amountLeftInLast < amt) {
                if (firstBytes[2] == (byte) 0xFF) {
                    if (firstBytes[1] == (byte) 0xFF) {
                        if (firstBytes[0] == (byte) 0xFF) {
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
                lastBytes[(short) (0x3F & firstBytes[2])] = (byte) (amt - amountLeftInLast);
            } else {
                lastBytes[lbIdx] = (byte) (lastBytes[lbIdx] + amt);
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
     */
    public void pack(byte[] outBuf, short outOffset) {
        outBuf[outOffset++] = firstBytes[0];
        outBuf[outOffset++] = firstBytes[1];
        outBuf[outOffset++] = firstBytes[2];
        outBuf[outOffset++] = lastBytes[(short) (0x3F & firstBytes[2])];
    }
}
