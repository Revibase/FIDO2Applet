package us.q3q.fido2;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Per-session request/response state, held in one small CLEAR_ON_DESELECT byte array so it
 * costs almost no RAM and is wiped automatically on deselect.
 *
 * <p>Layout of {@code tempBytes} ({@value #NUM_RESET_BYTES} bytes):
 * <pre>
 *   [0..1] stored index    scratch (offset into the request buffer) — {@code setStoredVars}
 *   [2]    stored length   scratch (paired with the index)
 *   [3..4] outgoing response continuation: write offset
 *   [5..6] outgoing response continuation: bytes remaining
 *   [7..8] incoming command-chaining read offset
 *   [9]    boolean omnibus: bit flags packed into one byte (see BOOL_IDX_* and 0x02 = x5c)
 * </pre>
 * The {@code stored index/length} pair is reused as a general "return two values from a
 * parser" channel (e.g. the located rp/user {@code id}). Everything here is transient.
 */
public final class TransientStorage {
    private final byte[] tempBytes;
    private static final byte IDX_TEMP_BUF_IDX_STORAGE = 0; // 2 bytes
    private static final byte IDX_TEMP_BUF_IDX_LEN = 2; // 1 byte
    private static final byte IDX_CONTINUATION_OUTGOING_WRITE_OFFSET = 3; // 2 bytes
    private static final byte IDX_CONTINUATION_OUTGOING_REMAINING = 5; // 2 bytes
    private static final byte IDX_CHAINING_INCOMING_READ_OFFSET = 7; // 2 bytes
    private static final byte IDX_BOOLEAN_OMNIBUS = 9; // 1 byte
    private static final byte NUM_RESET_BYTES = 10;

    private static final byte BOOL_IDX_OPTION_RK = 3;
    private static final byte BOOL_IDX_OPTION_UP = 5;

    public TransientStorage() {
        tempBytes = JCSystem.makeTransientByteArray(NUM_RESET_BYTES, JCSystem.CLEAR_ON_DESELECT);
    }

    private boolean getBoolByIdx(byte idx) {
        return (byte) ((tempBytes[IDX_BOOLEAN_OMNIBUS] & (1 << idx))) != 0;
    }

    private void setBoolByIdx(byte idx, boolean val) {
        if (val) {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte) (tempBytes[IDX_BOOLEAN_OMNIBUS] | (1 << idx));
        } else {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte) (tempBytes[IDX_BOOLEAN_OMNIBUS] & ~(1 << idx));
        }
    }

    public boolean shouldStreamX5CLater() {
        return (tempBytes[IDX_BOOLEAN_OMNIBUS] & 0x02) != 0;
    }

    public void setStreamX5CLater(boolean stream) {
        if (stream) {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte) (tempBytes[IDX_BOOLEAN_OMNIBUS] | 0x02);
        } else {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte) (tempBytes[IDX_BOOLEAN_OMNIBUS] & 0xFD);
        }
    }

    public short getChainIncomingReadOffset() {
        return Util.getShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET);
    }

    public void resetChainIncomingReadOffset() {
        Util.setShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET, (short) 0);
    }

    public void increaseChainIncomingReadOffset(short numBytes) {
        Util.setShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET,
                (short) (Util.getShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET) + numBytes));
    }

    public void clearOnDeselect() {
        Util.arrayFillNonAtomic(tempBytes, (short) 0, NUM_RESET_BYTES, (byte) 0x00);
    }

    public void readyStoredVars() {
        setStoredVars((short) 0, (byte) -1);
    }

    public void setStoredVars(short idx, byte len) {
        Util.setShort(tempBytes, IDX_TEMP_BUF_IDX_STORAGE, idx);
        tempBytes[IDX_TEMP_BUF_IDX_LEN] = len;
    }

    public short getStoredIdx() {
        return Util.getShort(tempBytes, IDX_TEMP_BUF_IDX_STORAGE);
    }

    public byte getStoredLen() {
        return tempBytes[IDX_TEMP_BUF_IDX_LEN];
    }

    public void defaultOptions() {
        setBoolByIdx(BOOL_IDX_OPTION_RK, false);
        setBoolByIdx(BOOL_IDX_OPTION_UP, true);
    }

    public boolean hasRKOption() {
        return getBoolByIdx(BOOL_IDX_OPTION_RK);
    }

    public void setRKOption(boolean val) {
        setBoolByIdx(BOOL_IDX_OPTION_RK, val);
    }

    public boolean hasUPOption() {
        return getBoolByIdx(BOOL_IDX_OPTION_UP);
    }

    public void setUPOption(boolean val) {
        setBoolByIdx(BOOL_IDX_OPTION_UP, val);
    }

    public void setOutgoingContinuation(short offset, short remaining) {
        Util.setShort(tempBytes, IDX_CONTINUATION_OUTGOING_WRITE_OFFSET, offset);
        Util.setShort(tempBytes, IDX_CONTINUATION_OUTGOING_REMAINING, remaining);
    }

    public void clearOutgoingContinuation() {
        setOutgoingContinuation((short) 0, (short) 0);
        tempBytes[IDX_BOOLEAN_OMNIBUS] = (byte) (tempBytes[IDX_BOOLEAN_OMNIBUS] & 0xFC);
    }

    public short getOutgoingContinuationOffset() {
        return Util.getShort(tempBytes, IDX_CONTINUATION_OUTGOING_WRITE_OFFSET);
    }

    public short getOutgoingContinuationRemaining() {
        return Util.getShort(tempBytes, IDX_CONTINUATION_OUTGOING_REMAINING);
    }
}
