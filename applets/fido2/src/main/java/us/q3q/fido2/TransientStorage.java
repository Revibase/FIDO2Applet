package us.q3q.fido2;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Provides in-memory state in a maximally compact way
 */
public final class TransientStorage {
    private final byte[] tempBytes;
    private static final byte IDX_TEMP_BUF_IDX_STORAGE = 0; // 2 bytes
    private static final byte IDX_TEMP_BUF_IDX_LEN = 2; // 1 byte
    private static final byte IDX_TEMP_BUF_IDX2_STORAGE = 3; // 2 bytes
    private static final byte IDX_TEMP_BUF_IDX2_LEN = 5; // 1 byte
    private static final byte IDX_CONTINUATION_OUTGOING_WRITE_OFFSET = 6; // 2 bytes
    private static final byte IDX_CONTINUATION_OUTGOING_REMAINING = 8; // 2 bytes
    private static final byte IDX_CHAINING_INCOMING_READ_OFFSET = 10; // 2 bytes
    private static final byte IDX_BOOLEAN_OMNIBUS = 12; // 1 byte
    private static final byte NUM_RESET_BYTES = 13;

    private static final byte BOOL_IDX_STREAM_STATEKEEPING = 0;
    private static final byte BOOL_IDX_OPTION_RK = 3;
    private static final byte BOOL_IDX_AUTHENTICATOR_DISABLED = 4;

    public TransientStorage() {
        tempBytes = JCSystem.makeTransientByteArray(NUM_RESET_BYTES, JCSystem.CLEAR_ON_DESELECT);
    }

    private boolean getBoolByIdx(byte idx) {
        return (byte)((tempBytes[IDX_BOOLEAN_OMNIBUS] & (1 << idx))) != 0;
    }

    private void setBoolByIdx(byte idx, boolean val) {
        if (val) {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte)(tempBytes[IDX_BOOLEAN_OMNIBUS] | (1 << idx));
        } else {
            tempBytes[IDX_BOOLEAN_OMNIBUS] =
                    (byte)(tempBytes[IDX_BOOLEAN_OMNIBUS] & ~(1 << idx));
        }
    }

    public boolean authenticatorDisabled() {
        return getBoolByIdx(BOOL_IDX_AUTHENTICATOR_DISABLED);
    }

    public void disableAuthenticator() {
        setBoolByIdx(BOOL_IDX_AUTHENTICATOR_DISABLED, true);
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
                (short)(Util.getShort(tempBytes, IDX_CHAINING_INCOMING_READ_OFFSET) + numBytes));
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

    public void setStoredVars2(short idx, byte len) {
        Util.setShort(tempBytes, IDX_TEMP_BUF_IDX2_STORAGE, idx);
        tempBytes[IDX_TEMP_BUF_IDX2_LEN] = len;
    }

    public short getStoredIdx2() {
        return Util.getShort(tempBytes, IDX_TEMP_BUF_IDX2_STORAGE);
    }

    public byte getStoredLen2() {
        return tempBytes[IDX_TEMP_BUF_IDX2_LEN];
    }

    public void defaultOptions() {
        setBoolByIdx(BOOL_IDX_OPTION_RK, false);
    }

    public boolean hasRKOption() {
        return getBoolByIdx(BOOL_IDX_OPTION_RK);
    }

    public void setRKOption(boolean val) {
        setBoolByIdx(BOOL_IDX_OPTION_RK, val);
    }

    public void setOutgoingContinuation(short offset, short remaining) {
        Util.setShort(tempBytes, IDX_CONTINUATION_OUTGOING_WRITE_OFFSET, offset);
        Util.setShort(tempBytes, IDX_CONTINUATION_OUTGOING_REMAINING, remaining);
    }

    public void clearOutgoingContinuation() {
        setOutgoingContinuation((short) 0, (short) 0);
        tempBytes[IDX_BOOLEAN_OMNIBUS] = (byte)(tempBytes[IDX_BOOLEAN_OMNIBUS] & 0xFC);
    }

    public short getOutgoingContinuationOffset() {
        return Util.getShort(tempBytes, IDX_CONTINUATION_OUTGOING_WRITE_OFFSET);
    }

    public short getOutgoingContinuationRemaining() {
        return Util.getShort(tempBytes, IDX_CONTINUATION_OUTGOING_REMAINING);
    }
}
