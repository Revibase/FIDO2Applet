package org.openjavacard.ndef.stub;

import javacard.framework.Shareable;

/**
 * Shareable interface implemented by {@link NdefApplet} so FIDO2 can push the
 * credential private key and compressed public key once during
 * {@code makeCredential} (while FIDO2 is selected).
 *
 * <p>Bytes land in CLEAR_ON_RESET staging. {@link #commit} only marks them ready;
 * NdefApplet AES-wraps on the first NDEF SELECT and signs on the first E104 read.
 * No runtime Shareable call back to FIDO2 is needed after the push.
 *
 * <p>All parameters are primitives so no byte array crosses the applet firewall.
 */
public interface NdefKeyStore extends Shareable {

    /** Service-parameter byte passed to {@code getShareableInterfaceObject}. */
    byte SERVICE_ID = (byte) 0x41;

    /** EC private key scalar length in bytes. */
    short PRIV_KEY_LEN = 32;

    /** Compressed SEC-1 public key length in bytes (0x02/0x03 + 32). */
    short PUB_KEY_LEN = 33;

    /**
     * Receives one byte of the 32-byte EC private key scalar.
     * Call for {@code offset} 0..31 before {@link #commit}.
     */
    void setPrivKeyByte(short offset, byte value);

    /**
     * Receives one byte of the 33-byte compressed public key.
     * Call for {@code offset} 0..32 before {@link #commit}.
     */
    void setPubKeyByte(short offset, byte value);

    /**
     * Marks previously received key bytes ready in transient staging.
     * Encryption into EEPROM happens on the first NDEF SELECT.
     */
    void commit();
}
