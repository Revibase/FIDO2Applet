package org.openjavacard.ndef.stub;

import javacard.framework.Shareable;

/**
 * Shareable interface implemented by {@link NdefApplet} so FIDO2 can push the
 * signing key once (during {@code makeCredential}) while FIDO2 is selected and
 * AES decryption works normally.
 *
 * <p>After the push, NdefApplet signs URLs independently on every NDEF read —
 * no runtime Shareable call to FIDO2 is needed.
 *
 * <p>All parameters are primitives so no byte array ever crosses the applet
 * firewall boundary.
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
     * Atomically persists all previously received bytes and marks the key as
     * valid. After this returns, NdefApplet will sign URLs locally on every
     * NDEF read.
     */
    void commit();
}
