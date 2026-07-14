package us.q3q.fido2;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

/**
 * Stores discoverable (resident) credential metadata.
 * Persists credential ID, encrypted user.id, and public key only.
 * user.name and RP ID are not stored (never returned / never enforced).
 */
public class ResidentKeyData {
    private static final short IV_LEN = 16;
    private static final short USER_ID_IV_OFFSET = 0;

    private final byte[] IVs;
    private byte[] credential;
    private byte[] userId;
    private byte userIdLength;
    private final byte[] publicKey;

    public ResidentKeyData(RandomData random,
                           byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength) {
        IVs = new byte[IV_LEN];
        random.generateData(IVs, (short) 0, IV_LEN);

        publicKey = new byte[publicKeyLength];
        Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                publicKey, (short) 0, publicKeyLength);
    }

    public void setEncryptedCredential(byte[] credBuffer, short credOffset, short credLen) {
        if (credential != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        this.credential = new byte[credLen];
        Util.arrayCopy(credBuffer, credOffset,
                this.credential, (short) 0, credLen);
    }

    private short encryptableLength(short rawLength) {
        short num16s = (short) (rawLength >> 4);
        if ((rawLength & 0x0F) != 0) {
            num16s += 1;
        }
        return (short) (num16s * 16);
    }

    /**
     * Encrypt user.id into EEPROM in one write.
     * {@code userIdBuffer} must contain at least {@code encryptableLength(userIdLength)}
     * bytes from {@code userIdOffset} (zero-padded as needed).
     */
    public void setUser(AESKey key, Cipher wrapper,
                        byte[] userIdBuffer, short userIdOffset, byte userIdLength) {
        if (userId != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        short encLen = encryptableLength(userIdLength);
        userId = new byte[encLen];
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, USER_ID_IV_OFFSET, IV_LEN);
        wrapper.doFinal(userIdBuffer, userIdOffset, encLen, userId, (short) 0);
        this.userIdLength = userIdLength;
    }

    public void unpackUserID(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, IVs, USER_ID_IV_OFFSET, IV_LEN);
        unwrapper.doFinal(userId, (short) 0, (short) userId.length,
                targetBuffer, targetOffset);
    }

    public void unpackPublicKey(byte[] targetBuffer, short targetOffset) {
        Util.arrayCopyNonAtomic(publicKey, (short) 0,
                targetBuffer, targetOffset, (short) publicKey.length);
    }

    public byte[] getEncryptedCredentialID() {
        return credential;
    }

    public short getUserIdLength() {
        return userIdLength;
    }

    public short getCredLen() {
        return (short) credential.length;
    }
}
