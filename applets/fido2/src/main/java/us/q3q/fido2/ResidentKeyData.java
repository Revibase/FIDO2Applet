package us.q3q.fido2;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

/**
 * Stores discoverable (resident) credential metadata.
 * Persists private key (Java Card ECPrivateKey), encrypted user.id, and public key.
 * External FIDO credential ID is the compressed form of {@link #publicKey}.
 * user.name and RP ID are not stored (never returned / never enforced).
 */
public class ResidentKeyData {
    private static final short IV_LEN = 16;
    private static final short KEY_POINT_LENGTH = 32;
    private static final short CREDENTIAL_ID_LEN = 33;

    private final byte[] IVs;
    private final ECPrivateKey privateKey;
    private byte[] userId;
    private byte userIdLength;
    private final byte[] publicKey;

    public ResidentKeyData(RandomData random,
                           byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength) {
        IVs = new byte[IV_LEN];
        random.generateData(IVs, (short) 0, IV_LEN);

        privateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        P256Constants.setCurve(privateKey);

        publicKey = new byte[publicKeyLength];
        Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                publicKey, (short) 0, publicKeyLength);
    }

    /**
     * Stores the private scalar once. Must not be called again for this resident key.
     */
    public void setPrivateKey(byte[] sBuffer, short sOffset) {
        if (privateKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        privateKey.setS(sBuffer, sOffset, KEY_POINT_LENGTH);
    }

    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    public boolean hasPrivateKey() {
        return privateKey.isInitialized();
    }

    /**
     * Writes the 33-byte compressed secp256r1 public key used as the FIDO credential ID.
     * Stored public key must be uncompressed SEC1 ({@code 0x04||X||Y}).
     */
    public short packCredentialId(byte[] outBuffer, short outOffset) {
        // publicKey[0]=0x04; X at [1..32]; Y LSB at [64]
        outBuffer[outOffset] = (byte) (0x02 | (publicKey[64] & 1));
        Util.arrayCopyNonAtomic(publicKey, (short) 1, outBuffer, (short) (outOffset + 1), KEY_POINT_LENGTH);
        return CREDENTIAL_ID_LEN;
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
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, (short) 0, IV_LEN);
        wrapper.doFinal(userIdBuffer, userIdOffset, encLen, userId, (short) 0);
        this.userIdLength = userIdLength;
    }

    public void unpackUserID(AESKey key, Cipher unwrapper, byte[] targetBuffer, short targetOffset) {
        unwrapper.init(key, Cipher.MODE_DECRYPT, IVs, (short) 0, IV_LEN);
        unwrapper.doFinal(userId, (short) 0, (short) userId.length,
                targetBuffer, targetOffset);
    }

    public void unpackPublicKey(byte[] targetBuffer, short targetOffset) {
        Util.arrayCopyNonAtomic(publicKey, (short) 0,
                targetBuffer, targetOffset, (short) publicKey.length);
    }

    public short getUserIdLength() {
        return userIdLength;
    }
}
