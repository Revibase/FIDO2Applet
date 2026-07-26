package us.q3q.fido2;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;

/**
 * Stores discoverable (resident) credential metadata: private key and public key.
 * Credential ID and getAssertion {@code user.id} are the compressed form of
 * {@link #publicKey}. Request {@code user.id} / user.name / RP ID are not stored.
 */
public class ResidentKeyData {
    private static final short KEY_POINT_LENGTH = 32;
    private static final short CREDENTIAL_ID_LEN = 33;

    private final ECPrivateKey privateKey;
    private final byte[] publicKey;

    public ResidentKeyData(byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength) {
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        P256Constants.setCurve(privateKey);

        publicKey = new byte[publicKeyLength];
        Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                publicKey, (short) 0, publicKeyLength);
    }

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

    public short packCredentialId(byte[] outBuffer, short outOffset) {
        outBuffer[outOffset] = (byte) (0x02 | (publicKey[64] & 1));
        Util.arrayCopyNonAtomic(publicKey, (short) 1, outBuffer, (short) (outOffset + 1), KEY_POINT_LENGTH);
        return CREDENTIAL_ID_LEN;
    }

    public void unpackPublicKey(byte[] targetBuffer, short targetOffset) {
        Util.arrayCopyNonAtomic(publicKey, (short) 0,
                targetBuffer, targetOffset, (short) publicKey.length);
    }
}
