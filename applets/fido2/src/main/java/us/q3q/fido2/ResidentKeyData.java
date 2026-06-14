package us.q3q.fido2;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

/**
 * Stores discoverable (resident) credential metadata.
 */
public class ResidentKeyData {
    private static final short IV_LEN = 16;

    private final byte[] IVs;
    private static final short USER_ID_IV_OFFSET = 0;
    private static final short USER_NAME_IV_OFFSET = USER_ID_IV_OFFSET + IV_LEN;
    private static final short RP_IV_OFFSET = USER_NAME_IV_OFFSET + IV_LEN;

    private byte[] credential;
    private byte[] userId;
    private byte userIdLength;
    private byte[] userName;
    private byte userNameLength;
    private byte[] rpId;
    private byte rpIdLength;
    private final byte[] publicKey;

    public ResidentKeyData(RandomData random, AESKey key, Cipher wrapper,
                           byte[] publicKeyBuffer, short publicKeyOffset, short publicKeyLength) {
        IVs = new byte[RP_IV_OFFSET + IV_LEN];
        random.generateData(IVs, (short) 0, (short) IVs.length);

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
        short num16s = (short)(rawLength >> 4);
        if ((rawLength & 0x0F) != 0) {
            num16s += 1;
        }
        return (short)(num16s * 16);
    }

    public void setRpId(AESKey key, Cipher wrapper, byte[] rpIdBuffer, short rpIdOffset, byte rpIdLength) {
        if (rpId != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        rpId = new byte[encryptableLength(rpIdLength)];
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, RP_IV_OFFSET, IV_LEN);
        wrapper.doFinal(rpIdBuffer, rpIdOffset, (short) rpId.length,
                rpId, (short) 0);
        this.rpIdLength = rpIdLength;
    }

    public void setUser(AESKey key, Cipher wrapper,
                        byte[] userIdBuffer, short userIdOffset, byte userIdLength,
                        byte[] userNameBuffer, short userNameOffset, byte userNameLength) {
        if (userId != null) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        userId = new byte[encryptableLength(userIdLength)];
        Util.arrayCopy(userIdBuffer, userIdOffset,
                userId, (short) 0, userIdLength);
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, USER_ID_IV_OFFSET, IV_LEN);
        wrapper.doFinal(userId, (short) 0, (short) userId.length,
                userId, (short) 0);
        this.userIdLength = userIdLength;

        if (userNameLength > 64) {
            userNameLength = 64;
        }

        userName = new byte[encryptableLength(userNameLength)];
        Util.arrayCopy(userNameBuffer, userNameOffset,
                userName, (short) 0, userNameLength);
        wrapper.init(key, Cipher.MODE_ENCRYPT, IVs, USER_NAME_IV_OFFSET, IV_LEN);
        wrapper.doFinal(userName, (short) 0, (short) userName.length,
                userName, (short) 0);
        this.userNameLength = userNameLength;
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
