package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class NdefSignatureTest {

    @Test
    public void ecdsaSha256SignsTwelveByteMessage() throws Exception {
        CardSimulator simulator = new CardSimulator();
        AID aid = AIDUtil.create("A0000006472F0001");
        simulator.installApplet(aid, FIDO2Applet.class);
        simulator.selectApplet(aid);

        KeyPair keyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
        P256Constants.setCurve((javacard.security.ECKey) keyPair.getPrivate());
        P256Constants.setCurve((javacard.security.ECKey) keyPair.getPublic());
        keyPair.genKeyPair();

        byte[] message = new byte[] {0, 0, 0, 8, 0x41, (byte) 0xba, (byte) 0xc7, 0x6d, 0x55, (byte) 0xf3, 0x30, (byte) 0xb3};
        byte[] derSig = new byte[80];
        Signature signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signer.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        short sigLen = signer.sign(message, (short) 0, (short) message.length, derSig, (short) 0);

        assertTrue(sigLen > 0);
        boolean allZero = true;
        for (short i = 0; i < sigLen; i++) {
            if (derSig[i] != 0) {
                allZero = false;
                break;
            }
        }
        assertNotEquals(true, allZero);

        signer.init(keyPair.getPublic(), Signature.MODE_VERIFY);
        assertTrue(signer.verify(message, (short) 0, (short) message.length, derSig, (short) 0, sigLen));
    }
}
