package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openjavacard.ndef.stub.NdefApplet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class NdefAppletTest {

    private static final AID FIDO_AID = AIDUtil.create("A0000006472F0001");
    private static final AID NDEF_AID = AIDUtil.create("D2760000850101");
    private static final byte[] NDEF_INSTALL_PARAMS = {
            7, (byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01,
            0,
            9,
            (byte) 0x3F,
            (byte) 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
    };
    private static final String PLACEHOLDER_URI = "https://not-provisioned";

    CardSimulator simulator;

    @BeforeEach
    public void setupApplets() {
        simulator = new CardSimulator();
        simulator.installApplet(FIDO_AID, FIDO2Applet.class);
        simulator.installApplet(NDEF_AID, NdefApplet.class,
                NDEF_INSTALL_PARAMS, (short) 0, (byte) NDEF_INSTALL_PARAMS.length);
    }

    @Test
    public void stubConnects() {
        ResponseAPDU response = selectNdefApplet();
        assertEquals(0x9000, response.getSW());
    }

    @Test
    public void placeholderWithoutResidentCredential() {
        assertEquals(PLACEHOLDER_URI, readNdefUri());
    }

    private ResponseAPDU selectNdefApplet() {
        byte[] aid = hexToBytes("D2760000850101");
        byte[] apdu = new byte[5 + aid.length];
        apdu[0] = 0x00;
        apdu[1] = ISO7816.INS_SELECT;
        apdu[2] = 0x04;
        apdu[3] = 0x0C;
        apdu[4] = (byte) aid.length;
        System.arraycopy(aid, 0, apdu, 5, aid.length);
        return simulator.transmitCommand(new CommandAPDU(apdu));
    }

    private void selectNdefFile(short fileId) {
        byte[] apdu = new byte[] {
                0x00, ISO7816.INS_SELECT, 0x00, 0x0C, 0x02,
                (byte) (fileId >> 8), (byte) fileId
        };
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(apdu));
        assertEquals(0x9000, response.getSW());
    }

    private byte[] readBinary(int offset, int le) {
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(new byte[] {
                0x00, (byte) 0xB0,
                (byte) (offset >> 8), (byte) offset,
                (byte) le
        }));
        assertEquals(0x9000, response.getSW());
        return response.getData();
    }

    private String readNdefUri() {
        assertEquals(0x9000, selectNdefApplet().getSW());
        selectNdefFile((short) 0xE104);
        byte[] nlenBytes = readBinary(0, 2);
        int nlen = ((nlenBytes[0] & 0xFF) << 8) | (nlenBytes[1] & 0xFF);
        byte[] payload = readBinary(2, nlen);
        return parseNdefUri(payload);
    }

    private static String parseNdefUri(byte[] payload) {
        assertTrue(payload.length >= 5);
        assertEquals((byte) 0xD1, payload[0]);
        assertEquals((byte) 0x55, payload[3]);
        byte prefixCode = payload[4];
        String body = new String(payload, 5, payload.length - 5);
        switch (prefixCode) {
            case 0x01:
                return "http://www." + body;
            case 0x02:
                return "https://www." + body;
            case 0x03:
                return "http://" + body;
            case 0x04:
                return "https://" + body;
            default:
                return body;
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
