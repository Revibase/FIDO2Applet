package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * APDU sequences modeled on Android GMS FIDO NFC ({@code bwag.g} / {@code bvww}).
 */
public class GmsNfcSelectTest {

    private static final AID FIDO_AID = AIDUtil.create("A0000006472F0001");

    /** GMS {@code bwag.g()} extended SELECT when flag 45782654 is false (default). */
    private static final byte[] GMS_EXTENDED_SELECT = hex(
            "00A40400000008A0000006472F00010000");

    /** GMS {@code bvww} short SELECT (case 4, Le=256). */
    private static final byte[] GMS_SHORT_SELECT = hex(
            "00A4040008A0000006472F000100");

    /** GMS U2F fallback GET_PROTOCOL_VERSION after SELECT returned 6A82/6D00. */
    private static final byte[] GMS_GET_PROTOCOL_VERSION = hex("0003000000");

    private CardSimulator simulator;

    @BeforeEach
    public void setupApplet() {
        simulator = new CardSimulator();
        simulator.installApplet(FIDO_AID, FIDO2Applet.class);
        simulator.selectApplet(FIDO_AID);
    }

    @Test
    public void gmsExtendedSelectReturnsFido2Version() {
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(GMS_EXTENDED_SELECT));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
        assertEquals("FIDO_2_0", new String(response.getData()));
    }

    @Test
    public void gmsShortSelectReturnsFido2Version() {
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(GMS_SHORT_SELECT));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
        assertEquals("FIDO_2_0", new String(response.getData()));
    }

    @Test
    public void gmsEmptySelectAfterInitialSelect() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(0x00, 0xA4, 0x04, 0x00));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
        assertEquals("FIDO_2_0", new String(response.getData()));
    }

    @Test
    public void gmsGetProtocolVersionWithoutAttestation() {
        // VERSION is not gated on attestation; AUTHENTICATE is (see u2FAuthenticate).
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(GMS_GET_PROTOCOL_VERSION));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
        assertEquals("U2F_V2", new String(response.getData()));
    }

    @Test
    public void gmsExtendedSelectThenGetProtocolVersionWithoutAttestation() {
        ResponseAPDU select = simulator.transmitCommand(new CommandAPDU(GMS_EXTENDED_SELECT));
        assertEquals(ISO7816.SW_NO_ERROR, (short) select.getSW());
        assertEquals("FIDO_2_0", new String(select.getData()));

        ResponseAPDU version = simulator.transmitCommand(new CommandAPDU(GMS_GET_PROTOCOL_VERSION));
        assertEquals(ISO7816.SW_NO_ERROR, (short) version.getSW());
        assertEquals("U2F_V2", new String(version.getData()));
    }

    private static byte[] hex(String s) {
        int len = s.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
