package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static us.q3q.fido2.JcardsimTestSupport.FIDO_AID;
import static us.q3q.fido2.JcardsimTestSupport.FIDO_DEFAULT_INSTALL_PARAMS;
import static us.q3q.fido2.JcardsimTestSupport.MAKE_CREDENTIAL_CBOR;
import static us.q3q.fido2.JcardsimTestSupport.NDEF_AID;
import static us.q3q.fido2.JcardsimTestSupport.NDEF_URL_INSTALL_PARAMS;
import static us.q3q.fido2.JcardsimTestSupport.sendCtap;
import static us.q3q.fido2.JcardsimTestSupport.sendCtapShort;
import static us.q3q.fido2.JcardsimTestSupport.wrapFidoInstallParams;

import org.openjavacard.ndef.stub.NdefApplet;

/**
 * Extended-length APDU coverage for CTAP (NFCCTAP_MSG over 80 10).
 *
 * Extended commands use Lc/Le as 16-bit fields; the applet must answer with
 * setOutgoingLength + sendBytes rather than a single short setOutgoingAndSend.
 */
public class ExtendedApduTest {

    CardSimulator simulator;

    @BeforeEach
    public void setupApplets() {
        simulator = new CardSimulator();
        byte[] fidoInstall = wrapFidoInstallParams(FIDO_DEFAULT_INSTALL_PARAMS);
        simulator.installApplet(FIDO_AID, FIDO2Applet.class,
                fidoInstall, (short) 0, (byte) fidoInstall.length);
        simulator.installApplet(NDEF_AID, NdefApplet.class,
                NDEF_URL_INSTALL_PARAMS, (short) 0, (byte) NDEF_URL_INSTALL_PARAMS.length);
        simulator.selectApplet(FIDO_AID);
    }

    @Test
    public void getInfoViaExtendedApdu() {
        ResponseAPDU response = sendCtap(simulator, new byte[] {0x04});
        assertEquals(0x9000, response.getSW());
        assertTrue(response.getData().length > 20);
        assertEquals(0x00, response.getData()[0] & 0xFF);
    }

    @Test
    public void makeCredentialExtendedApduSingleRoundTrip() {
        ResponseAPDU response = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, response.getSW());
        assertEquals(0x00, response.getData()[0] & 0xFF);
        assertTrue(response.getData().length > 100,
                "extended response should include full attestation CBOR");
    }

    @Test
    @Timeout(15)
    public void makeCredentialShortApduWithGetResponseChaining() {
        ResponseAPDU response = sendCtapShort(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, response.getSW());
        assertEquals(0x00, response.getData()[0] & 0xFF);
        assertTrue(response.getData().length > 100);
    }
}
