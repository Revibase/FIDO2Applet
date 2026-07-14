package us.q3q.fido2;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.framework.AID;
import javacard.framework.Applet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.ResponseAPDU;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static us.q3q.fido2.JcardsimTestSupport.FIDO_AID;
import static us.q3q.fido2.JcardsimTestSupport.FIDO_DEFAULT_INSTALL_PARAMS;
import static us.q3q.fido2.JcardsimTestSupport.GET_ASSERTION_CBOR;
import static us.q3q.fido2.JcardsimTestSupport.MAKE_CREDENTIAL_CBOR;
import static us.q3q.fido2.JcardsimTestSupport.NDEF_AID;
import static us.q3q.fido2.JcardsimTestSupport.NDEF_URL_INSTALL_PARAMS;
import static us.q3q.fido2.JcardsimTestSupport.sendCtap;
import static us.q3q.fido2.JcardsimTestSupport.wrapFidoInstallParams;

import org.openjavacard.ndef.stub.NdefApplet;

/**
 * Exercises INTEGRITY_FAILURE by corrupting stored credential bytes from the test
 * harness (reflection into jcardsim). No production/test hooks in the applet.
 */
public class ErrorCodeInjectionTest {

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
    public void getAssertionIntegrityFailureAfterMacCorruption() throws Exception {
        ResponseAPDU makeCred = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, makeCred.getSW());
        assertEquals(0x00, makeCred.getData()[0] & 0xFF);

        corruptResidentCredentialMac(simulator, FIDO_AID);

        ResponseAPDU assertion = sendCtap(simulator, GET_ASSERTION_CBOR);
        assertEquals(0x9000, assertion.getSW());
        assertEquals(FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE, assertion.getData()[0]);
    }

    @Test
    public void makeCredentialReuseIntegrityFailureAfterMacCorruption() throws Exception {
        ResponseAPDU first = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, first.getSW());
        assertEquals(0x00, first.getData()[0] & 0xFF);

        corruptResidentCredentialMac(simulator, FIDO_AID);

        ResponseAPDU second = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, second.getSW());
        assertEquals(FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE, second.getData()[0]);
    }

    /**
     * XOR the last byte of the resident credential blob (HMAC tag) via the simulator
     * runtime — keeps corruption entirely outside production applet code.
     */
    static void corruptResidentCredentialMac(CardSimulator simulator, AID fidoAid)
            throws Exception {
        Field runtimeField = Simulator.class.getDeclaredField("runtime");
        runtimeField.setAccessible(true);
        SimulatorRuntime runtime = (SimulatorRuntime) runtimeField.get(simulator);
        Method getApplet = SimulatorRuntime.class.getDeclaredMethod("getApplet", AID.class);
        getApplet.setAccessible(true);
        Applet applet = (Applet) getApplet.invoke(runtime, fidoAid);
        assertNotNull(applet);

        Field residentKeysField = FIDO2Applet.class.getDeclaredField("residentKeys");
        residentKeysField.setAccessible(true);
        ResidentKeyData[] residentKeys = (ResidentKeyData[]) residentKeysField.get(applet);
        assertNotNull(residentKeys);
        assertNotNull(residentKeys[0]);

        byte[] cred = residentKeys[0].getEncryptedCredentialID();
        cred[cred.length - 1] ^= (byte) 0xFF;
    }
}
