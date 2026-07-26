package us.q3q.fido2;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.security.ECPrivateKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.ResponseAPDU;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;

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
 * Fault-injection tests via jcardsim reflection (no production hooks).
 * An uninitialized resident private key surfaces as
 * {@link FIDOConstants#CTAP2_ERR_NO_CREDENTIALS}.
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
    public void getAssertionNoCredentialsAfterPrivateKeyCleared() throws Exception {
        ResponseAPDU makeCred = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, makeCred.getSW());
        assertEquals(0x00, makeCred.getData()[0] & 0xFF);

        clearResidentPrivateKey(simulator, FIDO_AID);

        ResponseAPDU assertion = sendCtap(simulator, GET_ASSERTION_CBOR);
        assertEquals(0x9000, assertion.getSW());
        assertEquals(FIDOConstants.CTAP2_ERR_NO_CREDENTIALS, assertion.getData()[0]);
    }

    @Test
    public void makeCredentialReuseNoCredentialsAfterPrivateKeyCleared() throws Exception {
        ResponseAPDU first = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, first.getSW());
        assertEquals(0x00, first.getData()[0] & 0xFF);

        clearResidentPrivateKey(simulator, FIDO_AID);

        ResponseAPDU second = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, second.getSW());
        assertEquals(FIDOConstants.CTAP2_ERR_NO_CREDENTIALS, second.getData()[0]);
    }

    /**
     * NDEF repush requires a usable resident private key. Clearing it after resetting
     * the one-shot push flag makes the subsequent makeCredential fail closed.
     */
    @Test
    public void ndefRepushBlockedWhenPrivateKeyCleared() throws Exception {
        ResponseAPDU first = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, first.getSW());
        assertEquals(0x00, first.getData()[0] & 0xFF);

        clearNdefKeyPushed(simulator, FIDO_AID);
        clearResidentPrivateKey(simulator, FIDO_AID);

        ResponseAPDU second = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, second.getSW());
        assertEquals(FIDOConstants.CTAP2_ERR_NO_CREDENTIALS, second.getData()[0]);
    }

    /**
     * I1 regression. On real hardware a reset in the window between the FIDO2 key push and
     * the first NDEF SELECT wipes NDEF's CLEAR_ON_RESET staging while the EEPROM-persistent
     * {@code ndefKeyPushed} flag survives; previously FIDO2 never re-pushed and NDEF was
     * permanently stuck on the placeholder. The simulator's reset() also clears the
     * persistent flag, so we reproduce the exact on-card condition by reflection: wipe the
     * NDEF staging while leaving {@code ndefKeyPushed} set, then verify a later
     * makeCredential re-pushes the key (staging becomes ready again).
     */
    @Test
    public void ndefRecoversAfterStagingWipedButFlagPersists() throws Exception {
        ResponseAPDU first = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, first.getSW());
        assertEquals(0x00, first.getData()[0] & 0xFF);

        // NDEF staged the pushed key but has not committed it (no SELECT yet).
        assertEquals(1, ndefByteFieldValue(simulator, NDEF_AID, "pendingPushReady"));
        assertEquals(0, ndefByteFieldValue(simulator, NDEF_AID, "keyValid"));

        // Simulate the reset: CLEAR_ON_RESET staging is wiped, but the persistent
        // FIDO2 ndefKeyPushed flag survives (this is the state a power cut leaves on-card).
        wipeNdefStaging(simulator, NDEF_AID);
        assertEquals(0, ndefByteFieldValue(simulator, NDEF_AID, "pendingPushReady"));

        // A later makeCredential must re-push (fix) rather than early-return on the stale flag.
        ResponseAPDU second = sendCtap(simulator, MAKE_CREDENTIAL_CBOR);
        assertEquals(0x9000, second.getSW());
        assertEquals(0x00, second.getData()[0] & 0xFF);

        // Re-push happened: NDEF is holding the key again and will commit on next SELECT.
        assertEquals(1, ndefByteFieldValue(simulator, NDEF_AID, "pendingPushReady"));
    }

    static Applet getApplet(CardSimulator simulator, AID aid) throws Exception {
        Field runtimeField = Simulator.class.getDeclaredField("runtime");
        runtimeField.setAccessible(true);
        SimulatorRuntime runtime = (SimulatorRuntime) runtimeField.get(simulator);
        Method getApplet = SimulatorRuntime.class.getDeclaredMethod("getApplet", AID.class);
        getApplet.setAccessible(true);
        Applet applet = (Applet) getApplet.invoke(runtime, aid);
        assertNotNull(applet);
        return applet;
    }

    static int ndefByteFieldValue(CardSimulator simulator, AID ndefAid, String name)
            throws Exception {
        Applet applet = getApplet(simulator, ndefAid);
        Field f = NdefApplet.class.getDeclaredField(name);
        f.setAccessible(true);
        byte[] arr = (byte[]) f.get(applet);
        return arr[0] & 0xFF;
    }

    static void wipeNdefStaging(CardSimulator simulator, AID ndefAid) throws Exception {
        Applet applet = getApplet(simulator, ndefAid);
        Field ready = NdefApplet.class.getDeclaredField("pendingPushReady");
        ready.setAccessible(true);
        ((byte[]) ready.get(applet))[0] = 0;
        Field staging = NdefApplet.class.getDeclaredField("pendingKeyStaging");
        staging.setAccessible(true);
        Arrays.fill((byte[]) staging.get(applet), (byte) 0);
    }

    static void clearResidentPrivateKey(CardSimulator simulator, AID fidoAid)
            throws Exception {
        Applet applet = getApplet(simulator, fidoAid);

        Field residentKeysField = FIDO2Applet.class.getDeclaredField("residentKeys");
        residentKeysField.setAccessible(true);
        ResidentKeyData[] residentKeys = (ResidentKeyData[]) residentKeysField.get(applet);
        assertNotNull(residentKeys);
        assertNotNull(residentKeys[0]);

        Field privateKeyField = ResidentKeyData.class.getDeclaredField("privateKey");
        privateKeyField.setAccessible(true);
        ECPrivateKey privateKey = (ECPrivateKey) privateKeyField.get(residentKeys[0]);
        privateKey.clearKey();
    }

    static void clearNdefKeyPushed(CardSimulator simulator, AID fidoAid) throws Exception {
        Applet applet = getApplet(simulator, fidoAid);
        Field pushed = FIDO2Applet.class.getDeclaredField("ndefKeyPushed");
        pushed.setAccessible(true);
        pushed.setBoolean(applet, false);
    }
}
