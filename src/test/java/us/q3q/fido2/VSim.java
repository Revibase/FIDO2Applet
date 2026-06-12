package us.q3q.fido2;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.remote.VSmartCard;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import org.openjavacard.ndef.stub.NdefApplet;

import java.lang.reflect.Field;

/**
 * Launches jcardsim with VSmartCard connectivity
 */
public class VSim {

    static final AID fidoAppletAID = AIDUtil.create("A0000006472F0001");
    static final AID ndefAppletAID = AIDUtil.create("D2760000850101");
    /** @deprecated use {@link #fidoAppletAID} */
    static final AID appletAID = fidoAppletAID;
    static final int PORT = 35963;

    private static final byte[] NDEF_INSTALL_PARAMS = {
            7, (byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01,
            0,
            9,
            (byte) 0x3F,
            (byte) 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
    };

    public static Simulator startBackgroundSimulator() throws Exception {
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.port", "" + PORT);
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.delay", "1000");

        VSmartCard sc = new VSmartCard("127.0.0.1", PORT);

        // The JCardSim VSmartCard class doesn't natively support loading applets at startup...
        // ... and it also doesn't provide access to the Simulator class necessary to do that!
        // To avoid needing to patch VCardSim, we'll violate Java member visibility rules
        // and reach directly into the class to install our applet.
        Field f = sc.getClass().getDeclaredField("sim");
        f.setAccessible(true);
        return (Simulator) f.get(sc);
    }

    public static synchronized void installApplet(Simulator sim, byte[] params) {
        installApplet(sim, params, NDEF_INSTALL_PARAMS);
    }

    public static synchronized void installApplet(Simulator sim, byte[] params, byte[] ndefParams) {
        if (params.length > 255) {
            throw new IllegalArgumentException("Install parameters too long!");
        }
        if (ndefParams.length > 255) {
            throw new IllegalArgumentException("NDEF install parameters too long!");
        }
        sim.installApplet(fidoAppletAID, FIDO2Applet.class, params, (short) 0, (byte) params.length);
        sim.installApplet(ndefAppletAID, NdefApplet.class,
                ndefParams, (short) 0, (byte) ndefParams.length);
        selectFido(sim);
    }

    public static synchronized void selectFido(Simulator sim) {
        sim.selectApplet(fidoAppletAID);
    }

    public static synchronized void selectNdef(Simulator sim) {
        sim.selectApplet(ndefAppletAID);
    }

    public static Simulator startForegroundSimulator() {
        return new Simulator();
    }

    public static synchronized byte[] transmitCommand(Simulator sim, byte[] command) {
        return sim.transmitCommand(command);
    }

    public static synchronized void softReset(Simulator sim) {
        sim.reset();
        selectFido(sim);
    }

    public static void main(String[] args) throws Exception {
        Simulator sim = startBackgroundSimulator();

        installApplet(sim, new byte[0]);
    }

}
