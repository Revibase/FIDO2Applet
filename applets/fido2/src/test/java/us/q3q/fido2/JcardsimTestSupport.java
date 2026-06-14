package us.q3q.fido2;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Shared jcardsim helpers for CTAP integration tests (not NDEF-specific).
 */
public final class JcardsimTestSupport {

    public static final AID FIDO_AID = AIDUtil.create("A0000006472F0001");
    public static final AID NDEF_AID = AIDUtil.create("D2760000850101");

    public static final String BASE_URL = "https://example.com/verify";

    /** FIDO install CBOR: enable attestation only ({@code {0: true}}). */
    public static final byte[] FIDO_DEFAULT_INSTALL_PARAMS = hexToBytes("a100f5");

    public static final byte[] NDEF_URL_INSTALL_PARAMS = buildNdefJcardsimInstallBuffer(BASE_URL);

    public static final byte[] MAKE_CREDENTIAL_CBOR = hexToBytes(
            "01a5015820000000000000000000000000000000000000000000000000000000000000000002"
                    + "a26269646b6578616d706c652e636f6d646e616d65676578616d706c6503a362696445"
                    + "7573657231646e616d6564757365726b646973706c61794e616d6564557365720481"
                    + "a263616c672664747970656a7075626c69632d6b657907a162726bf5");

    private JcardsimTestSupport() {
    }

    public static byte[] buildNdefJcardsimInstallBuffer(String baseUrl) {
        byte[] aid = hexToBytes("D2760000850101");
        byte[] ad = baseUrl.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[1 + aid.length + 2 + ad.length];
        short pos = 0;
        out[pos++] = (byte) aid.length;
        System.arraycopy(aid, 0, out, pos, aid.length);
        pos += aid.length;
        out[pos++] = 0;
        out[pos++] = (byte) ad.length;
        System.arraycopy(ad, 0, out, pos, ad.length);
        return out;
    }

    /** GP-style C9 wrapper around UTF-8 base URL (physical {@code gp --params}). */
    public static byte[] buildNdefGpInstallParams(String baseUrl) {
        byte[] ad = baseUrl.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[2 + ad.length];
        out[0] = (byte) 0xC9;
        out[1] = (byte) ad.length;
        System.arraycopy(ad, 0, out, 2, ad.length);
        return out;
    }

    public static byte[] wrapFidoInstallParams(byte[] cborParams) {
        byte[] wrapped = new byte[5 + cborParams.length];
        wrapped[0] = 1;
        wrapped[1] = (byte) 0x95;
        wrapped[2] = 1;
        wrapped[3] = (byte) 0x86;
        wrapped[4] = (byte) cborParams.length;
        System.arraycopy(cborParams, 0, wrapped, 5, cborParams.length);
        return wrapped;
    }

    public static ResponseAPDU sendCtap(CardSimulator simulator, byte[] cborBody) {
        byte[] framed = new byte[9 + cborBody.length];
        framed[0] = (byte) 0x80;
        framed[1] = 0x10;
        framed[2] = 0x00;
        framed[3] = 0x00;
        framed[4] = 0x00;
        framed[5] = (byte) ((cborBody.length >> 8) & 0xFF);
        framed[6] = (byte) (cborBody.length & 0xFF);
        System.arraycopy(cborBody, 0, framed, 7, cborBody.length);
        framed[7 + cborBody.length] = 0x00;
        framed[8 + cborBody.length] = 0x00;
        return simulator.transmitCommand(new CommandAPDU(framed));
    }

    /** CTAP over short APDU with ISO GET RESPONSE chaining (tests multi-chunk responses). */
    public static ResponseAPDU sendCtapShort(CardSimulator simulator, byte[] cborBody) {
        byte[] framed = new byte[6 + cborBody.length];
        framed[0] = (byte) 0x80;
        framed[1] = 0x10;
        framed[2] = 0x00;
        framed[3] = 0x00;
        framed[4] = (byte) cborBody.length;
        System.arraycopy(cborBody, 0, framed, 5, cborBody.length);
        framed[5 + cborBody.length] = 0x00;
        return transmitWithGetResponseChaining(simulator, framed);
    }

    public static ResponseAPDU transmitWithGetResponseChaining(CardSimulator simulator, byte[] apdu) {
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(apdu));
        ArrayList<ResponseAPDU> parts = new ArrayList<>();
        parts.add(response);
        int totalLen = response.getData().length;
        int rounds = 0;
        while (response.getSW() >= ISO7816.SW_BYTES_REMAINING_00
                && response.getSW() < ISO7816.SW_BYTES_REMAINING_00 + 256
                && totalLen < 65537) {
            if (++rounds > 64) {
                throw new AssertionError(
                        "GET RESPONSE chaining exceeded 64 rounds (last SW="
                                + Integer.toHexString(response.getSW()) + ")");
            }
            byte le = (byte) (response.getSW() & 0xFF);
            response = simulator.transmitCommand(
                    new CommandAPDU(new byte[] {0x00, (byte) 0xC0, 0x00, 0x00, le}));
            parts.add(response);
            totalLen += response.getData().length;
        }
        byte[] combined = new byte[totalLen + 2];
        int off = 0;
        for (ResponseAPDU part : parts) {
            byte[] data = part.getData();
            System.arraycopy(data, 0, combined, off, data.length);
            off += data.length;
        }
        ResponseAPDU last = parts.get(parts.size() - 1);
        combined[off++] = (byte) last.getSW1();
        combined[off] = (byte) last.getSW2();
        return new ResponseAPDU(combined);
    }

    public static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
