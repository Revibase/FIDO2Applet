package us.q3q.fido2;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class Base64UrlUtilTest {

    @Test
    public void encodesWithoutPadding() {
        byte[] in = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] out = new byte[16];
        short len = Base64UrlUtil.encode(in, (short) 0, (short) 8, out, (short) 0);
        assertEquals(11, len);
        assertArrayEquals("AQIDBAUGBwg".getBytes(), java.util.Arrays.copyOf(out, len));
    }
}
