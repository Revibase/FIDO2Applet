"""GMS Android NFC SELECT / U2F version probes (bwag.g / bvww fallbacks)."""

import struct
import unittest

from fido2applet.sim import JCardSimTestCase

FIDO_AID = bytes.fromhex("A0000006472F0001")
U2F_V2_RESPONSE = b"U2F_V2"
FIDO_2_0_RESPONSE = b"FIDO_2_0"

SW_NO_ERROR = 0x9000

# GMS bwag.g() extended SELECT (flag 45782654 default false).
GMS_EXTENDED_SELECT = bytes.fromhex(
    "00A40400000008A0000006472F00010000"
)
# GMS bvww short SELECT (case 4, Le=0x00 = 256 bytes).
GMS_SHORT_SELECT = bytes.fromhex(
    "00A4040008A0000006472F000100"
)
GMS_GET_PROTOCOL_VERSION = bytes.fromhex("0003000000")


def _sw(resp: bytes) -> int:
    return struct.unpack(">H", resp[-2:])[0]


class GmsNfcSelectTestCase(JCardSimTestCase):
    """jcardsim coverage for GMS-modeled NFC applet selection."""

    def test_gms_extended_select(self):
        resp = self.transmit_apdu(GMS_EXTENDED_SELECT)
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(FIDO_2_0_RESPONSE, resp[:-2])

    def test_gms_short_select(self):
        resp = self.transmit_apdu(GMS_SHORT_SELECT)
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(FIDO_2_0_RESPONSE, resp[:-2])

    def test_gms_empty_select_after_initial_select(self):
        self.transmit_apdu(GMS_SHORT_SELECT)
        resp = self.transmit_apdu(bytes([0x00, 0xA4, 0x04, 0x00]))
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(FIDO_2_0_RESPONSE, resp[:-2])

    def test_gms_get_protocol_version_without_attestation(self):
        # VERSION is not gated on attestation; U2F AUTHENTICATE is.
        resp = self.transmit_apdu(GMS_GET_PROTOCOL_VERSION)
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(U2F_V2_RESPONSE, resp[:-2])

    def test_gms_extended_select_then_get_protocol_version_without_attestation(self):
        resp = self.transmit_apdu(GMS_EXTENDED_SELECT)
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(FIDO_2_0_RESPONSE, resp[:-2])
        resp = self.transmit_apdu(GMS_GET_PROTOCOL_VERSION)
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(U2F_V2_RESPONSE, resp[:-2])

if __name__ == "__main__":
    unittest.main()
