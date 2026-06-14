import unittest

from fido2applet.ndef.protocol import (
    CC_EXPECTED_LEN,
    CC_EXPECTED_MAPPING_VERSION,
    CC_EXPECTED_MLE,
    CC_EXPECTED_MLC,
    CC_EXPECTED_NDEF_FILE_SIZE,
    FILEID_NDEF_DATA,
    MAX_NDEF_URI_BODY,
    build_ndef_uri_message,
    build_type4_ndef_file,
    parse_cc_ndef_file_id,
    parse_cc_ndef_file_size,
    parse_ndef_uri,
    signed_ndef_url_fits,
    validate_ndef_base_url,
    validate_ndef_uri_record_strict,
)

# NdefApplet.makeCaps(320) — fixed CC at install (mapping 0x20, MLE/MLC 32, E104 size 320).
CC_FIXTURE = bytes.fromhex("000f20002000200406e104014000ff")


class NdefUriEncodingTest(unittest.TestCase):
    def test_https_example_com_nfc_forum_rdt(self):
        """NFC Forum URI RTD: https:// = prefix 0x04 (not 0x02)."""
        message = build_ndef_uri_message("https://example.com")
        expected = bytes.fromhex("d1010c5504") + b"example.com"
        self.assertEqual(16, len(expected))
        self.assertEqual(expected, message)
        self.assertEqual("https://example.com", parse_ndef_uri(message))

    def test_type4_file_wraps_message_with_nlen(self):
        ndef_file = build_type4_ndef_file("https://example.com")
        self.assertEqual(bytes.fromhex("0010"), ndef_file[:2])  # NLEN = 16
        self.assertEqual(
            bytes.fromhex("d1010c5504") + b"example.com",
            ndef_file[2:],
        )
        validate_ndef_uri_record_strict(ndef_file)

    def test_signed_url_shape_allows_query_in_body(self):
        """Dynamic signed URLs keep ?&= in the URI body after the prefix byte."""
        url = (
            "https://example.com/verify"
            "?pk=AbCd"
            "&c=0000000001"
            "&n=XyZ"
            "&s=Sig"
        )
        message = build_ndef_uri_message(url)
        self.assertEqual(0xD1, message[0])
        self.assertEqual(0x01, message[1])
        self.assertEqual(0x55, message[3])
        self.assertEqual(0x04, message[4])  # https://
        self.assertEqual(message[2], len(message) - 4)
        self.assertTrue(message[5:].startswith(b"example.com/verify?pk="))
        self.assertEqual(url, parse_ndef_uri(message))

    def test_cc_tlv_parses_ndef_file_id_and_size(self):
        self.assertEqual(CC_EXPECTED_LEN, len(CC_FIXTURE))
        self.assertEqual(CC_EXPECTED_LEN, (CC_FIXTURE[0] << 8) | CC_FIXTURE[1])
        self.assertEqual(CC_EXPECTED_MAPPING_VERSION, CC_FIXTURE[2])
        self.assertEqual(CC_EXPECTED_MLE, (CC_FIXTURE[3] << 8) | CC_FIXTURE[4])
        self.assertEqual(CC_EXPECTED_MLC, (CC_FIXTURE[5] << 8) | CC_FIXTURE[6])
        self.assertEqual(FILEID_NDEF_DATA, parse_cc_ndef_file_id(CC_FIXTURE))
        self.assertEqual(CC_EXPECTED_NDEF_FILE_SIZE, parse_cc_ndef_file_size(CC_FIXTURE))

    def test_https_example_fits_signed_url_budget(self):
        self.assertTrue(signed_ndef_url_fits("https://example.com/verify"))

    def test_long_url_without_scheme_rejected(self):
        url = "x" * (MAX_NDEF_URI_BODY + 1)
        self.assertFalse(signed_ndef_url_fits(url))
        with self.assertRaises(ValueError):
            validate_ndef_base_url(url)


if __name__ == "__main__":
    unittest.main()
