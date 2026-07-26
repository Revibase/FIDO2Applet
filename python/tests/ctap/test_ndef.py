from typing import Optional

from .ctap_test import CTAPTestCase
from fido2applet.ndef.protocol import (
    CC_EXPECTED_LEN,
    CC_EXPECTED_MAPPING_VERSION,
    CC_EXPECTED_MLE,
    CC_EXPECTED_MLC,
    CC_EXPECTED_NDEF_FILE_SIZE,
    FILEID_NDEF_DATA,
    MAX_COUNTER_DECIMAL_DIGITS,
    apdu_sw,
    build_ndef_gp_c9_install_params,
    fido_default_install_params,
    ndef_jcardsim_install_buffer,
    parse_cc_ndef_file_id,
    parse_cc_ndef_file_size,
    parse_ndef_uri,
    parse_query_param,
    read_binary,
    read_capability_container,
    read_ndef_taginfo_order,
    read_type4_ndef_file,
    select_ndef_application_phone,
    select_ndef_type4_file,
    update_binary,
    validate_ndef_uri_record_strict,
    verify_signed_ndef_uri,
)

FIDO_AID = bytes.fromhex("A0000006472F0001")


def deselect_by_selecting_fido(transmit) -> None:
    """Simulate end of RF session by selecting another applet (clears NDEF transient state)."""
    transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(FIDO_AID)]) + FIDO_AID + b"\x00")


class NdefTestCase(CTAPTestCase):
    BASE_URL = "https://example.com/verify"
    PLACEHOLDER_URI = "https://not-provisioned"

    def setUp(self, install_params: Optional[bytes | tuple[bytes, Optional[bytes]]] = None) -> None:
        if install_params is None:
            install_params = (
                fido_default_install_params(),
                ndef_jcardsim_install_buffer(self.BASE_URL),
            )
        super().setUp(install_params)

    def read_ndef_uri(self, *, select_applet: bool = True) -> str:
        ndef_file = read_type4_ndef_file(self.transmit_apdu, select_applet=select_applet)
        cc = read_capability_container(self.transmit_apdu)
        return validate_ndef_uri_record_strict(ndef_file, cc)


class NdefPlaceholderTestCase(NdefTestCase):
    def setUp(self, install_params: Optional[bytes | tuple[bytes, Optional[bytes]]] = None) -> None:
        if install_params is None:
            install_params = (
                fido_default_install_params(),
                ndef_jcardsim_install_buffer(""),
            )
        super().setUp(install_params)

    def test_placeholder_without_resident_credential(self):
        uri = self.read_ndef_uri()
        self.assertEqual(self.PLACEHOLDER_URI, uri)

    def test_stub_connects(self):
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, 7]) + bytes.fromhex("D2760000850101") + b"\x00"
        resp = self.transmit_apdu(apdu)
        self.assertEqual(0x9000, apdu_sw(resp), msg=resp.hex())

    def test_cc_file_matches_applet(self):
        select_ndef_application_phone(self.transmit_apdu)
        cc = read_capability_container(self.transmit_apdu)
        self.assertEqual(CC_EXPECTED_LEN, len(cc))
        self.assertEqual(CC_EXPECTED_LEN, (cc[0] << 8) | cc[1])
        self.assertEqual(CC_EXPECTED_MAPPING_VERSION, cc[2])
        self.assertEqual(CC_EXPECTED_MLE, (cc[3] << 8) | cc[4])
        self.assertEqual(CC_EXPECTED_MLC, (cc[5] << 8) | cc[6])
        self.assertEqual(FILEID_NDEF_DATA, parse_cc_ndef_file_id(cc))
        self.assertEqual(CC_EXPECTED_NDEF_FILE_SIZE, parse_cc_ndef_file_size(cc))

    def test_taginfo_order_cc_before_ndef(self):
        cc, ndef_file = read_ndef_taginfo_order(self.transmit_apdu)
        self.assertEqual(CC_EXPECTED_NDEF_FILE_SIZE, parse_cc_ndef_file_size(cc))
        uri = validate_ndef_uri_record_strict(ndef_file, cc)
        self.assertEqual(self.PLACEHOLDER_URI, uri)

    def test_update_binary_rejected(self):
        select_ndef_application_phone(self.transmit_apdu)
        select_ndef_type4_file(self.transmit_apdu, FILEID_NDEF_DATA)
        resp = update_binary(self.transmit_apdu, 0, b"\x00")
        self.assertEqual(0x6986, apdu_sw(resp), msg=resp.hex())


class NdefPlaceholderNoBaseUrlTestCase(CTAPTestCase):
    def setUp(self, install_params: Optional[bytes | tuple[bytes, Optional[bytes]]] = None) -> None:
        super().setUp((
            fido_default_install_params(),
            ndef_jcardsim_install_buffer(""),
        ))

    def test_placeholder_without_base_url(self):
        cc, ndef_file = read_ndef_taginfo_order(self.transmit_apdu)
        parsed = validate_ndef_uri_record_strict(ndef_file, cc)
        self.assertEqual(NdefTestCase.PLACEHOLDER_URI, parsed)


class NdefSignedUrlTestCase(NdefTestCase):
    def test_signed_url_after_resident_credential(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri = self.read_ndef_uri()
        self.assertTrue(uri.startswith(self.BASE_URL), uri)
        self.assertIn("?", uri)
        verify_signed_ndef_uri(uri, self.BASE_URL)

    def test_phone_read_without_applet_select(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        select_ndef_application_phone(self.transmit_apdu)
        cc = read_capability_container(self.transmit_apdu)
        ndef_file = read_type4_ndef_file(self.transmit_apdu, select_applet=False)
        uri = validate_ndef_uri_record_strict(ndef_file, cc)
        verify_signed_ndef_uri(uri, self.BASE_URL)

    def test_taginfo_order_cc_before_ndef_signed(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        cc, ndef_file = read_ndef_taginfo_order(self.transmit_apdu)
        self.assertEqual(CC_EXPECTED_NDEF_FILE_SIZE, parse_cc_ndef_file_size(cc))
        uri = validate_ndef_uri_record_strict(ndef_file, cc)
        verify_signed_ndef_uri(uri, self.BASE_URL)

    def test_counter_zero_padded(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri = self.read_ndef_uri()
        counter = parse_query_param(uri, "c")
        self.assertEqual(MAX_COUNTER_DECIMAL_DIGITS, len(counter))
        self.assertTrue(counter.isdigit())

    def test_signed_ndef_file_length_constant(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        file1 = read_type4_ndef_file(self.transmit_apdu)
        deselect_by_selecting_fido(self.transmit_apdu)
        file2 = read_type4_ndef_file(self.transmit_apdu)
        self.assertEqual(len(file1), len(file2))

    def test_counter_increments_on_each_read(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri1 = self.read_ndef_uri()
        deselect_by_selecting_fido(self.transmit_apdu)
        uri2 = self.read_ndef_uri()
        verify_signed_ndef_uri(uri1, self.BASE_URL)
        verify_signed_ndef_uri(uri2, self.BASE_URL)
        nonce1 = parse_query_param(uri1, "n")
        nonce2 = parse_query_param(uri2, "n")
        self.assertNotEqual(nonce1, nonce2)
        counter1 = int(parse_query_param(uri1, "c"))
        counter2 = int(parse_query_param(uri2, "c"))
        self.assertGreaterEqual(counter2, counter1)

    def test_cached_payload_without_applet_reselect(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri_full = self.read_ndef_uri()

        select_ndef_type4_file(self.transmit_apdu, FILEID_NDEF_DATA)
        nlen_bytes = read_binary(self.transmit_apdu, 0, 2)
        nlen = (nlen_bytes[0] << 8) | nlen_bytes[1]
        payload1 = read_binary(self.transmit_apdu, 2, nlen)
        uri1 = parse_ndef_uri(payload1)

        select_ndef_type4_file(self.transmit_apdu, FILEID_NDEF_DATA)
        nlen_bytes = read_binary(self.transmit_apdu, 0, 2)
        nlen = (nlen_bytes[0] << 8) | nlen_bytes[1]
        payload2 = read_binary(self.transmit_apdu, 2, nlen)
        uri2 = parse_ndef_uri(payload2)

        self.assertEqual(uri_full, uri1)
        self.assertEqual(uri1, uri2)

    def test_cc_read_does_not_change_ndef_payload(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri_before = self.read_ndef_uri()

        read_capability_container(self.transmit_apdu)

        select_ndef_type4_file(self.transmit_apdu, FILEID_NDEF_DATA)
        nlen_bytes = read_binary(self.transmit_apdu, 0, 2)
        nlen = (nlen_bytes[0] << 8) | nlen_bytes[1]
        uri_after = parse_ndef_uri(read_binary(self.transmit_apdu, 2, nlen))

        self.assertEqual(uri_before, uri_after)

    def test_min_counter_rejects_stale(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri = self.read_ndef_uri()
        counter = int(parse_query_param(uri, "c"))
        verify_signed_ndef_uri(uri, self.BASE_URL, min_counter=counter)
        with self.assertRaises(ValueError):
            verify_signed_ndef_uri(uri, self.BASE_URL, min_counter=counter + 1)


class NdefGpInstallTestCase(NdefTestCase):
    def setUp(self, install_params: Optional[bytes | tuple[bytes, Optional[bytes]]] = None) -> None:
        super().setUp((
            fido_default_install_params(),
            build_ndef_gp_c9_install_params(self.BASE_URL),
        ))

    def test_gp_style_c9_wrapped_base_url(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri = self.read_ndef_uri()
        self.assertTrue(uri.startswith(self.BASE_URL), uri)
        verify_signed_ndef_uri(uri, self.BASE_URL)
        cc, ndef_file = read_ndef_taginfo_order(self.transmit_apdu)
        validate_ndef_uri_record_strict(ndef_file, cc)
