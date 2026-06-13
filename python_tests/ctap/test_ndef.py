from typing import Optional

from .ctap_test import CTAPTestCase
from .ndef_util import (
    ndef_fido_install_params,
    parse_ndef_uri,
    parse_query_param,
    read_ndef_data_file,
    select_ndef_applet,
    verify_signed_ndef_uri,
)


class NdefTestCase(CTAPTestCase):
    BASE_URL = "https://example.com/verify"
    PLACEHOLDER_URI = "https://not-provisioned"

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        if install_params is None:
            install_params = ndef_fido_install_params(self.BASE_URL)
        super().setUp(install_params)

    def read_ndef_uri(self) -> str:
        payload = read_ndef_data_file(self.transmit_apdu)
        return parse_ndef_uri(payload)


class NdefPlaceholderTestCase(NdefTestCase):
    def test_placeholder_without_resident_credential(self):
        uri = self.read_ndef_uri()
        self.assertEqual(self.PLACEHOLDER_URI, uri)

    def test_stub_connects(self):
        select_ndef_applet(self.transmit_apdu)


class NdefPlaceholderNoBaseUrlTestCase(CTAPTestCase):
    def test_placeholder_without_base_url(self):
        uri = read_ndef_data_file(self.transmit_apdu)
        parsed = parse_ndef_uri(uri)
        self.assertEqual(NdefTestCase.PLACEHOLDER_URI, parsed)


class NdefSignedUrlTestCase(NdefTestCase):
    def test_signed_url_after_resident_credential(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri = self.read_ndef_uri()
        self.assertTrue(uri.startswith(self.BASE_URL), uri)
        self.assertIn("?", uri)
        verify_signed_ndef_uri(uri, self.BASE_URL)

    def test_counter_increments_on_each_read(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        uri1 = self.read_ndef_uri()
        uri2 = self.read_ndef_uri()
        verify_signed_ndef_uri(uri1, self.BASE_URL)
        verify_signed_ndef_uri(uri2, self.BASE_URL)
        counter1 = int(parse_query_param(uri1, "c"))
        counter2 = int(parse_query_param(uri2, "c"))
        self.assertGreater(counter2, counter1)
