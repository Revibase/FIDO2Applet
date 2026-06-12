import secrets

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin

from .ctap_test import CTAPTestCase
from .install_util import fido_install_params


class DisablePinSetTestCase(CTAPTestCase):
    def setUp(self, install_params=None) -> None:
        super().setUp(fido_install_params("--disable-pin-set"))

    def test_set_pin_rejected(self):
        with self.assertRaises(CtapError) as ctx:
            ClientPin(self.ctap2).set_pin(secrets.token_hex(10))
        self.assertEqual(CtapError.ERR.NOT_ALLOWED, ctx.exception.code)


class DisableResetTestCase(CTAPTestCase):
    def setUp(self, install_params=None) -> None:
        super().setUp(fido_install_params("--disable-reset"))

    def test_reset_rejected(self):
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.reset()
        self.assertEqual(CtapError.ERR.NOT_ALLOWED, ctx.exception.code)


class OnlyOneResidentCredentialTestCase(CTAPTestCase):
    def setUp(self, install_params=None) -> None:
        super().setUp(fido_install_params(
            "--only-allow-one-resident-credential",
            "--enable-attestation",
        ))

    def test_non_resident_make_credential_rejected(self):
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.INVALID_OPTION, ctx.exception.code)

    def test_second_resident_credential_same_rp_rejected(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        self.basic_makecred_params["user"]["id"] = secrets.token_bytes(16)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.CREDENTIAL_EXCLUDED, ctx.exception.code)

    def test_second_resident_credential_different_rp_rejected(self):
        self.basic_makecred_params["options"] = {"rk": True}
        self.ctap2.make_credential(**self.basic_makecred_params)

        self.basic_makecred_params["rp"]["id"] = secrets.token_hex(8) + ".example.com"
        self.basic_makecred_params["user"]["id"] = secrets.token_bytes(16)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.LIMIT_EXCEEDED, ctx.exception.code)
