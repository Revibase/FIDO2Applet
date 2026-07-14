"""Coverage matrix: one test per distinct CTAP error the applet returns via API."""

import copy
import secrets
from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2.base import args
from fido2.webauthn import Aaguid, PublicKeyCredentialType

from .ctap_test import CTAPTestCase


class CTAPErrorCodeTestCase(CTAPTestCase):
    """API-reachable CTAP error codes (see docs/capabilities.md Error codes)."""

    def test_missing_parameter_make_credential(self):
        # Empty CBOR map — fewer than the four required makeCredential params.
        res = self.ctap2.device.call(0x10, bytes.fromhex("01a0"))
        self.assertEqual(CtapError.ERR.MISSING_PARAMETER, res[0])

    def test_missing_parameter_get_assertion(self):
        res = self.ctap2.device.call(0x10, bytes.fromhex("02a0"))
        self.assertEqual(CtapError.ERR.MISSING_PARAMETER, res[0])

    def test_invalid_cbor_out_of_order_keys(self):
        # Five map entries: valid 01..04 then key 0x03 (<= previous) → INVALID_CBOR.
        body = bytes.fromhex(
            "01a5015820" + ("00" * 32)
            + "02a16269646b6578616d706c652e636f6d"
            + "03a16269644475736572"  # user.id = "user" (4 bytes)
            + "0481a263616c672664747970656a7075626c69632d6b6579"
            + "03a16269644478787878"
        )
        res = self.ctap2.device.call(0x10, body)
        self.assertEqual(CtapError.ERR.INVALID_CBOR, res[0])

    def test_cbor_unexpected_type(self):
        params = copy.copy(self.basic_makecred_params)
        params["options"] = []
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.CBOR_UNEXPECTED_TYPE, ctx.exception.code)

    def test_unsupported_algorithm(self):
        params = copy.copy(self.basic_makecred_params)
        params["key_params"] = [
            {"type": PublicKeyCredentialType.PUBLIC_KEY, "alg": -257},
        ]
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.UNSUPPORTED_ALGORITHM, ctx.exception.code)

    def test_request_too_large_user_id(self):
        params = copy.copy(self.basic_makecred_params)
        params["user"] = {"id": secrets.token_bytes(65), "name": "toolong"}
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.REQUEST_TOO_LARGE, ctx.exception.code)

    def test_no_credentials_get_assertion(self):
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.get_assertion(
                rp_id=self.rp_id,
                client_data_hash=self.get_random_client_data(),
            )
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, ctx.exception.code)

    def test_invalid_option_rk_false(self):
        params = copy.copy(self.basic_makecred_params)
        params["options"] = {"rk": False}
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.INVALID_OPTION, ctx.exception.code)

    def test_unsupported_option_uv_true(self):
        params = copy.copy(self.basic_makecred_params)
        params["options"] = {"rk": True, "uv": True}
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.UNSUPPORTED_OPTION, ctx.exception.code)

    def test_pin_not_set(self):
        params = copy.copy(self.basic_makecred_params)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params, pin_uv_param=b"")
        self.assertEqual(CtapError.ERR.PIN_NOT_SET, ctx.exception.code)

    def test_pin_auth_invalid(self):
        params = copy.copy(self.basic_makecred_params)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(
                **params, pin_uv_param=secrets.token_bytes(16), pin_uv_protocol=1
            )
        self.assertEqual(CtapError.ERR.PIN_AUTH_INVALID, ctx.exception.code)

    def test_not_allowed_attestation_locked(self):
        # Reinstall with empty params → attestation switching off.
        self.setUp(bytes())
        info = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info.aaguid)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.send_cbor(0x46, args(secrets.token_bytes(122)))
        self.assertEqual(CtapError.ERR.NOT_ALLOWED, ctx.exception.code)

    def test_invalid_length_attestation_install(self):
        # Default setUp enables switching (0x00: true); tiny 0x46 body → INVALID_LENGTH.
        res = self.ctap2.device.call(0x10, bytes([0x46, 0x00]))
        self.assertEqual(CtapError.ERR.INVALID_LENGTH, res[0])

    def test_invalid_command(self):
        res = self.ctap2.device.call(0x10, bytes([0x99]))
        self.assertEqual(CtapError.ERR.INVALID_COMMAND, res[0])


class CTAPErrorCodeNoNdefTestCase(CTAPTestCase):
    """CTAP1_ERR_OTHER when NDEF applet is not installed (push fails)."""

    def setUp(
        self,
        install_params: Optional[bytes | tuple[bytes, Optional[bytes]]] = None,
    ) -> None:
        super().setUp((bytes([0xA1, 0x00, 0xF5]), None))

    def test_other_when_ndef_missing(self):
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.OTHER, ctx.exception.code)
