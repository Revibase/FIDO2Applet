"""U2F (CTAP1) authenticate integration tests via raw ISO7816 APDUs."""

import secrets
import struct
from typing import Optional

from cryptography.exceptions import InvalidSignature

from .ctap_test import BasicAttestationTestCase, CTAPTestCase

FIDO_AID = bytes.fromhex("A0000006472F0001")
CREDENTIAL_ID_LEN = 33
U2F_INS_REGISTER = 0x01
U2F_INS_AUTHENTICATE = 0x02
U2F_INS_VERSION = 0x03

SW_NO_ERROR = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA = 0x6A80
SW_COMMAND_NOT_ALLOWED = 0x6986
SW_BYTES_REMAINING_00 = 0x6100


def _sw(resp: bytes) -> int:
    return struct.unpack(">H", resp[-2:])[0]


def select_fido_applet(transmit) -> bytes:
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(FIDO_AID)]) + FIDO_AID + b"\x00"
    resp = transmit(apdu)
    assert _sw(resp) == SW_NO_ERROR, f"SELECT failed: {_sw(resp):04X}"
    return resp[:-2]


def transmit_with_get_response(transmit, apdu: bytes) -> bytes:
    """Transmit an APDU and follow ISO GET RESPONSE (0x61XX) chaining."""
    resp = transmit(apdu)
    parts = [resp[:-2]]
    rounds = 0
    while SW_BYTES_REMAINING_00 <= _sw(resp) < SW_BYTES_REMAINING_00 + 256:
        if rounds > 64:
            raise AssertionError(f"GET RESPONSE chaining exceeded 64 rounds (last SW={_sw(resp):04X})")
        rounds += 1
        le = _sw(resp) & 0xFF
        if le == 0:
            le = 256
        resp = transmit(bytes([0x00, 0xC0, 0x00, 0x00, le & 0xFF]))
        parts.append(resp[:-2])
    return b"".join(parts) + resp[-2:]


def build_u2f_register_apdu(challenge_hash: bytes, app_id_hash: bytes) -> bytes:
    data = challenge_hash + app_id_hash
    return bytes([0x00, U2F_INS_REGISTER, 0x00, 0x00, len(data)]) + data


def build_u2f_authenticate_apdu(
    challenge_hash: bytes,
    app_id_hash: bytes,
    key_handle: bytes,
    p1: int = 0x03,
) -> bytes:
    assert len(challenge_hash) == 32
    assert len(app_id_hash) == 32
    assert len(key_handle) <= 255
    data = challenge_hash + app_id_hash + bytes([len(key_handle)]) + key_handle
    return bytes([0x00, U2F_INS_AUTHENTICATE, p1, 0x00, len(data)]) + data


def parse_u2f_authenticate_response(resp: bytes) -> tuple[int, Optional[dict]]:
    sw = _sw(resp)
    data = resp[:-2]
    if sw != SW_NO_ERROR:
        return sw, None
    if not data:
        return sw, None
    return sw, {
        "flags": data[0],
        "counter": struct.unpack(">I", data[1:5])[0],
        "signature": data[5:],
    }


def u2f_signed_payload(app_id_hash: bytes, flags: int, counter: int, challenge_hash: bytes) -> bytes:
    return app_id_hash + bytes([flags]) + struct.pack(">I", counter) + challenge_hash


class U2FAuthenticateWithoutAttestationTestCase(CTAPTestCase):
    def test_u2f_authenticate_requires_attestation(self):
        """Without attestation certs installed, U2F authenticate is disallowed."""
        select_fido_applet(self.transmit_apdu)
        self.ctap2.make_credential(**self.basic_makecred_params)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        key_handle = secrets.token_bytes(CREDENTIAL_ID_LEN)
        apdu = build_u2f_authenticate_apdu(challenge, app_id, key_handle)
        resp = self.transmit_apdu(apdu)
        self.assertEqual(SW_COMMAND_NOT_ALLOWED, _sw(resp))


class U2FAuthenticateTestCase(BasicAttestationTestCase):
    def setUp(self, install_params=None) -> None:
        super().setUp(install_params)
        self.install_attestation_cert()

    def u2f_transmit(self, apdu: bytes) -> bytes:
        return transmit_with_get_response(self.transmit_apdu, apdu)

    def test_select_returns_u2f_v2_after_attestation(self):
        resp_data = select_fido_applet(self.u2f_transmit)
        self.assertEqual(b"U2F_V2", resp_data)

    def test_u2f_version_command(self):
        select_fido_applet(self.u2f_transmit)
        resp = self.u2f_transmit(bytes([0x00, U2F_INS_VERSION, 0x00, 0x00, 0x00]))
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        self.assertEqual(b"U2F_V2", resp[:-2])

    def test_u2f_register_requires_resident_key(self):
        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_register_apdu(challenge, app_id))
        # Attestation is present (see setUp) but no RK yet — same SW as AUTHENTICATE.
        self.assertEqual(SW_WRONG_DATA, _sw(resp))

    def test_u2f_register_reuses_resident_key(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        expected_cred_id = cred.auth_data.credential_data.credential_id
        expected_pubkey = cred.auth_data.credential_data.public_key

        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_register_apdu(challenge, app_id))
        self.assertEqual(SW_NO_ERROR, _sw(resp))
        data = resp[:-2]
        self.assertEqual(0x05, data[0])
        # SEC1 uncompressed P-256 public key
        self.assertEqual(0x04, data[1])
        self.assertEqual(CREDENTIAL_ID_LEN, data[66])
        self.assertEqual(expected_cred_id, data[67:67 + CREDENTIAL_ID_LEN])

        # Second register must reuse the same resident key (idempotent).
        challenge2 = secrets.token_bytes(32)
        resp2 = self.u2f_transmit(build_u2f_register_apdu(challenge2, app_id))
        self.assertEqual(SW_NO_ERROR, _sw(resp2))
        data2 = resp2[:-2]
        self.assertEqual(expected_cred_id, data2[67:67 + CREDENTIAL_ID_LEN])
        self.assertEqual(data[1:66], data2[1:66])

        # Returned key must still authenticate as the CTAP2 credential public key.
        auth_apdu = build_u2f_authenticate_apdu(challenge, app_id, expected_cred_id)
        auth_resp = self.u2f_transmit(auth_apdu)
        sw, parsed = parse_u2f_authenticate_response(auth_resp)
        self.assertEqual(SW_NO_ERROR, sw)
        signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], challenge)
        expected_pubkey.verify(signed, parsed["signature"])

    def test_u2f_authenticate_no_resident_key(self):
        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        key_handle = secrets.token_bytes(CREDENTIAL_ID_LEN)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, key_handle))
        self.assertEqual(SW_WRONG_DATA, _sw(resp))

    def test_u2f_authenticate_short_key_handle_succeeds(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        pubkey = cred.auth_data.credential_data.public_key
        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        short_handle = secrets.token_bytes(5)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, short_handle))
        sw, parsed = parse_u2f_authenticate_response(resp)
        self.assertEqual(SW_NO_ERROR, sw)
        signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], challenge)
        pubkey.verify(signed, parsed["signature"])

    def test_u2f_authenticate_empty_key_handle_succeeds(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        pubkey = cred.auth_data.credential_data.public_key
        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, b""))
        sw, parsed = parse_u2f_authenticate_response(resp)
        self.assertEqual(SW_NO_ERROR, sw)
        signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], challenge)
        pubkey.verify(signed, parsed["signature"])

    def test_u2f_authenticate_wrong_key_handle_len_byte(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        key_handle = cred.auth_data.credential_data.credential_id
        data = challenge + app_id + bytes([32]) + key_handle
        apdu = bytes([0x00, U2F_INS_AUTHENTICATE, 0x03, 0x00, len(data)]) + data
        resp = self.u2f_transmit(apdu)
        self.assertEqual(SW_WRONG_LENGTH, _sw(resp))

    def test_u2f_authenticate_check_only(self):
        # U2F spec: check-only with a key handle this token accepts must answer
        # SW_CONDITIONS_NOT_SATISFIED ("test-of-user-presence required"), never 0x9000.
        self.ctap2.make_credential(**self.basic_makecred_params)
        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        key_handle = secrets.token_bytes(CREDENTIAL_ID_LEN)
        apdu = build_u2f_authenticate_apdu(challenge, app_id, key_handle, p1=0x07)
        resp = self.u2f_transmit(apdu)
        self.assertEqual(SW_CONDITIONS_NOT_SATISFIED, _sw(resp))
        self.assertEqual(b"", resp[:-2])

    def test_u2f_authenticate_signs_with_resident_key(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        pubkey = cred.auth_data.credential_data.public_key
        key_handle = cred.auth_data.credential_data.credential_id

        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, key_handle))
        sw, parsed = parse_u2f_authenticate_response(resp)
        self.assertEqual(SW_NO_ERROR, sw)
        self.assertIsNotNone(parsed)
        self.assertEqual(0x01, parsed["flags"] & 0x01)  # user present
        signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], challenge)
        pubkey.verify(signed, parsed["signature"])

    def test_u2f_authenticate_ignores_stale_key_handle(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        pubkey = cred.auth_data.credential_data.public_key
        stale_handle = secrets.token_bytes(CREDENTIAL_ID_LEN)

        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, stale_handle))
        sw, parsed = parse_u2f_authenticate_response(resp)
        self.assertEqual(SW_NO_ERROR, sw)
        signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], challenge)
        pubkey.verify(signed, parsed["signature"])

    def test_u2f_authenticate_counter_increases(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        key_handle = cred.auth_data.credential_data.credential_id
        select_fido_applet(self.u2f_transmit)
        app_id = self.rp_id_hash(self.rp_id)

        challenge1 = secrets.token_bytes(32)
        resp1 = self.u2f_transmit(build_u2f_authenticate_apdu(challenge1, app_id, key_handle))
        _, parsed1 = parse_u2f_authenticate_response(resp1)

        challenge2 = secrets.token_bytes(32)
        resp2 = self.u2f_transmit(build_u2f_authenticate_apdu(challenge2, app_id, key_handle))
        _, parsed2 = parse_u2f_authenticate_response(resp2)

        self.assertGreater(parsed2["counter"], parsed1["counter"])

    def test_u2f_authenticate_p1_08(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        pubkey = cred.auth_data.credential_data.public_key
        key_handle = cred.auth_data.credential_data.credential_id

        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, key_handle, p1=0x08))
        sw, parsed = parse_u2f_authenticate_response(resp)
        self.assertEqual(SW_NO_ERROR, sw)
        signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], challenge)
        pubkey.verify(signed, parsed["signature"])

    def test_u2f_signature_rejects_wrong_challenge(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        pubkey = cred.auth_data.credential_data.public_key
        key_handle = cred.auth_data.credential_data.credential_id

        select_fido_applet(self.u2f_transmit)
        challenge = secrets.token_bytes(32)
        app_id = self.rp_id_hash(self.rp_id)
        resp = self.u2f_transmit(build_u2f_authenticate_apdu(challenge, app_id, key_handle))
        _, parsed = parse_u2f_authenticate_response(resp)
        wrong_signed = u2f_signed_payload(app_id, parsed["flags"], parsed["counter"], secrets.token_bytes(32))
        with self.assertRaises(InvalidSignature):
            pubkey.verify(wrong_signed, parsed["signature"])
