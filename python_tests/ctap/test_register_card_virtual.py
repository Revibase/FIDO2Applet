"""Test register_card provisioning flow on jcardsim (virtual card)."""

from __future__ import annotations

import json
from pathlib import Path

from fido2.ctap2.base import args as ctap_args

from python_scripts.attestation import (
    VENDOR_COMMAND_SWITCH_ATT,
    attestation_config_from_dict,
    build_attestation_payload,
)
from python_scripts.provision import (
    build_fido_install_params_bytes,
    build_make_credential_params,
    build_ndef_javacard_install_buffer,
)
from python_scripts.virtual_provision import verify_signed_ndef_uri_virtual
from python_tests.ctap.ctap_test import CTAPTestCase

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPO_ROOT / "config" / "card.example.json"


def load_example_config() -> dict:
    with EXAMPLE_CONFIG.open(encoding="utf-8") as f:
        return json.load(f)


class RegisterCardVirtualTestCase(CTAPTestCase):
    """Mirrors register_card.py --virtual using card.example.json."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_example_config()
        super().setUpClass()

    def setUp(self) -> None:
        fido_params = build_fido_install_params_bytes(self.config.get("fido_install", {}))
        ndef_params = build_ndef_javacard_install_buffer(self.config)
        super().setUp((fido_params, ndef_params))

    def test_full_virtual_registration_flow(self) -> None:
        att_cfg = attestation_config_from_dict(self.config.get("attestation", {}))
        att_result = build_attestation_payload(att_cfg)

        res = self.ctap2.send_cbor(
            VENDOR_COMMAND_SWITCH_ATT,
            ctap_args(att_result.payload),
        )
        self.assertIsNotNone(res)

        cred = self.ctap2.make_credential(**build_make_credential_params(self.config))
        self.assertTrue(len(cred.auth_data.credential_data.credential_id) > 0)

        fido_install = self.config.get("fido_install", {})
        base_url = fido_install.get("ndef_base_url")
        self.assertIsNotNone(base_url)

        uri = verify_signed_ndef_uri_virtual(self.transmit_apdu, base_url)
        self.assertTrue(uri.startswith(base_url))
        for param in ("pk=", "c=", "n=", "s="):
            self.assertIn(param, uri)
