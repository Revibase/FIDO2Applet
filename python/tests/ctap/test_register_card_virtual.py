"""Test register_card provisioning flow on jcardsim (virtual card)."""

from __future__ import annotations

import json

from fido2.ctap2.base import args as ctap_args

from fido2applet.attestation import (
    VENDOR_COMMAND_SWITCH_ATT,
    attestation_config_from_dict,
    build_attestation_payload,
)
from fido2applet.paths import repo_root
from fido2applet.provision import (
    build_fido_install_params_bytes,
    build_make_credential_params,
    build_ndef_javacard_install_buffer,
)
from fido2applet.virtual_provision import verify_signed_ndef_uri_virtual
from fido2applet.sim import CTAPTestCase

EXAMPLE_CONFIG = repo_root() / "config" / "card.example.json"
