"""Vendor CTAP 0x47 helpers shared by NDEF diagnostics."""

from __future__ import annotations

from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID

from fido2applet.attestation import get_pcsc_device

VENDOR_COMMAND_DEBUG_NDEF = 0x47


def ctap2(reader_name: Optional[str] = None) -> Ctap2:
    return Ctap2(get_pcsc_device(reader_name))


def ctap_response_body(raw: bytes) -> bytes:
    if raw and raw[0] == 0x00 and len(raw) > 1:
        return raw[1:]
    return raw


def send_vendor(ctap2: Ctap2, payload: bytes) -> bytes:
    request = bytes([VENDOR_COMMAND_DEBUG_NDEF]) + payload
    response = bytes(ctap2.device.call(CTAPHID.CBOR, request))
    status = response[0]
    if status != 0x00:
        raise CtapError(status)
    return response[1:]
