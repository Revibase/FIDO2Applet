"""Raw PC/SC APDU helpers for reading NDEF data from a physical JavaCard."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator, Optional

from fido2.pcsc import CtapPcscDevice
from smartcard.CardConnection import CardConnection
from smartcard.System import readers
from smartcard.scard import SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1

from fido2applet.ndef.protocol import (
    parse_ndef_uri,
    read_ndef_type4_phone,
    verify_signed_ndef_uri as verify_ndef_signature,
)


class PcscConnection:
    """Minimal PC/SC transmit wrapper compatible with ndef_util helpers."""

    def __init__(self, connection: CardConnection):
        self._conn = connection

    def connect(self) -> None:
        self._conn.connect(protocol=SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)

    def disconnect(self) -> None:
        self._conn.disconnect()

    def transmit(self, apdu: bytes) -> bytes:
        data, sw1, sw2 = self._conn.transmit(list(apdu))
        return bytes(data) + bytes([sw1, sw2])


FIDO_APPLET_AID = bytes.fromhex("A0000006472F0001")


def fido_applet_select_sw(reader_name: Optional[str] = None) -> str:
    """Return status word hex from SELECT FIDO applet (e.g. 9000, 6a82)."""
    conn = open_pcsc_connection(reader_name)
    try:
        apdu = (
            bytes([0x00, 0xA4, 0x04, 0x00, len(FIDO_APPLET_AID)])
            + FIDO_APPLET_AID
            + b"\x00"
        )
        resp = conn.transmit(apdu)
        return resp[-2:].hex()
    finally:
        conn.disconnect()


def verify_fido_applet_installed(reader_name: Optional[str] = None) -> None:
    sw = fido_applet_select_sw(reader_name)
    if sw != "9000":
        raise RuntimeError(
            f"FIDO applet A0000006472F0001 not selectable after install (SW {sw}). "
            "Check card state with: gp -l "
            "(expect APP SELECTABLE, not only PKG LOADED). "
            "If PKG is LOADED only, delete and retry install_fido."
        )


def list_reader_names() -> list[str]:
    return [str(r) for r in readers()]


def resolve_pcsc_reader(reader_name: Optional[str] = None):
    """Match a PC/SC reader (substring match, same convention as gp -r / CtapPcscDevice)."""
    available = readers()
    if not available:
        raise RuntimeError("No PC/SC readers found")

    if reader_name:
        matches = [r for r in available if reader_name in str(r)]
        if not matches:
            raise RuntimeError(f"PC/SC reader not found: {reader_name!r}")
        if len(matches) > 1:
            names = ", ".join(str(r) for r in matches)
            raise RuntimeError(
                f"Reader name {reader_name!r} matches multiple PC/SC readers: {names}"
            )
        return matches[0]

    if len(available) > 1:
        names = ", ".join(str(r) for r in available)
        raise RuntimeError(f"Multiple PC/SC readers found; set gp.reader in config: {names}")
    return available[0]


def open_pcsc_connection(reader_name: Optional[str] = None) -> PcscConnection:
    conn = PcscConnection(resolve_pcsc_reader(reader_name).createConnection())
    conn.connect()
    return conn


def _transmit_from_ctap_device(device: CtapPcscDevice) -> Callable[[bytes], bytes]:
    def transmit(apdu: bytes) -> bytes:
        resp, sw1, sw2 = device.apdu_exchange(apdu)
        return resp + bytes([sw1, sw2])

    return transmit


@contextmanager
def ndef_transmit(reader_name: Optional[str] = None) -> Iterator[Callable[[bytes], bytes]]:
    """Yield an APDU transmit function for NDEF reads on a physical card.

    Use a plain ISO7816 PC/SC session (no CTAP probe) so SELECT NDEF does not inherit
    FIDO/CTAP state from makeCredential. Fall back to CtapPcscDevice only if needed.
    """
    try:
        conn = open_pcsc_connection(reader_name)
    except RuntimeError:
        conn = None

    if conn is not None:
        try:
            yield conn.transmit
            return
        finally:
            conn.disconnect()

    devices = list(CtapPcscDevice.list_devices(reader_name or ""))
    if len(devices) > 1:
        names = ", ".join(d.name for d in devices)
        raise RuntimeError(
            f"Multiple CTAP PC/SC devices match reader {reader_name!r}: {names}"
        )
    if len(devices) == 1:
        device = devices[0]
        try:
            yield _transmit_from_ctap_device(device)
        finally:
            device.close()
        return

    raise RuntimeError("No PC/SC reader available for NDEF read")


def read_ndef_uri_from_pcsc(reader_name: Optional[str] = None) -> str:
    with ndef_transmit(reader_name) as transmit:
        payload = read_ndef_type4_phone(transmit)
        return parse_ndef_uri(payload)


def verify_signed_ndef_uri(
    base_url: str,
    reader_name: Optional[str] = None,
) -> str:
    uri = read_ndef_uri_from_pcsc(reader_name)
    print(uri)
    verify_ndef_signature(uri, base_url)
    return uri
