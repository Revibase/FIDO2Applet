"""Raw PC/SC APDU helpers for reading NDEF data from a physical JavaCard."""

from __future__ import annotations

from typing import Callable, Optional

from smartcard.CardConnection import CardConnection
from smartcard.System import readers
from smartcard.scard import SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1

from python_tests.ctap.ndef_util import (
    parse_ndef_uri,
    read_ndef_data_file,
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


def list_reader_names() -> list[str]:
    return [str(r) for r in readers()]


def open_pcsc_connection(reader_name: Optional[str] = None) -> PcscConnection:
    available = readers()
    if not available:
        raise RuntimeError("No PC/SC readers found")

    if reader_name is None:
        if len(available) > 1:
            names = ", ".join(str(r) for r in available)
            raise RuntimeError(f"Multiple PC/SC readers found; set reader in config: {names}")
        reader = available[0]
    else:
        reader = next((r for r in available if str(r) == reader_name), None)
        if reader is None:
            raise RuntimeError(f"PC/SC reader not found: {reader_name!r}")

    conn = PcscConnection(reader.createConnection())
    conn.connect()
    return conn


def read_ndef_uri_from_pcsc(reader_name: Optional[str] = None) -> str:
    conn = open_pcsc_connection(reader_name)
    try:
        transmit: Callable[[bytes], bytes] = conn.transmit
        payload = read_ndef_data_file(transmit)
        return parse_ndef_uri(payload)
    finally:
        conn.disconnect()


def verify_signed_ndef_uri(
    base_url: str,
    reader_name: Optional[str] = None,
) -> str:
    uri = read_ndef_uri_from_pcsc(reader_name)
    if not uri.startswith(base_url):
        raise ValueError(f"NDEF URI does not start with {base_url!r}: {uri!r}")
    for param in ("pk=", "c=", "n=", "s="):
        if param not in uri:
            raise ValueError(f"Missing query parameter {param!r} in {uri!r}")
    return uri
