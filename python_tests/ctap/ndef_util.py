import os
import subprocess
import sys
from typing import Callable

from .install_util import fido_install_params

NDEF_AID = bytes.fromhex("D2760000850101")
FILEID_NDEF_CAPABILITIES = 0xE103
FILEID_NDEF_DATA = 0xE104

URI_PREFIXES = {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
}


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ndef_fido_install_params(base_url: str) -> bytes:
    return fido_install_params(
        "--only-allow-one-resident-credential",
        "--enable-attestation",
        "--disable-pin-set",
        "--disable-reset",
        "--ndef-base-url", base_url,
    )


def apdu_sw(response: bytes) -> int:
    return (response[-2] << 8) | response[-1]


def check_sw(response: bytes, expected: int = 0x9000) -> bytes:
    sw = apdu_sw(response)
    if sw != expected:
        raise ValueError(f"Unexpected SW {sw:04X}, expected {expected:04X}")
    return response[:-2]


def select_ndef_applet(transmit: Callable[[bytes], bytes]) -> None:
    apdu = bytes([0x00, 0xA4, 0x04, 0x0C, len(NDEF_AID)]) + NDEF_AID
    check_sw(transmit(apdu))


def select_ndef_file(transmit: Callable[[bytes], bytes], file_id: int) -> None:
    apdu = bytes([
        0x00, 0xA4, 0x00, 0x0C, 0x02,
        (file_id >> 8) & 0xFF, file_id & 0xFF,
    ])
    check_sw(transmit(apdu))


def read_binary(transmit: Callable[[bytes], bytes], offset: int, le: int) -> bytes:
    out = bytearray()
    remaining = le
    pos = offset
    while remaining > 0:
        chunk = min(remaining, 128)
        apdu = bytes([
            0x00, 0xB0,
            (pos >> 8) & 0xFF, pos & 0xFF,
            chunk & 0xFF,
        ])
        out.extend(check_sw(transmit(apdu)))
        pos += chunk
        remaining -= chunk
    return bytes(out)


def read_ndef_data_file(transmit: Callable[[bytes], bytes]) -> bytes:
    select_ndef_applet(transmit)
    select_ndef_file(transmit, FILEID_NDEF_DATA)
    nlen_bytes = read_binary(transmit, 0, 2)
    nlen = (nlen_bytes[0] << 8) | nlen_bytes[1]
    return read_binary(transmit, 2, nlen)


def parse_ndef_uri(file_payload: bytes) -> str:
    if len(file_payload) < 6:
        raise ValueError("NDEF payload too short")
    if file_payload[0] != 0xD1 or file_payload[3] != 0x55:
        raise ValueError(f"Unexpected NDEF URI record: {file_payload[:10].hex()}")
    prefix_code = file_payload[4]
    body = file_payload[5:].decode("ascii")
    return URI_PREFIXES.get(prefix_code, "") + body


def parse_query_param(uri: str, name: str) -> str:
    query = uri.split("?", 1)[1] if "?" in uri else ""
    prefix = name + "="
    for part in query.split("&"):
        if part.startswith(prefix):
            return part[len(prefix):]
    raise ValueError(f"Missing query parameter {name!r} in {uri!r}")
