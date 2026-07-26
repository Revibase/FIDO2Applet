import base64
import os
import subprocess
import sys
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from fido2applet.ndef.install import fido_install_params

NDEF_AID = bytes.fromhex("D2760000850101")
FILEID_NDEF_CAPABILITIES = 0xE103
FILEID_NDEF_DATA = 0xE104
# Must match NdefApplet.NDEF_MAX_READ (32 on physical JCOP; large Le often → SW 6700).
NDEF_MAX_READ_CHUNK = 32
NDEF_READ_CHUNK_FALLBACKS = (32, 16, 8, 4, 2, 1)
NDEF_DATA_FILE_MAX = 320
MAX_NDEF_BASE_URL_LEN = 96

# Signed URL encoding limits (match NdefApplet.encodeSignedNdefUriFile).
SIGNED_URI_QUERY_OVERHEAD = 154
MAX_COUNTER_DECIMAL_DIGITS = 10
NDEF_TYPE4_FILE_PREFIX = 7
MAX_NDEF_URI_BODY = 255 - 1 - SIGNED_URI_QUERY_OVERHEAD - MAX_COUNTER_DECIMAL_DIGITS

# NFC Forum Type 4 CC layout (matches NdefApplet.makeCaps).
CC_TAG_NDEF_FILE_CONTROL = 0x04
CC_TLV_NDEF_FILE_ID_OFFSET = 9
CC_TLV_NDEF_FILE_SIZE_OFFSET = 11
CC_EXPECTED_LEN = 15
CC_EXPECTED_MAPPING_VERSION = 0x20
CC_EXPECTED_MLE = 32
CC_EXPECTED_MLC = 32
CC_EXPECTED_NDEF_FILE_SIZE = NDEF_DATA_FILE_MAX

URI_PREFIXES = {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
}


def ndef_uri_prefix_code(url: str) -> int:
    """NFC Forum URI RTD identifier byte for the URL scheme (RTD URI Record Type Definition)."""
    if url.startswith("https://"):
        return 0x04
    if url.startswith("http://"):
        return 0x03
    if url.startswith("https://www."):
        return 0x02
    if url.startswith("http://www."):
        return 0x01
    return 0x00


def build_ndef_uri_message(url: str) -> bytes:
    """Build a single-record NDEF URI message (no Type 4 NLEN prefix).

    Record layout: D1 01 PL 55 [prefix] [uri-body-after-scheme]
    """
    scheme_skip = ndef_scheme_prefix_skip(url)
    prefix_code = ndef_uri_prefix_code(url)
    body = url[scheme_skip:].encode("ascii")
    payload_len = 1 + len(body)
    if payload_len > 255:
        raise ValueError(f"URI payload too long for short record: {payload_len}")
    return bytes([0xD1, 0x01, payload_len, 0x55, prefix_code]) + body


def build_type4_ndef_file(url: str) -> bytes:
    """Type 4 NDEF file: 2-byte big-endian NLEN + NDEF message."""
    message = build_ndef_uri_message(url)
    nlen = len(message)
    return bytes([(nlen >> 8) & 0xFF, nlen & 0xFF]) + message

NDEF_SW_MEANINGS: dict[int, str] = {
    0x6700: "wrong length (try smaller READ BINARY Le; reinstall NDEF stub CAP if stale)",
    0x6985: "NDEF data not ready (select NDEF file before READ)",
    0x6F00: "unknown applet error (uncaught exception or stale CAP)",
}


def format_apdu_sw(sw: int) -> str:
    extra = NDEF_SW_MEANINGS.get(sw)
    if extra:
        return f"{sw:04X} ({extra})"
    return f"{sw:04X}"


def format_apdu(apdu: bytes) -> str:
    return apdu.hex()


def fido_default_install_params() -> bytes:
    return fido_install_params("--enable-attestation")


def ndef_scheme_prefix_skip(base_url: str) -> int:
    if base_url.startswith("https://"):
        return 8
    if base_url.startswith("http://"):
        return 7
    return 0


def signed_ndef_url_fits(base_url: str) -> bool:
    """Return True if base_url encodes into the stub's NDEF data file budget."""
    encoded = base_url.encode("utf-8")
    if len(encoded) > MAX_NDEF_BASE_URL_LEN:
        return False
    scheme_skip = ndef_scheme_prefix_skip(base_url)
    base_body_len = len(encoded) - scheme_skip
    if base_body_len < 0 or base_body_len > MAX_NDEF_URI_BODY:
        return False
    body_len = base_body_len + SIGNED_URI_QUERY_OVERHEAD + MAX_COUNTER_DECIMAL_DIGITS
    payload_len = 1 + body_len
    if payload_len > 255:
        return False
    file_len = NDEF_TYPE4_FILE_PREFIX + body_len
    return file_len <= NDEF_DATA_FILE_MAX


def validate_ndef_base_url(base_url: str) -> None:
    """Reject base URLs that cannot fit in a signed NDEF Type 4 file."""
    if not base_url:
        return
    encoded = base_url.encode("utf-8")
    if len(encoded) > MAX_NDEF_BASE_URL_LEN:
        raise ValueError(
            f"NDEF base URL must be at most {MAX_NDEF_BASE_URL_LEN} bytes, got {len(encoded)}"
        )
    if not signed_ndef_url_fits(base_url):
        scheme_skip = ndef_scheme_prefix_skip(base_url)
        body_len = len(encoded) - scheme_skip
        raise ValueError(
            "NDEF base URL is too long for signed URI encoding "
            f"({len(encoded)} bytes, {body_len} after scheme strip; "
            f"max body {MAX_NDEF_URI_BODY}). Use http:// or https:// and a shorter path."
        )


def ndef_jcardsim_install_buffer(base_url: str = "") -> bytes:
    """JavaCard install buffer for NdefApplet (AID + CI + AD), as used by jcardsim."""
    validate_ndef_base_url(base_url)
    ad = base_url.encode("utf-8")
    if len(NDEF_AID) > 127:
        raise ValueError("NDEF AID too long")
    if len(ad) > 255:
        raise ValueError("NDEF install application data too long")
    return bytes([len(NDEF_AID)]) + NDEF_AID + bytes([0, len(ad)]) + ad


def ndef_gp_install_params_hex(base_url: str = "") -> bytes:
    """Raw application data for GlobalPlatformPro --params (URL UTF-8 bytes)."""
    validate_ndef_base_url(base_url)
    ad = base_url.encode("utf-8")
    return ad


def build_ndef_gp_c9_install_params(base_url: str = "") -> bytes:
    """GP-style C9 wrapper around UTF-8 base URL (physical gp --params)."""
    ad = ndef_gp_install_params_hex(base_url)
    return bytes([0xC9, len(ad) & 0xFF]) + ad


def update_binary(
    transmit: Callable[[bytes], bytes],
    offset: int,
    data: bytes,
) -> bytes:
    """UPDATE BINARY (INS=D6); returns full response including SW."""
    apdu = bytes([
        0x00, 0xD6,
        (offset >> 8) & 0xFF, offset & 0xFF,
        len(data) & 0xFF,
    ]) + data
    return transmit(apdu)


def apdu_sw(response: bytes) -> int:
    return (response[-2] << 8) | response[-1]


def check_sw(
    response: bytes,
    expected: int = 0x9000,
    *,
    label: str = "APDU",
    apdu: bytes | None = None,
) -> bytes:
    sw = apdu_sw(response)
    if sw != expected:
        print(format_apdu_sw(sw))
        detail = f"{label}: unexpected SW {format_apdu_sw(sw)}, expected {expected:04X}"
        if apdu is not None:
            detail += f"; apdu={format_apdu(apdu)}"
        raise ValueError(detail)
    return response[:-2]


def select_ndef_application_phone(transmit: Callable[[bytes], bytes]) -> None:
    """SELECT NDEF application AID (Android passive Type 4: P2=0x00, Le=0)."""
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(NDEF_AID)]) + NDEF_AID + b"\x00"
    check_sw(transmit(apdu), label="SELECT NDEF application (phone)", apdu=apdu)


def select_ndef_type4_file(transmit: Callable[[bytes], bytes], file_id: int) -> None:
    """SELECT a Type 4 file by ID (P2=0x0C, as Android NFC stack uses)."""
    apdu = bytes([
        0x00, 0xA4, 0x00, 0x0C, 0x02,
        (file_id >> 8) & 0xFF, file_id & 0xFF,
    ])
    check_sw(transmit(apdu), label=f"SELECT Type 4 file {file_id:04X}", apdu=apdu)


def select_ndef_file_cc(transmit: Callable[[bytes], bytes]) -> None:
    select_ndef_type4_file(transmit, FILEID_NDEF_CAPABILITIES)


def _read_binary_chunk(
    transmit: Callable[[bytes], bytes],
    offset: int,
    le: int,
) -> bytes:
    apdu = bytes([
        0x00, 0xB0,
        (offset >> 8) & 0xFF, offset & 0xFF,
        le & 0xFF,
    ])
    return check_sw(
        transmit(apdu),
        label=f"READ BINARY offset={offset} le={le}",
        apdu=apdu,
    )


def read_binary(transmit: Callable[[bytes], bytes], offset: int, le: int) -> bytes:
    out = bytearray()
    pos = offset
    remaining = le
    while remaining > 0:
        preferred = min(remaining, NDEF_MAX_READ_CHUNK)
        chunks_to_try = [preferred] + [c for c in NDEF_READ_CHUNK_FALLBACKS if c < preferred]
        last_error: ValueError | None = None
        for chunk in chunks_to_try:
            try:
                out.extend(_read_binary_chunk(transmit, pos, chunk))
                pos += chunk
                remaining -= chunk
                break
            except ValueError as exc:
                last_error = exc
                if "6700" not in str(exc):
                    raise
        else:
            if last_error is not None:
                raise last_error
            raise RuntimeError(f"READ BINARY failed at offset={pos}")
    return bytes(out)


def parse_cc_ndef_file_id(cc: bytes) -> int:
    """Parse NDEF File Control TLV (tag 0x04) and return the 2-byte file identifier."""
    if len(cc) < CC_TLV_NDEF_FILE_ID_OFFSET + 2:
        raise ValueError(f"CC too short for NDEF file ID: {len(cc)} bytes")
    cc_len = (cc[0] << 8) | cc[1]
    if cc_len > len(cc):
        raise ValueError(f"CC CCLEN {cc_len} exceeds buffer {len(cc)}")
    if cc[7] != CC_TAG_NDEF_FILE_CONTROL:
        raise ValueError(f"Expected NDEF File Control tag 0x04 at offset 7, got 0x{cc[7]:02X}")
    if cc[8] != 6:
        raise ValueError(f"Expected NDEF File Control length 6, got {cc[8]}")
    return (cc[CC_TLV_NDEF_FILE_ID_OFFSET] << 8) | cc[CC_TLV_NDEF_FILE_ID_OFFSET + 1]


def parse_cc_ndef_file_size(cc: bytes) -> int:
    """Parse NDEF file size from CC NDEF File Control TLV."""
    if len(cc) < CC_TLV_NDEF_FILE_SIZE_OFFSET + 2:
        raise ValueError(f"CC too short for NDEF file size: {len(cc)} bytes")
    return (cc[CC_TLV_NDEF_FILE_SIZE_OFFSET] << 8) | cc[CC_TLV_NDEF_FILE_SIZE_OFFSET + 1]


def read_capability_container(transmit: Callable[[bytes], bytes]) -> bytes:
    """SELECT CC file and READ its contents (CCLEN bytes from offset 0)."""
    select_ndef_file_cc(transmit)
    header = read_binary(transmit, 0, 2)
    cc_len = (header[0] << 8) | header[1]
    if cc_len < 2:
        raise ValueError(f"Invalid CC CCLEN: {cc_len}")
    rest = read_binary(transmit, 2, cc_len - 2) if cc_len > 2 else b""
    return header + rest


def read_ndef_type4_phone(
    transmit: Callable[[bytes], bytes],
    *,
    select_applet: bool = True,
) -> bytes:
    """Full NFC Forum Type 4 NDEF detection procedure (mobile passive read path)."""
    if select_applet:
        select_ndef_application_phone(transmit)
    cc = read_capability_container(transmit)
    ndef_file_id = parse_cc_ndef_file_id(cc)
    select_ndef_type4_file(transmit, ndef_file_id)
    nlen_bytes = read_binary(transmit, 0, 2)
    nlen = (nlen_bytes[0] << 8) | nlen_bytes[1]
    if nlen > NDEF_DATA_FILE_MAX:
        raise ValueError(
            f"NDEF message length {nlen} exceeds file maximum {NDEF_DATA_FILE_MAX}; "
            "card may be serving corrupt data or stale CAP"
        )
    return read_binary(transmit, 2, nlen)


def parse_ndef_uri(file_payload: bytes) -> str:
    if len(file_payload) < 6:
        raise ValueError("NDEF payload too short")
    if file_payload[0] != 0xD1 or file_payload[3] != 0x55:
        raise ValueError(f"Unexpected NDEF URI record: {file_payload[:10].hex()}")
    prefix_code = file_payload[4]
    body = file_payload[5:].decode("ascii")
    return URI_PREFIXES.get(prefix_code, "") + body


def validate_ndef_uri_record_strict(
    ndef_file: bytes,
    cc: bytes | None = None,
) -> str:
    """Validate Type 4 NDEF file + URI record lengths (Android NdefMessage rules)."""
    if len(ndef_file) < 2:
        raise ValueError(f"NDEF Type 4 file too short: {len(ndef_file)} bytes")
    nlen = (ndef_file[0] << 8) | ndef_file[1]
    if nlen == 0:
        raise ValueError("NDEF message length (NLEN) is zero")
    if len(ndef_file) != 2 + nlen:
        raise ValueError(
            f"Type 4 file length {len(ndef_file)} != 2 + NLEN ({nlen})"
        )
    if cc is not None:
        cc_size = parse_cc_ndef_file_size(cc)
        if cc_size < 5:
            raise ValueError(f"CC NDEF file size {cc_size} is invalid (must be >= 5)")
        if cc_size < len(ndef_file):
            raise ValueError(
                f"CC NDEF file size {cc_size} < active file length {len(ndef_file)}"
            )

    msg = ndef_file[2:]
    if len(msg) != nlen:
        raise ValueError(f"NDEF message length mismatch: NLEN={nlen}, got {len(msg)}")

    flags = msg[0]
    tnf = flags & 0x07
    sr = (flags >> 4) & 1
    il = (flags >> 3) & 1
    if flags != 0xD1:
        raise ValueError(f"Expected single URI record header D1, got {flags:02X}")
    if tnf != 0x01 or sr != 1 or il != 0:
        raise ValueError(
            f"Expected Well-Known short URI record (TNF=1 SR=1 IL=0), flags={flags:02X}"
        )
    if len(msg) < 4:
        raise ValueError("NDEF record header truncated")

    type_len = msg[1]
    payload_len = msg[2]
    if type_len != 1:
        raise ValueError(f"URI record type length must be 1, got {type_len}")
    if msg[3] != 0x55:
        raise ValueError(f"URI record type must be 0x55, got {msg[3]:02X}")
    if len(msg) != 4 + payload_len:
        raise ValueError(
            f"Record length {len(msg)} != 4 + payload_len ({payload_len})"
        )
    payload = msg[4:]
    if len(payload) != payload_len:
        raise ValueError(
            f"Payload length {len(payload)} != payload_len byte ({payload_len})"
        )
    if nlen != 4 + payload_len:
        raise ValueError(f"NLEN {nlen} != 4 + payload_len ({payload_len})")

    return parse_ndef_uri(msg)


def read_type4_ndef_file(
    transmit: Callable[[bytes], bytes],
    *,
    select_applet: bool = True,
) -> bytes:
    """Read full E104 contents (2-byte NLEN + NDEF message)."""
    if select_applet:
        select_ndef_application_phone(transmit)
    cc = read_capability_container(transmit)
    ndef_file_id = parse_cc_ndef_file_id(cc)
    select_ndef_type4_file(transmit, ndef_file_id)
    nlen_bytes = read_binary(transmit, 0, 2)
    nlen = (nlen_bytes[0] << 8) | nlen_bytes[1]
    if nlen > NDEF_DATA_FILE_MAX - 2:
        raise ValueError(
            f"NDEF message length {nlen} exceeds file maximum {NDEF_DATA_FILE_MAX - 2}"
        )
    message = read_binary(transmit, 2, nlen) if nlen > 0 else b""
    return nlen_bytes + message


def read_ndef_taginfo_order(
    transmit: Callable[[bytes], bytes],
) -> tuple[bytes, bytes]:
    """TagInfo/Android order: SELECT AID → CC → E104 (CC before NDEF file read)."""
    select_ndef_application_phone(transmit)
    cc = read_capability_container(transmit)
    ndef_file = read_type4_ndef_file(transmit, select_applet=False)
    return cc, ndef_file


def parse_query_param(uri: str, name: str) -> str:
    query = uri.split("?", 1)[1] if "?" in uri else ""
    prefix = name + "="
    for part in query.split("&"):
        if part.startswith(prefix):
            return part[len(prefix):]
    raise ValueError(f"Missing query parameter {name!r} in {uri!r}")


def verify_ndef_extras(uri: str) -> dict[str, dict[str, str]]:
    """Provision-state payload from a verified NDEF signed URL."""
    public_key = parse_query_param(uri, "pk")
    return {"verify_ndef": {"public_key": public_key, "ndef_uri": uri}}


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def verify_signed_ndef_uri(
    uri: str,
    base_url: str | None = None,
    *,
    min_counter: int | None = None,
) -> None:
    """Verify NDEF signed URL: ECDSA P-256 SHA-256 over counter||nonce.

    Anti-replay is server-side (NFC Type 4 is read-only). Persist the last-seen
    counter per ``pk`` and pass ``min_counter=last + 1`` to reject replays.
    Optional ``base_url`` only checks that the URI starts with that prefix.
    """
    if base_url is not None and not uri.startswith(base_url):
        raise ValueError(f"NDEF URI does not start with {base_url!r}: {uri!r}")

    compressed_pk = b64url_decode(parse_query_param(uri, "pk"))
    if len(compressed_pk) != 33:
        raise ValueError(f"pk must be 33-byte compressed P-256 key, got {len(compressed_pk)} bytes")

    nonce = b64url_decode(parse_query_param(uri, "n"))
    if len(nonce) != 8:
        raise ValueError(f"n must be 8 bytes, got {len(nonce)} bytes")

    raw_sig = b64url_decode(parse_query_param(uri, "s"))
    if len(raw_sig) != 64:
        raise ValueError(f"s must be 64-byte raw ECDSA signature, got {len(raw_sig)} bytes")

    counter = int(parse_query_param(uri, "c"))
    if counter < 0 or counter > 0xFFFFFFFF:
        raise ValueError(f"counter out of uint32 range: {counter}")

    if min_counter is not None and counter < min_counter:
        raise ValueError(f"counter {counter} below min_counter {min_counter}")

    message = counter.to_bytes(4, "big") + nonce
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), compressed_pk)
    der_sig = encode_dss_signature(
        int.from_bytes(raw_sig[:32], "big"),
        int.from_bytes(raw_sig[32:], "big"),
    )
    public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
