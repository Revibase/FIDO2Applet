"""Build and install FIDO2Applet attestation certificate data via CTAP vendor command 0x46."""

from __future__ import annotations

import base64
import binascii
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives._serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key
from fido2.ctap2 import Ctap2
from fido2.ctap2.base import args as ctap_args
from fido2.pcsc import CtapPcscDevice

from fido2applet.sim import BasicAttestationTestCase

VENDOR_COMMAND_SWITCH_ATT = 0x46
CTAP_DEVICE_WAIT_SECONDS = 15.0
CTAP_DEVICE_POLL_INTERVAL = 0.5


@dataclass
class AttestationConfig:
    name: str = "FIDO2Applet"
    org: str = "REVIBASE"
    country: str = "US"
    aaguid: Optional[bytes] = None
    ca_cert_bytes: Optional[bytes] = None
    ca_private_key: Optional[bytes] = None
    already_loaded_public_key: Optional[bytes] = None


@dataclass
class AttestationResult:
    aaguid: bytes
    payload: bytes
    ca_private_key_der: Optional[bytes] = None
    ca_cert_der: Optional[bytes] = None


def build_attestation_payload(config: AttestationConfig) -> AttestationResult:
    if (config.ca_private_key is None) != (config.ca_cert_bytes is None):
        raise ValueError("Either both or neither of CA certificate and private key must be set")

    aaguid = config.aaguid if config.aaguid is not None else secrets.token_bytes(16)
    if len(aaguid) != 16:
        raise ValueError("AAGUID must be 16 bytes")

    tc = BasicAttestationTestCase()
    ca_private_key_der: Optional[bytes] = None
    ca_cert_der: Optional[bytes] = None

    if config.ca_private_key is None:
        ca_privkey_and_cert = tc.get_ca_cert(org=config.org)
        ca_private_key_der = ca_privkey_and_cert[0].private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        ca_cert_der = ca_privkey_and_cert[1]
    else:
        privkey = load_der_private_key(data=config.ca_private_key, password=None)
        ca_privkey_and_cert = privkey, config.ca_cert_bytes

    get_certs_args = {
        "name": config.name,
        "ca_privkey_and_cert": ca_privkey_and_cert,
        "org": config.org,
        "country": config.country,
    }

    if config.already_loaded_public_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        get_certs_args["private_key"] = private_key
    else:
        private_key = None
        get_certs_args["public_key"] = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            config.already_loaded_public_key,
        )

    cert_bytes = tc.get_x509_certs(**get_certs_args)
    payload = tc.assemble_cbor_from_attestation_certs(
        private_key=private_key,
        cert_bytes=cert_bytes[:-1],
        aaguid=aaguid,
    )

    return AttestationResult(
        aaguid=aaguid,
        payload=payload,
        ca_private_key_der=ca_private_key_der,
        ca_cert_der=ca_cert_der,
    )


def _probe_fido_applet(reader_name: Optional[str]) -> str:
    from fido2applet.pcsc_util import fido_applet_select_sw

    try:
        return f"SELECT FIDO applet -> SW {fido_applet_select_sw(reader_name)}"
    except Exception as exc:
        return f"SELECT FIDO applet failed: {exc}"


def _ctap_device_error(reader_name: Optional[str]) -> str:
    from fido2applet.pcsc_util import list_reader_names

    readers = list_reader_names()
    probe = _probe_fido_applet(reader_name)
    msg = (
        "No usable FIDO PC/SC device found; ensure pcscd is running and your user can access it"
    )
    if reader_name:
        msg += f" (gp.reader={reader_name!r})"
    if readers:
        msg += f"\n    PC/SC readers: {', '.join(readers)}"
    else:
        msg += "\n    PC/SC readers: none"
    msg += f"\n    {probe}"
    msg += (
        "\n    After gp install over NFC, re-tap the card and keep it on the reader "
        "for CTAP steps (attestation, makeCredential)."
    )
    return msg


def get_pcsc_device(
    reader_name: Optional[str] = None,
    *,
    wait_seconds: float = CTAP_DEVICE_WAIT_SECONDS,
    poll_interval: float = CTAP_DEVICE_POLL_INTERVAL,
) -> CtapPcscDevice:
    deadline = time.time() + wait_seconds
    prompted = False
    while True:
        devices = list(CtapPcscDevice.list_devices(reader_name or ""))
        if len(devices) > 1:
            names = ", ".join(d.name for d in devices)
            raise RuntimeError(
                f"Found multiple CTAP PC/SC devices"
                + (f" matching {reader_name!r}" if reader_name else "")
                + f": {names}"
            )
        if len(devices) == 1:
            return devices[0]

        if not prompted:
            print(
                "    Waiting for FIDO card on PC/SC reader "
                "(tap/hold card on NFC reader after gp install)..."
            )
            prompted = True
        if time.time() >= deadline:
            raise RuntimeError(_ctap_device_error(reader_name))
        time.sleep(poll_interval)


def install_attestation(device: CtapPcscDevice, payload: bytes) -> object:
    return Ctap2(device).send_cbor(VENDOR_COMMAND_SWITCH_ATT, ctap_args(payload))


def attestation_config_from_dict(data: dict) -> AttestationConfig:
    aaguid = None
    if data.get("aaguid"):
        aaguid_hex = data["aaguid"]
        if len(aaguid_hex) != 32:
            raise ValueError("attestation.aaguid must be 32 hex characters")
        aaguid = bytes.fromhex(aaguid_hex)

    ca_cert = data.get("ca_cert_bytes")
    ca_key = data.get("ca_private_key")
    loaded_pub = data.get("already_loaded_public_key")

    return AttestationConfig(
        name=data.get("name", "FIDO2Applet"),
        org=data.get("org", "REVIBASE"),
        country=data.get("country", "US"),
        aaguid=aaguid,
        ca_cert_bytes=base64.b64decode(ca_cert) if ca_cert else None,
        ca_private_key=base64.b64decode(ca_key) if ca_key else None,
        already_loaded_public_key=base64.b64decode(loaded_pub) if loaded_pub else None,
    )


def main_cli(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Install AAGUID and attestation certificate(s)")
    parser.add_argument("--name", default="FIDO2Applet", help="Common name for the certificate")
    parser.add_argument(
        "--aaguid",
        default=None,
        help="AAGUID as 32 hex characters (16 bytes); random if omitted",
    )
    parser.add_argument("--ca-cert-bytes", default=None, help="CA certificate as base64-encoded DER")
    parser.add_argument(
        "--ca-private-key",
        default=None,
        help="CA private key as base64-encoded unencrypted PKCS8 DER",
    )
    parser.add_argument("--org", default="REVIBASE", help="Organization name for certificates")
    parser.add_argument("--country", default="US", help="ISO country code for certificates")
    parser.add_argument(
        "--already-loaded-public-key",
        help="Private key already on card; base64 DER-encoded public key point",
    )
    args = parser.parse_args(argv)

    aaguid = None
    if args.aaguid is not None:
        if len(args.aaguid) != 32:
            sys.stderr.write("Invalid AAGUID length!\n")
            return 1
        aaguid = bytes.fromhex(args.aaguid)

    config = AttestationConfig(
        name=args.name,
        org=args.org,
        country=args.country,
        aaguid=aaguid,
        ca_cert_bytes=base64.b64decode(args.ca_cert_bytes) if args.ca_cert_bytes else None,
        ca_private_key=base64.b64decode(args.ca_private_key) if args.ca_private_key else None,
        already_loaded_public_key=(
            base64.b64decode(args.already_loaded_public_key)
            if args.already_loaded_public_key
            else None
        ),
    )

    try:
        result = build_attestation_payload(config)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    if result.ca_private_key_der is not None:
        print("Generated new CA private key (not printed; save via provision state if needed)")
    if result.ca_cert_der is not None:
        print(f"Generated CA cert: {base64.b64encode(result.ca_cert_der).decode()}")

    print(f"Using AAGUID: {result.aaguid.hex()}")
    print(binascii.hexlify(result.payload).decode())

    device = get_pcsc_device()
    if config.already_loaded_public_key is not None:
        print("Using existing public key " + binascii.hexlify(config.already_loaded_public_key).decode())

    res = install_attestation(device, result.payload)
    print(f"Got response: {res} (empty is good)")
    return 0
