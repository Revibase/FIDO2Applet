"""Shared provisioning helpers for register_card (physical and virtual)."""

from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from fido2.cose import ES256

REPO_ROOT = Path(__file__).resolve().parent.parent

FIDO_INSTALL_FLAGS: dict[str, tuple[str, str]] = {
    "enable_attestation": ("--enable-attestation", "bool"),
    "high_security": ("--high-security", "bool"),
    "force_always_uv": ("--force-always-uv", "bool"),
    "high_security_rks": ("--high-security-rks", "bool"),
    "protect_against_reset": ("--protect-against-reset", "bool"),
    "only_allow_one_resident_credential": ("--only-allow-one-resident-credential", "bool"),
    "disable_pin_set": ("--disable-pin-set", "bool"),
    "disable_reset": ("--disable-reset", "bool"),
    "do_not_store_pin_length": ("--do-not-store-pin-length", "bool_false"),
    "cache_pin_token": ("--cache-pin-token", "bool_false"),
    "multiple_writes_per_pin_token": ("--multiple-writes-per-pin-token", "bool_false"),
    "kdf_iterations": ("--kdf-iterations", "int"),
    "max_cred_blob_len": ("--max-cred-blob-len", "int"),
    "large_blob_store_size": ("--large-blob-store-size", "int"),
    "max_rk_rp_length": ("--max-rk-rp-length", "int"),
    "max_ram_scratch": ("--max-ram-scratch", "int"),
    "buffer_mem": ("--buffer-mem", "int"),
    "flash_scratch": ("--flash-scratch", "int"),
    "certification_level": ("--certification-level", "int"),
    "attestation_private_key": ("--attestation-private-key", "str"),
    "ndef_base_url": ("--ndef-base-url", "str"),
}


def _fido_install_argv(fido_install: dict[str, Any]) -> list[str]:
    argv = [sys.executable, str(REPO_ROOT / "get_install_parameters.py")]
    for key, (flag, kind) in FIDO_INSTALL_FLAGS.items():
        if key not in fido_install:
            continue
        value = fido_install[key]
        if kind == "bool":
            if value:
                argv.append(flag)
        elif kind == "bool_false":
            if value is False:
                argv.append(flag)
        elif kind == "int":
            argv.extend([flag, str(value)])
        elif kind == "str":
            argv.extend([flag, str(value)])
    return argv


def build_fido_install_params_hex(fido_install: dict[str, Any]) -> str:
    return subprocess.check_output(
        _fido_install_argv(fido_install), cwd=REPO_ROOT, text=True
    ).strip()


def build_fido_install_params_bytes(fido_install: dict[str, Any]) -> bytes:
    return bytes.fromhex(build_fido_install_params_hex(fido_install))


def build_ndef_javacard_install_buffer(config: dict[str, Any]) -> bytes:
    """JavaCard install buffer for NdefApplet (AID + CI + AD), as used by jcardsim."""
    aids = config["aids"]
    ndef_aid = bytes.fromhex(aids["ndef_applet"])
    fido_aid = bytes.fromhex(aids["fido_applet"])
    service_id = bytes.fromhex(aids.get("ndef_service_id", "3F"))
    ad = service_id + fido_aid
    if len(ndef_aid) > 127:
        raise ValueError("aids.ndef_applet AID too long")
    if len(ad) > 255:
        raise ValueError("NDEF install application data too long")
    return bytes([len(ndef_aid)]) + ndef_aid + bytes([0, len(ad)]) + ad


def ndef_gp_install_params(config: dict[str, Any]) -> str:
    aids = config["aids"]
    service_id = aids.get("ndef_service_id", "3F")
    return f"{service_id}{aids['fido_applet']}"


def build_make_credential_params(config: dict[str, Any]) -> dict[str, Any]:
    mc = config["make_credential"]
    rp = mc["rp"]
    user = mc["user"]
    options = mc.get("options", {"rk": True})

    params: dict[str, Any] = {
        "rp": {"id": rp["id"], "name": rp.get("name", rp["id"])},
        "user": {
            "id": bytes.fromhex(user["id_hex"]),
            "name": user["name"],
        },
        "key_params": [{"type": "public-key", "alg": ES256.ALGORITHM}],
        "options": options,
        "client_data_hash": secrets.token_bytes(32),
    }
    if user.get("display_name"):
        params["user"]["display_name"] = user["display_name"]
    return params


def wrap_fido_javacard_install_params(fido_params: bytes) -> bytes:
    """Prefix FIDO install CBOR with JavaCard package/platform header (jcardsim)."""
    return bytes([1, 95, 1, 86, len(fido_params)]) + fido_params
