"""Shared provisioning helpers for register_card (physical and virtual)."""

from __future__ import annotations

import base64
import hashlib
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from fido2.cose import ES256

from fido2applet.paths import repo_root
from fido2applet.ndef.protocol import validate_ndef_base_url

REPO_ROOT = repo_root()

MAX_NDEF_BASE_URL_LEN = 96


def credential_id_b64url(cred_id: bytes) -> str:
    """base64url (no padding) credential ID — the form the backend expects."""
    return base64.urlsafe_b64encode(cred_id).decode("ascii").rstrip("=")


def cap_file_digest(cap_path: Path) -> str:
    """Short SHA-256 prefix for logging which CAP file was installed."""
    digest = hashlib.sha256(cap_path.read_bytes()).hexdigest()
    return f"{digest[:16]}… ({cap_path.stat().st_size} bytes)"


def cap_file_hash(cap_path: Path) -> str:
    """Full SHA-256 hex of a CAP file (for provision-state change detection)."""
    return hashlib.sha256(cap_path.read_bytes()).hexdigest()

FIDO_INSTALL_FLAGS: dict[str, tuple[str, str]] = {
    "enable_attestation": ("--enable-attestation", "bool"),
    "max_ram_scratch": ("--max-ram-scratch", "int"),
    "buffer_mem": ("--buffer-mem", "int"),
    "flash_scratch": ("--flash-scratch", "int"),
    "certification_level": ("--certification-level", "int"),
    "attestation_private_key": ("--attestation-private-key", "str"),
}


def _fido_install_argv(fido_install: dict[str, Any]) -> list[str]:
    argv = [sys.executable, str(REPO_ROOT / "tools" / "get_install_parameters.py")]
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


def _ndef_base_url_bytes(config: dict[str, Any]) -> bytes:
    ndef_install = config.get("ndef_install", {})
    base_url = ndef_install.get("base_url")
    if base_url is None:
        return b""
    encoded = str(base_url).encode("utf-8")
    if len(encoded) > MAX_NDEF_BASE_URL_LEN:
        raise ValueError(
            f"ndef_install.base_url exceeds {MAX_NDEF_BASE_URL_LEN} bytes"
        )
    validate_ndef_base_url(str(base_url))
    return encoded


def build_ndef_javacard_install_buffer(config: dict[str, Any]) -> bytes:
    """JavaCard install buffer for NdefApplet (AID + CI + AD), as used by jcardsim."""
    aids = config["aids"]
    ndef_aid = bytes.fromhex(aids["ndef_applet"])
    ad = _ndef_base_url_bytes(config)
    if len(ndef_aid) > 127:
        raise ValueError("aids.ndef_applet AID too long")
    if len(ad) > 255:
        raise ValueError("NDEF install application data too long")
    return bytes([len(ndef_aid)]) + ndef_aid + bytes([0, len(ad)]) + ad


def ndef_gp_install_params(config: dict[str, Any]) -> str:
    return _ndef_base_url_bytes(config).hex()


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


GP_SCP_MAC_OVERHEAD = 8


def gp_tagged_install_params(params: bytes) -> bytes:
    """Mirror GlobalPlatformPro --params C9 wrapping."""
    if params and params[0] == 0xC9:
        return params
    return bytes([0xC9, len(params)]) + params


def gp_install_and_make_selectable_data_len(
    package_aid_hex: str,
    applet_aid_hex: str,
    params_hex: str,
    *,
    privileges_body_len: int = 1,
) -> int:
    """Bytes in GP INSTALL (install and make selectable) command data."""
    pkg = bytes.fromhex(package_aid_hex)
    app = bytes.fromhex(applet_aid_hex)
    install_params = gp_tagged_install_params(bytes.fromhex(params_hex))
    total = 0
    for aid in (pkg, app, app):
        total += 1 + len(aid)
    total += 1 + privileges_body_len
    total += 1 + len(install_params)
    total += 1  # empty install token (length 0)
    return total


def gp_min_block_size_for_command_data(data_len: int) -> int:
    """Minimum gp so SCP-wrapped command data fits (MAC subtracts 8)."""
    return data_len + GP_SCP_MAC_OVERHEAD
