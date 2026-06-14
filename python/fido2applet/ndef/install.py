"""FIDO2 install-parameter helpers shared with NDEF tooling."""

from __future__ import annotations

import subprocess
import sys

from fido2applet.paths import repo_root


def fido_install_params(*cli_args: str) -> bytes:
    """Build FIDO2Applet install CBOR bytes via tools/get_install_parameters.py."""
    script = repo_root() / "tools" / "get_install_parameters.py"
    hex_out = subprocess.check_output(
        [sys.executable, str(script), *cli_args],
        cwd=repo_root(),
    ).strip().decode()
    return bytes.fromhex(hex_out)
