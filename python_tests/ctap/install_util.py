import os
import subprocess
import sys


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def fido_install_params(*cli_args: str) -> bytes:
    """Build FIDO2Applet install CBOR bytes via get_install_parameters.py."""
    hex_out = subprocess.check_output(
        [sys.executable, "get_install_parameters.py", *cli_args],
        cwd=repo_root(),
    ).strip().decode()
    return bytes.fromhex(hex_out)
