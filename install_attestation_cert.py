#!/usr/bin/env python3
"""Install attestation certificate on a provisioned FIDO2Applet (backward-compatible CLI)."""

from python_scripts.attestation import main_cli

if __name__ == "__main__":
    raise SystemExit(main_cli())
