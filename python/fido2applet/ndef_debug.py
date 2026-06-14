"""NDEF provisioning diagnostics for physical JavaCards.

Run after makeCredential to verify NdefApplet serves a signed URL via the
passive Type 4 read path (SELECT AID → CC → NDEF file → READ).
"""

from __future__ import annotations

import sys
from typing import Any, Callable, Optional

from fido2.ctap2 import Ctap2

from fido2applet.pcsc_util import ndef_transmit
from fido2applet.ndef.protocol import (
    parse_cc_ndef_file_id,
    parse_ndef_uri,
    read_capability_container,
    read_ndef_type4_phone,
    select_ndef_application_phone,
)


def format_sw(sw: int) -> str:
    return f"{sw:04X}"


def _ctap2(reader_name: Optional[str] = None) -> Ctap2:
    from fido2applet.ndef_vendor import ctap2 as vendor_ctap2

    return vendor_ctap2(reader_name)


def probe_ndef(
    reader_name: Optional[str] = None,
    *,
    verbose: bool = True,
    expected_base_url: Optional[str] = None,
) -> dict[str, Any]:
    """Run passive Type 4 NDEF read. Returns structured results."""
    log: Callable[[str], None] = print if verbose else lambda _msg: None
    results: dict[str, Any] = {"reader": reader_name}

    log("==> NDEF diagnostics")
    log("    NdefApplet signs URLs on first READ of E104 (offset 0) in a session.")

    log("\n[1] CTAP GET_INFO (FIDO2 selectable)")
    try:
        info = _ctap2(reader_name).get_info()
        results["get_info"] = "ok"
        log(f"    OK: versions={info.versions!r}")
    except Exception as exc:  # noqa: BLE001
        results["get_info"] = f"error: {exc}"
        log(f"    FAIL: {exc}")

    log("\n[2] Passive Type 4 NDEF read (SELECT AID → CC → NDEF file → READ)")
    try:
        with ndef_transmit(reader_name) as transmit:
            select_ndef_application_phone(transmit)
            results["select_ndef"] = 0x9000
            log("    OK: SELECT NDEF application SW 9000")

            cc = read_capability_container(transmit)
            ndef_file_id = parse_cc_ndef_file_id(cc)
            results["cc_len"] = len(cc)
            results["ndef_file_id"] = f"{ndef_file_id:04X}"
            log(f"    CC: {len(cc)} bytes, NDEF file ID {ndef_file_id:04X}")

            payload = read_ndef_type4_phone(transmit, select_applet=False)
            uri = parse_ndef_uri(payload)
            results["ndef_uri"] = uri
            log(f"    URI: {uri}")
            if expected_base_url:
                if uri.startswith(expected_base_url):
                    log(f"    OK: URI starts with expected base {expected_base_url!r}")
                    results["uri_prefix_ok"] = True
                else:
                    log(f"    WARN: URI does not start with {expected_base_url!r}")
                    results["uri_prefix_ok"] = False
    except Exception as exc:  # noqa: BLE001
        results["select_ndef"] = f"error: {exc}"
        log(f"    FAIL: {exc}")

    log("\n[3] Interpretation")
    select_sw = results.get("select_ndef")
    if select_sw == 0x9000:
        uri = results.get("ndef_uri", "")
        if "not-provisioned" in uri:
            log("    Placeholder URL — run makeCredential (rk:true) after reinstalling CAPs.")
        elif expected_base_url and not results.get("uri_prefix_ok", True):
            log("    Signed URL present but base URL mismatch — check ndef_install.base_url at install.")
        else:
            log("    NDEF read succeeded.")
    else:
        log("    NDEF read failed — reinstall NDEF stub CAP and retry.")

    return results


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Diagnose physical-card NDEF reads")
    parser.add_argument(
        "--reader",
        help="PC/SC reader substring (same as gp.reader in config/card.json)",
    )
    parser.add_argument(
        "--expected-base-url",
        help="Optional base URL prefix to check on the read URI",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable results only")
    args = parser.parse_args(argv)

    results = probe_ndef(
        args.reader,
        verbose=not args.json,
        expected_base_url=args.expected_base_url,
    )
    if args.json:
        print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
