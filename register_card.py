#!/usr/bin/env python3
"""
Provision a physical or virtual JavaCard with FIDO2Applet, attestation, NDEF stub, and resident credential.

Usage:
    ./register_card.py config/card.json
    ./register_card.py config/card.json --virtual
    ./register_card.py config/card.json --dry-run
    ./register_card.py config/card.json --fresh          # ignore saved state
    ./register_card.py config/card.json --from-step install_attestation
    ./register_card.py config/card.json --status
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal, Optional

from fido2.ctap2 import Ctap2

from python_scripts.attestation import (
    attestation_config_from_dict,
    build_attestation_payload,
    get_pcsc_device,
    install_attestation,
)
from python_scripts.pcsc_util import verify_signed_ndef_uri
from python_scripts.provision import (
    build_fido_install_params_hex,
    build_make_credential_params,
    ndef_gp_install_params,
)
from python_scripts.provision_state import (
    PHYSICAL_STEPS,
    VIRTUAL_STEPS,
    ProvisionRunner,
    ProvisionState,
    attestation_dict_with_state,
    attestation_extras_from_result,
    default_state_path,
)
from python_scripts.virtual_provision import provision_virtual_card

MAX_NDEF_BASE_URL_LEN = 96
# GlobalPlatformPro key: optional type prefix (emv:, mac:, …) + 16–32 byte hex
MASTER_KEY_RE = re.compile(
    r"^(?:(?:emv|mac|dek|enc|kek|rc|admin|psk):)?[0-9A-Fa-f]{32,64}$",
    re.IGNORECASE,
)

REPO_ROOT = Path(__file__).resolve().parent


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def resolve_path(path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def validate_config(config: dict[str, Any]) -> None:
    paths = config.get("paths", {})
    for key in ("fido_cap", "ndef_stub_cap"):
        if key not in paths:
            raise ValueError(f"config.paths.{key} is required")

    fido_install = config.get("fido_install", {})
    base_url = fido_install.get("ndef_base_url")
    if base_url is not None:
        if len(base_url.encode("utf-8")) > MAX_NDEF_BASE_URL_LEN:
            raise ValueError(
                f"fido_install.ndef_base_url exceeds {MAX_NDEF_BASE_URL_LEN} bytes"
            )

    mc = config.get("make_credential", {})
    if "rp" not in mc or "id" not in mc["rp"]:
        raise ValueError("make_credential.rp.id is required")
    if "user" not in mc or "id_hex" not in mc["user"] or "name" not in mc["user"]:
        raise ValueError("make_credential.user.id_hex and user.name are required")

    user_id = bytes.fromhex(mc["user"]["id_hex"])
    if not user_id:
        raise ValueError("make_credential.user.id_hex must decode to non-empty bytes")

    gp_cfg = config.get("gp", {})
    lifecycle = gp_cfg.get("card_lifecycle", {})
    master_key = gp_cfg.get("master_key")
    if master_key is not None:
        if not MASTER_KEY_RE.match(master_key):
            raise ValueError(
                "gp.master_key must be 16–32 bytes of hex (32–64 hex characters), "
                "optionally prefixed for gp (e.g. emv:404142434445464748494a4b4c4d4e4f)"
            )
    default_key = gp_cfg.get("default_master_key")
    if default_key is not None and not MASTER_KEY_RE.match(default_key):
        raise ValueError(
            "gp.default_master_key must be 16–32 bytes of hex (32–64 hex characters), "
            "optionally prefixed for gp (e.g. emv:404142434445464748494a4b4c4d4e4f)"
        )
    if lifecycle.get("lock") and lifecycle.get("run_before_install") and not master_key:
        raise ValueError("gp.master_key is required when card_lifecycle.lock is enabled")


def gp_command_prefix(
    config: dict[str, Any],
    key_source: Literal["master", "default", "none"] = "master",
) -> list[str]:
    gp_cfg = config.get("gp", {})
    cmd = [gp_cfg.get("executable", "gp")]
    cmd.extend(gp_cfg.get("extra_args", []))
    reader = gp_cfg.get("reader")
    if reader:
        cmd.extend(["-r", reader])
    key = None
    if key_source == "master":
        key = gp_cfg.get("master_key")
    elif key_source == "default":
        key = gp_cfg.get("default_master_key")
    if key:
        cmd.extend(["-k", key])
    return cmd


def gp_key_for_operations(config: dict[str, Any]) -> Literal["master", "default", "none"]:
    gp_cfg = config.get("gp", {})
    if gp_cfg.get("master_key"):
        return "master"
    if gp_cfg.get("default_master_key"):
        return "default"
    return "none"


def build_fido_install_params(fido_install: dict[str, Any]) -> str:
    return build_fido_install_params_hex(fido_install)


def ndef_install_params(config: dict[str, Any]) -> str:
    return ndef_gp_install_params(config)


def run_gp(
    config: dict[str, Any],
    args: list[str],
    dry_run: bool,
    label: str,
    key_source: Literal["master", "default", "none"] | None = None,
) -> None:
    if key_source is None:
        key_source = gp_key_for_operations(config)
    cmd = gp_command_prefix(config, key_source) + args
    print(f"==> {label}")
    print("    " + " ".join(cmd))
    if dry_run:
        return
    subprocess.run(cmd, check=True)


def step_card_lifecycle(config: dict[str, Any], dry_run: bool) -> None:
    gp_cfg = config.get("gp", {})
    lifecycle = gp_cfg.get("card_lifecycle", {})
    if not lifecycle.get("run_before_install", False):
        return

    master_key = gp_cfg.get("master_key")
    if lifecycle.get("lock", True) and not master_key:
        raise ValueError("gp.master_key is required when card_lifecycle.lock is enabled")

    key_source: Literal["default", "none"] = (
        "default" if gp_cfg.get("default_master_key") else "none"
    )

    if lifecycle.get("initialize", True):
        run_gp(
            config, ["--initialize-card"], dry_run,
            "Initialize card (GP INITIALIZED state)",
            key_source=key_source,
        )
    if lifecycle.get("secure", True):
        run_gp(
            config, ["--secure-card"], dry_run,
            "Secure card (GP SECURED state)",
            key_source=key_source,
        )
    if lifecycle.get("lock", True):
        run_gp(
            config, ["--lock", master_key], dry_run,
            "Lock card with MASTER_KEY (install/delete will use -k MASTER_KEY)",
            key_source=key_source,
        )


def step_delete_packages(config: dict[str, Any], dry_run: bool) -> None:
    gp_cfg = config.get("gp", {})
    if not gp_cfg.get("delete_before_install", True):
        return
    for aid in gp_cfg.get("delete_package_aids", []):
        run_gp(config, ["--delete", aid, "--force"], dry_run, f"Delete package {aid}")


def step_install_fido(config: dict[str, Any], dry_run: bool) -> None:
    paths = config["paths"]
    aids = config["aids"]
    fido_cap = resolve_path(paths["fido_cap"])
    if not dry_run and not fido_cap.is_file():
        raise FileNotFoundError(
            f"FIDO CAP not found: {fido_cap} "
            "(run ./gradlew buildJavaCard with JC_HOME set)"
        )

    params = build_fido_install_params(config.get("fido_install", {}))
    run_gp(
        config,
        [
            "--install", str(fido_cap),
            "--create", aids["fido_package"],
            "--params", params,
        ],
        dry_run,
        "Install FIDO2Applet",
    )


def step_install_attestation_physical(
    config: dict[str, Any],
    state: ProvisionState,
    dry_run: bool,
) -> dict[str, Any]:
    att_cfg = attestation_config_from_dict(attestation_dict_with_state(config, state))
    result = build_attestation_payload(att_cfg)

    print(f"==> Install attestation (AAGUID {result.aaguid.hex()})")
    if result.ca_private_key_der is not None:
        print("    Generated new CA key/cert (saved to state for resume)")
    if dry_run:
        print(f"    CTAP vendor 0x46 payload ({len(result.payload)} bytes)")
        return {"attestation": attestation_extras_from_result(result)}

    device = get_pcsc_device()
    res = install_attestation(device, result.payload)
    print(f"    Attestation response: {res!r} (empty is good)")
    return {"attestation": attestation_extras_from_result(result)}


def step_install_ndef(config: dict[str, Any], dry_run: bool) -> None:
    paths = config["paths"]
    aids = config["aids"]
    ndef_cap = resolve_path(paths["ndef_stub_cap"])
    if not dry_run and not ndef_cap.is_file():
        raise FileNotFoundError(
            f"NDEF stub CAP not found: {ndef_cap} "
            "(run ./gradlew :applet-stub:buildJavaCard with JC_HOME set)"
        )

    params = ndef_install_params(config)
    run_gp(
        config,
        [
            "--install", str(ndef_cap),
            "--create", aids["ndef_applet"],
            "--params", params,
            "--default",
        ],
        dry_run,
        "Install NDEF stub applet",
    )


def step_make_credential_physical(config: dict[str, Any], dry_run: bool) -> dict[str, Any]:
    mc = config["make_credential"]
    rp = mc["rp"]
    user = mc["user"]
    options = mc.get("options", {"rk": True})

    print("==> makeCredential (resident key)")
    print(f"    rp.id={rp['id']!r}, user.name={user['name']!r}, options={options!r}")
    if dry_run:
        return {}

    device = get_pcsc_device()
    cred = Ctap2(device).make_credential(**build_make_credential_params(config))
    cred_id = cred.auth_data.credential_data.credential_id
    print(f"    Credential ID: {cred_id.hex()}")
    print(f"    AAGUID: {cred.auth_data.credential_data.aaguid.hex()}")
    return {"make_credential": {"credential_id": cred_id.hex()}}


def step_verify_ndef_physical(config: dict[str, Any], dry_run: bool) -> None:
    verify = config.get("verify", {})
    if not verify.get("check_ndef", True):
        return

    fido_install = config.get("fido_install", {})
    base_url = verify.get("expected_base_url") or fido_install.get("ndef_base_url")
    if not base_url:
        print("==> Skip NDEF verify (no base URL configured)")
        return

    print(f"==> Verify NDEF signed URL (base {base_url!r})")
    if dry_run:
        return

    reader = config.get("gp", {}).get("reader")
    uri = verify_signed_ndef_uri(base_url, reader_name=reader)
    print(f"    NDEF URI: {uri}")


def provision_physical_card(config: dict[str, Any], runner: ProvisionRunner) -> None:
    dry_run = runner.dry_run
    state = runner.state

    if not dry_run and state.first_incomplete() is None:
        print("All physical provisioning steps already complete.")
        return

    runner.run_step(
        "card_lifecycle",
        lambda: step_card_lifecycle(config, dry_run),
    )
    runner.run_step(
        "delete_packages",
        lambda: step_delete_packages(config, dry_run),
    )
    runner.run_step(
        "install_fido",
        lambda: step_install_fido(config, dry_run),
    )
    runner.run_step(
        "install_attestation",
        lambda: step_install_attestation_physical(config, state, dry_run),
    )
    runner.run_step(
        "install_ndef",
        lambda: step_install_ndef(config, dry_run),
    )
    runner.run_step(
        "make_credential",
        lambda: step_make_credential_physical(config, dry_run),
    )
    runner.run_step(
        "verify_ndef",
        lambda: step_verify_ndef_physical(config, dry_run),
    )


def print_step_list(virtual: bool) -> None:
    steps = VIRTUAL_STEPS if virtual else PHYSICAL_STEPS
    print("Provisioning steps (in order):")
    for step_id in steps:
        print(f"  - {step_id}")


def check_config_fingerprint(
    state: ProvisionState,
    config: dict[str, Any],
    *,
    ignore_config_change: bool,
) -> None:
    from python_scripts.provision_state import config_fingerprint

    current = config_fingerprint(config)
    if state.config_fingerprint != current:
        msg = (
            "Config changed since last run (fingerprint mismatch). "
            "Use --fresh to start over or --ignore-config-change to resume anyway."
        )
        if ignore_config_change:
            print(f"Warning: {msg}")
            state.config_fingerprint = current
        else:
            raise ValueError(msg)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Register a new FIDO2 + NDEF JavaCard")
    parser.add_argument(
        "config",
        nargs="?",
        default="config/card.json",
        help="Path to JSON config (default: config/card.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing gp or CTAP operations",
    )
    parser.add_argument(
        "--virtual",
        action="store_true",
        help="Run on jcardsim virtual card instead of physical card + gp",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Clear saved state and run all steps from the beginning",
    )
    parser.add_argument(
        "--from-step",
        metavar="STEP",
        help="Re-run from this step (clears it and all later steps from saved state)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show saved provisioning state and exit",
    )
    parser.add_argument(
        "--list-steps",
        action="store_true",
        help="List step names and exit",
    )
    parser.add_argument(
        "--state-file",
        metavar="PATH",
        help="Override default state file (default: <config>.provision-state.json)",
    )
    parser.add_argument(
        "--ignore-config-change",
        action="store_true",
        help="Resume even if config changed since last run",
    )
    args = parser.parse_args(argv)

    if args.list_steps:
        print_step_list(args.virtual)
        return 0

    config_path = resolve_path(args.config)
    if not config_path.is_file():
        sys.stderr.write(f"Config not found: {config_path}\n")
        sys.stderr.write("Copy config/card.example.json to config/card.json and edit it.\n")
        return 1

    state_path = Path(args.state_file) if args.state_file else default_state_path(config_path)
    if args.status:
        if not state_path.is_file():
            print(f"No state file at {state_path}")
            return 0
        state = ProvisionState.load(state_path)
        runner = ProvisionRunner(state, state_path)
        runner.print_status()
        return 0

    config = load_config(config_path)
    try:
        validate_config(config)
    except (ValueError, KeyError) as exc:
        sys.stderr.write(f"Invalid config: {exc}\n")
        return 1

    try:
        state = ProvisionState.load_or_create(
            config_path=config_path,
            config=config,
            virtual=args.virtual,
            state_path=state_path,
            fresh=args.fresh,
        )
        if args.from_step:
            state.reset_from_step(args.from_step)
            state.save(state_path)

        if not args.fresh and state_path.is_file() and state.completed_steps:
            check_config_fingerprint(
                state, config, ignore_config_change=args.ignore_config_change
            )

        runner = ProvisionRunner(state, state_path, dry_run=args.dry_run)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    print(f"Using config: {config_path}")
    if args.virtual:
        print("(virtual card — jcardsim, no gp)")
    if args.dry_run:
        print("(dry run — no gp/CTAP changes)")
    if state.completed_steps and not args.fresh:
        print("(resuming from saved state)")
    print()
    runner.print_status()
    print()

    try:
        if args.virtual:
            provision_virtual_card(config, runner)
        else:
            provision_physical_card(config, runner)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(f"\nRegistration failed at step {state.failed_step}: gp exited {exc.returncode}\n")
        sys.stderr.write(f"State saved to {state_path}. Re-run to resume, or use --from-step to retry.\n")
        return 1
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        sys.stderr.write(f"\nRegistration failed at step {state.failed_step}: {exc}\n")
        sys.stderr.write(f"State saved to {state_path}. Re-run to resume, or use --from-step to retry.\n")
        return 1

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
