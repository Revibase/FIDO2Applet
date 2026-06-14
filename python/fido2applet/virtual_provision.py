"""Provision FIDO2Applet on jcardsim (virtual card) — same CTAP steps as register_card."""

from __future__ import annotations

from multiprocessing import Process, Queue
from typing import Any, Callable, Optional

from fido2.ctap2 import Ctap2
from fido2.ctap2.base import args as ctap_args
from fido2.pcsc import CtapPcscDevice

from fido2applet.attestation import (
    VENDOR_COMMAND_SWITCH_ATT,
    attestation_config_from_dict,
    build_attestation_payload,
)
from fido2applet.provision import (
    build_fido_install_params_bytes,
    build_make_credential_params,
    build_ndef_javacard_install_buffer,
    wrap_fido_javacard_install_params,
)
from fido2applet.provision_state import (
    ProvisionRunner,
    ProvisionState,
    attestation_dict_with_state,
    attestation_extras_from_result,
)
from fido2applet.sim import CommandType, FakeSCConnection, JCardSimTestCase
from fido2applet.ndef.protocol import (
    parse_ndef_uri,
    read_ndef_type4_phone,
    verify_signed_ndef_uri,
)


class VirtualCardSession:
    """jcardsim session with CTAP2 and raw APDU access."""

    def __init__(self) -> None:
        self._q_in: Queue = Queue(maxsize=1)
        self._q_out: Queue = Queue(maxsize=1)
        self._process: Optional[Process] = None

    def start(self) -> None:
        if self._process is not None and self._process.is_alive():
            return
        startup = Queue(maxsize=1)
        self._process = Process(
            target=JCardSimTestCase.launch_sim,
            args=(self._q_out, self._q_in, startup),
        )
        self._process.start()
        startup.get(block=True)

    def stop(self) -> None:
        if self._process is None:
            return
        if self._process.is_alive():
            self._q_out.put((CommandType.APPLET_REINSTALL, None))
            self._process.join(timeout=5)
            if self._process.is_alive():
                self._process.kill()
                self._process.join()
        self._process = None

    def reinstall(
        self,
        fido_params: bytes,
        ndef_params: Optional[bytes] = None,
    ) -> None:
        wrapped = wrap_fido_javacard_install_params(fido_params)
        command: bytes | tuple[bytes, bytes] = wrapped
        if ndef_params is not None:
            command = (wrapped, ndef_params)
        self._q_out.put((CommandType.APPLET_REINSTALL, command))
        self._q_in.get(block=True)

    def transmit_apdu(self, apdu: bytes) -> bytes:
        self._q_out.put((CommandType.DIRECT_COMMUNICATE, list(apdu)))
        return bytes(self._q_in.get(block=True))

    @property
    def ctap2(self) -> Ctap2:
        device = CtapPcscDevice(
            FakeSCConnection(self._q_in, self._q_out),
            "virtual_card",
        )
        device.use_ext_apdu = True
        return Ctap2(device)

    def __enter__(self) -> VirtualCardSession:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()


def verify_signed_ndef_uri_virtual(
    transmit: Callable[[bytes], bytes],
    base_url: str,
) -> str:
    uri = parse_ndef_uri(read_ndef_type4_phone(transmit))
    verify_signed_ndef_uri(uri, base_url)
    return uri


def provision_virtual_card(
    config: dict[str, Any],
    runner: ProvisionRunner,
) -> None:
    dry_run = runner.dry_run
    state = runner.state

    fido_params = build_fido_install_params_bytes(config.get("fido_install", {}))
    ndef_params = build_ndef_javacard_install_buffer(config)
    mc = config["make_credential"]
    verify = config.get("verify", {})
    ndef_install = config.get("ndef_install", {})
    base_url = verify.get("expected_base_url") or ndef_install.get("base_url")

    session_steps = state.virtual_session_steps()
    if not session_steps and not dry_run:
        print("All virtual provisioning steps already complete.")
        return

    first_incomplete = state.first_incomplete()
    if first_incomplete and first_incomplete != "install_applets":
        print(
            "Note: jcardsim does not persist between runs; "
            f"re-running CTAP steps from install_applets through {first_incomplete}."
        )

    def step_install_applets() -> None:
        print("==> Virtual card: install FIDO2Applet + NDEF stub (jcardsim)")
        print(f"    FIDO install params: {len(fido_params)} bytes")
        print(f"    NDEF install buffer: {ndef_params.hex()}")

    def step_install_attestation(session: VirtualCardSession) -> dict[str, Any]:
        att_cfg = attestation_config_from_dict(attestation_dict_with_state(config, state))
        att_result = build_attestation_payload(att_cfg)
        print(f"==> Install attestation (AAGUID {att_result.aaguid.hex()})")
        if att_result.ca_private_key_der is not None:
            print("    Generated new CA key/cert (saved to state for resume)")
        if dry_run:
            print(f"    CTAP vendor 0x46 payload ({len(att_result.payload)} bytes)")
            return {"attestation": attestation_extras_from_result(att_result)}

        session.ctap2.send_cbor(
            VENDOR_COMMAND_SWITCH_ATT,
            ctap_args(att_result.payload),
        )
        print("    Attestation installed")
        return {"attestation": attestation_extras_from_result(att_result)}

    def step_make_credential(session: VirtualCardSession) -> dict[str, Any]:
        print("==> makeCredential (resident key)")
        print(
            f"    rp.id={mc['rp']['id']!r}, "
            f"user.name={mc['user']['name']!r}, "
            f"options={mc.get('options', {'rk': True})!r}"
        )
        if dry_run:
            return {}

        cred = session.ctap2.make_credential(**build_make_credential_params(config))
        cred_id = cred.auth_data.credential_data.credential_id
        print(f"    Credential ID: {cred_id.hex()}")
        print(f"    AAGUID: {cred.auth_data.credential_data.aaguid.hex()}")
        return {"make_credential": {"credential_id": cred_id.hex()}}

    def step_verify_ndef(session: VirtualCardSession) -> None:
        if not verify.get("check_ndef", True):
            return
        if not base_url:
            print("==> Skip NDEF verify (no base URL configured)")
            return
        print(f"==> Verify NDEF signed URL (base {base_url!r})")
        if dry_run:
            return
        uri = verify_signed_ndef_uri_virtual(session.transmit_apdu, base_url)
        print(f"    NDEF URI: {uri}")

    if dry_run:
        for step_id in state.steps:
            if state.is_complete(step_id):
                print(f"==> Skip {step_id} (already completed)")
                continue
            if step_id == "install_applets":
                step_install_applets()
            elif step_id == "install_attestation":
                att_cfg = attestation_config_from_dict(attestation_dict_with_state(config, state))
                att_result = build_attestation_payload(att_cfg)
                print(f"==> Install attestation (AAGUID {att_result.aaguid.hex()})")
                print(f"    CTAP vendor 0x46 payload ({len(att_result.payload)} bytes)")
            elif step_id == "make_credential":
                print("==> makeCredential (resident key)")
                print(
                    f"    rp.id={mc['rp']['id']!r}, "
                    f"user.name={mc['user']['name']!r}, "
                    f"options={mc.get('options', {'rk': True})!r}"
                )
            elif step_id == "verify_ndef":
                if verify.get("check_ndef", True) and base_url:
                    print(f"==> Verify NDEF signed URL (base {base_url!r})")
                elif verify.get("check_ndef", True):
                    print("==> Skip NDEF verify (no base URL configured)")
        return

    with VirtualCardSession() as session:
        for step_id in session_steps:
            force = state.virtual_force_step(step_id)
            if step_id == "install_applets":
                def do_install_applets() -> None:
                    step_install_applets()
                    session.reinstall(fido_params, ndef_params)

                runner.run_step(step_id, do_install_applets, force=force)
            elif step_id == "install_attestation":
                runner.run_step(
                    step_id,
                    lambda: step_install_attestation(session),
                    force=force,
                )
            elif step_id == "make_credential":
                runner.run_step(
                    step_id,
                    lambda: step_make_credential(session),
                    force=force,
                )
            elif step_id == "verify_ndef":
                runner.run_step(
                    step_id,
                    lambda: step_verify_ndef(session),
                    force=force,
                )
