"""Tests for provision checkpoint state."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from python_scripts.provision_state import (
    PHYSICAL_STEPS,
    ProvisionRunner,
    ProvisionState,
    config_fingerprint,
    default_state_path,
)


class ProvisionStateTest(unittest.TestCase):
    def test_default_state_path(self) -> None:
        self.assertEqual(
            default_state_path(Path("config/card.json")),
            Path("config/card.json.provision-state.json"),
        )

    def test_mark_complete_and_save(self) -> None:
        config = {"aids": {"fido_applet": "A0000006472F0001"}}
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state = ProvisionState(
                config_path="/tmp/card.json",
                config_fingerprint=config_fingerprint(config),
                virtual=False,
            )
            state.mark_complete("install_fido")
            state.save(state_path)

            loaded = ProvisionState.load(state_path)
            self.assertEqual(loaded.completed_steps, ["install_fido"])
            self.assertIsNone(loaded.failed_step)

    def test_mark_failed(self) -> None:
        state = ProvisionState(
            config_path="/tmp/card.json",
            config_fingerprint="abc",
            virtual=False,
        )
        state.mark_complete("install_fido")
        state.mark_failed("install_attestation", "reader timeout")
        self.assertEqual(state.failed_step, "install_attestation")
        self.assertEqual(state.last_error, "reader timeout")
        self.assertEqual(state.completed_steps, ["install_fido"])

    def test_reset_from_step_clears_attestation(self) -> None:
        state = ProvisionState(
            config_path="/tmp/card.json",
            config_fingerprint="abc",
            virtual=False,
        )
        for step in ("install_fido", "install_attestation", "install_ndef"):
            state.mark_complete(step)
        state.attestation = {"aaguid": "deadbeef" * 4}

        state.reset_from_step("install_attestation")
        self.assertEqual(state.completed_steps, ["install_fido"])
        self.assertEqual(state.attestation, {})

    def test_runner_skips_completed(self) -> None:
        state = ProvisionState(
            config_path="/tmp/card.json",
            config_fingerprint="abc",
            virtual=False,
        )
        state.mark_complete("card_lifecycle")
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            runner = ProvisionRunner(state, state_path)
            calls: list[str] = []

            def fn() -> None:
                calls.append("ran")

            runner.run_step("card_lifecycle", fn)
            runner.run_step("delete_packages", fn)
            self.assertEqual(calls, ["ran"])
            self.assertIn("delete_packages", state.completed_steps)

    def test_virtual_session_steps(self) -> None:
        state = ProvisionState(
            config_path="/tmp/card.json",
            config_fingerprint="abc",
            virtual=True,
        )
        state.mark_complete("install_applets")
        state.mark_complete("install_attestation")
        self.assertEqual(
            state.virtual_session_steps(),
            ["install_applets", "install_attestation", "make_credential", "verify_ndef"],
        )
        self.assertTrue(state.virtual_force_step("install_applets"))
        self.assertTrue(state.virtual_force_step("install_attestation"))
        self.assertTrue(state.virtual_force_step("make_credential"))
        self.assertFalse(state.virtual_force_step("verify_ndef"))

    def test_load_or_create_fresh(self) -> None:
        config = {"x": 1}
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "card.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            state_path = default_state_path(config_path)
            state_path.write_text('{"version":1,"config_path":"x","config_fingerprint":"old","virtual":false,"completed_steps":["install_fido"]}', encoding="utf-8")

            state = ProvisionState.load_or_create(
                config_path=config_path,
                config=config,
                virtual=False,
                state_path=state_path,
                fresh=True,
            )
            self.assertFalse(state_path.is_file())
            self.assertEqual(state.completed_steps, [])


if __name__ == "__main__":
    unittest.main()
