"""Checkpoint state for register_card — resume after failures."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

STATE_VERSION = 1

PHYSICAL_STEPS = (
    "card_lifecycle",
    "delete_packages",
    "install_fido",
    "install_attestation",
    "install_ndef",
    "make_credential",
    "verify_ndef",
)

VIRTUAL_STEPS = (
    "install_applets",
    "install_attestation",
    "make_credential",
    "verify_ndef",
)


def default_state_path(config_path: Path) -> Path:
    return config_path.with_suffix(config_path.suffix + ".provision-state.json")


def config_fingerprint(config: dict[str, Any]) -> str:
    payload = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ProvisionState:
    config_path: str
    config_fingerprint: str
    virtual: bool
    completed_steps: list[str] = field(default_factory=list)
    attestation: dict[str, Any] = field(default_factory=dict)
    make_credential: dict[str, Any] = field(default_factory=dict)
    last_error: Optional[str] = None
    failed_step: Optional[str] = None
    updated_at: Optional[str] = None
    version: int = STATE_VERSION

    @property
    def steps(self) -> tuple[str, ...]:
        return VIRTUAL_STEPS if self.virtual else PHYSICAL_STEPS

    def is_complete(self, step_id: str) -> bool:
        return step_id in self.completed_steps

    def first_incomplete(self) -> Optional[str]:
        for step_id in self.steps:
            if step_id not in self.completed_steps:
                return step_id
        return None

    def mark_complete(self, step_id: str, **extras: Any) -> None:
        if step_id not in self.completed_steps:
            self.completed_steps.append(step_id)
        if extras.get("attestation"):
            self.attestation.update(extras["attestation"])
        if extras.get("make_credential"):
            self.make_credential.update(extras["make_credential"])
        self.last_error = None
        self.failed_step = None
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_failed(self, step_id: str, error: str) -> None:
        self.failed_step = step_id
        self.last_error = error
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def reset_all(self) -> None:
        self.completed_steps = []
        self.attestation = {}
        self.make_credential = {}
        self.last_error = None
        self.failed_step = None
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def reset_from_step(self, step_id: str) -> None:
        if step_id not in self.steps:
            raise ValueError(f"Unknown step {step_id!r}; expected one of: {', '.join(self.steps)}")
        idx = self.steps.index(step_id)
        drop = set(self.steps[idx:])
        self.completed_steps = [s for s in self.completed_steps if s not in drop]
        if step_id in (
            "install_applets",
            "install_fido",
            "install_attestation",
            "card_lifecycle",
            "delete_packages",
        ):
            self.attestation = {}
        if step_id in ("make_credential", "verify_ndef", "install_applets", "install_fido"):
            self.make_credential = {}
        self.last_error = None
        self.failed_step = None
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def virtual_session_steps(self) -> list[str]:
        """Steps to run in one jcardsim session when resuming (sim state is ephemeral)."""
        first = self.first_incomplete()
        if first is None:
            return []
        start = self.steps.index("install_applets")
        return list(self.steps[start:])

    def virtual_force_step(self, step_id: str) -> bool:
        """Re-run completed steps that precede the first incomplete step (fresh sim)."""
        first = self.first_incomplete()
        if first is None:
            return False
        return self.steps.index(step_id) <= self.steps.index(first)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "config_path": self.config_path,
            "config_fingerprint": self.config_fingerprint,
            "virtual": self.virtual,
            "completed_steps": self.completed_steps,
            "attestation": self.attestation,
            "make_credential": self.make_credential,
            "last_error": self.last_error,
            "failed_step": self.failed_step,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvisionState:
        if data.get("version", 1) != STATE_VERSION:
            raise ValueError(f"Unsupported provision state version: {data.get('version')}")
        return cls(
            version=data.get("version", STATE_VERSION),
            config_path=data["config_path"],
            config_fingerprint=data["config_fingerprint"],
            virtual=bool(data["virtual"]),
            completed_steps=list(data.get("completed_steps", [])),
            attestation=dict(data.get("attestation", {})),
            make_credential=dict(data.get("make_credential", {})),
            last_error=data.get("last_error"),
            failed_step=data.get("failed_step"),
            updated_at=data.get("updated_at"),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
            f.write("\n")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> ProvisionState:
        with path.open(encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    @classmethod
    def load_or_create(
        cls,
        *,
        config_path: Path,
        config: dict[str, Any],
        virtual: bool,
        state_path: Path,
        fresh: bool,
    ) -> ProvisionState:
        fingerprint = config_fingerprint(config)
        if fresh and state_path.is_file():
            state_path.unlink()

        if state_path.is_file():
            state = cls.load(state_path)
            if state.virtual != virtual:
                raise ValueError(
                    f"State file {state_path} is for "
                    f"{'virtual' if state.virtual else 'physical'} mode; "
                    f"re-run with {'--virtual' if state.virtual else 'no --virtual'} or --fresh"
                )
            return state

        return cls(
            config_path=str(config_path.resolve()),
            config_fingerprint=fingerprint,
            virtual=virtual,
        )


def attestation_dict_with_state(
    config: dict[str, Any],
    state: ProvisionState,
) -> dict[str, Any]:
    att = dict(config.get("attestation", {}))
    saved = state.attestation
    if saved.get("aaguid"):
        att["aaguid"] = saved["aaguid"]
    if saved.get("ca_private_key"):
        att["ca_private_key"] = saved["ca_private_key"]
    if saved.get("ca_cert_bytes"):
        att["ca_cert_bytes"] = saved["ca_cert_bytes"]
    return att


def attestation_extras_from_result(result: Any) -> dict[str, Any]:
    extras: dict[str, Any] = {"aaguid": result.aaguid.hex()}
    if result.ca_private_key_der is not None:
        extras["ca_private_key"] = base64.b64encode(result.ca_private_key_der).decode()
    if result.ca_cert_der is not None:
        extras["ca_cert_bytes"] = base64.b64encode(result.ca_cert_der).decode()
    return extras


class ProvisionRunner:
    """Run provisioning steps with checkpoint persistence."""

    def __init__(
        self,
        state: ProvisionState,
        state_path: Path,
        *,
        dry_run: bool = False,
    ) -> None:
        self.state = state
        self.state_path = state_path
        self.dry_run = dry_run

    def print_status(self) -> None:
        print(f"State file: {self.state_path}")
        if self.state.completed_steps:
            print(f"Completed: {', '.join(self.state.completed_steps)}")
        if self.state.failed_step:
            print(f"Last failure: {self.state.failed_step} — {self.state.last_error}")
        next_step = self.state.first_incomplete()
        if next_step:
            print(f"Next step: {next_step}")
        else:
            print("All steps complete.")

    def run_step(
        self,
        step_id: str,
        fn: Callable[[], Any],
        *,
        force: bool = False,
    ) -> Any:
        if not force and self.state.is_complete(step_id):
            print(f"==> Skip {step_id} (already completed)")
            return None
        try:
            result = fn()
            if not self.dry_run:
                extras: dict[str, Any] = {}
                if isinstance(result, dict):
                    extras = result
                self.state.mark_complete(step_id, **extras)
                self.state.save(self.state_path)
            return result
        except Exception as exc:
            if not self.dry_run:
                self.state.mark_failed(step_id, str(exc))
                self.state.save(self.state_path)
            raise
