"""Repository root and shared path helpers."""

from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    """Absolute path to the repository root (parent of ``python/``)."""
    return Path(__file__).resolve().parent.parent.parent


def fido2_jar_dir() -> Path:
    """Directory containing fido2applet main/test JARs for jcardsim."""
    return repo_root() / "applets" / "fido2" / "build" / "libs"
