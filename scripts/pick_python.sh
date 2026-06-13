#!/usr/bin/env bash
# Shared Python selection for scripts that need fido2/cryptography.
# Usage:
#   source "$(dirname "$0")/scripts/pick_python.sh"
#   pick_python "$REPO_ROOT"
#   exec "${PYTHON_LAUNCH[@]}" register_card.py ...

pick_python() {
    local root="$1"
    PYTHON_LAUNCH=()

    if [[ -n "${PYTHON:-}" && -x "$PYTHON" ]]; then
        PYTHON_LAUNCH=("$PYTHON")
        return 0
    fi
    if [[ -x "$root/venv/bin/python" ]]; then
        PYTHON_LAUNCH=("$root/venv/bin/python")
        return 0
    fi
    if [[ -x "$root/venv-x86/bin/python" ]]; then
        if [[ "$(uname -m)" == "arm64" ]]; then
            PYTHON_LAUNCH=(arch -x86_64 "$root/venv-x86/bin/python")
        else
            PYTHON_LAUNCH=("$root/venv-x86/bin/python")
        fi
        return 0
    fi
    PYTHON_LAUNCH=("$(command -v python3)")
}
