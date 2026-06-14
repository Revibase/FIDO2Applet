#!/usr/bin/env bash
# Shared Python selection for scripts that need fido2/cryptography.
# Usage:
#   source "$(dirname "$0")/scripts/pick_python.sh"
#   pick_python "$REPO_ROOT"
#   exec "${PYTHON_LAUNCH[@]}" tools/register_card.py ...

# True when this shell/process runs as x86_64 (native Intel or Rosetta).
is_x86_64_process() {
    if [[ "$(uname -m)" == "x86_64" ]]; then
        return 0
    fi
    if [[ "$(uname -m)" == "arm64" ]]; then
        [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" == "1" ]]
        return
    fi
    return 1
}

pick_python() {
    local root="$1"
    export PYTHONPATH="${root}/python${PYTHONPATH:+:${PYTHONPATH}}"
    PYTHON_LAUNCH=()

    _jvm_resolvable() {
        local -a py=("$@")
        "${py[@]}" -c "
import sys
sys.path.insert(0, '${root}/python')
from fido2applet.jvm_util import resolve_jvm_path
resolve_jvm_path()
" 2>/dev/null
    }

    if [[ -n "${PYTHON:-}" && -x "$PYTHON" ]]; then
        PYTHON_LAUNCH=("$PYTHON")
        return 0
    fi
    if is_x86_64_process && [[ -x "$root/venv-x86/bin/python" ]]; then
        PYTHON_LAUNCH=("$root/venv-x86/bin/python")
        return 0
    fi
    if [[ -x "$root/venv/bin/python" ]] && _jvm_resolvable "$root/venv/bin/python"; then
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
    if [[ -x "$root/venv/bin/python" ]] && [[ "$(uname -m)" == "arm64" ]]; then
        if _jvm_resolvable arch -x86_64 "$root/venv/bin/python"; then
            PYTHON_LAUNCH=(arch -x86_64 "$root/venv/bin/python")
            return 0
        fi
    fi
    if [[ -x "$root/venv/bin/python" ]]; then
        PYTHON_LAUNCH=("$root/venv/bin/python")
        return 0
    fi
    PYTHON_LAUNCH=("$(command -v python3)")
}
