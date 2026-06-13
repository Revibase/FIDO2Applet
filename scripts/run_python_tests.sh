#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pick_python() {
    if [[ -n "${PYTHON:-}" && -x "$PYTHON" ]]; then
        echo "$PYTHON"
        return
    fi
    if [[ -x "$ROOT/venv/bin/python" ]]; then
        echo "$ROOT/venv/bin/python"
        return
    fi
    if [[ -x "$ROOT/venv-x86/bin/python" ]]; then
        echo "$ROOT/venv-x86/bin/python"
        return
    fi
    command -v python3
}

PYTHON="$(pick_python)"

if ! "$PYTHON" -c "import fido2" 2>/dev/null; then
    echo "Python test dependencies missing. Run once:" >&2
    echo "  python3 -m venv venv && ./venv/bin/pip install -U -r requirements.txt" >&2
    exit 1
fi

if [[ "$(uname -m)" == "arm64" && "$PYTHON" == *"venv-x86"* ]]; then
    exec arch -x86_64 "$PYTHON" -m unittest discover -s python_tests "$@"
fi

exec "$PYTHON" -m unittest discover -s python_tests "$@"
