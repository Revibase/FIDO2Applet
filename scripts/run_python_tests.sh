#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/pick_python.sh
source "$ROOT/scripts/pick_python.sh"
pick_python "$ROOT"

if ! "${PYTHON_LAUNCH[@]}" -c "import fido2" 2>/dev/null; then
    echo "Python dependencies missing. Run once:" >&2
    echo "  python3 -m venv venv && ./venv/bin/pip install -U -r requirements.txt" >&2
    exit 1
fi

exec "${PYTHON_LAUNCH[@]}" -m unittest discover -s python_tests "$@"
