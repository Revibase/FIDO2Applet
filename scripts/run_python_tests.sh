#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="${ROOT}/python${PYTHONPATH:+:${PYTHONPATH}}"

# shellcheck source=scripts/pick_python.sh
source "$ROOT/scripts/pick_python.sh"
pick_python "$ROOT"

if ! "${PYTHON_LAUNCH[@]}" -c "import fido2" 2>/dev/null; then
    echo "Python dependencies missing or wrong CPU architecture for this process." >&2
    if is_x86_64_process && [[ ! -x "$ROOT/venv-x86/bin/python" ]]; then
        echo "This shell is x86_64 (often via Rosetta when Gradle/Java is Intel)." >&2
        echo "Create an x86_64 venv and retry:" >&2
        echo "  arch -x86_64 python3 -m venv venv-x86" >&2
        echo "  arch -x86_64 ./venv-x86/bin/pip install -U -r requirements.txt" >&2
    else
        echo "Run once:" >&2
        echo "  python3 -m venv venv && ./venv/bin/pip install -U -r requirements.txt" >&2
    fi
    exit 1
fi

exec "${PYTHON_LAUNCH[@]}" -m unittest discover -s python/tests "$@"
