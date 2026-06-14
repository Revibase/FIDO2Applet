#!/usr/bin/env bash
set -euo pipefail

# Provision a physical or virtual JavaCard: FIDO2 + attestation + NDEF stub + resident credential.
#
# Usage:
#   cp config/card.example.json config/card.json
#   ./tools/register_card.sh [config/card.json] [--dry-run]
#   ./tools/register_card.sh config/card.example.json --virtual   # jcardsim, no gp/reader
#   ./tools/register_card.sh config/card.json --status            # show resume state
#
# Requires: gp, python3, fido2, cryptography, pyscard; built CAP files (./gradlew buildAllCaps)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

CONFIG="${1:-config/card.json}"
shift || true

# shellcheck source=scripts/pick_python.sh
source "$REPO_ROOT/scripts/pick_python.sh"
pick_python "$REPO_ROOT"

if ! "${PYTHON_LAUNCH[@]}" -c "import fido2" 2>/dev/null; then
    echo "Python dependencies missing. Run once:" >&2
    echo "  python3 -m venv venv && ./venv/bin/pip install -U -r requirements.txt" >&2
    exit 1
fi

use_virtual=0
for arg in "$@"; do
    if [[ "$arg" == "--virtual" ]]; then
        use_virtual=1
        break
    fi
done
if [[ "$use_virtual" -eq 1 && "$(uname -m)" == "arm64" && "${FIDO2_NATIVE_JVM:-}" != "1" ]]; then
    if ! "${PYTHON_LAUNCH[@]}" -c "from fido2applet.jvm_util import jvm_path_loadable; raise SystemExit(0 if jvm_path_loadable() else 1)" 2>/dev/null; then
        echo "Note: arm64 Python + x86_64 JDK — re-running under Rosetta (arch -x86_64)." >&2
        echo "      Set FIDO2_NATIVE_JVM=1 to skip, or install an arm64 JDK and JAVA_HOME." >&2
        exec arch -x86_64 "$0" "$CONFIG" "$@"
    fi
fi

exec "${PYTHON_LAUNCH[@]}" "$REPO_ROOT/tools/register_card.py" "$CONFIG" "$@"
