#!/usr/bin/env bash
set -euo pipefail

# Provision a physical or virtual JavaCard: FIDO2 + attestation + NDEF stub + resident credential.
#
# Usage:
#   cp config/card.example.json config/card.json
#   ./register_card.sh [config/card.json] [--dry-run]
#   ./register_card.sh config/card.example.json --virtual   # jcardsim, no gp/reader
#   ./register_card.sh config/card.json --status            # show resume state
#
# Requires: gp, python3, fido2, cryptography, pyscard; built CAP files (./gradlew buildAllCaps)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CONFIG="${1:-config/card.json}"
shift || true

# shellcheck source=scripts/pick_python.sh
source "$SCRIPT_DIR/scripts/pick_python.sh"
pick_python "$SCRIPT_DIR"

if ! "${PYTHON_LAUNCH[@]}" -c "import fido2" 2>/dev/null; then
    echo "Python dependencies missing. Run once:" >&2
    echo "  python3 -m venv venv && ./venv/bin/pip install -U -r requirements.txt" >&2
    exit 1
fi

exec "${PYTHON_LAUNCH[@]}" register_card.py "$CONFIG" "$@"
