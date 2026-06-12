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

PYTHON="${PYTHON:-python3}"
if [[ -x "$SCRIPT_DIR/venv-x86/bin/python" ]]; then
  PYTHON="$SCRIPT_DIR/venv-x86/bin/python"
fi

exec "$PYTHON" register_card.py "$CONFIG" "$@"
