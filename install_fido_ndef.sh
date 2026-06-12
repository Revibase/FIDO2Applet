#!/usr/bin/env bash
set -euo pipefail

# DEPRECATED: use register_card.sh for full card provisioning.
#
# Install FIDO2Applet (NDEF backend) and the in-repo NDEF stub on a JavaCard.
#
# Usage:
#   ./register_card.sh config/card.json
#
# Or for FIDO+NDEF only (no attestation / makeCredential):
#   ./install_fido_ndef.sh "https://your.server/verify"
#
# Requires: gp (GlobalPlatformPro), built CAP files, python3

FIDO_CAP="${FIDO_CAP:-build/javacard/FIDO2.cap}"
NDEF_STUB_CAP="${NDEF_STUB_CAP:-applet-stub/build/javacard/openjavacard-ndef-stub.cap}"

FIDO_PACKAGE_AID="A000000647"
FIDO_APPLET_AID="A0000006472F0001"
NDEF_PACKAGE_AID="D276000177100211020001"
NDEF_APPLET_AID="D2760000850101"

NDEF_BASE_URL="${1:-}"

if [[ -z "$NDEF_BASE_URL" ]]; then
  echo "Usage: $0 <ndef-base-url>"
  echo "Example: $0 https://your.server/verify"
  exit 1
fi

if [[ ! -f "$FIDO_CAP" ]]; then
  echo "Missing FIDO2 CAP: $FIDO_CAP (run ./gradlew buildJavaCard with JC_HOME set)"
  exit 1
fi

if [[ ! -f "$NDEF_STUB_CAP" ]]; then
  echo "Missing NDEF stub CAP: $NDEF_STUB_CAP (run ./gradlew :applet-stub:buildJavaCard with JC_HOME set)"
  exit 1
fi

FIDO_PARAMS=$(python3 get_install_parameters.py \
  --only-allow-one-resident-credential \
  --enable-attestation \
  --ndef-base-url "$NDEF_BASE_URL")

echo "==> Installing FIDO2 host applet (package $FIDO_PACKAGE_AID)"
gp --install "$FIDO_CAP" --create "$FIDO_PACKAGE_AID" --params "$FIDO_PARAMS"

echo ""
echo "==> Load attestation certificate if needed:"
echo "    ./install_attestation_cert.py"
echo ""
echo "==> Create resident credential via CTAP makeCredential before relying on NDEF URL content."
echo ""

# serviceID 0x3F + FIDO2 applet AID A0000006472F0001
NDEF_INSTALL_PARAMS="3FA0000006472F0001"

echo "==> Installing read-only NDEF stub (package $NDEF_PACKAGE_AID, applet $NDEF_APPLET_AID)"
gp --install "$NDEF_STUB_CAP" \
  --create "$NDEF_APPLET_AID" \
  --params "$NDEF_INSTALL_PARAMS" \
  --default

echo ""
echo "Done. NDEF stub is contactless default; FIDO2 serves dynamic signed URLs via SIO."
