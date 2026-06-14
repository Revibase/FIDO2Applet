# NDEF applet (`applets/ndef`)

Read-only NDEF Type 4 tag stub. On **NDEF applet SELECT** (and before CC / E104 reads in the same session), `NdefApplet` builds a signed URL locally using the resident credential key pushed by FIDO2 during `makeCredential`. The CC advertises a fixed NDEF file capacity (320 bytes); the active message length comes from the 2-byte NLEN prefix. The counter in the signed URL is zero-padded to 10 decimal digits so the encoded file size is constant for a given base URL. Host tools and tests use the passive Type 4 detection procedure (SELECT AID → CC → NDEF file → READ), matching Android/iOS NFC stacks, and validate NDEF record lengths strictly (as Android `NdefMessage` does).

This tree was vendored from [openjavacard-ndef](https://github.com/openjavacard/openjavacard-ndef) (`applet-stub` variant only).

## Build

```bash
./gradlew :applets:ndef:buildJavaCard
```

Output: `applets/ndef/build/javacard/openjavacard-ndef-stub.cap`

Install **before** `FIDO2.cap` (FIDO2 imports `NdefKeyStore` from the stub `.exp`).

## Install parameters

GlobalPlatformPro `--params` for the NDEF applet instance is the **raw UTF-8 base URL** (hex-encoded), e.g.:

```bash
gp --install openjavacard-ndef-stub.cap \
  --create D2760000850101 \
  --params 68747470733a2f2f6578616d706c652e636f6d2f766572696679
```

Empty params serve the placeholder URL until `makeCredential` pushes a signing key.

## Shareable

FIDO2 pushes the EC private key once via `NdefKeyStore` (service ID `0x41`) during resident `makeCredential`. Only the FIDO2 applet AID (`A0000006472F0001`) may call that interface.
