# NDEF applet

Read-only NFC Type 4 tag. On SELECT, builds a **signed HTTPS URL** using the P-256 key pushed by FIDO2 during `makeCredential`.

Vendored from [openjavacard-ndef](https://github.com/openjavacard/openjavacard-ndef) (`applet-stub`).

## Build & install

```bash
./gradlew :applets:ndef:buildJavaCard
# → applets/ndef/build/javacard/openjavacard-ndef-stub.cap
```

Install **before** `FIDO2.cap`. Install param is the **hex-encoded UTF-8 base URL**:

```bash
gp --install openjavacard-ndef-stub.cap --create D2760000850101 \
  --params 68747470733a2f2f6578616d706c652e636f6d2f766572696679
```

Empty params → placeholder URL until `makeCredential` runs.

## FIDO2 integration

During resident `makeCredential`, FIDO2 pushes the EC private key through the `NdefKeyStore` shareable interface (service ID `0x41`). Only the FIDO2 AID (`A0000006472F0001`) may call it.

Main docs: [README](../../README.md) · [capabilities](../../docs/capabilities.md)
