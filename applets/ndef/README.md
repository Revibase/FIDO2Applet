# NDEF applet

Read-only NFC Type 4 tag. Serves a **signed HTTPS URL** using the P-256 key pushed by FIDO2 during `makeCredential`.

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

## Signed URL format

Query params: `pk` (compressed public key), `c` (uint32 counter, zero-padded decimal), `n` (8-byte nonce), `s` (64-byte raw ECDSA r||s).

**Signed preimage:** `counter (4 bytes BE) || nonce (8 bytes)`, hashed with SHA-256 under ECDSA P-256. The install base URL is not covered by the signature; pass `base_url=` to `verify_signed_ndef_uri` for a URI prefix check.

Only the exact FIDO2 AID (`A0000006472F0001`) may push keys via `NdefKeyStore`. After push, plaintext staging is AES-encrypted on the **first NDEF applet SELECT**. The signed payload is built on the first E104 data read (not on SELECT/CC probes).

**Anti-replay:** NFC Type 4 is read-only — servers must persist the last-seen counter per `pk` and reject `c < last+1` (see `verify_signed_ndef_uri(..., min_counter=...)`).

`pk` equals the FIDO credential ID / assertion `user.id`. NDEF and FIDO2 use **independent** wear-leveled counters.

## FIDO2 integration

During resident `makeCredential`, FIDO2 pushes the EC private key and compressed public key through the `NdefKeyStore` shareable interface (service ID `0x41`).

Main docs: [README](../../README.md) · [capabilities](../../docs/capabilities.md)
