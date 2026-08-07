# NDEF applet

Read-only NFC Type 4 tag. Serves a **signed HTTPS URL** using its **own** on-card P-256 key (generated at install; never shared with or received from any other applet).

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

Empty params → placeholder URL (no base URL configured).

## Signed URL format

Query params: `pk` (compressed public key), `c` (uint32 counter, zero-padded decimal), `n` (8-byte nonce), `s` (64-byte raw ECDSA r||s).

**Signed preimage:** `counter (4 bytes BE) || nonce (8 bytes)`, hashed with SHA-256 under ECDSA P-256. The install base URL is not covered by the signature; pass `base_url=` to `verify_signed_ndef_uri` for a URI prefix check.

The applet generates its P-256 keypair on install, stores the private key as a persistent Java Card key object, and signs locally on the first E104 data read (not on SELECT/CC probes). The private key never leaves the applet.

**Anti-replay:** NFC Type 4 is read-only — servers must persist the last-seen counter per `pk` and reject `c < last+1` (see `verify_signed_ndef_uri(..., min_counter=...)`).

`pk` is this applet's own public key — **distinct** from the FIDO credential ID. The two are bound to one card server-side at enrollment. Each applet keeps its own wear-leveled counter.

## FIDO2 integration

None at the applet level: FIDO2 and NDEF are independent, each with its own key. They are linked only server-side, where enrollment records both public keys against one card.

Main docs: [README](../../README.md) · [capabilities](../../docs/capabilities.md)
