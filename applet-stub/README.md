# NDEF stub applet

Read-only NDEF Type 4 tag stub that forwards NDEF payload bytes from the FIDO2Applet host via JavaCard SIO (`NdefService`).

This tree was vendored from [openjavacard-ndef](https://github.com/openjavacard/openjavacard-ndef) (`applet-stub` variant only).

## Build

With `JC_HOME` set:

```bash
./gradlew :applet-stub:buildJavaCard
```

Output: `applet-stub/build/javacard/openjavacard-ndef-stub.cap`

Install on card with GlobalPlatform `--create D2760000850101` (NFC Type 4 Tag application AID). The CAP package AID is `D276000177100211020001`; see `config/card.example.json` for `aids.ndef_applet` vs `aids.ndef_package`.

Install parameters: `{ndef_service_id}{fido_applet_aid}` (default `3FA0000006472F0001`). See `config/card.example.json` and `docs/installation.md`.
