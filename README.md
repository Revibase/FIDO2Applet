# FIDO2Applet

A **JavaCard signing appliance** with two applets on one card:

| Applet | Interface | Purpose |
|--------|-----------|---------|
| **FIDO2** (`applets/fido2/`) | PC/SC, CTAP-like APDUs | Create one P-256 key, sign challenges |
| **NDEF** (`applets/ndef/`) | NFC tap (Type 4 tag) | Serve a signed HTTPS URL with the same key |

Both applets share one private key via [`NdefKeyStore`](applets/ndef/src/main/java/org/openjavacard/ndef/stub/NdefKeyStore.java). The key is created on `makeCredential` and never leaves the card.

> **Not FIDO-certified.** This reuses CTAP/U2F framing for host integration but is **not** a full WebAuthn passkey token. See [docs/capabilities.md](docs/capabilities.md) for what is and is not supported.

## Quick start

```bash
git submodule update --init sdks
python3 -m venv venv && ./venv/bin/pip install -U -r requirements.txt
./gradlew testAll
```

`testAll` runs JUnit and Python integration tests in jcardsim (no physical card needed).

## How it works

```
Host (PC/SC)  ──makeCredential/getAssertion──►  FIDO2 applet  ──►  P-256 key
Phone (NFC)   ──read NDEF URL────────────────►  NDEF applet   ──►  same key
```

1. **Provision** — install both CAPs, optionally load an attestation cert, run `makeCredential` with `rk: true`.
2. **Contact** — host sends CTAP commands over APDUs; FIDO2 signs with the resident key.
3. **Contactless** — phone reads the NDEF URL; server verifies the ECDSA signature in the query string.

Until step 1 completes, NDEF serves a placeholder URL.

## Provision a physical card

```bash
cp config/card.example.json config/card.json   # edit base_url, master_key, etc.
./gradlew buildAllCaps
./register_card.sh config/card.json
```

You need: JavaCard SDK (submodule), [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (`gp`), a PC/SC reader, and Python deps from `requirements.txt`.

| Command | Use |
|---------|-----|
| `./register_card.sh config/card.json --dry-run` | Print steps without touching the card |
| `./register_card.sh config/card.json --virtual` | Smoke test in jcardsim |
| `./register_card.sh config/card.json --status` | Resume / check progress |

**Install order matters:** NDEF CAP first, then FIDO2 (FIDO2 imports the NDEF package).

Keep `config/card.json` private — it contains your GP master key.

## Build CAP files

```bash
./gradlew buildAllCaps
# FIDO2: applets/fido2/build/javacard/FIDO2.cap
# NDEF:  applets/ndef/build/javacard/openjavacard-ndef-stub.cap
```

Gradle picks up the SDK from `sdks/` or `JC_HOME`. Install-parameter helpers: `tools/get_install_parameters.py --help`.

## Project layout

```
FIDO2Applet/
├── applets/fido2/     CTAP-like applet source + CAP build
├── applets/ndef/      NDEF signed-URL applet
├── python/
│   ├── fido2applet/   Shared library (provisioning, sim, NDEF)
│   └── tests/         Integration tests
├── tools/             register_card.py, attestation helpers
├── config/            card.json example + fixtures
├── docs/              Capabilities and development notes
└── sdks/              JavaCard SDK (git submodule)
```

More detail: [docs/development.md](docs/development.md).

## What it supports (summary)

- **One** resident credential per card lifetime (`rk: true` required)
- CTAP 2.0 subset: `makeCredential`, `getAssertion`, `getInfo`
- U2F authenticate fallback after attestation cert is loaded (no U2F register)
- NDEF signed URLs on NFC tap
- ES256 (P-256) only; no PIN, UV, or credential management

Full list of supported commands, intentional deviations, and install parameters: [docs/capabilities.md](docs/capabilities.md).

## Security notes

- Possession of the card is enough to sign — there is no PIN or user verification.
- Exactly one credential per card; reinstall CAPs to reset.
- FIDO2 stores the resident private key as a persistent Java Card `ECPrivateKey` (signing uses a transient working copy). NDEF keeps its own AES wrap of the key copy it receives. FIDO2 and NDEF each maintain an **independent** wear-leveled signature counter.
- Credential ID is the 33-byte compressed public key; `getAssertion` returns the same value as `user.id` (and NDEF `pk`). See [docs/capabilities.md](docs/capabilities.md).
- Tune buffer install params only after `testAll` passes with your attestation chain size.

## Contributing

Pull requests and issues are welcome.
