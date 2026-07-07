# Capabilities

> Custom single-credential signing appliance — not FIDO-certified.

## At a glance

| | This project |
|--|--------------|
| Credentials | **One** resident key for the life of the card |
| Algorithms | ES256 (P-256) only |
| PIN / UV | Not supported |
| CTAP 2.1 | Not advertised or implemented |
| Transport | CTAP CBOR over APDU (`CLA 0x80`, `INS 0x10`); **extended APDUs** for `makeCredential`, `getAssertion`, `getInfo` |

Applet AIDs: FIDO2 `A0000006472F0001`, NDEF `D2760000850101`.

## CTAP 2.0 commands

| Command | Status |
|---------|--------|
| `makeCredential` (`0x01`) | Supported (subset) |
| `getAssertion` (`0x02`) | Supported (subset) |
| `getInfo` (`0x04`) | Supported (subset) |
| `clientPIN`, `reset`, `cancel` | Not supported |
| Vendor `0x46` | Load attestation certificate chain (short APDU / command chaining only) |

### `getInfo`

Advertises `FIDO_2_0` always; adds `U2F_V2` after attestation cert is loaded.

Options: `rk: true`, `up: true` only. Extensions: none. `maxCredentialIdLength`: 64.

### `makeCredential`

| Behavior | Detail |
|----------|--------|
| `rk: true` | **Required** — omit or `false` → `INVALID_OPTION` |
| Second credential | `LIMIT_EXCEEDED` |
| `excludeList` | Ignored |
| Attestation | `packed` self-attestation by default; basic (`x5c`) after cert install |
| Credential ID | Fixed 64 bytes |

### `getAssertion`

| Behavior | Detail |
|----------|--------|
| `allowList` | Ignored — always signs with the resident key if present |
| RP ID | Not enforced — signs over whatever RP ID the host sends |
| User `id` | Returned when resident key is used |
| Counter | Wear-leveled 32-bit |

## U2F (`U2F_V2`)

Available only **after** attestation cert is loaded and **after** `makeCredential`.

| Command | Status |
|---------|--------|
| REGISTER | Always rejected (`SW_FILE_FULL`) |
| AUTHENTICATE | Signs with resident key |
| VERSION | Returns `U2F_V2` |

**Intentional differences from U2F spec:**

- Key handle is **ignored** (any length 0–255; content not checked)
- AppId hash binding is not enforced
- User-presence flag always set

Raw U2F uses `CLA 0x00`; errors are ISO 7816 status words, not CTAP bytes.

## NDEF (contactless)

Not part of FIDO. On NFC read, the NDEF applet returns an HTTPS URL with query params `pk`, `n`, `c`, `s` where `s` is an ECDSA signature over `(counter || nonce)` using the same P-256 key from `makeCredential`.

Placeholder URL until `makeCredential` runs. See [applets/ndef/README.md](../applets/ndef/README.md).

## Install parameters (FIDO2 applet)

| Key | Purpose | Default |
|-----|---------|---------|
| `0x00` | Allow attestation switch via `0x46` | `false` |
| `0x09` | `max_ram_scratch` | 512 |
| `0x0A` | `buffer_mem` / `maxMsgSize` | 2048 |
| `0x0B` | `flash_scratch` | 1024 |
| `0x0F` | Fixed attestation private key (32 bytes) | none |

## Source of truth

Code: [`FIDO2Applet.java`](../applets/fido2/src/main/java/us/q3q/fido2/FIDO2Applet.java)

Tests: [`test_ctap_basics.py`](../python/tests/ctap/test_ctap_basics.py), [`test_u2f_authenticate.py`](../python/tests/ctap/test_u2f_authenticate.py), [`test_ctap_basic_attestation.py`](../python/tests/ctap/test_ctap_basic_attestation.py)
