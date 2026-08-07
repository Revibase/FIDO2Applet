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

## Key protection & threat model

**Two applets, two independent keys — nothing is ever shared between them.** The FIDO2 applet and
the NDEF applet each generate and hold their **own** P-256 key on-card, as a persistent Java Card
`ECPrivateKey` key object. Neither private key is ever transferred, wrapped, copied, or exposed
across the applet firewall. The two public keys are different; they are bound to one card
**server-side at enrollment** (provisioning posts both the FIDO `credentialId` and the NDEF `pk`).

**No command on either applet returns private-key material.** The full command surface — FIDO2
`makeCredential` / `getAssertion` / `getInfo` / vendor `0x46` / U2F register+authenticate, and
NDEF SELECT / READ BINARY (UPDATE BINARY is disabled) — emits only public keys, credential IDs,
attestation certs, and signatures. There is no export, dump, or debug path. Each applet signs
locally, in its own selected context, using its own key object; the private scalar never enters
an application buffer at all. No key material crosses the firewall because there is no
inter-applet key channel to attack.

**At-rest confidentiality depends on the secure element.** Both keys are stored as platform key
objects — there is no software wrapping and no wrapping secret to protect. Confidentiality at rest
(against physical EEPROM readout, side-channel, or fault attacks) is delegated entirely to the SE;
there are no application-level countermeasures. Choose hardware certified for your threat model
(CC EAL5+/6+ or FIPS 140-2/3, with DPA/fault/nonce-quality assurances). Because the card requires
no PIN or user verification, **possession of the card is full authorization to obtain
signatures** — by design.

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

Options: `rk: true`, `up: true` only. Extensions: none. `maxCredentialIdLength`: 33.

### `makeCredential`

| Behavior | Detail |
|----------|--------|
| `rk: true` | **Required** — omit or `false` → `INVALID_OPTION` |
| Second credential | Reuses the existing resident key (same credential ID); ignores new user/RP fields |
| User identity | Request `user.id` is required by clients but **not stored**. Assertion `user.id` is always the credential ID |
| `user.name` / RP ID | Accepted in the request CBOR but **not stored** |
| `excludeList` | Ignored |
| `up` option | `true` accepted (CTAP 2.1 style, sent by real platforms); `false` → `INVALID_OPTION` |
| `uv: true` | `UNSUPPORTED_OPTION` (no built-in UV) |
| `pinUvAuthParam` | Zero-length → `PIN_NOT_SET`; anything else → `PIN_AUTH_INVALID` |
| Attestation | `packed` self-attestation by default; basic (`x5c`) after cert install |
| Credential ID | Fixed **33 bytes** — compressed secp256r1 public key (`0x02/0x03 \|\| X`) of the FIDO2 key (distinct from the NDEF `pk`) |
| Private key storage | Persistent Java Card `ECPrivateKey`; signing uses a transient working key (never the persistent object directly) |

### `getAssertion`

| Behavior | Detail |
|----------|--------|
| `allowList` | Ignored — always signs with the resident key if present |
| RP ID | Not enforced — signs over whatever RP ID the host sends |
| User `id` | Always the **33-byte compressed public key** (same as the FIDO credential ID) |
| `up: false` | Accepted — signs silently with the UP flag cleared |
| `uv: true` | `UNSUPPORTED_OPTION` (no built-in UV) |
| `pinUvAuthParam` | Zero-length → `PIN_NOT_SET`; anything else → `PIN_AUTH_INVALID` |
| No resident key | `NO_CREDENTIALS` |
| Uninitialized / cleared private key | `NO_CREDENTIALS` |
| Counter | Wear-leveled 32-bit (independent of the NDEF counter) |

## U2F (`U2F_V2`)

Available only **after** attestation cert is loaded and **after** `makeCredential`.

| Command | Status |
|---------|--------|
| REGISTER | Reuses the existing resident key; no attestation → `SW_COMMAND_NOT_ALLOWED`; no RK → `SW_WRONG_DATA` |
| AUTHENTICATE | Signs with resident key; check-only (P1 `0x07`) → `SW_CONDITIONS_NOT_SATISFIED` (`0x6985`) per spec |
| VERSION | Returns `U2F_V2` |

**Intentional differences from U2F spec:**

- Key handle is **ignored** (any length 0–255; content not checked)
- AppId hash binding is not enforced
- User-presence flag always set

Raw U2F uses `CLA 0x00`; errors are ISO 7816 status words, not CTAP bytes.

## NDEF (contactless)

Not part of FIDO. On NFC read, the NDEF applet returns an HTTPS URL with query params `pk`, `n`, `c`, `s` where `s` is an ECDSA P-256 signature over `(counter || nonce)` using the **NDEF applet's own** P-256 key (generated on-card, independent of the FIDO2 key). `pk` is that key's 33-byte compressed public key — **distinct** from the FIDO credential ID; the server binds both to one card at enrollment.

NDEF’s signature counter is **independent** of FIDO2’s. Verifiers should check the signature and **should** reject replays by persisting the last-seen `c` per `pk` (pass `min_counter=last+1` to `verify_signed_ndef_uri`). NFC Type 4 is read-only; anti-replay is server-side. Optional `base_url` on the verifier only checks URI prefix (the base URL is not covered by the signature).

The NDEF applet generates its own key on install and signs locally; the signed payload is built on the first E104 data read. A placeholder URL is served only when no base URL is configured. See [applets/ndef/README.md](../applets/ndef/README.md).

## Install parameters (FIDO2 applet)

| Key | Purpose | Default |
|-----|---------|---------|
| `0x00` | Allow attestation switch via `0x46` | `false` |
| `0x09` | `max_ram_scratch` | 512 |
| `0x0A` | `buffer_mem` / `maxMsgSize` | 2048 |
| `0x0B` | `flash_scratch` | 1024 |
| `0x0F` | Fixed attestation private key (32 bytes) | none |

## Error codes

Distinct status values returned by the applet and the test that asserts each one.
Internal codes that need fault injection are covered in Java unit tests.

### CTAP (response body byte)

| Code | When | Test |
|------|------|------|
| `OK` (`0x00`) | Success | `ExtendedApduTest` / CTAP basics |
| `INVALID_COMMAND` (`0x01`) | Unknown CTAP command | `test_error_codes.test_invalid_command` |
| `INVALID_LENGTH` (`0x03`) | Bad vendor `0x46` length | `test_error_codes.test_invalid_length_attestation_install` |
| `CBOR_UNEXPECTED_TYPE` (`0x11`) | Wrong CBOR major type | `test_error_codes.test_cbor_unexpected_type` |
| `INVALID_CBOR` (`0x12`) | Out-of-order CTAP map keys | `test_error_codes.test_invalid_cbor_out_of_order_keys` |
| `MISSING_PARAMETER` (`0x14`) | Required CTAP field missing | `test_error_codes.test_missing_parameter_*` |
| `UNSUPPORTED_ALGORITHM` (`0x26`) | No ES256 in pubKeyCredParams | `test_error_codes.test_unsupported_algorithm` |
| `KEY_STORE_FULL` (`0x28`) | Cannot persist resident key (EEPROM/write failure) | Not CI-covered (no production test hooks) |
| `UNSUPPORTED_OPTION` (`0x2B`) | e.g. `uv: true` | `test_error_codes.test_unsupported_option_uv_true` |
| `INVALID_OPTION` (`0x2C`) | e.g. `rk: false` / missing `rk` | `test_error_codes.test_invalid_option_rk_false` |
| `NO_CREDENTIALS` (`0x2E`) | getAssertion with no RK | `test_error_codes.test_no_credentials_get_assertion` |
| `NOT_ALLOWED` (`0x30`) | Attestation switch when locked | `test_error_codes.test_not_allowed_attestation_locked` |
| `PIN_AUTH_INVALID` (`0x33`) | Non-empty pinUvAuthParam | `test_error_codes.test_pin_auth_invalid` |
| `PIN_NOT_SET` (`0x35`) | Empty pinUvAuthParam | `test_error_codes.test_pin_not_set` |
| `REQUEST_TOO_LARGE` (`0x39`) | user.id &gt; 64 | `test_error_codes.test_request_too_large_user_id` |
| `OTHER` (`0x7F`) | Internal failure (e.g. EC key generation) | Not CI-covered (no production test hooks) |

### ISO 7816 (status word)

| SW | When | Test |
|----|------|------|
| `CLA_NOT_SUPPORTED` | Wrong CLA | `AppletBasicTest.checkIncorrectCLA` |
| `INS_NOT_SUPPORTED` | Wrong INS | `AppletBasicTest.checkIncorrectINS` |
| `INCORRECT_P1P2` | Bad P1/P2 | `AppletBasicTest.checkIncorrectP1/P2` |
| `COMMAND_NOT_ALLOWED` (`0x6986`) | U2F without attestation | `test_u2f_authenticate` |
| `WRONG_DATA` (`0x6A80`) | U2F with no resident key | `test_u2f_authenticate` |
| `CONDITIONS_NOT_SATISFIED` (`0x6985`) | U2F check-only | `test_u2f_authenticate` |
| `WRONG_LENGTH` (`0x6700`) | U2F bad Lc | `test_u2f_authenticate` |

Intentionally untested: `SW_FILE_FULL` (sig-counter exhaustion). Chaining `0x61XX` is covered by short-APDU response tests.

## Source of truth

Code: [`FIDO2Applet.java`](../applets/fido2/src/main/java/us/q3q/fido2/FIDO2Applet.java)

Tests: [`test_error_codes.py`](../python/tests/ctap/test_error_codes.py), [`ErrorCodeInjectionTest.java`](../applets/fido2/src/test/java/us/q3q/fido2/ErrorCodeInjectionTest.java), [`test_ctap_basics.py`](../python/tests/ctap/test_ctap_basics.py), [`test_u2f_authenticate.py`](../python/tests/ctap/test_u2f_authenticate.py)
