# Development guide

## Prerequisites

- JDK (for Gradle)
- JavaCard SDK 3.0.4+ — `git submodule update --init sdks`
- Python 3 + venv with `requirements.txt`
- Optional: GlobalPlatformPro (`gp`) and a PC/SC reader for physical cards

## Build

```bash
./gradlew buildAllCaps
```

Individual modules:

```bash
./gradlew :applets:fido2:buildJavaCard
./gradlew :applets:ndef:buildJavaCard
```

Outputs:

| Artifact | Path |
|----------|------|
| FIDO2 CAP | `applets/fido2/build/javacard/FIDO2.cap` |
| NDEF CAP | `applets/ndef/build/javacard/openjavacard-ndef-stub.cap` |

## Test

```bash
./gradlew testAll          # JUnit + Python (recommended)
./scripts/run_python_tests.sh   # Python only
./gradlew :applets:fido2:test   # JUnit only
```

Simulator tests compile applet source directly — CAP files are not required for `testAll`.

CTAP commands `makeCredential`, `getAssertion`, and `getInfo` support **extended APDUs** (16-bit Lc/Le). Vendor `0x46` (attestation install) uses short APDUs with ISO command chaining. Other large responses use ISO GET RESPONSE chaining when needed. See `ExtendedApduTest` and `python/tests/ctap/test_extended_apdus.py`.

**Rosetta / architecture mismatch:** if `testAll` fails on `_cffi_backend`, create an x86_64 venv:

```bash
arch -x86_64 python3 -m venv venv-x86
arch -x86_64 ./venv-x86/bin/pip install -U -r requirements.txt
```

## Virtual provisioning

```bash
./gradlew buildAllCaps :applets:fido2:testJar
./register_card.sh config/card.example.json --virtual
```

## Code layout

| Path | Role |
|------|------|
| `applets/fido2/src/main/java/` | FIDO2 applet |
| `applets/ndef/src/main/java/` | NDEF applet (owns its own signing key) |
| `python/fido2applet/` | Provisioning, jcardsim harness, NDEF helpers |
| `python/tests/` | Integration tests (`unittest discover`) |
| `tools/` | CLIs (`register_card.py`, `get_install_parameters.py`, …) |

**Dependency rules:** `tools/` and `python/tests/` import `python/fido2applet/`. The library must not import tests. FIDO2 CAP build depends on the NDEF `.exp` export.

## Provisioning flow

`register_card.sh` (wraps `tools/register_card.py`) runs roughly:

1. Optional GP lifecycle for blank cards (`initialize` → `secure` → `lock`)
2. Delete old packages (if configured)
3. Install **NDEF** CAP
4. Install **FIDO2** CAP with install parameters
5. Load attestation cert (optional, vendor command `0x46`)
6. `makeCredential` with `rk: true` — creates key and wires NDEF
7. Optional NDEF URL verification over PC/SC

Resume: `--status`, `--from-step <name>`, `--fresh`, `--list-steps`.

## Common issues

| Symptom | Fix |
|---------|-----|
| `0x6985` on FIDO2 LOAD | Install NDEF first; delete partial package and retry from `install_ndef` |
| NDEF shows placeholder URL | Run `makeCredential` (step 6) |
| EEPROM full | Lower `fido_install` buffer sizes in `config/card.json` |
| Heavy CTAP traffic wears EEPROM | Increase `max_ram_scratch` / tune buffers with `tools/get_install_parameters.py` after tests pass |

## Config files

| File | Purpose |
|------|---------|
| `config/card.example.json` | Template — copy to `config/card.json` |
| `config/card.json` | Your GP key, base URL, install params (**gitignored**) |
| `config/fixtures/mds.json` | Test fixture metadata |
