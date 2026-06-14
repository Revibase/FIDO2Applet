# Repository layout

This monorepo separates JavaCard applets, Python libraries, CLI tools, and docs.

```text
FIDO2Applet/
├── applets/
│   ├── fido2/          # FIDO2 CTAP2 applet (CAP: FIDO2.cap)
│   └── ndef/           # NDEF Type 4 signed-URL applet (vendored openjavacard-ndef stub)
├── python/
│   ├── fido2applet/    # Shared library (provisioning, NDEF, jcardsim harness)
│   └── tests/          # Python integration tests (unittest discover)
├── tools/              # User-facing CLIs (register_card, install params, …)
├── scripts/            # Build helpers (run_python_tests.sh, pick_python.sh)
├── config/             # card.json example + certs/fixtures templates
├── docs/               # Repository layout reference (repo_layout.md)
├── sdks/               # JavaCard SDK submodule (git submodule)
└── gradle/             # Shared Gradle config (JC_HOME resolution)
```

## Dependency direction

| Layer | May import |
|-------|------------|
| `tools/` | `python/fido2applet/` |
| `python/tests/` | `python/fido2applet/` |
| `python/fido2applet/` | must **not** import from `python/tests/` |
| `applets/fido2` | `applets/ndef` (JavaCard `.exp` dependency for CAP build) |

## Common paths

| Artifact | Path |
|----------|------|
| FIDO2 CAP | `applets/fido2/build/javacard/FIDO2.cap` |
| NDEF CAP | `applets/ndef/build/javacard/openjavacard-ndef-stub.cap` |
| jcardsim JARs | `applets/fido2/build/libs/fido2applet-*.jar` |
| Card config | `config/card.json` (copy from `config/card.example.json`) |

## Migration from old layout

| Old | New |
|-----|-----|
| `src/main/java/…` | `applets/fido2/src/main/java/…` |
| `applet-stub/` | `applets/ndef/` |
| `python_scripts/` | `python/fido2applet/` |
| `python_tests/` | `python/tests/` |
| Root `register_card.py` | `tools/register_card.py` (root `register_card.sh` wrapper kept) |
| `get_install_parameters.py` | `tools/get_install_parameters.py` |
| `certs.json` | `config/certs.example.json` |
| `mds.json` | `config/fixtures/mds.json` |
