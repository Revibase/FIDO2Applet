# Installation Parameters

This applet provides a variety of install-time configurable settings. These are configured via a
CBOR map provided when the applet is installed (for example, via `gpp --install <applet> --params <params>`).

To generate the parameter string, use the `get_install_parameters.py` script at the root of the repository.
The help the script provides (`--help`) explains each options.

The defaults - when no install parameters are provided - are for maximum FIDO standards compatibility, but
won't accept an attestation certificate. So if you want CTAP1/U2F, you'll need to install the applet with
parameters.

If you want attestation to work, you'll also need to run `./install_attestation_cert.py` after installing the
applet itself!

## Full card registration (FIDO + attestation + NDEF + credential)

For provisioning a new physical JavaCard in one step, use the registration script and config file:

```bash
cp config/card.example.json config/card.json
# Edit config/card.json (NDEF base URL, RP/user, attestation org, etc.)
./register_card.sh config/card.json
```

This performs, in order:

1. Initialize, secure, and lock the card with `gp.master_key` (optional, when `gp.card_lifecycle.run_before_install` is true)
2. Delete existing FIDO/NDEF packages (optional, configurable)
3. Install FIDO2Applet with CBOR install parameters from `fido_install` in the config
4. Load attestation certificate and AAGUID via CTAP vendor command `0x46`
5. Install the NDEF stub applet from `applet-stub/` (contactless default) wired to FIDO2 via SIO
6. Call CTAP `makeCredential` with a resident key (`rk: true`) so NDEF serves a signed URL
7. Optionally read and verify the NDEF URI over PC/SC

Use `./register_card.sh config/card.json --dry-run` to print `gp` and CTAP steps without executing them.

### Resume after failure

Progress is saved to `<config>.provision-state.json` (e.g. `config/card.json.provision-state.json`) after each successful step. If a step fails, re-run the same command to resume from the next incomplete step:

```bash
./register_card.sh config/card.json          # resumes automatically
./register_card.sh config/card.json --status # show completed steps / last error
./register_card.sh config/card.json --fresh    # clear state and start over
./register_card.sh config/card.json --from-step install_attestation  # retry from a step
./register_card.sh config/card.json --list-steps
```

Generated attestation CA keys and AAGUID are stored in the state file when first created so a resumed run uses the same attestation material.

For **virtual** mode (`--virtual`), jcardsim does not persist between runs; resume re-runs CTAP steps from the first incomplete step in a fresh simulator session.

### Prerequisites

- `JC_HOME` set; build CAPs: `./gradlew buildJavaCard :applet-stub:buildJavaCard`
- [GlobalPlatformPro](https://github.com/martinpaloukas/globalplatformpro) (`gp`) on `PATH`
- Python 3 with `fido2`, `cryptography`, and `pyscard` (same as the CTAP test suite)
- PC/SC reader connected; user allowed to access `pcscd`

See [`config/card.example.json`](../config/card.example.json) for all configuration fields.

### GlobalPlatform card lifecycle (MASTER_KEY)

When provisioning a **new** blank card, set `gp.card_lifecycle.run_before_install` to `true`. The script will run, in order:

1. **`gp --initialize-card`** — ISD to INITIALIZED state  
2. **`gp --secure-card`** — ISD to SECURED state  
3. **`gp --lock <MASTER_KEY>`** — replace the factory SCP key with your `gp.master_key`

Lifecycle commands authenticate with `gp.default_master_key` if set, otherwise GlobalPlatformPro’s factory default. All subsequent `gp` steps (delete, install) use `-k <MASTER_KEY>`.

For a card that is **already locked** with your key, set `run_before_install` to `false` and keep `gp.master_key` set so every `gp` invocation passes `-k`.

Keep `config/card.json` out of version control (it contains `master_key`). Copy from `config/card.example.json`.

### Attestation only

To load attestation on an already-installed applet:

```bash
./install_attestation_cert.py
```

See also [Installing the Applet for Basic Attestation](certs.md).
