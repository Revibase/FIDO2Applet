"""POST card secp256r1 public key to Revibase /api/mint after provisioning."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from fido2applet.provision_state import ProvisionState


def register_card_with_backend(
    config: dict[str, Any],
    state: ProvisionState,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    reg = config.get("register") or {}
    if reg.get("enabled") is False:
        print("==> Skip register (register.enabled is false)")
        return None

    endpoint = reg.get("end_point") or reg.get("endpoint")
    mint = reg.get("mint")
    if not endpoint or not mint:
        print("==> Skip register (register.end_point or register.mint not configured)")
        return None

    public_key = state.verify_ndef.get("public_key")
    if not public_key:
        raise RuntimeError(
            "verify_ndef.public_key missing from provision state; "
            "re-run from --from-step verify_ndef"
        )

    credential_id = state.make_credential.get("credential_id")
    if not credential_id:
        raise RuntimeError(
            "make_credential.credential_id missing from provision state; "
            "re-run from --from-step make_credential"
        )

    asset_type = reg.get("asset_type") or reg.get("assetType")
    if asset_type is None:
        raise ValueError(
            "register.asset_type is required for backend registration"
        )

    secret = reg.get("secret") or os.environ.get("OPERATOR_SECRET")
    if not secret and not dry_run:
        raise ValueError(
            "register.secret or OPERATOR_SECRET env var is required for backend registration"
        )

    payload: dict[str, Any] = {
        "mint": mint,
        "publicKey": public_key,
        "assetType": asset_type,
        "credentialId": credential_id,
    }

    print(f"==> Register card with backend ({endpoint})")
    print(
        f"    mint={mint!r}, assetType={asset_type!r}, "
        f"credentialId={credential_id[:20]}…, publicKey={public_key[:20]}…"
    )
    if dry_run:
        return {}

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {secret}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
            status = getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Register failed HTTP {exc.code}: {detail}") from exc

    if status >= 400:
        raise RuntimeError(f"Register failed HTTP {status}: {body}")

    result = json.loads(body) if body else {}
    print(f"    Backend response: {result}")
    return {
        "register": {
            "mint": mint,
            "public_key": public_key,
            "asset_type": asset_type,
            "credential_id": credential_id,
            "result": result,
        }
    }
