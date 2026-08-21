"""POST card secp256r1 public key to Revibase /api/initialize after provisioning."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

from fido2applet.provision_state import ProvisionState

TOKEN_TYPE_NAMES = ("Controlled", "Bearer")


def _resolve_token_type(reg: dict[str, Any]) -> str:
    raw = reg.get("token_type", "Controlled")
    if raw in TOKEN_TYPE_NAMES:
        return raw
    raise ValueError(
        "register.token_type must be 'Controlled' or 'Bearer' "
        f"(got {raw!r})"
    )


def _ssl_context() -> ssl.SSLContext:
    """Build a verifying SSL context, falling back to certifi's CA bundle.

    Some Python installs (notably python.org builds on macOS) ship without a
    CA bundle wired into OpenSSL, so the default context can't verify any
    certificate. Prefer certifi's bundle when it's importable.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


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
    if not endpoint:
        print("==> Skip register (register.end_point not configured)")
        return None

    ndef_public_key = state.verify_ndef.get("public_key")
    if not ndef_public_key:
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

    # FIDO2 and NDEF applets use independent secp256r1 keys.
    # POST /api/initialize expects:
    #   publicKey   — FIDO2 credential id (compressed secp256r1 pubkey; PDA seed)
    #   identifier  — NDEF URL pk (chip binding field stored on the token)
    #   tokenType   — "Controlled" or "Bearer"
    secp256r1_public_key = credential_id
    identifier = reg.get("identifier") or ndef_public_key
    token_type = _resolve_token_type(reg)

    secret = (
        reg.get("secret")
        or os.environ.get("MINT_API_SECRET")
        or os.environ.get("OPERATOR_SECRET")
    )
    if not secret and not dry_run:
        raise ValueError(
            "register.secret or MINT_API_SECRET / OPERATOR_SECRET env var "
            "is required for backend registration"
        )

    payload: dict[str, Any] = {
        "publicKey": secp256r1_public_key,
        "identifier": identifier,
        "tokenType": token_type,
    }

    print(f"==> Register card with backend ({endpoint})")
    print(
        f"    tokenType={token_type!r}, "
        f"publicKey(fido)={secp256r1_public_key[:20]}… "
        f"identifier(ndef)={identifier[:20]}…"
    )
    if dry_run:
        return {}

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {secret}",
            "Accept": "application/json",
            # Cloudflare (error 1010) blocks the default "Python-urllib/x.y"
            # User-Agent, so present a normal browser signature.
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60, context=_ssl_context()) as resp:
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
            "public_key": secp256r1_public_key,
            "identifier": identifier,
            "token_type": token_type,
            "credential_id": credential_id,
            "result": result,
        }
    }
