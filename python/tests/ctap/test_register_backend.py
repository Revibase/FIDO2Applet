"""Tests for POST /api/initialize payload from register_card."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from fido2applet.provision_state import ProvisionState
from fido2applet.register_backend import register_card_with_backend


class RegisterBackendTest(unittest.TestCase):
    def _state(self) -> ProvisionState:
        state = ProvisionState(
            config_path="/tmp/card.json",
            config_fingerprint="abc",
            virtual=True,
        )
        state.verify_ndef = {"public_key": "ndef-pk-b64url"}
        state.make_credential = {"credential_id": "fido-cred-b64url"}
        return state

    def _urlopen(self, captured: dict[str, object], body: bytes = b'{"result":"Success"}'):
        def fake_urlopen(req, **kwargs):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            captured["body"] = json.loads(req.data.decode("utf-8"))
            resp = MagicMock()
            resp.__enter__.return_value = resp
            resp.read.return_value = body
            resp.status = 200
            return resp

        return fake_urlopen

    def test_posts_initialize_api_payload(self) -> None:
        config = {
            "register": {
                "end_point": "https://developer.revibase.com/api/initialize",
                "secret": "test-secret",
                "token_type": "Controlled",
            }
        }
        captured: dict[str, object] = {}

        with patch("urllib.request.urlopen", side_effect=self._urlopen(captured)):
            result = register_card_with_backend(config, self._state())

        self.assertEqual(
            captured["url"],
            "https://developer.revibase.com/api/initialize",
        )
        self.assertEqual(captured["body"], {
            "publicKey": "fido-cred-b64url",
            "identifier": "ndef-pk-b64url",
            "tokenType": "Controlled",
        })
        self.assertEqual(captured["headers"]["Authorization"], "Bearer test-secret")
        self.assertEqual(result["register"]["result"], {"result": "Success"})
        self.assertEqual(result["register"]["token_type"], "Controlled")

    def test_identifier_override(self) -> None:
        config = {
            "register": {
                "end_point": "https://developer.revibase.com/api/initialize",
                "secret": "test-secret",
                "identifier": "custom-id",
            }
        }
        captured: dict[str, object] = {}

        with patch("urllib.request.urlopen", side_effect=self._urlopen(captured, b"{}")):
            register_card_with_backend(config, self._state())

        self.assertEqual(captured["body"]["identifier"], "custom-id")
        self.assertEqual(captured["body"]["tokenType"], "Controlled")

    def test_rejects_invalid_token_type(self) -> None:
        config = {
            "register": {
                "end_point": "https://developer.revibase.com/api/initialize",
                "secret": "test-secret",
                "token_type": 0,
            }
        }

        with self.assertRaisesRegex(ValueError, "Controlled.*Bearer"):
            register_card_with_backend(config, self._state())


if __name__ == "__main__":
    unittest.main()
