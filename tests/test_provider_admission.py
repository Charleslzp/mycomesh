from __future__ import annotations

import json
import os
import socket
import threading
import unittest
from unittest.mock import patch

from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity, sign_document
from gateway.provider_admission import ENV_NAME, manifest_provider_keys, provider_keys_from_env
from gateway.relay import (RELAY_PROVIDER_REGISTRATION_PURPOSE, RelayError,
                           RelayProviderTCPServer, RelayState)


class ControlledProviderAdmissionTests(unittest.TestCase):
    def test_absent_policy_preserves_legacy_but_explicit_empty_never_opens_admission(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(provider_keys_from_env())
        for value in ("", " ", "aa", "a" * 64 + ",", "A" * 64):
            with self.subTest(value=value), patch.dict(os.environ, {ENV_NAME: value}):
                with self.assertRaises(ValueError):
                    provider_keys_from_env()

    def test_controlled_manifest_requires_nonempty_explicit_membership(self):
        for manifest in ({}, {"provider_admission": "any_signed"},
                         {"provider_admission": "allowlist", "provider_public_keys": []}):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                manifest_provider_keys(manifest, required=True)
        self.assertEqual(manifest_provider_keys({"provider_admission": "allowlist",
                         "provider_public_keys": ["a" * 64]}, required=True), frozenset(["a" * 64]))

    def test_cannot_use_allowlist_without_signature_verification(self):
        with self.assertRaises(RelayError):
            RelayState(require_signed_providers=False, authorized_provider_public_keys=frozenset(["a" * 64]))

    def test_direct_v9_entrypoint_cannot_bypass_membership_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RelayError, "explicit Provider allowlist"):
                RelayState(network_profile="testnet", settlement_version=9)
            # Local fixtures and existing V8 deployment behavior remain separate.
            private_key = "0x" + "13".rjust(64, "0")
            address = private_key_to_address(parse_private_key(private_key))
            identity = {"payment_address": address, "attestation_private_keys": {address: private_key}}
            self.assertIsNone(RelayState(network_profile="local", settlement_version=9, **identity).authorized_provider_public_keys)
            self.assertIsNone(RelayState(network_profile="testnet", settlement_version=8, **identity).authorized_provider_public_keys)

    def test_real_tcp_registration_accepts_member_rejects_stranger_and_forgery(self):
        allowed, stranger = create_identity(), create_identity()
        state = RelayState(authorized_provider_public_keys=frozenset([allowed.public_key]))
        server = RelayProviderTCPServer(("127.0.0.1", 0), state, "127.0.0.1", 9900)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        sockets = []
        try:
            def register(identity, claimed=None):
                sock = socket.create_connection(server.server_address, timeout=2)
                sock.settimeout(2)
                sockets.append(sock)
                stream = sock.makefile("rwb")
                sockets.append(stream)
                challenge = json.loads(stream.readline())
                public = claimed or identity
                peer = {"peer_id": public.peer_id, "public_key": public.public_key,
                        "network_profile": "local", "challenge": challenge["challenge"]}
                signed = sign_document(peer, identity.private_key,
                    purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=challenge["audience"])
                stream.write(json.dumps({"type": "provider_register", "peer": signed}).encode() + b"\n")
                stream.flush()
                return json.loads(stream.readline())
            self.assertFalse(register(stranger, claimed=allowed)["ok"])
            rejected = register(stranger)
            self.assertFalse(rejected["ok"])
            self.assertIn("not admitted", rejected["error"])
            self.assertEqual(len(state.providers), 0)
            self.assertTrue(register(allowed)["ok"])
            self.assertIn(allowed.peer_id, state.providers)
        finally:
            for resource in reversed(sockets):
                resource.close()
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
