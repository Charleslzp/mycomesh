from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gateway.identity import IdentityError, create_identity, load_or_create_identity, sign_document, verify_document


class IdentityTest(unittest.TestCase):
    def test_sign_and_verify_document(self) -> None:
        identity = create_identity()
        signed = sign_document({"hello": "world"}, identity.private_key, purpose="test")

        verified = verify_document(signed, purpose="test")

        self.assertEqual(verified, {"hello": "world"})

    def test_load_or_create_identity_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity.json"
            first = load_or_create_identity(path)
            second = load_or_create_identity(path)

        self.assertEqual(first.peer_id, second.peer_id)
        self.assertEqual(first.public_key, second.public_key)

    def test_verify_rejects_far_future_timestamp(self) -> None:
        identity = create_identity()
        signed = sign_document({"hello": "world"}, identity.private_key, purpose="test", timestamp=10_000)

        with self.assertRaisesRegex(IdentityError, "future"):
            verify_document(signed, purpose="test", now=1_000)


if __name__ == "__main__":
    unittest.main()
