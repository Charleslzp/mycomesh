from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from gateway.identity import create_identity, save_identity
from gateway.proxy_identity import ProxyIdentityError, import_proxy_identity, validate_proxy_identity


class ProxyIdentityTest(unittest.TestCase):
    def test_gateway_compatibility_keys_are_separate_from_provider_admission(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.json"
            save_identity(source, identity)
            source.chmod(0o600)
            manifest = root / "network.json"
            manifest.write_text(
                json.dumps(
                    {
                        "consumer_public_keys": [],
                        "gateway_consumer_public_keys": [identity.public_key],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(validate_proxy_identity(source, manifest), identity)

    def _manifest(self, root: Path, public_key: str) -> Path:
        path = root / "network.json"
        path.write_text(json.dumps({"consumer_public_keys": [public_key]}), encoding="utf-8")
        return path

    def test_imports_only_the_manifest_pinned_identity_with_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "backup.json"
            identity = create_identity()
            save_identity(source, identity)
            target = root / "volume" / "request-identity.json"

            imported = import_proxy_identity(source, target, self._manifest(root, identity.public_key))

            self.assertEqual(imported, identity)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
            self.assertEqual(validate_proxy_identity(target, root / "network.json"), identity)

    def test_rejects_unpinned_or_insecure_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "backup.json"
            identity = create_identity()
            save_identity(source, identity)
            manifest = self._manifest(root, create_identity().public_key)
            with self.assertRaisesRegex(ProxyIdentityError, "not authorized"):
                import_proxy_identity(source, root / "target.json", manifest)

            source.chmod(0o644)
            with self.assertRaisesRegex(ProxyIdentityError, "0600"):
                validate_proxy_identity(source, self._manifest(root, identity.public_key))

    def test_refuses_to_replace_an_existing_pinned_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = create_identity()
            second = create_identity()
            first_source = root / "first.json"
            second_source = root / "second.json"
            save_identity(first_source, first)
            save_identity(second_source, second)
            manifest = root / "network.json"
            manifest.write_text(
                json.dumps({"consumer_public_keys": [first.public_key, second.public_key]}),
                encoding="utf-8",
            )
            target = root / "volume" / "request-identity.json"
            import_proxy_identity(first_source, target, manifest)

            with self.assertRaisesRegex(ProxyIdentityError, "Refusing to replace"):
                import_proxy_identity(second_source, target, manifest)


if __name__ == "__main__":
    unittest.main()
