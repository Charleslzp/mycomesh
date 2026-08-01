from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.provider_bootstrap import load_or_create_provider_evm_identity
from gateway.provider_identity import (
    ProviderIdentityImportError,
    import_provider_evm_identity,
    main,
    provider_evm_identity_from_private_key,
    provider_identity_fingerprint,
    validate_provider_evm_identity,
    write_provider_evm_identity,
)


class ProviderIdentityImportTest(unittest.TestCase):
    def _identity(self, path: Path):
        return load_or_create_provider_evm_identity(path)

    def test_imports_identity_atomically_with_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "backup" / "provider-evm-identity.json"
            identity = self._identity(source)
            target = root / "volume" / "provider-evm-identity.json"

            imported = import_provider_evm_identity(source, target)

            self.assertEqual(imported, identity)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
            self.assertEqual(validate_provider_evm_identity(target), identity)
            self.assertEqual(import_provider_evm_identity(source, target), identity)

    def test_rejects_symlink_and_insecure_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source" / "provider-evm-identity.json"
            self._identity(source)
            symlink = root / "identity-link.json"
            symlink.symlink_to(source)

            with self.assertRaisesRegex(ProviderIdentityImportError, "symbolic link"):
                import_provider_evm_identity(symlink, root / "target.json")

            source.chmod(0o640)
            with self.assertRaisesRegex(ProviderIdentityImportError, "0600"):
                import_provider_evm_identity(source, root / "target.json")

    def test_refuses_to_replace_a_different_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_source = root / "first" / "provider-evm-identity.json"
            second_source = root / "second" / "provider-evm-identity.json"
            self._identity(first_source)
            self._identity(second_source)
            target = root / "volume" / "provider-evm-identity.json"
            import_provider_evm_identity(first_source, target)

            with self.assertRaisesRegex(ProviderIdentityImportError, "Refusing to replace"):
                import_provider_evm_identity(second_source, target)

    def test_cli_prints_only_public_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "provider-evm-identity.json"
            identity = self._identity(path)
            with patch("builtins.print") as output:
                self.assertEqual(main(["validate", "--identity", str(path)]), 0)
            rendered = str(output.call_args.args[0])
            self.assertIn(identity.address, rendered)
            self.assertNotIn(identity.private_key, rendered)

    def test_raw_key_import_derives_and_writes_identity_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.json"
            identity = self._identity(source)
            derived = provider_evm_identity_from_private_key(
                "0x" + identity.private_key[2:].upper()
            )
            self.assertEqual(derived, identity)
            self.assertEqual(
                provider_identity_fingerprint(identity),
                identity.private_key[2:6] + "..." + identity.private_key[-8:],
            )
            target = root / "target.json"
            self.assertEqual(write_provider_evm_identity(target, derived), identity)
            self.assertEqual(validate_provider_evm_identity(target), identity)
            with self.assertRaisesRegex(ProviderIdentityImportError, "Refusing to replace"):
                write_provider_evm_identity(
                    target,
                    provider_evm_identity_from_private_key("0x" + "12" * 32),
                )


if __name__ == "__main__":
    unittest.main()
