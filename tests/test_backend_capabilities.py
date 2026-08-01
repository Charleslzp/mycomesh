from __future__ import annotations

import unittest

from gateway.backend_capabilities import (
    BACKEND_CAPABILITY_SCHEMA,
    CHAT_COMPLETIONS_ENDPOINT,
    CODEX_OAUTH_SIDECAR_KIND,
    RESPONSES_ENDPOINT,
    SELF_ATTESTED_TRUST_LEVEL,
    TRUST_EVIDENCE_SCHEMA,
    BackendCapabilityError,
    build_backend_capability,
    build_self_attested_trust_evidence,
    derive_verified_trust_level,
    normalize_backend_capability,
    normalize_trust_evidence,
    parse_provider_backend_metadata,
    validate_provider_backend_metadata,
)
from gateway.identity import IdentityError, create_identity, verify_document
from gateway.p2p import P2PError, ProviderConfig, provider_runtime_capabilities
from gateway.relay import (
    RELAY_PROVIDER_REGISTRATION_PURPOSE,
    _relay_provider_peer,
)


class BackendCapabilitySchemaTest(unittest.TestCase):
    def test_codex_app_server_advertises_dynamic_tool_support(self) -> None:
        capability = build_backend_capability("codex_app_server")

        self.assertEqual(capability["schema"], BACKEND_CAPABILITY_SCHEMA)
        self.assertEqual(capability["kind"], CODEX_OAUTH_SIDECAR_KIND)
        self.assertEqual(
            capability["endpoints"],
            [RESPONSES_ENDPOINT, CHAT_COMPLETIONS_ENDPOINT],
        )
        self.assertEqual(capability["protocol"], "openai_compatible")
        self.assertIs(capability["supports_streaming"], False)
        self.assertIs(capability["supports_tools"], True)

        for backend in ("codex_cli", "native_metered_http", "openai_http", "unknown"):
            with self.subTest(backend=backend):
                self.assertIs(build_backend_capability(backend)["supports_tools"], False)

    def test_backend_capability_keeps_unknown_extensions(self) -> None:
        capability = build_backend_capability("codex_app_server")
        capability["vendor_extension"] = {"revision": 2}

        normalized = normalize_backend_capability(capability)

        self.assertEqual(normalized["vendor_extension"], {"revision": 2})

    def test_backend_capability_rejects_malformed_critical_fields(self) -> None:
        for field, value, message in (
            ("schema", "future-schema", "schema"),
            ("kind", "Codex OAuth", "lowercase identifier"),
            ("protocol", "custom", "protocol"),
            ("endpoints", ["https://example.test/v1/responses"], "canonical"),
            ("supports_streaming", 1, "boolean"),
            ("supports_tools", "false", "boolean"),
        ):
            with self.subTest(field=field):
                capability = build_backend_capability("codex_app_server")
                capability[field] = value
                with self.assertRaisesRegex(BackendCapabilityError, message):
                    normalize_backend_capability(capability)

    def test_backend_capability_rejects_nested_credentials(self) -> None:
        capability = build_backend_capability("codex_app_server")
        capability["extension"] = {"refreshToken": "secret"}

        with self.assertRaisesRegex(BackendCapabilityError, "must not contain credentials"):
            normalize_backend_capability(capability)

    def test_backend_capability_rejects_embedded_trust_promotions(self) -> None:
        capability = build_backend_capability("codex_app_server")
        capability["extension"] = {"verifiedTrustLevel": "tee_verified"}

        with self.assertRaisesRegex(BackendCapabilityError, "reserved trust assertions"):
            normalize_backend_capability(capability)


class TrustEvidenceSchemaTest(unittest.TestCase):
    def test_self_attested_evidence_derives_only_self_attested_level(self) -> None:
        evidence = build_self_attested_trust_evidence()

        self.assertEqual(evidence["schema"], TRUST_EVIDENCE_SCHEMA)
        self.assertEqual(evidence["mode"], "self_attested")
        self.assertEqual(
            derive_verified_trust_level(evidence),
            SELF_ATTESTED_TRUST_LEVEL,
        )
        self.assertEqual(set(evidence["claims"].values()), {"not_verified"})

    def test_self_attested_evidence_keeps_benign_extensions(self) -> None:
        evidence = build_self_attested_trust_evidence()
        evidence["extension"] = {"operator_note": "local policy only"}
        evidence["claims"]["future_claim"] = "not_evaluated"

        normalized = normalize_trust_evidence(evidence)

        self.assertEqual(normalized["extension"]["operator_note"], "local policy only")
        self.assertEqual(normalized["claims"]["future_claim"], "not_evaluated")

    def test_self_attested_evidence_rejects_unverified_high_trust_claims(self) -> None:
        candidates = []
        tee_mode = build_self_attested_trust_evidence()
        tee_mode["mode"] = "tee"
        candidates.append((tee_mode, "only self_attested"))
        trust_level = build_self_attested_trust_evidence()
        trust_level["trust_level"] = "tee_verified"
        candidates.append((trust_level, "reserved trust assertions"))
        runtime_claim = build_self_attested_trust_evidence()
        runtime_claim["claims"]["runtime_integrity"] = "tee_verified"
        candidates.append((runtime_claim, "runtime_integrity"))
        upstream_claim = build_self_attested_trust_evidence()
        upstream_claim["upstream_signed"] = True
        candidates.append((upstream_claim, "reserved trust assertions"))
        camel_case_level = build_self_attested_trust_evidence()
        camel_case_level["verifiedTrustLevel"] = "tee_verified"
        candidates.append((camel_case_level, "reserved trust assertions"))
        nested_tee = build_self_attested_trust_evidence()
        nested_tee["extension"] = {"vendor": {"tee": "claimed"}}
        candidates.append((nested_tee, "reserved trust assertions"))

        for evidence, message in candidates:
            with self.subTest(evidence=evidence):
                with self.assertRaisesRegex(BackendCapabilityError, message):
                    normalize_trust_evidence(evidence)

    def test_self_attested_evidence_rejects_nested_credentials(self) -> None:
        evidence = build_self_attested_trust_evidence()
        evidence["extension"] = {"oauth": {"clientSecret": "secret"}}

        with self.assertRaisesRegex(BackendCapabilityError, "must not contain credentials"):
            normalize_trust_evidence(evidence)

    def test_provider_metadata_parser_never_upgrades_self_attestation(self) -> None:
        parsed = parse_provider_backend_metadata(
            {
                "backend_capability": build_backend_capability("codex_app_server"),
                "trust_evidence": build_self_attested_trust_evidence(),
                "future_descriptor_field": True,
            }
        )

        self.assertEqual(parsed["verified_trust_level"], SELF_ATTESTED_TRUST_LEVEL)
        self.assertEqual(
            validate_provider_backend_metadata(
                {
                    "backend_capability": parsed["backend_capability"],
                    "trust_evidence": parsed["trust_evidence"],
                }
            )["verified_trust_level"],
            SELF_ATTESTED_TRUST_LEVEL,
        )

    def test_metadata_parser_does_not_limit_unrelated_descriptor_fields(self) -> None:
        parsed = parse_provider_backend_metadata(
            {
                "backend_capability": build_backend_capability("codex_app_server"),
                "trust_evidence": build_self_attested_trust_evidence(),
                "unrelated_signed_extension": "x" * (40 * 1024),
            }
        )

        self.assertEqual(parsed["verified_trust_level"], SELF_ATTESTED_TRUST_LEVEL)


class ProviderDescriptorIntegrationTest(unittest.TestCase):
    def _provider(self, **overrides: object) -> ProviderConfig:
        identity = overrides.pop("identity", create_identity())
        values = {
            "peer_id": identity.peer_id,
            "channel": "codex-standard-v1",
            "agent_id": "coder",
            "agent_key": "local-key",
            "gateway_url": "http://127.0.0.1:8000/v1",
            "model": "mycomesh-codex-standard-v1",
            "advertise_host": "127.0.0.1",
            "advertise_port": 9700,
            "identity": identity,
            "network_profile": "local",
            "backend": "codex_app_server",
        }
        values.update(overrides)
        return ProviderConfig(**values)

    def test_runtime_capabilities_include_normalized_backend_and_trust(self) -> None:
        capabilities = provider_runtime_capabilities(self._provider())

        self.assertEqual(
            capabilities["backend_capability"]["kind"],
            CODEX_OAUTH_SIDECAR_KIND,
        )
        self.assertEqual(capabilities["trust_evidence"]["mode"], "self_attested")

    def test_provider_rejects_backend_kind_mismatch(self) -> None:
        wrong = build_backend_capability("openai_http")

        with self.assertRaisesRegex(P2PError, "kind must be 'codex_oauth_sidecar'"):
            self._provider(backend_capability=wrong)

    def test_relay_registration_signature_covers_backend_metadata(self) -> None:
        config = self._provider()
        audience = "relay.example:9901"
        signed = _relay_provider_peer(config, audience=audience, challenge="12" * 32)
        unsigned = verify_document(
            signed,
            purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE,
            audience=audience,
        )

        self.assertEqual(
            unsigned["backend_capability"]["kind"],
            CODEX_OAUTH_SIDECAR_KIND,
        )
        self.assertEqual(unsigned["trust_evidence"]["mode"], "self_attested")

        signed["backend_capability"]["supports_tools"] = False
        with self.assertRaises(IdentityError):
            verify_document(
                signed,
                purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE,
                audience=audience,
            )


if __name__ == "__main__":
    unittest.main()
