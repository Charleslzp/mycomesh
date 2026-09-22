import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.capture_oci_metadata import (
    OCIMetadataError,
    SCHEMA,
    capture_oci_metadata,
    main,
)


COMMIT = "a" * 40
REPOSITORY = "ghcr.io/charleslzp/mycomesh-provider-codex"
INDEX_DIGEST = "sha256:" + "1" * 64
AMD64_DIGEST = "sha256:" + "2" * 64
ARM64_DIGEST = "sha256:" + "3" * 64


def descriptor(os_name, architecture, digest, **extra):
    value = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": digest,
        "size": 777,
        "platform": {"os": os_name, "architecture": architecture},
    }
    value.update(extra)
    return value


def inspection():
    return {
        "name": REPOSITORY + ":candidate",
        "manifest": {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": INDEX_DIGEST,
            "size": 2048,
            "manifests": [
                descriptor("linux", "amd64", AMD64_DIGEST),
                descriptor(
                    "unknown",
                    "unknown",
                    "sha256:" + "4" * 64,
                    annotations={
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": AMD64_DIGEST,
                    },
                ),
                descriptor(
                    "linux",
                    "arm64",
                    ARM64_DIGEST,
                    platform={"os": "linux", "architecture": "arm64", "variant": "v8"},
                ),
                descriptor(
                    "unknown",
                    "unknown",
                    "sha256:" + "5" * 64,
                    annotations={
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": ARM64_DIGEST,
                    },
                ),
            ],
        },
        "image": {
            "linux/amd64": {
                "os": "linux",
                "architecture": "amd64",
                "config": {"Labels": {"org.opencontainers.image.revision": COMMIT}},
            },
            "linux/arm64": {
                "os": "linux",
                "architecture": "arm64",
                "variant": "v8",
                "config": {"Labels": {"org.opencontainers.image.revision": COMMIT}},
            },
        },
    }


class CaptureOCIMetadataTest(unittest.TestCase):
    def capture(self, value=None, *, commit=COMMIT, repository=REPOSITORY):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inspect.json"
            path.write_text(json.dumps(inspection() if value is None else value))
            return capture_oci_metadata(
                inspect_path=path, source_commit=commit, repository=repository
            )

    def test_captures_pinned_two_platform_metadata_and_ignores_attestations(self):
        result = self.capture()
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["image"], REPOSITORY + "@" + INDEX_DIGEST)
        self.assertEqual(result["index_digest"], INDEX_DIGEST)
        self.assertEqual(result["revision"], COMMIT)
        self.assertEqual(
            result["platforms"],
            [
                {
                    "os": "linux",
                    "architecture": "amd64",
                    "digest": AMD64_DIGEST,
                    "revision": COMMIT,
                },
                {
                    "os": "linux",
                    "architecture": "arm64",
                    "digest": ARM64_DIGEST,
                    "revision": COMMIT,
                },
            ],
        )

    def test_rejects_wrong_repository_or_noncanonical_commit(self):
        value = inspection()
        value["name"] = "ghcr.io/attacker/provider:candidate"
        with self.assertRaisesRegex(OCIMetadataError, "official Provider repository"):
            self.capture(value)
        with self.assertRaisesRegex(OCIMetadataError, "lowercase 40-character"):
            self.capture(commit="A" * 40)
        with self.assertRaisesRegex(OCIMetadataError, "without tag or digest"):
            self.capture(repository=REPOSITORY + ":latest")

    def test_rejects_extra_missing_or_duplicate_runnable_platforms(self):
        extra = inspection()
        extra["manifest"]["manifests"].append(
            descriptor("linux", "s390x", "sha256:" + "6" * 64)
        )
        with self.assertRaisesRegex(OCIMetadataError, "unexpected runnable platform"):
            self.capture(extra)

        missing = inspection()
        missing["manifest"]["manifests"] = missing["manifest"]["manifests"][:2]
        missing["image"].pop("linux/arm64")
        with self.assertRaisesRegex(OCIMetadataError, "exactly linux/amd64"):
            self.capture(missing)

        duplicate = inspection()
        duplicate["manifest"]["manifests"].insert(
            1, descriptor("linux", "amd64", "sha256:" + "6" * 64)
        )
        with self.assertRaisesRegex(OCIMetadataError, "duplicate linux/amd64"):
            self.capture(duplicate)

    def test_unknown_platform_must_be_attestation_for_a_release_platform(self):
        not_attestation = inspection()
        not_attestation["manifest"]["manifests"][1].pop("annotations")
        with self.assertRaisesRegex(OCIMetadataError, "not a BuildKit attestation"):
            self.capture(not_attestation)

        wrong_subject = inspection()
        wrong_subject["manifest"]["manifests"][1]["annotations"][
            "vnd.docker.reference.digest"
        ] = "sha256:" + "9" * 64
        with self.assertRaisesRegex(OCIMetadataError, "does not reference"):
            self.capture(wrong_subject)

    def test_each_platform_config_must_have_matching_revision_label(self):
        wrong = inspection()
        wrong["image"]["linux/arm64"]["config"]["Labels"][
            "org.opencontainers.image.revision"
        ] = "b" * 40
        with self.assertRaisesRegex(OCIMetadataError, "arm64.*does not match"):
            self.capture(wrong)

        missing = inspection()
        del missing["image"]["linux/amd64"]["config"]["Labels"]
        with self.assertRaisesRegex(OCIMetadataError, "amd64.*does not match"):
            self.capture(missing)

    def test_rejects_non_oci_index_and_invalid_digest(self):
        docker_list = inspection()
        docker_list["manifest"]["mediaType"] = (
            "application/vnd.docker.distribution.manifest.list.v2+json"
        )
        with self.assertRaisesRegex(OCIMetadataError, "OCI image index"):
            self.capture(docker_list)
        bad_digest = inspection()
        bad_digest["manifest"]["digest"] = "sha256:ABC"
        with self.assertRaisesRegex(OCIMetadataError, "canonical sha256"):
            self.capture(bad_digest)

    def test_strict_json_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inspect.json"
            path.write_text('{"name":"one","name":"two"}')
            with self.assertRaisesRegex(OCIMetadataError, "duplicate JSON key"):
                capture_oci_metadata(
                    inspect_path=path, source_commit=COMMIT, repository=REPOSITORY
                )

    def test_cli_exclusive_create(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "inspect.json"
            output_path = root / "evidence" / "oci.json"
            input_path.write_text(json.dumps(inspection()))
            arguments = [
                "--inspect-json",
                str(input_path),
                "--source-commit",
                COMMIT,
                "--repository",
                REPOSITORY,
                "--output",
                str(output_path),
            ]
            self.assertEqual(main(arguments), 0)
            self.assertEqual(json.loads(output_path.read_text())["schema"], SCHEMA)
            self.assertEqual(main(arguments), 1)
            self.assertTrue(output_path.is_file())


if __name__ == "__main__":
    unittest.main()
