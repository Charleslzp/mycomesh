#!/usr/bin/env python3
"""Validate Buildx inspection output and capture pinned Provider OCI metadata.

The input is the JSON emitted by::

    docker buildx imagetools inspect IMAGE --format '{{json .}}'

Only a two-platform linux/amd64 + linux/arm64 OCI index is accepted. BuildKit
attestation manifests (reported as unknown/unknown) may be present, but they
are validated as attestations and never counted as runnable platforms.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "mycomesh.oci-metadata.v1"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
REVISION_LABEL = "org.opencontainers.image.revision"
ATTESTATION_TYPE = "attestation-manifest"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
REPOSITORY_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$"
)
REQUIRED_PLATFORMS = ("linux/amd64", "linux/arm64")
MAX_INPUT_BYTES = 8 * 1024 * 1024


class OCIMetadataError(ValueError):
    """The inspection result cannot prove the expected release image."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OCIMetadataError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_inspection(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise OCIMetadataError("Buildx inspection input must be a regular file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise OCIMetadataError("Buildx inspection input exceeds 8 MiB")
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise OCIMetadataError("Buildx inspection input exceeds 8 MiB")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                OCIMetadataError(f"invalid JSON constant: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OCIMetadataError("Buildx inspection input is not strict JSON") from exc
    if not isinstance(value, dict):
        raise OCIMetadataError("Buildx inspection input must be a JSON object")
    return value


def _validate_repository(repository: str) -> None:
    if (
        not isinstance(repository, str)
        or repository != repository.strip()
        or REPOSITORY_RE.fullmatch(repository) is None
        or "@" in repository
    ):
        raise OCIMetadataError(
            "Provider repository must be a lowercase registry/repository without tag or digest"
        )


def _validate_inspected_name(name: Any, repository: str, index_digest: str) -> None:
    if not isinstance(name, str) or name != name.strip():
        raise OCIMetadataError("Buildx inspection is missing the image name")
    if name == repository:
        return
    if name.startswith(repository + ":") and TAG_RE.fullmatch(name[len(repository) + 1 :]):
        return
    if name == repository + "@" + index_digest:
        return
    raise OCIMetadataError("Buildx inspection image is not the official Provider repository")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise OCIMetadataError(f"{label} must be a canonical sha256 OCI digest")
    return value


def _descriptor_common(descriptor: dict[str, Any], label: str) -> str:
    if descriptor.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
        raise OCIMetadataError(f"{label} is not an OCI image manifest descriptor")
    size = descriptor.get("size")
    if type(size) is not int or size <= 0:
        raise OCIMetadataError(f"{label} has an invalid descriptor size")
    return _digest(descriptor.get("digest"), f"{label} digest")


def _target_platform(platform: Any) -> str | None:
    if not isinstance(platform, dict):
        raise OCIMetadataError("OCI manifest descriptor is missing its platform")
    os_name = platform.get("os")
    architecture = platform.get("architecture")
    if not isinstance(os_name, str) or not isinstance(architecture, str):
        raise OCIMetadataError("OCI manifest descriptor has an invalid platform")
    platform_name = f"{os_name}/{architecture}"
    if platform_name not in REQUIRED_PLATFORMS:
        return None
    variant = platform.get("variant")
    if platform_name == "linux/amd64" and variant is not None:
        raise OCIMetadataError("linux/amd64 descriptor must not declare a variant")
    if platform_name == "linux/arm64" and variant not in (None, "v8"):
        raise OCIMetadataError("linux/arm64 descriptor has an unsupported variant")
    return platform_name


def _validate_attestation(
    descriptor: dict[str, Any], target_digests: set[str], seen_digests: set[str]
) -> None:
    digest = _descriptor_common(descriptor, "unknown/unknown descriptor")
    if digest in seen_digests:
        raise OCIMetadataError("OCI index contains duplicate manifest descriptor digests")
    seen_digests.add(digest)
    annotations = descriptor.get("annotations")
    if not isinstance(annotations, dict):
        raise OCIMetadataError("unknown/unknown descriptor is not a BuildKit attestation")
    if annotations.get("vnd.docker.reference.type") != ATTESTATION_TYPE:
        raise OCIMetadataError("unknown/unknown descriptor is not a BuildKit attestation")
    subject = annotations.get("vnd.docker.reference.digest")
    if subject not in target_digests:
        raise OCIMetadataError("BuildKit attestation does not reference a release platform")


def _revision_for_platform(image: dict[str, Any], platform_name: str, commit: str) -> str:
    image_config = image.get(platform_name)
    if not isinstance(image_config, dict):
        raise OCIMetadataError(f"Buildx inspection is missing {platform_name} image config")
    os_name, architecture = platform_name.split("/", 1)
    if image_config.get("os") != os_name or image_config.get("architecture") != architecture:
        raise OCIMetadataError(f"{platform_name} image config has mismatched platform fields")
    variant = image_config.get("variant")
    if platform_name == "linux/amd64" and variant is not None:
        raise OCIMetadataError("linux/amd64 image config must not declare a variant")
    if platform_name == "linux/arm64" and variant not in (None, "v8"):
        raise OCIMetadataError("linux/arm64 image config has an unsupported variant")
    config = image_config.get("config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or labels.get(REVISION_LABEL) != commit:
        raise OCIMetadataError(
            f"{platform_name} org.opencontainers.image.revision does not match source commit"
        )
    return commit


def capture_oci_metadata(
    *, inspect_path: Path, source_commit: str, repository: str
) -> dict[str, Any]:
    """Return release-gate metadata after validating Buildx inspection evidence."""
    if not isinstance(source_commit, str) or COMMIT_RE.fullmatch(source_commit) is None:
        raise OCIMetadataError("source commit must be lowercase 40-character hex")
    _validate_repository(repository)
    inspection = _load_inspection(inspect_path)

    manifest = inspection.get("manifest")
    if not isinstance(manifest, dict):
        raise OCIMetadataError("Buildx inspection is missing the OCI index manifest")
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != OCI_INDEX_MEDIA_TYPE:
        raise OCIMetadataError("Buildx inspection does not describe an OCI image index")
    index_digest = _digest(manifest.get("digest"), "OCI index digest")
    _validate_inspected_name(inspection.get("name"), repository, index_digest)

    raw_descriptors = manifest.get("manifests")
    if not isinstance(raw_descriptors, list) or not raw_descriptors:
        raise OCIMetadataError("OCI index does not contain manifest descriptors")
    targets: dict[str, str] = {}
    unknown: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    for descriptor in raw_descriptors:
        if not isinstance(descriptor, dict):
            raise OCIMetadataError("OCI index contains a non-object manifest descriptor")
        platform = descriptor.get("platform")
        platform_name = _target_platform(platform)
        if platform_name is None:
            assert isinstance(platform, dict)
            if platform.get("os") == "unknown" and platform.get("architecture") == "unknown":
                unknown.append(descriptor)
                continue
            raise OCIMetadataError("OCI index contains an unexpected runnable platform")
        digest = _descriptor_common(descriptor, platform_name)
        if platform_name in targets:
            raise OCIMetadataError(f"OCI index contains duplicate {platform_name} descriptors")
        if digest in seen_digests:
            raise OCIMetadataError("OCI index contains duplicate manifest descriptor digests")
        seen_digests.add(digest)
        targets[platform_name] = digest

    if set(targets) != set(REQUIRED_PLATFORMS):
        raise OCIMetadataError("OCI index must contain exactly linux/amd64 and linux/arm64")
    target_digests = set(targets.values())
    for descriptor in unknown:
        _validate_attestation(descriptor, target_digests, seen_digests)

    image = inspection.get("image")
    if not isinstance(image, dict) or set(image) != set(REQUIRED_PLATFORMS):
        raise OCIMetadataError(
            "Buildx image configs must contain exactly linux/amd64 and linux/arm64"
        )
    platforms = []
    for platform_name in REQUIRED_PLATFORMS:
        os_name, architecture = platform_name.split("/", 1)
        revision = _revision_for_platform(image, platform_name, source_commit)
        platforms.append(
            {
                "os": os_name,
                "architecture": architecture,
                "digest": targets[platform_name],
                "revision": revision,
            }
        )

    return {
        "schema": SCHEMA,
        "image": repository + "@" + index_digest,
        "index_digest": index_digest,
        "revision": source_commit,
        "platforms": platforms,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect-json", "--input", dest="inspect_json", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", "--provider-repository", dest="repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        metadata = capture_oci_metadata(
            inspect_path=args.inspect_json,
            source_commit=args.source_commit,
            repository=args.repository,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(metadata, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    except (OCIMetadataError, OSError) as exc:
        print(f"capture OCI metadata: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(args.output), "schema": SCHEMA}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
