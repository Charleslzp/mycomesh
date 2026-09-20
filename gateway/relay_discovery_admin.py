"""Offline, explicit Relay admission signing. Never generates identities or sends transactions."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .provider_bootstrap import load_provider_evm_identity
from .relay_discovery import (
    ADMISSION_SCHEMA, DiscoveryError, MAX_RECORD_BYTES, _read_file,
    load_discovery_config, sign_record, verify_admission,
)


def endorse_admission(admission: dict, config: dict, *, private_key: str, address: str) -> dict:
    if address not in config["policy"]["authorities"]:
        raise DiscoveryError("Signing identity is not a configured discovery authority")
    if not isinstance(admission, dict) or not isinstance(admission.get("signatures"), list):
        raise DiscoveryError("Admission must include a signatures array (empty for an unsigned draft)")
    if any(not isinstance(item, dict) or item.get("signer") == address for item in admission["signatures"]):
        raise DiscoveryError("Invalid or already present authority endorsement")
    unsigned = {key: value for key, value in admission.items() if key != "signatures"}
    signed = {**unsigned, "signatures": [*admission["signatures"], {
        "signer": address, "signature": sign_record(ADMISSION_SCHEMA, unsigned, private_key),
    }]}
    # Partial certificates may be passed between authorities, but every existing
    # signature and the complete endpoint/deployment binding must already verify.
    return verify_admission(signed, policy={**config["policy"], "threshold": 1}, context=config["context"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["endorse", "verify"])
    parser.add_argument("--network-config", required=True)
    parser.add_argument("--admission", required=True)
    parser.add_argument("--identity-file", help="Existing protected authority identity file, only for endorse")
    parser.add_argument("--output", help="New output certificate file; existing files are never overwritten")
    args = parser.parse_args(argv)
    try:
        config = load_discovery_config(args.network_config)
        if config is None:
            raise DiscoveryError("Manifest does not enable Relay discovery")
        admission = _read_file(Path(args.admission), MAX_RECORD_BYTES)
        if args.action == "verify":
            if args.identity_file or args.output:
                raise DiscoveryError("Verification does not accept identity or output arguments")
            verified = verify_admission(admission, policy=config["policy"], context=config["context"])
            print(json.dumps({"valid": True, "relay": verified["public_url"], "attestation_address": verified["attestation_address"],
                              "expires_at": verified["expires_at"]}, sort_keys=True))
            return 0
        if not args.identity_file or not args.output:
            raise DiscoveryError("Endorsement requires --identity-file and a new --output path")
        identity = load_provider_evm_identity(args.identity_file)
        signed = endorse_admission(admission, config, private_key=identity.private_key, address=identity.address)
        with Path(args.output).open("x", encoding="ascii") as stream:
            stream.write(json.dumps(signed, sort_keys=True, indent=2) + "\n")
        count = len(signed["signatures"])
        print(json.dumps({"output": args.output, "endorsements": count, "required": config["policy"]["threshold"],
                          "quorum_met": count >= config["policy"]["threshold"]}, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
