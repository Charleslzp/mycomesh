"""Production composition for Relay-hosted dynamic Provider-AI juries.

The lower-level jury modules are intentionally dependency-injected.  This file
is the single runtime composition boundary used by ``relay serve``: it binds a
validated dynamic V10 manifest to an RPC quorum, three durable stores, the Relay's
authenticated Provider sessions, and one private local evidence resolver.

No evidence HTTP client or public jury endpoint is provided here.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import math
import os
from pathlib import Path
from typing import Any

from . import chain, chain_v10, provider_jury
from .identity import NodeIdentity, peer_id_from_public_key
from .provider_bootstrap import (
    ProviderBootstrapError,
    ProviderNetworkConfig,
    _read_json_object,
)
from .provider_jury_chain import (
    ProviderJuryChainAdapter,
    ProviderJuryChainConfig,
    ProviderJuryChainError,
    _protected_key,
)
from .provider_jury_intake import (
    ProviderJuryEventIntake,
    ProviderJuryEventIntakeConfig,
)
from .provider_jury_runtime import (
    ProviderJuryRuntime,
    ProviderJuryRuntimePolicy,
)
from .provider_jury_worker import ProviderJuryRelayWorker


class ProviderJuryServiceError(RuntimeError):
    """The Relay jury service could not be composed safely."""


EvidenceResolver = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _canonical_hash(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryServiceError(f"{label} must be a canonical bytes32") from exc
    if normalized != value or normalized == chain.ZERO_BYTES32:
        raise ProviderJuryServiceError(
            f"{label} must be lowercase canonical nonzero bytes32"
        )
    return normalized


def _canonical_address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryServiceError(f"{label} must be a canonical address") from exc
    if normalized != value or normalized == chain.ZERO_ADDRESS:
        raise ProviderJuryServiceError(
            f"{label} must be lowercase canonical and nonzero"
        )
    return normalized


def _durable_path(value: Any, label: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise ProviderJuryServiceError(f"{label} is required")
    path = Path(value)
    if str(path) == ":memory:" or not path.is_absolute():
        raise ProviderJuryServiceError(f"{label} must be an absolute durable path")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ProviderJuryServiceError(f"{label} must be a regular file, not a symlink")
    if path.exists() and hasattr(os, "getuid") and path.stat().st_uid != os.getuid():
        raise ProviderJuryServiceError(f"{label} must be owned by the Relay account")
    return path


@dataclass(frozen=True)
class ProviderJuryServiceConfig:
    network: ProviderNetworkConfig
    rpc_url: str
    genesis_hash: str
    settlement_runtime_code_hash: str
    registry_runtime_code_hash: str
    jury_relay_public_key: str
    transaction_sender: str
    confirmations: int
    deployment_block: int
    policy_path: Path
    worker_db_path: Path
    transaction_db_path: Path
    intake_db_path: Path
    execution_enabled: bool
    transaction_key_file: Path | None = None
    max_gas_price_wei: int | None = None
    max_gas_units: int | None = None
    max_total_gas_cost_wei: int | None = None
    rpc_timeout_seconds: int = 15
    provider_timeout_seconds: float = 180.0
    max_snapshot_age_seconds: int = 300
    intake_max_scan_blocks: int = 500
    intake_max_logs_per_scan: int = 2_000

    def __post_init__(self) -> None:
        if not isinstance(self.network, ProviderNetworkConfig):
            raise ProviderJuryServiceError(
                "a validated Provider network config is required"
            )
        deployment = getattr(self.network, "deployment", None)
        if (
            deployment is None
            or int(getattr(deployment, "protocol_version", 0)) != 10
            or getattr(deployment, "committee_mode", "")
            != chain_v10.DYNAMIC_PROVIDER_JURY
        ):
            raise ProviderJuryServiceError(
                "Provider jury service requires a validated dynamic V10 network manifest"
            )
        if (
            not isinstance(self.rpc_url, str)
            or not self.rpc_url
            or self.rpc_url.strip() != self.rpc_url
            or "," in self.rpc_url
            or self.rpc_url not in self.network.settlement_rpc_urls
        ):
            raise ProviderJuryServiceError(
                "Provider jury service requires one RPC pinned by the network manifest"
            )
        _canonical_hash(self.genesis_hash, "jury genesis hash")
        _canonical_hash(
            self.settlement_runtime_code_hash, "Settlement runtime code hash",
        )
        _canonical_hash(
            self.registry_runtime_code_hash, "Jury Registry runtime code hash",
        )
        if (
            not isinstance(self.jury_relay_public_key, str)
            or self.jury_relay_public_key not in self.network.jury_relay_public_keys
            or self.network.jury_transaction_senders.get(self.jury_relay_public_key)
            != self.transaction_sender
        ):
            raise ProviderJuryServiceError(
                "jury Relay identity has no dedicated manifest-pinned transaction sender"
            )
        sender = _canonical_address(self.transaction_sender, "jury transaction sender")
        if type(self.confirmations) is not int or not 2 <= self.confirmations <= 256:
            raise ProviderJuryServiceError(
                "jury confirmations must be an integer between 2 and 256"
            )
        if (
            type(self.deployment_block) is not int
            or self.deployment_block < 0
            or getattr(deployment, "deployment_block", None) != self.deployment_block
        ):
            raise ProviderJuryServiceError(
                "jury intake deployment block must be pinned by the deployment manifest"
            )
        if type(self.execution_enabled) is not bool:
            raise ProviderJuryServiceError("execution_enabled must be an explicit boolean")
        paths = (
            _durable_path(self.worker_db_path, "jury worker database"),
            _durable_path(self.transaction_db_path, "jury transaction database"),
            _durable_path(self.intake_db_path, "jury intake database"),
        )
        if len({os.path.realpath(path) for path in paths}) != len(paths):
            raise ProviderJuryServiceError("jury durable databases must use distinct paths")
        if not isinstance(self.policy_path, Path) or not self.policy_path.is_absolute():
            raise ProviderJuryServiceError("jury policy must use an absolute local path")
        # Parse and hash the policy before RelayState or any durable DB is opened.
        ProviderJuryRuntimePolicy.load(
            self.policy_path,
            deployment_decision_policy_hash=deployment.jury_decision_policy_hash,
        )
        if (
            type(self.rpc_timeout_seconds) is not int
            or not 1 <= self.rpc_timeout_seconds <= 300
        ):
            raise ProviderJuryServiceError("jury RPC timeout is out of bounds")
        if (
            isinstance(self.provider_timeout_seconds, bool)
            or not isinstance(self.provider_timeout_seconds, (int, float))
            or not math.isfinite(self.provider_timeout_seconds)
            or not 1 <= self.provider_timeout_seconds <= 300
        ):
            raise ProviderJuryServiceError("jury Provider timeout is out of bounds")
        if (
            type(self.max_snapshot_age_seconds) is not int
            or not 30 <= self.max_snapshot_age_seconds <= 86_400
        ):
            raise ProviderJuryServiceError("jury snapshot age is out of bounds")
        if (
            type(self.intake_max_scan_blocks) is not int
            or not 1 <= self.intake_max_scan_blocks <= 2_000
        ):
            raise ProviderJuryServiceError("jury intake scan range is out of bounds")
        if (
            type(self.intake_max_logs_per_scan) is not int
            or not 1 <= self.intake_max_logs_per_scan <= 10_000
        ):
            raise ProviderJuryServiceError("jury intake log limit is out of bounds")

        cap_values = (
            self.max_gas_price_wei,
            self.max_gas_units,
            self.max_total_gas_cost_wei,
        )
        if self.execution_enabled:
            if self.transaction_key_file is None:
                raise ProviderJuryServiceError(
                    "enabled jury execution requires a protected transaction key file"
                )
            key_path = _durable_path(
                self.transaction_key_file, "jury transaction key file",
            )
            if any(type(value) is not int or value <= 0 for value in cap_values):
                raise ProviderJuryServiceError(
                    "enabled jury execution requires all three positive gas caps"
                )
            try:
                derived = chain.private_key_to_address(_protected_key(key_path))
            except Exception as exc:
                raise ProviderJuryServiceError(
                    "jury transaction key is unavailable or not safely protected"
                ) from exc
            if derived != sender:
                raise ProviderJuryServiceError(
                    "jury transaction key differs from the manifest-pinned sender"
                )
        elif self.transaction_key_file is not None or any(
            value is not None for value in cap_values
        ):
            raise ProviderJuryServiceError(
                "jury key and gas caps require explicit execution enablement"
            )
        try:
            self.chain_config()
        except ProviderJuryChainError as exc:
            raise ProviderJuryServiceError(
                "Provider jury service requires a valid multi-RPC chain quorum"
            ) from exc

    @property
    def deployment(self) -> Any:
        return self.network.deployment

    def chain_config(self) -> ProviderJuryChainConfig:
        deployment = self.deployment
        return ProviderJuryChainConfig(
            network_id=self.network.network_id,
            rpc_urls=tuple(self.network.settlement_rpc_urls),
            chain_id=deployment.chain_id,
            genesis_hash=self.genesis_hash,
            settlement_contract=deployment.settlement,
            settlement_runtime_code_hash=self.settlement_runtime_code_hash,
            jury_registry=deployment.jury_registry,
            registry_runtime_code_hash=self.registry_runtime_code_hash,
            jury_registry_governance=deployment.jury_registry_governance,
            reputation_authority=deployment.reputation_authority,
            bond_penalty_recipient=deployment.policy["bond_penalty_recipient"],
            minimum_reputation=deployment.minimum_provider_reputation,
            jury_size=deployment.jury_size,
            adjudication_threshold=deployment.adjudication_threshold,
            selection_delay_blocks=deployment.jury_selection_delay_blocks,
            confirmations=self.confirmations,
            max_snapshot_age_seconds=self.max_snapshot_age_seconds,
            timeout_seconds=self.rpc_timeout_seconds,
        )


def load_provider_jury_service_config(
    network: ProviderNetworkConfig,
    *,
    jury_relay_public_key: str,
    rpc_url: str,
    policy_path: str | Path,
    worker_db_path: str | Path,
    transaction_db_path: str | Path,
    intake_db_path: str | Path,
    execution_enabled: bool,
    transaction_key_file: str | Path | None = None,
    max_gas_price_wei: int | None = None,
    max_gas_units: int | None = None,
    max_total_gas_cost_wei: int | None = None,
    rpc_timeout_seconds: int = 15,
    provider_timeout_seconds: float = 180.0,
) -> ProviderJuryServiceConfig:
    """Load service-only security pins from the already validated manifests."""
    if not isinstance(network, ProviderNetworkConfig):
        raise ProviderJuryServiceError("a validated Provider network config is required")
    try:
        network_payload = _read_json_object(
            network.path, label="Provider network config",
        )
        deployment_payload = _read_json_object(
            network.deployment_path, label="Provider settlement deployment",
        )
    except ProviderBootstrapError as exc:
        raise ProviderJuryServiceError(str(exc)) from exc
    normalized_rpc_values = network_payload.get(
        "settlement_rpc_urls", [network_payload.get("settlement_rpc_url")],
    )
    expected_network_context = {
        "network_id": network.network_id,
        "deployment": network.deployment_path.name,
        "settlement_rpc_urls": list(network.settlement_rpc_urls),
        "jury_relay_public_keys": list(network.jury_relay_public_keys),
        "jury_transaction_senders": dict(network.jury_transaction_senders),
        "jury_decision_policy_hash": network.jury_decision_policy_hash,
    }
    observed_network_context = {
        "network_id": network_payload.get("network_id"),
        "deployment": network_payload.get("deployment"),
        "settlement_rpc_urls": normalized_rpc_values,
        "jury_relay_public_keys": network_payload.get("jury_relay_public_keys"),
        "jury_transaction_senders": network_payload.get(
            "jury_transaction_senders"
        ),
        "jury_decision_policy_hash": network_payload.get(
            "jury_decision_policy_hash"
        ),
    }
    if observed_network_context != expected_network_context:
        raise ProviderJuryServiceError(
            "Provider network manifest changed after validation"
        )
    deployment = network.deployment
    expected_deployment_context = {
        "protocol_version": 10,
        "committee_mode": chain_v10.DYNAMIC_PROVIDER_JURY,
        "chain_id": deployment.chain_id,
        "settlement": deployment.settlement,
        "jury_registry": deployment.jury_registry,
        "jury_decision_policy_hash": deployment.jury_decision_policy_hash,
        "deployment_block": deployment.deployment_block,
    }
    if any(
        deployment_payload.get(name) != value
        for name, value in expected_deployment_context.items()
    ):
        raise ProviderJuryServiceError(
            "dynamic V10 deployment manifest changed after validation"
        )
    required_deployment_pins = {
        "genesis_hash",
        "settlement_runtime_code_keccak256",
        "jury_registry_runtime_code_keccak256",
        "confirmations",
    }
    missing = sorted(required_deployment_pins - set(deployment_payload))
    if missing:
        raise ProviderJuryServiceError(
            "dynamic V10 deployment is missing jury runtime pins: "
            + ", ".join(missing)
        )
    if jury_relay_public_key not in network.jury_relay_public_keys:
        raise ProviderJuryServiceError(
            "current jury Relay identity is not pinned by the network manifest"
        )
    sender = network.jury_transaction_senders.get(jury_relay_public_key)
    if sender is None:
        raise ProviderJuryServiceError(
            "current jury Relay identity has no dedicated transaction sender"
        )
    deployment_block = getattr(network.deployment, "deployment_block", None)
    return ProviderJuryServiceConfig(
        network=network,
        rpc_url=rpc_url,
        genesis_hash=deployment_payload["genesis_hash"],
        settlement_runtime_code_hash=deployment_payload[
            "settlement_runtime_code_keccak256"
        ],
        registry_runtime_code_hash=deployment_payload[
            "jury_registry_runtime_code_keccak256"
        ],
        jury_relay_public_key=jury_relay_public_key,
        transaction_sender=sender,
        confirmations=deployment_payload["confirmations"],
        deployment_block=deployment_block,
        policy_path=Path(policy_path),
        worker_db_path=Path(worker_db_path),
        transaction_db_path=Path(transaction_db_path),
        intake_db_path=Path(intake_db_path),
        execution_enabled=execution_enabled,
        transaction_key_file=(
            Path(transaction_key_file) if transaction_key_file is not None else None
        ),
        max_gas_price_wei=max_gas_price_wei,
        max_gas_units=max_gas_units,
        max_total_gas_cost_wei=max_total_gas_cost_wei,
        rpc_timeout_seconds=rpc_timeout_seconds,
        provider_timeout_seconds=provider_timeout_seconds,
    )


def _descriptor_candidate(
    state: Any, peer_id: str, session: Any, config: ProviderJuryServiceConfig,
) -> dict[str, Any] | None:
    peer = getattr(session, "peer", None)
    if not isinstance(peer, Mapping):
        return None
    public_key = peer.get("public_key")
    try:
        if peer_id_from_public_key(str(public_key or "")) != peer_id:
            return None
    except Exception:
        return None
    descriptor = peer.get("provider_jury")
    fields = {
        "schema", "provider_owner", "vote_signer", "operator_id",
        "operator_id_hash", "peer_id_hash", "capability", "capability_hash",
    }
    if not isinstance(descriptor, Mapping) or set(descriptor) != fields:
        return None
    settlement = peer.get("settlement")
    if not isinstance(settlement, Mapping):
        return None
    if (
        peer.get("network_id") != config.network.network_id
        or peer.get("payment_address") != descriptor.get("provider_owner")
        or getattr(session, "authenticated_signer", None)
        != descriptor.get("vote_signer")
        or settlement.get("version") != 10
        or settlement.get("chain_id") != config.deployment.chain_id
        or settlement.get("contract") != config.deployment.settlement
        or settlement.get("provider_signer") != descriptor.get("vote_signer")
        or peer.get("secure_transport_required") is not True
        or not peer.get("transport_key")
        or descriptor.get("schema") != "mycomesh.provider-jury.descriptor.v1"
        or descriptor.get("peer_id_hash") != provider_jury._keccak_text(peer_id)
        or not isinstance(descriptor.get("capability"), Mapping)
        or descriptor["capability"].get("decision_policy_hash")
        != config.deployment.jury_decision_policy_hash
    ):
        return None
    candidate = {
        "owner": descriptor["provider_owner"],
        "vote_signer": descriptor["vote_signer"],
        "operator_id": descriptor["operator_id"],
        "operator_id_hash": descriptor["operator_id_hash"],
        "peer_id": peer_id,
        "peer_id_hash": descriptor["peer_id_hash"],
        "capability": dict(descriptor["capability"]),
        "capability_hash": descriptor["capability_hash"],
    }
    try:
        # Add a temporary valid score so the shared canonical descriptor parser
        # validates every non-chain field. The chain snapshot supplies the real
        # score in resolve_provider_descriptor below.
        provider_jury._selected_provider({**candidate, "reputation": 1})
    except provider_jury.ProviderJuryError:
        return None
    return candidate


def resolve_provider_descriptor(
    state: Any, snapshot: Mapping[str, Any], config: ProviderJuryServiceConfig,
) -> dict[str, Any]:
    """Resolve an immutable Registry member only from live authenticated peers."""
    expected_fields = {
        "owner", "vote_signer", "operator_id_hash", "peer_id_hash",
        "capability_hash", "reputation",
    }
    if not isinstance(snapshot, Mapping) or set(snapshot) != expected_fields:
        raise ProviderJuryServiceError("jury Provider snapshot is malformed")
    lock = getattr(state, "lock", None)
    providers = getattr(state, "providers", None)
    if lock is None or not isinstance(providers, Mapping):
        raise ProviderJuryServiceError("Relay Provider state is unavailable")
    with lock:
        sessions = list(providers.items())
    matches: list[tuple[Any, dict[str, Any]]] = []
    for peer_id, session in sessions:
        candidate = _descriptor_candidate(state, peer_id, session, config)
        if candidate is None:
            continue
        compared = {
            "owner": candidate["owner"],
            "vote_signer": candidate["vote_signer"],
            "operator_id_hash": candidate["operator_id_hash"],
            "peer_id_hash": candidate["peer_id_hash"],
            "capability_hash": candidate["capability_hash"],
        }
        if all(compared[name] == snapshot[name] for name in compared):
            matches.append((session, {**candidate, "reputation": snapshot["reputation"]}))
    if len(matches) != 1:
        raise ProviderJuryServiceError(
            "assigned jury Provider is unavailable or ambiguously authenticated"
        )
    session, selected = matches[0]
    try:
        from .relay import _require_provider_admissible

        _require_provider_admissible(state, session)
        return provider_jury._selected_provider(selected)
    except Exception as exc:
        raise ProviderJuryServiceError(
            "assigned jury Provider is not currently admissible"
        ) from exc


def _transport_ready(state: Any, config: ProviderJuryServiceConfig) -> bool:
    identity = getattr(state, "_jury_identity", None)
    if (
        not isinstance(identity, NodeIdentity)
        or identity.public_key != config.jury_relay_public_key
    ):
        return False
    lock = getattr(state, "lock", None)
    providers = getattr(state, "providers", None)
    if lock is None or not isinstance(providers, Mapping):
        return False
    with lock:
        sessions = list(providers.items())
    owners: set[str] = set()
    signers: set[str] = set()
    operators: set[str] = set()
    peers: set[str] = set()
    try:
        from .relay import _require_provider_admissible
    except ImportError:
        return False
    for peer_id, session in sessions:
        candidate = _descriptor_candidate(state, peer_id, session, config)
        if candidate is None:
            continue
        try:
            _require_provider_admissible(state, session)
        except Exception:
            continue
        owners.add(candidate["owner"])
        signers.add(candidate["vote_signer"])
        operators.add(candidate["operator_id_hash"])
        peers.add(candidate["peer_id_hash"])
    return (
        len(owners) >= config.deployment.jury_size
        and len(signers) >= config.deployment.jury_size
        and len(operators) >= config.deployment.jury_size
        and len(peers) >= config.deployment.jury_size
    )


@dataclass(frozen=True)
class ProviderJuryServiceFactories:
    config: ProviderJuryServiceConfig
    evidence_resolver: EvidenceResolver | None = None

    def _evidence_resolver(self, state: Any) -> EvidenceResolver:
        if self.evidence_resolver is not None:
            if not callable(self.evidence_resolver):
                raise ProviderJuryServiceError(
                    "trusted local jury evidence resolver must be callable"
                )
            return self.evidence_resolver
        store = getattr(state, "_incident_store", None)
        resolver = getattr(store, "resolve_provider_jury_evidence", None)
        if not callable(resolver):
            raise ProviderJuryServiceError(
                "jury service requires a trusted local Relay incident store"
            )
        return resolver

    def intake_factory(self, state: Any) -> ProviderJuryEventIntake:
        config = self.config
        try:
            intake_config = ProviderJuryEventIntakeConfig(
                network_id=config.network.network_id,
                rpc_url=config.rpc_url,
                chain_id=config.deployment.chain_id,
                genesis_hash=config.genesis_hash,
                settlement_contract=config.deployment.settlement,
                jury_registry=config.deployment.jury_registry,
                deployment_block=config.deployment_block,
                confirmations=config.confirmations,
                max_scan_blocks=config.intake_max_scan_blocks,
                max_logs_per_scan=config.intake_max_logs_per_scan,
                rpc_timeout=config.rpc_timeout_seconds,
            )
            return ProviderJuryEventIntake(
                config.intake_db_path,
                config=intake_config,
                resolve_evidence=self._evidence_resolver(state),
            )
        except ProviderJuryServiceError:
            raise
        except Exception as exc:
            raise ProviderJuryServiceError(
                "failed to construct the trusted Provider jury event intake"
            ) from exc

    def runtime_factory(self, state: Any) -> ProviderJuryRuntime:
        config = self.config
        identity = getattr(state, "_jury_identity", None)
        if (
            not isinstance(identity, NodeIdentity)
            or identity.public_key != config.jury_relay_public_key
        ):
            raise ProviderJuryServiceError(
                "Relay jury identity differs from the network manifest"
            )
        if config.execution_enabled:
            forbidden = {
                config.deployment.settlement,
                config.deployment.jury_registry,
                config.deployment.jury_registry_governance,
                config.deployment.reputation_authority,
                config.deployment.treasury,
                config.deployment.policy["bond_penalty_recipient"],
                getattr(state, "payment_address", None),
                getattr(state, "attestation_address", None),
            }
            settlement_key = getattr(state, "settlement_private_key", None)
            if settlement_key:
                try:
                    forbidden.add(chain.private_key_to_address(
                        chain.parse_private_key(settlement_key)
                    ))
                except chain.ChainError as exc:
                    raise ProviderJuryServiceError(
                        "Relay settlement transaction identity is invalid"
                    ) from exc
            if config.transaction_sender in forbidden:
                raise ProviderJuryServiceError(
                    "jury execution requires a dedicated transaction sender"
                )

        adapter: ProviderJuryChainAdapter | None = None
        worker: ProviderJuryRelayWorker | None = None
        try:
            adapter = ProviderJuryChainAdapter(
                config.chain_config(),
                outbox_path=config.transaction_db_path,
                resolve_provider=lambda snapshot: resolve_provider_descriptor(
                    state, snapshot, config,
                ),
                sender=config.transaction_sender,
                execution_enabled=config.execution_enabled,
                dedicated_sender=config.execution_enabled,
                key_file=config.transaction_key_file,
                max_gas_price_wei=config.max_gas_price_wei,
                max_gas_units=config.max_gas_units,
                max_total_gas_cost_wei=config.max_total_gas_cost_wei,
            )
            # Startup is a real chain-pin gate, not merely manifest parsing.
            adapter.confirmed_context()
            worker = ProviderJuryRelayWorker(
                config.worker_db_path,
                relay_identity=identity,
                network_id=config.network.network_id,
                chain_id=config.deployment.chain_id,
                settlement_contract=config.deployment.settlement,
                jury_registry=config.deployment.jury_registry,
                minimum_reputation=config.deployment.minimum_provider_reputation,
                jury_size=config.deployment.jury_size,
                adjudication_threshold=config.deployment.adjudication_threshold,
                decision_policy_hash=config.deployment.jury_decision_policy_hash,
                execution_enabled=config.execution_enabled,
                required_confirmations=config.confirmations,
            )

            def invoke(task: Mapping[str, Any]) -> Mapping[str, Any]:
                from .relay import invoke_provider_jury

                return invoke_provider_jury(
                    state, task, timeout=config.provider_timeout_seconds,
                    relay_identity=identity,
                )

            return ProviderJuryRuntime(
                worker=worker,
                chain_adapter=adapter,
                invoke_provider=invoke,
                policy_path=config.policy_path,
                deployment_decision_policy_hash=(
                    config.deployment.jury_decision_policy_hash
                ),
                execution_enabled=config.execution_enabled,
                transport_health=lambda: _transport_ready(state, config),
                # Relay rederives strict schema, cursor, halt and loop health;
                # do not let the raw intake ready bit bypass lifecycle state.
                case_intake_health=state.provider_jury_case_intake_health,
            )
        except Exception as exc:
            if worker is not None:
                worker.close()
            if adapter is not None:
                adapter.close()
            if isinstance(exc, ProviderJuryServiceError):
                raise
            raise ProviderJuryServiceError(
                "failed to construct or verify the Provider jury runtime"
            ) from exc
        except BaseException:
            if worker is not None:
                worker.close()
            if adapter is not None:
                adapter.close()
            raise


__all__ = [
    "ProviderJuryServiceConfig",
    "ProviderJuryServiceError",
    "ProviderJuryServiceFactories",
    "load_provider_jury_service_config",
    "resolve_provider_descriptor",
]
